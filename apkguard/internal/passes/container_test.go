package passes

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/pipeline"
	"apkguard/internal/zipx"
)

// TestPayloadContainerMovesAndDeceives 是 B8 的核心判据。
//
// 参考样本的做法是：真实载荷藏在 assets/<随机名>.zip 里，zip 内含 .dat 密文与
// 一份写着假包名的 json。我们的实现要达到同样的效果：
//   - 真实载荷不再出现在 assets 顶层（改名到容器目录树里）；
//   - 载荷清单同步更新（否则 B3 生成的 Loader 会去开一个不存在的条目，
//     应用启动即崩——这是本功能最容易踩的坑）；
//   - 另有一个同构的诱饵容器（.dat + json，json 里是假包名）。
func TestPayloadContainerMovesAndDeceives(t *testing.T) {
	art := newArtifact(
		zipx.NewStored("classes.dex", smallDexWithClass(t, "Lapp/A;")),
		zipx.NewStored("classes2.dex", smallDexWithClass(t, "Lapp/B;")),
	)
	opts := &config.Options{
		Enabled: map[config.FeatureID]bool{"B1": true, "B8": true},
		Seed:    "cont",
	}
	ctx := context.Background()
	if err := (&encryptDex{}).Run(ctx, art, opts); err != nil {
		t.Fatalf("B1 执行失败: %v", err)
	}

	sp := payloadsOf(art)
	if sp == nil || len(sp.Items) == 0 {
		t.Fatal("B1 未产出载荷清单")
	}
	beforeNames := make([]string, 0, len(sp.Items))
	for _, it := range sp.Items {
		beforeNames = append(beforeNames, it.Asset)
	}

	if err := (&payloadContainer{}).Run(ctx, art, opts); err != nil {
		t.Fatalf("B8 执行失败: %v", err)
	}

	// ① 清单里的条目名必须已更新，且每个都能在归档里找到
	moved := 0
	for i, it := range sp.Items {
		if it.Asset == beforeNames[i] {
			t.Fatalf("第 %d 份载荷的条目名未更新（%s）", i, it.Asset)
		}
		if !strings.HasPrefix(it.Asset, "assets/") {
			t.Fatalf("载荷路径应以 assets/ 开头: %s", it.Asset)
		}
		if pipeline.Find(art, it.Asset) == nil {
			t.Fatalf("载荷清单指向了不存在的条目 %s（Loader 会在运行时打开失败）", it.Asset)
		}
		moved++
	}
	if moved != len(sp.Items) {
		t.Fatalf("只更新了 %d/%d 份载荷", moved, len(sp.Items))
	}

	// ② 出现诱饵容器，且内含 .dat 与 json（json 里是假包名）
	decoy := art.Stats["B8.decoy"]
	if decoy == "" {
		t.Fatal("未记录诱饵容器名")
	}
	de := pipeline.Find(art, decoy)
	if de == nil {
		t.Fatalf("诱饵容器 %s 不存在", decoy)
	}
	blob, err := de.Data()
	if err != nil {
		t.Fatalf("读取诱饵容器失败: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(blob), int64(len(blob)))
	if err != nil {
		t.Fatalf("诱饵容器不是合法 zip: %v", err)
	}
	var sawDat, sawJSON bool
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("打开 %s 失败: %v", f.Name, err)
		}
		data, _ := io.ReadAll(rc)
		rc.Close()
		switch {
		case strings.HasSuffix(f.Name, ".dat"):
			sawDat = true
			// 高熵：字节种类应接近 256
			seen := map[byte]bool{}
			for _, b := range data {
				seen[b] = true
			}
			if len(seen) < 200 {
				t.Errorf("诱饵 .dat 熵值过低（只出现 %d 种字节），会被一眼看作占位文件", len(seen))
			}
		case strings.HasSuffix(f.Name, ".json"):
			sawJSON = true
			var cfg decoyConfig
			if err := json.Unmarshal(data, &cfg); err != nil {
				t.Fatalf("诱饵配置不是合法 JSON: %v", err)
			}
			if cfg.PackageName != defaultDecoyPkg {
				t.Errorf("诱饵包名应为 %q，实际 %q", defaultDecoyPkg, cfg.PackageName)
			}
			if cfg.APKFileName == "" {
				t.Error("诱饵配置缺少 apkFileName")
			}
		}
	}
	if !sawDat || !sawJSON {
		t.Fatalf("诱饵容器内容不全：dat=%v json=%v", sawDat, sawJSON)
	}
	// ③ 诱饵包名不得等于真实包名（否则起不到误导作用）
	if defaultDecoyPkg == "com.agtest" {
		t.Fatal("诱饵包名与真实包名相同，失去误导价值")
	}
	t.Logf("B8：%d 份载荷移入容器目录，诱饵容器 %s（%d 字节，假包名 %s）",
		moved, decoy, len(blob), defaultDecoyPkg)
}

// TestPayloadContainerRequiresB1 校验未启用 B1 时给出可操作的错误。
func TestPayloadContainerRequiresB1(t *testing.T) {
	art := newArtifact(zipx.NewStored("classes.dex", smallDexWithClass(t, "Lapp/A;")))
	err := (&payloadContainer{}).Run(context.Background(), art, &config.Options{
		Enabled: map[config.FeatureID]bool{"B8": true},
	})
	if err == nil {
		t.Fatal("未启用 B1 时应报错")
	}
	if !strings.Contains(err.Error(), "B1") {
		t.Fatalf("错误信息应点明需要 B1，实际: %v", err)
	}
}

// TestPayloadContainerChainWithShell 验证 B8 之后加壳链路仍然可用。
//
// 这是最关键的一条：B8 改的是载荷条目名，而 B3 会把这些名字内联进壳的字节码。
// 若清单没同步更新，产物能装上但一启动就 DexPathList 为空 / 打开资产失败。
// 这里跑完整的 B1→B8→B2→B3，并确认壳 DEX 里出现的是**新**路径。
func TestPayloadContainerChainWithShell(t *testing.T) {
	// 用仓库固件 APK：B2 需要真实的 AndroidManifest.xml（含 application/android:name）
	art := loadSample(t)
	opts := &config.Options{
		Enabled: map[config.FeatureID]bool{"B1": true, "B2": true, "B3": true, "B8": true},
		Seed:    "chain8",
	}
	ctx := context.Background()
	for _, p := range []pipeline.Pass{&encryptDex{}, &payloadContainer{}, &appReplace{}, &classLoader{}} {
		if err := p.Run(ctx, art, opts); err != nil {
			t.Fatalf("功能项 %s 执行失败: %v", p.ID(), err)
		}
	}
	sp := payloadsOf(art)
	shell := pipeline.Find(art, "classes.dex")
	if shell == nil {
		t.Fatal("壳 DEX 不存在")
	}
	data, err := shell.Data()
	if err != nil {
		t.Fatalf("读取壳 DEX 失败: %v", err)
	}
	// 壳 DEX 的字符串池里必须出现每一份载荷的新路径（去掉 assets/ 前缀后）
	for _, it := range sp.Items {
		key := strings.TrimPrefix(it.Asset, "assets/")
		if !bytes.Contains(data, []byte(key)) {
			t.Fatalf("壳 DEX 里找不到载荷路径 %s（Loader 会打开不存在的资产）", key)
		}
	}
	t.Logf("B8 + 加壳链路：壳 DEX 已内联 %d 份载荷的新路径", len(sp.Items))
}

// smallDexWithClass 造一个只含指定类的最小 DEX（供 B8 的载荷测试使用）。
func smallDexWithClass(t *testing.T, cls string) []byte {
	t.Helper()
	d, err := dex.Build(dex.Addition{Classes: []dex.ClassSpec{{
		Name: cls, Super: "Ljava/lang/Object;", Access: 0x0001,
	}}})
	if err != nil {
		t.Fatalf("构造 DEX 失败: %v", err)
	}
	return d
}
