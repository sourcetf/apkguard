package passes

import (
	"bytes"
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/pipeline"
	"apkguard/internal/zipx"
)

// TestPayloadContainerMovesAndDeceives 是 B8 的核心判据。
//
// 真实载荷移入 assets/<词>/<hex8>/<hex12>.<ext>；诱饵必须**与真载荷同构**——
// 同目录树、同命名形态、纯高熵字节且不带 PK 头。否则脱壳脚本只要「找 PK 头」
// 就能锁定诱饵、跳过真载荷，等于用排除法替攻击者定位真目标。
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

	// ② 诱饵与真载荷同构：同目录树、同命名形态、高熵、无 PK 头
	decoy := art.Stats["B8.decoy"]
	cfgName := art.Stats["B8.decoy_cfg"]
	if decoy == "" || cfgName == "" {
		t.Fatalf("未记录诱饵条目（decoy=%q cfg=%q）", decoy, cfgName)
	}
	tree := dirOf(sp.Items[0].Asset)
	if dirOf(decoy) != tree {
		t.Fatalf("诱饵 %s 不在真载荷目录树 %s 下（可被路径差异识别）", decoy, tree)
	}
	if dirOf(cfgName) != tree {
		t.Fatalf("诱饵配置 %s 不在真载荷目录树 %s 下", cfgName, tree)
	}
	// 命名形态：<hex12>.<ext>，ext 属于容器扩展名集合。
	isoName := regexp.MustCompile(`^[0-9a-f]{12}\.(dat|bin|res|pack)$`)
	if !isoName.MatchString(pathBaseName(decoy)) {
		t.Fatalf("诱饵 %s 的命名形态与真载荷不同构", decoy)
	}
	if !regexp.MustCompile(`^[0-9a-f]{12}\.json$`).MatchString(pathBaseName(cfgName)) {
		t.Fatalf("诱饵配置 %s 的命名形态异常", cfgName)
	}

	de := pipeline.Find(art, decoy)
	if de == nil {
		t.Fatalf("诱饵条目 %s 不存在", decoy)
	}
	blob, err := de.Data()
	if err != nil {
		t.Fatalf("读取诱饵失败: %v", err)
	}
	if bytes.HasPrefix(blob, []byte("PK")) {
		t.Fatal("诱饵带 PK 头：脱壳脚本只要找 PK 就能锁定诱饵、跳过真载荷")
	}
	if len(blob) < 256<<10 {
		t.Fatalf("诱饵只有 %d 字节，太小会被一眼看作占位文件", len(blob))
	}
	seen := map[byte]bool{}
	for _, b := range blob {
		seen[b] = true
	}
	if len(seen) < 200 {
		t.Errorf("诱饵熵值过低（只出现 %d 种字节），会被一眼看作占位文件", len(seen))
	}

	// 配置 JSON 与样本同构，写的是假包名。
	ce := pipeline.Find(art, cfgName)
	if ce == nil {
		t.Fatalf("诱饵配置 %s 不存在", cfgName)
	}
	cfgBlob, err := ce.Data()
	if err != nil {
		t.Fatalf("读取诱饵配置失败: %v", err)
	}
	var cfg decoyConfig
	if err := json.Unmarshal(cfgBlob, &cfg); err != nil {
		t.Fatalf("诱饵配置不是合法 JSON: %v", err)
	}
	if cfg.PackageName != defaultDecoyPkg {
		t.Errorf("诱饵包名应为 %q，实际 %q", defaultDecoyPkg, cfg.PackageName)
	}
	if cfg.APKFileName == "" {
		t.Error("诱饵配置缺少 apkFileName")
	}

	// ③ 诱饵包名不得等于真实包名（否则起不到误导作用）
	if defaultDecoyPkg == "com.agtest" {
		t.Fatal("诱饵包名与真实包名相同，失去误导价值")
	}
	t.Logf("B8：%d 份载荷移入 %s/，同构诱饵 %s（%d 字节，无 PK 头），假包名 %s",
		moved, tree, decoy, len(blob), defaultDecoyPkg)
}

// dirOf 返回路径的目录部分（含结尾斜杠前的内容）。
func dirOf(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[:i]
	}
	return ""
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
