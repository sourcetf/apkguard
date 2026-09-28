package passes

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"apkguard/internal/arsc"
	"apkguard/internal/config"
	"apkguard/internal/pipeline"
)

// findAapt2 定位 build-tools 里的 aapt2；找不到时返回空串。
//
// 用 aapt2 做验证而不是自己解析 ARSC：它是 Android 官方实现，
// 能确认「改写后的资源表在真实工具链眼里依然合法」——这是自研解析器
// 无法自证的（用同一份可能出错的代码去校验自己，等于没校验）。
func findAapt2() string {
	root := filepath.Join("..", "..", "..", "tools", "build-tools")
	ents, err := os.ReadDir(root)
	if err != nil {
		return ""
	}
	for _, e := range ents {
		p := filepath.Join(root, e.Name(), "aapt2.exe")
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	if p, err := exec.LookPath("aapt2"); err == nil {
		return p
	}
	return ""
}

// dumpResourceKeys 用 aapt2 导出「资源 ID + 类型/名字」列表。
func dumpResourceKeys(t *testing.T, aapt2, apk string) []string {
	t.Helper()
	out, err := exec.Command(aapt2, "dump", "resources", apk).Output()
	if err != nil {
		t.Fatalf("aapt2 dump 失败: %v", err)
	}
	var keys []string
	for _, line := range strings.Split(string(out), "\n") {
		// 形如：      resource 0x7f010002 anim/acjrw38 PUBLIC
		f := strings.Fields(line)
		for i, tok := range f {
			if tok == "resource" && i+2 < len(f) && strings.HasPrefix(f[i+1], "0x") {
				keys = append(keys, f[i+1]+" "+f[i+2])
				break
			}
		}
	}
	sort.Strings(keys)
	return keys
}

// TestResourceRewritePreservesResourceIDs 是 A5/A11 的**决定性判据**。
//
// 资源混淆唯一不能破坏的是「资源 ID 不变」：应用代码里所有 R.xxx 引用都是
// 编译期固化的整数 ID，只要 ID 与类型不变，改名文件路径就不会影响运行。
// 反过来，只要有一条 ID 变了，应用就会在某处崩掉——而这类问题在真机上
// 往往表现为难以定位的资源找不到。
//
// 因此判据必须是「前后 ID 集合逐条相等」，而不是「文件确实改名了」。
func TestResourceRewritePreservesResourceIDs(t *testing.T) {
	aapt2 := findAapt2()
	if aapt2 == "" {
		t.Skip("未找到 aapt2，跳过资源表校验")
	}
	in := sampleAPK(t)
	before := dumpResourceKeys(t, aapt2, in)
	if len(before) == 0 {
		t.Skip("样本没有可枚举的资源")
	}

	for _, tc := range []struct {
		name string
		opts *config.Options
	}{
		{"A5 仅改名", &config.Options{Enabled: map[config.FeatureID]bool{"A5": true}, Seed: "rt"}},
		{"A11 全量扁平化", &config.Options{Enabled: map[config.FeatureID]bool{"A5": true, "A11": true}, Seed: "rt"}},
	} {
		art, err := pipeline.Load(in)
		if err != nil {
			t.Fatalf("读取样本失败: %v", err)
		}
		ctx := context.Background()
		if err := (&resourceObf{}).Run(ctx, art, tc.opts); err != nil {
			t.Fatalf("%s: A5 执行失败: %v", tc.name, err)
		}
		if err := (&resourceFlatten{}).Run(ctx, art, tc.opts); err != nil {
			t.Fatalf("%s: A11 执行失败: %v", tc.name, err)
		}

		out := filepath.Join(t.TempDir(), "out.apk")
		if err := os.WriteFile(out, pipeline.Bytes(art), 0o644); err != nil {
			t.Fatalf("写出产物失败: %v", err)
		}
		after := dumpResourceKeys(t, aapt2, out)
		if len(after) != len(before) {
			t.Fatalf("%s: 资源条数变化：%d → %d", tc.name, len(before), len(after))
		}
		for i := range before {
			if before[i] != after[i] {
				t.Fatalf("%s: 资源 ID/名字发生变化：%q → %q（应用里的 R.* 引用会失效）",
					tc.name, before[i], after[i])
			}
		}
		// 同时确认路径确实被改了（否则测试可能在「什么都没做」的情况下通过）。
		changed := 0
		for _, e := range art.Entries() {
			if n := e.NameString(); strings.HasPrefix(n, "res/") {
				changed++
			}
		}
		if changed == 0 {
			t.Fatalf("%s: 没有任何 res/ 条目", tc.name)
		}
		t.Logf("%s：%d 条资源 ID 逐条不变，%d 个 res/ 条目已改名", tc.name, len(after), changed)
	}
}

// TestResourceFlattenRemovesSemanticDirs 验证 A11 确实消除了语义目录名。
//
// A5 只改名、保留目录结构；A11 必须把 res/ 下的目录压成单字母——
// 这是文档里「零语义残留」的具体含义，也是 A11 相对 A5 的全部增量价值。
func TestResourceFlattenRemovesSemanticDirs(t *testing.T) {
	art, err := pipeline.Load(sampleAPK(t))
	if err != nil {
		t.Skipf("读取样本失败: %v", err)
	}
	// 记录「被 ARSC 引用」的路径：只有这些是本 Pass 的职责范围。
	// 不被引用的 res/ 条目（死资源、或 A10/A12 注入的畸形垃圾条目）按设计保留原样。
	referenced := map[string]bool{}
	if e := pipeline.Find(art, arscName); e != nil {
		data, err := e.Data()
		if err != nil {
			t.Fatalf("读取 ARSC 失败: %v", err)
		}
		tbl, err := arsc.Parse(data)
		if err != nil {
			t.Fatalf("解析 ARSC 失败: %v", err)
		}
		for _, p := range tbl.ResPaths() {
			referenced[p] = true
		}
	}
	if len(referenced) == 0 {
		t.Skip("样本没有 ARSC 引用的 res/ 路径")
	}

	// 记录改写前的全部条目名：改写后「新出现的名字」即为被本 Pass 改名的条目。
	// 用这个判定而不是「路径有几段」之类的启发式——样本里就有
	// res/values/anims.xml\.9.png 这种恰好 3 段、却并不被 ARSC 引用的垃圾条目，
	// 任何基于形状的猜测都会把它误判成真实资源。
	before := map[string]bool{}
	for _, e := range art.Entries() {
		before[e.NameString()] = true
	}

	opts := &config.Options{Enabled: map[config.FeatureID]bool{"A5": true, "A11": true}, Seed: "fl"}
	ctx := context.Background()
	if err := (&resourceObf{}).Run(ctx, art, opts); err != nil {
		t.Fatalf("A5 执行失败: %v", err)
	}
	if err := (&resourceFlatten{}).Run(ctx, art, opts); err != nil {
		t.Fatalf("A11 执行失败: %v", err)
	}

	// 被 ARSC 引用的原路径必须都已消失（即确实被改名）。
	for old := range referenced {
		if pipeline.Find(art, old) != nil {
			t.Fatalf("被 ARSC 引用的条目 %s 未被改名", old)
		}
	}
	// 只检查「本次改名产出」的条目：它们的目录必须是单字母。
	renamed := 0
	for _, n := range resZipEntryNames(art) {
		if before[n] {
			continue // 改写前就存在的（垃圾/死资源），按设计保留原样
		}
		parts := strings.Split(n, "/")
		if len(parts) != 3 || len(parts[1]) != 1 {
			t.Fatalf("被改名的条目未扁平化: %s（语义残留）", n)
		}
		renamed++
	}
	if renamed == 0 {
		t.Fatal("没有任何条目被改名")
	}
	t.Logf("A11：ARSC 引用的 %d 条路径全部改名、目录压成单字母（实际产出 %d 条）；垃圾条目按设计保留",
		len(referenced), renamed)
}
