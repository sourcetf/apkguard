package passes

import (
	"bytes"
	"context"
	"sort"
	"strings"
	"testing"

	"apkguard/internal/arsc"
	"apkguard/internal/axml"
	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/pipeline"
	"apkguard/internal/zipx"
)

// ---- A16 测试辅助 ----

// decoyCoreRealArtifact 构造一份含三个真核心文件的产物，并返回原始内容快照。
//
// 用真实的合法内容（而不是随意字节）作为「真文件」：这样「内容未被改坏」的断言
// 才真正有意义——如果我们误改了 resources.arsc 或 Manifest，逐字节比对会立刻发现。
func decoyCoreRealArtifact(t *testing.T) (*pipeline.Artifact, map[string][]byte) {
	t.Helper()
	mf := realisticAXML(newRand("real-mf"), 512)
	ar := decoyArsc(newRand("real-ar"))
	dx, err := decoyDexBody(newRand("real-dx"))
	if err != nil {
		t.Fatalf("构造基准 DEX 失败: %v", err)
	}
	orig := map[string][]byte{manifestName: mf, arscName: ar, "classes.dex": dx}
	art := newArtifact(
		zipx.NewStored(manifestName, mf),
		zipx.NewStored(arscName, ar),
		zipx.NewStored("classes.dex", dx),
	)
	return art, orig
}

func decoyCoreOpts(count int) *config.Options {
	return &config.Options{
		Enabled:        map[config.FeatureID]bool{"A16": true},
		Seed:           "a16-seed",
		DecoyCoreCount: count,
	}
}

// decoyCoreInjectedNames 返回产物中由本 Pass 注入（即不在 orig 里）的条目名。
func decoyCoreInjectedNames(art *pipeline.Artifact, orig map[string][]byte) []string {
	var out []string
	for _, e := range art.Entries() {
		if _, ok := orig[e.NameString()]; !ok {
			out = append(out, e.NameString())
		}
	}
	sort.Strings(out)
	return out
}

// ---- 核心价值：假核心文件必须是「可解析的完整结构」 ----

// TestDecoyCoreManifestsAreParsableAXML 是 A16 的决定性判据之一。
//
// 假 Manifest 的价值在于「像真的」：如果它只有 8 字节头或随机字节，扫描器一次解析
// 失败就把整类丢弃，反而更快定位真文件。因此这里断言每个注入的假 Manifest 都能被
// axml.Parse 解析，并且能解出 manifest/application/activity 元素与 package 属性。
func TestDecoyCoreManifestsAreParsableAXML(t *testing.T) {
	art, _ := decoyCoreRealArtifact(t)
	if err := (&decoyCore{}).Run(context.Background(), art, decoyCoreOpts(4)); err != nil {
		t.Fatalf("A16 执行失败: %v", err)
	}

	checked := 0
	for _, e := range art.Entries() {
		n := e.NameString()
		if !strings.EqualFold(n, manifestName) || n == manifestName {
			continue
		}
		data, err := e.Data()
		if err != nil {
			t.Fatalf("读取 %s 失败: %v", n, err)
		}
		f, err := axml.Parse(data)
		if err != nil {
			t.Fatalf("%s 不是可解析的 AXML: %v（假 Manifest 必须是合法结构）", n, err)
		}
		if f.FindElement("manifest") == nil {
			t.Fatalf("%s 解析成功但没有 <manifest> 元素", n)
		}
		if f.FindElement("application") == nil {
			t.Fatalf("%s 缺少 <application> 元素", n)
		}
		if f.FindElement("activity") == nil {
			t.Fatalf("%s 缺少 <activity> 元素", n)
		}
		m := f.FindElement("manifest")
		if m.AttrString("package") == "" {
			t.Fatalf("%s 的 <manifest> 缺少 package 属性（下标错位会让 aapt2 读到空值）", n)
		}
		checked++
	}
	if checked < 3 {
		t.Fatalf("只生成了 %d 个可解析的假 Manifest，覆盖不足", checked)
	}
	t.Logf("已生成 %d 个可解析的假 Manifest（含 manifest/application/activity 元素树）", checked)
}

// TestDecoyCoreDexIsParseableAndVerified 钉住「假 DEX 是结构完整的最小 DEX」。
//
// 与 A9 的分工：A9 只伪造 magic（解析必失败）；A16 这一档必须真的能通过
// dex.Parse 与 dex.Verify，jadx/apktool 会把它当正常 DEX 反编译。
func TestDecoyCoreDexIsParseableAndVerified(t *testing.T) {
	art, _ := decoyCoreRealArtifact(t)
	if err := (&decoyCore{}).Run(context.Background(), art, decoyCoreOpts(4)); err != nil {
		t.Fatalf("A16 执行失败: %v", err)
	}

	checked := 0
	for _, e := range art.Entries() {
		n := e.NameString()
		if !strings.EqualFold(n, "classes.dex") || n == "classes.dex" {
			continue
		}
		data, err := e.Data()
		if err != nil {
			t.Fatalf("读取 %s 失败: %v", n, err)
		}
		f, err := dex.Parse(data)
		if err != nil {
			t.Fatalf("%s 无法通过 dex.Parse: %v（假 DEX 必须是合法结构）", n, err)
		}
		if f.NClass < 1 {
			t.Fatalf("%s 解析成功但没有任何类定义，jadx 打开会是空 DEX", n)
		}
		if err := dex.Verify(data); err != nil {
			t.Fatalf("%s 无法通过 dex.Verify: %v", n, err)
		}
		checked++
	}
	if checked < 3 {
		t.Fatalf("只生成了 %d 个合法假 DEX，覆盖不足", checked)
	}
	t.Logf("已生成 %d 个能通过 dex.Parse/dex.Verify 的假 DEX（含类定义与方法体）", checked)
}

// TestDecoyCoreArscIsParsable 校验假 arsc 至少是「头部 + 字符串池」的合法最小形态。
//
// 局限（与实现注释一致）：aapt2/apktool 需要 package 块才会认作完整资源表，
// 这里只保证本项目 arsc.Parse 与「只读全局字符串池」的工具能解析。
func TestDecoyCoreArscIsParsable(t *testing.T) {
	art, _ := decoyCoreRealArtifact(t)
	if err := (&decoyCore{}).Run(context.Background(), art, decoyCoreOpts(4)); err != nil {
		t.Fatalf("A16 执行失败: %v", err)
	}

	checked := 0
	for _, e := range art.Entries() {
		n := e.NameString()
		if !strings.EqualFold(n, arscName) || n == arscName {
			continue
		}
		data, err := e.Data()
		if err != nil {
			t.Fatalf("读取 %s 失败: %v", n, err)
		}
		tbl, err := arsc.Parse(data)
		if err != nil {
			t.Fatalf("%s 不是可解析的最小 arsc: %v", n, err)
		}
		if len(tbl.Strings()) == 0 {
			t.Fatalf("%s 的全局字符串池为空，工具一眼看出是空壳", n)
		}
		checked++
	}
	if checked < 3 {
		t.Fatalf("只生成了 %d 个可解析的假 arsc，覆盖不足", checked)
	}
	t.Logf("已生成 %d 个可解析的假 arsc（ResTable_header + 全局字符串池）", checked)
}

// ---- 硬约束：绝不撞真名、不破坏真文件 ----

// TestDecoyCoreNeverShadowsRealCore 钉住最关键的硬约束。
//
// Android 只按**精确名**读取 AndroidManifest.xml / resources.arsc / classes.dex；
// 一旦注入精确同名条目，系统会读到假文件、应用直接死。这里断言：
//   - 三个精确名各自恰好 1 条（就是我们原来的真文件，没有被复制/覆盖）；
//   - 内容与原始字节逐字节一致（没有被写坏）。
func TestDecoyCoreNeverShadowsRealCore(t *testing.T) {
	art, orig := decoyCoreRealArtifact(t)
	if err := (&decoyCore{}).Run(context.Background(), art, decoyCoreOpts(4)); err != nil {
		t.Fatalf("A16 执行失败: %v", err)
	}

	for name, want := range orig {
		found := 0
		for _, e := range art.Entries() {
			if e.NameString() != name {
				continue
			}
			found++
			got, err := e.Data()
			if err != nil {
				t.Fatalf("读取真核心文件 %s 失败: %v", name, err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("真核心文件 %s 内容被改坏（%d -> %d 字节）", name, len(want), len(got))
			}
		}
		if found != 1 {
			t.Fatalf("精确名 %s 应恰好 1 条，实际 %d 条（注入假核心文件绝不能撞真名）", name, found)
		}
	}
}

// TestDecoyCorePassesManifestCollisionGuard 钉住「所有注入条目都过 manifestCollision」。
//
// 违反该守卫会破坏 v1 签名校验：实测 RustDesk 报
// java.lang.SecurityException: Invalid signature file digest for Manifest main attributes。
func TestDecoyCorePassesManifestCollisionGuard(t *testing.T) {
	art, orig := decoyCoreRealArtifact(t)
	if err := (&decoyCore{}).Run(context.Background(), art, decoyCoreOpts(4)); err != nil {
		t.Fatalf("A16 执行失败: %v", err)
	}

	injected := decoyCoreInjectedNames(art, orig)
	if len(injected) == 0 {
		t.Fatal("没有注入任何条目")
	}
	for _, n := range injected {
		if manifestCollision(n) {
			t.Fatalf("注入条目 %q 撞签名关键文件（会破坏 v1 签名校验）", n)
		}
		if realCoreNames[n] {
			t.Fatalf("注入条目 %q 是精确真核心名（会让系统读到假文件）", n)
		}
	}
	t.Logf("已注入 %d 个条目，全部通过 manifestCollision 守卫且未撞真名", len(injected))
}

// ---- 可复现 ----

// TestDecoyCoreReproducible 钉住「同一 seed 得到同一产物」。
func TestDecoyCoreReproducible(t *testing.T) {
	run := func() []string {
		art, orig := decoyCoreRealArtifact(t)
		if err := (&decoyCore{}).Run(context.Background(), art, decoyCoreOpts(4)); err != nil {
			t.Fatalf("A16 执行失败: %v", err)
		}
		return decoyCoreInjectedNames(art, orig)
	}
	a, b := run(), run()
	if strings.Join(a, "|") != strings.Join(b, "|") {
		t.Fatalf("同一 seed 两次运行的条目名不一致:\n%v\n%v", a, b)
	}
	if len(a) != 12 {
		t.Fatalf("4 组应注入 12 个条目（每组 Manifest/arsc/dex 各一），实际 %d：%v", len(a), a)
	}
	t.Logf("同 seed 可复现，共 %d 个注入条目", len(a))
}

// TestDecoyCoreDefaultCount 校验未指定组数时用默认值（4 组 = 12 个条目）。
func TestDecoyCoreDefaultCount(t *testing.T) {
	art, orig := decoyCoreRealArtifact(t)
	opts := &config.Options{Enabled: map[config.FeatureID]bool{"A16": true}, Seed: "def"}
	if err := (&decoyCore{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A16 执行失败: %v", err)
	}
	injected := decoyCoreInjectedNames(art, orig)
	want := decoyCoreDefaultGroups * 3
	if len(injected) != want {
		t.Fatalf("默认应注入 %d 个条目，实际 %d：%v", want, len(injected), injected)
	}
	// 统计项必须齐备。
	for _, k := range []string{"A16.manifests", "A16.arcs", "A16.dex", "A16.bytes"} {
		if art.Stats[k] == "" {
			t.Fatalf("缺少统计项 %s：%v", k, art.Stats)
		}
	}
	t.Logf("默认 %d 组，统计：%v", decoyCoreDefaultGroups, art.Stats)
}

// TestDecoyCoreDedupesExistingNames 钉住「与既有条目去重」。
//
// A9 也会注入 CLASSES.DEX / Classes.Dex / classes.DEX；A16 必须避开已被占用的名字，
// 否则同一 ZIP 里会出现重名条目（apksigner 会以 Duplicate entry 拒绝整个归档）。
func TestDecoyCoreDedupesExistingNames(t *testing.T) {
	art, orig := decoyCoreRealArtifact(t)
	// 预置 A9 会用的名字，模拟 A9 先执行的场景。
	for _, n := range []string{"CLASSES.DEX", "Classes.Dex", "classes.DEX"} {
		zipxAddStored(art, n, []byte("fake"))
		orig[n] = []byte("fake")
	}
	if err := (&decoyCore{}).Run(context.Background(), art, decoyCoreOpts(4)); err != nil {
		t.Fatalf("A16 执行失败: %v", err)
	}

	seen := map[string]int{}
	for _, e := range art.Entries() {
		seen[e.NameString()]++
	}
	for n, c := range seen {
		if c > 1 {
			t.Fatalf("条目名 %q 出现 %d 次（重名会让 apksigner 拒绝整个归档）", n, c)
		}
	}
	// 假 DEX 仍应注入 4 个（避开 A9 占用的三个名字后改用其它变体/序号名）。
	// 注意兜底名形如 CLASSES_2.dex，不再 EqualFold 于 classes.dex，因此按后缀归类。
	dexCount := 0
	for _, n := range decoyCoreInjectedNames(art, orig) {
		if strings.HasSuffix(strings.ToLower(n), ".dex") && n != "classes.dex" {
			dexCount++
		}
	}
	if dexCount != 4 {
		t.Fatalf("预置 A9 名字后仍应注入 4 个假 DEX，实际 %d", dexCount)
	}
}

// zipxAddStored 是测试内的便捷追加（避免依赖 pipeline.Add 之外的私有辅助）。
func zipxAddStored(art *pipeline.Artifact, name string, data []byte) {
	pipeline.Add(art, zipx.NewStored(name, data))
}
