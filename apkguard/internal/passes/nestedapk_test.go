package passes

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"apkguard/internal/arsc"
	"apkguard/internal/axml"
	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/pipeline"
	"apkguard/internal/zipx"
)

// ---- A17 嵌套 APK 诱饵 ----

// nestedAPKReadEntry 从内层假 APK 中读出指定条目（不存在则 Fatal）。
func nestedAPKReadEntry(t *testing.T, zr *zip.Reader, name string) []byte {
	t.Helper()
	for _, f := range zr.File {
		if f.Name != name {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("打开内层条目 %s 失败: %v", name, err)
		}
		defer rc.Close()
		data, err := io.ReadAll(rc)
		if err != nil {
			t.Fatalf("读取内层条目 %s 失败: %v", name, err)
		}
		return data
	}
	t.Fatalf("假 APK 缺少条目 %s", name)
	return nil
}

// nestedAPKZipNames 返回内层假 APK 的全部条目名（排序）。
func nestedAPKZipNames(zr *zip.Reader) []string {
	out := make([]string, 0, len(zr.File))
	for _, f := range zr.File {
		out = append(out, f.Name)
	}
	sort.Strings(out)
	return out
}

// TestNestedAPKStructure 是 A17 的核心判据：假 APK 必须「像真的」。
//
// 断言：外层新增条目过 manifestCollision、可被 archive/zip 打开、条目齐全、
// 内含的 Manifest 能被 axml.Parse 解析出 manifest/application/activity，
// 三个 DEX 都能被 dex.Parse+dex.Verify 通过，resources.arsc 能被 arsc.Parse
// 接受，且体积达到目标；同时外层既有条目（真载荷/壳 Manifest）内容不变。
func TestNestedAPKStructure(t *testing.T) {
	realDex1 := smallDexWithClass(t, "Lreal/App;")
	realDex2 := smallDexWithClass(t, "Lreal/B;")
	realMF := []byte("REAL-MANIFEST-BYTES")
	realARSC := []byte("REAL-ARSC-BYTES")

	art := newArtifact(
		zipx.NewStored("classes.dex", realDex1),
		zipx.NewStored("classes2.dex", realDex2),
		zipx.NewStored("AndroidManifest.xml", realMF),
		zipx.NewStored("resources.arsc", realARSC),
	)
	opts := &config.Options{Seed: "nested-a17", DecoyAPKMB: 1, DecoyPkg: "com.example.decoy"}
	if err := (&nestedDecoyAPK{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A17 执行失败: %v", err)
	}

	name := art.Stats["A17.name"]
	if name == "" {
		t.Fatalf("未记录 A17.name: %v", art.Stats)
	}
	if manifestCollision(name) {
		t.Fatalf("外层诱饵条目名 %q 撞签名关键文件", name)
	}
	if art.Stats["A17.pkg"] != "com.example.decoy" {
		t.Fatalf("A17.pkg 不符: %q", art.Stats["A17.pkg"])
	}

	entry := pipeline.Find(art, name)
	if entry == nil {
		t.Fatalf("外层诱饵条目 %s 不存在", name)
	}
	blob, err := entry.Data()
	if err != nil {
		t.Fatalf("读取诱饵条目失败: %v", err)
	}
	// 体积必须达到目标（默认关系会撑到 >= 目标）。
	if len(blob) < 1<<20 {
		t.Fatalf("诱饵 APK 体积 %d 未达到 1MB 目标（DecoyAPKMB=1）", len(blob))
	}
	if art.Stats["A17.bytes"] != "" {
		if got := len(blob); got < 1<<20 {
			t.Fatalf("A17.bytes 记录与实际不符")
		}
	}

	// ① 假 APK 自身必须是合法 zip，且条目齐全。
	zr, err := zip.NewReader(bytes.NewReader(blob), int64(len(blob)))
	if err != nil {
		t.Fatalf("假 APK 不是合法 zip（archive/zip 打不开）: %v", err)
	}
	names := nestedAPKZipNames(zr)
	have := map[string]bool{}
	for _, n := range names {
		have[n] = true
	}
	for _, want := range []string{
		"AndroidManifest.xml", "resources.arsc",
		"classes.dex", "classes2.dex", "classes3.dex",
		"META-INF/MANIFEST.MF",
	} {
		if !have[want] {
			t.Fatalf("假 APK 缺少条目 %s（实际条目: %v）", want, names)
		}
	}
	if art.Stats["A17.entries"] != strconv.Itoa(len(names)) {
		t.Fatalf("A17.entries=%s 与实际条目数 %d 不符", art.Stats["A17.entries"], len(names))
	}

	// ② 假 Manifest 必须是可解析的合法 AXML，且结构像真实应用。
	mfBytes := nestedAPKReadEntry(t, zr, "AndroidManifest.xml")
	mf, err := axml.Parse(mfBytes)
	if err != nil {
		t.Fatalf("假 Manifest 无法被 axml.Parse 解析（核心价值失败）: %v", err)
	}
	man := mf.FindElement("manifest")
	if man == nil {
		t.Fatal("假 Manifest 没有 <manifest> 元素")
	}
	if got := man.AttrString("package"); got != "com.example.decoy" {
		t.Fatalf("假 Manifest 包名应为 com.example.decoy，实际 %q", got)
	}
	if mf.FindElement("application") == nil {
		t.Fatal("假 Manifest 没有 <application>")
	}
	activities := 0
	for _, e := range mf.Elements {
		if e.Name == "activity" {
			activities++
		}
	}
	if activities < 2 {
		t.Fatalf("假 Manifest 的 <activity> 数量不足（%d），不像真实应用", activities)
	}

	// ③ 三个 DEX 都必须是能被 dex.Parse 接受的合法 DEX（不是伪 DEX）。
	for _, dn := range []string{"classes.dex", "classes2.dex", "classes3.dex"} {
		d := nestedAPKReadEntry(t, zr, dn)
		f, err := dex.Parse(d)
		if err != nil {
			t.Fatalf("假 APK 的 %s 无法被 dex.Parse 通过: %v", dn, err)
		}
		if err := dex.Verify(d); err != nil {
			t.Fatalf("假 APK 的 %s 校验失败: %v", dn, err)
		}
		n := 0
		f.Classes(func(_ uint32, _ dex.ClassDef, _ string) error { n++; return nil })
		if n == 0 {
			t.Fatalf("假 APK 的 %s 不含任何类，太空壳", dn)
		}
	}

	// ④ resources.arsc 必须能被 arsc.Parse 接受。
	if _, err := arsc.Parse(nestedAPKReadEntry(t, zr, "resources.arsc")); err != nil {
		t.Fatalf("假 resources.arsc 无法被 arsc.Parse 接受: %v", err)
	}

	// ④b 假应用必须「像真的」：App 继承 Application、MainActivity 继承 Activity
	// （与假 Manifest 的声明一致），而不是一眼假的 Object 子类。
	mainDex, err := dex.Parse(nestedAPKReadEntry(t, zr, "classes.dex"))
	if err != nil {
		t.Fatalf("解析假 classes.dex 失败: %v", err)
	}
	infos, err := mainDex.ClassInfos()
	if err != nil {
		t.Fatalf("读取假 classes.dex 类信息失败: %v", err)
	}
	supers := map[string]string{}
	for _, ci := range infos {
		supers[ci.Desc] = ci.Super
	}
	if got := supers["Lcom/example/decoy/App;"]; got != "Landroid/app/Application;" {
		t.Fatalf("假 App 的父类应为 android.app.Application，实际 %q", got)
	}
	if got := supers["Lcom/example/decoy/MainActivity;"]; got != "Landroid/app/Activity;" {
		t.Fatalf("假 MainActivity 的父类应为 android.app.Activity，实际 %q", got)
	}

	// ⑤ 既有真实条目不得被改动。
	checks := map[string][]byte{
		"classes.dex":         realDex1,
		"classes2.dex":        realDex2,
		"AndroidManifest.xml": realMF,
		"resources.arsc":      realARSC,
	}
	for n, want := range checks {
		e := pipeline.Find(art, n)
		if e == nil {
			t.Fatalf("A17 之后既有条目 %s 消失", n)
		}
		got, err := e.Data()
		if err != nil {
			t.Fatalf("读取既有条目 %s 失败: %v", n, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("A17 改动了既有条目 %s 的内容", n)
		}
	}

	// ⑥ 外层不得出现重复条目名（apksigner 会拒绝）。
	seen := map[string]int{}
	for _, e := range art.Entries() {
		seen[e.NameString()]++
	}
	for n, c := range seen {
		if c > 1 {
			t.Fatalf("外层条目 %s 重复 %d 次", n, c)
		}
	}

	t.Logf("A17：%s（%d 字节，%d 条目），假 Manifest 解析出 %d 个 activity，包名 %s",
		name, len(blob), len(names), activities, art.Stats["A17.pkg"])
}

// TestNestedAPKDeterministic 验证同 seed 两次产出的条目名集合与字节完全一致。
func TestNestedAPKDeterministic(t *testing.T) {
	run := func() (string, []string, []byte) {
		art := newArtifact(zipx.NewStored("classes.dex", smallDexWithClass(t, "Lreal/A;")))
		opts := &config.Options{Seed: "fixed-a17", DecoyAPKMB: 1}
		if err := (&nestedDecoyAPK{}).Run(context.Background(), art, opts); err != nil {
			t.Fatalf("A17 执行失败: %v", err)
		}
		name := art.Stats["A17.name"]
		blob, err := pipeline.Find(art, name).Data()
		if err != nil {
			t.Fatal(err)
		}
		zr, err := zip.NewReader(bytes.NewReader(blob), int64(len(blob)))
		if err != nil {
			t.Fatalf("假 APK 不是合法 zip: %v", err)
		}
		return name, nestedAPKZipNames(zr), blob
	}
	n1, s1, b1 := run()
	n2, s2, b2 := run()
	if n1 != n2 {
		t.Fatalf("同 seed 的外层条目名不一致: %q vs %q", n1, n2)
	}
	if !bytes.Equal(b1, b2) {
		t.Fatal("同 seed 的假 APK 字节不一致（存在未受控随机性）")
	}
	if !reflect.DeepEqual(s1, s2) {
		t.Fatalf("同 seed 的条目名集合不一致: %v vs %v", s1, s2)
	}
}

// TestNestedAPKWithContainer 验证 A17 与 B8 同时启用时不冲突、产物仍可解析。
//
// B8 会把真实载荷移进与 A17 相同的目录树；A17 只新增一个同构条目。
// 断言两个诱饵各自存在且不重名、真载荷清单仍可打开、外层归档能被重新解析。
func TestNestedAPKWithContainer(t *testing.T) {
	art := newArtifact(
		zipx.NewStored("classes.dex", smallDexWithClass(t, "Lapp/A;")),
		zipx.NewStored("classes2.dex", smallDexWithClass(t, "Lapp/B;")),
	)
	opts := &config.Options{
		Enabled:    map[config.FeatureID]bool{"B1": true, "B8": true},
		Seed:       "both-a17-b8",
		DecoyAPKMB: 1,
	}
	ctx := context.Background()
	for _, p := range []pipeline.Pass{&encryptDex{}, &payloadContainer{}, &nestedDecoyAPK{}} {
		if err := p.Run(ctx, art, opts); err != nil {
			t.Fatalf("功能项 %s 执行失败: %v", p.ID(), err)
		}
	}

	a17 := art.Stats["A17.name"]
	b8 := art.Stats["B8.decoy"]
	if a17 == "" || b8 == "" {
		t.Fatalf("两个诱饵都应记录：A17=%q B8=%q", a17, b8)
	}
	if a17 == b8 {
		t.Fatalf("A17 与 B8 的诱饵条目名相同（%s），会互相覆盖", a17)
	}
	if manifestCollision(a17) || manifestCollision(b8) {
		t.Fatal("诱饵条目名撞签名关键文件")
	}

	// 两个诱饵都必须能被 archive/zip 打开。
	for _, n := range []string{a17, b8} {
		e := pipeline.Find(art, n)
		if e == nil {
			t.Fatalf("诱饵条目 %s 不存在", n)
		}
		blob, err := e.Data()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := zip.NewReader(bytes.NewReader(blob), int64(len(blob))); err != nil {
			t.Fatalf("诱饵 %s 不是合法 zip: %v", n, err)
		}
	}

	// 真实载荷清单仍指向存在的条目（B3 会内联这些名字，清单坏了应用启动即崩）。
	sp := payloadsOf(art)
	if sp == nil || len(sp.Items) == 0 {
		t.Fatal("B1 载荷清单丢失")
	}
	for _, it := range sp.Items {
		if pipeline.Find(art, it.Asset) == nil {
			t.Fatalf("A17 介入后真载荷条目 %s 不存在", it.Asset)
		}
		if !strings.HasPrefix(it.Asset, "assets/") {
			t.Fatalf("真载荷路径应以 assets/ 开头: %s", it.Asset)
		}
	}
	// A17 的假 APK 与真载荷同目录树，但不得覆盖它们。
	if pipeline.Find(art, a17).NameString() == "" {
		t.Fatal("A17 条目丢失")
	}

	// 外层不得重名，序列化后仍可被两种解析器读取。
	seen := map[string]int{}
	for _, e := range art.Entries() {
		seen[e.NameString()]++
	}
	for n, c := range seen {
		if c > 1 {
			t.Fatalf("外层条目 %s 重复 %d 次（apksigner 会拒绝）", n, c)
		}
	}
	out := pipeline.Bytes(art)
	if _, err := zipx.Read(out); err != nil {
		t.Fatalf("A17+B8 产物无法被 zipx.Read 解析: %v", err)
	}
	if _, err := zip.NewReader(bytes.NewReader(out), int64(len(out))); err != nil {
		t.Fatalf("A17+B8 产物无法被 archive/zip 解析: %v", err)
	}
	t.Logf("A17+B8 共存：A17=%s B8=%s，真载荷 %d 份完好", a17, b8, len(sp.Items))
}
