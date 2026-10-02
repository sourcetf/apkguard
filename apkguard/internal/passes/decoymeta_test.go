package passes

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"testing"

	"apkguard/internal/axml"
	"apkguard/internal/config"
	"apkguard/internal/pipeline"
)

// ---- A18 Manifest 诱饵元数据 ----

// TestDecoyMetaInjection 钉住 A18 的四类注入、既有元素不被改动，以及三条
// 「安全约束」——这三条是本 Pass 最有价值的部分，必须机器化断言。
func TestDecoyMetaInjection(t *testing.T) {
	art := loadSample(t)
	entry := pipeline.Find(art, "AndroidManifest.xml")
	if entry == nil {
		t.Skip("样本没有 AndroidManifest.xml")
	}

	// ---- 改写前快照 ----
	beforeData, err := entry.Data()
	if err != nil {
		t.Fatalf("读取 Manifest 失败: %v", err)
	}
	before, err := axml.Parse(beforeData)
	if err != nil {
		t.Fatalf("样本 Manifest 无法解析: %v", err)
	}
	beforeSigs := manifestSigs(before)
	beforeCount := countElems(before)
	beforePerm := elemNames(before, "uses-permission")
	beforeFeat := elemNames(before, "uses-feature")
	beforePkg := elemNames(before, "package")

	rootBefore := before.FindElement("manifest")
	if rootBefore == nil {
		t.Fatal("样本 Manifest 没有 <manifest>")
	}
	pkgBefore := rootBefore.AttrString("package")
	appBefore := ""
	if app := before.FindElement("application"); app != nil {
		appBefore = app.AttrString("name")
	}
	var minSdkBefore, targetSdkBefore string
	if us := before.FindElement("uses-sdk"); us != nil {
		minSdkBefore = us.AttrString("minSdkVersion")
		targetSdkBefore = us.AttrString("targetSdkVersion")
	}

	// ---- 执行 A18 ----
	opts := &config.Options{
		Enabled:        map[config.FeatureID]bool{"A18": true},
		Seed:           "decoy-meta-seed",
		ShellPkg:       "com.apkguard.shell",
		DecoyMetaCount: 30,
	}
	if err := (&decoyMeta{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A18 执行失败: %v", err)
	}

	// ---- 改写后：必须仍可解析 ----
	afterData, err := entry.Data()
	if err != nil {
		t.Fatalf("读取产物 Manifest 失败: %v", err)
	}
	after, err := axml.Parse(afterData)
	if err != nil {
		t.Fatalf("A18 写回后 Manifest 无法解析（写坏会让应用启动即死）: %v", err)
	}
	afterCount := countElems(after)

	// ---- 1) 注入数量与统计一致 ----
	wantPerm := statInt(t, art, "A18.perms")
	wantMeta := statInt(t, art, "A18.meta")
	wantFeat := statInt(t, art, "A18.features")
	wantQuery := statInt(t, art, "A18.queries")
	if wantPerm+wantMeta+wantFeat+wantQuery == 0 {
		t.Fatal("A18 未注入任何内容")
	}
	checkDelta := func(name string, want int) {
		t.Helper()
		if got := afterCount[name] - beforeCount[name]; got != want {
			t.Fatalf("<%s> 新增数量不符：实际 %d，统计 %d", name, got, want)
		}
	}
	checkDelta("uses-permission", wantPerm)
	checkDelta("meta-data", wantMeta)
	checkDelta("uses-feature", wantFeat)
	checkDelta("package", wantQuery) // <queries> 的 <package> 子元素
	if beforeCount["queries"] == 0 && afterCount["queries"] != 1 {
		t.Fatalf("样本原本没有 <queries>，A18 应恰好补一个容器，实际 %d", afterCount["queries"])
	}
	t.Logf("A18 注入：权限 %d、meta-data %d、特性 %d、queries 包名 %d",
		wantPerm, wantMeta, wantFeat, wantQuery)

	// ---- 2) 既有元素一个都不能被改动 ----
	afterSet := map[string]bool{}
	for _, s := range manifestSigs(after) {
		afterSet[s] = true
	}
	for _, s := range beforeSigs {
		if !afterSet[s] {
			t.Fatalf("A18 改动了既有元素（应只追加）: %s", s)
		}
	}
	if got := after.FindElement("manifest").AttrString("package"); got != pkgBefore {
		t.Fatalf("manifest package 被改动: %q -> %q", pkgBefore, got)
	}
	appAfter := ""
	if app := after.FindElement("application"); app != nil {
		appAfter = app.AttrString("name")
	}
	if appAfter != appBefore {
		t.Fatalf("application android:name 被改动: %q -> %q", appBefore, appAfter)
	}
	if us := after.FindElement("uses-sdk"); us != nil {
		if us.AttrString("minSdkVersion") != minSdkBefore || us.AttrString("targetSdkVersion") != targetSdkBefore {
			t.Fatalf("uses-sdk 被改动: min/target %q/%q -> %q/%q",
				minSdkBefore, targetSdkBefore, us.AttrString("minSdkVersion"), us.AttrString("targetSdkVersion"))
		}
	}

	// ---- 3) 安全约束（最有价值的一组） ----

	// 3a) 注入的 uses-permission 不得是系统权限。
	injectedPerm := 0
	for _, e := range after.Elements {
		if e.Name != "uses-permission" {
			continue
		}
		name := e.AttrString("name")
		if beforePerm[name] {
			continue // 既有声明（可能是真实系统权限），不归 A18 管
		}
		injectedPerm++
		if strings.HasPrefix(name, "android.permission.") {
			t.Fatalf("A18 注入了系统权限 %q（会触发授权、改变运行时行为）", name)
		}
		if !strings.Contains(name, ".permission.") || !strings.HasPrefix(name, "com.") {
			t.Fatalf("A18 注入的自定义权限名形态不符: %q", name)
		}
	}
	if injectedPerm != wantPerm {
		t.Fatalf("按名字统计的注入权限数 %d 与统计 %d 不符", injectedPerm, wantPerm)
	}

	// 3b) 注入的 uses-feature 的 android:required 必须为 false。
	injectedFeat := 0
	for _, e := range after.Elements {
		if e.Name != "uses-feature" {
			continue
		}
		name := e.AttrString("name")
		if beforeFeat[name] {
			continue
		}
		injectedFeat++
		req := e.AttrNS(axml.AndroidNS, "required")
		if req == nil {
			t.Fatalf("A18 注入的 uses-feature %q 缺少 android:required（不能省略成默认 true）", name)
		}
		isFalse := (req.DataType == axml.TypeIntBoolean && req.Data == 0) || req.RawValue == "false"
		if !isFalse {
			t.Fatalf("A18 注入的 uses-feature %q 的 required 必须为 false，实际 type=0x%02x data=%d raw=%q",
				name, req.DataType, req.Data, req.RawValue)
		}
	}
	if injectedFeat != wantFeat {
		t.Fatalf("按名字统计的注入特性数 %d 与统计 %d 不符", injectedFeat, wantFeat)
	}

	// 3c) 注入的 <queries>/<package> 不得是固件已知的应用包名。
	known := map[string]bool{"com.agtest": true, pkgBefore: true}
	injectedPkg := 0
	for _, e := range after.Elements {
		if e.Name != "package" {
			continue
		}
		name := e.AttrString("name")
		if beforePkg[name] {
			continue
		}
		injectedPkg++
		if name == "" {
			t.Fatal("A18 注入的 <package> 缺少 android:name")
		}
		if known[name] {
			t.Fatalf("A18 的 <queries> 注入了固件已知应用包名 %q（会真的影响包可见性）", name)
		}
	}
	if injectedPkg != wantQuery {
		t.Fatalf("按名字统计的注入包名数 %d 与统计 %d 不符", injectedPkg, wantQuery)
	}
}

// TestDecoyMetaDefaultCount 钉住未指定 DecoyMetaCount 时使用默认总量。
func TestDecoyMetaDefaultCount(t *testing.T) {
	art := loadSample(t)
	if pipeline.Find(art, "AndroidManifest.xml") == nil {
		t.Skip("样本没有 AndroidManifest.xml")
	}
	opts := &config.Options{
		Enabled:  map[config.FeatureID]bool{"A18": true},
		Seed:     "default-count",
		ShellPkg: "com.apkguard.shell",
	}
	if err := (&decoyMeta{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A18 执行失败: %v", err)
	}
	total := statInt(t, art, "A18.perms") + statInt(t, art, "A18.meta") +
		statInt(t, art, "A18.features") + statInt(t, art, "A18.queries")
	if total != defaultDecoyMetaCount {
		t.Fatalf("默认总量应为 %d，实际 %d", defaultDecoyMetaCount, total)
	}
}

// TestA18Reproducible 同 seed 两次注入的权限名集合必须一致。
func TestA18Reproducible(t *testing.T) {
	permNames := func() []string {
		art := loadSample(t)
		if pipeline.Find(art, "AndroidManifest.xml") == nil {
			t.Skip("样本没有 AndroidManifest.xml")
		}
		opts := &config.Options{
			Enabled:        map[config.FeatureID]bool{"A18": true},
			Seed:           "repro-seed",
			ShellPkg:       "com.apkguard.shell",
			DecoyMetaCount: 30,
		}
		if err := (&decoyMeta{}).Run(context.Background(), art, opts); err != nil {
			t.Fatalf("A18 执行失败: %v", err)
		}
		data, err := pipeline.Find(art, "AndroidManifest.xml").Data()
		if err != nil {
			t.Fatalf("读取 Manifest 失败: %v", err)
		}
		mf, err := axml.Parse(data)
		if err != nil {
			t.Fatalf("解析 Manifest 失败: %v", err)
		}
		var out []string
		for _, e := range mf.Elements {
			if e.Name == "uses-permission" {
				out = append(out, e.AttrString("name"))
			}
		}
		sort.Strings(out)
		return out
	}

	a := permNames()
	b := permNames()
	if len(a) == 0 {
		t.Fatal("A18 未注入任何权限")
	}
	if strings.Join(a, ",") != strings.Join(b, ",") {
		t.Fatalf("同 seed 两次注入的权限集合不一致：\n%v\n%v", a, b)
	}
}

// TestA18CoexistWithA8 先跑 A8 再跑 A18，最终 Manifest 必须同时含有 A8 的
// 诱饵组件与 A18 的诱饵元数据，且仍可解析（两者都写 Manifest，顺序敏感）。
func TestA18CoexistWithA8(t *testing.T) {
	art := loadSample(t)
	if pipeline.Find(art, "AndroidManifest.xml") == nil {
		t.Skip("样本没有 AndroidManifest.xml")
	}
	if pipeline.FindAll(art, isDexEntry) == nil {
		t.Skip("样本没有 DEX")
	}

	opts := &config.Options{
		Enabled:        map[config.FeatureID]bool{"A8": true, "A18": true},
		Seed:           "coexist-seed",
		ShellPkg:       "com.apkguard.shell",
		DecoyMetaCount: 20,
	}
	if err := (&decoyClass{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A8 执行失败: %v", err)
	}
	if err := (&decoyMeta{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A18 执行失败: %v", err)
	}

	data, err := pipeline.Find(art, "AndroidManifest.xml").Data()
	if err != nil {
		t.Fatalf("读取 Manifest 失败: %v", err)
	}
	mf, err := axml.Parse(data)
	if err != nil {
		t.Fatalf("A8+A18 之后 Manifest 无法解析: %v", err)
	}

	comps, customPerms, metas := 0, 0, 0
	for _, e := range mf.Elements {
		switch e.Name {
		case "receiver", "service":
			if strings.HasPrefix(e.AttrString("name"), "com.apkguard.shell.") {
				comps++
			}
		case "uses-permission":
			if !strings.HasPrefix(e.AttrString("name"), "android.permission.") {
				customPerms++
			}
		case "meta-data":
			metas++
		}
	}
	if comps == 0 {
		t.Fatal("A18 之后 A8 的诱饵组件消失了")
	}
	if customPerms == 0 || metas == 0 {
		t.Fatalf("A18 的诱饵元数据缺失：自定义权限 %d、meta-data %d", customPerms, metas)
	}
	t.Logf("A8+A18 共存：诱饵组件 %d、自定义权限 %d、meta-data %d", comps, customPerms, metas)
}

// ---- 测试辅助 ----

// manifestSigs 把 Manifest 里每个元素的「名字 + 全部属性」编码成可比较的字符串，
// 用于断言 A18 只追加、不改动既有元素（含布尔属性的 ns/name/取值）。
func manifestSigs(f *axml.File) []string {
	out := make([]string, 0, len(f.Elements))
	for _, e := range f.Elements {
		var b strings.Builder
		b.WriteString(e.Name)
		for _, a := range e.Attrs {
			b.WriteString("|")
			if a.NSName != "" {
				b.WriteString(a.NSName)
				b.WriteString(":")
			}
			b.WriteString(a.Name)
			b.WriteString("=")
			if a.DataType == axml.TypeIntBoolean {
				b.WriteString(strconv.FormatUint(uint64(a.Data), 10))
			} else {
				b.WriteString(a.RawValue)
			}
		}
		out = append(out, b.String())
	}
	return out
}

// countElems 统计每种元素名的出现次数。
func countElems(f *axml.File) map[string]int {
	out := map[string]int{}
	for _, e := range f.Elements {
		out[e.Name]++
	}
	return out
}

// elemNames 返回某元素名上 android:name 的集合（用于区分既有声明与注入项）。
func elemNames(f *axml.File, elem string) map[string]bool {
	out := map[string]bool{}
	for _, e := range f.Elements {
		if e.Name == elem {
			out[e.AttrString("name")] = true
		}
	}
	return out
}

// statInt 读取并解析一个统计项。
func statInt(t *testing.T, art *pipeline.Artifact, key string) int {
	t.Helper()
	v, ok := art.Stats[key]
	if !ok {
		t.Fatalf("缺少统计项 %s（现有：%v）", key, art.Stats)
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		t.Fatalf("统计项 %s 不是整数: %q", key, v)
	}
	return n
}
