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

// TestDecoyMetaDefaultCount 钉住未指定 DecoyMetaCount 时四类「通用」注入
// 仍按默认总量拆分；样本风格的额外 meta-data（水印/同名不同值/com.x.y）
// 不计入 DecoyMetaCount，但必须出现在统计里。
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
	// 通用部分 = meta-data 总量减去三组样本风格附加项。
	genericMeta := statInt(t, art, "A18.meta") - statInt(t, art, "A18.mark") -
		statInt(t, art, "A18.dupes") - statInt(t, art, "A18.commeta")
	total := statInt(t, art, "A18.perms") + genericMeta +
		statInt(t, art, "A18.features") + statInt(t, art, "A18.queries")
	if total != defaultDecoyMetaCount {
		t.Fatalf("通用注入总量应为 %d，实际 %d（meta 总量 %d，附加 %d）",
			defaultDecoyMetaCount, total, statInt(t, art, "A18.meta"),
			statInt(t, art, "A18.mark")+statInt(t, art, "A18.dupes")+statInt(t, art, "A18.commeta"))
	}
	if m := statInt(t, art, "A18.mark"); m < 12 || m > 16 {
		t.Fatalf("构建水印应为 12~16 条，实际 %d", m)
	}
	if d := statInt(t, art, "A18.dupes"); d != 8 {
		t.Fatalf("同名不同值应为四组 8 条，实际 %d", d)
	}
	if c := statInt(t, art, "A18.commeta"); c != 9 {
		t.Fatalf("com.<随机>.<随机> 应为 9 条，实际 %d", c)
	}
}

// TestA18Reproducible 同 seed 两次注入的权限名与全部 meta-data 签名必须一致。
//
// 覆盖新增的水印值、同名不同值的两组值以及 int 型 seq_mark 的取值：
// 这些都由 seed + opts.UnifiedStamp() 派生，绝不允许引入 time.Now() 一类
// 不可复现的输入。
func TestA18Reproducible(t *testing.T) {
	sig := func() string {
		art := loadSample(t)
		if pipeline.Find(art, "AndroidManifest.xml") == nil {
			t.Skip("样本没有 AndroidManifest.xml")
		}
		opts := &config.Options{
			Enabled:        map[config.FeatureID]bool{"A18": true},
			Seed:           "repro-seed",
			ShellPkg:       "com.apkguard.shell",
			DecoyMetaCount: 30,
			StampTime:      "2026-09-19T22:01:02Z",
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
		var perms []string
		for _, e := range mf.Elements {
			if e.Name == "uses-permission" {
				perms = append(perms, e.AttrString("name"))
			}
		}
		sort.Strings(perms)
		if len(perms) == 0 {
			t.Fatal("A18 未注入任何权限")
		}
		metas := manifestMetaSig(t, mf)
		if len(metas) == 0 {
			t.Fatal("A18 未注入任何 meta-data")
		}
		return strings.Join(perms, ",") + "\n" + strings.Join(metas, "\n")
	}

	a := sig()
	b := sig()
	if a != b {
		t.Fatalf("同 seed 两次注入不一致：\n%s\n---\n%s", a, b)
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
		DecoyMetaCount: 20,
	}
	if err := (&decoyClass{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A8 执行失败: %v", err)
	}
	theme := decoyThemeOf(opts) // A8 的主题包由同 seed 派生
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
		case "activity", "receiver", "service":
			if strings.HasPrefix(e.AttrString("name"), theme.pkg+".") {
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
	if want := decoyFamilyCount * decoyDeclarePerFam; comps != want {
		t.Fatalf("A18 之后 A8 的诱饵组件应仍有 %d 个，实际 %d", want, comps)
	}
	if customPerms == 0 || metas < 20 {
		t.Fatalf("A18 的诱饵元数据缺失：自定义权限 %d、meta-data %d", customPerms, metas)
	}
	t.Logf("A8+A18 共存：主题包 %s，诱饵组件 %d、自定义权限 %d、meta-data %d",
		theme.pkg, comps, customPerms, metas)
}

// TestDecoyMetaSampleSignatures 钉住 A18 复刻参考样本的三组标志性噪音：
// 构建水印、同名不同值四组、com.<随机>.<随机>。其中最关键的断言是
// seq_mark 的类型：必须用 axml.Parse 回读出 Res_value.dataType == 0x10
// （TYPE_INT_DEC），而不是普通字符串——这是样本里最难伪装的细节。
func TestDecoyMetaSampleSignatures(t *testing.T) {
	art := loadSample(t)
	entry := pipeline.Find(art, "AndroidManifest.xml")
	if entry == nil {
		t.Skip("样本没有 AndroidManifest.xml")
	}
	beforeData, err := entry.Data()
	if err != nil {
		t.Fatalf("读取 Manifest 失败: %v", err)
	}
	before, err := axml.Parse(beforeData)
	if err != nil {
		t.Fatalf("样本 Manifest 无法解析: %v", err)
	}
	beforeMeta := elemNames(before, "meta-data")

	opts := &config.Options{
		Enabled:        map[config.FeatureID]bool{"A18": true},
		Seed:           "sample-signature",
		DecoyMetaCount: 30,
		// 固定时间戳：水印与 compile_ms 都必须确定性派生。
		StampTime: "2026-09-19T22:01:02Z",
	}
	if err := (&decoyMeta{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A18 执行失败: %v", err)
	}
	afterData, err := entry.Data()
	if err != nil {
		t.Fatalf("读取产物 Manifest 失败: %v", err)
	}
	after, err := axml.Parse(afterData)
	if err != nil {
		t.Fatalf("A18 写回后 Manifest 无法解析: %v", err)
	}
	stamp, err := opts.UnifiedStamp()
	if err != nil {
		t.Fatalf("统一时间戳非法: %v", err)
	}

	// 收集「注入的」meta-data：名字不在原 Manifest 里的那些。
	vals := map[string][]*axml.Attr{}
	var names []string
	for _, e := range after.Elements {
		if e.Name != "meta-data" {
			continue
		}
		n := e.AttrString("name")
		if beforeMeta[n] {
			continue
		}
		v := e.AttrNS(axml.AndroidNS, "value")
		if v == nil {
			t.Fatalf("注入的 meta-data %q 缺少 android:value", n)
		}
		vals[n] = append(vals[n], v)
		names = append(names, n)
	}

	// ① 构建水印：cfg_mark_<UTC 时间戳>_<序号>_<随机串>，时间戳来源是
	//    opts.UnifiedStamp()，条数与 A18.mark 统计一致（12~16）。
	markPrefix := "cfg_mark_" + stamp.UTC().Format("20060102150405") + "_"
	marks := 0
	for _, n := range names {
		if strings.HasPrefix(n, markPrefix) {
			marks++
		}
	}
	if want := statInt(t, art, "A18.mark"); marks != want || want < 12 || want > 16 {
		t.Fatalf("构建水印条数不符：实际 %d，统计 %d（应为 12~16）", marks, want)
	}
	for n, vs := range vals {
		if !strings.HasPrefix(n, markPrefix) {
			continue
		}
		if len(vs) != 1 || vs[0].DataType != axml.TypeString || vs[0].RawValue == "" {
			t.Fatalf("水印 %s 的值应为非空随机串", n)
		}
	}

	// ② 同名不同值四组。
	pair := func(name string) []*axml.Attr {
		t.Helper()
		vs := vals[name]
		if len(vs) != 2 {
			t.Fatalf("%s 应恰好注入 2 条同名不同值，实际 %d", name, len(vs))
		}
		return vs
	}
	nonce := pair("cfg_nonce")
	if nonce[0].DataType != axml.TypeString || nonce[0].RawValue == "" || nonce[0].RawValue == nonce[1].RawValue {
		t.Fatalf("cfg_nonce 应为两个不同的非空字符串: %q / %q", nonce[0].RawValue, nonce[1].RawValue)
	}
	lane := pair("build_lane")
	for _, v := range lane {
		if !strings.HasPrefix(v.RawValue, "lane_") {
			t.Fatalf("build_lane 的形态应为 lane_XXXXXXXX，实际 %q", v.RawValue)
		}
	}
	if lane[0].RawValue == lane[1].RawValue {
		t.Fatalf("build_lane 两个值不得相同: %q", lane[0].RawValue)
	}
	seq := pair("seq_mark")
	for _, v := range seq {
		if v.DataType != axml.TypeIntDec {
			t.Fatalf("seq_mark 的 AXML 类型必须是 TYPE_INT_DEC(0x%02x)，实际 0x%02x（rawValue=%q）",
				axml.TypeIntDec, v.DataType, v.RawValue)
		}
	}
	if seq[0].Data == seq[1].Data {
		t.Fatalf("seq_mark 两个 int 值不得相同: %d", seq[0].Data)
	}
	ms := pair("compile_ms")
	var msVals []int64
	for _, v := range ms {
		if v.DataType != axml.TypeString {
			t.Fatalf("compile_ms 应为字符串形式的毫秒时间戳（type=0x%02x）", v.DataType)
		}
		n, perr := strconv.ParseInt(v.RawValue, 10, 64)
		if perr != nil {
			t.Fatalf("compile_ms 不是十进制毫秒时间戳: %q", v.RawValue)
		}
		msVals = append(msVals, n)
	}
	if msVals[0] == msVals[1] {
		t.Fatalf("compile_ms 两个值不得相同: %d", msVals[0])
	}
	base := stamp.UnixMilli()
	for _, v := range msVals {
		if d := v - base; d < -60_000 || d > 60_000 {
			t.Fatalf("compile_ms %d 与统一时间戳 %d 偏差 %dms（应在 ±60s 内）", v, base, d)
		}
	}

	// ③ com.<随机>.<随机>：恰好 9 条，值为 28~50 字符。
	coms := 0
	for n, vs := range vals {
		seg := strings.Split(strings.TrimPrefix(n, "com."), ".")
		if !strings.HasPrefix(n, "com.") || len(seg) != 2 {
			continue
		}
		coms++
		if got := len(vs[0].RawValue); got < 28 || got > 50 {
			t.Fatalf("%s 的值长度应为 28~50，实际 %d", n, got)
		}
	}
	if want := statInt(t, art, "A18.commeta"); coms != want || want != 9 {
		t.Fatalf("com.<随机>.<随机> 应为 9 条，实际 %d（统计 %d）", coms, want)
	}

	// ④ 三组附加名字（水印/同名不同值/com.x.y）不得命中保留的 SDK 关键键。
	//    通用键清单（如 com.umeng.message.appkey）是刻意设计的近似键，走
	//    decoyMetaKeys 自己的评审规则，不在这里重复断言。
	isRandomCom := func(n string) bool {
		return strings.HasPrefix(n, "com.") &&
			len(strings.Split(strings.TrimPrefix(n, "com."), ".")) == 2
	}
	extraNames := 0
	for _, n := range names {
		isExtra := strings.HasPrefix(n, markPrefix) || n == "cfg_nonce" ||
			n == "build_lane" || n == "seq_mark" || n == "compile_ms" || isRandomCom(n)
		if !isExtra {
			continue
		}
		extraNames++
		if metaKeyReserved(n) {
			t.Fatalf("A18 注入了保留 meta-data 键 %q", n)
		}
	}
	if extraNames == 0 {
		t.Fatal("没有发现任何样本风格附加 meta-data")
	}
	t.Logf("样本签名：水印 %d 条（%s…）、同名不同值 4 组、com.x.y 9 条；seq_mark int 回读 type=0x%02x",
		marks, markPrefix, axml.TypeIntDec)
}

// ---- 测试辅助 ----

// manifestMetaSig 返回 Manifest 里全部 meta-data 的 (name|type|value) 签名
// （排序），用于断言可复现性：int 型（如 seq_mark）按数值、字符串按原文，
// 因此水印随机值、同名不同值的两个值都会被覆盖。
func manifestMetaSig(t *testing.T, f *axml.File) []string {
	t.Helper()
	out := make([]string, 0, len(f.Elements))
	for _, e := range f.Elements {
		if e.Name != "meta-data" {
			continue
		}
		v := e.AttrNS(axml.AndroidNS, "value")
		if v == nil {
			continue
		}
		val := v.RawValue
		if v.DataType != axml.TypeString {
			val = strconv.FormatUint(uint64(v.Data), 10)
		}
		out = append(out, e.AttrString("name")+"|"+strconv.Itoa(int(v.DataType))+"|"+val)
	}
	sort.Strings(out)
	return out
}

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
