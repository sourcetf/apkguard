package passes

import (
	"context"
	"strings"
	"testing"

	"apkguard/internal/axml"
	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/pipeline"
)

// containsProductName 报告字符串里是否出现产品名 apkguard（大小写不敏感）。
// A8 的命名必须完全由 seed 派生，产物任何可见面都不得再写死产品名。
func containsProductName(s string) bool {
	return strings.Contains(strings.ToLower(s), "apkguard")
}

// themeSig 把命名方案编码成可比较的字符串（可复现性断言用）。
func themeSig(th decoyTheme) string {
	var b strings.Builder
	b.WriteString(th.pkg)
	for _, f := range th.families {
		b.WriteString("|" + f.prefix + ":" + f.kind)
		for _, n := range f.names {
			b.WriteString("," + n)
		}
	}
	return b.String()
}

// TestDecoyComponentsDeclaredInManifest 钉住 A8 把诱饵类真的声明成 Manifest 组件。
//
// 只注入类是不够的：静态分析者扫一遍组件表就能看出「没有任何安全相关组件」，
// 于是立刻判定诱饵是填充物。把它们真的声明成 <activity>/<receiver>/<service>，
// 这些名字才会出现在组件表、权限视图与导出组件清单里。
//
// 同时钉住三条约束：
//   - 声明必须指向**实际存在的类**，且这些类继承正确的框架基类（否则万一被
//     实例化就是 ClassCastException / 找不到类）；
//   - 三类形态各至少一个，与样本的三名族一一对应；
//   - 绝不声明 provider（ContentProvider 会在应用启动时被 ActivityThread
//     主动实例化），且 enabled/exported 全为 false（样本同款，零运行影响）。
func TestDecoyComponentsDeclaredInManifest(t *testing.T) {
	art := loadSample(t)
	if pipeline.Find(art, "AndroidManifest.xml") == nil {
		t.Skip("样本没有 AndroidManifest.xml")
	}
	if pipeline.FindAll(art, isDexEntry) == nil {
		t.Skip("样本没有 DEX")
	}

	opts := &config.Options{
		Enabled: map[config.FeatureID]bool{"A8": true},
		Seed:    "decoy",
		// 故意传入旧的产品包名：A8 必须忽略它，主题包只由 seed 决定。
		ShellPkg: "com.apkguard.shell",
	}
	if err := (&decoyClass{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A8 执行失败: %v", err)
	}
	theme := decoyThemeOf(opts) // 同 seed 派生，与 Pass 内部一致

	// ---- 1) Manifest 里出现了声明 ----
	mfData, err := pipeline.Find(art, "AndroidManifest.xml").Data()
	if err != nil {
		t.Fatalf("读取 Manifest 失败: %v", err)
	}
	mf, err := axml.Parse(mfData)
	if err != nil {
		t.Fatalf("产物 Manifest 无法解析（写坏了会启动即死）: %v", err)
	}
	if mf.FindElement("application") == nil {
		t.Fatal("Manifest 中没有 <application>")
	}
	var declared []axml.Element
	for _, e := range mf.Elements {
		name := e.AttrString("name")
		switch e.Name {
		case "activity", "receiver", "service":
			if strings.HasPrefix(name, theme.pkg+".") {
				declared = append(declared, *e)
			}
		case "provider":
			if strings.HasPrefix(name, theme.pkg+".") {
				t.Fatalf("A8 不得把诱饵声明成 provider（会在启动时被实例化）: %s", name)
			}
		}
	}
	if len(declared) == 0 {
		t.Fatal("Manifest 里没有任何诱饵组件声明")
	}
	if want := decoyFamilyCount * decoyDeclarePerFam; len(declared) != want {
		t.Fatalf("应声明 %d 个诱饵组件（3 族 × %d），实际 %d", want, decoyDeclarePerFam, len(declared))
	}
	// 三类形态各至少一条，与 activity/receiver/service 三名族一一对应。
	kinds := map[string]int{}
	for _, e := range declared {
		kinds[e.Name]++
	}
	for _, k := range []string{"activity", "receiver", "service"} {
		if kinds[k] == 0 {
			t.Fatalf("缺少 <%s> 形态的诱饵声明（三类必须各一组）：%v", k, kinds)
		}
	}
	// 每个声明必须 exported=false 且 enabled=false（显式布尔，targetSdk 31+ 要求）。
	for _, e := range declared {
		for _, attr := range []string{"exported", "enabled"} {
			a := e.AttrNS(axml.AndroidNS, attr)
			if a == nil {
				t.Fatalf("<%s %s> 缺少 android:%s", e.Name, e.AttrString("name"), attr)
			}
			if a.DataType != axml.TypeIntBoolean || a.Data != 0 {
				t.Fatalf("<%s %s> 的 %s 应为布尔 false", e.Name, e.AttrString("name"), attr)
			}
		}
	}

	// ---- 2) 声明的类必须真的存在，且继承正确的框架基类 ----
	var dexData []byte
	for _, e := range pipeline.FindAll(art, isDexEntry) {
		if d, derr := e.Data(); derr == nil {
			if _, perr := dex.Parse(d); perr == nil {
				dexData = d
				break
			}
		}
	}
	if dexData == nil {
		t.Fatal("产物里没有可解析的 DEX")
	}
	f, err := dex.Parse(dexData)
	if err != nil {
		t.Fatalf("解析产物 DEX 失败: %v", err)
	}
	supers := map[string]string{}
	if err := f.Classes(func(_ uint32, cd dex.ClassDef, name string) error {
		s, serr := f.Type(cd.SuperIdx)
		if serr != nil {
			return serr
		}
		supers[name] = s
		return nil
	}); err != nil {
		t.Fatalf("遍历类失败: %v", err)
	}

	wantBase := map[string]string{
		"activity": "Landroid/app/Activity;",
		"receiver": "Landroid/content/BroadcastReceiver;",
		"service":  "Landroid/app/Service;",
	}
	for _, e := range declared {
		desc := "L" + strings.ReplaceAll(e.AttrString("name"), ".", "/") + ";"
		got, ok := supers[desc]
		if !ok {
			t.Fatalf("Manifest 声明了组件 %s，但产物 DEX 里没有这个类", e.AttrString("name"))
		}
		if got != wantBase[e.Name] {
			t.Fatalf("%s 的父类应为 %s，实际 %s", e.AttrString("name"), wantBase[e.Name], got)
		}
	}
	t.Logf("A8 主题包 %s，声明了 %d 个诱饵组件：%v", theme.pkg, len(declared), compNamesFromElems(declared))
}

// TestDecoyThemeFamiliesAndReproducibility 钉住 A8 的命名契约：
//   - 三个名族，每族 ≥ 3 个类、族内共享前缀、名字全局唯一；
//   - 主题包是两段小写名词组合，不含任何产品名；
//   - 同 seed 完全可复现，不同 seed 得到不同命名方案。
func TestDecoyThemeFamiliesAndReproducibility(t *testing.T) {
	opts := &config.Options{Seed: "family-seed"}
	th := decoyThemeOf(opts)
	if len(th.families) != decoyFamilyCount {
		t.Fatalf("应有 %d 个名族，实际 %d", decoyFamilyCount, len(th.families))
	}
	parts := strings.Split(th.pkg, ".")
	if len(parts) != 2 {
		t.Fatalf("主题包应为两段式（形如 vault.monitor），实际 %q", th.pkg)
	}
	for _, p := range parts {
		if p != strings.ToLower(p) || p == "" {
			t.Fatalf("主题包段应为非空小写词: %q", th.pkg)
		}
		if containsProductName(p) {
			t.Fatalf("主题包不得含产品名: %q", th.pkg)
		}
	}

	seen := map[string]bool{}
	for _, fam := range th.families {
		if len(fam.names) < 3 {
			t.Fatalf("名族 %s 只有 %d 个类（要求 ≥ 3）", fam.prefix, len(fam.names))
		}
		if fam.kind != "activity" && fam.kind != "receiver" && fam.kind != "service" {
			t.Fatalf("名族 %s 的组件形态非法: %q", fam.prefix, fam.kind)
		}
		for _, n := range fam.names {
			if !strings.HasPrefix(n, fam.prefix) {
				t.Fatalf("类名 %s 不是族前缀 %s + 名词", n, fam.prefix)
			}
			rest := strings.TrimPrefix(n, fam.prefix)
			nounsOK := false
			for _, noun := range decoyNouns {
				if rest == noun {
					nounsOK = true
					break
				}
			}
			if !nounsOK {
				t.Fatalf("类名 %s 的名词部分 %q 不在词表内", n, rest)
			}
			if seen[n] {
				t.Fatalf("类名 %s 全局重复", n)
			}
			seen[n] = true
			if containsProductName(n) {
				t.Fatalf("类名不得含产品名: %s", n)
			}
		}
	}

	if got := decoyThemeOf(&config.Options{Seed: "family-seed"}); themeSig(got) != themeSig(th) {
		t.Fatalf("同 seed 命名方案不可复现:\n%s\n%s", themeSig(th), themeSig(got))
	}
	if other := decoyThemeOf(&config.Options{Seed: "another-seed"}); themeSig(other) == themeSig(th) {
		t.Fatal("不同 seed 得到了同一命名方案（随机挑选退化为常量？）")
	}
	// seed 为空（CLI 会先生成随机 seed）时同样不得回退到产品名/固定包。
	if free := decoyThemeOf(&config.Options{}); containsProductName(free.pkg) {
		t.Fatalf("空 seed 时主题包不得含产品名: %q", free.pkg)
	}
	t.Logf("seed=family-seed → 主题包 %s；名族 %s*/%s*/%s*",
		th.pkg, th.families[0].prefix, th.families[1].prefix, th.families[2].prefix)
}

// TestDecoyArtifactHasNoProductName 是「去产品化」的决定性断言：
// A8 执行后，产物三个可见面（ZIP 条目名、Manifest 字符串池、每个 DEX 的
// 字符串池）都不得出现 apkguard。
//
// 即使显式把 opts.ShellPkg 设成旧的 com.apkguard.shell 也不得泄漏——
// 这正是本测试最有价值的部分：证明 A8 已不再读取 ShellPkg 命名诱饵。
func TestDecoyArtifactHasNoProductName(t *testing.T) {
	art := loadSample(t)
	if pipeline.Find(art, "AndroidManifest.xml") == nil {
		t.Skip("样本没有 AndroidManifest.xml")
	}
	if pipeline.FindAll(art, isDexEntry) == nil {
		t.Skip("样本没有 DEX")
	}

	opts := &config.Options{
		Enabled:  map[config.FeatureID]bool{"A8": true},
		Seed:     "no-product",
		ShellPkg: "com.apkguard.shell",
	}
	if err := (&decoyClass{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A8 执行失败: %v", err)
	}

	// ① ZIP 条目名（A8 不改名，但契约要求这三个面一起扫）。
	for _, e := range art.Entries() {
		if containsProductName(e.NameString()) {
			t.Fatalf("产物条目名泄漏产品名: %s", e.NameString())
		}
	}

	// ② Manifest 字符串池。
	mfData, err := pipeline.Find(art, "AndroidManifest.xml").Data()
	if err != nil {
		t.Fatalf("读取 Manifest 失败: %v", err)
	}
	mf, err := axml.Parse(mfData)
	if err != nil {
		t.Fatalf("解析 Manifest 失败: %v", err)
	}
	for _, s := range mf.Strings() {
		if containsProductName(s) {
			t.Fatalf("Manifest 字符串池泄漏产品名: %q", s)
		}
	}

	// ③ 每个 DEX 的字符串池。
	scanned := 0
	for _, e := range pipeline.FindAll(art, isDexEntry) {
		d, derr := e.Data()
		if derr != nil {
			t.Fatalf("读取 %s 失败: %v", e.NameString(), derr)
		}
		f, perr := dex.Parse(d)
		if perr != nil {
			// A8 只改主 DEX；其余 DEX 理论上都可解析，解析失败说明产物被别的东西破坏了。
			t.Fatalf("解析 %s 失败: %v", e.NameString(), perr)
		}
		for i := uint32(0); i < f.NString; i++ {
			s, serr := f.String(i)
			if serr != nil {
				continue
			}
			if containsProductName(s) {
				t.Fatalf("DEX %s 字符串池泄漏产品名: %q", e.NameString(), s)
			}
		}
		scanned++
	}
	if scanned == 0 {
		t.Fatal("没有扫描到任何 DEX")
	}
	t.Logf("已扫描 %d 个 DEX、Manifest 字符串池与全部条目名：均不含 apkguard", scanned)
}

// compNamesFromElems 提取元素上的 android:name（用于日志）。
func compNamesFromElems(es []axml.Element) []string {
	out := make([]string, 0, len(es))
	for _, e := range es {
		out = append(out, e.Name+":"+e.AttrString("name"))
	}
	return out
}
