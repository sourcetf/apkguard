package passes

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/pipeline"
	"apkguard/internal/zipx"
)

// TestPackageShrinkCompressesPackageNames 钉住 A1 的包名压缩。
//
// 目标与参考样本一致：从类名读不出模块划分。但实现不能「把所有类压成同一个
// 默认包」——那会把原本同包的 package-private 访问变成跨包访问，运行时报
// IllegalAccessError（实测于 Termux，见 TestPackageShrinkKeepsPackagesWithKeptClasses）。
// 因此这里断言：每个原包被整体映射到一个**无意义短包名**，包内类仍然同包。
func TestPackageShrinkCompressesPackageNames(t *testing.T) {
	// 构造两个不同包下的类：压缩后各自进入一个短包，且互不相同
	art := newArtifact(zipx.NewStored("classes.dex", buildTwoPkgDex(t)))

	opts := &config.Options{
		Enabled:       map[config.FeatureID]bool{"A1": true},
		Seed:          "shrink",
		PackageShrink: true,
	}
	if err := (&renameClass{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A1 执行失败: %v", err)
	}

	e := pipeline.Find(art, "classes.dex")
	if e == nil {
		t.Fatal("产物里没有 classes.dex")
	}
	data, err := e.Data()
	if err != nil {
		t.Fatalf("读取产物失败: %v", err)
	}
	f, err := dex.Parse(data)
	if err != nil {
		t.Fatalf("产物无法解析: %v", err)
	}
	infos, err := f.ClassInfos()
	if err != nil {
		t.Fatalf("读取类信息失败: %v", err)
	}
	desc := map[string]bool{}
	for _, ci := range infos {
		desc[ci.Desc] = true
	}
	if desc["Lcom/a/Foo;"] || desc["Lorg/b/Bar;"] {
		t.Fatalf("原类名仍在产物中，测试失去意义: %v", keysOfDesc(desc))
	}
	// 每个新名都必须是「短包 + 短名」形态，且原包名不得残留。
	pkgs := map[string]bool{}
	for d := range desc {
		if strings.Contains(d, "com/") || strings.Contains(d, "org/") {
			t.Fatalf("包名压缩后仍能读出原包名: %s", d)
		}
		slash := strings.LastIndex(d, "/")
		if slash < 0 {
			t.Fatalf("包名压缩后类仍在默认包（应进入短包）: %s", d)
		}
		pkg := d[:slash+1]
		if !regexp.MustCompile(`^Lp[a-z]+/$`).MatchString(pkg) {
			t.Fatalf("短包名不合形态: %s", pkg)
		}
		pkgs[pkg] = true
	}
	if len(pkgs) != 2 {
		t.Fatalf("两个原包应产生两个不同的短包，实际 %d 个: %v", len(pkgs), keysOfDesc(pkgs))
	}
	if len(desc) != 2 {
		t.Fatalf("类数量应保持 2，实际 %d", len(desc))
	}
	t.Logf("包名压缩生效：%v（原包保留同包语义，仅包名不可读）", keysOfDesc(desc))
}

// TestPackageShrinkKeepsPackagesWithKeptClasses 钉住「含保留类的包不得被压缩」。
//
// 真实缺陷（实测于 Termux）：`-package-shrink` 曾把所有可改名类压进默认包，
// 而 `$` 内部类因「内外层命名强耦合」被保留在原包。于是原本同包的访问变成了
// 跨包访问，运行时报
//
//	java.lang.IllegalAccessError: Illegal class access: 'ac' attempting to
//	access 'com.termux.app.utils.CrashUtils$1'
//
// 修法：含保留类的包整体保持原包名（可改名类也留在该包，仅换短名）。
func TestPackageShrinkKeepsPackagesWithKeptClasses(t *testing.T) {
	art := newArtifact(zipx.NewStored("classes.dex", buildKeptPkgDex(t)))
	opts := &config.Options{
		Enabled:       map[config.FeatureID]bool{"A1": true},
		Seed:          "shrink3",
		PackageShrink: true,
	}
	if err := (&renameClass{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A1 执行失败: %v", err)
	}
	data, err := pipeline.Find(art, "classes.dex").Data()
	if err != nil {
		t.Fatalf("读取产物失败: %v", err)
	}
	if err := dex.ValidateDescriptors(data); err != nil {
		t.Fatalf("产物描述符非法: %v", err)
	}
	f, err := dex.Parse(data)
	if err != nil {
		t.Fatalf("产物无法解析: %v", err)
	}
	infos, err := f.ClassInfos()
	if err != nil {
		t.Fatalf("读取类信息失败: %v", err)
	}
	pkgShort := regexp.MustCompile(`^Lp[a-z]+/$`)
	pkgs := map[string]int{}
	innerKept := false
	for _, ci := range infos {
		if ci.Desc == "Lapp/Ui$1;" {
			innerKept = true
		}
		slash := strings.LastIndex(ci.Desc, "/")
		if slash < 0 {
			t.Fatalf("类不在任何包内: %s", ci.Desc)
		}
		pkgs[ci.Desc[:slash+1]]++
	}
	if !innerKept {
		t.Fatalf("被保留的 $ 内部类 Lapp/Ui$1; 不该被改名/搬走: %v", keysOfDesc(classDescs(infos)))
	}
	if pkgs["Lapp/"] == 0 {
		t.Fatalf("含保留类的包 Lapp/ 被错误压缩掉: %v", pkgs)
	}
	if pkgs["Lother/"] != 0 {
		t.Fatalf("无保留类的包 Lother/ 应被压缩掉，实际仍有 %d 个类: %v", pkgs["Lother/"], pkgs)
	}
	short := 0
	for p := range pkgs {
		if pkgShort.MatchString(p) {
			short++
		}
	}
	if short != 1 {
		t.Fatalf("应恰好产生 1 个短包（来自 Lother/），实际 %d 个: %v", short, pkgs)
	}
	// 同包内的可改名类必须换短名，否则测试失去意义。
	if classDescs(infos)["Lapp/Helper;"] {
		t.Fatalf("Lapp/Helper; 未被改名: %v", keysOfDesc(classDescs(infos)))
	}
	t.Logf("保留类所在的包 Lapp/ 未被压缩（仅类名变短），其余包压缩为短包；包分布 %v", pkgs)
}

// classDescs 把类信息转成描述符集合（用于日志与断言）。
func classDescs(infos []dex.ClassInfo) map[string]bool {
	out := map[string]bool{}
	for _, ci := range infos {
		out[ci.Desc] = true
	}
	return out
}

// buildKeptPkgDex 造一个「某包内既有保留类（$ 内部类）又有普通类」的 DEX。
func buildKeptPkgDex(t *testing.T) []byte {
	t.Helper()
	d, err := dex.Build(dex.Addition{Classes: []dex.ClassSpec{
		{Name: "Lapp/Ui;", Super: "Ljava/lang/Object;", Access: 0x0001},
		{Name: "Lapp/Ui$1;", Super: "Ljava/lang/Object;", Access: 0x0001}, // 内部类 → 保留
		{Name: "Lapp/Helper;", Super: "Ljava/lang/Object;", Access: 0x0001},
		{Name: "Lother/Thing;", Super: "Ljava/lang/Object;", Access: 0x0001},
	}})
	if err != nil {
		t.Fatalf("构造 DEX 失败: %v", err)
	}
	return d
}

// TestPackageShrinkAvoidsCollisions 钉住「压缩不会与既有类型冲突」。
//
// 应用本身可能已有默认包类（样本里就有 A0/A1），若不与既有类型去重，
// 会产生 class_def 里 class_idx 重复的非法 DEX。
func TestPackageShrinkAvoidsCollisions(t *testing.T) {
	// 构造一个已含默认包类的 DEX，和一个包内类
	art := newArtifact(zipx.NewStored("classes.dex", buildMixedDex(t)))

	o := &config.Options{
		Enabled:       map[config.FeatureID]bool{"A1": true},
		Seed:          "shrink2",
		PackageShrink: true,
	}
	if err := (&renameClass{}).Run(context.Background(), art, o); err != nil {
		t.Fatalf("A1 执行失败: %v", err)
	}
	e := pipeline.Find(art, "classes.dex")
	if e == nil {
		t.Fatal("产物里没有 classes.dex")
	}
	data, err := e.Data()
	if err != nil {
		t.Fatalf("读取产物失败: %v", err)
	}
	if err := dex.Verify(data); err != nil {
		t.Fatalf("产物校验失败: %v", err)
	}
	if err := dex.ValidateDescriptors(data); err != nil {
		t.Fatalf("产物描述符非法: %v", err)
	}
	// 描述符必须唯一（class_defs 里不允许重复的 class_idx）
	f, err := dex.Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	seen := map[string]bool{}
	if err := f.Classes(func(_ uint32, _ dex.ClassDef, name string) error {
		if seen[name] {
			t.Fatalf("类描述符重复: %s（会产生非法 DEX）", name)
		}
		seen[name] = true
		return nil
	}); err != nil {
		t.Fatalf("遍历失败: %v", err)
	}
	t.Logf("包名压缩后类描述符唯一：%v", keysOfDesc(seen))
}

// buildTwoPkgDex 造一个含两个不同包下类的 DEX。
func buildTwoPkgDex(t *testing.T) []byte {
	t.Helper()
	d, err := dex.Build(dex.Addition{Classes: []dex.ClassSpec{
		{Name: "Lcom/a/Foo;", Super: "Ljava/lang/Object;", Access: 0x0001},
		{Name: "Lorg/b/Bar;", Super: "Ljava/lang/Object;", Access: 0x0001},
	}})
	if err != nil {
		t.Fatalf("构造 DEX 失败: %v", err)
	}
	return d
}

// buildMixedDex 造一个「已含默认包类 + 包内类」的 DEX，用于验证压缩后的去重。
func buildMixedDex(t *testing.T) []byte {
	t.Helper()
	d, err := dex.Build(dex.Addition{Classes: []dex.ClassSpec{
		{Name: "LA0;", Super: "Ljava/lang/Object;", Access: 0x0001}, // 既有默认包类
		{Name: "Lcom/a/Foo;", Super: "Ljava/lang/Object;", Access: 0x0001},
	}})
	if err != nil {
		t.Fatalf("构造 DEX 失败: %v", err)
	}
	return d
}

// keysOfDesc 返回集合里的键（用于日志）。
func keysOfDesc(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
