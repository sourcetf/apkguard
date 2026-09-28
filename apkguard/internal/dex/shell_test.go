package dex

import (
	"strings"
	"testing"
)

// TestShellJavaName 验证描述符到 Java 点分名的转换。
func TestShellJavaName(t *testing.T) {
	cases := map[string]string{
		"Lcom/a/B;":            "com.a.B",
		"Lapkguard/App;":       "apkguard.App",
		"Lfoo/bar/Baz$Qux;":    "foo.bar.Baz$Qux",
		"Ljava/lang/Object;":   "java.lang.Object",
		"LDefault;":            "Default",
	}
	for in, want := range cases {
		if got := ShellJavaName(in); got != want {
			t.Errorf("ShellJavaName(%q) = %q，期望 %q", in, got, want)
		}
	}
}

// TestShellAppAddition 验证壳 Application 的条目完整性。
func TestShellAppAddition(t *testing.T) {
	sh := &ShellApp{Class: "Lapkguard/App;", Orig: "com.orig.MyApp"}
	add, err := ShellAppAddition(sh)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	if len(add.Classes) != 1 {
		t.Fatalf("应注入 1 个类，实际 %d", len(add.Classes))
	}
	c := add.Classes[0]
	if c.Name != sh.Class {
		t.Fatalf("类名不符: %s", c.Name)
	}
	// 关键：壳类必须继承框架 Application，而不是原 Application
	if c.Super != descApplication {
		t.Fatalf("父类应为 %s，实际 %s", descApplication, c.Super)
	}
	if c.Access&accSuper == 0 {
		t.Fatal("非 Object 子类必须置 accSuper 标志")
	}
	// 必须覆写 attachBaseContext 与 onCreate
	names := map[string]uint32{}
	for _, m := range c.Methods {
		names[m.Name] = m.Access
		if m.Code == nil {
			t.Fatalf("方法 %s 缺少方法体", m.Name)
		}
	}
	for _, want := range []string{"<init>", "attachBaseContext", "onCreate", shellHelperName} {
		if _, ok := names[want]; !ok {
			t.Fatalf("缺少方法 %s（已有 %v）", want, keysOf(names))
		}
	}
	// attachBaseContext 必须是 protected（与框架签名一致）
	if names["attachBaseContext"]&accProtected == 0 {
		t.Fatal("attachBaseContext 应为 protected")
	}
	// 未声明原 Application 时不应生成反射辅助方法
	add2, err := ShellAppAddition(&ShellApp{Class: "Lapkguard/App;"})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	for _, m := range add2.Classes[0].Methods {
		if m.Name == shellHelperName {
			t.Fatal("原 APK 未声明 Application 时不应生成反射辅助方法")
		}
	}
}

func keysOf(m map[string]uint32) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestShellAppAdditionRejectsEmptyClass 验证参数校验。
func TestShellAppAdditionRejectsEmptyClass(t *testing.T) {
	if _, err := ShellAppAddition(&ShellApp{}); err == nil {
		t.Fatal("类名为空时应返回错误")
	}
}

// TestBuildShellAppDex 验证壳 Application 能被编译进一个全新的 DEX。
func TestBuildShellAppDex(t *testing.T) {
	add, err := ShellAppAddition(&ShellApp{
		Class: "Lapkguard/App;", Orig: "com.orig.MyApp",
	})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	out, err := Build(add)
	if err != nil {
		t.Fatalf("Build 失败: %v", err)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("校验失败: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if g.NClass != 1 {
		t.Fatalf("应只有 1 个类，实际 %d", g.NClass)
	}
	name, err := g.ClassName(0)
	if err != nil {
		t.Fatalf("读取类名失败: %v", err)
	}
	if name != "Lapkguard/App;" {
		t.Fatalf("类名不符: %s", name)
	}
	// 全部方法体必须能被解析为合法指令流
	n := 0
	if err := g.walkAllCode(func(codeOff uint32) error {
		ci, err := g.ParseCodeItem(codeOff)
		if err != nil {
			return err
		}
		if _, err := ParseInsns(ci.Insns); err != nil {
			return err
		}
		n++
		return nil
	}); err != nil {
		t.Fatalf("方法体校验失败: %v", err)
	}
	if n < 4 {
		t.Fatalf("应至少有 4 个方法体，实际 %d", n)
	}
	t.Logf("B2：壳 DEX 生成成功，%d 个类、%d 个方法体、%d 字节", g.NClass, n, len(out))
}

// TestShellAppDexDelegation 用解释器真正执行壳 Application，
// 验证 attachBaseContext / onCreate 的委托语义。
//
// 这是 B2 正确性的关键证据：DEX 结构自洽不代表运行时会正确委托，
// 只有把注入的字节码跑一遍、断言「父类实现被调用 + 原 Application 收到
// attachBaseContext」才能证明。
func TestShellAppDexDelegation(t *testing.T) {
	const origName = "com.orig.MyApp"
	add, err := ShellAppAddition(&ShellApp{Class: "Lapkguard/App;", Orig: origName})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	out, err := Build(add)
	if err != nil {
		t.Fatalf("Build 失败: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	// 构造模拟环境：原 Application 类**没有**覆写 attachBaseContext，
	// 其父类（模拟 android.app.Application）才有——这正是壳必须沿父类链
	// 扫描的原因。
	paramCtx := &fakeCls{name: "android.content.Context"}
	baseApp := &fakeCls{
		name: "android.app.Application",
		mths: []*fakeMth{{name: "attachBaseContext", params: []*fakeCls{paramCtx}}},
	}
	origCls := &fakeCls{name: origName, supers: []*fakeCls{baseApp}}
	fakeClasses[origName] = origCls
	defer delete(fakeClasses, origName)

	// 清空静态区，避免测试间相互影响
	objStatics = map[string]any{}
	// 注册壳类自身的方法体，使解释器能进入静态辅助方法 a()。
	fakeCode = map[string]uint32{}
	defer func() { fakeCode = map[string]uint32{} }()

	// 定位壳类的三个方法
	var attachIdx, attachOff, createIdx, createOff uint32
	var ctorIdx, ctorOff uint32
	if err := g.Classes(func(_ uint32, cd ClassDef, name string) error {
		if name != "Lapkguard/App;" {
			return nil
		}
		pcd, err := g.ParseClassData(cd.ClassDataOff)
		if err != nil {
			return err
		}
		scan := func(ms []EncodedMethod) {
			for _, m := range ms {
				d, _ := g.MethodDesc(m.Idx)
				// 把壳类的全部方法登记给解释器，使其能进入方法体执行。
				fakeCode[d] = m.CodeOff
				switch {
				case strings.Contains(d, "->attachBaseContext("):
					attachIdx, attachOff = m.Idx, m.CodeOff
				case strings.Contains(d, "->onCreate("):
					createIdx, createOff = m.Idx, m.CodeOff
				case strings.Contains(d, "-><init>("):
					ctorIdx, ctorOff = m.Idx, m.CodeOff
				}
			}
		}
		scan(pcd.DirectMethods)
		scan(pcd.VirtualMethods)
		return nil
	}); err != nil {
		t.Fatalf("遍历类失败: %v", err)
	}
	if attachOff == 0 || createOff == 0 || ctorOff == 0 {
		t.Fatalf("未定位到全部方法（attach=%d create=%d ctor=%d）", attachOff, createOff, ctorOff)
	}

	// ① 执行 <init>：应调用父类构造器
	app := &fakeObj{desc: "Lapkguard/App;"}
	if _, err := runPadMethod(g, ctorIdx, ctorOff, app); err != nil {
		t.Fatalf("壳 Application 的 <init> 执行失败: %v", err)
	}

	// ② 执行 attachBaseContext：应调用 super 并完成对原 Application 的反射委托
	ctx := &fakeObj{desc: "Landroid/content/Context;"}
	debugCalls = []string{}
	_, err = runPadMethod(g, attachIdx, attachOff, app, ctx)
	t.Logf("attachBaseContext 调用轨迹: %v", debugCalls)
	debugCalls = nil
	if err != nil {
		t.Fatalf("attachBaseContext 执行失败: %v", err)
	}

	// 原 Application 实例必须已缓存到静态字段
	key := "Lapkguard/App;->" + shellFieldOrig
	cached, ok := objStatics[key].(*fakeObj)
	if !ok {
		t.Fatalf("未把原 Application 实例写入静态字段 %s", key)
	}
	wantDesc := "L" + strings.ReplaceAll(origName, ".", "/") + ";"
	if cached.desc != wantDesc {
		t.Fatalf("缓存的实例类型应为 %s，实际 %s", wantDesc, cached.desc)
	}
	// 原 Application 的 attachBaseContext 必须被调用，且收到同一个 Context
	if cached.getField("$attach") != 1 {
		t.Fatalf("原 Application 的 attachBaseContext 应被调用 1 次，实际 %d",
			cached.getField("$attach"))
	}
	if got := baseApp.mths[0].invoked; len(got) != 1 || got[0] != ctx {
		t.Fatalf("反射调用未传入正确的 Context：%v", got)
	}
	if !baseApp.mths[0].accessed {
		t.Fatal("反射调用前未调用 setAccessible(true)")
	}

	// ③ 执行 onCreate：应先调用父类实现，再委托给原 Application
	if _, err := runPadMethod(g, createIdx, createOff, app); err != nil {
		t.Fatalf("onCreate 执行失败: %v", err)
	}
	if app.getField("$onCreate") != 1 {
		t.Fatalf("super.onCreate 应被调用 1 次，实际 %d", app.getField("$onCreate"))
	}
	t.Logf("B2：壳 Application 委托链验证通过（父类 attachBaseContext 命中于 %s，原 Application 已收到 Context）",
		baseApp.name)
}

// TestShellAppDexNoOrig 验证原 APK 未声明 Application 时，
// 壳只调用父类实现而不做任何反射委托。
func TestShellAppDexNoOrig(t *testing.T) {
	add, err := ShellAppAddition(&ShellApp{Class: "Lapkguard/App;"})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	out, err := Build(add)
	if err != nil {
		t.Fatalf("Build 失败: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	var attachIdx, attachOff uint32
	if err := g.Classes(func(_ uint32, cd ClassDef, name string) error {
		if name != "Lapkguard/App;" {
			return nil
		}
		pcd, err := g.ParseClassData(cd.ClassDataOff)
		if err != nil {
			return err
		}
		for _, ms := range [][]EncodedMethod{pcd.DirectMethods, pcd.VirtualMethods} {
			for _, m := range ms {
				d, _ := g.MethodDesc(m.Idx)
				if strings.Contains(d, "->attachBaseContext(") {
					attachIdx, attachOff = m.Idx, m.CodeOff
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("遍历类失败: %v", err)
	}
	objStatics = map[string]any{}
	app := &fakeObj{desc: "Lapkguard/App;"}
	if _, err := runPadMethod(g, attachIdx, attachOff, app, &fakeObj{desc: "Landroid/content/Context;"}); err != nil {
		t.Fatalf("attachBaseContext 执行失败: %v", err)
	}
	if _, ok := objStatics["Lapkguard/App;->"+shellFieldOrig]; ok {
		t.Fatal("未声明原 Application 时不应写入静态字段")
	}
}

// TestShellAppBuildDeterministic 验证同一输入产出完全一致（可复现）。
func TestShellAppBuildDeterministic(t *testing.T) {
	mk := func() []byte {
		add, err := ShellAppAddition(&ShellApp{Class: "Lapkguard/App;", Orig: "com.orig.MyApp"})
		if err != nil {
			t.Fatalf("构造失败: %v", err)
		}
		out, err := Build(add)
		if err != nil {
			t.Fatalf("Build 失败: %v", err)
		}
		return out
	}
	a, b := mk(), mk()
	if len(a) != len(b) {
		t.Fatalf("长度不一致: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("第 %d 字节不一致", i)
		}
	}
}
