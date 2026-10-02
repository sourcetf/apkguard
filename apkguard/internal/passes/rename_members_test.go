package passes

import (
	"context"
	"testing"

	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/pipeline"
	"apkguard/internal/zipx"
)

// voidBlob 构造一个只含 return-void 的方法体。
func voidBlob(t *testing.T) *dex.CodeBlob {
	t.Helper()
	a := dex.NewAsm()
	a.ReturnVoid()
	insns, patches, err := a.Assemble()
	if err != nil {
		t.Fatalf("汇编失败: %v", err)
	}
	return &dex.CodeBlob{Registers: 1, Ins: 1, Outs: 0, Insns: insns, Patches: patches}
}

// TestRenameMemberCoverage 是覆盖率的端到端正向证据：
// 可改名类的私有/静态成员，即使名字与被保留类共用，也必须真的被改名。
//
// 这正是当前基线「字段改名 0」的根因：值键路径按名称字符串全局决策，一个名字
// 只要被保留类共用就整体保留。按 (类, 名字) 引用的覆盖通道打破了这条连锁。
func TestRenameMemberCoverage(t *testing.T) {
	// Only 可改名；Main 继承 Activity（入口类）被保留，两者共用成员名。
	data, err := dex.Build(dex.Addition{Classes: []dex.ClassSpec{
		{
			Name: "Lapp/Only;", Super: "Ljava/lang/Object;", Access: 0x0001,
			Fields: []dex.ClassField{
				{Name: "sharedF", Type: "I", Access: 0x0002}, // 私有字段
				{Name: "statF", Type: "I", Access: 0x0009},   // 静态字段
			},
			Methods: []dex.ClassMethod{
				{Name: "shared", Proto: dex.ProtoSpec{Ret: "V"}, Access: 0x0009, Code: voidBlob(t)}, // 私有静态
				{Name: "statM", Proto: dex.ProtoSpec{Ret: "V"}, Access: 0x0009, Code: voidBlob(t)},  // 静态
			},
		},
		{
			// 继承框架入口类 → 被保留；其成员名与 Only 共用，逼值键路径放弃。
			Name: "Lapp/Main;", Super: "Landroid/app/Activity;", Access: 0x0001,
			Fields: []dex.ClassField{
				{Name: "sharedF", Type: "I", Access: 0x0001},
			},
			Methods: []dex.ClassMethod{
				{Name: "shared", Proto: dex.ProtoSpec{Ret: "V"}, Access: 0x0001, Code: voidBlob(t)},
			},
		},
	}})
	if err != nil {
		t.Fatalf("构造 DEX 失败: %v", err)
	}
	art := newArtifact(zipx.NewStored("classes.dex", data))
	if err := (&renameClass{}).Run(context.Background(), art, &config.Options{Seed: "member-cov"}); err != nil {
		t.Fatalf("A1 执行失败: %v", err)
	}
	if art.Stats["A1.fields_byid"] == "" || art.Stats["A1.fields_byid"] == "0" {
		t.Fatalf("按条目覆盖没有改任何字段（fields_byid=%q）：字段覆盖率提升失败；stats=%v",
			art.Stats["A1.fields_byid"], art.Stats)
	}
	if art.Stats["A1.methods_byid"] == "" || art.Stats["A1.methods_byid"] == "0" {
		t.Fatalf("按条目覆盖没有改任何方法（methods_byid=%q）；stats=%v",
			art.Stats["A1.methods_byid"], art.Stats)
	}

	out := parseEntry(t, art, "classes.dex")
	if err := dex.Verify(mustData(t, art, "classes.dex")); err != nil {
		t.Fatalf("产物校验失败: %v", err)
	}
	if err := dex.ValidateDescriptors(mustData(t, art, "classes.dex")); err != nil {
		t.Fatalf("产物描述符非法: %v", err)
	}
	infos, err := out.ClassInfos()
	if err != nil {
		t.Fatalf("读取类信息失败: %v", err)
	}
	var only, main *dex.ClassInfo
	for i := range infos {
		switch infos[i].Desc {
		case "Lapp/Main;":
			main = &infos[i]
		default:
			only = &infos[i]
		}
	}
	if main == nil {
		t.Fatal("被保留的入口类 Lapp/Main; 被改名/丢失")
	}
	if only == nil {
		t.Fatal("可改名类丢失")
	}
	// 被保留类 Main 的成员名必须原样。
	for _, m := range main.Methods() {
		if m.Name != "shared" {
			t.Errorf("被保留类的成员被改名: %s", m.Name)
		}
	}
	for _, f := range main.Fields() {
		if f.Name != "sharedF" {
			t.Errorf("被保留类的字段被改名: %s", f.Name)
		}
	}
	// 可改名类 Only 的私有/静态成员必须已改名。
	onlyNames := map[string]bool{}
	for _, m := range only.Methods() {
		onlyNames[m.Name] = true
	}
	if onlyNames["shared"] || onlyNames["statM"] {
		t.Errorf("可改名类的私有/静态方法未被改名: %v", onlyNames)
	}
	onlyFields := map[string]bool{}
	for _, f := range only.Fields() {
		onlyFields[f.Name] = true
	}
	if onlyFields["sharedF"] || onlyFields["statF"] {
		t.Errorf("可改名类的字段未被改名: %v", onlyFields)
	}
	t.Logf("成员覆盖生效：方法引用 %s 个、字段引用 %s 个；stats=%v",
		art.Stats["A1.methods_byid"], art.Stats["A1.fields_byid"], art.Stats)
}

// TestRenameMemberCrossDexConsistent 钉住跨 DEX 一致性：
// A DEX 定义、B DEX 引用的静态成员，改名后定义方与引用方必须用同一个新名，
// 否则运行时 NoSuchFieldError / NoSuchMethodError。
//
// 注意：值键路径在引用侧解析不到声明（类不在本 DEX），必然放弃；这条跨 DEX
// 一致性正是按条目覆盖路径必须自己保证的。
func TestRenameMemberCrossDexConsistent(t *testing.T) {
	const shared = "Lapp/Shared;"
	const fname = "VALUE"
	const mname = "compute"

	def, err := dex.Build(dex.Addition{Classes: []dex.ClassSpec{{
		Name: shared, Super: "Ljava/lang/Object;", Access: 0x0001,
		Fields: []dex.ClassField{{Name: fname, Type: "I", Access: 0x0009}},
		Methods: []dex.ClassMethod{{
			Name: mname, Proto: dex.ProtoSpec{Ret: "I"}, Access: 0x0009, Code: voidBlob(t),
		}},
	}}})
	if err != nil {
		t.Fatalf("构造定义侧 DEX 失败: %v", err)
	}

	a := dex.NewAsm()
	a.SGet(0, dex.FieldSpec{Class: shared, Name: fname, Type: "I"})
	if err := a.InvokeStatic(nil, dex.MethodSpec{Class: shared, Name: mname, Proto: dex.ProtoSpec{Ret: "I"}}); err != nil {
		t.Fatalf("汇编失败: %v", err)
	}
	a.MoveResult(0)
	a.Return(0)
	insns, patches, err := a.Assemble()
	if err != nil {
		t.Fatalf("汇编失败: %v", err)
	}
	ref, err := dex.Build(dex.Addition{Classes: []dex.ClassSpec{{
		Name: "Lapp/User;", Super: "Ljava/lang/Object;", Access: 0x0001,
		Methods: []dex.ClassMethod{{
			Name: "use", Proto: dex.ProtoSpec{Ret: "V"}, Access: 0x0001,
			Code: &dex.CodeBlob{Registers: 1, Ins: 1, Outs: 0, Insns: insns, Patches: patches},
		}},
	}}})
	if err != nil {
		t.Fatalf("构造引用侧 DEX 失败: %v", err)
	}

	art := newArtifact(
		zipx.NewStored("classes.dex", def),
		zipx.NewStored("classes2.dex", ref),
	)
	if err := (&renameClass{}).Run(context.Background(), art, &config.Options{Seed: "xd-member"}); err != nil {
		t.Fatalf("A1 执行失败: %v", err)
	}

	defOut := parseEntry(t, art, "classes.dex")
	refOut := parseEntry(t, art, "classes2.dex")

	// 定义侧：唯一类改名后的描述符与成员名。
	defInfos, err := defOut.ClassInfos()
	if err != nil {
		t.Fatalf("读取定义侧信息失败: %v", err)
	}
	var newDesc, newField, newMethod string
	for _, ci := range defInfos {
		newDesc = ci.Desc
		for _, fl := range ci.Fields() {
			newField = fl.Name
		}
		for _, m := range ci.Methods() {
			if m.Proto == "()I" {
				newMethod = m.Name
			}
		}
	}
	if newDesc == "" || newField == "" || newMethod == "" {
		t.Fatalf("定义侧信息不完整: desc=%q field=%q method=%q", newDesc, newField, newMethod)
	}
	if newField == fname {
		t.Fatal("定义侧静态字段未被改名，测试失去意义")
	}
	if newMethod == mname {
		t.Fatal("定义侧静态方法未被改名，测试失去意义")
	}

	// 引用侧：指向新描述符的字段/方法引用必须使用同一个新名。
	foundF, foundM := 0, 0
	for i := uint32(0); i < refOut.NField; i++ {
		c, _, n, err := refOut.FieldRefAt(i)
		if err != nil {
			t.Fatalf("读取字段引用失败: %v", err)
		}
		cd, _ := refOut.Type(uint32(c))
		if cd != newDesc {
			continue
		}
		foundF++
		nm, _ := refOut.String(n)
		if nm != newField {
			t.Fatalf("跨 DEX 字段不一致：定义侧 %s，引用侧 %s（NoSuchFieldError）", newField, nm)
		}
	}
	for i := uint32(0); i < refOut.NMethod; i++ {
		r, err := refOut.MethodRefAt(i)
		if err != nil {
			t.Fatalf("读取方法引用失败: %v", err)
		}
		cd, _ := refOut.Type(uint32(r.ClassIdx))
		if cd != newDesc {
			continue
		}
		nm, _ := refOut.String(r.NameIdx)
		if nm != newMethod {
			t.Fatalf("跨 DEX 方法不一致：定义侧 %s，引用侧 %s（NoSuchMethodError）", newMethod, nm)
		}
		foundM++
	}
	if foundF == 0 || foundM == 0 {
		t.Fatalf("引用侧没有引用到改名后的静态成员（field=%d method=%d），跨 DEX 改名断链", foundF, foundM)
	}
	t.Logf("跨 DEX 成员一致：%s.%s->%s、%s->%s", newDesc, fname, newField, mname, newMethod)
}

// TestLookLikeMemberIdentifier 直接钉住 passive 方法名判据。
func TestLookLikeMemberIdentifier(t *testing.T) {
	cases := map[string]bool{
		"onFoo":    true,
		"_x$1":     true,
		"a1":       true,
		"":         false,
		"1abc":     false,
		"com.X":    false,
		"@{handl}": false,
		"a b":      false,
	}
	for in, want := range cases {
		if got := looksLikeMemberIdentifier(in); got != want {
			t.Errorf("looksLikeMemberIdentifier(%q)=%v，期望 %v", in, got, want)
		}
	}
}

// mustData 读取产物条目字节。
func mustData(t *testing.T, art *pipeline.Artifact, name string) []byte {
	t.Helper()
	e := pipeline.Find(art, name)
	if e == nil {
		t.Fatalf("产物缺少 %s", name)
	}
	d, err := e.Data()
	if err != nil {
		t.Fatalf("读取 %s 失败: %v", name, err)
	}
	return d
}
