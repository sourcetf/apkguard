package dex

import (
	"testing"
)

// voidBody 返回一个只含 return-void 的方法体。
func voidBody(t *testing.T) *CodeBlob {
	t.Helper()
	a := NewAsm()
	a.ReturnVoid()
	insns, patches, err := a.Assemble()
	if err != nil {
		t.Fatalf("汇编失败: %v", err)
	}
	return &CodeBlob{Registers: 1, Ins: 1, Outs: 0, Insns: insns, Patches: patches}
}

// methodIDIndex 找到 (类, 名字, 原型) 对应的 method_ids 索引。
func methodIDIndex(t *testing.T, f *File, classDesc, name, proto string) uint32 {
	t.Helper()
	for i := uint32(0); i < f.NMethod; i++ {
		ref, err := f.MethodRefAt(i)
		if err != nil {
			t.Fatalf("读取方法引用失败: %v", err)
		}
		cls, _ := f.Type(uint32(ref.ClassIdx))
		nm, _ := f.String(ref.NameIdx)
		pd, _ := f.ProtoDesc(uint32(ref.ProtoIdx))
		if cls == classDesc && nm == name && pd == proto {
			return i
		}
	}
	t.Fatalf("找不到 method_id %s->%s%s", classDesc, name, proto)
	return 0
}

// fieldIDIndex 找到 (类, 名字, 类型) 对应的 field_ids 索引。
func fieldIDIndex(t *testing.T, f *File, classDesc, name, typ string) uint32 {
	t.Helper()
	for i := uint32(0); i < f.NField; i++ {
		c, ty, n, err := f.FieldRefAt(i)
		if err != nil {
			t.Fatalf("读取字段引用失败: %v", err)
		}
		cd, _ := f.Type(uint32(c))
		td, _ := f.Type(uint32(ty))
		nm, _ := f.String(n)
		if cd == classDesc && nm == name && td == typ {
			return i
		}
	}
	t.Fatalf("找不到 field_id %s->%s:%s", classDesc, name, typ)
	return 0
}

// memberName 返回类里某原型的定义方法名（renamed 产物里查）。
func memberName(t *testing.T, f *File, classDesc, proto string) string {
	t.Helper()
	infos, err := f.ClassInfos()
	if err != nil {
		t.Fatalf("读取类信息失败: %v", err)
	}
	for _, ci := range infos {
		if ci.Desc != classDesc {
			continue
		}
		for _, m := range ci.Methods() {
			if m.Proto == proto {
				return m.Name
			}
		}
	}
	t.Fatalf("类 %s 没有原型 %s 的方法", classDesc, proto)
	return ""
}

// TestRebuildMethodNameByIDIsPerEntry 钉住按条目覆盖通道的核心语义：
// 多条 method_id 共用同一个名字字符串时，只覆盖其中一个索引，
// 其它引用必须保持原名。
//
// 这是成员名覆盖率提升的关键基建：当前实现按字符串值改名（改一个名字会波及
// 所有同名引用），而私有/静态成员恰恰经常与框架方法同名，因此无法在值键路径
// 下改名。按索引覆盖解耦了这两者。
func TestRebuildMethodNameByIDIsPerEntry(t *testing.T) {
	body := voidBody(t)
	d, err := Build(Addition{Classes: []ClassSpec{
		{Name: "Lapp/A;", Super: "Ljava/lang/Object;", Access: 0x0001,
			Methods: []ClassMethod{{Name: "helper", Proto: ProtoSpec{Ret: "V"}, Access: 0x0002 | 0x0008, Code: body}}},
		{Name: "Lapp/B;", Super: "Ljava/lang/Object;", Access: 0x0001,
			Methods: []ClassMethod{{Name: "helper", Proto: ProtoSpec{Ret: "V"}, Access: 0x0002 | 0x0008, Code: body}}},
	}})
	if err != nil {
		t.Fatalf("构造 DEX 失败: %v", err)
	}
	f, err := Parse(d)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	idxA := methodIDIndex(t, f, "Lapp/A;", "helper", "()V")

	out, err := Rebuild(f, RebuildOptions{MethodNameByID: map[uint32]string{idxA: "zq"}})
	if err != nil {
		t.Fatalf("重建失败: %v", err)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("产物校验失败: %v", err)
	}
	if err := ValidateDescriptors(out); err != nil {
		t.Fatalf("产物描述符非法: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("产物无法解析: %v", err)
	}
	if got := memberName(t, g, "Lapp/A;", "()V"); got != "zq" {
		t.Fatalf("A.helper 未被按条目覆盖: %q", got)
	}
	if got := memberName(t, g, "Lapp/B;", "()V"); got != "helper" {
		t.Fatalf("B.helper 被误改: %q（它只是恰好与 A 共用同一个名字字符串）", got)
	}
	// 旧字符串必须保留（可能仍被其它引用/常量使用），新字符串必须入池。
	pool := map[string]bool{}
	for i := uint32(0); i < g.NString; i++ {
		s, _ := g.String(i)
		pool[s] = true
	}
	if !pool["helper"] {
		t.Fatal("旧名字字符串被删除：其它引用会断链")
	}
	if !pool["zq"] {
		t.Fatal("新名字字符串未加入池")
	}
}

// TestPlanMemberRenamesPrivateStaticCandidates 是覆盖率的正向证据：
// 私有/静态成员必须被列入覆盖表，而公有实例成员不得被动。
func TestPlanMemberRenamesPrivateStaticCandidates(t *testing.T) {
	body := voidBody(t)
	d, err := Build(Addition{Classes: []ClassSpec{{
		Name: "Lapp/Target;", Super: "Ljava/lang/Object;", Access: 0x0001,
		Fields: []ClassField{
			{Name: "privF", Type: "I", Access: 0x0002},
			{Name: "statF", Type: "I", Access: 0x0009},
			{Name: "pubF", Type: "I", Access: 0x0001},
		},
		Methods: []ClassMethod{
			{Name: "privM", Proto: ProtoSpec{Ret: "V"}, Access: 0x0002, Code: body},
			{Name: "statM", Proto: ProtoSpec{Ret: "V"}, Access: 0x0009, Code: body},
			{Name: "pubM", Proto: ProtoSpec{Ret: "V"}, Access: 0x0001, Code: body},
		},
	}}})
	if err != nil {
		t.Fatalf("构造 DEX 失败: %v", err)
	}
	f, err := Parse(d)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	res, err := PlanMemberRenames([]*File{f}, MemberRenameConfig{
		ClassMap: map[string]string{"Lapp/Target;": "La;"},
	})
	if err != nil {
		t.Fatalf("规划失败: %v", err)
	}
	if res.Methods < 2 || res.Fields < 2 {
		t.Fatalf("私有/静态成员候选过少：方法 %d、字段 %d", res.Methods, res.Fields)
	}

	m := res.MethodByID[0]
	if m == nil {
		t.Fatal("方法覆盖表为空")
	}
	if _, ok := m[methodIDIndex(t, f, "Lapp/Target;", "privM", "()V")]; !ok {
		t.Error("私有方法 privM 未被列入覆盖表")
	}
	if _, ok := m[methodIDIndex(t, f, "Lapp/Target;", "statM", "()V")]; !ok {
		t.Error("静态方法 statM 未被列入覆盖表")
	}
	if _, ok := m[methodIDIndex(t, f, "Lapp/Target;", "pubM", "()V")]; ok {
		t.Error("公有实例方法 pubM 被改名：本实现不碰需要虚方法族证明的成员")
	}

	fm := res.FieldByID[0]
	if fm == nil {
		t.Fatal("字段覆盖表为空")
	}
	if _, ok := fm[fieldIDIndex(t, f, "Lapp/Target;", "privF", "I")]; !ok {
		t.Error("私有字段 privF 未被列入覆盖表")
	}
	if _, ok := fm[fieldIDIndex(t, f, "Lapp/Target;", "statF", "I")]; !ok {
		t.Error("静态字段 statF 未被列入覆盖表")
	}
	if _, ok := fm[fieldIDIndex(t, f, "Lapp/Target;", "pubF", "I")]; ok {
		t.Error("公有实例字段 pubF 被改名")
	}

	// 端到端：应用覆盖表后，私有/静态成员名确实变了，公有实例成员不变。
	out, err := Rebuild(f, RebuildOptions{MethodNameByID: m, FieldNameByID: fm})
	if err != nil {
		t.Fatalf("重建失败: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("产物无法解析: %v", err)
	}
	infos, _ := g.ClassInfos()
	var target *ClassInfo
	for i := range infos {
		if infos[i].Desc == "Lapp/Target;" {
			target = &infos[i]
		}
	}
	if target == nil {
		t.Fatal("产物缺少 Lapp/Target;")
	}
	names := map[string]bool{}
	for _, mm := range target.Methods() {
		names[mm.Name] = true
	}
	if len(names) != len(target.Methods()) {
		t.Errorf("产物类内出现重复方法名: %v", names)
	}
	if names["privM"] || names["statM"] {
		t.Errorf("私有/静态方法未被改名: %v", names)
	}
	if !names["pubM"] {
		t.Errorf("公有实例方法 pubM 被改名了: %v", names)
	}
	fnames := map[string]bool{}
	for _, fl := range target.Fields() {
		fnames[fl.Name] = true
	}
	if len(fnames) != len(target.Fields()) {
		t.Errorf("产物类内出现重复字段名: %v", fnames)
	}
	if fnames["privF"] || fnames["statF"] {
		t.Errorf("私有/静态字段未被改名: %v", fnames)
	}
	if !fnames["pubF"] {
		t.Errorf("公有实例字段 pubF 被改名了: %v", fnames)
	}
}

// TestPlanMemberRenamesSharedNameIsolation 钉住「同名不连带」：
// 一个可改名类的私有方法与被保留类的公有方法同名时，只能改前者。
func TestPlanMemberRenamesSharedNameIsolation(t *testing.T) {
	body := voidBody(t)
	d, err := Build(Addition{Classes: []ClassSpec{
		{Name: "Lapp/RenameMe;", Super: "Ljava/lang/Object;", Access: 0x0001,
			Methods: []ClassMethod{{Name: "shared", Proto: ProtoSpec{Ret: "V"}, Access: 0x0002, Code: body}}},
		// 被保留类（不在 ClassMap 里）声明同名公有方法。
		{Name: "Lapp/KeepMe;", Super: "Ljava/lang/Object;", Access: 0x0001,
			Methods: []ClassMethod{{Name: "shared", Proto: ProtoSpec{Ret: "V"}, Access: 0x0001, Code: body}}},
	}})
	if err != nil {
		t.Fatalf("构造 DEX 失败: %v", err)
	}
	f, err := Parse(d)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	res, err := PlanMemberRenames([]*File{f}, MemberRenameConfig{
		ClassMap: map[string]string{"Lapp/RenameMe;": "La;"},
	})
	if err != nil {
		t.Fatalf("规划失败: %v", err)
	}
	m := res.MethodByID[0]
	if _, ok := m[methodIDIndex(t, f, "Lapp/RenameMe;", "shared", "()V")]; !ok {
		t.Fatal("可改名类的私有 shared 未被列入覆盖表")
	}
	if _, ok := m[methodIDIndex(t, f, "Lapp/KeepMe;", "shared", "()V")]; ok {
		t.Fatal("被保留类的 shared 被改名：同名连带，会破坏保留类的语义")
	}
	out, err := Rebuild(f, RebuildOptions{MethodNameByID: m})
	if err != nil {
		t.Fatalf("重建失败: %v", err)
	}
	g, _ := Parse(out)
	if got := memberName(t, g, "Lapp/KeepMe;", "()V"); got != "shared" {
		t.Fatalf("保留类的同名方法被误改: %q", got)
	}
	if got := memberName(t, g, "Lapp/RenameMe;", "()V"); got == "shared" {
		t.Fatal("可改名类的私有方法未被改名")
	}
}

// TestPlanMemberRenamesOverrideInvariant 钉住方案文档 R6/R7/R8：
// 覆写关系不得被破坏，也不得凭空新建覆写。
//
// 本实现只改私有/静态成员，它们不参与虚派发；公有实例覆写对（Base.m / Child.m）
// 必须原样保留同名。新名全局唯一，因此不会与任何既有方法撞名。
func TestPlanMemberRenamesOverrideInvariant(t *testing.T) {
	body := voidBody(t)
	d, err := Build(Addition{Classes: []ClassSpec{
		{Name: "Lapp/Base;", Super: "Ljava/lang/Object;", Access: 0x0001,
			Methods: []ClassMethod{{Name: "m", Proto: ProtoSpec{Ret: "V"}, Access: 0x0001, Code: body}}},
		{Name: "Lapp/Child;", Super: "Lapp/Base;", Access: 0x0001,
			Methods: []ClassMethod{
				{Name: "m", Proto: ProtoSpec{Ret: "V"}, Access: 0x0001, Code: body},      // 覆写
				{Name: "secret", Proto: ProtoSpec{Ret: "V"}, Access: 0x0002, Code: body}, // 私有，应改名
			}},
	}})
	if err != nil {
		t.Fatalf("构造 DEX 失败: %v", err)
	}
	f, err := Parse(d)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	classMap := map[string]string{"Lapp/Base;": "La;", "Lapp/Child;": "Lb;"}
	res, err := PlanMemberRenames([]*File{f}, MemberRenameConfig{ClassMap: classMap})
	if err != nil {
		t.Fatalf("规划失败: %v", err)
	}
	// 私有 secret 应被改；覆写对 m 不应被列入。
	m := res.MethodByID[0]
	if _, ok := m[methodIDIndex(t, f, "Lapp/Child;", "secret", "()V")]; !ok {
		t.Fatal("私有 secret 未被列入覆盖表")
	}
	if _, ok := m[methodIDIndex(t, f, "Lapp/Base;", "m", "()V")]; ok {
		t.Fatal("Base.m 被改名：覆写关系会断裂")
	}
	if _, ok := m[methodIDIndex(t, f, "Lapp/Child;", "m", "()V")]; ok {
		t.Fatal("Child.m 被改名：覆写关系会断裂")
	}

	out, err := Rebuild(f, RebuildOptions{
		MethodNameByID: m,
		// 同时应用类名，验证产物级结构。
		Rename: map[string]string{"Lapp/Base;": "La;", "Lapp/Child;": "Lb;"},
	})
	if err != nil {
		t.Fatalf("重建失败: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("产物无法解析: %v", err)
	}
	baseM := memberName(t, g, "La;", "()V")
	// Child 有两个 ()V 方法（m 与 secret），需要按 set 判断。
	childInfos, _ := g.ClassInfos()
	var childM, childSecret string
	for _, ci := range childInfos {
		if ci.Desc != "Lb;" {
			continue
		}
		for _, mm := range ci.Methods() {
			if mm.Proto != "()V" {
				continue
			}
			if mm.Name == "m" {
				childM = mm.Name
			}
			if mm.Name != "m" {
				childSecret = mm.Name
			}
		}
	}
	if childM != "m" {
		t.Errorf("R6/R8：Child.m 不再与 Base.m 同名（Base=%q Child=%q）", baseM, childM)
	}
	if childSecret == "" || childSecret == "secret" {
		t.Errorf("私有 secret 未被改名（got %q）", childSecret)
	}
	// R7：产物里不得出现「原始不存在」的父子同名同原型。
	// 这里 Child 的方法集合与 Base 的交集应恰好只有 m。
	if childSecret == baseM {
		t.Errorf("私有方法的新名与 Base.m 撞名（%q），凭空新建了覆写", childSecret)
	}
}

// TestPlanMemberRenamesSkipsKeptClass 钉住 A2：被保留类的成员一律不改。
func TestPlanMemberRenamesSkipsKeptClass(t *testing.T) {
	body := voidBody(t)
	d, err := Build(Addition{Classes: []ClassSpec{{
		Name: "Lapp/Kept;", Super: "Ljava/lang/Object;", Access: 0x0001,
		Methods: []ClassMethod{{Name: "priv", Proto: ProtoSpec{Ret: "V"}, Access: 0x0002, Code: body}},
	}}})
	if err != nil {
		t.Fatalf("构造 DEX 失败: %v", err)
	}
	f, _ := Parse(d)
	res, err := PlanMemberRenames([]*File{f}, MemberRenameConfig{ClassMap: map[string]string{}})
	if err != nil {
		t.Fatalf("规划失败: %v", err)
	}
	if len(res.MethodByID[0]) != 0 || len(res.FieldByID[0]) != 0 {
		t.Fatal("被保留类的成员被列入覆盖表")
	}
}
