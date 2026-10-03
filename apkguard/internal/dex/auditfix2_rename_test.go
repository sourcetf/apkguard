package dex

import (
	"testing"
)

// 本文件收口前几轮审计遗留的两条 A1 重命名缺陷（auditfix2）：
//
//  1. hasInner 的键构造成 "Lapp/Outer$"（截到 '$' 含它），而查询用 ci.Desc
//     （"Lapp/Outer;"），两者永不相等 → 含内部类的外层类仍被改名；
//  2. planFields 误用方法解析器 resolvesVisibly（按 (name, proto) 找方法），
//     传入的却是字段类型 → 值键路径下字段改名整体失效。

// audit2StaticMethod 构造一个 public static void 方法体。
func audit2StaticMethod(t *testing.T) *CodeBlob {
	t.Helper()
	a := NewAsm()
	a.ReturnVoid()
	insns, patches, err := a.Assemble()
	if err != nil {
		t.Fatalf("汇编测试方法失败: %v", err)
	}
	return &CodeBlob{Registers: 1, Ins: 0, Outs: 0, Insns: insns, Patches: patches}
}

// audit2RenamePlan 构造 DEX 并返回重命名计划与统计。
func audit2RenamePlan(t *testing.T, add Addition, cfg RenameConfig) (map[string]string, Stats) {
	t.Helper()
	d, err := Build(add)
	if err != nil {
		t.Fatalf("构造测试 DEX 失败: %v", err)
	}
	f, err := Parse(d)
	if err != nil {
		t.Fatalf("解析测试 DEX 失败: %v", err)
	}
	rn, err := NewRenamer(f, cfg)
	if err != nil {
		t.Fatalf("构造重命名器失败: %v", err)
	}
	plan, err := rn.Plan()
	if err != nil {
		t.Fatalf("生成重命名计划失败: %v", err)
	}
	return plan, rn.LastStats()
}

// TestAuditFix2OuterClassWithInnerIsKept 回归：含内部类的外层类不得被改名。
//
// 缺陷形态：hasInner[ci.Desc[:i+1]] 存入 "Lapp/Outer$"，查询用
// hasInner[ci.Desc]（"Lapp/Outer;"），永远不命中；内部类自身又在更早的
// strings.Contains(ci.Desc, "$") 分支被保留，于是外层类被单独改名。
// 运行期若代码用 outer.getName()+"$Inner" 拼名，或 Kotlin/Gson 按名反射
// 嵌套类，拼出来的名字在 DEX 里不存在 → ClassNotFoundException。
func TestAuditFix2OuterClassWithInnerIsKept(t *testing.T) {
	body := audit2StaticMethod(t)
	plan, stats := audit2RenamePlan(t, Addition{Classes: []ClassSpec{
		{
			Name:   "Lapp/Outer;",
			Super:  "Ljava/lang/Object;",
			Access: accPublic,
			Methods: []ClassMethod{
				{Name: "m", Proto: ProtoSpec{Ret: "V"}, Access: accPublic | accStatic, Code: body},
			},
		},
		{
			Name:   "Lapp/Outer$Inner;",
			Super:  "Ljava/lang/Object;",
			Access: accPublic,
			Methods: []ClassMethod{
				{Name: "n", Proto: ProtoSpec{Ret: "V"}, Access: accPublic | accStatic, Code: body},
			},
		},
	}}, RenameConfig{})

	if nw, ok := plan["Lapp/Outer;"]; ok {
		t.Errorf("含内部类的外层类被改名（%q）——内部类仍保留原名，"+
			"运行期拼名/反射嵌套类会抛 ClassNotFoundException", nw)
	}
	if _, ok := plan["Lapp/Outer$Inner;"]; ok {
		t.Errorf("内部类被改名：外层类保留时内部类也必须保留（命名强耦合）")
	}
	// keepReason 必须给出正确的原因：外层类命中「含内部类」，内部类命中「内部类」。
	if got := stats.KeepReasons["含内部类（需整体处理）"]; got < 1 {
		t.Errorf("外层类的保留原因未命中「含内部类」：%v", stats.KeepReasons)
	}
	if got := stats.KeepReasons["内部类（与外层类命名强耦合）"]; got < 1 {
		t.Errorf("内部类的保留原因未命中「内部类」：%v", stats.KeepReasons)
	}
	if stats.KeptCls != 2 {
		t.Errorf("应保留 2 个类，实际 %d（原因 %v）", stats.KeptCls, stats.KeepReasons)
	}
}

// TestAuditFix2PublicInstanceFieldRenamed 回归：值键路径下可改名的公有实例字段
// 必须真的被改名；声明在不可见父类型上的字段必须保留。
//
// 缺陷形态：planFields 对每个引用调用的是方法解析器 resolvesVisibly，
// 内部按 (name, proto) 在 DirectMethods/VirtualMethods 里查找；而 rf.sig 是
// 字段类型（"I"），字段名永远匹配不到方法声明 → all 恒为 false →
// ObfuscateFields 在值键路径下形同虚设。
//
// 第二个类（Sub 继承不可见的 Lframework/Base;）是反向守卫：新解析器必须像
// 方法侧一样保守——可见链里找不到声明（声明在框架/未打包库里）就不能改名，
// 否则运行期 NoSuchFieldError。
func TestAuditFix2PublicInstanceFieldRenamed(t *testing.T) {
	// Holder.count 是公有实例字段；User 的 iget 引用它。
	// Sub.value 的引用点在 Sub 上，但 Sub 自身不声明该字段
	// （声明在不可见的父类 Lframework/Base; 上）→ 必须保留。
	makeGetter := func(t *testing.T, class, field string) *CodeBlob {
		t.Helper()
		a := NewAsm()
		// public static int get(Class h) { return h.field; }
		// registers=4、ins=1：入参对象在 v3。
		if err := a.IGet(0, 3, FieldSpec{Class: class, Name: field, Type: "I"}); err != nil {
			t.Fatalf("汇编 iget 失败: %v", err)
		}
		a.Return(0)
		insns, patches, err := a.Assemble()
		if err != nil {
			t.Fatalf("汇编 getter 失败: %v", err)
		}
		return &CodeBlob{Registers: 4, Ins: 1, Outs: 0, Insns: insns, Patches: patches}
	}
	protoIHolder := ProtoSpec{Ret: "I", Params: []string{"Lapp/Holder;"}}
	protoISub := ProtoSpec{Ret: "I", Params: []string{"Lapp/Sub;"}}

	plan, _ := audit2RenamePlan(t, Addition{Classes: []ClassSpec{
		{
			Name:   "Lapp/Holder;",
			Super:  "Ljava/lang/Object;",
			Access: accPublic,
			Fields: []ClassField{
				{Name: "count", Type: "I", Access: accPublic},
			},
			Methods: []ClassMethod{
				{Name: "peek", Proto: ProtoSpec{Ret: "V"}, Access: accPublic | accStatic, Code: audit2StaticMethod(t)},
			},
		},
		{
			Name:   "Lapp/User;",
			Super:  "Ljava/lang/Object;",
			Access: accPublic,
			Methods: []ClassMethod{
				{Name: "read", Proto: protoIHolder, Access: accPublic | accStatic, Code: makeGetter(t, "Lapp/Holder;", "count")},
			},
		},
		{
			Name:   "Lapp/Sub;",
			Super:  "Lframework/Base;",
			Access: accPublic,
			Methods: []ClassMethod{
				{Name: "read", Proto: protoISub, Access: accPublic | accStatic, Code: makeGetter(t, "Lapp/Sub;", "value")},
			},
		},
	}}, RenameConfig{ObfuscateFields: true})

	// 先确认两个类本身都在改名集合里——否则「字段保留」会因类未改名而
	// 平凡成立，测试就钉不住字段解析器。
	for _, cls := range []string{"Lapp/Holder;", "Lapp/User;", "Lapp/Sub;"} {
		if _, ok := plan[cls]; !ok {
			t.Fatalf("类 %s 未被改名，测试前提不成立（无法检验字段解析路径）", cls)
		}
	}
	if nw, ok := plan["count"]; !ok {
		t.Errorf("可改名类上的公有实例字段 count 未被改名——" +
			"值键路径下字段改名失效（resolvesVisibly 是方法解析器，遇到字段类型必然找不到声明）")
	} else if nw == "count" {
		t.Errorf("字段 count 的新名与旧名相同: %q", nw)
	}
	if nw, ok := plan["value"]; ok {
		t.Errorf("声明在不可见父类型（Lframework/Base;）上的字段被改名（%q）——"+
			"可见链里找不到声明的字段引用绝不能改，运行期 NoSuchFieldError", nw)
	}
}
