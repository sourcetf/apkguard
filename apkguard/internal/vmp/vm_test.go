package vmp_test

import (
	"fmt"
	"sort"
	"testing"

	"apkguard/internal/dex"
	"apkguard/internal/vmp"
)

// fixMethod 描述一个 fixture 方法。
type fixMethod struct {
	Name   string
	Ret    string
	Params []string
	Access uint32
	Code   *dex.CodeBlob
}

const fixtureClass = "Ltest/Fixture;"

// holderFields 是测试用的字段集合。
var holderFields = []dex.FieldSpec{
	{Class: "Ltest/Holder;", Name: "i", Type: "I"},
	{Class: "Ltest/Holder;", Name: "w", Type: "J"},
	{Class: "Ltest/Holder;", Name: "s", Type: "Ljava/lang/String;"},
	{Class: "Ltest/Holder;", Name: "b", Type: "Z"},
	{Class: "Ltest/Holder;", Name: "by", Type: "B"},
	{Class: "Ltest/Holder;", Name: "ch", Type: "C"},
	{Class: "Ltest/Holder;", Name: "sh", Type: "S"},
	{Class: "Ltest/Holder;", Name: "si", Type: "I"},
	{Class: "Ltest/Holder;", Name: "sw", Type: "J"},
	{Class: "Ltest/Holder;", Name: "ss", Type: "Ljava/lang/String;"},
	{Class: "Ltest/Holder;", Name: "sb", Type: "Z"},
	{Class: "Ltest/Holder;", Name: "sby", Type: "B"},
	{Class: "Ltest/Holder;", Name: "sch", Type: "C"},
	{Class: "Ltest/Holder;", Name: "ssh", Type: "S"},
}

func static(proto dex.ProtoSpec) uint32 { return 0x9 } // public static

// buildFixture 生成包含全部 fixture 方法的 DEX。
func buildFixture(t *testing.T, methods []fixMethod) *dex.File {
	t.Helper()
	add := dex.Addition{}
	cls := dex.ClassSpec{
		Name:   fixtureClass,
		Super:  "Ljava/lang/Object;",
		Access: 0x1,
	}
	for _, m := range methods {
		proto := dex.ProtoSpec{Ret: m.Ret, Params: m.Params}
		cls.Methods = append(cls.Methods, dex.ClassMethod{Name: m.Name, Proto: proto, Access: m.Access, Code: m.Code})
		add.Methods = append(add.Methods, dex.MethodSpec{Class: fixtureClass, Name: m.Name, Proto: proto})
	}
	for _, f := range holderFields {
		add.Fields = append(add.Fields, f)
	}
	// Holder 类只声明字段（实例字段公有、静态字段带 static 标志）。
	add.Classes = append(add.Classes, dex.ClassSpec{
		Name: "Ltest/Holder;", Super: "Ljava/lang/Object;", Access: 0x1,
		Fields: []dex.ClassField{
			{Name: "i", Type: "I", Access: 0x1}, {Name: "w", Type: "J", Access: 0x1},
			{Name: "s", Type: "Ljava/lang/String;", Access: 0x1},
			{Name: "b", Type: "Z", Access: 0x1}, {Name: "by", Type: "B", Access: 0x1},
			{Name: "ch", Type: "C", Access: 0x1}, {Name: "sh", Type: "S", Access: 0x1},
			{Name: "si", Type: "I", Access: 0x9}, {Name: "sw", Type: "J", Access: 0x9},
			{Name: "ss", Type: "Ljava/lang/String;", Access: 0x9},
			{Name: "sb", Type: "Z", Access: 0x9}, {Name: "sby", Type: "B", Access: 0x9},
			{Name: "sch", Type: "C", Access: 0x9}, {Name: "ssh", Type: "S", Access: 0x9},
		},
	})
	// Fixture 类自身没有字段：Holder 的字段在上面已登记。
	add.Classes = append([]dex.ClassSpec{cls}, add.Classes...)

	data, err := dex.Build(add)
	if err != nil {
		t.Fatalf("构建 fixture DEX 失败: %v", err)
	}
	f, err := dex.Parse(data)
	if err != nil {
		t.Fatalf("解析 fixture DEX 失败: %v", err)
	}
	if err := dex.ValidateDescriptors(data); err != nil {
		t.Fatalf("fixture 描述符非法: %v", err)
	}
	return f
}

// ---- fixture 方法定义 ----

func fixtureMix() fixMethod {
	a := newWA()
	a.emit(0x00) // nop：A20 会向方法体插入 nop，必须可翻译
	a.const4(2, 7)
	a.bin23x(0x90, 3, 0, 1) // add-int
	a.bin23x(0x92, 3, 3, 2) // mul-int
	a.bin23x(0x91, 3, 3, 1) // sub-int
	a.bin23x(0x95, 3, 3, 0) // and-int
	a.bin23x(0x96, 3, 3, 1) // or-int
	a.bin23x(0x97, 3, 3, 2) // xor-int
	a.bin23x(0x98, 3, 3, 2) // shl-int
	a.bin23x(0x99, 3, 3, 2) // shr-int
	a.bin23x(0x9a, 3, 3, 2) // ushr-int
	a.unary12x(0x7b, 3, 3)  // neg-int
	a.unary12x(0x7c, 3, 3)  // not-int
	a.const16(4, -1234)
	a.bin23x(0x90, 3, 3, 4)
	a.const32(4, 0x12345678)
	a.bin23x(0x90, 3, 3, 4)
	a.const4(4, -1)
	a.bin23x(0x90, 3, 3, 4)
	a.returnReg(3)
	return fixMethod{Name: "mix", Ret: "I", Params: []string{"I", "I"}, Access: static(dex.ProtoSpec{}), Code: a.assemble(5, 2, 0)}
}

func fixtureDivRem() fixMethod {
	a := newWA()
	a.bin23x(0x93, 2, 0, 1)
	a.bin23x(0x94, 3, 0, 1)
	a.bin23x(0x90, 2, 2, 3)
	a.returnReg(2)
	return fixMethod{Name: "divrem", Ret: "I", Params: []string{"I", "I"}, Access: static(dex.ProtoSpec{}), Code: a.assemble(4, 2, 0)}
}

func fixtureLitOps() fixMethod {
	a := newWA()
	a.lit16(0xd0, 2, 0, 1000)
	a.lit8(0xd8, 2, 2, 5)
	a.lit8(0xd9, 2, 2, 7)
	a.lit8(0xda, 2, 2, 3)
	a.lit8(0xdd, 2, 2, 0x7f)
	a.lit8(0xde, 2, 2, 0x10)
	a.lit8(0xdf, 2, 2, 0x55)
	a.lit8(0xe0, 2, 2, 2)
	a.lit8(0xe1, 2, 2, 1)
	a.lit8(0xe2, 2, 2, 1)
	a.const4(3, 9)
	a.lit8(0xdb, 2, 2, 9)
	a.lit8(0xdc, 2, 2, 3)
	a.bin23x(0x90, 2, 2, 3)
	a.bin23x(0x90, 2, 2, 1)
	a.returnReg(2)
	return fixMethod{Name: "litops", Ret: "I", Params: []string{"I", "I"}, Access: static(dex.ProtoSpec{}), Code: a.assemble(4, 2, 0)}
}

func fixtureConvs() fixMethod {
	a := newWA()
	a.unary12x(0x8d, 1, 0) // int-to-byte
	a.unary12x(0x8f, 2, 0) // int-to-short
	a.unary12x(0x8e, 3, 0) // int-to-char
	a.unary12x(0x81, 1, 1) // int-to-long（宽值 v1/v2）
	a.unary12x(0x81, 3, 3) // int-to-long（宽值 v3/v4）
	a.bin23x(0x9b, 1, 1, 3)
	a.returnWide(1)
	return fixMethod{Name: "convs", Ret: "J", Params: []string{"I"}, Access: static(dex.ProtoSpec{}), Code: a.assemble(6, 1, 0)}
}

func fixtureLongOps() fixMethod {
	a := newWA()
	a.constWide16(4, 123)
	a.bin23x(0x9b, 0, 0, 4) // add-long
	a.constWide32(4, 100000)
	a.bin23x(0x9c, 0, 0, 4) // sub-long
	a.constWide(4, 0x1122334455667788)
	a.bin23x(0xa2, 0, 0, 4) // xor-long
	a.constWideHigh16(4, 0x4000)
	a.bin23x(0xa1, 0, 0, 4) // or-long
	a.bin23x(0xa0, 0, 0, 4) // and-long
	a.const4(6, 4)
	a.bin23x(0xa3, 0, 0, 6) // shl-long
	a.bin23x(0xa4, 0, 0, 6) // shr-long
	a.bin23x(0xa5, 0, 0, 6) // ushr-long
	a.constWide16(6, 3)
	a.bin23x(0x9e, 0, 0, 6) // div-long
	a.bin23x(0x9f, 0, 0, 6) // rem-long
	a.bin23x(0x9d, 0, 0, 6) // mul-long
	a.unary12x(0x7d, 0, 0)  // neg-long
	a.unary12x(0x7e, 0, 0)  // not-long
	a.cmpLong(8, 0, 2)      // cmp-long
	a.unary12x(0x83, 9, 0)  // long-to-int
	a.bin23x(0x90, 9, 9, 8)
	a.unary12x(0x81, 8, 9) // int-to-long（宽值 v8/v9）
	a.bin23x(0x9b, 0, 0, 2)
	a.bin23x(0x9c, 0, 0, 8)
	a.returnWide(0)
	return fixMethod{Name: "longops", Ret: "J", Params: []string{"J", "J"}, Access: static(dex.ProtoSpec{}), Code: a.assemble(10, 4, 0)}
}

func fixtureLongConv() fixMethod {
	a := newWA()
	a.unary12x(0x83, 2, 0) // long-to-int v2, v0
	a.unary12x(0x81, 0, 2) // int-to-long v0, v2
	a.constWide16(2, 5)
	a.bin23x(0x9b, 0, 0, 2)
	a.returnWide(0)
	return fixMethod{Name: "longconv", Ret: "J", Params: []string{"J"}, Access: static(dex.ProtoSpec{}), Code: a.assemble(4, 2, 0)}
}

func fixtureSumLoop() fixMethod {
	a := newWA()
	a.const4(1, 0)
	a.const4(2, 0)
	a.label("loop")
	a.ifGe(2, 0, "end")
	a.bin23x(0x90, 1, 1, 2)
	a.lit8(0xd8, 2, 2, 1)
	a.goto10("loop")
	a.label("end")
	a.returnReg(1)
	return fixMethod{Name: "sumloop", Ret: "I", Params: []string{"I"}, Access: static(dex.ProtoSpec{}), Code: a.assemble(3, 1, 0)}
}

// 每个条件分支一条独立方法，返回值 1/0 表示是否走分支。
func branchFixture(name string, dexOp byte, z bool) fixMethod {
	a := newWA()
	if z {
		a.ifOpZ(dexOp, 0, "t")
	} else {
		a.ifOp(dexOp, 0, 1, "t")
	}
	a.const4(2, 0)
	a.returnReg(2)
	a.label("t")
	a.const4(2, 1)
	a.returnReg(2)
	var params []string
	if z {
		params = []string{"I"}
	} else {
		params = []string{"I", "I"}
	}
	return fixMethod{Name: name, Ret: "I", Params: params, Access: static(dex.ProtoSpec{}), Code: a.assemble(3, len(params), 0)}
}

// gotosFixture 用 10t/20t/30t 三种宽度的 goto 串起来。
func fixtureGotos() fixMethod {
	a := newWA()
	a.const4(0, 0)
	a.goto10("l1")
	a.const4(0, 99) // 不可达
	a.label("l1")
	a.lit8(0xd8, 0, 0, 1)
	a.goto16("l2")
	a.const4(0, 99)
	a.label("l2")
	a.lit8(0xd8, 0, 0, 1)
	a.goto32("l3")
	a.const4(0, 99)
	a.label("l3")
	a.lit8(0xd8, 0, 0, 1)
	a.returnReg(0)
	return fixMethod{Name: "gotos", Ret: "I", Access: static(dex.ProtoSpec{}), Code: a.assemble(2, 0, 0)}
}

func fixtureMoveInt() fixMethod {
	a := newWA()
	a._mov(1, 0)
	a.moveFrom16(2, 1)
	a.move16(3, 2)
	a.returnReg(3)
	return fixMethod{Name: "moveint", Ret: "I", Params: []string{"I"}, Access: static(dex.ProtoSpec{}), Code: a.assemble(4, 1, 0)}
}

func fixtureMoveWide() fixMethod {
	a := newWA()
	a.moveWide(4, 0)
	a.moveWideFrom16(6, 4)
	a.moveWide16(0, 6)
	a.returnWide(0)
	return fixMethod{Name: "movewide", Ret: "J", Params: []string{"J"}, Access: static(dex.ProtoSpec{}), Code: a.assemble(8, 2, 0)}
}

func fixtureMoveObject() fixMethod {
	a := newWA()
	a.moveObject(1, 0)
	a.moveObjectFrom16(2, 1)
	a.moveObject16(3, 2)
	a.returnObject(3)
	return fixMethod{Name: "moveobj", Ret: "Ltest/Holder;", Params: []string{"Ltest/Holder;"}, Access: static(dex.ProtoSpec{}), Code: a.assemble(4, 1, 0)}
}

func fixtureCallStatic() fixMethod {
	a := newWA()
	a.invoke35c(0x71, []int{0, 1}, dex.MethodSpec{Class: fixtureClass, Name: "mix", Proto: dex.ProtoSpec{Ret: "I", Params: []string{"I", "I"}}})
	a.moveResult(0)
	a.returnReg(0)
	return fixMethod{Name: "callstatic", Ret: "I", Params: []string{"I", "I"}, Access: static(dex.ProtoSpec{}), Code: a.assemble(4, 2, 2)}
}

func fixtureCallFive() fixMethod {
	a := newWA()
	m := dex.MethodSpec{Class: fixtureClass, Name: "sum5", Proto: dex.ProtoSpec{Ret: "I", Params: []string{"I", "I", "I", "I", "I"}}}
	a.invoke35c(0x71, []int{0, 1, 2, 3, 4}, m)
	a.moveResult(0)
	a.returnReg(0)
	return fixMethod{Name: "callfive", Ret: "I", Params: []string{"I", "I", "I", "I", "I"}, Access: static(dex.ProtoSpec{}), Code: a.assemble(6, 5, 5)}
}

func fixtureSum5() fixMethod {
	a := newWA()
	a.const4(5, 0)
	a.bin23x(0x90, 5, 5, 0)
	a.bin23x(0x90, 5, 5, 1)
	a.bin23x(0x90, 5, 5, 2)
	a.bin23x(0x90, 5, 5, 3)
	a.bin23x(0x90, 5, 5, 4)
	a.returnReg(5)
	return fixMethod{Name: "sum5", Ret: "I", Params: []string{"I", "I", "I", "I", "I"}, Access: static(dex.ProtoSpec{}), Code: a.assemble(6, 5, 0)}
}

func fixtureCallRange() fixMethod {
	a := newWA()
	a.invoke3rc(0x77, 0, 2, dex.MethodSpec{Class: fixtureClass, Name: "mix", Proto: dex.ProtoSpec{Ret: "I", Params: []string{"I", "I"}}})
	a.moveResult(0)
	a.returnReg(0)
	return fixMethod{Name: "callrange", Ret: "I", Params: []string{"I", "I"}, Access: static(dex.ProtoSpec{}), Code: a.assemble(4, 2, 2)}
}

func fixtureCallDirect() fixMethod {
	a := newWA()
	a.invoke35c(0x70, []int{0, 1}, dex.MethodSpec{Class: fixtureClass, Name: "direct", Proto: dex.ProtoSpec{Ret: "I", Params: []string{"I"}}})
	a.moveResult(0)
	a.returnReg(0)
	return fixMethod{Name: "calldirect", Ret: "I", Params: []string{fixtureClass, "I"}, Access: static(dex.ProtoSpec{}), Code: a.assemble(4, 2, 2)}
}

func fixtureCallDirectRange() fixMethod {
	a := newWA()
	a.invoke3rc(0x76, 0, 2, dex.MethodSpec{Class: fixtureClass, Name: "direct", Proto: dex.ProtoSpec{Ret: "I", Params: []string{"I"}}})
	a.moveResult(0)
	a.returnReg(0)
	return fixMethod{Name: "calldirectR", Ret: "I", Params: []string{fixtureClass, "I"}, Access: static(dex.ProtoSpec{}), Code: a.assemble(4, 2, 2)}
}

func fixtureDirect() fixMethod {
	a := newWA()
	a.bin23x(0x90, 0, 2, 2)
	a.returnReg(0)
	return fixMethod{Name: "direct", Ret: "I", Params: []string{"I"}, Access: 0x2, Code: a.assemble(3, 2, 0)}
}

func fixtureCallVirt() fixMethod {
	a := newWA()
	a.invoke35c(0x6e, []int{0}, dex.MethodSpec{Class: "Ljava/lang/String;", Name: "length", Proto: dex.ProtoSpec{Ret: "I"}})
	a.moveResult(0)
	a.returnReg(0)
	return fixMethod{Name: "callvirt", Ret: "I", Params: []string{"Ljava/lang/String;"}, Access: static(dex.ProtoSpec{}), Code: a.assemble(2, 1, 1)}
}

func fixtureCallVirtRange() fixMethod {
	a := newWA()
	a.invoke3rc(0x74, 0, 1, dex.MethodSpec{Class: "Ljava/lang/String;", Name: "length", Proto: dex.ProtoSpec{Ret: "I"}})
	a.moveResult(0)
	a.returnReg(0)
	return fixMethod{Name: "callvirtR", Ret: "I", Params: []string{"Ljava/lang/String;"}, Access: static(dex.ProtoSpec{}), Code: a.assemble(2, 1, 1)}
}

func fixtureCallSuper() fixMethod {
	a := newWA()
	a.invoke35c(0x6f, []int{0}, dex.MethodSpec{Class: "Ljava/lang/Object;", Name: "hashCode", Proto: dex.ProtoSpec{Ret: "I"}})
	a.moveResult(0)
	a.returnReg(0)
	return fixMethod{Name: "callsuper", Ret: "I", Params: []string{"Ljava/lang/Object;"}, Access: static(dex.ProtoSpec{}), Code: a.assemble(2, 1, 1)}
}

func fixtureCallSuperRange() fixMethod {
	a := newWA()
	a.invoke3rc(0x75, 0, 1, dex.MethodSpec{Class: "Ljava/lang/Object;", Name: "hashCode", Proto: dex.ProtoSpec{Ret: "I"}})
	a.moveResult(0)
	a.returnReg(0)
	return fixMethod{Name: "callsuperR", Ret: "I", Params: []string{"Ljava/lang/Object;"}, Access: static(dex.ProtoSpec{}), Code: a.assemble(2, 1, 1)}
}

func fixtureCallIface() fixMethod {
	a := newWA()
	a.invoke35c(0x72, []int{0}, dex.MethodSpec{Class: "Ljava/util/List;", Name: "size", Proto: dex.ProtoSpec{Ret: "I"}})
	a.moveResult(0)
	a.returnReg(0)
	return fixMethod{Name: "calliface", Ret: "I", Params: []string{"Ljava/util/List;"}, Access: static(dex.ProtoSpec{}), Code: a.assemble(2, 1, 1)}
}

func fixtureCallIfaceRange() fixMethod {
	a := newWA()
	a.invoke3rc(0x78, 0, 1, dex.MethodSpec{Class: "Ljava/util/List;", Name: "size", Proto: dex.ProtoSpec{Ret: "I"}})
	a.moveResult(0)
	a.returnReg(0)
	return fixMethod{Name: "callifaceR", Ret: "I", Params: []string{"Ljava/util/List;"}, Access: static(dex.ProtoSpec{}), Code: a.assemble(2, 1, 1)}
}

func fixtureCallWide() fixMethod {
	a := newWA()
	a.invoke35c(0x71, []int{0, 1}, dex.MethodSpec{Class: fixtureClass, Name: "lwide", Proto: dex.ProtoSpec{Ret: "J", Params: []string{"J"}}})
	a.moveResultWide(0)
	a.returnWide(0)
	return fixMethod{Name: "callwide", Ret: "J", Params: []string{"J"}, Access: static(dex.ProtoSpec{}), Code: a.assemble(4, 2, 2)}
}

func fixtureLWide() fixMethod {
	a := newWA()
	a.constWide16(2, 3)
	a.bin23x(0x9d, 0, 0, 2) // mul-long
	a.returnWide(0)
	return fixMethod{Name: "lwide", Ret: "J", Params: []string{"J"}, Access: static(dex.ProtoSpec{}), Code: a.assemble(4, 2, 0)}
}

// fixtureCallComputedWide 先在方法内算出 long 再把它当参数传给调用。
//
// 这是宽值表示一致性的回归用例：宽值必须在寄存器里占两个相邻槽
// （低字在前），任何「只写单槽/只读单槽」的实现都会在这里丢高 32 位。
// 只是把形参原样传出去测不出这个问题（形参入口处恰好就是两槽布局）。
func fixtureCallComputedWide() fixMethod {
	a := newWA()
	a.constWide16(2, 7)
	a.bin23x(0x9b, 0, 0, 2) // add-long v0, v0, v2（v0/v1 是 long 形参）
	m := dex.MethodSpec{Class: fixtureClass, Name: "lwide", Proto: dex.ProtoSpec{Ret: "J", Params: []string{"J"}}}
	a.invoke35c(0x71, []int{0, 1}, m)
	a.moveResultWide(0)
	a.returnWide(0)
	return fixMethod{Name: "callcw", Ret: "J", Params: []string{"J"}, Access: static(dex.ProtoSpec{}), Code: a.assemble(4, 2, 2)}
}

// fixtureCmpLongDstLast 覆盖 cmp-long 的特殊寄存器布局：目标是 32 位 int
// （可以落在最后一个寄存器），两个源才是宽值。
//
// 校验器若把 cmp-long 的目标也当宽值（需要相邻的高字），会在
// `cmp-long v4, v2, v0` + registers=5 这种完全合法的 DEX 上误报
// 「宽寄存器越界」——RustDesk 的真实方法就是这样被拒掉的。
func fixtureCmpLongDstLast() fixMethod {
	a := newWA()
	a.cmpLong(4, 2, 0)
	a.returnReg(4)
	return fixMethod{Name: "cmpdst", Ret: "I", Params: []string{"J", "J"}, Access: static(dex.ProtoSpec{}), Code: a.assemble(5, 4, 0)}
}

// fixtureVoidZeroRegs 覆盖 registers=0 的静态 void 方法（只有 return-void）。
// 真实应用里编译器大量生成这种空方法，早期校验把它当非法直接拒绝了。
func fixtureVoidZeroRegs() fixMethod {
	a := newWA()
	a.returnVoid()
	return fixMethod{Name: "void0", Ret: "V", Access: static(dex.ProtoSpec{}), Code: a.assemble(0, 0, 0)}
}

func fixtureStrConst() fixMethod {
	a := newWA()
	a.constString(0, "hello-中文")
	a.returnObject(0)
	return fixMethod{Name: "strconst", Ret: "Ljava/lang/String;", Access: static(dex.ProtoSpec{}), Code: a.assemble(1, 0, 0)}
}

func fixtureStrConcat() fixMethod {
	a := newWA()
	a.constStringShort(1, "-x")
	m := dex.MethodSpec{Class: "Ljava/lang/String;", Name: "concat", Proto: dex.ProtoSpec{Ret: "Ljava/lang/String;", Params: []string{"Ljava/lang/String;"}}}
	a.invoke35c(0x6e, []int{0, 1}, m)
	a.moveResultObject(2)
	a.returnObject(2)
	return fixMethod{Name: "strconcat", Ret: "Ljava/lang/String;", Params: []string{"Ljava/lang/String;"}, Access: static(dex.ProtoSpec{}), Code: a.assemble(3, 1, 2)}
}

func fixtureFields() fixMethod {
	a := newWA()
	f := func(name, typ string) dex.FieldSpec {
		return dex.FieldSpec{Class: "Ltest/Holder;", Name: name, Type: typ}
	}
	a.field22c(0x52, 1, 0, f("i", "I"))
	a.field22c(0x53, 2, 0, f("w", "J"))
	a.field22c(0x54, 4, 0, f("s", "Ljava/lang/String;"))
	a.field22c(0x55, 5, 0, f("b", "Z"))
	a.field22c(0x56, 6, 0, f("by", "B"))
	a.field22c(0x57, 7, 0, f("ch", "C"))
	a.field22c(0x58, 8, 0, f("sh", "S"))
	a.unary12x(0x83, 9, 2) // long-to-int
	a.bin23x(0x90, 1, 1, 9)
	a.bin23x(0x90, 1, 1, 5)
	a.bin23x(0x90, 1, 1, 6)
	a.bin23x(0x90, 1, 1, 7)
	a.bin23x(0x90, 1, 1, 8)
	a.const4(10, 5)
	a.field22c(0x59, 10, 0, f("i", "I"))
	a.field22c(0x5a, 2, 0, f("w", "J"))
	a.field22c(0x5b, 4, 0, f("s", "Ljava/lang/String;"))
	a.const4(11, 1)
	a.field22c(0x5c, 11, 0, f("b", "Z"))
	a.field22c(0x5d, 11, 0, f("by", "B"))
	a.field22c(0x5e, 11, 0, f("ch", "C"))
	a.field22c(0x5f, 11, 0, f("sh", "S"))
	a.bin23x(0x90, 1, 1, 11)
	a.bin23x(0x90, 1, 1, 1)
	a.returnReg(1)
	return fixMethod{Name: "fields", Ret: "I", Params: []string{"Ltest/Holder;", "I"}, Access: static(dex.ProtoSpec{}), Code: a.assemble(12, 2, 0)}
}

func fixtureStatics() fixMethod {
	a := newWA()
	f := func(name, typ string) dex.FieldSpec {
		return dex.FieldSpec{Class: "Ltest/Holder;", Name: name, Type: typ}
	}
	a.field21c(0x60, 1, f("si", "I"))
	a.field21c(0x61, 2, f("sw", "J"))
	a.field21c(0x62, 4, f("ss", "Ljava/lang/String;"))
	a.field21c(0x63, 5, f("sb", "Z"))
	a.field21c(0x64, 6, f("sby", "B"))
	a.field21c(0x65, 7, f("sch", "C"))
	a.field21c(0x66, 8, f("ssh", "S"))
	a.unary12x(0x83, 9, 2) // long-to-int
	a.bin23x(0x90, 1, 1, 9)
	a.bin23x(0x90, 1, 1, 5)
	a.bin23x(0x90, 1, 1, 6)
	a.bin23x(0x90, 1, 1, 7)
	a.bin23x(0x90, 1, 1, 8)
	a.const4(10, 1)
	a.field21c(0x67, 10, f("si", "I"))
	a.field21c(0x68, 2, f("sw", "J"))
	a.field21c(0x69, 4, f("ss", "Ljava/lang/String;"))
	a.field21c(0x6a, 10, f("sb", "Z"))
	a.field21c(0x6b, 10, f("sby", "B"))
	a.field21c(0x6c, 10, f("sch", "C"))
	a.field21c(0x6d, 10, f("ssh", "S"))
	a.bin23x(0x90, 1, 1, 10)
	a.returnReg(1)
	return fixMethod{Name: "statics", Ret: "I", Params: []string{"I"}, Access: static(dex.ProtoSpec{}), Code: a.assemble(11, 1, 0)}
}

func fixtureRetVoid() fixMethod {
	a := newWA()
	a.const4(0, 1)
	a.returnVoid()
	return fixMethod{Name: "retvoid", Ret: "V", Params: []string{"I"}, Access: static(dex.ProtoSpec{}), Code: a.assemble(1, 1, 0)}
}

func fixtureInstance() fixMethod {
	a := newWA()
	a.field22c(0x52, 0, 1, dex.FieldSpec{Class: "Ltest/Holder;", Name: "i", Type: "I"})
	a.bin23x(0x90, 0, 0, 2)
	a.returnReg(0)
	return fixMethod{Name: "inst", Ret: "I", Params: []string{"I"}, Access: 0x1, Code: a.assemble(3, 2, 0)}
}

func allFixtures() []fixMethod {
	ms := []fixMethod{
		fixtureMix(), fixtureDivRem(), fixtureLitOps(), fixtureConvs(), fixtureLongOps(),
		fixtureLongConv(), fixtureSumLoop(), fixtureGotos(), fixtureMoveInt(), fixtureMoveWide(),
		fixtureMoveObject(), fixtureCallStatic(), fixtureCallFive(), fixtureSum5(), fixtureCallRange(),
		fixtureCallDirect(), fixtureCallDirectRange(), fixtureDirect(), fixtureCallVirt(), fixtureCallVirtRange(),
		fixtureCallSuper(), fixtureCallSuperRange(), fixtureCallIface(), fixtureCallIfaceRange(),
		fixtureCallWide(), fixtureLWide(), fixtureCallComputedWide(), fixtureCmpLongDstLast(),
		fixtureVoidZeroRegs(), fixtureStrConst(), fixtureStrConcat(),
		fixtureFields(), fixtureStatics(), fixtureRetVoid(), fixtureInstance(),
	}
	// 12 条条件分支各一个方法。
	for _, b := range []struct {
		name string
		op   byte
		z    bool
	}{
		{"ifEq", 0x32, false}, {"ifNe", 0x33, false}, {"ifLt", 0x34, false},
		{"ifGe", 0x35, false}, {"ifGt", 0x36, false}, {"ifLe", 0x37, false},
		{"ifEqz", 0x38, true}, {"ifNez", 0x39, true}, {"ifLtz", 0x3a, true},
		{"ifGez", 0x3b, true}, {"ifGtz", 0x3c, true}, {"ifLez", 0x3d, true},
	} {
		ms = append(ms, branchFixture(b.name, b.op, b.z))
	}
	return ms
}

// ifOpZ 是 z 变体分支的发射辅助（22t 的 z 形式实为 21t）。
func (a *wa) ifOpZ(op byte, r int, l string) { a.ifzOp(op, r, l) }

// ---- 对拍环境 ----

type diffEnv struct {
	t     *testing.T
	f     *dex.File
	dex   *dexRunner
	progs map[string]*vmp.Program
	dexRt *mockRuntime
	vmRt  *mockRuntime
}

func newDiffEnv(t *testing.T) *diffEnv {
	t.Helper()
	methods := allFixtures()
	f := buildFixture(t, methods)
	sel := vmp.Select(f, "fixture.dex", len(methods)+10)
	if n := len(sel.Programs); n != len(methods) {
		t.Fatalf("fixture 方法应全部被选中，实际 %d/%d；跳过明细: %s", n, len(methods), sel.ReasonReport())
	}
	progs := map[string]*vmp.Program{}
	for _, p := range sel.Programs {
		progs[p.Sig()] = p
	}
	dexR := newDexRunner(t, f, fixtureClass, methods)
	env := &diffEnv{t: t, f: f, dex: dexR, progs: progs, dexRt: newMockRuntime(), vmRt: newMockRuntime()}
	dexR.rt = env.dexRt
	env.seed(env.dexRt)
	env.seed(env.vmRt)
	// 外部调用的 mock。
	external := func(rt *mockRuntime) {
		rt.on("Ljava/lang/String;->length()I", func(args []vmp.Value) (vmp.Value, error) {
			s, ok := args[0].Ref.(*mockStr)
			if !ok {
				return vmp.Value{}, fmt.Errorf("length 接收者不是字符串")
			}
			return vmp.Int(int32(len([]rune(s.text)))), nil
		})
		rt.on("Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;", func(args []vmp.Value) (vmp.Value, error) {
			a, ok1 := args[0].Ref.(*mockStr)
			b, ok2 := args[1].Ref.(*mockStr)
			if !ok1 || !ok2 {
				return vmp.Value{}, fmt.Errorf("concat 参数不是字符串")
			}
			return vmp.Ref(&mockStr{text: a.text + b.text}), nil
		})
		rt.on("Ljava/lang/Object;->hashCode()I", func(args []vmp.Value) (vmp.Value, error) {
			return vmp.Int(42), nil
		})
		rt.on("Ljava/util/List;->size()I", func(args []vmp.Value) (vmp.Value, error) {
			return vmp.Int(3), nil
		})
	}
	external(env.dexRt)
	external(env.vmRt)
	// fixture 内部调用：各自路由回本侧的执行器（保证嵌套调用也被对拍）。
	for _, m := range methods {
		sig := fixtureClass + "->" + m.Name + dex.BuildProtoDesc(m.Ret, m.Params)
		msig := sig
		env.dexRt.on(msig, func(args []vmp.Value) (vmp.Value, error) {
			return env.dex.run(t, msig, args)
		})
		env.vmRt.on(msig, func(args []vmp.Value) (vmp.Value, error) {
			return env.runVM(msig, args)
		})
	}
	return env
}

// seed 预置两侧一致的静态字段/对象初始状态。
func (e *diffEnv) seed(rt *mockRuntime) {
	h := rt.staticFor("Ltest/Holder;")
	h.ints["si"] = 7
	h.wides["sw"] = 100
	h.ints["sb"] = 1
	h.ints["sby"] = -3
	h.ints["sch"] = 65
	h.ints["ssh"] = -9
}

func (e *diffEnv) runVM(sig string, args []vmp.Value) (vmp.Value, error) {
	p, ok := e.progs[sig]
	if !ok {
		return vmp.Value{}, fmt.Errorf("未知程序 %s", sig)
	}
	return p.Run(e.vmRt, args)
}

// compare 对一种实参组合做两侧对拍。
func (e *diffEnv) compare(sig string, args ...vmp.Value) {
	e.t.Helper()
	// 每次用例都重置两侧静态区，保证初始状态一致；对象参数深拷贝，
	// 避免一侧的 iput 污染另一侧看到的初始状态。
	e.seed(e.dexRt)
	e.seed(e.vmRt)
	dv, derr := e.dex.run(e.t, sig, cloneArgs(args))
	vv, verr := e.runVM(sig, cloneArgs(args))
	if (derr == nil) != (verr == nil) {
		e.t.Fatalf("%s%v: 错误行为不一致 DEX=%v VM=%v", sig, args, derr, verr)
	}
	if derr != nil {
		return
	}
	if got, want := repr(vv), repr(dv); got != want {
		e.t.Fatalf("%s%v: 结果不一致 VM=%s DEX=%s", sig, args, got, want)
	}
}

// cloneArgs 深拷贝 mock 对象参数（mockStr 不可变，可共享）。
func cloneArgs(args []vmp.Value) []vmp.Value {
	out := make([]vmp.Value, len(args))
	for i, a := range args {
		if o, ok := a.Ref.(*mockObj); ok {
			c := newMockObj(o.desc)
			for k, v := range o.ints {
				c.ints[k] = v
			}
			for k, v := range o.wides {
				c.wides[k] = v
			}
			for k, v := range o.refs {
				c.refs[k] = v
			}
			out[i] = vmp.Ref(c)
			continue
		}
		out[i] = a
	}
	return out
}

// ---- 测试 ----

func TestDifferentialAllFixtures(t *testing.T) {
	env := newDiffEnv(t)

	ipairs := [][2]int32{
		{0, 0}, {1, 1}, {-1, 1}, {7, 3}, {-7, 3},
		{2147483647, -2147483648}, {-2147483648, -1}, {123456789, -987654321},
		{0, 5}, {-1, 0}, {255, 256},
	}
	for _, p := range ipairs {
		env.compare(fixtureClass+"->mix(II)I", vmp.Int(p[0]), vmp.Int(p[1]))
		env.compare(fixtureClass+"->litops(II)I", vmp.Int(p[0]), vmp.Int(p[1]))
	}
	for _, p := range [][2]int32{
		{1, 1}, {-1, 1}, {7, 3}, {-7, 3}, {2147483647, 3}, {-2147483648, -1}, {100, -7}, {-100, 7},
	} {
		env.compare(fixtureClass+"->divrem(II)I", vmp.Int(p[0]), vmp.Int(p[1]))
	}
	for _, x := range []int32{0, 1, -1, 127, 128, -128, 255, 256, 32767, -32768, 65535, 65536, 2147483647, -2147483648} {
		env.compare(fixtureClass+"->convs(I)J", vmp.Int(x))
		env.compare(fixtureClass+"->longconv(J)J", vmp.Wide(int64(x)))
		env.compare(fixtureClass+"->moveint(I)I", vmp.Int(x))
	}
	jpairs := [][2]int64{
		{0, 0}, {1, 2}, {-1, 3}, {1 << 40, 7}, {-(1 << 40), -7},
		{0x7fffffffffffffff, -1}, {-1 << 62, 5}, {123456789012345, -9876543210},
	}
	for _, p := range jpairs {
		env.compare(fixtureClass+"->longops(JJ)J", vmp.Wide(p[0]), vmp.Wide(p[1]))
	}
	for _, x := range []int64{0, 1, -1, 1 << 40, -(1 << 40), 0x7fffffffffffffff, -1 << 62} {
		env.compare(fixtureClass+"->movewide(J)J", vmp.Wide(x))
	}
	for _, n := range []int32{0, 1, 2, 5, 8, 13, -3} {
		env.compare(fixtureClass+"->sumloop(I)I", vmp.Int(n))
	}
	env.compare(fixtureClass + "->gotos()I")
	for _, c := range []struct {
		sig  string
		args []vmp.Value
	}{
		{"ifEq(II)I", []vmp.Value{vmp.Int(3), vmp.Int(3)}},
		{"ifEq(II)I", []vmp.Value{vmp.Int(3), vmp.Int(4)}},
		{"ifNe(II)I", []vmp.Value{vmp.Int(3), vmp.Int(3)}},
		{"ifNe(II)I", []vmp.Value{vmp.Int(3), vmp.Int(4)}},
		{"ifLt(II)I", []vmp.Value{vmp.Int(-5), vmp.Int(3)}},
		{"ifLt(II)I", []vmp.Value{vmp.Int(5), vmp.Int(-3)}},
		{"ifGe(II)I", []vmp.Value{vmp.Int(5), vmp.Int(5)}},
		{"ifGe(II)I", []vmp.Value{vmp.Int(4), vmp.Int(5)}},
		{"ifGt(II)I", []vmp.Value{vmp.Int(5), vmp.Int(4)}},
		{"ifGt(II)I", []vmp.Value{vmp.Int(4), vmp.Int(5)}},
		{"ifLe(II)I", []vmp.Value{vmp.Int(5), vmp.Int(5)}},
		{"ifLe(II)I", []vmp.Value{vmp.Int(6), vmp.Int(5)}},
		{"ifEqz(I)I", []vmp.Value{vmp.Int(0)}},
		{"ifEqz(I)I", []vmp.Value{vmp.Int(1)}},
		{"ifNez(I)I", []vmp.Value{vmp.Int(1)}},
		{"ifNez(I)I", []vmp.Value{vmp.Int(0)}},
		{"ifLtz(I)I", []vmp.Value{vmp.Int(-1)}},
		{"ifLtz(I)I", []vmp.Value{vmp.Int(0)}},
		{"ifGez(I)I", []vmp.Value{vmp.Int(0)}},
		{"ifGez(I)I", []vmp.Value{vmp.Int(-1)}},
		{"ifGtz(I)I", []vmp.Value{vmp.Int(1)}},
		{"ifGtz(I)I", []vmp.Value{vmp.Int(0)}},
		{"ifLez(I)I", []vmp.Value{vmp.Int(0)}},
		{"ifLez(I)I", []vmp.Value{vmp.Int(1)}},
	} {
		env.compare(fixtureClass+"->"+c.sig, c.args...)
	}

	// 调用形态。
	env.compare(fixtureClass+"->callstatic(II)I", vmp.Int(11), vmp.Int(-4))
	env.compare(fixtureClass+"->callrange(II)I", vmp.Int(11), vmp.Int(-4))
	env.compare(fixtureClass+"->calldirect("+fixtureClass+"I)I", vmp.Ref(newMockObj(fixtureClass)), vmp.Int(-4))
	env.compare(fixtureClass+"->calldirectR("+fixtureClass+"I)I", vmp.Ref(newMockObj(fixtureClass)), vmp.Int(-4))
	env.compare(fixtureClass+"->callfive(IIIII)I", vmp.Int(1), vmp.Int(2), vmp.Int(3), vmp.Int(4), vmp.Int(5))
	env.compare(fixtureClass+"->callwide(J)J", vmp.Wide(1<<40+7))
	for _, x := range []int64{0, 1, -1, 1 << 40, -(1 << 40), 0x7fffffffffffffff} {
		env.compare(fixtureClass+"->callcw(J)J", vmp.Wide(x))
	}
	// cmp-long 目标落在最后一个寄存器（合法：目标是 32 位 int）。
	for _, p := range [][2]int64{{1, 2}, {2, 1}, {5, 5}, {-1 << 40, 1}, {0, 0}} {
		env.compare(fixtureClass+"->cmpdst(JJ)I", vmp.Wide(p[0]), vmp.Wide(p[1]))
	}
	env.compare(fixtureClass+"->callvirt(Ljava/lang/String;)I", vmp.Ref(&mockStr{text: "abcdef"}))
	env.compare(fixtureClass+"->callvirtR(Ljava/lang/String;)I", vmp.Ref(&mockStr{text: "abcdef"}))
	env.compare(fixtureClass+"->callsuper(Ljava/lang/Object;)I", vmp.Ref(newMockObj("Ljava/lang/Object;")))
	env.compare(fixtureClass+"->callsuperR(Ljava/lang/Object;)I", vmp.Ref(newMockObj("Ljava/lang/Object;")))
	env.compare(fixtureClass+"->calliface(Ljava/util/List;)I", vmp.Ref(newMockObj("Ljava/util/List;")))
	env.compare(fixtureClass+"->callifaceR(Ljava/util/List;)I", vmp.Ref(newMockObj("Ljava/util/List;")))
	env.compare(fixtureClass + "->strconst()Ljava/lang/String;")
	env.compare(fixtureClass+"->strconcat(Ljava/lang/String;)Ljava/lang/String;", vmp.Ref(&mockStr{text: "abc"}))

	// 字段。
	h := func() *mockObj {
		o := newMockObj("Ltest/Holder;")
		o.ints["i"], o.ints["b"], o.ints["by"], o.ints["ch"], o.ints["sh"] = -7, 1, -5, 0xffff, -300
		o.wides["w"] = 1<<40 + 9
		o.refs["s"] = &mockStr{text: "field"}
		return o
	}
	env.compare(fixtureClass+"->fields(Ltest/Holder;I)I", vmp.Ref(h()), vmp.Int(100))
	env.compare(fixtureClass+"->statics(I)I", vmp.Int(-3))
	env.compare(fixtureClass+"->retvoid(I)V", vmp.Int(1))
	env.compare(fixtureClass + "->void0()V")
	env.compare(fixtureClass+"->inst(I)I", vmp.Ref(h()), vmp.Int(5))
	env.compare(fixtureClass+"->moveobj(Ltest/Holder;)Ltest/Holder;", vmp.Ref(h()))
}

// TestEverySupportedDexOpcodeUsed 断言「声明支持的 DEX 操作码」全部被 fixture 覆盖。
//
// 如果没有这条断言，翻译器里某个 case 分支可能永远是死代码——覆盖率报告里
// 写着「支持 add-long」，实际从未验证过。
func TestEverySupportedDexOpcodeUsed(t *testing.T) {
	methods := allFixtures()
	f := buildFixture(t, methods)
	seen := map[byte]int{}
	for _, m := range methods {
		for i := 0; i < len(m.Code.Insns); {
			op := byte(m.Code.Insns[i] & 0xff)
			seen[op]++
			i += dexInsnWidth(op)
		}
	}
	declared := []byte{
		0x00,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
		0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
		0x28, 0x29, 0x2a, 0x31,
		0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
		0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
		0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
		0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
		0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d,
		0x6e, 0x6f, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78,
		0x7b, 0x7c, 0x7d, 0x7e, 0x81, 0x83, 0x8d, 0x8e, 0x8f,
		0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a,
		0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5,
		0xd0, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2,
	}
	var missing []string
	for _, op := range declared {
		if seen[op] == 0 {
			missing = append(missing, fmt.Sprintf("0x%02x", op))
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("以下声明支持的 DEX 操作码未被任何 fixture 覆盖: %v", missing)
	}
	_ = f
}

// TestEveryPrivateOpcodeUsed 断言翻译结果覆盖全部私有操作码（除却不可达者）。
func TestEveryPrivateOpcodeUsed(t *testing.T) {
	methods := allFixtures()
	f := buildFixture(t, methods)
	sel := vmp.Select(f, "fixture.dex", len(methods)+1)
	seen := map[uint8]int{}
	for _, p := range sel.Programs {
		for pc := 0; pc < len(p.Code); {
			op := uint8(p.Code[pc])
			seen[op]++
			pc += privateWidth(p.Code, pc)
		}
	}
	declared := []uint8{
		vmp.OpNop,
		vmp.OpMove, vmp.OpMoveWide, vmp.OpMoveObject, vmp.OpConst, vmp.OpConstWide,
		vmp.OpConstString, vmp.OpMoveResult, vmp.OpMoveResultWide, vmp.OpMoveResultObject,
		vmp.OpNegInt, vmp.OpNotInt, vmp.OpNegLong, vmp.OpNotLong,
		vmp.OpI2B, vmp.OpI2C, vmp.OpI2S, vmp.OpI2L, vmp.OpL2I,
		vmp.OpAddInt, vmp.OpSubInt, vmp.OpMulInt, vmp.OpDivInt, vmp.OpRemInt,
		vmp.OpAndInt, vmp.OpOrInt, vmp.OpXorInt, vmp.OpShlInt, vmp.OpShrInt, vmp.OpUshrInt,
		vmp.OpAddLong, vmp.OpSubLong, vmp.OpMulLong, vmp.OpDivLong, vmp.OpRemLong,
		vmp.OpAndLong, vmp.OpOrLong, vmp.OpXorLong, vmp.OpShlLong, vmp.OpShrLong, vmp.OpUshrLong,
		vmp.OpCmpLong,
		vmp.OpAddIntImm, vmp.OpMulIntImm, vmp.OpDivIntImm, vmp.OpRemIntImm,
		vmp.OpAndIntImm, vmp.OpOrIntImm, vmp.OpXorIntImm, vmp.OpShlIntImm, vmp.OpShrIntImm, vmp.OpUshrIntImm,
		vmp.OpGoto,
		vmp.OpIfEq, vmp.OpIfNe, vmp.OpIfLt, vmp.OpIfGe, vmp.OpIfGt, vmp.OpIfLe,
		vmp.OpIfEqz, vmp.OpIfNez, vmp.OpIfLtz, vmp.OpIfGez, vmp.OpIfGtz, vmp.OpIfLez,
		vmp.OpIGet, vmp.OpIPut, vmp.OpSGet, vmp.OpSPut,
		vmp.OpIGetWide, vmp.OpIPutWide, vmp.OpSGetWide, vmp.OpSPutWide,
		vmp.OpIGetObject, vmp.OpIPutObject, vmp.OpSGetObject, vmp.OpSPutObject,
		vmp.OpInvokeStatic, vmp.OpInvokeVirtual, vmp.OpInvokeDirect, vmp.OpInvokeSuper, vmp.OpInvokeInterface,
		vmp.OpReturnVoid, vmp.OpReturn, vmp.OpReturnWide, vmp.OpReturnObject,
	}
	var missing []string
	for _, op := range declared {
		if seen[op] == 0 {
			missing = append(missing, fmt.Sprintf("0x%02x", op))
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("以下私有操作码未被翻译结果覆盖（翻译分支可能不可达）: %v", missing)
	}
}

// privateWidth 与实现侧的宽度表一致（测试独立抄一份，防止实现改错后自洽）。
func privateWidth(code []uint32, pc int) int {
	op := uint8(code[pc])
	switch {
	case op == vmp.OpNop || op == vmp.OpMove || op == vmp.OpMoveWide || op == vmp.OpMoveObject ||
		op == vmp.OpMoveResult || op == vmp.OpMoveResultWide || op == vmp.OpMoveResultObject ||
		(op >= vmp.OpNegInt && op <= vmp.OpL2I) ||
		(op >= vmp.OpAddInt && op <= vmp.OpCmpLong) ||
		(op >= vmp.OpReturnVoid && op <= vmp.OpReturnObject):
		return 1
	case op == vmp.OpConst || op == vmp.OpConstString ||
		(op >= vmp.OpAddIntImm && op <= vmp.OpUshrIntImm) ||
		(op >= vmp.OpGoto && op <= vmp.OpIfLez) ||
		(op >= vmp.OpIGet && op <= vmp.OpSPutObject):
		return 2
	case op == vmp.OpConstWide:
		return 3
	case op >= vmp.OpInvokeStatic && op <= vmp.OpInvokeInterface:
		return 2 + (int(code[pc]>>8&0xff)+3)/4
	}
	return 0
}

// dexInsnWidth 是 fixture 用的「已知操作码宽度表」（与实现侧独立抄写）。
func dexInsnWidth(op byte) int {
	switch op {
	case 0x02, 0x05, 0x08, 0x13, 0x16, 0x19, 0x1a, 0x29, 0x31,
		0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
		0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
		0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
		0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
		0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d,
		0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a,
		0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5,
		0xd0, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2:
		return 2
	case 0x03, 0x06, 0x09, 0x14, 0x17, 0x1b, 0x2a,
		0x6e, 0x6f, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78:
		return 3
	case 0x18:
		return 5
	}
	return 1
}
