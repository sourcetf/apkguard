package dex

import (
	"fmt"
	"math/rand"
	"strings"
)

// ClassPadder 描述 A13 类膨胀的参数。
//
// 设计要点：注入的类必须是「真实类」——有字段、有构造器、有带循环的方法体。
// 实测样本的空类率与正常 DEX 相当（4.2%~5.4%），大量空类反而是明显的加固特征，
// 因此这里为每个膨胀类生成 2 个字段与 6 个方法，其中含循环与静态状态。
type ClassPadder struct {
	// Count 是要生成的类数量。
	Count int
	// Seed 决定类名与结构的确定性随机序列；相同种子产生相同结果。
	//
	// 多 DEX 场景下调用者应为每个 DEX 传入不同的 Seed，否则各 DEX 会生成
	// 同名类，运行时出现「类重复定义」。
	Seed string
	// Existing 是「已存在、不可复用」的类描述符集合。
	//
	// 必须包含本 DEX 已有的全部类型，以及本次重建将要新增的类型
	// （如 A2 解密器、A3 还原器）；否则注入类会与既有条目共用 class_idx，
	// 在 class_defs 中形成重复定义。
	Existing map[string]bool
	// Classes 为预先分配好类名的膨胀类。
	//
	// 多 DEX 场景下类名必须全局唯一，而单一 DEX 的视角看不到其它 DEX 的
	// 分配结果，因此由 Pass 层先调用 ClassPadPlan 统一取名，再把结果填回
	// 本字段；非空时直接使用，不再自行生成。
	Classes []ClassPadClass
}

// ClassPadClass 是一个待注入的真实类，附带它自身引用的字段与方法。
type ClassPadClass struct {
	Spec    ClassSpec
	Fields  []FieldSpec
	Methods []MethodSpec
}

// ClassPadKind 表示类名策略。
type ClassPadKind int

// 类名策略：分别对应样本中的三种手法。
const (
	PadDefaultPkg ClassPadKind = iota // 默认包类（无包名）
	PadLongPath                       // 超长类名路径（30+ 层）
	PadNormal                         // 常规包名 + 短名
)

// String 返回策略名。
func (k ClassPadKind) String() string {
	switch k {
	case PadDefaultPkg:
		return "默认包类"
	case PadLongPath:
		return "超长类名路径"
	default:
		return "常规短名"
	}
}

// ClassPadStats 汇总生成结果。
type ClassPadStats struct {
	// Kinds 按策略统计生成的类数量。
	Kinds map[ClassPadKind]int
	// Fields 是生成的字段总数。
	Fields int
	// Methods 是生成的方法总数。
	Methods int
	// Bytes 是类名描述符的总长度（衡量类名膨胀效果）。
	Bytes int
}

// 膨胀类共用的原型与类型。
var (
	padProtoV  = ProtoSpec{Ret: "V"}
	padProtoI  = ProtoSpec{Ret: "I"}
	padProtoVI = ProtoSpec{Ret: "V", Params: []string{"I"}}
	padProtoII = ProtoSpec{Ret: "I", Params: []string{"I"}}

	padObjInit = MethodSpec{Class: "Ljava/lang/Object;", Name: "<init>", Proto: padProtoV}
)

// padMethodNames 是膨胀类使用的方法名（与字段名一起在所有类间复用，
// 从而让新增的 method_ids 条目尽量少，同时类本身仍是「真实」的）。
const (
	padFieldInst  = "f"
	padFieldStat  = "s"
	padMethodGet  = "a"
	padMethodSet  = "b"
	padMethodSum  = "c"
	padMethodBump = "d"
)

// padLongDepth 是超长类名路径的最小层级（样本中最长 30+ 层）。
const padLongDepth = 30

// ClassPadPlan 生成 Count 个真实类。
//
// 返回的类描述符保证互不重复，且不与 cp.Existing 冲突。
func ClassPadPlan(cp *ClassPadder) ([]ClassPadClass, ClassPadStats, error) {
	if len(cp.Classes) > 0 {
		return cp.Classes, ClassPadStatsOf(cp.Classes), nil
	}
	if cp.Count <= 0 {
		return nil, ClassPadStats{}, nil
	}
	r := padRand(cp.Seed)

	used := make(map[string]bool, len(cp.Existing)+cp.Count)
	for k := range cp.Existing {
		used[k] = true
	}

	out := make([]ClassPadClass, 0, cp.Count)
	for len(out) < cp.Count {
		// 三种策略轮转，使类名分布贴近样本（默认包类占多数）。
		//
		// 比例：默认包类 2/3、常规短名 1/3；超长路径类每 10 个里出 1 个
		// ——它的描述符极长，数量过多会显著增大 DEX。
		i := len(out)
		var kind ClassPadKind
		switch {
		case i%10 == 9:
			kind = PadLongPath
		case i%3 == 2:
			kind = PadNormal
		default:
			kind = PadDefaultPkg
		}
		desc := padClassName(r, kind, used)
		if desc == "" {
			return nil, ClassPadStats{}, fmt.Errorf("dex: 连续多次无法生成不冲突的膨胀类名")
		}
		used[desc] = true

		cls, err := padBuildClass(desc)
		if err != nil {
			return nil, ClassPadStats{}, err
		}
		out = append(out, cls)
	}
	return out, ClassPadStatsOf(out), nil
}

// ClassPadStatsOf 统计一批膨胀类的规模。
func ClassPadStatsOf(cls []ClassPadClass) ClassPadStats {
	st := ClassPadStats{Kinds: map[ClassPadKind]int{}}
	for _, c := range cls {
		st.Kinds[padKindOf(c.Spec.Name)]++
		st.Fields += len(c.Fields)
		st.Methods += len(c.Methods)
		st.Bytes += len(c.Spec.Name)
	}
	return st
}

// padKindOf 依据描述符反推它使用的类名策略。
func padKindOf(desc string) ClassPadKind {
	body := strings.TrimSuffix(strings.TrimPrefix(desc, "L"), ";")
	n := strings.Count(body, "/")
	switch {
	case n == 0:
		return PadDefaultPkg
	case n >= padLongDepth:
		return PadLongPath
	default:
		return PadNormal
	}
}

// ClassPadAdditionOf 把一批膨胀类组装成可追加的条目集合。
func ClassPadAdditionOf(cls []ClassPadClass) Addition {
	add := Addition{
		Types:   []string{"I", "V", "Ljava/lang/Object;"},
		Protos:  []ProtoSpec{padProtoV, padProtoI, padProtoVI, padProtoII},
		Methods: []MethodSpec{padObjInit},
	}
	for _, c := range cls {
		add.Types = append(add.Types, c.Spec.Name)
		add.Fields = append(add.Fields, c.Fields...)
		add.Methods = append(add.Methods, c.Methods...)
		add.Classes = append(add.Classes, c.Spec)
	}
	return add
}

// padBuildClass 依据描述符构造一个「真实类」。
//
// 等价 Java 源码：
//
//	public class X {
//	    public int f;
//	    public static int s;
//	    public X() { super(); }
//	    public int a() { return this.f; }
//	    public void b(int v) { this.f = v; }
//	    public static int c(int n) { int r = 0; for (int i = 0; i < n; i++) r += i; return r; }
//	    static { s = 0; }
//	    public static void d() { s++; }
//	}
func padBuildClass(desc string) (ClassPadClass, error) {
	fields := []FieldSpec{
		{Class: desc, Name: padFieldInst, Type: "I"},
		{Class: desc, Name: padFieldStat, Type: "I"},
	}
	inst := fields[0]
	stat := fields[1]

	ctor, err := padCtorCode()
	if err != nil {
		return ClassPadClass{}, err
	}
	get, err := padGetCode(inst)
	if err != nil {
		return ClassPadClass{}, err
	}
	set, err := padSetCode(inst)
	if err != nil {
		return ClassPadClass{}, err
	}
	sum, err := padSumCode()
	if err != nil {
		return ClassPadClass{}, err
	}
	clinit, err := padClinitCode(stat)
	if err != nil {
		return ClassPadClass{}, err
	}
	bump, err := padBumpCode(stat)
	if err != nil {
		return ClassPadClass{}, err
	}

	methods := []MethodSpec{
		{Class: desc, Name: "<init>", Proto: padProtoV},
		{Class: desc, Name: padMethodGet, Proto: padProtoI},
		{Class: desc, Name: padMethodSet, Proto: padProtoVI},
		{Class: desc, Name: padMethodSum, Proto: padProtoII},
		{Class: desc, Name: "<clinit>", Proto: padProtoV},
		{Class: desc, Name: padMethodBump, Proto: padProtoV},
	}

	spec := ClassSpec{
		Name:   desc,
		Super:  "Ljava/lang/Object;",
		Access: accPublic,
		Fields: []ClassField{
			{Name: padFieldInst, Type: "I", Access: accPublic},
			{Name: padFieldStat, Type: "I", Access: accPublic | accStatic},
		},
		Methods: []ClassMethod{
			{Name: "<init>", Proto: padProtoV, Access: accPublic, Code: ctor},
			{Name: padMethodGet, Proto: padProtoI, Access: accPublic, Code: get},
			{Name: padMethodSet, Proto: padProtoVI, Access: accPublic, Code: set},
			{Name: padMethodSum, Proto: padProtoII, Access: accPublic | accStatic, Code: sum},
			{Name: "<clinit>", Proto: padProtoV, Access: accStatic, Code: clinit},
			{Name: padMethodBump, Proto: padProtoV, Access: accPublic | accStatic, Code: bump},
		},
	}
	return ClassPadClass{Spec: spec, Fields: fields, Methods: methods}, nil
}

// padCtorCode 生成构造器：invoke-direct {this}, Object.<init>; return-void。
//
// registers=1、ins=1 → 入参 this 落在 v0。
func padCtorCode() (*CodeBlob, error) {
	a := NewAsm()
	if err := a.InvokeDirect([]int{0}, padObjInit); err != nil {
		return nil, err
	}
	a.ReturnVoid()
	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	return &CodeBlob{Registers: 1, Ins: 1, Outs: 1, Insns: insns, Patches: patches}, nil
}

// padGetCode 生成 a()I：返回实例字段。
func padGetCode(f FieldSpec) (*CodeBlob, error) {
	a := NewAsm()
	if err := a.IGet(0, 0, f); err != nil {
		return nil, err
	}
	a.Return(0)
	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	return &CodeBlob{Registers: 1, Ins: 1, Insns: insns, Patches: patches}, nil
}

// padSetCode 生成 b(I)V：写入实例字段。
//
// registers=2、ins=2 → this 在 v0、入参 v 在 v1。
func padSetCode(f FieldSpec) (*CodeBlob, error) {
	a := NewAsm()
	if err := a.IPut(1, 0, f); err != nil {
		return nil, err
	}
	a.ReturnVoid()
	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	return &CodeBlob{Registers: 2, Ins: 2, Insns: insns, Patches: patches}, nil
}

// padSumCode 生成 c(I)I：带循环的累加，使方法体不是常量折叠可消除的形式。
//
// registers=4、ins=1 → 入参 n 落在 v3；v0=r、v1=i。
func padSumCode() (*CodeBlob, error) {
	a := NewAsm()
	a.Const4(0, 0) // r = 0
	a.Const4(1, 0) // i = 0
	a.Label("loop")
	if err := a.IfGe(1, 3, "end"); err != nil { // if (i >= n) goto end
		return nil, err
	}
	a.AddInt(0, 0, 1) // r += i
	a.AddIntLit8(1, 1)
	a.Goto16("loop")
	a.Label("end")
	a.Return(0)
	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	return &CodeBlob{Registers: 4, Ins: 1, Insns: insns, Patches: patches}, nil
}

// padClinitCode 生成静态初始化块：s = 0。
func padClinitCode(f FieldSpec) (*CodeBlob, error) {
	a := NewAsm()
	a.Const4(0, 0)
	a.SPut(0, f)
	a.ReturnVoid()
	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	return &CodeBlob{Registers: 1, Ins: 0, Insns: insns, Patches: patches}, nil
}

// padBumpCode 生成 d()V：s++，使静态字段具有可观测的状态变化。
func padBumpCode(f FieldSpec) (*CodeBlob, error) {
	a := NewAsm()
	a.SGet(0, f)
	a.AddIntLit8(0, 1)
	a.SPut(0, f)
	a.ReturnVoid()
	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	return &CodeBlob{Registers: 1, Ins: 0, Insns: insns, Patches: patches}, nil
}

// padClassName 依据策略生成一个未被使用的类描述符。
func padClassName(r *rand.Rand, kind ClassPadKind, used map[string]bool) string {
	for try := 0; try < 64; try++ {
		var desc string
		switch kind {
		case PadDefaultPkg:
			// 默认包类：源码中无法正常声明，属混淆强信号。
			desc = "L" + padLeaf(r) + ";"
		case PadLongPath:
			depth := padLongDepth + r.Intn(6)
			segs := make([]string, 0, depth+1)
			for i := 0; i < depth; i++ {
				segs = append(segs, padSeg(r))
			}
			segs = append(segs, padLeaf(r))
			desc = "L" + strings.Join(segs, "/") + ";"
		default:
			desc = "L" + padSeg(r) + "/" + padLeaf(r) + ";"
		}
		if !used[desc] {
			return desc
		}
	}
	return ""
}

// padLeaf 生成类的简单名。
//
// 末段一律含数字：A1 重命名只会产出纯字母短名（a、b、…、aa），
// 因此含数字的名字天然不会与 A1 的结果冲突。
func padLeaf(r *rand.Rand) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	out := string(letters[r.Intn(len(letters))])
	out += fmt.Sprint(1 + r.Intn(900))
	if r.Intn(3) == 0 {
		out += "$" + string(letters[r.Intn(len(letters))])
	}
	return out
}

// padSeg 生成一个包路径段。
func padSeg(r *rand.Rand) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	n := 1 + r.Intn(3)
	out := make([]byte, n)
	for i := range out {
		out[i] = letters[r.Intn(len(letters))]
	}
	return string(out)
}

// padRand 由种子字符串派生一个确定性随机源。
func padRand(seed string) *rand.Rand {
	var h uint64 = 1469598103934665603
	for i := 0; i < len(seed); i++ {
		h ^= uint64(seed[i])
		h *= 1099511628211
	}
	if seed == "" {
		h = 1469598103934665603
	}
	return rand.New(rand.NewSource(int64(h)))
}
