package dex2c

import (
	"fmt"
	"hash/fnv"
	"sort"

	"apkguard/internal/dex"
)

// 选择器常量。上限刻意收紧：候选方法都应是小型方法，方法越大，
// 类型推断与 JNI 交互的出错过面越大。
const (
	// MaxInsns 是单方法指令字数的上限（超过即跳过）。
	MaxInsns = 64
	// MaxRegisters 是单方法寄存器数的上限。
	MaxRegisters = 32
	// MaxParamWords 是参数个数上限（35c 调用形态的实参上限也是 5）。
	MaxParams = 5
)

// DEX access_flags 中与本选择器相关的位。
const (
	accPublic       = 0x0001
	accStatic       = 0x0008
	accFinal        = 0x0010
	accSynchronized = 0x0020
	accBridge       = 0x0040
	accNative       = 0x0100
	accInterface    = 0x0200
	accAbstract     = 0x0400
	accAnnotation   = 0x2000
	accConstructor  = 0x10000
	accDeclSync     = 0x20000
)

// DexInput 是一个可解析的 DEX 条目。
type DexInput struct {
	// Name 是条目名（如 classes.dex），用于报告与方法身份。
	Name string
	// File 是解析后的 DEX。
	File *dex.File
}

// Method 是一个被选中的方法（含全部编译期所需信息）。
type Method struct {
	Entry  string // 来源 DEX 条目名
	Class  string // 类描述符
	Name   string
	Proto  string // 完整描述符，如 (II)I
	Access uint32
	// Static 表示静态方法（JNI 第二参数为 jclass，否则 jobject）。
	Static bool
	// Registers/Ins/Outs 来自 code_item。
	Registers, Ins, Outs int
	// InsnsCount 是 DEX 指令字数（不是指令条数）。
	InsnsCount int
	// Source 是诊断信息（条目名 + code_off）。
	Source string
	// FnName 是生成的 C 函数名（稳定、全局唯一）。
	FnName string

	file  *dex.File
	words []uint16
	ins   []insn
	// params/ret 是方法原型的参数与返回类型（宽值已在选择阶段拒绝）。
	params []string
	ret    string
	// 类型推断结果：每条指令入口处的寄存器种类。
	states [][]valKind
	// pcIdx/labels 是代码生成用的辅助索引（惰性构建）。
	pcIdx  map[int]int
	labels map[int]bool
	// 引用解析结果，按指令下标索引；非对应类型为 nil。
	strRefs []string
	fldRefs []*fieldRef
	mthRefs []*methodRef
	// 需要哪些运行时辅助函数。
	needsDiv, needsRem, needsArith, needsJni bool
}

// fieldRef 是解析后的字段引用。
type fieldRef struct {
	class string
	name  string
	typ   string
}

// methodRef 是解析后的方法引用。
type methodRef struct {
	class  string
	name   string
	proto  string
	ret    string
	params []string
	kind   int // 0=static 1=virtual 2=interface
	cls    string
}

// Selection 是一次方法选择的结果。
type Selection struct {
	// Methods 是按确定性顺序排好的选中方法。
	Methods []*Method
	// Candidates 是扫描到的全部方法数（含被跳过的）。
	Candidates int
	// Skip 是「原因 -> 方法数」的聚合。
	Skip map[string]int
	// Examples 是每个原因的第一条示例（类->方法），便于报告定位。
	Examples map[string]string
}

// Skip 记录一次跳过。
func (s *Selection) SkipMethod(reason, example string) {
	if s.Skip == nil {
		s.Skip = map[string]int{}
		s.Examples = map[string]string{}
	}
	s.Skip[reason]++
	if _, ok := s.Examples[reason]; !ok {
		s.Examples[reason] = example
	}
}

// ReasonReport 返回按数量降序的原因摘要（同数量按原因字典序，保证可复现）。
func (s *Selection) ReasonReport() string {
	type kv struct {
		k string
		n int
	}
	out := make([]kv, 0, len(s.Skip))
	for k, n := range s.Skip {
		out = append(out, kv{k, n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].n != out[j].n {
			return out[i].n > out[j].n
		}
		return out[i].k < out[j].k
	})
	rep := ""
	for i, e := range out {
		if i > 0 {
			rep += "、"
		}
		rep += fmt.Sprintf("%s×%d", e.k, e.n)
	}
	return rep
}

// Select 扫描给定的全部 DEX，按确定性顺序选出至多 limit 个可翻译方法。
//
// 全部满足才入选：非 native/abstract/synchronized/bridge、非 <init>/<clinit>、
// 声明类不是接口/注解、无 try/catch、指令数与寄存器数在上限内、指令流全部
// 在支持子集内、参数/返回类型只含 32 位整型与引用、invoke 目标类在白名单内、
// 方法名未被 A7 登记为反射调用目标。
func Select(inputs []DexInput, limit int, seed string, reflected map[string]bool) *Selection {
	sel := &Selection{Skip: map[string]int{}, Examples: map[string]string{}}
	if limit <= 0 {
		return sel
	}
	var cands []*Method
	for _, in := range inputs {
		if in.File == nil {
			continue
		}
		f := in.File
		for i := uint32(0); i < f.NClass; i++ {
			cd, err := f.ClassDefAt(i)
			if err != nil || cd.ClassDataOff == 0 {
				continue
			}
			if cd.AccessFlags&(accInterface|accAnnotation) != 0 {
				continue
			}
			classDesc, err := f.Type(cd.ClassIdx)
			if err != nil {
				continue
			}
			pcd, err := f.ParseClassData(cd.ClassDataOff)
			if err != nil {
				continue
			}
			methods := make([]dex.EncodedMethod, 0, len(pcd.DirectMethods)+len(pcd.VirtualMethods))
			methods = append(methods, pcd.DirectMethods...)
			methods = append(methods, pcd.VirtualMethods...)
			for _, em := range methods {
				sel.Candidates++
				m, reason, detail := consider(f, in.Name, classDesc, em, reflected)
				if reason != "" {
					sel.SkipMethod(reason, classDesc+"->"+detail)
					continue
				}
				cands = append(cands, m)
			}
		}
	}
	// 确定性排序：指令数多者优先（翻译价值更高），静态方法优先（绑定最简单），
	// 再按 hash(seed‖身份) 打散（不同 seed 选不同集合，避免位置成为指纹），
	// 最后按身份兜底。
	sort.SliceStable(cands, func(a, b int) bool {
		ma, mb := cands[a], cands[b]
		if ma.InsnsCount != mb.InsnsCount {
			return ma.InsnsCount > mb.InsnsCount
		}
		if ma.Static != mb.Static {
			return ma.Static
		}
		ha, hb := methodHash(seed, ma), methodHash(seed, mb)
		if ha != hb {
			return ha < hb
		}
		return methodIdentity(ma) < methodIdentity(mb)
	})
	if len(cands) > limit {
		cands = cands[:limit]
	}
	sel.Methods = cands
	return sel
}

// consider 检查一个方法是否可翻译；返回空 reason 表示可翻译。
//
// reason 是统计口径的短键：ctor/native/abstract/sync/bridge/interface/blacklist/
// reflect/try/big/regs/wide/type/insn/invoke/decode。
func consider(f *dex.File, entry, classDesc string, em dex.EncodedMethod, reflected map[string]bool) (*Method, string, string) {
	ref, err := f.MethodRefAt(em.Idx)
	if err != nil {
		return nil, "decode", "<method-ref>"
	}
	name, err := f.String(ref.NameIdx)
	if err != nil {
		return nil, "decode", "<name>"
	}
	identity := name
	if em.CodeOff == 0 {
		if em.Acc&accNative != 0 {
			return nil, "native", identity
		}
		return nil, "abstract", identity
	}
	if em.Acc&accAbstract != 0 {
		return nil, "abstract", identity
	}
	if name == "<init>" || name == "<clinit>" || em.Acc&accConstructor != 0 {
		return nil, "ctor", identity
	}
	if em.Acc&(accSynchronized|accDeclSync) != 0 {
		return nil, "sync", identity
	}
	if em.Acc&accBridge != 0 {
		return nil, "bridge", identity
	}
	if reflected[name] {
		return nil, "reflect", identity
	}
	if blacklistedName(name) {
		return nil, "blacklist", identity
	}
	ret, params, err := f.ProtoParts(uint32(ref.ProtoIdx))
	if err != nil {
		return nil, "decode", identity
	}
	proto := dex.BuildProtoDesc(ret, params)
	if len(params) > MaxParams {
		return nil, "type", proto
	}
	if ret != "V" {
		if _, ok := typeKind(ret); !ok {
			return nil, "wide", proto
		}
	}
	for _, p := range params {
		if _, ok := typeKind(p); !ok {
			return nil, "wide", proto
		}
	}
	ci, err := f.ParseCodeItem(em.CodeOff)
	if err != nil {
		return nil, "decode", proto
	}
	if len(ci.Tries) > 0 {
		return nil, "try", proto
	}
	if len(ci.Insns) > MaxInsns {
		return nil, "big", proto
	}
	if int(ci.Registers) > MaxRegisters {
		return nil, "regs", proto
	}
	m := &Method{
		Entry: entry, Class: classDesc, Name: name, Proto: proto,
		Access: em.Acc, Static: em.Acc&accStatic != 0,
		Registers: int(ci.Registers), Ins: int(ci.Ins), Outs: int(ci.Outs),
		InsnsCount: len(ci.Insns),
		Source:     fmt.Sprintf("%s@0x%x", entry, em.CodeOff),
		file:       f,
		words:      ci.Insns,
		params:     params,
		ret:        ret,
	}
	if err := m.prepare(); err != nil {
		if se, ok := err.(*skipErr); ok {
			return nil, se.reason, se.detail
		}
		return nil, "decode", err.Error()
	}
	return m, "", ""
}

// blacklistedName 是显式排除的方法名（与设计文档的黑名单一致）。
//
// 这些方法要么被框架按特殊时机调用（toString/hashCode 常在调试/日志里出现），
// 要么被反射/序列化按名访问，翻译成 native 的收益低于风险。
func blacklistedName(name string) bool {
	switch name {
	case "equals", "hashCode", "toString", "clone", "finalize", "main":
		return true
	}
	return false
}

// methodHash 返回「seed + 方法身份」的 FNV-1a 哈希，用于同长度候选的定序。
func methodHash(seed string, m *Method) uint64 {
	h := fnv.New64a()
	h.Write([]byte(seed))
	h.Write([]byte{0})
	h.Write([]byte(m.Entry))
	h.Write([]byte{0})
	h.Write([]byte(m.Class))
	h.Write([]byte{0})
	h.Write([]byte(m.Name))
	h.Write([]byte{0})
	h.Write([]byte(m.Proto))
	return h.Sum64()
}

// methodIdentity 是稳定的兜底排序键。
func methodIdentity(m *Method) string {
	return m.Entry + "|" + m.Class + "->" + m.Name + m.Proto
}

// ---- 类型与工具 ----

// valKind 是寄存器的值种类（第一版只有 32 位整型与引用）。
type valKind uint8

const (
	kindUnknown valKind = iota
	kindInt
	kindRef
	kindVoid // 仅作为 invoke 的返回种类
	kindBad  // 推断冲突（不可翻译）
)

// typeKind 把 DEX 类型描述符归类：整型/引用返回 ok；wide/float/void 返回
// ok=false（调用方按上下文处理 V）。
func typeKind(t string) (valKind, bool) {
	if t == "" {
		return kindUnknown, false
	}
	switch t[0] {
	case 'Z', 'B', 'S', 'C', 'I':
		return kindInt, true
	case 'L', '[':
		return kindRef, true
	}
	return kindUnknown, false
}
