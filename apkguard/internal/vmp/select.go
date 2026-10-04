package vmp

import (
	"fmt"
	"sort"

	"apkguard/internal/dex"
)

// DEX access_flags 中与本选择器相关的位。
const (
	accNative       = 0x0100
	accAbstract     = 0x0400
	accSynchronized = 0x0020
)

// Selection 是一次选择的结果。
type Selection struct {
	// Programs 是被选中的方法（按扫描顺序，VMID 已分配）。
	Programs []*Program
	// SkipReasons 是「原因 -> 方法数」的聚合，用于报告。
	SkipReasons map[string]int
	// UnsupportedInsn 是因指令不在支持集合而被跳过的方法数。
	UnsupportedInsn int
	// Candidates 是扫描到的全部方法数（含被跳过的）。
	Candidates int
}

// Skip 把原因计入聚合。
func (s *Selection) Skip(reason string) {
	if s.SkipReasons == nil {
		s.SkipReasons = map[string]int{}
	}
	s.SkipReasons[reason]++
}

// ReasonReport 返回按数量降序的原因摘要（同数量按原因字典序，保证可复现）。
func (s *Selection) ReasonReport() string {
	type kv struct {
		k string
		n int
	}
	out := make([]kv, 0, len(s.SkipReasons))
	for k, n := range s.SkipReasons {
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
			rep += "；"
		}
		rep += fmt.Sprintf("%s×%d", e.k, e.n)
	}
	return rep
}

// Select 扫描一个 DEX 的类/方法，翻译至多 limit 个方法（按文件顺序确定性选取）。
//
// 门槛（全部满足才翻译，任一不满足即跳过）：
//   - 非 native/abstract、非 <init>/<clinit>、非 synchronized；
//   - 有方法体、无 try/catch；
//   - 指令数 ≤ MaxInsns、寄存器数 ≤ MaxRegisters；
//   - 指令流可被**完整**解码（遇到任何不支持的操作码即拒绝整个方法）；
//   - 参数/返回类型只含整型/长整型/引用（无 float/double）。
//
// skipReasons 中会给出每一类拒绝的数量，绝不静默。
func Select(f *dex.File, source string, limit int) *Selection {
	sel := &Selection{}
	if limit <= 0 {
		return sel
	}
	nextVMID := uint32(0)
	for i := uint32(0); i < f.NClass && len(sel.Programs) < limit; i++ {
		cd, err := f.ClassDefAt(i)
		if err != nil {
			continue
		}
		if cd.ClassDataOff == 0 {
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
		for _, m := range methods {
			if len(sel.Programs) >= limit {
				break
			}
			sel.Candidates++
			prog, skip, unsupported := considerMethod(f, classDesc, m, source)
			if skip != "" {
				sel.Skip(skip)
				if unsupported {
					sel.UnsupportedInsn++
				}
				continue
			}
			if prog == nil {
				continue
			}
			prog.VMID = nextVMID
			nextVMID++
			sel.Programs = append(sel.Programs, prog)
		}
	}
	return sel
}

// considerMethod 检查并尝试翻译一个方法。
//
// 返回 (程序, 跳过原因, 是否因不支持指令)。prog 非 nil 时跳过原因为空。
func considerMethod(f *dex.File, classDesc string, m dex.EncodedMethod, source string) (*Program, string, bool) {
	if m.CodeOff == 0 {
		if m.Acc&accNative != 0 {
			return nil, "native 方法", false
		}
		return nil, "无方法体（abstract/接口）", false
	}
	if m.Acc&accAbstract != 0 {
		return nil, "abstract 方法", false
	}
	if m.Acc&accSynchronized != 0 {
		return nil, "synchronized 方法", false
	}
	ref, err := f.MethodRefAt(m.Idx)
	if err != nil {
		return nil, "method 引用损坏", false
	}
	name, err := f.String(ref.NameIdx)
	if err != nil {
		return nil, "方法名读取失败", false
	}
	if name == "<init>" || name == "<clinit>" {
		return nil, "构造器/<clinit>", false
	}
	proto, err := f.ProtoDesc(uint32(ref.ProtoIdx))
	if err != nil {
		return nil, "原型读取失败", false
	}
	if ret, params, perr := ParseProtoDesc(proto); perr != nil {
		return nil, "原型非法", false
	} else if terr := checkProtoTypes(ret, params); terr != nil {
		return nil, "类型不支持: " + terr.Error(), false
	}
	ci, err := f.ParseCodeItem(m.CodeOff)
	if err != nil {
		return nil, "code_item 解析失败", false
	}
	if len(ci.Tries) > 0 {
		return nil, "含 try/catch", false
	}
	if len(ci.Insns) > MaxInsns {
		return nil, fmt.Sprintf("指令数超限（>%d）", MaxInsns), false
	}
	if ci.Registers > MaxRegisters {
		return nil, fmt.Sprintf("寄存器数超限（>%d）", MaxRegisters), false
	}
	// 单独跑一遍解码，以便把「不支持指令」的原因写得具体（翻译器内部也会再解一次）。
	if _, derr := decodeDex(ci.Insns); derr != nil {
		// decodeDex 的错误文本已含「不支持指令 ... @pc」，不再重复加前缀。
		return nil, derr.Error(), true
	}
	prog, err := Translate(f, classDesc, m.Acc, name, proto, ci, source)
	if err != nil {
		return nil, "翻译失败: " + err.Error(), false
	}
	return prog, "", false
}

// dexOpName 返回部分常见「不支持操作码」的可读名，用于报告。
//
// 只覆盖最容易在真实应用里出现且最值得解释的那些；其余以 0xNN 形式出现。
func dexOpName(op byte) string {
	switch op {
	case 0x0d:
		return "move-exception"
	case 0x1c:
		return "const-class"
	case 0x1d:
		return "monitor-enter"
	case 0x1e:
		return "monitor-exit"
	case 0x1f:
		return "check-cast"
	case 0x20:
		return "instance-of"
	case 0x21:
		return "array-length"
	case 0x22:
		return "new-instance"
	case 0x23:
		return "new-array"
	case 0x24, 0x25:
		return "filled-new-array"
	case 0x26:
		return "fill-array-data"
	case 0x27:
		return "throw"
	case 0x2b:
		return "packed-switch"
	case 0x2c:
		return "sparse-switch"
	case 0xfc, 0xfd, 0xfe:
		return "invoke-custom/polymorphic"
	}
	return fmt.Sprintf("0x%02x", op)
}
