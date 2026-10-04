// Package vmp 实现 B6 VMP 虚拟化的编译期侧：把受支持的 Dalvik 方法体
// 翻译成**私有定长字节码**（32 位字、寄存器机），并提供：
//
//   - 纯 Go 的参考解释器（internal/vmp.Interp）——语义基准，用于对拍；
//   - blob 序列化/反序列化与反汇编校验——产物侧守卫；
//   - 选择器——只挑选「可被完整翻译」的方法，遇任何不确定即拒绝。
//
// 私有指令是**数据**，解释器是固定的 C 代码（internal/native/csrc/apkguard.c）。
// 因此 B6 不需要 NDK，也不需要 per-app 编译。
//
// 设计约束（第一版，宁少勿错）：
//   - 只支持整数/长整数/引用类语义，浮点一律拒绝；
//   - 不含 try/catch、switch、fill-array-data、monitor、new-instance/数组；
//   - invoke-static/virtual/direct/super/interface 均编码，但运行时对调用形态
//     的支持面由解释器后端决定（Go 侧由 Runtime 回调实现，C/JNI 侧见 apkguard.c）。
package vmp

import "fmt"

// 私有指令操作码。
//
// !! 这些数值是 Go 与 C 两侧的**二进制契约**。C 侧在
// internal/native/csrc/apkguard.c 里有一份同名枚举（AG_OP_*），
// internal/vmp 的 TestOpcodeContractWithC 会解析 C 源码并逐值比对，
// 防止任何一侧悄悄改号导致产物在设备上执行成另一条指令。
const (
	OpNop = 0x00

	OpMove             = 0x01 // A = B
	OpMoveWide         = 0x02 // 64 位搬移
	OpMoveObject       = 0x03
	OpConst            = 0x04 // [1] = imm32（符号扩展）
	OpConstWide        = 0x05 // [1..2] = imm64
	OpConstString      = 0x06
	OpMoveResult       = 0x07
	OpMoveResultWide   = 0x08
	OpMoveResultObject = 0x09

	OpNegInt  = 0x10
	OpNotInt  = 0x11
	OpNegLong = 0x12
	OpNotLong = 0x13
	OpI2B     = 0x14
	OpI2C     = 0x15
	OpI2S     = 0x16
	OpI2L     = 0x17
	OpL2I     = 0x18

	OpAddInt   = 0x20
	OpSubInt   = 0x21
	OpMulInt   = 0x22
	OpDivInt   = 0x23
	OpRemInt   = 0x24
	OpAndInt   = 0x25
	OpOrInt    = 0x26
	OpXorInt   = 0x27
	OpShlInt   = 0x28
	OpShrInt   = 0x29
	OpUshrInt  = 0x2a
	OpAddLong  = 0x2b
	OpSubLong  = 0x2c
	OpMulLong  = 0x2d
	OpDivLong  = 0x2e
	OpRemLong  = 0x2f
	OpAndLong  = 0x30
	OpOrLong   = 0x31
	OpXorLong  = 0x32
	OpShlLong  = 0x33
	OpShrLong  = 0x34
	OpUshrLong = 0x35
	OpCmpLong  = 0x36

	OpAddIntImm = 0x40
	// 0x41 保留（历史设计中的 sub-int/imm 在 Dalvik 里没有对应指令，
	// rsub-int/lit8 翻译为 NEG + ADD_IMM，故不占用操作码）。
	OpMulIntImm  = 0x42
	OpDivIntImm  = 0x43
	OpRemIntImm  = 0x44
	OpAndIntImm  = 0x45
	OpOrIntImm   = 0x46
	OpXorIntImm  = 0x47
	OpShlIntImm  = 0x48
	OpShrIntImm  = 0x49
	OpUshrIntImm = 0x4a

	OpGoto  = 0x50
	OpIfEq  = 0x51
	OpIfNe  = 0x52
	OpIfLt  = 0x53
	OpIfGe  = 0x54
	OpIfGt  = 0x55
	OpIfLe  = 0x56
	OpIfEqz = 0x57
	OpIfNez = 0x58
	OpIfLtz = 0x59
	OpIfGez = 0x5a
	OpIfGtz = 0x5b
	OpIfLez = 0x5c

	OpIGet       = 0x60
	OpIPut       = 0x61
	OpSGet       = 0x62
	OpSPut       = 0x63
	OpIGetWide   = 0x64
	OpIPutWide   = 0x65
	OpSGetWide   = 0x66
	OpSPutWide   = 0x67
	OpIGetObject = 0x68
	OpIPutObject = 0x69
	OpSGetObject = 0x6a
	OpSPutObject = 0x6b

	OpInvokeStatic    = 0x70
	OpInvokeVirtual   = 0x71
	OpInvokeDirect    = 0x72
	OpInvokeSuper     = 0x73
	OpInvokeInterface = 0x74

	OpReturnVoid   = 0x75
	OpReturn       = 0x76
	OpReturnWide   = 0x77
	OpReturnObject = 0x78
)

// MaxRegisters 是单方法私有寄存器的上限。
//
// 私有编码的寄存器字段是 8 位（上限 255），但第一版刻意收紧到 64：
// 候选方法都应是小型方法，寄存器越多，翻译与后端 JNI 装箱的出错过面越大。
const MaxRegisters = 64

// MaxInsns 是单方法 DEX 指令条数的上限（候选门槛，不是 ISA 限制）。
const MaxInsns = 64

// maxInvokeArgs 是单次 invoke 的实参上限（对应 DEX 35c 的 5 个）。
// 3rc 形态的实参数可以更多，但第一版跟随 35c，只翻译 ≤5 个实参的调用。
const maxInvokeArgs = 5

// InvokeKind 是私有 INVOKE 指令携带的调用形态。
type InvokeKind uint8

const (
	InvokeStatic    InvokeKind = 0
	InvokeVirtual   InvokeKind = 1
	InvokeDirect    InvokeKind = 2
	InvokeSuper     InvokeKind = 3
	InvokeInterface InvokeKind = 4
)

// String 返回调用形态的中文名，用于报告。
func (k InvokeKind) String() string {
	switch k {
	case InvokeStatic:
		return "static"
	case InvokeVirtual:
		return "virtual"
	case InvokeDirect:
		return "direct"
	case InvokeSuper:
		return "super"
	case InvokeInterface:
		return "interface"
	}
	return fmt.Sprintf("kind#%d", uint8(k))
}

// PoolKind 是常量池条目类型。
type PoolKind uint8

const (
	PoolString PoolKind = 0
	PoolMethod PoolKind = 1
	PoolField  PoolKind = 2
)

// MethodRef 是池中的方法引用。
type MethodRef struct {
	Class string
	Name  string
	Proto string // 形如 "(ILjava/lang/String;)I"
	Kind  InvokeKind
}

// Sig 返回与方法描述符一致的签名，形如 "Lcls;->name(I)V"。
//
// 运行时 registerVmMethod(String sig, byte[] code) 用的就是这个串；
// 壳侧生成的桥接代码与 native 侧的查找表必须使用同一格式。
func (m MethodRef) Sig() string { return m.Class + "->" + m.Name + m.Proto }

// FieldRef 是池中的字段引用。
type FieldRef struct {
	Class string
	Name  string
	Type  string // 类型描述符
	// Static 表示静态字段（sget/sput）。
	Static bool
}

// Program 是一个已翻译方法的私有程序。
type Program struct {
	// VMID 是方法在载荷内的稳定编号（跨 DEX 全局唯一，与顺序绑定）。
	VMID uint32
	// Access 是原 DEX 方法的 access_flags（仅用于诊断/未来接 stub 生成）。
	Access uint32
	// Class/Name/Proto 是方法身份；Proto 是形如 "(II)I" 的完整描述符。
	Class string
	Name  string
	Proto string
	// Registers 是私有寄存器文件大小（等于原 registers_size）。
	Registers int
	// Ins 是入参寄存器个数（等于原 ins_size）。
	Ins int
	// Code 是私有指令流（32 位字）。
	Code []uint32
	// Strings 是字符串池（UTF-16 码元，按池索引）。
	Strings [][]uint16
	// Methods 是方法池。
	Methods []MethodRef
	// Fields 是字段池。
	Fields []FieldRef
	// Source 是来源信息（DEX 条目名 + code_off），仅用于报告与测试诊断。
	Source string
}

// Sig 返回方法签名（与 MethodRef.Sig 同格式）。
func (p *Program) Sig() string { return p.Class + "->" + p.Name + p.Proto }

// widthOf 返回 pc 处私有指令的字数。
//
// 未知操作码返回 0，由调用方报错——解释器与校验器都绝不允许「猜宽度」。
func widthOf(code []uint32, pc int) int {
	if pc < 0 || pc >= len(code) {
		return 0
	}
	op := uint8(code[pc])
	switch {
	case op == OpNop || op == OpMove || op == OpMoveWide || op == OpMoveObject ||
		op == OpMoveResult || op == OpMoveResultWide || op == OpMoveResultObject ||
		(op >= OpNegInt && op <= OpL2I) ||
		(op >= OpAddInt && op <= OpCmpLong) ||
		(op >= OpReturnVoid && op <= OpReturnObject):
		return 1
	case op == OpConst || op == OpConstString ||
		(op >= OpAddIntImm && op <= OpUshrIntImm) ||
		(op >= OpGoto && op <= OpIfLez) ||
		(op >= OpIGet && op <= OpSPutObject):
		return 2
	case op == OpConstWide:
		return 3
	case op >= OpInvokeStatic && op <= OpInvokeInterface:
		argc := int(code[pc] >> 8 & 0xff)
		return 2 + (argc+3)/4
	}
	return 0
}

// invokeArgc 读取 INVOKE 指令的实参个数。
func invokeArgc(code []uint32, pc int) int { return int(code[pc] >> 8 & 0xff) }

// invokeArgs 读取 INVOKE 指令的实参寄存器列表（长度 = argc）。
func invokeArgs(code []uint32, pc int) []int {
	argc := invokeArgc(code, pc)
	out := make([]int, argc)
	for i := 0; i < argc; i++ {
		w := code[pc+2+i/4]
		out[i] = int(w >> (8 * uint(i%4)) & 0xff)
	}
	return out
}

// pack 构造私有指令字。
func pack(op uint8, a, b, c int) uint32 {
	return uint32(op) | uint32(a&0xff)<<8 | uint32(b&0xff)<<16 | uint32(c&0xff)<<24
}
