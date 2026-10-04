package vmp

import (
	"encoding/binary"
	"fmt"
	"strings"

	"apkguard/internal/dex"
)

// ---- DEX 侧解码 ----

// dexInsn 是一条解码后的受支持 Dalvik 指令。
type dexInsn struct {
	op     byte
	width  int
	a, b   int    // 寄存器（b 兼作对象寄存器）
	c      int    // 第三寄存器（cmp-long/二元运算）
	lit    int64  // 立即数
	target int    // 分支目标（DEX 字偏移）
	ref    uint32 // 池索引（string/field/method）
	// invoke 专用
	regs []int
	ret  string // invoke 的返回类型描述符（"I"/"V"/"L...;"）；其余指令为空
}

// supportedDexOp 报告操作码是否在支持集合内，并返回可读名。
func supportedDexOp(op byte) (string, bool) {
	switch op {
	case 0x00:
		return "nop", true
	case 0x01, 0x02, 0x03:
		return "move", true
	case 0x04, 0x05, 0x06:
		return "move-wide", true
	case 0x07, 0x08, 0x09:
		return "move-object", true
	case 0x0a:
		return "move-result", true
	case 0x0b:
		return "move-result-wide", true
	case 0x0c:
		return "move-result-object", true
	case 0x0e:
		return "return-void", true
	case 0x0f:
		return "return", true
	case 0x10:
		return "return-wide", true
	case 0x11:
		return "return-object", true
	case 0x12:
		return "const/4", true
	case 0x13:
		return "const/16", true
	case 0x14:
		return "const", true
	case 0x16:
		return "const-wide/16", true
	case 0x17:
		return "const-wide/32", true
	case 0x18:
		return "const-wide", true
	case 0x19:
		return "const-wide/high16", true
	case 0x1a:
		return "const-string", true
	case 0x1b:
		return "const-string/jumbo", true
	case 0x28:
		return "goto", true
	case 0x29:
		return "goto/16", true
	case 0x2a:
		return "goto/32", true
	case 0x31:
		return "cmp-long", true
	case 0x32:
		return "if-eq", true
	case 0x33:
		return "if-ne", true
	case 0x34:
		return "if-lt", true
	case 0x35:
		return "if-ge", true
	case 0x36:
		return "if-gt", true
	case 0x37:
		return "if-le", true
	case 0x38:
		return "if-eqz", true
	case 0x39:
		return "if-nez", true
	case 0x3a:
		return "if-ltz", true
	case 0x3b:
		return "if-gez", true
	case 0x3c:
		return "if-gtz", true
	case 0x3d:
		return "if-lez", true
	case 0x52:
		return "iget", true
	case 0x53:
		return "iget-wide", true
	case 0x54:
		return "iget-object", true
	case 0x55:
		return "iget-boolean", true
	case 0x56:
		return "iget-byte", true
	case 0x57:
		return "iget-char", true
	case 0x58:
		return "iget-short", true
	case 0x59:
		return "iput", true
	case 0x5a:
		return "iput-wide", true
	case 0x5b:
		return "iput-object", true
	case 0x5c:
		return "iput-boolean", true
	case 0x5d:
		return "iput-byte", true
	case 0x5e:
		return "iput-char", true
	case 0x5f:
		return "iput-short", true
	case 0x60:
		return "sget", true
	case 0x61:
		return "sget-wide", true
	case 0x62:
		return "sget-object", true
	case 0x63:
		return "sget-boolean", true
	case 0x64:
		return "sget-byte", true
	case 0x65:
		return "sget-char", true
	case 0x66:
		return "sget-short", true
	case 0x67:
		return "sput", true
	case 0x68:
		return "sput-wide", true
	case 0x69:
		return "sput-object", true
	case 0x6a:
		return "sput-boolean", true
	case 0x6b:
		return "sput-byte", true
	case 0x6c:
		return "sput-char", true
	case 0x6d:
		return "sput-short", true
	case 0x6e:
		return "invoke-virtual", true
	case 0x6f:
		return "invoke-super", true
	case 0x70:
		return "invoke-direct", true
	case 0x71:
		return "invoke-static", true
	case 0x72:
		return "invoke-interface", true
	case 0x74:
		return "invoke-virtual/range", true
	case 0x75:
		return "invoke-super/range", true
	case 0x76:
		return "invoke-direct/range", true
	case 0x77:
		return "invoke-static/range", true
	case 0x78:
		return "invoke-interface/range", true
	case 0x7b:
		return "neg-int", true
	case 0x7c:
		return "not-int", true
	case 0x7d:
		return "neg-long", true
	case 0x7e:
		return "not-long", true
	case 0x81:
		return "int-to-long", true
	case 0x83:
		return "long-to-int", true
	case 0x8d:
		return "int-to-byte", true
	case 0x8e:
		return "int-to-char", true
	case 0x8f:
		return "int-to-short", true
	case 0x90:
		return "add-int", true
	case 0x91:
		return "sub-int", true
	case 0x92:
		return "mul-int", true
	case 0x93:
		return "div-int", true
	case 0x94:
		return "rem-int", true
	case 0x95:
		return "and-int", true
	case 0x96:
		return "or-int", true
	case 0x97:
		return "xor-int", true
	case 0x98:
		return "shl-int", true
	case 0x99:
		return "shr-int", true
	case 0x9a:
		return "ushr-int", true
	case 0x9b:
		return "add-long", true
	case 0x9c:
		return "sub-long", true
	case 0x9d:
		return "mul-long", true
	case 0x9e:
		return "div-long", true
	case 0x9f:
		return "rem-long", true
	case 0xa0:
		return "and-long", true
	case 0xa1:
		return "or-long", true
	case 0xa2:
		return "xor-long", true
	case 0xa3:
		return "shl-long", true
	case 0xa4:
		return "shr-long", true
	case 0xa5:
		return "ushr-long", true
	case 0xd0:
		return "add-int/lit16", true
	case 0xd8:
		return "add-int/lit8", true
	case 0xd9:
		return "rsub-int/lit8", true
	case 0xda:
		return "mul-int/lit8", true
	case 0xdb:
		return "div-int/lit8", true
	case 0xdc:
		return "rem-int/lit8", true
	case 0xdd:
		return "and-int/lit8", true
	case 0xde:
		return "or-int/lit8", true
	case 0xdf:
		return "xor-int/lit8", true
	case 0xe0:
		return "shl-int/lit8", true
	case 0xe1:
		return "shr-int/lit8", true
	case 0xe2:
		return "ushr-int/lit8", true
	}
	return "", false
}

// dexWidth 返回受支持指令的字数；op 必须已被 supportedDexOp 接受。
func dexWidth(op byte) int {
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

// decodeDex 解码整个方法体，遇到任何不支持/畸形的指令立即失败。
//
// 这是「宁少勿错」的入口：调用方拿到 error 就跳过整个方法。
func decodeDex(insns []uint16) ([]dexInsn, error) {
	var out []dexInsn
	pc := 0
	for pc < len(insns) {
		w0 := insns[pc]
		op := byte(w0 & 0xff)
		name, ok := supportedDexOp(op)
		if !ok {
			return nil, fmt.Errorf("不支持指令 %s @%d", dexOpName(op), pc)
		}
		width := dexWidth(op)
		if pc+width > len(insns) {
			return nil, fmt.Errorf("%s @%d 越界", name, pc)
		}
		in := dexInsn{op: op, width: width}
		switch op {
		case 0x00:
		case 0x01, 0x04, 0x07:
			in.a, in.b = int(w0>>8&0xf), int(w0>>12&0xf)
		case 0x02, 0x05, 0x08:
			in.a, in.b = int(w0>>8), int(insns[pc+1])
		case 0x03, 0x06, 0x09:
			in.a, in.b = int(insns[pc+1]), int(insns[pc+2])
		case 0x0a, 0x0b, 0x0c, 0x0f, 0x10, 0x11:
			in.a = int(w0 >> 8)
		case 0x0e:
		case 0x12:
			in.a = int(w0 >> 8 & 0xf)
			in.lit = int64(int8(w0 >> 12))
		case 0x13, 0x16:
			in.a = int(w0 >> 8)
			in.lit = int64(int16(insns[pc+1]))
		case 0x14, 0x17:
			in.a = int(w0 >> 8)
			in.lit = int64(int32(uint32(insns[pc+1]) | uint32(insns[pc+2])<<16))
		case 0x18:
			u := uint64(insns[pc+1]) | uint64(insns[pc+2])<<16 |
				uint64(insns[pc+3])<<32 | uint64(insns[pc+4])<<48
			in.a, in.lit = int(w0>>8), int64(u)
		case 0x19:
			in.a = int(w0 >> 8)
			in.lit = int64(int16(insns[pc+1])) << 48
		case 0x1a:
			in.a, in.ref = int(w0>>8), uint32(insns[pc+1])
		case 0x1b:
			in.a = int(w0 >> 8)
			in.ref = uint32(insns[pc+1]) | uint32(insns[pc+2])<<16
		case 0x28:
			in.target = pc + int(int8(w0>>8))
		case 0x29:
			in.target = pc + int(int16(insns[pc+1]))
		case 0x2a:
			rel := int32(uint32(insns[pc+1]) | uint32(insns[pc+2])<<16)
			in.target = pc + int(rel)
		case 0x31:
			in.a = int(w0 >> 8)
			in.b, in.c = int(insns[pc+1]&0xff), int(insns[pc+1]>>8)
		case 0x32, 0x33, 0x34, 0x35, 0x36, 0x37:
			in.a, in.b = int(w0>>8&0xf), int(w0>>12&0xf)
			in.target = pc + int(int16(insns[pc+1]))
		case 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d:
			in.a = int(w0 >> 8)
			in.target = pc + int(int16(insns[pc+1]))
		case 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
			0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f:
			in.a, in.b = int(w0>>8&0xf), int(w0>>12&0xf)
			in.ref = uint32(insns[pc+1])
		case 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
			0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d:
			in.a = int(w0 >> 8)
			in.ref = uint32(insns[pc+1])
		case 0x6e, 0x6f, 0x70, 0x71, 0x72:
			argc := int(w0 >> 12)
			g := int(w0 >> 8 & 0xf)
			in.ref = uint32(insns[pc+1])
			w2 := insns[pc+2]
			slots := []int{int(w2 & 0xf), int(w2 >> 4 & 0xf), int(w2 >> 8 & 0xf), int(w2 >> 12 & 0xf)}
			in.regs = append(in.regs, slots[:min(argc, 4)]...)
			if argc == 5 {
				in.regs = append(in.regs, g)
			}
		case 0x74, 0x75, 0x76, 0x77, 0x78:
			argc := int(w0 >> 8)
			in.ref = uint32(insns[pc+1])
			first := int(insns[pc+2])
			for i := 0; i < argc; i++ {
				in.regs = append(in.regs, first+i)
			}
		case 0x7b, 0x7c, 0x7d, 0x7e, 0x81, 0x83, 0x8d, 0x8e, 0x8f:
			in.a, in.b = int(w0>>8&0xf), int(w0>>12&0xf)
		case 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
			0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
			0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5:
			in.a = int(w0 >> 8)
			in.b, in.c = int(insns[pc+1]&0xff), int(insns[pc+1]>>8)
		case 0xd0:
			in.a, in.b = int(w0>>8), int(insns[pc+1]&0xff)
			in.lit = int64(int16(insns[pc+1] >> 8))
		case 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2:
			in.a, in.b = int(w0>>8), int(insns[pc+1]&0xff)
			in.lit = int64(int8(insns[pc+1] >> 8))
		default:
			return nil, fmt.Errorf("内部错误：操作码 0x%02x 无解码分支", op)
		}
		if in.op >= 0x74 && in.op <= 0x78 && len(in.regs) > maxInvokeArgs {
			return nil, fmt.Errorf("invoke/range 实参 %d 个，超过第一版上限 %d", len(in.regs), maxInvokeArgs)
		}
		if (in.op >= 0x6e && in.op <= 0x72) && len(in.regs) != int(w0>>12) {
			return nil, fmt.Errorf("invoke 实参个数与 35c 字段不一致")
		}
		out = append(out, in)
		pc += width
	}
	return out, nil
}

// ---- 翻译 ----

// skipInfo 说明一个方法被跳过的原因（供报告聚合）。
type SkipInfo struct {
	Reason string
}

type translator struct {
	f    *dex.File
	prog *Program

	strKey map[string]int
	mthKey map[string]int
	fldKey map[string]int

	oldToNew map[int]int // DEX 字偏移 -> 私有字偏移
	// fixups 记录待回填的跳转目标。
	//
	// 私有指令与 DEX 指令不是一一对应（const 展开为 2 字、rsub 展开为 3 字、
	// invoke 的宽度还取决于实参个数），所以目标位置必须在**全部指令落位后**
	// 才能确定。早期实现试图在翻译前预扫一遍，但那时 Code 还是空的，
	// 所有目标都落到 0——分支方法一执行就死循环。
	fixups []branchFix
}

// branchFix 是一处待回填的跳转目标。
type branchFix struct {
	at        int // 目标字在 prog.Code 中的下标
	dexTarget int // 目标的 DEX 字偏移
}

// Translate 把一条受支持的方法体翻译为私有程序。
//
// 调用方必须先完成访问标志/异常表/指令数等门槛检查（见 Select）；
// 本函数只保证「能翻译」，遇到任何不确定都返回错误。
func Translate(f *dex.File, classDesc string, access uint32, name, proto string, ci *dex.CodeItemFull, source string) (*Program, error) {
	if len(ci.Tries) > 0 {
		return nil, fmt.Errorf("含异常表")
	}
	if ci.Registers > MaxRegisters {
		return nil, fmt.Errorf("寄存器数 %d 超过上限 %d", ci.Registers, MaxRegisters)
	}
	insns, err := decodeDex(ci.Insns)
	if err != nil {
		return nil, err
	}
	if len(insns) > MaxInsns {
		return nil, fmt.Errorf("指令数 %d 超过上限 %d", len(insns), MaxInsns)
	}
	if ret, params, err := ParseProtoDesc(proto); err != nil {
		return nil, fmt.Errorf("原型 %q 无法解析: %w", proto, err)
	} else if err := checkProtoTypes(ret, params); err != nil {
		return nil, err
	}
	if ci.Ins > ci.Registers {
		return nil, fmt.Errorf("ins=%d 大于 registers=%d", ci.Ins, ci.Registers)
	}

	t := &translator{
		f:        f,
		prog:     &Program{Access: access, Class: classDesc, Name: name, Proto: proto, Registers: int(ci.Registers), Ins: int(ci.Ins), Source: source},
		strKey:   map[string]int{},
		mthKey:   map[string]int{},
		fldKey:   map[string]int{},
		oldToNew: map[int]int{},
	}
	// 逐条翻译，同时记录「DEX 指令起点 -> 私有起点」。跳转目标先写 0，
	// 等循环结束后用这张表回填（见 fixups 注释）。
	pc := 0
	justInvoked := false
	for _, in := range insns {
		t.oldToNew[pc] = len(t.prog.Code)
		pc += in.width
		var err error
		switch in.op {
		case 0x00:
			err = t.emit(pack(OpNop, 0, 0, 0))
		case 0x01:
			err = t.emit(pack(OpMove, in.a, in.b, 0))
		case 0x02, 0x03:
			err = t.emit(pack(OpMove, in.a, in.b, 0))
		case 0x04:
			err = t.emit(pack(OpMoveWide, in.a, in.b, 0))
		case 0x05, 0x06:
			err = t.emit(pack(OpMoveWide, in.a, in.b, 0))
		case 0x07, 0x08, 0x09:
			err = t.emit(pack(OpMoveObject, in.a, in.b, 0))
		case 0x0a, 0x0b, 0x0c:
			if !justInvoked {
				err = fmt.Errorf("move-result 之前不是 invoke")
				break
			}
			op := uint8(OpMoveResult)
			if in.op == 0x0b {
				op = OpMoveResultWide
			} else if in.op == 0x0c {
				op = OpMoveResultObject
			}
			err = t.emit(pack(op, in.a, 0, 0))
		case 0x0e:
			err = t.emit(pack(OpReturnVoid, 0, 0, 0))
		case 0x0f:
			err = t.emit(pack(OpReturn, in.a, 0, 0))
		case 0x10:
			err = t.emit(pack(OpReturnWide, in.a, 0, 0))
		case 0x11:
			err = t.emit(pack(OpReturnObject, in.a, 0, 0))
		case 0x12, 0x13, 0x14:
			err = t.emit(pack(OpConst, in.a, 0, 0), uint32(in.lit))
		case 0x16, 0x17, 0x18, 0x19:
			u := uint64(in.lit)
			err = t.emit(pack(OpConstWide, in.a, 0, 0), uint32(u), uint32(u>>32))
		case 0x1a, 0x1b:
			var s string
			s, err = t.f.String(in.ref)
			if err == nil {
				var idx int
				idx, err = t.poolString(s)
				if err == nil {
					err = t.emit(pack(OpConstString, in.a, 0, 0), uint32(idx))
				}
			}
		case 0x28, 0x29, 0x2a:
			err = t.emitTarget(OpGoto, 0, 0, in.target)
		case 0x31:
			err = t.emit(pack(OpCmpLong, in.a, in.b, in.c))
		case 0x32, 0x33, 0x34, 0x35, 0x36, 0x37:
			op := map[byte]uint8{0x32: OpIfEq, 0x33: OpIfNe, 0x34: OpIfLt, 0x35: OpIfGe, 0x36: OpIfGt, 0x37: OpIfLe}[in.op]
			err = t.emitTarget(op, in.a, in.b, in.target)
		case 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d:
			op := map[byte]uint8{0x38: OpIfEqz, 0x39: OpIfNez, 0x3a: OpIfLtz, 0x3b: OpIfGez, 0x3c: OpIfGtz, 0x3d: OpIfLez}[in.op]
			err = t.emitTarget(op, in.a, 0, in.target)
		case 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
			0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
			0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
			0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d:
			err = t.translateField(in)
		case 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78:
			err = t.translateInvoke(in)
		case 0x7b, 0x7c, 0x7d, 0x7e, 0x81, 0x83, 0x8d, 0x8e, 0x8f:
			op := map[byte]uint8{0x7b: OpNegInt, 0x7c: OpNotInt, 0x7d: OpNegLong, 0x7e: OpNotLong,
				0x81: OpI2L, 0x83: OpL2I, 0x8d: OpI2B, 0x8e: OpI2C, 0x8f: OpI2S}[in.op]
			err = t.emit(pack(op, in.a, in.b, 0))
		case 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a,
			0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5:
			op := uint8(OpAddInt) + (in.op - 0x90)
			err = t.emit(pack(op, in.a, in.b, in.c))
		case 0xd0:
			err = t.translateLitImm(OpAddIntImm, in.a, in.b, in.lit)
		case 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2:
			op := map[byte]uint8{0xd8: OpAddIntImm, /* 0xd9 见下方特判 */
				0xda: OpMulIntImm, 0xdb: OpDivIntImm, 0xdc: OpRemIntImm,
				0xdd: OpAndIntImm, 0xde: OpOrIntImm, 0xdf: OpXorIntImm,
				0xe0: OpShlIntImm, 0xe1: OpShrIntImm, 0xe2: OpUshrIntImm}[in.op]
			if in.op == 0xd9 {
				// rsub-int/lit8 vA, vB, #lit => vA = lit - vB
				// 私有 ISA 没有 rsub：翻译为 NEG(vA=vB) + ADD_IMM(lit)，
				// 用目标寄存器自身当临时寄存器（先取负再立即数加）。
				if err = t.emit(pack(OpNegInt, in.a, in.b, 0)); err == nil {
					err = t.emit(pack(OpAddIntImm, in.a, in.a, 0), uint32(in.lit))
				}
				break
			}
			err = t.translateLitImm(op, in.a, in.b, in.lit)
		default:
			err = fmt.Errorf("内部错误：操作码 0x%02x 无翻译分支", in.op)
		}
		if err != nil {
			return nil, err
		}
		justInvoked = in.op == 0x6e || in.op == 0x6f || in.op == 0x70 || in.op == 0x71 || in.op == 0x72 ||
			in.op == 0x74 || in.op == 0x75 || in.op == 0x76 || in.op == 0x77 || in.op == 0x78
	}
	// 全部指令已落位：回填跳转目标。目标必须落在已记录的指令边界上，
	// 且不能是方法末尾（末尾不是可执行位置，Verify 同样拒绝）。
	for _, f := range t.fixups {
		tgt, ok := t.oldToNew[f.dexTarget]
		if !ok {
			return nil, fmt.Errorf("跳转目标 %d 不是指令边界", f.dexTarget)
		}
		if tgt >= len(t.prog.Code) {
			return nil, fmt.Errorf("跳转目标 %d 落在方法末尾之外", f.dexTarget)
		}
		t.prog.Code[f.at] = uint32(tgt)
	}
	return t.prog, nil
}

// translateLitImm 处理 lit8/lit16 形式的「二元运算 + 立即数」。
//
// 0xd1（rsub-int，21s）不受支持，因此这里只面对 add/mul/... 家族。
func (t *translator) translateLitImm(op uint8, a, b int, lit int64) error {
	return t.emit(pack(op, a, b, 0), uint32(lit))
}

// emit 追加指令字。
func (t *translator) emit(words ...uint32) error {
	if len(t.prog.Code)+len(words) > 0xffffff {
		return fmt.Errorf("私有指令流超出 24 位 PC 上限")
	}
	t.prog.Code = append(t.prog.Code, words...)
	return nil
}

// emitTarget 发射一条 2 字形式、第 2 字为跳转目标的私有指令（Goto/If*/If*z）。
// 目标先占位，待 Translate 收集完全部旧→新映射后回填。
func (t *translator) emitTarget(op uint8, a, b int, dexTarget int) error {
	if err := t.emit(pack(op, a, b, 0), 0); err != nil {
		return err
	}
	t.fixups = append(t.fixups, branchFix{at: len(t.prog.Code) - 1, dexTarget: dexTarget})
	return nil
}

// poolString 登记字符串池项，返回池索引。
func (t *translator) poolString(s string) (int, error) {
	units := utf16Units(s)
	key := unitsKey(units)
	if idx, ok := t.strKey[key]; ok {
		return idx, nil
	}
	idx := len(t.prog.Strings)
	t.prog.Strings = append(t.prog.Strings, units)
	t.strKey[key] = idx
	return idx, nil
}

// poolMethod 登记方法池项，返回池索引。
func (t *translator) poolMethod(m MethodRef) int {
	key := fmt.Sprintf("%d\x00%s\x00%s\x00%s", m.Kind, m.Class, m.Name, m.Proto)
	if idx, ok := t.mthKey[key]; ok {
		return idx
	}
	idx := len(t.prog.Methods)
	t.prog.Methods = append(t.prog.Methods, m)
	t.mthKey[key] = idx
	return idx
}

// poolField 登记字段池项，返回池索引。
func (t *translator) poolField(f FieldRef) int {
	key := fmt.Sprintf("%v\x00%s\x00%s\x00%s", f.Static, f.Class, f.Name, f.Type)
	if idx, ok := t.fldKey[key]; ok {
		return idx
	}
	idx := len(t.prog.Fields)
	t.prog.Fields = append(t.prog.Fields, f)
	t.fldKey[key] = idx
	return idx
}

// translateField 处理 12 条字段读写指令。
func (t *translator) translateField(in dexInsn) error {
	classIdx, typeIdx, nameIdx, err := t.f.FieldRefAt(in.ref)
	if err != nil {
		return err
	}
	cls, err := t.f.Type(uint32(classIdx))
	if err != nil {
		return err
	}
	name, err := t.f.String(nameIdx)
	if err != nil {
		return err
	}
	typ, err := t.f.Type(uint32(typeIdx))
	if err != nil {
		return err
	}
	if err := checkFieldType(typ); err != nil {
		return err
	}
	ref := FieldRef{Class: cls, Name: name, Type: typ}
	var op uint8
	switch in.op {
	case 0x52:
		op = OpIGet
	case 0x53:
		op = OpIGetWide
	case 0x54:
		op = OpIGetObject
	case 0x55, 0x56, 0x57, 0x58:
		op = OpIGet
	case 0x59:
		op = OpIPut
	case 0x5a:
		op = OpIPutWide
	case 0x5b:
		op = OpIPutObject
	case 0x5c, 0x5d, 0x5e, 0x5f:
		op = OpIPut
	case 0x60:
		ref.Static, op = true, OpSGet
	case 0x61:
		ref.Static, op = true, OpSGetWide
	case 0x62:
		ref.Static, op = true, OpSGetObject
	case 0x63, 0x64, 0x65, 0x66:
		ref.Static, op = true, OpSGet
	case 0x67:
		ref.Static, op = true, OpSPut
	case 0x68:
		ref.Static, op = true, OpSPutWide
	case 0x69:
		ref.Static, op = true, OpSPutObject
	case 0x6a, 0x6b, 0x6c, 0x6d:
		ref.Static, op = true, OpSPut
	default:
		return fmt.Errorf("内部错误：字段操作码 0x%02x", in.op)
	}
	// 第一版不支持浮点字段（类型检查已挡），但 double 的宽字段另有语义，拒绝。
	if typ == "D" || typ == "F" {
		return fmt.Errorf("字段类型 %s 不支持", typ)
	}
	idx := t.poolField(ref)
	return t.emit(pack(op, in.a, in.b, 0), uint32(idx))
}

// translateInvoke 处理 35c/3rc 调用指令。
func (t *translator) translateInvoke(in dexInsn) error {
	cls, name, ret, params, err := t.f.MethodFull(in.ref)
	if err != nil {
		return err
	}
	kind, err := invokedKind(in.op)
	if err != nil {
		return err
	}
	// 实参寄存器数以**寄存器字**计：long/double 占两格。
	wantRegs := 0
	for _, p := range params {
		if p[0] == 'J' || p[0] == 'D' {
			wantRegs += 2
		} else {
			wantRegs++
		}
	}
	if kind != InvokeStatic {
		wantRegs++
	}
	if len(in.regs) != wantRegs {
		return fmt.Errorf("调用 %s->%s 的实参寄存器数 %d 与原型要求 %d 不匹配", cls, name, len(in.regs), wantRegs)
	}
	proto := dex.BuildProtoDesc(ret, params)
	if err := checkProtoTypes(ret, params); err != nil {
		return fmt.Errorf("调用 %s: %w", cls+"->"+name+proto, err)
	}
	idx := t.poolMethod(MethodRef{Class: cls, Name: name, Proto: proto, Kind: kind})
	argc := len(in.regs)
	words := make([]uint32, 2+(argc+3)/4)
	words[0] = uint32(invokeOpcode(kind)) | uint32(argc)<<8
	words[1] = uint32(idx)
	for i, r := range in.regs {
		words[2+i/4] |= uint32(r&0xff) << (8 * uint(i%4))
	}
	return t.emit(words...)
}

// invokeOpcode 把调用形态映射为私有操作码。
func invokeOpcode(k InvokeKind) uint8 {
	switch k {
	case InvokeStatic:
		return OpInvokeStatic
	case InvokeVirtual:
		return OpInvokeVirtual
	case InvokeDirect:
		return OpInvokeDirect
	case InvokeSuper:
		return OpInvokeSuper
	case InvokeInterface:
		return OpInvokeInterface
	}
	return OpInvokeStatic
}

// invokedKind 把 DEX 调用操作码映射为调用形态。
func invokedKind(op byte) (InvokeKind, error) {
	switch op {
	case 0x6e, 0x74:
		return InvokeVirtual, nil
	case 0x6f, 0x75:
		return InvokeSuper, nil
	case 0x70, 0x76:
		return InvokeDirect, nil
	case 0x71, 0x77:
		return InvokeStatic, nil
	case 0x72, 0x78:
		return InvokeInterface, nil
	}
	return 0, fmt.Errorf("内部错误：调用操作码 0x%02x", op)
}

// checkFieldType 校验字段类型属于第一版支持集合。
func checkFieldType(typ string) error {
	if typ == "" {
		return fmt.Errorf("字段类型为空")
	}
	switch typ[0] {
	case 'Z', 'B', 'S', 'C', 'I', 'J', 'L', '[':
		return nil
	}
	return fmt.Errorf("字段类型 %s 不支持（仅整型/长整型/引用）", typ)
}

// checkProtoTypes 校验参数与返回类型属于第一版支持集合。
//
// 第一版明确不支持 float/double：即使算术没用到，只要形参/返回值出现
// F/D，翻译出的 JNI 调用也无法用统一的整型/引用路径还原。
func checkProtoTypes(ret string, params []string) error {
	if err := checkFieldType(ret); err != nil {
		if ret == "V" {
			// void 允许
		} else {
			return fmt.Errorf("返回类型: %w", err)
		}
	}
	for _, p := range params {
		if err := checkFieldType(p); err != nil {
			return fmt.Errorf("参数类型: %w", err)
		}
	}
	return nil
}

// ParseProtoDesc 解析形如 "(ILjava/lang/String;)V" 的方法描述符。
func ParseProtoDesc(proto string) (string, []string, error) {
	if len(proto) == 0 || proto[0] != '(' {
		return "", nil, fmt.Errorf("缺少 '('")
	}
	i := 1
	var params []string
	for i < len(proto) && proto[i] != ')' {
		start := i
		switch proto[i] {
		case 'L':
			j := strings.IndexByte(proto[i:], ';')
			if j < 0 {
				return "", nil, fmt.Errorf("对象类型未闭合")
			}
			i += j + 1
		case '[':
			i++
			if i < len(proto) && (proto[i] == '[') {
				// 多维数组：逐个 '[' 之后必须跟元素类型
				for i < len(proto) && proto[i] == '[' {
					i++
				}
			}
			if i >= len(proto) {
				return "", nil, fmt.Errorf("数组类型不完整")
			}
			if proto[i] == 'L' {
				j := strings.IndexByte(proto[i:], ';')
				if j < 0 {
					return "", nil, fmt.Errorf("数组元素类型未闭合")
				}
				i += j + 1
			} else {
				i++
			}
		default:
			i++
		}
		params = append(params, proto[start:i])
	}
	if i >= len(proto) || proto[i] != ')' {
		return "", nil, fmt.Errorf("缺少 ')'")
	}
	i++
	if i >= len(proto) {
		return "", nil, fmt.Errorf("缺少返回类型")
	}
	ret := proto[i:]
	if !validTypeDesc(ret) {
		return "", nil, fmt.Errorf("返回类型 %q 非法", ret)
	}
	for _, p := range params {
		if !validTypeDesc(p) {
			return "", nil, fmt.Errorf("参数类型 %q 非法", p)
		}
	}
	return ret, params, nil
}

// validTypeDesc 判断类型描述符语法是否合法（不判断业务支持面）。
func validTypeDesc(t string) bool {
	if t == "" {
		return false
	}
	switch t[0] {
	case 'V', 'Z', 'B', 'S', 'C', 'I', 'J', 'F', 'D':
		return len(t) == 1
	case 'L':
		return len(t) >= 3 && strings.HasSuffix(t, ";")
	case '[':
		return validTypeDesc(t[1:])
	}
	return false
}

// utf16Units 把 Go 字符串（可能含已合并的补充平面字符）编码为 UTF-16 码元。
//
// 说明：dex.File.String 对常规 BPM/补充平面字符给出正确 UTF-8；只有
// 未配对的代理项会被 Go 侧转义为 U+FFFD（极罕见，报告里如实说明）。
func utf16Units(s string) []uint16 {
	out := make([]uint16, 0, len(s))
	for _, r := range s {
		if r > 0xffff {
			r -= 0x10000
			out = append(out, uint16(0xd800+(r>>10)), uint16(0xdc00+(r&0x3ff)))
			continue
		}
		out = append(out, uint16(r))
	}
	return out
}

// unitsKey 生成 UTF-16 码元序列的去重键（按字节编码，避免代理项失真）。
func unitsKey(u []uint16) string {
	b := make([]byte, len(u)*2)
	for i, v := range u {
		binary.LittleEndian.PutUint16(b[2*i:], v)
	}
	return string(b)
}
