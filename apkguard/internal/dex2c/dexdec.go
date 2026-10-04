// Package dex2c 实现 B7（Dex2C / Java2C）的编译期侧：把一个受支持子集的
// Dalvik 方法体翻译成 C，再用 Android NDK 交叉编译成 .so。
//
// 设计边界（第一版，宁少勿错）：
//   - 只支持 32 位整型/引用语义；long/double/float 一律拒绝（不做宽值拆分）；
//   - 不含 try/catch、switch、fill-array-data、数组、new-instance、monitor；
//   - invoke 只支持 static/virtual/interface，且目标类在白名单内；
//   - 带循环的方法若在循环体内创建 JNI 局部引用会被拒绝（引用表溢出）；
//   - 类型推断采用「前向数据流 + 交并」：任何推断不足或冲突即拒绝该方法。
//
// 本文件是 DEX 指令子集解码器：把 code_item 的指令流解码成带操作数的结构，
// 遇到任何不支持的操作码立即报错（调用方据此拒绝整个方法）。
//
// 操作码表经 d8 + dexdump 实测核对（build-tools 34.0.0，见测试
// TestOpcodeTableMatchesD8）。特别地：0xd0 起是 int/lit16，0xd8 起是
// int/lit8（0xd8=add-int/lit8、0xe0=shl-int/lit8），0xb0-0xba 是 int 的
// /2addr 形态——javac/d8 生成的循环几乎都用 /2addr。
package dex2c

import (
	"fmt"
)

// 支持的指令宽度/操作数格式。
const (
	f10x = iota // op
	f12x        // op A, B（4 位）
	f11n        // op A, #+lit4
	f11x        // op A（8 位）
	f10t        // op +off8
	f20t        // op +off16
	f22x        // op A, B（16 位）
	f21s        // op A, #+lit16
	f21h        // op A, #+lit16 << 16
	f21c        // op A, ref@16
	f23x        // op AA, BB, CC（8 位）
	f22b        // op A, B, #+lit8
	f22s        // op A, B, #+lit16
	f22c        // op A, B, ref@16（A/B 各 4 位）
	f22t        // op A, B, +off16
	f21t        // op A, +off16
	f30t        // op +off32
	f31i        // op A, #+lit32
	f31c        // op A, ref@32
	f31t        // op A, +off32
	f32x        // op A, B（16 位）
	f35c        // op {regs}, ref@16
	f3rc        // op {vCCCC..vNNNN}, ref@16
	f51l        // op A, #+lit64
)

// insn 是解码后的一条指令。
type insn struct {
	op     byte
	name   string
	pc     int // 指令在 code_item 指令流中的字偏移
	width  int // 指令长度（字）
	a, b   int // 寄存器
	c      int // 第三寄存器（23x/22s 等）
	lit    int64
	ref    uint32 // string/field/method/type 池索引
	target int    // 分支/跳转目标（字偏移，绝对）
	args   []int  // invoke 的实参寄存器（含接收者，按 DEX 顺序）
}

// insnInfo 返回操作码的可读名、字长与操作数格式。
//
// ok=false 表示该操作码不在 B7 支持子集内（调用方据此拒绝方法）；此时
// name 仍会给出可读名，用于跳过原因统计。
func insnInfo(op byte) (name string, width int, form int, ok bool) {
	switch op {
	case 0x00:
		return "nop", 1, f10x, true
	case 0x01:
		return "move", 1, f12x, true
	case 0x02:
		return "move/from16", 2, f22x, true
	case 0x03:
		return "move/16", 3, f32x, true
	case 0x04:
		return "move-wide", 1, f12x, false
	case 0x05:
		return "move-wide/from16", 2, f22x, false
	case 0x06:
		return "move-wide/16", 3, f32x, false
	case 0x07:
		return "move-object", 1, f12x, true
	case 0x08:
		return "move-object/from16", 2, f22x, true
	case 0x09:
		return "move-object/16", 3, f32x, true
	case 0x0a:
		return "move-result", 1, f11x, true
	case 0x0b:
		return "move-result-wide", 1, f11x, false
	case 0x0c:
		return "move-result-object", 1, f11x, true
	case 0x0d:
		return "move-exception", 1, f11x, false
	case 0x0e:
		return "return-void", 1, f10x, true
	case 0x0f:
		return "return", 1, f11x, true
	case 0x10:
		return "return-wide", 1, f11x, false
	case 0x11:
		return "return-object", 1, f11x, true
	case 0x12:
		return "const/4", 1, f11n, true
	case 0x13:
		return "const/16", 2, f21s, true
	case 0x14:
		return "const", 3, f31i, true
	case 0x15:
		return "const/high16", 2, f21h, true
	case 0x16:
		return "const-wide/16", 2, f21s, false
	case 0x17:
		return "const-wide/32", 3, f31i, false
	case 0x18:
		return "const-wide", 5, f51l, false
	case 0x19:
		return "const-wide/high16", 2, f21h, false
	case 0x1a:
		return "const-string", 2, f21c, true
	case 0x1b:
		return "const-string/jumbo", 3, f31c, true
	case 0x1c:
		return "const-class", 2, f21c, false
	case 0x1d:
		return "monitor-enter", 1, f11x, false
	case 0x1e:
		return "monitor-exit", 1, f11x, false
	case 0x1f:
		return "check-cast", 2, f21c, false
	case 0x20:
		return "instance-of", 2, f22c, false
	case 0x21:
		return "array-length", 1, f12x, false
	case 0x22:
		return "new-instance", 2, f21c, false
	case 0x23:
		return "new-array", 2, f22c, false
	case 0x24, 0x25:
		return "filled-new-array", 3, f35c, false
	case 0x26:
		return "fill-array-data", 3, f31t, false
	case 0x27:
		return "throw", 1, f11x, false
	case 0x28:
		return "goto", 1, f10t, true
	case 0x29:
		return "goto/16", 2, f20t, true
	case 0x2a:
		return "goto/32", 3, f30t, true
	case 0x2b:
		return "packed-switch", 3, f31t, false
	case 0x2c:
		return "sparse-switch", 3, f31t, false
	case 0x2d:
		return "cmpl-float", 2, f23x, false
	case 0x2e:
		return "cmpg-float", 2, f23x, false
	case 0x2f:
		return "cmpl-double", 2, f23x, false
	case 0x30:
		return "cmpg-double", 2, f23x, false
	case 0x31:
		return "cmp-long", 2, f23x, false
	case 0x32:
		return "if-eq", 2, f22t, true
	case 0x33:
		return "if-ne", 2, f22t, true
	case 0x34:
		return "if-lt", 2, f22t, true
	case 0x35:
		return "if-ge", 2, f22t, true
	case 0x36:
		return "if-gt", 2, f22t, true
	case 0x37:
		return "if-le", 2, f22t, true
	case 0x38:
		return "if-eqz", 2, f21t, true
	case 0x39:
		return "if-nez", 2, f21t, true
	case 0x3a:
		return "if-ltz", 2, f21t, true
	case 0x3b:
		return "if-gez", 2, f21t, true
	case 0x3c:
		return "if-gtz", 2, f21t, true
	case 0x3d:
		return "if-lez", 2, f21t, true
	case 0x44:
		return "aget", 2, f23x, false
	case 0x45:
		return "aget-wide", 2, f23x, false
	case 0x46:
		return "aget-object", 2, f23x, false
	case 0x47:
		return "aget-boolean", 2, f23x, false
	case 0x48:
		return "aget-byte", 2, f23x, false
	case 0x49:
		return "aget-char", 2, f23x, false
	case 0x4a:
		return "aget-short", 2, f23x, false
	case 0x4b:
		return "aput", 2, f23x, false
	case 0x4c:
		return "aput-wide", 2, f23x, false
	case 0x4d:
		return "aput-object", 2, f23x, false
	case 0x4e:
		return "aput-boolean", 2, f23x, false
	case 0x4f:
		return "aput-byte", 2, f23x, false
	case 0x50:
		return "aput-char", 2, f23x, false
	case 0x51:
		return "aput-short", 2, f23x, false
	case 0x52:
		return "iget", 2, f22c, true
	case 0x53:
		return "iget-wide", 2, f22c, false
	case 0x54:
		return "iget-object", 2, f22c, true
	case 0x55:
		return "iget-boolean", 2, f22c, true
	case 0x56:
		return "iget-byte", 2, f22c, true
	case 0x57:
		return "iget-char", 2, f22c, true
	case 0x58:
		return "iget-short", 2, f22c, true
	case 0x59:
		return "iput", 2, f22c, true
	case 0x5a:
		return "iput-wide", 2, f22c, false
	case 0x5b:
		return "iput-object", 2, f22c, true
	case 0x5c:
		return "iput-boolean", 2, f22c, true
	case 0x5d:
		return "iput-byte", 2, f22c, true
	case 0x5e:
		return "iput-char", 2, f22c, true
	case 0x5f:
		return "iput-short", 2, f22c, true
	case 0x60:
		return "sget", 2, f21c, true
	case 0x61:
		return "sget-wide", 2, f21c, false
	case 0x62:
		return "sget-object", 2, f21c, true
	case 0x63:
		return "sget-boolean", 2, f21c, true
	case 0x64:
		return "sget-byte", 2, f21c, true
	case 0x65:
		return "sget-char", 2, f21c, true
	case 0x66:
		return "sget-short", 2, f21c, true
	case 0x67:
		return "sput", 2, f21c, true
	case 0x68:
		return "sput-wide", 2, f21c, false
	case 0x69:
		return "sput-object", 2, f21c, true
	case 0x6a:
		return "sput-boolean", 2, f21c, true
	case 0x6b:
		return "sput-byte", 2, f21c, true
	case 0x6c:
		return "sput-char", 2, f21c, true
	case 0x6d:
		return "sput-short", 2, f21c, true
	case 0x6e:
		return "invoke-virtual", 3, f35c, true
	case 0x6f:
		return "invoke-super", 3, f35c, false
	case 0x70:
		return "invoke-direct", 3, f35c, false
	case 0x71:
		return "invoke-static", 3, f35c, true
	case 0x72:
		return "invoke-interface", 3, f35c, true
	case 0x74:
		return "invoke-virtual/range", 3, f3rc, true
	case 0x75:
		return "invoke-super/range", 3, f3rc, false
	case 0x76:
		return "invoke-direct/range", 3, f3rc, false
	case 0x77:
		return "invoke-static/range", 3, f3rc, true
	case 0x78:
		return "invoke-interface/range", 3, f3rc, true
	case 0x7b:
		return "neg-int", 1, f12x, true
	case 0x7c:
		return "not-int", 1, f12x, true
	case 0x7d:
		return "neg-long", 1, f12x, false
	case 0x7e:
		return "not-long", 1, f12x, false
	case 0x7f:
		return "neg-float", 1, f12x, false
	case 0x80:
		return "neg-double", 1, f12x, false
	case 0x81:
		return "int-to-long", 1, f12x, false
	case 0x82:
		return "int-to-float", 1, f12x, false
	case 0x83:
		return "int-to-double", 1, f12x, false
	case 0x84:
		return "long-to-int", 1, f12x, false
	case 0x85:
		return "long-to-float", 1, f12x, false
	case 0x86:
		return "long-to-double", 1, f12x, false
	case 0x87:
		return "float-to-int", 1, f12x, false
	case 0x88:
		return "float-to-long", 1, f12x, false
	case 0x89:
		return "float-to-double", 1, f12x, false
	case 0x8a:
		return "double-to-int", 1, f12x, false
	case 0x8b:
		return "double-to-long", 1, f12x, false
	case 0x8c:
		return "double-to-float", 1, f12x, false
	case 0x8d:
		return "int-to-byte", 1, f12x, true
	case 0x8e:
		return "int-to-char", 1, f12x, true
	case 0x8f:
		return "int-to-short", 1, f12x, true
	case 0x90:
		return "add-int", 2, f23x, true
	case 0x91:
		return "sub-int", 2, f23x, true
	case 0x92:
		return "mul-int", 2, f23x, true
	case 0x93:
		return "div-int", 2, f23x, true
	case 0x94:
		return "rem-int", 2, f23x, true
	case 0x95:
		return "and-int", 2, f23x, true
	case 0x96:
		return "or-int", 2, f23x, true
	case 0x97:
		return "xor-int", 2, f23x, true
	case 0x98:
		return "shl-int", 2, f23x, true
	case 0x99:
		return "shr-int", 2, f23x, true
	case 0x9a:
		return "ushr-int", 2, f23x, true
	case 0x9b:
		return "add-long", 2, f23x, false
	case 0x9c:
		return "sub-long", 2, f23x, false
	case 0x9d:
		return "mul-long", 2, f23x, false
	case 0x9e:
		return "div-long", 2, f23x, false
	case 0x9f:
		return "rem-long", 2, f23x, false
	case 0xa0:
		return "and-long", 2, f23x, false
	case 0xa1:
		return "or-long", 2, f23x, false
	case 0xa2:
		return "xor-long", 2, f23x, false
	case 0xa3:
		return "shl-long", 2, f23x, false
	case 0xa4:
		return "shr-long", 2, f23x, false
	case 0xa5:
		return "ushr-long", 2, f23x, false
	case 0xa6:
		return "add-float", 2, f23x, false
	case 0xa7:
		return "sub-float", 2, f23x, false
	case 0xa8:
		return "mul-float", 2, f23x, false
	case 0xa9:
		return "div-float", 2, f23x, false
	case 0xaa:
		return "rem-float", 2, f23x, false
	case 0xab:
		return "add-double", 2, f23x, false
	case 0xac:
		return "sub-double", 2, f23x, false
	case 0xad:
		return "mul-double", 2, f23x, false
	case 0xae:
		return "div-double", 2, f23x, false
	case 0xaf:
		return "rem-double", 2, f23x, false
	case 0xb0:
		return "add-int/2addr", 1, f12x, true
	case 0xb1:
		return "sub-int/2addr", 1, f12x, true
	case 0xb2:
		return "mul-int/2addr", 1, f12x, true
	case 0xb3:
		return "div-int/2addr", 1, f12x, true
	case 0xb4:
		return "rem-int/2addr", 1, f12x, true
	case 0xb5:
		return "and-int/2addr", 1, f12x, true
	case 0xb6:
		return "or-int/2addr", 1, f12x, true
	case 0xb7:
		return "xor-int/2addr", 1, f12x, true
	case 0xb8:
		return "shl-int/2addr", 1, f12x, true
	case 0xb9:
		return "shr-int/2addr", 1, f12x, true
	case 0xba:
		return "ushr-int/2addr", 1, f12x, true
	case 0xbb:
		return "add-long/2addr", 1, f12x, false
	case 0xbc:
		return "sub-long/2addr", 1, f12x, false
	case 0xbd:
		return "mul-long/2addr", 1, f12x, false
	case 0xbe:
		return "div-long/2addr", 1, f12x, false
	case 0xbf:
		return "rem-long/2addr", 1, f12x, false
	case 0xc0:
		return "and-long/2addr", 1, f12x, false
	case 0xc1:
		return "or-long/2addr", 1, f12x, false
	case 0xc2:
		return "xor-long/2addr", 1, f12x, false
	case 0xc3:
		return "shl-long/2addr", 1, f12x, false
	case 0xc4:
		return "shr-long/2addr", 1, f12x, false
	case 0xc5:
		return "ushr-long/2addr", 1, f12x, false
	case 0xc6:
		return "add-float/2addr", 1, f12x, false
	case 0xc7:
		return "sub-float/2addr", 1, f12x, false
	case 0xc8:
		return "mul-float/2addr", 1, f12x, false
	case 0xc9:
		return "div-float/2addr", 1, f12x, false
	case 0xca:
		return "rem-float/2addr", 1, f12x, false
	case 0xcb:
		return "add-double/2addr", 1, f12x, false
	case 0xcc:
		return "sub-double/2addr", 1, f12x, false
	case 0xcd:
		return "mul-double/2addr", 1, f12x, false
	case 0xce:
		return "div-double/2addr", 1, f12x, false
	case 0xcf:
		return "rem-double/2addr", 1, f12x, false
	case 0xd0:
		return "add-int/lit16", 2, f22s, true
	case 0xd1:
		return "rsub-int", 2, f22s, true
	case 0xd2:
		return "mul-int/lit16", 2, f22s, true
	case 0xd3:
		return "div-int/lit16", 2, f22s, true
	case 0xd4:
		return "rem-int/lit16", 2, f22s, true
	case 0xd5:
		return "and-int/lit16", 2, f22s, true
	case 0xd6:
		return "or-int/lit16", 2, f22s, true
	case 0xd7:
		return "xor-int/lit16", 2, f22s, true
	case 0xd8:
		return "add-int/lit8", 2, f22b, true
	case 0xd9:
		return "rsub-int/lit8", 2, f22b, true
	case 0xda:
		return "mul-int/lit8", 2, f22b, true
	case 0xdb:
		return "div-int/lit8", 2, f22b, true
	case 0xdc:
		return "rem-int/lit8", 2, f22b, true
	case 0xdd:
		return "and-int/lit8", 2, f22b, true
	case 0xde:
		return "or-int/lit8", 2, f22b, true
	case 0xdf:
		return "xor-int/lit8", 2, f22b, true
	case 0xe0:
		return "shl-int/lit8", 2, f22b, true
	case 0xe1:
		return "shr-int/lit8", 2, f22b, true
	case 0xe2:
		return "ushr-int/lit8", 2, f22b, true
	case 0xe3:
		return "add-long/lit8", 2, f22b, false
	case 0xe4:
		return "rsub-long/lit8", 2, f22b, false
	case 0xe5:
		return "mul-long/lit8", 2, f22b, false
	case 0xe6:
		return "div-long/lit8", 2, f22b, false
	case 0xe7:
		return "rem-long/lit8", 2, f22b, false
	case 0xe8:
		return "and-long/lit8", 2, f22b, false
	case 0xe9:
		return "or-long/lit8", 2, f22b, false
	case 0xea:
		return "xor-long/lit8", 2, f22b, false
	case 0xeb:
		return "shl-long/lit8", 2, f22b, false
	case 0xec:
		return "shr-long/lit8", 2, f22b, false
	case 0xed:
		return "ushr-long/lit8", 2, f22b, false
	case 0xee, 0xef, 0xf0, 0xf1, 0xf2:
		return "float/lit8", 2, f22b, false
	case 0xf3, 0xf4, 0xf5, 0xf6, 0xf7:
		return "double/lit8", 2, f22b, false
	case 0xf8, 0xf9:
		return "unused", 2, f22b, false
	case 0xfa:
		return "invoke-polymorphic", 3, f35c, false
	case 0xfb:
		return "invoke-polymorphic/range", 3, f3rc, false
	case 0xfc:
		return "invoke-custom", 3, f35c, false
	case 0xfd:
		return "invoke-custom/range", 3, f3rc, false
	case 0xfe:
		return "const-method-handle", 2, f21c, false
	case 0xff:
		return "const-method-type", 2, f21c, false
	}
	return fmt.Sprintf("opcode-0x%02x", op), 0, 0, false
}

// decodeInsns 把指令字流解码成受支持指令序列；遇到不支持的操作码、
// 越界或畸形操作数时报错。
func decodeInsns(words []uint16) ([]insn, error) {
	out := make([]insn, 0, len(words)/2)
	for pc := 0; pc < len(words); {
		op := byte(words[pc])
		name, width, form, ok := insnInfo(op)
		if !ok {
			return nil, fmt.Errorf("不支持指令 %s（0x%02x @%d）", name, op, pc)
		}
		if pc+width > len(words) {
			return nil, fmt.Errorf("指令 %s 越界（@%d 需要 %d 字，剩余 %d）", name, pc, width, len(words)-pc)
		}
		it := insn{op: op, name: name, pc: pc, width: width}
		w := func(i int) uint16 { return words[pc+i] }
		switch form {
		case f10x:
		case f12x:
			it.a, it.b = int(w(0)>>8&0xf), int(w(0)>>12)
		case f11n:
			it.a, it.lit = int(w(0)>>8&0xf), int64(int8(w(0)>>12))
		case f11x:
			it.a = int(w(0) >> 8)
		case f10t:
			it.target = pc + int(int8(w(0)>>8))
		case f20t:
			it.target = pc + int(int16(w(1)))
		case f22x:
			it.a, it.b = int(w(0)>>8), int(w(1))
		case f21s:
			it.a, it.lit = int(w(0)>>8), int64(int16(w(1)))
		case f21h:
			it.a, it.lit = int(w(0)>>8), int64(int16(w(1)))<<16
		case f21c:
			it.a, it.ref = int(w(0)>>8), uint32(w(1))
		case f23x:
			it.a, it.b, it.c = int(w(0)>>8), int(w(1)&0xff), int(w(1)>>8)
		case f22b:
			// 22b 的布局是「AA|op CC|BB」（d8/dexdump 实证：d802 0201 →
			// add-int/lit8 v2, v2, #1）：word0 高字节是 8 位目标寄存器，
			// word1 低字节是 8 位源寄存器、高字节是 lit8。
			it.a, it.b, it.lit = int(w(0)>>8), int(w(1)&0xff), int64(int8(w(1)>>8))
		case f22s:
			it.a, it.b, it.lit = int(w(0)>>8&0xf), int(w(0)>>12), int64(int16(w(1)))
		case f22c:
			it.a, it.b, it.ref = int(w(0)>>8&0xf), int(w(0)>>12), uint32(w(1))
		case f22t:
			it.a, it.b, it.target = int(w(0)>>8&0xf), int(w(0)>>12), pc+int(int16(w(1)))
		case f21t:
			it.a, it.target = int(w(0)>>8), pc+int(int16(w(1)))
		case f30t:
			it.target = pc + int(int32(uint32(w(1))|uint32(w(2))<<16))
		case f31i:
			it.a, it.lit = int(w(0)>>8), int64(int32(uint32(w(1))|uint32(w(2))<<16))
		case f31c:
			it.a, it.ref = int(w(0)>>8), uint32(w(1))|uint32(w(2))<<16
		case f31t:
			it.a, it.target = int(w(0)>>8), pc+int(int32(uint32(w(1))|uint32(w(2))<<16))
		case f32x:
			it.a, it.b = int(w(1)), int(w(2))
		case f35c:
			count := int(w(0) >> 12)
			if count > 5 {
				return nil, fmt.Errorf("invoke 实参数 %d 非法（@%d）", count, pc)
			}
			it.ref = uint32(w(1))
			regs := []int{int(w(2) & 0xf), int(w(2) >> 4 & 0xf), int(w(2) >> 8 & 0xf), int(w(2) >> 12), int(w(0) >> 8 & 0xf)}
			it.args = append([]int(nil), regs[:count]...)
		case f3rc:
			count := int(w(0) >> 8)
			it.ref = uint32(w(1))
			first := int(w(2))
			if first+count > 0x10000 {
				return nil, fmt.Errorf("invoke/range 寄存器范围非法（@%d）", pc)
			}
			for i := 0; i < count; i++ {
				it.args = append(it.args, first+i)
			}
		case f51l:
			it.a = int(w(0) >> 8)
			lo := uint64(w(1)) | uint64(w(2))<<16 | uint64(w(3))<<32 | uint64(w(4))<<48
			it.lit = int64(lo)
		default:
			return nil, fmt.Errorf("内部错误：未处理的格式 %d（%s @%d）", form, name, pc)
		}
		out = append(out, it)
		pc += width
	}
	return out, nil
}

// opIsInvoke 报告操作码是否属于受支持的 invoke 形态。
func opIsInvoke(op byte) bool {
	switch op {
	case 0x6e, 0x71, 0x72, 0x74, 0x77, 0x78:
		return true
	}
	return false
}

// opInvokeKind 返回受支持 invoke 的调用种类：0=static 1=virtual 2=interface。
func opInvokeKind(op byte) (kind int, ok bool) {
	switch op {
	case 0x6e, 0x74:
		return 1, true
	case 0x71, 0x77:
		return 0, true
	case 0x72, 0x78:
		return 2, true
	}
	return 0, false
}

// opIsMoveResult 报告操作码是否为 move-result / move-result-object。
func opIsMoveResult(op byte) bool { return op == 0x0a || op == 0x0c }

// int2addrOp 把 /2addr 操作码映射到对应的三操作数整型操作码，
// 便于翻译器统一处理；非 /2addr 返回 0。
func int2addrOp(op byte) byte {
	if op >= 0xb0 && op <= 0xba {
		return 0x90 + (op - 0xb0)
	}
	return 0
}
