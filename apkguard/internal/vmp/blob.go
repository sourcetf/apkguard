package vmp

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// blobMagic 是私有字节码载荷的魔数。
var blobMagic = [4]byte{'A', 'G', 'V', 'M'}

// BlobVersion 是当前私有字节码格式版本。
const BlobVersion = 1

// Blob 是一份载荷的解码结果。
type Blob struct {
	Methods []*Program
}

// EncodeBlob 把一组私有程序序列化为明文 blob。
//
// 该明文随后交由 B1 同款载荷加密（pack.Encrypt / pack.Make）放入 assets；
// 明文**绝不**直接落盘到产物。
func EncodeBlob(progs []*Program) ([]byte, error) {
	var out []byte
	out = append(out, blobMagic[:]...)
	out = appendU32(out, BlobVersion)
	out = appendU32(out, uint32(len(progs)))
	for _, p := range progs {
		rec, err := EncodeMethodRecord(p)
		if err != nil {
			return nil, err
		}
		out = append(out, rec...)
	}
	return out, nil
}

// EncodeMethodRecord 序列化单个方法（registerVmMethod 收到的就是这个格式）。
func EncodeMethodRecord(p *Program) ([]byte, error) {
	if p.Registers > 0xffff || p.Ins > 0xffff {
		return nil, fmt.Errorf("vmp: 寄存器数 %d/%d 超出 u16", p.Registers, p.Ins)
	}
	if err := Verify(p); err != nil {
		return nil, fmt.Errorf("vmp: %s 校验失败: %w", p.Sig(), err)
	}
	var out []byte
	out = appendU32(out, p.VMID)
	out = appendU32(out, p.Access)
	out = appendStr(out, p.Class)
	out = appendStr(out, p.Name)
	out = appendStr(out, p.Proto)
	out = appendU16(out, uint16(p.Registers))
	out = appendU16(out, uint16(p.Ins))
	out = appendU32(out, uint32(len(p.Code)))
	for _, w := range p.Code {
		out = appendU32(out, w)
	}
	out = appendU32(out, uint32(len(p.Strings)))
	for _, s := range p.Strings {
		out = appendU32(out, uint32(len(s)))
		for _, u := range s {
			out = appendU16(out, u)
		}
	}
	out = appendU32(out, uint32(len(p.Methods)))
	for _, m := range p.Methods {
		out = append(out, byte(m.Kind))
		out = appendStr(out, m.Class)
		out = appendStr(out, m.Name)
		out = appendStr(out, m.Proto)
	}
	out = appendU32(out, uint32(len(p.Fields)))
	for _, f := range p.Fields {
		var flags byte
		if f.Static {
			flags = 1
		}
		out = append(out, flags)
		out = appendStr(out, f.Class)
		out = appendStr(out, f.Name)
		out = appendStr(out, f.Type)
	}
	return out, nil
}

// DecodeMethodRecord 反序列化单个方法记录。
func DecodeMethodRecord(b []byte) (*Program, error) {
	r := &reader{b: b}
	return r.method()
}

// DecodeBlob 反序列化整份 blob，并逐方法执行结构校验。
func DecodeBlob(b []byte) (*Blob, error) {
	if len(b) < 12 || string(b[:4]) != string(blobMagic[:]) {
		return nil, fmt.Errorf("vmp: blob 魔数不符")
	}
	r := &reader{b: b}
	r.pos = 4
	ver := r.u32()
	if ver != BlobVersion {
		return nil, fmt.Errorf("vmp: blob 版本 %d 不支持（当前 %d）", ver, BlobVersion)
	}
	n := r.u32()
	if r.err != nil {
		return nil, r.err
	}
	if n > 1<<20 {
		return nil, fmt.Errorf("vmp: blob 方法数 %d 异常", n)
	}
	blob := &Blob{}
	for i := uint32(0); i < n; i++ {
		p, err := r.method()
		if err != nil {
			return nil, fmt.Errorf("vmp: 第 %d 个方法记录损坏: %w", i, err)
		}
		blob.Methods = append(blob.Methods, p)
	}
	if r.pos != len(b) {
		return nil, fmt.Errorf("vmp: blob 尾部有 %d 字节多余数据", len(b)-r.pos)
	}
	return blob, nil
}

// reader 是一个带边界检查的小端读取器。
type reader struct {
	b   []byte
	pos int
	err error
}

func (r *reader) need(n int) bool {
	if r.err != nil {
		return false
	}
	if n < 0 || r.pos+n > len(r.b) {
		r.err = fmt.Errorf("vmp: 记录在偏移 %d 处截断（还需 %d 字节）", r.pos, n)
		return false
	}
	return true
}

func (r *reader) u8() byte {
	if !r.need(1) {
		return 0
	}
	v := r.b[r.pos]
	r.pos++
	return v
}

func (r *reader) u16() uint16 {
	if !r.need(2) {
		return 0
	}
	v := binary.LittleEndian.Uint16(r.b[r.pos:])
	r.pos += 2
	return v
}

func (r *reader) u32() uint32 {
	if !r.need(4) {
		return 0
	}
	v := binary.LittleEndian.Uint32(r.b[r.pos:])
	r.pos += 4
	return v
}

// str 读取 u16 长度 + 字节串。
func (r *reader) str() string {
	n := int(r.u16())
	if n > 4096 {
		r.err = fmt.Errorf("vmp: 字符串长度 %d 异常", n)
		return ""
	}
	if !r.need(n) {
		return ""
	}
	s := string(r.b[r.pos : r.pos+n])
	r.pos += n
	return s
}

func (r *reader) method() (*Program, error) {
	p := &Program{}
	p.VMID = r.u32()
	p.Access = r.u32()
	p.Class = r.str()
	p.Name = r.str()
	p.Proto = r.str()
	p.Registers = int(r.u16())
	p.Ins = int(r.u16())
	codeLen := r.u32()
	if r.err != nil {
		return nil, r.err
	}
	if codeLen > 1<<20 {
		return nil, fmt.Errorf("vmp: 指令流长度 %d 异常", codeLen)
	}
	if !r.need(int(codeLen) * 4) {
		return nil, r.err
	}
	p.Code = make([]uint32, codeLen)
	for i := range p.Code {
		p.Code[i] = binary.LittleEndian.Uint32(r.b[r.pos:])
		r.pos += 4
	}
	nStr := r.u32()
	if r.err != nil {
		return nil, r.err
	}
	if nStr > 1<<16 {
		return nil, fmt.Errorf("vmp: 字符串池 %d 项异常", nStr)
	}
	for i := uint32(0); i < nStr; i++ {
		n := r.u32()
		if r.err != nil {
			return nil, r.err
		}
		if n > 1<<20 {
			return nil, fmt.Errorf("vmp: 字符串码元数 %d 异常", n)
		}
		if !r.need(int(n) * 2) {
			return nil, r.err
		}
		u := make([]uint16, n)
		for k := range u {
			u[k] = binary.LittleEndian.Uint16(r.b[r.pos:])
			r.pos += 2
		}
		p.Strings = append(p.Strings, u)
	}
	nM := r.u32()
	if r.err != nil {
		return nil, r.err
	}
	if nM > 1<<16 {
		return nil, fmt.Errorf("vmp: 方法池 %d 项异常", nM)
	}
	for i := uint32(0); i < nM; i++ {
		kind := InvokeKind(r.u8())
		c := r.str()
		n := r.str()
		pr := r.str()
		if r.err != nil {
			return nil, r.err
		}
		if kind > InvokeInterface {
			return nil, fmt.Errorf("vmp: 调用形态 %d 非法", kind)
		}
		p.Methods = append(p.Methods, MethodRef{Class: c, Name: n, Proto: pr, Kind: kind})
	}
	nF := r.u32()
	if r.err != nil {
		return nil, r.err
	}
	if nF > 1<<16 {
		return nil, fmt.Errorf("vmp: 字段池 %d 项异常", nF)
	}
	for i := uint32(0); i < nF; i++ {
		flags := r.u8()
		c := r.str()
		n := r.str()
		ty := r.str()
		if r.err != nil {
			return nil, r.err
		}
		p.Fields = append(p.Fields, FieldRef{Class: c, Name: n, Type: ty, Static: flags&1 != 0})
	}
	if r.err != nil {
		return nil, r.err
	}
	if err := Verify(p); err != nil {
		return nil, err
	}
	return p, nil
}

// ---- 序列化辅助 ----

func appendU16(b []byte, v uint16) []byte {
	var t [2]byte
	binary.LittleEndian.PutUint16(t[:], v)
	return append(b, t[:]...)
}

func appendU32(b []byte, v uint32) []byte {
	var t [4]byte
	binary.LittleEndian.PutUint32(t[:], v)
	return append(b, t[:]...)
}

// appendStr 写入 u16 长度 + 原始字节。
func appendStr(b []byte, s string) []byte {
	b = appendU16(b, uint16(len(s)))
	return append(b, s...)
}

// ---- 结构校验 ----

// Verify 校验私有程序的结构完整性。
//
// 这是产物侧守卫的核心：反汇编每一条指令、检查操作数寄存器/池索引/
// 跳转目标全部合法。任何一处非法都会让设备上的解释器读到越界数据，
// 因此宁可在这里拒绝，也不能让坏 blob 进产物。
func Verify(p *Program) error {
	if p.Registers < 0 || p.Registers > MaxRegisters {
		return fmt.Errorf("寄存器数 %d 超出 [0,%d]", p.Registers, MaxRegisters)
	}
	if p.Ins < 0 || p.Ins > p.Registers {
		return fmt.Errorf("ins=%d 非法（registers=%d）", p.Ins, p.Registers)
	}
	if len(p.Code) == 0 {
		return fmt.Errorf("指令流为空")
	}
	if len(p.Code) > 0xffffff {
		return fmt.Errorf("指令流长度 %d 超出 24 位 PC 上限", len(p.Code))
	}
	// 第一遍：收集指令起点，检查宽度与译码。
	starts := map[int]bool{}
	pc := 0
	for pc < len(p.Code) {
		starts[pc] = true
		w := widthOf(p.Code, pc)
		if w == 0 {
			return fmt.Errorf("未知操作码 0x%02x @%d", uint8(p.Code[pc]), pc)
		}
		if pc+w > len(p.Code) {
			return fmt.Errorf("指令 @%d 越界（宽度 %d，总长 %d）", pc, w, len(p.Code))
		}
		pc += w
	}
	if pc != len(p.Code) {
		return fmt.Errorf("指令流尾部不对齐：pc=%d 总长=%d", pc, len(p.Code))
	}
	// 第二遍：逐条检查操作数。
	pc = 0
	for pc < len(p.Code) {
		w := widthOf(p.Code, pc)
		op := uint8(p.Code[pc])
		a := int(p.Code[pc] >> 8 & 0xff)
		b := int(p.Code[pc] >> 16 & 0xff)
		c := int(p.Code[pc] >> 24 & 0xff)
		reg := func(name string, r int) error {
			if r < 0 || r >= p.Registers {
				return fmt.Errorf("%s 的寄存器 v%d 越界（registers=%d）@%d", name, r, p.Registers, pc)
			}
			return nil
		}
		// regWide 校验宽值占用的两个相邻槽都在界内。宽值写 v(N)/v(N+1)，
		// 只校验 v(N) 会让 v(N+1) 越界时解释器直接崩（Go 侧是 panic，
		// C 侧是越界读写），必须在产物入包前就拒绝。
		regWide := func(name string, r int) error {
			if r < 0 || r+1 >= p.Registers {
				return fmt.Errorf("%s 的宽寄存器 v%d/v%d 越界（registers=%d）@%d", name, r, r+1, p.Registers, pc)
			}
			return nil
		}
		switch {
		case op == OpNop:
		case op == OpMove || op == OpMoveObject:
			if err := reg("move", a); err != nil {
				return err
			}
			if err := reg("move", b); err != nil {
				return err
			}
		case op == OpMoveWide:
			if err := regWide("move-wide", a); err != nil {
				return err
			}
			if err := regWide("move-wide", b); err != nil {
				return err
			}
		case op == OpConst:
			if err := reg("const", a); err != nil {
				return err
			}
		case op == OpConstWide:
			if err := regWide("const-wide", a); err != nil {
				return err
			}
		case op == OpConstString:
			if err := reg("const-string", a); err != nil {
				return err
			}
			if int(p.Code[pc+1]) >= len(p.Strings) {
				return fmt.Errorf("const-string 的池索引 %d 越界（池大小 %d）@%d", p.Code[pc+1], len(p.Strings), pc)
			}
		case op == OpMoveResult:
			if err := reg("move-result", a); err != nil {
				return err
			}
		case op == OpMoveResultWide:
			if err := regWide("move-result-wide", a); err != nil {
				return err
			}
		case op == OpMoveResultObject:
			if err := reg("move-result-object", a); err != nil {
				return err
			}
		case op >= OpNegInt && op <= OpL2I:
			if op == OpNegLong || op == OpNotLong {
				if err := regWide("unary-wide", a); err != nil {
					return err
				}
				if err := regWide("unary-wide", b); err != nil {
					return err
				}
				break
			}
			if op == OpI2L {
				// int-to-long：目标是宽值，源是 32 位 int。
				if err := regWide("int-to-long", a); err != nil {
					return err
				}
				if err := reg("int-to-long", b); err != nil {
					return err
				}
				break
			}
			if op == OpL2I {
				// long-to-int：源是宽值，目标是 32 位 int。
				if err := reg("long-to-int", a); err != nil {
					return err
				}
				if err := regWide("long-to-int", b); err != nil {
					return err
				}
				break
			}
			if err := reg("unary", a); err != nil {
				return err
			}
			if err := reg("unary", b); err != nil {
				return err
			}
		case op >= OpAddInt && op <= OpCmpLong:
			if op == OpCmpLong {
				// cmp-long 的**目标**是 32 位 int（写 -1/0/1），只有两个源是宽值。
				if err := reg("cmp-long", a); err != nil {
					return err
				}
				if err := regWide("cmp-long", b); err != nil {
					return err
				}
				if err := regWide("cmp-long", c); err != nil {
					return err
				}
				break
			}
			if op >= OpAddLong {
				for _, r := range []int{a, b, c} {
					if err := regWide("binary-wide", r); err != nil {
						return err
					}
				}
				break
			}
			for _, r := range []int{a, b, c} {
				if err := reg("binary", r); err != nil {
					return err
				}
			}
		case op >= OpAddIntImm && op <= OpUshrIntImm:
			if err := reg("imm", a); err != nil {
				return err
			}
			if err := reg("imm", b); err != nil {
				return err
			}
		case op == OpGoto:
			if err := branchTarget(starts, int(p.Code[pc+1]), len(p.Code), pc); err != nil {
				return err
			}
		case op >= OpIfEq && op <= OpIfLe:
			for _, r := range []int{a, b} {
				if err := reg("if", r); err != nil {
					return err
				}
			}
			if err := branchTarget(starts, int(p.Code[pc+1]), len(p.Code), pc); err != nil {
				return err
			}
		case op >= OpIfEqz && op <= OpIfLez:
			if err := reg("ifz", a); err != nil {
				return err
			}
			if err := branchTarget(starts, int(p.Code[pc+1]), len(p.Code), pc); err != nil {
				return err
			}
		case op >= OpIGet && op <= OpSPutObject:
			if op == OpIGetWide || op == OpIPutWide || op == OpSGetWide || op == OpSPutWide {
				if err := regWide("field-wide", a); err != nil {
					return err
				}
			} else if err := reg("field-a", a); err != nil {
				return err
			}
			// 实例字段指令（iget*/iput*）的第二个寄存器是对象寄存器。
			// 不能用 op < OpSGet 判断：wide/object 形态的编号大于 OpSGet，
			// 会被漏检（fieldOpStatic 按 4 个一组的排列判断，语义正确）。
			if !fieldOpStatic(op) {
				if err := reg("field-b", b); err != nil {
					return err
				}
			}
			if int(p.Code[pc+1]) >= len(p.Fields) {
				return fmt.Errorf("字段池索引 %d 越界（池大小 %d）@%d", p.Code[pc+1], len(p.Fields), pc)
			}
			if err := checkFieldOpType(op, p.Fields[p.Code[pc+1]].Type); err != nil {
				return fmt.Errorf("%s @%d", err, pc)
			}
		case op >= OpInvokeStatic && op <= OpInvokeInterface:
			argc := invokeArgc(p.Code, pc)
			if argc > maxInvokeArgs {
				return fmt.Errorf("invoke 实参 %d 个超过上限 @%d", argc, pc)
			}
			if int(p.Code[pc+1]) >= len(p.Methods) {
				return fmt.Errorf("方法池索引 %d 越界（池大小 %d）@%d", p.Code[pc+1], len(p.Methods), pc)
			}
			// 实参寄存器列表必须与原型逐槽吻合（宽值占两槽），否则解释器
			// 会把 long 的高低字读串或越界读取列表。
			m := p.Methods[p.Code[pc+1]]
			_, params, perr := ParseProtoDesc(m.Proto)
			if perr != nil {
				return fmt.Errorf("方法池条目 %d 的原型 %q 非法: %w @%d", p.Code[pc+1], m.Proto, perr, pc)
			}
			argv := invokeArgs(p.Code, pc)
			li := 0
			if m.Kind != InvokeStatic {
				if li >= len(argv) {
					return fmt.Errorf("invoke 缺少接收者寄存器 @%d", pc)
				}
				if err := reg("invoke-recv", argv[li]); err != nil {
					return err
				}
				li++
			}
			for _, prm := range params {
				if prm[0] == 'F' || prm[0] == 'D' {
					return fmt.Errorf("invoke %s 含浮点参数（第一版不支持）@%d", m.Sig(), pc)
				}
				if prm[0] == 'J' {
					if li+1 >= len(argv) {
						return fmt.Errorf("invoke %s 的宽参数缺第二个槽 @%d", m.Sig(), pc)
					}
					if err := regWide("invoke", argv[li]); err != nil {
						return err
					}
					li += 2
					continue
				}
				if err := reg("invoke", argv[li]); err != nil {
					return err
				}
				li++
			}
			if li != len(argv) {
				return fmt.Errorf("invoke %s 实参槽数 %d 与原型要求 %d 不符 @%d", m.Sig(), len(argv), li, pc)
			}
		case op >= OpReturnVoid && op <= OpReturnObject:
			if op == OpReturnWide {
				if err := regWide("return-wide", a); err != nil {
					return err
				}
			} else if op != OpReturnVoid {
				if err := reg("return", a); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("未知操作码 0x%02x @%d", op, pc)
		}
		pc += w
	}
	return nil
}

// branchTarget 校验跳转目标必须落在指令边界上。
func branchTarget(starts map[int]bool, target, codeLen, pc int) error {
	if target < 0 || target >= codeLen {
		return fmt.Errorf("跳转目标 %d 越界（代码长度 %d）@%d", target, codeLen, pc)
	}
	if !starts[target] {
		return fmt.Errorf("跳转目标 %d 不是指令边界 @%d", target, pc)
	}
	return nil
}

// checkFieldOpType 校验字段读写指令的宽窄与字段类型一致。
//
// 这类错误翻译器不会产生，但手工构造/损坏的 blob 必须被拒绝：
// 把 long 字段当 int 读会让解释器只搬 32 位，静默算错。
func checkFieldOpType(op uint8, typ string) error {
	if typ == "" {
		return fmt.Errorf("字段类型为空")
	}
	wide := op == OpIGetWide || op == OpIPutWide || op == OpSGetWide || op == OpSPutWide
	obj := op == OpIGetObject || op == OpIPutObject || op == OpSGetObject || op == OpSPutObject
	switch {
	case wide && typ != "J":
		return fmt.Errorf("宽字段指令的字段类型应为 J，实际 %s", typ)
	case obj && typ[0] != 'L' && typ[0] != '[':
		return fmt.Errorf("对象字段指令的字段类型应为引用，实际 %s", typ)
	case !wide && !obj && typ[0] != 'Z' && typ[0] != 'B' && typ[0] != 'S' && typ[0] != 'C' && typ[0] != 'I':
		return fmt.Errorf("整型字段指令的字段类型非法 %s", typ)
	}
	return nil
}

// ---- 反汇编（调试/断言） ----

// Disasm 把私有程序反汇编为可读文本，供测试与产物报告使用。
func Disasm(p *Program) []string {
	var out []string
	pc := 0
	for pc < len(p.Code) {
		w := widthOf(p.Code, pc)
		if w == 0 {
			out = append(out, fmt.Sprintf("%04d: <非法 0x%02x>", pc, uint8(p.Code[pc])))
			return out
		}
		out = append(out, disasmOne(p, pc, w))
		pc += w
	}
	return out
}

func disasmOne(p *Program, pc, w int) string {
	op := uint8(p.Code[pc])
	a := int(p.Code[pc] >> 8 & 0xff)
	b := int(p.Code[pc] >> 16 & 0xff)
	c := int(p.Code[pc] >> 24 & 0xff)
	name := opName(op)
	args := ""
	switch {
	case op == OpConst:
		args = fmt.Sprintf("v%d, #%d", a, int32(p.Code[pc+1]))
	case op == OpConstWide:
		v := uint64(p.Code[pc+1]) | uint64(p.Code[pc+2])<<32
		args = fmt.Sprintf("v%d, #%d", a, int64(v))
	case op == OpConstString:
		args = fmt.Sprintf("v%d, str#%d(%q)", a, p.Code[pc+1], unitsString(p.Strings[p.Code[pc+1]]))
	case op == OpMove || op == OpMoveWide || op == OpMoveObject ||
		op == OpMoveResult || op == OpMoveResultWide || op == OpMoveResultObject:
		if strings.HasPrefix(name, "move-result") {
			args = fmt.Sprintf("v%d", a)
		} else {
			args = fmt.Sprintf("v%d, v%d", a, b)
		}
	case op >= OpNegInt && op <= OpL2I:
		args = fmt.Sprintf("v%d, v%d", a, b)
	case op >= OpAddInt && op <= OpCmpLong:
		args = fmt.Sprintf("v%d, v%d, v%d", a, b, c)
	case op >= OpAddIntImm && op <= OpUshrIntImm:
		args = fmt.Sprintf("v%d, v%d, #%d", a, b, int32(p.Code[pc+1]))
	case op == OpGoto:
		args = fmt.Sprintf("-> %d", p.Code[pc+1])
	case op >= OpIfEq && op <= OpIfLe:
		args = fmt.Sprintf("v%d, v%d, -> %d", a, b, p.Code[pc+1])
	case op >= OpIfEqz && op <= OpIfLez:
		args = fmt.Sprintf("v%d, -> %d", a, p.Code[pc+1])
	case op >= OpIGet && op <= OpSPutObject:
		pool := p.Fields[p.Code[pc+1]]
		if op < OpSGet {
			args = fmt.Sprintf("v%d, v%d, %s.%s:%s", a, b, pool.Class, pool.Name, pool.Type)
		} else {
			args = fmt.Sprintf("v%d, %s.%s:%s", a, pool.Class, pool.Name, pool.Type)
		}
	case op >= OpInvokeStatic && op <= OpInvokeInterface:
		m := p.Methods[p.Code[pc+1]]
		regs := invokeArgs(p.Code, pc)
		args = fmt.Sprintf("%v, %s", regs, m.Sig())
	case op >= OpReturnVoid && op <= OpReturnObject:
		if op == OpReturnVoid {
			args = ""
		} else {
			args = fmt.Sprintf("v%d", a)
		}
	}
	return fmt.Sprintf("%04d: %-18s %s", pc, name, args)
}

// opName 返回私有操作码的可读名。
func opName(op uint8) string {
	switch op {
	case OpNop:
		return "nop"
	case OpMove:
		return "move"
	case OpMoveWide:
		return "move-wide"
	case OpMoveObject:
		return "move-object"
	case OpConst:
		return "const"
	case OpConstWide:
		return "const-wide"
	case OpConstString:
		return "const-string"
	case OpMoveResult:
		return "move-result"
	case OpMoveResultWide:
		return "move-result-wide"
	case OpMoveResultObject:
		return "move-result-object"
	case OpNegInt:
		return "neg-int"
	case OpNotInt:
		return "not-int"
	case OpNegLong:
		return "neg-long"
	case OpNotLong:
		return "not-long"
	case OpI2B:
		return "int-to-byte"
	case OpI2C:
		return "int-to-char"
	case OpI2S:
		return "int-to-short"
	case OpI2L:
		return "int-to-long"
	case OpL2I:
		return "long-to-int"
	case OpAddInt:
		return "add-int"
	case OpSubInt:
		return "sub-int"
	case OpMulInt:
		return "mul-int"
	case OpDivInt:
		return "div-int"
	case OpRemInt:
		return "rem-int"
	case OpAndInt:
		return "and-int"
	case OpOrInt:
		return "or-int"
	case OpXorInt:
		return "xor-int"
	case OpShlInt:
		return "shl-int"
	case OpShrInt:
		return "shr-int"
	case OpUshrInt:
		return "ushr-int"
	case OpAddLong:
		return "add-long"
	case OpSubLong:
		return "sub-long"
	case OpMulLong:
		return "mul-long"
	case OpDivLong:
		return "div-long"
	case OpRemLong:
		return "rem-long"
	case OpAndLong:
		return "and-long"
	case OpOrLong:
		return "or-long"
	case OpXorLong:
		return "xor-long"
	case OpShlLong:
		return "shl-long"
	case OpShrLong:
		return "shr-long"
	case OpUshrLong:
		return "ushr-long"
	case OpCmpLong:
		return "cmp-long"
	case OpAddIntImm:
		return "add-int/imm"
	case OpMulIntImm:
		return "mul-int/imm"
	case OpDivIntImm:
		return "div-int/imm"
	case OpRemIntImm:
		return "rem-int/imm"
	case OpAndIntImm:
		return "and-int/imm"
	case OpOrIntImm:
		return "or-int/imm"
	case OpXorIntImm:
		return "xor-int/imm"
	case OpShlIntImm:
		return "shl-int/imm"
	case OpShrIntImm:
		return "shr-int/imm"
	case OpUshrIntImm:
		return "ushr-int/imm"
	case OpGoto:
		return "goto"
	case OpIfEq:
		return "if-eq"
	case OpIfNe:
		return "if-ne"
	case OpIfLt:
		return "if-lt"
	case OpIfGe:
		return "if-ge"
	case OpIfGt:
		return "if-gt"
	case OpIfLe:
		return "if-le"
	case OpIfEqz:
		return "if-eqz"
	case OpIfNez:
		return "if-nez"
	case OpIfLtz:
		return "if-ltz"
	case OpIfGez:
		return "if-gez"
	case OpIfGtz:
		return "if-gtz"
	case OpIfLez:
		return "if-lez"
	case OpIGet:
		return "iget"
	case OpIPut:
		return "iput"
	case OpSGet:
		return "sget"
	case OpSPut:
		return "sput"
	case OpIGetWide:
		return "iget-wide"
	case OpIPutWide:
		return "iput-wide"
	case OpSGetWide:
		return "sget-wide"
	case OpSPutWide:
		return "sput-wide"
	case OpIGetObject:
		return "iget-object"
	case OpIPutObject:
		return "iput-object"
	case OpSGetObject:
		return "sget-object"
	case OpSPutObject:
		return "sput-object"
	case OpInvokeStatic:
		return "invoke-static"
	case OpInvokeVirtual:
		return "invoke-virtual"
	case OpInvokeDirect:
		return "invoke-direct"
	case OpInvokeSuper:
		return "invoke-super"
	case OpInvokeInterface:
		return "invoke-interface"
	case OpReturnVoid:
		return "return-void"
	case OpReturn:
		return "return"
	case OpReturnWide:
		return "return-wide"
	case OpReturnObject:
		return "return-object"
	}
	return fmt.Sprintf("op#0x%02x", op)
}

// unitsString 把 UTF-16 码元还原为可打印字符串（反汇编展示用）。
func unitsString(u []uint16) string {
	var sb strings.Builder
	for _, v := range u {
		if v >= 0x20 && v < 0x7f {
			sb.WriteByte(byte(v))
		} else {
			fmt.Fprintf(&sb, "\\u%04x", v)
		}
	}
	return sb.String()
}
