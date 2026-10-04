package vmp

import (
	"fmt"
)

// Kind 是 VM 值/返回值的类别。
type Kind uint8

const (
	KindVoid Kind = iota
	KindInt
	KindWide
	KindRef
)

// String 返回可读名。
func (k Kind) String() string {
	switch k {
	case KindVoid:
		return "void"
	case KindInt:
		return "int"
	case KindWide:
		return "wide"
	case KindRef:
		return "ref"
	}
	return "?"
}

// Value 是私有 VM 的一个值。
//
// Int 存符号扩展后的 32 位；Wide 存 64 位原始位；Ref 存后端不透明引用。
type Value struct {
	Kind Kind
	I    uint64
	Ref  any
}

// Int 构造 32 位值（符号扩展）。
func Int(v int32) Value { return Value{Kind: KindInt, I: uint64(int64(v))} }

// Wide 构造 64 位值。
func Wide(v int64) Value { return Value{Kind: KindWide, I: uint64(v)} }

// Ref 构造引用值。
func Ref(v any) Value { return Value{Kind: KindRef, Ref: v} }

// Runtime 是私有 VM 与宿主（Go 对拍环境 / C JNI 环境）之间的边界。
//
// 所有方法都由后端实现；VM 只依赖这里定义的语义，不感知 JNI 或 mock。
type Runtime interface {
	// NewString 由 UTF-16 码元构造一个字符串对象。
	NewString(units []uint16) (any, error)
	// FieldGet 读取字段；obj 为 nil 表示静态字段。
	FieldGet(f FieldRef, obj any) (Value, error)
	// FieldPut 写入字段；obj 为 nil 表示静态字段。
	FieldPut(f FieldRef, obj any, v Value) error
	// Invoke 执行一次方法调用（参数按原型顺序，实例方法第 0 个参数是接收者）。
	Invoke(m MethodRef, args []Value) (Value, error)
}

// ErrDivZero 表示整数除零（Dalvik 语义为 ArithmeticException）。
var ErrDivZero = fmt.Errorf("vmp: 整数除数为零")

// MaxSteps 是单次 Run 的最大派发步数，防止坏程序死循环拖死测试/宿主。
const MaxSteps = 10_000_000

// interp 是一次方法执行的寄存器状态。
type interp struct {
	p     *Program
	rt    Runtime
	vals  []uint64
	refs  []any
	last  Value // 最近一次 invoke 的结果（供 move-result* 消费）
	steps int
}

// Run 执行程序并返回方法返回值。
//
// args 对应方法的形参（实例方法含 this，位于最前），每个 long 形参占一个
// Value；寄存器按 Dalvik 约定位于最高编号的 ins 个寄存器，long 占两个相邻格。
func (p *Program) Run(rt Runtime, args []Value) (Value, error) {
	if err := Verify(p); err != nil {
		return Value{}, fmt.Errorf("vmp: 程序结构非法: %w", err)
	}
	_, params, err := ParseProtoDesc(p.Proto)
	if err != nil {
		return Value{}, fmt.Errorf("vmp: 方法原型非法: %w", err)
	}
	want := len(params)
	if p.Access&0x8 == 0 { // 非 static：多一个 this
		want++
	}
	if len(args) != want {
		return Value{}, fmt.Errorf("vmp: 实参个数 %d 与签名要求 %d 不符", len(args), want)
	}
	in := &interp{p: p, rt: rt, vals: make([]uint64, p.Registers), refs: make([]any, p.Registers)}
	base := p.Registers - p.Ins
	reg := base
	for i, a := range args {
		if i == 0 && p.Access&0x8 == 0 {
			// 接收者：必须是引用。
			if a.Kind != KindRef {
				return Value{}, fmt.Errorf("vmp: 实例方法的接收者必须是引用，实际 %s", a.Kind)
			}
			if reg >= p.Registers {
				return Value{}, fmt.Errorf("vmp: 实参寄存器溢出 v%d（registers=%d）", reg, p.Registers)
			}
			in.refs[reg] = a.Ref
			reg++
			continue
		}
		pi := i
		if p.Access&0x8 == 0 {
			pi--
		}
		if pi < 0 || pi >= len(params) {
			return Value{}, fmt.Errorf("vmp: 实参个数 %d 超出形参数 %d", len(args), len(params))
		}
		pt := params[pi]
		if pt[0] == 'F' || pt[0] == 'D' {
			return Value{}, fmt.Errorf("vmp: 浮点形参 %s 不在第一版支持集合内", pt)
		}
		wide := pt[0] == 'J'
		switch {
		case wide:
			if a.Kind != KindWide {
				return Value{}, fmt.Errorf("vmp: 形参 %d（%s）需要 wide 值，实际 %s", pi, pt, a.Kind)
			}
			if reg+1 >= p.Registers {
				return Value{}, fmt.Errorf("vmp: 宽实参寄存器溢出 v%d（registers=%d）", reg, p.Registers)
			}
			in.vals[reg] = a.I
			in.vals[reg+1] = a.I >> 32
			reg += 2
		case pt[0] == 'L' || pt[0] == '[':
			if a.Kind != KindRef {
				return Value{}, fmt.Errorf("vmp: 形参 %d（%s）需要引用，实际 %s", pi, pt, a.Kind)
			}
			if reg >= p.Registers {
				return Value{}, fmt.Errorf("vmp: 实参寄存器溢出 v%d（registers=%d）", reg, p.Registers)
			}
			in.refs[reg] = a.Ref
			reg++
		default:
			if a.Kind != KindInt {
				return Value{}, fmt.Errorf("vmp: 形参 %d（%s）需要 int 值，实际 %s", pi, pt, a.Kind)
			}
			if reg >= p.Registers {
				return Value{}, fmt.Errorf("vmp: 实参寄存器溢出 v%d（registers=%d）", reg, p.Registers)
			}
			in.vals[reg] = a.I
			reg++
		}
	}
	if reg != base+p.Ins {
		return Value{}, fmt.Errorf("vmp: 实参占 %d 个寄存器，ins=%d", reg-base, p.Ins)
	}

	pc := 0
	for {
		in.steps++
		if in.steps > MaxSteps {
			return Value{}, fmt.Errorf("vmp: 执行步数超过上限（疑似死循环）")
		}
		if pc < 0 || pc >= len(p.Code) {
			return Value{}, fmt.Errorf("vmp: pc 越界 %d/%d", pc, len(p.Code))
		}
		w := widthOf(p.Code, pc)
		if w == 0 {
			return Value{}, fmt.Errorf("vmp: 未知操作码 0x%02x @%d", uint8(p.Code[pc]), pc)
		}
		op := uint8(p.Code[pc])
		a := int(p.Code[pc] >> 8 & 0xff)
		b := int(p.Code[pc] >> 16 & 0xff)
		c := int(p.Code[pc] >> 24 & 0xff)
		next := pc + w
		switch op {
		case OpNop:
		case OpMove:
			in.vals[a] = in.vals[b]
			in.refs[a] = in.refs[b]
		case OpMoveWide:
			// 宽值占两格：必须整对搬移。只搬低字会静默丢高 32 位——早期实现
			// 就是这样，而 fixture 恰好让源、目标的高字重合，对拍测不出来。
			in.vals[a] = in.vals[b]
			in.vals[a+1] = in.vals[b+1]
			in.refs[a], in.refs[a+1] = nil, nil
		case OpMoveObject:
			in.refs[a] = in.refs[b]
		case OpConst:
			in.vals[a] = uint64(int64(int32(p.Code[pc+1])))
			in.refs[a] = nil
		case OpConstWide:
			in.setWide(a, int64(uint64(p.Code[pc+1])|uint64(p.Code[pc+2])<<32))
		case OpConstString:
			obj, err := in.rt.NewString(p.Strings[p.Code[pc+1]])
			if err != nil {
				return Value{}, err
			}
			in.refs[a] = obj
		case OpMoveResult:
			if in.last.Kind != KindInt {
				return Value{}, fmt.Errorf("vmp: move-result 时最近一次调用返回 %s", in.last.Kind)
			}
			in.vals[a] = in.last.I
			in.last = Value{}
		case OpMoveResultWide:
			if in.last.Kind != KindWide {
				return Value{}, fmt.Errorf("vmp: move-result-wide 时最近一次调用返回 %s", in.last.Kind)
			}
			in.setWide(a, int64(in.last.I))
			in.last = Value{}
		case OpMoveResultObject:
			if in.last.Kind != KindRef {
				return Value{}, fmt.Errorf("vmp: move-result-object 时最近一次调用返回 %s", in.last.Kind)
			}
			in.refs[a] = in.last.Ref
			in.last = Value{}
		case OpNegInt:
			in.setInt(a, -in.i32(b))
		case OpNotInt:
			in.setInt(a, ^in.i32(b))
		case OpNegLong:
			in.setWide(a, -in.i64(b))
		case OpNotLong:
			in.setWide(a, ^in.i64(b))
		case OpI2B:
			in.setInt(a, int32(int8(in.i32(b))))
		case OpI2C:
			in.setInt(a, int32(uint16(in.i32(b))))
		case OpI2S:
			in.setInt(a, int32(int16(in.i32(b))))
		case OpI2L:
			in.setWide(a, int64(in.i32(b)))
		case OpL2I:
			in.setInt(a, int32(in.i64(b)))
		case OpAddInt:
			in.setInt(a, in.i32(b)+in.i32(c))
		case OpSubInt:
			in.setInt(a, in.i32(b)-in.i32(c))
		case OpMulInt:
			in.setInt(a, in.i32(b)*in.i32(c))
		case OpDivInt:
			if in.i32(c) == 0 {
				return Value{}, ErrDivZero
			}
			in.setInt(a, in.i32(b)/in.i32(c))
		case OpRemInt:
			if in.i32(c) == 0 {
				return Value{}, ErrDivZero
			}
			in.setInt(a, in.i32(b)%in.i32(c))
		case OpAndInt:
			in.setInt(a, in.i32(b)&in.i32(c))
		case OpOrInt:
			in.setInt(a, in.i32(b)|in.i32(c))
		case OpXorInt:
			in.setInt(a, in.i32(b)^in.i32(c))
		case OpShlInt:
			in.setInt(a, in.i32(b)<<(uint32(in.i32(c))&31))
		case OpShrInt:
			in.setInt(a, in.i32(b)>>(uint32(in.i32(c))&31))
		case OpUshrInt:
			in.setInt(a, int32(uint32(in.i32(b))>>(uint32(in.i32(c))&31)))
		case OpAddLong:
			in.setWide(a, in.i64(b)+in.i64(c))
		case OpSubLong:
			in.setWide(a, in.i64(b)-in.i64(c))
		case OpMulLong:
			in.setWide(a, in.i64(b)*in.i64(c))
		case OpDivLong:
			if in.i64(c) == 0 {
				return Value{}, ErrDivZero
			}
			in.setWide(a, in.i64(b)/in.i64(c))
		case OpRemLong:
			if in.i64(c) == 0 {
				return Value{}, ErrDivZero
			}
			in.setWide(a, in.i64(b)%in.i64(c))
		case OpAndLong:
			in.setWide(a, in.i64(b)&in.i64(c))
		case OpOrLong:
			in.setWide(a, in.i64(b)|in.i64(c))
		case OpXorLong:
			in.setWide(a, in.i64(b)^in.i64(c))
		case OpShlLong:
			in.setWide(a, in.i64(b)<<(uint32(in.i32(c))&63))
		case OpShrLong:
			in.setWide(a, in.i64(b)>>(uint32(in.i32(c))&63))
		case OpUshrLong:
			in.setWide(a, int64(uint64(in.i64(b))>>(uint32(in.i32(c))&63)))
		case OpCmpLong:
			x, y := in.i64(b), in.i64(c)
			switch {
			case x < y:
				in.setInt(a, -1)
			case x > y:
				in.setInt(a, 1)
			default:
				in.setInt(a, 0)
			}
		case OpAddIntImm:
			in.setInt(a, in.i32(b)+int32(p.Code[pc+1]))
		case OpMulIntImm:
			in.setInt(a, in.i32(b)*int32(p.Code[pc+1]))
		case OpDivIntImm:
			if int32(p.Code[pc+1]) == 0 {
				return Value{}, ErrDivZero
			}
			in.setInt(a, in.i32(b)/int32(p.Code[pc+1]))
		case OpRemIntImm:
			if int32(p.Code[pc+1]) == 0 {
				return Value{}, ErrDivZero
			}
			in.setInt(a, in.i32(b)%int32(p.Code[pc+1]))
		case OpAndIntImm:
			in.setInt(a, in.i32(b)&int32(p.Code[pc+1]))
		case OpOrIntImm:
			in.setInt(a, in.i32(b)|int32(p.Code[pc+1]))
		case OpXorIntImm:
			in.setInt(a, in.i32(b)^int32(p.Code[pc+1]))
		case OpShlIntImm:
			in.setInt(a, in.i32(b)<<(p.Code[pc+1]&31))
		case OpShrIntImm:
			in.setInt(a, in.i32(b)>>(p.Code[pc+1]&31))
		case OpUshrIntImm:
			in.setInt(a, int32(uint32(in.i32(b))>>(p.Code[pc+1]&31)))
		case OpGoto:
			next = int(p.Code[pc+1])
		case OpIfEq:
			if in.i32(a) == in.i32(b) {
				next = int(p.Code[pc+1])
			}
		case OpIfNe:
			if in.i32(a) != in.i32(b) {
				next = int(p.Code[pc+1])
			}
		case OpIfLt:
			if in.i32(a) < in.i32(b) {
				next = int(p.Code[pc+1])
			}
		case OpIfGe:
			if in.i32(a) >= in.i32(b) {
				next = int(p.Code[pc+1])
			}
		case OpIfGt:
			if in.i32(a) > in.i32(b) {
				next = int(p.Code[pc+1])
			}
		case OpIfLe:
			if in.i32(a) <= in.i32(b) {
				next = int(p.Code[pc+1])
			}
		case OpIfEqz:
			if in.i32(a) == 0 {
				next = int(p.Code[pc+1])
			}
		case OpIfNez:
			if in.i32(a) != 0 {
				next = int(p.Code[pc+1])
			}
		case OpIfLtz:
			if in.i32(a) < 0 {
				next = int(p.Code[pc+1])
			}
		case OpIfGez:
			if in.i32(a) >= 0 {
				next = int(p.Code[pc+1])
			}
		case OpIfGtz:
			if in.i32(a) > 0 {
				next = int(p.Code[pc+1])
			}
		case OpIfLez:
			if in.i32(a) <= 0 {
				next = int(p.Code[pc+1])
			}
		case OpIGet, OpIGetWide, OpIGetObject,
			OpSGet, OpSGetWide, OpSGetObject:
			f := p.Fields[p.Code[pc+1]]
			var obj any
			if !fieldOpStatic(op) {
				obj = in.refs[b]
			}
			v, err := in.rt.FieldGet(f, obj)
			if err != nil {
				return Value{}, err
			}
			in.storeFieldValue(f, a, v)
		case OpIPut, OpIPutWide, OpIPutObject,
			OpSPut, OpSPutWide, OpSPutObject:
			f := p.Fields[p.Code[pc+1]]
			var obj any
			if !fieldOpStatic(op) {
				obj = in.refs[b]
			}
			v, err := in.loadFieldValue(f, a)
			if err != nil {
				return Value{}, err
			}
			if err := in.rt.FieldPut(f, obj, v); err != nil {
				return Value{}, err
			}
		case OpInvokeStatic, OpInvokeVirtual, OpInvokeDirect, OpInvokeSuper, OpInvokeInterface:
			m := p.Methods[p.Code[pc+1]]
			args, err := in.invokeArgs(m, invokeArgs(p.Code, pc))
			if err != nil {
				return Value{}, err
			}
			v, err := in.rt.Invoke(m, args)
			if err != nil {
				return Value{}, err
			}
			in.last = v
		case OpReturnVoid:
			return Value{Kind: KindVoid}, nil
		case OpReturn:
			return Int(in.i32(a)), nil
		case OpReturnWide:
			return Wide(in.i64(a)), nil
		case OpReturnObject:
			return Ref(in.refs[a]), nil
		default:
			return Value{}, fmt.Errorf("vmp: 未实现的操作码 0x%02x @%d", op, pc)
		}
		pc = next
	}
}

// ---- 寄存器读写（统一入口，保证 int/ref 两堆不串味）----
//
// 宽值（long）的表示是**唯一**的：占两个相邻槽，低 32 位在 r、高 32 位在 r+1
// （与 Dalvik 一致）。所有宽值写入都必须走 setWide，所有读取都必须走 i64 拼
// 高低位。早期实现把完整 64 位塞进单个槽、却按两槽约定传给 invoke/Run 入口，
// 于是「先算 long 再当参数传出去」会丢高字——fixture 里恰好都以参数为源，
// 对拍测不出来。

func (in *interp) i32(r int) int32 { return int32(in.vals[r]) }

func (in *interp) i64(r int) int64 {
	return int64(in.vals[r] | in.vals[r+1]<<32)
}

func (in *interp) setInt(r int, v int32) {
	in.vals[r] = uint64(int64(v))
	in.refs[r] = nil
}

func (in *interp) setWide(r int, v int64) {
	in.vals[r] = uint64(v)
	in.vals[r+1] = uint64(v) >> 32
	in.refs[r], in.refs[r+1] = nil, nil
}

// loadFieldValue 把寄存器值打包为字段写入值（按字段类型规格化）。
func (in *interp) loadFieldValue(f FieldRef, r int) (Value, error) {
	switch f.Type[0] {
	case 'J':
		return Wide(in.i64(r)), nil
	case 'L', '[':
		return Ref(in.refs[r]), nil
	case 'Z':
		return Int(in.i32(r) & 1), nil
	case 'B':
		return Int(int32(int8(in.i32(r)))), nil
	case 'C':
		return Int(int32(uint16(in.i32(r)))), nil
	case 'S':
		return Int(int32(int16(in.i32(r)))), nil
	default:
		return Int(in.i32(r)), nil
	}
}

// storeFieldValue 把读到的字段值写入寄存器（按字段类型规格化）。
func (in *interp) storeFieldValue(f FieldRef, r int, v Value) error {
	switch f.Type[0] {
	case 'J':
		if v.Kind != KindWide {
			return fmt.Errorf("vmp: 字段 %s 需要 wide 值，后端返回 %s", f.Name, v.Kind)
		}
		in.setWide(r, int64(v.I))
	case 'L', '[':
		if v.Kind != KindRef {
			return fmt.Errorf("vmp: 字段 %s 需要引用，后端返回 %s", f.Name, v.Kind)
		}
		in.refs[r] = v.Ref
	default:
		if v.Kind != KindInt {
			return fmt.Errorf("vmp: 字段 %s 需要 int 值，后端返回 %s", f.Name, v.Kind)
		}
		x := int32(v.I)
		switch f.Type[0] {
		case 'Z':
			x &= 1
		case 'B':
			x = int32(int8(x))
		case 'C':
			x = int32(uint16(x))
		case 'S':
			x = int32(int16(x))
		}
		in.setInt(r, x)
	}
	return nil
}

// invokeArgs 按方法原型把寄存器列表（以**寄存器字**为单位）打包为调用参数。
func (in *interp) invokeArgs(m MethodRef, regs []int) ([]Value, error) {
	ret, params, err := ParseProtoDesc(m.Proto)
	if err != nil {
		return nil, err
	}
	want := 0
	for _, p := range params {
		if p[0] == 'J' || p[0] == 'D' {
			want += 2
		} else {
			want++
		}
	}
	if m.Kind != InvokeStatic {
		want++ // 接收者
	}
	if len(regs) != want {
		return nil, fmt.Errorf("vmp: %s 实参占 %d 个寄存器，原型要求 %d 个", m.Sig(), len(regs), want)
	}
	_ = ret
	args := make([]Value, 0, len(regs))
	ri := 0
	if m.Kind != InvokeStatic {
		args = append(args, Ref(in.refs[regs[0]]))
		ri = 1
	}
	for _, p := range params {
		if p[0] == 'F' || p[0] == 'D' {
			return nil, fmt.Errorf("vmp: %s 含浮点参数 %s（第一版不支持）", m.Sig(), p)
		}
		switch p[0] {
		case 'J':
			if ri+1 >= len(regs) {
				return nil, fmt.Errorf("vmp: %s 的宽参数缺第二个寄存器槽", m.Sig())
			}
			lo := uint64(uint32(in.i32(regs[ri])))
			hi := uint64(uint32(in.i32(regs[ri+1])))
			args = append(args, Value{Kind: KindWide, I: hi<<32 | lo})
			ri += 2
		case 'L', '[':
			args = append(args, Ref(in.refs[regs[ri]]))
			ri++
		default:
			args = append(args, Int(in.i32(regs[ri])))
			ri++
		}
	}
	return args, nil
}

// fieldOpStatic 判断字段读写操作码是否为静态字段形态。
//
// 字段操作码按 4 个一组排列：iget/iput/sget/sput，因此 (op-0x60)%4 >= 2
// 即为静态。不能用 `op < OpSGet` 这种区间判断——iget-object 等编号大于
// OpSGet，会被误判成静态。
func fieldOpStatic(op uint8) bool { return (op-OpIGet)%4 >= 2 }
