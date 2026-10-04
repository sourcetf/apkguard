package dex

import "fmt"

// Asm 是一个面向「注入代码」的极简 Dalvik 汇编器。
//
// 它解决两个问题：
//  1. 用标签（Label）描述分支目标，组装时自动计算相对偏移——注入的壳代码
//     （字符串解密器、Application 代理等）不可避免地含有循环，手算相对偏移
//     既易错又不可维护；
//  2. 用符号（MethodSpec / 类型描述符 / 字符串）描述池引用，组装后交由
//     CodeBlob 在索引表建好后回填真实索引。
//
// 不支持异常表与调试信息——注入代码也不需要。
type Asm struct {
	items   []asmItem
	labels  map[string]int
	refs    []asmRef
	patches []asmPatch
}

type asmItem struct{ words []uint16 }

// asmRef 记录一处待解析的分支。
type asmRef struct {
	item  int
	label string
	form  branchForm
}

// asmPatch 记录一处待回填的符号引用。
type asmPatch struct {
	item int
	word int
	ref  RefSpec
}

// NewAsm 创建一个空的汇编器。
func NewAsm() *Asm { return &Asm{labels: map[string]int{}} }

// Label 在当前末尾位置定义一个标签。
func (a *Asm) Label(name string) { a.labels[name] = len(a.items) }

// emit 追加一条指令。
func (a *Asm) emit(words ...uint16) {
	a.items = append(a.items, asmItem{words: append([]uint16(nil), words...)})
}

// patch 追加一条指令并登记一处符号引用。
func (a *Asm) patch(word int, r RefSpec, words ...uint16) {
	idx := len(a.items)
	a.items = append(a.items, asmItem{words: append([]uint16(nil), words...)})
	a.patches = append(a.patches, asmPatch{item: idx, word: word, ref: r})
}

// branch 追加一条分支指令；word0 只填操作码与寄存器字段，偏移由 Assemble 回填。
func (a *Asm) branch(form branchForm, label string, word0 uint16) {
	w := 1
	switch form {
	case form20t, form22t:
		w = 2
	case form30t:
		w = 3
	}
	words := make([]uint16, w)
	words[0] = word0
	idx := len(a.items)
	a.items = append(a.items, asmItem{words: words})
	a.refs = append(a.refs, asmRef{item: idx, label: label, form: form})
}

// checkReg4 校验寄存器可编码进 4 位字段。
func checkReg4(op string, regs ...int) error {
	for _, r := range regs {
		if r < 0 || r > 15 {
			return fmt.Errorf("dex: %s 的寄存器 v%d 超出 4 位编码范围", op, r)
		}
	}
	return nil
}

// ---- 常量 ----

// Const4 生成 const/4 vReg, #+lit（格式 11n）。
func (a *Asm) Const4(reg int, lit int8) {
	a.emit(0x12 | uint16(reg&0xf)<<8 | uint16(byte(lit))<<12)
}

// Const16 生成 const/16 vReg, #+lit（格式 21s）。
func (a *Asm) Const16(reg int, lit int16) {
	a.emit(0x13|uint16(reg&0xff)<<8, uint16(lit))
}

// Const32 生成 const vReg, #+lit（格式 31i）。
func (a *Asm) Const32(reg int, lit int32) {
	a.emit(0x14|uint16(reg&0xff)<<8, uint16(lit&0xffff), uint16(uint32(lit)>>16))
}

// ConstString 生成 const-string/jumbo vReg, string@符号。
//
// 一律使用 jumbo 形式：注入代码无法预知最终字符串池大小，
// jumbo 的 32 位索引对任意规模都安全，代价仅多一个字。
func (a *Asm) ConstString(reg int, s string) {
	a.patch(1, RefSpec{Kind: RefString, Word: 1, Wide: true, String: s},
		0x1b|uint16(reg&0xff)<<8, 0, 0)
}

// ConstClass 生成 const-class vReg, type@符号。
func (a *Asm) ConstClass(reg int, typ string) {
	a.patch(1, RefSpec{Kind: RefType, Word: 1, Type: typ}, 0x1c|uint16(reg&0xff)<<8, 0)
}

// CheckCast 生成 check-cast vReg, type@符号。
func (a *Asm) CheckCast(reg int, typ string) {
	a.patch(1, RefSpec{Kind: RefType, Word: 1, Type: typ}, 0x1f|uint16(reg&0xff)<<8, 0)
}

// ---- 移动与转换 ----

// MoveObject 生成 move-object vDst, vSrc（格式 12x）。
func (a *Asm) MoveObject(dst, src int) {
	a.emit(0x07 | uint16(dst&0xf)<<8 | uint16(src&0xf)<<12)
}

// Move 生成 move vDst, vSrc（格式 12x，用于整型寄存器）。
func (a *Asm) Move(dst, src int) {
	a.emit(0x01 | uint16(dst&0xf)<<8 | uint16(src&0xf)<<12)
}

// MoveResult 生成 move-result vReg。
func (a *Asm) MoveResult(reg int) { a.emit(0x0a | uint16(reg&0xff)<<8) }

// MoveResultObject 生成 move-result-object vReg。
func (a *Asm) MoveResultObject(reg int) { a.emit(0x0c | uint16(reg&0xff)<<8) }

// ArrayLength 生成 array-length vDst, vArray（格式 12x）。
func (a *Asm) ArrayLength(dst, arr int) {
	a.emit(0x21 | uint16(dst&0xf)<<8 | uint16(arr&0xf)<<12)
}

// IntToByte 生成 int-to-byte vDst, vSrc（格式 12x）。
func (a *Asm) IntToByte(dst, src int) {
	a.emit(0x8d | uint16(dst&0xf)<<8 | uint16(src&0xf)<<12)
}

// ---- 数组 ----

// NewArray 生成 new-array vReg, vSize, type@符号（格式 22c）。
func (a *Asm) NewArray(reg, sizeReg int, typ string) error {
	if err := checkReg4("new-array", reg, sizeReg); err != nil {
		return err
	}
	a.patch(1, RefSpec{Kind: RefType, Word: 1, Type: typ},
		0x23|uint16(reg)<<8|uint16(sizeReg)<<12, 0)
	return nil
}

// AGetByte 生成 aget-byte vDst, vArr, vIdx（格式 23x）。
func (a *Asm) AGetByte(dst, arr, idx int) {
	a.emit(0x48|uint16(dst&0xff)<<8, uint16(arr&0xff)|uint16(idx&0xff)<<8)
}

// APutByte 生成 aput-byte vVal, vArr, vIdx（格式 23x）。
func (a *Asm) APutByte(val, arr, idx int) {
	a.emit(0x4f|uint16(val&0xff)<<8, uint16(arr&0xff)|uint16(idx&0xff)<<8)
}

// AGetObject 生成 aget-object vDst, vArr, vIdx（格式 23x）。
func (a *Asm) AGetObject(dst, arr, idx int) {
	a.emit(0x46|uint16(dst&0xff)<<8, uint16(arr&0xff)|uint16(idx&0xff)<<8)
}

// APutObject 生成 aput-object vVal, vArr, vIdx（格式 23x）。
func (a *Asm) APutObject(val, arr, idx int) {
	a.emit(0x4d|uint16(val&0xff)<<8, uint16(arr&0xff)|uint16(idx&0xff)<<8)
}

// ---- 算术 ----

// XorInt 生成 xor-int vDst, vA, vB（格式 23x）。
func (a *Asm) XorInt(dst, x, y int) {
	a.emit(0x97|uint16(dst&0xff)<<8, uint16(x&0xff)|uint16(y&0xff)<<8)
}

// OrInt 生成 or-int vDst, vA, vB（格式 23x）。
func (a *Asm) OrInt(dst, x, y int) {
	a.emit(0x96|uint16(dst&0xff)<<8, uint16(x&0xff)|uint16(y&0xff)<<8)
}

// AddInt 生成 add-int vDst, vA, vB（格式 23x）。
func (a *Asm) AddInt(dst, x, y int) {
	a.emit(0x90|uint16(dst&0xff)<<8, uint16(x&0xff)|uint16(y&0xff)<<8)
}

// intOp 生成一条 23x 格式的二元整型运算：op vAA, vBB, vCC。
//
// 23x 布局：word0 = AA|op，word1 = CC|BB（BB、CC 均为 8 位寄存器号）。
func (a *Asm) intOp(op byte, dst, x, y int) {
	a.emit(uint16(op)|uint16(dst&0xff)<<8, uint16(x&0xff)|uint16(y&0xff)<<8)
}

// SubInt 生成 sub-int vDst, vA, vB（0x91）。
//
// 壳的载荷读取循环要按「剩余 = 总长 − 已读」计算每次 read 的长度，
// 因此减法不可缺。
func (a *Asm) SubInt(dst, x, y int) { a.intOp(0x91, dst, x, y) }

// MulInt 生成 mul-int vDst, vA, vB（0x92）。
func (a *Asm) MulInt(dst, x, y int) { a.intOp(0x92, dst, x, y) }

// DivInt 生成 div-int vDst, vA, vB（0x93）。
func (a *Asm) DivInt(dst, x, y int) { a.intOp(0x93, dst, x, y) }

// RemInt 生成 rem-int vDst, vA, vB（0x94）。
func (a *Asm) RemInt(dst, x, y int) { a.intOp(0x94, dst, x, y) }

// AndInt 生成 and-int vDst, vA, vB（0x95）。
func (a *Asm) AndInt(dst, x, y int) { a.intOp(0x95, dst, x, y) }

// ShlInt 生成 shl-int vDst, vA, vB（0x98）。
func (a *Asm) ShlInt(dst, x, y int) { a.intOp(0x98, dst, x, y) }

// ShrInt 生成 shr-int vDst, vA, vB（0x99，算术右移）。
func (a *Asm) ShrInt(dst, x, y int) { a.intOp(0x99, dst, x, y) }

// UshrInt 生成 ushr-int vDst, vA, vB（0x9a，逻辑右移）。
func (a *Asm) UshrInt(dst, x, y int) { a.intOp(0x9a, dst, x, y) }

// NegInt 生成 neg-int vDst, vSrc（0x7b，格式 12x）。
func (a *Asm) NegInt(dst, src int) {
	a.emit(0x7b | uint16(dst&0xf)<<8 | uint16(src&0xf)<<12)
}

// NotInt 生成 not-int vDst, vSrc（0x7c，格式 12x）。
func (a *Asm) NotInt(dst, src int) {
	a.emit(0x7c | uint16(dst&0xf)<<8 | uint16(src&0xf)<<12)
}

// InstanceOf 生成 instance-of vDst, vSrc, type@符号（格式 22c）。
//
// 壳在扫描反射结果时用它做类型判定，从而不需要为「字段缺失/类型不符」
// 引入异常处理（注入方法体不支持异常表）。
func (a *Asm) InstanceOf(dst, src int, typ string) error {
	if err := checkReg4("instance-of", dst, src); err != nil {
		return err
	}
	a.patch(1, RefSpec{Kind: RefType, Word: 1, Type: typ},
		0x20|uint16(dst)<<8|uint16(src)<<12, 0)
	return nil
}

// lit8Op 生成一条「22b」格式的 lit8 运算：op vAA, vBB, #+lit。
//
// 22b 布局：word0 = AA|op，word1 = CC|BB（BB 为源寄存器，CC 为 8 位有符号立即数）。
func (a *Asm) lit8Op(op byte, dst, src int, lit int8) {
	a.emit(uint16(op)|uint16(dst&0xff)<<8, uint16(src&0xff)|uint16(byte(lit))<<8)
}

// AddIntLit8 生成 add-int/lit8 vReg, vReg, #+lit（0xd8）。
func (a *Asm) AddIntLit8(reg int, lit int8) { a.lit8Op(0xd8, reg, reg, lit) }

// MulIntLit8 生成 mul-int/lit8 vReg, vReg, #+lit（0xda）。
func (a *Asm) MulIntLit8(reg int, lit int8) { a.lit8Op(0xda, reg, reg, lit) }

// ShlIntLit8 生成 shl-int/lit8 vReg, vReg, #+lit（0xe0）。
func (a *Asm) ShlIntLit8(reg int, lit int8) { a.lit8Op(0xe0, reg, reg, lit) }

// ShrIntLit8 生成 shr-int/lit8 vReg, vReg, #+lit（0xe1）。
func (a *Asm) ShrIntLit8(reg int, lit int8) { a.lit8Op(0xe1, reg, reg, lit) }

// ---- 调用 ----

// invoke 生成一条 35c 形式的调用指令。
//
// 允许 0 个寄存器：invoke-static 调用无参方法时 A 字段就是 0
// （例如壳调用自身的失败处理方法 System.exit）。上限 5 个是 35c 的格式限制，
// 超过需改用 invoke-*/range。
func (a *Asm) invoke(op byte, regs []int, m MethodSpec) error {
	if len(regs) > 5 {
		return fmt.Errorf("dex: invoke 的寄存器个数非法 %d（35c 最多 5 个）", len(regs))
	}
	if err := checkReg4("invoke", regs...); err != nil {
		return err
	}
	var g uint16
	if len(regs) == 5 {
		g = uint16(regs[4])
	}
	// 35c 的寄存器表：A 在 word0 高字节，C/D/E/F 依次在 word2 的 4 位字段。
	// 实际给出的寄存器数由 A 字段表示，未使用的槽位固定填 0。
	get := func(i int) uint16 {
		if i < len(regs) {
			return uint16(regs[i])
		}
		return 0
	}
	word2 := get(0) | get(1)<<4 | get(2)<<8 | get(3)<<12
	a.patch(1, RefSpec{Kind: RefMethod, Word: 1, Method: m},
		uint16(op)|g<<8|uint16(len(regs))<<12, 0, word2)
	return nil
}

// InvokeStatic 生成 invoke-static。
func (a *Asm) InvokeStatic(regs []int, m MethodSpec) error { return a.invoke(0x71, regs, m) }

// InvokeVirtual 生成 invoke-virtual。
func (a *Asm) InvokeVirtual(regs []int, m MethodSpec) error { return a.invoke(0x6e, regs, m) }

// InvokeDirect 生成 invoke-direct。
func (a *Asm) InvokeDirect(regs []int, m MethodSpec) error { return a.invoke(0x70, regs, m) }

// InvokeSuper 生成 invoke-super。
//
// 覆写父类方法并调用其实现时必须用它（如壳 Application 调用
// Application.attachBaseContext / onCreate）：用 invoke-virtual 会在
// 子类自身实现上递归，用 invoke-direct 则会被校验器拒绝。
func (a *Asm) InvokeSuper(regs []int, m MethodSpec) error { return a.invoke(0x6f, regs, m) }

// InvokeInterface 生成 invoke-interface。
func (a *Asm) InvokeInterface(regs []int, m MethodSpec) error { return a.invoke(0x72, regs, m) }

// ---- 字段与实例 ----

// NewInstance 生成 new-instance vReg, type@符号。
func (a *Asm) NewInstance(reg int, typ string) {
	a.patch(1, RefSpec{Kind: RefType, Word: 1, Type: typ}, 0x22|uint16(reg&0xff)<<8, 0)
}

// SGetObject 生成 sget-object vReg, field@符号。
func (a *Asm) SGetObject(reg int, f FieldSpec) {
	a.patch(1, RefSpec{Kind: RefField, Word: 1, Field: f}, 0x62|uint16(reg&0xff)<<8, 0)
}

// SGet 生成读取静态字段的指令（格式 21c）。
//
// 操作码按**字段声明类型**选择：`sget`(0x60) 只接受 int/float 字段，对
// boolean/byte/char/short 字段必须用各自的 `sget-*` 变体。曾经无脑写 0x60，
// 结果 B9 的双 APK 宿主在真机上被 ART 直接判死：
//
//	java.lang.VerifyError: Verifier rejected class …B:
//	  void …B.run(Context): expected field boolean …B.s to have type
//	  descriptor starting with 'I' or 'F' but found 'Z' in sget
//
// 结构校验（dex.Verify/ValidateDescriptors）看不出「操作码与字段类型不匹配」，
// 只有 ART 的校验器会拒绝，所以在构建器这一层就按类型选对。
func (a *Asm) SGet(reg int, f FieldSpec) {
	a.patch(1, RefSpec{Kind: RefField, Word: 1, Field: f}, narrowFieldOp(0x60, f.Type)|uint16(reg&0xff)<<8, 0)
}

// narrowFieldOp 把「int 家族的字段操作码」按字段类型换成对应的窄类型变体。
//
// base 是 int/float 版本（sget 0x60 / sput 0x67 / iget 0x52 / iput 0x59）；
// Z/B/C/S 依次是 base+3/+4/+5/+6（DEX 指令表：sget-boolean 0x63、
// sput-short 0x6d、iget-char 0x57…）。其余类型（I/F/对象/宽值）原样返回，
// 由调用方用 SGetObject/SPutObject 等专用方法另行选择。
func narrowFieldOp(base byte, typ string) uint16 {
	switch typ {
	case "Z":
		return uint16(base + 3)
	case "B":
		return uint16(base + 4)
	case "C":
		return uint16(base + 5)
	case "S":
		return uint16(base + 6)
	}
	return uint16(base)
}

// IGetObject 生成 iget-object vDst, vObj, field@符号。
func (a *Asm) IGetObject(dst, obj int, f FieldSpec) error {
	if err := checkReg4("iget-object", dst, obj); err != nil {
		return err
	}
	a.patch(1, RefSpec{Kind: RefField, Word: 1, Field: f},
		0x54|uint16(dst)<<8|uint16(obj)<<12, 0)
	return nil
}

// IGet 生成读取 int 实例字段的指令（格式 22c）；窄类型字段按声明类型选变体。
func (a *Asm) IGet(dst, obj int, f FieldSpec) error {
	if err := checkReg4("iget", dst, obj); err != nil {
		return err
	}
	a.patch(1, RefSpec{Kind: RefField, Word: 1, Field: f},
		narrowFieldOp(0x52, f.Type)|uint16(dst)<<8|uint16(obj)<<12, 0)
	return nil
}

// IPut 生成写入 int 实例字段的指令（格式 22c）；窄类型字段按声明类型选变体。
func (a *Asm) IPut(val, obj int, f FieldSpec) error {
	if err := checkReg4("iput", val, obj); err != nil {
		return err
	}
	a.patch(1, RefSpec{Kind: RefField, Word: 1, Field: f},
		narrowFieldOp(0x59, f.Type)|uint16(val)<<8|uint16(obj)<<12, 0)
	return nil
}

// SPut 生成写入静态字段的指令（格式 21c）；窄类型字段按声明类型选变体。
func (a *Asm) SPut(reg int, f FieldSpec) {
	a.patch(1, RefSpec{Kind: RefField, Word: 1, Field: f}, narrowFieldOp(0x67, f.Type)|uint16(reg&0xff)<<8, 0)
}

// SPutObject 生成 sput-object vReg, field@符号（写入对象静态字段，格式 21c）。
//
// 操作码是 0x69。写成 0x68 会变成 sput-wide（写入 long/double 字段），
// ART 的校验器立刻判 VerifyError——「寄存器里是对象、字段要的是宽类型」。
// 这类错在本地解释器里曾经看不出来（它把 0x68 也当 sput-object 处理），
// 属于两个错误互相掩盖，因此下面留了 opcode 断言测试。
func (a *Asm) SPutObject(reg int, f FieldSpec) {
	a.patch(1, RefSpec{Kind: RefField, Word: 1, Field: f}, 0x69|uint16(reg&0xff)<<8, 0)
}

// ---- 返回 ----

// ReturnVoid 生成 return-void。
func (a *Asm) ReturnVoid() { a.emit(0x0e) }

// Return 生成 return vReg（返回 int）。
func (a *Asm) Return(reg int) { a.emit(0x0f | uint16(reg&0xff)<<8) }

// ReturnObject 生成 return-object vReg。
//
// 操作码是 0x11。写成 0x10 会变成 return-wide（返回 long/double），
// ART 的校验器会报 "return-wide not expected" 并拒绝整个类——
// 与 sput-object 那次是同一类错误：操作码的宽度选错。
func (a *Asm) ReturnObject(reg int) { a.emit(0x11 | uint16(reg&0xff)<<8) }

// ---- 分支 ----

// Goto 生成 goto :label（10t）。
func (a *Asm) Goto(label string) { a.branch(form10t, label, 0x28) }

// Goto16 生成 goto/16 :label（20t），用于距离超出 8 位范围时。
func (a *Asm) Goto16(label string) { a.branch(form20t, label, 0x29) }

// IfEqz 生成 if-eqz vReg, :label。
func (a *Asm) IfEqz(reg int, label string) { a.branch(form22t, label, 0x38|uint16(reg&0xff)<<8) }

// IfNez 生成 if-nez vReg, :label。
func (a *Asm) IfNez(reg int, label string) { a.branch(form22t, label, 0x39|uint16(reg&0xff)<<8) }

// IfEq 生成 if-eq vA, vB, :label。
func (a *Asm) IfEq(x, y int, label string) error {
	if err := checkReg4("if-eq", x, y); err != nil {
		return err
	}
	a.branch(form22t, label, 0x32|uint16(x)<<8|uint16(y)<<12)
	return nil
}

// IfNe 生成 if-ne vA, vB, :label。
func (a *Asm) IfNe(x, y int, label string) error {
	if err := checkReg4("if-ne", x, y); err != nil {
		return err
	}
	a.branch(form22t, label, 0x33|uint16(x)<<8|uint16(y)<<12)
	return nil
}

// IfLt 生成 if-lt vA, vB, :label。
func (a *Asm) IfLt(x, y int, label string) error {
	if err := checkReg4("if-lt", x, y); err != nil {
		return err
	}
	a.branch(form22t, label, 0x34|uint16(x)<<8|uint16(y)<<12)
	return nil
}

// IfGe 生成 if-ge vA, vB, :label。
func (a *Asm) IfGe(x, y int, label string) error {
	if err := checkReg4("if-ge", x, y); err != nil {
		return err
	}
	a.branch(form22t, label, 0x35|uint16(x)<<8|uint16(y)<<12)
	return nil
}

// IfGt 生成 if-gt vA, vB, :label。
func (a *Asm) IfGt(x, y int, label string) error {
	if err := checkReg4("if-gt", x, y); err != nil {
		return err
	}
	a.branch(form22t, label, 0x36|uint16(x)<<8|uint16(y)<<12)
	return nil
}

// ---- 组装 ----

// Assemble 解析全部标签与符号引用，返回指令字与待回填的补丁。
func (a *Asm) Assemble() ([]uint16, []InsnPatch, error) {
	off := make([]int, len(a.items)+1)
	for i, it := range a.items {
		off[i+1] = off[i] + len(it.words)
	}
	out := make([]uint16, off[len(a.items)])
	for i, it := range a.items {
		copy(out[off[i]:], it.words)
	}

	for _, r := range a.refs {
		tgt, ok := a.labels[r.label]
		if !ok {
			return nil, nil, fmt.Errorf("dex: 注入代码引用了未定义的标签 %q", r.label)
		}
		rel := off[tgt] - off[r.item]
		switch r.form {
		case form10t:
			if rel < -128 || rel > 127 {
				return nil, nil, fmt.Errorf(
					"dex: 注入代码的分支距离 %d 超出 goto 的 8 位范围（请改用 goto/16）", rel)
			}
			out[off[r.item]] = out[off[r.item]]&0xff | uint16(byte(int8(rel)))<<8
		case form20t, form22t:
			if rel < -32768 || rel > 32767 {
				return nil, nil, fmt.Errorf("dex: 注入代码的分支距离 %d 超出 16 位范围", rel)
			}
			out[off[r.item]+1] = uint16(int16(rel))
		case form30t:
			out[off[r.item]+1] = uint16(rel & 0xffff)
			out[off[r.item]+2] = uint16(uint32(int32(rel)) >> 16)
		default:
			return nil, nil, fmt.Errorf("dex: 注入代码不支持的分支格式 %d", r.form)
		}
	}

	var patches []InsnPatch
	for _, p := range a.patches {
		patches = append(patches, InsnPatch{At: off[p.item] + p.word, Ref: p.ref})
	}
	return out, patches, nil
}
