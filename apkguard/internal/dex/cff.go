package dex

import "sort"

// 本文件实现 A6（控制流混淆）的**最小可落地子集**：不透明谓词注入 + 等价指令替换。
//
// 明确不做基本块平坦化（dispatcher / packed-switch 重排）。排除理由见文件末尾
// 的说明，以及最终交付报告。实现结构对齐已有的两个「改写方法体」范例
// constarr.go / strenc.go：XxxAddition（本技术无池引用，故省略）→ planXxx
// （plan 字段）→ xxxCodeItem（本文件的 controlFlowCodeItem）。
//
// 三条硬约束（每一条都对应一类真机崩溃，详见各处注释）：
//  1. **绝不增大 registers_size**：入参寄存器会整体后移，原引用失配，ART VerifyError；
//  2. 只插入/替换**无池引用、无异常、纯整数**的指令：否则会干扰 A2/A3 的字符串
//     处理，或扩大 try 覆盖范围；
//  3. 所有新增分支必须通过 InsnList 登记（InsertBefore 护住原项旧偏移，
//     AppendSynth 为死代码块分配唯一旧偏移），偏移回填全部交给 Encode。

// ControlFlow 描述 A6 控制流混淆的参数。
type ControlFlow struct {
	// Seed 决定不透明谓词的常量选择，保证同一种子产出可复现的同一产物。
	Seed int64
	// MaxPredicates 是每个方法最多注入的不透明谓词组数；0 表示取默认值 1。
	//
	// 默认只注入 1 组（方法入口）：最小切片优先保证不破坏产物，插入点越少，
	// 需要重定位的分支越少，回归面越可控。
	MaxPredicates int
	// Substitute 为 true 时执行等价指令替换（add-int → neg-int + sub-int 等）。
	Substitute bool
	// MaxItems 是参与改写的方法的最大指令项数；0 表示取默认值 200。
	MaxItems int
	// JunkFill 为 true 时向方法体插入**无害花指令**：nop 填充 + 不可达前向跳转。
	//
	// 与不透明谓词的区别是它**不写任何寄存器**，因此不存在「写坏活跃寄存器」
	// 的类型冲突风险（那正是 A6 早期形态在真实应用上崩掉的原因）。
	// 代价是它只增加反编译噪音、不改变控制流图，属低强度手法，但覆盖面可以很大。
	//
	// JunkFill 是**独占模式**：开启后只做花指令填充，不注入不透明谓词、也不做
	// 等价指令替换。这样 A20（花指令）与 A6（控制流混淆）在语义上彼此独立——
	// A20 的产物里绝不会悄悄出现写寄存器的谓词（那是「偷偷开 A6」）。
	JunkFill bool
	// JunkNops 是 JunkFill 模式下每个方法插入的 nop 数量；0 表示默认 4。
	//
	// 硬上限 cffMaxJunkNops（8）：花指令的覆盖面靠「每个方法都插」，而不是
	// 「每个方法插很多」。设上限可避免小方法被撑大数倍、增加 dex2oat 与运行时
	// 校验负担，也避免入口附近的短距 goto 被迫加宽、进而扰动更多指令布局。
	JunkNops int
}

// ControlFlowStats 汇总一次 A6 改写的量化结果与跳过原因分布。
type ControlFlowStats struct {
	// MethodsRewritten 是被实际改写（插入谓词或做替换）的方法数。
	MethodsRewritten int
	// Predicates 是注入的不透明谓词组数。
	Predicates int
	// Substitutions 是执行的等价指令替换条数。
	Substitutions int
	// SkippedTry 是因含 try/catch 而跳过的方法数。
	SkippedTry int
	// SkippedPayload 是因含 switch/fill-array-data payload 而跳过的方法数。
	SkippedPayload int
	// SkippedRegisters 是因可用局部寄存器不足而跳过的方法数。
	SkippedRegisters int
	// FakeJumps 是插入「不可达跳转块」的方法数（无空闲寄存器时的兜底形态）。
	FakeJumps int
	// Nops 是 JunkFill 模式下插入的 nop 指令总数（A20）。
	Nops int
	// SkippedInit 是因是 <init>/<clinit> 而跳过的方法数。
	SkippedInit int
	// SkippedShape 是因方法体过小/过大、结尾非终结指令或含
	// invoke-polymorphic/invoke-custom 而跳过的方法数。
	SkippedShape int
}

// controlFlowPlan 是 A6 在 plan 中的落点。
type controlFlowPlan struct {
	spec  ControlFlow
	stats ControlFlowStats
}

// cffNormalize 补齐 ControlFlow 的默认值。
func cffNormalize(cf ControlFlow) ControlFlow {
	if cf.MaxPredicates <= 0 {
		cf.MaxPredicates = 1
	}
	if cf.MaxItems <= 0 {
		cf.MaxItems = 200
	}
	return cf
}

// isInitMethodName 判断方法名是否为构造器/静态初始化器。
//
// 保守跳过：它们会被 ART 的校验器与类初始化流程特殊对待，且 <clinit> 的
// 执行时机由运行时决定，插入任何多余指令都增加不可控风险。最小切片只求稳。
func isInitMethodName(name string) bool {
	return name == "<init>" || name == "<clinit>"
}

// cffIsTerminator 判断一条指令是否终结控制流（其后再无 fallthrough）。
//
// 死代码块会被追加在指令流末尾，只有确认最后一条指令不会 fallthrough 到它，
// 才能保证死代码块真的不可达——否则方法会从末尾流入死块、再跳回入口，
// 把「语义不变」变成死循环。合法 DEX 的方法末条指令必然是终结指令。
func cffIsTerminator(op byte) bool {
	switch {
	case op >= 0x0e && op <= 0x11: // return-void / return / return-wide / return-object
		return true
	case op == 0x27: // throw
		return true
	case op == 0x28 || op == 0x29 || op == 0x2a: // goto / goto/16 / goto/32
		return true
	case op == 0x2b || op == 0x2c: // packed-switch / sparse-switch
		return true
	}
	return false
}

// cffRegs 返回一条指令引用的全部寄存器（读写不区分，宁多勿漏）。
//
// ok=false 表示该操作码未在本表覆盖：调用方必须**保守跳过整个方法**。
// 绝不能「未识别就当无寄存器」，那会把活跃寄存器当成空闲的临时寄存器，
// 改写后的方法在真机上读到被篡改的值——本地解释器未必发现，ART 也未必
// 立刻报错，属于最难排查的一类静默损坏。
func cffRegs(op byte, w []uint16) (regs []int, ok bool) {
	a4 := func() int { return int(w[0] >> 8 & 0xf) }
	b4 := func() int { return int(w[0] >> 12 & 0xf) }
	aa := func() int { return int(w[0] >> 8) }
	w1b := func() int { return int(w[1] & 0xff) }
	w1c := func() int { return int(w[1] >> 8) }
	switch {
	case op == 0x00, op == 0x0e, op >= 0x28 && op <= 0x2a:
		return nil, true // nop / return-void / goto*
	case op == 0x0a, op == 0x0b, op == 0x0c, op == 0x0d,
		op == 0x0f, op == 0x10, op == 0x11, op == 0x1d, op == 0x1e, op == 0x27:
		return []int{aa()}, true // 11x
	case op == 0x12:
		return []int{a4()}, true // const/4（11n）
	case op == 0x13, op == 0x14, op == 0x15, op == 0x16, op == 0x17, op == 0x18, op == 0x19:
		return []int{aa()}, true // const*（21s/31i/21h/51l）
	case op == 0x1a, op == 0x1b, op == 0x1c, op == 0x1f, op == 0x22:
		return []int{aa()}, true // 21c/31c
	case op == 0x01, op == 0x04, op == 0x07, op == 0x21:
		return []int{a4(), b4()}, true // 12x（move/array-length）
	case op == 0x02, op == 0x05, op == 0x08:
		return []int{aa(), int(w[1])}, true // 22x move/from16
	case op == 0x03, op == 0x06, op == 0x09:
		// 32x 布局：word0 高位保留，word1=AAAA（目标）、word2=BBBB（源），共 3 字。
		// 旧实现误按 22x 解析（只读 word1），漏掉源寄存器 word2，导致该寄存器
		// 被误判为空闲、谓词写进原指令的操作数（真机静默改坏活跃值）。
		return []int{int(w[1]), int(w[2])}, true // 32x move/16
	case op == 0x20, op == 0x23:
		return []int{a4(), b4()}, true // 22c
	case op >= 0x52 && op <= 0x5f:
		return []int{a4(), b4()}, true // iget/iput（22c）
	case op >= 0x60 && op <= 0x6d:
		return []int{aa()}, true // sget/sput（21c）
	case (op >= 0x6e && op <= 0x72) || op == 0x24 || op == 0xfc:
		// 35c：A 是实参个数（高 4 位），C/D/E/F 在 word2，G 在 word0。
		// 这里一律返回全部 5 个槽位（比实际多算不误事，少算才会出事）。
		return []int{a4(), int(w[2] & 0xf), int(w[2] >> 4 & 0xf), int(w[2] >> 8 & 0xf), int(w[2] >> 12 & 0xf)}, true
	case (op >= 0x74 && op <= 0x78) || op == 0x25 || op == 0xfd:
		// 3rc：A 是寄存器个数，C（word2）是首个寄存器，覆盖 C..C+A-1。
		n, first := aa(), int(w[2])
		out := make([]int, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, first+i)
		}
		return out, true
	case op == 0xfa: // 45cc：A 是实参个数，寄存器布局同 35c
		return []int{a4(), int(w[2] & 0xf), int(w[2] >> 4 & 0xf), int(w[2] >> 8 & 0xf), int(w[2] >> 12 & 0xf)}, true
	case op == 0xfb: // 4rcc：同 3rc
		n, first := aa(), int(w[2])
		out := make([]int, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, first+i)
		}
		return out, true
	case op == 0xfe || op == 0xff:
		return []int{aa()}, true // const-method-handle / const-method-type（21c）
	case op >= 0x7b && op <= 0x8f:
		return []int{a4(), b4()}, true // 12x 一元运算（neg/not/to-*）
	case op >= 0x90 && op <= 0xaf:
		return []int{aa(), w1b(), w1c()}, true // 23x 二元运算
	case op >= 0xb0 && op <= 0xcf:
		return []int{a4(), b4()}, true // 12x .../2addr
	case op >= 0xd0 && op <= 0xd7:
		return []int{a4(), b4()}, true // 22s lit16
	case op >= 0xd8 && op <= 0xe2:
		return []int{aa(), w1b()}, true // 22b lit8
	case op >= 0x2d && op <= 0x31:
		return []int{aa(), w1b(), w1c()}, true // 23x cmp
	case op >= 0x32 && op <= 0x37:
		return []int{a4(), b4()}, true // 22t if-*
	case op >= 0x38 && op <= 0x3d:
		return []int{aa()}, true // 21t if-*z
	case op >= 0x44 && op <= 0x51:
		return []int{aa(), w1b(), w1c()}, true // 23x aget/aput
	case op == 0x26 || op == 0x2b || op == 0x2c:
		return []int{aa()}, true // 31t fill-array-data / switch
	}
	return nil, false
}

// cffSubstitute 返回一条等价替换后的指令字；ok=false 表示不做替换。
//
// 只接受「纯整数、无副作用、不抛异常、无池引用」的指令，且替换序列只使用
// 本地解释器（interp_test.go）已实现的操作码——否则强制的语义等价测试
// 无法执行。为此刻意**不使用** and-int/lit8、sub-int/lit8：方案文档给出的
// 谓词模板用了 and-int/lit8，但本地解释器没有实现 0xdd，改用寄存器形式
// and-int 后语义完全相同。
//
// tmp 必须是一个方法内未被读写的空闲局部寄存器，且编号 ≤15（neg-int/not-int
// 是 12x 格式，只有 4 位寄存器字段）。
func cffSubstitute(w []uint16, tmp int) ([]uint16, bool) {
	if len(w) == 0 || tmp < 0 || tmp > 15 {
		return nil, false
	}
	op := byte(w[0] & 0xff)
	switch op {
	case 0x90: // add-int vD,vA,vB  →  neg-int vT,vB; sub-int vD,vA,vT
		d, a, b := int(w[0]>>8), int(w[1]&0xff), int(w[1]>>8)
		if b > 15 {
			return nil, false // neg-int 的目标/源只能是 4 位寄存器
		}
		return []uint16{
			0x7b | uint16(tmp)<<8 | uint16(b)<<12,
			0x91 | uint16(d)<<8, uint16(a) | uint16(tmp)<<8,
		}, true
	case 0x91: // sub-int vD,vA,vB  →  neg-int vT,vB; add-int vD,vA,vT
		d, a, b := int(w[0]>>8), int(w[1]&0xff), int(w[1]>>8)
		if b > 15 {
			return nil, false
		}
		return []uint16{
			0x7b | uint16(tmp)<<8 | uint16(b)<<12,
			0x90 | uint16(d)<<8, uint16(a) | uint16(tmp)<<8,
		}, true
	case 0xd8: // add-int/lit8 vA,vB,#k  →  const/16 vT,#k; add-int vA,vB,vT
		a, b := int(w[0]>>8), int(w[1]&0xff)
		k := int16(int8(w[1] >> 8))
		return []uint16{
			0x13 | uint16(tmp)<<8, uint16(k),
			0x90 | uint16(a)<<8, uint16(b) | uint16(tmp)<<8,
		}, true
	case 0xda: // mul-int/lit8 vA,vB,#k  →  const/16 vT,#k; mul-int vA,vB,vT
		a, b := int(w[0]>>8), int(w[1]&0xff)
		k := int16(int8(w[1] >> 8))
		return []uint16{
			0x13 | uint16(tmp)<<8, uint16(k),
			0x92 | uint16(a)<<8, uint16(b) | uint16(tmp)<<8,
		}, true
	case 0x7b: // neg-int vD,vA  →  not-int vD,vA; add-int/lit8 vD,vD,#1（-x == ~x+1）
		d, a := int(w[0]>>8&0xf), int(w[0]>>12&0xf)
		return []uint16{
			0x7c | uint16(d)<<8 | uint16(a)<<12,
			0xd8 | uint16(d)<<8, uint16(d) | 0x01<<8,
		}, true
	case 0x7c: // not-int vD,vA  →  neg-int vD,vA; add-int/lit8 vD,vD,#-1（~x == -x-1）
		d, a := int(w[0]>>8&0xf), int(w[0]>>12&0xf)
		return []uint16{
			0x7b | uint16(d)<<8 | uint16(a)<<12,
			0xd8 | uint16(d)<<8, uint16(d) | 0xff<<8,
		}, true
	}
	return nil, false
}

// cffConst 由种子与方法名确定性地派生一个 16 位谓词常量。
//
// 谓词的正确性不依赖常量的具体取值；随机化只是让不同方法的谓词序列不同，
// 避免「一模一样的前缀」成为批量识别特征。刻意避开 0/±1 这类一眼可折叠的值。
func cffConst(seed int64, name string) int16 {
	h := uint64(seed)*1099511628211 + 1469598103934665603
	for i := 0; i < len(name); i++ {
		h ^= uint64(name[i])
		h *= 1099511628211
	}
	v := int16(h & 0xffff)
	switch v {
	case 0, 1, -1:
		v += 3
	}
	return v
}

// cffInsertable 判断第 i 项之前是否适合插入谓词。
//
// move-result*（0x0a-0x0c）与 move-exception（0x0d）必须紧跟在 invoke/异常
// 入口之后；在它们之前插入指令会触发 ART
//
//	VerifyError: move-result-object not immediately after invoke
//
// 并拒绝整个类，因此这类锚点一律排除。
func cffInsertable(l *InsnList, i int) bool {
	if i < 0 || i >= l.ItemCount() || !l.ItemIsInsn(i) {
		return false
	}
	op := byte(l.ItemWords(i)[0] & 0xff)
	return op < 0x0a || op > 0x0d
}

// predicateInsns 构造一组不透明谓词指令。
//
// 恒真证明：对任意 32 位整数 c，c*(c-1) 恒为偶数（相邻整数必有一个偶数），
// 其最低位恒为 0；取最低位后寄存器恒为 0，故 if-eqz 恒成立。乘法的溢出回绕
// 不改变最低位，因此该性质在 32 位环绕下依然成立。
//
// 关键设计：全部指令都是纯整数运算，**无任何池引用、不抛异常、不读未初始化
// 寄存器、不动 ins 入参寄存器**（vP/vT 只取方法内空闲局部寄存器）。因此它既
// 不会干扰 A2/A3 的字符串池处理，也不会改变 try 覆盖范围，ART 校验器也不会
// 做常量折叠。
//
// 返回 8 条指令：前 6 条计算谓词，第 7 条 if-eqz 恒真跳向「真实入口」，
// 第 8 条 goto/16 通向死代码块（恒假分支）。
func predicateInsns(vP, vT int, c int16) [][]uint16 {
	return [][]uint16{
		{0x13 | uint16(vP)<<8, uint16(c)},                  // const/16 vP, #c
		{0x13 | uint16(vT)<<8, uint16(c)},                  // const/16 vT, #c
		{0x92 | uint16(vP)<<8, uint16(vP) | uint16(vP)<<8}, // mul-int vP, vP, vP  → c*c
		{0x91 | uint16(vP)<<8, uint16(vP) | uint16(vT)<<8}, // sub-int vP, vP, vT  → c*c-c
		{0x13 | uint16(vT)<<8, 1},                          // const/16 vT, #1
		{0x95 | uint16(vP)<<8, uint16(vP) | uint16(vT)<<8}, // and-int vP, vP, vT  → 恒 0
		{0x38 | uint16(vP)<<8, 0},                          // if-eqz vP, :real（偏移由 Encode 回填）
		{0x29, 0},                                          // goto/16 :real（恒假分支，同样前向汇合）
	}
}

// controlFlowCodeItem 对单个 code_item 实施 A6 改写。
//
// 输入 src 是「当前形态」的 code_item 字节流。返回的 blob 尚未做索引重映射；
// 本技术不新增任何池引用，因此 skip 恒为 nil。changed=false 时调用方沿用原字节。
func (b *builder) controlFlowCodeItem(pl *plan, methodName string, src []byte) (blob []byte, skip map[int]bool, changed bool, err error) {
	cfp := pl.controlFlow
	if cfp == nil {
		return nil, nil, false, nil
	}
	cf := cfp.spec
	st := &cfp.stats

	if isInitMethodName(methodName) {
		// <init>/<clinit> 可能被校验器特殊对待，保守跳过。
		st.SkippedInit++
		return nil, nil, false, nil
	}

	ci, err := ParseCodeItemBytes(src)
	if err != nil {
		return nil, nil, false, err
	}

	// 含 try/catch：插入会平移 try 区间端点，ART 会因端点不落在指令边界而
	// 拒绝整个 DEX（"Bogus handler offset" 一类）。最小切片直接跳过。
	if len(ci.Tries) != 0 {
		st.SkippedTry++
		return nil, nil, false, nil
	}

	l, err := ParseInsns(ci.Insns)
	if err != nil {
		return nil, nil, false, err
	}

	// 含 switch / fill-array-data payload：payload 是内联伪指令，其 target 基准
	// 与 4 字节对齐规则一旦被插入项打乱，ART 会判 "invalid switch target"。
	// 最小切片直接跳过。
	for i := 0; i < l.ItemCount(); i++ {
		if !l.ItemIsInsn(i) {
			st.SkippedPayload++
			return nil, nil, false, nil
		}
	}

	// 方法体过小没有足够插入点；过大则改写收益低、影响面大，都跳过。
	if l.ItemCount() < 2 || l.ItemCount() > cf.MaxItems {
		st.SkippedShape++
		return nil, nil, false, nil
	}

	// 末尾必须是终结指令，否则追加的死代码块可能被 fallthrough 命中。
	lastOp := byte(l.ItemWords(l.ItemCount() - 1)[0] & 0xff)
	if !cffIsTerminator(lastOp) {
		st.SkippedShape++
		return nil, nil, false, nil
	}

	// ---- A20：无害花指令填充（JunkFill，独占模式） ----
	//
	// 放在「形状/终结指令」判定之后、**寄存器扫描之前**：花指令不读写任何寄存器，
	// 不需要（也不应依赖）寄存器使用信息，因此即便某方法含未覆盖的操作码，只要它
	// 不含 try/payload、方法体规模合适，就仍然可以安全地填充，覆盖面由此最大化。
	//
	// 安全论证：本分支插入的指令只有 nop（0x00，无副作用）与 goto/16（0x29，只改
	// pc），两者都**不产生任何寄存器定义或使用**。ART 校验器在真实入口处合并到的
	// 类型状态与改写前逐位相同，因此不可能出现 A6 早期形态那种
	//   VerifyError: Verifier rejected class pan.bbu: [0x6D] wide register v7
	//   has type Low-half Constant/Conflict
	// （RustDesk/Dhizuku 开启「会在入口写寄存器」的 A6 即崩、关掉即正常。）
	// 这是 A20 能覆盖到极大方法集合却几乎没有真机回归风险的根因。
	if cf.JunkFill {
		return b.junkFillCodeItem(pl, ci, l)
	}

	// 扫描活跃寄存器：任何未覆盖的操作码都导致整个方法跳过。
	used := map[int]bool{}
	for i := 0; i < l.ItemCount(); i++ {
		w := l.ItemWords(i)
		op := byte(w[0] & 0xff)
		// invoke-polymorphic / invoke-custom 的引用处理不完整，保守跳过。
		if op >= 0xfa && op <= 0xfd {
			st.SkippedShape++
			return nil, nil, false, nil
		}
		rs, ok := cffRegs(op, w)
		if !ok {
			st.SkippedShape++
			return nil, nil, false, nil
		}
		for _, r := range rs {
			used[r] = true
			// **必须把相邻寄存器也算占用**：DEX 里 long/double 占**两个**寄存器
			// （低半 r、高半 r+1），而 cffRegs 只报告指令显式写出的那一个。
			// 若只按 rs 判"空闲"，我们会挑中某个宽值的高半，往里写一个 int 常量，
			// 校验器随即报
			//   VerifyError: ... wide register v4 has type Long (Low Half)/Integer
			// （实测 Dhizuku 的 dqg.equals/hashCode 与 RustDesk 的 pan.bbu.c，
			// 都是 A6 一开就崩、关掉即正常。）
			// 多算一格只会让我们更保守（少挑几个寄存器），不会写坏任何值。
			if r+1 <= 15 {
				used[r+1] = true
			}
		}
	}

	// ---- 寄存器预算：只从「寄存器数 - ins」的空闲局部寄存器里取，且编号 ≤15 ----
	//
	// 绝不增大 registers_size：入参寄存器位于最高编号段，一旦增大 R，所有入参
	// 整体后移，原指令仍引用旧编号 → 读到错误的参数。本地解释器可能不报错，
	// 真机 ART 直接 VerifyError。这是本项最硬的约束。
	locals := int(ci.Registers) - int(ci.Ins)
	var free []int
	for r := 0; r < locals && r <= 15; r++ {
		if !used[r] {
			free = append(free, r)
		}
	}
	// 谓词必须只用「全方法从未被引用」的寄存器。
	//
	// 这里曾放松成「入口处可复用任意局部寄存器」，理由是入口尚未定义任何局部量。
	// 实测证明那是**错的**：ART 校验器在入口处把未定义寄存器视为可匹配任意类型，
	// 一旦我们在入口写进一个 int 常量，后续某条路径上该寄存器被当作宽值
	// （long/double）使用时就变成「常量 vs 宽值低半」的类型冲突，真机直接
	//
	//	VerifyError: Verifier rejected class pan.bbu:
	//	  [0x6D] wide register v7 has type Low-half Constant/Conflict
	//
	// （RustDesk 与 Dhizuku 都是开启 A6 即崩、关掉即正常。）
	// 要安全地复用「可能活跃」的寄存器，需要真正的寄存器类型/活跃性分析——
	// 那是后续工作；在那之前只认「从未被引用」这一条可证明安全的判据。
	//
	// 代价是优化过的 DEX 里这种寄存器很少，于是谓词往往插不进去。
	// 为此下面提供了**不写任何寄存器**的兜底形态（不可达跳转块），
	// 保证 A6 在真实产物上始终有效，而不是静默地什么都不做。
	var vP, vT int
	havePredicate := false
	if len(free) >= 2 {
		vP, vT = free[0], free[1]
		havePredicate = true
	} else {
		st.SkippedRegisters++
	}
	// 替换的临时寄存器必须「全方法未被引用」（替换发生在任意位置，
	// 复用可能活跃的寄存器会写坏原值）；没有这种寄存器就退化为只做谓词。
	vS, hasVS := 0, false
	if len(free) >= 1 {
		vS, hasVS = free[0], true
	}

	did := false

	// ---- 指令替换（等价改写） ----
	if cf.Substitute && hasVS {
		for i := 0; i < l.ItemCount(); i++ {
			if !l.ItemIsInsn(i) {
				continue
			}
			if nw, ok := cffSubstitute(l.ItemWords(i), vS); ok {
				l.Replace(i, nw)
				st.Substitutions++
				did = true
			}
		}
	}

	// ---- 不透明谓词注入 ----
	anchors := []int{0}
	if cf.MaxPredicates > 1 {
		tset := map[int]bool{}
		for _, br := range l.branches {
			tset[br.target] = true
		}
		oldToItem := map[int]int{}
		for i := 0; i < l.ItemCount(); i++ {
			oldToItem[l.ItemOldOffset(i)] = i
		}
		for t := range tset {
			if i, ok := oldToItem[t]; ok && i != 0 {
				anchors = append(anchors, i)
			}
		}
	}
	sort.Ints(anchors)
	// 没有空闲寄存器时的兜底：插入一个**不可达跳转块**。
	//
	// 形态是「goto/16 :real; goto/16 :real」——第一条无条件跳过第二条，
	// 第二条永远不可达，但结构上完全合法（连续的无条件跳转在正常编译产物里
	// 不会出现，因此它本身就是「这里被人为改过」的信号，也是虚假控制流的最小形态）。
	// 关键性质：**不写任何寄存器**，因此不存在类型冲突的可能；
	// 两条跳转都前向汇聚到真实入口，校验器合并的两条路径状态完全相同。
	if !havePredicate {
		for _, a := range anchors {
			if !cffInsertable(l, a) {
				continue
			}
			realOld := l.ItemOldOffset(a)
			l.InsertBefore(a, []uint16{0x29, 0}, []uint16{0x29, 0})
			l.AddBranch(a, 1, 0, realOld, form20t)
			l.AddBranch(a+1, 1, 0, realOld, form20t)
			st.FakeJumps++
			st.MethodsRewritten++
			did = true
			break // 每方法一个即可，避免无谓膨胀
		}
		if !did {
			return nil, nil, false, nil
		}
		insns, m, fresh, eerr := l.EncodeChecked()
		if eerr != nil {
			return nil, nil, false, eerr
		}
		ci.Insns = insns
		return ci.Encode(func(old uint32) uint32 { return FixAddr(m, old) }), fresh, true, nil
	}

	var picked []int
	seen := map[int]bool{}
	for _, a := range anchors {
		if seen[a] || !cffInsertable(l, a) {
			continue
		}
		seen[a] = true
		picked = append(picked, a)
		if len(picked) >= cf.MaxPredicates {
			break
		}
	}

	// 每个谓词的落地信息：if-eqz 所在项、goto/16 :decoy 所在项、以及该谓词
	// 对应的「真实入口」旧偏移（死代码块要跳回它）。
	type predSlot struct {
		ifEqz, gotoDecoy int
		realOld          int
	}
	var slots []predSlot
	c := cffConst(cf.Seed, methodName)

	// 从后往前插入：InsertBefore 会平移其后的项下标，倒序处理可让尚未处理的
	// 较小锚点下标保持有效。
	//
	// 注意：在较小的 idx 处插入，会把**已记录的高位锚点槽位**整体后移 8 项。
	// 若不修正，MaxPredicates>1 时先记录的那些槽位会指向错误项，登记的分支
	// 落在别的指令上——产物结构仍「看起来合法」，但语义错乱。这里每插入一次
	// 就把已有槽位加 8（它们全部位于刚插入位置之后）。
	for k := len(picked) - 1; k >= 0; k-- {
		idx := picked[k]
		realOld := l.ItemOldOffset(idx)
		l.InsertBefore(idx, predicateInsns(vP, vT, c)...)
		for j := range slots {
			slots[j].ifEqz += 8
			slots[j].gotoDecoy += 8
		}
		slots = append(slots, predSlot{ifEqz: idx + 6, gotoDecoy: idx + 7, realOld: realOld})
		st.Predicates++
		did = true
	}

	// ---- 两条分支都**前向**汇合到真实入口 ----
	//
	// 这里刻意不追加「尾部死代码块 + 跳回入口」那种形态。原因是 ART 校验器
	// 会把「跳回方法入口」当成一条**回边**，于是在入口处必须合并「入口类型状态」
	// 与「方法末尾类型状态」——凡是宽度发生变化的寄存器都会冲突，真机直接
	//   VerifyError: Verifier rejected class ...: [0x6D] wide register v7
	//   has type Low-half Constant/Conflict
	// （实测 RustDesk：A6 一开就崩，关掉立刻正常；Dhizuku 同样。）
	//
	// 改为「if-eqz 恒真走 :real，恒假分支用 goto/16 也前向跳到 :real」：
	// 结构上仍是一条条件分支 + 一条冗余跳转（不透明谓词的本意），但不产生回边，
	// 校验器只需合并两条**同源**路径的状态（vP/vT 两边都是 int），必然一致。
	for _, s := range slots {
		// if-eqz 恒真：直接落到真实入口。
		l.AddBranch(s.ifEqz, 1, 0, s.realOld, form22t)
		// 恒假分支：同样前向跳到真实入口（不产生回边）。
		l.AddBranch(s.gotoDecoy, 1, 0, s.realOld, form20t)
	}

	if !did {
		return nil, nil, false, nil
	}

	insns, m, fresh, eerr := l.EncodeChecked()
	if eerr != nil {
		return nil, nil, false, eerr
	}
	// 不新增 invoke，outs_size 保持原值；不触碰 Registers，入参编号不变。
	ci.Insns = insns
	st.MethodsRewritten++
	// try/handler 偏移统一交给 Encode 重算（本切片不处理含 try 的方法，
	// 但仍走同一条修正路径，保证行为与 A2/A3 一致）。
	return ci.Encode(func(old uint32) uint32 { return FixAddr(m, old) }), fresh, true, nil
}

// cffMaxJunkNops 是 JunkFill 模式下每个方法插入 nop 的硬上限。
//
// 理由：花指令的价值来自「每个方法都插一点」带来的全局噪音，而不是单个方法里
// 堆很多。上限 8 使单方法最多膨胀 8 个字（nop）+ 4 个字（两条 goto/16），
// 相对常见方法体（几十到几百字）占比很小；无上限则小方法可能被撑大数倍，
// 既拖慢 dex2oat/校验，又可能把入口附近的短距 goto 逼出 8 位范围而被迫加宽。
const cffMaxJunkNops = 8

// junkFillCodeItem 对单个 code_item 实施 A20 无害花指令填充。
//
// 插入形态（以入口为锚点）：
//
//	nop × N ; goto/16 :real ; goto/16 :real ; :real <原第一条指令>
//
// 第一条 goto 无条件跳过第二条，两条都**前向**汇聚到真实入口，第二条永远不可达。
// 执行时前 N 个 nop 无副作用地落入第一条 goto，随即跳到真实入口，因此改写前后
// 逐位语义相同。刻意不追加「尾部死代码块 + 跳回入口」，因为跳回入口会形成回边，
// 校验器须在入口处合并入口态与末尾态，宽值寄存器可能冲突（A6 早期形态的真机崩溃）。
//
// 插入项与入口锚点共享旧偏移，Encode 的 old2new 以最后出现的项为准，因此
// 旧偏移 0 映射到**锚点**的新位置：两条 goto 以及任何原有「跳回入口」的分支都会
// 落到真实入口，而不是落进花指令块。
func (b *builder) junkFillCodeItem(pl *plan, ci *CodeItemFull, l *InsnList) ([]byte, map[int]bool, bool, error) {
	st := &pl.controlFlow.stats
	cf := pl.controlFlow.spec

	// 入口若恰好是 move-result*/move-exception（正常编译产物不会出现），
	// 不能在其前插入——ART 要求 move-result 紧跟 invoke。
	if !cffInsertable(l, 0) {
		st.SkippedShape++
		return nil, nil, false, nil
	}

	nops := cf.JunkNops
	if nops <= 0 {
		nops = 4
	}
	if nops > cffMaxJunkNops {
		nops = cffMaxJunkNops
	}

	realOld := l.ItemOldOffset(0)

	insns := make([][]uint16, 0, nops+2)
	for i := 0; i < nops; i++ {
		insns = append(insns, []uint16{0x0000}) // nop
	}
	// 两条 goto/16 的偏移字段由 Encode 依据 target 回填。
	insns = append(insns, []uint16{0x0029, 0}, []uint16{0x0029, 0})
	l.InsertBefore(0, insns...)

	// 插入后两条 goto 的项下标：nops 个 nop 之后依次是 0x29、0x29。
	l.AddBranch(nops, 1, 0, realOld, form20t)
	l.AddBranch(nops+1, 1, 0, realOld, form20t)

	st.Nops += nops
	st.FakeJumps++
	st.MethodsRewritten++

	out, m, fresh, eerr := l.EncodeChecked()
	if eerr != nil {
		return nil, nil, false, eerr
	}
	ci.Insns = out
	return ci.Encode(func(old uint32) uint32 { return FixAddr(m, old) }), fresh, true, nil
}

// 为什么最小切片不做基本块平坦化（dispatcher / packed-switch 重排）：
//
//  1. 平坦化需要把原块出口改写为「设置状态变量 + goto dispatcher」，这会改变
//     原 gotos/fallthrough 的目标集合，进而要求 payload 的 owner 关系、switch
//     target 的基准（相对 switch 指令而非 payload）全部重建；任一处理不当，
//     ART 报 "invalid switch target" 并拒绝整个类。
//  2. 方案文档 §5.1 已指出：InsnList 只支持插入与单条替换，Encode 依赖
//     「items 按 old 递增」推导流末尾（异常表区间端点映射）。物理重排会破坏
//     该假设，可能把 try 端点映射到错误位置。
//  3. 本项目的验收要求「不破坏三真实应用」。真实应用遍布 try/catch 与 switch，
//     而平坦化恰在这些形态上风险最高。最小切片选择先交付不透明谓词 + 等价
//     指令替换（CFF 三子技术中的 2 项），把平坦化留待有真机回归支撑的完整版。
