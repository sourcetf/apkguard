package dex

import (
	"bytes"
	"os"
	"testing"
)

// ---- A6 控制流混淆回归测试 ----
//
// 断言分成四层，分别防住不同的回归：
//  1. 结构不变量（Verify / ValidateDescriptors / 分支边界 / try-handler / outs）：
//     防「产物结构损坏，ART 拒绝整个 DEX」；
//  2. 语义等价（本地解释器逐方法比对返回值）：防「谓词非恒真、替换不等价、
//     块出口映射错误」——这是最强的一条，因为结构合法但语义错乱同样致命；
//  3. registers_size 不变：防「入参寄存器整体后移」这类本地看不出的真机崩；
//  4. 跳过即不变（含 try/payload 的方法逐字节未变）：防「跳过判定写错，
//     误改了不该改的方法」。

// cffFixture 构造一个测试用 DEX，包含若干可被 A6 改写的方法与一个含
// packed-switch payload（应被跳过）的方法。
//
// 注入的方法在第一次 Build 后即成为「原有方法」，因此第二次带 ControlFlow 的
// Rebuild 会把它们纳入候选——这正是 A6 的实际工作路径。
func cffFixture(t *testing.T) []byte {
	t.Helper()
	protoAdd := ProtoSpec{Ret: "I", Params: []string{"I", "I"}}
	protoOne := ProtoSpec{Ret: "I", Params: []string{"I"}}

	mustAsm := func(fn func(*Asm)) *CodeBlob {
		a := NewAsm()
		fn(a)
		insns, patches, err := a.Assemble()
		if err != nil {
			t.Fatalf("汇编测试方法失败: %v", err)
		}
		return &CodeBlob{Insns: insns, Patches: patches}
	}

	// add(a,b) = a+b；registers=5、ins=2 → 局部 v0..v2，其中 v1/v2 空闲。
	codeAdd := mustAsm(func(a *Asm) {
		a.AddInt(0, 3, 4)
		a.Return(0)
	})
	codeAdd.Registers, codeAdd.Ins, codeAdd.Outs = 5, 2, 0

	// loop(n) = sum(0..n-1)；含 if/goto，检验分支重定位。
	// registers=7、ins=1 → 局部 v0..v5，v2..v5 空闲。
	codeLoop := mustAsm(func(a *Asm) {
		a.Const4(0, 0)
		a.Const4(1, 0)
		a.Label("loop")
		if err := a.IfGe(0, 6, "end"); err != nil {
			t.Fatal(err)
		}
		a.AddInt(1, 1, 0)
		a.AddIntLit8(0, 1)
		a.Goto16("loop")
		a.Label("end")
		a.Return(1)
	})
	codeLoop.Registers, codeLoop.Ins, codeLoop.Outs = 7, 1, 0

	// mix(n) = -2n；覆盖 add/sub/mul-lit8/neg 多种可替换指令。
	codeMix := mustAsm(func(a *Asm) {
		a.Const16(0, 7)
		a.AddInt(1, 6, 0)
		a.SubInt(2, 1, 0)
		a.MulIntLit8(2, 3)
		a.NegInt(3, 2)
		a.AddInt(0, 3, 6)
		a.Return(0)
	})
	codeMix.Registers, codeMix.Ins, codeMix.Outs = 7, 1, 0

	// sw(n)：手工构造 packed-switch + payload，A6 必须整体跳过。
	//   word0-2 packed-switch v0, +4（payload 在 word4）
	//   word3   nop（4 字节对齐填充）
	//   word4-9 packed-switch-payload（size=1, target 相对 switch = +10）
	//   word10  return v3
	swWords := []uint16{
		0x002b, 4, 0,
		0x0000,
		0x0100, 1,
		0, 0,
		10, 0,
		0x030f,
	}
	codeSW := &CodeBlob{Registers: 4, Ins: 1, Outs: 0, Insns: swWords}

	// bits(n) = n + ~n = -1；专门覆盖 not-int 的等价替换。
	codeBits := mustAsm(func(a *Asm) {
		a.NotInt(0, 6)
		a.AddInt(1, 6, 0)
		a.Return(1)
	})
	codeBits.Registers, codeBits.Ins, codeBits.Outs = 7, 1, 0

	add := Addition{Classes: []ClassSpec{{
		Name:  "Lcff/T;",
		Super: "Ljava/lang/Object;",
		// 类级标志不含 STATIC（那是成员标志）。
		Access: accPublic | accFinal,
		Methods: []ClassMethod{
			{Name: "add", Proto: protoAdd, Access: accPublic | accStatic, Code: codeAdd},
			{Name: "loop", Proto: protoOne, Access: accPublic | accStatic, Code: codeLoop},
			{Name: "mix", Proto: protoOne, Access: accPublic | accStatic, Code: codeMix},
			{Name: "bits", Proto: protoOne, Access: accPublic | accStatic, Code: codeBits},
			{Name: "sw", Proto: protoOne, Access: accPublic | accStatic, Code: codeSW},
		},
	}}}
	data, err := Build(add)
	if err != nil {
		t.Fatalf("构造测试 DEX 失败: %v", err)
	}
	return data
}

// cffRawCode 返回某方法 code_item 的原始字节。
func cffRawCode(t *testing.T, f *File, m EncodedMethod) []byte {
	t.Helper()
	ci, err := f.ParseCodeItem(m.CodeOff)
	if err != nil {
		t.Fatalf("解析 code_item @%d 失败: %v", m.CodeOff, err)
	}
	n := len(ci.Encode(nil))
	d := f.Data()
	return append([]byte(nil), d[int(m.CodeOff):int(m.CodeOff)+n]...)
}

// cffMethodCode 返回「方法描述符 -> code_item 原始字节」。
func cffMethodCode(t *testing.T, f *File) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	if err := f.AllMethods(func(_, desc string, m EncodedMethod) error {
		if m.CodeOff == 0 {
			return nil
		}
		out[desc] = cffRawCode(t, f, m)
		return nil
	}); err != nil {
		t.Fatalf("遍历方法失败: %v", err)
	}
	return out
}

// cffMethodFlag 返回「方法描述符 -> 是否含 try / 是否含 payload」。
func cffMethodFlag(t *testing.T, f *File) map[string][2]bool {
	t.Helper()
	out := map[string][2]bool{}
	if err := f.AllMethods(func(_, desc string, m EncodedMethod) error {
		if m.CodeOff == 0 {
			return nil
		}
		ci, err := f.ParseCodeItem(m.CodeOff)
		if err != nil {
			return nil
		}
		l, err := ParseInsns(ci.Insns)
		if err != nil {
			return nil
		}
		hasPayload := false
		for i := 0; i < l.ItemCount(); i++ {
			if !l.ItemIsInsn(i) {
				hasPayload = true
			}
		}
		out[desc] = [2]bool{len(ci.Tries) > 0, hasPayload}
		return nil
	}); err != nil {
		t.Fatalf("遍历方法失败: %v", err)
	}
	return out
}

// cffFind 按类与方法名前缀定位 code_item。
func cffFind(t *testing.T, f *File, class, descPart string) (*CodeItemFull, uint32, uint32) {
	t.Helper()
	idx, off := findMethod(t, f, class, descPart)
	ci, err := f.ParseCodeItem(off)
	if err != nil {
		t.Fatalf("解析 %s %s 失败: %v", class, descPart, err)
	}
	return ci, idx, off
}

// TestCffSemanticEquivalence 用本地解释器验证改写前后语义完全一致。
//
// 同时断言 registers_size / outs_size 不变——它们是最容易被忽略、却会让真机
// 直接 VerifyError 的两项。
func TestCffSemanticEquivalence(t *testing.T) {
	base := cffFixture(t)
	f0, err := Parse(base)
	if err != nil {
		t.Fatalf("解析测试 DEX 失败: %v", err)
	}

	type runCase struct {
		name string
		args []any
	}
	cases := []runCase{
		{"->add(", []any{int32(3), int32(5)}},
		{"->add(", []any{int32(-7), int32(20)}},
		{"->loop(", []any{int32(5)}},
		{"->loop(", []any{int32(1)}},
		{"->loop(", []any{int32(0)}},
		{"->mix(", []any{int32(4)}},
		{"->mix(", []any{int32(-3)}},
		{"->bits(", []any{int32(42)}},
		{"->bits(", []any{int32(-1)}},
	}

	// 改写前的结果与寄存器/outs 快照。
	type snap struct {
		res  any
		regs uint16
		outs uint16
	}
	before := make([]snap, len(cases))
	for i, c := range cases {
		ci, idx, off := cffFind(t, f0, "Lcff/T;", c.name)
		v, err := runPadMethod(f0, idx, off, c.args...)
		if err != nil {
			t.Fatalf("改写前执行 %s%v 失败: %v", c.name, c.args, err)
		}
		before[i] = snap{res: v, regs: ci.Registers, outs: ci.Outs}
	}

	out, st, err := RebuildWithStats(f0, RebuildOptions{
		ControlFlow: &ControlFlow{Seed: 12345, MaxPredicates: 1, Substitute: true},
	})
	if err != nil {
		t.Fatalf("A6 重建失败: %v", err)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("A6 产物 Verify 失败（ART 会拒绝加载）: %v", err)
	}
	if err := ValidateDescriptors(out); err != nil {
		t.Fatalf("A6 产物描述符非法: %v", err)
	}
	if st.ControlFlow.MethodsRewritten < 4 {
		t.Fatalf("应至少改写 add/loop/mix/bits 四个方法，实际 %d（谓词 %d、替换 %d）",
			st.ControlFlow.MethodsRewritten, st.ControlFlow.Predicates, st.ControlFlow.Substitutions)
	}
	// 两类插入任一发生即可：谓词/替换都需要「全方法未引用、且相邻格也未引用」的
	// 寄存器（DEX 的 long/double 占两格，只按显式寄存器判空闲会写坏宽值的高半，
	// 实测 Dhizuku/RustDesk 因此 VerifyError）。优化过的 DEX 里这种寄存器很少，
	// 于是多数方法回退到**不需要寄存器**的不可达跳转块。断言的是"确实改写了"，
	// 而不是"必须用某一种技术"—— 后者会让测试随寄存器分布变化而假失败。
	if st.ControlFlow.MethodsRewritten < 4 {
		t.Fatalf("应至少改写 4 个方法，实际 %d", st.ControlFlow.MethodsRewritten)
	}
	if st.ControlFlow.Predicates+st.ControlFlow.FakeJumps == 0 {
		t.Fatalf("既没有谓词也没有不可达跳转块：A6 静默失效")
	}

	f1, err := Parse(out)
	if err != nil {
		t.Fatalf("解析 A6 产物失败: %v", err)
	}
	for i, c := range cases {
		ci, idx, off := cffFind(t, f1, "Lcff/T;", c.name)
		v, err := runPadMethod(f1, idx, off, c.args...)
		if err != nil {
			t.Fatalf("改写后执行 %s%v 失败: %v", c.name, c.args, err)
		}
		if v != before[i].res {
			t.Errorf("%s%v 改写前后返回值不同：%v → %v（谓词非恒真或替换不等价）",
				c.name, c.args, before[i].res, v)
		}
		if ci.Registers != before[i].regs {
			t.Errorf("%s 的 registers_size 被改变：%d → %d（入参会整体后移，ART VerifyError）",
				c.name, before[i].regs, ci.Registers)
		}
		if ci.Outs != before[i].outs {
			t.Errorf("%s 的 outs_size 被改变：%d → %d", c.name, before[i].outs, ci.Outs)
		}
	}

	// 产物级结构体检：分支目标、try/handler、outs。
	if n := checkBranchTargets(t, "cff-fixture", f1); n == 0 {
		t.Errorf("产物中未检查到任何分支，测试样本失效")
	}
	checkTryHandlers(t, "cff-fixture", f1)
	if n := checkOutsOf(t, "cff-fixture", f1); n == 0 {
		t.Errorf("产物中未检查到任何方法体，测试样本失效")
	}
}

// TestCffMultiPredicateSemantics 覆盖 MaxPredicates>1 的多锚点插入路径。
//
// 多个锚点从后往前插入时，低位插入会把已记录的高位槽位整体后移；若槽位下标
// 不及时修正，登记的分支会落在别的指令上，语义随之错乱。这里用 loop（含
// 分支目标，可产生 2 个锚点）做语义等价断言，专门钉住这个回归。
func TestCffMultiPredicateSemantics(t *testing.T) {
	base := cffFixture(t)
	f0, err := Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	type rc struct {
		name string
		args []any
	}
	cases := []rc{
		{"->loop(", []any{int32(6)}},
		{"->add(", []any{int32(9), int32(4)}},
		{"->bits(", []any{int32(0)}},
	}
	before := make([]any, len(cases))
	for i, c := range cases {
		_, idx, off := cffFind(t, f0, "Lcff/T;", c.name)
		v, err := runPadMethod(f0, idx, off, c.args...)
		if err != nil {
			t.Fatalf("改写前执行失败: %v", err)
		}
		before[i] = v
	}

	out, st, err := RebuildWithStats(f0, RebuildOptions{
		ControlFlow: &ControlFlow{Seed: 321, MaxPredicates: 2, Substitute: true},
	})
	if err != nil {
		t.Fatalf("A6 重建失败: %v", err)
	}
	if err := Verify(out); err != nil {
		t.Fatal(err)
	}
	if err := ValidateDescriptors(out); err != nil {
		t.Fatal(err)
	}
	if st.ControlFlow.MethodsRewritten == 0 {
		t.Fatalf("没有改写任何方法：A6 静默失效")
	}
	if st.ControlFlow.Predicates+st.ControlFlow.FakeJumps == 0 {
		t.Fatalf("既没有谓词也没有不可达跳转块：A6 静默失效")
	}
	f1, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	for i, c := range cases {
		_, idx, off := cffFind(t, f1, "Lcff/T;", c.name)
		v, err := runPadMethod(f1, idx, off, c.args...)
		if err != nil {
			t.Fatalf("改写后执行失败: %v", err)
		}
		if v != before[i] {
			t.Errorf("%s%v 多谓词模式下返回值不同：%v → %v", c.name, c.args, before[i], v)
		}
	}
	checkBranchTargets(t, "cff-multi", f1)
	checkTryHandlers(t, "cff-multi", f1)
	checkOutsOf(t, "cff-multi", f1)
}

// TestCffOpaquePredicateShape 断言产物中确实出现了谓词特征序列。
//
// 若「启用了 A6 但产物里没有任何谓词」，功能项就是静默失效——这条专门防它。
func TestCffOpaquePredicateShape(t *testing.T) {
	base := cffFixture(t)
	f0, err := Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Rebuild(f0, RebuildOptions{
		ControlFlow: &ControlFlow{Seed: 99, MaxPredicates: 1, Substitute: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	f1, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	_, _, off := cffFind(t, f1, "Lcff/T;", "->add(")
	ci, err := f1.ParseCodeItem(off)
	if err != nil {
		t.Fatal(err)
	}
	// 特征：const/16 + const/16 + mul-int + sub-int + const/16 + and-int + if-eqz
	// 连续出现。操作码序列固定，操作数可不同。
	//
	// 必须按指令边界取操作码，不能逐字扫描——每条指令的操作数字节也会落在
	// 0x13/0x92 这些值上，逐字扫描会得到假的「不匹配」。
	l, err := ParseInsns(ci.Insns)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x13, 0x13, 0x92, 0x91, 0x13, 0x95, 0x38}
	// 无寄存器形态：两条连续的无条件 goto/16（第一条跳过第二条，两条都前向汇聚）。
	fakeJump := []byte{0x29, 0x29}
	got := make([]byte, 0, 32)
	for i := 0; i < l.ItemCount(); i++ {
		if !l.ItemIsInsn(i) {
			continue
		}
		got = append(got, byte(l.ItemWords(i)[0]&0xff))
	}
	if !bytes.Contains(got, want) && !bytes.Contains(got, fakeJump) {
		t.Fatalf("add 方法里既无谓词特征序列 % x、也无不可达跳转块 % x（A6 静默失效）\n实际操作码: % x", want, fakeJump, got)
	}
}

// TestCffCombinedWithA2A3 验证 A6 与 A2/A3 在同一次 Rebuild 中共存时产物仍合法。
//
// 关键点：generate 把 A6 排在 A2/A3 之前。A2/A3 会返回「不可再映射」的绝对
// 字位置（skip），若 A6 在其后插入/替换指令，这些位置会整体错位，remapCode
// 会跳过错误的字，导致池引用二次映射或漏映射。这条测试让三个选项同时非 nil，
// 至少保证链路顺序不会引发 panic 或结构性损坏。
func TestCffCombinedWithA2A3(t *testing.T) {
	base := cffFixture(t)
	f0, err := Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	out, st, err := RebuildWithStats(f0, RebuildOptions{
		StringEncrypt: &StringEncrypt{Class: "Lcff/D;", MethodName: "a", Key: [32]byte{0x5a}, MinLen: 1, InjectClass: true},
		ConstantArray: &ConstantArray{Class: "Lcff/Ar;", MethodName: "b", MinLen: 1, InjectClass: true},
		ControlFlow:   &ControlFlow{Seed: 3, MaxPredicates: 1, Substitute: true},
	})
	if err != nil {
		t.Fatalf("A2+A3+A6 联合重建失败: %v", err)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("联合产物 Verify 失败: %v", err)
	}
	if err := ValidateDescriptors(out); err != nil {
		t.Fatalf("联合产物描述符非法: %v", err)
	}
	if st.ControlFlow.MethodsRewritten < 4 {
		t.Fatalf("联合模式下 A6 应仍改写 4 个方法，实际 %d", st.ControlFlow.MethodsRewritten)
	}
	f1, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	checkBranchTargets(t, "cff-combined", f1)
	checkTryHandlers(t, "cff-combined", f1)
	checkOutsOf(t, "cff-combined", f1)
}

// TestCffSkipsTryCodeItem 直接验证含 try 的方法在 A6 阶段被整体跳过。
//
// 含 try 的方法必须逐字节不动：插入会平移 try 区间端点，ART 会因端点不落在
// 指令边界而拒绝整个 DEX（Bogus handler offset 一类）。
func TestCffSkipsTryCodeItem(t *testing.T) {
	ci := &CodeItemFull{
		Registers: 4, Ins: 1, Outs: 0,
		Insns: []uint16{
			0x13 | 1<<8, 5, // const/16 v1, 5
			0x0f | 1<<8, // return v1
		},
		Tries:    []TryItem{{StartAddr: 0, InsnCount: 2, HandlerOff: 1}},
		Handlers: []CatchHandler{{Types: []uint32{0}, Addrs: []uint32{1}}},
	}
	src := ci.Encode(nil)

	b := &builder{}
	pl := &plan{controlFlow: &controlFlowPlan{spec: cffNormalize(ControlFlow{MaxPredicates: 1, Substitute: true})}}
	blob, _, changed, err := b.controlFlowCodeItem(pl, "m", src)
	if err != nil {
		t.Fatalf("改写失败: %v", err)
	}
	if changed || blob != nil {
		t.Fatalf("含 try 的方法应被跳过（changed=false），实际 changed=%v blob=%d 字节", changed, len(blob))
	}
	if pl.controlFlow.stats.SkippedTry != 1 {
		t.Fatalf("SkippedTry 应为 1，实际 %d", pl.controlFlow.stats.SkippedTry)
	}
}

// TestCffSkipsPayloadCodeItem 直接验证含 switch payload 的方法被整体跳过。
func TestCffSkipsPayloadCodeItem(t *testing.T) {
	ci := &CodeItemFull{
		Registers: 4, Ins: 1, Outs: 0,
		Insns: []uint16{
			0x002b, 4, 0, // packed-switch v0, +4
			0x0000,    // nop
			0x0100, 1, // payload ident + size
			0, 0, // first_key
			10, 0, // target[0] 相对 switch = +10
			0x030f, // return v3
		},
	}
	src := ci.Encode(nil)

	b := &builder{}
	pl := &plan{controlFlow: &controlFlowPlan{spec: cffNormalize(ControlFlow{MaxPredicates: 1, Substitute: true})}}
	blob, _, changed, err := b.controlFlowCodeItem(pl, "m", src)
	if err != nil {
		t.Fatalf("改写失败: %v", err)
	}
	if changed || blob != nil {
		t.Fatalf("含 switch payload 的方法应被跳过（changed=false），实际 changed=%v blob=%d 字节", changed, len(blob))
	}
	if pl.controlFlow.stats.SkippedPayload != 1 {
		t.Fatalf("SkippedPayload 应为 1，实际 %d", pl.controlFlow.stats.SkippedPayload)
	}
}

// TestCffSkipsPayloadMethodByteIdentical 在完整 Rebuild 上断言含 switch 的
// 方法逐字节未变，防「跳过判定写错、误改了不该改的」。
func TestCffSkipsPayloadMethodByteIdentical(t *testing.T) {
	base := cffFixture(t)
	f0, err := Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	before := cffMethodCode(t, f0)
	flags := cffMethodFlag(t, f0)

	out, st, err := RebuildWithStats(f0, RebuildOptions{
		ControlFlow: &ControlFlow{Seed: 5, MaxPredicates: 1, Substitute: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(out); err != nil {
		t.Fatal(err)
	}
	if err := ValidateDescriptors(out); err != nil {
		t.Fatal(err)
	}
	f1, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	after := cffMethodCode(t, f1)

	payloadMethods := 0
	for desc, fl := range flags {
		if !fl[1] {
			continue
		}
		payloadMethods++
		if !bytes.Equal(before[desc], after[desc]) {
			t.Errorf("含 payload 的方法 %s 的 code_item 被改动了（应逐字节未变）", desc)
		}
	}
	if payloadMethods == 0 {
		t.Fatalf("测试样本中未找到含 payload 的方法，跳过判定未被真正验证")
	}
	if st.ControlFlow.SkippedPayload < 1 {
		t.Errorf("SkippedPayload 应 >=1，实际 %d", st.ControlFlow.SkippedPayload)
	}
}

// cffMethodInsns 返回「方法描述符 -> 指令字序列」。
func cffMethodInsns(t *testing.T, f *File) map[string][]uint16 {
	t.Helper()
	out := map[string][]uint16{}
	if err := f.AllMethods(func(_, desc string, m EncodedMethod) error {
		if m.CodeOff == 0 {
			return nil
		}
		ci, err := f.ParseCodeItem(m.CodeOff)
		if err != nil {
			return nil
		}
		out[desc] = append([]uint16(nil), ci.Insns...)
		return nil
	}); err != nil {
		t.Fatalf("遍历方法失败: %v", err)
	}
	return out
}

// TestCffSampleTryMethodsUnchanged 用仓库固件 sample.dex 验证：
//   - 含 try/payload 的方法**指令流**未被 A6 改动；
//   - 产物通过全部结构体检。
//
// 这里比较指令流而不是整个 code_item 字节：一次完整 Rebuild 本身会重排
// debug_info 并回填 code_item 的 debug_info_off（属于 Rebuild 的正常行为，
// 与 A6 无关），逐字节比较会把这种无关变化误判为 A6 的改动。A6 层面的
// 「逐字节未变」由 TestCffSkipsTryCodeItem / TestCffSkipsPayloadMethodByteIdentical
// 保证（changed=false 时 generate 原样沿用该 code_item 字节）。
//
// 固件缺席时跳过（干净检出场景由前面的合成样本兜底）。
func TestCffSampleTryMethodsUnchanged(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/sample.dex")
	if err != nil {
		t.Skipf("未找到 testdata/sample.dex，跳过: %v", err)
	}
	f0, err := Parse(data)
	if err != nil {
		t.Fatalf("解析 sample.dex 失败: %v", err)
	}
	before := cffMethodInsns(t, f0)
	flags := cffMethodFlag(t, f0)

	out, st, err := RebuildWithStats(f0, RebuildOptions{
		ControlFlow: &ControlFlow{Seed: 7, MaxPredicates: 1, Substitute: true},
	})
	if err != nil {
		t.Fatalf("A6 重建 sample.dex 失败: %v", err)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("A6 产物 Verify 失败: %v", err)
	}
	if err := ValidateDescriptors(out); err != nil {
		t.Fatalf("A6 产物描述符非法: %v", err)
	}
	f1, err := Parse(out)
	if err != nil {
		t.Fatalf("解析 A6 产物失败: %v", err)
	}
	after := cffMethodInsns(t, f1)

	skipExpected := 0
	for desc, fl := range flags {
		if !fl[0] && !fl[1] {
			continue // 既无 try 也无 payload，允许被改写
		}
		skipExpected++
		if !sameWords(before[desc], after[desc]) {
			t.Errorf("应被跳过的 %s（try=%v payload=%v）指令流被 A6 改动了（应原样保留）",
				desc, fl[0], fl[1])
		}
	}
	if skipExpected == 0 {
		t.Log("sample.dex 中没有含 try/payload 的方法，跳过判定未被该固件覆盖")
	}

	// 产物结构体检。
	if n := checkBranchTargets(t, "cff-sample", f1); n == 0 {
		t.Log("sample.dex 产物中未检查到分支")
	}
	checkTryHandlers(t, "cff-sample", f1)
	checkOutsOf(t, "cff-sample", f1)

	t.Logf("sample.dex A6：改写 %d 个方法、注入 %d 组谓词、替换 %d 条；跳过 try=%d payload=%d reg=%d init=%d shape=%d",
		st.ControlFlow.MethodsRewritten, st.ControlFlow.Predicates, st.ControlFlow.Substitutions,
		st.ControlFlow.SkippedTry, st.ControlFlow.SkippedPayload, st.ControlFlow.SkippedRegisters,
		st.ControlFlow.SkippedInit, st.ControlFlow.SkippedShape)
}
