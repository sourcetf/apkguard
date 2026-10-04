package dex

import (
	"bytes"
	"strings"
	"testing"
)

// ---- A20 无害花指令填充回归测试 ----
//
// 断言分层，与 cff_test.go 对齐：
//  1. 语义等价：本地解释器逐方法比对返回值——这是「无害」的全部意义；
//  2. registers_size / outs_size 不变：防「入参整体后移」这类本地看不出的真机崩；
//  3. 产物结构体检（Verify/ValidateDescriptors/分支边界/try-handler/outs）；
//  4. 产物里**真的**出现 nop 与不可达跳转块：防「启用了却静默什么都没做」；
//  5. 插入的指令只可能是 nop(0x00) 与 goto/16(0x29)：直接钉死「不写任何寄存器」
//     这一安全前提；
//  6. 含 try/payload 的方法逐字节（指令流）不变：防跳过判定写错。

// junkLeadingOps 返回某方法指令流开头的操作码序列（按指令边界，不逐字扫描）。
func junkLeadingOps(t *testing.T, f *File, descPart string) []byte {
	t.Helper()
	_, _, off := cffFind(t, f, "Lcff/T;", descPart)
	ci, err := f.ParseCodeItem(off)
	if err != nil {
		t.Fatalf("解析 %s 失败: %v", descPart, err)
	}
	l, err := ParseInsns(ci.Insns)
	if err != nil {
		t.Fatalf("解析 %s 指令流失败: %v", descPart, err)
	}
	var ops []byte
	for i := 0; i < l.ItemCount(); i++ {
		if !l.ItemIsInsn(i) {
			continue
		}
		ops = append(ops, byte(l.ItemWords(i)[0]&0xff))
	}
	return ops
}

// junkOpcodeHist 按指令边界统计操作码出现次数。
func junkOpcodeHist(t *testing.T, words []uint16) map[byte]int {
	t.Helper()
	l, err := ParseInsns(words)
	if err != nil {
		t.Fatalf("解析指令流失败: %v", err)
	}
	m := map[byte]int{}
	for i := 0; i < l.ItemCount(); i++ {
		if !l.ItemIsInsn(i) {
			continue
		}
		m[byte(l.ItemWords(i)[0]&0xff)]++
	}
	return m
}

// TestJunkFillSemanticEquivalence 用本地解释器验证 A20 改写前后语义完全一致。
func TestJunkFillSemanticEquivalence(t *testing.T) {
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
		ControlFlow: &ControlFlow{JunkFill: true, JunkNops: 4},
	})
	if err != nil {
		t.Fatalf("A20 重建失败: %v", err)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("A20 产物 Verify 失败（ART 会拒绝加载）: %v", err)
	}
	if err := ValidateDescriptors(out); err != nil {
		t.Fatalf("A20 产物描述符非法: %v", err)
	}
	// add/loop/mix/bits 四个方法应被填充；sw 含 payload 被跳过。
	if st.ControlFlow.MethodsRewritten < 4 {
		t.Fatalf("应至少改写 add/loop/mix/bits 四个方法，实际 %d", st.ControlFlow.MethodsRewritten)
	}
	if st.ControlFlow.Nops < 16 {
		t.Fatalf("应至少插入 16 条 nop（4 方法 × 4），实际 %d", st.ControlFlow.Nops)
	}
	if st.ControlFlow.FakeJumps < 4 {
		t.Fatalf("应至少插入 4 个不可达跳转块，实际 %d", st.ControlFlow.FakeJumps)
	}
	// A20 绝不能在背后做 A6 的事（写寄存器的谓词 / 等价替换）。
	if st.ControlFlow.Predicates != 0 || st.ControlFlow.Substitutions != 0 {
		t.Fatalf("A20 不得注入谓词或做替换，实际 preds=%d subs=%d",
			st.ControlFlow.Predicates, st.ControlFlow.Substitutions)
	}

	f1, err := Parse(out)
	if err != nil {
		t.Fatalf("解析 A20 产物失败: %v", err)
	}
	for i, c := range cases {
		ci, idx, off := cffFind(t, f1, "Lcff/T;", c.name)
		v, err := runPadMethod(f1, idx, off, c.args...)
		if err != nil {
			t.Fatalf("改写后执行 %s%v 失败: %v", c.name, c.args, err)
		}
		if v != before[i].res {
			t.Errorf("%s%v 改写前后返回值不同：%v → %v（花指令不应改变语义）",
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

	if n := checkBranchTargets(t, "junkfill-fixture", f1); n == 0 {
		t.Errorf("产物中未检查到任何分支，测试样本失效")
	}
	checkTryHandlers(t, "junkfill-fixture", f1)
	if n := checkOutsOf(t, "junkfill-fixture", f1); n == 0 {
		t.Errorf("产物中未检查到任何方法体，测试样本失效")
	}
}

// TestJunkFillEmitsNopsAndUnreachableJumps 断言产物里真的出现了花指令特征。
//
// 若「启用了 A20 但产物里一个 nop/不可达跳转都没有」，功能项就是静默失效——
// 这条专门防它。检查一律按**指令边界**进行，绝不逐字扫描（操作数字节会误命中）。
func TestJunkFillEmitsNopsAndUnreachableJumps(t *testing.T) {
	base := cffFixture(t)
	f0, err := Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Rebuild(f0, RebuildOptions{
		ControlFlow: &ControlFlow{JunkFill: true, JunkNops: 6},
	})
	if err != nil {
		t.Fatal(err)
	}
	f1, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}

	ops := junkLeadingOps(t, f1, "->add(")
	wantPrefix := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x29, 0x29}
	if !bytes.HasPrefix(ops, wantPrefix) {
		t.Fatalf("add 方法开头应为 6×nop + 2×goto/16 % x，实际 % x", wantPrefix, ops)
	}

	// 两条 goto/16 必须**前向**且汇聚到同一个真实入口。
	// 布局（字单位）：6 个 nop = 0..5；两条 goto/16 各占 2 字 = 6..7 与 8..9；
	// 真实入口（锚点）从第 10 字开始。第一条跳过第二条（+4 字），第二条落到入口（+2 字）。
	_, _, off := cffFind(t, f1, "Lcff/T;", "->add(")
	ci, err := f1.ParseCodeItem(off)
	if err != nil {
		t.Fatal(err)
	}
	l, err := ParseInsns(ci.Insns)
	if err != nil {
		t.Fatal(err)
	}
	anchorPos := 6*1 + 2*2 // 6 个 nop（1 字）+ 两条 goto/16（各 2 字）
	got1 := 6 + int(int16(l.ItemWords(6)[1]))
	got2 := 8 + int(int16(l.ItemWords(7)[1]))
	if got1 != anchorPos || got2 != anchorPos {
		t.Errorf("两条 goto/16 应前向汇聚到真实入口 @word %d：第一条 → %d，第二条 → %d",
			anchorPos, got1, got2)
	}
	if got2 <= 8 {
		t.Errorf("第二条 goto/16 必须前向，实际目标 %d 不大于自身位置 8", got2)
	}
}

// TestJunkFillNopCap 钉住 nop 数量上限，并覆盖「0=默认」。
//
// 上限存在的理由：花指令的价值来自「每个方法都插一点」，而不是单方法堆很多；
// 无上限会让小方法膨胀数倍并拖慢 dex2oat/校验，也可能把入口附近的短 goto
// 逼出 8 位范围而被迫加宽。
func TestJunkFillNopCap(t *testing.T) {
	base := cffFixture(t)
	f0, err := Parse(base)
	if err != nil {
		t.Fatal(err)
	}

	countLeadingNops := func(cf *ControlFlow) int {
		t.Helper()
		out, err := Rebuild(f0, RebuildOptions{ControlFlow: cf})
		if err != nil {
			t.Fatalf("重建失败: %v", err)
		}
		f1, err := Parse(out)
		if err != nil {
			t.Fatal(err)
		}
		ops := junkLeadingOps(t, f1, "->add(")
		n := 0
		for _, op := range ops {
			if op != 0x00 {
				break
			}
			n++
		}
		return n
	}

	if got := countLeadingNops(&ControlFlow{JunkFill: true}); got != 4 {
		t.Errorf("JunkNops=0 应取默认 4，实际 %d", got)
	}
	if got := countLeadingNops(&ControlFlow{JunkFill: true, JunkNops: -3}); got != 4 {
		t.Errorf("JunkNops<0 应取默认 4，实际 %d", got)
	}
	if got := countLeadingNops(&ControlFlow{JunkFill: true, JunkNops: 1000}); got != cffMaxJunkNops {
		t.Errorf("JunkNops 超限应封顶 %d，实际 %d", cffMaxJunkNops, got)
	}
}

// TestJunkFillInjectsOnlyNopAndGoto16 直接钉住「不写任何寄存器」的安全前提。
//
// 方法：按指令边界比较改写前后的操作码直方图。A20 只允许新增
//
//	0x00（nop）与 0x29（goto/16）；
//
// 其余任何操作码的新增都会失败——它们都可能读写寄存器，从而引入
// 「入口写坏活跃寄存器 → ART VerifyError」的风险。
//
// 注意：原指令中的短 goto（0x28）可能因插入被加宽为 goto/16（0x29），
// 这属于既有指令的格式变化，同样是 0x29，不违反本判据。
func TestJunkFillInjectsOnlyNopAndGoto16(t *testing.T) {
	base := cffFixture(t)
	f0, err := Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	before := cffMethodInsns(t, f0)

	out, err := Rebuild(f0, RebuildOptions{
		ControlFlow: &ControlFlow{JunkFill: true, JunkNops: 4},
	})
	if err != nil {
		t.Fatal(err)
	}
	f1, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	after := cffMethodInsns(t, f1)

	var newNops, newGotos int
	for desc, bw := range before {
		aw := after[desc]
		if aw == nil {
			continue
		}
		bm := junkOpcodeHist(t, bw)
		am := junkOpcodeHist(t, aw)
		for op, n := range am {
			if op == 0x00 || op == 0x29 {
				continue
			}
			if n > bm[op] {
				t.Errorf("方法 %s 新增了非 nop/goto16 指令 0x%02x（+%d）——可能写寄存器，破坏 A20 安全前提",
					desc, op, n-bm[op])
			}
		}
		newNops += am[0x00] - bm[0x00]
		newGotos += am[0x29] - bm[0x29]
	}
	if newNops <= 0 {
		t.Fatalf("产物中未新增任何 nop，A20 静默失效")
	}
	if newGotos <= 0 {
		t.Fatalf("产物中未新增任何 goto/16，A20 静默失效")
	}
}

// TestJunkFillSkipsTryCodeItem 直接验证含 try 的方法在 A20 阶段被整体跳过。
func TestJunkFillSkipsTryCodeItem(t *testing.T) {
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
	pl := &plan{controlFlow: &controlFlowPlan{spec: cffNormalize(ControlFlow{JunkFill: true})}}
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

// TestJunkFillPayloadMethodUnchanged 断言含 switch payload 的方法指令流未被 A20 改动。
func TestJunkFillPayloadMethodUnchanged(t *testing.T) {
	base := cffFixture(t)
	f0, err := Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	before := cffMethodInsns(t, f0)

	out, st, err := RebuildWithStats(f0, RebuildOptions{
		ControlFlow: &ControlFlow{JunkFill: true, JunkNops: 4},
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
	after := cffMethodInsns(t, f1)

	found := false
	for desc, bw := range before {
		if !strings.Contains(desc, "->sw(") {
			continue
		}
		found = true
		if !sameWords(bw, after[desc]) {
			t.Errorf("含 payload 的方法 %s 的指令流被 A20 改动了（应原样保留）", desc)
		}
	}
	if !found {
		t.Fatalf("测试样本中未找到含 payload 的 sw 方法，跳过判定未被真正验证")
	}
	if st.ControlFlow.SkippedPayload < 1 {
		t.Errorf("SkippedPayload 应 >=1，实际 %d", st.ControlFlow.SkippedPayload)
	}
}

// ---- A20 第二种形态：return 前单发 nop（参考样本形态） ----

// returnNopPositions 返回指令流中「前一条是 nop 的 return*」的位置集合，
// 以及全部 return* 的位置集合。
func returnNopPositions(l *InsnList) (covered, returns map[int]bool) {
	covered = map[int]bool{}
	returns = map[int]bool{}
	prevNop := false
	for i := 0; i < l.ItemCount(); i++ {
		if !l.ItemIsInsn(i) {
			prevNop = false
			continue
		}
		op := byte(l.ItemWords(i)[0] & 0xff)
		pos := l.ItemOldOffset(i)
		if op >= 0x0e && op <= 0x11 {
			returns[pos] = true
			if prevNop {
				covered[pos] = true
			}
		}
		prevNop = op == 0x00
	}
	return covered, returns
}

// nopBeforeReturnsInMethod 判断指令流中「每个 return 之前恰好一条 nop」，
// 并返回「return 前 nop」的条数；同时拒绝出现连续 nop 段（单发形态）。
func nopBeforeReturnsInMethod(t *testing.T, tag string, l *InsnList) (int, int) {
	t.Helper()
	nReturn, nCovered := 0, 0
	run := 0 // 连续 nop 段长度
	for i := 0; i < l.ItemCount(); i++ {
		if !l.ItemIsInsn(i) {
			run = 0
			continue
		}
		op := byte(l.ItemWords(i)[0] & 0xff)
		if op == 0x00 {
			run++
			if run > 1 && i+1 < l.ItemCount() && l.ItemIsInsn(i+1) {
				next := byte(l.ItemWords(i + 1)[0] & 0xff)
				if next >= 0x0e && next <= 0x11 {
					t.Errorf("%s：return 前出现连续 %d 条 nop（参考样本全部单发，不允许连发）", tag, run)
				}
			}
			continue
		}
		if op >= 0x0e && op <= 0x11 {
			nReturn++
			if i > 0 && l.ItemIsInsn(i-1) && byte(l.ItemWords(i - 1)[0]&0xff) == 0x00 {
				nCovered++
			}
		}
		run = 0
	}
	return nReturn, nCovered
}

// checkNoBranchTargetsNop 断言产物中没有任何分支指向一条 nop。
//
// 这是「分支目标仍指向原逻辑指令」的直接证据：改写前分支从不指向 nop，
// 若重定位把目标落到插入的 nop 上，就是跳错了位置（nop 后继续 fallthrough
// 可能改变语义）。
func checkNoBranchTargetsNop(t *testing.T, tag string, f *File) int {
	t.Helper()
	checked, bad := 0, 0
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
		at := map[int]uint16{}
		for i := 0; i < l.ItemCount(); i++ {
			if l.ItemIsInsn(i) {
				at[l.ItemOldOffset(i)] = l.ItemWords(i)[0]
			}
		}
		for i := 0; i < l.ItemCount(); i++ {
			if !l.ItemIsInsn(i) {
				continue
			}
			w := l.ItemWords(i)
			op := byte(w[0] & 0xff)
			var rel int
			switch {
			case op == 0x28:
				rel = int(int8(w[0] >> 8))
			case op == 0x29, op == 0x2a, op >= 0x32 && op <= 0x3d:
				rel = int(int16(w[1]))
			default:
				continue // switch/fill-array-data 的 payload 方法已被跳过
			}
			checked++
			tgt := l.ItemOldOffset(i) + rel
			if word, ok := at[tgt]; ok && word&0xff == 0x00 {
				bad++
				t.Errorf("%s：方法 %s 的分支（@word %d）指向了 nop（@word %d）——分支目标被重定位到了插入指令上",
					tag, desc, l.ItemOldOffset(i), tgt)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("%s：遍历方法失败: %v", tag, err)
	}
	if bad > 0 {
		t.Fatalf("%s：%d 条分支指向 nop", tag, bad)
	}
	return checked
}

// TestJunkFillReturnNopsShape 验证 return 前单发 nop 形态：
// 条数与 return 数一致、每条 nop 紧邻 return、无连发、分支不指向 nop、
// 产物 Verify 通过且语义不变。
func TestJunkFillReturnNopsShape(t *testing.T) {
	base := cffFixture(t)
	f0, err := Parse(base)
	if err != nil {
		t.Fatal(err)
	}

	// 语义基线：解释器跑一遍 loop（含分支）与 add。
	type runCase struct {
		name string
		args []any
	}
	cases := []runCase{{"->loop(", []any{int32(5)}}, {"->add(", []any{int32(3), int32(5)}}}
	before := make([]any, len(cases))
	for i, c := range cases {
		_, idx, off := cffFind(t, f0, "Lcff/T;", c.name)
		v, err := runPadMethod(f0, idx, off, c.args...)
		if err != nil {
			t.Fatalf("改写前执行 %s 失败: %v", c.name, err)
		}
		before[i] = v
	}

	out, st, err := RebuildWithStats(f0, RebuildOptions{
		ControlFlow: &ControlFlow{JunkFill: true, JunkNops: 4, ReturnNops: true},
	})
	if err != nil {
		t.Fatalf("A20 return-nop 重建失败: %v", err)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("产物 Verify 失败（ART 会拒绝加载）: %v", err)
	}
	if err := ValidateDescriptors(out); err != nil {
		t.Fatalf("产物描述符非法: %v", err)
	}
	// cffFixture 中 add/loop/mix/bits 各 1 条 return 且预算足够；
	// sw 含 payload 被跳过，因此应是 4 条。
	if st.ControlFlow.ReturnNops != 4 {
		t.Fatalf("ReturnNops 统计应为 4，实际 %d", st.ControlFlow.ReturnNops)
	}
	if st.ControlFlow.ReturnNops > st.ControlFlow.Nops {
		t.Fatalf("ReturnNops(%d) 不应超过 Nops(%d)", st.ControlFlow.ReturnNops, st.ControlFlow.Nops)
	}

	f1, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	rewritten := 0
	if err := f1.AllMethods(func(_, desc string, m EncodedMethod) error {
		if m.CodeOff == 0 || strings.Contains(desc, "->sw(") {
			return nil // sw 含 payload，整体跳过
		}
		ci, err := f1.ParseCodeItem(m.CodeOff)
		if err != nil {
			return nil
		}
		l, err := ParseInsns(ci.Insns)
		if err != nil {
			return nil
		}
		nReturn, nCovered := nopBeforeReturnsInMethod(t, desc, l)
		if nReturn == 0 {
			return nil
		}
		rewritten++
		if nCovered != nReturn {
			t.Errorf("方法 %s：%d 条 return 中只有 %d 条前面有 nop（预算足够时应全覆盖）", desc, nReturn, nCovered)
		}
		if n, _ := returnNopPositions(l); len(n) != nReturn {
			t.Errorf("方法 %s：return 前 nop 计数不一致", desc)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if rewritten != 4 {
		t.Fatalf("应有 4 个方法被插入 return 前 nop，实际 %d", rewritten)
	}

	// 分支目标不得指向插入的 nop。
	if n := checkNoBranchTargetsNop(t, "junkfill-returnnops", f1); n == 0 {
		t.Fatalf("产物中未检查到任何分支，测试样本失效")
	}
	checkTryHandlers(t, "junkfill-returnnops", f1)

	// 语义等价（改写只插 nop，不应改变任何返回值）。
	for i, c := range cases {
		_, idx, off := cffFind(t, f1, "Lcff/T;", c.name)
		v, err := runPadMethod(f1, idx, off, c.args...)
		if err != nil {
			t.Fatalf("改写后执行 %s 失败: %v", c.name, err)
		}
		if v != before[i] {
			t.Errorf("%s 改写前后返回值不同：%v → %v", c.name, before[i], v)
		}
	}

	// 同输入同选项必须字节可复现。
	out2, _, err := RebuildWithStats(f0, RebuildOptions{
		ControlFlow: &ControlFlow{JunkFill: true, JunkNops: 4, ReturnNops: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, out2) {
		t.Fatal("同一输入两次 rewrite 的产物不一致（存在未受控随机性）")
	}
}

// TestJunkFillReturnNopsMultiReturn 用多 return 方法验证：
// 「插入的 nop 数 == return 数」（预算足够时逐条覆盖），且每个 nop 的下一条
// 就是 return*。
func TestJunkFillReturnNopsMultiReturn(t *testing.T) {
	a := NewAsm()
	a.Const4(0, 0)
	for k := 0; k < 20; k++ { // 40 字填充，保证 8% 预算 >= 3
		a.AddIntLit8(0, 1)
	}
	a.IfEqz(0, "r0")
	a.Return(0) // return #1
	a.Label("r0")
	a.Const4(0, 1)
	for k := 0; k < 20; k++ {
		a.AddIntLit8(0, 1)
	}
	a.IfEqz(0, "r1")
	a.Return(0) // return #2
	a.Label("r1")
	a.Return(0) // return #3
	insns, patches, err := a.Assemble()
	if err != nil {
		t.Fatal(err)
	}
	code := &CodeBlob{Registers: 2, Ins: 1, Outs: 0, Insns: insns, Patches: patches}

	base, err := Build(Addition{Classes: []ClassSpec{{
		Name: "Lcff/Multi;", Super: "Ljava/lang/Object;", Access: accPublic | accFinal,
		Methods: []ClassMethod{{
			Name: "m", Proto: ProtoSpec{Ret: "I", Params: []string{"I"}},
			Access: accPublic | accStatic, Code: code,
		}},
	}}})
	if err != nil {
		t.Fatalf("构造多 return DEX 失败: %v", err)
	}
	f0, err := Parse(base)
	if err != nil {
		t.Fatal(err)
	}

	out, st, err := RebuildWithStats(f0, RebuildOptions{
		ControlFlow: &ControlFlow{JunkFill: true, JunkNops: 4, ReturnNops: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("产物 Verify 失败: %v", err)
	}
	if st.ControlFlow.ReturnNops != 3 {
		t.Fatalf("3 条 return 应各插 1 条 nop（共 3），实际 %d", st.ControlFlow.ReturnNops)
	}
	f1, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	ci, _, _ := cffFind(t, f1, "Lcff/Multi;", "->m(")
	l, err := ParseInsns(ci.Insns)
	if err != nil {
		t.Fatal(err)
	}
	covered, returns := returnNopPositions(l)
	if len(returns) != 3 {
		t.Fatalf("产物中 return 数应为 3，实际 %d", len(returns))
	}
	if len(covered) != 3 {
		t.Fatalf("3 条 return 应全部被 nop 覆盖，实际 %d", len(covered))
	}
}

// TestJunkFillReturnNopsOffByDefault 断言不开选项时形态与既有产物一致（零回归）。
func TestJunkFillReturnNopsOffByDefault(t *testing.T) {
	base := cffFixture(t)
	f0, err := Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	out, st, err := RebuildWithStats(f0, RebuildOptions{
		ControlFlow: &ControlFlow{JunkFill: true, JunkNops: 4},
	})
	if err != nil {
		t.Fatal(err)
	}
	if st.ControlFlow.ReturnNops != 0 {
		t.Fatalf("未开启 ReturnNops 时不应插入 return 前 nop，实际 %d", st.ControlFlow.ReturnNops)
	}
	// 指令流中不得出现「nop 紧邻 return」的形态（fixture 原始代码里没有这种组合）。
	f1, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	if err := f1.AllMethods(func(_, desc string, m EncodedMethod) error {
		if m.CodeOff == 0 || strings.Contains(desc, "->sw(") {
			return nil
		}
		ci, err := f1.ParseCodeItem(m.CodeOff)
		if err != nil {
			return nil
		}
		l, err := ParseInsns(ci.Insns)
		if err != nil {
			return nil
		}
		if covered, _ := returnNopPositions(l); len(covered) != 0 {
			t.Errorf("未开启选项却出现 %d 处 return 前 nop（方法 %s）", len(covered), desc)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
