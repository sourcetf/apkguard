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
