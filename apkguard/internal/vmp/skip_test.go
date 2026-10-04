package vmp_test

import (
	"bytes"
	"strings"
	"testing"

	"apkguard/internal/dex"
	"apkguard/internal/vmp"
)

// 本文件覆盖「不支持就拒绝」的选择器契约：每个 fixture 都是一类必须被
// 挡在门外的方法，断言它不被选中、且给出可读的跳过原因。
//
// 为什么在测试里单列：B6 的整个安全前提是「宁可拒绝，不可静默降级」。
// 一旦某条拒绝规则失效（例如 try/catch 方法被翻译），产物在设备上不会
// 立刻崩溃，而是异常不按 Java 语义传播、静默算错——只有真机回归能发现。
// 因此这里把每条拒绝规则钉死。

// unsupportedFixture 是一组「含不支持结构」的方法，全部必须被跳过。
func unsupportedFixture(t *testing.T) []fixMethod {
	t.Helper()
	// fill-array-data（0x26 + payload）。
	fa := newWA()
	fa.const4(0, 1)
	fa.fillArrayData(1, []byte{1, 2, 3, 4})
	fa.returnVoid()

	// packed-switch（0x2b + payload）。
	sw := newWA()
	sw.packedSwitch(0, []string{"a", "b"})
	sw.label("a")
	sw.returnVoid()
	sw.label("b")
	sw.returnVoid()

	// try/catch 在下面单独构造（需要带异常表的 code_item）。
	th := newWA()
	th.emit(0x27) // throw v0
	th.returnVoid()

	me := newWA()
	me.emit(0x1d | 0<<8) // monitor-enter v0
	me.returnVoid()

	// 指令数 > 64（MaxInsns）。
	big := newWA()
	for i := 0; i < 70; i++ {
		big.emit(0x00)
	}
	big.returnVoid()

	// 寄存器数 > 64（MaxRegisters）。
	wide := newWA()
	wide.returnVoid()

	return []fixMethod{
		{Name: "fillarr", Ret: "V", Access: static(dex.ProtoSpec{}), Code: fa.assemble(2, 0, 0)},
		{Name: "switchm", Ret: "V", Access: static(dex.ProtoSpec{}), Code: sw.assemble(2, 0, 0)},
		{Name: "throwm", Ret: "V", Access: static(dex.ProtoSpec{}), Code: th.assemble(1, 0, 0)},
		{Name: "monitorm", Ret: "V", Access: static(dex.ProtoSpec{}), Code: me.assemble(1, 0, 0)},
		{Name: "bigm", Ret: "V", Access: static(dex.ProtoSpec{}), Code: big.assemble(0, 0, 0)},
		{Name: "wideregs", Ret: "V", Access: static(dex.ProtoSpec{}), Code: wide.assemble(70, 0, 0)},
		{Name: "syncm", Ret: "V", Access: 0x21, Code: wide.assemble(1, 0, 0)},                     // public synchronized
		{Name: "floatm", Ret: "F", Access: static(dex.ProtoSpec{}), Code: wide.assemble(1, 0, 0)}, // 浮点返回
		{Name: "floatarg", Ret: "V", Params: []string{"F"}, Access: static(dex.ProtoSpec{}), Code: wide.assemble(1, 1, 0)},
		{Name: "good", Ret: "I", Params: []string{"I"}, Access: static(dex.ProtoSpec{}), Code: func() *dex.CodeBlob {
			a := newWA()
			a._mov(0, 0)
			a.returnReg(0)
			return a.assemble(1, 1, 0)
		}()},
	}
}

// TestSkipUnsupportedMethods 断言每一类不支持的方法都被跳过、且原因可读；
// 同一 DEX 里的可翻译方法必须仍然被选中（拒绝规则不能误伤）。
func TestSkipUnsupportedMethods(t *testing.T) {
	methods := unsupportedFixture(t)
	f := buildFixture(t, methods)

	sel := vmp.Select(f, "skip.dex", 100)
	if len(sel.Programs) != 1 || sel.Programs[0].Name != "good" {
		t.Fatalf("应只选中 good 方法，实际选中 %d 个（%v）；跳过明细: %s",
			len(sel.Programs), programNames(sel.Programs), sel.ReasonReport())
	}
	// 每个被跳过的方法都必须计入 SkipReasons（不静默）。
	if got := sel.Candidates; got != len(methods) {
		t.Fatalf("候选数应为 %d，实际 %d", len(methods), got)
	}
	total := 0
	for _, n := range sel.SkipReasons {
		total += n
	}
	if total != len(methods)-1 {
		t.Fatalf("跳过计数 %d 与「候选-选中」%d 不符", total, len(methods)-1)
	}
	for _, key := range []string{"不支持指令 packed-switch", "不支持指令 fill-array-data",
		"不支持指令 throw", "不支持指令 monitor-enter", "指令数超限", "寄存器数超限",
		"synchronized", "类型不支持"} {
		found := false
		for reason := range sel.SkipReasons {
			if strings.Contains(reason, key) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("跳过原因里应包含 %q，实际: %s", key, sel.ReasonReport())
		}
	}
}

// TestSkipTryCatchMethod 单独构造一个带异常表的方法，断言被拒绝。
//
// 异常表不能用测试汇编器表达（CodeBlob 没有 tries 字段），所以先正常构建
// DEX，再用 dex.Rebuild 的 CodeReplacements 把方法体替换成手工构造的
// 带 try/catch 的 code_item。
func TestSkipTryCatchMethod(t *testing.T) {
	m := fixMethod{Name: "trym", Ret: "V", Access: static(dex.ProtoSpec{}), Code: func() *dex.CodeBlob {
		a := newWA()
		a.returnVoid()
		return a.assemble(1, 0, 0)
	}()}
	f := buildFixture(t, []fixMethod{m})
	off, _ := findMethod(t, f, fixtureClass, "trym")

	// 手工 code_item：return-void + 一条覆盖它的 catch-all 异常记录。
	ci := &dex.CodeItemFull{
		Registers: 1,
		Insns:     []uint16{0x0e},
		Tries:     []dex.TryItem{{StartAddr: 0, InsnCount: 1, HandlerOff: 1}},
		Handlers:  []dex.CatchHandler{{CatchAll: true, AllAddr: 0}},
	}
	blob, err := ci.EncodeChecked(nil)
	if err != nil {
		t.Fatalf("构造带异常表的 code_item 失败: %v", err)
	}
	data, err := dex.Rebuild(f, dex.RebuildOptions{CodeReplacements: map[uint32][]byte{off: blob}})
	if err != nil {
		t.Fatalf("替换方法体失败: %v", err)
	}
	f2, err := dex.Parse(data)
	if err != nil {
		t.Fatalf("重建后的 DEX 解析失败: %v", err)
	}
	// 先确认替换真的生效（异常表能被解析出来），否则这条测试是空转。
	ci2, err := f2.ParseCodeItem(off)
	if err != nil {
		t.Fatalf("替换后的 code_item 解析失败: %v", err)
	}
	if len(ci2.Tries) != 1 {
		t.Fatalf("替换后的方法应含 1 条 try 记录，实际 %d", len(ci2.Tries))
	}

	sel := vmp.Select(f2, "try.dex", 10)
	if len(sel.Programs) != 0 {
		t.Fatalf("含 try/catch 的方法不得被选中，实际选了 %v", programNames(sel.Programs))
	}
	if sel.SkipReasons["含 try/catch"] != 1 {
		t.Fatalf("跳过原因应为「含 try/catch」×1，实际: %s", sel.ReasonReport())
	}
}

// TestBlobRoundTrip 断言 blob 编解码逐字段一致，且反汇编不产生非法行。
func TestBlobRoundTrip(t *testing.T) {
	methods := allFixtures()
	f := buildFixture(t, methods)
	sel := vmp.Select(f, "fixture.dex", len(methods)+10)
	if len(sel.Programs) == 0 {
		t.Fatal("fixture 未选中任何方法")
	}
	blob, err := vmp.EncodeBlob(sel.Programs)
	if err != nil {
		t.Fatalf("编码 blob 失败: %v", err)
	}
	got, err := vmp.DecodeBlob(blob)
	if err != nil {
		t.Fatalf("解码 blob 失败: %v", err)
	}
	if len(got.Methods) != len(sel.Programs) {
		t.Fatalf("blob 方法数 %d != %d", len(got.Methods), len(sel.Programs))
	}
	for i, p := range got.Methods {
		want := sel.Programs[i]
		if p.Sig() != want.Sig() || p.VMID != want.VMID || p.Access != want.Access ||
			p.Registers != want.Registers || p.Ins != want.Ins {
			t.Fatalf("第 %d 个方法元数据不一致: got %+v want %+v", i, *p, *want)
		}
		if len(p.Code) != len(want.Code) {
			t.Fatalf("%s 指令数不一致", p.Sig())
		}
		for k := range p.Code {
			if p.Code[k] != want.Code[k] {
				t.Fatalf("%s @%d 指令字不一致: got 0x%08x want 0x%08x", p.Sig(), k, p.Code[k], want.Code[k])
			}
		}
		if len(p.Strings) != len(want.Strings) || len(p.Methods) != len(want.Methods) || len(p.Fields) != len(want.Fields) {
			t.Fatalf("%s 池项数不一致", p.Sig())
		}
		// 反汇编必须每一条都能解码（无「<非法」占位）。
		lines := vmp.Disasm(p)
		if len(lines) == 0 {
			t.Fatalf("%s 反汇编为空", p.Sig())
		}
		for _, ln := range lines {
			if strings.Contains(ln, "非法") {
				t.Fatalf("%s 反汇编出现非法指令: %s", p.Sig(), ln)
			}
		}
	}

	// 同输入重复编码必须逐字节一致（可复现）。
	blob2, err := vmp.EncodeBlob(sel.Programs)
	if err != nil {
		t.Fatalf("再次编码失败: %v", err)
	}
	if !bytes.Equal(blob, blob2) {
		t.Fatal("同一程序两次编码结果不一致（不可复现）")
	}
}

// TestDecodeBlobRejectsCorruption 断言损坏的 blob 在解码期被拒绝，而不是
// 一路走到设备上的解释器里越界执行。
func TestDecodeBlobRejectsCorruption(t *testing.T) {
	methods := allFixtures()
	f := buildFixture(t, methods)
	sel := vmp.Select(f, "fixture.dex", 3)
	if len(sel.Programs) == 0 {
		t.Fatal("fixture 未选中任何方法")
	}
	blob, err := vmp.EncodeBlob(sel.Programs)
	if err != nil {
		t.Fatalf("编码失败: %v", err)
	}
	cases := map[string][]byte{
		"魔数错误": append([]byte("XXXX"), blob[4:]...),
		"截断":   blob[:len(blob)/2],
		"尾部多余": append(append([]byte(nil), blob...), 0, 1, 2, 3),
	}
	for name, bad := range cases {
		if _, err := vmp.DecodeBlob(bad); err == nil {
			t.Errorf("%s 的 blob 应被拒绝", name)
		}
	}
}

func programNames(ps []*vmp.Program) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.Name)
	}
	return out
}
