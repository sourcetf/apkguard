package dex2c

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"apkguard/internal/dex"
)

// ---- 测试辅助 ----

// blobOf 用汇编器构造一个 CodeBlob。
func blobOf(t *testing.T, regs, ins, outs int, f func(a *dex.Asm) error) *dex.CodeBlob {
	t.Helper()
	a := dex.NewAsm()
	if err := f(a); err != nil {
		t.Fatalf("汇编失败: %v", err)
	}
	insns, patches, err := a.Assemble()
	if err != nil {
		t.Fatalf("汇编失败: %v", err)
	}
	return &dex.CodeBlob{
		Registers: uint16(regs), Ins: uint16(ins), Outs: uint16(outs),
		Insns: insns, Patches: patches,
	}
}

// blobRaw 用原始指令字构造 CodeBlob（用于 Asm 未覆盖的形式，如 2addr）。
func blobRaw(regs, ins, outs int, words ...uint16) *dex.CodeBlob {
	return &dex.CodeBlob{
		Registers: uint16(regs), Ins: uint16(ins), Outs: uint16(outs), Insns: words,
	}
}

// buildDex 用给定方法构造一个含单类 Lcom/t/A; 的 DEX。
func buildDex(t *testing.T, methods ...dex.ClassMethod) []byte {
	t.Helper()
	for i := range methods {
		if methods[i].Access == 0 {
			methods[i].Access = 0x0009 // public static
		}
	}
	out, err := dex.Build(dex.Addition{
		Types: []string{"Lcom/t/A;", "Ljava/lang/Object;"},
		Classes: []dex.ClassSpec{{
			Name: "Lcom/t/A;", Super: "Ljava/lang/Object;", Access: 0x0001,
			Methods: methods,
		}},
	})
	if err != nil {
		t.Fatalf("构造 DEX 失败: %v", err)
	}
	return out
}

// staticMethod 构造一个静态方法。
func staticMethod(name string, proto dex.ProtoSpec, blob *dex.CodeBlob) dex.ClassMethod {
	return dex.ClassMethod{Name: name, Proto: proto, Access: 0x0009, Code: blob}
}

// selectAll 在 DEX 上执行选择。
func selectAll(t *testing.T, data []byte, limit int, reflected map[string]bool) *Selection {
	t.Helper()
	f, err := dex.Parse(data)
	if err != nil {
		t.Fatalf("解析 DEX 失败: %v", err)
	}
	return Select([]DexInput{{Name: "classes.dex", File: f}}, limit, "test-seed", reflected)
}

// selectOne 选中并返回指定名字的方法。
func selectOne(t *testing.T, data []byte, name string) *Method {
	t.Helper()
	sel := selectAll(t, data, 100, nil)
	for _, m := range sel.Methods {
		if m.Name == name {
			return m
		}
	}
	t.Fatalf("方法 %s 未被选中；选中: %v；跳过: %v", name, methodNames(sel.Methods), sel.Skip)
	return nil
}

func methodNames(ms []*Method) []string {
	var out []string
	for _, m := range ms {
		out = append(out, m.Name+m.Proto)
	}
	return out
}

// generateFor 为选中方法生成 C 源。
func generateFor(t *testing.T, data []byte, limit int) (*Selection, []byte) {
	t.Helper()
	sel := selectAll(t, data, limit, nil)
	for i, m := range sel.Methods {
		m.FnName = funcNameOf(fmt.Sprintf("test-seed#%d", i), m)
	}
	csrc, err := generateC(sel.Methods, "test-seed")
	if err != nil {
		t.Fatalf("生成 C 失败: %v", err)
	}
	return sel, csrc
}

// ---- 操作码表（d8/dexdump 实证） ----

// TestOpcodeTableMatchesD8Evidence 钉住操作码编号与宽度。
//
// 证据来自 build-tools 34.0.0 的 d8 + dexdump 实测（javac --release 11）：
//
//	d800 0007 → add-int/lit8 v0, v0, #7
//	d000 e803 → add-int/lit16 v0, v0, #1000
//	e000 0007 → shl-int/lit8 v0, v0, #7
//	b001      → add-int/2addr v1, v0
//	1200      → const/4 v0, #0
func TestOpcodeTableMatchesD8Evidence(t *testing.T) {
	cases := []struct {
		op    byte
		name  string
		width int
	}{
		{0x00, "nop", 1},
		{0x01, "move", 1},
		{0x02, "move/from16", 2},
		{0x07, "move-object", 1},
		{0x0a, "move-result", 1},
		{0x0c, "move-result-object", 1},
		{0x0f, "return", 1},
		{0x11, "return-object", 1},
		{0x12, "const/4", 1},
		{0x13, "const/16", 2},
		{0x14, "const", 3},
		{0x15, "const/high16", 2},
		{0x1a, "const-string", 2},
		{0x1b, "const-string/jumbo", 3},
		{0x28, "goto", 1},
		{0x29, "goto/16", 2},
		{0x2a, "goto/32", 3},
		{0x32, "if-eq", 2},
		{0x38, "if-eqz", 2},
		{0x3d, "if-lez", 2},
		{0x52, "iget", 2},
		{0x54, "iget-object", 2},
		{0x59, "iput", 2},
		{0x60, "sget", 2},
		{0x62, "sget-object", 2},
		{0x69, "sput-object", 2},
		{0x6e, "invoke-virtual", 3},
		{0x71, "invoke-static", 3},
		{0x72, "invoke-interface", 3},
		{0x77, "invoke-static/range", 3},
		{0x7b, "neg-int", 1},
		{0x7c, "not-int", 1},
		{0x8d, "int-to-byte", 1},
		{0x8e, "int-to-char", 1},
		{0x8f, "int-to-short", 1},
		{0x90, "add-int", 2},
		{0x9a, "ushr-int", 2},
		{0xb0, "add-int/2addr", 1},
		{0xba, "ushr-int/2addr", 1},
		{0xd0, "add-int/lit16", 2},
		{0xd1, "rsub-int", 2},
		{0xd7, "xor-int/lit16", 2},
		{0xd8, "add-int/lit8", 2},
		{0xda, "mul-int/lit8", 2},
		{0xdf, "xor-int/lit8", 2},
		{0xe0, "shl-int/lit8", 2},
		{0xe1, "shr-int/lit8", 2},
		{0xe2, "ushr-int/lit8", 2},
	}
	for _, c := range cases {
		name, width, _, ok := insnInfo(c.op)
		if !ok {
			t.Errorf("0x%02x (%s) 应在支持集合内", c.op, c.name)
			continue
		}
		if name != c.name || width != c.width {
			t.Errorf("0x%02x: got (%s,%d) want (%s,%d)", c.op, name, width, c.name, c.width)
		}
	}
	// 明确不在子集内的常用指令。
	for _, op := range []byte{0x04, 0x1c, 0x1d, 0x20, 0x22, 0x26, 0x27, 0x2b, 0x2c, 0x44, 0x53, 0x61, 0x6f, 0x70, 0x75, 0x76, 0x7d, 0x9b, 0xe3, 0xfa} {
		if _, _, _, ok := insnInfo(op); ok {
			t.Errorf("0x%02x 不应在支持集合内", op)
		}
	}
}

// TestDecodeOperandFields 校验各格式的操作数解析。
func TestDecodeOperandFields(t *testing.T) {
	must := func(words []uint16) insn {
		t.Helper()
		got, err := decodeInsns(words)
		if err != nil {
			t.Fatalf("解码 %v 失败: %v", words, err)
		}
		if len(got) != 1 {
			t.Fatalf("期望 1 条指令，得到 %d", len(got))
		}
		return got[0]
	}
	// d800 0007 → add-int/lit8 v0, v0, #7（字节序：首字节是操作码）。
	it := must([]uint16{0x00d8, 0x0700})
	if it.op != 0xd8 || it.a != 0 || it.b != 0 || it.lit != 7 || it.width != 2 {
		t.Fatalf("add-int/lit8 解码错误: %+v", it)
	}
	// d000 e803 → add-int/lit16 v0, v0, #1000
	it = must([]uint16{0x00d0, 0x03e8})
	if it.op != 0xd0 || it.a != 0 || it.b != 0 || it.lit != 1000 {
		t.Fatalf("add-int/lit16 解码错误: %+v", it)
	}
	// 22b: A=v1, B=v2, lit=-7 → word0 = 0xd8 | 1<<8 = 0x01d8，word1 = 0xf902
	it = must([]uint16{0x01d8, 0xf902})
	if it.a != 1 || it.b != 2 || it.lit != -7 {
		t.Fatalf("lit8 操作数错误: %+v", it)
	}
	// 23x: add-int v3, v4, v5 → word0=0x0390, word1=0x0504
	it = must([]uint16{0x0390, 0x0504})
	if it.a != 3 || it.b != 4 || it.c != 5 {
		t.Fatalf("23x 操作数错误: %+v", it)
	}
	// 10t: goto -5 → word0 = 0x28 | 0xfb<<8 = 0xfb28
	it = must([]uint16{0xfb28})
	if it.target != -5 || it.width != 1 {
		t.Fatalf("goto 解码错误: %+v", it)
	}
	// 21t: if-eqz v7, +4 → word0 = 0x38 | 7<<8 = 0x0738, word1=4
	it = must([]uint16{0x0738, 0x0004})
	if it.op != 0x38 || it.a != 7 || it.target != 4 {
		t.Fatalf("if-eqz 解码错误: %+v", it)
	}
	// 35c: invoke-static {v1}, method@3 → word0 = 0x71 | 1<<12 = 0x1071, word1=3, word2=1
	it = must([]uint16{0x1071, 0x0003, 0x0001})
	if it.op != 0x71 || it.ref != 3 || !reflect.DeepEqual(it.args, []int{1}) {
		t.Fatalf("invoke-static 解码错误: %+v", it)
	}
	// 3rc: invoke-static/range {v2..v4}, method@9
	it = must([]uint16{0x0377, 0x0009, 0x0002})
	if it.op != 0x77 || it.ref != 9 || !reflect.DeepEqual(it.args, []int{2, 3, 4}) {
		t.Fatalf("invoke-static/range 解码错误: %+v", it)
	}
}

// ---- 参考解释器（测试用，语义基准） ----

// u32 是运行期有符号转无符号（避免常量转换溢出检查）。
func u32(v int32) uint32 { return uint32(v) }

// runInterp 对纯整型方法执行参考解释，返回 (返回值, 是否抛异常)。
func runInterp(t *testing.T, m *Method, args []uint32) (uint32, bool) {
	t.Helper()
	regs := make([]uint32, m.Registers)
	base := m.Registers - m.Ins
	if m.Static {
		for i, a := range args {
			regs[base+i] = a
		}
	} else {
		for i, a := range args {
			regs[base+1+i] = a
		}
	}
	idx := 0
	steps := 0
	for {
		steps++
		if steps > 3000000 {
			t.Fatalf("解释器步数超限（死循环？）")
		}
		it := m.ins[idx]
		x := func(r int) int32 { return int32(regs[r]) }
		switch it.op {
		case 0x00:
		case 0x01, 0x02, 0x03, 0x07, 0x08, 0x09:
			regs[it.a] = regs[it.b]
		case 0x0a:
			// 结果由 invoke 直接写入，这里无操作。
		case 0x12, 0x13, 0x14, 0x15:
			regs[it.a] = uint32(int32(it.lit))
		case 0x0f:
			return regs[it.a], false
		case 0x7b:
			regs[it.a] = uint32(-x(it.b))
		case 0x7c:
			regs[it.a] = ^regs[it.b]
		case 0x8d:
			regs[it.a] = uint32(int32(int8(regs[it.b])))
		case 0x8e:
			regs[it.a] = uint32(uint16(regs[it.b]))
		case 0x8f:
			regs[it.a] = uint32(int32(int16(regs[it.b])))
		case 0x90, 0x91, 0x92, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a:
			regs[it.a] = intBin(it.op, regs[it.b], regs[it.c])
		case 0x93:
			if regs[it.c] == 0 {
				return 0, true
			}
			regs[it.a] = uint32(x(it.b) / x(it.c))
		case 0x94:
			if regs[it.c] == 0 {
				return 0, true
			}
			regs[it.a] = uint32(x(it.b) % x(it.c))
		case 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba:
			bop := int2addrOp(it.op)
			if (bop == 0x93 || bop == 0x94) && regs[it.b] == 0 {
				return 0, true
			}
			regs[it.a] = intBin(bop, regs[it.a], regs[it.b])
		case 0xd0, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7:
			if (it.op == 0xd3 || it.op == 0xd4) && int32(it.lit) == 0 {
				return 0, true
			}
			regs[it.a] = intBin(0x90+(it.op-0xd0), regs[it.b], uint32(int32(it.lit)))
		case 0xd1:
			regs[it.a] = uint32(int32(it.lit) - x(it.b))
		case 0xd8, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2:
			if (it.op == 0xdb || it.op == 0xdc) && int32(it.lit) == 0 {
				return 0, true
			}
			regs[it.a] = intBin(0x90+(it.op-0xd8), regs[it.b], uint32(int32(it.lit)))
		case 0xd9:
			regs[it.a] = uint32(int32(it.lit) - x(it.b))
		case 0x28, 0x29, 0x2a:
			ti, _ := m.targetIdx(it)
			idx = ti
			continue
		case 0x32, 0x33:
			take := regs[it.a] == regs[it.b]
			if it.op == 0x33 {
				take = !take
			}
			ti, _ := m.targetIdx(it)
			if take {
				idx = ti
				continue
			}
		case 0x34, 0x35, 0x36, 0x37:
			cmp := int32(regs[it.a]) - int32(regs[it.b])
			var take bool
			switch it.op {
			case 0x34:
				take = cmp < 0
			case 0x35:
				take = cmp >= 0
			case 0x36:
				take = cmp > 0
			case 0x37:
				take = cmp <= 0
			}
			ti, _ := m.targetIdx(it)
			if take {
				idx = ti
				continue
			}
		case 0x38, 0x39:
			take := regs[it.a] == 0
			if it.op == 0x39 {
				take = !take
			}
			ti, _ := m.targetIdx(it)
			if take {
				idx = ti
				continue
			}
		case 0x3a, 0x3b, 0x3c, 0x3d:
			v := x(it.a)
			var take bool
			switch it.op {
			case 0x3a:
				take = v < 0
			case 0x3b:
				take = v >= 0
			case 0x3c:
				take = v > 0
			case 0x3d:
				take = v <= 0
			}
			ti, _ := m.targetIdx(it)
			if take {
				idx = ti
				continue
			}
		default:
			t.Fatalf("参考解释器不支持的指令 %s（0x%02x）", it.name, it.op)
		}
		idx++
	}
}

// intBin 按 DEX 语义执行整型二元运算。
func intBin(op byte, a, b uint32) uint32 {
	switch op {
	case 0x90:
		return a + b
	case 0x91:
		return a - b
	case 0x92:
		return a * b
	case 0x93:
		return uint32(int32(a) / int32(b))
	case 0x94:
		return uint32(int32(a) % int32(b))
	case 0x95:
		return a & b
	case 0x96:
		return a | b
	case 0x97:
		return a ^ b
	case 0x98:
		return a << (b & 31)
	case 0x99:
		return uint32(int32(a) >> (b & 31))
	case 0x9a:
		return a >> (b & 31)
	}
	panic("bad op")
}

// TestJavaSemanticsBoundaries 用参考解释器断言边界值与 DEX 语义一致。
func TestJavaSemanticsBoundaries(t *testing.T) {
	const minI = uint32(0x80000000)
	mk := func(name string, params []string, f func(a *dex.Asm) error) dex.ClassMethod {
		n := len(params)
		return staticMethod(name, dex.ProtoSpec{Ret: "I", Params: params}, blobOf(t, n+1, n, 0, f))
	}
	data := buildDex(t,
		mk("divv", []string{"I", "I"}, func(a *dex.Asm) error { a.DivInt(0, 1, 2); a.Return(0); return nil }),
		mk("remv", []string{"I", "I"}, func(a *dex.Asm) error { a.RemInt(0, 1, 2); a.Return(0); return nil }),
		mk("shl", []string{"I", "I"}, func(a *dex.Asm) error { a.ShlInt(0, 1, 2); a.Return(0); return nil }),
		mk("shr", []string{"I", "I"}, func(a *dex.Asm) error { a.ShrInt(0, 1, 2); a.Return(0); return nil }),
		mk("ushr", []string{"I", "I"}, func(a *dex.Asm) error { a.UshrInt(0, 1, 2); a.Return(0); return nil }),
		mk("addv", []string{"I", "I"}, func(a *dex.Asm) error { a.AddInt(0, 1, 2); a.Return(0); return nil }),
		mk("i2b", []string{"I"}, func(a *dex.Asm) error { a.IntToByte(0, 1); a.Return(0); return nil }),
		staticMethod("sum", dex.ProtoSpec{Ret: "I", Params: []string{"I"}}, blobOf(t, 3, 1, 0, func(a *dex.Asm) error {
			a.Const4(0, 0) // v0 = s
			a.Const4(1, 0) // v1 = i
			a.Label("loop")
			if err := a.IfGe(1, 2, "done"); err != nil { // i >= n（n 是 v2）
				return err
			}
			a.AddInt(0, 0, 1)
			a.AddIntLit8(1, 1)
			a.Goto("loop")
			a.Label("done")
			a.Return(0)
			return nil
		})),
	)
	sel := selectAll(t, data, 100, nil)
	if len(sel.Methods) != 8 {
		t.Fatalf("应选中 8 个方法，实际 %d（跳过 %v）", len(sel.Methods), sel.Skip)
	}
	byName := map[string]*Method{}
	for _, m := range sel.Methods {
		byName[m.Name] = m
	}

	type tc struct {
		method string
		args   []uint32
		want   uint32
		throws bool
	}
	cases := []tc{
		{"divv", []uint32{7, 2}, 3, false},
		{"divv", []uint32{u32(-7), 2}, u32(-3), false},
		{"divv", []uint32{7, u32(-2)}, u32(-3), false},
		{"divv", []uint32{minI, u32(-1)}, minI, false}, // 溢出回绕，不抛
		{"divv", []uint32{1, 0}, 0, true},              // ArithmeticException
		{"remv", []uint32{7, 2}, 1, false},
		{"remv", []uint32{u32(-7), 2}, u32(-1), false},
		{"remv", []uint32{minI, u32(-1)}, 0, false},
		{"remv", []uint32{1, 0}, 0, true},
		{"shl", []uint32{1, 33}, 2, false}, // 位移量按 5 位掩码
		{"shl", []uint32{1, u32(-1)}, 1 << 31, false},
		{"shl", []uint32{minI, 1}, 0, false},
		{"shr", []uint32{u32(-1), 1}, u32(-1), false},
		{"shr", []uint32{minI, 31}, u32(-1), false},
		{"ushr", []uint32{minI, 31}, 1, false},
		{"ushr", []uint32{u32(-1), 1}, 0x7fffffff, false},
		{"addv", []uint32{0x7fffffff, 1}, 0x80000000, false}, // 溢出回绕
		{"addv", []uint32{u32(-1), 1}, 0, false},
		{"i2b", []uint32{0x1ff}, u32(-1), false},
		{"i2b", []uint32{0x80}, u32(-128), false},
		{"sum", []uint32{0}, 0, false},
		{"sum", []uint32{1}, 0, false},
		{"sum", []uint32{5}, 10, false},
		{"sum", []uint32{100}, 4950, false},
	}
	for _, c := range cases {
		m := byName[c.method]
		if m == nil {
			t.Fatalf("方法 %s 未被选中", c.method)
		}
		got, thrown := runInterp(t, m, c.args)
		if thrown != c.throws {
			t.Errorf("%s%v: 抛异常=%v，期望 %v", c.method, c.args, thrown, c.throws)
			continue
		}
		if !thrown && got != c.want {
			t.Errorf("%s%v: got 0x%08x，期望 0x%08x", c.method, c.args, got, c.want)
		}
	}
}

// ---- 翻译与代码形态 ----

// TestTranslatePerInstruction 对支持子集的每条指令做一次翻译，断言 C 形态。
func TestTranslatePerInstruction(t *testing.T) {
	type item struct {
		name   string
		method dex.ClassMethod
		want   string
	}
	mk1 := func(name string, ret string, params []string, f func(a *dex.Asm) error) dex.ClassMethod {
		n := len(params)
		return staticMethod(name, dex.ProtoSpec{Ret: ret, Params: params}, blobOf(t, n+1, n, 0, f))
	}
	items := []item{
		{"const4", mk1("const4", "I", nil, func(a *dex.Asm) error {
			a.Const4(0, 5)
			a.Return(0)
			return nil
		}), "v[0] = (uint32_t)0x00000005u"},
		{"const16", mk1("const16", "I", nil, func(a *dex.Asm) error {
			a.Const16(0, 1000)
			a.Return(0)
			return nil
		}), "v[0] = (uint32_t)0x000003e8u"},
		{"const32", mk1("const32", "I", nil, func(a *dex.Asm) error {
			a.Const32(0, 100000)
			a.Return(0)
			return nil
		}), "v[0] = (uint32_t)0x000186a0u"},
		{"div", mk1("divx", "I", []string{"I", "I"}, func(a *dex.Asm) error {
			a.DivInt(0, 1, 2)
			a.Return(0)
			return nil
		}), "b7_div(env"},
		{"rem", mk1("remx", "I", []string{"I", "I"}, func(a *dex.Asm) error {
			a.RemInt(0, 1, 2)
			a.Return(0)
			return nil
		}), "b7_rem(env"},
		{"addlit8", mk1("addl8", "I", []string{"I"}, func(a *dex.Asm) error {
			a.AddIntLit8(1, 3)
			a.Return(1)
			return nil
		}), "v[1] = v[1] + (uint32_t)0x00000003u"},
		{"if", mk1("ifx", "I", []string{"I"}, func(a *dex.Asm) error {
			a.Const4(0, 0)
			if err := a.IfLt(1, 0, "neg"); err != nil { // v1 < 0
				return err
			}
			a.Const4(0, 1)
			a.Return(0)
			a.Label("neg")
			a.Const4(0, 0)
			a.Return(0)
			return nil
		}), "if ((int32_t)v[1] < (int32_t)v[0]) goto L5;"},
		{"goto", mk1("gotox", "I", nil, func(a *dex.Asm) error {
			a.Goto("end")
			a.Const4(0, 1)
			a.Label("end")
			a.Const4(0, 2)
			a.Return(0)
			return nil
		}), "goto L2;"},
		{"int-to-short", staticMethod("i2s", dex.ProtoSpec{Ret: "I", Params: []string{"I"}},
			blobRaw(2, 1, 0, 0x108f, 0x000f)), "v[0] = (uint32_t)(int16_t)v[1];"},
		{"shl-int/2addr", staticMethod("shl2", dex.ProtoSpec{Ret: "I", Params: []string{"I", "I"}},
			blobRaw(3, 2, 0, 0x20b8, 0x000f)), "<< (v[2] & 31u)"},
		{"rsub-int/lit8", staticMethod("rsub", dex.ProtoSpec{Ret: "I", Params: []string{"I"}},
			blobRaw(2, 1, 0, 0x00d9, 0x0701, 0x000f)), "(int32_t)0x00000007u - (int32_t)v[1]"},
	}
	for _, it := range items {
		data := buildDex(t, it.method)
		sel, csrc := generateFor(t, data, 10)
		if len(sel.Methods) != 1 {
			t.Errorf("%s: 应选中 1 个方法，实际 %d（跳过 %v）", it.name, len(sel.Methods), sel.Skip)
			continue
		}
		if !strings.Contains(string(csrc), it.want) {
			t.Errorf("%s: 生成的 C 中未找到 %q\n%s", it.name, it.want, csrc)
		}
	}
}

// TestTranslateRefsAndInvokes 覆盖字符串/字段/静态/虚/接口调用。
func TestTranslateRefsAndInvokes(t *testing.T) {
	data := buildDex(t,
		staticMethod("str", dex.ProtoSpec{Ret: "Ljava/lang/String;"}, blobOf(t, 1, 0, 0, func(a *dex.Asm) error {
			a.ConstString(0, "héllo")
			a.ReturnObject(0)
			return nil
		})),
		staticMethod("sgetx", dex.ProtoSpec{Ret: "I"}, blobOf(t, 1, 0, 0, func(a *dex.Asm) error {
			a.SGet(0, dex.FieldSpec{Class: "Lcom/t/A;", Name: "COUNT", Type: "I"})
			a.Return(0)
			return nil
		})),
		staticMethod("igetx", dex.ProtoSpec{Ret: "I", Params: []string{"Lcom/t/A;"}}, blobOf(t, 2, 1, 0, func(a *dex.Asm) error {
			if err := a.IGet(0, 1, dex.FieldSpec{Class: "Lcom/t/A;", Name: "n", Type: "I"}); err != nil {
				return err
			}
			a.Return(0)
			return nil
		})),
		staticMethod("iputx", dex.ProtoSpec{Ret: "V", Params: []string{"Lcom/t/A;", "I"}}, blobOf(t, 3, 2, 0, func(a *dex.Asm) error {
			if err := a.IPut(2, 1, dex.FieldSpec{Class: "Lcom/t/A;", Name: "n", Type: "I"}); err != nil {
				return err
			}
			a.ReturnVoid()
			return nil
		})),
		staticMethod("callstatic", dex.ProtoSpec{Ret: "I", Params: []string{"I"}}, blobOf(t, 2, 1, 1, func(a *dex.Asm) error {
			if err := a.InvokeStatic([]int{1}, dex.MethodSpec{Class: "Ljava/lang/Math;", Name: "abs", Proto: dex.ProtoSpec{Ret: "I", Params: []string{"I"}}}); err != nil {
				return err
			}
			a.MoveResult(0)
			a.Return(0)
			return nil
		})),
		staticMethod("callvirt", dex.ProtoSpec{Ret: "I", Params: []string{"Ljava/lang/String;"}}, blobOf(t, 2, 1, 1, func(a *dex.Asm) error {
			if err := a.InvokeVirtual([]int{1}, dex.MethodSpec{Class: "Ljava/lang/String;", Name: "length", Proto: dex.ProtoSpec{Ret: "I"}}); err != nil {
				return err
			}
			a.MoveResult(0)
			a.Return(0)
			return nil
		})),
		staticMethod("calliface", dex.ProtoSpec{Ret: "C", Params: []string{"Ljava/lang/CharSequence;", "I"}}, blobOf(t, 3, 2, 2, func(a *dex.Asm) error {
			if err := a.InvokeInterface([]int{1, 2}, dex.MethodSpec{Class: "Ljava/lang/CharSequence;", Name: "charAt", Proto: dex.ProtoSpec{Ret: "C", Params: []string{"I"}}}); err != nil {
				return err
			}
			a.MoveResult(0)
			a.Return(0)
			return nil
		})),
	)
	sel, csrc := generateFor(t, data, 100)
	if len(sel.Methods) != 7 {
		t.Fatalf("应选中 7 个方法，实际 %d；跳过: %v", len(sel.Methods), sel.Skip)
	}
	s := string(csrc)
	for _, want := range []string{
		"NewString(env, (const jchar *)b7_str_", "GetFieldID", "GetStaticFieldID",
		"SetIntField", "FindClass(env, \"java/lang/Math\")", "CallStaticIntMethod",
		"GetObjectClass", "CallIntMethod", "CallCharMethod", "RegisterNatives", "b7_register_all",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("生成的 C 中未找到 %q", want)
		}
	}
	// UTF-16 字面量必须包含 é (U+00E9)，验证不是 NewStringUTF 路径。
	if !strings.Contains(s, "0x00e9") {
		t.Errorf("字符串常量未按 UTF-16 输出:\n%s", s)
	}
}

// ---- 跳过规则 ----

func TestSelectSkipReasons(t *testing.T) {
	nativeM := dex.ClassMethod{Name: "nat", Proto: dex.ProtoSpec{Ret: "I"}, Access: 0x0109}
	abstractM := dex.ClassMethod{Name: "absm", Proto: dex.ProtoSpec{Ret: "I"}, Access: 0x0409}
	syncM := dex.ClassMethod{Name: "sync", Proto: dex.ProtoSpec{Ret: "I"}, Access: 0x0029,
		Code: blobOf(t, 1, 0, 0, func(a *dex.Asm) error { a.Const4(0, 1); a.Return(0); return nil })}
	ctorM := dex.ClassMethod{Name: "<init>", Proto: dex.ProtoSpec{Ret: "V"}, Access: 0x10001,
		Code: blobOf(t, 1, 0, 0, func(a *dex.Asm) error { a.ReturnVoid(); return nil })}
	wideM := staticMethod("w", dex.ProtoSpec{Ret: "J"}, blobOf(t, 3, 0, 0, func(a *dex.Asm) error {
		a.Const32(0, 1)
		a.Return(0)
		return nil
	}))
	longFn := func(a *dex.Asm) error {
		for i := 0; i < 70; i++ {
			a.Const4(0, 1)
		}
		a.Return(0)
		return nil
	}
	longM := staticMethod("longm", dex.ProtoSpec{Ret: "I"}, blobOf(t, 1, 0, 0, longFn))
	unsupM := staticMethod("newx", dex.ProtoSpec{Ret: "V"}, blobOf(t, 2, 0, 1, func(a *dex.Asm) error {
		a.NewInstance(0, "Ljava/lang/Object;")
		if err := a.InvokeDirect([]int{0}, dex.MethodSpec{Class: "Ljava/lang/Object;", Name: "<init>", Proto: dex.ProtoSpec{Ret: "V"}}); err != nil {
			return err
		}
		a.ReturnVoid()
		return nil
	}))
	badCallM := staticMethod("badcall", dex.ProtoSpec{Ret: "V"}, blobOf(t, 1, 0, 1, func(a *dex.Asm) error {
		if err := a.InvokeStatic(nil, dex.MethodSpec{Class: "Ljava/lang/Runtime;", Name: "getRuntime", Proto: dex.ProtoSpec{Ret: "Ljava/lang/Runtime;"}}); err != nil {
			return err
		}
		a.MoveResultObject(0)
		a.ReturnVoid()
		return nil
	}))
	reflectM := staticMethod("refl", dex.ProtoSpec{Ret: "I"}, blobOf(t, 1, 0, 0, func(a *dex.Asm) error {
		a.Const4(0, 1)
		a.Return(0)
		return nil
	}))
	convM := staticMethod("conv", dex.ProtoSpec{Ret: "I", Params: []string{"I"}}, blobRaw(2, 1, 0, 0x108f, 0x000f))
	okM := staticMethod("okm", dex.ProtoSpec{Ret: "I"}, blobOf(t, 1, 0, 0, func(a *dex.Asm) error {
		a.Const4(0, 1)
		a.Return(0)
		return nil
	}))

	data := buildDex(t, nativeM, abstractM, syncM, ctorM, wideM, longM, unsupM, badCallM, reflectM, convM, okM)
	sel := selectAll(t, data, 100, map[string]bool{"refl": true})
	gotNames := map[string]bool{}
	for _, m := range sel.Methods {
		gotNames[m.Name] = true
	}
	for _, want := range []string{"conv", "okm"} {
		if !gotNames[want] {
			t.Fatalf("应选中 %s；实际 %v（跳过 %v）", want, methodNames(sel.Methods), sel.Skip)
		}
	}
	for _, reason := range []string{"native", "abstract", "sync", "ctor", "wide", "big", "insn", "invoke", "reflect"} {
		if sel.Skip[reason] == 0 {
			t.Errorf("缺少跳过原因 %s；全部统计: %v", reason, sel.Skip)
		}
	}
	// 有 try/catch 的方法。
	if reasonOfTry(t) != "try" {
		t.Error("try/catch 方法的跳过原因应为 try")
	}
	if sel.ReasonReport() == "" {
		t.Error("跳过原因报告为空")
	}
	rep1 := sel.ReasonReport()
	sel2 := selectAll(t, data, 100, map[string]bool{"refl": true})
	if rep1 != sel2.ReasonReport() {
		t.Errorf("原因报告不稳定:\n%s\n%s", rep1, sel2.ReasonReport())
	}
}

// reasonOfTry 构造一个带 try/catch 的方法并断言其被以 try 跳过。
func reasonOfTry(t *testing.T) string {
	t.Helper()
	base := buildDex(t, staticMethod("trym", dex.ProtoSpec{Ret: "V"}, blobOf(t, 1, 0, 0, func(a *dex.Asm) error {
		a.ReturnVoid()
		return nil
	})))
	f, err := dex.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	var codeOff uint32
	f.Classes(func(_ uint32, cd dex.ClassDef, name string) error {
		if name != "Lcom/t/A;" || cd.ClassDataOff == 0 {
			return nil
		}
		pcd, err := f.ParseClassData(cd.ClassDataOff)
		if err != nil {
			return err
		}
		for _, m := range pcd.DirectMethods {
			if m.CodeOff != 0 && codeOff == 0 {
				codeOff = m.CodeOff
			}
		}
		return nil
	})
	if codeOff == 0 {
		t.Fatal("没找到可改写的 code_item")
	}
	ci := &dex.CodeItemFull{
		Registers: 1, Ins: 0,
		Insns: []uint16{0x000e}, // return-void
		Tries: []dex.TryItem{{StartAddr: 0, InsnCount: 1, HandlerOff: 0}},
		Handlers: []dex.CatchHandler{{
			Types: []uint32{0}, Addrs: []uint32{1}, CatchAll: true, AllAddr: 1,
		}},
		HandlerOffs: []uint16{0},
	}
	blob, err := ci.EncodeChecked(nil)
	if err != nil {
		t.Fatalf("编码 try code_item 失败: %v", err)
	}
	out, err := dex.Rebuild(f, dex.RebuildOptions{CodeReplacements: map[uint32][]byte{codeOff: blob}})
	if err != nil {
		t.Fatalf("重建失败: %v", err)
	}
	f2, err := dex.Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	sel := Select([]DexInput{{Name: "classes.dex", File: f2}}, 100, "s", nil)
	if sel.Skip["try"] == 0 {
		t.Fatalf("未产生 try 跳过；统计 %v，选中 %v", sel.Skip, methodNames(sel.Methods))
	}
	return "try"
}

// ---- 确定性与零方法 ----

func TestGenerateDeterministic(t *testing.T) {
	data := buildDex(t,
		staticMethod("f1", dex.ProtoSpec{Ret: "I", Params: []string{"I", "I"}}, blobOf(t, 3, 2, 0, func(a *dex.Asm) error {
			a.AddInt(0, 1, 2)
			a.MulInt(0, 0, 2)
			a.Return(0)
			return nil
		})),
		staticMethod("f2", dex.ProtoSpec{Ret: "Ljava/lang/String;"}, blobOf(t, 1, 0, 0, func(a *dex.Asm) error {
			a.ConstString(0, "abc")
			a.ReturnObject(0)
			return nil
		})),
	)
	gen := func(seed string) []byte {
		f, err := dex.Parse(data)
		if err != nil {
			t.Fatal(err)
		}
		sel := Select([]DexInput{{Name: "classes.dex", File: f}}, 10, seed, nil)
		for i, m := range sel.Methods {
			m.FnName = funcNameOf(fmt.Sprintf("%s#%d", seed, i), m)
		}
		csrc, err := generateC(sel.Methods, seed)
		if err != nil {
			t.Fatal(err)
		}
		return csrc
	}
	a, b := gen("same"), gen("same")
	if !bytes.Equal(a, b) {
		t.Fatal("同 seed 两次生成的 C 不一致")
	}
	fd, err := dex.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	selRef := Select([]DexInput{{Name: "classes.dex", File: fd}}, 10, "same", nil)
	if libNameOf("same", selRef.Methods) != libNameOf("same", selRef.Methods) {
		t.Fatal("同 seed 库名不稳定")
	}
	if libNameOf("same", selRef.Methods) == libNameOf("other", selRef.Methods) {
		t.Fatal("不同 seed 应得到不同库名")
	}
	if len(gen("other")) == 0 {
		t.Fatal("生成结果为空")
	}
}

func TestSelectZeroLimit(t *testing.T) {
	data := buildDex(t, staticMethod("f", dex.ProtoSpec{Ret: "I"}, blobOf(t, 1, 0, 0, func(a *dex.Asm) error {
		a.Const4(0, 1)
		a.Return(0)
		return nil
	})))
	if sel := selectAll(t, data, 0, nil); len(sel.Methods) != 0 {
		t.Fatal("limit=0 不应选中任何方法")
	}
}

// ---- 宿主差分测试（可选，需要 WSL + gcc） ----

// TestHostGccDifferential 把生成的 C 用宿主 gcc 编译执行，与参考解释器对拍。
//
// 设置 APKGUARD_TEST_WSL=1 启用；可用 WSLDistroEnv 指定发行版。NDK 产物无法
// 在 x86 Linux 上直接运行，因此这里对纯整型子集用宿主 gcc 验证「生成的 C 与
// DEX 语义一致」——这是翻译器正确性最直接的端到端证据。
func TestHostGccDifferential(t *testing.T) {
	if os.Getenv("APKGUARD_TEST_WSL") != "1" {
		t.Skip("未设置 APKGUARD_TEST_WSL=1，跳过宿主 gcc 差分测试")
	}
	distro := os.Getenv(WSLDistroEnv)
	if distro == "" {
		distro = "Ubuntu-26.04"
	}
	binaryMk := func(name string, params []string, f func(a *dex.Asm) error) dex.ClassMethod {
		n := len(params)
		return staticMethod(name, dex.ProtoSpec{Ret: "I", Params: params}, blobOf(t, n+1, n, 0, f))
	}
	data := buildDex(t,
		binaryMk("addv", []string{"I", "I"}, func(a *dex.Asm) error { a.AddInt(0, 1, 2); a.Return(0); return nil }),
		binaryMk("subv", []string{"I", "I"}, func(a *dex.Asm) error { a.SubInt(0, 1, 2); a.Return(0); return nil }),
		binaryMk("mulv", []string{"I", "I"}, func(a *dex.Asm) error { a.MulInt(0, 1, 2); a.Return(0); return nil }),
		binaryMk("divv", []string{"I", "I"}, func(a *dex.Asm) error { a.DivInt(0, 1, 2); a.Return(0); return nil }),
		binaryMk("remv", []string{"I", "I"}, func(a *dex.Asm) error { a.RemInt(0, 1, 2); a.Return(0); return nil }),
		binaryMk("shlv", []string{"I", "I"}, func(a *dex.Asm) error { a.ShlInt(0, 1, 2); a.Return(0); return nil }),
		binaryMk("shrv", []string{"I", "I"}, func(a *dex.Asm) error { a.ShrInt(0, 1, 2); a.Return(0); return nil }),
		binaryMk("ushrv", []string{"I", "I"}, func(a *dex.Asm) error { a.UshrInt(0, 1, 2); a.Return(0); return nil }),
		staticMethod("sumv", dex.ProtoSpec{Ret: "I", Params: []string{"I"}}, blobOf(t, 3, 1, 0, func(a *dex.Asm) error {
			a.Const4(0, 0)
			a.Const4(1, 0)
			a.Label("loop")
			if err := a.IfGe(1, 2, "done"); err != nil {
				return err
			}
			a.AddInt(0, 0, 1)
			a.AddIntLit8(1, 1)
			a.Goto("loop")
			a.Label("done")
			a.Return(0)
			return nil
		})),
	)
	sel, csrc := generateFor(t, data, 100)
	if len(sel.Methods) != 9 {
		t.Fatalf("应选中 9 个纯整型方法，实际 %d（跳过 %v）", len(sel.Methods), sel.Skip)
	}

	dir := t.TempDir()
	stub := `#ifndef B7_STUB_JNI_H
#define B7_STUB_JNI_H
#include <stdint.h>
#include <stddef.h>
typedef int32_t jint; typedef uint8_t jboolean; typedef int8_t jbyte;
typedef int16_t jshort; typedef uint16_t jchar; typedef int64_t jlong;
typedef float jfloat; typedef double jdouble;
typedef void *jobject; typedef void *jclass; typedef void *jstring;
typedef void *jmethodID; typedef void *jfieldID; typedef int jsize;
typedef struct { const char *name; const char *signature; void *fnPtr; } JNINativeMethod;
struct JNIEnv_;
typedef struct JNIEnv_ *JNIEnv;
struct JNIEnv_ {
  jclass (*FindClass)(JNIEnv *, const char *);
  jint (*ThrowNew)(JNIEnv *, jclass, const char *);
  void (*DeleteLocalRef)(JNIEnv *, jobject);
  jint (*ExceptionCheck)(JNIEnv *);
  jint (*RegisterNatives)(JNIEnv *, jclass, const JNINativeMethod *, jint);
};
#define JNIEXPORT
#define JNICALL
#endif
`
	harness := &bytes.Buffer{}
	harness.WriteString("#include <jni.h>\n#include <stdio.h>\n")
	for _, m := range sel.Methods {
		fmt.Fprintf(harness, "extern jint %s(JNIEnv *, jclass, %s);\n", m.FnName,
			strings.TrimSuffix(strings.Repeat("jint, ", len(m.params)), ", "))
	}
	harness.WriteString("static jclass fk(JNIEnv *e, const char *n){(void)e;(void)n;return 0;}\n")
	harness.WriteString("static jint tn(JNIEnv *e, jclass c, const char *m){(void)e;(void)c;(void)m;return 0;}\n")
	harness.WriteString("static void dl(JNIEnv *e, jobject o){(void)e;(void)o;}\n")
	harness.WriteString("static jint ec(JNIEnv *e){(void)e;return 0;}\n")
	harness.WriteString("int main(void){ struct JNIEnv_ e; JNIEnv ep=&e; JNIEnv *env=&ep; (*env)->FindClass=fk; (*env)->ThrowNew=tn; (*env)->DeleteLocalRef=dl; (*env)->ExceptionCheck=ec; (void)env;\n")
	vals := []uint32{0, 1, 2, 7, 0x7fffffff, 0x80000000, 0xffffffff, 0xfffffffe, 100, 0x12345678}
	smallVals := []uint32{0, 1, 2, 5, 100}
	for i, m := range sel.Methods {
		for _, a := range vals {
			switch len(m.params) {
			case 1:
				if m.Name == "sumv" && a > 1000 {
					continue // 避免 20 亿次循环
				}
				fmt.Fprintf(harness, "  { uint32_t r = (uint32_t)%s(env, 0, (jint)0x%08xu); printf(\"%%d 0x%%08x\\n\", %d, r); }\n", m.FnName, a, i)
			case 2:
				for _, b := range smallVals {
					fmt.Fprintf(harness, "  { uint32_t r = (uint32_t)%s(env, 0, (jint)0x%08xu, (jint)0x%08xu); printf(\"%%d 0x%%08x\\n\", %d, r); }\n", m.FnName, a, b, i)
				}
			}
		}
	}
	harness.WriteString("  return 0;\n}\n")
	writeFile(t, filepath.Join(dir, "jni.h"), []byte(stub))
	writeFile(t, filepath.Join(dir, "b7.c"), csrc)
	writeFile(t, filepath.Join(dir, "harness.c"), harness.Bytes())

	wslDir, err := wslPathOf(t, distro, dir)
	if err != nil {
		t.Skipf("WSL 路径转换失败（%v），跳过", err)
	}
	script := fmt.Sprintf("cd %s && gcc -std=gnu11 -O1 -I. -o b7test harness.c b7.c && ./b7test", shq(wslDir))
	out, err := wslRun(distro, script)
	if err != nil {
		t.Fatalf("宿主 gcc 编译/执行失败: %v\n%s", err, out)
	}
	cRes := map[int][]uint32{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var idx int
		var v uint32
		if _, err := fmt.Sscanf(line, "%d 0x%x", &idx, &v); err != nil {
			t.Fatalf("解析输出 %q 失败: %v", line, err)
		}
		cRes[idx] = append(cRes[idx], v)
	}
	for i, m := range sel.Methods {
		got := cRes[i]
		pos := 0
		for _, a := range vals {
			switch len(m.params) {
			case 1:
				if m.Name == "sumv" && a > 1000 {
					continue
				}
				want, thrown := runInterp(t, m, []uint32{a})
				if thrown {
					want = 0
				}
				if pos >= len(got) || got[pos] != want {
					t.Fatalf("%s(0x%08x): C=%v 解释器=0x%08x", m.Name, a, got, want)
				}
				pos++
			case 2:
				for _, b := range smallVals {
					want, thrown := runInterp(t, m, []uint32{a, b})
					if thrown {
						want = 0
					}
					if pos >= len(got) || got[pos] != want {
						t.Fatalf("%s(0x%08x,0x%08x): C=0x%08x 解释器=0x%08x", m.Name, a, b, got[pos], want)
					}
					pos++
				}
			}
		}
	}
}

// ---- 小工具 ----

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// wslPathOf 把 Windows 路径转换为 WSL 内的 /mnt/<drive>/ 路径。
func wslPathOf(t *testing.T, distro, win string) (string, error) {
	t.Helper()
	abs, err := filepath.Abs(win)
	if err != nil {
		return "", err
	}
	out, err := wslRun(distro, "wslpath -a -u "+shq(abs))
	if err != nil {
		return "", fmt.Errorf("%v: %s", err, out)
	}
	return strings.TrimSpace(out), nil
}

// wslRun 在 WSL 发行版内执行 shell 命令。
func wslRun(distro, script string) (string, error) {
	args := wslPrefix(distro)
	args = append(args, "-e", "sh", "-c", script)
	cmd := exec.Command("wsl", args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// shq 给 shell 参数加单引号。
func shq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// sortedMethodNames 返回排序后的方法名（供稳定断言）。
func sortedMethodNames(ms []*Method) []string {
	out := methodNames(ms)
	sort.Strings(out)
	return out
}
