package dex

import (
	"archive/zip"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// ---- #1 A3 常量数组化：长度 > 0x7fff 必须用 const(31i) 承载 ----

// decodeConstSize 按操作码解释「new-array 前驱常量」的立即数：
// 0x13 是 const/16（21s，有符号 16 位），0x14 是 const（31i，有符号 32 位）。
func decodeConstSize(op byte, w []uint16) (int, bool) {
	switch op {
	case 0x13:
		return int(int16(w[1])), true
	case 0x14:
		return int(int32(uint32(w[1]) | uint32(w[2])<<16)), true
	}
	return 0, false
}

// TestAuditA3LargeConstArrayImmediate 钉住 40000 字节字符串必须生成**非负**的长度常量。
//
// 缺陷：长度 > 0x7fff 时旧实现仍用 const/16（21s）承载，uint16(40000)=40000 被
// 当作有符号 int16 解释成 -25536；真机 new-array 收到负长度抛
// NegativeArraySizeException。修复后必须用 const（0x14，31i，3 字）。
func TestAuditA3LargeConstArrayImmediate(t *testing.T) {
	words := []uint16{0x001a, 0, 0x000e} // const-string v0,#0 ; return-void
	l, err := ParseInsns(words)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	data := make([]byte, 40000)
	for i := range data {
		data[i] = byte(i)
	}
	if !l.ReplaceWithArrayData(0, data, 7, 9) {
		t.Fatal("大长度常量数组化应成功")
	}
	out, _, fresh := l.Encode()

	op := byte(out[0] & 0xff)
	imm, ok := decodeConstSize(op, out)
	if !ok {
		t.Fatalf("new-array 前驱常量应为 const/16(0x13) 或 const(0x14)，实际 0x%02x", op)
	}
	if imm != 40000 {
		t.Fatalf("前驱常量应为 40000，实际 %d (op=0x%02x, 立即数被截断/符号化)", imm, op)
	}
	if imm < 0 {
		t.Fatalf("前驱常量为负 %d（真机 new-array 抛 NegativeArraySizeException）", imm)
	}
	if op != 0x14 {
		t.Fatalf("> 0x7fff 必须用 const(0x14, 31i)，实际 0x%02x", op)
	}
	// 后续指令布局整体 +1 字：new-array @3、fill-array-data @5、invoke @8、move-result @11
	if out[3]&0xff != 0x23 {
		t.Fatalf("new-array 应在 word 3，实际 op=0x%02x", out[3]&0xff)
	}
	if out[5]&0xff != 0x26 {
		t.Fatalf("fill-array-data 应在 word 5，实际 op=0x%02x", out[5]&0xff)
	}
	if out[8]&0xff != 0x77 {
		t.Fatalf("invoke-static/range 应在 word 8，实际 op=0x%02x", out[8]&0xff)
	}
	if out[11]&0xff != 0x0c {
		t.Fatalf("move-result-object 应在 word 11，实际 op=0x%02x", out[11]&0xff)
	}
	// fresh：new-array 类型索引 @4、invoke 方法索引 @9
	if !fresh[4] || !fresh[9] {
		t.Fatalf("fresh 位置应为 {4,9}，实际 %v", fresh)
	}
	// fill-array-data 的落点必须是 payload 起点（基准为项内 5）
	rel := int32(uint32(out[6]) | uint32(out[7])<<16)
	payloadStart := 5 + int(rel)
	if payloadStart < 0 || payloadStart >= len(out) || out[payloadStart] != payloadFillArray {
		t.Fatalf("fill-array-data 未指向 payload（5+%d=%d）", rel, payloadStart)
	}
	if got := int(out[payloadStart+2]) | int(out[payloadStart+3])<<16; got != 40000 {
		t.Fatalf("payload size 应为 40000，实际 %d", got)
	}
	if _, err := ParseInsns(out); err != nil {
		t.Fatalf("替换结果不是合法指令流: %v", err)
	}
}

// findTermuxClassesDex 从 realworld/apps/termux.apk 读出 classes.dex。
func findTermuxClassesDex(t *testing.T) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "..", "realworld", "apps", "termux.apk")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("termux.apk 不存在（%s），跳过真实样本回归", path)
	}
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatalf("打开 termux.apk 失败: %v", err)
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.Name != "classes.dex" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("打开 classes.dex 失败: %v", err)
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("读取 classes.dex 失败: %v", err)
		}
		return b
	}
	t.Fatalf("termux.apk 内没有 classes.dex")
	return nil
}

// TestAuditA3RealTermuxLargeString 用 termux.apk 真实 classes.dex 里那条 57328 字节
// 的字符串跑一遍数组化，断言产出的长度常量非负且等于 57328、序列合法。
func TestAuditA3RealTermuxLargeString(t *testing.T) {
	data := findTermuxClassesDex(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析 termux classes.dex 失败: %v", err)
	}
	// 找到 57328 字节的字符串。
	var target uint32
	var bigStr string
	found := false
	for i := uint32(0); i < f.NString; i++ {
		s, err := f.String(i)
		if err != nil {
			continue
		}
		if len(s) == 57328 {
			target = i
			bigStr = s
			found = true
			break
		}
	}
	if !found {
		t.Skip("termux classes.dex 里未找到 57328 字节的字符串，跳过")
	}
	_ = target

	// 1) 真实字符串直接数组化（该串未必被指令引用，但数据来自真实 DEX）。
	l, err := ParseInsns([]uint16{0x001b, uint16(target & 0xffff), uint16(target >> 16), 0x000e})
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if !l.ReplaceWithArrayData(0, []byte(bigStr), 7, 9) {
		t.Fatal("57328 字节串应可数组化")
	}
	out, _, _ := l.Encode()
	op := byte(out[0] & 0xff)
	imm, ok := decodeConstSize(op, out)
	if !ok || imm != 57328 || op != 0x14 {
		t.Fatalf("termux 57328 串：前驱常量应为非负 57328 且用 const(0x14)，实际 imm=%d op=0x%02x", imm, op)
	}

	// 2) 整份真实 DEX 重建，扫描全部 A3 生成的超长序列。
	ca := &ConstantArray{Class: "Lapkguard/Arr;", MethodName: "b", MinLen: 32768, InjectClass: true}
	prod, st, err := RebuildWithStats(f, RebuildOptions{ConstantArray: ca})
	if err != nil {
		t.Fatalf("termux 全量重建失败: %v", err)
	}
	if err := Verify(prod); err != nil {
		t.Fatalf("termux 重建产物校验失败: %v", err)
	}
	if st.StringsArrayized == 0 {
		t.Fatal("termux 上 A3 未数组化任何超长串，样本无效")
	}
	g, err := Parse(prod)
	if err != nil {
		t.Fatalf("termux 重建产物无法解析: %v", err)
	}
	checked := 0
	err = g.walkAllCode(func(codeOff uint32) error {
		ci, err := g.ParseCodeItem(codeOff)
		if err != nil {
			return err
		}
		items, err := ParseInsns(ci.Insns)
		if err != nil {
			return err
		}
		for i := 1; i < items.ItemCount(); i++ {
			if !items.ItemIsInsn(i) || !items.ItemIsInsn(i-1) {
				continue
			}
			w := items.ItemWords(i)
			if byte(w[0]&0xff) != 0x23 { // new-array
				continue
			}
			pw := items.ItemWords(i - 1)
			size, ok := decodeConstSize(byte(pw[0]&0xff), pw)
			if !ok || size <= 0x7fff {
				continue
			}
			if size < 0 {
				return fmt.Errorf("code@%d 的 A3 序列长度常量为负 %d（真机 NegativeArraySizeException）", codeOff, size)
			}
			checked++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatalf("termux 重建产物中未找到超长 A3 序列（arrayized=%d）", st.StringsArrayized)
	}
	t.Logf("termux A3：数组化 %d 条，检查 %d 条超长序列的长度常量均非负", st.StringsArrayized, checked)
}

// ---- #3 A6 cffRegs 32x 漏报源寄存器 ----

// TestAuditCffRegs32x 直接钉住 32x（move/16 等）必须返回 word1 与 word2 两个寄存器。
func TestAuditCffRegs32x(t *testing.T) {
	// move/16 v7, v9：word0=0x0003（高位保留）、word1=7（目标）、word2=9（源）
	regs, ok := cffRegs(0x03, []uint16{0x0003, 7, 9})
	if !ok {
		t.Fatal("cffRegs(0x03) 应被覆盖")
	}
	got := map[int]bool{}
	for _, r := range regs {
		got[r] = true
	}
	if !got[7] || !got[9] {
		t.Fatalf("move/16 v7,v9 应返回 {7,9}，实际 %v", regs)
	}
	// 22x 复核：move/from16 v3, v20：word0=0x0302（AA=3, op=0x02）、word1=20
	regs, ok = cffRegs(0x02, []uint16{0x0302, 20})
	if !ok || len(regs) != 2 || regs[0] != 3 || regs[1] != 20 {
		t.Fatalf("move/from16 v3,v20 应返回 [3 20]，实际 %v ok=%v", regs, ok)
	}
	// 23x 复核：add-int v4, v5, v6：word0=0x0490（AA=4, op=0x90）、word1=0x0605
	regs, ok = cffRegs(0x90, []uint16{0x0490, 0x0605})
	if !ok || len(regs) != 3 || regs[0] != 4 || regs[1] != 5 || regs[2] != 6 {
		t.Fatalf("add-int v4,v5,v6 应返回 [4 5 6]，实际 %v", regs)
	}
}

// TestAuditA6PredicateAvoidsMove16Operands 端到端：构造含 move/16 的方法跑 A6，
// 断言谓词注入没有写进任何原指令的操作数寄存器（源与目标都算）。
func TestAuditA6PredicateAvoidsMove16Operands(t *testing.T) {
	// registers=14, ins=0 → 局部寄存器 v0..v13。
	// 只显式使用 v0/v2/v4（经 r+1 保守标记占用 v0..v5），
	// move/16 v9, v6 的**源** v6 是唯一引用它的指令——旧 cffRegs 漏报它，
	// 于是空闲集合里包含 v6，谓词被写进 v6。
	words := []uint16{
		0x13 | uint16(0)<<8, 1, // const/16 v0,#1
		0x13 | uint16(2)<<8, 1, // const/16 v2,#1
		0x13 | uint16(4)<<8, 1, // const/16 v4,#1
		0x0003, 9, 6, // move/16 v9, v6
		0x000e, // return-void
	}
	src := (&CodeItemFull{Registers: 14, Ins: 0, Insns: words}).Encode(nil)
	pl := &plan{controlFlow: &controlFlowPlan{spec: cffNormalize(ControlFlow{})}}
	var b builder
	nb, _, changed, err := b.controlFlowCodeItem(pl, "m", src)
	if err != nil {
		t.Fatalf("A6 改写失败: %v", err)
	}
	if !changed {
		t.Fatal("方法应被 A6 改写（含 move/16）")
	}
	ci, err := ParseCodeItemBytes(nb)
	if err != nil {
		t.Fatalf("解析 A6 产物失败: %v", err)
	}
	operands := map[int]bool{6: true, 9: true}
	sawPredicate := false
	for pos := 0; pos < len(ci.Insns); {
		w := ci.Insns
		op := byte(w[pos] & 0xff)
		width := int(insnWidths[op])
		if width <= 0 {
			t.Fatalf("word %d 处宽度非法 op=0x%02x", pos, op)
		}
		if op == 0x92 { // mul-int：谓词的标志性指令
			sawPredicate = true
			dst := int(w[pos] >> 8)
			b := int(w[pos+1] & 0xff)
			c := int(w[pos+1] >> 8)
			for _, r := range []int{dst, b, c} {
				if operands[r] {
					t.Fatalf("A6 谓词写进了原指令操作数寄存器 v%d（dst=%d b=%d c=%d）", r, dst, b, c)
				}
			}
		}
		pos += width
	}
	if !sawPredicate {
		t.Fatal("未找到谓词指令（mul-int），A6 未按预期注入")
	}
}

// ---- #4 重命名把成员 id 塌缩为同一条时的映射回填 ----

// TestAuditRenameDedupMemberMapping 钉住：Rename 让 m1/m2、f1/f2 塌缩为同一条时，
// 被去重丢弃的旧 id 必须映射到存活那条的新索引，而不是保留 Identity（越界）。
func TestAuditRenameDedupMemberMapping(t *testing.T) {
	code := &CodeBlob{Registers: 2, Ins: 1, Outs: 0, Insns: []uint16{0x000e}}
	a := NewAsm()
	if err := a.InvokeStatic(nil, MethodSpec{Class: "Lapp/Target;", Name: "m1", Proto: ProtoSpec{Ret: "V", Params: []string{"I"}}}); err != nil {
		t.Fatal(err)
	}
	if err := a.InvokeStatic(nil, MethodSpec{Class: "Lapp/Target;", Name: "m2", Proto: ProtoSpec{Ret: "V", Params: []string{"I"}}}); err != nil {
		t.Fatal(err)
	}
	a.ReturnVoid()
	callerInsns, callerPatches, err := a.Assemble()
	if err != nil {
		t.Fatal(err)
	}
	caller := &CodeBlob{Registers: 1, Ins: 0, Outs: 0, Insns: callerInsns, Patches: callerPatches}

	d, err := Build(Addition{Classes: []ClassSpec{{
		Name: "Lapp/Target;", Super: "Ljava/lang/Object;", Access: 0x0001,
		Fields: []ClassField{
			{Name: "f1", Type: "I", Access: 0x0002},
			{Name: "f2", Type: "I", Access: 0x0002},
		},
		Methods: []ClassMethod{
			{Name: "m1", Proto: ProtoSpec{Ret: "V", Params: []string{"I"}}, Access: 0x0002 | 0x0008, Code: code},
			{Name: "m2", Proto: ProtoSpec{Ret: "V", Params: []string{"I"}}, Access: 0x0002 | 0x0008, Code: code},
			{Name: "call", Proto: ProtoSpec{Ret: "V"}, Access: 0x0009, Code: caller},
		},
	}}})
	if err != nil {
		t.Fatalf("构造 DEX 失败: %v", err)
	}
	f, err := Parse(d)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	out, err := Rebuild(f, RebuildOptions{Rename: map[string]string{
		"m1": "z", "m2": "z", "f1": "w", "f2": "w",
	}})
	if err != nil {
		t.Fatalf("重命名塌缩后重建失败: %v", err)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("产物校验失败: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("产物无法解析: %v", err)
	}
	if g.NMethod != 2 {
		t.Fatalf("m1/m2 应塌缩为 1 条（加 call 共 2），实际 NMethod=%d", g.NMethod)
	}
	if g.NField != 1 {
		t.Fatalf("f1/f2 应塌缩为 1 条，实际 NField=%d", g.NField)
	}

	// 1) class_data 里引用的索引必须全部 < NMethod / NField。
	err = g.Classes(func(_ uint32, cd ClassDef, name string) error {
		if cd.ClassDataOff == 0 {
			return nil
		}
		parsed, err := g.ParseClassData(cd.ClassDataOff)
		if err != nil {
			return err
		}
		for _, lst := range [][]EncodedField{parsed.StaticFields, parsed.InstanceFields} {
			for _, fl := range lst {
				if fl.Idx >= g.NField {
					t.Fatalf("类 %s 的 class_data 字段索引越界 %d/%d", name, fl.Idx, g.NField)
				}
			}
		}
		for _, lst := range [][]EncodedMethod{parsed.DirectMethods, parsed.VirtualMethods} {
			for _, m := range lst {
				if m.Idx >= g.NMethod {
					t.Fatalf("类 %s 的 class_data 方法索引越界 %d/%d", name, m.Idx, g.NMethod)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("遍历类失败: %v", err)
	}

	// 2) 方法体里对 m1/m2 的引用必须都指向存活的那条（名字 z、原型 (I)V）。
	zIdx := methodIDIndex(t, g, "Lapp/Target;", "z", "(I)V")
	callIdx := methodIDIndex(t, g, "Lapp/Target;", "call", "()V")
	var callOff uint32
	err = g.AllMethods(func(_, _ string, m EncodedMethod) error {
		if m.Idx == callIdx {
			callOff = m.CodeOff
		}
		return nil
	})
	if err != nil {
		t.Fatalf("遍历方法失败: %v", err)
	}
	if callOff == 0 {
		t.Fatal("未找到 call 方法体")
	}
	cic, err := g.ParseCodeItem(callOff)
	if err != nil {
		t.Fatal(err)
	}
	l, err := ParseInsns(cic.Insns)
	if err != nil {
		t.Fatal(err)
	}
	nInvoke := 0
	for i := 0; i < l.ItemCount(); i++ {
		if !l.ItemIsInsn(i) {
			continue
		}
		w := l.ItemWords(i)
		if byte(w[0]&0xff) != 0x71 { // invoke-static
			continue
		}
		nInvoke++
		if int(w[1]) != int(zIdx) {
			t.Fatalf("call 中 invoke 方法索引应为存活的 %d，实际 %d（旧 id 未回填 → 指向错误方法）", zIdx, w[1])
		}
	}
	if nInvoke != 2 {
		t.Fatalf("call 应有 2 条 invoke，实际 %d", nInvoke)
	}
}

// ---- #2 测试见 constarr_test.go（TestRebuildConstantArrayComposesWithEncrypt） ----

// ---- #5 健壮性：畸形输入必须返回 error，而不是 panic / 静默清零 ----

// TestAuditMalformedHandlerOff 畸形 try_item.handler_off 必须在解析阶段报错。
func TestAuditMalformedHandlerOff(t *testing.T) {
	// 合法布局：handler 列表在列表内偏移 1 处；try 指向 1。
	build := func(handlerOff uint16) []byte {
		b := make([]byte, 16)
		binary.LittleEndian.PutUint16(b[0:], 1)  // registers
		binary.LittleEndian.PutUint16(b[6:], 1)  // tries_size
		binary.LittleEndian.PutUint32(b[12:], 2) // insns_size
		// insns：return-void, nop
		b = append(b, 0x0e, 0x00, 0x00, 0x00)
		// try_item：start=0 count=2 handler_off
		var tr [8]byte
		binary.LittleEndian.PutUint16(tr[4:], 2)
		binary.LittleEndian.PutUint16(tr[6:], handlerOff)
		b = append(b, tr[:]...)
		// encoded_catch_handler_list：size=1；handler：size=1 type=0 addr=0
		b = append(b, 0x01, 0x01, 0x00, 0x00)
		return b
	}
	if _, err := ParseCodeItemBytes(build(1)); err != nil {
		t.Fatalf("合法的 handler_off=1 不应报错: %v", err)
	}
	if _, err := ParseCodeItemBytes(build(7)); err == nil {
		t.Fatal("畸形的 handler_off=7 必须返回 error（旧实现会在 Encode 里 panic）")
	}
	// 手工构造不一致的 CodeItemFull，EncodeChecked 必须返回 error（不 panic）。
	ci := &CodeItemFull{
		Insns:       []uint16{0x000e},
		Tries:       []TryItem{{StartAddr: 0, InsnCount: 1, HandlerOff: 9}},
		Handlers:    []CatchHandler{{Types: []uint32{0}, Addrs: []uint32{0}}},
		HandlerOffs: []uint16{1},
	}
	if _, err := ci.EncodeChecked(nil); err == nil {
		t.Fatal("EncodeChecked 对不一致的 handler_off 必须返回 error")
	}
	// 历史签名 Encode 不得 panic（可退化）。
	_ = ci.Encode(nil)
}

// TestAuditMalformedDebugRefs 调试信息/注解中的越界索引必须返回 error。
func TestAuditMalformedDebugRefs(t *testing.T) {
	b := &builder{R: &Remap{String: []uint32{0}, Type: []uint32{0}, Field: []uint32{0}, Method: []uint32{0}, Proto: []uint32{0}}}
	// encoded_value: VALUE_STRING(0x17) 索引 5，越界。
	if _, _, err := b.remapEncodedValue(0, []byte{0x17, 0x05}); err == nil {
		t.Fatal("encoded_value 字符串索引越界必须返回 error")
	}
	// encoded_annotation: type_idx=5 越界。
	if _, _, err := b.remapEncodedAnnotation(0, []byte{0x05, 0x00}); err == nil {
		t.Fatal("encoded_annotation 类型索引越界必须返回 error")
	}
	// uleb128p1 越界。
	if _, err := b.remapP1(9, []uint32{0}); err == nil {
		t.Fatal("debug_info 的 uleb128p1 索引越界必须返回 error")
	}
}

// TestAuditMalformedDirMap class_def 的注解目录偏移缺键必须报错，不能静默清零。
func TestAuditMalformedDirMap(t *testing.T) {
	if v, err := resolveAnnoOff(map[uint32]uint32{}, 0); err != nil || v != 0 {
		t.Fatalf("annoOff=0（无注解）应返回 (0,nil)，实际 (%d,%v)", v, err)
	}
	if _, err := resolveAnnoOff(map[uint32]uint32{4: 8}, 123); err == nil {
		t.Fatal("annoOff 非 0 却缺映射必须返回 error（旧实现静默清掉注解目录）")
	}
	if v, err := resolveAnnoOff(map[uint32]uint32{4: 8}, 4); err != nil || v != 8 {
		t.Fatalf("有效映射应返回 (8,nil)，实际 (%d,%v)", v, err)
	}
}

// ---- #6 分支偏移静默截断 ----

// TestAuditBranchOverflow 20t/22t 相对偏移超出 int16 必须报错，而不是截断。
func TestAuditBranchOverflow(t *testing.T) {
	l := &InsnList{total: 40003}
	// item0：if-eqz v0（22t，2 字），new=0。
	l.items = append(l.items, &insnItem{words: []uint16{0x0038, 0}, kind: itemInsn, old: 0})
	// item1：40000 字的大块，new=2。
	l.items = append(l.items, &insnItem{words: make([]uint16, 40000), kind: itemInsn, old: 2})
	// item2：return-void，new=40002。
	l.items = append(l.items, &insnItem{words: []uint16{0x000e}, kind: itemInsn, old: 40002})
	// 分支目标为 item2 的旧偏移：相对偏移 40002 - 0 > 32767。
	l.AddBranch(0, 1, 0, 40002, form22t)

	if _, _, _, err := l.EncodeChecked(); err == nil {
		t.Fatal("超出 int16 的 22t 分支必须返回 error（不能静默截断跳错位置）")
	}
	// 历史 Encode 不得 panic，但会退化为截断（证明「静默截断」确实存在，
	// 也因此所有我方改写路径都必须走 EncodeChecked）。
	out, _, _ := l.Encode()
	if len(out) == 0 {
		t.Fatal("Encode 退化路径应仍返回指令流")
	}
	if got := int(int16(out[1])); got != 32767 {
		t.Fatalf("非严格 Encode 应把 40002 夹到 32767（证明会静默截断），实际 %d", got)
	}
}
