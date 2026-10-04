package dex

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// ---- B5 函数抽取：dex 层纯函数守卫 ----

// extractTestSafe 是测试用的「安全方法」判据（与 passes 层的策略同构的最小版）。
func extractTestSafe(info ExtractInfo) bool {
	if info.Name == "<init>" || info.Name == "<clinit>" ||
		info.Access&(extractAccConstructor|extractAccNative|extractAccAbstract) != 0 {
		return false
	}
	if info.Access&(extractAccSynchronized|extractAccDeclSync) != 0 || info.Shared {
		return false
	}
	return info.TriesSize == 0 && info.InsnsWords >= 8
}

// codeItemBytes 读取一个方法的完整 code_item 字节。
func codeItemBytes(t *testing.T, f *File, codeOff uint32) []byte {
	t.Helper()
	n, err := codeItemByteLen(f, codeOff)
	if err != nil {
		t.Fatalf("计算 code_item 长度失败 @%d: %v", codeOff, err)
	}
	out := make([]byte, n)
	copy(out, f.data[codeOff:codeOff+uint32(n)])
	return out
}

// TestExtractStubWordsTable 验证各返回类型的 stub 编码与非法返回值报错。
func TestExtractStubWordsTable(t *testing.T) {
	cases := []struct {
		ret  string
		want []uint16
	}{
		{"V", []uint16{0x000e}},
		{"Z", []uint16{0x0012, 0x000f}},
		{"I", []uint16{0x0012, 0x000f}},
		{"F", []uint16{0x0012, 0x000f}},
		{"J", []uint16{0x0014, 0x0010}},
		{"D", []uint16{0x0014, 0x0010}},
		{"Ljava/lang/String;", []uint16{0x0012, 0x0011}},
		{"[B", []uint16{0x0012, 0x0011}},
	}
	for _, c := range cases {
		got, err := ExtractStubWords(c.ret)
		if err != nil {
			t.Fatalf("返回类型 %q 生成 stub 失败: %v", c.ret, err)
		}
		if len(got) != len(c.want) {
			t.Fatalf("返回类型 %q 的 stub 长度不符: got %v want %v", c.ret, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("返回类型 %q 的 stub[%d] 不符: got 0x%04x want 0x%04x", c.ret, i, got[i], c.want[i])
			}
		}
	}
	if _, err := ExtractStubWords("X"); err == nil {
		t.Fatal("非法返回类型应报错，而不是产出一个 ART 会拒收的 stub")
	}
}

// TestExtractCodeNoSelectionIsNoop 验证没有任何命中时字节不变。
func TestExtractCodeNoSelectionIsNoop(t *testing.T) {
	data := sampleDex(t)
	out, plan, err := ExtractCode(data, func(ExtractInfo) bool { return false })
	if err != nil {
		t.Fatalf("抽取失败: %v", err)
	}
	if plan != nil {
		t.Fatal("无命中时不应产生计划")
	}
	if !bytes.Equal(out, data) {
		t.Fatal("无命中时 DEX 字节被改动")
	}
}

// TestExtractCodeRoundTripOnRealDex 是 B5 的核心守卫（判据 1/2/3/5/8/9）：
//
//  1. 选中方法的 code_item 变成等长 stub（registers/ins/outs/tries/debug 不变）；
//  2. code_off 非 0 且指向合法 code_item；
//  3. stub DEX（前 file_size 字节）中不再出现被抽方法的原始指令字节；
//  4. 未选中方法逐字节不变，索引表计数不变；
//  5. ApplyExtractPlan 回填后与抽取前逐字节一致（含头部 checksum/SHA-1）；
//  6. 同输入两次抽取逐字节一致（确定性）。
func TestExtractCodeRoundTripOnRealDex(t *testing.T) {
	data := sampleDex(t)
	orig, err := Parse(data)
	if err != nil {
		t.Fatalf("解析样本失败: %v", err)
	}
	infos, err := ScanExtractCandidates(data)
	if err != nil {
		t.Fatalf("扫描候选失败: %v", err)
	}
	sel := map[uint32]bool{}
	for _, info := range infos {
		if extractTestSafe(info) && len(sel) < 32 {
			sel[info.CodeOff] = true
		}
	}
	if len(sel) == 0 {
		t.Skip("样本中没有满足测试判据的方法")
	}

	out, plan, err := ExtractCode(data, func(info ExtractInfo) bool { return sel[info.CodeOff] })
	if err != nil {
		t.Fatalf("抽取失败: %v", err)
	}
	if plan == nil || len(plan.Entries) == 0 {
		t.Fatal("有命中却没有计划")
	}
	fs := binary.LittleEndian.Uint32(out[32:])
	if int(fs) != len(data) {
		t.Fatalf("stub DEX 的 file_size 应等于原 DEX 长度（等长 stub），got %d want %d", fs, len(data))
	}
	f, err := Parse(out)
	if err != nil {
		t.Fatalf("stub DEX 无法解析: %v", err)
	}
	if err := Verify(out[:fs]); err != nil {
		t.Fatalf("stub DEX（前 file_size 字节）校验失败: %v", err)
	}
	if err := ValidateDescriptors(out); err != nil {
		t.Fatalf("stub DEX 类型描述符校验失败: %v", err)
	}
	// 索引表计数不变：抽取不增删任何索引。
	if f.NString != orig.NString || f.NType != orig.NType || f.NProto != orig.NProto ||
		f.NField != orig.NField || f.NMethod != orig.NMethod || f.NClass != orig.NClass {
		t.Fatalf("索引表计数被改动: got(str=%d type=%d proto=%d field=%d method=%d class=%d) "+
			"want(str=%d type=%d proto=%d field=%d method=%d class=%d)",
			f.NString, f.NType, f.NProto, f.NField, f.NMethod, f.NClass,
			orig.NString, orig.NType, orig.NProto, orig.NField, orig.NMethod, orig.NClass)
	}

	// 逐方法断言：选中的 stub 化且等长；未选中的逐字节不变。
	checked, untouched := 0, 0
	for _, info := range infos {
		gotCI, err := f.ParseCodeItem(info.CodeOff)
		if err != nil {
			t.Fatalf("%s 的 code_item 解析失败: %v", info.Name, err)
		}
		origCI, err := orig.ParseCodeItem(info.CodeOff)
		if err != nil {
			t.Fatalf("%s 的原 code_item 解析失败: %v", info.Name, err)
		}
		origRaw := codeItemBytes(t, orig, info.CodeOff)
		gotRaw := codeItemBytes(t, f, info.CodeOff)
		if sel[info.CodeOff] && extractTestSafe(info) {
			stub, err := ExtractStubWords(info.Ret)
			if err != nil {
				t.Fatalf("生成 %s 的 stub 失败: %v", info.Name, err)
			}
			if len(gotCI.Insns) != len(origCI.Insns) {
				t.Fatalf("%s 抽取后 insns_size 变了: %d -> %d", info.Name, len(origCI.Insns), len(gotCI.Insns))
			}
			for i := range stub {
				if gotCI.Insns[i] != stub[i] {
					t.Fatalf("%s 的 stub 第 %d 字不符: got 0x%04x want 0x%04x", info.Name, i, gotCI.Insns[i], stub[i])
				}
			}
			for i := len(stub); i < len(gotCI.Insns); i++ {
				if gotCI.Insns[i] != 0x0000 {
					t.Fatalf("%s 的 stub 补位应为 nop(0)，第 %d 字是 0x%04x", info.Name, i, gotCI.Insns[i])
				}
			}
			if gotCI.Registers != origCI.Registers || gotCI.Ins != origCI.Ins ||
				gotCI.Outs != origCI.Outs || gotCI.DebugInfoOff != origCI.DebugInfoOff ||
				len(gotCI.Tries) != len(origCI.Tries) {
				t.Fatalf("%s 的 code_item 头部/异常表被改动", info.Name)
			}
			if bytes.Equal(gotRaw, origRaw) {
				t.Fatalf("%s 被选中却没有任何改写", info.Name)
			}
			checked++
		} else {
			if !bytes.Equal(gotRaw, origRaw) {
				t.Fatalf("%s 未被选中却被改动", info.Name)
			}
			untouched++
		}
	}
	if checked != len(plan.Entries) {
		t.Fatalf("校验的抽取方法与计划条目数不符: %d vs %d", checked, len(plan.Entries))
	}
	if untouched == 0 {
		t.Fatal("样本里应有大量未被抽取的方法")
	}

	// plan 与实际中的元数据一致
	for _, ent := range plan.Entries {
		if ent.CodeOff == 0 || ent.ByteLen < 16 || len(ent.Data) != ent.ByteLen {
			t.Fatalf("计划条目非法: %+v", ent.Info)
		}
	}
	// 判据 3：stub DEX 本体内不得残留被抽方法的原始指令字节。
	for _, ent := range plan.Entries {
		origInsns := ent.Data[16 : 16+2*ent.Info.InsnsWords]
		if bytes.Contains(out[:fs], origInsns) {
			t.Fatalf("%s 的原始指令字节仍存在于 stub DEX 中", ent.Info.Name)
		}
	}

	// 判据 2 & 5：回填后与抽取前逐字节一致。
	restored, n, err := ApplyExtractPlan(out)
	if err != nil {
		t.Fatalf("回填失败: %v", err)
	}
	if n != len(plan.Entries) {
		t.Fatalf("回填条数不符: got %d want %d", n, len(plan.Entries))
	}
	if !bytes.Equal(restored, data) {
		t.Fatalf("回填后与原 DEX 不一致（%d vs %d 字节）", len(restored), len(data))
	}
	// 回填结果必须重新通过结构校验，且索引计数与原始一致——这是 ART 在
	// DexClassLoader 打开载荷时会做的同一组检查。
	if err := Verify(restored); err != nil {
		t.Fatalf("回填后的 DEX 校验失败（ART 会拒绝加载）: %v", err)
	}
	if err := ValidateDescriptors(restored); err != nil {
		t.Fatalf("回填后的 DEX 描述符校验失败: %v", err)
	}
	rf, err := Parse(restored)
	if err != nil {
		t.Fatalf("回填后的 DEX 无法解析: %v", err)
	}
	if rf.NString != orig.NString || rf.NType != orig.NType || rf.NProto != orig.NProto ||
		rf.NField != orig.NField || rf.NMethod != orig.NMethod || rf.NClass != orig.NClass {
		t.Fatalf("回填后索引表计数与原始不一致: got(str=%d type=%d proto=%d field=%d method=%d class=%d) "+
			"want(str=%d type=%d proto=%d field=%d method=%d class=%d)",
			rf.NString, rf.NType, rf.NProto, rf.NField, rf.NMethod, rf.NClass,
			orig.NString, orig.NType, orig.NProto, orig.NField, orig.NMethod, orig.NClass)
	}

	// 判据 9：确定性。
	out2, plan2, err := ExtractCode(data, func(info ExtractInfo) bool { return sel[info.CodeOff] })
	if err != nil {
		t.Fatalf("第二次抽取失败: %v", err)
	}
	if !bytes.Equal(out, out2) {
		t.Fatal("同输入两次抽取的字节不一致")
	}
	if len(plan2.Entries) != len(plan.Entries) {
		t.Fatal("同输入两次抽取的条目数不一致")
	}
	t.Logf("样本 %d 方法中抽取 %d 个，stub DEX %d 字节 + trailer %d 字节",
		len(infos), len(plan.Entries), len(data), len(out)-len(data))
}

// TestApplyExtractPlanWithoutTrailer 验证普通 DEX（无 trailer）回填为空操作。
func TestApplyExtractPlanWithoutTrailer(t *testing.T) {
	data := Empty()
	out, n, err := ApplyExtractPlan(data)
	if err != nil {
		t.Fatalf("回填失败: %v", err)
	}
	if n != 0 {
		t.Fatalf("无 trailer 时应回填 0 条，实际 %d", n)
	}
	if !bytes.Equal(out, data) {
		t.Fatal("无 trailer 时 DEX 字节被改动")
	}
}

// TestApplyExtractPlanRejectsCorruption 验证损坏的 trailer 被显式拒绝，
// 而不是回填到错误地址（那会让 ART 执行到垃圾指令）。
func TestApplyExtractPlanRejectsCorruption(t *testing.T) {
	data := sampleDex(t)
	infos, err := ScanExtractCandidates(data)
	if err != nil {
		t.Fatalf("扫描失败: %v", err)
	}
	sel := map[uint32]bool{}
	for _, info := range infos {
		if extractTestSafe(info) && len(sel) < 4 {
			sel[info.CodeOff] = true
		}
	}
	if len(sel) == 0 {
		t.Skip("样本中没有满足判据的方法")
	}
	out, plan, err := ExtractCode(data, func(info ExtractInfo) bool { return sel[info.CodeOff] })
	if err != nil || plan == nil {
		t.Fatalf("抽取失败: %v", err)
	}
	fs := int(binary.LittleEndian.Uint32(out[32:]))

	// 篡改 count：越界条目表必须报错。
	bad := append([]byte(nil), out...)
	binary.LittleEndian.PutUint32(bad[fs+4:], 0x7ffffff0)
	if _, _, err := ApplyExtractPlan(bad); err == nil {
		t.Fatal("条目表越界时应报错")
	}
	// 篡改第一条的 len：越界写必须报错。
	bad2 := append([]byte(nil), out...)
	binary.LittleEndian.PutUint32(bad2[fs+extractPlanEntriesOff+4:], 0x7ffffff0)
	if _, _, err := ApplyExtractPlan(bad2); err == nil {
		t.Fatal("条目越界时应报错")
	}
	// 魔数被改：视为「非 B5 载荷」，原样返回（不作为错误，否则普通载荷无法加载）。
	bad3 := append([]byte(nil), out...)
	binary.LittleEndian.PutUint32(bad3[fs:], 0xdeadbeef)
	got, n, err := ApplyExtractPlan(bad3)
	if err != nil || n != 0 {
		t.Fatalf("魔数不符时应静默跳过（普通载荷路径），got n=%d err=%v", n, err)
	}
	if !bytes.Equal(got, bad3) {
		t.Fatal("魔数不符时不应改动字节")
	}
}

// TestExtractSemanticEquivalence 用解释器对拍「原始 vs 回填后」的方法语义。
//
// 构造一个静态方法 add(II)I（若干 nop 填充使方法体达到可抽取长度），抽取后
// 分别在原 DEX 与回填后的 DEX 上执行，结果必须相同——证明回填恢复的是原
// 指令流本身，而不是「恰好能过结构校验」。
func TestExtractSemanticEquivalence(t *testing.T) {
	const cls = "Lx/Calc;"
	addM := MethodSpec{Class: cls, Name: "add", Proto: ProtoSpec{Ret: "I", Params: []string{"I", "I"}}}
	a := NewAsm()
	for i := 0; i < 6; i++ {
		a.emit(0x0000) // nop 填充
	}
	// registers=4、ins=2 → 入参在 v2/v3，局部用 v0。
	a.AddInt(0, 2, 3)
	a.Return(0)
	insns, patches, err := a.Assemble()
	if err != nil {
		t.Fatalf("汇编失败: %v", err)
	}
	add := Addition{
		Types:   []string{cls, "Ljava/lang/Object;"},
		Protos:  []ProtoSpec{addM.Proto},
		Methods: []MethodSpec{addM},
		Classes: []ClassSpec{{
			Name: cls, Super: "Ljava/lang/Object;", Access: accPublic,
			Methods: []ClassMethod{{
				Name: "add", Proto: addM.Proto, Access: accPublic | accStatic,
				Code: &CodeBlob{Registers: 4, Ins: 2, Insns: insns, Patches: patches},
			}},
		}},
	}
	data, err := Build(add)
	if err != nil {
		t.Fatalf("构造 DEX 失败: %v", err)
	}
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	idx, off := findMethod(t, f, cls, "->add(II)I")

	got, err := runPadMethod(f, idx, off, int32(7), int32(5))
	if err != nil {
		t.Fatalf("原 DEX 执行 add 失败: %v", err)
	}
	if got != int32(12) {
		t.Fatalf("原 DEX 的 add(7,5) 应为 12，实际 %v", got)
	}

	out, plan, err := ExtractCode(data, func(info ExtractInfo) bool { return info.CodeOff == off })
	if err != nil || plan == nil || len(plan.Entries) != 1 {
		t.Fatalf("抽取失败: %v（plan=%v）", err, plan)
	}
	restored, n, err := ApplyExtractPlan(out)
	if err != nil || n != 1 {
		t.Fatalf("回填失败: %v n=%d", err, n)
	}
	if !bytes.Equal(restored, data) {
		t.Fatal("回填结果与原 DEX 不一致")
	}
	rf, err := Parse(restored)
	if err != nil {
		t.Fatalf("解析回填结果失败: %v", err)
	}
	_, roff := findMethod(t, rf, cls, "->add(II)I")
	got2, err := runPadMethod(rf, idx, roff, int32(7), int32(5))
	if err != nil {
		t.Fatalf("回填后执行 add 失败: %v", err)
	}
	if got2 != int32(12) {
		t.Fatalf("回填后的 add(7,5) 应为 12，实际 %v——说明回填没有恢复原指令流", got2)
	}
}

// TestLoaderReadU32Helper 单测 Loader 的 q()：小端 u32 读取必须与 Go 侧一致。
func TestLoaderReadU32Helper(t *testing.T) {
	ls := &LoaderSpec{
		Class:   "Lcom/apkguard/shell/Loader;",
		Key:     testPackKey,
		TempDir: "ag",
		Items:   []LoaderItem{{Asset: "assets/p.bin", DexName: "d0.dex", Size: 16}},
	}
	add, err := LoaderAddition(ls)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	out, err := Build(add)
	if err != nil {
		t.Fatalf("Build 失败: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	idx, off := findMethod(t, g, ls.Class, "->q([BI)I")
	buf := &fakeBytes{b: []byte{0x41, 0x47, 0x58, 0x31, 0xff, 0x00, 0x80, 0x7f}}
	cases := []struct {
		at   int32
		want int32
	}{
		{0, int32(ExtractPlanMagic)},
		{4, int32(0x7f8000ff)},
	}
	for _, c := range cases {
		got, err := runPadMethod(g, idx, off, buf, c.at)
		if err != nil {
			t.Fatalf("q(%d) 执行失败: %v", c.at, err)
		}
		if got != c.want {
			t.Fatalf("q(%d) = %v，期望 %v", c.at, got, c.want)
		}
	}
}

// TestLoaderApplyExtractHelper 单测 Loader 的 p()：直接对带 trailer 的
// stub DEX 调用，必须返回 file_size 且原地恢复原 DEX 本体。
func TestLoaderApplyExtractHelper(t *testing.T) {
	data := sampleDex(t)
	infos, err := ScanExtractCandidates(data)
	if err != nil {
		t.Fatalf("扫描失败: %v", err)
	}
	sel := map[uint32]bool{}
	for _, info := range infos {
		if extractTestSafe(info) && len(sel) < 4 {
			sel[info.CodeOff] = true
		}
	}
	if len(sel) == 0 {
		t.Skip("样本中没有满足判据的方法")
	}
	stubDex, plan, err := ExtractCode(data, func(info ExtractInfo) bool { return sel[info.CodeOff] })
	if err != nil || plan == nil {
		t.Fatalf("抽取失败: %v", err)
	}
	ls := &LoaderSpec{
		Class:   "Lcom/apkguard/shell/Loader;",
		Key:     testPackKey,
		TempDir: "ag",
		Items:   []LoaderItem{{Asset: "assets/p.bin", DexName: "d0.dex", Size: 16}},
	}
	add, err := LoaderAddition(ls)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	out, err := Build(add)
	if err != nil {
		t.Fatalf("Build 失败: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	restore := installLoaderMocks(&loaderEnv{assets: map[string][]byte{}, fs: map[string][]byte{}})
	defer restore()
	fakeCode = map[string]uint32{}
	defer func() { fakeCode = map[string]uint32{} }()
	registerFakeCode(t, g, ls.Class)
	idx, off := findMethod(t, g, ls.Class, "->p([B)I")
	buf := &fakeBytes{b: stubDex}
	got, err := runPadMethod(g, idx, off, buf)
	if err != nil {
		t.Fatalf("p() 执行失败: %v", err)
	}
	if got != int32(len(data)) {
		t.Fatalf("p() 应返回 %d（file_size），实际 %v", len(data), got)
	}
	if !bytes.Equal(buf.b[:len(data)], data) {
		t.Fatal("p() 回填后的字节与本 DEX 不一致")
	}
}

// TestLoaderRefillsExtractPlanViaInterpreter 是本项目回填链路的端到端守卫：
// 把带抽取计划的 DEX 加密成载荷，让编译器生成的 Loader.a 在模拟环境里
// 完整走一遍「解密 → 回填 → 截断落盘」，断言落盘文件与原 DEX 逐字节一致。
//
// 这是「ART 看到的就是原始 DEX」的最直接证据：stub 只在内存中的解密缓冲区
// 里短暂存在，任何一步偏移/长度/头部修复算错都会在这里暴露。
func TestLoaderRefillsExtractPlanViaInterpreter(t *testing.T) {
	data := sampleDex(t)
	infos, err := ScanExtractCandidates(data)
	if err != nil {
		t.Fatalf("扫描失败: %v", err)
	}
	sel := map[uint32]bool{}
	for _, info := range infos {
		if extractTestSafe(info) && len(sel) < 16 {
			sel[info.CodeOff] = true
		}
	}
	if len(sel) == 0 {
		t.Skip("样本中没有满足判据的方法")
	}
	stubDex, plan, err := ExtractCode(data, func(info ExtractInfo) bool { return sel[info.CodeOff] })
	if err != nil || plan == nil {
		t.Fatalf("抽取失败: %v", err)
	}

	key := testPackKey
	blob := mustEncrypt(t, stubDex, key, testPackIV)
	ls := &LoaderSpec{
		Class:   "Lcom/apkguard/shell/Loader;",
		Key:     key,
		TempDir: "ag",
		Items:   []LoaderItem{{Asset: "assets/pay_ab12.bin", DexName: "d0.dex", Size: len(blob)}},
	}
	add, err := LoaderAddition(ls)
	if err != nil {
		t.Fatalf("构造 Loader 失败: %v", err)
	}
	out, err := Build(add)
	if err != nil {
		t.Fatalf("Build 失败: %v", err)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("Loader DEX 校验失败: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("解析 Loader DEX 失败: %v", err)
	}

	env := &loaderEnv{assets: map[string][]byte{"pay_ab12.bin": blob}, fs: map[string][]byte{}}
	restore := installLoaderMocks(env)
	defer restore()
	// t() 用 FileOutputStream.write([BII) 只写 DEX 本体；标准 mock 只实现了
	// write([B)，这里补上。
	fakeCalls["Ljava/io/FileOutputStream;->write([BII)V"] =
		func(in *interp, regs []int) (int32, any, error) {
			o, ok := in.objs[regs[0]].(*fakeObj)
			if !ok {
				return 0, nil, errf("write([BII) 的接收者不是 FileOutputStream")
			}
			b, ok := in.objs[regs[1]].(*fakeBytes)
			if !ok {
				return 0, nil, errf("write([BII) 的实参不是 byte[]")
			}
			off := int(in.regs[regs[2]])
			n := int(in.regs[regs[3]])
			if off < 0 || n < 0 || off+n > len(b.b) {
				return 0, nil, errf("write([BII) 区间非法 off=%d n=%d len=%d", off, n, len(b.b))
			}
			p, _ := o.aux.(string)
			env.fs[p] = append([]byte(nil), b.b[off:off+n]...)
			return 0, nil, nil
		}
	fakeCode = map[string]uint32{}
	defer func() { fakeCode = map[string]uint32{} }()
	registerFakeCode(t, g, ls.Class)
	installActivityThreadMock()
	defer clearActivityThreadMock()
	idx, off := findMethod(t, g, ls.Class, "->"+LoaderEntry+"(")
	if _, err := runPadMethod(g, idx, off, &fakeObj{desc: descContext}); err != nil {
		t.Fatalf("Loader.a 执行失败: %v", err)
	}

	got, ok := env.fs["/data/user/0/app/ag/d0.dex"]
	if !ok {
		t.Fatalf("DEX 未落盘，已有文件: %v", keysOfBytes(env.fs))
	}
	if len(got) != len(data) {
		t.Fatalf("落盘长度应为抽取前 DEX 的长度（trailer 必须被截掉）：got %d want %d", len(got), len(data))
	}
	if !bytes.Equal(got, data) {
		t.Fatal("落盘 DEX 与抽取前不一致：回填/截断/头部修复链路有错（ART 会看到 stub 而不是原始方法体）")
	}
	if env.exited {
		t.Fatal("合法计划不应触发 System.exit")
	}
	t.Logf("Loader 端到端回填：%d 条计划，落盘 %d 字节与原 DEX 逐字节一致", len(plan.Entries), len(got))
}

// TestLoaderSkipsPatchWithoutTrailerViaInterpreter 验证普通载荷（无 trailer）
// 仍走原 write 路径：落盘内容 = 解密明文，字节不变（B5 关闭时零回归）。
func TestLoaderSkipsPatchWithoutTrailerViaInterpreter(t *testing.T) {
	plain := Empty()
	key := testPackKey
	blob := mustEncrypt(t, plain, key, testPackIV)
	ls := &LoaderSpec{
		Class:   "Lcom/apkguard/shell/Loader;",
		Key:     key,
		TempDir: "ag",
		Items:   []LoaderItem{{Asset: "assets/pay_ab12.bin", DexName: "d0.dex", Size: len(blob)}},
	}
	env := &loaderEnv{assets: map[string][]byte{"pay_ab12.bin": blob}, fs: map[string][]byte{}}
	runLoaderEntry(t, ls, env)
	got, ok := env.fs["/data/user/0/app/ag/d0.dex"]
	if !ok {
		t.Fatalf("DEX 未落盘，已有文件: %v", keysOfBytes(env.fs))
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("无 trailer 载荷的落盘内容被改动")
	}
	if env.exited {
		t.Fatal("无 trailer 时不应触发 System.exit")
	}
}
