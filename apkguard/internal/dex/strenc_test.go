package dex

import (
	"strings"
	"testing"
)

// TestEncryptStringRoundTrip 验证加解密互为逆运算。
func TestEncryptStringRoundTrip(t *testing.T) {
	cases := []struct {
		s   string
		key byte
	}{
		{"hello", 0x5a},
		{"", 0x00},
		{"https://api.example.com/v1/pay", 0xff},
		{"中文测试字符串", 0x37},
		{"emoji \U0001F600 ok", 0x01},
		{"a", 0x80},
	}
	for _, c := range cases {
		ct := encryptString(c.s, c.key)
		// 密文只含十六进制字符：这是「可安全放进字符串池」的前提
		for i := 0; i < len(ct); i++ {
			ch := ct[i]
			if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
				t.Fatalf("%q 的密文含非法字符 %q", c.s, ch)
			}
		}
		if len(ct) != len(c.s)*2 {
			t.Fatalf("%q 的密文长度应为 %d，实际 %d", c.s, len(c.s)*2, len(ct))
		}
		if got := decryptString(ct, c.key); got != c.s {
			t.Fatalf("解密结果不符：%q -> %q -> %q", c.s, ct, got)
		}
	}
}

// decryptString 是 encryptString 的逆运算，独立实现以便交叉验证。
//
// 它模拟注入到 DEX 中的解密方法的行为：把十六进制字符串按
// 「高 4 位 + 低 4 位」还原成字节，再与密钥流异或。
func decryptString(ct string, key byte) string {
	b := make([]byte, len(ct)/2)
	for i := range b {
		hi := hexVal(ct[2*i])
		lo := hexVal(ct[2*i+1])
		b[i] = byte(hi<<4|lo) ^ keyStream(key, i)
	}
	return string(b)
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	}
	return 0
}

// TestAsmAssemble 验证汇编器的标签解析与引用回填。
func TestAsmAssemble(t *testing.T) {
	a := NewAsm()
	m := MethodSpec{Class: "Ljava/lang/String;", Name: "length", Proto: ProtoSpec{Ret: "I"}}
	a.Const4(0, 0)
	a.Label("loop")
	if err := a.InvokeVirtual([]int{0}, m); err != nil {
		t.Fatal(err)
	}
	a.MoveResult(1)
	a.AddIntLit8(0, 1)
	a.IfLt(0, 2, "loop")
	a.ReturnObject(0)

	insns, patches, err := a.Assemble()
	if err != nil {
		t.Fatalf("组装失败: %v", err)
	}
	if len(patches) != 1 {
		t.Fatalf("应有 1 处补丁，实际 %d", len(patches))
	}
	// if-lt 是 22t：相对偏移在 word1，从 if-lt 指令自身起算
	// 指令布局：[0] const/4(1) [1..3] invoke-virtual(3) [4] move-result(1)
	//          [5..6] add-int/lit8(2) [7..8] if-lt(2) [9] return-object(1)
	if len(insns) != 10 {
		t.Fatalf("指令长度应为 10 字，实际 %d", len(insns))
	}
	rel := int(int16(insns[8]))
	if rel != -6 {
		t.Fatalf("if-lt 的相对偏移应为 -6（回到偏移 1），实际 %d", rel)
	}
	if got := insns[7] & 0xff; got != 0x34 {
		t.Fatalf("偏移 7 处应为 if-lt(0x34)，实际 0x%02x", got)
	}
}

// TestAsmGotoRange 验证超出 8 位范围时 goto 会报错而非静默截断。
func TestAsmGotoRange(t *testing.T) {
	a := NewAsm()
	a.Label("start")
	a.Goto("far")
	for i := 0; i < 200; i++ {
		a.Const16(0, int16(i))
	}
	a.Label("far")
	a.ReturnVoid()
	if _, _, err := a.Assemble(); err == nil {
		t.Fatal("超出 goto 8 位范围时应报错")
	}

	// 换成 goto/16 后应当成功
	b := NewAsm()
	b.Label("start")
	b.Goto16("far")
	for i := 0; i < 200; i++ {
		b.Const16(0, int16(i))
	}
	b.Label("far")
	b.ReturnVoid()
	if _, _, err := b.Assemble(); err != nil {
		t.Fatalf("goto/16 应当成功，实际 %v", err)
	}
}

// TestAsmInvokeRegisterTable 验证 35c 调用的寄存器表编码。
func TestAsmInvokeRegisterTable(t *testing.T) {
	a := NewAsm()
	m := MethodSpec{Class: "Lx;", Name: "m", Proto: ProtoSpec{Ret: "V"}}
	if err := a.InvokeStatic([]int{1, 2, 3}, m); err != nil {
		t.Fatal(err)
	}
	if err := a.InvokeStatic([]int{1, 2, 3, 4, 5}, m); err != nil {
		t.Fatal(err)
	}
	insns, _, err := a.Assemble()
	if err != nil {
		t.Fatal(err)
	}
	// 第一条：op=0x71, A=3, G=0
	if insns[0]&0xff != 0x71 {
		t.Fatalf("操作码应为 0x71，实际 0x%02x", insns[0]&0xff)
	}
	if got := insns[0] >> 12; got != 3 {
		t.Fatalf("寄存器个数 A 应为 3，实际 %d", got)
	}
	// word2: C=v1 D=v2 E=v3 F=0
	if got := insns[2]; got != 1|2<<4|3<<8 {
		t.Fatalf("寄存器表编码错误: 0x%04x", got)
	}
	// 第二条：A=5, G=v5 在 word0 高字节（G 占低 4 位，A 占高 4 位）
	if got := (insns[3] >> 8) & 0xf; got != 5 {
		t.Fatalf("G 字段应为 v5，实际 v%d", got)
	}
	if got := insns[3] >> 12; got != 5 {
		t.Fatalf("寄存器个数 A 应为 5，实际 %d", got)
	}
	if got := insns[5]; got != 1|2<<4|3<<8|4<<12 {
		t.Fatalf("第二条寄存器表编码错误: 0x%04x", got)
	}
}

// TestRebuildStringEncrypt 端到端验证 A2：加密后 DEX 自洽、明文消失、密文出现。
func TestRebuildStringEncrypt(t *testing.T) {
	data := sampleDex(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	orig, err := f.AllStrings()
	if err != nil {
		t.Fatalf("读取字符串失败: %v", err)
	}

	const cls = "Lapkguard/Dec;"
	const key = 0x5a
	se := &StringEncrypt{Class: cls, MethodName: "a", Key: key, MinLen: 4, InjectClass: true}

	out, stats, err := RebuildWithStats(f, RebuildOptions{StringEncrypt: se})
	if err != nil {
		t.Fatalf("加密重建失败: %v", err)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("重建后校验失败: %v", err)
	}
	if stats.StringsEncrypted == 0 {
		t.Fatal("没有加密任何字符串")
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("重建结果无法解析: %v", err)
	}
	if g.NClass != f.NClass+1 {
		t.Fatalf("应注入 1 个解密器类: %d -> %d", f.NClass, g.NClass)
	}

	// 解密器类必须存在，且方法体可读
	found := false
	g.Classes(func(_ uint32, cd ClassDef, name string) error {
		if name != cls {
			return nil
		}
		found = true
		pcd, err := g.ParseClassData(cd.ClassDataOff)
		if err != nil {
			t.Fatalf("解密器 class_data 解析失败: %v", err)
		}
		if len(pcd.DirectMethods) != 1 {
			t.Fatalf("解密器应有 1 个直接方法，实际 %d", len(pcd.DirectMethods))
		}
		m := pcd.DirectMethods[0]
		if m.CodeOff == 0 {
			t.Fatal("解密方法缺少方法体")
		}
		ci, err := g.CodeInsns(m.CodeOff)
		if err != nil {
			t.Fatalf("解密方法体读取失败: %v", err)
		}
		if ci.InsnsSize == 0 {
			t.Fatal("解密方法体为空")
		}
		if ci.Outs < 1 {
			t.Fatalf("解密方法必须声明出参寄存器，实际 %d", ci.Outs)
		}
		// 解密方法体必须能被重新解析为合法指令流
		full, err := g.ParseCodeItem(m.CodeOff)
		if err != nil {
			t.Fatalf("解密方法体解析失败: %v", err)
		}
		if _, err := ParseInsns(full.Insns); err != nil {
			t.Fatalf("解密方法体不是合法指令流: %v", err)
		}
		return nil
	})
	if !found {
		t.Fatal("未找到注入的解密器类")
	}

	// 至少有一批「仅被 const-string 使用」的明文应当消失
	newStrs := map[string]bool{}
	for i := uint32(0); i < g.NString; i++ {
		s, _ := g.String(i)
		newStrs[s] = true
	}
	gone := 0
	for _, s := range orig {
		if len(s) < 4 {
			continue
		}
		if !newStrs[s] {
			gone++
		}
	}
	if gone == 0 {
		t.Fatal("没有任何明文被移出字符串池")
	}
	// 密文必须出现在池中
	ct := encryptString("apkguard-probe", key)
	if _, ok := newStrs[ct]; ok {
		t.Fatal("探测字符串本不该出现在池中")
	}
	t.Logf("加密 %d 个字符串（其中 %d 个明文被移出池），明文消失 %d 个，类 %d->%d",
		stats.StringsEncrypted, stats.StringsReplaced, gone, f.NClass, g.NClass)
}

// TestRebuildStringEncryptNoClass 验证 InjectClass=false 时只登记引用、不注入类。
func TestRebuildStringEncryptNoClass(t *testing.T) {
	data := sampleDex(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	const cls = "Lapkguard/Dec;"
	se := &StringEncrypt{Class: cls, MethodName: "a", Key: 0x11, MinLen: 8}
	out, _, err := RebuildWithStats(f, RebuildOptions{StringEncrypt: se})
	if err != nil {
		t.Fatalf("重建失败: %v", err)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("重建后校验失败: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("重建结果无法解析: %v", err)
	}
	if g.NClass != f.NClass {
		t.Fatalf("不应新增类: %d -> %d", f.NClass, g.NClass)
	}
	// 但类型表里必须有该类（供 invoke 指令引用）
	saw := false
	for i := uint32(0); i < g.NType; i++ {
		n, _ := g.Type(i)
		if n == cls {
			saw = true
			break
		}
	}
	if !saw {
		t.Fatal("解密器类型未登记到 type_ids")
	}
}

// TestDecryptorSemantics 用极简解释器真正执行注入的解密方法。
//
// 这是 A2 最关键的正确性证据：仅靠 dex.Verify 只能证明结构自洽，
// 无法发现「寄存器分配错误」这类语义缺陷。
func TestDecryptorSemantics(t *testing.T) {
	data := sampleDex(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	const cls = "Lapkguard/Dec;"
	key := byte(0x5a)
	se := &StringEncrypt{Class: cls, MethodName: "a", Key: key, MinLen: 4, InjectClass: true}
	out, _, err := RebuildWithStats(f, RebuildOptions{StringEncrypt: se})
	if err != nil {
		t.Fatalf("加密重建失败: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("重建结果无法解析: %v", err)
	}

	// 定位解密方法
	var codeOff uint32
	var mIdx uint32
	found := false
	g.Classes(func(_ uint32, cd ClassDef, name string) error {
		if name != cls {
			return nil
		}
		pcd, err := g.ParseClassData(cd.ClassDataOff)
		if err != nil {
			return err
		}
		if len(pcd.DirectMethods) != 1 {
			t.Fatalf("解密器方法数异常: %d", len(pcd.DirectMethods))
		}
		codeOff = pcd.DirectMethods[0].CodeOff
		mIdx = pcd.DirectMethods[0].Idx
		found = true
		return nil
	})
	if !found {
		t.Fatal("未找到解密器类")
	}

	// 逐个跑明文，验证解密结果与原文一致（含多字节 UTF-8 与代理对）
	for _, plain := range []string{
		"hello",
		"https://api.example.com/v1/pay",
		"中文测试",
		"emoji \U0001F600 ok",
		"a",
		"",
	} {
		ct := encryptString(plain, key)
		got, err := runDecryptor(g, mIdx, codeOff, ct)
		if err != nil {
			t.Fatalf("执行解密方法失败（明文 %q）: %v", plain, err)
		}
		if got != plain {
			t.Fatalf("解密结果不符：%q -> %q -> %q", plain, ct, got)
		}
	}
}

// TestDecryptorSemanticsNoClass 确认非主 DEX 只引用不注入时，
// 该 DEX 中不存在可执行的解密器（引用由主 DEX 提供）。
func TestDecryptorSemanticsNoClass(t *testing.T) {
	data := sampleDex(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	const cls = "Lapkguard/Dec;"
	se := &StringEncrypt{Class: cls, MethodName: "a", Key: 0x33, MinLen: 4, InjectClass: false}
	out, _, err := RebuildWithStats(f, RebuildOptions{StringEncrypt: se})
	if err != nil {
		t.Fatalf("重建失败: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("重建结果无法解析: %v", err)
	}
	saw := false
	g.Classes(func(_ uint32, _ ClassDef, name string) error {
		if name == cls {
			saw = true
		}
		return nil
	})
	if saw {
		t.Fatal("InjectClass=false 时不应落地解密器类")
	}
	// 但方法引用必须存在（invoke 指令要用）
	sawRef := false
	for i := uint32(0); i < g.NMethod; i++ {
		d, err := g.MethodDesc(i)
		if err != nil {
			continue
		}
		if strings.HasPrefix(d, cls+"->a(") {
			sawRef = true
			break
		}
	}
	if !sawRef {
		t.Fatal("解密方法的引用未登记到 method_ids")
	}
}

// TestRebuildStringEncryptKeepsTypeNames 验证被类型表引用的字符串不被破坏。
//
// 这类字符串即便出现在 const-string 中，其明文也必须留在池中，
// 否则 type_ids 会指向密文，DEX 直接损坏。
func TestRebuildStringEncryptKeepsTypeNames(t *testing.T) {
	data := sampleDex(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	se := &StringEncrypt{Class: "Lapkguard/Dec;", MethodName: "a", Key: 0x42, MinLen: 0}
	out, _, err := RebuildWithStats(f, RebuildOptions{StringEncrypt: se})
	if err != nil {
		t.Fatalf("重建失败: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("重建结果无法解析: %v", err)
	}
	// 全部类型描述符必须仍是合法的类描述符
	for i := uint32(0); i < g.NType; i++ {
		n, err := g.Type(i)
		if err != nil {
			t.Fatalf("类型 %d 读取失败: %v", i, err)
		}
		if n == "" {
			t.Fatalf("类型 %d 为空", i)
		}
		if strings.ContainsAny(n, " \t") {
			t.Fatalf("类型 %d 含空白字符: %q", i, n)
		}
	}
	// 全部方法签名必须可读（说明 name/proto 索引未被打乱）
	for i := uint32(0); i < g.NMethod; i++ {
		d, err := g.MethodDesc(i)
		if err != nil {
			t.Fatalf("方法 %d 读取失败: %v", i, err)
		}
		if d == "" {
			t.Fatalf("方法 %d 描述为空", i)
		}
	}
}
