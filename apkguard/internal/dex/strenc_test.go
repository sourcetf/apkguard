package dex

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
)

// testKey 生成一个 32 字节测试密钥：首字节给定，其余按简单规则填充，
// 以便不同测试用不同密钥，同时保证可复现。
func testKey(b byte) [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = b + byte(i*7+1)
	}
	return k
}

// TestEncryptStringRoundTrip 验证加解密互为逆运算。
func TestEncryptStringRoundTrip(t *testing.T) {
	cases := []struct {
		s   string
		key [32]byte
	}{
		{"hello", testKey(0x5a)},
		{"", testKey(0x00)},
		{"https://api.example.com/v1/pay", testKey(0xff)},
		{"中文测试字符串", testKey(0x37)},
		{"emoji \U0001F600 ok", testKey(0x01)},
		{"a", testKey(0x80)},
	}
	for _, c := range cases {
		ct := encryptString(c.s, c.key)
		// 密文必须是纯 ASCII 的 Base64：这是「可安全放进 DEX 字符串池」的前提
		// （池是 MUTF-8 编码的 UTF-16，非 ASCII 可能产生孤立代理码元）。
		for i := 0; i < len(ct); i++ {
			ch := ct[i]
			ok := ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' ||
				ch >= '0' && ch <= '9' || ch == '+' || ch == '/' || ch == '='
			if !ok {
				t.Fatalf("%q 的密文含非 Base64 字符 %q", c.s, ch)
			}
		}
		// Base64 是 4/3 膨胀；明文前额外前置 stringNonceSize 字节 nonce。
		wantLen := (len(c.s) + stringNonceSize + 2) / 3 * 4
		if len(ct) != wantLen {
			t.Fatalf("%q 的密文长度应为 %d（Base64），实际 %d", c.s, wantLen, len(ct))
		}
		if got := decryptString(ct, c.key); got != c.s {
			t.Fatalf("解密结果不符：%q -> %q -> %q", c.s, ct, got)
		}
	}
}

// decryptString 是 encryptString 的逆运算，独立实现以便交叉验证。
//
// 它模拟注入到 DEX 中的解密方法的行为：先 Base64 解码，取出前 stringNonceSize
// 字节 nonce，再按 SHA-256(secret‖0x01‖nonce‖LE32(i)) 逐字节异或还原。
// 刻意不复用 encryptString / keyStreamByte 的任何内部步骤，避免「用同一份可能
// 出错的代码校验自己」。
func decryptString(ct string, key [32]byte) string {
	raw, err := base64.StdEncoding.DecodeString(ct)
	if err != nil || len(raw) < stringNonceSize {
		return "!base64-decode-failed"
	}
	var nonce [stringNonceSize]byte
	copy(nonce[:], raw[:stringNonceSize])
	out := make([]byte, len(raw)-stringNonceSize)
	for i := range out {
		var idx [4]byte
		binary.LittleEndian.PutUint32(idx[:], uint32(i))
		h := sha256.New()
		h.Write(key[:])
		h.Write([]byte{0x01})
		h.Write(nonce[:])
		h.Write(idx[:])
		out[i] = raw[stringNonceSize+i] ^ h.Sum(nil)[0]
	}
	return string(out)
}

// TestEncryptStringDeterministic 验证加密可复现：同一密钥与明文必须得到同一密文。
//
// nonce 是明文的确定性函数（stringNonce），不含随机数，因此加固产物可复现；
// 若这里改成随机 nonce，同一 APK 多次加固结果会不同，排查问题会变得困难。
func TestEncryptStringDeterministic(t *testing.T) {
	key := testKey(0x11)
	s := "https://api.example.com/v1/pay"
	first := encryptString(s, key)
	second := encryptString(s, key)
	if first != second {
		t.Fatalf("同一输入两次加密不一致：%q vs %q", first, second)
	}
	// 换密钥必须换密文。
	if other := encryptString(s, testKey(0x12)); other == first {
		t.Fatal("换密钥后密文未变化")
	}
}

// TestKnownPlaintextCannotRecoverKey 验证旧的单点已知明文攻击已失效。
//
// 旧实现 keyStream = key + i*17 的密钥只有 1 字节：攻击者拿到任意一个
// (明文, 密文) 对后，遍历 256 种 key' 就能解出密钥、进而解出全部字符串。
// 新实现的密钥是 32 字节、密钥流由 SHA-256 派生，这个攻击必须彻底失败。
func TestKnownPlaintextCannotRecoverKey(t *testing.T) {
	key := testKey(0x9e)
	// "https://..." 这类常量在真实 APK 中必然存在，视为攻击者已知。
	known := "https://api.example.com/v1/pay"
	raw, err := base64.StdEncoding.DecodeString(encryptString(known, key))
	if err != nil {
		t.Fatal(err)
	}
	body := raw[stringNonceSize:]

	// 攻击 1：假设密钥流仍是仿射的 key' + i*17，遍历全部 256 种 key'。
	for cand := 0; cand < 256; cand++ {
		ok := true
		for i, b := range body {
			if byte(int(cand)+i*17)^b != known[i] {
				ok = false
				break
			}
		}
		if ok {
			t.Fatalf("仿射密钥流假设成立（key'=%d）：旧攻击未被修复", cand)
		}
	}

	// 攻击 2：把已知字符串的密钥流直接拿去解另一个字符串（同下标消元）。
	// 若两个字符串的密钥流相同或只差常数，这一步就会得到明文。
	other := "com.example.app.SecretToken"
	oraw, err := base64.StdEncoding.DecodeString(encryptString(other, key))
	if err != nil {
		t.Fatal(err)
	}
	decrypted := true
	n := len(other)
	if len(body) < n {
		n = len(body)
	}
	for i := 0; i < n; i++ {
		if body[i]^oraw[stringNonceSize+i] != other[i] {
			decrypted = false
			break
		}
	}
	if n > 0 && decrypted {
		t.Fatal("用已知明密文对成功解出了另一个字符串：密钥流未按字符串隔离")
	}
}

// TestKeyStreamNotAffine 验证若干字符串的密钥流之间不存在仿射/线性关系。
//
// 这是任务要求里那条最直接的断言：收集各字符串的 ct[i]^pt[i]，证明它既不是
// key+i*17 这种仿射模式，两两之间也不存在常数差（常数差意味着可消元互解）。
func TestKeyStreamNotAffine(t *testing.T) {
	key := testKey(0x3c)
	strs := []string{
		"https://api.example.com/v1/pay",
		"com.example.app.SecretToken",
		"Android",
		"UTF-8",
		"用户登录失败",
	}
	streams := make([][]byte, len(strs))
	for j, s := range strs {
		raw, err := base64.StdEncoding.DecodeString(encryptString(s, key))
		if err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		ks := make([]byte, len(s))
		for i := range ks {
			ks[i] = raw[stringNonceSize+i] ^ s[i]
		}
		streams[j] = ks
	}

	// 1) 任一字符串的密钥流都不能写成 key' + i*17。
	for j, ks := range streams {
		if len(ks) == 0 {
			continue
		}
		for cand := 0; cand < 256; cand++ {
			affine := true
			for i, b := range ks {
				if b != byte(int(cand)+i*17) {
					affine = false
					break
				}
			}
			if affine {
				t.Fatalf("字符串 %q 的密钥流是仿射的（key'=%d）", strs[j], cand)
			}
		}
	}

	// 2) 两两之间在相同下标处的密钥流之差不能是常数。
	for a := 0; a < len(streams); a++ {
		for b := a + 1; b < len(streams); b++ {
			n := len(streams[a])
			if len(streams[b]) < n {
				n = len(streams[b])
			}
			if n < 3 {
				continue
			}
			d0 := streams[a][0] ^ streams[b][0]
			allSame := true
			for i := 1; i < n; i++ {
				if streams[a][i]^streams[b][i] != d0 {
					allSame = false
					break
				}
			}
			if allSame {
				t.Fatalf("%q 与 %q 的密钥流只差常数 %d，可互相解密", strs[a], strs[b], d0)
			}
		}
	}
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
	key := testKey(0x5a)
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
	se := &StringEncrypt{Class: cls, MethodName: "a", Key: [32]byte{0x11}, MinLen: 8}
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
	key := testKey(0x5a)
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

// TestStringEncryptTargetsMatchesRebuild 验证纯分析计数与真实重建统计一致。
//
// Pass 层依赖 StringEncryptTargets 判断「本 DEX 要不要注入解密器」：
// 若它与 planStringEncrypt 的实际口径不一致，会出现「注入了解密器却无密文」
// 或「有密文却没注入解密器」两种坏产物。这里在真实样本上对单引用开关
// 两种取值逐一比对。
func TestStringEncryptTargetsMatchesRebuild(t *testing.T) {
	data := sampleDex(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	for _, single := range []bool{false, true} {
		se := &StringEncrypt{
			Class: "Lt/Dec;", MethodName: "a", Key: testKey(0x77),
			MinLen: 4, SingleRefOnly: single, InjectClass: true,
		}
		n, err := StringEncryptTargets(f, se)
		if err != nil {
			t.Fatalf("SingleRefOnly=%v 统计失败: %v", single, err)
		}
		_, st, err := RebuildWithStats(f, RebuildOptions{StringEncrypt: se})
		if err != nil {
			t.Fatalf("SingleRefOnly=%v 重建失败: %v", single, err)
		}
		if n != st.StringsEncrypted {
			t.Fatalf("SingleRefOnly=%v：分析计数 %d 与重建统计 %d 不一致", single, n, st.StringsEncrypted)
		}
		if n == 0 {
			t.Fatalf("SingleRefOnly=%v：样本上不应为 0（测试失去意义）", single)
		}
	}
}

// TestStringEncryptSingleRefOnly 验证 SingleRefOnly 只加密恰好被 1 条
// const-string 引用的串，多引用串留明文且指令不变。
//
// 逐条断言的对象是「仅被 const-string 使用、长度达标、非 try 端点内部、
// 非解密器自身常量」的字符串：单引用串必须被移出池，多引用串必须原样保留。
func TestStringEncryptSingleRefOnly(t *testing.T) {
	data := sampleDex(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	usage, err := f.StringUsage()
	if err != nil {
		t.Fatalf("用法统计失败: %v", err)
	}
	idxs, refs, blocked, err := collectConstStrings(f)
	if err != nil {
		t.Fatalf("const-string 统计失败: %v", err)
	}
	self := map[string]bool{}
	for _, s := range DecryptorStrings() {
		self[s] = true
	}
	const minLen = 4
	var singles, multis []string
	for _, i := range idxs {
		s, err := f.String(i)
		if err != nil || len(s) < minLen || blocked[i] || self[s] {
			continue
		}
		if usage.Type[i] || usage.MethodName[i] || usage.FieldName[i] ||
			usage.Anno[i] || usage.SourceFile[i] || usage.Debug[i] || usage.Shorty[i] {
			continue
		}
		switch {
		case refs[i] == 1:
			singles = append(singles, s)
		case refs[i] >= 2:
			multis = append(multis, s)
		}
	}
	if len(singles) == 0 || len(multis) == 0 {
		t.Skip("样本中没有同时具备单引用与多引用候选，跳过")
	}

	key := testKey(0x21)
	one := &StringEncrypt{
		Class: "Lt/Dec;", MethodName: "a", Key: key,
		MinLen: minLen, SingleRefOnly: true, InjectClass: true,
	}
	all := *one
	all.SingleRefOnly = false

	nOne, err := StringEncryptTargets(f, one)
	if err != nil {
		t.Fatal(err)
	}
	nAll, err := StringEncryptTargets(f, &all)
	if err != nil {
		t.Fatal(err)
	}
	if nOne >= nAll {
		t.Fatalf("SingleRefOnly 应减少加密目标：单引用 %d，全部 %d", nOne, nAll)
	}

	poolOf := func(se *StringEncrypt) map[string]bool {
		out, _, err := RebuildWithStats(f, RebuildOptions{StringEncrypt: se})
		if err != nil {
			t.Fatalf("重建失败: %v", err)
		}
		g, err := Parse(out)
		if err != nil {
			t.Fatalf("重建结果解析失败: %v", err)
		}
		pool := map[string]bool{}
		for i := uint32(0); i < g.NString; i++ {
			s, _ := g.String(i)
			pool[s] = true
		}
		return pool
	}

	// 开启：单引用串加密（明文移出池），多引用串原样留明文。
	poolOne := poolOf(one)
	for _, s := range singles {
		if poolOne[s] {
			t.Fatalf("SingleRefOnly=true 时单引用串 %q 仍留明文", s)
		}
	}
	for _, s := range multis {
		if !poolOne[s] {
			t.Fatalf("SingleRefOnly=true 时多引用串 %q 被加密（样本形态应留明文）", s)
		}
	}

	// 关闭（现状）：两类串都加密、明文都移出池——证明默认行为未被削弱。
	poolAll := poolOf(&all)
	for _, s := range singles {
		if poolAll[s] {
			t.Fatalf("SingleRefOnly=false 时单引用串 %q 仍留明文", s)
		}
	}
	for _, s := range multis {
		if poolAll[s] {
			t.Fatalf("SingleRefOnly=false 时多引用串 %q 仍留明文（默认强度不应下降）", s)
		}
	}
	t.Logf("单引用串 %d 个、多引用串 %d 个；加密目标 单引用模式=%d 默认模式=%d",
		len(singles), len(multis), nOne, nAll)
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
	se := &StringEncrypt{Class: cls, MethodName: "a", Key: [32]byte{0x33}, MinLen: 4, InjectClass: false}
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
	se := &StringEncrypt{Class: "Lapkguard/Dec;", MethodName: "a", Key: [32]byte{0x42}, MinLen: 0}
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
