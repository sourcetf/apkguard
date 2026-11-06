package dex

import (
	"encoding/base64"
	"strings"
	"testing"

	"apkguard/internal/pack"
)

// 本文件是 A2 从自造 SHA-256 keystream 换成 AES-256-SIV 后的专项测试：
//   - DEX 级：注入的解密方法只做「Base64 → Native.sivDecrypt → new String」，
//     不再出现 MessageDigest/digest/异或循环；
//   - 解释器级：用 internal/pack 真实现做桩跑生成的字节码，覆盖中文/emoji/空串，
//     并断言「桩返回 null 时解密器抛异常/不返回原文」；
//   - 形态对比：新版解密方法比旧版短多少条指令。

// installStrencSIVStub 注册解释器用的 Native.sivDecrypt 桩（真 SIV 解密）。
//
// 返回恢复函数。与 loader_test.go 的 installLoaderMocks 里的同名桩行为一致：
// 解密失败返回 null（与真 native 一致）。
func installStrencSIVStub() func() {
	desc := NativeBridgeClass + "->sivDecrypt([B[B[B)[B"
	prev, had := fakeCalls[desc]
	fakeCalls[desc] = func(in *interp, regs []int) (int32, any, error) {
		keyB, ok := in.objs[regs[0]].(*fakeBytes)
		if !ok {
			return 0, nil, errf("sivDecrypt 的密钥不是 byte[]")
		}
		adB, ok := in.objs[regs[1]].(*fakeBytes)
		if !ok {
			return 0, nil, errf("sivDecrypt 的 ad 不是 byte[]")
		}
		blob, ok := in.objs[regs[2]].(*fakeBytes)
		if !ok {
			return 0, nil, errf("sivDecrypt 的密文不是 byte[]")
		}
		if len(keyB.b) != 32 {
			return 0, nil, errf("sivDecrypt 的密钥长度应为 32，实际 %d", len(keyB.b))
		}
		var k [32]byte
		copy(k[:], keyB.b)
		plain, err := pack.DecryptNamed(blob.b, k, string(adB.b))
		if err != nil {
			return 0, nil, nil // 与真 native 一致：SIV 校验失败返回 null
		}
		return 0, &fakeBytes{b: plain}, nil
	}
	return func() {
		if had {
			fakeCalls[desc] = prev
		} else {
			delete(fakeCalls, desc)
		}
	}
}

// buildSIVDecryptor 在 sampleDex 上做一次 A2（SIV 路径）重建，返回结果与解密器
// 方法定位信息。
func buildSIVDecryptor(t *testing.T, key [32]byte) (f *File, codeOff, mIdx uint32) {
	t.Helper()
	data := sampleDex(t)
	src, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	const cls = "Lapkguard/Dec;"
	se := &StringEncrypt{Class: cls, MethodName: "a", Key: key, MinLen: 4, InjectClass: true}
	out, _, err := RebuildWithStats(src, RebuildOptions{StringEncrypt: se})
	if err != nil {
		t.Fatalf("SIV 重建失败: %v", err)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("SIV 重建后校验失败: %v", err)
	}
	f, err = Parse(out)
	if err != nil {
		t.Fatalf("重建结果无法解析: %v", err)
	}
	found := false
	f.Classes(func(_ uint32, cd ClassDef, name string) error {
		if name != cls {
			return nil
		}
		pcd, err := f.ParseClassData(cd.ClassDataOff)
		if err != nil {
			return err
		}
		for _, m := range pcd.DirectMethods {
			d, err := f.MethodDesc(m.Idx)
			if err != nil {
				continue
			}
			if strings.HasSuffix(d, "->a(Ljava/lang/String;)Ljava/lang/String;") {
				codeOff, mIdx = m.CodeOff, m.Idx
				found = true
			}
		}
		return nil
	})
	if !found {
		t.Fatal("未找到 SIV 解密器方法")
	}
	return f, codeOff, mIdx
}

// TestDecryptorSIVInterpreter 是解释器级证据：Go 侧加密 → 跑生成的解密方法 →
// 得到原文，覆盖中文/emoji/空串/长度 1。
func TestDecryptorSIVInterpreter(t *testing.T) {
	key := testKey(0x5a)
	g, codeOff, mIdx := buildSIVDecryptor(t, key)
	defer installStrencSIVStub()()

	for _, plain := range []string{
		"hello",
		"中文测试字符串",
		"emoji \U0001F600 ok",
		"",
		"a",
		"https://api.example.com/v1/pay",
	} {
		ct, err := encryptString(plain, key, false)
		if err != nil {
			t.Fatalf("加密 %q 失败: %v", plain, err)
		}
		got, err := runDecryptor(g, mIdx, codeOff, ct)
		if err != nil {
			t.Fatalf("解释器执行解密失败（明文 %q）: %v", plain, err)
		}
		if got != plain {
			t.Fatalf("解密结果不符：%q -> %q", plain, got)
		}
	}
}

// TestDecryptorSIVRejectsNull 验证 SIV 校验失败时（桩返回 null）解密器抛异常、
// 绝不返回原文。解释器未实现 throw，因此表现为执行报错——关键是**没有**返回
// 任何字符串结果。
func TestDecryptorSIVRejectsNull(t *testing.T) {
	key := testKey(0x5a)
	g, codeOff, mIdx := buildSIVDecryptor(t, key)
	defer installStrencSIVStub()()

	ct, err := encryptString("中文测试", key, false)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(ct)
	if err != nil {
		t.Fatal(err)
	}
	// 篡改 SIV 标签：真 native 会返回 null。
	raw[0] ^= 0x01
	bad := base64.StdEncoding.EncodeToString(raw)

	got, err := runDecryptor(g, mIdx, codeOff, bad)
	if err == nil {
		t.Fatalf("桩返回 null 时解密器未抛异常，反而返回 %q（必须失败可见）", got)
	}
	if got == "中文测试" {
		t.Fatal("解密器在失败时返回了原文")
	}
	t.Logf("篡改密文后解密器按预期报错: %v", err)
}

// collectMethodAndStringRefs 收集一段方法体里调用的方法描述符与引用的字符串。
func collectMethodAndStringRefs(t *testing.T, f *File, insns []uint16) (methods, strings_ []string) {
	t.Helper()
	err := walkInsns(insns, func(op byte, pos int, w []uint16) error {
		switch {
		case op >= 0x6e && op <= 0x72, op >= 0x74 && op <= 0x78: // 35c / 3rc invoke
			if d, err := f.MethodDesc(uint32(w[pos+1])); err == nil {
				methods = append(methods, d)
			}
		case op == 0x1a:
			if s, err := f.String(uint32(w[pos+1])); err == nil {
				strings_ = append(strings_, s)
			}
		case op == 0x1b:
			idx := uint32(w[pos+1]) | uint32(w[pos+2])<<16
			if s, err := f.String(idx); err == nil {
				strings_ = append(strings_, s)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("遍历指令失败: %v", err)
	}
	return methods, strings_
}

// TestDecryptorCodeSIVShape 是 DEX 级证据：解密方法只做「Base64 解码 →
// Native.sivDecrypt → new String」，不含 MessageDigest/Digest/异或循环；
// 且类 <clinit> 里有 System.loadLibrary。
func TestDecryptorCodeSIVShape(t *testing.T) {
	key := testKey(0x33)
	g, codeOff, _ := buildSIVDecryptor(t, key)

	ci, err := g.ParseCodeItem(codeOff)
	if err != nil {
		t.Fatalf("读取解密方法体失败: %v", err)
	}
	methods, strs := collectMethodAndStringRefs(t, g, ci.Insns)

	has := func(list []string, want string) bool {
		for _, s := range list {
			if s == want {
				return true
			}
		}
		return false
	}
	// 必须出现：Base64 解码、Native.sivDecrypt、String.<init>(byte[],String)。
	if !has(methods, "Landroid/util/Base64;->decode(Ljava/lang/String;I)[B") {
		t.Fatalf("解密方法未调用 Base64.decode，实际调用 %v", methods)
	}
	if !has(methods, NativeBridgeClass+"->sivDecrypt([B[B[B)[B") {
		t.Fatalf("解密方法未调用 Native.sivDecrypt，实际调用 %v", methods)
	}
	if !has(methods, "Ljava/lang/String;-><init>([BLjava/lang/String;)V") {
		t.Fatalf("解密方法未用 new String(byte[], String)，实际调用 %v", methods)
	}
	if !has(strs, "UTF-8") {
		t.Fatalf("解密方法未引用 UTF-8，实际字符串 %v", strs)
	}
	// 不得出现任何 MessageDigest/digest 相关引用与 SHA-256 常量。
	for _, m := range methods {
		if strings.Contains(m, "MessageDigest") || strings.Contains(m, "->digest(") ||
			strings.Contains(m, "getInstance") {
			t.Fatalf("解密方法仍引用旧摘要链路: %s", m)
		}
	}
	for _, s := range strs {
		if s == "SHA-256" {
			t.Fatal("解密方法仍引用 SHA-256 常量（旧 keystream）")
		}
	}
	// 不得有 xor-int（异或循环的痕迹）。
	if err := walkInsns(ci.Insns, func(op byte, _ int, _ []uint16) error {
		if op == 0x97 {
			t.Fatal("解密方法体仍出现 xor-int（旧异或密钥流残留）")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// 类 <clinit> 必须调用 System.loadLibrary，且字符串池含 loadLibrary/sivDecrypt。
	clinitFound := false
	g.Classes(func(_ uint32, cd ClassDef, name string) error {
		if name != "Lapkguard/Dec;" {
			return nil
		}
		pcd, err := g.ParseClassData(cd.ClassDataOff)
		if err != nil {
			return err
		}
		for _, m := range pcd.DirectMethods {
			d, err := g.MethodDesc(m.Idx)
			if err != nil {
				continue
			}
			if !strings.HasSuffix(d, "-><clinit>()V") || m.CodeOff == 0 {
				continue
			}
			cc, err := g.ParseCodeItem(m.CodeOff)
			if err != nil {
				return err
			}
			cms, css := collectMethodAndStringRefs(t, g, cc.Insns)
			if !has(cms, "Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V") {
				t.Fatalf("解密器 <clinit> 未调用 System.loadLibrary，实际 %v", cms)
			}
			if !has(css, NativeLibName) {
				t.Fatalf("解密器 <clinit> 未引用库名 %q，实际 %v", NativeLibName, css)
			}
			clinitFound = true
		}
		return nil
	})
	if !clinitFound {
		t.Fatal("解密器类没有 <clinit>（守卫库不会被加载）")
	}

	// 全局字符串池/类型池必须含 sivDecrypt、loadLibrary 与桥接类。
	pool := map[string]bool{}
	for i := uint32(0); i < g.NString; i++ {
		s, _ := g.String(i)
		pool[s] = true
	}
	for _, want := range []string{NativeDecrypt, "loadLibrary"} {
		if !pool[want] {
			t.Fatalf("DEX 字符串池缺少 %q（NATIVE 链路不完整）", want)
		}
	}
	typeFound := false
	for i := uint32(0); i < g.NType; i++ {
		n, _ := g.Type(i)
		if n == NativeBridgeClass {
			typeFound = true
		}
	}
	if !typeFound {
		t.Fatalf("DEX 类型池缺少桥接类 %s", NativeBridgeClass)
	}
}

// decryptorInsnLen 返回注入解密器类里解密方法的指令字数。
func decryptorInsnLen(t *testing.T, add Addition, methodName string) int {
	t.Helper()
	for _, c := range add.Classes {
		for _, m := range c.Methods {
			if m.Name == methodName && m.Code != nil {
				return len(m.Code.Insns)
			}
		}
	}
	t.Fatalf("未找到方法 %s 的代码", methodName)
	return 0
}

// TestDecryptorSIVShorterThanLegacy 量化新版解密器比旧版短多少条指令。
func TestDecryptorSIVShorterThanLegacy(t *testing.T) {
	key := testKey(0x5a)
	legacy, err := stringDecryptorAddition(&StringEncrypt{
		Class: "Lx/Dec;", MethodName: "a", Key: key, InjectClass: true, LegacyKeystream: true,
	})
	if err != nil {
		t.Fatalf("构造旧解密器失败: %v", err)
	}
	siv, err := stringDecryptorAddition(&StringEncrypt{
		Class: "Lx/Dec;", MethodName: "a", Key: key, InjectClass: true,
	})
	if err != nil {
		t.Fatalf("构造新解密器失败: %v", err)
	}
	oldLen := decryptorInsnLen(t, legacy, "a")
	newLen := decryptorInsnLen(t, siv, "a")
	if newLen >= oldLen {
		t.Fatalf("新版解密器应更短：旧 %d 字，新 %d 字", oldLen, newLen)
	}
	t.Logf("解密方法指令长度：旧 %d 字 → 新 %d 字（减少 %d，约 %.0f%%）",
		oldLen, newLen, oldLen-newLen, 100*float64(oldLen-newLen)/float64(oldLen))
}

// TestLegacyDecryptorShape 断言逃生开关路径仍是旧形态：有 MessageDigest、
// 没有 <clinit>/loadLibrary。这保证旧路径确实「不嵌守卫库」。
func TestLegacyDecryptorShape(t *testing.T) {
	legacy, err := stringDecryptorAddition(&StringEncrypt{
		Class: "Lx/Dec;", MethodName: "a", Key: testKey(0x11), InjectClass: true, LegacyKeystream: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(legacy.Classes) != 1 {
		t.Fatalf("旧解密器应注入 1 个类，实际 %d", len(legacy.Classes))
	}
	cls := legacy.Classes[0]
	if len(cls.Methods) != 1 || cls.Methods[0].Name != "a" {
		t.Fatalf("旧解密器不应有 <clinit>，实际方法 %+v", cls.Methods)
	}
	// 直接检查代码补丁：必须引用 MessageDigest。
	hasMD := false
	for _, p := range cls.Methods[0].Code.Patches {
		if p.Ref.Kind == RefMethod && strings.Contains(p.Ref.Method.Class, "MessageDigest") {
			hasMD = true
		}
		if p.Ref.Kind == RefString && p.Ref.String == "SHA-256" {
			hasMD = true
		}
	}
	if !hasMD {
		t.Fatal("旧解密器路径未引用 MessageDigest/SHA-256")
	}
	// 不得出现桥接类。
	for _, mt := range legacy.Methods {
		if mt.Class == NativeBridgeClass {
			t.Fatal("旧解密器路径不应引用 native 桥接类")
		}
	}
	if len(legacy.Classes[0].Super) == 0 {
		t.Fatal("旧解密器类缺少父类")
	}
}

// TestDecryptorStringsIncludesBridge 断言 DecryptorStrings 同时覆盖解密器与
// 桥接类的常量（否则 A3 会把桥接类的 "SHA-256" 数组化，破坏 A2→A3 不变量）。
func TestDecryptorStringsIncludesBridge(t *testing.T) {
	got := map[string]bool{}
	for _, s := range DecryptorStrings() {
		got[s] = true
	}
	for _, want := range []string{"UTF-8", NativeLibName, "SHA-256"} {
		if !got[want] {
			t.Fatalf("DecryptorStrings 缺少 %q，实际 %v", want, got)
		}
	}
}

// TestSivWrapperAdditionShape 断言 Siv 包装类的形态：
//   - 只有一个 public static d([B[B[B)[B 方法，**没有** <clinit>；
//   - 方法体调用桥接类的 sivDecrypt，自身不做 loadLibrary。
//
// 这是「业务 DEX 里发起的原生调用改由壳侧包装类转发」这一方案的核心构造。
func TestSivWrapperAdditionShape(t *testing.T) {
	const cls = "Lcom/apkguard/shell/Siv;"
	add, err := SivWrapperAddition(&SivWrapperSpec{Class: cls})
	if err != nil {
		t.Fatalf("构造 Siv 包装类失败: %v", err)
	}
	if len(add.Classes) != 1 {
		t.Fatalf("包装类应注入 1 个类，实际 %d", len(add.Classes))
	}
	c := add.Classes[0]
	if c.Name != cls {
		t.Fatalf("包装类名 = %q，期望 %q", c.Name, cls)
	}
	if len(c.Methods) != 1 {
		t.Fatalf("包装类应只有 1 个方法（无 <clinit>），实际 %d", len(c.Methods))
	}
	m := c.Methods[0]
	if m.Name != SivWrapperMethod {
		t.Fatalf("包装方法名 = %q，期望 %q", m.Name, SivWrapperMethod)
	}
	if m.Code == nil {
		t.Fatal("包装方法缺少方法体")
	}
	hasSiv := false
	for _, p := range m.Code.Patches {
		if p.Ref.Kind == RefMethod {
			if p.Ref.Method.Class == NativeBridgeClass && p.Ref.Method.Name == NativeDecrypt {
				hasSiv = true
			}
			if p.Ref.Method.Name == "loadLibrary" {
				t.Fatal("包装类不应调用 loadLibrary（它不含 <clinit>）")
			}
		}
	}
	if !hasSiv {
		t.Fatal("包装方法未调用桥接类的 sivDecrypt")
	}
	// 类体里不得出现 <clinit>，且 Addition 里不得登记 System/loadLibrary。
	for _, cm := range c.Methods {
		if cm.Name == "<clinit>" {
			t.Fatal("包装类不应有 <clinit>")
		}
	}
	for _, ty := range add.Types {
		if ty == descSystem {
			t.Fatal("包装类不应登记 java/lang/System 类型引用")
		}
	}
	for _, ms := range add.Methods {
		if ms.Name == "loadLibrary" {
			t.Fatal("包装类不应登记 loadLibrary 方法引用")
		}
	}
}

// TestDecryptorBridgeShape 断言 StringEncrypt.Bridge 非空时解密器的形态：
//   - 不再注入 <clinit>（不加载库）；
//   - 解密方法调用的是包装类的 d，而不是 Native.sivDecrypt；
//   - Addition 里不登记 System/loadLibrary，因此业务 DEX 字符串池不会出现
//     "loadLibrary"，也不出现对桥接类的直接引用。
func TestDecryptorBridgeShape(t *testing.T) {
	const cls = "Lx/Dec;"
	const wrap = "Lcom/apkguard/shell/Siv;"
	add, err := stringDecryptorAddition(&StringEncrypt{
		Class: cls, MethodName: "a", Key: testKey(0x22), InjectClass: true, Bridge: wrap,
	})
	if err != nil {
		t.Fatalf("构造 Bridge 解密器失败: %v", err)
	}
	if len(add.Classes) != 1 {
		t.Fatalf("应注入 1 个类，实际 %d", len(add.Classes))
	}
	c := add.Classes[0]
	if len(c.Methods) != 1 || c.Methods[0].Name != "a" {
		t.Fatalf("Bridge 路径解密器不应有 <clinit>，实际方法 %+v", methodNames(c.Methods))
	}
	hasWrapper, hasNative := false, false
	for _, p := range c.Methods[0].Code.Patches {
		if p.Ref.Kind != RefMethod {
			continue
		}
		if p.Ref.Method.Class == wrap && p.Ref.Method.Name == SivWrapperMethod {
			hasWrapper = true
		}
		if p.Ref.Method.Class == NativeBridgeClass {
			hasNative = true
		}
	}
	if !hasWrapper {
		t.Fatal("解密方法未调用包装类的 d")
	}
	if hasNative {
		t.Fatal("Bridge 路径解密方法仍直接引用 Native 桥接类")
	}
	for _, ty := range add.Types {
		if ty == descSystem || ty == NativeBridgeClass {
			t.Fatalf("Bridge 路径不应登记 %s 类型引用", ty)
		}
	}
	for _, ms := range add.Methods {
		if ms.Name == "loadLibrary" || ms.Name == NativeDecrypt {
			t.Fatalf("Bridge 路径不应登记方法引用 %s", ms.Name)
		}
		if ms.Class == NativeBridgeClass {
			t.Fatal("Bridge 路径不应登记对 Native 桥接类的方法引用")
		}
	}
}

// methodNames 返回方法名列表，仅用于测试报错可读性。
func methodNames(ms []ClassMethod) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.Name)
	}
	return out
}
