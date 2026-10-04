package pack

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// ---- 基础辅助 ----

// mustKey 是测试用的口令派生辅助（口令非空，不会失败）。
func mustKey(t *testing.T, secret string) [KeySize]byte {
	t.Helper()
	k, err := Key(secret)
	if err != nil {
		t.Fatalf("派生密钥失败: %v", err)
	}
	return k
}

// mustHex 解析允许空格的十六进制串。
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("测试向量十六进制非法: %v", err)
	}
	return b
}

// cmacRef 用给定密钥对消息算 CMAC（测试独立入口）。
func cmacRef(t *testing.T, key, msg []byte) []byte {
	t.Helper()
	b, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("构造 AES 失败: %v", err)
	}
	out := newCMAC(b).sum(msg)
	return out[:]
}

// ---- CMAC 本体：RFC 4493 官方向量（AES-128） ----

// TestCMACRFC4493 用 RFC 4493 的 4 条官方向量验证 CMAC 算法本体。
//
// 本项目生产路径用 AES-256 跑 CMAC（SIV 的 K1 为 32 字节），但算法结构
// 与密钥长度无关：先用官方向量证明「子密钥 + 10* 填充 + 末块选择」正确，
// AES-256 的正确性再由 RFC 5297 交叉向量与自洽往返覆盖。
func TestCMACRFC4493(t *testing.T) {
	key := mustHex(t, "2b7e1516 28aed2a6 abf71588 09cf4f3c")
	// RFC 4493 §2.3 子密钥：
	//   L  = AES(K, 0^128) = 7df76b0c1ab899b33e42f047b91b546f
	//   K1 = dbl(L)        = fbeed618357133667c85e08f7236a8de
	//   K2 = dbl(K1)       = f7ddac306ae266ccf90bc11ee46d513b
	blk, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	var zero, l [BlockSize]byte
	blk.Encrypt(l[:], zero[:])
	if got := hex.EncodeToString(l[:]); got != "7df76b0c1ab899b33e42f047b91b546f" {
		t.Fatalf("L 不符: %s", got)
	}
	c := newCMAC(blk)
	if got := hex.EncodeToString(c.sub1[:]); got != "fbeed618357133667c85e08f7236a8de" {
		t.Fatalf("K1 不符: %s", got)
	}
	if got := hex.EncodeToString(c.sub2[:]); got != "f7ddac306ae266ccf90bc11ee46d513b" {
		t.Fatalf("K2 不符: %s", got)
	}

	cases := []struct {
		msg string // RFC 4493 的示例消息（空串表示 0 字节）
		sum string
	}{
		// RFC 4493 §D.1（空消息）
		{"", "bb1d6929e95937287fa37d129b756746"},
		// RFC 4493 §D.2（16 字节，整块 → 用 K1）
		{"6bc1bee22e409f96e93d7e117393172a", "070a16b46b4d4144f79bdd9dd04a287c"},
		// RFC 4493 §D.3（40 字节，末块 8 字节 → 10* 填充 + K2）
		{"6bc1bee22e409f96 e93d7e117393172a ae2d8a571e03ac9c 9eb76fac45af8e51 30c81c46a35ce411",
			"dfa66747de9ae63030ca32611497c827"},
		// RFC 4493 §D.4（64 字节，整块 → 用 K1）
		{"6bc1bee22e409f96 e93d7e117393172a ae2d8a571e03ac9c 9eb76fac45af8e51 30c81c46a35ce411" +
			"e5fbc1191a0a52ef f69f2445df4f9b17 ad2b417be66c3710", "51f0bebf7e3b9d92fc49741779363cfe"},
	}
	for i, tc := range cases {
		got := hex.EncodeToString(cmacRef(t, key, mustHex(t, tc.msg)))
		if got != tc.sum {
			t.Fatalf("RFC 4493 向量 %d 不符:\n got %s\nwant %s", i+1, got, tc.sum)
		}
	}
}

// ---- S2V + CTR：RFC 5297 官方向量 ----

// TestSIVRFC5297A1 跑 RFC 5297 Appendix A.1「Deterministic Authenticated
// Encryption Example」（AES-SIV-CMAC-256：K1/K2 各 16 字节）。
//
// 注意：RFC 5297 的官方向量（Appendix A）只有 A.1/A.2 两条，且都定义在
// §6.1 AEAD_AES_SIV_CMAC_256（K_LEN=32 字节）下；RFC 中不存在 CMAC-512
// 的官方向量。本项目生产使用 512 位变体，S2V/CTR 的代码路径与密钥长度
// 无关，故先用官方向量证明算法逐字节正确，AES-256 再由交叉向量覆盖。
func TestSIVRFC5297A1(t *testing.T) {
	key := mustHex(t, "fffefdfc fbfaf9f8 f7f6f5f4 f3f2f1f0"+
		"f0f1f2f3 f4f5f6f7 f8f9fafb fcfdfeff")
	k1, k2 := key[:16], key[16:]
	ad := mustHex(t, "10111213 14151617 18191a1b 1c1d1e1f 20212223 24252627")
	pt := mustHex(t, "11223344 55667788 99aabbcc ddee")
	want := mustHex(t, "85632d07 c6e8f37f 950acd32 0a2ecc93"+ // SIV 标签
		"40c02b96 90c4dc04 daef7f6a fe5c") // CTR 密文

	// 中间量（RFC 5297 A.1 的 S2V-CMAC-AES 小节），钉住 S2V 每一步。
	if got := hex.EncodeToString(cmacRef(t, k1, make([]byte, BlockSize))); got != "0e04dfafc1efbf040140582859bf073a" {
		t.Fatalf("CMAC(zero) 不符: %s", got)
	}
	if got := hex.EncodeToString(cmacRef(t, k1, ad)); got != "f1f922b7f5193ce64ff80cb47d93f23b" {
		t.Fatalf("CMAC(ad) 不符: %s", got)
	}
	tag := s2v(mustAES(t, k1), ad, pt)
	if got := hex.EncodeToString(tag[:]); got != "85632d07c6e8f37f950acd320a2ecc93" {
		t.Fatalf("S2V 标签不符: %s", got)
	}

	blob, err := sivSeal(k1, k2, [][]byte{ad, pt})
	if err != nil {
		t.Fatalf("sivSeal 失败: %v", err)
	}
	if !bytes.Equal(blob, want) {
		t.Fatalf("A.1 输出不符:\n got %x\nwant %x", blob, want)
	}
	// CTR 首个密钥流块 E(K, CTR)，其中 CTR = SIV 且 31/63 位被清零
	// （0x95 → 0x15），这一步专门钉住 §2.6 的清位要求。
	if ks := ctrCrypt(mustAES(t, k2), tag, make([]byte, BlockSize)); hex.EncodeToString(ks) != "51e218d2c5a2ab8c4345c4a623b2f08f" {
		t.Fatalf("E(K,CTR) 不符（计数器清位或递增有误）: %x", ks)
	}

	got, err := sivOpen(k1, k2, [][]byte{ad}, blob)
	if err != nil {
		t.Fatalf("sivOpen 失败: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatal("A.1 解密结果不符")
	}
}

// TestSIVRFC5297A2 跑 RFC 5297 Appendix A.2「Nonce-Based Authenticated
// Encryption Example」，覆盖多组件 AD（AD1、AD2、Nonce 共 3 个组件）与
// 非整块长度（明文 47 字节，xorend 作用于最后 16 字节）。
func TestSIVRFC5297A2(t *testing.T) {
	key := mustHex(t, "7f7e7d7c 7b7a7978 77767574 73727170"+
		"40414243 44454647 48494a4b 4c4d4e4f")
	k1, k2 := key[:16], key[16:]
	ad1 := mustHex(t, "00112233 44556677 8899aabb ccddeeff"+
		"deaddada deaddada ffeeddcc bbaa9988 77665544 33221100")
	ad2 := mustHex(t, "10203040 50607080 90a0")
	nonce := mustHex(t, "09f91102 9d74e35b d84156c5 635688c0")
	pt := []byte("this is some plaintext to encrypt using SIV-AES") // 47 字节
	want := mustHex(t, "7bdb6e3b 432667eb 06f4d14b ff2fbd0f"+
		"cb900f2f ddbe4043 26601965 c889bf17 dba77ceb 094fa663 b7a3f748 ba8af829"+
		"ea64ad54 4a272e9c 485b62a3 fd5c0d")

	if got := hex.EncodeToString(cmacRef(t, k1, ad1)); got != "3c9b689ab41102e4809547141dd0d15a" {
		t.Fatalf("CMAC(ad1) 不符: %s", got)
	}
	if got := hex.EncodeToString(cmacRef(t, k1, ad2)); got != "d98c9b0be42cb2d7aa98478ed11eda1b" {
		t.Fatalf("CMAC(ad2) 不符: %s", got)
	}
	if got := hex.EncodeToString(cmacRef(t, k1, nonce)); got != "128c62a1ce3747a8372c1c05a538b96d" {
		t.Fatalf("CMAC(nonce) 不符: %s", got)
	}
	tag := s2v(mustAES(t, k1), ad1, ad2, nonce, pt)
	if got := hex.EncodeToString(tag[:]); got != "7bdb6e3b432667eb06f4d14bff2fbd0f" {
		t.Fatalf("S2V 标签不符: %s", got)
	}

	blob, err := sivSeal(k1, k2, [][]byte{ad1, ad2, nonce, pt})
	if err != nil {
		t.Fatalf("sivSeal 失败: %v", err)
	}
	if !bytes.Equal(blob, want) {
		t.Fatalf("A.2 输出不符:\n got %x\nwant %x", blob, want)
	}
	// 三个计数器块的密钥流（CTR、CTR+1、CTR+2），钉住大端递增。
	ks := ctrCrypt(mustAES(t, k2), tag, make([]byte, 47))
	wantKS := mustHex(t, "bff8665c fdd73363 550f7400 e8f9d376"+
		"b2c9088e 713b8617 d8839226 d9f88159"+
		"9e44d827 234949bc 1b12348e bc195ec7")[:47] // 第三个块只取前 15 字节
	if !bytes.Equal(ks, wantKS) {
		t.Fatalf("A.2 密钥流不符（计数器递增有误）:\n got %x\nwant %x", ks, wantKS)
	}

	got, err := sivOpen(k1, k2, [][]byte{ad1, ad2, nonce}, blob)
	if err != nil {
		t.Fatalf("sivOpen 失败: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatal("A.2 解密结果不符")
	}
}

// TestSIVTamperRFCVectors 对 A.1 产物逐字节翻转，全部必须解密失败。
func TestSIVTamperRFCVectors(t *testing.T) {
	key := mustHex(t, "fffefdfc fbfaf9f8 f7f6f5f4 f3f2f1f0"+
		"f0f1f2f3 f4f5f6f7 f8f9fafb fcfdfeff")
	k1, k2 := key[:16], key[16:]
	ad := mustHex(t, "10111213 14151617 18191a1b 1c1d1e1f 20212223 24252627")
	pt := mustHex(t, "11223344 55667788 99aabbcc ddee")
	blob, err := sivSeal(k1, k2, [][]byte{ad, pt})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(blob); i++ {
		bad := append([]byte(nil), blob...)
		bad[i] ^= 0x01
		if _, err := sivOpen(k1, k2, [][]byte{ad}, bad); err == nil {
			t.Fatalf("翻转第 %d 字节后 SIV 校验仍通过", i)
		}
	}
	// 错误 AD 与错误 key 也必须失败。
	if _, err := sivOpen(k1, k2, [][]byte{append(append([]byte(nil), ad...), 0x00)}, blob); err == nil {
		t.Fatal("错误 AD 仍通过 SIV 校验")
	}
	if _, err := sivOpen(k2, k1, [][]byte{ad}, blob); err == nil {
		t.Fatal("K1/K2 对调仍通过 SIV 校验")
	}
}

// ---- 生产参数（AES-256-SIV，K1/K2 各 32 字节）交叉验证 ----

// TestSIVCrossCheckAES256 用独立实现（pyca/cryptography 50.0.1 的 AESSIV）
// 生成的向量验证生产路径：主密钥 → K1/K2 域分离 → S2V(AD=name)+CTR。
//
// 向量生成方式（与本实现无关）：
//
//	master = SHA-256("apkguard/packkey/" + secret)
//	K1     = SHA-256(master ‖ "apkguard/siv/mac")
//	K2     = SHA-256(master ‖ "apkguard/siv/ctr")
//	ct     = AESSIV(K1‖K2).encrypt(P, [name])
//
// 同一独立实现已复现 RFC 5297 A.1/A.2 官方向量，故这里同时验证了
// AES-256 与「AD=逻辑名」的生产用法。
func TestSIVCrossCheckAES256(t *testing.T) {
	// 先钉住 K1/K2 的派生公式（与独立实现的十六进制逐字节一致）。
	k1, k2 := sivDeriveKeys(mustKey(t, "siv-vec"))
	if got := hex.EncodeToString(append(append([]byte(nil), k1[:]...), k2[:]...)); got !=
		"2f68872112a9ceb354710f3dfee58ccb8d8ff56713606ee17496d0ae8fb79154"+
			"0696b54e16d660c581526b45115301f093de14efd59e062caa813128004223b0" {
		t.Fatalf("K1/K2 派生不符:\n got %s", got)
	}

	key := mustKey(t, "siv-vec")
	cases := []struct {
		name string
		pt   []byte
		ct   string
	}{
		{"classes.dex", []byte{}, "f4d2c95fdea8258711935cd767592bac"},
		{"classes.dex", mustHex(t, "000102030405060708090a0b0c0d0e"), // 15 字节
			"1e98761495eacde8e3ed0562ff07be2a379a4be5afae9a064f27974455a339"},
		{"classes.dex", mustHex(t, "000102030405060708090a0b0c0d0e0f"), // 16 字节
			"28105b50d931c94b85e104e602be26c2315279385140ac09ee96983a0c293fa7"},
		{"classes.dex", mustHex(t, "000102030405060708090a0b0c0d0e0f10"), // 17 字节
			"03fa9cbac24c5eda6a5aca06da77517d61d9df94892ed2cd4dc473efc5826a60d6"},
		{"classes.dex", bytes.Repeat([]byte{0x42}, 64),
			"646a18f524d695870cffcb8ef5b40a2a7150972ebc50a19a40f867cd66866e96" +
				"10bb50e144998eefa70b6cf48ce899ce3c376d0b3223c7d632bdbd800906275a" +
				"2cc2d814a93912902e7793690606a179"},
		{"classes2.dex", mustHex(t, "000102030405060708090a0b0c0d0e0f"), // 同明文不同 AD
			"e9e7eeb08441e93904a323f0a06d1fc2d8224fce60d74d928715ed39d6d8f832"},
	}
	for i, tc := range cases {
		blob, err := EncryptNamed(tc.pt, key, tc.name)
		if err != nil {
			t.Fatalf("用例 %d 加密失败: %v", i, err)
		}
		if hex.EncodeToString(blob) != tc.ct {
			t.Fatalf("用例 %d（name=%s, %d 字节）与独立实现不符:\n got %x\nwant %s",
				i, tc.name, len(tc.pt), blob, tc.ct)
		}
		if len(blob) != BlockSize+len(tc.pt) {
			t.Fatalf("用例 %d 长度 %d，应为 16+%d（无填充）", i, len(blob), len(tc.pt))
		}
		got, err := DecryptNamed(blob, key, tc.name)
		if err != nil {
			t.Fatalf("用例 %d 解密失败: %v", i, err)
		}
		if !bytes.Equal(got, tc.pt) {
			t.Fatalf("用例 %d 往返不一致", i)
		}
	}
}

// ---- 往返 / 确定性 / 篡改（生产 API） ----

// TestEncryptDecryptRoundTrip 验证 Encrypt/Decrypt 在各长度边界上的往返，
// 且密文长度严格等于 16 + 明文长度（SIV 无填充）。
func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := mustKey(t, "test-key")
	iv := IVFromSeed("s")

	cases := [][]byte{
		{},
		{0x00},
		bytes.Repeat([]byte{0xff}, 15),
		bytes.Repeat([]byte{0x5a}, 16),
		bytes.Repeat([]byte{0x33}, 17),
		bytes.Repeat([]byte{0x11}, 31),
		bytes.Repeat([]byte{0x22}, 32),
		bytes.Repeat([]byte{0x44}, 33),
		bytes.Repeat([]byte{0x55}, 1000),
		bytes.Repeat([]byte{0xAB}, 1<<20), // 1 MiB
	}
	for _, plain := range cases {
		blob, err := Encrypt(plain, key, iv)
		if err != nil {
			t.Fatalf("加密 %d 字节失败: %v", len(plain), err)
		}
		if len(blob) != BlockSize+len(plain) {
			t.Fatalf("%d 字节明文的密文长度 %d，应为 %d（无填充）", len(plain), len(blob), BlockSize+len(plain))
		}
		got, err := Decrypt(blob, key)
		if err != nil {
			t.Fatalf("解密 %d 字节失败: %v", len(plain), err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("往返不一致：%d 字节 -> %d 字节", len(plain), len(got))
		}
	}
}

// TestEncryptNamedRoundTrip 验证加密方绑定逻辑名、解密方必须提供同名。
func TestEncryptNamedRoundTrip(t *testing.T) {
	key := mustKey(t, "named")
	plain := bytes.Repeat([]byte{0x77}, 100)
	blob, err := EncryptNamed(plain, key, "classes.dex")
	if err != nil {
		t.Fatal(err)
	}
	if len(blob) != BlockSize+len(plain) {
		t.Fatalf("长度不符: %d", len(blob))
	}
	got, err := DecryptNamed(blob, key, "classes.dex")
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("同名解密失败: %v", err)
	}
	if _, err := DecryptNamed(blob, key, "classes2.dex"); err == nil {
		t.Fatal("错误逻辑名仍通过 SIV 校验")
	}
	if _, err := Decrypt(blob, key); err == nil {
		t.Fatal("无 AD 的 Decrypt 不应解开绑定名字的载荷")
	}
}

// TestSIVDeterministic 验证确定性：同 key + 同 name + 同明文 → 逐字节相同；
// 换 name（AD 不同）→ 密文不同。这是「产物可复现」承诺的密码学基础。
func TestSIVDeterministic(t *testing.T) {
	key := mustKey(t, "det")
	plain := bytes.Repeat([]byte{0x09}, 333)

	a1, _ := Encrypt(plain, key, IVFromSeed("s1"))
	a2, _ := Encrypt(plain, key, IVFromSeed("s2")) // iv 被忽略，必须相同
	if !bytes.Equal(a1, a2) {
		t.Fatal("同 key/明文两次加密不一致（iv 不应参与）")
	}
	n1, _ := EncryptNamed(plain, key, "classes.dex")
	n2, _ := EncryptNamed(plain, key, "classes.dex")
	if !bytes.Equal(n1, n2) {
		t.Fatal("同 key/name/明文两次加密不一致")
	}
	other, _ := EncryptNamed(plain, mustKey(t, "other"), "classes.dex")
	if bytes.Equal(n1, other) {
		t.Fatal("不同 key 得到相同密文")
	}
	n3, _ := EncryptNamed(plain, key, "classes2.dex")
	if bytes.Equal(n1, n3) {
		t.Fatal("不同 name（AD）得到相同密文")
	}
	if bytes.Equal(n1, a1) {
		t.Fatal("有 AD 与无 AD 的密文不应相同")
	}
}

// TestSIVTamperEverywhere 验证篡改标签/密文/长度后 Decrypt/DecryptNamed 必失败。
func TestSIVTamperEverywhere(t *testing.T) {
	key := mustKey(t, "tamper")
	plain := bytes.Repeat([]byte{0x31}, 50)
	blob, err := EncryptNamed(plain, key, "classes.dex")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		label string
		mut   func([]byte) []byte
	}{
		{"SIV 标签首字节", func(b []byte) []byte { b[0] ^= 0x80; return b }},
		{"SIV 标签末字节", func(b []byte) []byte { b[15] ^= 0x01; return b }},
		{"密文首字节", func(b []byte) []byte { b[16] ^= 0x01; return b }},
		{"密文末字节", func(b []byte) []byte { b[len(b)-1] ^= 0x01; return b }},
		{"截断 1 字节", func(b []byte) []byte { return b[:len(b)-1] }},
		{"追加 1 字节", func(b []byte) []byte { return append(b, 0x00) }},
		{"清空", func(b []byte) []byte { return nil }},
	}
	for _, tc := range cases {
		bad := tc.mut(append([]byte(nil), blob...))
		if _, err := DecryptNamed(bad, key, "classes.dex"); err == nil {
			t.Fatalf("%s 后仍解密成功", tc.label)
		}
	}
	// 错误 key 必失败（SIV 校验是认证的）。
	if _, err := DecryptNamed(blob, mustKey(t, "other"), "classes.dex"); err == nil {
		t.Fatal("错误 key 仍解密成功")
	}
}

// TestDecryptWrongKey 验证错误密钥不会静默返回垃圾数据（SIV 直接报错）。
func TestDecryptWrongKey(t *testing.T) {
	key := mustKey(t, "right")
	plain := bytes.Repeat([]byte{0x42}, 64)
	blob, err := Encrypt(plain, key, IVFromSeed("s"))
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}
	wrong := mustKey(t, "wrong")
	if got, err := Decrypt(blob, wrong); err == nil {
		t.Fatalf("错误密钥竟然解出了明文（%d 字节）", len(got))
	}
}

// TestNoPadding 显式验证分组整数倍明文不再膨胀一个分组（CBC+PKCS#7 的特征）。
func TestNoPadding(t *testing.T) {
	key := mustKey(t, "pad")
	for _, n := range []int{15, 16, 17, 31, 32, 33, 48} {
		blob, err := Encrypt(bytes.Repeat([]byte{0x0f}, n), key, IVFromSeed("s"))
		if err != nil {
			t.Fatal(err)
		}
		if len(blob) != n+BlockSize {
			t.Fatalf("%d 字节明文的密文为 %d，应恰为 %d（16B 标签 + 等长密文）", n, len(blob), n+BlockSize)
		}
	}
}

// ---- Key / AssetName / MAC 既有语义 ----

// TestKeyDeterministic 验证密钥派生可复现。
func TestKeyDeterministic(t *testing.T) {
	a, b := mustKey(t, "same"), mustKey(t, "same")
	if a != b {
		t.Fatal("同口令派生出的密钥不一致")
	}
	if c := mustKey(t, "other"); c == a {
		t.Fatal("不同口令派生出了相同密钥")
	}
	// 空口令不再回退到固定常量：必须生成随机密钥（两次不同）。
	k1, err := Key("")
	if err != nil {
		t.Fatalf("空口令生成随机密钥失败: %v", err)
	}
	k2, err := Key("")
	if err != nil {
		t.Fatalf("空口令生成随机密钥失败: %v", err)
	}
	if k1 == k2 {
		t.Fatal("空口令两次派生出了同一个密钥——退回了固定常量")
	}
	if k1 == sha256.Sum256([]byte("apkguard/packkey/apkguard")) {
		t.Fatal("空口令等于旧的固定兜底常量")
	}
}

// TestAssetName 验证载荷名的伪装性与确定性。
func TestAssetName(t *testing.T) {
	n1 := AssetName("seed", "classes.dex")
	n2 := AssetName("seed", "classes.dex")
	if n1 != n2 {
		t.Fatalf("同名同种子应产生相同载荷名: %q vs %q", n1, n2)
	}
	if !strings.HasPrefix(n1, "assets/") {
		t.Fatalf("载荷必须放在 assets/ 下: %q", n1)
	}
	if strings.Contains(strings.ToLower(n1), "dex") {
		t.Fatalf("载荷名泄露了用途: %q", n1)
	}
	if AssetName("seed", "classes2.dex") == n1 {
		t.Fatal("不同 DEX 得到了相同载荷名")
	}
	if AssetName("seed2", "classes.dex") == n1 {
		t.Fatal("不同种子得到了相同载荷名")
	}
}

// TestMake 验证批量生成：数量、命名唯一、SIV 无填充、可按名字解密还原。
func TestMake(t *testing.T) {
	key := mustKey(t, "k")
	dexes := []Dex{
		{Name: "classes.dex", Data: bytes.Repeat([]byte{0x01}, 100)},
		{Name: "classes2.dex", Data: bytes.Repeat([]byte{0x02}, 200)},
		{Name: "classes3.dex", Data: bytes.Repeat([]byte{0x03}, 300)},
	}
	ps, err := Make(dexes, key, "s1")
	if err != nil {
		t.Fatalf("生成失败: %v", err)
	}
	if len(ps) != 3 {
		t.Fatalf("应生成 3 份载荷，实际 %d", len(ps))
	}
	seen := map[string]bool{}
	for i, p := range ps {
		if seen[p.Asset] {
			t.Fatalf("载荷名重复: %s", p.Asset)
		}
		seen[p.Asset] = true
		if p.Name != dexes[i].Name {
			t.Fatalf("载荷 %d 的名字不符: %s", i, p.Name)
		}
		if p.Plain != len(dexes[i].Data) {
			t.Fatalf("明文长度记录错误: %d vs %d", p.Plain, len(dexes[i].Data))
		}
		if len(p.Blob) != BlockSize+len(dexes[i].Data) {
			t.Fatalf("载荷 %s 长度 %d，应为 16+%d（无填充）", p.Asset, len(p.Blob), len(dexes[i].Data))
		}
		// 新格式不再有 IV‖CBC；SIV 的 AD = 原始 DEX 名。
		got, err := DecryptNamed(p.Blob, key, p.Name)
		if err != nil {
			t.Fatalf("载荷 %s 解密失败: %v", p.Asset, err)
		}
		if !bytes.Equal(got, dexes[i].Data) {
			t.Fatalf("载荷 %s 还原内容不一致", p.Asset)
		}
		// 无 AD 的 Decrypt 不应解开（名字已绑定进 SIV）。
		if _, err := Decrypt(p.Blob, key); err == nil {
			t.Fatalf("载荷 %s 未绑定名字（Decrypt 竟然成功）", p.Asset)
		}
	}
	if TotalPlain(ps) != 600 {
		t.Fatalf("明文总长应为 600，实际 %d", TotalPlain(ps))
	}
	if TotalBlob(ps) != 600+BlockSize*len(ps) {
		t.Fatalf("密文总长应为 16×载荷数 + 明文总长（无填充），实际 %d", TotalBlob(ps))
	}
	// 空数据应被跳过
	ps2, err := Make([]Dex{{Name: "empty.dex", Data: nil}}, key, "s")
	if err != nil {
		t.Fatalf("生成失败: %v", err)
	}
	if len(ps2) != 0 {
		t.Fatalf("空 DEX 不应生成载荷，实际 %d", len(ps2))
	}
}

// TestMakeDeterministic 验证同输入可复现。
func TestMakeDeterministic(t *testing.T) {
	key := mustKey(t, "k")
	dexes := []Dex{{Name: "classes.dex", Data: bytes.Repeat([]byte{0x07}, 128)}}
	a, err := Make(dexes, key, "seed")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Make(dexes, key, "seed")
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 1 || len(b) != 1 {
		t.Fatal("生成数量异常")
	}
	if a[0].Asset != b[0].Asset || !bytes.Equal(a[0].Blob, b[0].Blob) {
		t.Fatal("同输入两次生成结果不一致")
	}
}

// ---- 载荷 MAC（encrypt-then-MAC，外层纵深防御） ----

// TestMACRoundTrip 验证带 MAC 载荷的「先验后解」往返与格式。
func TestMACRoundTrip(t *testing.T) {
	key := mustKey(t, "mac-key")
	plain := bytes.Repeat([]byte{0x5a}, 333)
	dex := Dex{Name: "classes.dex", Data: plain}

	ps, err := MakeMAC([]Dex{dex}, key, "s")
	if err != nil {
		t.Fatalf("MakeMAC 失败: %v", err)
	}
	if len(ps) != 1 {
		t.Fatalf("应生成 1 份载荷，实际 %d", len(ps))
	}
	p := ps[0]
	if !p.Tagged {
		t.Fatal("载荷未标记 Tagged")
	}
	// 最终 blob = [SIV(16)][CTR 密文(==明文长度)][HMAC(32)]。
	if len(p.Blob) != BlockSize+len(plain)+TagSize {
		t.Fatalf("带 MAC 载荷长度 %d，应为 16+%d+32", len(p.Blob), len(plain))
	}
	ref, err := EncryptNamed(plain, key, dex.Name)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p.Blob[:len(ref)], ref) {
		t.Fatal("带 MAC 载荷的前段不是 EncryptNamed 的产物")
	}
	if !VerifyMAC(p.Blob, key, dex.Name) {
		t.Fatal("VerifyMAC 应为真")
	}
	got, err := DecryptMAC(p.Blob, key, p.Name)
	if err != nil {
		t.Fatalf("DecryptMAC 失败: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("MAC 往返内容不一致")
	}
	// 未剥离 tag 时 Decrypt 必须失败（tag 会被当成 CTR 密文）。
	if _, err := Decrypt(p.Blob, key); err == nil {
		t.Fatal("未剥离 tag 时 Decrypt 不应成功")
	}
}

// TestMACTamperDetected 验证篡改任意关键字节都会被 DecryptMAC 拒绝。
func TestMACTamperDetected(t *testing.T) {
	key := mustKey(t, "mac-key")
	plain := bytes.Repeat([]byte{0x11}, 200)
	ps, err := MakeMAC([]Dex{{Name: "classes2.dex", Data: plain}}, key, "s")
	if err != nil {
		t.Fatal(err)
	}
	p := ps[0]

	cases := []struct {
		label string
		at    int
	}{
		{"SIV 标签", 0},
		{"密文", 17},
		{"HMAC tag", len(p.Blob) - 1},
	}
	for _, tc := range cases {
		blob := append([]byte(nil), p.Blob...)
		blob[tc.at] ^= 0x01
		if _, err := DecryptMAC(blob, key, p.Name); err == nil {
			t.Fatalf("篡改 %s 后仍通过 MAC 校验", tc.label)
		}
	}
	// 正确 key / 错误 name：HMAC 与 SIV 的 AD 双重绑定，必须失败。
	if _, err := DecryptMAC(p.Blob, key, "classes9.dex"); err == nil {
		t.Fatal("错误 name 仍通过 MAC 校验（载荷可被互换）")
	}
	// 错误 key：macKey 不同，失败。
	if _, err := DecryptMAC(p.Blob, mustKey(t, "other"), p.Name); err == nil {
		t.Fatal("错误 key 仍通过 MAC 校验")
	}
	// 过短载荷必须失败而不是 panic。
	if _, err := DecryptMAC(p.Blob[:BlockSize+TagSize-1], key, p.Name); err == nil {
		t.Fatal("过短载荷应失败")
	}
}

// TestMACDisabledNameBound 验证 PayloadMAC 关闭时：不追加 tag、SIV 仍绑定名字。
func TestMACDisabledNameBound(t *testing.T) {
	key := mustKey(t, "compat")
	dex := Dex{Name: "classes.dex", Data: bytes.Repeat([]byte{0x42}, 100)}
	ps, err := Make([]Dex{dex}, key, "s")
	if err != nil {
		t.Fatal(err)
	}
	p := ps[0]
	if p.Tagged {
		t.Fatal("未启用 MAC 时不应标记 Tagged")
	}
	if len(p.Blob) != BlockSize+len(dex.Data) {
		t.Fatalf("未启用 MAC 时不应追加任何尾部字节: %d", len(p.Blob))
	}
	ref, err := EncryptNamed(dex.Data, key, dex.Name)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p.Blob, ref) {
		t.Fatal("Payload 产物应为 EncryptNamed(name) 的输出")
	}
	if VerifyMAC(p.Blob, key, dex.Name) {
		t.Fatal("未启用 MAC 时 VerifyMAC 不应通过")
	}
	got, err := DecryptNamed(p.Blob, key, dex.Name)
	if err != nil || !bytes.Equal(got, dex.Data) {
		t.Fatal("未启用 MAC 时 DecryptNamed 应还原明文")
	}
}

// TestMacKeyDomainSeparation 验证 MAC 密钥经过域分离，且与实现使用同一公式。
func TestMacKeyDomainSeparation(t *testing.T) {
	key := mustKey(t, "k")
	mk := MacKey(key)
	if bytes.Equal(mk[:], key[:]) {
		t.Fatal("MAC 密钥不应等于 AES 密钥")
	}
	h := sha256.New()
	h.Write(key[:])
	h.Write([]byte("apkguard/payload-mac"))
	if !bytes.Equal(mk[:], h.Sum(nil)) {
		t.Fatal("MAC 密钥派生公式与文档不符")
	}
}

// TestCryptoConstants 钉住跨语言对拍常量（pack.go / siv.go 与 DEX、native 三侧）。
func TestCryptoConstants(t *testing.T) {
	if KeySize != 32 {
		t.Fatalf("KeySize=%d，应为 32（AES-256）", KeySize)
	}
	if BlockSize != 16 {
		t.Fatalf("BlockSize=%d，应为 16", BlockSize)
	}
	if TagSize != 32 {
		t.Fatalf("TagSize=%d，应为 32（HMAC-SHA256）", TagSize)
	}
	if macDomain != "apkguard/payload-mac" {
		t.Fatalf("macDomain=%q 与壳侧不一致", macDomain)
	}
	if sivMacDomain != "apkguard/siv/mac" {
		t.Fatalf("sivMacDomain=%q 与壳侧不一致", sivMacDomain)
	}
	if sivCTRDomain != "apkguard/siv/ctr" {
		t.Fatalf("sivCTRDomain=%q 与壳侧不一致", sivCTRDomain)
	}
}

// mustAES 是测试辅助：构造 AES 分组密码。
func mustAES(t *testing.T, key []byte) cipher.Block {
	t.Helper()
	b, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("构造 AES 失败: %v", err)
	}
	return b
}
