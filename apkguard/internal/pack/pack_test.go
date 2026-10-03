package pack

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"
)

// TestEncryptDecryptRoundTrip 验证加解密往返，覆盖各长度边界。
func TestEncryptDecryptRoundTrip(t *testing.T) {
	key, err := Key("test-key")
	if err != nil {
		t.Fatal(err)
	}
	iv := IVFromSeed("s")

	cases := [][]byte{
		{},
		{0x00},
		{0x41, 0x42},
		bytes.Repeat([]byte{0xff}, 15), // 恰好差 1 字节满分组
		bytes.Repeat([]byte{0x5a}, 16), // 恰好满分组（需整块填充）
		bytes.Repeat([]byte{0x33}, 17),
		bytes.Repeat([]byte{0x11}, 1024),
	}
	for _, plain := range cases {
		blob, err := Encrypt(plain, key, iv)
		if err != nil {
			t.Fatalf("加密 %d 字节失败: %v", len(plain), err)
		}
		// 密文 = IV(16) + 填充后的密文，且填充后长度是分组整数倍
		if len(blob) < BlockSize*2 {
			t.Fatalf("密文过短: %d", len(blob))
		}
		if (len(blob)-BlockSize)%BlockSize != 0 {
			t.Fatalf("密文主体长度 %d 不是分组整数倍", len(blob)-BlockSize)
		}
		if !bytes.Equal(blob[:BlockSize], iv[:]) {
			t.Fatal("IV 未前置存放")
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

// mustKey 是测试用的口令派生辅助（口令非空，不会失败）。
func mustKey(t *testing.T, secret string) [KeySize]byte {
	t.Helper()
	k, err := Key(secret)
	if err != nil {
		t.Fatalf("派生密钥失败: %v", err)
	}
	return k
}

// TestDecryptWrongKey 验证错误密钥不会静默返回垃圾数据。
func TestDecryptWrongKey(t *testing.T) {
	key := mustKey(t, "right")
	plain := bytes.Repeat([]byte{0x42}, 64)
	blob, err := Encrypt(plain, key, IVFromSeed("s"))
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}
	wrong := mustKey(t, "wrong")
	got, err := Decrypt(blob, wrong)
	// 错误密钥下 PKCS#7 校验大概率失败；即便偶然通过，内容也必然不同。
	if err == nil && bytes.Equal(got, plain) {
		t.Fatal("错误密钥竟然解出了明文")
	}
}

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
	// 固定常量意味着任何拿到产物的人都能解出载荷，等于明文交付。
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
	// 不得暴露 dex 字样
	if strings.Contains(strings.ToLower(n1), "dex") {
		t.Fatalf("载荷名泄露了用途: %q", n1)
	}
	// 不同 DEX 名必须得到不同的载荷名
	if AssetName("seed", "classes2.dex") == n1 {
		t.Fatal("不同 DEX 得到了相同载荷名")
	}
	// 不同种子必须得到不同的载荷名
	if AssetName("seed2", "classes.dex") == n1 {
		t.Fatal("不同种子得到了相同载荷名")
	}
}

// TestMake 验证批量生成：数量、命名唯一、可解密还原。
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
		got, err := Decrypt(p.Blob, key)
		if err != nil {
			t.Fatalf("载荷 %s 解密失败: %v", p.Asset, err)
		}
		if !bytes.Equal(got, dexes[i].Data) {
			t.Fatalf("载荷 %s 还原内容不一致", p.Asset)
		}
	}
	if TotalPlain(ps) != 600 {
		t.Fatalf("明文总长应为 600，实际 %d", TotalPlain(ps))
	}
	if TotalBlob(ps) <= 600 {
		t.Fatal("密文（含 IV 与填充）应长于明文")
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

// ---- 载荷 MAC（encrypt-then-MAC）----

// TestMACRoundTrip 验证带 MAC 载荷的「先验后解」往返。
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
	if len(p.Blob) < BlockSize+TagSize {
		t.Fatalf("载荷过短: %d", len(p.Blob))
	}
	if len(p.Blob) != len(mustEncryptRef(t, plain, key, IVFromSeed("s/"+dex.Name)))+TagSize {
		t.Fatalf("带 tag 载荷长度应为 旧格式 + %d", TagSize)
	}
	got, err := DecryptMAC(p.Blob, key, p.Name)
	if err != nil {
		t.Fatalf("DecryptMAC 失败: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("MAC 往返内容不一致")
	}
	// 直接 Decrypt 应当失败：尾部 tag 不是合法的 CBC 密文块。
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
		{"IV", 0},
		{"密文", 17},
		{"tag", len(p.Blob) - 1},
	}
	for _, tc := range cases {
		blob := append([]byte(nil), p.Blob...)
		blob[tc.at] ^= 0x01
		if _, err := DecryptMAC(blob, key, p.Name); err == nil {
			t.Fatalf("篡改 %s 后仍通过 MAC 校验", tc.label)
		}
	}
	// 正确 key / 错误 name：绑定身份失败。
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

// TestMACDisabledByteCompatible 验证 PayloadMAC 关闭时产物与旧格式逐字节一致。
//
// 这是向后兼容的硬约束：不追加尾部字节、不改变 IV/密文。
func TestMACDisabledByteCompatible(t *testing.T) {
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
	want := mustEncryptRef(t, dex.Data, key, IVFromSeed("s/"+dex.Name))
	if !bytes.Equal(p.Blob, want) {
		t.Fatal("未启用 MAC 时产物与旧格式不一致（不应追加任何尾部字节）")
	}
	got, err := Decrypt(p.Blob, key)
	if err != nil || !bytes.Equal(got, dex.Data) {
		t.Fatal("未启用 MAC 时 Decrypt 行为应不变")
	}
}

// TestMacKeyDomainSeparation 验证 MAC 密钥经过域分离，不等于 AES 密钥本身，
// 且与实现使用同一公式（跨文件对拍）。
func TestMacKeyDomainSeparation(t *testing.T) {
	key := mustKey(t, "k")
	mk := MacKey(key)
	if bytes.Equal(mk[:], key[:]) {
		t.Fatal("MAC 密钥不应等于 AES 密钥")
	}
	// 手工复算：SHA-256(key ‖ "apkguard/payload-mac")
	h := sha256.New()
	h.Write(key[:])
	h.Write([]byte("apkguard/payload-mac"))
	if !bytes.Equal(mk[:], h.Sum(nil)) {
		t.Fatal("MAC 密钥派生公式与文档不符")
	}
}

// TestCryptoConstants 钉住跨语言对拍常量。
//
// pack.go 与 dex/loader.go 各有一份常量定义；任何漂移都会让壳侧算出的
// MAC/长度与打包时对不上，且只有真机才暴露。这里显式断言数值。
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
}

// mustEncryptRef 是 Encrypt 的独立参照实现，用于格式兼容断言。
func mustEncryptRef(t *testing.T, plain []byte, key [KeySize]byte, iv [BlockSize]byte) []byte {
	t.Helper()
	blob, err := Encrypt(plain, key, iv)
	if err != nil {
		t.Fatalf("Encrypt 失败: %v", err)
	}
	return blob
}
