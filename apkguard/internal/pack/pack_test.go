package pack

import (
	"bytes"
	"strings"
	"testing"
)

// TestEncryptDecryptRoundTrip 验证加解密往返，覆盖各长度边界。
func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := Key("test-key")
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

// TestDecryptWrongKey 验证错误密钥不会静默返回垃圾数据。
func TestDecryptWrongKey(t *testing.T) {
	key := Key("right")
	plain := bytes.Repeat([]byte{0x42}, 64)
	blob, err := Encrypt(plain, key, IVFromSeed("s"))
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}
	wrong := Key("wrong")
	got, err := Decrypt(blob, wrong)
	// 错误密钥下 PKCS#7 校验大概率失败；即便偶然通过，内容也必然不同。
	if err == nil && bytes.Equal(got, plain) {
		t.Fatal("错误密钥竟然解出了明文")
	}
}

// TestKeyDeterministic 验证密钥派生可复现。
func TestKeyDeterministic(t *testing.T) {
	a, b := Key("same"), Key("same")
	if a != b {
		t.Fatal("同口令派生出的密钥不一致")
	}
	if c := Key("other"); c == a {
		t.Fatal("不同口令派生出了相同密钥")
	}
	// 空口令必须有兜底值，不能panic
	_ = Key("")
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
	key := Key("k")
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
	key := Key("k")
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
