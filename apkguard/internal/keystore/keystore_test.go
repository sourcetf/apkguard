package keystore

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	keystorego "github.com/pavlo-v-chernykh/keystore-go/v4"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// 本文件为两种密钥库格式建立回归保护。
//
// 之所以必须分别测：JKS 与 PKCS12 走的是完全独立的解析路径
// （loadJKS / loadPKCS12），而现实中的 .jks 文件未必真是 JKS——
// 新版 keytool 默认产出 PKCS12，只是沿用 .jks 扩展名。
// 开发期用到的 sigtest/test.jks 实际上就是 PKCS12，若无本文件，
// loadJKS 这条「文档中列为受支持」的路径会从未被真正执行过。

// testKeyMaterial 返回一把自签名密钥、其证书与编码后的字节。
func testKeyMaterial(t *testing.T) (*rsa.PrivateKey, *x509.Certificate, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "apkguard test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("生成证书失败: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("解析证书失败: %v", err)
	}
	return key, cert, der
}

// TestLoadJKS 验证 JKS 密钥库的读取路径。
func TestLoadJKS(t *testing.T) {
	key, _, der := testKeyMaterial(t)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("编码私钥失败: %v", err)
	}

	ks := keystorego.New()
	entry := keystorego.PrivateKeyEntry{
		CreationTime: time.Now(),
		PrivateKey:   pkcs8,
		CertificateChain: []keystorego.Certificate{
			{Type: "X.509", Content: der},
		},
	}
	const alias = "mykey"
	const pass = "123456"
	if err := ks.SetPrivateKeyEntry(alias, entry, []byte(pass)); err != nil {
		t.Fatalf("写入 JKS 条目失败: %v", err)
	}
	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(pass)); err != nil {
		t.Fatalf("序列化 JKS 失败: %v", err)
	}
	if got := DetectType(buf.Bytes()); got != TypeJKS {
		t.Fatalf("生成的文件应被识别为 JKS，实际 %s", got)
	}

	path := filepath.Join(t.TempDir(), "real.jks")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("写出临时密钥库失败: %v", err)
	}

	m, err := Load(path, pass, pass, "", "")
	if err != nil {
		t.Fatalf("读取 JKS 失败: %v", err)
	}
	if m.Source != TypeJKS {
		t.Errorf("Source 应为 jks，实际 %s", m.Source)
	}
	if m.Alias != alias {
		t.Errorf("别名应为 %q，实际 %q（未指定别名时应取第一个私钥条目）", alias, m.Alias)
	}
	if m.Leaf() == nil {
		t.Fatal("未解析出叶子证书")
	}
	if m.Leaf().Subject.CommonName != "apkguard test" {
		t.Errorf("证书主题不符: %s", m.Leaf().Subject.CommonName)
	}

	// 指定别名同样应能命中；不存在的别名必须报错而不是静默换一个。
	if _, err := Load(path, pass, pass, "", alias); err != nil {
		t.Fatalf("按别名读取失败: %v", err)
	}
	if _, err := Load(path, pass, pass, "", "nope"); err == nil {
		t.Fatal("指定不存在的别名时应报错")
	}
	// 口令错误必须报错，不能退化成「随便找一个条目」。
	if _, err := Load(path, "wrong", "wrong", "", ""); err == nil {
		t.Fatal("口令错误时应报错")
	}
}

// TestLoadPKCS12 验证 PKCS12 密钥库的读取路径。
func TestLoadPKCS12(t *testing.T) {
	key, cert, _ := testKeyMaterial(t)
	const pass = "123456"
	blob, err := pkcs12.Modern.Encode(key, cert, nil, pass)
	if err != nil {
		t.Fatalf("生成 PKCS12 失败: %v", err)
	}
	if got := DetectType(blob); got != TypePKCS12 {
		t.Fatalf("生成的文件应被识别为 PKCS12，实际 %s", got)
	}

	path := filepath.Join(t.TempDir(), "test.pfx")
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatalf("写出临时密钥库失败: %v", err)
	}

	m, err := Load(path, pass, "", "", "")
	if err != nil {
		t.Fatalf("读取 PKCS12 失败: %v", err)
	}
	if m.Source != TypePKCS12 {
		t.Errorf("Source 应为 pkcs12，实际 %s", m.Source)
	}
	if m.Leaf() == nil || m.Leaf().Subject.CommonName != "apkguard test" {
		t.Fatalf("证书解析不符: %v", m.Leaf())
	}
	// PKCS12 没有别名概念，应为空——调用方据此决定是否展示别名。
	if m.Alias != "" {
		t.Errorf("PKCS12 不应报告别名，实际 %q", m.Alias)
	}
	if _, err := Load(path, "wrong", "", "", ""); err == nil {
		t.Fatal("口令错误时应报错")
	}
}

// TestDetectTypeByExt 验证按扩展名的类型推断。
func TestDetectTypeByExt(t *testing.T) {
	cases := map[string]string{
		"a.jks": TypeJKS, "a.keystore": TypeJKS,
		"a.pfx": TypePKCS12, "a.p12": TypePKCS12, "a.pkcs12": TypePKCS12,
		"a.apk": TypeUnknown,
	}
	for in, want := range cases {
		if got := DetectTypeByExt(in); got != want {
			t.Errorf("DetectTypeByExt(%q) = %s，期望 %s", in, got, want)
		}
	}
}
