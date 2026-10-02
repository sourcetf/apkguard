// Command genkey 生成一张自签名测试密钥库（PKCS12），用于加固产物的签名与装机实测。
//
// 为什么需要它：本项目的端到端脚本用 `keytool`（JDK）生成测试密钥库，但
// 「加固 + 装机」这条链路本身并不需要 JDK——签名与对齐都由本工具自己完成。
// 在没装 JDK 的机器上（例如只用 Windows 侧 Go 交叉编译、在 WSL 里跑 adb 的场景），
// 这个小工具就是生成密钥库的唯一途径，从而让实测流程不依赖 JDK。
//
// 用法：
//
//	go run ./cmd/genkey /tmp/test.p12 apkguard
//	apkguard -in app.apk -ks /tmp/test.p12 -ks-pass apkguard ...
//
// 注意：这是**测试用**密钥，只应用于本地验证，不要用于发布。
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "用法: genkey <out.p12> <password>")
		os.Exit(2)
	}
	out, pass := os.Args[1], os.Args[2]

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Fprintln(os.Stderr, "生成密钥失败:", err)
		os.Exit(1)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "apkguard test", Organization: []string{"apkguard"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(30, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		fmt.Fprintln(os.Stderr, "生成证书失败:", err)
		os.Exit(1)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		fmt.Fprintln(os.Stderr, "解析证书失败:", err)
		os.Exit(1)
	}
	blob, err := pkcs12.Modern.Encode(key, cert, nil, pass)
	if err != nil {
		fmt.Fprintln(os.Stderr, "编码 PKCS12 失败:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(out, blob, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "写入失败:", err)
		os.Exit(1)
	}
	fmt.Printf("已生成 %s（%d 字节，测试用密钥）\n", out, len(blob))
}
