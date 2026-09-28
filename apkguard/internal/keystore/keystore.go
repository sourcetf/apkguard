// Package keystore 提供 JKS 与 PKCS12(.pfx/.p12) 的统一读取接口，
// 输出统一的私钥 + 证书链表示，供签名模块使用。
package keystore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	keystorego "github.com/pavlo-v-chernykh/keystore-go/v4"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// 支持的类型标识。
const (
	TypeJKS     = "jks"
	TypePKCS12  = "pkcs12"
	TypeUnknown = "unknown"
)

var (
	ErrUnsupportedKey = errors.New("keystore: 不支持的私钥类型（仅支持 RSA / ECDSA）")
	ErrNoPrivateKey   = errors.New("keystore: 未找到私钥条目")
)

// Material 是从密钥库中提取出的签名材料。
type Material struct {
	// PrivateKey 是解析后的私钥（*rsa.PrivateKey 或 *ecdsa.PrivateKey）。
	PrivateKey crypto.PrivateKey
	// CertChain 是证书链，CertChain[0] 为签名证书（叶子证书）。
	CertChain []*x509.Certificate
	// Source 记录来源类型（jks / pkcs12）。
	Source string
	// Alias 是命中的条目别名（JKS 有意义）。
	Alias string
}

// Leaf 返回叶子证书，不存在时返回 nil。
func (m *Material) Leaf() *x509.Certificate {
	if len(m.CertChain) == 0 {
		return nil
	}
	return m.CertChain[0]
}

// DetectType 依据文件内容判断密钥库类型。
//
// JKS 以 0xFEEDFEED 魔数开头；PKCS12 是 ASN.1 DER，以 SEQUENCE 标签 0x30 开头。
func DetectType(data []byte) string {
	if len(data) >= 4 && data[0] == 0xFE && data[1] == 0xED && data[2] == 0xFE && data[3] == 0xED {
		return TypeJKS
	}
	if len(data) >= 1 && data[0] == 0x30 {
		return TypePKCS12
	}
	return TypeUnknown
}

// DetectTypeByExt 依据扩展名判断密钥库类型。
func DetectTypeByExt(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".jks", ".keystore":
		return TypeJKS
	case ".pfx", ".p12", ".pkcs12":
		return TypePKCS12
	}
	return TypeUnknown
}

// Load 读取密钥库并提取签名材料。
//
// storeType 为 "jks" / "pkcs12" / ""（自动探测）；
// keyPassword 为空时回退使用 storePassword（PKCS12 与 JKS 常见同口令）。
func Load(path string, storePassword, keyPassword, storeType, alias string) (*Material, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("keystore: 读取文件失败: %w", err)
	}
	if storeType == "" {
		storeType = DetectType(data)
		if storeType == TypeUnknown {
			storeType = DetectTypeByExt(path)
		}
	}
	if keyPassword == "" {
		keyPassword = storePassword
	}

	switch storeType {
	case TypeJKS:
		return loadJKS(data, storePassword, keyPassword, alias)
	case TypePKCS12:
		return loadPKCS12(data, storePassword, keyPassword)
	default:
		return nil, fmt.Errorf("keystore: 无法识别密钥库类型 (%s)", path)
	}
}

func loadJKS(data []byte, storePassword, keyPassword, alias string) (*Material, error) {
	ks := keystorego.New(keystorego.WithCaseExactAliases())
	if err := ks.Load(strings.NewReader(string(data)), []byte(storePassword)); err != nil {
		return nil, fmt.Errorf("keystore: 解析 JKS 失败（口令是否正确？）: %w", err)
	}

	aliases := ks.Aliases()
	target := ""
	if alias != "" {
		for _, a := range aliases {
			if a == alias {
				target = a
				break
			}
		}
		if target == "" {
			return nil, fmt.Errorf("keystore: JKS 中不存在别名 %q", alias)
		}
	} else {
		for _, a := range aliases {
			if ks.IsPrivateKeyEntry(a) {
				target = a
				break
			}
		}
		if target == "" {
			return nil, ErrNoPrivateKey
		}
	}

	entry, err := ks.GetPrivateKeyEntry(target, []byte(keyPassword))
	if err != nil {
		return nil, fmt.Errorf("keystore: 读取 JKS 私钥失败（key 口令是否正确？）: %w", err)
	}

	key, err := parsePKCS8(entry.PrivateKey)
	if err != nil {
		return nil, err
	}

	chain := make([]*x509.Certificate, 0, len(entry.CertificateChain))
	for _, c := range entry.CertificateChain {
		cert, err := x509.ParseCertificate(c.Content)
		if err != nil {
			return nil, fmt.Errorf("keystore: 解析 JKS 证书失败: %w", err)
		}
		chain = append(chain, cert)
	}
	if len(chain) == 0 {
		return nil, errors.New("keystore: JKS 条目不含证书")
	}

	return &Material{PrivateKey: key, CertChain: chain, Source: TypeJKS, Alias: target}, nil
}

func loadPKCS12(data []byte, storePassword, keyPassword string) (*Material, error) {
	key, cert, cas, err := pkcs12.DecodeChain(data, storePassword)
	if err != nil {
		// 尝试用 key 口令再解一次，覆盖 store/key 口令分离的场景。
		if keyPassword != storePassword {
			key, cert, cas, err = pkcs12.DecodeChain(data, keyPassword)
		}
		if err != nil {
			return nil, fmt.Errorf("keystore: 解析 PKCS12 失败（口令是否正确？）: %w", err)
		}
	}
	if cert == nil {
		return nil, errors.New("keystore: PKCS12 不含证书")
	}

	chain := append([]*x509.Certificate{cert}, cas...)
	return &Material{PrivateKey: key, CertChain: chain, Source: TypePKCS12}, nil
}

// parsePKCS8 解析 PKCS#8 私钥；失败时回退尝试 PKCS#1（部分 JKS 工具链会写入）。
func parsePKCS8(der []byte) (crypto.PrivateKey, error) {
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch k.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return k, nil
		default:
			return nil, ErrUnsupportedKey
		}
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	return nil, ErrUnsupportedKey
}

// ToPEM 把签名材料导出为 PEM 块，便于调试与人工核对。
func (m *Material) ToPEM() ([]byte, error) {
	var out []byte
	der, err := x509.MarshalPKCS8PrivateKey(m.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("keystore: 导出私钥失败: %w", err)
	}
	out = append(out, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})...)
	for _, c := range m.CertChain {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return out, nil
}
