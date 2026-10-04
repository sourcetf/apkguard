// Package keystore 提供 JKS 与 PKCS12(.pfx/.p12) 的统一读取接口，
// 输出统一的私钥 + 证书链表示，供签名模块使用。
package keystore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
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

// ---- 自签名证书身份生成（cmd/genkey 使用） ----

// 随机身份的候选表。
//
// 取值刻意保持「真实发布公司」的形态，且任何候选项都不得包含 apkguard /
// example / test / demo 字样：证书 DER 会被原样复制进每个已签名产物的
// v1 CERT.RSA 与 v2/v3/v4 签名块，主体一旦带产品名，整包字节就能被一条
// grep（或任何 YARA 规则）命中——审计实测旧主体在产物里出现 14 次。
var (
	// subjectCountries 候选国家代码（≥8 个）。
	subjectCountries = []string{"NO", "US", "DE", "NL", "SE", "SG", "IE", "CA", "GB", "FR"}
	// subjectStates 候选省/州名（≥6 个）。
	subjectStates = []string{
		"Massachusetts", "California", "Washington", "Ontario", "Bavaria",
		"Nordland", "Gauteng", "Victoria", "Utrecht", "Cork",
	}
	// subjectLocalities 候选城市名（≥6 个）。
	subjectLocalities = []string{
		"Dublin", "Boston", "San Jose", "Amsterdam", "Munich",
		"Oslo", "Toronto", "London", "Paris", "Sydney",
	}
	// subjectOrgNouns 公司名里的「名词」部分（≥10 个）。
	subjectOrgNouns = []string{
		"Harborlight", "Quietforge", "Northline", "Bluepeak", "Silverbrook",
		"Ironvale", "Clearpath", "Redwood", "Stonebridge", "Larkspur",
		"Westwind", "Amberfield",
	}
	// subjectOrgFields 公司名里的「行业词」部分（≥10 个）。
	subjectOrgFields = []string{
		"Digital", "Systems", "Software", "Technologies", "Labs",
		"Networks", "Solutions", "Analytics", "Media", "Works",
		"Computing", "Dynamics",
	}
	// subjectOUs 候选组织单元名。
	subjectOUs = []string{"Client", "Development", "Release", "Mobile", "Engineering"}
)

// randIndex 返回 [0, n) 内的均匀随机下标（crypto/rand）。
func randIndex(n int) (int, error) {
	if n <= 0 {
		return 0, errors.New("keystore: 随机候选表为空")
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0, err
	}
	return int(v.Int64()), nil
}

// RandomSubject 生成一个随机但形如真实发布身份的证书主体：
//
//	C/ST/L 各自从候选表随机取（不追求地理对应），O = 随机名词 + 随机行业词
//	（如 Quietforge Systems），OU 从 Client/Development/… 中随机取，
//	CN 是 8~20 个小写字母的随机串。
//
// 全部取值来自 crypto/rand，不提供确定性开关：证书身份不需要可复现（产物形态
// 的复现由 -seed 控制的命名族负责），而固定主体会让每个用户拿到同一张证书，
// 比随机更糟。唯一硬约束：任何字段都不得含 apkguard/example/test/demo 字样。
func RandomSubject() (pkix.Name, error) {
	var err error
	pick := func(vals []string) string {
		if err != nil {
			return ""
		}
		var i int
		i, err = randIndex(len(vals))
		if err != nil {
			return ""
		}
		return vals[i]
	}

	country := pick(subjectCountries)
	state := pick(subjectStates)
	locality := pick(subjectLocalities)
	noun := pick(subjectOrgNouns)
	field := pick(subjectOrgFields)
	ou := pick(subjectOUs)

	// CN：8~20 个小写字母。
	extra, cerr := randIndex(13) // 0..12
	if err == nil {
		err = cerr
	}
	cn := make([]byte, 0, 8+12)
	for i := 0; i < 8+extra && err == nil; i++ {
		var c int
		c, err = randIndex(26)
		if err != nil {
			break
		}
		cn = append(cn, byte('a'+c))
	}
	if err != nil {
		return pkix.Name{}, fmt.Errorf("keystore: 生成证书主体失败: %w", err)
	}

	return pkix.Name{
		Country:            []string{country},
		Province:           []string{state},
		Locality:           []string{locality},
		Organization:       []string{noun + " " + field},
		OrganizationalUnit: []string{ou},
		CommonName:         string(cn),
	}, nil
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
