package sign

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
)

// v1ManifestName 是 JAR 清单文件名。
const v1ManifestName = "META-INF/MANIFEST.MF"

// IsV1SignatureFile 判断条目是否属于 v1 签名产物（MANIFEST.MF 除外）。
func IsV1SignatureFile(name string) bool {
	upper := strings.ToUpper(name)
	if !strings.HasPrefix(upper, "META-INF/") {
		return false
	}
	if upper == "META-INF/MANIFEST.MF" {
		return false
	}
	rest := upper[len("META-INF/"):]
	if strings.Contains(rest, "/") {
		return false
	}
	switch {
	case strings.HasSuffix(rest, ".SF"),
		strings.HasSuffix(rest, ".RSA"),
		strings.HasSuffix(rest, ".DSA"),
		strings.HasSuffix(rest, ".EC"):
		return true
	}
	return false
}

// ManifestEntry 是参与 v1 签名的一个条目。
type ManifestEntry struct {
	// Name 是归档内的路径名。
	Name string
	// SHA256Base64 是该条目未压缩内容的 SHA-256 的 Base64 编码。
	SHA256Base64 string
}

// manifestSection 是清单中的一个条目区块。
type manifestSection struct {
	Name  string
	Bytes []byte
}

// BuildManifest 生成 MANIFEST.MF 内容。
//
// 按 JAR 规范：先写主属性区，再为每个条目写独立区块（区块间以空行分隔）。
func BuildManifest(entries []ManifestEntry, mainAttrs [][2]string) []byte {
	var b bytes.Buffer
	if len(mainAttrs) == 0 {
		mainAttrs = [][2]string{
			{"Manifest-Version", "1.0"},
			{"Created-By", "1.0 (Android)"},
		}
	}
	for _, kv := range mainAttrs {
		writeManifestAttr(&b, kv[0], kv[1])
	}
	b.WriteString("\r\n")

	sorted := make([]ManifestEntry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	for _, e := range sorted {
		writeManifestAttr(&b, "Name", e.Name)
		writeManifestAttr(&b, "SHA-256-Digest", e.SHA256Base64)
		b.WriteString("\r\n")
	}
	return b.Bytes()
}

// splitManifest 把清单拆分为主属性区与各条目区块。
//
// 摘要覆盖范围的边界依据 apksig 的实现（经 apksigner 实测校准）：
// 主属性区与条目区块都覆盖「正文 + CRLFCRLF」，即包含终止区块的空行。
func splitManifest(manifest []byte) (mainSection []byte, sections []manifestSection) {
	// 统一按 \n 切分，兼容仅使用 \r\n 或 \n 的输入。
	norm := bytes.ReplaceAll(manifest, []byte("\r\n"), []byte("\n"))
	parts := bytes.Split(norm, []byte("\n\n"))

	for i, p := range parts {
		if len(p) == 0 {
			continue
		}
		block := append(append([]byte(nil), bytes.ReplaceAll(p, []byte("\n"), []byte("\r\n"))...),
			'\r', '\n', '\r', '\n')

		if i == 0 {
			mainSection = block
			continue
		}
		if name, ok := attrValue(p, "Name"); ok {
			sections = append(sections, manifestSection{Name: name, Bytes: block})
		}
	}
	return mainSection, sections
}

// attrValue 从区块中取出指定属性的值。
func attrValue(block []byte, key string) (string, bool) {
	prefix := key + ": "
	lines := bytes.Split(block, []byte("\n"))
	for i := 0; i < len(lines); i++ {
		line := strings.TrimRight(string(lines[i]), "\r")
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		val := strings.TrimPrefix(line, prefix)
		// 拼接续行（以单个空格开头）。
		for i+1 < len(lines) {
			next := strings.TrimRight(string(lines[i+1]), "\r")
			if !strings.HasPrefix(next, " ") {
				break
			}
			val += strings.TrimPrefix(next, " ")
			i++
		}
		return val, true
	}
	return "", false
}

// writeManifestAttr 按 JAR 规范写入一个属性，超过 72 字节时折行。
func writeManifestAttr(b *bytes.Buffer, key, value string) {
	line := key + ": " + value
	const maxLine = 72
	if len(line) <= maxLine {
		b.WriteString(line)
		b.WriteString("\r\n")
		return
	}
	b.WriteString(line[:maxLine])
	b.WriteString("\r\n")
	rest := line[maxLine:]
	for len(rest) > maxLine-1 {
		b.WriteString(" ")
		b.WriteString(rest[:maxLine-1])
		b.WriteString("\r\n")
		rest = rest[maxLine-1:]
	}
	if len(rest) > 0 {
		b.WriteString(" ")
		b.WriteString(rest)
		b.WriteString("\r\n")
	}
}

// BuildSF 生成 .SF 文件内容。
//
// extra 用于写入 X-Android-APK-Signed 属性（如 "2, 3"），
// 声明该 APK 同时使用了哪些 v2+ 方案；传空串则不写该属性。
//
// 结构：
//
//	Signature-Version / Created-By
//	SHA-256-Digest-Manifest               （整份 MANIFEST.MF 的摘要）
//	SHA-256-Digest-Manifest-Main-Attributes（主属性区的摘要）
//	每个条目：Name + SHA-256-Digest        （该条目区块的摘要）
func BuildSF(manifest []byte, extra string) []byte {
	mainSection, sections := splitManifest(manifest)

	var b bytes.Buffer
	writeManifestAttr(&b, "Signature-Version", "1.0")
	writeManifestAttr(&b, "Created-By", "1.0 (Android)")

	sum := sha256.Sum256(manifest)
	writeManifestAttr(&b, "SHA-256-Digest-Manifest", base64.StdEncoding.EncodeToString(sum[:]))

	if len(mainSection) > 0 {
		ms := sha256.Sum256(mainSection)
		writeManifestAttr(&b, "SHA-256-Digest-Manifest-Main-Attributes",
			base64.StdEncoding.EncodeToString(ms[:]))
	}
	// 声明本 APK 同时使用了 v2/v3 方案，与 Android 平台约定一致。
	if extra != "" {
		writeManifestAttr(&b, "X-Android-APK-Signed", extra)
	}
	b.WriteString("\r\n")

	for _, s := range sections {
		writeManifestAttr(&b, "Name", s.Name)
		d := sha256.Sum256(s.Bytes)
		writeManifestAttr(&b, "SHA-256-Digest", base64.StdEncoding.EncodeToString(d[:]))
		b.WriteString("\r\n")
	}
	return b.Bytes()
}

// SignSF 用私钥对 .SF 文件签名，生成 PKCS#7 签名数据。
func SignSF(sf []byte, key crypto.PrivateKey) ([]byte, error) {
	digest := sha256.Sum256(sf)
	switch k := key.(type) {
	case *rsa.PrivateKey:
		sig, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, digest[:])
		if err != nil {
			return nil, fmt.Errorf("sign: v1 签名失败: %w", err)
		}
		return sig, nil
	default:
		return nil, fmt.Errorf("sign: v1 目前仅支持 RSA 私钥，当前为 %T", key)
	}
}

// CertBase64 返回证书的 Base64 编码，便于调试输出。
func CertBase64(cert *x509.Certificate) string {
	return base64.StdEncoding.EncodeToString(cert.Raw)
}
