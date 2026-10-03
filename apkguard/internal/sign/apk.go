package sign

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"apkguard/internal/keystore"
	"apkguard/internal/zipx"
)

// Options 控制签名方案与参数。
type Options struct {
	// V1 启用 JAR 签名。
	V1 bool
	// V2 启用 APK Signature Scheme v2。
	V2 bool
	// V3 启用 APK Signature Scheme v3。
	V3 bool
	// V4 生成 .idsig 文件（需同时启用 V2 或 V3）。
	V4 bool

	// MinSDK / MaxSDK 写入 v3 签名块，用于平台版本区间判定。
	MinSDK uint32
	MaxSDK uint32

	// Stamp 是新增 v1 签名条目（MANIFEST.MF / CERT.SF / CERT.RSA）使用的时间戳。
	//
	// 这三个条目是签名阶段才追加的，晚于 A14 元数据统一化；若不显式给它们
	// 同一个时间，它们会退回 ZIP 的 1980 默认值，产物里就出现「唯独签名文件
	// 是 1980」这一枚独有指纹，与 A14 消除重打包痕迹的目的背道而驰。
	// 零值表示沿用 1980 默认（即不做统一，用于不关心元数据的调用方）。
	Stamp time.Time

	// Align 是 v1 重写归档时使用的对齐参数。
	//
	// v1 会新增条目并重写归档，若在此处硬编码 DefaultAlign，则调用方即使
	// 关闭了 E2（zipalign）也会被强制对齐——E2 的开关因此形同虚设。
	// 零值表示使用 zipx.DefaultAlign()；调用方应把当前实际使用的对齐参数
	// 传进来（例如 E2 关闭时的 Align:1, SoAlign:1）。
	Align zipx.AlignOptions
}

// DefaultOptions 返回与 apksigner 默认行为接近的配置。
func DefaultOptions() Options {
	return Options{
		V1:     true,
		V2:     true,
		V3:     true,
		V4:     false,
		MinSDK: v3MinSDK,
		MaxSDK: v3MaxSDK,
	}
}

// Result 是签名产物。
type Result struct {
	// APK 是签名后的归档数据。
	APK []byte
	// IDSig 是 v4 签名文件内容，未启用时为 nil。
	IDSig []byte
	// Schemes 记录实际启用的方案。
	Schemes []string
}

// Sign 对已对齐的 APK 数据执行签名。
//
// 输入应为「已移除旧签名块」的归档；本函数会重新计算摘要并写入新签名块。
func Sign(apk []byte, mat *keystore.Material, opts Options) (*Result, error) {
	if mat == nil || mat.PrivateKey == nil {
		return nil, fmt.Errorf("sign: 签名材料为空")
	}
	if len(mat.CertChain) == 0 {
		return nil, ErrNoCert
	}
	leaf := mat.CertChain[0]

	// 1) v1：改写 MANIFEST.MF 并加入 .SF / .RSA 条目。
	//    v1 会改变归档内容，因此必须在计算 v2/v3 摘要之前完成。
	if opts.V1 {
		var err error
		apk, err = applyV1(apk, mat, leaf, opts)
		if err != nil {
			return nil, err
		}
	}

	// 2) v2/v3：在中央目录之前插入签名块。
	res := &Result{}
	var contentDigest []byte
	if opts.V2 || opts.V3 {
		algo, err := pickAlgo(mat.PrivateKey)
		if err != nil {
			return nil, err
		}

		sec, err := zipx.Split(apk)
		if err != nil {
			return nil, fmt.Errorf("sign: 切分归档失败: %w", err)
		}

		certsDER := make([][]byte, 0, len(mat.CertChain))
		for _, c := range mat.CertChain {
			certsDER = append(certsDER, c.Raw)
		}

		// 内容摘要覆盖三段：条目数据区、中央目录、EOCD。
		// 依据规范，摘要计算时 EOCD 的「中央目录偏移」字段应取「真实中央目录位置」
		// 在插入签名块之前的原值，即签名块起点。
		eocd := make([]byte, len(sec.EOCD))
		copy(eocd, sec.EOCD)
		binary.LittleEndian.PutUint32(eocd[16:], uint32(len(sec.BeforeBlock)))

		contentDigest = chunkedDigest([][]byte{sec.BeforeBlock, sec.CentralDir, eocd})

		var body []byte
		var schemes []string

		if opts.V2 {
			signer, err := buildSignerV2(algo, mat.PrivateKey, certsDER, contentDigest)
			if err != nil {
				return nil, err
			}
			body = append(body, sigPair(blockIDV2, seq(signer))...)
			schemes = append(schemes, "v2")
		}
		if opts.V3 {
			signer, err := buildSignerV3(algo, mat.PrivateKey, certsDER, contentDigest, opts.MinSDK, opts.MaxSDK)
			if err != nil {
				return nil, err
			}
			body = append(body, sigPair(blockIDV3, seq(signer))...)
			schemes = append(schemes, "v3")
		}

		block := assembleBlock(body)

		// 写出时 EOCD 的「中央目录偏移」指向签名块之后的真实中央目录位置。
		outEOCD := make([]byte, len(sec.EOCD))
		copy(outEOCD, sec.EOCD)
		binary.LittleEndian.PutUint32(outEOCD[16:], uint32(len(sec.BeforeBlock)+len(block)))

		out := make([]byte, 0, len(sec.BeforeBlock)+len(block)+len(sec.CentralDir)+len(outEOCD))
		out = append(out, sec.BeforeBlock...)
		out = append(out, block...)
		out = append(out, sec.CentralDir...)
		out = append(out, outEOCD...)
		apk = out
		res.Schemes = schemes
	}

	if opts.V1 {
		res.Schemes = append([]string{"v1"}, res.Schemes...)
	}
	res.APK = apk

	// 3) v4：基于 v2/v3 的内容摘要生成 .idsig。
	//    v4 的 apk_digest 必须与 v2/v3 签名块中的内容摘要一致，否则平台会判定不匹配。
	if opts.V4 {
		if !opts.V2 && !opts.V3 {
			return nil, fmt.Errorf("sign: v4 需要同时启用 v2 或 v3")
		}
		idsig, err := buildIDSig(apk, mat, contentDigest)
		if err != nil {
			return nil, err
		}
		res.IDSig = idsig
		res.Schemes = append(res.Schemes, "v4")
	}
	return res, nil
}

// assembleBlock 把若干 ID-value 对包装成完整的 APK 签名块。
//
// 布局：uint64(块长) | 各 ID-value 对 | uint64(块长) | "APK Sig Block 42"
// 其中块长字段的值等于「各 ID-value 对长度 + 8 + 16」，两侧一致。
func assembleBlock(body []byte) []byte {
	blockLen := uint64(len(body) + 8 + len(sigBlockMag))
	out := make([]byte, 0, 8+len(body)+8+len(sigBlockMag))
	var hdr [8]byte
	binary.LittleEndian.PutUint64(hdr[:], blockLen)
	out = append(out, hdr[:]...)
	out = append(out, body...)
	binary.LittleEndian.PutUint64(hdr[:], blockLen)
	out = append(out, hdr[:]...)
	out = append(out, sigBlockMag...)
	return out
}

// applyV1 为归档生成 JAR 签名条目。
func applyV1(apk []byte, mat *keystore.Material, leaf *x509.Certificate, opts Options) ([]byte, error) {
	archive, err := zipx.Read(apk)
	if err != nil {
		return nil, fmt.Errorf("sign: 解析归档失败: %w", err)
	}

	// 移除旧签名文件，避免与本次签名冲突。
	kept := archive.Entries[:0]
	for _, e := range archive.Entries {
		if IsV1SignatureFile(e.NameString()) {
			continue
		}
		kept = append(kept, e)
	}
	archive.Entries = kept

	// 收集参与签名的条目摘要（未压缩内容）。
	entries := make([]ManifestEntry, 0, len(archive.Entries))
	for _, e := range archive.Entries {
		if e.IsDir() {
			continue
		}
		name := e.NameString()
		if name == v1ManifestName {
			continue
		}
		content, err := inflateEntry(e)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(content)
		entries = append(entries, ManifestEntry{
			Name:         name,
			SHA256Base64: b64(sum[:]),
		})
	}

	manifest := BuildManifest(entries, nil)
	// 若同时启用 v2/v3，在 .SF 中声明，便于平台优先使用新方案。
	var extra string
	if opts.V2 || opts.V3 {
		var parts []string
		if opts.V2 {
			parts = append(parts, "2")
		}
		if opts.V3 {
			parts = append(parts, "3")
		}
		extra = strings.Join(parts, ", ")
	}
	sf := BuildSF(manifest, extra)
	sig, err := SignSF(sf, mat.PrivateKey)
	if err != nil {
		return nil, err
	}

	// 按 JAR 规范，.RSA 块是 PKCS#7 签名。此处写入简化的 DER 结构，
	// 其中包含签名与证书，供校验方按 JAR 规则解析。
	pkcs7, err := buildPKCS7(sig, leaf)
	if err != nil {
		return nil, err
	}

	// 先移除可能存在的旧 MANIFEST.MF，再按 JAR 规范顺序重排：
	// MANIFEST.MF 必须位于归档最前，随后是业务条目，最后是 .SF / .RSA。
	// 这三个新增条目沿用调用方给定的统一时间戳，避免成为产物里仅存的
	// 1980 默认值（详见 Options.Stamp 的说明）。
	stampTime, stampDate := uint16(0), uint16(0x21)
	if !opts.Stamp.IsZero() {
		stampTime, stampDate = zipx.DOSDateTime(opts.Stamp)
	}
	archive.Remove(v1ManifestName)
	ordered := make([]*zipx.Entry, 0, len(archive.Entries)+3)
	ordered = append(ordered, zipx.NewStoredAt(v1ManifestName, manifest, stampTime, stampDate))
	ordered = append(ordered, archive.Entries...)
	ordered = append(ordered,
		zipx.NewStoredAt("META-INF/CERT.SF", sf, stampTime, stampDate),
		zipx.NewStoredAt("META-INF/CERT.RSA", pkcs7, stampTime, stampDate),
	)
	archive.Entries = ordered

	// 沿用调用方当前实际使用的对齐参数，而不是硬编码 DefaultAlign：
	// 否则 E2（zipalign）被关闭时，v1 仍会强制重排对齐，开关失去意义。
	// 零值表示调用方未指定，按默认对齐处理。
	align := opts.Align
	if align == (zipx.AlignOptions{}) {
		align = zipx.DefaultAlign()
	}
	return zipx.WriteChecked(archive, align)
}

func b64(b []byte) string {
	const table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var out []byte
	for i := 0; i < len(b); i += 3 {
		var n uint32
		rem := len(b) - i
		n = uint32(b[i]) << 16
		if rem > 1 {
			n |= uint32(b[i+1]) << 8
		}
		if rem > 2 {
			n |= uint32(b[i+2])
		}
		out = append(out, table[(n>>18)&0x3f], table[(n>>12)&0x3f])
		if rem > 1 {
			out = append(out, table[(n>>6)&0x3f])
		} else {
			out = append(out, '=')
		}
		if rem > 2 {
			out = append(out, table[n&0x3f])
		} else {
			out = append(out, '=')
		}
	}
	return string(out)
}
