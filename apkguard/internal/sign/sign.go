// Package sign 实现 APK Signature Scheme v1/v2/v3/v4 签名。
//
// 全部为纯 Go 实现，不依赖 JDK、apksigner 或任何外部进程。
package sign

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
)

// 签名算法 ID（与 Android 平台定义一致）。
const (
	AlgoRSAPSSSHA256    = 0x0101
	AlgoRSAPSSSHA512    = 0x0102
	AlgoRSAPKCS1SHA256  = 0x0103
	AlgoRSAPKCS1SHA512  = 0x0104
	AlgoECDSASHA256     = 0x0201
	AlgoECDSASHA512     = 0x0202
	AlgoDSASHA256       = 0x0301
	AlgoVerityRSAPKCS1  = 0x0421
	AlgoVerityRSAPSS    = 0x0423
	AlgoVerityECDSASHA2 = 0x0425
)

// 签名块 ID。
const (
	blockIDV2   = 0x7109871a
	blockIDV3   = 0xf05368c0
	blockIDV31  = 0x1b93ad61
	blockIDPad  = 0x42726577 // verity padding（apksig VERITY_PADDING_BLOCK_ID）
	sigBlockMag = "APK Sig Block 42"
)

// v2 signed data 的防剥离（anti-stripping）附加属性。
//
// apksig 常量：V2SchemeConstants.STRIPPING_PROTECTION_ATTR_ID；值写
// ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V3（=3），语义是
// 「本包还必须带一个能通过校验的 v3 签名块」。平台验签 v2 时发现该属性，
// 但整个 APK 里找不到对应方案的签名块，就会以 V2_SIG_MISSING_APK_SIG_REFERENCED
// 拒绝，攻击者无法靠删掉 v3 块把包降级回 v2 验签。
//
// 注意：apksig 只在同时启用 v3 签名时才写该属性（generateAdditionalAttributes
// 的 v3SigningEnabled 参数）；只签 v2 时写空属性——否则没有 v3 块可供引用，
// 合规的验证方会直接判包无效。
const (
	strippingProtectionAttrID = 0xbeeff00d
	schemeVersionV3           = 3
)

// signingBlockAlign 是签名块与签名块起点的对齐粒度（4 KiB）。
//
// 与 apksig ANDROID_COMMON_PAGE_ALIGNMENT_BYTES 一致：数据区尾部补零使签名块
// 起点落在页边界，块内再用 verity padding 使块长为 4096 的整数倍；于是中央
// 目录与 EOCD 的偏移也落在页边界，便于 fs-verity（v4）按页校验与增量安装。
const signingBlockAlign = 1 << 12

// SDK 版本边界。
const (
	v3MinSDK = 24
	v3MaxSDK = 0x7fffffff
)

// chunkSize 是内容摘要的分块大小（1 MiB）。
const chunkSize = 1 << 20

var (
	ErrNoCert       = errors.New("sign: 证书链为空")
	ErrAlgoMismatch = errors.New("sign: 私钥类型与签名算法不匹配")
)

// signerAlgo 描述一次签名所用的算法组合。
type signerAlgo struct {
	// ID 是写入签名块的算法 ID。
	ID uint32
	// Hash 是内容摘要与签名所用的哈希。
	Hash crypto.Hash
	// sign 执行实际签名，返回签名字节。
	sign func(key crypto.PrivateKey, digest []byte) ([]byte, error)
}

// pickAlgo 依据私钥类型挑选默认签名算法。
func pickAlgo(key crypto.PrivateKey) (signerAlgo, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return signerAlgo{ID: AlgoRSAPKCS1SHA256, Hash: crypto.SHA256, sign: signRSA}, nil
	case *ecdsa.PrivateKey:
		_ = k
		return signerAlgo{ID: AlgoECDSASHA256, Hash: crypto.SHA256, sign: signECDSA}, nil
	default:
		return signerAlgo{}, fmt.Errorf("%w: %T", ErrAlgoMismatch, key)
	}
}

func signRSA(key crypto.PrivateKey, digest []byte) ([]byte, error) {
	k, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrAlgoMismatch
	}
	return rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, digest)
}

func signECDSA(key crypto.PrivateKey, digest []byte) ([]byte, error) {
	k, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, ErrAlgoMismatch
	}
	return ecdsa.SignASN1(rand.Reader, k, digest)
}

// chunkedDigest 按 Android 规范计算分块内容摘要。
//
// 每块摘要为 H(0xa5 || uint32(len(chunk)) || chunk)，
// 最终摘要为 H(0x5a || uint32(块数) || 各块摘要拼接)。
func chunkedDigest(sections [][]byte) []byte {
	var (
		chunkDigests [][]byte
		buf          [4]byte
	)
	emit := func(part []byte) {
		for off := 0; off < len(part); off += chunkSize {
			end := off + chunkSize
			if end > len(part) {
				end = len(part)
			}
			chunk := part[off:end]
			h := sha256.New()
			h.Write([]byte{0xa5})
			binary.LittleEndian.PutUint32(buf[:], uint32(len(chunk)))
			h.Write(buf[:])
			h.Write(chunk)
			chunkDigests = append(chunkDigests, h.Sum(nil))
		}
	}
	for _, s := range sections {
		emit(s)
	}

	top := sha256.New()
	top.Write([]byte{0x5a})
	binary.LittleEndian.PutUint32(buf[:], uint32(len(chunkDigests)))
	top.Write(buf[:])
	for _, d := range chunkDigests {
		top.Write(d)
	}
	return top.Sum(nil)
}

// ---- 长度前缀编码工具（APK 签名块全部使用 uint32 小端长度前缀）----

func lp(b []byte) []byte {
	out := make([]byte, 4+len(b))
	binary.LittleEndian.PutUint32(out, uint32(len(b)))
	copy(out[4:], b)
	return out
}

func seq(elems ...[]byte) []byte {
	var n int
	for _, e := range elems {
		n += 4 + len(e)
	}
	out := make([]byte, 0, 4+n)
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], uint32(n))
	out = append(out, hdr[:]...)
	for _, e := range elems {
		out = append(out, lp(e)...)
	}
	return out
}

// u32seq 编码「uint32 算法 ID + 长度前缀值」的序列。
func u32seq(id uint32, value []byte) []byte {
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], id)
	return seq(append(hdr[:], lp(value)...))
}

// sigPair 编码签名块中的一个 ID-value 对。
//
// 格式为：uint64 长度（含 4 字节 ID）+ uint32 ID + value。
func sigPair(id uint32, value []byte) []byte {
	var hdr [12]byte
	binary.LittleEndian.PutUint64(hdr[0:], uint64(4+len(value)))
	binary.LittleEndian.PutUint32(hdr[8:], id)
	return append(hdr[:], value...)
}

// buildSignerV2 构造一个 v2 signer 结构。
//
// v3Enabled 表示本次签名是否同时产出 v3 块：只有在「存在 v3 可供引用」时
// 才写入防剥离属性（见 strippingProtectionAttrID 的说明）。
func buildSignerV2(algo signerAlgo, key crypto.PrivateKey, certsDER [][]byte, contentDigest []byte, v3Enabled bool) ([]byte, error) {
	digests := u32seq(algo.ID, contentDigest)
	certSeq := seq(certsDER...)
	signedData := append(append(digests, certSeq...), v2AdditionalAttributes(v3Enabled)...)

	digestOfSigned, err := hashBytes(algo.Hash, signedData)
	if err != nil {
		return nil, err
	}
	sig, err := algo.sign(key, digestOfSigned)
	if err != nil {
		return nil, fmt.Errorf("sign: v2 签名失败: %w", err)
	}
	spki, err := marshalSPKI(key)
	if err != nil {
		return nil, err
	}
	return append(append(lp(signedData), u32seq(algo.ID, sig)...), lp(spki)...), nil
}

// v2AdditionalAttributes 编码 v2 signed data 的 additional attributes 段。
//
// 格式（apksig V2SchemeSigner.generateAdditionalAttributes，均为小端）：
//
//	u32 属性元素长度 = 8（ID 4 + 值 4）
//	u32 属性 ID = 0xbeeff00d
//	u32 值     = 3（v3 方案号）
//
// seq 再为整个属性列表补一层 u32 长度前缀（=12），因此 signed_data 中该段共
// 16 字节；未启用 v3 时为空序列（外层前缀 0），与 apksig 一致。
func v2AdditionalAttributes(v3Enabled bool) []byte {
	if !v3Enabled {
		return seq()
	}
	attr := make([]byte, 8)
	binary.LittleEndian.PutUint32(attr[0:], strippingProtectionAttrID)
	binary.LittleEndian.PutUint32(attr[4:], schemeVersionV3)
	return seq(attr)
}

// buildSignerV3 构造一个 v3 signer 结构。
func buildSignerV3(algo signerAlgo, key crypto.PrivateKey, certsDER [][]byte, contentDigest []byte, minSDK, maxSDK uint32) ([]byte, error) {
	digests := u32seq(algo.ID, contentDigest)
	certSeq := seq(certsDER...)

	var sdk [8]byte
	binary.LittleEndian.PutUint32(sdk[0:], minSDK)
	binary.LittleEndian.PutUint32(sdk[4:], maxSDK)

	// v3 的 signed data = digests | certificates | minSDK | maxSDK | additional attributes
	signedData := make([]byte, 0, len(digests)+len(certSeq)+8+4)
	signedData = append(signedData, digests...)
	signedData = append(signedData, certSeq...)
	signedData = append(signedData, sdk[:]...)
	signedData = append(signedData, seq()...)

	digestOfSigned, err := hashBytes(algo.Hash, signedData)
	if err != nil {
		return nil, err
	}
	sig, err := algo.sign(key, digestOfSigned)
	if err != nil {
		return nil, fmt.Errorf("sign: v3 签名失败: %w", err)
	}
	spki, err := marshalSPKI(key)
	if err != nil {
		return nil, err
	}

	// v3 signer = signed data | minSDK | maxSDK | signatures | public key
	out := make([]byte, 0, 64+len(signedData))
	out = append(out, lp(signedData)...)
	out = append(out, sdk[:]...)
	out = append(out, u32seq(algo.ID, sig)...)
	out = append(out, lp(spki)...)
	return out, nil
}

func hashBytes(h crypto.Hash, data []byte) ([]byte, error) {
	if !h.Available() {
		return nil, fmt.Errorf("sign: 哈希 %v 不可用", h)
	}
	hh := h.New()
	hh.Write(data)
	return hh.Sum(nil), nil
}

func marshalSPKI(key crypto.PrivateKey) ([]byte, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return x509.MarshalPKIXPublicKey(&k.PublicKey)
	case *ecdsa.PrivateKey:
		return x509.MarshalPKIXPublicKey(&k.PublicKey)
	default:
		return nil, fmt.Errorf("%w: %T", ErrAlgoMismatch, key)
	}
}

// ---- v4 (.idsig) 所需的 SHA-512 支持 ----

var _ = sha512.New
