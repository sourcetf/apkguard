package sign

import (
	"bytes"
	"compress/flate"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"

	"apkguard/internal/zipx"
)

// OID 定义（PKCS#7 / CMS 相关）。
var (
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSHA256     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidRSA        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
)

// pkcs7ContentInfo 对应 ContentInfo 结构。
type pkcs7ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

// pkcs7SignedData 对应 SignedData 结构。
type pkcs7SignedData struct {
	Version          int
	DigestAlgorithms []pkcs7AlgorithmIdentifier `asn1:"set"`
	ContentInfo      pkcs7ContentInfo
	Certificates     asn1.RawValue     `asn1:"optional,tag:0"`
	SignerInfos      []pkcs7SignerInfo `asn1:"set"`
}

type pkcs7AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type pkcs7SignerInfo struct {
	Version             int
	IssuerAndSerial     pkcs7IssuerAndSerial
	DigestAlgorithm     pkcs7AlgorithmIdentifier
	DigestEncryptionAlg pkcs7AlgorithmIdentifier
	EncryptedDigest     []byte
}

// pkcs7IssuerAndSerial 对应 IssuerAndSerialNumber。
//
// SerialNumber 必须使用 *big.Int，才会被编码为 ASN.1 INTEGER；
// 若用 []byte 会被编码成 OCTET STRING，导致校验方解析失败。
type pkcs7IssuerAndSerial struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

// buildPKCS7 构造 JAR 签名所需的 PKCS#7 SignedData 结构（DER 编码）。
//
// 结构为：ContentInfo(SignedData) {
//
//	version, digestAlgorithms, contentInfo(data),
//	certificates, signerInfos }
func buildPKCS7(signature []byte, cert *x509.Certificate) ([]byte, error) {
	if cert == nil {
		return nil, fmt.Errorf("sign: 证书为空，无法构造 PKCS#7")
	}

	// 证书集合：用原始 DER 拼接后包进 [0] 隐式标签。
	var certsBuf bytes.Buffer
	certsBuf.Write(cert.Raw)
	certSet := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      certsBuf.Bytes(),
	}

	digestAlg := pkcs7AlgorithmIdentifier{Algorithm: oidSHA256}
	// RSA 的 AlgorithmIdentifier 参数必须是 NULL。
	rsaAlg := pkcs7AlgorithmIdentifier{
		Algorithm:  oidRSA,
		Parameters: asn1.RawValue{Tag: 5}, // NULL
	}

	signerInfo := pkcs7SignerInfo{
		Version: 1,
		IssuerAndSerial: pkcs7IssuerAndSerial{
			Issuer:       asn1.RawValue{FullBytes: cert.RawIssuer},
			SerialNumber: cert.SerialNumber,
		},
		DigestAlgorithm:     digestAlg,
		DigestEncryptionAlg: rsaAlg,
		EncryptedDigest:     signature,
	}

	sd := pkcs7SignedData{
		Version:          1,
		DigestAlgorithms: []pkcs7AlgorithmIdentifier{digestAlg},
		ContentInfo: pkcs7ContentInfo{
			ContentType: oidData,
		},
		Certificates: certSet,
		SignerInfos:  []pkcs7SignerInfo{signerInfo},
	}

	sdDER, err := asn1.Marshal(sd)
	if err != nil {
		return nil, fmt.Errorf("sign: 编码 SignedData 失败: %w", err)
	}

	outer := pkcs7ContentInfo{
		ContentType: oidSignedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      sdDER,
		},
	}
	return asn1.Marshal(outer)
}

// inflateEntry 取得条目的未压缩内容。
func inflateEntry(e *zipx.Entry) ([]byte, error) {
	switch e.Method {
	case 0:
		return e.Raw, nil
	case 8:
		r := flate.NewReader(bytes.NewReader(e.Raw))
		defer r.Close()
		out, err := io.ReadAll(r)
		if err != nil {
			return nil, fmt.Errorf("sign: 解压条目 %q 失败: %w", e.NameString(), err)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("sign: 条目 %q 使用了不支持的压缩方法 %d", e.NameString(), e.Method)
	}
}
