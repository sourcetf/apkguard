package sign

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"strings"
	"testing"

	"apkguard/internal/zipx"
)

// 本文件用**独立实现**（不复用 sign 包内的 lp/seq/chunkedDigest）复核两件事：
//
//  1. v2 signer 的 signed_data.additional_attributes 里写入了防剥离属性
//     ID 0xBEEFF00D、值 3，且长度前缀编码符合 APK Signature Scheme v2 规范；
//  2. 签名块 4096 对齐：块长为 4096 倍数、块起点对齐、EOCD 记录的 CD 偏移
//     对齐，且 v2 内容摘要与 RSA 签名仍能按规范独立重算通过。

// ---- 独立解析工具（测试侧第二实现） ----

// rawLP 读取一个 uint32 小端长度前缀字段，返回其内容与下一偏移。
func rawLP(t *testing.T, b []byte, off int) ([]byte, int) {
	t.Helper()
	if off < 0 || off+4 > len(b) {
		t.Fatalf("长度前缀越界: off=%d len=%d", off, len(b))
	}
	n := int(binary.LittleEndian.Uint32(b[off:]))
	if off+4+n > len(b) {
		t.Fatalf("字段越界: off=%d n=%d len=%d", off, n, len(b))
	}
	return b[off+4 : off+4+n], off + 4 + n
}

type rawPair struct {
	id  uint32
	val []byte
}

// rawParseBlock 按签名块布局独立解析 ID-value 对。
//
// [u64 块长][u64 对长][u32 ID][值]... [u64 块长][16 字节 magic]
func rawParseBlock(t *testing.T, block []byte) []rawPair {
	t.Helper()
	if len(block) < 32 {
		t.Fatalf("签名块过短: %d", len(block))
	}
	first := binary.LittleEndian.Uint64(block)
	last := binary.LittleEndian.Uint64(block[len(block)-24:])
	if first != last || int(first) != len(block)-8 {
		t.Fatalf("签名块长度字段不自洽: first=%d last=%d len=%d", first, last, len(block))
	}
	if string(block[len(block)-16:]) != sigBlockMag {
		t.Fatal("签名块末尾不是 APK Sig Block 42 magic")
	}
	rest := block[8 : len(block)-24]
	var out []rawPair
	for len(rest) > 0 {
		if len(rest) < 12 {
			t.Fatalf("ID-value 对头部不完整: 剩 %d 字节", len(rest))
		}
		l := binary.LittleEndian.Uint64(rest)
		if l < 4 || int(l) > len(rest)-8 {
			t.Fatalf("ID-value 对长度非法: %d", l)
		}
		out = append(out, rawPair{
			id:  binary.LittleEndian.Uint32(rest[8:]),
			val: rest[12 : 8+l],
		})
		rest = rest[8+l:]
	}
	return out
}

func rawPairByID(t *testing.T, pairs []rawPair, id uint32) []byte {
	t.Helper()
	for _, p := range pairs {
		if p.id == id {
			return p.val
		}
	}
	t.Fatalf("签名块里没有 ID 0x%08x 的对", id)
	return nil
}

// rawChunkedSHA256 按 v2 规范独立实现分块内容摘要：
// 每 1 MiB 块为 H(0xa5 || u32(len) || chunk)，最终为 H(0x5a || u32(块数) || 各块摘要)。
func rawChunkedSHA256(sections ...[]byte) []byte {
	const chunk = 1 << 20
	var per [][]byte
	var n [4]byte
	for _, s := range sections {
		for off := 0; off < len(s); off += chunk {
			end := off + chunk
			if end > len(s) {
				end = len(s)
			}
			h := sha256.New()
			h.Write([]byte{0xa5})
			binary.LittleEndian.PutUint32(n[:], uint32(end-off))
			h.Write(n[:])
			h.Write(s[off:end])
			per = append(per, h.Sum(nil))
		}
	}
	h := sha256.New()
	h.Write([]byte{0x5a})
	binary.LittleEndian.PutUint32(n[:], uint32(len(per)))
	h.Write(n[:])
	for _, d := range per {
		h.Write(d)
	}
	return h.Sum(nil)
}

func rawAllZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// rawV2Signer 从 v2 块 value（长度前缀的 signer 序列）里取出第一个 signer。
func rawV2Signer(t *testing.T, v2val []byte) []byte {
	t.Helper()
	signerSeq, n := rawLP(t, v2val, 0)
	if n != len(v2val) {
		t.Fatalf("v2 块 value 尾部多出 %d 字节", len(v2val)-n)
	}
	signer, n := rawLP(t, signerSeq, 0)
	if n != len(signerSeq) {
		t.Fatalf("v2 应恰有一个 signer，尾部多出 %d 字节", len(signerSeq)-n)
	}
	return signer
}

// rawVerifyRSAPKCS1 独立验证 signed_data 上的 RSA PKCS1-SHA256 签名：
// 证书来自 certsField，公钥字节来自 signer，签名记录来自 sigsField。
// 返回签名算法 ID。
func rawVerifyRSAPKCS1(t *testing.T, signedData, sigsField, pubKey, certsField []byte) uint32 {
	t.Helper()
	certDER, _ := rawLP(t, certsField, 0)
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("解析证书失败: %v", err)
	}
	if !bytes.Equal(pubKey, cert.RawSubjectPublicKeyInfo) {
		t.Fatal("signer 内嵌公钥与证书 SPKI 不一致")
	}
	// 签名记录 = u32 算法 ID | lp(签名字节)，外面还套着 seq 的元素长度前缀。
	sigEntry, _ := rawLP(t, sigsField, 0)
	if len(sigEntry) < 8 {
		t.Fatalf("签名记录过短: %d", len(sigEntry))
	}
	sigAlgo := binary.LittleEndian.Uint32(sigEntry)
	if sigAlgo != AlgoRSAPKCS1SHA256 {
		t.Fatalf("测试应产出 RSA PKCS1-SHA256 签名（0x%04x），实际 0x%04x", AlgoRSAPKCS1SHA256, sigAlgo)
	}
	sig, n := rawLP(t, sigEntry, 4)
	if n != len(sigEntry) {
		t.Fatalf("签名记录尾部多出 %d 字节", len(sigEntry)-n)
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatal("证书公钥不是 RSA")
	}
	digestOfSigned := sha256.Sum256(signedData)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digestOfSigned[:], sig); err != nil {
		t.Fatalf("signed_data 上的 RSA 签名独立验证失败: %v", err)
	}
	return sigAlgo
}

// ---- 需求 1：防剥离属性 ----

// TestV2StrippingProtectionAttribute 独立解析 v2 的 signed_data，断言
// additional attributes 的字节布局，并用证书公钥独立验证 signed_data 上的
// RSA 签名与内容分块摘要（即属性写入后 v2 摘要/签名仍正确）。
func TestV2StrippingProtectionAttribute(t *testing.T) {
	mat := testMaterial(t, false)
	res, err := Sign(minimalAPK(t), mat, Options{
		V2: true, V3: true, MinSDK: 24, MaxSDK: 0x7fffffff,
	})
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	sec, err := zipx.Split(res.APK)
	if err != nil {
		t.Fatalf("切分归档失败: %v", err)
	}
	pairs := rawParseBlock(t, sec.SigningBlock)
	signer := rawV2Signer(t, rawPairByID(t, pairs, blockIDV2))

	// signer = lp(signed_data) | lp(signatures) | lp(public_key)
	signedData, off := rawLP(t, signer, 0)
	sigsField, off := rawLP(t, signer, off)
	pubKey, off := rawLP(t, signer, off)
	if off != len(signer) {
		t.Fatalf("v2 signer 尾部多出 %d 字节", len(signer)-off)
	}

	// signed_data = lp(digests) | lp(certificates) | lp(additional_attributes)
	digestsField, p := rawLP(t, signedData, 0)
	certsField, p := rawLP(t, signedData, p)
	attrFieldStart := p
	attrsField, p := rawLP(t, signedData, p)
	if p != len(signedData) {
		t.Fatalf("signed_data 尾部多出 %d 字节", len(signedData)-p)
	}

	// 属性段编码（apksig generateAdditionalAttributes + 外层 lp）：
	//   u32 12 = 属性列表长度     → 由 seq 的外层长度前缀提供
	//   u32  8 = 属性元素长度     → 元素自身的长度前缀
	//   u32 ID = 0xbeeff00d
	//   u32 值 = 3
	if got := binary.LittleEndian.Uint32(signedData[attrFieldStart:]); got != 12 {
		t.Fatalf("属性段外层长度前缀应为 12，实际 %d", got)
	}
	if len(attrsField) != 12 {
		t.Fatalf("属性元素列表应为 12 字节，实际 %d：%x", len(attrsField), attrsField)
	}
	entry, q := rawLP(t, attrsField, 0)
	if q != len(attrsField) {
		t.Fatalf("属性段应恰有一个元素，尾部多出 %d 字节", len(attrsField)-q)
	}
	if len(entry) != 8 {
		t.Fatalf("属性元素应为 8 字节（ID+值），实际 %d", len(entry))
	}
	wantAttr := []byte{8, 0, 0, 0, 0x0d, 0xf0, 0xef, 0xbe, 3, 0, 0, 0}
	if !bytes.Equal(attrsField, wantAttr) {
		t.Fatalf("additional attributes 字节布局不符：\n got  %x\n want %x", attrsField, wantAttr)
	}
	attrID := binary.LittleEndian.Uint32(entry[0:])
	attrVal := binary.LittleEndian.Uint32(entry[4:])
	if attrID != strippingProtectionAttrID {
		t.Fatalf("属性 ID 应为 0x%08x，实际 0x%08x", uint32(strippingProtectionAttrID), attrID)
	}
	if attrVal != schemeVersionV3 {
		t.Fatalf("属性值应为 %d（v3 方案号），实际 %d", schemeVersionV3, attrVal)
	}

	// 证书、内嵌公钥与 signed_data 上的签名独立验证。
	sigAlgo := rawVerifyRSAPKCS1(t, signedData, sigsField, pubKey, certsField)

	// 摘要记录按签名算法 ID 索引；独立重算内容摘要：数据区（含对齐补零）+
	// 中央目录 + EOCD（参与摘要时 CD 偏移 = 签名块起点）与产物逐字节一致。
	rec, _ := rawLP(t, digestsField, 0)
	if len(rec) < 8 {
		t.Fatalf("摘要记录过短: %d", len(rec))
	}
	if got := binary.LittleEndian.Uint32(rec); got != sigAlgo {
		t.Fatalf("摘要记录的算法 ID 0x%04x 与签名 0x%04x 不匹配", got, sigAlgo)
	}
	gotDigest, _ := rawLP(t, rec, 4)
	eocd := append([]byte(nil), sec.EOCD...)
	binary.LittleEndian.PutUint32(eocd[16:], uint32(len(sec.BeforeBlock)))
	wantDigest := rawChunkedSHA256(sec.BeforeBlock, sec.CentralDir, eocd)
	if !bytes.Equal(gotDigest, wantDigest) {
		t.Fatalf("v2 内容摘要不匹配（签名块/补零后摘要计算错误）：\n got  %x\n want %x", gotDigest, wantDigest)
	}

	t.Logf("v2 防剥离属性 0x%08x=%d 布局正确；RSA 签名与分块摘要独立复核通过",
		attrID, attrVal)
}

// TestV2AdditionalAttributesEmptyWithoutV3 钉住与 apksig 一致的边界：
// 只签 v2（不启用 v3）时属性段必须为空，否则引用了不存在的 v3 方案，
// 合规验证方会以 V2_SIG_MISSING_APK_SIG_REFERENCED 判包无效。
func TestV2AdditionalAttributesEmptyWithoutV3(t *testing.T) {
	mat := testMaterial(t, false)
	res, err := Sign(minimalAPK(t), mat, Options{V2: true, V3: false, MinSDK: 24})
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	sec, err := zipx.Split(res.APK)
	if err != nil {
		t.Fatalf("切分归档失败: %v", err)
	}
	pairs := rawParseBlock(t, sec.SigningBlock)
	for _, p := range pairs {
		if p.id == blockIDV3 {
			t.Fatal("未启用 v3 却出现了 v3 块")
		}
	}
	signer := rawV2Signer(t, rawPairByID(t, pairs, blockIDV2))
	signedData, _ := rawLP(t, signer, 0)
	_, p := rawLP(t, signedData, 0)
	_, p = rawLP(t, signedData, p)
	attrsField, p := rawLP(t, signedData, p)
	if p != len(signedData) {
		t.Fatalf("signed_data 尾部多出 %d 字节", len(signedData)-p)
	}
	if len(attrsField) != 0 {
		t.Fatalf("v2-only 时 additional attributes 应为空，实际 %x", attrsField)
	}
}

// ---- 需求 3：v2+v3-only 与 v3 SDK 区间（既有行为确认） ----

// TestV2V3OnlyOmitsV1Entries 确认 V1=false + V2/V3 时：
//   - 归档里没有任何 META-INF 签名条目（不产出 v1）；
//   - v3 signer 的 minSdk/maxSdk 与 Options 完全一致，且 v3 的 signed_data
//     上的 RSA 签名可独立验证（属性为空，与样本/apksig 一致）。
func TestV2V3OnlyOmitsV1Entries(t *testing.T) {
	mat := testMaterial(t, false)
	res, err := Sign(minimalAPK(t), mat, Options{V2: true, V3: true, MinSDK: 26, MaxSDK: 33})
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(res.APK), int64(len(res.APK)))
	if err != nil {
		t.Fatalf("读取产物归档失败: %v", err)
	}
	for _, f := range zr.File {
		if strings.HasPrefix(strings.ToUpper(f.Name), "META-INF/") {
			t.Errorf("V1=false 时不应有 META-INF 条目，实际存在 %s", f.Name)
		}
	}

	sec, err := zipx.Split(res.APK)
	if err != nil {
		t.Fatalf("切分归档失败: %v", err)
	}
	v3val := rawPairByID(t, rawParseBlock(t, sec.SigningBlock), blockIDV3)
	if m1, m2 := v3SignerRange(t, v3val); m1 != 26 || m2 != 33 {
		t.Fatalf("v3 SDK 区间应为 [26,33]，实际 [%d,%d]", m1, m2)
	}
	signer := rawV2Signer(t, v3val)
	signedData, off := rawLP(t, signer, 0)
	if off+8 > len(signer) {
		t.Fatal("v3 signer 缺少 minSdk/maxSdk 字段")
	}
	if m := binary.LittleEndian.Uint32(signer[off:]); m != 26 {
		t.Fatalf("v3 signer 内的 minSdk 应为 26，实际 %d", m)
	}
	if m := binary.LittleEndian.Uint32(signer[off+4:]); m != 33 {
		t.Fatalf("v3 signer 内的 maxSdk 应为 33，实际 %d", m)
	}
	off += 8
	sigsField, off := rawLP(t, signer, off)
	pubKey, off := rawLP(t, signer, off)
	if off != len(signer) {
		t.Fatalf("v3 signer 尾部多出 %d 字节", len(signer)-off)
	}
	// v3 signed_data = digests | certificates | minSdk | maxSdk | 空属性
	digestsField, p := rawLP(t, signedData, 0)
	if len(digestsField) == 0 {
		t.Fatal("v3 signed_data 缺少摘要记录")
	}
	certsField, p := rawLP(t, signedData, p)
	if p+8+4 != len(signedData) {
		t.Fatalf("v3 signed_data 在 SDK 字段与空属性前应剩 12 字节，实际剩 %d", len(signedData)-p)
	}
	attrsField, p := rawLP(t, signedData, p+8)
	if len(attrsField) != 0 || p != len(signedData) {
		t.Fatalf("v3 additional attributes 应为空，实际 %x（尾部多 %d 字节）", attrsField, len(signedData)-p)
	}
	rawVerifyRSAPKCS1(t, signedData, sigsField, pubKey, certsField)
	t.Log("V1=false 无 META-INF 条目；v3 区间与签名独立复核通过")
}

// ---- 需求 2：签名块 4KB 对齐 + verity padding ----

// TestSigningBlockPaddedTo4K 断言签名块与中央目录都落在 4096 边界，
// verity padding 对编码与 apksig 的补长规则一致。
func TestSigningBlockPaddedTo4K(t *testing.T) {
	const align = 4096
	cases := []struct {
		name string
		opts Options
	}{
		{"v2+v3", Options{V2: true, V3: true, MinSDK: 24, MaxSDK: 0x7fffffff}},
		{"v1+v2+v3", Options{V1: true, V2: true, V3: true, MinSDK: 24, MaxSDK: 0x7fffffff}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mat := testMaterial(t, false)
			res, err := Sign(minimalAPK(t), mat, tc.opts)
			if err != nil {
				t.Fatalf("签名失败: %v", err)
			}
			sec, err := zipx.Split(res.APK)
			if err != nil {
				t.Fatalf("切分归档失败: %v", err)
			}
			if !sec.HasSigningBlock() {
				t.Fatal("产物缺少签名块")
			}
			block, before := sec.SigningBlock, sec.BeforeBlock

			// ① 块长（含首尾长度字段与 magic）是 4096 的整数倍。
			if len(block)%align != 0 {
				t.Fatalf("签名块总长 %d 不是 %d 的倍数", len(block), align)
			}
			// ② 块起点 4096 对齐：数据区（含补零）长度为 4096 倍数。
			if len(before)%align != 0 {
				t.Fatalf("签名块起点 %d 未对齐到 %d", len(before), align)
			}
			// ③ EOCD 记录的 CD 偏移 4096 对齐，且等于实际中央目录位置。
			cdOff := int(binary.LittleEndian.Uint32(sec.EOCD[16:]))
			if cdOff%align != 0 {
				t.Fatalf("EOCD 中的 CD 偏移 %d 未对齐到 %d", cdOff, align)
			}
			if want := len(before) + len(block); cdOff != want {
				t.Fatalf("EOCD CD 偏移 %d 与块后真实位置 %d 不符", cdOff, want)
			}
			if actual := len(res.APK) - len(sec.EOCD) - len(sec.CentralDir); cdOff != actual {
				t.Fatalf("EOCD CD 偏移 %d 与中央目录实际起点 %d 不符", cdOff, actual)
			}

			// verity padding 对必须存在、值全零、尺寸恰为 apksig 规则算出的最小补长。
			pairs := rawParseBlock(t, block)
			pad := rawPairByID(t, pairs, blockIDPad)
			if !rawAllZero(pad) {
				t.Fatal("verity padding 对的值不是全零")
			}
			pairTotal := 8 + 4 + len(pad)
			// base = 去掉 padding 对后的完整块长（含首尾长度字段与 magic），
			// 即 assembleBlock 补长前看到的 resultSize。
			base := len(block) - pairTotal
			rem := base % align
			if rem == 0 {
				t.Fatalf("无需 padding 时不应写入 verity padding 对")
			}
			want := align - rem
			if want < 12 {
				want += align
			}
			if pairTotal != want {
				t.Fatalf("verity padding 对总长 %d，apksig 规则应为 %d", pairTotal, want)
			}
			t.Logf("%s: 块长=%d 块起点=%d CD偏移=%d padding对=%d(值%d字节)",
				tc.name, len(block), len(before), cdOff, pairTotal, len(pad))
		})
	}
}
