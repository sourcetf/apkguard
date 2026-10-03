package sign

import (
	"archive/zip"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"

	"apkguard/internal/keystore"
	"apkguard/internal/zipx"
)

// ---- 测试素材 ----

// testMaterial 生成一张自签证书并返回签名用的密钥材料。
func testMaterial(t *testing.T, ec bool) *keystore.Material {
	t.Helper()
	var priv any
	var pub any
	if ec {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("生成 EC 密钥失败: %v", err)
		}
		priv, pub = k, &k.PublicKey
	} else {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("生成 RSA 密钥失败: %v", err)
		}
		priv, pub = k, &k.PublicKey
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "apkguard sign test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("自签证书失败: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("解析证书失败: %v", err)
	}
	return &keystore.Material{
		PrivateKey: priv,
		CertChain:  []*x509.Certificate{cert},
		Source:     "test",
		Alias:      "test",
	}
}

// minimalAPK 造一个结构最小的合法 ZIP（签名只关心归档字节，不关心 APK 语义）。
func minimalAPK(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range []struct{ name, data string }{
		{"AndroidManifest.xml", "manifest-bytes"},
		{"classes.dex", strings.Repeat("dex-byte-", 200)},
		{"resources.arsc", "arsc"},
	} {
		w, err := zw.Create(e.name)
		if err != nil {
			t.Fatalf("写条目失败: %v", err)
		}
		if _, err := w.Write([]byte(e.data)); err != nil {
			t.Fatalf("写条目失败: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("关闭归档失败: %v", err)
	}
	return buf.Bytes()
}

// ---- v2/v3 结构 ----

// signingPairs 解析 APK 签名块的 id-value 对。
func signingPairs(t *testing.T, block []byte) map[uint32][]byte {
	t.Helper()
	if len(block) < 32 {
		t.Fatalf("签名块过短: %d 字节", len(block))
	}
	// 结构：[u64 总长][id-value 对...][u64 总长][16 字节 magik]
	pairs := block[8 : len(block)-24]
	out := map[uint32][]byte{}
	for len(pairs) > 0 {
		if len(pairs) < 12 {
			t.Fatalf("签名块对长度不足: %d", len(pairs))
		}
		l := binary.LittleEndian.Uint64(pairs)
		if l < 4 || int(l) > len(pairs) {
			t.Fatalf("签名块对长度非法: %d", l)
		}
		id := binary.LittleEndian.Uint32(pairs[8:])
		out[id] = pairs[12 : 8+l]
		pairs = pairs[8+l:]
	}
	return out
}

// v3SignerRange 从 v3 块里取出第一个 signer 声明的 SDK 区间。
//
// 布局：value = [u32 signers 总长][signer...]；signer = [u32 总长][signed data][u32 minSdk][u32 maxSdk]...
func v3SignerRange(t *testing.T, v3 []byte) (uint32, uint32) {
	t.Helper()
	if len(v3) < 12 {
		t.Fatalf("v3 块过短: %d", len(v3))
	}
	// v3[0:4] 是 signers 列表总长；v3[4:8] 是第一个 signer 的长度；
	// signed data 从 v3[8] 开始，自身也带长度前缀。
	signedDataLen := int(binary.LittleEndian.Uint32(v3[8:]))
	off := 8 + 4 + signedDataLen
	if off+8 > len(v3) {
		t.Fatalf("v3 signer 长度越界（signedDataLen=%d 总长=%d）", signedDataLen, len(v3))
	}
	return binary.LittleEndian.Uint32(v3[off:]), binary.LittleEndian.Uint32(v3[off+4:])
}

// TestSignV2V3BlockStructure 校验 v2/v3 签名块的基本结构与声明的 SDK 区间。
func TestSignV2V3BlockStructure(t *testing.T) {
	const apkID, v3ID = 0x7109871a, 0xf05368c0
	mat := testMaterial(t, false)
	res, err := Sign(minimalAPK(t), mat, Options{V2: true, V3: true, MinSDK: 24, MaxSDK: 0x7fffffff})
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	sec, err := zipx.Split(res.APK)
	if err != nil {
		t.Fatalf("切分归档失败: %v", err)
	}
	if !sec.HasSigningBlock() {
		t.Fatal("产物里没有 APK 签名块")
	}
	pairs := signingPairs(t, sec.SigningBlock)
	if _, ok := pairs[apkID]; !ok {
		t.Fatalf("缺少 v2 块（0x%08x）：%v", apkID, keysOf(pairs))
	}
	v3, ok := pairs[v3ID]
	if !ok {
		t.Fatalf("缺少 v3 块（0x%08x）：%v", v3ID, keysOf(pairs))
	}
	min, max := v3SignerRange(t, v3)
	if min != 24 || max != 0x7fffffff {
		t.Fatalf("v3 signer 声明的区间应为 [24, 0x7fffffff]，实际 [%d, %d]", min, max)
	}
	t.Logf("v2/v3 结构正确，v3 区间 = [%d, %d]", min, max)

	// 区间参数必须真的生效（否则平台会跳过该 signer，见 sink 里的注释）
	res2, err := Sign(minimalAPK(t), mat, Options{V2: true, V3: true, MinSDK: 30, MaxSDK: 31})
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	sec2, err2 := zipx.Split(res2.APK)
	if err2 != nil {
		t.Fatalf("切分归档失败: %v", err2)
	}
	v3b := signingPairs(t, sec2.SigningBlock)[v3ID]
	if m1, m2 := v3SignerRange(t, v3b); m1 != 30 || m2 != 31 {
		t.Fatalf("区间参数未生效：期望 [30,31]，实际 [%d,%d]", m1, m2)
	}
}

// ---- v1（JAR 签名） ----

// TestSignV1ManifestDigests 独立复核 v1 的 MANIFEST.MF 摘要。
//
// 判据不看我们自己的代码，而是按 JAR 规范重新算一遍：把 MANIFEST.MF 里声明的
// 每个条目的 SHA-256 与条目**实际字节**比对。写错摘要的 v1 签名在旧系统上
// 会校验失败（而新系统走 v2/v3，本地根本发现不了）。
func TestSignV1ManifestDigests(t *testing.T) {
	mat := testMaterial(t, false)
	res, err := Sign(minimalAPK(t), mat, Options{V1: true, V2: true, V3: false, MinSDK: 24})
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(res.APK), int64(len(res.APK)))
	if err != nil {
		t.Fatalf("读取产物归档失败: %v", err)
	}
	entryData := map[string][]byte{}
	var mf []byte
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("打开 %s 失败: %v", f.Name, err)
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("读取 %s 失败: %v", f.Name, err)
		}
		if f.Name == "META-INF/MANIFEST.MF" {
			mf = b
			continue
		}
		entryData[f.Name] = b
	}
	if mf == nil {
		t.Fatal("产物里没有 META-INF/MANIFEST.MF")
	}
	// 解析「Name: ...\nSHA-256-Digest: ...」段落
	checked := 0
	var cur string
	for _, line := range strings.Split(string(mf), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "Name: ") {
			cur = strings.TrimPrefix(line, "Name: ")
			continue
		}
		if strings.HasPrefix(line, "SHA-256-Digest: ") && cur != "" {
			want := parseBase64Digest(t, strings.TrimPrefix(line, "SHA-256-Digest: "))
			data, ok := entryData[cur]
			if !ok {
				t.Fatalf("MANIFEST.MF 声明了不存在的条目 %q", cur)
			}
			sum := sha256.Sum256(data)
			if !bytes.Equal(sum[:], want) {
				t.Fatalf("条目 %s 的 SHA-256 摘要不匹配（v1 签名会校验失败）", cur)
			}
			checked++
			cur = ""
		}
	}
	if checked < 2 {
		t.Fatalf("只校验了 %d 个条目的摘要，测试覆盖不足", checked)
	}
	t.Logf("v1 MANIFEST.MF 的 %d 个条目摘要与条目实际字节一致", checked)
}

// ---- v4（.idsig / fs-verity） ----

// TestSignV4MerkleMatchesIndependent 用**独立实现**的 fs-verity 算法复核 .idsig。
//
// v4 的 .idsig 里放着整个 APK 的 Merkle 树与根哈希，平台会拿它做增量安装校验。
// 这里不复用被测代码：按 fs-verity 规范（4096 字节分块 → 每 128 个哈希打包成页
// → 逐层向上 → 根页摘要）重新算一遍，与 .idsig 里的字节逐字节比对。
func TestSignV4MerkleMatchesIndependent(t *testing.T) {
	mat := testMaterial(t, false)
	res, err := Sign(minimalAPK(t), mat, Options{V2: true, V3: true, V4: true, MinSDK: 24})
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	if len(res.IDSig) == 0 {
		t.Fatal("启用了 v4 却没有产出 .idsig 内容")
	}
	// .idsig 结构：u32 版本 | sized(hashing_info) | sized(signing_info) | sized(merkle_tree)
	if v := binary.LittleEndian.Uint32(res.IDSig); v != 2 {
		t.Fatalf("v4 版本应为 2，实际 %d", v)
	}
	hashing, off := sizedForTest(t, res.IDSig, 4)
	_, off = sizedForTest(t, res.IDSig, off)
	tree, off := sizedForTest(t, res.IDSig, off)
	if off != len(res.IDSig) {
		t.Fatalf("解析后仍剩余 %d 字节，布局与规范不符", len(res.IDSig)-off)
	}
	if algo := binary.LittleEndian.Uint32(hashing); algo != 1 {
		t.Fatalf("哈希算法应为 SHA-256(1)，实际 %d", algo)
	}
	if hashing[4] != 12 {
		t.Fatalf("log2(block size) 应为 12(4096)，实际 %d", hashing[4])
	}
	salt, p := sizedForTest(t, hashing, 5)
	rootWant, _ := sizedForTest(t, hashing, p)

	treeWant, rootGot := fsverityIndependent(res.APK, salt)
	if !bytes.Equal(rootWant, rootGot) {
		t.Fatalf("根哈希不符：\n  .idsig  = %x\n  独立算出 = %x", rootWant, rootGot)
	}
	if !bytes.Equal(tree, treeWant) {
		t.Fatalf("Merkle 树不符：.idsig %d 字节，独立算出 %d 字节", len(tree), len(treeWant))
	}
	t.Logf("v4 fs-verity 独立复核通过：%d 字节树，根哈希 %x…", len(tree), rootWant[:8])
}

// fsverityIndependent 按 fs-verity 规范独立计算 Merkle 树与根哈希。
//
// 与 sign.v4.go 的实现无关：这里是测试侧的第二实现，用来交叉验证。
func fsverityIndependent(data, salt []byte) (tree, rootHash []byte) {
	const blk, per = 4096, 4096 / sha256.Size
	h := func(b []byte) []byte {
		d := sha256.New()
		d.Write(salt)
		d.Write(b)
		return d.Sum(nil)
	}
	n := (len(data) + blk - 1) / blk
	if n == 0 {
		n = 1
	}
	level := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		chunk := make([]byte, blk)
		if off := i * blk; off < len(data) {
			copy(chunk, data[off:])
		}
		level = append(level, h(chunk))
	}
	var levels [][]byte
	for {
		page := make([]byte, 0, ((len(level)+per-1)/per)*blk)
		for i := 0; i < len(level); i += per {
			end := i + per
			if end > len(level) {
				end = len(level)
			}
			buf := make([]byte, blk)
			p := 0
			for _, x := range level[i:end] {
				copy(buf[p:], x)
				p += sha256.Size
			}
			page = append(page, buf...)
		}
		levels = append(levels, page)
		if len(level) <= per {
			break
		}
		var next [][]byte
		for i := 0; i < len(page); i += blk {
			next = append(next, h(page[i:i+blk]))
		}
		level = next
	}
	root := h(levels[len(levels)-1])
	for i := len(levels) - 1; i >= 0; i-- {
		tree = append(tree, levels[i]...)
	}
	return tree, root
}

// ---- 边界：EC 密钥 ----

// TestSignECKeyRejectsV1 记录并钉住「EC 密钥 + v1」的限制。
//
// v1（JAR 签名）只实现了 RSA 的 PKCS#7；EC 密钥启用 v1 时必须**明确报错**，
// 而不是产出一个签名无效的包。关掉 v1 后 EC 的 v2/v3/v4 都应当可用。
func TestSignECKeyRejectsV1(t *testing.T) {
	mat := testMaterial(t, true)
	if _, err := Sign(minimalAPK(t), mat, Options{V1: true, V2: true}); err == nil {
		t.Fatal("EC 密钥 + v1 应当报错")
	} else if !strings.Contains(err.Error(), "RSA") {
		t.Fatalf("错误信息应点明只支持 RSA，实际: %v", err)
	}
	res, err := Sign(minimalAPK(t), mat, Options{V1: false, V2: true, V3: true, V4: true, MinSDK: 24})
	if err != nil {
		t.Fatalf("EC 密钥的 v2/v3/v4 应当可用: %v", err)
	}
	if len(res.IDSig) == 0 {
		t.Fatal("EC 密钥下 v4 也应当产出 .idsig")
	}
	t.Log("EC 密钥：v1 明确拒绝，v2/v3/v4 正常")
}

// ---- 小工具 ----

func sizedForTest(t *testing.T, buf []byte, off int) ([]byte, int) {
	t.Helper()
	if off+4 > len(buf) {
		t.Fatalf("长度前缀越界（off=%d 总长=%d）", off, len(buf))
	}
	n := int(binary.LittleEndian.Uint32(buf[off:]))
	if off+4+n > len(buf) {
		t.Fatalf("字段越界（off=%d n=%d 总长=%d）", off, n, len(buf))
	}
	return buf[off+4 : off+4+n], off + 4 + n
}

func parseBase64Digest(t *testing.T, s string) []byte {
	t.Helper()
	out := make([]byte, 0, 32)
	var acc uint32
	var bits uint
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	for _, c := range s {
		if c == '=' {
			break
		}
		i := strings.IndexRune(alphabet, c)
		if i < 0 {
			t.Fatalf("摘要含非法 base64 字符 %q", c)
		}
		acc = acc<<6 | uint32(i)
		bits += 6
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(acc>>bits))
		}
	}
	return out
}

func keysOf[V any](m map[uint32]V) []uint32 {
	var out []uint32
	for k := range m {
		out = append(out, k)
	}
	return out
}

// ---- 元数据一致性（A14 回归） ----

// TestSignStampUnifiesSignatureEntries 断言签名新增的 v1 条目沿用调用方给定的时间戳。
//
// 背景：A14 统一了归档里全部条目的时间戳，但 MANIFEST.MF / CERT.SF / CERT.RSA
// 是签名阶段才追加的，晚于 A14。若它们退回 ZIP 的 1980 默认值，产物里就会
// 出现「唯独签名文件是 1980」这一枚独有的重打包指纹——恰好是 A14 想消除的东西。
//
// 这里复刻真实链路：先让全部条目统一时间戳（等价 A14），再签名并给定同一 Stamp。
func TestSignStampUnifiesSignatureEntries(t *testing.T) {
	mat := testMaterial(t, false)
	stamp := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	dosT, dosD := zipx.DOSDateTime(stamp)

	// 等价 A14：把归档里全部既有条目统一到同一时间戳。
	ar, err := zipx.Read(minimalAPK(t))
	if err != nil {
		t.Fatalf("解析归档失败: %v", err)
	}
	for _, e := range ar.Entries {
		e.ModTime, e.ModDate = dosT, dosD
	}
	pre := zipx.Write(ar, zipx.DefaultAlign())

	res, err := Sign(pre, mat, Options{
		V1: true, V2: true, V3: false, MinSDK: 24, Stamp: stamp,
	})
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	// 逐一比对 DOS 字段：这是写入端唯一的事实来源，且不受读方时区解释影响。
	got, err := zipx.Read(res.APK)
	if err != nil {
		t.Fatalf("解析签名产物失败: %v", err)
	}
	seen := map[[2]uint16][]string{}
	for _, e := range got.Entries {
		k := [2]uint16{e.ModTime, e.ModDate}
		seen[k] = append(seen[k], e.NameString())
	}
	if len(seen) != 1 {
		t.Fatalf("产物出现 %d 个不同时间戳 %v；A14 之后签名条目必须与其他条目同戳", len(seen), seen)
	}
	if _, ok := seen[[2]uint16{dosT, dosD}]; !ok {
		t.Fatalf("统一后的时间戳与给定 Stamp 不符: %v", seen)
	}
	// 三个签名条目确实存在，别被「全都没时间戳」糊弄过去。
	names := map[string]bool{}
	for _, e := range got.Entries {
		names[e.NameString()] = true
	}
	for _, want := range []string{"META-INF/MANIFEST.MF", "META-INF/CERT.SF", "META-INF/CERT.RSA"} {
		if !names[want] {
			t.Errorf("产物缺少 v1 签名条目 %s", want)
		}
	}
}

// TestSignWithoutStampKeepsDefault 记录未指定时间戳时的既有行为。
func TestSignWithoutStampKeepsDefault(t *testing.T) {
	mat := testMaterial(t, false)
	res, err := Sign(minimalAPK(t), mat, Options{V1: true, V2: true, V3: false, MinSDK: 24})
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(res.APK), int64(len(res.APK)))
	if err != nil {
		t.Fatalf("读取产物归档失败: %v", err)
	}
	for _, f := range zr.File {
		if f.Name == "META-INF/MANIFEST.MF" || f.Name == "META-INF/CERT.SF" || f.Name == "META-INF/CERT.RSA" {
			if f.Modified.Year() != 1980 {
				t.Errorf("未给定 Stamp 时 %s 应为 1980 默认值，实际 %s", f.Name, f.Modified)
			}
		}
	}
}
