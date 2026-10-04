package passes

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"apkguard/internal/config"
	"apkguard/internal/pipeline"
	"apkguard/internal/zipx"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// ---- A12 归一化近重名族 ----
//
// 与「精确重名」的关键差别：本族在中央目录里的精确名互不相同，启用 E1 签名时
// 也照常生效（样本 /resources.arsc//.xml 一族最多 13 条，正是带签名的归档）。
// 下面的用例分别钉住：形态与去重、与 A10 各族共存、E1 签名后仍存在、同 seed 可复现。

// nearDupForbiddenNames 是不能与之精确同名的真实核心/签名文件（本族的硬约束）。
var nearDupForbiddenNames = []string{
	"AndroidManifest.xml", "classes.dex", "classes2.dex", "resources.arsc",
	"META-INF/MANIFEST.MF", "META-INF/CERT.SF", "META-INF/CERT.RSA",
}

// nearDupFamily 按基础路径 × 变体名单精确查找族条目；缺任何一条即 Fatal。
func nearDupFamily(t *testing.T, art *pipeline.Artifact) (map[string]*zipx.Entry, int) {
	t.Helper()
	byName := map[string]*zipx.Entry{}
	for _, e := range art.Entries() {
		byName[e.NameString()] = e
	}
	found := map[string]*zipx.Entry{}
	for _, base := range nearDupBases {
		for _, v := range nearDupVariants(base) {
			e, ok := byName[v]
			if !ok {
				t.Fatalf("归一化近重名族缺少变体 %q（基础路径 %v）", v, base)
			}
			found[v] = e
		}
	}
	return found, len(found)
}

// TestNearDupFamilyShape 钉住 A12 归一化近重名族的形态与安全硬约束：
//   - 8 个基础路径、每组 4 变体，总数 ≥16；
//   - 同组变体归一化（\→/、折叠连续 /）后路径相同，不同组之间路径不同；
//   - 全部条目（含 A12 前缀/绝对路径族）精确名唯一；
//   - 无 `.`/`..` 段、不以分隔符结尾、不与真实核心/签名文件精确同名；
//   - 内容与 A10/A12 其它族同源（176B 共用载荷）。
func TestNearDupFamilyShape(t *testing.T) {
	const seed = "neardup-shape"
	art := newArtifact(zipx.NewStored("classes.dex", []byte("dex\n035\x00")))
	opts := &config.Options{
		Enabled:     map[config.FeatureID]bool{"A12": true, "E1": true},
		Seed:        seed,
		ZipAtkCount: 3,
	}
	if err := (&zipPathAttack{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A12 执行失败: %v", err)
	}

	payload := sharedJunkPayload(art, seed)
	found, total := nearDupFamily(t, art)
	if total < 16 {
		t.Fatalf("归一化近重名族只有 %d 条，要求 ≥16", total)
	}
	wantTotal := len(nearDupBases) * len(nearDupSepForms)
	if total != wantTotal {
		t.Fatalf("族条目数 %d，期望 %d（%d 个基础路径 × %d 个变体）",
			total, wantTotal, len(nearDupBases), len(nearDupSepForms))
	}

	normSeen := map[string][]string{}
	for _, base := range nearDupBases {
		want := nearDupNormalize(strings.Join(base, "/"))
		if prev, ok := normSeen[want]; ok {
			t.Fatalf("基础路径 %v 与 %v 归一化后撞车（%q）", base, prev, want)
		}
		normSeen[want] = base

		seen := map[string]bool{}
		for _, v := range nearDupVariants(base) {
			if seen[v] {
				t.Fatalf("同组变体 %q 重复生成", v)
			}
			seen[v] = true

			if got := nearDupNormalize(v); got != want {
				t.Fatalf("变体 %q 归一化为 %q，期望 %q", v, got, want)
			}
			e := found[v]
			if !bytes.Equal(entryData(t, e), payload) {
				t.Fatalf("变体 %q 的内容不是族 A 的 %dB 共用载荷", v, junkPayloadSize)
			}
			// 硬约束：无空段以外的畸形、无点段、非目录条目。
			if !safeJunkPath(v) {
				t.Fatalf("变体 %q 违反 safeJunkPath（空段 / 点段 / 目录条目）", v)
			}
			if strings.HasSuffix(v, "/") || strings.HasSuffix(v, `\`) {
				t.Fatalf("变体 %q 以分隔符结尾（目录条目）", v)
			}
			// 绝不与真实核心文件/签名文件精确同名（归一化后同路径允许，
			// 精确名相撞会让 Android 读到假文件或让 apksigner 拒绝归档）。
			for _, real := range nearDupForbiddenNames {
				if v == real || strings.EqualFold(v, real) {
					t.Fatalf("变体 %q 与真实核心文件 %q 精确同名", v, real)
				}
			}
			if manifestCollision(v) || coreCollision(v, nil) {
				t.Fatalf("变体 %q 撞上 v1 签名关键名或核心文件判据", v)
			}
		}
	}

	// 全部条目精确名唯一——包括 A12 前缀滥用族、绝对路径族与原始 classes.dex。
	counts := map[string]int{}
	for _, e := range art.Entries() {
		counts[e.NameString()]++
	}
	for name, n := range counts {
		if n != 1 {
			t.Fatalf("产物存在精确重名条目 %q × %d", name, n)
		}
	}
	if counts["classes.dex"] != 1 {
		t.Fatalf("核心条目 classes.dex 必须唯一，实际 %d 份", counts["classes.dex"])
	}

	if art.Stats["A12.neardup"] != itoa(total) {
		t.Fatalf("A12.neardup = %s，期望 %d", art.Stats["A12.neardup"], total)
	}
	if art.Stats["A12.neardup_groups"] != itoa(len(nearDupBases)) {
		t.Fatalf("A12.neardup_groups = %s，期望 %d",
			art.Stats["A12.neardup_groups"], len(nearDupBases))
	}
	t.Logf("归一化近重名 %d 组 / %d 条，全部归一化同路径且中央目录精确名唯一；样例：%q / %q → %q",
		len(nearDupBases), total,
		nearDupVariants(nearDupBases[0])[1], nearDupVariants(nearDupBases[0])[2],
		nearDupNormalize(strings.Join(nearDupBases[0], "/")))
}

// TestNearDupCoexistsWithA10 钉住本族与 A10 各族同时启用时：
//   - 8 组、每组 4 变体全部产出（不会被 A10 已注入条目按归一化路径挡下）；
//   - 全部条目精确名仍唯一（与 A10 的畸形 META-INF / 4hex / kotlin / res 变体交叉比对）；
//   - 内容仍是同一份 176B 共用载荷。
func TestNearDupCoexistsWithA10(t *testing.T) {
	const seed = "neardup-a10"
	art := runJunkPasses(t, seed, 20, 30, 5, 30, 40)
	payload := sharedJunkPayload(art, seed)

	found, total := nearDupFamily(t, art)
	if total != len(nearDupBases)*len(nearDupSepForms) {
		t.Fatalf("与 A10 共存时族条目数 %d，期望 %d（说明有变体被既有条目按归一化路径挡下）",
			total, len(nearDupBases)*len(nearDupSepForms))
	}
	counts := map[string]int{}
	for _, e := range art.Entries() {
		counts[e.NameString()]++
	}
	for name, n := range counts {
		if n != 1 {
			t.Fatalf("与 A10 共存时出现精确重名 %q × %d", name, n)
		}
	}
	for v, e := range found {
		if !bytes.Equal(entryData(t, e), payload) {
			t.Fatalf("变体 %q 的内容与 A10/A12 共用载荷不一致", v)
		}
	}
	for _, real := range nearDupForbiddenNames {
		if n, ok := counts[real]; ok && n != 1 {
			t.Fatalf("真实核心/签名文件 %q 条目数 %d，应为 1", real, n)
		}
	}
	t.Logf("与 A10 共存：近重名 %d 条全部产出，%d 个条目精确名唯一，真实核心文件保持唯一",
		total, len(counts))
}

// TestNearDupSurvivesSigning 是本族与「精确重名」的关键差别所在：
// 跑完整 DefaultSink（E1 签名 + E2 对齐）后，产物里本族必须全部仍在。
//
// 精确重名族在 E1 开启时按设计跳过（apksigner 会以 Duplicate entry 拒绝整个
// 归档），而本族中央目录精确名唯一，签名与安装均不受影响。
func TestNearDupSurvivesSigning(t *testing.T) {
	ks := writeNearDupKeystore(t, "123456")
	art := newArtifact(zipx.NewStored("classes.dex", []byte("dex\n035\x00")))
	opts := &config.Options{
		Enabled:     map[config.FeatureID]bool{"A12": true, "E1": true, "E2": true, "E3": false},
		Seed:        "neardup-sign",
		ZipAtkCount: 3,
		KS:          ks, KSPass: "123456",
	}
	if err := (&zipPathAttack{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A12 执行失败: %v", err)
	}
	// 对照组：精确重名族在签名开启时必须为 0，否则这条测试就证明不了本族
	// 与它的差别。
	if art.Stats["A12.dup"] != "0" {
		t.Fatalf("E1 开启时精确重名族应跳过，实际 A12.dup=%s", art.Stats["A12.dup"])
	}

	out, err := (pipeline.DefaultSink{}).Finish(context.Background(), art, opts)
	if err != nil {
		t.Fatalf("收尾（对齐+签名）失败: %v", err)
	}
	// 产物确实带 APK 签名块，否则「签名后仍存在」无从谈起。
	sec, err := zipx.Split(out)
	if err != nil {
		t.Fatalf("解析签名块失败: %v", err)
	}
	if !sec.HasSigningBlock() {
		t.Fatal("产物没有 APK 签名块，签名没有真正发生")
	}

	za, err := zipx.Read(out)
	if err != nil {
		t.Fatalf("签名后解析产物失败: %v", err)
	}
	byName := map[string]int{}
	for _, e := range za.Entries {
		byName[e.NameString()]++
	}
	n := 0
	for _, base := range nearDupBases {
		for _, v := range nearDupVariants(base) {
			if byName[v] != 1 {
				t.Fatalf("签名后变体 %q 出现 %d 次（要求恰好 1 次）", v, byName[v])
			}
			n++
		}
	}
	if n < 16 {
		t.Fatalf("签名后本族只剩 %d 条，要求 ≥16", n)
	}
	// apksigner 的硬前提：中央目录里不得有精确重名条目。
	for name, c := range byName {
		if c != 1 {
			t.Fatalf("签名产物存在精确重名 %q × %d", name, c)
		}
	}
	t.Logf("E1 签名后归一化近重名 %d 条全部保留（签名块 %d 字节），精确重名 0（A12.dup=0）",
		n, len(sec.SigningBlock))
}

// TestNearDupDeterministic 钉住同 seed 两次运行的产物逐字节一致。
func TestNearDupDeterministic(t *testing.T) {
	build := func() []byte {
		art := newArtifact(zipx.NewStored("classes.dex", []byte("dex\n035\x00")))
		opts := &config.Options{
			Enabled:     map[config.FeatureID]bool{"A12": true, "E1": true},
			Seed:        "neardup-det",
			ZipAtkCount: 5,
		}
		if err := (&zipPathAttack{}).Run(context.Background(), art, opts); err != nil {
			t.Fatalf("A12 执行失败: %v", err)
		}
		return pipeline.Bytes(art)
	}
	a, b := build(), build()
	if !bytes.Equal(a, b) {
		t.Fatal("同 seed 两次运行产物不一致（归一化近重名族引入了非确定性）")
	}
}

// writeNearDupKeystore 生成一个 PKCS12 密钥库并返回路径（与 internal/pipeline
// 的测试同法）。自包含生成而不是依赖 testapp/build/test.jks：保证这条签名用例
// 在任何检出下都真的跑签名，而不是因缺少密钥库被跳过。
func writeNearDupKeystore(t *testing.T, pass string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "apkguard neardup test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("自签证书失败: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("解析证书失败: %v", err)
	}
	blob, err := pkcs12.Modern.Encode(key, cert, nil, pass)
	if err != nil {
		t.Fatalf("编码 PKCS12 失败: %v", err)
	}
	p := filepath.Join(t.TempDir(), "neardup.p12")
	if err := os.WriteFile(p, blob, 0o600); err != nil {
		t.Fatalf("写出密钥库失败: %v", err)
	}
	return p
}
