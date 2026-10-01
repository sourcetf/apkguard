package pipeline

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

	"apkguard/internal/axml"
	"apkguard/internal/config"
	"apkguard/internal/zipx"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// writeTestKeystore 生成一个 PKCS12 密钥库文件并返回其路径。
func writeTestKeystore(t *testing.T, pass string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "apkguard test"},
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
	p := filepath.Join(t.TempDir(), "test.p12")
	if err := os.WriteFile(p, blob, 0o600); err != nil {
		t.Fatalf("写出密钥库失败: %v", err)
	}
	return p
}

// TestSinkStoresResourceTable 验证收尾时会把压缩的 resources.arsc 改回未压缩。
//
// 这是安装期硬要求：Android 11+ 拒绝安装 resources.arsc 被压缩的 APK
// （Failure [-124]），而签名与 zipalign 检查都不会报错。任何改写资源表的
// 功能项（A5/A11）都可能引入这个状态，因此收尾处必须统一兜底。
func TestSinkStoresResourceTable(t *testing.T) {
	art, err := Load(sampleAPK(t))
	if err != nil {
		t.Fatalf("读取样本失败: %v", err)
	}
	e := Find(art, "resources.arsc")
	if e == nil {
		t.Skip("样本没有 resources.arsc")
	}
	// 人为制造「被压缩」的状态，模拟 A5/A11 之后的产物。
	data, err := e.Data()
	if err != nil {
		t.Fatalf("读取 resources.arsc 失败: %v", err)
	}
	if err := e.SetData(data, true); err != nil {
		t.Fatalf("压缩 resources.arsc 失败: %v", err)
	}
	if e.IsStored() {
		t.Fatal("构造失败：resources.arsc 仍为未压缩")
	}

	out, err := DefaultSink{}.Finish(context.Background(), art, &config.Options{
		// E1 默认是开启的：这里显式关掉，避免为了「验证 arsc 存放方式」
		// 还要造一个密钥库。E3（自检）也一并关掉——它要求存在签名块。
		Enabled: map[config.FeatureID]bool{"E1": false, "E2": true, "E3": false},
	})
	if err != nil {
		t.Fatalf("收尾失败: %v", err)
	}
	got, err := zipx.Read(out)
	if err != nil {
		t.Fatalf("解析产物失败: %v", err)
	}
	re := got.Find("resources.arsc")
	if re == nil {
		t.Fatal("产物里没有 resources.arsc")
	}
	if !re.IsStored() {
		t.Fatal("收尾后 resources.arsc 仍为压缩存放——Android 11+ 会拒绝安装")
	}
}

// TestSinkPropagatesV4IDSig 验证启用 v4 时签名文件会被交给调用方。
//
// 只有 APK 字节流返回给调用方是不够的：`.idsig` 是一个**独立文件**，
// 不传出去就等于「算了一遍丢掉」——`-v4` 会静默地什么都不产出。
func TestSinkPropagatesV4IDSig(t *testing.T) {
	ks := writeTestKeystore(t, "123456")
	pipe := New(NewRegistry(), DefaultSink{})
	res, err := pipe.Run(context.Background(), &config.Options{
		In:      sampleAPK(t),
		Enabled: map[config.FeatureID]bool{"E1": true, "E2": true, "E3": false, "E4": false},
		KS:      ks, KSPass: "123456",
		V4: true,
	})
	if err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	if len(res.IDSig) == 0 {
		t.Fatal("启用 v4 后没有拿到 .idsig 内容（调用方无从落盘）")
	}
	// .idsig 的结构：version(4) | sized(hashing_info) | sized(signing_info) | sized(merkle_tree)
	if v := uint32(res.IDSig[0]) | uint32(res.IDSig[1])<<8 | uint32(res.IDSig[2])<<16 | uint32(res.IDSig[3])<<24; v != 2 {
		t.Fatalf("v4 签名文件版本应为 2，实际 %d", v)
	}
	t.Logf("v4 签名文件已传递：%d 字节（版本 2）", len(res.IDSig))
}

// TestSinkFillsV3SDKRange 验证「未指定 SDK 区间」时会被补齐成有效区间。
//
// 为什么要专门测：v3 签名块里的 [minSdk,maxSdk] 是平台挑选 signer 的依据。
// 取值为 0/0 时任何真实设备都不在区间内，apksig/AOSP 会抛
// NoSupportedSignatures **而不是**回退到 v2——实测这种包在 API 24 与 API 28
// 上都是 DOES NOT VERIFY，也就是装不上。
//
// CLI 的两个 flag 有默认值（24 / INT_MAX）所以掩盖了这个问题，而 Web UI 与
// 任何库调用都只给零值。判据：零值签名与「显式给出正确区间」的产物必须
// 逐字节一致。
func TestSinkFillsV3SDKRange(t *testing.T) {
	ks := writeTestKeystore(t, "123456")

	base, err := Load(sampleAPK(t))
	if err != nil {
		t.Fatalf("读取样本失败: %v", err)
	}
	wantMin := uint(manifestMinSDK(base))
	if wantMin == 0 {
		t.Skip("样本 Manifest 读不到 minSdkVersion，跳过")
	}

	run := func(minSDK, maxSDK uint) []byte {
		t.Helper()
		art, err := Load(sampleAPK(t))
		if err != nil {
			t.Fatalf("读取样本失败: %v", err)
		}
		opts := &config.Options{
			Enabled: map[config.FeatureID]bool{"E1": true, "E2": true},
			KS:      ks, KSPass: "123456",
			MinSDK: minSDK, MaxSDK: maxSDK,
		}
		out, err := DefaultSink{}.Finish(context.Background(), art, opts)
		if err != nil {
			t.Fatalf("签名失败: %v", err)
		}
		return out
	}

	zero := run(0, 0)
	explicit := run(wantMin, 0x7fffffff)
	if !bytes.Equal(zero, explicit) {
		t.Fatal("SDK 区间为 0/0 时未按 Manifest 的 minSdkVersion 补齐" +
			"（两种方式的签名产物不一致）——v3 signer 的区间会落在所有设备之外，产物无法安装")
	}
	t.Logf("零值 SDK 区间已补齐为 [%d, 0x7fffffff]（与显式指定逐字节一致）", wantMin)
}

// TestSinkRejectsInvertedSDKRange 验证区间反了必须报错而不是产出无效签名。
func TestSinkRejectsInvertedSDKRange(t *testing.T) {
	ks := writeTestKeystore(t, "123456")
	art, err := Load(sampleAPK(t))
	if err != nil {
		t.Fatalf("读取样本失败: %v", err)
	}
	opts := &config.Options{
		Enabled: map[config.FeatureID]bool{"E1": true, "E2": true},
		KS:      ks, KSPass: "123456",
		MinSDK: 30, MaxSDK: 24,
	}
	if _, err := (DefaultSink{}).Finish(context.Background(), art, opts); err == nil {
		t.Fatal("minSdk > maxSdk 时应报错")
	} else if !strings.Contains(err.Error(), "区间") {
		t.Fatalf("错误信息应点明签名区间，实际: %v", err)
	}
}

// sampleAPK 返回样本 APK 路径；不存在时跳过。
func sampleAPK(t *testing.T) string {
	t.Helper()
	candidates := []string{
		filepath.Join("..", "..", "..", "testapp", "testapp-signed.apk"),
		filepath.Join("..", "..", "..", "testdata", "sample.apk"),
		filepath.Join("..", "..", "..", "iterator.apk.apk"),
		filepath.Join("..", "..", "..", "payload_apk", "payload.apk"),
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && st.Size() > 0 {
			return p
		}
	}
	t.Skip("未找到测试用 APK，跳过")
	return ""
}

// rewriteMinSDK 把产物中 Manifest 的 minSdkVersion 改成指定值。
func rewriteMinSDK(t *testing.T, art *Artifact, val string) {
	t.Helper()
	e := Find(art, "AndroidManifest.xml")
	if e == nil {
		t.Skip("样本缺少 AndroidManifest.xml")
	}
	data, err := e.Data()
	if err != nil {
		t.Fatalf("读取 Manifest 失败: %v", err)
	}
	f, err := axml.Parse(data)
	if err != nil {
		t.Skipf("样本 Manifest 解析失败（%v），跳过", err)
	}
	if f.FindElement("uses-sdk") == nil {
		t.Skip("样本未声明 <uses-sdk>")
	}
	out, err := f.Rewrite(axml.Edit{SetAttr: []axml.AttrValue{{
		Element: "uses-sdk", Index: 0,
		NS: axml.AndroidNS, Name: "minSdkVersion", Value: val,
	}}})
	if err != nil {
		t.Fatalf("改写 minSdkVersion 失败: %v", err)
	}
	if err := e.SetData(out, true); err != nil {
		t.Fatalf("写回 Manifest 失败: %v", err)
	}
}

// TestManifestMinSDK 验证能从 Manifest 读出 minSdkVersion。
func TestManifestMinSDK(t *testing.T) {
	art, err := Load(sampleAPK(t))
	if err != nil {
		t.Fatalf("读取样本失败: %v", err)
	}
	got := manifestMinSDK(art)
	if got <= 0 {
		t.Fatalf("样本声明了 minSdkVersion，应读到正数，实际 %d", got)
	}
	// 改写为另一个值后应如实反映。
	rewriteMinSDK(t, art, "21")
	if got := manifestMinSDK(art); got != 21 {
		t.Fatalf("改写后应读到 21，实际 %d", got)
	}
	t.Logf("Manifest 的 minSdkVersion 解析正确（样本原始值 >0，改写后=21）")
}

// TestNoV1RejectedForLowMinSDK 验证「禁用 v1 签名 + 低 minSdk」会被拦住。
//
// Android 7.0（API 24）以下的系统只认 v1 的 JAR 签名，允许这种组合等于
// 产出在这些设备上装不上的包——必须在加固阶段就失败，而不是等装机才发现。
func TestNoV1RejectedForLowMinSDK(t *testing.T) {
	art, err := Load(sampleAPK(t))
	if err != nil {
		t.Fatalf("读取样本失败: %v", err)
	}
	rewriteMinSDK(t, art, "21")

	opts := &config.Options{
		Enabled: map[config.FeatureID]bool{"E1": true, "E2": true},
		NoV1:    true,
	}
	_, err = DefaultSink{}.Finish(context.Background(), art, opts)
	if err == nil {
		t.Fatal("禁用 v1 且 minSdk=21 时应报错")
	}
	if !strings.Contains(err.Error(), "minSdkVersion") {
		t.Fatalf("错误信息应点明 minSdkVersion，实际: %v", err)
	}
	if !strings.Contains(err.Error(), "no-v1") {
		t.Fatalf("错误信息应给出可执行的修复建议，实际: %v", err)
	}
}

// TestManifestMinSDKDefaultsZero 验证读不到时返回 0。
//
// 0 在 Android 语义里等同「支持到 API 1」，因此禁用 v1 时同样会被拦下——
// 这正是我们想要的保守行为：信息缺失时宁可拦住，也不要放出装不上的包。
func TestManifestMinSDKDefaultsZero(t *testing.T) {
	art := &Artifact{Archive: &zipx.Archive{}}
	if got := manifestMinSDK(art); got != 0 {
		t.Fatalf("没有 Manifest 时应返回 0，实际 %d", got)
	}
	// Manifest 存在但不是合法 AXML 时同样返回 0。
	bad := &Artifact{Archive: &zipx.Archive{Entries: []*zipx.Entry{
		zipx.NewStored("AndroidManifest.xml", []byte("not-an-axml")),
	}}}
	if got := manifestMinSDK(bad); got != 0 {
		t.Fatalf("Manifest 非法时应返回 0，实际 %d", got)
	}
}
