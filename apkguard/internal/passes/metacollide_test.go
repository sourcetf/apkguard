package passes

import (
	"context"
	"strings"
	"testing"

	"apkguard/internal/axml"
	"apkguard/internal/config"
	"apkguard/internal/pipeline"
	"apkguard/internal/zipx"
)

// TestManifestCollisionGuard 覆盖归一化识别的各种写法。
func TestManifestCollisionGuard(t *testing.T) {
	bad := []string{
		"META-INF/MANIFEST.MF",
		"meta-inf/MANIFEST.MF", // 大小写不敏感 → 撞名
		"META-INF//MANIFEST.MF",
		"META-INF/./MANIFEST.MF",
		"META-INF/../META-INF/MANIFEST.MF",
		"META-INF/CERT.SF",
		"META-INF/key.RSA",
		"META-INF/x.dsa",
		"META-INF/y.EC",
	}
	for _, n := range bad {
		if !manifestCollision(n) {
			t.Errorf("%q 应被判定为撞名（会破坏 v1 签名校验）", n)
		}
	}
	ok := []string{
		"META-INF//MANIFEST.MFx",
		"META-INF/.hidden",
		"META-INF/sub/",
		"META-INF/x.MF",
		"meta-inf/MANIFEST.MFx",
		"META-INF/services/j3.t",
		"META-INF/androidx.core_core.version",
		"classes.dex/abc",
	}
	for _, n := range ok {
		if manifestCollision(n) {
			t.Errorf("%q 不应被判定为撞名", n)
		}
	}
}

// TestJunkEntriesNeverInjectManifestCollision 钉住 A10/A12 不会新增撞名条目。
//
// 真实缺陷（实测于 RustDesk 1.5.0，Flutter）：A10 曾注入 `meta-inf/MANIFEST.MF`
// 与 `META-INF//MANIFEST.MF`。ServiceLoader 经 JarFile 读 META-INF/services 时触发
// v1 签名校验，校验器读到**假 manifest 的主属性**，抛
//
//	java.lang.SecurityException: Invalid signature file digest for Manifest main attributes
//
// 应用首次 attach 即崩。这里断言：注入前后「撞名条目」集合完全不变
// （既有的真 MANIFEST.MF 保持唯一，也不新增任何假签名文件）。
func TestJunkEntriesNeverInjectManifestCollision(t *testing.T) {
	art := newArtifact(
		zipx.NewStored("classes.dex", []byte("dex\n035\x00")),
		zipx.NewStored("META-INF/MANIFEST.MF", []byte("Manifest-Version: 1.0\r\n\r\n")),
		zipx.NewStored("META-INF/CERT.SF", []byte("Signature-Version: 1.0\r\n")),
	)
	collisions := func() map[string]int {
		out := map[string]int{}
		for _, e := range art.Entries() {
			if manifestCollision(e.NameString()) {
				out[e.NameString()]++
			}
		}
		return out
	}
	before := collisions()

	opts := &config.Options{
		Enabled:       map[config.FeatureID]bool{"A10": true, "A12": true},
		Seed:          "junk",
		JunkTopCount:  40,
		JunkDirCount:  40,
		JunkDirDepth:  8,
		JunkMetaCount: 60,
		ZipAtkCount:   30,
	}
	if err := (&junkEntries{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A10 执行失败: %v", err)
	}
	if err := (&zipPathAttack{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A12 执行失败: %v", err)
	}

	after := collisions()
	for name, n := range after {
		if before[name] != n {
			t.Fatalf("A10/A12 新增了会破坏 v1 签名校验的条目 %q（%d → %d）", name, before[name], n)
		}
	}
	if len(after) != len(before) {
		t.Fatalf("撞名条目集合发生变化：%v → %v", before, after)
	}
	if n := after["META-INF/MANIFEST.MF"]; n != 1 {
		t.Fatalf("MANIFEST.MF 应恰好 1 条，实际 %d 条", n)
	}
}

// ---- A18 meta-data 键名与真实 SDK 的冲突规则 ----

// TestMetaKeyReservedRules 钉住保留名单的判定规则本身。
func TestMetaKeyReservedRules(t *testing.T) {
	// 精确键：确定会被系统/流行 SDK 读取，一律保留。
	reserved := []string{
		"com.google.android.gms.version",
		"com.google.android.gms.ads.APPLICATION_ID",
		"firebase_analytics_collection_enabled",
		"com.facebook.sdk.ApplicationId",
		"UMENG_APPKEY",
		"BUGLY_APP_VERSION",
		"com.amap.api.v2.apikey",
		"com.baidu.lbsapi.API_KEY",
		"com.tencent.mm.opensdk.open_appid",
	}
	for _, k := range reserved {
		if !metaKeyReserved(k) {
			t.Errorf("%q 是真实 SDK 读取的键，必须判为保留", k)
		}
	}
	// 大小写不敏感：读取方对键名大小写的处理并不一致，保守取严。
	if !metaKeyReserved("umeng_appkey") || !metaKeyReserved("com.google.android.gms.VERSION") {
		t.Error("保留判定必须大小写不敏感")
	}
	// 前缀保留：随机合成名落入 SDK 命名空间时一律换名。
	for _, k := range []string{"com.google.firebase.any.key", "com.google.android.gms.foo", "com.umeng.whatever"} {
		if !metaKeyReserved(k) {
			t.Errorf("%q 落在保留前缀内，必须判为保留", k)
		}
	}
	// 明显无关的名字不得误判（否则过滤会退化、名字空间收缩）。
	for _, k := range []string{"cfg_nonce", "cfg_mark_20260919220102_01_ab12cd", "com.qcloud.cos.appid", "bugly_report_url"} {
		if metaKeyReserved(k) {
			t.Errorf("%q 不应被判为保留（会误伤正常注入）", k)
		}
	}
}

// TestDecoyMetaNewKeysAvoidReservedSDKKeys 钉住 A18 实际注入的样本风格名字
// （水印 / 同名不同值 / com.<随机>.<随机>）都不命中保留的 SDK 关键键。
func TestDecoyMetaNewKeysAvoidReservedSDKKeys(t *testing.T) {
	art := loadSample(t)
	entry := pipeline.Find(art, "AndroidManifest.xml")
	if entry == nil {
		t.Skip("样本没有 AndroidManifest.xml")
	}
	beforeData, err := entry.Data()
	if err != nil {
		t.Fatalf("读取 Manifest 失败: %v", err)
	}
	before, err := axml.Parse(beforeData)
	if err != nil {
		t.Fatalf("解析 Manifest 失败: %v", err)
	}
	beforeMeta := elemNames(before, "meta-data")

	opts := &config.Options{
		Enabled:        map[config.FeatureID]bool{"A18": true},
		Seed:           "collide-seed",
		DecoyMetaCount: 40,
	}
	if err := (&decoyMeta{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A18 执行失败: %v", err)
	}
	data, err := entry.Data()
	if err != nil {
		t.Fatalf("读取产物 Manifest 失败: %v", err)
	}
	after, err := axml.Parse(data)
	if err != nil {
		t.Fatalf("产物 Manifest 无法解析: %v", err)
	}

	checked := 0
	for _, e := range after.Elements {
		if e.Name != "meta-data" {
			continue
		}
		n := e.AttrString("name")
		if beforeMeta[n] {
			continue // 应用原有键，不归 A18 管
		}
		// 只检验样本风格新增键；通用近似键有自己的评审清单。
		segs := strings.Split(strings.TrimPrefix(n, "com."), ".")
		isNew := strings.HasPrefix(n, "cfg_mark_") || n == "cfg_nonce" || n == "build_lane" ||
			n == "seq_mark" || n == "compile_ms" ||
			(strings.HasPrefix(n, "com.") && len(segs) == 2)
		if !isNew {
			continue
		}
		checked++
		if metaKeyReserved(n) {
			t.Fatalf("A18 注入了保留的 SDK 关键键 %q", n)
		}
	}
	if checked < 25 {
		t.Fatalf("只检查到 %d 条样本风格新增键，覆盖不足", checked)
	}
	t.Logf("已检查 %d 条样本风格 meta-data 键，均未命中保留的 SDK 关键键", checked)
}
