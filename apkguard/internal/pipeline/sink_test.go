package pipeline

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"apkguard/internal/axml"
	"apkguard/internal/config"
	"apkguard/internal/zipx"
)

// sampleAPK 返回样本 APK 路径；不存在时跳过。
func sampleAPK(t *testing.T) string {
	t.Helper()
	candidates := []string{
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
