package passes

import (
	"context"
	"strings"
	"testing"

	"apkguard/internal/config"
	"apkguard/internal/zipx"
)

// TestE6ReportsMissingLibOnAlphabeticallyFirstABI 回归审计发现：E6 的 ABI
// 覆盖检查以「字母序第一个 ABI」为基准单向比较，当残缺方恰好字母序靠前时
// 它缺的库不会被报出来（假阴性）。
//
// 这里构造 arm64-v8a 只有 libA、armeabi-v7a 有 libA+libB 的场景：
// arm64-v8a 字母序在 armeabi-v7a 之前（'6' < 'e'），旧实现因此漏报。
func TestE6ReportsMissingLibOnAlphabeticallyFirstABI(t *testing.T) {
	art := newArtifact(
		zipx.NewStored("AndroidManifest.xml", nestedAPKManifestAXML(newRand("e6abi"), "com.agtest")),
		zipx.NewStored("classes.dex", smallDexWithClass(t, "Lapp/A;")),
		zipx.NewStored("lib/arm64-v8a/libA.so", []byte("a")),
		zipx.NewStored("lib/armeabi-v7a/libA.so", []byte("a")),
		zipx.NewStored("lib/armeabi-v7a/libB.so", []byte("b")),
	)
	err := (&compatCheck{}).Run(context.Background(), art, &config.Options{})
	if err == nil {
		t.Fatal("E6 应报出 arm64-v8a 缺失 libB.so（残缺方字母序靠前，旧实现会漏报）")
	}
	msg := err.Error()
	if !strings.Contains(msg, "arm64-v8a") || !strings.Contains(msg, "libB.so") {
		t.Fatalf("E6 错误信息未点明 arm64-v8a 缺少 libB.so: %v", err)
	}
	t.Logf("E6 已双向覆盖: %v", err)
}

// TestE6AcceptsCompleteABICoverage 是上一条的对照组：各 ABI 库集合一致时
// 不应报错，避免「修成逢多 ABI 就报」的过度修正。
func TestE6AcceptsCompleteABICoverage(t *testing.T) {
	art := newArtifact(
		zipx.NewStored("AndroidManifest.xml", nestedAPKManifestAXML(newRand("e6ok"), "com.agtest")),
		zipx.NewStored("classes.dex", smallDexWithClass(t, "Lapp/A;")),
		zipx.NewStored("lib/arm64-v8a/libA.so", []byte("a")),
		zipx.NewStored("lib/arm64-v8a/libB.so", []byte("b")),
		zipx.NewStored("lib/armeabi-v7a/libA.so", []byte("a")),
		zipx.NewStored("lib/armeabi-v7a/libB.so", []byte("b")),
	)
	if err := (&compatCheck{}).Run(context.Background(), art, &config.Options{}); err != nil {
		t.Fatalf("库集合一致的 ABI 不应报错: %v", err)
	}
}
