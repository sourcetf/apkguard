package passes

import (
	"context"
	"strings"
	"testing"

	"apkguard/internal/config"
	"apkguard/internal/zipx"
)

// TestE6RunTracesOnCompatibleArtifact 是 E6（compatCheck）成功路径的 Pass 级回归。
//
// 审计指出 E6 只有 ABI 缺库的失败用例，没有断言过成功路径的产物痕迹与统计键；
// 若判据被写反（例如 minSdk 比较方向颠倒），这类测试缺位时不会有人发现。
// 这里用最小合法产物直接调 Run，断言统计键与 Note。
func TestE6RunTracesOnCompatibleArtifact(t *testing.T) {
	art := newArtifact(
		// nestedAPKManifestAXML：minSdk=24、targetSdk=34。
		zipx.NewStored("AndroidManifest.xml", nestedAPKManifestAXML(newRand("e6trace"), "com.agtest")),
		zipx.NewStored("classes.dex", smallDexWithClass(t, "Lcom/agtest/A;")),
	)
	if err := (&compatCheck{}).Run(context.Background(), art, &config.Options{}); err != nil {
		t.Fatalf("兼容产物不应被 E6 拒绝: %v", err)
	}
	wantStats := map[string]string{"E6.min_sdk": "24", "E6.abis": "0", "E6.dex": "1"}
	for k, want := range wantStats {
		if got := art.Stats[k]; got != want {
			t.Errorf("%s = %q，应为 %q（统计 %v）", k, got, want, art.Stats)
		}
	}
	if !notesContain(art, "E6 兼容性自检") {
		t.Errorf("E6 未在 Notes 中留下说明: %v", art.Notes)
	}
}

// TestE6RejectsDexVersionNewerThanMinSdk 钉住 E6 的 DEX 版本判据方向：
// DEX 038 需要 API 26+，minSdk=24 时必须报错，而不是被反过来放行。
//
// DEX 版本只由 magic 的前 7 字节决定，因此这里直接把合法 DEX 的 magic 改成
// "dex\n038"（不重新签名/校验）——E6 的这条检查本就只读版本号。
func TestE6RejectsDexVersionNewerThanMinSdk(t *testing.T) {
	d := smallDexWithClass(t, "Lcom/agtest/A;")
	if len(d) < 8 || string(d[:4]) != "dex\n" {
		t.Fatalf("构造的 DEX magic 非预期: %q", d[:min(8, len(d))])
	}
	patched := append([]byte(nil), d...)
	copy(patched[4:7], "038")

	art := newArtifact(
		zipx.NewStored("AndroidManifest.xml", nestedAPKManifestAXML(newRand("e6ver"), "com.agtest")),
		zipx.NewStored("classes.dex", patched),
	)
	err := (&compatCheck{}).Run(context.Background(), art, &config.Options{})
	if err == nil {
		t.Fatal("DEX 038 配 minSdk=24 应被 E6 拒绝（038 需要 API 26+）")
	}
	msg := err.Error()
	if !strings.Contains(msg, "038") || !strings.Contains(msg, "26") {
		t.Errorf("E6 错误信息应点明 DEX 038 需要 API 26+，实际: %v", err)
	}
}
