package passes

import (
	"context"
	"strconv"
	"testing"

	"apkguard/internal/config"
	"apkguard/internal/zipx"
)

// TestManifestPadRejectsUint32Overflow 回归审计发现：A15 在 4096 MB 时
// 8+4096<<20 == 2^32，uint32 声明长度回绕成 8，Android 报 Bad XML block。
//
// 修后必须在**分配之前**显式报错，不静默截断，也不真的分配几 GB。
func TestManifestPadRejectsUint32Overflow(t *testing.T) {
	if strconv.IntSize < 64 {
		t.Skip("32 位平台下 int 无法表示 2^32，跳过")
	}
	raw := realisticAXML(newRand("a15ov"), 256)

	big := int64(1) << 32
	if _, err := padManifest(raw, int(big), newRand("a15ov")); err == nil {
		t.Fatal("padManifest 应对 2^32 填充量报错，而不是静默截断声明长度")
	}
	// 边界：8+pad == 2^32，填充 chunk 声明长度恰好溢出，也必须拒绝。
	if _, err := padManifest(raw, int(big-8), newRand("a15ov")); err == nil {
		t.Fatal("padManifest 应拒绝使填充 chunk 声明长度溢出的边界值 2^32-8")
	}
	// 正常值仍应可用，确认守卫没有误伤。
	if _, err := padManifest(raw, 1<<20, newRand("a15ov")); err != nil {
		t.Fatalf("正常填充量不应被拒绝: %v", err)
	}
}

// TestManifestPadOverflowPure 直接测边界判定函数，不分配任何大内存。
func TestManifestPadOverflowPure(t *testing.T) {
	cases := []struct {
		pad, total int64
		want       bool
	}{
		{1 << 20, 1<<20 + 16, false},                // 正常
		{int64(1) << 32, int64(1)<<32 + 16, true},   // 旧配置上限 4096MB<<20 == 2^32，恰溢出
		{int64(1)<<32 - 8, int64(1) << 32, true},    // 8+pad == 2^32 恰溢出
		{int64(1)<<32 - 9, int64(1)<<32 - 1, false}, // 8+pad == 2^32-1，恰好装得下
		{0, int64(1)<<32 + 1, true},                 // total 单独越界
	}
	for _, c := range cases {
		if got := manifestPadOverflows(c.pad, c.total); got != c.want {
			t.Errorf("manifestPadOverflows(pad=%d,total=%d)=%v，期望 %v", c.pad, c.total, got, c.want)
		}
	}
}

// TestManifestPadRunRejectsU32Overflow 从 Run 入口验证：4096 MB 即便绕过了
// 配置层（新配置上限已收紧到 1024 MB），也必须在分配前得到明确的 uint32
// 溢出错误，而不是试图分配几 GB 后被系统杀掉。
func TestManifestPadRunRejectsU32Overflow(t *testing.T) {
	if strconv.IntSize < 64 {
		t.Skip("32 位平台下 int 无法表示 2^32，跳过")
	}
	raw := realisticAXML(newRand("a15run"), 256)
	art := newArtifact(zipx.NewStored(manifestName, raw))
	err := (&manifestPad{}).Run(context.Background(), art, &config.Options{
		Enabled:       map[config.FeatureID]bool{"A15": true},
		ManifestPadMB: 4096,
	})
	if err == nil {
		t.Fatal("ManifestPadMB=4096（超过配置上限且触发 uint32 溢出）应报错")
	}
	t.Logf("A15 上限被正确拒绝: %v", err)
}
