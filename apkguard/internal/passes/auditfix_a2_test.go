package passes

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"apkguard/internal/config"
	"apkguard/internal/zipx"
)

// TestA2KeyNotLeakedInReport 回归审计发现：A2 曾把完整密钥写进 Note 与
// Stat("A2.key")，而日志/统计随产物一起交付存档，等于公开密钥。
//
// 修后只允许出现前 4 字节指纹 A2.key.fp，完整密钥不得出现在任何报告字段里。
func TestA2KeyNotLeakedInReport(t *testing.T) {
	art := newArtifact(zipx.NewStored("classes.dex", smallDexWithClass(t, "Lapp/A;")))
	opts := &config.Options{
		Enabled: map[config.FeatureID]bool{"A2": true},
		Seed:    "a2audit",
	}
	if err := (&encryptString{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A2 执行失败: %v", err)
	}

	key, err := deriveKey(opts.DexKey, opts.Seed)
	if err != nil {
		t.Fatalf("派生密钥失败: %v", err)
	}
	full := fmt.Sprintf("%x", key)

	if _, ok := art.Stats["A2.key"]; ok {
		t.Fatal("统计里仍存在 A2.key（完整密钥会随产物交付）")
	}
	if got := art.Stats["A2.key.fp"]; got != full[:8] {
		t.Fatalf("A2.key.fp = %q，期望前 4 字节指纹 %q", got, full[:8])
	}
	// 完整 64 位十六进制密钥不得出现在任何统计值或说明里。
	for k, v := range art.Stats {
		if strings.Contains(v, full) {
			t.Fatalf("统计 %s 泄露了完整密钥: %s", k, v)
		}
	}
	for _, n := range art.Notes {
		if strings.Contains(n, full) {
			t.Fatalf("说明泄露了完整密钥: %s", n)
		}
	}
	t.Logf("A2 报告仅含指纹 %s，未泄露完整密钥", full[:8])
}
