package passes

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"testing"

	"apkguard/internal/config"
	"apkguard/internal/pipeline"
)

// 同 seed 两次运行必须逐字节一致（A1 确定性回归）。
func TestAuditRenameDeterministic(t *testing.T) {
	in := os.Getenv("DET_APK")
	if in == "" {
		in = "../../../testapp/testapp-signed.apk"
	}
	ks := os.Getenv("DET_KS")
	if ks == "" {
		ks = "../../../testapp/build/test.jks"
	}
	if _, err := os.Stat(in); err != nil {
		t.Skip("找不到测试 APK")
	}
	run := func() string {
		opts := &config.Options{
			Enabled: map[config.FeatureID]bool{"A1": true, "E1": true, "E2": true, "E3": true},
			In:      in, KS: ks, KSPass: "123456",
			Seed: "FIXEDSEED",
		}
		pipe := pipeline.New(Registry(), pipeline.DefaultSink{})
		res, err := pipe.Run(context.Background(), opts)
		if err != nil {
			t.Fatalf("运行失败: %v", err)
		}
		return fmt.Sprintf("%x", sha256.Sum256(res.APK))
	}
	a, b := run(), run()
	if a != b {
		t.Fatalf("同 seed 两次产物不同:\n  %s\n  %s", a, b)
	}
	t.Logf("同 seed 两次产物一致: %s", a[:16])
}
