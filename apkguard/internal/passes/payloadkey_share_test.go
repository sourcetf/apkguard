package passes

import (
	"context"
	"testing"

	"apkguard/internal/config"
	"apkguard/internal/pipeline"
	"apkguard/internal/zipx"
)

// TestB1AndC2SharePayloadKey 断言 B1（DEX 载荷）与 C2（原生库载荷）拿到同一把密钥。
//
// 为什么必须有这条：DexKey 留空时密钥是**随机**生成的（绝不能回退到固定常量，
// 否则产物等价于明文）。B1 与 C2 是两个独立的 Pass，各自调用一次密钥解析；
// 若不共享结果，两次随机调用必然得到两把不同的密钥，壳就没法用一把密钥同时
// 解开 DEX 载荷与库载荷——B3 会直接报
// 「C2 的 SO 载荷密钥与 B1 载荷密钥不一致，无法由同一个壳解密」。
// 这条缺陷曾被 e2e 的 C2 功能集抓到，这里用更快的单元回归钉住。
func TestB1AndC2SharePayloadKey(t *testing.T) {
	art := loadSample(t)
	// 造一个可被 C2 处理的原生库（C2 检测到 Flutter 特征会整体跳过，故名字普通）。
	pipeline.Add(art, zipx.NewStored("lib/arm64-v8a/libfoo.so", make([]byte, 4096)))

	opts := &config.Options{
		Enabled: map[config.FeatureID]bool{"B1": true, "C2": true},
		// 故意留空 DexKey：走随机密钥路径，这正是曾经出错的分支。
		Seed: "sharekey",
	}
	ctx := context.Background()
	if err := (&encryptDex{}).Run(ctx, art, opts); err != nil {
		t.Fatalf("B1 执行失败: %v", err)
	}
	if err := (&encryptNativeLibs{}).Run(ctx, art, opts); err != nil {
		t.Fatalf("C2 执行失败: %v", err)
	}

	// 与壳侧的一致性校验同源：B3 读到的两把密钥必须相等。
	pl := payloadsOf(art)
	sl := soLibsOf(art)
	if pl == nil || sl == nil {
		t.Fatalf("载荷清单缺失：payloads=%v solibs=%v", pl != nil, sl != nil)
	}
	if pl.Key != sl.Key {
		t.Fatalf("B1 与 C2 的载荷密钥不一致：B1=%x C2=%x（壳无法用一把密钥解两者）", pl.Key[:4], sl.Key[:4])
	}
	if sl.Key == [32]byte{} {
		t.Fatal("载荷密钥为零值")
	}
}
