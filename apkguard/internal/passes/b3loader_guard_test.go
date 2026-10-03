package passes

import (
	"context"
	"testing"

	"apkguard/internal/config"
	"apkguard/internal/pipeline"
)

// TestB3WithoutB1IsRejected 断言「启用 B3 但不启用 B1」被配置层拦住。
//
// 这条组合曾经能通过校验并产出「看起来成功」的 APK：B2 只看到 B3 启用就让壳
// 生成对 `Lcom/apkguard/shell/Loader;` 的调用，而 B3 在没有加密载荷时会提前
// 返回、**不注入 Loader 类体**。于是产物引用一个从未定义的类，应用一启动就
// NoClassDefFoundError——而 Validate 与 CLI 都报成功。这是最糟的失败模式：
// 用户以为加固完成了，实际产物根本起不来。
func TestB3WithoutB1IsRejected(t *testing.T) {
	opts := &config.Options{Enabled: map[config.FeatureID]bool{"B2": true, "B3": true}}
	err := opts.Validate()
	if err == nil {
		t.Fatal("B2+B3 且未启用 B1 应被拒绝（否则产物会引用未定义的 Loader 类）")
	}
	// 依赖关系必须指向 B1，且提示要说得清是为什么。
	if !contains(err.Error(), "B1") || !contains(err.Error(), "B3") {
		t.Fatalf("错误信息应同时点名 B3 与 B1，实际: %v", err)
	}
	// 加了 B1 之后，与依赖相关的错误必须消失（其余校验错误如「必须指定输入 APK」
	// 与本条无关，只看是否还在报依赖）。
	opts.SetEnabled("B1", true)
	if err := opts.Validate(); err != nil && contains(err.Error(), "B3") {
		t.Fatalf("B1+B2+B3 不应再报 B3 的依赖错误，实际: %v", err)
	}
}

// TestB2DoesNotReferenceLoaderWithoutB1 从产物侧再钉一次：壳 DEX 不得出现
// 对 Loader 的引用，除非 Loader 类真的被定义了。
func TestB2DoesNotReferenceLoaderWithoutB1(t *testing.T) {
	art := loadSample(t)
	opts := &config.Options{
		Enabled: map[config.FeatureID]bool{"B2": true, "B3": true},
		Seed:    "b3guard",
	}
	// 直接调用 B2：即便绕过 Validate，也不得写出对 Loader 的引用。
	if err := (&appReplace{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("B2 执行失败: %v", err)
	}
	info, _ := art.Get(sharedKeyShell).(*shellInfo)
	if info == nil {
		t.Fatal("未找到壳信息")
	}
	if info.LoaderClass != "" {
		t.Fatalf("未启用 B1 时壳不应引用 Loader，实际 LoaderClass=%q", info.LoaderClass)
	}

	// 反向：启用 B1 时必须带上 Loader（否则 B3 注入的类没人调用）。
	art2 := loadSample(t)
	opts2 := &config.Options{
		Enabled: map[config.FeatureID]bool{"B1": true, "B2": true, "B3": true},
		Seed:    "b3guard",
	}
	if err := (&appReplace{}).Run(context.Background(), art2, opts2); err != nil {
		t.Fatalf("B2 执行失败: %v", err)
	}
	info2, _ := art2.Get(sharedKeyShell).(*shellInfo)
	if info2 == nil || info2.LoaderClass == "" {
		t.Fatalf("启用 B1 时壳应引用 Loader 类，实际 %+v", info2)
	}
	if want := "L" + shellPkgOf(opts2) + "/Loader;"; info2.LoaderClass != want {
		t.Fatalf("Loader 类描述符不符: got %q want %q", info2.LoaderClass, want)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

var _ = pipeline.LevelZip
