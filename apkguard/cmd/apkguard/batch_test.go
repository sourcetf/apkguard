package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"apkguard/internal/config"
)

// TestBatchProcessesDirectory 校验 E5 目录批量：逐个产出、跳过自己的产物、忽略非 APK。
//
// 批量是最容易「静默做错」的功能：路径算错会把结果写到别处，跳过规则写错会把
// 上一次的产物再加固一遍（层层套壳），而两者都不会报错。
func TestBatchProcessesDirectory(t *testing.T) {
	src := fixtureAPK(t)
	in := t.TempDir()
	out := t.TempDir()

	mk := func(name string) {
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatalf("读取样本失败: %v", err)
		}
		if err := os.WriteFile(filepath.Join(in, name), b, 0o644); err != nil {
			t.Fatalf("写出 %s 失败: %v", name, err)
		}
	}
	mk("a.apk")
	mk("b.apk")
	mk("c-protected.apk") // 本工具自己的产物：不应被再加固一遍
	if err := os.WriteFile(filepath.Join(in, "readme.txt"), []byte("not an apk"), 0o644); err != nil {
		t.Fatalf("写出非 APK 文件失败: %v", err)
	}

	opts := &config.Options{
		In:  in,
		Out: out,
		// E1 默认是开启的，必须显式关掉：批量逻辑本身是测试目标，不必依赖密钥库
		Enabled: map[config.FeatureID]bool{"E1": false, "E2": false, "E3": false, "E5": true},
	}
	if err := runBatch(opts, 2); err != nil {
		t.Fatalf("批量执行失败: %v", err)
	}

	ents, err := os.ReadDir(out)
	if err != nil {
		t.Fatalf("读取输出目录失败: %v", err)
	}
	var got []string
	for _, e := range ents {
		got = append(got, e.Name())
	}
	if len(got) != 2 {
		t.Fatalf("应产出 2 个加固包（跳过 *-protected.apk 与非 APK），实际 %d 个: %v", len(got), got)
	}
	for _, name := range got {
		if !strings.HasSuffix(name, "-protected.apk") {
			t.Errorf("输出名不符合约定: %s", name)
		}
		if st, err := os.Stat(filepath.Join(out, name)); err != nil || st.Size() == 0 {
			t.Errorf("输出为空或不存在: %s", name)
		}
	}
	// 被跳过的那个不应产生输出
	if _, err := os.Stat(filepath.Join(out, "c-protected-protected.apk")); err == nil {
		t.Error("把上一次的产物又加固了一遍（层层套壳）")
	}
	t.Logf("批量产出 %v（跳过了 *-protected.apk 与非 APK 文件）", got)
}

// TestBatchRejectsEmptyDir 校验空目录给出明确错误而不是静默成功。
func TestBatchRejectsEmptyDir(t *testing.T) {
	dir := t.TempDir()
	opts := &config.Options{In: dir, Out: t.TempDir(), Enabled: map[config.FeatureID]bool{"E5": true}}
	if err := runBatch(opts, 1); err == nil {
		t.Fatal("空目录应报错")
	} else if !strings.Contains(err.Error(), "没有找到") {
		t.Fatalf("错误信息应点明没找到 APK，实际: %v", err)
	}
}

// TestBatchOutputPath 直接钉住输出路径的推导规则。
func TestBatchOutputPath(t *testing.T) {
	base := filepath.Join("D:", "apps")
	cases := []struct{ in, out, want string }{
		{filepath.Join(base, "x.apk"), "", filepath.Join(base, "x-protected.apk")},
		// 输出名固定为小写 .apk（与输入扩展名大小写无关，便于 re-run 时被跳过）
		{filepath.Join(base, "y.APK"), "", filepath.Join(base, "y-protected.apk")},
		{filepath.Join(base, "sub", "z.apk"), base, filepath.Join(base, "z-protected.apk")},
	}
	for _, c := range cases {
		if got := batchOutputPath(c.out, c.in, base); got != c.want {
			t.Errorf("batchOutputPath(%q, %q) = %q，期望 %q", c.out, c.in, got, c.want)
		}
	}
}
