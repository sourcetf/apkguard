package dex

import (
	"os"
	"testing"
)

// TestOriginalDexStaticValues 用同一套守卫检查「未经加固的原始 dex」。
//
// 这是对守卫自身假设的验证：原始文件必然被 ART 接受，因此它必须通过。
// 若不通过，说明守卫（以及 static_values 重排实现）对「值↔字段对应顺序」
// 的理解有误。
//
// 样本优先用开发机上 RustDesk 的原始 dex（类多、覆盖面广），
// 缺席时回落到仓库内固件 testdata/sample.dex——语义相同（都是未经改写的
// 真实 d8 产物），但保证干净检出下这条守卫也能跑。
func TestOriginalDexStaticValues(t *testing.T) {
	path := ""
	for _, p := range []string{
		"../../../realworld/orig.dex",
		"../../../testapp/build/dex/classes.dex",
		"../../../testdata/sample.dex",
	} {
		if st, err := os.Stat(p); err == nil && st.Size() > 0 {
			path = p
			break
		}
	}
	if path == "" {
		t.Skip("未找到原始 dex 样本，跳过")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 %s 失败: %v", path, err)
	}
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	n := checkStaticValues(t, "原始 dex", f)
	t.Logf("原始 dex（%s）检查了 %d 个类的 static_values", path, n)
}
