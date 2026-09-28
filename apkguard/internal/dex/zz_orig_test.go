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
func TestOriginalDexStaticValues(t *testing.T) {
	data, err := os.ReadFile("../../../realworld/orig.dex")
	if err != nil {
		t.Skipf("未找到原始样本: %v", err)
	}
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	n := checkStaticValues(t, "原始 dex", f)
	t.Logf("原始 dex 检查了 %d 个类的 static_values", n)
}
