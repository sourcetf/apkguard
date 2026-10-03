package config

import (
	"strings"
	"testing"
)

// TestC1DescriptionMatchesImplementation 钉住 C1 的功能描述与真实实现一致。
//
// 审计发现 Desc 曾声称「密钥由 native 结合设备指纹、APK 签名、编译期随机
// 种子派生」，而实现（internal/native/derive.go）是
//
//	key = SHA-256(.so 内的固定种子 ‖ 签名证书摘要)
//
// 种子是编译期写死的常量（仅以异或掩码存放，属混淆而非随机），**没有任何
// 设备指纹参与**。这是诚实性问题：描述让人以为密钥会随设备变化。
//
// 为什么不能「顺手实现设备指纹」：载荷密钥必须在打包时算出用于加密，而设备
// 指纹只有运行时才知道；要让密钥随设备变化，必须由使用方在打包时提供目标设备
// 标识——那正是 D5（设备绑定）在做的事。因此正确做法是把描述改准确。
func TestC1DescriptionMatchesImplementation(t *testing.T) {
	f, ok := ByID()["C1"]
	if !ok {
		t.Fatal("找不到 C1")
	}
	// 不得再出现「设备指纹 / 随机种子」这类实现里没有的能力。
	for _, bad := range []string{"设备指纹", "随机种子", "随机"} {
		if strings.Contains(f.Desc, bad) {
			t.Errorf("C1 Desc 不应声称 %q（实现中种子是 .so 内固定常量，且无设备指纹参与）: %q",
				bad, f.Desc)
		}
	}
	// 应说明密钥的真实派生输入：签名证书摘要。
	if !strings.Contains(f.Desc, "签名证书摘要") {
		t.Errorf("C1 Desc 应说明密钥结合签名证书摘要派生，实际 %q", f.Desc)
	}
	// Note 必须写明真实边界，避免使用者高估防护强度：
	// 种子是 .so 里的固定常量；设备绑定属 D5。
	if !strings.Contains(f.Note, "固定") {
		t.Errorf("C1 Note 应写明种子是 .so 内的固定常量（混淆而非随机），实际 %q", f.Note)
	}
	if !strings.Contains(f.Note, "D5") {
		t.Errorf("C1 Note 应指出设备绑定是 D5 的职责，实际 %q", f.Note)
	}
}
