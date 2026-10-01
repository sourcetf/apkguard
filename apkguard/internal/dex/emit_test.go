package dex

import (
	"os"
	"path/filepath"
	"testing"
)

// TestEmitRebuilt 把恒等重建结果落盘，供官方 dexdump 交叉校验。
func TestEmitRebuilt(t *testing.T) {
	data := sampleDex(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	out, err := Rebuild(f, RebuildOptions{})
	if err != nil {
		t.Fatalf("重建失败: %v", err)
	}
	// 落盘位置在仓库根的 dex_tmp/（已被 .gitignore 忽略），供人工用官方
	// dexdump 交叉校验。目录可能不存在，先建出来——不能假设它一定在。
	dir := filepath.Join("..", "..", "..", "dex_tmp")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("创建目录失败: %v", err)
	}
	dst := filepath.Join(dir, "rebuilt-identity.dex")
	if err := os.WriteFile(dst, out, 0o644); err != nil {
		t.Fatalf("写盘失败: %v", err)
	}
	t.Logf("已写出 %s (%d 字节)", dst, len(out))
}
