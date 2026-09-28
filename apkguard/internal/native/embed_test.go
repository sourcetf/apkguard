package native

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"testing"
)

// TestPrebuiltIntegrityDigest 独立复核 C6 的期望摘要。
//
// C6 的运行时逻辑是「哈希自身 .text 与 .rodata，与 .agexpect 中的期望值
// 比对」。这里用 Go 的 debug/elf（与构建脚本的 Python 解析器相互独立）
// 重算一遍，确保：
//   - 期望值确实等于那两个节的内容摘要；
//   - 三个 ABI（含 32 位的 armeabi-v7a）都能被正确解析。
//
// 这条测试的价值在于：C6 一旦算错，产物会在真机上「自己判定自己
// 被篡改」而直接退出——那是最严重的自伤，必须在打包前就拦住。
func TestPrebuiltIntegrityDigest(t *testing.T) {
	libs, err := Prebuilt()
	if err != nil {
		t.Fatalf("读取预编译库失败: %v", err)
	}
	for _, l := range libs {
		f, err := elf.NewFile(bytes.NewReader(l.Data))
		if err != nil {
			t.Fatalf("%s: 解析 ELF 失败: %v", l.Abi, err)
		}
		// 运行时按 .text 再 .rodata 的顺序哈希。
		h := sha256.New()
		for _, name := range []string{".text", ".rodata"} {
			sec := f.Section(name)
			if sec == nil {
				f.Close()
				t.Fatalf("%s: 缺少节 %s", l.Abi, name)
			}
			// sec.Open 返回 io.ReadSeeker，节内容由 Section.Data 一次性取得。
			data, err := sec.Data()
			if err != nil {
				f.Close()
				t.Fatalf("%s: 读取节 %s 失败: %v", l.Abi, name, err)
			}
			h.Write(data)
		}
		want := h.Sum(nil)

		xs := f.Section(".agexpect")
		if xs == nil {
			f.Close()
			t.Fatalf("%s: 缺少 .agexpect 节（期望值未独立存放，会产生自指）", l.Abi)
		}
		got := make([]byte, 32)
		read, err := xs.ReadAt(got, 0)
		f.Close()
		if err != nil && read < 32 {
			t.Fatalf("%s: 读取期望值失败: %v", l.Abi, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s: 期望摘要与节内容不符——C6 会在真机上误判为被篡改\n  节内容 %x\n  期望值 %x",
				l.Abi, want, got)
		}
		// 期望值不能是占位全零（说明构建脚本没回填）。
		if bytes.Equal(got, make([]byte, 32)) {
			t.Fatalf("%s: 期望值仍为全零占位，构建脚本未回填", l.Abi)
		}
		t.Logf("%s: 完整性摘要一致（%x…）", l.Abi, got[:8])
	}
}

// TestPrebuiltCoversAllAbis 验证 ABI 集合完整。
//
// 少一个 ABI 就意味着对应架构的设备装不上（Android 安装时按 ABI 校验
// 原生库），这类问题漏到线上很难定位。
func TestPrebuiltCoversAllAbis(t *testing.T) {
	libs, err := Prebuilt()
	if err != nil {
		t.Fatalf("读取预编译库失败: %v", err)
	}
	got := map[string]bool{}
	for _, l := range libs {
		got[l.Abi] = true
		if len(l.Data) == 0 {
			t.Errorf("%s: 库内容为空", l.Abi)
		}
		if l.Entry != "lib/"+l.Abi+"/"+LibFileName {
			t.Errorf("%s: 条目名不符: %s", l.Abi, l.Entry)
		}
	}
	for _, want := range []string{"arm64-v8a", "armeabi-v7a", "x86_64"} {
		if !got[want] {
			t.Errorf("缺少 ABI %s", want)
		}
	}
}
