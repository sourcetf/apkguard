package arsc

import (
	"archive/zip"
	"encoding/binary"
	"io"
	"testing"

	"apkguard/internal/axml"
)

// wrapPool 把字符串池块包进一张最小的 ResTable（表头 + 池块）。
//
// arsc.Parse 只走到「能改字符串池」的程度，因此这些字节足够；真实资源表的
// package/TypeSpec/Type 块与改写无关（见包注释）。
func wrapPool(t *testing.T, strs []string, utf8Pool bool) []byte {
	t.Helper()
	pool := axml.EncodeStringPool(strs, utf8Pool)
	out := make([]byte, 12+len(pool))
	binary.LittleEndian.PutUint16(out[0:], 0x0002) // RES_TABLE_TYPE
	binary.LittleEndian.PutUint16(out[2:], 12)     // 表头长度
	binary.LittleEndian.PutUint32(out[4:], uint32(len(out)))
	binary.LittleEndian.PutUint32(out[8:], 0) // packageCount
	copy(out[12:], pool)
	return out
}

// TestParseAndEncodeIdentity 校验解析结果与「无改写时逐字节返回原数据」。
func TestParseAndEncodeIdentity(t *testing.T) {
	strs := []string{"res/layout/main.xml", "hello", "res/drawable/icon.png"}

	for _, utf8Pool := range []bool{true, false} {
		raw := wrapPool(t, strs, utf8Pool)
		tbl, err := Parse(raw)
		if err != nil {
			t.Fatalf("解析失败（utf8=%v）: %v", utf8Pool, err)
		}
		got := tbl.Strings()
		if len(got) != len(strs) {
			t.Fatalf("字符串数量不符（utf8=%v）: %d != %d（%v）", utf8Pool, len(got), len(strs), got)
		}
		for i := range strs {
			if got[i] != strs[i] {
				t.Fatalf("字符串 %d 不符（utf8=%v）: %q != %q", i, utf8Pool, got[i], strs[i])
			}
		}
		if tbl.UTF8() != utf8Pool {
			t.Errorf("池编码判断错误: UTF8()=%v，期望 %v", tbl.UTF8(), utf8Pool)
		}
		// 无改写时应当逐字节返回原数据（不重排、不丢字节）
		out, err := tbl.Encode()
		if err != nil {
			t.Fatalf("编码失败: %v", err)
		}
		if string(out) != string(raw) {
			t.Fatalf("无改写时产物应与原数据一致（utf8=%v）：%d -> %d 字节", utf8Pool, len(raw), len(out))
		}
	}
}

// TestNonASCIIStringsRoundTrip 钉住「非 ASCII 字符串不被截断」。
//
// 真实缺陷：UTF-8 池里有两个长度前缀，顺序是「UTF-16 码元数」在前、
// 「UTF-8 字节数」在后。早期实现把前者当字节数用，于是任何非 ASCII 字符串都被
// 截断（中文 1 码元 = 3 字节），而 Encode() 会把截断后的值整池写回——中文资源
// 被静默损坏。ASCII 串两者相等，所以本地测试一直没发现。
// 同一次修复里还修了 UTF-16 池的长度前缀（那里是小端 u16、不是变长整数，
// 读错会让整池解码成乱码）。
func TestNonASCIIStringsRoundTrip(t *testing.T) {
	strs := []string{
		"res/drawable/图标.png",
		"你好，世界",
		"res/values/字符串.xml",
		"ASCII-only",
		"emoji 😀 mixed", // 非 BMP：UTF-8 里是 4 字节
	}
	for _, utf8Pool := range []bool{true, false} {
		raw := wrapPool(t, strs, utf8Pool)
		tbl, err := Parse(raw)
		if err != nil {
			t.Fatalf("解析失败（utf8=%v）: %v", utf8Pool, err)
		}
		got := tbl.Strings()
		for i := range strs {
			if got[i] != strs[i] {
				t.Fatalf("utf8=%v 第 %d 条被损坏: 原始 %q，解析 %q", utf8Pool, i, strs[i], got[i])
			}
		}
		// 无改写时必须逐字节还原（若解析被截断，这里会把截断值写回）
		out, err := tbl.Encode()
		if err != nil {
			t.Fatalf("编码失败: %v", err)
		}
		if len(out) != len(raw) {
			t.Fatalf("utf8=%v 无改写时产物长度应不变: %d -> %d", utf8Pool, len(raw), len(out))
		}
		for i := range raw {
			if raw[i] != out[i] {
				t.Fatalf("utf8=%v 无改写时产物与原数据不一致（第 %d 字节起）——非 ASCII 串被改写回去了", utf8Pool, i)
			}
		}
		// res/ 路径（含中文文件名）必须被识别出来
		if n := len(tbl.ResPaths()); n != 2 {
			t.Fatalf("utf8=%v 应识别出 2 条 res/ 路径（含中文名），实际 %d: %v", utf8Pool, n, tbl.ResPaths())
		}
	}
	t.Log("非 ASCII（中文与 emoji）在 UTF-8 / UTF-16 两种池下均原样往返")
}

// TestResPathsAndReplace 校验 res/ 路径识别与改写（含长度变化）。
func TestResPathsAndReplace(t *testing.T) {
	strs := []string{"res/layout/main.xml", "hello", "res/drawable/icon.png"}
	raw := wrapPool(t, strs, true)
	tbl, err := Parse(raw)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	paths := tbl.ResPaths()
	if len(paths) != 2 {
		t.Fatalf("应识别出 2 条 res/ 路径，实际 %v", paths)
	}

	// 改名：一条变长、一条变短，验证长度变化不影响其它条目
	if n := tbl.Replace("res/layout/main.xml", "res/a/b/c/d/e/f/g.xml"); n != 1 {
		t.Fatalf("替换应命中 1 处，实际 %d", n)
	}
	if n := tbl.Replace("res/drawable/icon.png", "res/x.png"); n != 1 {
		t.Fatalf("替换应命中 1 处，实际 %d", n)
	}
	out, err := tbl.Encode()
	if err != nil {
		t.Fatalf("编码失败: %v", err)
	}
	again, err := Parse(out)
	if err != nil {
		t.Fatalf("改写后再解析失败: %v", err)
	}
	got := again.Strings()
	want := []string{"res/a/b/c/d/e/f/g.xml", "hello", "res/x.png"}
	if len(got) != len(want) {
		t.Fatalf("改写后字符串数量变化: %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("改写后第 %d 条不符: %q != %q（其余条目应保持不变）", i, got[i], want[i])
		}
	}
	if ps := again.ResPaths(); len(ps) != 2 {
		t.Fatalf("改写后 res/ 路径应仍为 2 条，实际 %v", ps)
	}
}

// TestParseRealArsc 用仓库固件里的真实 resources.arsc 跑一遍解析与改写。
func TestParseRealArsc(t *testing.T) {
	const apk = "../../../testdata/sample.apk"
	zr, err := zip.OpenReader(apk)
	if err != nil {
		t.Skipf("样本 APK 不在，跳过: %v", err)
	}
	defer zr.Close()
	var data []byte
	for _, f := range zr.File {
		if f.Name != "resources.arsc" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("读取 resources.arsc 失败: %v", err)
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("读取 resources.arsc 失败: %v", err)
		}
		data = b
	}
	if data == nil {
		t.Skip("样本 APK 里没有 resources.arsc")
	}
	tbl, err := Parse(data)
	if err != nil {
		t.Fatalf("解析真实 resources.arsc 失败: %v", err)
	}
	if len(tbl.Strings()) == 0 {
		t.Fatal("真实资源表的字符串池为空")
	}
	// 真实样本（testapp）应至少有一条 res/ 路径（A5/A11 的判据依赖它）
	if len(tbl.ResPaths()) == 0 {
		t.Error("真实资源表里没有 res/ 路径：testapp 固件应包含文件型资源")
	}
	// 无改写时必须逐字节还原
	out, err := tbl.Encode()
	if err != nil {
		t.Fatalf("编码失败: %v", err)
	}
	if string(out) != string(data) {
		t.Fatalf("无改写时产物应与原数据一致: %d -> %d 字节", len(data), len(out))
	}
	t.Logf("真实资源表：%d 条字符串、%d 条 res/ 路径", len(tbl.Strings()), len(tbl.ResPaths()))
}

// TestParseRejectsNonArsc 校验非法输入被明确拒绝（而不是产出垃圾）。
func TestParseRejectsNonArsc(t *testing.T) {
	for name, data := range map[string][]byte{
		"过短":      {1, 2, 3},
		"非资源表":    append([]byte{0x03, 0x00}, make([]byte, 64)...),
		"池块非法":    append(append([]byte{0x02, 0x00, 0x0c, 0x00}, make([]byte, 8)...), make([]byte, 8)...),
		"截断的真实数据": []byte{0x02, 0x00, 0x0c, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	} {
		if _, err := Parse(data); err == nil {
			t.Errorf("%s：应当报错", name)
		}
	}
}
