package axml

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// align4Test 是本包测试专用的 4 字节对齐（刻意不复用生产代码，保证测试
// 在修复前后都能编译——否则「修前失败」就退化成「修前编译不过」）。
func align4Test(n int) int {
	if r := n % 4; r != 0 {
		return n + 4 - r
	}
	return n
}

// buildStyledPoolUTF8 手工构造一个带 style 的 UTF-8 字符串池。
//
// styleOffs 长度为 styleCount，每项相对 stylesStart；styleData 是 style 数据区。
// 不依赖任何新 API，因此可用于「修前失败」复现。
func buildStyledPoolUTF8(strs []string, styleOffs []uint32, styleData []byte) []byte {
	n := len(strs)
	styleCount := len(styleOffs)
	datas := make([][]byte, n)
	dataLen := 0
	for i, s := range strs {
		datas[i] = encodeUTF8String(s)
		dataLen += len(datas[i])
	}
	stringsStart := 28 + n*4 + styleCount*4
	stylesStart := align4Test(stringsStart + dataLen)
	size := align4Test(stylesStart + len(styleData))

	out := make([]byte, size)
	binary.LittleEndian.PutUint16(out[0:], TypeStringPool)
	binary.LittleEndian.PutUint16(out[2:], 28)
	binary.LittleEndian.PutUint32(out[4:], uint32(size))
	binary.LittleEndian.PutUint32(out[8:], uint32(n))
	binary.LittleEndian.PutUint32(out[12:], uint32(styleCount))
	binary.LittleEndian.PutUint32(out[16:], utf8Flag)
	binary.LittleEndian.PutUint32(out[20:], uint32(stringsStart))
	binary.LittleEndian.PutUint32(out[24:], uint32(stylesStart))

	p := stringsStart
	for i, b := range datas {
		binary.LittleEndian.PutUint32(out[28+4*i:], uint32(p-stringsStart))
		copy(out[p:], b)
		p += len(b)
	}
	for i, o := range styleOffs {
		binary.LittleEndian.PutUint32(out[28+n*4+4*i:], o)
	}
	copy(out[stylesStart:], styleData)
	return out
}

// styleSpanBytes 构造一条 ResStringPool_span（name + firstChar + lastChar）。
func styleSpanBytes(name, first, last uint32) []byte {
	b := make([]byte, 12)
	binary.LittleEndian.PutUint32(b[0:], name)
	binary.LittleEndian.PutUint32(b[4:], first)
	binary.LittleEndian.PutUint32(b[8:], last)
	return b
}

// styleEndBytes 是 style 条目的结束标记（仅 4 字节 name = 0xffffffff）。
func styleEndBytes() []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b[0:], noEntry)
	return b
}

// poolStyleHeader 读取字符串池的 count/styleCount/stylesStart/块大小。
func poolStyleHeader(data []byte, off int) (count, styleCount, stylesStart, size int) {
	if off+28 > len(data) {
		return 0, 0, 0, 0
	}
	count = int(binary.LittleEndian.Uint32(data[off+8:]))
	styleCount = int(binary.LittleEndian.Uint32(data[off+12:]))
	stylesStart = int(binary.LittleEndian.Uint32(data[off+24:]))
	size = int(binary.LittleEndian.Uint32(data[off+4:]))
	return
}

// styledPoolFixture 返回 (池字节, 原始 style 偏移数组, 原始 style 数据区)。
func styledPoolFixture(t *testing.T) ([]byte, []uint32, []byte) {
	t.Helper()
	strs := []string{"hello", "world", "styled"}
	// 三条里前两条带 style（styleCount=2）：第一条一个 span，第二条一个 span。
	styleData := append(styleSpanBytes(2, 0, 4), styleEndBytes()...)
	styleData = append(styleData, styleSpanBytes(2, 1, 2)...)
	styleData = append(styleData, styleEndBytes()...)
	styleOffs := []uint32{0, 16}
	return buildStyledPoolUTF8(strs, styleOffs, styleData), styleOffs, styleData
}

// TestRewritePreservesStyles 钉住「axml.Rewrite 重建池时不丢弃 style」。
//
// 修前行为：encodeStringPool 无条件把 styleCount/stylesStart 置 0，
// 带 style 的 Manifest 经 Rewrite 后样式数据全部丢失。
func TestRewritePreservesStyles(t *testing.T) {
	pool, wantOffs, wantData := styledPoolFixture(t)
	data := wrapPool(pool)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if f.Count() != 3 {
		t.Fatalf("字符串数量应为 3，实际 %d", f.Count())
	}

	out, err := f.Rewrite(Edit{Replace: map[string]string{"hello": "HELLO"}})
	if err != nil {
		t.Fatalf("Rewrite 失败: %v", err)
	}

	// 产物池位于根块头之后（wrapPool 的根块头为 8 字节）。
	const poolOff = 8
	count, styleCount, stylesStart, size := poolStyleHeader(out, poolOff)
	if count != 3 {
		t.Fatalf("字符串数量变化: 3 -> %d", count)
	}
	if styleCount != 2 {
		t.Fatalf("styleCount 被丢弃: 期望 2，实际 %d", styleCount)
	}
	gotData := out[poolOff+stylesStart : poolOff+size]
	if !bytes.Equal(gotData, wantData) {
		t.Fatalf("style 数据区被改动：原始 %d 字节，产物 %d 字节\n原始 %x\n产物 %x",
			len(wantData), len(gotData), wantData, gotData)
	}
	for i, want := range wantOffs {
		got := binary.LittleEndian.Uint32(out[poolOff+28+count*4+4*i:])
		if got != want {
			t.Fatalf("第 %d 个 style 偏移不符: %d != %d", i, got, want)
		}
	}

	// 文本确实被改写，且其它条目保持不变。
	nf, err := Parse(out)
	if err != nil {
		t.Fatalf("改写结果无法重新解析: %v", err)
	}
	got := nf.Strings()
	wantStrs := []string{"HELLO", "world", "styled"}
	for i := range wantStrs {
		if got[i] != wantStrs[i] {
			t.Fatalf("第 %d 条不符: %q != %q", i, got[i], wantStrs[i])
		}
	}
}

// TestUTF16LongStringLength 钉住「utf16Len 长格式长度不再被截断为 16 位」。
//
// 构造一个码元数 70000（> 65535）的 UTF-16 池字符串：长格式首字 0x8001、
// 次字 4464。修前实现只取次字，读取长度变成 4464，字符串被截断。
func TestUTF16LongStringLength(t *testing.T) {
	const n = 70000
	long := strings.Repeat("x", n)
	blob := encodeStringPool([]string{long}, false)
	f, err := Parse(wrapPool(blob))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	got, err := f.String(0)
	if err != nil {
		t.Fatalf("读取字符串失败: %v", err)
	}
	if len(got) != n {
		t.Fatalf("长格式字符串长度被截断: 期望 %d，实际 %d（低 16 位 = %d）",
			n, len(got), n&0xffff)
	}
	if got != long {
		t.Fatalf("长格式字符串内容不符（前 8 字节 %q）", got[:minInt(8, len(got))])
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestEncodeStringPoolWithStylesGrowth 验证「字符串变多（追加）时 style 仍保留」——
// 这正是 SetAttr / AddElements 往池尾 intern 新文本的路径。
func TestEncodeStringPoolWithStylesGrowth(t *testing.T) {
	_, offs, sdata := styledPoolFixture(t)
	strs := []string{"hello", "world", "styled", "appended-new"}
	st := &Styles{Count: len(offs), Offsets: offs, Data: sdata}
	blob, err := EncodeStringPoolWithStyles(strs, true, st)
	if err != nil {
		t.Fatalf("编码失败: %v", err)
	}
	f, err := Parse(wrapPool(blob))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if f.Count() != len(strs) {
		t.Fatalf("字符串数量应为 %d，实际 %d", len(strs), f.Count())
	}
	count, styleCount, stylesStart, size := poolStyleHeader(blob, 0)
	if count != len(strs) || styleCount != len(offs) {
		t.Fatalf("count/styleCount 不符: count=%d styleCount=%d", count, styleCount)
	}
	if got := blob[stylesStart:size]; !bytes.Equal(got, sdata) {
		t.Fatalf("追加字符串后 style 数据区被改动：%x != %x", got, sdata)
	}
	for i, want := range offs {
		got := binary.LittleEndian.Uint32(blob[28+count*4+4*i:])
		if got != want {
			t.Fatalf("第 %d 个 style 偏移不符: %d != %d", i, got, want)
		}
	}
}

// TestEncodeStringPoolWithStylesTooFewStrings 验证「字符串变少到无法安全保留
// style」时显式报错，而不是静默把 styleCount 置零。
func TestEncodeStringPoolWithStylesTooFewStrings(t *testing.T) {
	_, offs, sdata := styledPoolFixture(t)
	st := &Styles{Count: len(offs), Offsets: offs, Data: sdata}
	if _, err := EncodeStringPoolWithStyles([]string{"only-one"}, true, st); err == nil {
		t.Fatal("字符串数量少于 styleCount 时应报错，绝不静默丢弃 style")
	}
}
