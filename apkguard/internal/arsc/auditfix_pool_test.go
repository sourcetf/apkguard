package arsc

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"io"
	"strconv"
	"testing"
)

// align4Test 是测试专用的 4 字节对齐（不复用生产代码，保证修前也能编译）。
func align4Test(n int) int {
	if r := n % 4; r != 0 {
		return n + 4 - r
	}
	return n
}

// encASCIIPoolString 编码一个 ASCII 的 UTF-8 池字符串（字符数 == 字节数）。
// 合成样本只用 ASCII，避免测试依赖池编码细节。
func encASCIIPoolString(s string) []byte {
	b := []byte(s)
	if len(b) > 0x7f {
		panic("合成样本字符串过长")
	}
	out := make([]byte, 0, len(b)+3)
	out = append(out, byte(len(b)), byte(len(b)))
	out = append(out, b...)
	out = append(out, 0)
	return out
}

// buildRawStyledPool 手工构造一个带 style 的 UTF-8 字符串池。
func buildRawStyledPool(strs []string, styleOffs []uint32, styleData []byte) []byte {
	n := len(strs)
	styleCount := len(styleOffs)
	datas := make([][]byte, n)
	dataLen := 0
	for i, s := range strs {
		datas[i] = encASCIIPoolString(s)
		dataLen += len(datas[i])
	}
	stringsStart := poolHeaderLen + n*4 + styleCount*4
	stylesStart := align4Test(stringsStart + dataLen)
	size := align4Test(stylesStart + len(styleData))

	out := make([]byte, size)
	binary.LittleEndian.PutUint16(out[0:], typeStringPool)
	binary.LittleEndian.PutUint16(out[2:], poolHeaderLen)
	binary.LittleEndian.PutUint32(out[4:], uint32(size))
	binary.LittleEndian.PutUint32(out[8:], uint32(n))
	binary.LittleEndian.PutUint32(out[12:], uint32(styleCount))
	binary.LittleEndian.PutUint32(out[16:], utf8Flag)
	binary.LittleEndian.PutUint32(out[20:], uint32(stringsStart))
	binary.LittleEndian.PutUint32(out[24:], uint32(stylesStart))

	p := stringsStart
	for i, b := range datas {
		binary.LittleEndian.PutUint32(out[poolHeaderLen+4*i:], uint32(p-stringsStart))
		copy(out[p:], b)
		p += len(b)
	}
	for i, o := range styleOffs {
		binary.LittleEndian.PutUint32(out[poolHeaderLen+n*4+4*i:], o)
	}
	copy(out[stylesStart:], styleData)
	return out
}

// wrapRawTable 把已构造好的池块包进最小的 ResTable（表头 + 池块）。
func wrapRawTable(pool []byte) []byte {
	out := make([]byte, tableHeaderLen+len(pool))
	binary.LittleEndian.PutUint16(out[0:], typeTable)
	binary.LittleEndian.PutUint16(out[2:], tableHeaderLen)
	binary.LittleEndian.PutUint32(out[4:], uint32(len(out)))
	copy(out[tableHeaderLen:], pool)
	return out
}

// arscPoolHeader 读取表内全局字符串池的 count/styleCount/stylesStart/块大小。
func arscPoolHeader(data []byte, off int) (count, styleCount, stylesStart, size int) {
	if off+poolHeaderLen > len(data) {
		return 0, 0, 0, 0
	}
	count = int(binary.LittleEndian.Uint32(data[off+8:]))
	styleCount = int(binary.LittleEndian.Uint32(data[off+12:]))
	stylesStart = int(binary.LittleEndian.Uint32(data[off+24:]))
	size = int(binary.LittleEndian.Uint32(data[off+4:]))
	return
}

// arscStyleOffsets 读取 style 偏移数组。
func arscStyleOffsets(data []byte, off, count, styleCount int) []uint32 {
	offs := make([]uint32, styleCount)
	for i := range offs {
		offs[i] = binary.LittleEndian.Uint32(data[off+poolHeaderLen+count*4+4*i:])
	}
	return offs
}

func styleSpanBytes(name, first, last uint32) []byte {
	b := make([]byte, 12)
	binary.LittleEndian.PutUint32(b[0:], name)
	binary.LittleEndian.PutUint32(b[4:], first)
	binary.LittleEndian.PutUint32(b[8:], last)
	return b
}

func styleEndBytes() []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b[0:], 0xffffffff)
	return b
}

// TestEncodeIndexMappingNoChain 钉住「Encode 的索引映射不得按值级联改写」。
//
// strings=["a","b"]，先 Replace("a","b") 再 Replace("b","c")，edits={0:"b",1:"c"}。
// 正确结果 ["b","c"]；修前实现额外做「旧值→新值」二次映射，得到 ["c","c"]
// （"a" 被错误地变成 "c"）。
func TestEncodeIndexMappingNoChain(t *testing.T) {
	raw := wrapPool(t, []string{"a", "b"}, true)
	tbl, err := Parse(raw)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if n := tbl.Replace("a", "b"); n != 1 {
		t.Fatalf("Replace(a,b) 应命中 1 处，实际 %d", n)
	}
	if n := tbl.Replace("b", "c"); n != 1 {
		t.Fatalf("Replace(b,c) 应命中 1 处，实际 %d", n)
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
	want := []string{"b", "c"}
	if len(got) != len(want) {
		t.Fatalf("字符串数量变化: %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("级联改写缺陷：第 %d 条应为 %q，实际 %q（完整 %v）", i, want[i], got[i], got)
		}
	}
}

// TestSyntheticStyledArscRoundTrip 是纯合成的带 style 池往返测试，CI 上必然运行。
//
// 断言 Parse→Encode→Parse 后 styleCount、每条 style 偏移与 style 数据区原样保留。
func TestSyntheticStyledArscRoundTrip(t *testing.T) {
	strs := []string{"res/layout/a.xml", "res/layout/b.xml", "keep"}
	styleData := append(styleSpanBytes(2, 0, 4), styleEndBytes()...)
	styleData = append(styleData, styleSpanBytes(2, 1, 2)...)
	styleData = append(styleData, styleEndBytes()...)
	styleOffs := []uint32{0, 16}

	raw := wrapRawTable(buildRawStyledPool(strs, styleOffs, styleData))
	off0 := int(binary.LittleEndian.Uint16(raw[2:]))
	count0, sc0, ss0, sz0 := arscPoolHeader(raw, off0)
	if count0 != 3 || sc0 != 2 {
		t.Fatalf("合成池构造错误: count=%d styleCount=%d", count0, sc0)
	}
	origData := append([]byte(nil), raw[off0+ss0:off0+sz0]...)

	tbl, err := Parse(raw)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if got := tbl.Strings(); len(got) != 3 || got[0] != strs[0] {
		t.Fatalf("字符串解析错误: %v", got)
	}
	// 改写其中的路径（长度也变化），验证样式仍保留。
	if n := tbl.Replace("res/layout/a.xml", "res/a/very/long/new/path.xml"); n != 1 {
		t.Fatalf("替换应命中 1 处，实际 %d", n)
	}
	out, err := tbl.Encode()
	if err != nil {
		t.Fatalf("编码失败: %v", err)
	}

	off1 := int(binary.LittleEndian.Uint16(out[2:]))
	count1, sc1, ss1, sz1 := arscPoolHeader(out, off1)
	if count1 != count0 {
		t.Fatalf("字符串数量变化: %d -> %d", count0, count1)
	}
	if sc1 != sc0 {
		t.Fatalf("styleCount 丢失: %d -> %d", sc0, sc1)
	}
	gotOffs := arscStyleOffsets(out, off1, count1, sc1)
	for i := range styleOffs {
		if gotOffs[i] != styleOffs[i] {
			t.Fatalf("第 %d 个 style 偏移不符: %d != %d", i, gotOffs[i], styleOffs[i])
		}
	}
	if gotData := out[off1+ss1 : off1+sz1]; !bytes.Equal(gotData, origData) {
		t.Fatalf("style 数据区不一致：%d -> %d 字节\n原始 %x\n产物 %x",
			len(origData), len(gotData), origData, gotData)
	}

	again, err := Parse(out)
	if err != nil {
		t.Fatalf("改写后再解析失败: %v", err)
	}
	got := again.Strings()
	want := []string{"res/a/very/long/new/path.xml", "res/layout/b.xml", "keep"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("第 %d 条不符: %q != %q", i, got[i], want[i])
		}
	}
}

// TestUTF16PoolLongString 钉住 arsc 侧长格式（> 65535 码元）长度解码正确，
// 与 axml 的实现保持一致。
func TestUTF16PoolLongString(t *testing.T) {
	const units = 70000
	// UTF-16 池：长度前缀（长格式 0x8001 4464）+ 70000 个 'x' + NUL。
	str := make([]byte, 4+units*2+2)
	binary.LittleEndian.PutUint16(str[0:], uint16(0x8000|(units>>16)))
	binary.LittleEndian.PutUint16(str[2:], uint16(units&0xffff))
	for i := 0; i < units; i++ {
		binary.LittleEndian.PutUint16(str[4+i*2:], 'x')
	}
	pool := make([]byte, poolHeaderLen+4+len(str))
	binary.LittleEndian.PutUint16(pool[0:], typeStringPool)
	binary.LittleEndian.PutUint16(pool[2:], poolHeaderLen)
	binary.LittleEndian.PutUint32(pool[4:], uint32(len(pool)))
	binary.LittleEndian.PutUint32(pool[8:], 1)  // stringCount
	binary.LittleEndian.PutUint32(pool[16:], 0) // flags: UTF-16
	binary.LittleEndian.PutUint32(pool[20:], poolHeaderLen+4)
	copy(pool[poolHeaderLen+4:], str)

	tbl, err := Parse(wrapRawTable(pool))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	got := tbl.Strings()
	if len(got) != 1 {
		t.Fatalf("字符串数量应为 1，实际 %d", len(got))
	}
	if len(got[0]) != units {
		t.Fatalf("长格式长度被截断: 期望 %d，实际 %d", units, len(got[0]))
	}
}

// TestRealArscPreservesStyles 用真实带 style 的 resources.arsc 跑 Parse→编辑→Encode→Parse，
// 断言 styleCount、style 偏移数组与 style 数据区与原始逐字节一致。
//
// 证据（dhizuku.apk）：输入 count=4060 styleCount=28 stringsStart=16380
// stylesStart=161832；修前产物 styleCount=0 stylesStart=0，456 字节 style 数据被丢弃。
func TestRealArscPreservesStyles(t *testing.T) {
	const apk = "../../../realworld/apps/dhizuku.apk"
	zr, err := zip.OpenReader(apk)
	if err != nil {
		t.Skipf("真实 APK 不在，跳过: %v", err)
	}
	defer zr.Close()
	var raw []byte
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
		raw = b
	}
	if raw == nil {
		t.Skip("APK 内没有 resources.arsc")
	}

	off0 := int(binary.LittleEndian.Uint16(raw[2:]))
	count0, sc0, ss0, sz0 := arscPoolHeader(raw, off0)
	if sc0 == 0 {
		t.Skip("真实 resources.arsc 的全局池没有 style，跳过")
	}
	origOffs := arscStyleOffsets(raw, off0, count0, sc0)
	origData := append([]byte(nil), raw[off0+ss0:off0+sz0]...)

	tbl, err := Parse(raw)
	if err != nil {
		t.Fatalf("解析真实 resources.arsc 失败: %v", err)
	}
	strs := tbl.Strings()
	if len(strs) != count0 {
		t.Fatalf("字符串数量不符: %d != %d", len(strs), count0)
	}

	// 选取若干「旧值 → 新值」改写：至少包含一条被 style 覆盖的
	// （下标 < sc0），以验证「改了带样式的字符串后样式仍在」。
	// 用「旧值→新值」而非「下标→新值」记录，因为 Replace 按内容匹配，
	// 重复值会被一并改写，期望值需要覆盖所有同值下标。
	rename := map[string]string{}
	for i := 0; i < sc0; i++ {
		if strs[i] != "" {
			rename[strs[i]] = "res/auditfix/style" + strconv.Itoa(i) + ".bin"
			break
		}
	}
	for i := 0; i < len(strs) && len(rename) < 3; i++ {
		if strs[i] == "" {
			continue
		}
		if _, ok := rename[strs[i]]; ok {
			continue
		}
		rename[strs[i]] = "res/auditfix/x" + strconv.Itoa(i) + ".bin"
	}
	if len(rename) == 0 {
		t.Skip("未选到可改写的非空字符串")
	}
	expected := make([]string, len(strs))
	copy(expected, strs)
	for i, s := range strs {
		if nv, ok := rename[s]; ok {
			expected[i] = nv
			if n := tbl.Replace(s, nv); n == 0 {
				t.Fatalf("替换 %q 未命中", s)
			}
		}
	}
	out, err := tbl.Encode()
	if err != nil {
		t.Fatalf("编码失败: %v", err)
	}

	off1 := int(binary.LittleEndian.Uint16(out[2:]))
	count1, sc1, ss1, sz1 := arscPoolHeader(out, off1)
	if count1 != count0 {
		t.Fatalf("字符串数量变化: %d -> %d", count0, count1)
	}
	if sc1 != sc0 {
		t.Fatalf("styleCount 被丢弃: %d -> %d", sc0, sc1)
	}
	gotOffs := arscStyleOffsets(out, off1, count1, sc1)
	if len(gotOffs) != len(origOffs) {
		t.Fatalf("style 偏移数组长度变化: %d -> %d", len(origOffs), len(gotOffs))
	}
	for i := range origOffs {
		if gotOffs[i] != origOffs[i] {
			t.Fatalf("第 %d 个 style 偏移不符: %d != %d", i, gotOffs[i], origOffs[i])
		}
	}
	gotData := out[off1+ss1 : off1+sz1]
	if !bytes.Equal(gotData, origData) {
		t.Fatalf("style 数据区不一致：原始 %d 字节，产物 %d 字节", len(origData), len(gotData))
	}

	// 改写确实生效、其它条目不变。
	again, err := Parse(out)
	if err != nil {
		t.Fatalf("改写后再解析失败: %v", err)
	}
	after := again.Strings()
	if len(after) != len(expected) {
		t.Fatalf("改写后字符串数量变化: %d -> %d", len(expected), len(after))
	}
	for i := range expected {
		if after[i] != expected[i] {
			t.Fatalf("第 %d 条不符: %q != %q", i, after[i], expected[i])
		}
	}
	t.Logf("真实资源表保留 style：count=%d styleCount=%d style 数据 %d 字节",
		count1, sc1, len(gotData))
}
