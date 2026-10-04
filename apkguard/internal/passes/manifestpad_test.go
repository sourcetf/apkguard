package passes

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"apkguard/internal/axml"
	"apkguard/internal/config"
	"apkguard/internal/zipx"
)

// ---- A15（巨型 Manifest 填充）测试工具 ----

// a15Chunk 是测试遍历器读到的一个 chunk。
type a15Chunk struct {
	off  int
	size int
	typ  uint16
}

// a15Walk 是一段自写的小遍历器：从顶层 XML 头开始，严格按各 chunk 的声明
// 长度走链，要求不重不漏地正好停在 EOF（任何 size 回绕/错位都会在这里暴露）。
func a15Walk(t *testing.T, data []byte) []a15Chunk {
	t.Helper()
	if len(data) < 8 {
		t.Fatalf("数据只有 %d 字节，放不下 AXML 头", len(data))
	}
	if typ := binary.LittleEndian.Uint16(data[0:]); typ != xmlChunkType {
		t.Fatalf("顶层类型 0x%04x，期望 0x0003", typ)
	}
	var out []a15Chunk
	off := int(binary.LittleEndian.Uint16(data[2:]))
	for off < len(data) {
		if off+8 > len(data) {
			t.Fatalf("chunk 链在 %d 处越界：只剩 %d 字节，放不下 chunk 头", off, len(data)-off)
		}
		typ := binary.LittleEndian.Uint16(data[off:])
		hs := int(binary.LittleEndian.Uint16(data[off+2:]))
		sz := int(binary.LittleEndian.Uint32(data[off+4:]))
		if hs < 8 || sz < hs || off+sz > len(data) {
			t.Fatalf("chunk@%d 头非法：type=0x%04x headerSize=%d size=%d（剩余 %d 字节）",
				off, typ, hs, sz, len(data)-off)
		}
		out = append(out, a15Chunk{off: off, size: sz, typ: typ})
		off += sz
	}
	if off != len(data) {
		t.Fatalf("chunk 链未走到 EOF：停在 %d，文件共 %d 字节", off, len(data))
	}
	return out
}

// a15CheckPool 按 AOSP 的偏移表语义校验池自洽：stringsStart/stylesStart 合法、
// 每条字符串偏移都落在数据区内、且按各自编码（UTF-8/UTF-16）读出的内容不越界。
func a15CheckPool(t *testing.T, data []byte, ch a15Chunk) {
	t.Helper()
	pool := data[ch.off : ch.off+ch.size]
	if binary.LittleEndian.Uint16(pool[0:]) != poolChunkType {
		t.Fatalf("chunk@%d 不是字符串池", ch.off)
	}
	if hs := int(binary.LittleEndian.Uint16(pool[2:])); hs != poolHeaderLen {
		t.Fatalf("池 headerSize=%d，期望 %d", hs, poolHeaderLen)
	}
	if sz := int(binary.LittleEndian.Uint32(pool[4:])); sz != ch.size {
		t.Fatalf("池声明 size=%d 与实际 chunk 大小 %d 不符", sz, ch.size)
	}
	count := int(binary.LittleEndian.Uint32(pool[8:]))
	styleCount := int(binary.LittleEndian.Uint32(pool[12:]))
	flags := binary.LittleEndian.Uint32(pool[16:])
	stringsStart := int(binary.LittleEndian.Uint32(pool[20:]))
	stylesStart := int(binary.LittleEndian.Uint32(pool[24:]))
	if count > maxPoolStringCount || styleCount > count {
		t.Fatalf("池数量异常：strings=%d styles=%d", count, styleCount)
	}
	if arrEnd := poolHeaderLen + 4*count + 4*styleCount; stringsStart < arrEnd || stringsStart > len(pool) {
		t.Fatalf("stringsStart=%d 非法（偏移表结束于 %d，池 %d 字节）", stringsStart, arrEnd, len(pool))
	}
	dataEnd := len(pool)
	if styleCount > 0 {
		if stylesStart < stringsStart || stylesStart > len(pool) {
			t.Fatalf("stylesStart=%d 非法", stylesStart)
		}
		dataEnd = stylesStart
	}
	utf8Pool := flags&utf8PoolFlag != 0
	for i := 0; i < count; i++ {
		rel := int(binary.LittleEndian.Uint32(pool[poolHeaderLen+4*i:]))
		p := stringsStart + rel
		if p >= dataEnd {
			t.Fatalf("第 %d 条字符串偏移 %d 越出数据区 [%d,%d)", i, rel, stringsStart, dataEnd)
		}
		if utf8Pool {
			// 字符数 + 字节数（各 1..2 字节）+ 字节数 + NUL
			cl, q, ok := a15UTF8Len(pool, p)
			if !ok {
				t.Fatalf("第 %d 条 UTF-8 字符数长度字段越界", i)
			}
			bl, q2, ok := a15UTF8Len(pool, q)
			if !ok || q2+int(bl)+1 > dataEnd {
				t.Fatalf("第 %d 条 UTF-8 字符串越界（char=%d byte=%d）", i, cl, bl)
			}
		} else {
			n, q := a15UTF16Len(pool, p)
			if q+int(n)*2+2 > dataEnd {
				t.Fatalf("第 %d 条 UTF-16 字符串越界（units=%d）", i, n)
			}
		}
	}
}

// a15UTF8Len 解码 UTF-8 池的变长长度字段（与 axml 的规则一致）。
func a15UTF8Len(d []byte, p int) (uint32, int, bool) {
	if p >= len(d) {
		return 0, p, false
	}
	b := d[p]
	if b&0x80 != 0 {
		if p+1 >= len(d) {
			return 0, p, false
		}
		return uint32(b&0x7f)<<8 | uint32(d[p+1]), p + 2, true
	}
	return uint32(b), p + 1, true
}

// a15UTF16Len 解码 UTF-16 池的变长长度字段。
func a15UTF16Len(d []byte, p int) (uint32, int) {
	v := binary.LittleEndian.Uint16(d[p:])
	if v&0x8000 != 0 {
		return uint32(v&0x7fff)<<16 | uint32(binary.LittleEndian.Uint16(d[p+2:])), p + 4
	}
	return uint32(v), p + 2
}

// a15FirstChunkType 取第一个子 chunk 的类型（假 chunk #1 / T1）。
func a15FirstChunkType(t *testing.T, out []byte) uint16 {
	t.Helper()
	hs := int(binary.LittleEndian.Uint16(out[2:]))
	if hs+2 > len(out) {
		t.Fatalf("AXML 头后没有子 chunk")
	}
	return binary.LittleEndian.Uint16(out[hs:])
}

// a15ManifestWithMap 构造一份结构对齐 aapt 真实产物的 AXML：
// 字符串池 + RES_XML_RESOURCE_MAP + start/end namespace + start/end element，
// 元素为 <manifest package="com.example.demo" android:versionCode="1"/>。
// utf8Pool 为 false 时字符串池是 UTF-16（覆盖长串 4 字节前缀路径）。
func a15ManifestWithMap(utf8Pool bool) []byte {
	// 池下标约定：0="", 1="android", 2=AndroidNS, 3="manifest",
	// 4="package", 5="com.example.demo", 6="versionCode", 7="1"。
	strs := []string{
		"", "android", axml.AndroidNS, "manifest",
		"package", "com.example.demo", "versionCode", "1",
	}
	pool := axml.EncodeStringPool(strs, utf8Pool)

	// RES_XML_RESOURCE_MAP：属性名到资源 ID 的映射，内容对 axml.Parse 不重要，
	// 但结构（type=0x0180, headerSize=8）必须与真实产物一致。
	rmap := make([]byte, 8+8)
	binary.LittleEndian.PutUint16(rmap[0:], 0x0180)
	binary.LittleEndian.PutUint16(rmap[2:], 8)
	binary.LittleEndian.PutUint32(rmap[4:], uint32(len(rmap)))
	binary.LittleEndian.PutUint32(rmap[8:], 0x01010000)
	binary.LittleEndian.PutUint32(rmap[12:], 0x01010001)

	nsExt := le32(1, 2) // prefix="android", uri=AndroidNS
	startNS := node(axml.TypeXMLStartNS, 1, []uint32{noIndex}, nsExt)
	endNS := node(axml.TypeXMLEndNS, 1, []uint32{noIndex}, nsExt)

	attrSize := uint16(20)
	ext := make([]byte, 20)
	binary.LittleEndian.PutUint32(ext[0:], noIndex) // ns：无
	binary.LittleEndian.PutUint32(ext[4:], 3)       // name=manifest
	binary.LittleEndian.PutUint16(ext[8:], 20)      // attributeStart
	binary.LittleEndian.PutUint16(ext[10:], attrSize)
	binary.LittleEndian.PutUint16(ext[12:], 2) // attributeCount
	binary.LittleEndian.PutUint16(ext[14:], 0)
	binary.LittleEndian.PutUint16(ext[16:], 0)
	binary.LittleEndian.PutUint16(ext[18:], 0)
	body := append([]byte(nil), ext...)

	// package="com.example.demo"（字符串类型）
	a1 := make([]byte, attrSize)
	binary.LittleEndian.PutUint32(a1[0:], noIndex)
	binary.LittleEndian.PutUint32(a1[4:], 4) // package
	binary.LittleEndian.PutUint32(a1[8:], 5) // rawValue
	binary.LittleEndian.PutUint16(a1[12:], 8)
	a1[15] = 0x03
	binary.LittleEndian.PutUint32(a1[16:], 5)
	body = append(body, a1...)

	// android:versionCode="1"（十进制整数）
	a2 := make([]byte, attrSize)
	binary.LittleEndian.PutUint32(a2[0:], 2) // ns=AndroidNS
	binary.LittleEndian.PutUint32(a2[4:], 6) // versionCode
	binary.LittleEndian.PutUint32(a2[8:], 7) // rawValue="1"
	binary.LittleEndian.PutUint16(a2[12:], 8)
	a2[15] = 0x10
	binary.LittleEndian.PutUint32(a2[16:], 1)
	body = append(body, a2...)

	startElem := node(axml.TypeXMLStartElem, 1, []uint32{noIndex}, body)
	endElem := node(axml.TypeXMLEndElem, 1, []uint32{noIndex}, le32(noIndex, 3))

	out := make([]byte, 8)
	binary.LittleEndian.PutUint16(out[0:], axml.TypeXML)
	binary.LittleEndian.PutUint16(out[2:], 8)
	out = append(out, pool...)
	out = append(out, rmap...)
	out = append(out, startNS...)
	out = append(out, startElem...)
	out = append(out, endElem...)
	out = append(out, endNS...)
	binary.LittleEndian.PutUint32(out[4:], uint32(len(out)))
	return out
}

// ---- 测试 ----

// TestManifestPadKeepsManifestParsable 是 A15 的**决定性判据**。
//
// 填充的价值来自「撑大体积但保持可解析」：一旦真实内容读不到，应用就装不上，
// 属于自伤。因此这里断言：
//   - 体积确实被撑大（否则没起到作用）；
//   - 我们的 axml 解析器仍能读出全部元素与原有字符串（证明巨串只挂在池尾、
//     没有挪动任何既有索引）；
//   - 顶层 XML chunk 的 size 被更新为整个新文件长度。
func TestManifestPadKeepsManifestParsable(t *testing.T) {
	raw := realisticAXML(newRand("pad"), 512)
	before, err := axml.Parse(raw)
	if err != nil || len(before.Elements) == 0 {
		t.Fatalf("构造的基准 AXML 无法解析：err=%v 元素=%d", err, len(before.Elements))
	}

	art := newArtifact(zipx.NewStored(manifestName, raw))
	// 用 1 MB 做测试（默认 100 MB 太慢），逻辑与参数无关。
	opts := &config.Options{
		Enabled:       map[config.FeatureID]bool{"A15": true},
		ManifestPadMB: 1,
		Seed:          "a15-parsable",
	}
	if err := (&manifestPad{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A15 执行失败: %v", err)
	}

	e := art.Entries()[0]
	data, err := e.Data()
	if err != nil {
		t.Fatalf("读取产物失败: %v", err)
	}
	if len(data) < 1<<20 {
		t.Fatalf("填充后体积只有 %d 字节，未达到 1 MB", len(data))
	}

	// 顶层 XML chunk 的 size 必须等于整个新文件长度
	if typ := binary.LittleEndian.Uint16(data[0:]); typ != 0x0003 {
		t.Fatalf("顶层类型应为 XML chunk，实际 0x%04x", typ)
	}
	if sz := int(binary.LittleEndian.Uint32(data[4:])); sz != len(data) {
		t.Fatalf("顶层 size=%d 应等于文件长度 %d", sz, len(data))
	}

	// 关键：解析器必须仍能找到真实内容，且原有元素/属性/字符串逐项一致。
	after, err := axml.Parse(data)
	if err != nil {
		t.Fatalf("填充后无法解析（应用会装不上）：%v", err)
	}
	if len(after.Elements) != len(before.Elements) {
		t.Fatalf("填充前后元素数不同：%d -> %d", len(before.Elements), len(after.Elements))
	}
	for i := range before.Elements {
		b, a := before.Elements[i], after.Elements[i]
		if a.Name != b.Name {
			t.Fatalf("第 %d 个元素名被破坏：%q -> %q", i, b.Name, a.Name)
		}
		if len(a.Attrs) != len(b.Attrs) {
			t.Fatalf("元素 %s 属性数不同：%d -> %d", b.Name, len(b.Attrs), len(a.Attrs))
		}
		for j := range b.Attrs {
			if a.Attrs[j].Name != b.Attrs[j].Name || a.Attrs[j].RawValue != b.Attrs[j].RawValue {
				t.Fatalf("元素 %s 属性 %d 被破坏：%q=%q -> %q=%q",
					b.Name, j, b.Attrs[j].Name, b.Attrs[j].RawValue,
					a.Attrs[j].Name, a.Attrs[j].RawValue)
			}
		}
	}
	if after.Count() < before.Count() {
		t.Fatalf("填充后字符串条数 %d 少于原 %d", after.Count(), before.Count())
	}
	for i := 0; i < before.Count(); i++ {
		want, _ := before.String(uint32(i))
		got, err := after.String(uint32(i))
		if err != nil || got != want {
			t.Fatalf("第 %d 条字符串被破坏：%q -> %q（err=%v）", i, want, got, err)
		}
	}
	t.Logf("A15：%d -> %d 字节，填充后仍能解析出 %d 个元素、前 %d 条字符串不变（%s）",
		len(raw), len(data), len(after.Elements), before.Count(), after.Elements[0].Name)
}

// TestManifestPadChunkLayout 用自写遍历器钉住新布局：
//
//	[T1][字符串池（被巨串放大）][T2][RESOURCE_MAP + 命名空间 + 元素]
//
// 链必须严丝合缝走到 EOF；T1/T2 必须是两个不同的未知类型；n1/n2/池增长
// 三项之和精确等于 pad；T2 之后的真实内容逐字节保留。
func TestManifestPadChunkLayout(t *testing.T) {
	raw := a15ManifestWithMap(true)
	before, err := axml.Parse(raw)
	if err != nil || before.FindElement("manifest") == nil {
		t.Fatalf("基准 Manifest 不可解析：err=%v", err)
	}
	origPoolSize := int(binary.LittleEndian.Uint32(raw[8+4:]))
	origCount := int(binary.LittleEndian.Uint32(raw[8+8:]))

	const pad = 1 << 20
	out, err := padManifest(raw, pad, newRand("layout-seed"))
	if err != nil {
		t.Fatalf("padManifest: %v", err)
	}
	if sz := int(binary.LittleEndian.Uint32(out[4:])); sz != len(out) {
		t.Fatalf("顶层 size=%d 应为文件长度 %d", sz, len(out))
	}

	chunks := a15Walk(t, out)
	wantTypes := []uint16{0, poolChunkType, 0, 0x0180, axml.TypeXMLStartNS, axml.TypeXMLStartElem, axml.TypeXMLEndElem, axml.TypeXMLEndNS}
	if len(chunks) != len(wantTypes) {
		t.Fatalf("chunk 数=%d，期望 %d（布局：T1/池/T2/资源映射/命名空间/元素）", len(chunks), len(wantTypes))
	}
	t1, t2 := chunks[0].typ, chunks[2].typ
	if knownAXMLChunkTypes[t1] {
		t.Fatalf("假 chunk #1 类型 0x%04x 属于已知 AXML 类型集合", t1)
	}
	if knownAXMLChunkTypes[t2] {
		t.Fatalf("假 chunk #2 类型 0x%04x 属于已知 AXML 类型集合", t2)
	}
	if t1 == t2 {
		t.Fatalf("两个假 chunk 类型相同（0x%04x），样本里两段就是不同随机值", t1)
	}
	if chunks[1].typ != poolChunkType {
		t.Fatalf("第二个 chunk 应为字符串池（0x0001），实际 0x%04x", chunks[1].typ)
	}
	for i, want := range wantTypes {
		if i == 0 || i == 2 {
			continue // T1/T2 随机
		}
		if chunks[i].typ != want {
			t.Fatalf("第 %d 个 chunk 类型 0x%04x，期望 0x%04x", i, chunks[i].typ, want)
		}
	}

	// 比例：n1 ≈8%、n2 ≈12%、池增长 ≈80%，且三项之和精确等于 pad。
	n1 := chunks[0].size - 8
	n2 := chunks[2].size - 8
	growth := chunks[1].size - origPoolSize
	if n1+n2+growth != pad {
		t.Fatalf("n1(%d)+n2(%d)+池增长(%d) = %d，应精确等于 pad %d", n1, n2, growth, n1+n2+growth, pad)
	}
	if n1 < pad*8/100-8 || n1 > pad*8/100+8 {
		t.Fatalf("n1=%d 偏离 8%%（%d）", n1, pad*8/100)
	}
	if n2 < pad*12/100-64 || n2 > pad*12/100+64 {
		t.Fatalf("n2=%d 偏离 12%%（%d）", n2, pad*12/100)
	}
	if int64(growth) < int64(pad)*75/100 {
		t.Fatalf("池只增长了 %d 字节，不足 pad 的 75%%：巨串没有藏进池里", growth)
	}

	// 池声明 size 必须明显大于「短串实际所需」，且内部偏移全部自洽。
	a15CheckPool(t, out, chunks[1])

	// T2 之后的真实内容逐字节保留（RESOURCE_MAP + 命名空间 + 元素）。
	rest := raw[8+origPoolSize:]
	if !bytes.Equal(out[chunks[3].off:], rest) {
		t.Fatalf("T2 之后的真实内容与原文不一致（%d 字节 vs %d 字节）", len(out)-chunks[3].off, len(rest))
	}

	// 仍可解析，且原字符串逐条不变、追加了字符串。
	after, err := axml.Parse(out)
	if err != nil {
		t.Fatalf("填充后 axml.Parse 失败：%v", err)
	}
	if after.Count() <= origCount {
		t.Fatalf("池内字符串条数未增长：%d -> %d", origCount, after.Count())
	}
	for i := 0; i < before.Count(); i++ {
		want, _ := before.String(uint32(i))
		got, err := after.String(uint32(i))
		if err != nil || got != want {
			t.Fatalf("第 %d 条字符串被破坏：%q -> %q（err=%v）", i, want, got, err)
		}
	}
	root := after.FindElement("manifest")
	if root == nil || root.AttrString("package") != "com.example.demo" {
		t.Fatalf("包名丢失或被破坏：%+v", root)
	}
	if v := root.AttrString("versionCode"); v != "1" {
		t.Fatalf("android:versionCode 被破坏：%q", v)
	}
	t.Logf("A15 布局：T1=0x%04x(%d) 池=%d(+%d,%d 条) T2=0x%04x(%d)；真实尾部 %d 字节原样保留",
		t1, n1, chunks[1].size, growth, after.Count(), t2, n2, len(rest))
}

// TestManifestPadUTF16GiantString 覆盖参考样本的形态：UTF-16 池 + **一条**
// 长串（4 字节长格式前缀 0x8000|高位 + 低位），数据同一 ASCII 字符重复、
// 无提前出现的 0x0000，末尾 2 字节 NUL 并补零到池声明末尾。
func TestManifestPadUTF16GiantString(t *testing.T) {
	raw := a15ManifestWithMap(false)
	before, err := axml.Parse(raw)
	if err != nil || before.Count() == 0 {
		t.Fatalf("基准 UTF-16 Manifest 不可解析：err=%v", err)
	}

	const pad = 1 << 20
	out, err := padManifest(raw, pad, newRand("utf16-seed"))
	if err != nil {
		t.Fatalf("padManifest: %v", err)
	}
	chunks := a15Walk(t, out)
	if len(chunks) < 3 || chunks[1].typ != poolChunkType {
		t.Fatalf("布局异常：%+v", chunks)
	}
	a15CheckPool(t, out, chunks[1])

	poolOff, poolSize := chunks[1].off, chunks[1].size
	count := int(binary.LittleEndian.Uint32(out[poolOff+8:]))
	flags := binary.LittleEndian.Uint32(out[poolOff+16:])
	if flags&utf8PoolFlag != 0 {
		t.Fatal("UTF-16 输入池被改成了 UTF-8 标志")
	}
	if count != before.Count()+1 {
		t.Fatalf("UTF-16 池应只追加一条巨串：%d -> %d", before.Count(), count)
	}
	stringsStart := int(binary.LittleEndian.Uint32(out[poolOff+20:]))
	lastRel := int(binary.LittleEndian.Uint32(out[poolOff+poolHeaderLen+4*(count-1):]))
	p := poolOff + stringsStart + lastRel
	if p+4 > poolOff+poolSize {
		t.Fatal("最后一条字符串偏移越界")
	}
	v := binary.LittleEndian.Uint16(out[p:])
	if v&0x8000 == 0 {
		t.Fatalf("巨串长度 %d 未使用 4 字节长格式前缀（首字 0x%04x）", v, v)
	}
	units := int(v&0x7fff)<<16 | int(binary.LittleEndian.Uint16(out[p+2:]))
	if units < 0x8000 {
		t.Fatalf("长格式长度 %d 反而小于 0x8000", units)
	}
	dataStart := p + 4
	end := dataStart + 2*units
	if end+2 > poolOff+poolSize {
		t.Fatalf("巨串数据 + NUL 越出池声明末尾：end=%d poolEnd=%d", end+2, poolOff+poolSize)
	}
	if binary.LittleEndian.Uint16(out[end:]) != 0 {
		t.Fatal("巨串末尾不是 2 字节 NUL")
	}
	ch := out[dataStart]
	if !bytes.Contains(giantCharChoices, []byte{ch}) {
		t.Fatalf("巨串字符 0x%02x 不在候选集中", ch)
	}
	for _, i := range []int{0, units / 2, units - 1} {
		if out[dataStart+2*i] != ch || out[dataStart+2*i+1] != 0 {
			t.Fatalf("第 %d 个码元不是 %q 的 UTF-16LE 编码（出现 0x0000 会提前终止）", i, ch)
		}
	}
	if int64(2*units) < int64(pad)*75/100 {
		t.Fatalf("巨串只有 %d 字节，不足 pad 的 75%%", 2*units)
	}

	// 解析器仍读到全部原有字符串；包名/属性不变。
	after, err := axml.Parse(out)
	if err != nil {
		t.Fatalf("填充后 axml.Parse 失败：%v", err)
	}
	for i := 0; i < before.Count(); i++ {
		want, _ := before.String(uint32(i))
		got, err := after.String(uint32(i))
		if err != nil || got != want {
			t.Fatalf("第 %d 条字符串被破坏：%q -> %q（err=%v）", i, want, got, err)
		}
	}
	if root := after.FindElement("manifest"); root == nil || root.AttrString("package") != "com.example.demo" {
		t.Fatalf("包名丢失或被破坏：%+v", root)
	}
	t.Logf("A15 UTF-16 巨串：%d 个码元（%d 字节），池 %d -> %d 字节", units, 2*units, len(raw), len(out))
}

// TestManifestPadAntiStrip 是**抗剥离**判据。
//
// 分析者可以按「未知类型」删掉 T1/T2 两个零填充 chunk，但体积大头是一条合法
// 字符串池内的巨串：池的声明 size 已经把巨串算进去，真实内容的位置由它决定，
// 删掉未知 chunk 并不能恢复原始体积（只省下 n1+n2 ≈20%）。本测试断言：
//   - 池声明 size 明显大于原有短串所需（巨串真的在池内）；
//   - 直接删除 T1/T2 后，顶层声明 size 与实际长度不一致（不再是自洽的 AXML）；
//   - 剥离后的字节流里巨串仍然存在（字符串条数仍含追加项）。
func TestManifestPadAntiStrip(t *testing.T) {
	raw := a15ManifestWithMap(true)
	before, err := axml.Parse(raw)
	if err != nil {
		t.Fatalf("基准 Manifest: %v", err)
	}
	origPoolSize := int(binary.LittleEndian.Uint32(raw[8+4:]))

	const pad = 1 << 20
	out, err := padManifest(raw, pad, newRand("strip-seed"))
	if err != nil {
		t.Fatalf("padManifest: %v", err)
	}
	chunks := a15Walk(t, out)
	if len(chunks) < 4 {
		t.Fatalf("chunk 数不足：%d", len(chunks))
	}

	// 1) 巨串确实在合法池内部：池声明 size 的增长接近 pad 的 80%。
	pool := chunks[1]
	growth := pool.size - origPoolSize
	if int64(growth) < int64(pad)*70/100 {
		t.Fatalf("池声明只增大了 %d 字节（pad=%d）：巨串没在池里", growth, pad)
	}

	// 2) 暴力剥离：把两个未知 chunk 的字节直接删掉，其他一概不动。
	stripped := make([]byte, 0, len(out))
	stripped = append(stripped, out[:chunks[0].off]...)
	stripped = append(stripped, out[pool.off:pool.off+pool.size]...)
	stripped = append(stripped, out[chunks[3].off:]...)

	declared := int(binary.LittleEndian.Uint32(stripped[4:]))
	if declared == len(stripped) {
		t.Fatalf("剥离 T1/T2 后顶层 size(%d) 仍与长度自洽，填充没有和池绑定", declared)
	}
	if int64(len(stripped)-len(raw)) < int64(pad)*70/100 {
		t.Fatalf("剥离后只比原文件大 %d 字节（pad=%d）：体积大头没被池绑住",
			len(stripped)-len(raw), pad)
	}
	if saved := int64(pad) - int64(len(stripped)-len(raw)); saved > int64(pad)/4+64 {
		t.Fatalf("剥离省下 %d 字节（超过 pad 的 25%%），未达到「约 80%% 体积藏在合法池里」的目标", saved)
	}

	// 3) 池仍是合法池，因此解析器还能读；但它读到的是**放大后的池**，
	//    而不是一个紧凑的原始 Manifest —— 这正说明剥离拿不回原始文件。
	if parsed, err := axml.Parse(stripped); err == nil {
		if parsed.Count() <= before.Count() {
			t.Fatalf("剥离后字符串条数 %d 未包含追加的巨串（原 %d）", parsed.Count(), before.Count())
		}
	} else {
		t.Logf("剥离后的字节流解析失败（同样满足抗剥离断言）：%v", err)
	}
	t.Logf("A15 抗剥离：剥离仅省下 n1+n2=%d 字节，池内巨串 %d 字节仍在（顶层声明 %d != 实际 %d）",
		declared-len(stripped), growth, declared, len(stripped))
}

// TestManifestPadDeterministic 钉住随机源契约：
//   - 同一 seed 两次跑出的字节完全相同；
//   - 不同 seed 的 T1 至少出现 2 个不同值（固定 seed 集合，避免概率性 flake）；
//   - 每个产物的 T1/T2 都不同且不属于已知类型集合。
func TestManifestPadDeterministic(t *testing.T) {
	raw := a15ManifestWithMap(true)
	const pad = 64 << 10

	a, err := padManifest(raw, pad, newRand("det-seed/manifestpad"))
	if err != nil {
		t.Fatalf("padManifest: %v", err)
	}
	b, err := padManifest(raw, pad, newRand("det-seed/manifestpad"))
	if err != nil {
		t.Fatalf("padManifest: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("同一 seed 两次产出不同字节")
	}

	seen := map[uint16]bool{}
	for i := 0; i < 8; i++ {
		out, err := padManifest(raw, pad, newRand(fmt.Sprintf("det-%d/manifestpad", i)))
		if err != nil {
			t.Fatalf("seed det-%d: %v", i, err)
		}
		chunks := a15Walk(t, out)
		t1, t2 := chunks[0].typ, chunks[2].typ
		if knownAXMLChunkTypes[t1] || knownAXMLChunkTypes[t2] {
			t.Fatalf("seed det-%d 产出已知类型：T1=0x%04x T2=0x%04x", i, t1, t2)
		}
		if t1 == t2 {
			t.Fatalf("seed det-%d 两个假 chunk 类型相同：0x%04x", i, t1)
		}
		seen[t1] = true
	}
	if len(seen) < 2 {
		t.Fatalf("8 个不同 seed 的 T1 只有 %d 个取值 %v：随机类型可能被写死", len(seen), seen)
	}
	// 明示不能退化成样本里那个固定指纹。
	if _, fixed := seen[0xb4a7]; fixed && len(seen) == 1 {
		t.Fatal("T1 退化为固定的 0xb4a7 指纹")
	}
}

// TestManifestPadZeroAndTiny 覆盖边界填充量：0（原样返回）、1/2/8/64（放不下
// 长串时优雅降级，但绝不产出非法池或长度回绕）。
func TestManifestPadZeroAndTiny(t *testing.T) {
	raw := a15ManifestWithMap(true)

	got, err := padManifest(raw, 0, newRand("zero"))
	if err != nil {
		t.Fatalf("pad=0: %v", err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatal("pad=0 应原样返回输入")
	}

	for _, pad := range []int{1, 2, 8, 64} {
		out, err := padManifest(raw, pad, newRand(fmt.Sprintf("tiny-%d", pad)))
		if err != nil {
			t.Fatalf("pad=%d: %v", pad, err)
		}
		if len(out) != len(raw)+16+pad {
			t.Fatalf("pad=%d 长度=%d，期望 %d", pad, len(out), len(raw)+16+pad)
		}
		if sz := int(binary.LittleEndian.Uint32(out[4:])); sz != len(out) {
			t.Fatalf("pad=%d 顶层 size=%d 应为 %d", pad, sz, len(out))
		}
		chunks := a15Walk(t, out)
		if len(chunks) < 3 || chunks[1].typ != poolChunkType {
			t.Fatalf("pad=%d 布局异常：%+v", pad, chunks)
		}
		t1, t2 := chunks[0].typ, chunks[2].typ
		if knownAXMLChunkTypes[t1] || knownAXMLChunkTypes[t2] || t1 == t2 {
			t.Fatalf("pad=%d 假 chunk 类型异常：T1=0x%04x T2=0x%04x", pad, t1, t2)
		}
		a15CheckPool(t, out, chunks[1])
		if _, err := axml.Parse(out); err != nil {
			t.Fatalf("pad=%d 产物无法解析：%v", pad, err)
		}
	}
}

// TestManifestPadRejectsNonPoolFirstChild 要求第一个子 chunk 不是字符串池时
// 明确拒绝（巨串只能挂在合法池上，否则会产出非法 AXML）。
func TestManifestPadRejectsNonPoolFirstChild(t *testing.T) {
	raw := a15ManifestWithMap(true)
	poolSize := int(binary.LittleEndian.Uint32(raw[8+4:]))
	noPool := make([]byte, 0, len(raw))
	noPool = append(noPool, raw[:8]...)
	noPool = append(noPool, raw[8+poolSize:]...) // 只剩 RESOURCE_MAP + 节点
	binary.LittleEndian.PutUint32(noPool[4:], uint32(len(noPool)))

	if _, err := padManifest(noPool, 1<<20, newRand("nopool")); err == nil {
		t.Fatal("第一个子 chunk 不是字符串池时应拒绝")
	} else if !strings.Contains(err.Error(), "字符串池") {
		t.Fatalf("错误信息应点明缺少字符串池：%v", err)
	}
}

// TestManifestPadRealSampleIfPresent 是可选的集成检查：仓库根目录放着参考
// 样本 sample.apk 时，抽它的 AndroidManifest.xml 跑一遍新布局并打印实测
// chunk 表（真实 UTF-16 池 + 157,800,394 字符巨串的场景）。
//
// 默认跳过：该检查要分配约 1 GB 内存，不能拖累每次全包测试；
// 用 APKGUARD_A15_REAL_SAMPLE=1 显式开启。
func TestManifestPadRealSampleIfPresent(t *testing.T) {
	if os.Getenv("APKGUARD_A15_REAL_SAMPLE") == "" {
		t.Skip("设置 APKGUARD_A15_REAL_SAMPLE=1 才运行真实样本集成检查")
	}
	// go test 的工作目录是包目录：<repo>/apkguard/internal/passes。
	const sample = "../../../sample.apk"
	if _, err := os.Stat(sample); err != nil {
		t.Skipf("参考样本不存在：%v", err)
	}
	zr, err := zip.OpenReader(sample)
	if err != nil {
		t.Fatalf("打开 sample.apk: %v", err)
	}
	defer zr.Close()
	var rc io.ReadCloser
	for _, f := range zr.File {
		if f.Name == manifestName {
			rc, err = f.Open()
			break
		}
	}
	if err != nil || rc == nil {
		t.Fatalf("读取 %s: %v", manifestName, err)
	}
	raw, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		t.Fatalf("读入 %s: %v", manifestName, err)
	}
	before, err := axml.Parse(raw)
	if err != nil {
		t.Fatalf("样本 Manifest 不可解析: %v", err)
	}
	root := before.FindElement("manifest")
	pkg := ""
	if root != nil {
		pkg = root.AttrString("package")
	}
	t.Logf("样本 %s：%d 字节，字符串 %d 条，包名 %q", manifestName, len(raw), before.Count(), pkg)

	// 样本本身已经是「假 chunk #1 + 池 + 假 chunk #2 + 真实内容」的加固形态，
	// 而 A15 的契约要求第一个子 chunk 是字符串池（否则拒绝，避免在未知布局上
	// 乱插）。这里先按声明长度遍历样本，剥掉它自己的两段假 chunk，得到一个
	// 「池在首位」的真实 Manifest 作为输入；池与真实节点字节完全取自样本。
	rawChunks := a15Walk(t, raw)
	for i := 0; i < len(rawChunks) && i < 5; i++ {
		t.Logf("  样本 chunk[%d] off=%d type=0x%04X size=%d", i, rawChunks[i].off, rawChunks[i].typ, rawChunks[i].size)
	}
	t.Logf("  样本其余 %d 个真实节点 chunk 直到 EOF", len(rawChunks)-4)
	if len(rawChunks) < 4 || rawChunks[1].typ != poolChunkType {
		t.Fatalf("样本结构与预期不符（第二个 chunk 应为池）：%+v", rawChunks[:min(4, len(rawChunks))])
	}
	pool := rawChunks[1]
	clean := make([]byte, 0, 8+pool.size+(len(raw)-rawChunks[3].off))
	clean = append(clean, raw[:8]...)
	clean = append(clean, raw[pool.off:pool.off+pool.size]...)
	clean = append(clean, raw[rawChunks[3].off:]...)
	binary.LittleEndian.PutUint32(clean[4:], uint32(len(clean)))
	if _, err := axml.Parse(clean); err != nil {
		t.Fatalf("剥离样本自有假 chunk 后的真实 Manifest 不可解析: %v", err)
	}
	raw = clean

	out, err := padManifest(raw, 8<<20, newRand("real-sample/manifestpad"))
	if err != nil {
		t.Fatalf("padManifest(真实样本): %v", err)
	}
	chunks := a15Walk(t, out)
	if len(chunks) < 4 {
		t.Fatalf("chunk 数不足：%d", len(chunks))
	}
	for i := 0; i < len(chunks) && i < 5; i++ {
		t.Logf("  chunk[%d] off=%d type=0x%04X size=%d", i, chunks[i].off, chunks[i].typ, chunks[i].size)
	}
	t.Logf("  ... 其余 %d 个真实节点 chunk 直到 EOF（链完整、无回绕）", len(chunks)-4)

	after, err := axml.Parse(out)
	if err != nil {
		t.Fatalf("填充后样本 Manifest 不可解析: %v", err)
	}
	root2 := after.FindElement("manifest")
	if root2 == nil || root2.AttrString("package") != pkg {
		t.Fatalf("包名被破坏：%q -> %+v", pkg, root2)
	}
	if after.Count() != before.Count()+1 {
		t.Fatalf("UTF-16 池应只追加一条巨串：%d -> %d", before.Count(), after.Count())
	}
	// 只比对短串（最后一条原始串是 1.5 亿字符的巨串，不复制到 Go 字符串）。
	n := before.Count() - 1
	if n > 64 {
		n = 64
	}
	for i := 0; i < n; i++ {
		want, _ := before.String(uint32(i))
		got, err := after.String(uint32(i))
		if err != nil || got != want {
			t.Fatalf("第 %d 条字符串被破坏：%q -> %q（err=%v）", i, want, got, err)
		}
	}
	t.Logf("真实样本填充：%d -> %d 字节（T1=0x%04X T2=0x%04X），包名与短串全部保留",
		len(raw), len(out), chunks[0].typ, chunks[2].typ)
}

// TestManifestPadKeepsPoolStyles 校验带 style（富文本样式）的池在追加巨串后
// styleCount、style 偏移数组与 style 数据区原样保留（真实 Manifest 几乎没有
// style，但 AXML 语法允许，不能让这条路径悄悄损坏池）。
func TestManifestPadKeepsPoolStyles(t *testing.T) {
	strs := []string{"", "android", axml.AndroidNS, "manifest", "package", "com.example.demo"}
	st := &axml.Styles{Count: 2, Offsets: []uint32{0, 4}, Data: []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}
	styledPool, err := axml.EncodeStringPoolWithStyles(strs, true, st)
	if err != nil {
		t.Fatalf("构造带 style 的池: %v", err)
	}

	base := a15ManifestWithMap(true)
	basePoolSize := int(binary.LittleEndian.Uint32(base[8+4:]))
	raw := make([]byte, 0, len(base)-basePoolSize+len(styledPool))
	raw = append(raw, base[:8]...)
	raw = append(raw, styledPool...)
	raw = append(raw, base[8+basePoolSize:]...)
	binary.LittleEndian.PutUint32(raw[4:], uint32(len(raw)))
	if _, err := axml.Parse(raw); err != nil {
		t.Fatalf("带 style 的基准 Manifest 不可解析: %v", err)
	}

	out, err := padManifest(raw, 256<<10, newRand("styled-pool"))
	if err != nil {
		t.Fatalf("padManifest: %v", err)
	}
	chunks := a15Walk(t, out)
	if _, err := axml.Parse(out); err != nil {
		t.Fatalf("带 style 的产物不可解析: %v", err)
	}
	a15CheckPool(t, out, chunks[1])

	oldPool := raw[8 : 8+len(styledPool)]
	newPool := out[chunks[1].off : chunks[1].off+chunks[1].size]
	oldCount := int(binary.LittleEndian.Uint32(oldPool[8:]))
	newCount := int(binary.LittleEndian.Uint32(newPool[8:]))
	oldSc := int(binary.LittleEndian.Uint32(oldPool[12:]))
	newSc := int(binary.LittleEndian.Uint32(newPool[12:]))
	if newSc != oldSc {
		t.Fatalf("styleCount 被改变：%d -> %d", oldSc, newSc)
	}
	oldStyles := int(binary.LittleEndian.Uint32(oldPool[24:]))
	newStyles := int(binary.LittleEndian.Uint32(newPool[24:]))
	if oldStyles == 0 || newStyles == 0 {
		t.Fatal("stylesStart 不应为 0")
	}
	oldOffs := oldPool[poolHeaderLen+4*oldCount : poolHeaderLen+4*oldCount+4*oldSc]
	newOffs := newPool[poolHeaderLen+4*newCount : poolHeaderLen+4*newCount+4*newSc]
	if !bytes.Equal(oldOffs, newOffs) {
		t.Fatal("style 偏移数组被改变")
	}
	if !bytes.Equal(oldPool[oldStyles:], newPool[newStyles:]) {
		t.Fatal("style 数据区被改变")
	}
}

// TestManifestPadIsCompressed 钉住「填充条目必须压缩存放」。
//
// 【为什么这条断言的语义与旧版相反】旧实现断言的是 IsStored（未压缩），
// 因为当时认为压缩会把几十 MB 的零压成几百 KB、从而抹掉体积压力。但实测
// 参考样本 sample.apk 推翻了这一点：它的 AndroidManifest.xml 解压后
// 369,623,060 字节，压缩后仅 367,318 字节（压缩比约 0.001），中央目录里
// 的压缩方式字段是 8（deflate）。既然 **Android 系统接受压缩存储的
// AndroidManifest.xml**，压缩就是纯收益：解压后体积与读取压力分毫不减，
// 包体却省约 1000 倍。因此断言反转为「必须是压缩存放」。
func TestManifestPadIsCompressed(t *testing.T) {
	raw := realisticAXML(newRand("pad2"), 512)
	art := newArtifact(zipx.NewStored(manifestName, raw))
	opts := &config.Options{Enabled: map[config.FeatureID]bool{"A15": true}, ManifestPadMB: 1, Seed: "a15-compress"}
	if err := (&manifestPad{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A15 执行失败: %v", err)
	}
	got := art.Entries()[0]
	if got.IsStored() {
		t.Fatalf("填充后的 Manifest 是未压缩存放（method=%d），包体会被填充实打实撑大", got.Method)
	}
	if got.Method != 8 {
		t.Fatalf("填充后的 Manifest 压缩方式应为 8（deflate），实际 %d", got.Method)
	}
	// 解压后体积必须仍是「巨型」：压缩不能成为偷工减料的借口。
	data, err := got.Data()
	if err != nil {
		t.Fatalf("解压产物失败: %v", err)
	}
	if len(data) < 1<<20 {
		t.Fatalf("解压后仅 %d 字节，未达到 1 MB 填充量", len(data))
	}
	// 防回归断言：填充内容是零 + 同一字符的重复（巨串），deflate 压缩比必须
	// 远小于 0.01。若有人为了「让包体更小」把填充换成随机数据，随机数据不可
	// 压缩，压缩比会立刻逼近 1，这条断言就会失败。
	ratio := float64(got.CompSize) / float64(got.UncompSize)
	if ratio >= 0.01 {
		t.Fatalf("压缩比 %.5f 未达标（应 < 0.01）：填充内容可能不是零/重复字符，而是随机数据", ratio)
	}
	t.Logf("A15：解压 %d 字节 / 压缩 %d 字节，压缩比 %.5f", got.UncompSize, got.CompSize, ratio)
}

// TestManifestPadDefaultSize 校验未指定尺寸时用默认值（100 MB）。
func TestManifestPadDefaultSize(t *testing.T) {
	raw := realisticAXML(newRand("pad3"), 256)
	art := newArtifact(zipx.NewStored(manifestName, raw))
	opts := &config.Options{Enabled: map[config.FeatureID]bool{"A15": true}, Seed: "a15-default"}
	if err := (&manifestPad{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A15 执行失败: %v", err)
	}
	data, _ := art.Entries()[0].Data()
	want := defaultManifestPadMB << 20
	if len(data) < want {
		t.Fatalf("默认填充应至少 %d 字节，实际 %d", want, len(data))
	}
	t.Logf("默认填充量 = %d MB", defaultManifestPadMB)
}
