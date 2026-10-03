package passes

import (
	"encoding/binary"
	"testing"

	"apkguard/internal/axml"
)

// walkStartElemChunks 从 AXML 字节流里取出所有 StartElement chunk 的原始字节。
//
// 顶层 XML chunk 的 headerSize 为 8，子 chunk 紧跟其后；每个子 chunk 头里
// 有 8/16/32 位的 type/headerSize/size。遇到不合法（如垃圾填充的零）即停止。
func walkStartElemChunks(t *testing.T, data []byte) [][]byte {
	t.Helper()
	if len(data) < 8 {
		t.Fatalf("AXML 过短: %d 字节", len(data))
	}
	var out [][]byte
	off := 8
	for off+8 <= len(data) {
		typ := binary.LittleEndian.Uint16(data[off:])
		sz := int(binary.LittleEndian.Uint32(data[off+4:]))
		if sz < 8 || off+sz > len(data) {
			break
		}
		if typ == axml.TypeXMLStartElem {
			out = append(out, data[off:off+sz])
		}
		off += sz
	}
	return out
}

// checkStartElemFields 断言一个 StartElement chunk 的 classIndex/styleIndex 与
// 每个属性的 Res_value.size 都是合法值。
//
// Res_value.size 必须是 8（Res_value 结构体大小），class/style 索引的「无」必须是
// 0（AOSP 语义，真实 aapt 产物即 0）；0xffff 会被解析器当成第 65534 个属性。
func checkStartElemFields(t *testing.T, label string, chunk []byte) {
	t.Helper()
	if len(chunk) < 36 {
		t.Fatalf("%s: StartElement chunk 过短（%d 字节）", label, len(chunk))
	}
	// node 头 16 字节后是 ResXMLTree_attrExt：classIndex 在 +16，styleIndex 在 +18。
	classIdx := binary.LittleEndian.Uint16(chunk[16+16:])
	styleIdx := binary.LittleEndian.Uint16(chunk[16+18:])
	if classIdx != 0 || styleIdx != 0 {
		t.Errorf("%s: classIndex/styleIndex = %d/%d，应为 0/0（0xffff 会被当成第 65534 个属性）",
			label, classIdx, styleIdx)
	}
	attrStart := int(binary.LittleEndian.Uint16(chunk[16+8:]))
	attrSize := int(binary.LittleEndian.Uint16(chunk[16+10:]))
	attrCount := int(binary.LittleEndian.Uint16(chunk[16+12:]))
	for i := 0; i < attrCount; i++ {
		base := 16 + attrStart + i*attrSize
		if base+16 > len(chunk) {
			break
		}
		// ResXMLTree_attribute：ns(4)+name(4)+rawValue(4)+Res_value(size u16…)
		if sz := binary.LittleEndian.Uint16(chunk[base+12:]); sz != 8 {
			t.Errorf("%s: attr[%d] 的 Res_value.size=%d，应为 8", label, i, sz)
		}
	}
}

// TestRealisticAXMLResValueFields 钉住 junk.go 生成的垃圾 AXML 字段合法。
func TestRealisticAXMLResValueFields(t *testing.T) {
	data := realisticAXML(newRand("axjunk"), 512)
	chunks := walkStartElemChunks(t, data)
	if len(chunks) == 0 {
		t.Fatal("未找到 StartElement chunk")
	}
	for i, c := range chunks {
		checkStartElemFields(t, "junk.startElem", c)
		_ = i
	}
}

// TestNestedAPKManifestResValueFields 钉住 nestedapk.go 的假 Manifest 字段合法。
func TestNestedAPKManifestResValueFields(t *testing.T) {
	data := nestedAPKManifestAXML(newRand("axnested"), "com.agtest")
	chunks := walkStartElemChunks(t, data)
	if len(chunks) == 0 {
		t.Fatal("未找到 StartElement chunk")
	}
	for _, c := range chunks {
		checkStartElemFields(t, "nestedapk.startElem", c)
	}
}

// TestDecoyElemBodyResValueFields 钉住 decoycore.go 的属性体字段合法。
func TestDecoyElemBodyResValueFields(t *testing.T) {
	body := decoyElemBody(1, 1, []decoyElemAttr{
		{ns: 1, name: 2, raw: 3, dtype: 0x10, data: 0x7f010000},
		{ns: 1, name: 4, raw: 5, dtype: axml.TypeString, data: 6},
	})
	// body 布局：attrExt 20 字节（classIndex +16、styleIndex +18），属性紧接其后。
	if got := binary.LittleEndian.Uint16(body[16:]); got != 0 {
		t.Errorf("classIndex = %d，应为 0", got)
	}
	if got := binary.LittleEndian.Uint16(body[18:]); got != 0 {
		t.Errorf("styleIndex = %d，应为 0", got)
	}
	for i := 0; i < 2; i++ {
		base := 20 + i*20
		if sz := binary.LittleEndian.Uint16(body[base+12:]); sz != 8 {
			t.Errorf("attr[%d] 的 Res_value.size=%d，应为 8", i, sz)
		}
	}
}
