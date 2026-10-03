// Package axml 提供 Android 二进制 XML（AndroidManifest.xml 等）的解析能力。
//
// 只实现加固工具真正需要的部分：字符串池、元素与属性遍历、属性值改写。
// 布局依据 Android 官方 ResourceTypes.h。
package axml

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// 块类型。
const (
	TypeNull         = 0x0000
	TypeStringPool   = 0x0001
	TypeTable        = 0x0002
	TypeXML          = 0x0003
	TypeXMLStartNS   = 0x0100
	TypeXMLEndNS     = 0x0101
	TypeXMLStartElem = 0x0102
	TypeXMLEndElem   = 0x0103
	TypeXMLCData     = 0x0104
	TypeXMLResource  = 0x0180
)

// 属性值的类型（Res_value.dataType）。
//
// 取值来自 AOSP 的 Res_value 定义。目前只需要区分「字符串」与「十进制整数」：
// 前者值在字符串池里，后者值直接放在 Res_value.data 字段中——
// 例如 <uses-sdk android:minSdkVersion="21"> 通常就是十进制整数。
const (
	TypeString = 0x03
	TypeIntDec = 0x10
	// TypeIntBoolean 是布尔值：值直接放在 Res_value.data（0/1），rawValue 为 -1。
	// aapt2 生成 android:exported="false" 时用的就是它。
	TypeIntBoolean = 0x12
)

// AndroidNS 是 Android 平台属性的命名空间 URI。
//
// 例如 android:name 的完整标识是 {http://schemas.android.com/apk/res/android}name。
const AndroidNS = "http://schemas.android.com/apk/res/android"

const (
	noEntry     = 0xffffffff
	utf8Flag    = 1 << 8
	chunkHdrLen = 8
)

// File 是一个已解析的二进制 XML。
//
// 解析采用「零拷贝 + 惰性字符串」策略：底层字节保持原样，
// 只在需要时解码字符串，从而支持后续就地改写。
type File struct {
	data []byte

	poolStart  int
	poolCount  int
	poolUTF8   bool
	poolStrOff []int // 每个字符串的数据起始偏移
	// poolStrEnd 是每个字符串数据的结束偏移（不含结尾 NUL 之外的填充）。
	//
	// 改写字符串池时按 [start,end) 原样搬运既有字符串，
	// 因此需要精确的结束位置——不能靠「下一个字符串的起始」推断，
	// 因为字符串之间可能存在对齐填充。
	poolStrEnd []int
	// poolStyles 是原池的 style（富文本样式）数据；无 style 时为 nil。
	//
	// 重建池时必须原样保留，否则富文本样式会被静默丢弃（真实产物已因此损坏）。
	poolStyles *Styles

	// Elements 是全部起始元素（按出现顺序）。
	Elements []*Element
}

// Element 是 XML 中的一个起始元素。
type Element struct {
	// Name 是元素名（如 "activity"）。
	Name string
	// NameIdx 是元素名在字符串池中的索引。
	NameIdx uint32
	// Attrs 是全部属性。
	Attrs []Attr
	// HeaderOff 是该 start element 块的起始偏移。
	HeaderOff int
}

// Attr 是元素的一个属性。
type Attr struct {
	// NS 是命名空间字符串索引。
	NS uint32
	// NameIdx 是属性名在字符串池中的索引。
	NameIdx uint32
	// Name 是属性名（如 "name"）。
	Name string
	// RawValueIdx 是属性原始文本在字符串池中的索引；noEntry 表示无。
	RawValueIdx uint32
	// RawValue 是属性原始文本（如 "com.foo.Bar"）。
	RawValue string
	// DataType 是 Res_value 的类型。
	DataType uint8
	// Data 是 Res_value 的原始数据（字符串类型时是字符串池索引）。
	Data uint32
	// off 是该属性条目在原始数据中的起始偏移（改写时使用）。
	off int
	// NSName 是命名空间 URI 文本（改写时使用）。
	NSName string
}

// Parse 解析一个二进制 XML。
func Parse(data []byte) (*File, error) {
	if len(data) < chunkHdrLen {
		return nil, fmt.Errorf("axml: 数据长度不足")
	}
	typ := binary.LittleEndian.Uint16(data[0:])
	if typ != TypeXML {
		return nil, fmt.Errorf("axml: 根块类型 0x%04x 不是 RES_XML_TYPE", typ)
	}
	headerSize := int(binary.LittleEndian.Uint16(data[2:]))
	if headerSize < chunkHdrLen || headerSize > len(data) {
		return nil, fmt.Errorf("axml: 头部长度非法 %d", headerSize)
	}

	f := &File{data: data}
	if err := f.parseChunks(headerSize); err != nil {
		return nil, err
	}
	if f.poolStart == 0 && f.poolCount == 0 {
		return nil, fmt.Errorf("axml: 未找到字符串池")
	}
	return f, nil
}

// parseChunks 顺序遍历全部子块。
func (f *File) parseChunks(off int) error {
	d := f.data
	for off+chunkHdrLen <= len(d) {
		typ := binary.LittleEndian.Uint16(d[off:])
		hs := int(binary.LittleEndian.Uint16(d[off+2:]))
		size := int(binary.LittleEndian.Uint32(d[off+4:]))
		if size < chunkHdrLen || off+size > len(d) {
			// 末尾填充或损坏：停止遍历而非报错，保持容错
			return nil
		}
		switch typ {
		case TypeStringPool:
			if err := f.parseStringPool(off, hs, size); err != nil {
				return err
			}
		case TypeXMLStartElem:
			if err := f.parseStartElement(off, hs); err != nil {
				return err
			}
		}
		off += size
	}
	return nil
}

// parseStringPool 解析字符串池头部与各字符串偏移。
func (f *File) parseStringPool(off, hs, size int) error {
	d := f.data
	if off+28 > len(d) {
		return fmt.Errorf("axml: 字符串池头部越界")
	}
	count := int(binary.LittleEndian.Uint32(d[off+8:]))
	styleCount := int(binary.LittleEndian.Uint32(d[off+12:]))
	flags := binary.LittleEndian.Uint32(d[off+16:])
	stringsStart := int(binary.LittleEndian.Uint32(d[off+20:]))
	stylesStart := int(binary.LittleEndian.Uint32(d[off+24:]))
	if count < 0 || count > 1<<20 {
		return fmt.Errorf("axml: 字符串数量异常 %d", count)
	}
	if styleCount < 0 || styleCount > 1<<20 || styleCount > count {
		return fmt.Errorf("axml: style 数量异常 %d（字符串 %d）", styleCount, count)
	}
	base := off + stringsStart
	if base > off+size {
		return fmt.Errorf("axml: 字符串数据区偏移越界")
	}

	f.poolStart = off
	f.poolCount = count
	f.poolUTF8 = flags&utf8Flag != 0
	f.poolStrOff = make([]int, count)
	f.poolStrEnd = make([]int, count)

	// style 偏移数组紧跟在字符串偏移数组之后，仅当 styleCount > 0 时存在；
	// style 数据区位于 stylesStart 起、直到池块末尾。二者都必须原样保留，
	// 否则富文本样式会被静默丢弃。
	if styleCount > 0 {
		styleArrEnd := off + 28 + count*4 + styleCount*4
		if styleArrEnd > off+size {
			return fmt.Errorf("axml: style 偏移数组越界")
		}
		if stylesStart <= 0 || off+stylesStart < styleArrEnd || off+stylesStart > off+size {
			return fmt.Errorf("axml: stylesStart 非法 %d", stylesStart)
		}
		offs := make([]uint32, styleCount)
		for i := range offs {
			offs[i] = binary.LittleEndian.Uint32(d[off+28+count*4+4*i:])
		}
		sdata := d[off+stylesStart : off+size]
		for i, o := range offs {
			if o != noEntry && int(o) >= len(sdata) {
				return fmt.Errorf("axml: 第 %d 个 style 偏移越界 %d", i, o)
			}
		}
		f.poolStyles = &Styles{Count: styleCount, Offsets: offs, Data: sdata}
	}

	p := base
	for i := 0; i < count; i++ {
		if p >= len(d) {
			return fmt.Errorf("axml: 第 %d 个字符串越界", i)
		}
		f.poolStrOff[i] = p
		if f.poolUTF8 {
			// UTF-8 池：先字符数（变长），再字节数（变长）
			_, p2, err := utf8Len(d, p)
			if err != nil {
				return err
			}
			blen, p3, err := utf8Len(d, p2)
			if err != nil {
				return err
			}
			f.poolStrEnd[i] = p3 + int(blen)
			p = p3 + int(blen) + 1 // 跳过结尾 NUL
		} else {
			n, p2 := utf16Len(d, p)
			f.poolStrEnd[i] = p2 + int(n)*2
			p = p2 + int(n)*2 + 2
		}
		if p > len(d) {
			return fmt.Errorf("axml: 第 %d 个字符串长度越界", i)
		}
	}
	return nil
}

// utf8Len 读取 UTF-8 字符串池中的变长长度字段。
//
// 编码规则：首字节若最高位为 1，则长度由两个字节组成。
func utf8Len(d []byte, p int) (uint32, int, error) {
	if p >= len(d) {
		return 0, p, fmt.Errorf("axml: 长度字段越界")
	}
	b := d[p]
	if b&0x80 != 0 {
		if p+1 >= len(d) {
			return 0, p, fmt.Errorf("axml: 长度字段越界")
		}
		return uint32(b&0x7f)<<8 | uint32(d[p+1]), p + 2, nil
	}
	return uint32(b), p + 1, nil
}

// utf16Len 读取 UTF-16 字符串池中的变长长度字段。
//
// 返回 uint32 而不是 uint16：长格式的首字只承载真实长度的**高 15 位**，
// 低 16 位在次字里，因此真实长度可达 0x7fffffff。早期实现只返回次字
// （`Uint16(d[p+2:])`），把任何码元数 > 65535 的字符串长度截断成低 16 位，
// 后续读取就会截短字符串并让池内所有后续偏移错位。这里与
// internal/arsc 的 utf16PoolLen 保持同一算法。
func utf16Len(d []byte, p int) (uint32, int) {
	if p+2 > len(d) {
		return 0, p
	}
	v := binary.LittleEndian.Uint16(d[p:])
	if v&0x8000 != 0 {
		if p+4 > len(d) {
			return 0, p
		}
		lo := binary.LittleEndian.Uint16(d[p+2:])
		return uint32(v&0x7fff)<<16 | uint32(lo), p + 4
	}
	return uint32(v), p + 2
}

// parseStartElement 解析一个 RES_XML_START_ELEMENT_TYPE 块。
func (f *File) parseStartElement(off, hs int) error {
	d := f.data
	// 头部布局：ResChunk_header(8) + lineNumber(4) + comment(4) = ResXMLTree_node(16)
	// 之后是 ResXMLTree_attrExt：ns(4) name(4) attributeStart(2) attributeSize(2)
	//   attributeCount(2) idIndex(2) classIndex(2) styleIndex(2)
	//
	// attributeStart 是「相对 ResXMLTree_attrExt 起始（即 off+16）」的偏移，
	// 而不是相对 chunk 起始，因此属性区起点为 off+16+attributeStart。
	if off+36 > len(d) {
		return fmt.Errorf("axml: start element 头部越界")
	}
	nameIdx := binary.LittleEndian.Uint32(d[off+20:])
	attrStart := int(binary.LittleEndian.Uint16(d[off+24:]))
	attrSize := int(binary.LittleEndian.Uint16(d[off+26:]))
	attrCount := int(binary.LittleEndian.Uint16(d[off+28:]))
	if attrSize < 20 {
		return fmt.Errorf("axml: 属性大小非法 %d", attrSize)
	}

	el := &Element{NameIdx: nameIdx, HeaderOff: off}
	el.Name, _ = f.String(nameIdx)

	p := off + 16 + attrStart
	for i := 0; i < attrCount; i++ {
		if p+attrSize > len(d) {
			return fmt.Errorf("axml: 第 %d 个属性越界", i)
		}
		a := Attr{
			NS:          binary.LittleEndian.Uint32(d[p:]),
			NameIdx:     binary.LittleEndian.Uint32(d[p+4:]),
			RawValueIdx: binary.LittleEndian.Uint32(d[p+8:]),
			DataType:    d[p+15],
			Data:        binary.LittleEndian.Uint32(d[p+16:]),
		}
		a.off = p
		a.Name, _ = f.String(a.NameIdx)
		if a.NS != noEntry {
			a.NSName, _ = f.String(a.NS)
		}
		if a.RawValueIdx != noEntry {
			a.RawValue, _ = f.String(a.RawValueIdx)
		} else if a.DataType == TypeString && a.Data != noEntry {
			a.RawValue, _ = f.String(a.Data)
		}
		el.Attrs = append(el.Attrs, a)
		p += attrSize
	}
	f.Elements = append(f.Elements, el)
	return nil
}

// String 返回字符串池中第 i 个字符串。
func (f *File) String(i uint32) (string, error) {
	if int(i) >= f.poolCount {
		return "", fmt.Errorf("axml: 字符串索引越界 %d/%d", i, f.poolCount)
	}
	d := f.data
	p := f.poolStrOff[i]
	if f.poolUTF8 {
		_, p2, err := utf8Len(d, p)
		if err != nil {
			return "", err
		}
		blen, p3, err := utf8Len(d, p2)
		if err != nil {
			return "", err
		}
		end := p3 + int(blen)
		if end > len(d) {
			return "", fmt.Errorf("axml: 字符串 %d 越界", i)
		}
		return string(d[p3:end]), nil
	}
	n, p2 := utf16Len(d, p)
	end := p2 + int(n)*2
	if end > len(d) {
		return "", fmt.Errorf("axml: 字符串 %d 越界", i)
	}
	// UTF-16 转 UTF-8（含代理对合并）
	return utf16ToString(d[p2:end]), nil
}

// Strings 返回全部字符串。
func (f *File) Strings() []string {
	out := make([]string, 0, f.poolCount)
	for i := 0; i < f.poolCount; i++ {
		s, err := f.String(uint32(i))
		if err != nil {
			out = append(out, "")
			continue
		}
		out = append(out, s)
	}
	return out
}

// Count 返回字符串数量。
func (f *File) Count() int { return f.poolCount }

// FindElement 返回第一个名字等于 name 的元素。
func (f *File) FindElement(name string) *Element {
	for _, e := range f.Elements {
		if e.Name == name {
			return e
		}
	}
	return nil
}

// Attr 按属性名查找属性，未找到返回 nil。
func (e *Element) Attr(name string) *Attr {
	for i := range e.Attrs {
		if e.Attrs[i].Name == name {
			return &e.Attrs[i]
		}
	}
	return nil
}

// AttrNS 按命名空间与属性名查找属性。
//
// ns 为空串时匹配「无命名空间」的属性。
func (e *Element) AttrNS(ns, name string) *Attr {
	for i := range e.Attrs {
		if e.Attrs[i].Name != name {
			continue
		}
		if ns == "" {
			if e.Attrs[i].NS == noEntry {
				return &e.Attrs[i]
			}
			continue
		}
		if e.Attrs[i].NSName == ns {
			return &e.Attrs[i]
		}
	}
	return nil
}

// AttrString 返回指定属性的字符串值，未找到返回空串。
func (e *Element) AttrString(name string) string {
	if a := e.Attr(name); a != nil {
		return a.RawValue
	}
	return ""
}

// ComponentClasses 从 AndroidManifest 中提取全部「组件类名」。
//
// 覆盖 application 的 android:name 以及 activity/service/receiver/provider
// 等组件的 android:name，另有 meta-data 中常见框架入口。
// 返回值已去重并按字母序排序。
func (f *File) ComponentClasses() []string {
	targets := map[string]bool{
		"application": true, "activity": true, "activity-alias": true,
		"service": true, "receiver": true, "provider": true,
		"instrumentation": true, "uses-library": true,
	}
	seen := map[string]bool{}
	var out []string
	for _, e := range f.Elements {
		if !targets[e.Name] {
			continue
		}
		v := e.AttrString("name")
		if v == "" || !looksLikeClass(v) || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// looksLikeClass 判断字符串是否形如 Java 类名（含包名，或单段大写开头）。
func looksLikeClass(s string) bool {
	if s == "" || strings.ContainsAny(s, " \t/") {
		return false
	}
	// 排除以 . 开头（相对类名）之外，必须含 '.' 或以大写字母开头
	if strings.HasPrefix(s, ".") {
		return len(s) > 1
	}
	if !strings.Contains(s, ".") {
		return s[0] >= 'A' && s[0] <= 'Z'
	}
	// 各段不得为空
	for _, seg := range strings.Split(s, ".") {
		if seg == "" {
			return false
		}
	}
	return true
}

// utf16ToString 把 UTF-16LE 字节序列转为 UTF-8 字符串（合并代理对）。
func utf16ToString(b []byte) string {
	units := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		units = append(units, uint16(b[i])|uint16(b[i+1])<<8)
	}
	var sb strings.Builder
	for i := 0; i < len(units); i++ {
		u := units[i]
		switch {
		case u >= 0xd800 && u <= 0xdbff && i+1 < len(units):
			lo := units[i+1]
			if lo >= 0xdc00 && lo <= 0xdfff {
				r := 0x10000 + (rune(u)-0xd800)<<10 + (rune(lo) - 0xdc00)
				sb.WriteRune(r)
				i++
				continue
			}
			sb.WriteRune(0xfffd)
		case u >= 0xdc00 && u <= 0xdfff:
			sb.WriteRune(0xfffd)
		default:
			sb.WriteRune(rune(u))
		}
	}
	return sb.String()
}
