package axml

import (
	"encoding/binary"
	"fmt"
)

// 改写相关的常量。
const (
	// flagSorted 表示字符串池已按 UTF-16 码元序排序（可用于二分查找）。
	flagSorted = 1 << 0
	// attrEntryLen 是 ResXMLTree_attribute 的固定长度。
	attrEntryLen = 20
)

// AttrValue 描述「把某个元素的某个属性设为字符串值」。
//
// 属性已存在则就地改值；不存在则在属性表末尾插入一条新属性。
// 这覆盖了加壳场景的全部需求：给 <application> 补/改 android:name。
type AttrValue struct {
	// Element 是元素名，如 "application"。
	Element string
	// Index 是同类元素中的序号（从 0 开始），用于 activity 等同名元素。
	Index int
	// NS 是属性的命名空间 URI；空串表示无命名空间。
	NS string
	// Name 是属性名（不带前缀），如 "name"。
	Name string
	// Value 是新的字符串值。
	Value string
}

// NewAttr 描述新元素的一个属性。
//
// 用构造器而不是裸结构体：属性值要么是字符串、要么是布尔，两者在
// Res_value 里的编码完全不同（字符串要把池索引同时写进 rawValue 与 data，
// 布尔则把 rawValue 置 -1、把 0/1 写进 data），用类型区分可以避免写错。
type NewAttr struct {
	NS   string // 命名空间 URI；空表示无命名空间
	Name string // 属性名（不带前缀）
	// 二者恰有一个非 nil。
	strVal  *string
	boolVal *bool
}

// StringAttr 构造一个字符串型属性。
func StringAttr(ns, name, value string) NewAttr {
	return NewAttr{NS: ns, Name: name, strVal: &value}
}

// BoolAttr 构造一个布尔型属性（对应 aapt2 的 android:exported="false" 之类）。
func BoolAttr(ns, name string, v bool) NewAttr {
	return NewAttr{NS: ns, Name: name, boolVal: &v}
}

// NewElement 描述要插到某个已有元素**末尾**的新元素。
//
// 二进制 XML 的块列表是线性的，子元素必须落在父元素的结束块**之前**，
// 因此这里用 Parent/ParentIndex 定位父元素，再找到与它配对的结束块，插在其前。
type NewElement struct {
	// Parent 是父元素名，如 "application"。
	Parent string
	// ParentIndex 是父元素在同类元素中的序号（从 0 开始）。
	ParentIndex int
	// Name 是新元素名，如 "receiver"。
	Name string
	// Attrs 是新元素的属性。
	Attrs []NewAttr
}

// Edit 描述对二进制 XML 的一次改写。
type Edit struct {
	// Replace 把字符串池中等于 key 的文本替换为 value。
	Replace map[string]string
	// SetAttr 逐条设置元素属性。
	SetAttr []AttrValue
	// AddElements 在指定父元素末尾插入新元素。
	AddElements []NewElement
}

// Rewrite 按 edit 改写二进制 XML，返回新的字节流。
//
// 关键设计：**保持原字符串池的索引顺序不变**，只替换文本内容；
// 改写过程中新出现的文本追加到池尾。这样「旧索引 -> 新索引」是恒等映射，
// 无需遍历修正既有引用，改写逻辑因此极其简单且不易出错。
//
// 代价是池可能不再有序，此时会如实清除 SORTED 标志
// （清标志只会让系统退化为线性查找，不影响正确性；
//
//	但错误地保留标志会让二分查找返回错误结果）。
func (f *File) Rewrite(edit Edit) ([]byte, error) {
	if len(edit.Replace) == 0 && len(edit.SetAttr) == 0 && len(edit.AddElements) == 0 {
		return append([]byte(nil), f.data...), nil
	}

	// ---- 1) 计算新字符串列表 ----
	values := f.Strings()
	for i, s := range values {
		if nv, ok := edit.Replace[s]; ok {
			values[i] = nv
		}
	}
	// 文本 -> 池索引（首次出现者胜出），用于复用既有字符串。
	index := make(map[string]uint32, len(values)+8)
	for i, s := range values {
		if _, ok := index[s]; !ok {
			index[s] = uint32(i)
		}
	}
	intern := func(s string) uint32 {
		if j, ok := index[s]; ok {
			return j
		}
		j := uint32(len(values))
		index[s] = j
		values = append(values, s)
		return j
	}

	// ---- 2) 解析每条属性改写，收集要插入的属性与要改值的属性 ----
	type insertion struct {
		off   int // 目标 start element 块在原始数据中的偏移
		entry [attrEntryLen]byte
	}
	type valuePatch struct {
		off int    // 属性条目起始位置（绝对偏移）
		val uint32 // 新的字符串池索引
	}
	var inserts []insertion
	var patches []valuePatch
	for i, av := range edit.SetAttr {
		el := f.nthElement(av.Element, av.Index)
		if el == nil {
			return nil, fmt.Errorf("axml: 第 %d 条属性改写找不到元素 <%s> 第 %d 个", i, av.Element, av.Index)
		}
		var nsIdx uint32 = noEntry
		if av.NS != "" {
			nsIdx = intern(av.NS)
		}
		nameIdx := intern(av.Name)
		valIdx := intern(av.Value)

		if a := el.AttrNS(av.NS, av.Name); a != nil {
			// 已存在：就地改值（原始值与字符串数据都指向新索引）。
			patches = append(patches, valuePatch{off: a.off, val: valIdx})
			continue
		}
		var e [attrEntryLen]byte
		binary.LittleEndian.PutUint32(e[0:], nsIdx)
		binary.LittleEndian.PutUint32(e[4:], nameIdx)
		binary.LittleEndian.PutUint32(e[8:], valIdx)
		binary.LittleEndian.PutUint16(e[12:], 8) // Res_value.size
		e[14] = 0                                // res0
		e[15] = TypeString
		binary.LittleEndian.PutUint32(e[16:], valIdx)
		inserts = append(inserts, insertion{off: el.HeaderOff, entry: e})
	}

	// ---- 3) 解析要插入的新元素，编码成 start+end 块对 ----
	//
	// 必须放在生成字符串池**之前**：新元素的元素名与属性值都要 intern 进池。
	insertBefore := map[int][][]byte{}
	for i, ne := range edit.AddElements {
		parent := f.nthElement(ne.Parent, ne.ParentIndex)
		if parent == nil {
			return nil, fmt.Errorf("axml: 第 %d 个新元素找不到父元素 <%s> 第 %d 个", i, ne.Parent, ne.ParentIndex)
		}
		endOff := f.matchingEnd(parent.HeaderOff)
		if endOff < 0 {
			return nil, fmt.Errorf("axml: 元素 <%s> 第 %d 个没有配对的结束块", ne.Parent, ne.ParentIndex)
		}
		attrs := make([][attrEntryLen]byte, 0, len(ne.Attrs))
		for _, na := range ne.Attrs {
			var e [attrEntryLen]byte
			var nsIdx uint32 = noEntry
			if na.NS != "" {
				nsIdx = intern(na.NS)
			}
			binary.LittleEndian.PutUint32(e[0:], nsIdx)
			binary.LittleEndian.PutUint32(e[4:], intern(na.Name))
			switch {
			case na.strVal != nil:
				valIdx := intern(*na.strVal)
				binary.LittleEndian.PutUint32(e[8:], valIdx) // rawValue
				binary.LittleEndian.PutUint16(e[12:], 8)     // Res_value.size
				e[15] = TypeString
				binary.LittleEndian.PutUint32(e[16:], valIdx) // Res_value.data
			case na.boolVal != nil:
				var v uint32
				if *na.boolVal {
					v = 1
				}
				binary.LittleEndian.PutUint32(e[8:], noEntry) // 布尔没有原始文本
				binary.LittleEndian.PutUint16(e[12:], 8)
				e[15] = TypeIntBoolean
				binary.LittleEndian.PutUint32(e[16:], v)
			default:
				return nil, fmt.Errorf("axml: 新元素 <%s> 的属性 %s 没有取值", ne.Name, na.Name)
			}
			attrs = append(attrs, e)
		}
		nameIdx := intern(ne.Name)
		blob := encodeStartElement(nameIdx, attrs)
		blob = append(blob, encodeEndElement(nameIdx)...)
		insertBefore[endOff] = append(insertBefore[endOff], blob)
	}

	// ---- 4) 生成新的字符串池块 ----
	// 原池若带 style 数据必须原样保留（只改文本、条数与索引不变时是安全的）；
	// 丢弃会让富文本样式静默损坏。
	poolBlob, err := encodeStringPoolStyled(values, f.poolUTF8, f.poolStyles)
	if err != nil {
		return nil, err
	}

	// ---- 5) 组装：根块头 + 新池 + 其余块（按需改值/插入属性/插入元素）----
	const rootHeaderSize = 8
	if len(f.data) < rootHeaderSize {
		return nil, fmt.Errorf("axml: 数据长度不足")
	}
	insByOff := make(map[int][][attrEntryLen]byte, len(inserts))
	for _, in := range inserts {
		insByOff[in.off] = append(insByOff[in.off], in.entry)
	}

	out := make([]byte, 0, len(f.data)+len(poolBlob))
	out = append(out, f.data[:rootHeaderSize]...)
	out = append(out, poolBlob...)

	d := f.data
	for off := rootHeaderSize; off+chunkHdrLen <= len(d); {
		typ := binary.LittleEndian.Uint16(d[off:])
		size := int(binary.LittleEndian.Uint32(d[off+4:]))
		if size < chunkHdrLen || off+size > len(d) {
			break
		}
		if typ == TypeStringPool {
			off += size
			continue
		}
		blob := append([]byte(nil), d[off:off+size]...)
		for _, p := range patches {
			if p.off < off || p.off+attrEntryLen > off+size {
				continue
			}
			q := p.off - off
			binary.LittleEndian.PutUint32(blob[q+8:], p.val)  // Res_value 的 rawValue
			binary.LittleEndian.PutUint16(blob[q+12:], 8)     // Res_value.size
			blob[q+15] = TypeString                           // Res_value.dataType
			binary.LittleEndian.PutUint32(blob[q+16:], p.val) // Res_value.data
		}
		if entries := insByOff[off]; len(entries) > 0 {
			var err error
			if blob, err = insertAttrs(blob, entries); err != nil {
				return nil, err
			}
		}
		// 新元素整棵子树插在该块**之前**：目标是父元素的结束块，
		// 因此插入后新元素恰好落在父元素内容末尾、父元素结束块之前。
		for _, pre := range insertBefore[off] {
			out = append(out, pre...)
		}
		out = append(out, blob...)
		off += size
	}

	// ---- 6) 修正根块与池块的总长度 ----
	// 根块 size 位于 +4；字符串池块的 size 位于 8+4。
	binary.LittleEndian.PutUint32(out[4:], uint32(len(out)))
	binary.LittleEndian.PutUint32(out[12:], uint32(len(poolBlob)))
	return out, nil
}

// matchingEnd 返回与 startOff 处 start element 配对的 end element 块偏移。
//
// 二进制 XML 的块列表是线性的，没有显式的父子指针：嵌套关系只能靠
// start/end 块的出现顺序推断——从该 start element 起深度计数，回到 0 即为配对者。
func (f *File) matchingEnd(startOff int) int {
	d := f.data
	depth := 0
	for off := startOff; off+chunkHdrLen <= len(d); {
		size := int(binary.LittleEndian.Uint32(d[off+4:]))
		if size < chunkHdrLen || off+size > len(d) {
			return -1
		}
		switch binary.LittleEndian.Uint16(d[off:]) {
		case TypeXMLStartElem:
			depth++
		case TypeXMLEndElem:
			depth--
			if depth == 0 {
				return off
			}
		}
		off += size
	}
	return -1
}

// encodeStartElement 生成一个 RES_XML_START_ELEMENT_TYPE 块。
//
// 布局：ResChunk_header(8，headerSize=16) + lineNumber(4) + comment(4)
//   - ResXMLTree_attrExt(20) + attributeCount * ResXMLTree_attribute(20)
//
// attributeStart 是相对 attrExt 起点的偏移，因此恒为 20（attrExt 自身长度）。
func encodeStartElement(nameIdx uint32, attrs [][attrEntryLen]byte) []byte {
	size := 16 + 20 + len(attrs)*attrEntryLen
	b := make([]byte, size)
	binary.LittleEndian.PutUint16(b[0:], TypeXMLStartElem)
	binary.LittleEndian.PutUint16(b[2:], 16) // headerSize 只到 ResXMLTree_node 末尾
	binary.LittleEndian.PutUint32(b[4:], uint32(size))
	// lineNumber / comment 保持 0（新元素没有源码位置）
	binary.LittleEndian.PutUint32(b[16:], noEntry) // attrExt.ns：无命名空间
	binary.LittleEndian.PutUint32(b[20:], nameIdx)
	binary.LittleEndian.PutUint16(b[24:], 20)
	binary.LittleEndian.PutUint16(b[26:], attrEntryLen)
	binary.LittleEndian.PutUint16(b[28:], uint16(len(attrs)))
	// idIndex / classIndex / styleIndex 保持 0
	p := 36
	for _, a := range attrs {
		copy(b[p:], a[:])
		p += attrEntryLen
	}
	return b
}

// encodeEndElement 生成一个 RES_XML_END_ELEMENT_TYPE 块。
//
// 布局：ResChunk_header(8，headerSize=16) + lineNumber(4) + comment(4)
//   - ResXMLTree_endElementExt(8)
func encodeEndElement(nameIdx uint32) []byte {
	b := make([]byte, 24)
	binary.LittleEndian.PutUint16(b[0:], TypeXMLEndElem)
	binary.LittleEndian.PutUint16(b[2:], 16)
	binary.LittleEndian.PutUint32(b[4:], 24)
	binary.LittleEndian.PutUint32(b[16:], noEntry)
	binary.LittleEndian.PutUint32(b[20:], nameIdx)
	return b
}

// insertAttrs 在一个 start element 块的属性表末尾追加若干属性。
//
// 属性表位于块尾，因此追加不会影响块内其它字段；
// 只需同步更新 attributeCount（+28）与块 size（+4）。
func insertAttrs(blob []byte, entries [][attrEntryLen]byte) ([]byte, error) {
	typ := binary.LittleEndian.Uint16(blob)
	if typ != TypeXMLStartElem {
		return nil, fmt.Errorf("axml: 偏移处不是 start element 块（0x%04x）", typ)
	}
	if len(blob) < 36 {
		return nil, fmt.Errorf("axml: start element 块过小")
	}
	attrStart := int(binary.LittleEndian.Uint16(blob[24:]))
	attrSize := int(binary.LittleEndian.Uint16(blob[26:]))
	attrCount := int(binary.LittleEndian.Uint16(blob[28:]))
	if attrSize != attrEntryLen {
		return nil, fmt.Errorf("axml: 属性大小 %d 不受支持", attrSize)
	}
	// 属性区必须位于块尾且完整落在块内，否则说明布局与预期不符。
	attrOff := 16 + attrStart
	if attrOff+attrCount*attrSize != len(blob) {
		return nil, fmt.Errorf("axml: 属性区布局异常（属性区 %d..%d，块长 %d）",
			attrOff, attrOff+attrCount*attrSize, len(blob))
	}
	for _, e := range entries {
		blob = append(blob, e[:]...)
	}
	binary.LittleEndian.PutUint16(blob[28:], uint16(attrCount+len(entries)))
	binary.LittleEndian.PutUint32(blob[4:], uint32(len(blob)))
	return blob, nil
}

// nthElement 返回第 n 个（从 0 开始）名字为 name 的元素。
func (f *File) nthElement(name string, n int) *Element {
	if n < 0 {
		return nil
	}
	for _, e := range f.Elements {
		if e.Name != name {
			continue
		}
		if n == 0 {
			return e
		}
		n--
	}
	return nil
}

// Styles 描述字符串池的 style（富文本样式）数据。
//
// ResStringPool 的 style 由两部分组成：
//   - style 偏移数组：紧跟在字符串偏移数组之后（仅当 styleCount > 0 时存在），
//     每项相对 stylesStart，0xffffffff 表示该字符串没有样式；
//   - style 数据区：位于 stylesStart 起，编码各字符串的 span 列表。
//
// 重建池时原样搬运这两部分即可——style 偏移是**相对** stylesStart 的，
// 字符串数据长度变化只会让 stylesStart 的绝对值平移，相对偏移不受影响，
// 因此只需回填新的 stringsStart/stylesStart，绝不能把 styleCount 置零。
type Styles struct {
	// Count 是 style 条目数（原池 styleCount）。
	Count int
	// Offsets 是长度为 Count 的 style 偏移数组（相对 stylesStart）。
	Offsets []uint32
	// Data 是从 stylesStart 起的 style 数据区（原样字节）。
	Data []byte
}

// encodeStringPool 按给定字符串列表生成一个字符串池块（无 style）。
//
// 布局：chunk 头(28) + 偏移表(n*4) + 字符串数据 + 4 字节对齐填充。
// 偏移表中的值是「相对 stringsStart 的偏移」——这是 AXML 的规定，
// 与 DEX 字符串池用绝对偏移不同。
//
// 编码风格（UTF-8 / UTF-16）跟随原文件，以免引入额外的兼容性差异。
func encodeStringPool(strs []string, utf8Pool bool) []byte {
	out, _ := encodeStringPoolStyled(strs, utf8Pool, nil)
	return out
}

// encodeStringPoolStyled 是字符串池编码的完整实现，支持原样保留 style 数据。
//
// 当 st 非空时，布局为：
//
//	chunk 头(28) + 字符串偏移表(n*4) + style 偏移表(styleCount*4)
//	  + 字符串数据 + 对齐填充 + style 数据区 + 对齐填充
//
// style 偏移数组与 style 数据区都按传入值原样写入；st.Count > n 时无法安全
// 保留（被引用的字符串不存在），返回错误而绝不静默置零。
func encodeStringPoolStyled(strs []string, utf8Pool bool, st *Styles) ([]byte, error) {
	n := len(strs)
	const headerSize = 28

	styleCount := 0
	if st != nil && st.Count > 0 {
		if len(st.Offsets) != st.Count {
			return nil, fmt.Errorf("axml: style 偏移数组长度 %d 与 styleCount %d 不符", len(st.Offsets), st.Count)
		}
		// style 条目按下标与字符串一一对应；字符串变少时无法安全保留。
		if n < st.Count {
			return nil, fmt.Errorf("axml: 字符串数量 %d 少于 styleCount %d，无法安全保留 style", n, st.Count)
		}
		styleCount = st.Count
	}

	datas := make([][]byte, n)
	dataLen := 0
	for i, s := range strs {
		if utf8Pool {
			datas[i] = encodeUTF8String(s)
		} else {
			datas[i] = encodeUTF16String(s)
		}
		dataLen += len(datas[i])
	}

	stringsStart := headerSize + n*4 + styleCount*4
	size := stringsStart + dataLen
	stylesStart := 0
	if styleCount > 0 {
		stylesStart = align4(size)
		size = stylesStart + len(st.Data)
	}
	if r := size % 4; r != 0 {
		size += 4 - r
	}

	out := make([]byte, size)
	binary.LittleEndian.PutUint16(out[0:], TypeStringPool)
	binary.LittleEndian.PutUint16(out[2:], headerSize)
	binary.LittleEndian.PutUint32(out[4:], uint32(size))
	binary.LittleEndian.PutUint32(out[8:], uint32(n))
	binary.LittleEndian.PutUint32(out[12:], uint32(styleCount))
	flags := uint32(0)
	if isSortedUTF16(strs) {
		flags |= flagSorted
	}
	if utf8Pool {
		flags |= utf8Flag
	}
	binary.LittleEndian.PutUint32(out[16:], flags)
	binary.LittleEndian.PutUint32(out[20:], uint32(stringsStart))
	binary.LittleEndian.PutUint32(out[24:], uint32(stylesStart))

	p := stringsStart
	for i, b := range datas {
		binary.LittleEndian.PutUint32(out[headerSize+4*i:], uint32(p-stringsStart))
		copy(out[p:], b)
		p += len(b)
	}
	if styleCount > 0 {
		// style 偏移数组原样搬运；相对偏移不随 stylesStart 平移而改变。
		for i := 0; i < styleCount; i++ {
			binary.LittleEndian.PutUint32(out[headerSize+n*4+4*i:], st.Offsets[i])
		}
		copy(out[stylesStart:], st.Data)
	}
	return out, nil
}

// align4 把 n 向上对齐到 4 的倍数。
func align4(n int) int {
	if r := n % 4; r != 0 {
		return n + 4 - r
	}
	return n
}

// isSortedUTF16 判断字符串列表是否已按 UTF-16 码元序严格递增。
//
// sorted 标志只是给系统二分查找用的提示，标错会导致 indexOf 返回错误结果，
// 因此必须如实计算，而不是无条件置位。
func isSortedUTF16(strs []string) bool {
	for i := 1; i < len(strs); i++ {
		if compareUTF16Units(strs[i-1], strs[i]) >= 0 {
			return false
		}
	}
	return true
}

// compareUTF16Units 按 UTF-16 码元序比较两个字符串。
func compareUTF16Units(a, b string) int {
	ua, ub := utf16Units(a), utf16Units(b)
	n := len(ua)
	if len(ub) < n {
		n = len(ub)
	}
	for i := 0; i < n; i++ {
		if ua[i] != ub[i] {
			if ua[i] < ub[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(ua) < len(ub):
		return -1
	case len(ua) > len(ub):
		return 1
	}
	return 0
}

// encodeUTF8String 编码一个 UTF-8 池字符串：字符数(变长) + 字节数(变长) + 数据 + NUL。
func encodeUTF8String(s string) []byte {
	raw := []byte(s)
	chars := 0
	for range s {
		chars++
	}
	out := appendUTF8Len(nil, uint32(chars))
	out = appendUTF8Len(out, uint32(len(raw)))
	out = append(out, raw...)
	out = append(out, 0)
	return out
}

// appendUTF8Len 按 Android 的变长长度格式追加一个长度字段。
func appendUTF8Len(out []byte, n uint32) []byte {
	if n > 0x7f {
		return append(out, byte(0x80|(n>>8)), byte(n))
	}
	return append(out, byte(n))
}

// encodeUTF16String 编码一个 UTF-16 池字符串：码元数(变长) + 数据 + NUL。
//
// 长度字段是一个或两个 **小端 uint16**：短格式直接写码元数；
// 长格式首字为 0x8000|(n>>16)、次字为 n&0xffff。
// 写成大端字节序会让解析方把长度读成 n<<8，必须避免。
func encodeUTF16String(s string) []byte {
	units := utf16Units(s)
	out := make([]byte, 0, len(units)*2+4)
	n := uint32(len(units))
	if n > 0x7fff {
		hi := uint16(0x8000 | (n >> 16))
		out = append(out, byte(hi), byte(hi>>8))
		out = append(out, byte(n), byte(n>>8))
	} else {
		out = append(out, byte(n), byte(n>>8))
	}
	for _, u := range units {
		out = append(out, byte(u), byte(u>>8))
	}
	out = append(out, 0, 0)
	return out
}

// utf16Units 把字符串转为 UTF-16 码元序列（含代理对拆分）。
func utf16Units(s string) []uint16 {
	out := make([]uint16, 0, len(s))
	for _, r := range s {
		if r < 0x10000 {
			out = append(out, uint16(r))
			continue
		}
		v := r - 0x10000
		out = append(out, uint16(0xd800+(v>>10)), uint16(0xdc00+(v&0x3ff)))
	}
	return out
}

// EncodeStringPool 编码一个 ResStringPool 块。
//
// 导出供 ARSC 重写复用：resources.arsc 的全局字符串池与 AXML 的字符串池
// 是**完全相同的结构**，共用同一份实现可以让「UTF-16 排序标志」「MUTF-8
// 长度前缀」这些容易出错的细节只有一处代码。
func EncodeStringPool(strs []string, utf8Pool bool) []byte {
	return encodeStringPool(strs, utf8Pool)
}

// EncodeStringPoolWithStyles 在编码字符串池时原样保留 style 数据。
//
// 供 ARSC / AXML 重写复用：只要字符串条数与索引顺序不变（只改文本），
// 传入原池的 *Styles 即可让 styleCount 与每条 style 的 span 数据保持不变。
// 若 strs 数量少于 st.Count（被引用字符串不存在），返回错误而不是丢样式。
func EncodeStringPoolWithStyles(strs []string, utf8Pool bool, st *Styles) ([]byte, error) {
	return encodeStringPoolStyled(strs, utf8Pool, st)
}

// PoolSorted 报告字符串列表是否已按 UTF-16 码元序严格递增。
//
// 调用方用它决定是否保留 sorted 标志——标错会让系统的二分查找返回错误结果。
func PoolSorted(strs []string) bool { return isSortedUTF16(strs) }
