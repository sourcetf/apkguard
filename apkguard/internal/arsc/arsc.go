// Package arsc 解析并重写 resources.arsc 的字符串池。
//
// 两条改写路径：
//   - 全局字符串池里的 res/ 文件路径（本文件的 Replace/Encode，服务 A5/A11 的路径改名）；
//   - 包内 keyStrings 池的资源条目名（keys.go 的 RandomizeKeys，服务 A5/A11
//     的条目名随机化）。
//
// 为什么只需要动字符串池：A5/A11 要做的是把 res/ 下的**文件路径**改名，
// 而资源引用走的是资源 ID（int），路径只作为「字符串值」存在全局字符串池里。
// 因此改路径 = 改字符串池里的若干条目。条目名同理：ResTable_entry 用池下标
// 引用 keyStrings，换掉槽位内容不影响任何资源 ID。
//
// 为什么不担心偏移：ARSC 是**按块顺序**解析的——
//
//	ResTable_header → 全局字符串池 → ResTable_package（内含 TypeSpec/Type 块）
//
// 表头只有 packageCount，没有任何绝对偏移；包块里的 typeStrings/keyStrings
// 是**相对包块自身**的偏移；Type 块内的 entriesStart 同样相对自身。
// 所以替换字符串池（长度可变）之后，只需回填字符串池块自己的 size、所属
// 包块的 size 与表头的 size。其余字节可以原样搬运。
//
// 这一点的价值在于：不必做任何重定位，出错面极小——这正是重写二进制
// 资源表最容易踩雷的地方。
package arsc

import (
	"encoding/binary"
	"fmt"
	"strings"

	"apkguard/internal/axml"
)

// 块类型与标志。
const (
	typeTable      = 0x0002 // RES_TABLE_TYPE
	typeStringPool = 0x0001 // RES_STRING_POOL_TYPE
	utf8Flag       = 1 << 8 // 池内字符串为 UTF-8（否则 UTF-16LE）
	// tableHeaderLen 是 ResTable_header 的固定长度（含 size 字段）。
	tableHeaderLen = 12
	// poolHeaderLen 是 ResStringPool_header 的固定长度。
	poolHeaderLen = 28
)

// Table 是一个已解析的 resources.arsc。
type Table struct {
	data []byte
	// poolOff / poolEnd 界定全局字符串池块在 data 中的范围。
	poolOff int
	poolEnd int
	// strings 是池内字符串（与池中索引一一对应）。
	strings []string
	utf8    bool
	// styles 是原池的 style（富文本样式）数据；无 style 时为 nil。
	// 重建池时必须原样保留，否则样式数据会被静默丢弃。
	styles *axml.Styles
	// edits 保存「索引 → 新值」的改写。
	edits map[int]string
}

// Parse 解析 resources.arsc，定位并解码全局字符串池。
//
// 只解析到「能改字符串池」所需的程度：整张资源表（类型、配置、条目）都不解读，
// 因为改写并不依赖它们。
func Parse(data []byte) (*Table, error) {
	if len(data) < tableHeaderLen {
		return nil, fmt.Errorf("arsc: 数据过短")
	}
	if binary.LittleEndian.Uint16(data[0:]) != typeTable {
		return nil, fmt.Errorf("arsc: 不是 RES_TABLE_TYPE（0x%04x）", binary.LittleEndian.Uint16(data[0:]))
	}
	off := int(binary.LittleEndian.Uint16(data[2:]))
	if off < tableHeaderLen || off > len(data) {
		return nil, fmt.Errorf("arsc: 表头长度非法 %d", off)
	}
	p, err := parseStringPool(data, off)
	if err != nil {
		return nil, err
	}
	return &Table{
		data:    data,
		poolOff: off,
		poolEnd: off + p.size,
		strings: p.strings,
		utf8:    p.utf8,
		styles:  p.styles,
		edits:   map[int]string{},
	}, nil
}

// stringPool 是一个已解析的 RES_STRING_POOL 块。
type stringPool struct {
	// strings 与池中索引一一对应。
	strings []string
	utf8    bool
	// styles 是原池的 style 数据；无 style 时为 nil。
	styles *axml.Styles
	// size 是块总长（含头部、偏移数组与对齐填充）。
	size int
}

// parseStringPool 解析 data[off:] 处的 RES_STRING_POOL 块。
//
// 全局字符串池（Parse）与包内的 keyStrings/typeStrings（keys.go）结构完全相同，
// 因此共用这一份实现：池头校验、style 保留与两种编码的解码只写一遍，
// 避免两处实现漂移（ARSC 解析最容易出错的就是这些边界）。
func parseStringPool(data []byte, off int) (*stringPool, error) {
	if off < 0 || off+poolHeaderLen > len(data) {
		return nil, fmt.Errorf("arsc: 字符串池头部越界")
	}
	if binary.LittleEndian.Uint16(data[off:]) != typeStringPool {
		return nil, fmt.Errorf("arsc: 偏移 %d 处不是字符串池（0x%04x）", off, binary.LittleEndian.Uint16(data[off:]))
	}
	poolSize := int(binary.LittleEndian.Uint32(data[off+4:]))
	poolEnd := off + poolSize
	if poolSize < poolHeaderLen || poolEnd > len(data) {
		return nil, fmt.Errorf("arsc: 字符串池长度非法 %d", poolSize)
	}

	count := int(binary.LittleEndian.Uint32(data[off+8:]))
	if count < 0 || count > 1<<22 {
		return nil, fmt.Errorf("arsc: 字符串数量异常 %d", count)
	}
	styleCount := int(binary.LittleEndian.Uint32(data[off+12:]))
	flags := binary.LittleEndian.Uint32(data[off+16:])
	stringsStart := int(binary.LittleEndian.Uint32(data[off+20:]))
	stylesStart := int(binary.LittleEndian.Uint32(data[off+24:]))
	base := off + stringsStart
	if base < off+poolHeaderLen || base > poolEnd {
		return nil, fmt.Errorf("arsc: 字符串数据区偏移非法 %d", stringsStart)
	}
	// 偏移数组紧跟在池头部之后。
	if off+poolHeaderLen+count*4 > poolEnd {
		return nil, fmt.Errorf("arsc: 字符串偏移数组越界")
	}
	if styleCount < 0 || styleCount > count {
		return nil, fmt.Errorf("arsc: style 数量异常 %d（字符串 %d）", styleCount, count)
	}

	// style 数据必须一并解析并保留：其偏移数组紧跟字符串偏移数组，
	// 数据区位于 stylesStart 起。丢失它会让富文本样式（权限对话框等）
	// 被静默破坏。
	var styles *axml.Styles
	if styleCount > 0 {
		styleArrEnd := off + poolHeaderLen + count*4 + styleCount*4
		if styleArrEnd > poolEnd {
			return nil, fmt.Errorf("arsc: style 偏移数组越界")
		}
		if stylesStart <= 0 || off+stylesStart < styleArrEnd || off+stylesStart > poolEnd {
			return nil, fmt.Errorf("arsc: stylesStart 非法 %d", stylesStart)
		}
		offs := make([]uint32, styleCount)
		for i := range offs {
			offs[i] = binary.LittleEndian.Uint32(data[off+poolHeaderLen+count*4+4*i:])
		}
		sdata := data[off+stylesStart : poolEnd]
		for i, o := range offs {
			if o != 0xffffffff && int(o) >= len(sdata) {
				return nil, fmt.Errorf("arsc: 第 %d 个 style 偏移越界 %d", i, o)
			}
		}
		styles = &axml.Styles{Count: styleCount, Offsets: offs, Data: sdata}
	}

	p := &stringPool{
		strings: make([]string, count),
		utf8:    flags&utf8Flag != 0,
		styles:  styles,
		size:    poolSize,
	}
	// decode 是 Table 的方法（仍是包内唯一实现），这里借一个只带编码信息
	// 的临时 Table 解码，不必复制解码逻辑。
	dec := &Table{data: data, utf8: p.utf8}
	for i := 0; i < count; i++ {
		so := base + int(binary.LittleEndian.Uint32(data[off+poolHeaderLen+4*i:]))
		if so < base || so >= poolEnd {
			return nil, fmt.Errorf("arsc: 第 %d 个字符串偏移越界 %d", i, so)
		}
		s, err := dec.decode(so)
		if err != nil {
			return nil, fmt.Errorf("arsc: 解码第 %d 个字符串失败: %w", i, err)
		}
		p.strings[i] = s
	}
	return p, nil
}

// Strings 返回池内全部字符串（只读）。
func (t *Table) Strings() []string { return t.strings }

// UTF8 报告池使用 UTF-8 还是 UTF-16 编码。
func (t *Table) UTF8() bool { return t.utf8 }

// Replace 把值等于 old 的字符串改为 new，返回改动的条数。
//
// 按**内容**匹配而不是按索引：调用方关心的是「这个路径要改名」，
// 而不是它在池里的下标。
func (t *Table) Replace(old, new string) int {
	n := 0
	for i, s := range t.strings {
		if s == old {
			t.edits[i] = new
			n++
		}
	}
	return n
}

// ResPaths 返回池内全部形如 res/ 的资源文件路径（去重后按序）。
func (t *Table) ResPaths() []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range t.strings {
		if !seen[s] && strings.HasPrefix(s, "res/") {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// Encode 用改写后的字符串池重建 ARSC。
//
// 未改动的字符串原样保留（包括顺序与索引），因此所有既有资源引用不受影响。
func (t *Table) Encode() ([]byte, error) {
	if len(t.edits) == 0 {
		return append([]byte(nil), t.data...), nil
	}
	vals := make([]string, len(t.strings))
	copy(vals, t.strings)
	// 单遍「索引 → 新值」映射：edits 的键就是池下标，直接逐个赋值即可。
	// 不要做「旧值 → 新值」的按值二次重写——那会级联改写：
	// strings=["a","b"]、edits={0:"b",1:"c"} 时，第一次映射得到 ["b","c"]，
	// 再按值把 "b" 重写成 "c" 就成了 ["c","c"]（"a" 被错误变成 "c"）。
	for i, v := range t.edits {
		vals[i] = v
	}

	pool, err := axml.EncodeStringPoolWithStyles(vals, t.utf8, t.styles)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(t.data)+len(pool))
	out = append(out, t.data[:t.poolOff]...)
	out = append(out, pool...)
	out = append(out, t.data[t.poolEnd:]...)
	// 表头的 size 字段描述整张表的总长度，必须同步更新。
	binary.LittleEndian.PutUint32(out[4:], uint32(len(out)))
	return out, nil
}

// decode 解码位于绝对偏移 p 处的池字符串。
func (t *Table) decode(p int) (string, error) {
	d := t.data
	if t.utf8 {
		// UTF-8 形式：u16len(varint) u8len(varint) bytes NUL
		//
		// 顺序不能搞反：**先**是 UTF-16 码元数，**后**才是 UTF-8 字节数
		// （AOSP ResStringPool::string8At 就是 decodeLength 两次）。
		// 早期实现把第一个前缀当字节数用，于是任何非 ASCII 字符串都被截断
		// （中文 1 个码元 = 3 字节），而 Encode() 会把截断后的值整池写回——
		// 中文资源会被静默损坏。ASCII 串两者相等，因此本地测试与
		// 「只比资源 ID」的用例都发现不了。
		if _, n := uvarint(d, p); n <= 0 {
			return "", fmt.Errorf("UTF-16 长度前缀非法")
		} else {
			p += n
		}
		u8len, n := uvarint(d, p)
		if n <= 0 {
			return "", fmt.Errorf("UTF-8 长度前缀非法")
		}
		p += n
		if p+int(u8len) > len(d) {
			return "", fmt.Errorf("字符串数据越界")
		}
		// 池内的「UTF-8」实际按 CESU-8 存放（4 字节代理对），
		// 直接用标准解码在 BMP 以外会失败，因此逐段容错解码。
		return decodeCESU8(d[p : p+int(u8len)]), nil
	}
	// UTF-16 形式：长度是**小端 uint16**（超长时首字置 0x8000 标志、次字为低 16 位），
	// 不是变长整数。用 uvarint 读会少读 1 字节，整个池解码成乱码
	// （实测："res/layout/main.xml" 会变成 "爀攀猀⼀..."，即按字节错位）。
	u16len, n := utf16PoolLen(d, p)
	if n == 0 {
		return "", fmt.Errorf("长度前缀非法")
	}
	p += n
	if p+int(u16len)*2 > len(d) {
		return "", fmt.Errorf("字符串数据越界")
	}
	return decodeUTF16(d[p : p+int(u16len)*2]), nil
}

// utf16PoolLen 读取 UTF-16 池字符串的长度前缀。
//
// 约定与 internal/axml 的 utf16Len 一致：小端 uint16；若首字的最高位为 1，
// 则它是长字符串标志，真实长度 = (首字 & 0x7fff) << 16 | 次字。
func utf16PoolLen(d []byte, p int) (uint32, int) {
	if p+2 > len(d) {
		return 0, 0
	}
	v := binary.LittleEndian.Uint16(d[p:])
	if v&0x8000 == 0 {
		return uint32(v), 2
	}
	if p+4 > len(d) {
		return 0, 0
	}
	lo := binary.LittleEndian.Uint16(d[p+2:])
	return uint32(v&0x7fff)<<16 | uint32(lo), 4
}

// uvarint 读取 1~2 字节的无符号变长整数（池字符串的长度前缀格式）。
func uvarint(d []byte, p int) (uint32, int) {
	if p >= len(d) {
		return 0, 0
	}
	b := d[p]
	if b&0x80 == 0 {
		return uint32(b), 1
	}
	if p+1 >= len(d) {
		return 0, 0
	}
	return uint32(b&0x7f)<<8 | uint32(d[p+1]), 2
}

// decodeUTF16 把 UTF-16LE 字节解码为字符串（含代理对合并）。
func decodeUTF16(b []byte) string {
	var sb strings.Builder
	for i := 0; i+1 < len(b); i += 2 {
		u := uint32(b[i]) | uint32(b[i+1])<<8
		if u >= 0xd800 && u <= 0xdbff && i+3 < len(b) {
			lo := uint32(b[i+2]) | uint32(b[i+3])<<8
			if lo >= 0xdc00 && lo <= 0xdfff {
				sb.WriteRune(rune(0x10000 + (u-0xd800)<<10 + (lo - 0xdc00)))
				i += 2
				continue
			}
		}
		sb.WriteRune(rune(u))
	}
	return sb.String()
}

// decodeCESU8 解码池中存放的 UTF-8/CESU-8 数据。
//
// 同时兼容标准 UTF-8（4 字节直编）与 CESU-8（3+3 代理对）两种写法：
// 不同 aapt 版本产出的编码不一致，容错解码才能正确读出原路径。
func decodeCESU8(b []byte) string {
	var out []rune
	for i := 0; i < len(b); {
		c := b[i]
		switch {
		case c < 0x80:
			out = append(out, rune(c))
			i++
		case c&0xe0 == 0xc0 && i+1 < len(b):
			out = append(out, rune(uint32(c&0x1f)<<6|uint32(b[i+1]&0x3f)))
			i += 2
		case c&0xf0 == 0xe0 && i+2 < len(b):
			u := uint32(c&0x0f)<<12 | uint32(b[i+1]&0x3f)<<6 | uint32(b[i+2]&0x3f)
			i += 3
			// CESU-8 的高位代理：尝试与紧随的低位代理拼成完整码点。
			if u >= 0xd800 && u <= 0xdbff && i+2 < len(b) && b[i]&0xf0 == 0xe0 {
				lo := uint32(b[i]&0x0f)<<12 | uint32(b[i+1]&0x3f)<<6 | uint32(b[i+2]&0x3f)
				if lo >= 0xdc00 && lo <= 0xdfff {
					out = append(out, rune(0x10000+((u-0xd800)<<10)+(lo-0xdc00)))
					i += 3
					continue
				}
			}
			out = append(out, rune(u))
		case c&0xf8 == 0xf0 && i+3 < len(b):
			out = append(out, rune(uint32(c&0x07)<<18|uint32(b[i+1]&0x3f)<<12|
				uint32(b[i+2]&0x3f)<<6|uint32(b[i+3]&0x3f)))
			i += 4
		default:
			// 非法字节：原样跳过，避免因为一个坏字符丢掉整张表。
			i++
		}
	}
	return string(out)
}
