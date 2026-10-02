package passes

import (
	"encoding/binary"
	"math/rand"
	"strings"

	"apkguard/internal/axml"
)

// ---- 垃圾条目的「质量」工具 ----
//
// 参考样本（`sample.apk`）在这方面的做法值得对齐：它的 885 个顶层垃圾 .xml
// **每一个都是 388 字节、可被解析的合法 AXML**，而不是「只有 8 字节头部」的空壳；
// 深目录用**同名单目录重复 76 层**；叶文件内容是**顺序字节**（0x20 0x21 0x22…），
// 看起来像某种格式，诱使分析工具去解析。
//
// 只放「看起来像但解析不了」的垃圾，收益很低：扫描器一次解析失败就把它整类丢弃，
// 反而更快定位到真文件。因此这里生成的是**能通过解析的真结构**。

// axmlChunk 常量（与 internal/axml 的 Type* 一致）。
const (
	chunkXML       = 0x0003
	chunkStringPol = 0x0001
	chunkStartElem = 0x0102
	chunkEndElem   = 0x0103
	chunkStartNS   = 0x0100
	chunkEndNS     = 0x0101
	xmlNodeHdr     = 16 // ResXMLTree_node 固定部分
	noIndex        = 0xffffffff
)

// realisticAXML 生成一个**合法**的二进制 AXML：字符串池 + 命名空间 + 一个元素
// （带若干属性）+ 结束元素，并补零到 target 字节。
//
// 结构与真实布局资源一致，因此它能被 aapt/androguard/jadx 正常解析——
// 这一点很重要：垃圾条目的目的是消耗分析者的时间，而不是被一眼识破。
func realisticAXML(rnd *rand.Rand, target int) []byte {
	rootName := randSeg(rnd, 3+rnd.Intn(6))
	attrNames := []string{"layout_width", "layout_height", "id", "visibility", "background", "textSize"}
	// 字符串池：下标与下面各 chunk 里硬编码的索引**必须严格对应**。
	// 约定：0=空串、1=android 前缀、2=android 命名空间 URI、3=元素名、4=类名。
	// 改这里的顺序就必须同步改 nsExt / elemExt / attr 表里的下标。
	strs := []string{
		"",        // 池首项固定为空串（与 aapt 一致）
		"android", // 命名空间前缀
		"http://schemas.android.com/apk/res/android",
		rootName,
		"TextView",
	}
	const (
		idxNSPrefix = 1
		idxNSURI    = 2
		idxElemName = 3
	)
	attrIdx := map[string]int{}
	for _, a := range attrNames {
		attrIdx[a] = len(strs)
		strs = append(strs, a)
	}
	valIdx := map[string]int{}
	vals := []string{"match_parent", "wrap_content", "true", "false", "1", "0x7f010000"}
	for _, v := range vals {
		valIdx[v] = len(strs)
		strs = append(strs, v)
	}
	pool := encodePool(strs)

	// ---- 元素：ns + name + 属性 ----
	attrList := []struct {
		name, value string
		dtype       byte
	}{
		{"layout_width", "match_parent", 0x03},
		{"layout_height", "wrap_content", 0x03},
		{"id", "0x7f010000", 0x10},
	}
	if rnd.Intn(2) == 0 {
		attrList = append(attrList, struct {
			name, value string
			dtype       byte
		}{"visibility", "true", 0x12})
	}
	elemBody := make([]byte, 0, 128)
	// ResXMLTree_attrExt: ns(4) name(4) attributeStart(2) attributeSize(2)
	//                     attributeCount(2) idIndex(2) classIndex(2) styleIndex(2)
	attrSize := uint16(20)
	ext := make([]byte, 20)
	binary.LittleEndian.PutUint32(ext[0:], idxNSURI)    // ns -> android 命名空间 URI
	binary.LittleEndian.PutUint32(ext[4:], idxElemName) // name -> rootName
	binary.LittleEndian.PutUint16(ext[8:], 20)          // attributeStart
	binary.LittleEndian.PutUint16(ext[10:], attrSize)   // attributeSize
	binary.LittleEndian.PutUint16(ext[12:], uint16(len(attrList)))
	binary.LittleEndian.PutUint16(ext[14:], 0)              // idIndex
	binary.LittleEndian.PutUint16(ext[16:], noIndex&0xffff) // classIndex
	binary.LittleEndian.PutUint16(ext[18:], noIndex&0xffff) // styleIndex
	elemBody = append(elemBody, ext...)
	for _, at := range attrList {
		attr := make([]byte, attrSize)
		binary.LittleEndian.PutUint32(attr[0:], idxNSURI) // ns -> android 命名空间 URI
		binary.LittleEndian.PutUint32(attr[4:], uint32(attrIdx[at.name]))
		binary.LittleEndian.PutUint32(attr[8:], uint32(valIdx[at.value])) // rawValue
		attr[15] = at.dtype
		if at.dtype == 0x10 {
			binary.LittleEndian.PutUint32(attr[16:], 0x7f010000)
		} else {
			binary.LittleEndian.PutUint32(attr[16:], uint32(valIdx[at.value]))
		}
		elemBody = append(elemBody, attr...)
	}

	lines := []int{1, 2, 3, 4, 5, 6}
	msgs := []uint32{noIndex, noIndex, noIndex, noIndex}
	startElem := node(chunkStartElem, lines[rnd.Intn(len(lines))], msgs, elemBody)
	// ResXMLTree_endElementExt = ns(4) + name(4)，共 8 字节
	endExt := le32(idxNSURI, idxElemName)
	endElem := node(chunkEndElem, lines[rnd.Intn(len(lines))], msgs, endExt)
	// ResXMLTree_namespaceExt = prefix(4) + uri(4)，共 8 字节
	// prefix 用字符串池里的 "android"，uri 用命名空间 URI（与真实布局一致）
	nsExt := le32(idxNSPrefix, idxNSURI)
	startNS := node(chunkStartNS, 1, msgs, nsExt)
	endNS := node(chunkEndNS, 1, msgs, nsExt)

	body := make([]byte, 0, len(pool)+512)
	body = append(body, pool...)
	body = append(body, startNS...)
	body = append(body, startElem...)
	body = append(body, endElem...)
	body = append(body, endNS...)

	out := make([]byte, 8, 8+len(body))
	binary.LittleEndian.PutUint16(out[0:], chunkXML)
	binary.LittleEndian.PutUint16(out[2:], 8)
	out = append(out, body...)
	// 补到目标大小：用零填充（与样本「头声明大、后面补零」的做法一致），
	// 解析器遇到越界会停止遍历而不是报错。
	if len(out) < target {
		out = append(out, make([]byte, target-len(out))...)
	}
	binary.LittleEndian.PutUint32(out[4:], uint32(len(out)))
	return out
}

// node 组装一个 ResXMLTree_node。
//
// 布局：ResChunk_header(8) + lineNumber(4) + comment(4) + body。
// headerSize 固定为 16（含 chunk header 与 line/comment），
// **size 必须等于本块实际占用的字节数**——算错会让解析器按错误的步长遍历，
// 直接跳过后续块（实测就是这样导致「解析成功但一个元素也没有」）。
func node(typ uint16, line int, commentIdx []uint32, body []byte) []byte {
	out := make([]byte, 0, xmlNodeHdr+len(body))
	hdr := make([]byte, 8)
	binary.LittleEndian.PutUint16(hdr[0:], typ)
	binary.LittleEndian.PutUint16(hdr[2:], xmlNodeHdr)
	binary.LittleEndian.PutUint32(hdr[4:], uint32(xmlNodeHdr+len(body)))
	out = append(out, hdr...)
	ln := make([]byte, 8)
	binary.LittleEndian.PutUint32(ln[0:], uint32(line))
	binary.LittleEndian.PutUint32(ln[4:], commentIdx[0])
	out = append(out, ln...)
	out = append(out, body...)
	return out
}

// encodePool 用 axml 的写入器生成 UTF-8 字符串池。
//
// 复用 axml 的编码器而不是自己拼：池的排序标志、长度前缀（u16len/u8len）
// 都有坑，写错会让整个文件解析失败，垃圾条目就失去意义了。
func encodePool(strs []string) []byte {
	return axml.EncodeStringPool(strs, true)
}

// sequentialBytes 生成顺序字节填充（0x20 起递增），模拟「看似某种格式」的数据。
//
// 参考样本的深目录叶文件正是这样：130 KB 的 0x20 0x21 0x22 0x23…，
// 比纯随机更耐看（随机数据一眼假，且不可压缩会显著撑大体积）。
func sequentialBytes(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(0x20 + (i % 0xd0))
	}
	return out
}

// deepAliasPath 生成「同一目录名重复 depth 层 + 随机叶文件」的路径。
//
// 样本用 76 层同名目录（assets/髕髖髈虄/…×76/骲髨虰骿）制造超长路径，
// 这类路径在解包工具里会触发路径长度/递归解析问题，而对真实文件毫无影响。
func deepAliasPath(rnd *rand.Rand, dirLen int, depth int, leaf string) string {
	seg := randSeg(rnd, dirLen)
	parts := make([]string, 0, depth+1)
	for i := 0; i < depth; i++ {
		parts = append(parts, seg)
	}
	parts = append(parts, leaf)
	return "assets/" + strings.Join(parts, "/")
}

// le32 把小端 uint32 依次打包，避免手写字节数组时下标写错。
func le32(vals ...uint32) []byte {
	out := make([]byte, 0, len(vals)*4)
	for _, v := range vals {
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], v)
		out = append(out, b[:]...)
	}
	return out
}
