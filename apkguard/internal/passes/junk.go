package passes

import (
	"encoding/binary"
	"math/rand"
	"strconv"
	"strings"

	"apkguard/internal/axml"
	"apkguard/internal/pipeline"
	"apkguard/internal/zipx"
)

// ---- 垃圾条目的「质量」工具 ----
//
// 参考样本（`sample.apk`，2418 个条目，逐条实测见 tmpwork/sample-recon/D/）的
// 垃圾条目是**成族设计**的，而不是同一手法铺量：
//
//   - 323 条共用同一份 176 字节随机载荷（CRC 0x9422BC80），分布在 7 个命名空间：
//     res/values/* 89、以 / 开头的绝对路径 84、META-INF/ 35、classes.dex/ 32、
//     resources.arsc/ 31、AndroidManifest.xml/ 28、kotlin/ 24。每份数据独立存储
//     （按偏移去重无效），但按内容哈希会聚成一大类——样本故意让分析者的去重规则
//     先命中这 323 条，从而漏掉下面几个内容各不相同的族。
//   - 884 条顶层非 ASCII 假 AXML：内容是合法 AXML（type 3 + 字符串池 + 随机填充），
//     每条的池大小/内容都不同，sha256 全不同。
//   - 837 条深目录，内容**全是空格 0x20**（80~400 字节，deflate 后 5~8 字节）：
//     看起来像正常占位/文本文件，而不是一眼假的递增字节。
//   - res/ 下 85+ 条畸形路径：把**真资源源文件名当目录名**再拼 `\`/`/` 混排与
//     随机扩展名（如 res/values/integers.xml//\///.xml）。
//   - 4 位随机 hex 后缀近重名（META-INF///.xml629c）、空格名（META-INF/ .idx）、
//     伪装成 kotlin/AGP 元数据的可信构件名（module.map.xml、package.hint 等）。
//
// 顶层垃圾 .xml **每一个都是可被解析的合法 AXML**，而不是「只有 8 字节头部」的
// 空壳。只放「看起来像但解析不了」的垃圾，收益很低：扫描器一次解析失败就把它整类
// 丢弃，反而更快定位到真文件。因此这里生成的是**能通过解析的真结构**。
//
// 样本的同类条目比「全部合法」更狠：884 条实测是**同一份 388 字节 AXML 模板 +
// 每条恰好 1 个随机差异字节**，其中约 8% 的差异字节落在字符串池头部字段
// （stringCount / flags / poolSize）的**高位**上——sha256 全不同（抗内容哈希聚类），
// 严格解析器按声明的高位长度读取时失败，而 Android 平台完全无感（条目从未被引用）。
// A10 顶层族复刻了这一手法（a10AXMLTemplate 唯一模板 + saltAXMLOneByte
// 每条 1 个盐字节 + poisonAXMLStringPool 毒化子集），并守住底线：绝不改 chunk
// type/根块 size，池 size 只增不减，毒化仅限本文件生成的顶层假 AXML；
// 其他调用方继续用行为不变的 realisticAXML。

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
	binary.LittleEndian.PutUint16(ext[14:], 0) // idIndex
	// classIndex/styleIndex 的「无」用 0（AOSP 语义，真实 aapt 产物即 0）；
	// 0xffff 会被解析器当成「第 65534 个属性」而错位。
	binary.LittleEndian.PutUint16(ext[16:], 0) // classIndex
	binary.LittleEndian.PutUint16(ext[18:], 0) // styleIndex
	elemBody = append(elemBody, ext...)
	for _, at := range attrList {
		attr := make([]byte, attrSize)
		binary.LittleEndian.PutUint32(attr[0:], idxNSURI) // ns -> android 命名空间 URI
		binary.LittleEndian.PutUint32(attr[4:], uint32(attrIdx[at.name]))
		binary.LittleEndian.PutUint32(attr[8:], uint32(valIdx[at.value])) // rawValue
		// Res_value.size 恒为 8（Res_value 结构体大小），不是整个 attribute 的 20。
		binary.LittleEndian.PutUint16(attr[12:], 8)
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

// ---- A10 顶层假 AXML 的「盐 + 毒化」变体 ----
//
// 参考样本实测：884 条顶层假 AXML 是「同一模板 + 每条 1 个随机差异字节」，
// 差异字节的位置在模板内部随机；约 8% 落在字符串池头部字段的高位上，使 sha256
// 全不同、严格解析器失败，而 Android 平台不受影响（条目从未被引用）。
//
// 这里把两类手法拆开，只给 A10 顶层族使用；realisticAXML 本身行为不变，
// 其他调用方（A16 假 Manifest、A18、测试）继续生成完全合法的 AXML：
//
//   - a10AXMLTemplate 每次运行只生成**一份**合法 AXML 模板（目标 388 字节，
//     对齐样本尺寸；实际约 500 字节），模板由 seed 派生，同 seed 可复现；
//   - saltAXMLOneByte 为复制出来的模板写入**恰好 1 个**盐字节，位置/取值由
//     seed 派生的随机源决定，并用 used 集合保证 (位置,取值) 全局唯一，
//     因此全部条目 sha256 两两不同；盐只落在池数据区的 ASCII 内容里，
//     不碰 chunk type/size/长度前缀/NUL；
//   - poisonAXMLStringPool 只对约 8% 的条目额外做池头高位加盐。

// 毒化类别：分别对应字符串池头部三个字段的高位加盐。
const (
	poisonStringCount = iota // 池头 offset 8（文件 offset 16）
	poisonFlags              // 池头 offset 16（文件 offset 24）
	poisonPoolSize           // 池块 size（池头 offset 4 / 文件 offset 12）
)

// a10PoisonedKey 是「A10 顶层毒化条目名 → 毒化类别」映射在 Artifact.Shared
// 中的键。自检/测试按名字身份跳过毒化条目，而不是靠「解析失败容忍」。
// 值类型为 map[string]int（类别取 poisonStringCount / poisonFlags / poisonPoolSize）。
// 自检接线方式：names := art.Get("a10.poisoned") 取 map 的键集合即可跳过。
const a10PoisonedKey = "a10.poisoned"

// a10Poisoned 读取 A10 记录在 Artifact.Shared 的毒化条目名集合。
func a10Poisoned(art *pipeline.Artifact) map[string]int {
	m, _ := art.Get(a10PoisonedKey).(map[string]int)
	if m == nil {
		return map[string]int{}
	}
	return m
}

// poolUTF8Span 是字符串池数据区里可安全改写的一个字节区间。
type poolUTF8Span struct{ lo, hi int }

// poolUTF8ContentSpans 找出 UTF-8 字符串池中纯 ASCII 字符串的内容字节区间。
//
// 只返回内容字节：不含 1~2 字节长度前缀与结尾 NUL（改写它们会破坏池布局），
// 并跳过 skip 中的下标（A10 跳过 android 命名空间 URI，既有测试断言它必须
// 原样保留）。解析异常时返回已找到的部分，绝不 panic。
func poolUTF8ContentSpans(data []byte, poolOff int, skip map[int]bool) []poolUTF8Span {
	const (
		poolHdr     = 28
		flagUTF8    = 1 << 8
		maxPoolStrs = 1 << 20
	)
	if poolOff < 0 || poolOff+poolHdr > len(data) {
		return nil
	}
	count := int(binary.LittleEndian.Uint32(data[poolOff+8:]))
	flags := binary.LittleEndian.Uint32(data[poolOff+16:])
	if flags&flagUTF8 == 0 || count <= 0 || count > maxPoolStrs {
		return nil
	}
	poolSize := int(binary.LittleEndian.Uint32(data[poolOff+4:]))
	stringsStart := int(binary.LittleEndian.Uint32(data[poolOff+20:]))
	if poolSize < poolHdr || stringsStart < poolHdr || poolOff+poolSize > len(data) {
		return nil
	}
	end := poolOff + poolSize
	readLen := func(p int) (uint32, int, bool) {
		if p >= end {
			return 0, p, false
		}
		if data[p]&0x80 != 0 {
			if p+1 >= end {
				return 0, p, false
			}
			return uint32(data[p]&0x7f)<<8 | uint32(data[p+1]), p + 2, true
		}
		return uint32(data[p]), p + 1, true
	}
	p := poolOff + stringsStart
	var out []poolUTF8Span
	for i := 0; i < count; i++ {
		_, p1, ok := readLen(p) // 字符数
		if !ok {
			break
		}
		blen, p2, ok := readLen(p1) // 字节数
		if !ok || p2+int(blen) > end {
			break
		}
		if blen > 0 && !skip[i] {
			body := data[p2 : p2+int(blen)]
			ascii := true
			for _, b := range body {
				if b < 0x20 || b > 0x7e {
					ascii = false
					break
				}
			}
			if ascii {
				out = append(out, poolUTF8Span{p2, p2 + int(blen)})
			}
		}
		p = p2 + int(blen) + 1 // 跳过内容与结尾 NUL
	}
	return out
}

// a10TopAXMLTarget 是 A10 顶层假 AXML 模板的目标字节数（与样本的 388 字节同量级）。
//
// 同一 seed 只生成一份模板，884 条顶层条目都是「这份模板的副本 + 1 个盐字节」，
// 与样本「同一模板 + 每条恰好 1 个随机差异字节」逐字节同构。模板本身是完整的
// 合法 AXML（池 + 命名空间 + 元素 + 属性），实际长度由内容决定（约 500 字节，
// realisticAXML 只补零、不截断），但对同一次运行的全部条目完全一致。
const a10TopAXMLTarget = 388

// a10AXMLTemplate 生成 A10 顶层族本次运行**唯一**的合法 AXML 模板。
//
// 模板由 seed 派生（独立随机源，不消费调用方的随机流），同 seed 完全可复现。
func a10AXMLTemplate(seed string) []byte {
	return realisticAXML(newRand(seed+"/a10xmltemplate"), a10TopAXMLTarget)
}

// saltAXMLOneByte 把 1 个盐字节写入模板副本的字符串池数据区。
//
// 要求与保证：
//   - 恰好改写 1 个字节：只写池数据区里纯 ASCII 字符串的内容字节，不碰
//     chunk type/size、长度前缀与结尾 NUL，因此副本仍 100% 可解析；
//   - 盐位置与取值由 r 决定，除了原字节之外的 0x21~0x7e 均可选；
//   - used 记录已用过的 (偏移,取值) 对：模板全局只有一份，因此 (偏移,取值)
//     唯一 ⇒ 任意两条副本的字节内容不同 ⇒ sha256 两两不同；
//   - 跳过池下标 2（android 命名空间 URI）：既有测试断言属性命名空间必须是它。
//
// 返回 false 仅当池里没有可写内容（理论上不会发生；调用方按未加盐处理）。
func saltAXMLOneByte(r *rand.Rand, data []byte, used map[uint64]bool) bool {
	spans := poolUTF8ContentSpans(data, 8, map[int]bool{2: true})
	total := 0
	for _, s := range spans {
		total += s.hi - s.lo
	}
	if total == 0 {
		return false
	}
	// 把 [0,total) 的扁平下标映射回模板内的绝对偏移。
	offAt := func(k int) int {
		for _, s := range spans {
			if n := s.hi - s.lo; k < n {
				return s.lo + k
			} else {
				k -= n
			}
		}
		return -1
	}
	put := func(off int, nb byte) bool {
		key := uint64(off)<<8 | uint64(nb)
		if used[key] {
			return false
		}
		used[key] = true
		data[off] = nb
		return true
	}
	for try := 0; try < 64; try++ {
		off := offAt(r.Intn(total))
		orig := data[off]
		nb := byte(0x21 + r.Intn(0x5e))
		if nb == orig { // 盐必须改变内容（「恰好差 1 字节」可断言）
			continue
		}
		if put(off, nb) {
			return true
		}
	}
	// 兜底：容量约 1.5 万个 (位置,取值) 对，正常永远走不到这里；
	// 线性扫描保证「两两不同」这一硬约束不依赖随机源的质量。
	for _, s := range spans {
		for off := s.lo; off < s.hi; off++ {
			orig := data[off]
			for c := 0; c < 0x5e; c++ {
				nb := byte(0x21 + c)
				if nb != orig && put(off, nb) {
					return true
				}
			}
		}
	}
	return false
}

// poisonAXMLStringPool 对合法 AXML 的字符串池头部做「高位加盐」毒化。
//
// 手法与参考样本一致：只改高位、保留低位，真实值仍可从低位读出。
//
//	class=poisonStringCount：count |= salt<<16（salt≥17，声明值必然超过 2^20）
//	class=poisonFlags：      flags |= salt<<8 （salt≥2，低 8 位保留且至少置一个未知高位）
//	class=poisonPoolSize：   size  += salt<<20（只增不减，低 20 位保留）
//
// 绝不触碰 chunk type 或 XML 根块的 size；池 size 只增不减，因此不会出现
// 「按原样解析即越界」的形态（虽然这些条目从未被 Android 引用）。
// 返回字段名与（原始值, 毒化值），便于测试逐条断言低位一致。
func poisonAXMLStringPool(r *rand.Rand, data []byte, class int) (string, uint32, uint32) {
	if len(data) < 28 {
		return "", 0, 0
	}
	put := func(off int, v uint32) { binary.LittleEndian.PutUint32(data[off:], v) }
	switch class % 3 {
	case poisonStringCount:
		orig := binary.LittleEndian.Uint32(data[16:])
		salt := uint32(17 + r.Intn(0xf0)) // ≥17：高位使声明 count > 2^20
		v := orig | salt<<16
		put(16, v)
		return "stringCount", orig, v
	case poisonFlags:
		orig := binary.LittleEndian.Uint32(data[24:])
		// salt≥2：salt==1 只会置 bit8（模板本就有的 UTF-8 位），OR 后字段不变
		// 就成了「假毒化」；≥2 至少置一个已知位之外的位，严格校验器必拒绝。
		salt := uint32(2 + r.Intn(0xfffe))
		v := orig | salt<<8
		put(24, v)
		return "flags", orig, v
	default:
		orig := binary.LittleEndian.Uint32(data[12:])
		salt := uint32(1 + r.Intn(0xfff))
		v := orig + salt<<20
		if v < orig { // 理论兜底：只增不减，绝不让 size 变小造成越界形态
			v = orig + 1<<20
		}
		put(12, v)
		return "poolSize", orig, v
	}
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
// 保留给 A17（假内层 APK 里的 assets 占位文件）使用。注意 A10 的深目录**不再**用
// 它：参考样本的 837 条深目录内容是清一色 0x20（见 junkSpaceFile），递增字节一眼
// 就能看出是填充物，反而是弱点。
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

// ---- 内容族工具（对齐样本的「成族设计」）----

// junkPayloadSize 是族 A「共用载荷」的字节数：样本实测 176 字节。
const junkPayloadSize = 176

// junkPayloadKey 是族 A 共用载荷在 Artifact.Shared 里的缓存键。
const junkPayloadKey = "passes.junkPayload"

// sharedJunkPayload 返回族 A 的共用载荷（176 字节随机数据）。
//
// A10 与 A12 各自调用却必须拿到**完全相同的字节**：样本 323 条共用载荷分布在
// 7 个命名空间，正是靠「同字节不同名」把分析者的内容哈希聚类引偏。这里用
// opts.Seed+"/junkpayload" 派生、并在 Artifact.Shared 里缓存，保证两处一致，
// 且同 seed 可复现。
func sharedJunkPayload(art *pipeline.Artifact, seed string) []byte {
	if v, ok := art.Get(junkPayloadKey).([]byte); ok && len(v) == junkPayloadSize {
		return v
	}
	r := newRand(seed + "/junkpayload")
	out := make([]byte, junkPayloadSize)
	for i := range out {
		out[i] = byte(r.Intn(256))
	}
	art.Put(junkPayloadKey, out)
	return out
}

// newJunkEntry 构造一个 Deflate 存储的垃圾条目。
//
// 样本的 2418 个条目里 2258 个是 Deflate（method 8）：323 条共用载荷 176B→181B，
// 837 条空格深目录 ~250B→6B。垃圾条目也用 Deflate，与样本的存储方式一致，且
// 空格文件与假 AXML 的体积开销降到最低（用 Stored 会白白多出几百 KB）。
func newJunkEntry(name string, data []byte) *zipx.Entry {
	e := zipx.NewStored(name, data)
	if err := e.SetData(data, true); err != nil {
		// flate 写 bytes.Buffer 不存在 I/O 错误，这里只是保守兜底：
		// 退回未压缩存储也不影响垃圾条目的功能。
		return zipx.NewStored(name, data)
	}
	return e
}

// junkSpaceFile 生成族 B 的「空格文件」：80~400 个 0x20。
//
// 样本的 837 条深目录条目全部是空格（deflate 后仅 5~8 字节）：看起来像正常的
// 占位/文本文件；早先用递增字节（0x20 0x21 …）一眼就能认出是填充物。
func junkSpaceFile(r *rand.Rand) []byte {
	n := 80 + r.Intn(321)
	out := make([]byte, n)
	for i := range out {
		out[i] = 0x20
	}
	return out
}

// junkPathPrefixes 是 A12「关键文件当目录」的前缀表。
//
// 与样本分布对应：classes.dex/ 32 条、resources.arsc/ 31 条、
// AndroidManifest.xml/ 28 条。
var junkPathPrefixes = []string{
	"classes.dex/", "AndroidManifest.xml/", "resources.arsc/",
	"classes2.dex/", "lib/",
}

// junkResSourceNames 是 aapt2 常见的 res/values 源文件名（样本拿其中 8 个
// 当目录名用，例如 res/values/integers.xml//\///.xml）。
var junkResSourceNames = [...]string{
	"values.xml", "integers.xml", "plurals.xml", "menus.xml", "anims.xml",
	"interpolators.xml", "transitions.xml", "public.xml", "strings.xml",
	"colors.xml", "dimens.xml", "attrs.xml", "styles.xml", "arrays.xml",
	"bools.xml", "ids.xml",
}

// junkResPathName 生成族 C 的路径：把真资源源文件名当目录名，再拼 `\`/`/`
// 混排的畸形子路径与随机扩展名（.xml/.png/.9.png）。
//
// 三种形态分别对应样本的：
//
//	res/values/integers.xml//\///.xml
//	res/values/anims.xml////\.png
//	res/values/menus.xml//xml
func junkResPathName(r *rand.Rand, i int) string {
	base := "res/values/" + junkResSourceNames[i%len(junkResSourceNames)]
	exts := [...]string{"xml", "png", "9.png"}
	ext := exts[r.Intn(len(exts))]
	switch (i / len(junkResSourceNames)) % 3 {
	case 0:
		return base + `//\///.` + ext
	case 1:
		return base + `////\.` + ext
	default:
		// 样本里还有「真资源路径直接当文件」的干净形态（res/values/menus.xml），
		// 但干净路径会被 A11 的「res/ 下不得残留语义目录名」断言当成**本应用
		// 的真实资源**而误报（见 scripts/verify-products.py 的 A11 段）。这里保留
		// 真名当前缀、尾部仍用 `//` 混排：与样本同族，又不与 A11 自相矛盾。
		return base + `//` + ext
	}
}

// junkKotlinName 生成族 D 的 kotlin/ 伪装名：kotlin/<词>/<词>.<xml|bin|png>。
//
// 样本在 kotlin/ 下有 31 条，其中 24 条是 176 字节共用载荷的假货，名字伪装成
// Kotlin 内置元数据/资源。分析者常按目录白名单（kotlin/、lib/）整目录跳过。
func junkKotlinName(r *rand.Rand, i int) string {
	exts := [...]string{"xml", "bin", "png"}
	ext := exts[i%len(exts)]
	return "kotlin/" + randSeg(r, 4+r.Intn(5)) + "/" + randSeg(r, 4+r.Intn(5)) + "." + ext
}

// junkHexSuffixBases 是 4 位 hex 近重名族的基础名。
//
// 样本用 4 位随机 hex 给同一基础名去重：META-INF///.xml629c 等，CD 里精确名字
// 互不相同，但按「去掉 hex 后缀」看是一组近重名。
var junkHexSuffixBases = [...]string{
	"META-INF///.xml", "META-INF//.png", "META-INF///.9.png", "META-INF/.blob",
}

// junkSpaceNames 是空格名条目（样本：META-INF/ .idx、META-INF/  .idx。
// ZIP 条目名允许空格，许多工具会 trim 后当成 META-INF/.idx）。
var junkSpaceNames = [...]string{
	"META-INF/ .idx", "META-INF/  .idx",
}

// junkTrustedNames 是伪装成可信构件/构建元数据的名字（kotlin、desugar、AGP
// 都会往 META-INF 写这类文件），样本里以 4hex 变体或原名的形式大量出现。
var junkTrustedNames = [...]string{
	"META-INF/module.map.xml",
	"META-INF/package.hint",
	"META-INF/package.hint.xml",
	"META-INF/table.blob.xml",
	"META-INF/.idx",
}

// hex4 生成 4 位小写十六进制串（样本的近重名后缀形态）。
func hex4(r *rand.Rand) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 4)
	for i := range out {
		out[i] = digits[r.Intn(len(digits))]
	}
	return string(out)
}

// ---- 注入路径的冲突保护 ----

// normZipPath 归一化 ZIP 条目名：把 `\` 也视为分隔符（样本刻意混用两种分隔符），
// 折叠空段并消解 `.`/`..`。用于判断注入名在解包工具规范化后是否会撞上真实条目。
func normZipPath(name string) string {
	segs := make([]string, 0, 8)
	for _, s := range strings.FieldsFunc(name, func(r rune) bool { return r == '/' || r == '\\' }) {
		switch s {
		case "", ".":
			continue
		case "..":
			if len(segs) > 0 {
				segs = segs[:len(segs)-1]
			}
		default:
			segs = append(segs, s)
		}
	}
	return strings.Join(segs, "/")
}

// normalizedPathIndex 收集现有条目的归一化路径集合。
func normalizedPathIndex(art *pipeline.Artifact) map[string]bool {
	idx := make(map[string]bool, len(art.Entries()))
	for _, e := range art.Entries() {
		if n := normZipPath(e.NameString()); n != "" {
			idx[n] = true
		}
	}
	return idx
}

// coreCollision 判断注入名是否会（在归一化后）撞上真实核心文件或既有条目。
//
// 这是 manifestCollision 的补充：manifestCollision 只管 v1 签名相关的
// MANIFEST.MF / *.SF / *.RSA 等（撞上会让应用启动即崩），这里再挡住
// AndroidManifest.xml、classes*.dex、resources.arsc 以及任何既有条目路径
// （含 `\` 分隔符与 . / .. 归一化后的形态）。样本自己也从不注入精确同名条目。
func coreCollision(name string, idx map[string]bool) bool {
	norm := normZipPath(name)
	if norm == "" {
		return true
	}
	if idx[norm] {
		return true
	}
	upper := strings.ToUpper(norm)
	if upper == "ANDROIDMANIFEST.XML" || upper == "RESOURCES.ARSC" {
		return true
	}
	// classes.dex / classes2.dex / classes10.dex …（Android 的精确名匹配）
	if strings.HasPrefix(upper, "CLASSES") && strings.HasSuffix(upper, ".DEX") {
		mid := upper[len("CLASSES") : len(upper)-len(".DEX")]
		if mid == "" {
			return true
		}
		if _, err := strconv.Atoi(mid); err == nil {
			return true
		}
	}
	return false
}

// safeJunkPath 是新增名字族的硬约束：非空、不以分隔符结尾（不生成目录条目）、
// 不含 `.` / `..` 段。A10 的旧畸形 META-INF 名单里仍有 `./`、`../` 形态
// （既有测试钉住，保留），但尾部 `/` 的两个目录形态已改为等价非目录路径
// （META-INF、META-INF/sub）；从这道约束起，任何新族都不再产生尾部斜杠。
func safeJunkPath(name string) bool {
	if name == "" || strings.HasSuffix(name, "/") || strings.HasSuffix(name, "\\") {
		return false
	}
	for _, seg := range strings.FieldsFunc(name, func(r rune) bool { return r == '/' || r == '\\' }) {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// ---- A14 三段时间戳的分组提示 ----

// 三组时间戳常量。样本的三次注入阶段落在 22:01:08 / 22:01:40 / 22:01:52，
// 即基准、+32s、+44s。
const (
	// stampGroupBase 是原始条目（非注入）的基准时间戳；签名三件套也用基准时间。
	stampGroupBase = iota
	// stampGroupInjected 是路径/名称攻击族（A12 路径攻击、A10 畸形 META-INF、
	// 4hex 近重名、空格名、伪装构件名、res/values 畸形变体）的 +32s。
	stampGroupInjected
	// stampGroupDecoy 是内容型诱饵族（顶层非 ASCII 假 AXML、深目录空格文件、
	// kotlin/ 伪装、假核心文件）的 +44s。
	stampGroupDecoy
)

// stampHintsKey 是 A10/A12 写入 Artifact.Shared 的「条目名 → 时间戳组」映射键。
const stampHintsKey = "passes.stampHints"

// stampHint 记录某条目在 A14 三段时间戳里应属的组。
//
// 分组不能靠 A14 事后猜：由注入它的 Pass 在注入时记录，同 seed 完全可复现。
func stampHint(art *pipeline.Artifact, name string, group int) {
	m, _ := art.Get(stampHintsKey).(map[string]int)
	if m == nil {
		m = map[string]int{}
		art.Put(stampHintsKey, m)
	}
	m[name] = group
}

// stampGroupOf 返回条目在 A14 三段时间戳中的组号。
//
// 优先用 A10/A12 记录的提示；没有提示时按名字特征兜底识别（A9 伪 DEX、A16
// 假核心文件等本 Pass 之外的注入），其余一律基准组。
func stampGroupOf(hints map[string]int, name string) int {
	if hints != nil {
		if g, ok := hints[name]; ok && g >= stampGroupBase && g <= stampGroupDecoy {
			return g
		}
	}
	return inferredStampGroup(name)
}

// inferredStampGroup 按名字特征推断三段时间戳的组号（兜底路径）。
func inferredStampGroup(name string) int {
	// +44s：内容型诱饵。
	if looksLikeFakeCore(name) {
		return stampGroupDecoy
	}
	if strings.HasPrefix(name, "kotlin/") {
		return stampGroupDecoy
	}
	if strings.HasSuffix(name, ".tmp") && strings.Contains(name, "/") {
		return stampGroupDecoy
	}
	if !strings.Contains(name, "/") && !isASCII(name) {
		return stampGroupDecoy
	}
	// 同名深目录（assets/<seg>/…/<seg>，76 层量级）。
	if strings.HasPrefix(name, "assets/") && strings.Count(name, "/") >= 30 {
		return stampGroupDecoy
	}
	// +32s：路径/名字攻击。
	if strings.HasPrefix(name, "/") {
		return stampGroupInjected
	}
	if strings.HasPrefix(name, "res/values/") {
		return stampGroupInjected
	}
	for _, p := range junkPathPrefixes {
		if p == "lib/" {
			// 原始应用的 lib/** 条目也会命中该前缀；没有注入提示时不能据此判定
			// 为注入条目（A12 注入的 lib/… 有提示，不走这条兜底）。
			continue
		}
		if strings.HasPrefix(name, p) {
			return stampGroupInjected
		}
	}
	return stampGroupBase
}

// looksLikeFakeCore 判断名字是否是「真核心文件的大小写/序号变体」（A9/A16 注入）。
//
// 精确同名（AndroidManifest.xml / resources.arsc / classes.dex）返回 false：
// 那是真文件，不在诱饵组。
func looksLikeFakeCore(name string) bool {
	reals := [...]string{"AndroidManifest.xml", "resources.arsc", "classes.dex"}
	for _, real := range reals {
		if name == real {
			return false
		}
	}
	for _, real := range reals {
		if strings.EqualFold(name, real) {
			return true
		}
		base := name
		if i := strings.LastIndexByte(base, '.'); i > 0 {
			if _, err := strconv.Atoi(base[i+1:]); err == nil {
				base = base[:i]
			}
		}
		if strings.EqualFold(base, real) {
			return true
		}
	}
	return false
}

// isASCII 判断字符串是否为纯 ASCII。
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return false
		}
	}
	return true
}
