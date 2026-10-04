package passes

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"

	"apkguard/internal/config"
	"apkguard/internal/pipeline"
)

// ---- A15 巨型 Manifest 填充 ----
//
// 手法来自参考样本（`sample.apk`）：它的 AndroidManifest.xml **未压缩体积
// 369,623,060 字节**，压缩后仅约 367 KB（压缩比约 0.001），而体积的大头
// **不是零，而是一条藏在合法字符串池里的巨串**。实测 chunk 结构：
//
//	偏移           type      size          内容
//	0              0x0003    369,623,060   顶层 RES_XML
//	8              0xB4A7    1,572,872     载荷 1,572,864 字节全 0
//	1,572,880      0x0001    315,611,976   合法字符串池：stringCount=168、styleCount=0、
//	                                        flags=0（UTF-16）、stringsStart=700；
//	                                        第 167 条（最后一条）是**长 157,800,394 个
//	                                        'K' 的合法长串**（4 字节长串前缀 67 89 CA D7，
//	                                        即 0x8000|0x0967 后跟 0xCAD7），
//	                                        数据 4B 00 × 157,800,394 + NUL + 2 字节对齐，
//	                                        结束位置正好等于池声明末尾 317,184,856
//	317,184,856    0x9D1E    52,428,800    载荷 52,428,792 字节全 0（与第一个假 chunk 类型不同）
//	369,613,656    0x0180    136           RES_XML_RESOURCE_MAP（真实内容开始）
//	369,613,792    0x0100…   —             178 个真实子 chunk 共 9,404 字节，直到 EOF
//
// 即 **85.4% 的体积是池内那一条合法巨串（157,800,394 字符 × 2 字节 ≈ 315.6 MB），
// 零填充只占 14.6%**（两段未知类型的 chunk）。按 chunk 头遍历的解析器
// （AOSP ResXMLTree / aapt2 / androguard）都能正常读到真实 Manifest：字符串池
// 是合法类型，只是池里多了一条永不被引用的巨串；未知类型走 default 按声明长度跳过。
//
// 为什么这样更抗剥离：分析者可以按「未知类型」删掉两个零填充 chunk，但巨串在
// **合法字符串池内部**——池声明长度把巨串算在内，真实内容的位置由它决定，
// 删掉未知 chunk 并不能让文件回到原体积；想真正瘦身必须完整重写字符串池。
// 反之，纯零填充（本工具之前的做法）类型是写死的 0xb4a7（固定指纹），
// 一旦被识别，一次删除就回到原体积。
//
// 我们采用同构布局（T1/T2 每个产物随机，不再是固定指纹）：
//
//	[RES_XML 头, size = 整个新文件]
//	[假 chunk #1: type = T1, headerSize=8, size=8+n1, 载荷 n1 字节全 0（≈8% pad）]
//	[真实字符串池 chunk: 声明 size 放大，末尾追加巨串承担 ≈80% pad]
//	[假 chunk #2: type = T2（T1 != T2）, headerSize=8, size=8+n2, 载荷 n2 字节全 0（≈12% pad）]
//	[真实剩余子 chunk 序列：RES_XML_RESOURCE_MAP + 命名空间 + 元素]
//
// 巨串永不被任何节点引用；字符串池的 offset 表、stringsStart、stylesStart 与
// 声明 size 全部自洽（见 appendPoolFill）。
type manifestPad struct{}

func (manifestPad) ID() config.FeatureID { return "A15" }
func (manifestPad) In() pipeline.Level   { return pipeline.LevelZip }
func (manifestPad) Out() pipeline.Level  { return pipeline.LevelZip }

// manifestName 是 Manifest 在归档中的固定条目名。
const manifestName = "AndroidManifest.xml"

// chunkHeaderLen 是 ResChunk_header 的固定长度。
const chunkHeaderLen = 8

// xmlChunkType 是顶层 RES_XML chunk 类型。
const xmlChunkType = 0x0003

// poolChunkType / poolHeaderLen 是字符串池 chunk 的类型与固定头长。
const (
	poolChunkType = 0x0001
	poolHeaderLen = 28
)

// knownAXMLChunkTypes 是 AOSP 的已知 chunk 类型集合。
//
// 填充 chunk 绝不能撞上其中任何一个：合法类型会让解析器真的去解析几十 MB 的
// 零载荷（而不是按长度跳过），轻则拖慢、重则报错退出。
var knownAXMLChunkTypes = map[uint16]bool{
	0x0000: true, // RES_NULL_TYPE
	0x0001: true, // RES_STRING_POOL_TYPE
	0x0002: true, // RES_TABLE_TYPE
	0x0003: true, // RES_XML_TYPE
	0x0100: true, // RES_XML_START_NAMESPACE_TYPE
	0x0101: true, // RES_XML_END_NAMESPACE_TYPE
	0x0102: true, // RES_XML_START_ELEMENT_TYPE
	0x0103: true, // RES_XML_END_ELEMENT_TYPE
	0x0104: true, // RES_XML_CDATA_TYPE
	0x0180: true, // RES_XML_RESOURCE_MAP_TYPE
	0x0200: true, // RES_TABLE_PACKAGE_TYPE
	0x0201: true, // RES_TABLE_TYPE_TYPE
	0x0202: true, // RES_TABLE_TYPE_SPEC_TYPE
	0x0203: true, // RES_TABLE_LIBRARY_TYPE
}

// randomPadChunkType 从随机源取一个「不属于已知 AXML 类型」的 uint16。
//
// 同 seed 可复现；空 seed 时随机源以时间为种（见 newRand），因此每次打包
// 的指纹都不同，不会像固定的 0xb4a7 一样成为识别标记。
func randomPadChunkType(rnd *rand.Rand) uint16 {
	for {
		t := uint16(rnd.Uint32())
		if !knownAXMLChunkTypes[t] {
			return t
		}
	}
}

func (m *manifestPad) Run(_ context.Context, art *pipeline.Artifact, opts *config.Options) error {
	mb := opts.ManifestPadMB
	if mb <= 0 {
		// 未指定尺寸时给一个保守默认值：100 MB。
		// 太小起不到作用，太大让产物解压/安装明显变慢。
		mb = defaultManifestPadMB
	}
	pad := mb << 20

	e := pipeline.Find(art, manifestName)
	if e == nil {
		return fmt.Errorf("未找到 %s", manifestName)
	}
	data, err := e.Data()
	if err != nil {
		return fmt.Errorf("读取 %s 失败: %w", manifestName, err)
	}
	rnd := newRand(opts.Seed + "/manifestpad")
	out, err := padManifest(data, pad, rnd)
	if err != nil {
		return err
	}
	// 必须**压缩**存放（deflate），而不是 STORED。
	//
	// 实测参考样本 sample.apk：它的 AndroidManifest.xml 解压后 369,623,060 字节，
	// 压缩后仅 367,318 字节（压缩比约 0.001），中央目录里的压缩方式字段是 8
	// （deflate）——证明 **Android 系统完全接受压缩存储的 AndroidManifest.xml**。
	// 压缩因此是纯收益：解压后仍是同样的巨型体积（读取/预分配压力不变），
	// 包体却省约三个数量级。巨串是同一个 ASCII 字符的重复，零填充本身就是零，
	// deflate 都能把它们压到极小。
	if err := e.SetData(out, true); err != nil {
		return fmt.Errorf("写回 %s 失败: %w", manifestName, err)
	}

	// 概要信息：说明两个假 chunk 的类型/载荷与放大后的池，
	// 便于在审计日志里确认产物确实用了「巨串 + 双随机 chunk」布局。
	t1, n1, poolCount, poolSize, t2, n2, ok := manifestPadSummary(out)
	if ok {
		zeroShare := 100 * float64(n1+n2) / float64(len(out)-len(data))
		art.Note("A15 巨型 Manifest 填充：%s 由 %d 字节膨胀到 %d 字节；假 chunk #1 type=0x%04x "+
			"载荷 %d 字节、假 chunk #2 type=0x%04x 载荷 %d 字节（零填充仅占 %.1f%%），"+
			"其余体积是字符串池内 %d 条字符串（池声明 %d 字节）中的巨串；"+
			"真实内容（RESOURCE_MAP + 节点）位于文件末尾，按 chunk 遍历的解析器仍能读到",
			manifestName, len(data), len(out), t1, n1, t2, n2, zeroShare, poolCount, poolSize)
		art.Stat("A15.chunk1", fmt.Sprintf("type=0x%04x payload=%d", t1, n1))
		art.Stat("A15.chunk2", fmt.Sprintf("type=0x%04x payload=%d", t2, n2))
		art.Stat("A15.pool", fmt.Sprintf("size=%d strings=%d", poolSize, poolCount))
	} else {
		art.Note("A15 巨型 Manifest 填充：%s 由 %d 字节膨胀到 %d 字节（真实内容位于文件末尾，"+
			"按 chunk 遍历的解析器仍能读到）", manifestName, len(data), len(out))
	}
	art.Stat("A15.before", fmt.Sprint(len(data)))
	art.Stat("A15.after", fmt.Sprint(len(out)))
	art.Stat("A15.pad", fmt.Sprint(pad))
	return nil
}

// defaultManifestPadMB 是未显式指定尺寸时使用的填充量（MB）。
const defaultManifestPadMB = 100

// maxPadU32 是 uint32 能表达的最大长度（各 chunk 头里的 size 字段是 uint32）。
const maxPadU32 = int64(1)<<32 - 1

// manifestPadOverflows 判断填充后的长度是否会越过 uint32 表达上限。
//
// 单独抽出成纯函数，便于在不分配几 GB 内存的前提下直接测试边界分支。
// total 是填充后整个文件的长度，pad 是填充字节数；这里仍按最保守的
// 「任何单个 chunk 不超过 8+pad」判定，再叠加整文件长度上限。
func manifestPadOverflows(pad, total int64) bool {
	return pad+8 > maxPadU32 || total > maxPadU32
}

// padTo4 返回把 x（非负）对齐到 4 的倍数所需的补零字节数（0..3）。
func padTo4(x int) int { return (4 - x%4) % 4 }

// writePadChunk 在 b 上写一个 headerSize=8 的假 chunk 头；载荷由调用方保证为 0。
func writePadChunk(b []byte, typ uint16, payload int) {
	binary.LittleEndian.PutUint16(b[0:], typ)
	binary.LittleEndian.PutUint16(b[2:], chunkHeaderLen)
	binary.LittleEndian.PutUint32(b[4:], uint32(chunkHeaderLen+payload))
}

// padManifest 生成 A15 的「巨串藏在合法字符串池里」布局，并更新顶层 size。
//
// 输入必须是**完整的 AXML**（顶层 XML chunk + 字符串池在前的子 chunk 序列）。
// 输出结构见文件头注释。pad 是填充字节数；n1、n2 与追加进池的字节数之和
// 恰好等于 pad（对齐产生的零头并入 n2），因此新文件长度恒为
// len(data)+16+pad，可由 manifestPadOverflows 在分配前完成校验。
func padManifest(data []byte, pad int, rnd *rand.Rand) ([]byte, error) {
	if len(data) < chunkHeaderLen {
		return nil, fmt.Errorf("A15：%s 过短（%d 字节）", manifestName, len(data))
	}
	typ := binary.LittleEndian.Uint16(data[0:])
	hs := int(binary.LittleEndian.Uint16(data[2:]))
	size := int(binary.LittleEndian.Uint32(data[4:]))
	if typ != xmlChunkType {
		return nil, fmt.Errorf("A15：%s 顶层不是 XML chunk（type=0x%04x）", manifestName, typ)
	}
	if hs < chunkHeaderLen || hs > len(data) {
		return nil, fmt.Errorf("A15：%s 的 headerSize 非法（%d）", manifestName, hs)
	}
	if size < hs || size > len(data) {
		// 声明长度超过实际长度：解析器会停止遍历。这种情况下填充会让
		// 真实内容彻底读不到，因此直接拒绝而不是产出一个装不上的包。
		return nil, fmt.Errorf("A15：%s 的声明长度 %d 非法（实际长度 %d），拒绝填充",
			manifestName, size, len(data))
	}
	if pad <= 0 {
		// 没有填充量：原样返回（拷贝一份，避免调用方持有别名）。
		return append([]byte(nil), data...), nil
	}

	real := data[hs:size]
	// 巨串必须挂在**真实字符串池**上：先解析第一个子 chunk，确认类型。
	if len(real) < poolHeaderLen {
		return nil, fmt.Errorf("A15：%s 的子 chunk 区只有 %d 字节，放不下字符串池，拒绝生成巨串填充",
			manifestName, len(real))
	}
	if t := binary.LittleEndian.Uint16(real[0:]); t != poolChunkType {
		return nil, fmt.Errorf("A15：%s 的第一个子 chunk 类型为 0x%04x，不是字符串池（0x0001），"+
			"拒绝生成巨串填充", manifestName, t)
	}
	poolSize := int(binary.LittleEndian.Uint32(real[4:]))
	if poolSize < poolHeaderLen || poolSize > len(real) {
		return nil, fmt.Errorf("A15：%s 字符串池声明长度 %d 非法（子 chunk 区 %d 字节）",
			manifestName, poolSize, len(real))
	}
	pool := real[:poolSize]
	rest := real[poolSize:] // RESOURCE_MAP + 命名空间 + 元素，原样保留
	trailing := data[size:] // 声明长度之外的字节，原样保留

	// 新文件长度 = 原长度 + 两个 8 字节 chunk 头 + pad，与追加条数无关
	// （n1+n2+池增长恒等于 pad）。在分配任何大内存之前先做 uint32 上限校验，
	// 否则 4096MB 这类配置会在拒绝之前先试图分配几 GB。
	total := int64(len(data)) + 2*chunkHeaderLen + int64(pad)
	if manifestPadOverflows(int64(pad), total) {
		return nil, fmt.Errorf(
			"A15：%s 填充后长度 total=%d 或填充量=%d 超过 uint32 上限（%d），"+
				"声明长度会被截断成错误的包头，拒绝生成",
			manifestName, total, int64(pad)+8, maxPadU32)
	}

	// 三段预算：假 chunk #1 ≈8%、假 chunk #2 ≈12%、字符串池内巨串 ≈80%。
	// 向下对齐到 4 字节，保证两个假 chunk 的边界仍是对齐的（AOSP chunk 习惯）。
	n1 := (pad * 8 / 100) &^ 3
	n2 := (pad * 12 / 100) &^ 3
	poolBudget := pad - n1 - n2
	if poolBudget < 0 {
		// 纯防御：上面的比例不可能让两者之和超过 pad。
		n1, n2, poolBudget = 0, pad, 0
	}

	t1 := randomPadChunkType(rnd)
	t2 := randomPadChunkType(rnd)
	for t2 == t1 {
		t2 = randomPadChunkType(rnd)
	}

	ap, err := appendPoolFill(pool, poolBudget, rnd)
	if err != nil {
		return nil, err
	}
	growth := len(ap.newPool) - len(pool)
	if growth == 0 {
		// 池里放不下哪怕一条合法字符串（pad 极小）：余量全部转给假 chunk #2，
		// 仍然绝不产出非法池。
		n2 += poolBudget
	} else {
		// 池没吃完的零头（长度字段/对齐的边角）也转给假 chunk #2，
		// 使 n1+n2+growth == pad 精确成立。
		n2 += poolBudget - growth
	}

	out := make([]byte, int(total))
	copy(out[:hs], data[:hs])
	binary.LittleEndian.PutUint32(out[4:], uint32(total))

	off := hs
	writePadChunk(out[off:off+chunkHeaderLen+n1], t1, n1) // 载荷全 0（make 已置零）
	off += chunkHeaderLen + n1
	copy(out[off:], ap.newPool) // 放大后的真实字符串池
	off += len(ap.newPool)
	writePadChunk(out[off:off+chunkHeaderLen+n2], t2, n2)
	off += chunkHeaderLen + n2
	copy(out[off:], rest)
	off += len(rest)
	copy(out[off:], trailing)
	return out, nil
}

// giantCharChoices 是巨串字符的候选集（可打印 ASCII）。
//
// 必须是可打印 ASCII：UTF-16 池里每个字符编码为「低字节 + 0x00」，只要字符
// 本身不是 U+0000，就不会出现提前终止字符串的 0x0000 码元；ASCII 也保证
// UTF-8 池里「字符数 == 字节数」，两个长度字段可以复用同一个值。
var giantCharChoices = []byte{'K', '0', 'A', 'x', '7', 'Q', 'm', 'Z'}

// 字符串池的两个硬上限：
//   - 单个 UTF-8 字符串长度字段只有 15 位（AOSP decodeLength8 只读两字节），
//     一条串最多 0x7fff 字节；
//   - axml.Parse 对 stringCount 的合理性上限是 1<<20（与 AOSP 的防护同量级）。
const (
	maxUTF8StrBytes    = 0x7fff
	maxUTF16StrUnits   = 0x7fffffff
	maxPoolStringCount = 1 << 20
)

// poolAdd 是一条待追加进字符串池的字符串。
type poolAdd struct {
	offset uint32 // 相对**新池**起点的数据偏移
	data   []byte // 完整编码：长度前缀（+ 字符数/字节数）+ 数据 + NUL + 对齐补零
}

// poolAppend 是向字符串池追加内容的结果。
type poolAppend struct {
	newPool  []byte // 放大后的池 chunk；未追加时就是原池
	count    int    // 追加的字符串条数
	strBytes int    // 追加的字符串数据字节数（不含新增 offset 表项）
}

// appendPoolFill 尝试让字符串池的声明体积增长不超过 budget 字节。
//
// 布局约定（AOSP ResStringPool）：header(28) + stringCount×4 + styleCount×4，
// 之后才是 stringsStart 指向的字符串数据区。因此新增的 offset 表项必须插在
// **旧字符串 offset 数组之后**，其后的 style offset 数组、字符串数据区、
// style 数据区整体后移；相应地 stringsStart/stylesStart 与池声明 size 一起更新，
// 旧 offset 值（相对各自区域起点）不受平移影响。
//
// 追加的字符串永不与既有索引冲突（排在末尾），也永不会被节点引用；
// UTF-16 池追加一条巨串（长度 ≥ 0x8000 时用 4 字节长格式前缀）；
// UTF-8 池因单串长度字段只有 15 位，改为追加多条 ≤0x7fff 字节的串，
// 条数由 budget 决定。budget 放不下任何一条合法字符串时原样返回（count=0）。
func appendPoolFill(pool []byte, budget int, rnd *rand.Rand) (poolAppend, error) {
	if len(pool) < poolHeaderLen {
		return poolAppend{newPool: pool}, fmt.Errorf("A15：字符串池头部只有 %d 字节，不足 %d",
			len(pool), poolHeaderLen)
	}
	if t := binary.LittleEndian.Uint16(pool[0:]); t != poolChunkType {
		return poolAppend{newPool: pool}, fmt.Errorf("A15：字符串池类型为 0x%04x，期望 0x0001", t)
	}
	if h := int(binary.LittleEndian.Uint16(pool[2:])); h != poolHeaderLen {
		return poolAppend{newPool: pool}, fmt.Errorf("A15：字符串池 headerSize=%d，期望 %d",
			h, poolHeaderLen)
	}
	if sz := int(binary.LittleEndian.Uint32(pool[4:])); sz != len(pool) {
		return poolAppend{newPool: pool}, fmt.Errorf("A15：字符串池声明 size=%d 与实际 %d 不符",
			sz, len(pool))
	}

	count := int(binary.LittleEndian.Uint32(pool[8:]))
	styleCount := int(binary.LittleEndian.Uint32(pool[12:]))
	flags := binary.LittleEndian.Uint32(pool[16:])
	stringsStart := int(binary.LittleEndian.Uint32(pool[20:]))
	stylesStart := int(binary.LittleEndian.Uint32(pool[24:]))

	if count > maxPoolStringCount || styleCount < 0 || styleCount > count {
		return poolAppend{newPool: pool}, fmt.Errorf(
			"A15：字符串池数量异常（strings=%d styles=%d）", count, styleCount)
	}
	arrEnd := poolHeaderLen + 4*count + 4*styleCount
	if arrEnd > len(pool) || stringsStart < arrEnd || stringsStart > len(pool) {
		return poolAppend{newPool: pool}, fmt.Errorf(
			"A15：字符串池偏移表/stringsStart 非法（strings=%d styles=%d stringsStart=%d size=%d）",
			count, styleCount, stringsStart, len(pool))
	}
	// 字符串数据区的结束位置：有 style 时是 stylesStart，否则到池末尾。
	dataEnd := len(pool)
	if styleCount > 0 {
		if stylesStart < stringsStart || stylesStart > len(pool) {
			return poolAppend{newPool: pool}, fmt.Errorf("A15：stylesStart=%d 非法", stylesStart)
		}
		dataEnd = stylesStart
	}
	oldStrLen := dataEnd - stringsStart
	if oldStrLen < 0 {
		return poolAppend{newPool: pool}, fmt.Errorf("A15：字符串数据区长度非法（%d）", oldStrLen)
	}

	ch := giantCharChoices[rnd.Intn(len(giantCharChoices))]
	utf8Pool := flags&utf8PoolFlag != 0
	if !utf8Pool {
		return appendPoolUTF16(pool, budget, count, styleCount, stringsStart, stylesStart, oldStrLen, ch)
	}
	return appendPoolUTF8(pool, budget, count, styleCount, stringsStart, stylesStart, oldStrLen, ch)
}

// utf8PoolFlag 是 ResStringPool flags 的 UTF-8 位（置位 = UTF-8，否则 UTF-16）。
const utf8PoolFlag = 1 << 8

// appendPoolUTF16 向 UTF-16 池追加一条巨串（可占满 budget）。
func appendPoolUTF16(pool []byte, budget, count, styleCount, stringsStart, stylesStart, oldStrLen int, ch byte) (poolAppend, error) {
	// 预留：新 offset 表项 4 + 长格式长度前缀 4 + 结尾 NUL 2 + 对齐补零最多 3。
	units := (budget - 4 - 4 - 2) / 2
	if units > maxUTF16StrUnits {
		units = maxUTF16StrUnits
	}
	if units <= 0 {
		return poolAppend{newPool: pool}, nil
	}
	base := stringsStart + 4 + oldStrLen // 巨串在新池中的物理偏移（相对池起点，用于对齐）
	for units > 0 && 4+utf16EncodedLen(units, base) > budget {
		units--
	}
	if units <= 0 {
		return poolAppend{newPool: pool}, nil
	}
	data := encodeGiantUTF16(units, ch, base)
	// offset 表里的值相对 stringsStart（新池的 stringsStart = 旧值 + 4），
	// 因此物理偏移 base 要减去 newStringsStart 才是表项值。
	rel := base - (stringsStart + 4)
	adds := []poolAdd{{offset: uint32(rel), data: data}}
	out := assembleGrownPool(pool, count, styleCount, stringsStart, stylesStart, adds)
	return poolAppend{newPool: out, count: 1, strBytes: len(data)}, nil
}

// appendPoolUTF8 向 UTF-8 池追加多条串，每条 ≤maxUTF8StrBytes 字节。
//
// AOSP 的 UTF-8 长度字段是「单/双字节」，15 位上限 0x7fff，一条串装不下
// 80% 的填充量，因此按 budget 贪心追加多条最大串；全部为同一 ASCII 字符，
// 压缩特性与单条巨串一致。
func appendPoolUTF8(pool []byte, budget, count, styleCount, stringsStart, stylesStart, oldStrLen int, ch byte) (poolAppend, error) {
	base := stringsStart + 4 + oldStrLen // 第一条新串在新池中的数据偏移
	var lens []int
	start, used := base, 0
	for {
		remain := budget - used
		// 预留：offset 4 + 两个长度字段最多 4 + NUL 1 + 对齐最多 3。
		maxLen := remain - 4 - 4 - 1 - 3
		if maxLen <= 0 {
			break
		}
		if maxLen > maxUTF8StrBytes {
			maxLen = maxUTF8StrBytes
		}
		for maxLen > 1 && 4+utf8EncodedLen(maxLen, start) > remain {
			maxLen--
		}
		if 4+utf8EncodedLen(maxLen, start) > remain {
			break
		}
		enc := utf8EncodedLen(maxLen, start)
		lens = append(lens, maxLen)
		used += 4 + enc
		start += enc
	}
	if len(lens) == 0 {
		return poolAppend{newPool: pool}, nil
	}
	// 防御：条数不能越过解析器的合理性上限（正常填充量远达不到）。
	if count+len(lens) > maxPoolStringCount {
		lens = lens[:maxPoolStringCount-count]
	}
	if len(lens) == 0 {
		return poolAppend{newPool: pool}, nil
	}

	adds := make([]poolAdd, 0, len(lens))
	strBytes := 0
	off := base // 物理偏移（相对池起点）
	for _, n := range lens {
		d := encodeGiantUTF8(n, ch, off)
		// offset 表里的值相对新池的 stringsStart（= 旧值 + 4）。
		adds = append(adds, poolAdd{offset: uint32(off - (stringsStart + 4)), data: d})
		off += len(d)
		strBytes += len(d)
	}
	out := assembleGrownPool(pool, count, styleCount, stringsStart, stylesStart, adds)
	return poolAppend{newPool: out, count: len(adds), strBytes: strBytes}, nil
}

// utf16EncodedLen 返回 UTF-16 池中一条 n 个码元的字符串在偏移 at 处的编码长度。
//
// 编码 = 长度前缀（n≥0x8000 时 4 字节长格式，否则 2 字节）+ 2n 字节数据
// + 2 字节 NUL，再补零到 4 字节对齐（与参考样本一致）。
func utf16EncodedLen(n, at int) int {
	prefix := 2
	if n >= 0x8000 {
		prefix = 4
	}
	base := prefix + 2*n + 2
	return base + padTo4(at+base)
}

// encodeGiantUTF16 编码一条 UTF-16 巨串；at 是该串在新池中的偏移（用于对齐）。
func encodeGiantUTF16(n int, ch byte, at int) []byte {
	prefix := 2
	if n >= 0x8000 {
		prefix = 4
	}
	out := make([]byte, utf16EncodedLen(n, at))
	if n >= 0x8000 {
		binary.LittleEndian.PutUint16(out[0:], uint16(0x8000|(n>>16)))
		binary.LittleEndian.PutUint16(out[2:], uint16(n))
	} else {
		binary.LittleEndian.PutUint16(out[0:], uint16(n))
	}
	for i := 0; i < n; i++ {
		out[prefix+2*i] = ch // 高字节保持 0；ch 非 0，不会出现 0x0000 码元
	}
	// 结尾 2 字节 NUL 与对齐补零已由 make 置零。
	return out
}

// utf8PoolLenBytes 返回 UTF-8 池长度字段的字节数（<0x80 为 1，否则 2）。
func utf8PoolLenBytes(n int) int {
	if n > 0x7f {
		return 2
	}
	return 1
}

// utf8EncodedLen 返回 UTF-8 池中一条 n 字节的字符串在偏移 at 处的编码长度。
//
// 编码 = 字符数(变长) + 字节数(变长) + n 字节数据 + 1 字节 NUL，
// 再补零到 4 字节对齐。全 ASCII 时字符数 == 字节数。
func utf8EncodedLen(n, at int) int {
	base := 2*utf8PoolLenBytes(n) + n + 1
	return base + padTo4(at+base)
}

// appendUTF8PoolLen 按 Android 的变长格式追加 UTF-8 池长度字段。
// n 必须 ≤0x7fff（单串长度字段是 15 位）。
func appendUTF8PoolLen(out []byte, n int) []byte {
	if n > 0x7f {
		return append(out, byte(0x80|(n>>8)), byte(n))
	}
	return append(out, byte(n))
}

// encodeGiantUTF8 编码一条 UTF-8 池字符串；at 是该串在新池中的偏移（用于对齐）。
func encodeGiantUTF8(n int, ch byte, at int) []byte {
	prefix := make([]byte, 0, 4)
	prefix = appendUTF8PoolLen(prefix, n) // 字符数
	prefix = appendUTF8PoolLen(prefix, n) // 字节数（全 ASCII，二者相等）
	// make 已置零：NUL 与对齐补零都在其中。
	out := make([]byte, utf8EncodedLen(n, at))
	copy(out, prefix)
	for i := 0; i < n; i++ {
		out[len(prefix)+i] = ch
	}
	return out
}

// assembleGrownPool 把 adds 写入池并生成放大后的池 chunk。
//
// 新布局：
//
//	header(28)
//	旧字符串 offset 数组(count×4)
//	新字符串 offset 数组(n×4)      ← 插入点
//	旧 style offset 数组(styleCount×4)
//	旧字符串数据区（原地内容整体后移 4n）
//	新字符串数据
//	旧 style 数据区（整体后移到新 stylesStart）
func assembleGrownPool(pool []byte, count, styleCount, stringsStart, stylesStart int, adds []poolAdd) []byte {
	n := len(adds)
	oldStrEnd := len(pool)
	if styleCount > 0 {
		oldStrEnd = stylesStart
	}
	oldStrLen := oldStrEnd - stringsStart
	grow := 0
	for _, a := range adds {
		grow += len(a.data)
	}
	newCount := count + n
	newStringsStart := stringsStart + 4*n
	newSize := len(pool) + 4*n + grow
	newStylesStart := 0
	if styleCount > 0 {
		newStylesStart = stylesStart + 4*n + grow
	}

	out := make([]byte, newSize)
	copy(out[:poolHeaderLen], pool[:poolHeaderLen])
	binary.LittleEndian.PutUint32(out[4:], uint32(newSize))
	binary.LittleEndian.PutUint32(out[8:], uint32(newCount))
	binary.LittleEndian.PutUint32(out[20:], uint32(newStringsStart))
	binary.LittleEndian.PutUint32(out[24:], uint32(newStylesStart))

	// 旧字符串 offset 数组。
	copy(out[poolHeaderLen:poolHeaderLen+4*count], pool[poolHeaderLen:poolHeaderLen+4*count])
	// 新字符串 offset 数组：插在旧字符串 offset 之后、style offset 之前。
	for i, a := range adds {
		binary.LittleEndian.PutUint32(out[poolHeaderLen+4*count+4*i:], a.offset)
	}
	// 旧 style offset 数组（相对 stylesStart，随数据区一起平移，值不变）。
	if styleCount > 0 {
		src := poolHeaderLen + 4*count
		dst := poolHeaderLen + 4*count + 4*n
		copy(out[dst:dst+4*styleCount], pool[src:src+4*styleCount])
	}
	// 旧字符串数据区整体后移 4n。
	copy(out[newStringsStart:newStringsStart+oldStrLen], pool[stringsStart:oldStrEnd])
	// 新字符串数据：a.offset 是**相对 newStringsStart** 的表项值，
	// 物理写入位置要再加上 newStringsStart。
	for _, a := range adds {
		copy(out[newStringsStart+int(a.offset):], a.data)
	}
	// 旧 style 数据区整体后移到新 stylesStart。
	if styleCount > 0 {
		copy(out[newStylesStart:], pool[stylesStart:])
	}
	return out
}

// manifestPadSummary 从填充产物里读出两段假 chunk 与字符串池的概要（供 Run 记录统计）。
func manifestPadSummary(out []byte) (t1 uint16, n1 int, poolCount, poolSize int, t2 uint16, n2 int, ok bool) {
	if len(out) < chunkHeaderLen {
		return
	}
	hs := int(binary.LittleEndian.Uint16(out[2:]))
	if hs < chunkHeaderLen || hs+chunkHeaderLen > len(out) {
		return
	}
	sz1 := int(binary.LittleEndian.Uint32(out[hs+4:]))
	if sz1 < chunkHeaderLen || hs+sz1+chunkHeaderLen > len(out) {
		return
	}
	t1 = binary.LittleEndian.Uint16(out[hs:])
	n1 = sz1 - chunkHeaderLen

	po := hs + sz1
	if binary.LittleEndian.Uint16(out[po:]) != poolChunkType || po+poolHeaderLen > len(out) {
		return
	}
	poolSize = int(binary.LittleEndian.Uint32(out[po+4:]))
	poolCount = int(binary.LittleEndian.Uint32(out[po+8:]))
	if poolSize < poolHeaderLen || po+poolSize+chunkHeaderLen > len(out) {
		return
	}
	to := po + poolSize
	t2 = binary.LittleEndian.Uint16(out[to:])
	sz2 := int(binary.LittleEndian.Uint32(out[to+4:]))
	if sz2 < chunkHeaderLen {
		return
	}
	n2 = sz2 - chunkHeaderLen
	ok = true
	return
}
