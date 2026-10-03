package passes

import (
	"context"
	"encoding/binary"
	"fmt"

	"apkguard/internal/config"
	"apkguard/internal/pipeline"
)

// ---- A15 巨型 Manifest 填充 ----
//
// 手法来自参考样本（`sample.apk`）：它的 AndroidManifest.xml **未压缩体积
// 369 MB**，压缩后却只有 367 KB（压缩比约 1000:1），而其中约 85% 是零。
//
// 结构（实测该样本）：
//
//	[XML 顶层 chunk，size = 整个文件]
//	[假 chunk，声明 size 1.5 MB]
//	[假字符串池 chunk，声明 size 315 MB —— 内容几乎全是 0]
//	[假 chunk，声明 size 52 MB]
//	[真实内容：字符串池 + 命名空间 + 元素]
//
// 关键点：**声明的 chunk 长度串起来正好落在真实内容上**，因此按 chunk 头
// 遍历的解析器（aapt/ART/androguard）最终仍能读到真实 Manifest，应用照常安装；
// 但任何把文件读进内存或按声明长度预分配的工具体验都会急剧变差。
//
// 我们采用同构做法：在真实内容**之前**插入一个/多个声明长度巨大的零填充 chunk，
// 并把顶层 XML chunk 的 size 更新为整个文件长度。
type manifestPad struct{}

func (manifestPad) ID() config.FeatureID { return "A15" }
func (manifestPad) In() pipeline.Level   { return pipeline.LevelZip }
func (manifestPad) Out() pipeline.Level  { return pipeline.LevelZip }

// manifestName 是 Manifest 在归档中的固定条目名。
const manifestName = "AndroidManifest.xml"

// padChunk 是插入的「假 chunk」类型。
//
// 用未知类型（0xb4a7 这类样本里也出现过的随机值）而不是合法的字符串池：
// 合法类型会让解析器真的去解析这几十 MB 的零，反而可能报错退出；
// 未知类型则是「按长度跳过」，最稳妥。
const padChunkType = 0xb4a7

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
	out, err := padManifest(data, pad)
	if err != nil {
		return err
	}
	// 必须**压缩**存放（deflate），而不是 STORED。
	//
	// 早期实现用 SetData(out, false) 即 STORED，16 MB 填充就实打实占 16 MB 包体。
	// 但实测参考样本 sample.apk：它的 AndroidManifest.xml 解压后 369,623,060 字节，
	// 压缩后仅 367,318 字节（压缩比约 0.001），中央目录里的压缩方式字段是 8
	// （deflate）——证明 **Android 系统完全接受压缩存储的 AndroidManifest.xml**。
	// 压缩因此是纯收益：解压后仍是同样的巨型体积（读取/预分配压力不变），
	// 包体却省约 1000 倍。填充内容几乎全是零，deflate 能把它压到极小。
	if err := e.SetData(out, true); err != nil {
		return fmt.Errorf("写回 %s 失败: %w", manifestName, err)
	}

	art.Note("A15 巨型 Manifest 填充：%s 由 %d 字节膨胀到 %d 字节（插入 %d MB 零填充，"+
		"真实内容位于文件末尾，按 chunk 遍历的解析器仍能读到）",
		manifestName, len(data), len(out), mb)
	art.Stat("A15.before", fmt.Sprint(len(data)))
	art.Stat("A15.after", fmt.Sprint(len(out)))
	art.Stat("A15.pad", fmt.Sprint(pad))
	return nil
}

// defaultManifestPadMB 是未显式指定尺寸时使用的填充量（MB）。
const defaultManifestPadMB = 100

// maxPadU32 是 uint32 能表达的最大长度（填充 chunk 头里的 size 字段是 uint32）。
const maxPadU32 = int64(1)<<32 - 1

// manifestPadOverflows 判断填充后的长度是否会越过 uint32 表达上限。
//
// 单独抽出成纯函数，便于在不分配几 GB 内存的前提下直接测试边界分支。
// total 是填充后整个文件的长度，pad 是填充字节数（填充 chunk = 8+pad）。
func manifestPadOverflows(pad, total int64) bool {
	return pad+8 > maxPadU32 || total > maxPadU32
}

// padManifest 在真实 XML 内容之前插入零填充 chunk，并更新顶层 size。
//
// 输入必须是**完整的 AXML**（顶层 XML chunk + 其后的各子 chunk）。
// 返回的新字节流结构：
//
//	[XML hdr, size = 整个新文件]
//	[填充 chunk: type=padChunkType, headerSize=8, size=8+pad, 之后是 pad 字节零]
//	[原始子 chunk 序列（真实内容）]
func padManifest(data []byte, pad int) ([]byte, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("A15：%s 过短（%d 字节）", manifestName, len(data))
	}
	typ := binary.LittleEndian.Uint16(data[0:])
	hs := int(binary.LittleEndian.Uint16(data[2:]))
	size := int(binary.LittleEndian.Uint32(data[4:]))
	if typ != 0x0003 {
		return nil, fmt.Errorf("A15：%s 顶层不是 XML chunk（type=0x%04x）", manifestName, typ)
	}
	if hs < 8 || hs > len(data) {
		return nil, fmt.Errorf("A15：%s 的 headerSize 非法（%d）", manifestName, hs)
	}
	if size > len(data) {
		// 声明长度超过实际长度：解析器会停止遍历。这种情况下填充会让
		// 真实内容彻底读不到，因此直接拒绝而不是产出一个装不上的包。
		return nil, fmt.Errorf("A15：%s 的声明长度 %d 大于实际长度 %d，拒绝填充",
			manifestName, size, len(data))
	}
	real := data[hs:size] // 真实子 chunk 序列
	trailing := data[size:]

	// 显式校验长度，绝不静默截断。
	//
	// 配置上限允许 4096 MB，而 4096<<20 == 2^32：此时 8+pad 的 uint32
	// 会回绕成 8，填充 chunk 的声明长度被截断，Android 直接报
	// "Bad XML block"。这里在分配之前就拒绝，既不产生几 GB 的临时内存，
	// 也避免产出一个装不上的包。
	total := int64(hs) + 8 + int64(pad) + int64(len(real)) + int64(len(trailing))
	if manifestPadOverflows(int64(pad), total) {
		return nil, fmt.Errorf(
			"A15：%s 填充后长度 total=%d 或填充 chunk 长度=%d 超过 uint32 上限（%d），"+
				"声明长度会被截断成错误的包头，拒绝生成",
			manifestName, total, int64(pad)+8, maxPadU32)
	}

	// 填充 chunk 自身：8 字节头 + pad 字节零
	padChunk := make([]byte, 8+pad)
	binary.LittleEndian.PutUint16(padChunk[0:], padChunkType)
	binary.LittleEndian.PutUint16(padChunk[2:], 8)
	binary.LittleEndian.PutUint32(padChunk[4:], uint32(len(padChunk)))

	out := make([]byte, 0, int(total))
	head := make([]byte, hs)
	copy(head, data[:hs])
	binary.LittleEndian.PutUint32(head[4:], uint32(total))
	out = append(out, head...)
	out = append(out, padChunk...)
	out = append(out, real...)
	out = append(out, trailing...)
	return out, nil
}
