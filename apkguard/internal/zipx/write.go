package zipx

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"time"
)

// 数据描述符与假加密 flag 相关的常量。
const (
	// sigDataDescriptor 是数据描述符的签名（PK\x07\x08）。
	sigDataDescriptor = 0x08074b50
	// dataDescriptorLen 是数据描述符的固定长度：4 字节签名 +
	// CRC32 + 压缩大小 + 原始大小，各 4 字节小端。
	dataDescriptorLen = 16
	// flagDataDescriptor 是 ZIP 通用标志位 bit 3：条目数据后带数据描述符。
	flagDataDescriptor = 0x0008
	// flagUTF8 是 ZIP 通用标志位 bit 11：条目名按 UTF-8 解码。
	flagUTF8 = 0x0800

	// LocalDecoyMask 是「本地头假加密」写入的 flag 位：bit0（加密）+
	// bit6（强加密）。只写本地头，中央目录保持原样，见 AlignOptions.LocalFlagDecoy。
	LocalDecoyMask = 0x0001 | 0x0040
)

// AlignOptions 控制重写归档时的对齐与 ZIP 层写法。
type AlignOptions struct {
	// Align 指定普通 Stored 条目的对齐字节数，0 表示使用默认值 4。
	Align int
	// SoAlign 指定未压缩 .so 条目的对齐字节数，0 表示使用 Align。
	SoAlign int

	// NoDataDescriptors 关闭压缩条目的数据描述符（默认 false，即写出）。
	//
	// 默认行为与参考样本一致：全部非 Stored 条目在本地头与中央目录都置
	// bit3，并在条目数据后追加 16 字节
	//
	//	PK\x07\x08 + CRC32 + 压缩大小 + 原始大小（小端）
	//
	// 同时本地头里的 CRC/大小字段仍写正确值（规范允许为 0，但样本写的是真值），
	// 因此「按本地头读」与「按中央目录读」两种实现都能正确解出内容。
	// Stored 条目不加描述符，与样本一致。
	//
	// 置 true 可完全恢复旧行为（清除 bit3、不追加描述符），供测试做对照。
	NoDataDescriptors bool

	// LocalFlagDecoy 为四个核心条目在**本地头**附加假加密 flag
	// （bit0 加密 + bit6 强加密，见 LocalDecoyMask），中央目录保持原样。
	//
	// 判定按条目名：AndroidManifest.xml、resources.arsc、classes.dex 及
	// classesN.dex（N 为纯数字）。与参考样本一致：读本地头的工具会要求口令，
	// 而 Android 平台按中央目录读取，照常安装。
	//
	// 默认关闭（零值）。这里是按名字判定的策略而非逐条目标记，是因为 v1
	// 签名会用 zipx.Read 读中央目录后重写整个归档，逐条目字段在那次重写中
	// 会丢失；只有随对齐参数一起传递的策略才能让标志位在重写后仍然存在。
	LocalFlagDecoy bool
}

// DefaultAlign 返回与 Android zipalign 默认行为一致的对齐参数。
//
// SoAlign 取 16384：Android 15 起 16KB 页设备要求未压缩 .so 按 16KB 对齐。
// 16384 是 4096 的整数倍，因此 `zipalign -c -p 4` 仍然通过，但对 16KB 页
// 设备（要求 16384）也能满足。
func DefaultAlign() AlignOptions {
	return AlignOptions{Align: 4, SoAlign: 16384}
}

// Write 按指定对齐参数重写归档。
//
// 为保持与既有 8 处跨包调用方的兼容，本函数不返回错误：内部调用
// WriteChecked，一旦输入触及 ZIP 的 16/32 位字段上限（例如条目数 > 65535）
// 将 panic。调用方的输入**可能触及这些上限**时，必须改用 WriteChecked 并处理
// 其返回的 error，而不是依赖 panic。
//
// 所有条目数据原样复制，不重新压缩，因此 CRC 与压缩大小保持有效。
//
// 默认对全部非 Stored 条目置 bit3 并追加 16 字节数据描述符（本地头里的
// CRC/大小仍写正确值），与参考样本的 2258/2258 个 deflate 条目一致；
// AlignOptions.NoDataDescriptors 可关闭该行为。
//
// 对齐通过向本地头与中央目录的扩展字段各追加一条 padding 记录（ID 0xd935）实现，
// 其载荷前 2 字节为该条目的对齐倍数。数据描述符被计入后续条目的偏移计算
// （前缀条目的数据 + 描述符之后才是下一个本地头），因此 .so 的数据起点对齐
// 仍然成立。
func Write(a *Archive, opts AlignOptions) []byte {
	out, err := WriteChecked(a, opts)
	if err != nil {
		panic("zipx.Write: " + err.Error())
	}
	return out
}

// WriteChecked 与 Write 相同，但会在写出前校验 ZIP 的字段上限并返回明确错误。
//
// ZIP 的非 ZIP64 结构用 16 位表示条目数、32 位表示偏移与长度；越界时静默
// 回绕会产出不可解析的坏归档，因此这里一律拒绝而非截断。
func WriteChecked(a *Archive, opts AlignOptions) ([]byte, error) {
	if opts.Align <= 0 {
		opts.Align = 4
	}
	if opts.SoAlign <= 0 {
		opts.SoAlign = opts.Align
	}

	if len(a.Entries) > 0xFFFF {
		return nil, fmt.Errorf("zipx: 条目数 %d 超过上限 65535（ZIP64 尚未支持）", len(a.Entries))
	}
	if len(a.Comment) > 0xFFFF {
		return nil, fmt.Errorf("zipx: 归档注释长度 %d 超过上限 65535", len(a.Comment))
	}

	type record struct {
		e            *Entry
		lho          int
		localExtra   []byte
		centralExtra []byte
		flags        uint16
	}

	out := make([]byte, 0, 1<<20)
	records := make([]record, 0, len(a.Entries))

	for _, e := range a.Entries {
		if len(e.Name) > 0xFFFF {
			return nil, fmt.Errorf("zipx: 条目名长度 %d 超过上限 65535", len(e.Name))
		}
		if len(e.Comment) > 0xFFFF {
			return nil, fmt.Errorf("zipx: 条目 %q 注释长度 %d 超过上限 65535", e.Name, len(e.Comment))
		}

		align := alignOf(e, opts)
		lho := len(out)
		if lho > 0xFFFFFFFF {
			return nil, fmt.Errorf("zipx: 条目 %q 本地头偏移 %d 超过上限 0xFFFFFFFF", e.Name, lho)
		}

		// 先清理扩展字段，再据其长度计算对齐：两者顺序不能反，
		// 否则截断后的实际长度与计算所用长度不一致，对齐会失效。
		//
		// 本地与中央目录的扩展字段分别处理：中央目录还有自己的额外字段
		// （如 0x5455 扩展时间戳），不能被本地扩展字段整体覆盖。
		localExtra := sanitizeExtra(e.LocalExtra)
		centralExtra := sanitizeExtra(e.CentralExtra)

		// 数据区起始偏移 = 本地头 + 文件名 + 本地扩展字段。
		// lho 是 len(out)，已包含前一条目数据之后的数据描述符（若有），
		// 因此描述符自然被计入本条目的对齐与偏移计算。
		base := lho + localHeaderLen + len(e.Name) + len(localExtra)
		padTotal := alignmentRecordSize(base, align)
		if padTotal > 0 {
			localExtra = appendAlignmentExtra(localExtra, padTotal, align)
			centralExtra = appendAlignmentExtra(centralExtra, padTotal, align)
		}
		if len(localExtra) > 0xFFFF {
			return nil, fmt.Errorf("zipx: 条目 %q 本地扩展字段长度 %d 超过上限 65535", e.Name, len(localExtra))
		}
		if len(centralExtra) > 0xFFFF {
			return nil, fmt.Errorf("zipx: 条目 %q 中央目录扩展字段长度 %d 超过上限 65535", e.Name, len(centralExtra))
		}

		// 数据描述符只加在压缩条目上（与参考样本一致）：本地头与中央目录
		// 都置 bit3，条目数据后追加 16 字节；Stored 条目不加，避免与对齐/
		// 签名逻辑冲突。
		writeDD := !opts.NoDataDescriptors && !e.IsStored()
		flags := e.Flags &^ flagDataDescriptor
		if writeDD {
			flags |= flagDataDescriptor
		}
		// 条目名含非 ASCII 字节时必须置 UTF-8 标志（ZIP 规范 bit 11）。
		//
		// 否则读方按 CP437 解码文件名，A10 刻意注入的非 ASCII 名字会变成
		// 乱码；参考样本中全部 885 个非 ASCII 条目都带该标志，缺了它本身
		// 就是一处可被识别的差异。
		if hasNonASCII(e.Name) {
			flags |= flagUTF8
		}

		// 本地头可附加仅本地的假加密位：中央目录写 flags（不含这些位），
		// 于是「读本地头」与「读中央目录」看到不同的加密状态。
		localFlags := flags
		if opts.LocalFlagDecoy && isCoreDecoyName(e.Name) {
			localFlags |= LocalDecoyMask
		}

		var hdr [localHeaderLen]byte
		binary.LittleEndian.PutUint32(hdr[0:], sigLocal)
		binary.LittleEndian.PutUint16(hdr[4:], e.VersionNeed)
		binary.LittleEndian.PutUint16(hdr[6:], localFlags)
		binary.LittleEndian.PutUint16(hdr[8:], e.Method)
		binary.LittleEndian.PutUint16(hdr[10:], e.ModTime)
		binary.LittleEndian.PutUint16(hdr[12:], e.ModDate)
		binary.LittleEndian.PutUint32(hdr[14:], e.CRC32)
		binary.LittleEndian.PutUint32(hdr[18:], e.CompSize)
		binary.LittleEndian.PutUint32(hdr[22:], e.UncompSize)
		binary.LittleEndian.PutUint16(hdr[26:], uint16(len(e.Name)))
		binary.LittleEndian.PutUint16(hdr[28:], uint16(len(localExtra)))

		out = append(out, hdr[:]...)
		out = append(out, e.Name...)
		out = append(out, localExtra...)
		out = append(out, e.Raw...)
		if writeDD {
			// 数据描述符：PK\x07\x08 + CRC32 + 压缩大小 + 原始大小（小端）。
			// 本地头里同时保留了正确值，两种读法都自洽（与样本一致）。
			var dd [dataDescriptorLen]byte
			binary.LittleEndian.PutUint32(dd[0:], sigDataDescriptor)
			binary.LittleEndian.PutUint32(dd[4:], e.CRC32)
			binary.LittleEndian.PutUint32(dd[8:], e.CompSize)
			binary.LittleEndian.PutUint32(dd[12:], e.UncompSize)
			out = append(out, dd[:]...)
		}

		records = append(records, record{e: e, lho: lho, localExtra: localExtra, centralExtra: centralExtra, flags: flags})
	}

	cdOff := len(out)
	if cdOff > 0xFFFFFFFF {
		return nil, fmt.Errorf("zipx: 中央目录偏移 %d 超过上限 0xFFFFFFFF", cdOff)
	}
	for _, r := range records {
		e := r.e

		var h [centralHeaderLen]byte
		binary.LittleEndian.PutUint32(h[0:], sigCentral)
		binary.LittleEndian.PutUint16(h[4:], e.VersionMade)
		binary.LittleEndian.PutUint16(h[6:], e.VersionNeed)
		binary.LittleEndian.PutUint16(h[8:], r.flags)
		binary.LittleEndian.PutUint16(h[10:], e.Method)
		binary.LittleEndian.PutUint16(h[12:], e.ModTime)
		binary.LittleEndian.PutUint16(h[14:], e.ModDate)
		binary.LittleEndian.PutUint32(h[16:], e.CRC32)
		binary.LittleEndian.PutUint32(h[20:], e.CompSize)
		binary.LittleEndian.PutUint32(h[24:], e.UncompSize)
		binary.LittleEndian.PutUint16(h[28:], uint16(len(e.Name)))
		binary.LittleEndian.PutUint16(h[30:], uint16(len(r.centralExtra)))
		binary.LittleEndian.PutUint16(h[32:], uint16(len(e.Comment)))
		binary.LittleEndian.PutUint16(h[36:], e.IntAttr)
		binary.LittleEndian.PutUint32(h[38:], e.ExtAttr)
		binary.LittleEndian.PutUint32(h[42:], uint32(r.lho))

		out = append(out, h[:]...)
		out = append(out, e.Name...)
		out = append(out, r.centralExtra...)
		out = append(out, e.Comment...)
	}
	cdSize := len(out) - cdOff
	if cdSize > 0xFFFFFFFF {
		return nil, fmt.Errorf("zipx: 中央目录大小 %d 超过上限 0xFFFFFFFF", cdSize)
	}

	var eo [eocdLen]byte
	binary.LittleEndian.PutUint32(eo[0:], sigEOCD)
	binary.LittleEndian.PutUint16(eo[8:], uint16(len(records)))
	binary.LittleEndian.PutUint16(eo[10:], uint16(len(records)))
	binary.LittleEndian.PutUint32(eo[12:], uint32(cdSize))
	binary.LittleEndian.PutUint32(eo[16:], uint32(cdOff))
	binary.LittleEndian.PutUint16(eo[20:], uint16(len(a.Comment)))
	out = append(out, eo[:]...)
	out = append(out, a.Comment...)

	return out, nil
}

// alignOf 返回条目应满足的对齐字节数。
//
// 只有未压缩（Stored）条目才能通过对齐获益；压缩条目按 1 字节处理。
// 未压缩的 .so 使用页对齐，便于运行时 mmap 映射。
// 后缀判定大小写不敏感：现实中存在 LIB.SO 这类大写扩展名。
func alignOf(e *Entry, opts AlignOptions) int {
	if !e.IsStored() {
		return 1
	}
	if hasSuffixFold(e.Name, ".so") {
		return opts.SoAlign
	}
	return opts.Align
}

// isCoreDecoyName 判断条目名是否属于「核心文件」。
//
// 与参考样本的本地头假加密目标一致：AndroidManifest.xml、resources.arsc、
// classes.dex 以及 classesN.dex（N 为纯数字，如 classes2.dex）。
// 大小写敏感：A16 注入的 ANDROIDMANIFEST.XML 等诱饵核心文件不应被误标。
func isCoreDecoyName(name []byte) bool {
	s := string(name)
	if s == "AndroidManifest.xml" || s == "resources.arsc" {
		return true
	}
	const prefix, suffix = "classes", ".dex"
	if len(s) < len(prefix)+len(suffix) || s[:len(prefix)] != prefix || s[len(s)-len(suffix):] != suffix {
		return false
	}
	mid := s[len(prefix) : len(s)-len(suffix)]
	for i := 0; i < len(mid); i++ {
		if mid[i] < '0' || mid[i] > '9' {
			return false
		}
	}
	return true
}

// sanitizeExtra 截掉扩展字段中无法构成完整记录的尾部字节。
//
// 现实中确实存在「扩展字段长度与内容对不上」的 APK：本工具的参考样本里
// resources.arsc 的本地扩展字段就只有 1 个孤立的 0x00 字节。
// 若原样保留、再把对齐记录追加到其后，读方会把这个孤立字节当作新记录的
// 字段 ID 高位，进而报「扩展字段损坏」——输出的 APK 会被严格实现的
// ZIP 解析器（如 Python zipfile）直接拒收。
//
// 截掉残尾不损失任何真实语义：它本来就不是一条合法记录。
func sanitizeExtra(extra []byte) []byte {
	p := 0
	for p+4 <= len(extra) {
		id := binary.LittleEndian.Uint16(extra[p:])
		n := int(binary.LittleEndian.Uint16(extra[p+2:]))
		if id == 0 && n == 0 {
			// 空记录是约定的终止标记，其后内容无意义。
			return extra[:p]
		}
		if p+4+n > len(extra) {
			break // 本记录的声明长度超出剩余字节：残尾
		}
		p += 4 + n
	}
	out := make([]byte, p)
	copy(out, extra[:p])
	return out
}

// alignmentRecordSize 计算为使数据区起始偏移对齐到 align，需要追加的扩展字段总字节数。
//
// 返回值 0 表示当前偏移已对齐，无需追加；否则返回值不小于 6，即至少容纳
// 4 字节记录头 + 2 字节对齐倍数载荷，且保证 base+返回值 是 align 的整数倍。
func alignmentRecordSize(base, align int) int {
	if align <= 1 {
		return 0
	}
	need := (align - (base % align)) % align
	if need == 0 {
		return 0
	}
	// 载荷前 2 字节要写对齐倍数，因此总长至少 6（4 字节头 + 2 字节载荷）。
	for need < 6 {
		need += align
	}
	return need
}

// appendAlignmentExtra 向扩展字段追加一条对齐记录（ID 0xd935），总长 total。
//
// 依据 AOSP ApkSigner.java，0xd935 的载荷前 2 字节是 alignment multiple，
// 其余为 0 填充。
func appendAlignmentExtra(extra []byte, total, align int) []byte {
	n := total - 4
	if n < 2 {
		// 调用方已通过 alignmentRecordSize 保证 total>=6；此处兜底避免越界。
		n = 2
	}
	var rh [4]byte
	binary.LittleEndian.PutUint16(rh[0:], 0xd935)
	binary.LittleEndian.PutUint16(rh[2:], uint16(n))
	extra = append(extra, rh[:]...)
	payload := make([]byte, n)
	binary.LittleEndian.PutUint16(payload[0:], uint16(align))
	return append(extra, payload...)
}

// NewStored 构造一个未压缩的新条目。
//
// 时间戳为 1980-01-01（ZIP 的 DOS 纪元下限）。需要与产物其余条目保持
// 一致的时间时用 NewStoredAt，否则单独追加的条目会成为「异类指纹」。
func NewStored(name string, data []byte) *Entry {
	return NewStoredAt(name, data, 0, 0x21)
}

// NewStoredAt 构造一个带指定 DOS 时间/日期戳的未压缩条目。
func NewStoredAt(name string, data []byte, dosTime, dosDate uint16) *Entry {
	return &Entry{
		VersionMade: 20,
		VersionNeed: 20,
		Method:      0,
		ModTime:     dosTime,
		ModDate:     dosDate,
		CRC32:       crc32.ChecksumIEEE(data),
		CompSize:    uint32(len(data)),
		UncompSize:  uint32(len(data)),
		Name:        []byte(name),
		Raw:         data,
	}
}

// DOSDateTime 把时间转换为 ZIP 使用的 DOS 时间与日期字段。
//
// ZIP 的 DOS 时间只精确到 2 秒，且年份下限是 1980；早于该时间一律钳到
// 1980-01-01，否则年份字段会下溢成负数。
func DOSDateTime(t time.Time) (uint16, uint16) {
	t = t.UTC()
	if t.Year() < 1980 {
		t = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	dosTime := uint16(t.Hour())<<11 | uint16(t.Minute())<<5 | uint16(t.Second()/2)
	dosDate := uint16(t.Year()-1980)<<9 | uint16(t.Month())<<5 | uint16(t.Day())
	return dosTime, dosDate
}

func hasSuffix(b []byte, s string) bool {
	if len(b) < len(s) {
		return false
	}
	return string(b[len(b)-len(s):]) == s
}

// hasSuffixFold 是 ASCII 大小写不敏感的后缀判定。
//
// 只对后缀做 ASCII 折叠，避免 strings.ToLower 对非法 UTF-8 字节做替换而改变长度。
func hasSuffixFold(b []byte, s string) bool {
	if len(b) < len(s) {
		return false
	}
	off := len(b) - len(s)
	for i := 0; i < len(s); i++ {
		c := b[off+i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		d := s[i]
		if d >= 'A' && d <= 'Z' {
			d += 'a' - 'A'
		}
		if c != d {
			return false
		}
	}
	return true
}

// hasNonASCII 判断字节串中是否含有 >= 0x80 的字节。
//
// ZIP 的条目名按规范是 UTF-8 字节串，但读方只有在 bit 11 置位时才按 UTF-8
// 解码，否则回退到 CP437。因此「名字里有非 ASCII 字节」这一事实必须通过
// 该标志显式告知读方。
func hasNonASCII(b []byte) bool {
	for _, c := range b {
		if c >= 0x80 {
			return true
		}
	}
	return false
}
