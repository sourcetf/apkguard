package zipx

import (
	"encoding/binary"
	"hash/crc32"
)

// AlignOptions 控制重写归档时的对齐行为。
type AlignOptions struct {
	// Align 指定普通 Stored 条目的对齐字节数，0 表示使用默认值 4。
	Align int
	// SoAlign 指定未压缩 .so 条目的对齐字节数，0 表示使用 Align。
	SoAlign int
}

// DefaultAlign 返回与 Android zipalign 默认行为一致的对齐参数。
func DefaultAlign() AlignOptions {
	return AlignOptions{Align: 4, SoAlign: 4096}
}

// Write 按指定对齐参数重写归档。
//
// 所有条目数据原样复制，不重新压缩，因此 CRC 与压缩大小保持有效。
// 若原条目设置了 bit 3（数据描述符），此处会清除该位并把长度写回本地头，
// 使结构更规范（Android 对此完全兼容）。
//
// 对齐通过向扩展字段追加一条 padding 记录实现（ID 0xd935），
// 本地头与中央目录中的扩展字段保持一致。
func Write(a *Archive, opts AlignOptions) []byte {
	if opts.Align <= 0 {
		opts.Align = 4
	}
	if opts.SoAlign <= 0 {
		opts.SoAlign = opts.Align
	}

	type record struct {
		e     *Entry
		lho   int
		extra []byte
		flags uint16
	}

	out := make([]byte, 0, 1<<20)
	records := make([]record, 0, len(a.Entries))

	for _, e := range a.Entries {
		align := alignOf(e, opts)
		lho := len(out)

		// 先清理扩展字段，再据其长度计算对齐：两者顺序不能反，
		// 否则截断后的实际长度与计算所用长度不一致，对齐会失效。
		extra := sanitizeExtra(e.LocalExtra)

		// 数据区起始偏移 = 本地头 + 文件名 + 扩展字段。
		base := lho + localHeaderLen + len(e.Name) + len(extra)
		padTotal := alignmentRecordSize(base, align)
		if padTotal > 0 {
			extra = appendAlignmentExtra(extra, padTotal-4)
		}

		flags := e.Flags &^ 0x0008 // 清除数据描述符位
		// 条目名含非 ASCII 字节时必须置 UTF-8 标志（ZIP 规范 bit 11）。
		//
		// 否则读方按 CP437 解码文件名，A10 刻意注入的非 ASCII 名字会变成
		// 乱码；参考样本中全部 885 个非 ASCII 条目都带该标志，缺了它本身
		// 就是一处可被识别的差异。
		if hasNonASCII(e.Name) {
			flags |= 0x0800
		}

		var hdr [localHeaderLen]byte
		binary.LittleEndian.PutUint32(hdr[0:], sigLocal)
		binary.LittleEndian.PutUint16(hdr[4:], e.VersionNeed)
		binary.LittleEndian.PutUint16(hdr[6:], flags)
		binary.LittleEndian.PutUint16(hdr[8:], e.Method)
		binary.LittleEndian.PutUint16(hdr[10:], e.ModTime)
		binary.LittleEndian.PutUint16(hdr[12:], e.ModDate)
		binary.LittleEndian.PutUint32(hdr[14:], e.CRC32)
		binary.LittleEndian.PutUint32(hdr[18:], e.CompSize)
		binary.LittleEndian.PutUint32(hdr[22:], e.UncompSize)
		binary.LittleEndian.PutUint16(hdr[26:], uint16(len(e.Name)))
		binary.LittleEndian.PutUint16(hdr[28:], uint16(len(extra)))

		out = append(out, hdr[:]...)
		out = append(out, e.Name...)
		out = append(out, extra...)
		out = append(out, e.Raw...)

		records = append(records, record{e: e, lho: lho, extra: extra, flags: flags})
	}

	cdOff := len(out)
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
		binary.LittleEndian.PutUint16(h[30:], uint16(len(r.extra)))
		binary.LittleEndian.PutUint16(h[32:], uint16(len(e.Comment)))
		binary.LittleEndian.PutUint16(h[36:], e.IntAttr)
		binary.LittleEndian.PutUint32(h[38:], e.ExtAttr)
		binary.LittleEndian.PutUint32(h[42:], uint32(r.lho))

		out = append(out, h[:]...)
		out = append(out, e.Name...)
		out = append(out, r.extra...)
		out = append(out, e.Comment...)
	}
	cdSize := len(out) - cdOff

	var eo [eocdLen]byte
	binary.LittleEndian.PutUint32(eo[0:], sigEOCD)
	binary.LittleEndian.PutUint16(eo[8:], uint16(len(records)))
	binary.LittleEndian.PutUint16(eo[10:], uint16(len(records)))
	binary.LittleEndian.PutUint32(eo[12:], uint32(cdSize))
	binary.LittleEndian.PutUint32(eo[16:], uint32(cdOff))
	binary.LittleEndian.PutUint16(eo[20:], uint16(len(a.Comment)))
	out = append(out, eo[:]...)
	out = append(out, a.Comment...)

	return out
}

// alignOf 返回条目应满足的对齐字节数。
//
// 只有未压缩（Stored）条目才能通过对齐获益；压缩条目按 1 字节处理。
// 未压缩的 .so 使用页对齐，便于运行时 mmap 映射。
func alignOf(e *Entry, opts AlignOptions) int {
	if !e.IsStored() {
		return 1
	}
	if hasSuffix(e.Name, ".so") {
		return opts.SoAlign
	}
	return opts.Align
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
// 返回值 0 表示当前偏移已对齐，无需追加；否则返回值不小于 4（扩展字段头长度），
// 且保证 base+返回值 是 align 的整数倍。
func alignmentRecordSize(base, align int) int {
	if align <= 1 {
		return 0
	}
	need := (align - (base % align)) % align
	if need == 0 {
		return 0
	}
	if need < 4 {
		// 扩展字段至少需要 4 字节头，因此补足一整轮对齐。
		need += align
	}
	return need
}

// appendAlignmentExtra 向扩展字段追加一条 padding 记录，payload 长度为 n。
func appendAlignmentExtra(extra []byte, n int) []byte {
	var rh [4]byte
	binary.LittleEndian.PutUint16(rh[0:], 0xd935)
	binary.LittleEndian.PutUint16(rh[2:], uint16(n))
	extra = append(extra, rh[:]...)
	extra = append(extra, make([]byte, n)...)
	return extra
}

// NewStored 构造一个未压缩的新条目。
func NewStored(name string, data []byte) *Entry {
	return &Entry{
		VersionMade: 20,
		VersionNeed: 20,
		Method:      0,
		ModDate:     0x21, // 1980-01-01
		CRC32:       crc32.ChecksumIEEE(data),
		CompSize:    uint32(len(data)),
		UncompSize:  uint32(len(data)),
		Name:        []byte(name),
		Raw:         data,
	}
}

func hasSuffix(b []byte, s string) bool {
	if len(b) < len(s) {
		return false
	}
	return string(b[len(b)-len(s):]) == s
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
