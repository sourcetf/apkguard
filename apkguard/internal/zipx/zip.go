// Package zipx 提供 ZIP/APK 容器的无损读写与对齐能力。
//
// 设计要点：条目数据以「压缩后的原始字节」为单位保存，重写归档时绝不重新压缩，
// 因此 CRC、压缩大小、压缩方法均保持不变，避免破坏已有资源。
package zipx

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
)

const (
	sigLocal     = 0x04034b50
	sigCentral   = 0x02014b50
	sigEOCD      = 0x06054b50
	sigZip64EOCD = 0x06064b50
	sigZip64Loc  = 0x07064b50

	localHeaderLen   = 30
	centralHeaderLen = 46
	eocdLen          = 22
)

// 常见错误。
var (
	ErrNotZip  = errors.New("zipx: 不是合法的 ZIP 归档（未找到 EOCD）")
	ErrZip64   = errors.New("zipx: 暂不支持 ZIP64 归档")
	ErrCorrupt = errors.New("zipx: 归档结构损坏")
)

// Entry 是 ZIP 中的一个成员。
type Entry struct {
	VersionMade uint16
	VersionNeed uint16
	Flags       uint16
	Method      uint16
	ModTime     uint16
	ModDate     uint16
	CRC32       uint32
	CompSize    uint32
	UncompSize  uint32
	IntAttr     uint16
	ExtAttr     uint32

	Name    []byte
	Comment []byte

	// CentralExtra / LocalExtra 分别是中央目录与本地头中的扩展字段。
	CentralExtra []byte
	LocalExtra   []byte

	// Raw 是压缩后的数据（Method=0 时为原始数据）。
	Raw []byte
}

// IsDir 判断该条目是否为目录项。
func (e *Entry) IsDir() bool { return len(e.Name) > 0 && e.Name[len(e.Name)-1] == '/' }

// IsStored 判断该条目是否为未压缩（Stored）存储。
func (e *Entry) IsStored() bool { return e.Method == 0 }

// NameString 返回条目名的字符串形式。
func (e *Entry) NameString() string { return string(e.Name) }

// Data 返回条目的未压缩内容。
//
// 支持 Stored（0）与 Deflate（8）两种方法；其余方法返回错误。
func (e *Entry) Data() ([]byte, error) {
	switch e.Method {
	case 0:
		return e.Raw, nil
	case 8:
		r := flate.NewReader(bytes.NewReader(e.Raw))
		defer r.Close()
		out, err := io.ReadAll(r)
		if err != nil {
			return nil, fmt.Errorf("%w: 解压条目 %q 失败: %v", ErrCorrupt, e.Name, err)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%w: 条目 %q 使用了不支持的压缩方法 %d", ErrCorrupt, e.Name, e.Method)
	}
}

// SetData 用未压缩内容替换条目数据，并按需压缩。
//
// compress 为 true 时使用 Deflate，否则使用 Stored。
func (e *Entry) SetData(data []byte, compress bool) error {
	e.UncompSize = uint32(len(data))
	e.CRC32 = crc32.ChecksumIEEE(data)
	if !compress {
		e.Method = 0
		e.CompSize = uint32(len(data))
		e.Raw = data
		return nil
	}
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	e.Method = 8
	e.CompSize = uint32(buf.Len())
	e.Raw = buf.Bytes()
	return nil
}

// Archive 是一个解析后的 ZIP 归档。
type Archive struct {
	Entries []*Entry
	Comment []byte
}

// findEOCD 从尾部向前搜索 EOCD 记录。
// ZIP 注释最长 65535 字节，因此最多回扫 65557 字节。
func findEOCD(data []byte) int {
	if len(data) < eocdLen {
		return -1
	}
	limit := len(data) - eocdLen
	low := limit - 65535
	if low < 0 {
		low = 0
	}
	for i := limit; i >= low; i-- {
		if binary.LittleEndian.Uint32(data[i:]) != sigEOCD {
			continue
		}
		// 注释长度必须与文件尾部长度自洽，避免误命中数据区里的同名字节串。
		clen := int(binary.LittleEndian.Uint16(data[i+20:]))
		if i+eocdLen+clen == len(data) {
			return i
		}
	}
	return -1
}

// Read 解析一个 ZIP/APK 归档。
func Read(data []byte) (*Archive, error) {
	eocd := findEOCD(data)
	if eocd < 0 {
		return nil, ErrNotZip
	}

	// ZIP64：EOCD 前 20 字节处存在 ZIP64 定位器。
	if eocd >= 20 && binary.LittleEndian.Uint32(data[eocd-20:]) == sigZip64Loc {
		return nil, ErrZip64
	}

	total := int(binary.LittleEndian.Uint16(data[eocd+10:]))
	cdSize := int(binary.LittleEndian.Uint32(data[eocd+12:]))
	commentLen := int(binary.LittleEndian.Uint16(data[eocd+20:]))

	// 中央目录物理上紧邻 EOCD，因此其起始位置可由 eocd-cdSize 反推。
	// 注意：EOCD 中的 cdOffset 字段在「已带签名块」的 APK 中指向签名块而非中央目录，
	// 所以不能用它来定位。
	cdStart := eocd - cdSize
	if cdStart < 0 || cdStart > eocd {
		return nil, fmt.Errorf("%w: 中央目录大小 %d 越界", ErrCorrupt, cdSize)
	}
	if total > 0 && cdStart+4 <= len(data) && binary.LittleEndian.Uint32(data[cdStart:]) != sigCentral {
		// 回退：按 cdOffset 定位（兼容非标准布局）。
		alt := int(binary.LittleEndian.Uint32(data[eocd+16:]))
		if alt >= 0 && alt+4 <= len(data) && binary.LittleEndian.Uint32(data[alt:]) == sigCentral {
			cdStart = alt
		} else {
			return nil, fmt.Errorf("%w: 中央目录起始位置非法 (%d)", ErrCorrupt, cdStart)
		}
	}

	a := &Archive{}
	if commentLen > 0 && eocd+eocdLen+commentLen <= len(data) {
		a.Comment = append([]byte(nil), data[eocd+eocdLen:eocd+eocdLen+commentLen]...)
	}

	off := cdStart
	for i := 0; i < total; i++ {
		if off+centralHeaderLen > len(data) {
			return nil, fmt.Errorf("%w: 第 %d 个中央目录项越界", ErrCorrupt, i)
		}
		if binary.LittleEndian.Uint32(data[off:]) != sigCentral {
			return nil, fmt.Errorf("%w: 第 %d 个中央目录项签名错误", ErrCorrupt, i)
		}

		e := &Entry{}
		e.VersionMade = binary.LittleEndian.Uint16(data[off+4:])
		e.VersionNeed = binary.LittleEndian.Uint16(data[off+6:])
		e.Flags = binary.LittleEndian.Uint16(data[off+8:])
		e.Method = binary.LittleEndian.Uint16(data[off+10:])
		e.ModTime = binary.LittleEndian.Uint16(data[off+12:])
		e.ModDate = binary.LittleEndian.Uint16(data[off+14:])
		e.CRC32 = binary.LittleEndian.Uint32(data[off+16:])
		e.CompSize = binary.LittleEndian.Uint32(data[off+20:])
		e.UncompSize = binary.LittleEndian.Uint32(data[off+24:])
		nameLen := int(binary.LittleEndian.Uint16(data[off+28:]))
		extraLen := int(binary.LittleEndian.Uint16(data[off+30:]))
		cmtLen := int(binary.LittleEndian.Uint16(data[off+32:]))
		e.IntAttr = binary.LittleEndian.Uint16(data[off+36:])
		e.ExtAttr = binary.LittleEndian.Uint32(data[off+38:])
		lho := int(binary.LittleEndian.Uint32(data[off+42:]))

		if off+centralHeaderLen+nameLen+extraLen+cmtLen > len(data) {
			return nil, fmt.Errorf("%w: 第 %d 个中央目录项可变长字段越界", ErrCorrupt, i)
		}
		p := off + centralHeaderLen
		e.Name = append([]byte(nil), data[p:p+nameLen]...)
		p += nameLen
		e.CentralExtra = append([]byte(nil), data[p:p+extraLen]...)
		p += extraLen
		if cmtLen > 0 {
			e.Comment = append([]byte(nil), data[p:p+cmtLen]...)
		}

		// 定位本地头，取出压缩数据。
		if lho < 0 || lho+localHeaderLen > len(data) {
			return nil, fmt.Errorf("%w: 条目 %q 本地头偏移非法 (%d)", ErrCorrupt, e.Name, lho)
		}
		if binary.LittleEndian.Uint32(data[lho:]) != sigLocal {
			return nil, fmt.Errorf("%w: 条目 %q 本地头签名错误", ErrCorrupt, e.Name)
		}
		lnlen := int(binary.LittleEndian.Uint16(data[lho+26:]))
		lelen := int(binary.LittleEndian.Uint16(data[lho+28:]))
		e.LocalExtra = append([]byte(nil), data[lho+localHeaderLen+lnlen:lho+localHeaderLen+lnlen+lelen]...)

		dataStart := lho + localHeaderLen + lnlen + lelen
		dataEnd := dataStart + int(e.CompSize)
		if dataEnd > len(data) {
			return nil, fmt.Errorf("%w: 条目 %q 数据越界", ErrCorrupt, e.Name)
		}
		e.Raw = append([]byte(nil), data[dataStart:dataEnd]...)

		a.Entries = append(a.Entries, e)
		off += centralHeaderLen + nameLen + extraLen + cmtLen
	}
	return a, nil
}

// Find 按名字返回第一个匹配的条目，未找到返回 nil。
func (a *Archive) Find(name string) *Entry {
	for _, e := range a.Entries {
		if string(e.Name) == name {
			return e
		}
	}
	return nil
}

// Remove 删除所有指定名字的条目，返回删除数量。
func (a *Archive) Remove(names ...string) int {
	drop := make(map[string]bool, len(names))
	for _, n := range names {
		drop[n] = true
	}
	kept := a.Entries[:0]
	n := 0
	for _, e := range a.Entries {
		if drop[string(e.Name)] {
			n++
			continue
		}
		kept = append(kept, e)
	}
	a.Entries = kept
	return n
}
