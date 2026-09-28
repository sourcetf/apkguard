// Package dex 提供 DEX（Dalvik Executable）文件的解析与重建能力。
//
// 设计目标：完整保留原文件的语义（调试信息、注解、静态值、类数据），
// 并支持在重建时插入新字符串、替换方法体、重排索引。
package dex

import (
	"errors"
	"fmt"
	"unicode/utf8"
)

var (
	ErrNotDex     = errors.New("dex: 不是合法的 DEX 文件")
	ErrTruncated  = errors.New("dex: 数据被截断")
	ErrBadLEB128  = errors.New("dex: LEB128 编码非法")
	ErrBadMUTF8   = errors.New("dex: MUTF-8 编码非法")
	ErrTooManyLEB = errors.New("dex: LEB128 长度超过 5 字节")
	// ErrBadLayout 表示段的尺寸与偏移自相矛盾（例如 size 为 0 却给了非 0 偏移）。
	// ART 的校验器同样会拒绝这类文件，因此必须在本地就拦下。
	ErrBadLayout = errors.New("dex: 段布局非法")
)

// ---- LEB128 ----

// ULEB128 从 data[off:] 解码一个无符号 LEB128，返回值与新偏移。
func ULEB128(data []byte, off int) (uint32, int, error) {
	var result uint32
	var shift uint
	for i := 0; i < 5; i++ {
		if off+i >= len(data) {
			return 0, off, ErrTruncated
		}
		b := data[off+i]
		result |= uint32(b&0x7f) << shift
		if b&0x80 == 0 {
			return result, off + i + 1, nil
		}
		shift += 7
	}
	return 0, off, ErrTooManyLEB
}

// SLEB128 从 data[off:] 解码一个有符号 LEB128，返回值与新偏移。
func SLEB128(data []byte, off int) (int32, int, error) {
	var result int32
	var shift uint
	for i := 0; i < 5; i++ {
		if off+i >= len(data) {
			return 0, off, ErrTruncated
		}
		b := data[off+i]
		result |= int32(b&0x7f) << shift
		shift += 7
		if b&0x80 == 0 {
			if shift < 32 && b&0x40 != 0 {
				result |= -1 << shift
			}
			return result, off + i + 1, nil
		}
	}
	return 0, off, ErrTooManyLEB
}

// PutULEB128 把 v 编码为无符号 LEB128 并追加到 dst。
func PutULEB128(dst []byte, v uint32) []byte {
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			dst = append(dst, b|0x80)
			continue
		}
		return append(dst, b)
	}
}

// PutSLEB128 把 v 编码为有符号 LEB128 并追加到 dst。
func PutSLEB128(dst []byte, v int32) []byte {
	for {
		b := byte(v & 0x7f)
		v >>= 7
		// 若剩余位全为符号位延伸且当前符号位正确，则结束。
		if (v == 0 && b&0x40 == 0) || (v == -1 && b&0x40 != 0) {
			return append(dst, b)
		}
		dst = append(dst, b|0x80)
	}
}

// ---- MUTF-8 ----

// DecodeMUTF8 解码 DEX 使用的 Modified UTF-8 字符串（不含结尾 0）。
func DecodeMUTF8(data []byte) (string, error) {
	// 快速路径：纯 ASCII 且无 0 字节。
	ascii := true
	for _, b := range data {
		if b == 0 || b >= 0x80 {
			ascii = false
			break
		}
	}
	if ascii {
		return string(data), nil
	}

	var out []rune
	for i := 0; i < len(data); {
		b := data[i]
		switch {
		case b == 0:
			return "", ErrBadMUTF8
		case b < 0x80:
			out = append(out, rune(b))
			i++
		case b&0xe0 == 0xc0:
			if i+1 >= len(data) {
				return "", ErrBadMUTF8
			}
			out = append(out, rune(b&0x1f)<<6|rune(data[i+1]&0x3f))
			i += 2
		case b&0xf0 == 0xe0:
			if i+2 >= len(data) {
				return "", ErrBadMUTF8
			}
			r := rune(b&0x0f)<<12 | rune(data[i+1]&0x3f)<<6 | rune(data[i+2]&0x3f)
			i += 3
			// MUTF-8 用 UTF-16 代理对表示补充平面字符，需要合并。
			if r >= 0xd800 && r <= 0xdbff && i+2 < len(data) {
				if hi, lo := data[i], data[i+1]; hi&0xf0 == 0xe0 && lo&0xc0 == 0x80 {
					low := rune(hi&0x0f)<<12 | rune(lo&0x3f)<<6 | rune(data[i+2]&0x3f)
					if low >= 0xdc00 && low <= 0xdfff {
						r = 0x10000 + (r-0xd800)<<10 + (low - 0xdc00)
						i += 3
					}
				}
			}
			out = append(out, r)
		default:
			return "", ErrBadMUTF8
		}
	}
	return string(out), nil
}

// EncodeMUTF8 把字符串编码为 DEX 使用的 Modified UTF-8（含结尾 0 字节）。
func EncodeMUTF8(s string) []byte {
	out := make([]byte, 0, len(s)+1)
	for _, r := range s {
		switch {
		case r == 0:
			// MUTF-8 中 0 用双字节表示
			out = append(out, 0xc0, 0x80)
		case r < 0x80:
			out = append(out, byte(r))
		case r < 0x800:
			out = append(out, 0xc0|byte(r>>6), 0x80|byte(r&0x3f))
		case r < 0x10000:
			out = append(out, 0xe0|byte(r>>12), 0x80|byte((r>>6)&0x3f), 0x80|byte(r&0x3f))
		default:
			// 补充平面按 UTF-16 代理对拆成两个三字节序列
			r -= 0x10000
			hi := 0xd800 + (r >> 10)
			lo := 0xdc00 + (r & 0x3ff)
			for _, u := range []rune{hi, lo} {
				out = append(out, 0xe0|byte(u>>12), 0x80|byte((u>>6)&0x3f), 0x80|byte(u&0x3f))
			}
		}
	}
	return append(out, 0)
}

// UTF16Len 返回字符串按 UTF-16 编码后的码元数量（DEX string_data 的头部字段）。
func UTF16Len(s string) int {
	n := 0
	for _, r := range s {
		if r >= 0x10000 {
			n += 2
		} else {
			n++
		}
	}
	return n
}

// ValidUTF8 判断字符串是否为合法 UTF-8，便于早期拒绝异常输入。
func ValidUTF8(s string) bool { return utf8.ValidString(s) }

// CompareUTF16 按 DEX 规范要求比较两个字符串：以 UTF-16 码元为单位的字典序。
//
// 注意这与 Go 的字节序比较不同：补充平面字符（如 emoji）在 UTF-16 中
// 表示为 0xd800-0xdfff 区间的代理对，而 UTF-8 编码的首字节是 0xf0 开头，
// 两种顺序在某些字符组合下会得出相反结果。
func CompareUTF16(a, b string) int {
	// 快速路径：两者均为 BMP 且不含代理区字符时，字节序等价于码元序。
	if isBMPFast(a) && isBMPFast(b) {
		switch {
		case a < b:
			return -1
		case a > b:
			return 1
		}
		return 0
	}
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

// isBMPFast 判断字符串是否只含基本多文种平面字符（不含代理区）。
func isBMPFast(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			for _, r := range s {
				if r >= 0xd800 && r <= 0xdfff || r >= 0x10000 {
					return false
				}
			}
			return true
		}
	}
	return true
}

// utf16Units 把字符串展开为 UTF-16 码元序列。
func utf16Units(s string) []uint16 {
	out := make([]uint16, 0, len(s))
	for _, r := range s {
		if r < 0x10000 {
			out = append(out, uint16(r))
			continue
		}
		r -= 0x10000
		out = append(out, uint16(0xd800+(r>>10)), uint16(0xdc00+(r&0x3ff)))
	}
	return out
}

// ---- 通用小工具 ----

func u16(b []byte, off int) (uint16, error) {
	if off+2 > len(b) {
		return 0, fmt.Errorf("%w: u16@%d", ErrTruncated, off)
	}
	return uint16(b[off]) | uint16(b[off+1])<<8, nil
}

func u32(b []byte, off int) (uint32, error) {
	if off+4 > len(b) {
		return 0, fmt.Errorf("%w: u32@%d", ErrTruncated, off)
	}
	return uint32(b[off]) | uint32(b[off+1])<<8 | uint32(b[off+2])<<16 | uint32(b[off+3])<<24, nil
}

func putU16(b []byte, off int, v uint16) {
	b[off] = byte(v)
	b[off+1] = byte(v >> 8)
}

func putU32(b []byte, off int, v uint32) {
	b[off] = byte(v)
	b[off+1] = byte(v >> 8)
	b[off+2] = byte(v >> 16)
	b[off+3] = byte(v >> 24)
}
