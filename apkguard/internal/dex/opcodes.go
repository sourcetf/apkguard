package dex

import (
	"encoding/binary"
	"fmt"
)

// refKind 表示指令操作数引用哪一类索引池。
type refKind uint8

const (
	refNone refKind = iota
	refString
	refType
	refField
	refMethod
	refProto
)

// insnRef 描述一条指令中池引用的位置。
type insnRef struct {
	kind refKind
	// word 是引用索引所在的字偏移（相对指令起始）。
	word int
	// wide 表示索引占 32 位（占两个字）。
	wide bool
}

// insnWidths 是 Dalvik 全部 256 个操作码的指令字长表。
//
// 数据依据 Android 官方 Dalvik 字节码格式表逐条整理，
// 未使用的操作码按 1 字长处理（它们不应出现在合法 DEX 中）。
var insnWidths = [256]uint8{
	// 0x00 nop .. 0x0f return
	1, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 1, 1, 1, 1, 1,
	// 0x10 return-wide .. 0x1f check-cast
	1, 1, 1, 2, 3, 2, 2, 3, 5, 2, 2, 3, 2, 1, 1, 2,
	// 0x20 instance-of .. 0x2f cmpl-double
	2, 1, 2, 2, 3, 3, 3, 1, 1, 2, 3, 3, 3, 2, 2, 2,
	// 0x30 cmpg-double .. 0x3f unused
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1,
	// 0x40 unused .. 0x4f aput-byte
	1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	// 0x50 aput-char .. 0x5f iput-short
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	// 0x60 sget .. 0x6f invoke-super
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3,
	// 0x70 invoke-direct .. 0x7f unused
	3, 3, 3, 1, 3, 3, 3, 3, 3, 1, 1, 1, 1, 1, 1, 1,
	// 0x80-0x8f unused
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	// 0x90 add-int .. 0x9f rem-double
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	// 0xa0 add-int/lit16 .. 0xaf ushr-long
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	// 0xb0 add-int/2addr .. 0xbf xor-long/2addr
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	// 0xc0 shl-long/2addr .. 0xcf ushr-int
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	// 0xd0 add-int/lit8 .. 0xdf ushr-int/lit8
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	// 0xe0 shl-int/lit8, 0xe1 shr-int/lit8, 0xe2 ushr-int/lit8（均 22b，2 字）；
	// 0xe3-0xef 为未使用操作码
	2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	// 0xf0-0xf9 unused；0xfa/0xfb invoke-polymorphic；0xfc/0xfd invoke-custom；
	// 0xfe const-method-handle；0xff const-method-type
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 4, 4, 3, 3, 2, 2,
}

// insnRefs 记录含池引用的指令。未列出的操作码一律视为无引用。
//
// 注意：
//   - invoke-custom 系列引用的是 call_site_ids，const-method-handle 引用
//     method_handles——这两类索引在本工具中不发生重排，因此不做处理。
//   - fill-array-data（0x26）是格式 31t，其 word1-2 是**相对偏移**而非类型索引，
//     误当作池引用会把分支目标改写成池索引，因此绝不能登记在此表中。
var insnRefs = map[byte]insnRef{
	0x1a: {kind: refString, word: 1},             // const-string
	0x1b: {kind: refString, word: 1, wide: true}, // const-string/jumbo
	0x1c: {kind: refType, word: 1},               // const-class
	0x1f: {kind: refType, word: 1},               // check-cast
	0x20: {kind: refType, word: 1},               // instance-of
	0x22: {kind: refType, word: 1},               // new-instance
	0x23: {kind: refType, word: 1},               // new-array
	0x24: {kind: refType, word: 1},               // filled-new-array/range
	0x25: {kind: refType, word: 1},               // filled-new-array
	0x52: {kind: refField, word: 1},              // iget
	0x53: {kind: refField, word: 1},              // iget-wide
	0x54: {kind: refField, word: 1},              // iget-object
	0x55: {kind: refField, word: 1},              // iget-boolean
	0x56: {kind: refField, word: 1},              // iget-byte
	0x57: {kind: refField, word: 1},              // iget-char
	0x58: {kind: refField, word: 1},              // iget-short
	0x59: {kind: refField, word: 1},              // iput
	0x5a: {kind: refField, word: 1},              // iput-wide
	0x5b: {kind: refField, word: 1},              // iput-object
	0x5c: {kind: refField, word: 1},              // iput-boolean
	0x5d: {kind: refField, word: 1},              // iput-byte
	0x5e: {kind: refField, word: 1},              // iput-char
	0x5f: {kind: refField, word: 1},              // iput-short
	0x60: {kind: refField, word: 1},              // sget
	0x61: {kind: refField, word: 1},              // sget-wide
	0x62: {kind: refField, word: 1},              // sget-object
	0x63: {kind: refField, word: 1},              // sget-boolean
	0x64: {kind: refField, word: 1},              // sget-byte
	0x65: {kind: refField, word: 1},              // sget-char
	0x66: {kind: refField, word: 1},              // sget-short
	0x67: {kind: refField, word: 1},              // sput
	0x68: {kind: refField, word: 1},              // sput-wide
	0x69: {kind: refField, word: 1},              // sput-object
	0x6a: {kind: refField, word: 1},              // sput-boolean
	0x6b: {kind: refField, word: 1},              // sput-byte
	0x6c: {kind: refField, word: 1},              // sput-char
	0x6d: {kind: refField, word: 1},              // sput-short
	0x6e: {kind: refMethod, word: 1},             // invoke-virtual
	0x6f: {kind: refMethod, word: 1},             // invoke-super
	0x70: {kind: refMethod, word: 1},             // invoke-direct
	0x71: {kind: refMethod, word: 1},             // invoke-static
	0x72: {kind: refMethod, word: 1},             // invoke-interface
	0x74: {kind: refMethod, word: 1},             // invoke-virtual/range
	0x75: {kind: refMethod, word: 1},             // invoke-super/range
	0x76: {kind: refMethod, word: 1},             // invoke-direct/range
	0x77: {kind: refMethod, word: 1},             // invoke-static/range
	0x78: {kind: refMethod, word: 1},             // invoke-interface/range
	0xff: {kind: refProto, word: 1},              // const-method-type
}

// protoRefInsns 记录「除主引用外还额外引用 proto_ids」的指令。
//
// invoke-polymorphic 的格式为 45cc / 4rcc：
// 主方法引用在 word 1，proto 引用在 word 3。
var protoRefInsns = map[byte]int{
	0xfa: 3, // invoke-polymorphic
	0xfb: 3, // invoke-polymorphic/range
}

// insnWidth 返回指令字长。
func insnWidth(words []uint16, pos int) (int, error) {
	if pos >= len(words) {
		return 0, fmt.Errorf("%w: 指令位置越界 %d/%d", ErrTruncated, pos, len(words))
	}
	op := byte(words[pos] & 0xff)
	w := int(insnWidths[op])
	if pos+w > len(words) {
		return 0, fmt.Errorf("%w: 指令 0x%02x 操作数越界 @word %d (需要 %d 字)",
			ErrTruncated, op, pos, w)
	}
	return w, nil
}

// payload 相关的伪指令标识（出现在指令流中的 ushort 值）。
const (
	payloadPackedSwitch = 0x0100
	payloadSparseSwitch = 0x0200
	payloadFillArray    = 0x0300
)

// branchInsns 记录「分支目标可能是 payload」的指令，值为偏移量所在的字偏移。
//
// 这三条指令的格式均为 31t：操作码+AA 在 word 0，32 位相对偏移在 word 1-2。
var branchInsns = map[byte]int{
	0x26: 1, // fill-array-data
	0x2b: 1, // packed-switch
	0x2c: 1, // sparse-switch
}

// payloadWidth 返回位于 pos 处的 payload 占用的字长。
//
// 依据 Dalvik 规范，payload 以 ushort 标识开头，且必须 4 字节对齐。
func payloadWidth(words []uint16, pos int) (int, bool, error) {
	if pos+1 >= len(words) {
		return 0, false, nil
	}
	ident := words[pos]
	switch ident {
	case payloadPackedSwitch:
		// 布局：ident(1) + size(1) + first_key(2) + targets(2*size)
		size := int(words[pos+1])
		return 4 + size*2, true, nil
	case payloadSparseSwitch:
		// 布局：ident(1) + size(1) + keys(2*size) + targets(2*size)
		size := int(words[pos+1])
		return 2 + size*4, true, nil
	case payloadFillArray:
		if pos+3 >= len(words) {
			return 0, false, ErrTruncated
		}
		elemWidth := int(words[pos+1])
		size := int(words[pos+2]) | int(words[pos+3])<<16
		if elemWidth <= 0 {
			return 0, false, fmt.Errorf("dex: fill-array-data-payload 的 element_width 为 0")
		}
		bytes := size * elemWidth
		// 头部 4 字 + 数据（按字对齐向上取整）
		return 4 + (bytes+1)/2, true, nil
	default:
		return 0, false, nil
	}
}

// remapCode 就地重映射 code_item 中所有池引用。
//
// 需要注意：switch / fill-array-data 的 payload 以伪指令形式内联在指令流中，
// 线性遍历时必须识别并整体跳过，否则会因错位而误读后续指令。
//
// skip 给出「已经是新索引、不可再映射」的字位置（A2 替换 const-string 时写入
// 的密文与解密方法索引）。为 nil 时表示不做任何跳过。
func (b *builder) remapCode(buf []byte, skip map[int]bool) ([]byte, error) {
	ci, err := ParseCodeItemBytes(buf)
	if err != nil {
		return nil, err
	}
	insnsSize := binary.LittleEndian.Uint32(buf[12:])
	words := make([]uint16, insnsSize)
	for i := uint32(0); i < insnsSize; i++ {
		words[i] = binary.LittleEndian.Uint16(buf[16+2*i:])
	}
	putWord := func(pos int, v uint16) { binary.LittleEndian.PutUint16(buf[16+2*pos:], v) }

	// 已知的 payload 起始位置：由前向遍历中遇到的分支指令推导。
	payloadAt := map[int]bool{}

	pos := 0
	for pos < len(words) {
		// 命中 payload：整体跳过
		if payloadAt[pos] {
			w, ok, perr := payloadWidth(words, pos)
			if perr != nil {
				return nil, perr
			}
			if !ok {
				return nil, fmt.Errorf("dex: word %d 处标记为 payload 但标识不匹配 (0x%04x)",
					pos, words[pos])
			}
			if pos+w > len(words) {
				return nil, fmt.Errorf("%w: payload @word %d 越界 (需要 %d 字，剩余 %d)",
					ErrTruncated, pos, w, len(words)-pos)
			}
			pos += w
			continue
		}

		op := byte(words[pos] & 0xff)
		w, werr := insnWidth(words, pos)
		if werr != nil {
			return nil, werr
		}

		if ref, ok := insnRefs[op]; ok && !skip[pos+ref.word] {
			var oldIdx uint32
			if ref.wide {
				oldIdx = uint32(words[pos+ref.word]) | uint32(words[pos+ref.word+1])<<16
			} else {
				oldIdx = uint32(words[pos+ref.word])
			}
			newIdx, merr := b.mapRef(ref.kind, oldIdx)
			if merr != nil {
				return nil, fmt.Errorf("dex: 指令 0x%02x @word %d: %w", op, pos, merr)
			}
			if ref.wide {
				putWord(pos+ref.word, uint16(newIdx&0xffff))
				putWord(pos+ref.word+1, uint16(newIdx>>16))
			} else {
				if newIdx > 0xffff {
					return nil, fmt.Errorf("dex: 指令 0x%02x @word %d 引用索引 %d 超出 16 位，需要指令加宽",
						op, pos, newIdx)
				}
				putWord(pos+ref.word, uint16(newIdx))
			}
		}

		if pw, ok := protoRefInsns[op]; ok {
			oldProto := uint32(words[pos+pw])
			newProto, perr := b.mapRef(refProto, oldProto)
			if perr != nil {
				return nil, fmt.Errorf("dex: 指令 0x%02x @word %d 的 proto 引用: %w", op, pos, perr)
			}
			if newProto > 0xffff {
				return nil, fmt.Errorf("dex: 指令 0x%02x 的 proto 索引 %d 超出 16 位", op, newProto)
			}
			putWord(pos+pw, uint16(newProto))
		}

		// 记录分支目标，供后续识别 payload
		if offWord, ok := branchInsns[op]; ok {
			rel := int32(uint32(words[pos+offWord]) | uint32(words[pos+offWord+1])<<16)
			target := pos + int(rel)
			if target >= 0 && target < len(words) {
				payloadAt[target] = true
			}
		}

		pos += w
	}
	// 异常处理器的 catch_type_idx 也要重映射。
	//
	// 它指向 type_ids，而 A1 改名会重排 type_ids；漏掉这一步，处理器就会
	// 去捕获一个**错误的类**，ART 判
	//   "unexpected non-exception class Reference: <某无关类>"
	// 并拒绝整个类（真实案例：RustDesk 加固后 w.g 类的 g() 方法被拒）。
	//
	// 这里不能在原缓冲区里原地改：类型索引是 ULEB128，长度可能变化，
	// 会顶掉后面的字节。因此改为按 code_item 整体域重编码——
	// 顺带也让 Encode 重算 handler_off（它的列表长度同样可能变化）。
	if len(ci.Handlers) == 0 {
		return buf, nil
	}
	needRemap := false
	for k := range ci.Handlers {
		if len(ci.Handlers[k].Types) > 0 {
			needRemap = true
			break
		}
	}
	if !needRemap {
		return buf, nil
	}
	// 指令重映射是写进 buf 的（见 putWord），因此必须从 buf 回读一遍，
	// 否则 Encode 会用上面那份**未重映射**的副本覆盖掉改动。
	for i := uint32(0); i < insnsSize; i++ {
		words[i] = binary.LittleEndian.Uint16(buf[16+2*i:])
	}
	ci.Insns = words
	for k := range ci.Handlers {
		for j := range ci.Handlers[k].Types {
			ni, err := b.mapRef(refType, ci.Handlers[k].Types[j])
			if err != nil {
				return nil, fmt.Errorf("dex: 异常处理器类型引用: %w", err)
			}
			ci.Handlers[k].Types[j] = ni
		}
	}
	return ci.Encode(nil), nil
}

// mapRef 把某一类旧索引映射为新索引。
func (b *builder) mapRef(kind refKind, idx uint32) (uint32, error) {
	var tbl []uint32
	var name string
	switch kind {
	case refString:
		tbl, name = b.R.String, "string"
	case refType:
		tbl, name = b.R.Type, "type"
	case refField:
		tbl, name = b.R.Field, "field"
	case refMethod:
		tbl, name = b.R.Method, "method"
	case refProto:
		tbl, name = b.R.Proto, "proto"
	default:
		return idx, nil
	}
	if int(idx) >= len(tbl) {
		return 0, fmt.Errorf("dex: %s 索引越界 %d/%d", name, idx, len(tbl))
	}
	return tbl[idx], nil
}
