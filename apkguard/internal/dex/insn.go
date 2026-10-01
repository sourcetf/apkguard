package dex

import (
	"encoding/binary"
	"fmt"
)

// ---- 完整 code_item 解析 ----

// TryItem 是一条 try 记录。
type TryItem struct {
	StartAddr  uint32
	InsnCount  uint16
	HandlerOff uint16
}

// CatchHandler 是一个 encoded_catch_handler。
//
// Types 与 Addrs 一一对应；CatchAll 为 true 时存在 catch_all_addr。
type CatchHandler struct {
	Types    []uint32
	Addrs    []uint32
	CatchAll bool
	AllAddr  uint32
}

// CodeItemFull 是完整解析后的 code_item（含异常表与 catch handler）。
type CodeItemFull struct {
	Registers    uint16
	Ins          uint16
	Outs         uint16
	DebugInfoOff uint32
	Insns        []uint16
	Tries        []TryItem
	Handlers     []CatchHandler
	// HandlerOffs 是每个处理器**在原始字节流中**的起始偏移（与 try_item 的
	// handler_off 同一基准：相对 encoded_catch_handler_list 的 size 字段起）。
	//
	// 为什么必须记录下来：读回内存的 handler 里存的是**类型索引**，而重命名会
	// 改写这些索引；索引跨过 ULEB128 的 1→2 字节边界时任一处长度变化都会让后续
	// 处理器整体后移。此时若「用内存里的 handler 重新编码一遍」来推算旧偏移，
	// 得到的并不是文件里的真实偏移，映射查不到就静默沿用旧值，产物直接非法。
	// 记录解析时的真实偏移后，映射的键始终是文件事实。
	HandlerOffs []uint16
}

// ParseCodeItem 完整解析一个 code_item。
func (f *File) ParseCodeItem(off uint32) (*CodeItemFull, error) {
	d := f.data
	if int(off) > len(d) {
		return nil, fmt.Errorf("%w: code_item 越界 @%d", ErrTruncated, off)
	}
	return ParseCodeItemBytes(d[off:])
}

// ParseCodeItemBytes 从一段以 code_item 起始的字节中完整解析。
//
// 与 ParseCodeItem 的区别：本函数不依赖文件偏移，因此可用于解析
// 「已被 A2/A3 改写、尚未写回文件」的中间态 code_item 字节流。
func ParseCodeItemBytes(d []byte) (*CodeItemFull, error) {
	if len(d) < 16 {
		return nil, fmt.Errorf("%w: code_item 头部不足 16 字节", ErrTruncated)
	}
	ci := &CodeItemFull{
		Registers:    binary.LittleEndian.Uint16(d[0:]),
		Ins:          binary.LittleEndian.Uint16(d[2:]),
		Outs:         binary.LittleEndian.Uint16(d[4:]),
		DebugInfoOff: binary.LittleEndian.Uint32(d[8:]),
	}
	insnsSize := binary.LittleEndian.Uint32(d[12:])
	triesSize := binary.LittleEndian.Uint16(d[6:])
	if 16+int(insnsSize)*2 > len(d) {
		return nil, fmt.Errorf("%w: 字节码越界（需要 %d 字节，实际 %d）",
			ErrTruncated, 16+int(insnsSize)*2, len(d))
	}
	ci.Insns = make([]uint16, insnsSize)
	for i := uint32(0); i < insnsSize; i++ {
		ci.Insns[i] = binary.LittleEndian.Uint16(d[16+2*int(i):])
	}

	p := 16 + int(insnsSize)*2
	if triesSize > 0 {
		// tries 数组前需 4 字节对齐
		if insnsSize&1 != 0 {
			p += 2
		}
		for i := uint16(0); i < triesSize; i++ {
			if p+8 > len(d) {
				return nil, fmt.Errorf("%w: try_item 越界", ErrTruncated)
			}
			ci.Tries = append(ci.Tries, TryItem{
				StartAddr:  binary.LittleEndian.Uint32(d[p:]),
				InsnCount:  binary.LittleEndian.Uint16(d[p+4:]),
				HandlerOff: binary.LittleEndian.Uint16(d[p+6:]),
			})
			p += 8
		}
		// encoded_catch_handler_list
		listStart := p
		handlersSize, np, err := ULEB128(d, p)
		if err != nil {
			return nil, err
		}
		p = np
		for i := uint32(0); i < handlersSize; i++ {
			// 记录该处理器在列表内的真实起始偏移（handler_off 的基准）。
			if p-listStart > 0xffff {
				return nil, fmt.Errorf("%w: 处理器列表超过 65535 字节，handler_off 无法表示", ErrBadLayout)
			}
			ci.HandlerOffs = append(ci.HandlerOffs, uint16(p-listStart))
			var size int32
			size, p, err = SLEB128(d, p)
			if err != nil {
				return nil, err
			}
			h := CatchHandler{}
			n := size
			if n < 0 {
				n = -n
			}
			for k := int32(0); k < n; k++ {
				var t, a uint32
				if t, p, err = ULEB128(d, p); err != nil {
					return nil, err
				}
				if a, p, err = ULEB128(d, p); err != nil {
					return nil, err
				}
				h.Types = append(h.Types, t)
				h.Addrs = append(h.Addrs, a)
			}
			if size <= 0 {
				var a uint32
				if a, p, err = ULEB128(d, p); err != nil {
					return nil, err
				}
				h.CatchAll = true
				h.AllAddr = a
			}
			ci.Handlers = append(ci.Handlers, h)
		}
	}
	return ci, nil
}

// Encode 把 code_item 编码为字节流。
//
// 传入的 addrFix 用于修正 try 与 catch handler 中的代码偏移；
// 为 nil 时按原值输出。
func (ci *CodeItemFull) Encode(addrFix func(old uint32) uint32) []byte {
	fix := func(v uint32) uint32 {
		if addrFix == nil {
			return v
		}
		return addrFix(v)
	}
	out := make([]byte, 16+len(ci.Insns)*2)
	binary.LittleEndian.PutUint16(out[0:], ci.Registers)
	binary.LittleEndian.PutUint16(out[2:], ci.Ins)
	binary.LittleEndian.PutUint16(out[4:], ci.Outs)
	binary.LittleEndian.PutUint16(out[6:], uint16(len(ci.Tries)))
	binary.LittleEndian.PutUint32(out[8:], ci.DebugInfoOff)
	binary.LittleEndian.PutUint32(out[12:], uint32(len(ci.Insns)))
	for i, w := range ci.Insns {
		binary.LittleEndian.PutUint16(out[16+2*i:], w)
	}
	if len(ci.Tries) == 0 {
		return out
	}
	// tries 前需 4 字节对齐
	if len(ci.Insns)&1 != 0 {
		out = append(out, 0, 0)
	}
	// handler_off 是「相对异常处理器列表起点的**字节**偏移」，必须重新计算。
	//
	// 它不能像普通代码地址那样直接沿用旧值：处理器的目标地址在改写后会变大，
	// 而 ULEB128 的编码长度随数值增长（1 字节可涨到 3 字节），于是后续处理器
	// 在列表中的字节位置整体后移。沿用旧偏移会让某些 try_item 指向列表中间
	// 甚至越界，ART 的结构校验器直接判
	//   "Failure to verify dex file: Bogus handler offset: N"
	// 并**丢弃整个 DEX**——表现就是 DexPathList 为空、业务类全部找不到
	// （ClassNotFoundException），而 dex2oat 的 verify 模式并不报错，
	// 因此本地极难发现。
	//
	// 做法：先确定「旧偏移 -> 新偏移」的映射，再改写 try_item 的 handler_off。
	//
	// 旧偏移必须取自**解析时记录的真实值**（ci.HandlerOffs）。早期实现是
	// 「用内存里的 handler 再编码一遍」来推算旧偏移，这在类型索引因改名而跨过
	// ULEB128 的 1→2 字节边界时是错的：那时内存里已是新索引，重编码得到的布局
	// 不是文件里的布局，映射键对不上，代码就静默沿用旧偏移——产物被 ART 判
	//   "Failure to verify dex file: Bogus handler offset: N"
	// 并整个 DEX 被丢弃（表现同样是 ClassNotFoundException）。
	// 索引小的应用（如我们的测试应用）永远碰不到这个边界，所以此前没暴露。
	var oldOffs []uint16
	if len(ci.HandlerOffs) == len(ci.Handlers) {
		oldOffs = ci.HandlerOffs
	} else {
		// 自建 code_item（注入类）没有原始字节，此时 handler 索引从未被改写，
		// 恒等重编码得到的偏移就是真值。
		_, offs := encodeHandlerList(ci.Handlers, func(v uint32) uint32 { return v })
		oldOffs = make([]uint16, len(offs))
		for i, o := range offs {
			oldOffs[i] = uint16(o)
		}
	}
	newHandlers, newOffs := encodeHandlerList(ci.Handlers, fix)
	remap := make(map[uint32]uint32, len(oldOffs))
	for i := range oldOffs {
		remap[uint32(oldOffs[i])] = uint32(newOffs[i])
	}
	for _, t := range ci.Tries {
		s := fix(t.StartAddr)
		e := fix(t.StartAddr + uint32(t.InsnCount))
		cnt := uint16(0)
		if e > s {
			cnt = uint16(e - s)
		}
		ho := uint32(t.HandlerOff)
		if v, ok := remap[ho]; ok {
			ho = v
		} else if len(ci.HandlerOffs) == len(ci.Handlers) {
			// 记了旧偏移却查不到，说明上游把 handler 结构改坏了——
			// 绝不能静默沿用旧值，那会产出被 ART 丢弃的非法 DEX。
			panic(fmt.Sprintf("dex: try_item.handler_off=%d 不在处理器起始偏移中（code_item 结构已损坏）", ho))
		}
		var b [8]byte
		binary.LittleEndian.PutUint32(b[0:], s)
		binary.LittleEndian.PutUint16(b[4:], cnt)
		binary.LittleEndian.PutUint16(b[6:], uint16(ho))
		out = append(out, b[:]...)
	}
	out = append(out, newHandlers...)
	return out
}

// encodeHandlerList 编码 encoded_catch_handler_list，并返回每个处理器
// 在列表内的起始字节偏移（供 try_item 的 handler_off 使用）。
func encodeHandlerList(hs []CatchHandler, fix func(uint32) uint32) ([]byte, []int) {
	out := PutULEB128(nil, uint32(len(hs)))
	offs := make([]int, len(hs))
	for i := range hs {
		offs[i] = len(out)
		h := hs[i]
		size := int32(len(h.Types))
		if h.CatchAll {
			size = -size
		}
		out = PutSLEB128(out, size)
		for j, t := range h.Types {
			out = PutULEB128(out, t)
			out = PutULEB128(out, fix(h.Addrs[j]))
		}
		if h.CatchAll {
			out = PutULEB128(out, fix(h.AllAddr))
		}
	}
	return out, offs
}

// ---- 可编辑指令流 ----

// 指令项类型。
const (
	itemInsn          = 0
	itemPackedSwitch  = 1
	itemSparseSwitch  = 2
	itemFillArrayData = 3
)

// insnItem 是指令流中的一项（普通指令或 payload）。
type insnItem struct {
	words []uint16
	kind  byte
	// old 是该项在原指令流中的起始字偏移。
	old int
	// pad 为 true 表示编码时需在其前面插入一个 nop 以满足 4 字节对齐。
	pad bool
	// new 是编码后的起始字偏移。
	new int
	// fresh 是「已写成最终索引、不可再被 remapCode 映射」的字偏移列表
	// （相对本项起始）。A2/A3 改写常量时使用。
	//
	// 用「项内相对偏移」而不是「指令流绝对偏移」记录，是因为后续的
	// 改写步骤会改变整体布局；标记随项移动，最终编码时才换算为绝对位置，
	// 从而保证多个改写步骤可以安全串行。
	fresh []int
}

// InsnList 是一条可编辑的指令流。
//
// 编辑只允许「插入」与「替换单条指令」，不支持删除：这样每个原指令项都能
// 保留旧偏移，从而为分支重定位提供稳定的锚点。
type InsnList struct {
	// payloadOwner 记录「switch payload 项下标 -> 引用它的 switch 指令项下标」。
	//
	// 必须建立这个对应关系：DEX 规范规定 switch payload 里的 target
	// 是**相对 switch 指令**的偏移（不是相对 payload 自身）。改写后指令位置
	// 变化，若不按「相对 switch 指令」重算，ART 会报
	//   "invalid switch target"
	// 并拒绝整个类（真实案例：RustDesk 加固后 androidx.lifecycle.g$a 被拒）。
	payloadOwner map[int]int
	items        []*insnItem
	// branches 记录全部分支指令：项下标 + 项内字偏移 + 目标旧字偏移。
	branches []branchRef
	// total 是原指令流的字长度，用于把「流末尾」也纳入偏移映射，
	// 这样异常表的区间端点（start+count）才能被正确修正。
	total int
	// synth 是已追加的合成项数量，用于为它们分配互不冲突的合成旧偏移。
	synth int
}

type branchRef struct {
	item int // 分支指令所在项
	word int // 项内字偏移：存放相对偏移的位置
	// base 是项内「分支指令自身」的起始字偏移，相对偏移即以此为准。
	//
	// 对常规指令，指令就是整项，base 为 0；
	// 对 A3 生成的合成项（一条 const-string 被展开成多条指令），
	// fill-array-data 位于项内偏移 4，因此 base 必须为 4，
	// 否则算出的相对偏移会偏大 4，指向 payload 之后的垃圾数据。
	base int
	// target 是目标旧字偏移。
	//
	// 对指令内的分支（goto / if-* / switch / fill-array-data），
	// 偏移基准是指令自身；对 switch payload 内的 target 表项，
	// 基准是 payload 自身。两者在 branchRef 里已统一换算为绝对旧偏移。
	target int
	// form 是分支的编码格式，决定如何写回。
	form branchForm
}

// branchForm 是分支指令的编码格式。
type branchForm uint8

const (
	form10t     branchForm = iota // goto：偏移在 word 0 高字节（8 位）
	form20t                       // goto/16：偏移在 word 1（16 位）
	form30t                       // goto/32：偏移在 word 1-2（32 位）
	form22t                       // if-*：偏移在 word 1（16 位）
	form31t                       // fill-array-data / switch：偏移在 word 1-2（32 位）
	formPayload                   // switch payload 内的 target：偏移在 word/word+1（32 位）
)

// insnBranchForm 返回指令的分支格式；非分支指令返回 false。
func insnBranchForm(op byte) (branchForm, bool) {
	switch {
	case op == 0x28:
		return form10t, true
	case op == 0x29:
		return form20t, true
	case op == 0x2a:
		return form30t, true
	case op >= 0x32 && op <= 0x3d:
		return form22t, true
	case op == 0x26 || op == 0x2b || op == 0x2c:
		return form31t, true
	}
	return 0, false
}

// ParseInsns 把指令流解析为可编辑列表。
func ParseInsns(words []uint16) (*InsnList, error) {
	l := &InsnList{total: len(words)}
	payloadAt := map[int]bool{}

	// 第一遍：切分指令与 payload
	pos := 0
	for pos < len(words) {
		if payloadAt[pos] {
			kind, w, err := payloadKind(words, pos)
			if err != nil {
				return nil, err
			}
			if pos+w > len(words) {
				return nil, fmt.Errorf("%w: payload @word %d 越界", ErrTruncated, pos)
			}
			l.items = append(l.items, &insnItem{
				words: append([]uint16(nil), words[pos:pos+w]...),
				kind:  kind, old: pos,
			})
			pos += w
			continue
		}
		op := byte(words[pos] & 0xff)
		w := int(insnWidths[op])
		if w <= 0 || pos+w > len(words) {
			return nil, fmt.Errorf("%w: 指令 0x%02x @word %d 宽度非法", ErrTruncated, op, pos)
		}
		idx := len(l.items)
		l.items = append(l.items, &insnItem{
			words: append([]uint16(nil), words[pos:pos+w]...),
			kind:  itemInsn, old: pos,
		})
		if form, ok := insnBranchForm(op); ok {
			rel, err := readBranchRel(words, pos, form)
			if err != nil {
				return nil, err
			}
			target := pos + rel
			l.branches = append(l.branches, branchRef{
				item: idx, word: branchWord(form), target: target, form: form,
			})
			if form == form31t && target >= 0 && target < len(words) {
				payloadAt[target] = true
			}
		}
		pos += w
	}

	// 第二遍：解析 switch payload 内部的 target 表。
	//
	// 先建立「payload -> 引用它的 switch 指令」对应：payload 内的 target
	// 是相对 **switch 指令** 的偏移（DEX 规范），不是相对 payload 自身。
	l.payloadOwner = map[int]int{}
	oldToItem := map[int]int{}
	for i, it := range l.items {
		oldToItem[it.old] = i
	}
	for _, b := range l.branches {
		if b.form != form31t {
			continue
		}
		if pi, ok := oldToItem[b.target]; ok {
			if k := l.items[pi].kind; k == itemPackedSwitch || k == itemSparseSwitch {
				l.payloadOwner[pi] = b.item
			}
		}
	}
	for i, it := range l.items {
		if it.kind != itemPackedSwitch && it.kind != itemSparseSwitch {
			continue
		}
		// 基准地址：优先取 switch 指令的旧偏移；找不到归属时退回 payload 自身
		// （退化行为与历史一致，避免因个别畸形样本导致整体失败）。
		baseAddr := it.old
		if owner, ok := l.payloadOwner[i]; ok && owner >= 0 && owner < len(l.items) {
			baseAddr = l.items[owner].old
		}
		size := int(it.words[1])
		base := 4 // packed-switch 的 target 从 word 4 开始
		if it.kind == itemSparseSwitch {
			base = 2 + 2*size // sparse-switch 的 keys 在前
		}
		for k := 0; k < size; k++ {
			rel := int32(uint32(it.words[base+2*k]) | uint32(it.words[base+2*k+1])<<16)
			l.branches = append(l.branches, branchRef{
				item: i, word: base + 2*k, target: baseAddr + int(rel), form: formPayload,
			})
		}
	}
	return l, nil
}

// branchWord 返回分支偏移所在字的项内偏移。
func branchWord(f branchForm) int {
	switch f {
	case form10t:
		return 0
	default:
		return 1
	}
}

// readBranchRel 读取一条分支指令的相对偏移。
func readBranchRel(words []uint16, pos int, form branchForm) (int, error) {
	switch form {
	case form10t:
		return int(int8(words[pos] >> 8)), nil
	case form20t:
		if pos+1 >= len(words) {
			return 0, ErrTruncated
		}
		return int(int16(words[pos+1])), nil
	case form22t:
		if pos+1 >= len(words) {
			return 0, ErrTruncated
		}
		return int(int16(words[pos+1])), nil
	case form30t, form31t:
		if pos+2 >= len(words) {
			return 0, ErrTruncated
		}
		rel := int32(uint32(words[pos+1]) | uint32(words[pos+2])<<16)
		return int(rel), nil
	}
	return 0, fmt.Errorf("dex: 未知的分支格式 %d", form)
}

// payloadKind 判断 payload 的类型与字长。
func payloadKind(words []uint16, pos int) (byte, int, error) {
	if pos+1 >= len(words) {
		return 0, 0, fmt.Errorf("%w: payload @word %d 越界", ErrTruncated, pos)
	}
	switch words[pos] {
	case payloadPackedSwitch:
		size := int(words[pos+1])
		return itemPackedSwitch, 4 + size*2, nil
	case payloadSparseSwitch:
		size := int(words[pos+1])
		return itemSparseSwitch, 2 + size*4, nil
	case payloadFillArray:
		if pos+3 >= len(words) {
			return 0, 0, ErrTruncated
		}
		ew := int(words[pos+1])
		size := int(words[pos+2]) | int(words[pos+3])<<16
		if ew <= 0 {
			return 0, 0, fmt.Errorf("dex: fill-array-data-payload 的 element_width 为 0")
		}
		return itemFillArrayData, 4 + (size*ew+1)/2, nil
	}
	return 0, 0, fmt.Errorf("dex: word %d 处不是合法 payload (0x%04x)", pos, words[pos])
}

// ItemCount 返回指令项数量。
func (l *InsnList) ItemCount() int { return len(l.items) }

// ItemOldOffset 返回第 i 项的原始字偏移。
func (l *InsnList) ItemOldOffset(i int) int { return l.items[i].old }

// ItemWords 返回第 i 项的指令字（只读，请勿修改）。
func (l *InsnList) ItemWords(i int) []uint16 {
	if i < 0 || i >= len(l.items) {
		return nil
	}
	return l.items[i].words
}

// ItemIsInsn 判断第 i 项是否为普通指令（而非 switch / fill-array-data payload）。
func (l *InsnList) ItemIsInsn(i int) bool {
	return i >= 0 && i < len(l.items) && l.items[i].kind == itemInsn
}

// InsertBefore 在第 i 项之前插入若干条指令。
//
// 插入的指令会共享第 i 项的旧偏移，因此原分支若指向第 i 项，
// 重定位后仍指向「插入之后的第 i 项」，语义不变。
func (l *InsnList) InsertBefore(i int, insns ...[]uint16) {
	if i < 0 || i > len(l.items) {
		return
	}
	anchor := l.items[i].old
	var added []*insnItem
	for _, w := range insns {
		added = append(added, &insnItem{
			words: append([]uint16(nil), w...),
			kind:  itemInsn, old: anchor,
		})
	}
	// 已有分支指向第 i 项时，其项下标需要后移
	shift := len(added)
	for k := range l.branches {
		if l.branches[k].item >= i {
			l.branches[k].item += shift
		}
	}
	if l.payloadOwner != nil {
		moved := map[int]int{}
		for k, v := range l.payloadOwner {
			if k >= i {
				k += shift
			}
			if v >= i {
				v += shift
			}
			moved[k] = v
		}
		l.payloadOwner = moved
	}
	out := make([]*insnItem, 0, len(l.items)+shift)
	out = append(out, l.items[:i]...)
	out = append(out, added...)
	out = append(out, l.items[i:]...)
	l.items = out
}

// Replace 用新指令替换第 i 项（必须仍为单条指令，长度可不同）。
//
// fresh 给出新指令中「已写成最终索引、不可再映射」的项内字偏移。
func (l *InsnList) Replace(i int, words []uint16, fresh ...int) {
	if i < 0 || i >= len(l.items) {
		return
	}
	l.items[i].words = append([]uint16(nil), words...)
	l.items[i].kind = itemInsn
	l.items[i].fresh = append([]int(nil), fresh...)
}

// fillArrayPayload 构造一个 fill-array-data-payload 的指令字。
//
// 布局：ident(1) + element_width(1) + size(2) + data（按字打包，末尾补齐）。
func fillArrayPayload(data []byte) []uint16 {
	n := len(data)
	words := make([]uint16, 4+(n+1)/2)
	words[0] = payloadFillArray
	words[1] = 1 // element_width：按字节
	words[2] = uint16(n)
	words[3] = uint16(n >> 16)
	for i, b := range data {
		if i%2 == 0 {
			words[4+i/2] = uint16(b)
		} else {
			words[4+i/2] |= uint16(b) << 8
		}
	}
	return words
}

// ReplaceWithArrayData 把第 i 项（一条 const-string）替换为
// 「构造 byte[] 并调用还原方法」的指令序列，同时在流末尾追加 payload。
//
// 目标寄存器 vX 先当数组、随后被结果覆盖，因此不需要额外的临时寄存器。
// 各指令的字偏移如下（fresh 位置即其中已写成最终索引的字）：
//
//	0..1  const/16           vX, n            （21s，2 字）
//	2..3  new-array          vX, vX, [B       （22c，2 字）type 索引 @3
//	4..6  fill-array-data    vX, :payload     （31t，3 字）偏移 @5-6
//	7..9  invoke-static/range {vX}, helper    （3rc，3 字）method 索引 @8
//	10    move-result-object vX               （11x，1 字）
//
// 返回 false 表示该寄存器编号无法用 new-array 的 4 位字段编码（> v15），
// 此时不做任何修改。
func (l *InsnList) ReplaceWithArrayData(i int, data []byte, byteArrayTypeIdx, helperIdx uint32) bool {
	if i < 0 || i >= len(l.items) || !l.ItemIsInsn(i) {
		return false
	}
	reg := int(l.items[i].words[0] >> 8)
	if reg > 15 {
		// new-array 的目标与长度字段都只有 4 位，无法编码 v16 及以上
		return false
	}
	n := len(data)
	if n == 0 || n > 0x7fffffff {
		return false
	}

	// 追加 payload：合成旧偏移从 total 之后取，避免与真实项冲突
	l.synth++
	payloadOld := l.total + l.synth
	l.items = append(l.items, &insnItem{
		words: fillArrayPayload(data), kind: itemFillArrayData, old: payloadOld,
	})

	l.Replace(i, []uint16{
		0x13 | uint16(reg)<<8, uint16(n), // const/16 vX, n
		0x23 | uint16(reg)<<8 | uint16(reg)<<12, uint16(byteArrayTypeIdx), // new-array vX, vX, [B
		0x26 | uint16(reg)<<8, 0, 0, // fill-array-data vX, :payload
		0x77 | uint16(1)<<8, uint16(helperIdx), uint16(reg), // invoke-static/range {vX}, helper
		0x0c | uint16(reg)<<8, // move-result-object vX
	},
		3, // new-array 的 type 索引（22c 的 word1）
		8, // invoke-static/range 的 method 索引（3rc 的 word1）
	)
	l.branches = append(l.branches, branchRef{
		item: i, word: 5, base: 4, target: payloadOld, form: form31t,
	})
	return true
}

// Encode 编码为新的指令流，并自动修正全部分支偏移。
//
// 返回的新指令流、旧字偏移 → 新字偏移的映射（用于修正异常表），
// 以及全部「已写成最终索引、不可再映射」的绝对字位置（供 remapCode 跳过）。
func (l *InsnList) Encode() ([]uint16, map[int]int, map[int]bool) {
	// ---- 0) 布局迭代：必要时把 goto 加宽 ----
	//
	// goto 是格式 10t，相对偏移只有 **8 位**（-128..127）。A2/A3 改写会插入
	// 指令、拉长跳转距离，一旦超出 8 位就必须换成 goto/16（0x29）或
	// goto/32（0x2a）——否则偏移被截断，ART 报
	//   "invalid branch target"
	// 并拒绝整个类（真实案例：RustDesk 加固后大量 goto 目标乱飞）。
	//
	// 加宽会改变指令长度，进而影响后续布局，因此需要迭代到稳定。
	for iter := 0; iter < 8; iter++ {
		cur := 0
		for _, it := range l.items {
			if it.kind != itemInsn && cur%2 != 0 {
				cur++
			}
			it.new = cur
			cur += len(it.words)
		}
		old2newTmp := map[int]int{}
		for _, it := range l.items {
			old2newTmp[it.old] = it.new
		}
		changed := false
		for k := range l.branches {
			b := &l.branches[k]
			if b.form != form10t {
				continue
			}
			it := l.items[b.item]
			tgt, ok := old2newTmp[b.target]
			if !ok {
				continue
			}
			rel := tgt - (it.new + b.base)
			if rel >= -128 && rel <= 127 {
				continue
			}
			widenBranch(it, b, rel)
			changed = true
		}
		if !changed {
			break
		}
	}

	// ---- 1) 分配新偏移，必要时为 payload 插入对齐 nop ----
	cur := 0
	for _, it := range l.items {
		if it.kind != itemInsn && cur%2 != 0 {
			it.pad = true
			cur++
		}
		it.new = cur
		cur += len(it.words)
	}
	out := make([]uint16, cur)

	// ---- 2) 建立旧偏移 → 新偏移映射 ----
	//
	// 插入的指令与被锚定项共享旧偏移：映射时统一取「锚定项自身」的新偏移，
	// 使原本指向锚点的分支在重定位后跳过插入的指令，保持原语义。
	old2new := map[int]int{}
	for _, it := range l.items {
		old2new[it.old] = it.new
	}
	// 流末尾：异常表的区间端点可能正好等于指令流总长。
	//
	// 这里必须排除 A3 追加在末尾的 payload 合成项（其 old 大于 total）：
	// 若把端点映射到 payload 之后，try 区间会被延长到覆盖 payload，
	// 校验器可能因此拒绝整个方法。因此取「最后一个原始项的新终点」。
	end := cur
	for i := len(l.items) - 1; i >= 0; i-- {
		if l.items[i].old <= l.total {
			end = l.items[i].new + len(l.items[i].words)
			break
		}
	}
	old2new[l.total] = end

	// ---- 3) 写入指令字 ----
	fresh := map[int]bool{}
	for _, it := range l.items {
		if it.pad {
			out[it.new-1] = 0 // nop
		}
		copy(out[it.new:], it.words)
		for _, f := range it.fresh {
			fresh[it.new+f] = true
		}
	}

	// ---- 4) 修正分支偏移 ----
	//
	// 相对偏移的基准：指令内的分支以指令自身为基准；
	// switch payload 内的 target 表项以 payload 自身为基准。
	for _, b := range l.branches {
		it := l.items[b.item]
		newTarget, ok := old2new[b.target]
		if !ok {
			// 目标不在映射内：保持原值会被 ART 判 "invalid branch target"。
			// 正常情况下不会走到这里（解析时已把目标换算为绝对旧偏移），
			// 保留 continue 是为了不让畸形输入直接panic，问题由产物级守卫发现。
			continue
		}
		pos := it.new + b.word
		rel := newTarget - (it.new + b.base)
		switch b.form {
		case form10t:
			out[it.new] = uint16(it.words[0]&0xff) | uint16(byte(int8(rel)))<<8
		case form20t, form22t:
			out[pos] = uint16(int16(rel))
		case form30t, form31t:
			out[pos] = uint16(rel & 0xffff)
			out[pos+1] = uint16(uint32(int32(rel)) >> 16)
		case formPayload:
			// 重新以「switch 指令」为基准计算：规范要求 payload 内的 target
			// 相对 switch 指令，而不是相对 payload 自身。
			baseAddr := it.new
			if owner, ok := l.payloadOwner[b.item]; ok && owner >= 0 && owner < len(l.items) {
				baseAddr = l.items[owner].new
			}
			rel = newTarget - baseAddr
			out[pos] = uint16(rel & 0xffff)
			out[pos+1] = uint16(uint32(int32(rel)) >> 16)
		}
	}
	return out, old2new, fresh
}

// FixAddr 依据 old2new 映射修正一个代码偏移（用于异常表）。
func FixAddr(old2new map[int]int, old uint32) uint32 {
	if v, ok := old2new[int(old)]; ok {
		return uint32(v)
	}
	return old
}

// widenBranch 把一个 10t 分支（goto）加宽为 goto/16 或 goto/32。
//
// 只处理 goto：if-* 没有更宽的格式（规范只有 22t 的 16 位形式），
// 而 16 位范围（±32767 字）在我们的改写规模下不会被突破。
func widenBranch(it *insnItem, b *branchRef, rel int) {
	// 目标偏移的占位值由后续的修正步骤写入，这里只需保证长度与操作码正确。
	if rel >= -32768 && rel <= 32767 {
		it.words = []uint16{0x0029, 0, 0} // goto/16，格式 20t
		// fresh 中位于 word 1 之后的项要后移
		for i := range it.fresh {
			if it.fresh[i] > 0 {
				it.fresh[i] += 1
			}
		}
		b.form = form20t
		b.word = 1
		return
	}
	it.words = []uint16{0x002a, 0, 0, 0, 0} // goto/32，格式 30t
	for i := range it.fresh {
		if it.fresh[i] > 0 {
			it.fresh[i] += 2
		}
	}
	b.form = form30t
	b.word = 1
}
