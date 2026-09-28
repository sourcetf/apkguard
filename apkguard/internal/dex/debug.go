package dex

import (
	"encoding/binary"
	"fmt"
	"os"
	"sort"
)

// codeItemLength 计算 code_item 的字节长度（含异常表与末尾的 handler 数据）。
func (b *builder) codeItemLength(off uint32) (int, error) {
	d := b.f.data
	base := int(off)
	if base+16 > len(d) {
		return 0, fmt.Errorf("%w: code_item 越界 @%d", ErrTruncated, off)
	}
	insnsSize := binary.LittleEndian.Uint32(d[base+12:])
	triesSize := binary.LittleEndian.Uint16(d[base+6:])

	p := base + 16 + int(insnsSize)*2
	if triesSize > 0 {
		// tries 数组前需 4 字节对齐
		if (insnsSize & 1) != 0 {
			p += 2
		}
		p += int(triesSize) * 8
		// encoded_catch_handler_list
		handlersSize, np, err := ULEB128(d, p)
		if err != nil {
			return 0, err
		}
		p = np
		for i := uint32(0); i < handlersSize; i++ {
			var size int32
			size, p, err = SLEB128(d, p)
			if err != nil {
				return 0, err
			}
			cnt := size
			if cnt < 0 {
				cnt = -cnt
			}
			for k := int32(0); k < cnt; k++ {
				if _, p, err = ULEB128(d, p); err != nil { // type_idx
					return 0, err
				}
				if _, p, err = ULEB128(d, p); err != nil { // addr
					return 0, err
				}
			}
			if size <= 0 {
				// 含 catch_all_addr
				if _, p, err = ULEB128(d, p); err != nil {
					return 0, err
				}
			}
		}
	}
	return p - base, nil
}

// debugInfoLength 计算 debug_info_item 的字节长度。
func (b *builder) debugInfoLength(off uint32) (int, error) {
	d := b.f.data
	p := int(off)
	if p >= len(d) {
		return 0, fmt.Errorf("%w: debug_info 偏移越界 %d", ErrTruncated, off)
	}
	_, p, err := ULEB128(d, p) // line_start
	if err != nil {
		return 0, err
	}
	psize, p, err := ULEB128(d, p)
	if err != nil {
		return 0, err
	}
	for i := uint32(0); i < psize; i++ {
		if _, p, err = ULEB128(d, p); err != nil { // 参数名（uleb128p1）
			return 0, err
		}
	}
	for {
		if p >= len(d) {
			return 0, fmt.Errorf("%w: debug_info 状态机未终止", ErrTruncated)
		}
		op := d[p]
		p++
		switch op {
		case 0x00: // DBG_END_SEQUENCE
			return p - int(off), nil
		case 0x01: // DBG_ADVANCE_PC
			if _, p, err = ULEB128(d, p); err != nil {
				return 0, err
			}
		case 0x02: // DBG_ADVANCE_LINE
			if _, p, err = SLEB128(d, p); err != nil {
				return 0, err
			}
		case 0x03: // DBG_START_LOCAL
			for k := 0; k < 3; k++ {
				if _, p, err = ULEB128(d, p); err != nil {
					return 0, err
				}
			}
		case 0x04: // DBG_START_LOCAL_EXTENDED
			for k := 0; k < 4; k++ {
				if _, p, err = ULEB128(d, p); err != nil {
					return 0, err
				}
			}
		case 0x05, 0x06, 0x09: // END_LOCAL / RESTART_LOCAL / SET_FILE
			if _, p, err = ULEB128(d, p); err != nil {
				return 0, err
			}
		default:
			// 0x07,0x08 与 0x0a-0xff 的特殊操作码无操作数
		}
	}
}

// remapDebugInfo 重写 debug_info_item，把其中的字符串/类型索引映射为新值。
func (b *builder) remapDebugInfo(off uint32, length int) ([]byte, error) {
	d := b.f.data
	p := int(off)
	out := make([]byte, 0, length)
	var err error

	// line_start
	var v uint32
	v, p, err = ULEB128(d, p)
	if err != nil {
		return nil, err
	}
	out = PutULEB128(out, v)

	// parameters_size + 参数名（uleb128p1 形式引用字符串）
	var psize uint32
	psize, p, err = ULEB128(d, p)
	if err != nil {
		return nil, err
	}
	out = PutULEB128(out, psize)
	for i := uint32(0); i < psize; i++ {
		var nameIdx uint32
		nameIdx, p, err = ULEB128(d, p)
		if err != nil {
			return nil, err
		}
		out = PutULEB128(out, b.remapP1(nameIdx, b.R.String))
	}

	// 状态机
	for {
		op := d[p]
		p++
		out = append(out, op)
		switch op {
		case 0x00:
			return out, nil
		case 0x01: // ADVANCE_PC
			v, p, err = ULEB128(d, p)
			if err != nil {
				return nil, err
			}
			out = PutULEB128(out, v)
		case 0x02: // ADVANCE_LINE
			var sv int32
			sv, p, err = SLEB128(d, p)
			if err != nil {
				return nil, err
			}
			out = PutSLEB128(out, sv)
		case 0x03: // START_LOCAL: reg, name(string), type(type)
			var reg, nameIdx, typeIdx uint32
			if reg, p, err = ULEB128(d, p); err != nil {
				return nil, err
			}
			if nameIdx, p, err = ULEB128(d, p); err != nil {
				return nil, err
			}
			if typeIdx, p, err = ULEB128(d, p); err != nil {
				return nil, err
			}
			out = PutULEB128(out, reg)
			out = PutULEB128(out, b.remapP1(nameIdx, b.R.String))
			out = PutULEB128(out, b.remapP1(typeIdx, b.R.Type))
		case 0x04: // START_LOCAL_EXTENDED: reg, name, type, sig(string)
			var reg, nameIdx, typeIdx, sigIdx uint32
			if reg, p, err = ULEB128(d, p); err != nil {
				return nil, err
			}
			if nameIdx, p, err = ULEB128(d, p); err != nil {
				return nil, err
			}
			if typeIdx, p, err = ULEB128(d, p); err != nil {
				return nil, err
			}
			if sigIdx, p, err = ULEB128(d, p); err != nil {
				return nil, err
			}
			out = PutULEB128(out, reg)
			out = PutULEB128(out, b.remapP1(nameIdx, b.R.String))
			out = PutULEB128(out, b.remapP1(typeIdx, b.R.Type))
			out = PutULEB128(out, b.remapP1(sigIdx, b.R.String))
		case 0x05, 0x06: // END_LOCAL / RESTART_LOCAL: reg
			if v, p, err = ULEB128(d, p); err != nil {
				return nil, err
			}
			out = PutULEB128(out, v)
		case 0x09: // SET_FILE: name(string)
			if v, p, err = ULEB128(d, p); err != nil {
				return nil, err
			}
			out = PutULEB128(out, b.remapP1(v, b.R.String))
		default:
			// 无操作数
		}
	}
}

// remapP1 映射 uleb128p1 形式的索引（0 表示「无」，其余为 idx+1）。
func (b *builder) remapP1(v uint32, tbl []uint32) uint32 {
	if v == 0 {
		return 0
	}
	old := v - 1
	if int(old) >= len(tbl) {
		return 0
	}
	return tbl[old] + 1
}

// ---- 注解树 ----

// emitAnnotations 复制整棵注解偏移树，并修正其中的索引与偏移引用。
//
// DEX 的注解结构是四层间接引用：class_def -> annotations_directory ->
// annotation_set -> annotation_set_ref_list -> annotation_item。
func (b *builder) emitAnnotations() (aiMap, setMap, rlMap, dirMap map[uint32]uint32, err error) {
	f := b.f
	d := f.data
	aiMap = map[uint32]uint32{}
	setMap = map[uint32]uint32{}
	rlMap = map[uint32]uint32{}
	dirMap = map[uint32]uint32{}

	// 收集所有 annotations_directory 偏移
	dirOffs := []uint32{}
	seenDir := map[uint32]bool{}
	for i := uint32(0); i < f.NClass; i++ {
		cd, e := f.ClassDefAt(i)
		if e != nil {
			return nil, nil, nil, nil, e
		}
		if cd.AnnotationsOff != 0 && !seenDir[cd.AnnotationsOff] {
			seenDir[cd.AnnotationsOff] = true
			dirOffs = append(dirOffs, cd.AnnotationsOff)
		}
	}

	type dirInfo struct {
		classAnno  uint32
		fields     [][2]uint32
		methods    [][2]uint32
		parameters [][2]uint32
	}
	dirs := map[uint32]*dirInfo{}
	setOffs := map[uint32]bool{}
	rlOffs := map[uint32]bool{}

	for _, do := range dirOffs {
		base := int(do)
		if base+16 > len(d) {
			return nil, nil, nil, nil, fmt.Errorf("%w: annotations_directory 越界", ErrTruncated)
		}
		info := &dirInfo{classAnno: binary.LittleEndian.Uint32(d[base:])}
		fs := binary.LittleEndian.Uint32(d[base+4:])
		ms := binary.LittleEndian.Uint32(d[base+8:])
		ps := binary.LittleEndian.Uint32(d[base+12:])
		p := base + 16
		for k := uint32(0); k < fs; k++ {
			idx := binary.LittleEndian.Uint32(d[p:])
			ao := binary.LittleEndian.Uint32(d[p+4:])
			p += 8
			info.fields = append(info.fields, [2]uint32{idx, ao})
			setOffs[ao] = true
		}
		for k := uint32(0); k < ms; k++ {
			idx := binary.LittleEndian.Uint32(d[p:])
			ao := binary.LittleEndian.Uint32(d[p+4:])
			p += 8
			info.methods = append(info.methods, [2]uint32{idx, ao})
			setOffs[ao] = true
		}
		for k := uint32(0); k < ps; k++ {
			idx := binary.LittleEndian.Uint32(d[p:])
			ao := binary.LittleEndian.Uint32(d[p+4:])
			p += 8
			info.parameters = append(info.parameters, [2]uint32{idx, ao})
			rlOffs[ao] = true
		}
		if info.classAnno != 0 {
			setOffs[info.classAnno] = true
		}
		dirs[do] = info
	}

	// annotation_set_ref_list
	type rlInfo struct{ items []uint32 }
	rls := map[uint32]*rlInfo{}
	for ro := range rlOffs {
		n := binary.LittleEndian.Uint32(d[ro:])
		items := make([]uint32, 0, n)
		for k := uint32(0); k < n; k++ {
			s := binary.LittleEndian.Uint32(d[ro+4+4*k:])
			items = append(items, s)
			if s != 0 {
				setOffs[s] = true
			}
		}
		rls[ro] = &rlInfo{items: items}
	}

	// annotation_set
	type setInfo struct{ items []uint32 }
	sets := map[uint32]*setInfo{}
	aiOffs := map[uint32]bool{}
	for so := range setOffs {
		n := binary.LittleEndian.Uint32(d[so:])
		items := make([]uint32, 0, n)
		for k := uint32(0); k < n; k++ {
			ao := binary.LittleEndian.Uint32(d[so+4+4*k:])
			items = append(items, ao)
			aiOffs[ao] = true
		}
		sets[so] = &setInfo{items: items}
	}

	// annotation_item：先处理，供上层引用
	aiSorted := sortedKeys(aiOffs)
	for _, ao := range aiSorted {
		blob, e := b.remapAnnotationItem(ao)
		if e != nil {
			return nil, nil, nil, nil, e
		}
		aiMap[ao] = b.place(0x2004, blob, 1)
	}

	for _, so := range sortedKeys(setOffs) {
		s := sets[so]
		blob := make([]byte, 4+4*len(s.items))
		binary.LittleEndian.PutUint32(blob, uint32(len(s.items)))
		for k, ao := range s.items {
			binary.LittleEndian.PutUint32(blob[4+4*k:], aiMap[ao])
		}
		setMap[so] = b.place(0x1003, blob, 4)
	}

	for _, ro := range sortedKeys(rlOffs) {
		r := rls[ro]
		blob := make([]byte, 4+4*len(r.items))
		binary.LittleEndian.PutUint32(blob, uint32(len(r.items)))
		for k, so := range r.items {
			v := uint32(0)
			if so != 0 {
				v = setMap[so]
			}
			binary.LittleEndian.PutUint32(blob[4+4*k:], v)
		}
		rlMap[ro] = b.place(0x1002, blob, 4)
	}

	for _, do := range sortedKeysU32(dirOffs) {
		info := dirs[do]
		blob := make([]byte, 0, 16+8*(len(info.fields)+len(info.methods)+len(info.parameters)))
		blob = appendU32(blob, setMap[info.classAnno])
		blob = appendU32(blob, uint32(len(info.fields)))
		blob = appendU32(blob, uint32(len(info.methods)))
		blob = appendU32(blob, uint32(len(info.parameters)))

		// 目录内的条目必须按索引升序，重排后需重新排序
		type pair struct {
			idx uint32
			off uint32
		}
		emitPairs := func(items [][2]uint32, kind refKind, m map[uint32]uint32) {
			pairs := make([]pair, 0, len(items))
			for _, it := range items {
				var newIdx uint32
				switch kind {
				case refField:
					newIdx = b.R.Field[it[0]]
				case refMethod:
					newIdx = b.R.Method[it[0]]
				}
				pairs = append(pairs, pair{idx: newIdx, off: m[it[1]]})
			}
			sort.Slice(pairs, func(a, c int) bool { return pairs[a].idx < pairs[c].idx })
			for _, p := range pairs {
				blob = appendU32(blob, p.idx)
				blob = appendU32(blob, p.off)
			}
		}
		emitPairs(info.fields, refField, setMap)
		emitPairs(info.methods, refMethod, setMap)
		emitPairs(info.parameters, refMethod, rlMap)

		dirMap[do] = b.place(0x2006, blob, 4)
	}
	return aiMap, setMap, rlMap, dirMap, nil
}

// remapAnnotationItem 重写一个 annotation_item。
func (b *builder) remapAnnotationItem(off uint32) ([]byte, error) {
	d := b.f.data
	if int(off) >= len(d) {
		return nil, fmt.Errorf("%w: annotation_item 偏移越界 %d", ErrTruncated, off)
	}
	visibility := d[off]
	body, _, err := b.remapEncodedAnnotation(int(off)+1, d)
	if err != nil {
		return nil, err
	}
	return append([]byte{visibility}, body...), nil
}

// remapEncodedAnnotation 重写一个 encoded_annotation。
func (b *builder) remapEncodedAnnotation(p int, d []byte) ([]byte, int, error) {
	typeIdx, np, err := ULEB128(d, p)
	if err != nil {
		return nil, p, err
	}
	size, np2, err := ULEB128(d, np)
	if err != nil {
		return nil, np, err
	}
	out := PutULEB128(nil, b.R.Type[typeIdx])
	out = PutULEB128(out, size)
	p = np2
	for i := uint32(0); i < size; i++ {
		var nameIdx uint32
		nameIdx, p, err = ULEB128(d, p)
		if err != nil {
			return nil, p, err
		}
		out = PutULEB128(out, b.R.String[nameIdx])
		var ev []byte
		ev, p, err = b.remapEncodedValue(p, d)
		if err != nil {
			return nil, p, err
		}
		out = append(out, ev...)
	}
	return out, p, nil
}

// remapEncodedValue 重写一个 encoded_value。
func (b *builder) remapEncodedValue(p int, d []byte) ([]byte, int, error) {
	at := d[p]
	p++
	vt := at & 0x1f
	va := (at >> 5) & 0x7

	switch vt {
	case 0x1c: // array
		size, np, err := ULEB128(d, p)
		if err != nil {
			return nil, p, err
		}
		out := PutULEB128(nil, size)
		p = np
		for i := uint32(0); i < size; i++ {
			var ev []byte
			ev, p, err = b.remapEncodedValue(p, d)
			if err != nil {
				return nil, p, err
			}
			out = append(out, ev...)
		}
		return append([]byte{at}, out...), p, nil
	case 0x1d: // annotation
		body, np, err := b.remapEncodedAnnotation(p, d)
		if err != nil {
			return nil, p, err
		}
		return append([]byte{at}, body...), np, nil
	case 0x1e, 0x1f: // null, boolean
		return []byte{at}, p, nil
	}

	// 含索引的取值类型
	var tbl []uint32
	switch vt {
	case 0x15: // method_type
		tbl = b.R.Proto
	case 0x17: // string
		tbl = b.R.String
	case 0x18: // type
		tbl = b.R.Type
	case 0x19: // field
		tbl = b.R.Field
	case 0x1a: // method
		tbl = b.R.Method
	case 0x1b: // enum
		tbl = b.R.Field
	}
	if tbl == nil {
		// 数值型：原样复制
		n := int(va) + 1
		return append([]byte{at}, d[p:p+n]...), p + n, nil
	}
	old := readUintLE(d, p, int(va)+1)
	newVal := tbl[old]
	nb := uint32Bytes(newVal)
	return append([]byte{(at & 0x1f) | byte((len(nb)-1)<<5)}, nb...), p + int(va) + 1, nil
}

// encodedArrayLength 计算 encoded_array 的字节长度。
func (b *builder) encodedArrayLength(off uint32) (int, error) {
	d := b.f.data
	p := int(off)
	size, np, err := ULEB128(d, p)
	if err != nil {
		return 0, err
	}
	p = np
	for i := uint32(0); i < size; i++ {
		p, err = b.skipEncodedValue(p, d)
		if err != nil {
			return 0, err
		}
	}
	return p - int(off), nil
}

// skipEncodedValue 跳过（不解析内容地）一个 encoded_value。
func (b *builder) skipEncodedValue(p int, d []byte) (int, error) {
	at := d[p]
	p++
	vt := at & 0x1f
	va := (at >> 5) & 0x7
	switch vt {
	case 0x1c:
		size, np, err := ULEB128(d, p)
		if err != nil {
			return p, err
		}
		p = np
		for i := uint32(0); i < size; i++ {
			var err error
			if p, err = b.skipEncodedValue(p, d); err != nil {
				return p, err
			}
		}
		return p, nil
	case 0x1d:
		_, np, err := ULEB128(d, p)
		if err != nil {
			return p, err
		}
		size, np2, err := ULEB128(d, np)
		if err != nil {
			return p, err
		}
		p = np2
		for i := uint32(0); i < size; i++ {
			if _, np3, err := ULEB128(d, p); err != nil {
				return p, err
			} else {
				p = np3
			}
			var err error
			if p, err = b.skipEncodedValue(p, d); err != nil {
				return p, err
			}
		}
		return p, nil
	case 0x1e, 0x1f:
		return p, nil
	default:
		return p + int(va) + 1, nil
	}
}

// remapEncodedArray 重写一个 encoded_array（用于 static values）。
func (b *builder) remapEncodedArray(off uint32, length int) ([]byte, error) {
	d := b.f.data
	p := int(off)
	size, np, err := ULEB128(d, p)
	if err != nil {
		return nil, err
	}
	out := PutULEB128(nil, size)
	p = np
	for i := uint32(0); i < size; i++ {
		var ev []byte
		ev, p, err = b.remapEncodedValue(p, d)
		if err != nil {
			return nil, err
		}
		out = append(out, ev...)
	}
	return out, nil
}

// remapEncodedArrayValues 把一个 encoded_array 拆成「逐位置、已重映射」的值字节。
//
// 与 remapEncodedArray 的区别：它保留每个值在数组中的位置，便于**重排**——
// static_values 的第 i 个值必须对应「按新 field_idx 排序后的第 i 个静态字段」，
// 而 A1 改名会改变 field_idx 顺序，因此仅原地重映射是不够的
// （ART 会判 "unexpected static field initial value type: 'L' vs 'I'" 并拒绝整个 DEX）。
func (b *builder) remapEncodedArrayValues(off uint32) ([][]byte, error) {
	d := b.f.data
	p := int(off)
	size, np, err := ULEB128(d, p)
	if err != nil {
		return nil, err
	}
	p = np
	vals := make([][]byte, 0, size)
	for i := uint32(0); i < size; i++ {
		start := p
		var ev []byte
		ev, p, err = b.remapEncodedValue(p, d)
		if err != nil {
			return nil, err
		}
		if os.Getenv("AG_DEBUG_SV") != "" && i >= 160 && i <= 176 {
			fmt.Fprintf(os.Stderr, "[SV2] i=%d off=%d len=%d raw=% x out=% x\n", i, start, p-start, d[start:p], ev)
		}
		vals = append(vals, ev)
	}
	return vals, nil
}

// defaultEncodedValue 返回某字段类型的**完整**默认值编码。
//
// 必须是完整的 encoded_value，不能只给类型字节：数值型的值还需要载荷字节
// （例如 VALUE_INT 0 是 `04 00` 两个字节）。只给一个字节会让拼出的数组
// 长度少 1 字节，解析时整体错位，ART 判
//
//	"Bogus encoded_value value_type" 并拒绝整个 DEX
//
// （真实案例：RustDesk 加固后 d1.dex 被拒，其内所有类都无法解析）。
func defaultEncodedValue(desc string) []byte {
	if desc == "" {
		return []byte{0x1e} // VALUE_NULL：引用类型的默认值，无载荷
	}
	switch desc[0] {
	case 'L', '[':
		return []byte{0x1e} // VALUE_NULL
	case 'Z':
		return []byte{0x1f} // VALUE_BOOLEAN false（value_arg 即布尔值，无载荷）
	case 'B':
		return []byte{0x00, 0x00} // VALUE_BYTE 0
	case 'S':
		return []byte{0x02, 0x00} // VALUE_SHORT 0
	case 'C':
		return []byte{0x03, 0x00} // VALUE_CHAR 0
	case 'I':
		return []byte{0x04, 0x00} // VALUE_INT 0
	case 'J':
		return []byte{0x06, 0x00} // VALUE_LONG 0
	case 'F':
		return []byte{0x10, 0x00} // VALUE_FLOAT 0
	case 'D':
		return []byte{0x11, 0x00} // VALUE_DOUBLE 0
	}
	return []byte{0x04, 0x00} // 兜底按 VALUE_INT 0
}

// ---- 小工具 ----

func appendU32(dst []byte, v uint32) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return append(dst, b[:]...)
}

func readUintLE(d []byte, p, n int) uint32 {
	var v uint32
	for i := 0; i < n && p+i < len(d); i++ {
		v |= uint32(d[p+i]) << (8 * i)
	}
	return v
}

// uint32Bytes 返回表示 v 所需的最少字节（至少 1 字节）。
func uint32Bytes(v uint32) []byte {
	n := 1
	for x := v; x > 0xff; x >>= 8 {
		n++
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = byte(v >> (8 * i))
	}
	return out
}

func sortedKeys(m map[uint32]bool) []uint32 {
	out := make([]uint32, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sortU32(out)
	return out
}

func sortedKeysU32(in []uint32) []uint32 {
	out := append([]uint32(nil), in...)
	sortU32(out)
	return out
}

func sortU32(s []uint32) {
	// 使用简单插入排序即可：注解条目数量通常很小
	for i := 1; i < len(s); i++ {
		v := s[i]
		j := i - 1
		for j >= 0 && s[j] > v {
			s[j+1] = s[j]
			j--
		}
		s[j+1] = v
	}
}

// validateEncodedValue 校验一段 encoded_value 字节能否被完整解析（自校验）。
//
// 用于 static_values 重排：每个值切片必须自身合法，否则拼出的数组会字节错位，
// ART 会报 "Bogus encoded_value value_type" 并拒绝整个 DEX。
func validateEncodedValue(v []byte) (bool, byte) {
	if len(v) == 0 {
		return false, 0
	}
	vt := v[0] & 0x1f
	switch vt {
	case 0x00: // VALUE_BYTE
	case 0x02: // VALUE_SHORT
	case 0x03: // VALUE_CHAR
	case 0x04: // VALUE_INT
	case 0x06: // VALUE_LONG
	case 0x10: // VALUE_FLOAT
	case 0x11: // VALUE_DOUBLE
	case 0x15: // method_type
	case 0x16: // method_handle
	case 0x17: // string
	case 0x18: // type
	case 0x19: // field
	case 0x1a: // method
	case 0x1b: // enum
		if int(v[0]>>5)+2 != len(v) {
			return false, vt
		}
	case 0x1e: // null
	case 0x1f: // boolean
		if len(v) != 1 {
			return false, vt
		}
	case 0x1c: // array
		q := 1
		n, nq, err := ULEB128(v, q)
		if err != nil {
			return false, vt
		}
		q = nq
		for i := uint32(0); i < n; i++ {
			if q >= len(v) {
				return false, vt
			}
			vt2 := v[q] & 0x1f
			switch vt2 {
			case 0x1c:
				ok, _ := validateEncodedValue(v[q:])
				if !ok {
					return false, vt2
				}
				// 递归算长度：重新走一遍
				l, err := encodedValueLen(v[q:])
				if err != nil {
					return false, vt2
				}
				q += l
			case 0x1e, 0x1f:
				q++
			default:
				q += int(v[q]>>5) + 2
			}
		}
		if q != len(v) {
			return false, vt
		}
	case 0x1d: // annotation
		l, err := encodedValueLenAnno(v[1:])
		if err != nil || 1+l != len(v) {
			return false, vt
		}
	default:
		return false, vt
	}
	return true, vt
}

// encodedValueLen 返回一段 encoded_value 的长度（不含数组/注解递归以外的复杂处理）。
func encodedValueLen(v []byte) (int, error) {
	if len(v) == 0 {
		return 0, fmt.Errorf("空值")
	}
	vt := v[0] & 0x1f
	switch vt {
	case 0x1c:
		q := 1
		n, nq, err := ULEB128(v, q)
		if err != nil {
			return 0, err
		}
		q = nq
		for i := uint32(0); i < n; i++ {
			l, err := encodedValueLen(v[q:])
			if err != nil {
				return 0, err
			}
			q += l
		}
		return q, nil
	case 0x1d:
		// 注解体紧随类型字节；encodedValueLenAnno 从 type_idx 开始，故 +1。
		l, err := encodedValueLenAnno(v[1:])
		if err != nil {
			return 0, err
		}
		return 1 + l, nil
	case 0x1e, 0x1f:
		return 1, nil
	default:
		return int(v[0]>>5) + 2, nil
	}
}

// encodedValueLenAnno 返回一段 encoded_annotation 的长度。
func encodedValueLenAnno(v []byte) (int, error) {
	q := 0
	_, nq, err := ULEB128(v, q)
	if err != nil {
		return 0, err
	}
	q = nq
	n, nq, err := ULEB128(v, q)
	if err != nil {
		return 0, err
	}
	q = nq
	for i := uint32(0); i < n; i++ {
		_, nq, err = ULEB128(v, q)
		if err != nil {
			return 0, err
		}
		q = nq
		l, err := encodedValueLen(v[q:])
		if err != nil {
			return 0, err
		}
		q += l
	}
	return q, nil
}

// validateEncodedArray 校验一个拼好的 encoded_array 能否被完整解析出 want 个值。
//
// 返回第一个不合法值的序号与原因；全部合法时返回 -1。
func validateEncodedArray(blob []byte, want int) (int, string) {
	n, q, err := ULEB128(blob, 0)
	if err != nil {
		return -1, "size 无法解析"
	}
	if int(n) != want {
		return -1, fmt.Sprintf("size=%d 与预期 %d 不符", n, want)
	}
	for i := uint32(0); i < n; i++ {
		if q >= len(blob) {
			return int(i), fmt.Sprintf("第 %d 个值越界（剩余 0 字节）", i)
		}
		start := q
		vt := blob[q] & 0x1f
		l, err := encodedValueLen(blob[q:])
		if err != nil {
			return int(i), fmt.Sprintf("第 %d 个值解析失败: %v", i, err)
		}
		if l <= 0 || q+l > len(blob) {
			return int(i), fmt.Sprintf("第 %d 个值长度 %d 越界（type=0x%02x, 剩余 %d 字节）",
				i, l, vt, len(blob)-q)
		}
		q += l
		_ = start
	}
	if q != len(blob) {
		return int(n) - 1, fmt.Sprintf("解析在 %d 字节处结束，但数组长度为 %d（多出 %d 字节）",
			q, len(blob), len(blob)-q)
	}
	return -1, ""
}

// svlogf 输出一行调试信息（自带换行，避免转义问题）。
func svlogf(format string, args ...any) {
	if os.Getenv("AG_DEBUG_SV") == "" {
		return
	}
	fmt.Fprintf(os.Stderr, format+chr13(), args...)
}

func chr13() string { return string([]byte{10}) }
