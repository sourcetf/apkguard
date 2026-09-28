package dex

import (
	"encoding/binary"
	"fmt"
)

// MemberInfo 描述一个字段或方法的定义信息。
type MemberInfo struct {
	Name   string
	Access uint32
	// Proto 是方法描述符（形如 "(I)V"），字段为空。
	Proto string
	// Type 是字段的类型描述符，方法为空。
	Type string
	// Native 表示方法为 JNI 方法（名称与 native 符号绑定，不可重命名）。
	Native bool
}

// ClassInfo 汇总一个类的定义信息。
type ClassInfo struct {
	// Desc 是类描述符，形如 "Lcom/foo/Bar;"
	Desc string
	// Access 是 class_def 的访问标志。
	Access uint32
	// Super 是父类描述符；空字符串表示无父类（仅 java/lang/Object）。
	Super string
	// Interfaces 是直接实现的接口描述符。
	Interfaces []string
	// SourceFile 是源文件名；空字符串表示无。
	SourceFile string

	StaticFields   []MemberInfo
	InstanceFields []MemberInfo
	DirectMethods  []MemberInfo
	VirtualMethods []MemberInfo
}

// Methods 返回该类全部方法（直接方法在前）。
func (c *ClassInfo) Methods() []MemberInfo {
	out := make([]MemberInfo, 0, len(c.DirectMethods)+len(c.VirtualMethods))
	out = append(out, c.DirectMethods...)
	out = append(out, c.VirtualMethods...)
	return out
}

// Fields 返回该类全部字段。
func (c *ClassInfo) Fields() []MemberInfo {
	out := make([]MemberInfo, 0, len(c.StaticFields)+len(c.InstanceFields))
	out = append(out, c.StaticFields...)
	out = append(out, c.InstanceFields...)
	return out
}

// ClassInfos 返回全部类的定义信息（含成员访问标志）。
//
// 这个方法会完整解析 class_data，因此比只读 class_defs 慢，
// 但重命名类/方法/字段时必须依赖它来判断哪些成员不可改名。
func (f *File) ClassInfos() ([]ClassInfo, error) {
	out := make([]ClassInfo, 0, f.NClass)
	for i := uint32(0); i < f.NClass; i++ {
		cd, err := f.ClassDefAt(i)
		if err != nil {
			return nil, err
		}
		desc, err := f.Type(cd.ClassIdx)
		if err != nil {
			return nil, err
		}
		ci := ClassInfo{Desc: desc, Access: cd.AccessFlags}
		if cd.SuperIdx != noIndex {
			s, err := f.Type(cd.SuperIdx)
			if err != nil {
				return nil, err
			}
			ci.Super = s
		}
		if cd.InterfacesOff != 0 {
			list, err := f.typeList(cd.InterfacesOff)
			if err != nil {
				return nil, err
			}
			ci.Interfaces = list
		}
		if cd.SourceFileIdx != noIndex {
			s, err := f.String(cd.SourceFileIdx)
			if err != nil {
				return nil, err
			}
			ci.SourceFile = s
		}
		if cd.ClassDataOff == 0 {
			out = append(out, ci)
			continue
		}
		pcd, err := f.ParseClassData(cd.ClassDataOff)
		if err != nil {
			return nil, err
		}
		readField := func(e EncodedField) (MemberInfo, error) {
			_, t, n, err := f.FieldRefAt(e.Idx)
			if err != nil {
				return MemberInfo{}, err
			}
			name, err := f.String(n)
			if err != nil {
				return MemberInfo{}, err
			}
			typ, err := f.Type(uint32(t))
			if err != nil {
				return MemberInfo{}, err
			}
			return MemberInfo{Name: name, Access: e.Acc, Type: typ}, nil
		}
		readMethod := func(e EncodedMethod) (MemberInfo, error) {
			ref, err := f.MethodRefAt(e.Idx)
			if err != nil {
				return MemberInfo{}, err
			}
			name, err := f.String(ref.NameIdx)
			if err != nil {
				return MemberInfo{}, err
			}
			proto, err := f.ProtoDesc(uint32(ref.ProtoIdx))
			if err != nil {
				return MemberInfo{}, err
			}
			return MemberInfo{
				Name: name, Access: e.Acc, Proto: proto,
				Native: e.Acc&accNative != 0,
			}, nil
		}
		for _, e := range pcd.StaticFields {
			m, err := readField(e)
			if err != nil {
				return nil, err
			}
			ci.StaticFields = append(ci.StaticFields, m)
		}
		for _, e := range pcd.InstanceFields {
			m, err := readField(e)
			if err != nil {
				return nil, err
			}
			ci.InstanceFields = append(ci.InstanceFields, m)
		}
		for _, e := range pcd.DirectMethods {
			m, err := readMethod(e)
			if err != nil {
				return nil, err
			}
			ci.DirectMethods = append(ci.DirectMethods, m)
		}
		for _, e := range pcd.VirtualMethods {
			m, err := readMethod(e)
			if err != nil {
				return nil, err
			}
			ci.VirtualMethods = append(ci.VirtualMethods, m)
		}
		out = append(out, ci)
	}
	return out, nil
}

// StringUsage 汇总 DEX 中字符串池各条目的用途。
//
// 重命名时必须区分「作为标识符使用的字符串」与「作为数据使用的字符串」：
// 后者一旦被改写就会改变程序行为（例如反射用的类名、注解参数）。
type StringUsage struct {
	// Const 是 const-string 指令引用的字符串索引。
	Const map[uint32]bool
	// Anno 是注解中引用的字符串索引（元素名与字符串取值）。
	Anno map[uint32]bool
	// SourceFile 是 class_def 的 source_file_idx。
	SourceFile map[uint32]bool
	// Type 是被 type_ids 引用的字符串索引。
	Type map[uint32]bool
	// MethodName 是被 method_ids 引用的方法名索引。
	MethodName map[uint32]bool
	// FieldName 是被 field_ids 引用的字段名索引。
	FieldName map[uint32]bool
	// Debug 是被 debug_info_item 引用的字符串索引（参数名、局部变量名、
	// 源文件名）。这类字符串虽不影响执行，但被改写会让调试信息失真，
	// 因此重命名/加密时同样应当视为「已占用」。
	Debug map[uint32]bool
	// Shorty 是被 proto_ids 的 shorty_idx 引用的字符串索引（形如 "VL"）。
	//
	// 这类字符串**必须**保持原样：ART 的结构校验器要求 shorty 只含
	// VZBSCIJFD 或 L，一旦被加密（例如变成十六进制串）就直接拒绝整个 DEX，
	// 报 "Bad shorty character"。而它又不会被任何指令引用，
	// 因此极易被「仅被 const-string 引用才可整体替换」的判断漏掉。
	Shorty map[uint32]bool
}

// StringUsage 扫描整个 DEX，统计每个字符串的用途。
func (f *File) StringUsage() (*StringUsage, error) {
	u := &StringUsage{
		Const:      map[uint32]bool{},
		Anno:       map[uint32]bool{},
		SourceFile: map[uint32]bool{},
		Type:       map[uint32]bool{},
		MethodName: map[uint32]bool{},
		FieldName:  map[uint32]bool{},
		Debug:      map[uint32]bool{},
		Shorty:     map[uint32]bool{},
	}
	d := f.data

	// type_ids
	for i := uint32(0); i < f.NType; i++ {
		u.Type[typeNameIdx(f, i)] = true
	}
	// method_ids / field_ids
	for i := uint32(0); i < f.NMethod; i++ {
		ref, err := f.MethodRefAt(i)
		if err != nil {
			return nil, err
		}
		u.MethodName[ref.NameIdx] = true
	}
	for i := uint32(0); i < f.NField; i++ {
		_, _, n, err := f.FieldRefAt(i)
		if err != nil {
			return nil, err
		}
		u.FieldName[n] = true
	}
	// proto_ids 的 shorty_idx（形如 "VL"）：必须原样保留，见 StringUsage.Shorty。
	for i := uint32(0); i < f.NProto; i++ {
		base := f.OffProto + 12*i
		if base+4 > uint32(len(d)) {
			break
		}
		u.Shorty[binary.LittleEndian.Uint32(d[base:])] = true
	}
	// source_file
	for i := uint32(0); i < f.NClass; i++ {
		cd, err := f.ClassDefAt(i)
		if err != nil {
			return nil, err
		}
		if cd.SourceFileIdx != noIndex {
			u.SourceFile[cd.SourceFileIdx] = true
		}
	}

	// const-string 指令
	if err := f.walkAllCode(func(codeOff uint32) error {
		ci, err := f.CodeInsns(codeOff)
		if err != nil {
			return err
		}
		words := make([]uint16, ci.InsnsSize)
		for i := uint32(0); i < ci.InsnsSize; i++ {
			words[i] = binary.LittleEndian.Uint16(d[ci.InsnsOff+2*int(i):])
		}
		return walkInsns(words, func(op byte, pos int, w []uint16) error {
			switch op {
			case 0x1a: // const-string
				u.Const[uint32(w[pos+1])] = true
			case 0x1b: // const-string/jumbo
				u.Const[uint32(w[pos+1])|uint32(w[pos+2])<<16] = true
			}
			return nil
		})
	}); err != nil {
		return nil, err
	}

	// 注解与静态值中的字符串
	if err := f.walkAllAnnotations(
		// annotation_item：跳过 1 字节 visibility 后是 encoded_annotation
		func(p int, d []byte) error { return collectAnnotationStrings(p, d, u.Anno) },
		// encoded_array_item：static values
		func(p int, d []byte) error { return collectArrayStrings(p, d, u.Anno) },
	); err != nil {
		return nil, err
	}

	// debug_info 中的字符串（参数名、局部变量名、SET_FILE 的源文件名）
	if err := f.walkAllCode(func(codeOff uint32) error {
		dbgOff := binary.LittleEndian.Uint32(d[codeOff+8:])
		if dbgOff == 0 {
			return nil
		}
		return f.collectDebugStrings(dbgOff, u.Debug)
	}); err != nil {
		return nil, err
	}
	return u, nil
}

// collectDebugStrings 收集一个 debug_info_item 中引用的字符串索引。
//
// 所有字符串类操作数都是 uleb128p1 编码（0 表示「无」，其余为 idx+1）。
func (f *File) collectDebugStrings(off uint32, out map[uint32]bool) error {
	d := f.data
	p := int(off)
	if p >= len(d) {
		return fmt.Errorf("%w: debug_info 偏移越界 %d", ErrTruncated, off)
	}
	add := func(v uint32) {
		if v != 0 {
			out[v-1] = true
		}
	}
	// line_start
	if _, np, err := ULEB128(d, p); err != nil {
		return err
	} else {
		p = np
	}
	// parameters_size + 参数名
	psize, p, err := ULEB128(d, p)
	if err != nil {
		return err
	}
	for i := uint32(0); i < psize; i++ {
		v, np, err := ULEB128(d, p)
		if err != nil {
			return err
		}
		add(v)
		p = np
	}
	// 状态机
	for {
		if p >= len(d) {
			return fmt.Errorf("%w: debug_info 状态机未终止", ErrTruncated)
		}
		op := d[p]
		p++
		switch op {
		case 0x00: // DBG_END_SEQUENCE
			return nil
		case 0x01: // DBG_ADVANCE_PC
			if _, p, err = ULEB128(d, p); err != nil {
				return err
			}
		case 0x02: // DBG_ADVANCE_LINE
			if _, p, err = SLEB128(d, p); err != nil {
				return err
			}
		case 0x03: // DBG_START_LOCAL: reg, name(string), type(type)
			if _, p, err = ULEB128(d, p); err != nil {
				return err
			}
			name, np, err := ULEB128(d, p)
			if err != nil {
				return err
			}
			add(name)
			p = np
			if _, p, err = ULEB128(d, p); err != nil { // type 是 uleb128p1，但不是字符串
				return err
			}
		case 0x04: // DBG_START_LOCAL_EXTENDED: reg, name, type, sig(string)
			if _, p, err = ULEB128(d, p); err != nil {
				return err
			}
			name, np, err := ULEB128(d, p)
			if err != nil {
				return err
			}
			add(name)
			p = np
			if _, p, err = ULEB128(d, p); err != nil { // type
				return err
			}
			sig, np2, err := ULEB128(d, p)
			if err != nil {
				return err
			}
			add(sig)
			p = np2
		case 0x05, 0x06: // END_LOCAL / RESTART_LOCAL: reg
			if _, p, err = ULEB128(d, p); err != nil {
				return err
			}
		case 0x09: // SET_FILE: name(string)
			v, np, err := ULEB128(d, p)
			if err != nil {
				return err
			}
			add(v)
			p = np
		default:
			// 0x07、0x08 与 0x0a-0xff 的特殊操作码无操作数
		}
	}
}

// walkAllCode 遍历 DEX 中每个唯一的 code_item 偏移。
func (f *File) walkAllCode(fn func(codeOff uint32) error) error {
	seen := map[uint32]bool{}
	for i := uint32(0); i < f.NClass; i++ {
		cd, err := f.ClassDefAt(i)
		if err != nil {
			return err
		}
		if cd.ClassDataOff == 0 {
			continue
		}
		pcd, err := f.ParseClassData(cd.ClassDataOff)
		if err != nil {
			return err
		}
		for _, lst := range [][]EncodedMethod{pcd.DirectMethods, pcd.VirtualMethods} {
			for _, m := range lst {
				if m.CodeOff == 0 || seen[m.CodeOff] {
					continue
				}
				seen[m.CodeOff] = true
				if err := fn(m.CodeOff); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// walkAllAnnotations 遍历全部 annotation_item 与 encoded_array_item（static values）。
//
// 两个回调分别接收：
//   - anno：指向 encoded_annotation 主体的偏移（已跳过 visibility 字节）
//   - arr：指向 encoded_array 主体的偏移
func (f *File) walkAllAnnotations(anno, arr func(p int, d []byte) error) error {
	d := f.data
	seenSet := map[uint32]bool{}
	seenItem := map[uint32]bool{}
	seenArr := map[uint32]bool{}

	for i := uint32(0); i < f.NClass; i++ {
		cd, err := f.ClassDefAt(i)
		if err != nil {
			return err
		}
		if cd.StaticValuesOff != 0 && !seenArr[cd.StaticValuesOff] {
			seenArr[cd.StaticValuesOff] = true
			if err := arr(int(cd.StaticValuesOff), d); err != nil {
				return err
			}
		}
		if cd.AnnotationsOff == 0 {
			continue
		}
		base := int(cd.AnnotationsOff)
		if base+16 > len(d) {
			return fmt.Errorf("%w: annotations_directory 越界", ErrTruncated)
		}
		sets := []uint32{binary.LittleEndian.Uint32(d[base:])}
		p := base + 16
		nField := binary.LittleEndian.Uint32(d[base+4:])
		nMethod := binary.LittleEndian.Uint32(d[base+8:])
		nParam := binary.LittleEndian.Uint32(d[base+12:])
		for k := uint32(0); k < nField+nMethod; k++ {
			sets = append(sets, binary.LittleEndian.Uint32(d[p+4:]))
			p += 8
		}
		var rl []uint32
		for k := uint32(0); k < nParam; k++ {
			rl = append(rl, binary.LittleEndian.Uint32(d[p+4:]))
			p += 8
		}
		// 参数注解先展开 annotation_set_ref_list
		for _, r := range rl {
			if r == 0 {
				continue
			}
			n := binary.LittleEndian.Uint32(d[r:])
			for k := uint32(0); k < n; k++ {
				if so := binary.LittleEndian.Uint32(d[r+4+4*k:]); so != 0 {
					sets = append(sets, so)
				}
			}
		}
		for _, so := range sets {
			if so == 0 || seenSet[so] {
				continue
			}
			seenSet[so] = true
			n := binary.LittleEndian.Uint32(d[so:])
			for k := uint32(0); k < n; k++ {
				ao := binary.LittleEndian.Uint32(d[so+4+4*k:])
				if ao == 0 || seenItem[ao] {
					continue
				}
				seenItem[ao] = true
				// annotation_item = visibility(u8) + encoded_annotation
				if err := anno(int(ao)+1, d); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// collectAnnotationStrings 收集一个 encoded_annotation 中的字符串索引。
func collectAnnotationStrings(p int, d []byte, out map[uint32]bool) error {
	_, np, err := ULEB128(d, p)
	if err != nil {
		return err
	}
	size, np2, err := ULEB128(d, np)
	if err != nil {
		return err
	}
	q := np2
	for i := uint32(0); i < size; i++ {
		nameIdx, nq, err := ULEB128(d, q)
		if err != nil {
			return err
		}
		out[nameIdx] = true
		if q, err = walkValue(nq, d, out); err != nil {
			return err
		}
	}
	return nil
}

// collectArrayStrings 收集一个 encoded_array 中的字符串索引。
func collectArrayStrings(p int, d []byte, out map[uint32]bool) error {
	size, np, err := ULEB128(d, p)
	if err != nil {
		return err
	}
	q := np
	for i := uint32(0); i < size; i++ {
		if q, err = walkValue(q, d, out); err != nil {
			return err
		}
	}
	return nil
}

// walkValue 递归遍历一个 encoded_value，返回新的偏移。
func walkValue(p int, d []byte, out map[uint32]bool) (int, error) {
	if p >= len(d) {
		return p, fmt.Errorf("%w: encoded_value 越界", ErrTruncated)
	}
	at := d[p]
	p++
	vt := at & 0x1f
	va := int((at >> 5) & 0x7)

	switch vt {
	case 0x1c: // array
		size, np, err := ULEB128(d, p)
		if err != nil {
			return p, err
		}
		p = np
		for i := uint32(0); i < size; i++ {
			if p, err = walkValue(p, d, out); err != nil {
				return p, err
			}
		}
		return p, nil
	case 0x1d: // annotation
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
			nameIdx, nq, err := ULEB128(d, p)
			if err != nil {
				return p, err
			}
			out[nameIdx] = true
			if p, err = walkValue(nq, d, out); err != nil {
				return p, err
			}
		}
		return p, nil
	case 0x1e, 0x1f: // null / boolean
		return p, nil
	case 0x17: // string
		v := readUintLE(d, p, va+1)
		out[v] = true
	}
	return p + va + 1, nil
}

// walkInsns 线性遍历一段指令流，自动识别并跳过 switch / fill-array-data payload。
//
// 回调参数：操作码、指令起始字下标、完整字数组。
func walkInsns(words []uint16, visit func(op byte, pos int, words []uint16) error) error {
	payloadAt := map[int]bool{}
	pos := 0
	for pos < len(words) {
		if payloadAt[pos] {
			w, ok, err := payloadWidth(words, pos)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("dex: word %d 处标记为 payload 但标识不匹配 (0x%04x)",
					pos, words[pos])
			}
			if pos+w > len(words) {
				return fmt.Errorf("%w: payload @word %d 越界", ErrTruncated, pos)
			}
			pos += w
			continue
		}

		op := byte(words[pos] & 0xff)
		w, err := insnWidth(words, pos)
		if err != nil {
			return err
		}
		if err := visit(op, pos, words); err != nil {
			return err
		}
		if offWord, ok := branchInsns[op]; ok {
			rel := int32(uint32(words[pos+offWord]) | uint32(words[pos+offWord+1])<<16)
			target := pos + int(rel)
			if target >= 0 && target < len(words) {
				payloadAt[target] = true
			}
		}
		pos += w
	}
	return nil
}

// TypeListAt 读取指定偏移处的 type_list，返回类型索引列表。
func (f *File) TypeListAt(off uint32) ([]uint32, error) {
	if off == 0 {
		return nil, nil
	}
	if int(off)+4 > len(f.data) {
		return nil, fmt.Errorf("%w: type_list 偏移越界 %d", ErrTruncated, off)
	}
	n := binary.LittleEndian.Uint32(f.data[off:])
	if int(off)+4+int(n)*2 > len(f.data) {
		return nil, fmt.Errorf("%w: type_list 内容越界", ErrTruncated)
	}
	out := make([]uint32, 0, n)
	for k := uint32(0); k < n; k++ {
		out = append(out, uint32(binary.LittleEndian.Uint16(f.data[off+4+2*k:])))
	}
	return out, nil
}
