package dex

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"hash/adler32"
)

// DEX 头部常量。
const (
	headerSize    = 0x70
	endianTag     = 0x12345678
	noIndex       = 0xffffffff
	reverseEndian = 0x78563412
)

// DEX 头中的各段索引偏移（相对文件起始）。
const (
	offChecksum   = 8
	offSignature  = 12
	offFileSize   = 32
	offHeaderSize = 36
	offEndianTag  = 40
	offMapList    = 52
	offStringIDs  = 56
	offTypeIDs    = 64
	offProtoIDs   = 72
	offFieldIDs   = 80
	offMethodIDs  = 88
	offClassDefs  = 96
	offDataSize   = 104
	offDataOff    = 108
)

// File 是一个已解析的 DEX 文件。
//
// 解析阶段只读取索引表与元信息；字符串、类数据、字节码等按需惰性解析。
type File struct {
	data []byte

	// 各段条目数量与偏移
	NString   uint32
	OffString uint32
	NType     uint32
	OffType   uint32
	NProto    uint32
	OffProto  uint32
	NField    uint32
	OffField  uint32
	NMethod   uint32
	OffMethod uint32
	NClass    uint32
	OffClass  uint32

	stringCache map[uint32]string
}

// Parse 解析一个 DEX 文件。
func Parse(data []byte) (*File, error) {
	if len(data) < headerSize {
		return nil, fmt.Errorf("%w: 长度 %d 小于头部", ErrNotDex, len(data))
	}
	if !bytes.HasPrefix(data, []byte("dex\n")) {
		return nil, ErrNotDex
	}
	// 版本号形如 "035\0"
	if data[7] != 0 {
		return nil, fmt.Errorf("%w: magic 格式异常", ErrNotDex)
	}
	if tag := binary.LittleEndian.Uint32(data[offEndianTag:]); tag != endianTag {
		if tag == reverseEndian {
			return nil, fmt.Errorf("%w: 暂不支持大端 DEX", ErrNotDex)
		}
		return nil, fmt.Errorf("%w: endian_tag 异常 (0x%08x)", ErrNotDex, tag)
	}

	f := &File{data: data, stringCache: map[uint32]string{}}
	f.NString = binary.LittleEndian.Uint32(data[offStringIDs:])
	f.OffString = binary.LittleEndian.Uint32(data[offStringIDs+4:])
	f.NType = binary.LittleEndian.Uint32(data[offTypeIDs:])
	f.OffType = binary.LittleEndian.Uint32(data[offTypeIDs+4:])
	f.NProto = binary.LittleEndian.Uint32(data[offProtoIDs:])
	f.OffProto = binary.LittleEndian.Uint32(data[offProtoIDs+4:])
	f.NField = binary.LittleEndian.Uint32(data[offFieldIDs:])
	f.OffField = binary.LittleEndian.Uint32(data[offFieldIDs+4:])
	f.NMethod = binary.LittleEndian.Uint32(data[offMethodIDs:])
	f.OffMethod = binary.LittleEndian.Uint32(data[offMethodIDs+4:])
	f.NClass = binary.LittleEndian.Uint32(data[offClassDefs:])
	f.OffClass = binary.LittleEndian.Uint32(data[offClassDefs+4:])

	if err := f.validateSections(); err != nil {
		return nil, err
	}
	return f, nil
}

// validateSections 检查各索引表是否落在文件范围内。
func (f *File) validateSections() error {
	n := uint32(len(f.data))
	checks := []struct {
		name  string
		off   uint32
		count uint32
		size  uint32
	}{
		{"string_ids", f.OffString, f.NString, 4},
		{"type_ids", f.OffType, f.NType, 4},
		{"proto_ids", f.OffProto, f.NProto, 12},
		{"field_ids", f.OffField, f.NField, 8},
		{"method_ids", f.OffMethod, f.NMethod, 8},
		{"class_defs", f.OffClass, f.NClass, 32},
	}
	for _, c := range checks {
		if c.count == 0 {
			// DEX 规范（以及 ART 的校验器）要求：size 为 0 的段，offset 必须为 0。
			// 违反这一条的文件会被 ART 直接拒绝加载，报
			// "Offset(N) should be zero when size is zero"。重写后的 DEX
			// 很容易踩到——例如原 APK 有字段表、改名后字段表为空。
			if c.off != 0 {
				return fmt.Errorf("%w: %s 段 size 为 0 但 offset=%d（规范要求写 0）",
					ErrBadLayout, c.name, c.off)
			}
			continue
		}
		end := c.off + c.count*c.size
		if end < c.off || end > n {
			return fmt.Errorf("%w: %s 段越界 (off=%d count=%d end=%d size=%d)",
				ErrTruncated, c.name, c.off, c.count, end, n)
		}
	}
	return nil
}

// Data 返回底层字节。
func (f *File) Data() []byte { return f.data }

// String 返回第 i 个字符串。
func (f *File) String(i uint32) (string, error) {
	if s, ok := f.stringCache[i]; ok {
		return s, nil
	}
	if i >= f.NString {
		return "", fmt.Errorf("dex: string 索引越界 %d/%d", i, f.NString)
	}
	off := f.OffString + 4*i
	dataOff := binary.LittleEndian.Uint32(f.data[off:])
	if int(dataOff) >= len(f.data) {
		return "", fmt.Errorf("%w: string_data 偏移越界 %d", ErrTruncated, dataOff)
	}
	_, p, err := ULEB128(f.data, int(dataOff)) // utf16 长度，此处不使用
	if err != nil {
		return "", err
	}
	end := bytes.IndexByte(f.data[p:], 0)
	if end < 0 {
		return "", fmt.Errorf("%w: string_data 缺少结尾 0", ErrTruncated)
	}
	s, err := DecodeMUTF8(f.data[p : p+end])
	if err != nil {
		return "", err
	}
	f.stringCache[i] = s
	return s, nil
}

// Type 返回第 i 个类型描述符（形如 "Ljava/lang/String;"）。
func (f *File) Type(i uint32) (string, error) {
	if i >= f.NType {
		return "", fmt.Errorf("dex: type 索引越界 %d/%d", i, f.NType)
	}
	off := f.OffType + 4*i
	return f.String(binary.LittleEndian.Uint32(f.data[off:]))
}

// ProtoParts 返回第 i 个原型的返回类型与参数类型描述符。
func (f *File) ProtoParts(i uint32) (string, []string, error) {
	if i >= f.NProto {
		return "", nil, fmt.Errorf("dex: proto 索引越界 %d/%d", i, f.NProto)
	}
	base := f.OffProto + 12*i
	retIdx := binary.LittleEndian.Uint32(f.data[base+4:])
	paramsOff := binary.LittleEndian.Uint32(f.data[base+8:])

	ret, err := f.Type(retIdx)
	if err != nil {
		return "", nil, err
	}
	var params []string
	if paramsOff != 0 {
		list, err := f.typeList(paramsOff)
		if err != nil {
			return "", nil, err
		}
		params = list
	}
	return ret, params, nil
}

// ProtoDesc 返回第 i 个原型的完整描述符，形如 "(ILjava/lang/String;)V"。
func (f *File) ProtoDesc(i uint32) (string, error) {
	ret, params, err := f.ProtoParts(i)
	if err != nil {
		return "", err
	}
	return BuildProtoDesc(ret, params), nil
}

// BuildProtoDesc 依据返回类型与参数类型拼接方法描述符。
func BuildProtoDesc(ret string, params []string) string {
	var b bytes.Buffer
	b.WriteByte('(')
	for _, p := range params {
		b.WriteString(p)
	}
	b.WriteByte(')')
	b.WriteString(ret)
	return b.String()
}

// typeList 读取一个 type_list 结构（4 字节 size + size 个 u16 type 索引）。
func (f *File) typeList(off uint32) ([]string, error) {
	if int(off)+4 > len(f.data) {
		return nil, fmt.Errorf("%w: type_list 偏移越界 %d", ErrTruncated, off)
	}
	n := binary.LittleEndian.Uint32(f.data[off:])
	if int(off)+4+int(n)*2 > len(f.data) {
		return nil, fmt.Errorf("%w: type_list 内容越界", ErrTruncated)
	}
	out := make([]string, 0, n)
	for k := uint32(0); k < n; k++ {
		idx := binary.LittleEndian.Uint16(f.data[off+4+2*k:])
		t, err := f.Type(uint32(idx))
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// MethodRef 是 method_ids 中的一项。
type MethodRef struct {
	ClassIdx uint16
	ProtoIdx uint16
	NameIdx  uint32
}

// MethodRefAt 返回第 i 个方法引用。
func (f *File) MethodRefAt(i uint32) (MethodRef, error) {
	if i >= f.NMethod {
		return MethodRef{}, fmt.Errorf("dex: method 索引越界 %d/%d", i, f.NMethod)
	}
	base := f.OffMethod + 8*i
	return MethodRef{
		ClassIdx: binary.LittleEndian.Uint16(f.data[base:]),
		ProtoIdx: binary.LittleEndian.Uint16(f.data[base+2:]),
		NameIdx:  binary.LittleEndian.Uint32(f.data[base+4:]),
	}, nil
}

// MethodFull 返回第 i 个方法的所属类、名称、返回类型与参数类型。
func (f *File) MethodFull(i uint32) (string, string, string, []string, error) {
	ref, err := f.MethodRefAt(i)
	if err != nil {
		return "", "", "", nil, err
	}
	cls, err := f.Type(uint32(ref.ClassIdx))
	if err != nil {
		return "", "", "", nil, err
	}
	name, err := f.String(ref.NameIdx)
	if err != nil {
		return "", "", "", nil, err
	}
	ret, params, err := f.ProtoParts(uint32(ref.ProtoIdx))
	if err != nil {
		return "", "", "", nil, err
	}
	return cls, name, ret, params, nil
}

// MethodDesc 返回第 i 个方法的完整签名描述，形如 "Lcls;->name(I)V"。
func (f *File) MethodDesc(i uint32) (string, error) {
	cls, name, ret, params, err := f.MethodFull(i)
	if err != nil {
		return "", err
	}
	return cls + "->" + name + BuildProtoDesc(ret, params), nil
}

// FieldRefAt 返回第 i 个字段引用的所属类、类型与名称索引。
func (f *File) FieldRefAt(i uint32) (classIdx uint16, typeIdx uint16, nameIdx uint32, err error) {
	if i >= f.NField {
		return 0, 0, 0, fmt.Errorf("dex: field 索引越界 %d/%d", i, f.NField)
	}
	base := f.OffField + 8*i
	return binary.LittleEndian.Uint16(f.data[base:]),
		binary.LittleEndian.Uint16(f.data[base+2:]),
		binary.LittleEndian.Uint32(f.data[base+4:]), nil
}

// ClassDef 是 class_defs 中的一项。
type ClassDef struct {
	ClassIdx        uint32
	AccessFlags     uint32
	SuperIdx        uint32
	InterfacesOff   uint32
	SourceFileIdx   uint32
	AnnotationsOff  uint32
	ClassDataOff    uint32
	StaticValuesOff uint32
}

// ClassDefAt 返回第 i 个类定义。
func (f *File) ClassDefAt(i uint32) (ClassDef, error) {
	if i >= f.NClass {
		return ClassDef{}, fmt.Errorf("dex: class 索引越界 %d/%d", i, f.NClass)
	}
	base := f.OffClass + 32*i
	d := f.data[base:]
	return ClassDef{
		ClassIdx:        binary.LittleEndian.Uint32(d),
		AccessFlags:     binary.LittleEndian.Uint32(d[4:]),
		SuperIdx:        binary.LittleEndian.Uint32(d[8:]),
		InterfacesOff:   binary.LittleEndian.Uint32(d[12:]),
		SourceFileIdx:   binary.LittleEndian.Uint32(d[16:]),
		AnnotationsOff:  binary.LittleEndian.Uint32(d[20:]),
		ClassDataOff:    binary.LittleEndian.Uint32(d[24:]),
		StaticValuesOff: binary.LittleEndian.Uint32(d[28:]),
	}, nil
}

// ClassName 返回第 i 个类的类型描述符。
func (f *File) ClassName(i uint32) (string, error) {
	cd, err := f.ClassDefAt(i)
	if err != nil {
		return "", err
	}
	return f.Type(cd.ClassIdx)
}

// Classes 遍历所有类定义。
func (f *File) Classes(fn func(i uint32, cd ClassDef, name string) error) error {
	for i := uint32(0); i < f.NClass; i++ {
		cd, err := f.ClassDefAt(i)
		if err != nil {
			return err
		}
		name, err := f.Type(cd.ClassIdx)
		if err != nil {
			return err
		}
		if err := fn(i, cd, name); err != nil {
			return err
		}
	}
	return nil
}

// AllStrings 返回全部字符串（按索引顺序）。
func (f *File) AllStrings() ([]string, error) {
	out := make([]string, 0, f.NString)
	for i := uint32(0); i < f.NString; i++ {
		s, err := f.String(i)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// ClassData 是一个类的 class_data_item 内容。
type ClassData struct {
	StaticFields   []EncodedField
	InstanceFields []EncodedField
	DirectMethods  []EncodedMethod
	VirtualMethods []EncodedMethod
}

// EncodedField 是 class_data_item 中的字段项。
type EncodedField struct {
	Idx uint32
	Acc uint32
}

// EncodedMethod 是 class_data_item 中的方法项。
type EncodedMethod struct {
	Idx     uint32
	Acc     uint32
	CodeOff uint32
}

// ParseClassData 解析 class_data_item。
func (f *File) ParseClassData(off uint32) (*ClassData, error) {
	if off == 0 {
		return &ClassData{}, nil
	}
	p := int(off)
	sf, p, err := ULEB128(f.data, p)
	if err != nil {
		return nil, err
	}
	inf, p, err := ULEB128(f.data, p)
	if err != nil {
		return nil, err
	}
	dm, p, err := ULEB128(f.data, p)
	if err != nil {
		return nil, err
	}
	vm, p, err := ULEB128(f.data, p)
	if err != nil {
		return nil, err
	}

	cd := &ClassData{}
	readFields := func(n uint32) ([]EncodedField, error) {
		out := make([]EncodedField, 0, n)
		var idx uint32
		for k := uint32(0); k < n; k++ {
			diff, np, err := ULEB128(f.data, p)
			if err != nil {
				return nil, err
			}
			acc, np2, err := ULEB128(f.data, np)
			if err != nil {
				return nil, err
			}
			p = np2
			idx += diff
			out = append(out, EncodedField{Idx: idx, Acc: acc})
		}
		return out, nil
	}
	readMethods := func(n uint32) ([]EncodedMethod, error) {
		out := make([]EncodedMethod, 0, n)
		var idx uint32
		for k := uint32(0); k < n; k++ {
			diff, np, err := ULEB128(f.data, p)
			if err != nil {
				return nil, err
			}
			acc, np2, err := ULEB128(f.data, np)
			if err != nil {
				return nil, err
			}
			co, np3, err := ULEB128(f.data, np2)
			if err != nil {
				return nil, err
			}
			p = np3
			idx += diff
			out = append(out, EncodedMethod{Idx: idx, Acc: acc, CodeOff: co})
		}
		return out, nil
	}

	if cd.StaticFields, err = readFields(sf); err != nil {
		return nil, err
	}
	if cd.InstanceFields, err = readFields(inf); err != nil {
		return nil, err
	}
	if cd.DirectMethods, err = readMethods(dm); err != nil {
		return nil, err
	}
	if cd.VirtualMethods, err = readMethods(vm); err != nil {
		return nil, err
	}
	return cd, nil
}

// AllMethods 遍历 DEX 中所有带代码的方法，回调参数为类名与方法签名描述。
func (f *File) AllMethods(fn func(className, methodDesc string, m EncodedMethod) error) error {
	return f.Classes(func(_ uint32, cd ClassDef, name string) error {
		if cd.ClassDataOff == 0 {
			return nil
		}
		parsed, err := f.ParseClassData(cd.ClassDataOff)
		if err != nil {
			return err
		}
		for _, m := range append(append([]EncodedMethod{}, parsed.DirectMethods...), parsed.VirtualMethods...) {
			desc, err := f.MethodDesc(m.Idx)
			if err != nil {
				return err
			}
			if err := fn(name, desc, m); err != nil {
				return err
			}
		}
		return nil
	})
}

// CodeItem 是一个 code_item 的头部信息。
type CodeItem struct {
	Registers    uint16
	Ins          uint16
	Outs         uint16
	TriesSize    uint16
	DebugInfoOff uint32
	InsnsSize    uint32
	InsnsOff     int
}

// CodeInsns 读取 code_item 头部。
func (f *File) CodeInsns(codeOff uint32) (CodeItem, error) {
	base := int(codeOff)
	if base+16 > len(f.data) {
		return CodeItem{}, fmt.Errorf("%w: code_item 越界 @%d", ErrTruncated, codeOff)
	}
	d := f.data[base:]
	ci := CodeItem{
		Registers:    binary.LittleEndian.Uint16(d),
		Ins:          binary.LittleEndian.Uint16(d[2:]),
		Outs:         binary.LittleEndian.Uint16(d[4:]),
		TriesSize:    binary.LittleEndian.Uint16(d[6:]),
		DebugInfoOff: binary.LittleEndian.Uint32(d[8:]),
		InsnsSize:    binary.LittleEndian.Uint32(d[12:]),
		InsnsOff:     base + 16,
	}
	if ci.InsnsOff+int(ci.InsnsSize)*2 > len(f.data) {
		return CodeItem{}, fmt.Errorf("%w: 字节码越界", ErrTruncated)
	}
	return ci, nil
}

// Finalize 重算 DEX 的 SHA-1 签名与 Adler-32 校验和，返回修正后的数据。
//
// 修改任何字节后都必须调用，否则校验会失败。
func Finalize(data []byte) []byte {
	out := make([]byte, len(data))
	copy(out, data)
	if len(out) < 32 {
		return out
	}
	sum := sha1.Sum(out[32:])
	copy(out[offSignature:offSignature+20], sum[:])
	putU32(out, offChecksum, adler32.Checksum(out[offSignature:]))
	return out
}

// Verify 校验 DEX 的校验和与签名是否自洽。
func Verify(data []byte) error {
	if len(data) < 32 {
		return ErrNotDex
	}
	sum := sha1.Sum(data[32:])
	if !bytes.Equal(sum[:], data[offSignature:offSignature+20]) {
		return fmt.Errorf("dex: SHA-1 签名不匹配")
	}
	if got := binary.LittleEndian.Uint32(data[offChecksum:]); got != adler32.Checksum(data[offSignature:]) {
		return fmt.Errorf("dex: Adler-32 校验和不匹配")
	}
	return nil
}
