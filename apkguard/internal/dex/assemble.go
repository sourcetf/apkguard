package dex

import (
	"encoding/binary"
	"fmt"

	"sort"
	"strings"
)

// RefKind 表示注入代码中的符号引用类型。
type RefKind string

// 注入代码支持的符号引用类型。
const (
	RefString RefKind = "string"
	RefType   RefKind = "type"
	RefField  RefKind = "field"
	RefMethod RefKind = "method"
	RefProto  RefKind = "proto"
)

// RefSpec 描述注入代码中的一个符号引用。
//
// 写壳代码时无法预先知道池索引，因此用符号描述，重建时由引擎解析为实际索引。
type RefSpec struct {
	Kind RefKind
	// Word 是引用索引相对指令起始的字偏移（const-string 为 1，invoke-* 为 1）。
	Word int
	// Wide 表示索引占 32 位（const-string/jumbo）。
	Wide bool

	String string
	Type   string
	Field  FieldSpec
	Method MethodSpec
	Proto  ProtoSpec
}

// InsnPatch 表示「把某条指令中的引用替换为符号引用解析结果」。
type InsnPatch struct {
	// At 是目标指令在 Insns 中的起始字下标。
	At  int
	Ref RefSpec
}

// CodeBlob 描述一个方法的指令流，用于注入新方法。
//
// 这里只支持「无异常表、无调试信息」的简单方法体；注入的壳代码本身
// 也不需要异常表，因此足以覆盖全部注入场景。
type CodeBlob struct {
	Registers uint16
	Ins       uint16
	Outs      uint16
	Insns     []uint16
	// Patches 指定需要按符号解析并回填的池引用。
	Patches []InsnPatch
}

// Bytes 把方法体编码为 code_item 字节流，并按符号描述回填池引用。
func (c *CodeBlob) Bytes(pl *plan) ([]byte, error) {
	out := make([]byte, 16+len(c.Insns)*2)
	binary.LittleEndian.PutUint16(out[0:], c.Registers)
	binary.LittleEndian.PutUint16(out[2:], c.Ins)
	binary.LittleEndian.PutUint16(out[4:], c.Outs)
	binary.LittleEndian.PutUint16(out[6:], 0) // tries_size
	binary.LittleEndian.PutUint32(out[8:], 0) // debug_info_off
	binary.LittleEndian.PutUint32(out[12:], uint32(len(c.Insns)))
	for i, w := range c.Insns {
		binary.LittleEndian.PutUint16(out[16+2*i:], w)
	}
	for _, p := range c.Patches {
		if p.At < 0 || p.At+1 > len(c.Insns) {
			return nil, fmt.Errorf("dex: 注入代码的补丁位置 %d 越界", p.At)
		}
		idx, err := pl.resolveRef(p.Ref)
		if err != nil {
			return nil, err
		}
		if p.Ref.Wide {
			if p.At+2 > len(c.Insns) {
				return nil, fmt.Errorf("dex: 注入代码的宽引用补丁 %d 越界", p.At)
			}
			binary.LittleEndian.PutUint16(out[16+2*p.At:], uint16(idx&0xffff))
			binary.LittleEndian.PutUint16(out[16+2*(p.At+1):], uint16(idx>>16))
			continue
		}
		if idx > 0xffff {
			return nil, fmt.Errorf("dex: 注入代码引用的索引 %d 超出 16 位（需要加宽指令）", idx)
		}
		binary.LittleEndian.PutUint16(out[16+2*p.At:], uint16(idx))
	}
	return out, nil
}

// resolveRef 把符号引用解析为池索引。
func (pl *plan) resolveRef(r RefSpec) (uint32, error) {
	switch r.Kind {
	case RefString:
		i, ok := pl.stringIdx[r.String]
		if !ok {
			return 0, fmt.Errorf("dex: 注入代码引用的字符串 %q 未登记", r.String)
		}
		return i, nil
	case RefType:
		i, ok := pl.typeIdx[r.Type]
		if !ok {
			return 0, fmt.Errorf("dex: 注入代码引用的类型 %q 未登记", r.Type)
		}
		return i, nil
	case RefField:
		i, ok := pl.fieldIdx[r.Field.Key()]
		if !ok {
			return 0, fmt.Errorf("dex: 注入代码引用的字段 %s 未登记", r.Field.Key())
		}
		return i, nil
	case RefMethod:
		i, ok := pl.methodIdx[r.Method.Key()]
		if !ok {
			return 0, fmt.Errorf("dex: 注入代码引用的方法 %s 未登记", r.Method.Desc())
		}
		return i, nil
	case RefProto:
		i, ok := pl.protoIdx[r.Proto.Key()]
		if !ok {
			return 0, fmt.Errorf("dex: 注入代码引用的原型 %s 未登记", r.Proto.Desc())
		}
		return i, nil
	}
	return 0, fmt.Errorf("dex: 未知的注入引用类型 %q", r.Kind)
}

// builder 负责把各数据区元素重新放置并输出完整 DEX。
//
// DEX 要求「同一类型的条目在数据区中连续存放」，因此各 section 使用独立缓冲区，
// 待全部条目生成完毕后再统一排布偏移。由于 class_data_item 中的 code_off 是
// ULEB128 变长编码，条目长度依赖偏移取值，因此需要迭代「测量 → 重排」直至收敛。
type builder struct {
	f    *File
	R    *Remap
	opts RebuildOptions

	buf   map[uint16][]byte // 各 section 的内容
	base  map[uint16]uint32 // 各 section 的起始偏移
	count map[uint16]uint32 // 各 section 的条目数
}

// dataSectionOrder 是数据区各 section 的存放顺序。
//
// 顺序不影响正确性（map_list 会按偏移排序），按此顺序可让 4 字节对齐的
// 条目集中在前，减少填充字节。
var dataSectionOrder = []uint16{
	0x1001, // type_list
	0x1002, // annotation_set_ref_list
	0x1003, // annotation_set_item
	0x2006, // annotations_directory_item
	0x2001, // code_item
	0x2003, // debug_info_item
	0x2002, // string_data_item
	0x2005, // encoded_array_item
	0x2000, // class_data_item
	0x2004, // annotation_item
}

// unsupportedSectionNames 是「重建不保留」的 DEX 段（map_list 类型码 -> 名称）。
//
// dataSectionOrder 只列了 10 个段，call_site_ids（0x0007）与 method_handles
// （0x0008）都不在其中，map_list 也不登记它们。而 0xfa-0xfe 指令的索引正指向
// 这两段：任何含 invoke-custom / const-method-handle 的输入 DEX 经任一改写
// （A2/A3/A4/A6…）重建后，段消失、指令索引悬空，ART 结构校验必然拒绝加载。
//
// 正确保留需要一并重排这两段的内部索引（call_site_id 指向 method_handle 与
// 字符串/类型，method_handle 又指向成员），工作量大且难以验证；按项目原则
// 「宁可失败也不静默产出坏文件」，这里改为显式拒绝。
var unsupportedSectionNames = map[uint16]string{
	0x0007: "call_site_ids",
	0x0008: "method_handles",
}

// unsupportedInsnNames 是依赖上述两段的指令（0xfa-0xfe）。
//
// 0xfc/0xfd（invoke-custom）引用 call_site_ids；0xfe（const-method-handle）
// 引用 method_handles。0xfa/0xfb（invoke-polymorphic）本身只引用
// method_ids + proto_ids，但本工具对这三条指令的改写/校验路径并不完整
// （见 cff.go 的保守跳过），一并拒绝更符合「宁可失败」。
var unsupportedInsnNames = map[byte]string{
	0xfa: "invoke-polymorphic",
	0xfb: "invoke-polymorphic/range",
	0xfc: "invoke-custom",
	0xfd: "invoke-custom/range",
	0xfe: "const-method-handle",
}

// checkRebuildSupported 在重建前拒绝本工具无法安全处理的输入。
//
// 命中条件（任一）：map_list 里存在非空 count 的 call_site_ids/method_handles
// 段；或任一方法体里出现 0xfa-0xfe 指令。命中即返回明确错误，绝不静默继续。
func checkRebuildSupported(f *File) error {
	if secs := unsupportedSectionsInMap(f); len(secs) > 0 {
		return fmt.Errorf("%w：输入含 %s 段。invoke-custom/const-method-handle 的"+
			"索引指向这些段，重建会丢弃段且不重排其索引，继续会产出结构非法的 DEX"+
			"（ART 结构校验将拒绝加载）；请先用 d8/apktool 等重新编译以消除这些指令",
			ErrUnsupportedCallSite, strings.Join(secs, "、"))
	}
	op, where, err := findUnsupportedCallSiteInsn(f)
	if err != nil {
		return err
	}
	if where != "" {
		return fmt.Errorf("%w：%s 中出现指令 0x%02x（%s）。这类指令依赖 "+
			"call_site_ids/method_handles 段，重建会丢弃段且不重排其索引，"+
			"继续会产出结构非法的 DEX",
			ErrUnsupportedCallSite, where, op, unsupportedInsnNames[op])
	}
	return nil
}

// unsupportedSectionsInMap 返回 map_list 中非空 count 的不支持段名称（已排序）。
func unsupportedSectionsInMap(f *File) []string {
	d := f.data
	if len(d) < offMapList+4 {
		return nil
	}
	mapOff := binary.LittleEndian.Uint32(d[offMapList:])
	if mapOff == 0 || int(mapOff)+4 > len(d) {
		return nil
	}
	n := binary.LittleEndian.Uint32(d[mapOff:])
	if int(mapOff)+4+int(n)*12 > len(d) {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for i := uint32(0); i < n; i++ {
		base := int(mapOff) + 4 + 12*int(i)
		name, ok := unsupportedSectionNames[binary.LittleEndian.Uint16(d[base:])]
		if !ok || seen[name] || binary.LittleEndian.Uint32(d[base+4:]) == 0 {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// findUnsupportedCallSiteInsn 扫描全部方法体，返回首个 0xfa-0xfe 指令的
// 操作码与所在方法描述。找不到返回 ("", "")。
func findUnsupportedCallSiteInsn(f *File) (byte, string, error) {
	var foundOp byte
	var foundWhere string
	err := f.AllMethods(func(_, methodDesc string, m EncodedMethod) error {
		if foundWhere != "" || m.CodeOff == 0 {
			return nil
		}
		ci, err := f.CodeInsns(m.CodeOff)
		if err != nil {
			return nil // 无法解析的方法体会在后续重建步骤里报错，这里不重复报
		}
		words := make([]uint16, ci.InsnsSize)
		for i := range words {
			words[i] = binary.LittleEndian.Uint16(f.data[ci.InsnsOff+2*i:])
		}
		// 与 remapCode 相同：payload 是内联伪指令，必须整体跳过，
		// 否则其中的数据字节会被误当成操作码（假阳性）。
		payloadAt := map[int]bool{}
		for pos := 0; pos < len(words); {
			if payloadAt[pos] {
				w, ok, perr := payloadWidth(words, pos)
				if perr != nil || !ok {
					break
				}
				pos += w
				continue
			}
			op := byte(words[pos] & 0xff)
			if name, ok := unsupportedInsnNames[op]; ok {
				foundOp, foundWhere = op, name+"（"+methodDesc+"）"
				return nil
			}
			w, werr := insnWidth(words, pos)
			if werr != nil {
				break
			}
			if offWord, ok := branchInsns[op]; ok && pos+offWord+1 < len(words) {
				rel := int32(uint32(words[pos+offWord]) | uint32(words[pos+offWord+1])<<16)
				if t := pos + int(rel); t >= 0 && t < len(words) {
					payloadAt[t] = true
				}
			}
			pos += w
		}
		return nil
	})
	if err != nil {
		return 0, "", err
	}
	return foundOp, foundWhere, nil
}

// place 把一个条目追加到对应 section 的缓冲区，返回其绝对偏移。
func (b *builder) place(sectionType uint16, blob []byte, align int) uint32 {
	buf := b.buf[sectionType]
	base := b.base[sectionType]
	for align > 1 && (int(base)+len(buf))%align != 0 {
		buf = append(buf, 0)
	}
	off := base + uint32(len(buf))
	b.buf[sectionType] = append(buf, blob...)
	b.count[sectionType]++
	return off
}

// typeListKey 用于去重 type_list。
type typeListKey string

// layout 保存一遍生成得到的索引表字节。
type layout struct {
	stringIDs, typeIDs, protoIDs, fieldIDs, methodIDs, classDefs []byte
}

// assemble 是重建入口：先测量各 section 大小，再排布偏移，最后重新生成并组装文件。
func (b *builder) assemble(pl *plan) ([]byte, error) {
	f := b.f

	nStr := len(pl.pool)
	nType := len(pl.types)
	nProto := len(pl.protos)
	nField := len(pl.fields)
	nMethod := len(pl.methods)
	nClass := len(pl.classes)

	offStr := uint32(headerSize)
	offType := offStr + uint32(nStr)*4
	offProto := offType + uint32(nType)*4
	offField := offProto + uint32(nProto)*12
	offMethod := offField + uint32(nField)*8
	offClass := offMethod + uint32(nMethod)*8
	dataBase := offClass + uint32(nClass)*32
	dataBase += (4 - dataBase%4) % 4

	// ---- 迭代排布各 section 偏移直至稳定 ----
	var bases map[uint16]uint32
	var lay *layout
	for iter := 0; ; iter++ {
		l, err := b.generate(pl, bases)
		if err != nil {
			return nil, err
		}
		lay = l

		next := map[uint16]uint32{}
		cur := dataBase
		for _, tc := range dataSectionOrder {
			if len(b.buf[tc]) == 0 {
				continue
			}
			// 各 section 起点一律按 4 字节对齐，使内部填充量只取决于条目长度。
			cur = (cur + 3) &^ 3
			next[tc] = cur
			cur += uint32(len(b.buf[tc]))
		}

		if iter > 0 && sameBases(bases, next) {
			break
		}
		if iter >= 8 {
			return nil, fmt.Errorf("dex: 数据区布局未能在 8 次迭代内收敛")
		}
		bases = next
	}

	// ---- map_list ----
	end := dataBase
	for _, tc := range dataSectionOrder {
		if e := bases[tc] + uint32(len(b.buf[tc])); e > end {
			end = e
		}
	}
	mapOff := end + (4-end%4)%4

	type mapEntry struct {
		typ   uint16
		count uint32
		off   uint32
	}
	// map_list 只描述**存在**的段：size 为 0 的段不能出现在这里
	// （同样由 ART 校验器强制）。
	entries := []mapEntry{{0x0000, 1, 0}}
	for _, e := range []mapEntry{
		{0x0001, uint32(nStr), offStr},
		{0x0002, uint32(nType), offType},
		{0x0003, uint32(nProto), offProto},
		{0x0004, uint32(nField), offField},
		{0x0005, uint32(nMethod), offMethod},
		{0x0006, uint32(nClass), offClass},
	} {
		if e.count == 0 {
			continue
		}
		entries = append(entries, e)
	}
	for _, tc := range dataSectionOrder {
		if len(b.buf[tc]) == 0 {
			continue
		}
		entries = append(entries, mapEntry{tc, b.count[tc], bases[tc]})
	}
	entries = append(entries, mapEntry{0x1000, 1, mapOff})
	sort.Slice(entries, func(a, c int) bool { return entries[a].off < entries[c].off })

	mapList := make([]byte, 4+len(entries)*12)
	binary.LittleEndian.PutUint32(mapList, uint32(len(entries)))
	for i, e := range entries {
		base := 4 + 12*i
		binary.LittleEndian.PutUint16(mapList[base:], e.typ)
		binary.LittleEndian.PutUint16(mapList[base+2:], 0)
		binary.LittleEndian.PutUint32(mapList[base+4:], e.count)
		binary.LittleEndian.PutUint32(mapList[base+8:], e.off)
	}

	// ---- 组装 ----
	out := make([]byte, 0, int(mapOff)+len(mapList))
	out = append(out, make([]byte, headerSize)...)
	out = append(out, lay.stringIDs...)
	out = append(out, lay.typeIDs...)
	out = append(out, lay.protoIDs...)
	out = append(out, lay.fieldIDs...)
	out = append(out, lay.methodIDs...)
	out = append(out, lay.classDefs...)
	for len(out)%4 != 0 {
		out = append(out, 0)
	}
	for _, tc := range dataSectionOrder {
		if len(b.buf[tc]) == 0 {
			continue
		}
		for uint32(len(out)) < bases[tc] {
			out = append(out, 0)
		}
		out = append(out, b.buf[tc]...)
	}
	for uint32(len(out)) < mapOff {
		out = append(out, 0)
	}
	out = append(out, mapList...)

	// DEX 规范与 ART 校验都要求：某个 id 段 size 为 0 时，它的 offset 必须写 0。
	//
	// 这不是形式主义：ART 的校验器会因此直接拒绝整个 DEX
	// （"Offset(N) should be zero when size is zero"），表现就是应用在加载
	// 这个 DEX 时崩掉。重写后的 DEX 很容易出现「段被清空但偏移还是旧值」
	// （例如原 APK 有字段、改名后字段表为空），因此必须在这里统一归零。
	if nStr == 0 {
		offStr = 0
	}
	if nType == 0 {
		offType = 0
	}
	if nProto == 0 {
		offProto = 0
	}
	if nField == 0 {
		offField = 0
	}
	if nMethod == 0 {
		offMethod = 0
	}
	if nClass == 0 {
		offClass = 0
	}

	total := uint32(len(out))
	copy(out[0:8], f.data[0:8])
	// DEX 版本归一化：低于 037 的输入（老工具链产物，如 RustDesk 的 035）
	// 一律提升到 037。
	//
	// 版本号只表示「文件里允许出现哪些较新的格式特性」，035 的文件不可能
	// 用到 037 才引入的特性，因此提升是安全的；而现代安卓对过低版本会
	// 直接拒绝加载——实测安卓 16 会拒，表现为加固后业务类装载不到
	// （ClassNotFoundException），且本地任何结构校验都看不出来
	// （我们的分片仍能通过 dex2oat 校验器）。
	if out[4] == '0' && out[5] == '3' && (out[6] < '7') {
		out[4], out[5], out[6] = '0', '3', '7'
	}
	binary.LittleEndian.PutUint32(out[offFileSize:], total)
	binary.LittleEndian.PutUint32(out[offHeaderSize:], headerSize)
	binary.LittleEndian.PutUint32(out[offEndianTag:], endianTag)
	binary.LittleEndian.PutUint32(out[offMapList:], mapOff)
	binary.LittleEndian.PutUint32(out[offStringIDs:], uint32(nStr))
	binary.LittleEndian.PutUint32(out[offStringIDs+4:], offStr)
	binary.LittleEndian.PutUint32(out[offTypeIDs:], uint32(nType))
	binary.LittleEndian.PutUint32(out[offTypeIDs+4:], offType)
	binary.LittleEndian.PutUint32(out[offProtoIDs:], uint32(nProto))
	binary.LittleEndian.PutUint32(out[offProtoIDs+4:], offProto)
	binary.LittleEndian.PutUint32(out[offFieldIDs:], uint32(nField))
	binary.LittleEndian.PutUint32(out[offFieldIDs+4:], offField)
	binary.LittleEndian.PutUint32(out[offMethodIDs:], uint32(nMethod))
	binary.LittleEndian.PutUint32(out[offMethodIDs+4:], offMethod)
	binary.LittleEndian.PutUint32(out[offClassDefs:], uint32(nClass))
	binary.LittleEndian.PutUint32(out[offClassDefs+4:], offClass)
	binary.LittleEndian.PutUint32(out[offDataSize:], total-dataBase)
	binary.LittleEndian.PutUint32(out[offDataOff:], dataBase)

	return Finalize(out), nil
}

// sameBases 判断两组 section 起始偏移是否完全相同。
func sameBases(a, b map[uint16]uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// resolveAnnoOff 把 class_def 的旧 annotations_directory 偏移解析为新偏移。
//
// annoOff == 0 表示该类没有注解（合法）。非 0 却查不到映射说明注解树与
// class_def 不自洽：早期实现直接 dirMap[annoOff] 会返回零值，把注解目录
// 静默清掉（产物丢注解且无声）。这里改为报错。
func resolveAnnoOff(dirMap map[uint32]uint32, annoOff uint32) (uint32, error) {
	if annoOff == 0 {
		return 0, nil
	}
	v, ok := dirMap[annoOff]
	if !ok {
		return 0, fmt.Errorf("dex: 类的 annotations_directory 偏移 %d 未在注解树中重映射（结构不自洽）", annoOff)
	}
	return v, nil
}

// generate 生成一遍索引表与数据区内容。
//
// base 给出各 section 的起始偏移；传 nil 表示仅测量大小（此时偏移按 0 计算，
// 结果只用于确定长度，随后会被丢弃）。
func (b *builder) generate(pl *plan, base map[uint16]uint32) (*layout, error) {
	f := b.f
	d := f.data

	b.buf = map[uint16][]byte{}
	b.base = map[uint16]uint32{}
	b.count = map[uint16]uint32{}
	for k, v := range base {
		b.base[k] = v
	}

	nStr := len(pl.pool)
	nType := len(pl.types)
	nProto := len(pl.protos)
	nField := len(pl.fields)
	nMethod := len(pl.methods)
	nClass := len(pl.classes)

	// ---- type_list（去重）----
	tlCache := map[typeListKey]uint32{}
	makeTypeList := func(idx []uint32) uint32 {
		if len(idx) == 0 {
			return 0
		}
		key := make([]byte, 0, len(idx)*2)
		for _, v := range idx {
			key = append(key, byte(v), byte(v>>8))
		}
		k := typeListKey(key)
		if off, ok := tlCache[k]; ok {
			return off
		}
		blob := make([]byte, 4+len(idx)*2)
		binary.LittleEndian.PutUint32(blob, uint32(len(idx)))
		for i, v := range idx {
			binary.LittleEndian.PutUint16(blob[4+2*i:], uint16(v))
		}
		off := b.place(0x1001, blob, 4)
		tlCache[k] = off
		return off
	}
	// 旧 type_list：按旧偏移读取并重映射
	makeOldTypeList := func(oldOff uint32) (uint32, error) {
		if oldOff == 0 {
			return 0, nil
		}
		if int(oldOff)+4 > len(d) {
			return 0, fmt.Errorf("%w: type_list 偏移越界 %d", ErrTruncated, oldOff)
		}
		n := binary.LittleEndian.Uint32(d[oldOff:])
		if int(oldOff)+4+2*int(n) > len(d) {
			return 0, fmt.Errorf("%w: type_list @%d 声明 %d 项，超出文件范围", ErrTruncated, oldOff, n)
		}
		idx := make([]uint32, 0, n)
		for k := uint32(0); k < n; k++ {
			old := binary.LittleEndian.Uint16(d[oldOff+4+2*k:])
			v, err := mapRefChecked(b.R.Type, uint32(old), "type_list type")
			if err != nil {
				return 0, err
			}
			idx = append(idx, v)
		}
		return makeTypeList(idx), nil
	}

	// ---- 原型参数 type_list ----
	protoParamsOff := make([]uint32, nProto)
	for i, p := range pl.protos {
		protoParamsOff[i] = makeTypeList(p.params)
	}

	// ---- 旧类信息 ----
	type oldClass struct {
		idx int // 在 pl.classes 中的下标
		cd  ClassData
	}
	parsedCD := map[uint32]*ClassData{}
	codeOffs := []uint32{}
	seenCode := map[uint32]bool{}
	// codeName 记录「code_item 偏移 -> 方法名」，供 A6 保守跳过 <init>/<clinit>。
	// 多个方法可共享同一 code_off（少见但合法），取第一个到的名字即可。
	codeName := map[uint32]string{}
	for i := range pl.classes {
		c := &pl.classes[i]
		if c.old == noOld || c.dataOff == 0 {
			continue
		}
		if _, ok := parsedCD[c.dataOff]; ok {
			continue
		}
		pcd, err := f.ParseClassData(c.dataOff)
		if err != nil {
			return nil, err
		}
		parsedCD[c.dataOff] = pcd
		for _, lst := range [][]EncodedMethod{pcd.DirectMethods, pcd.VirtualMethods} {
			for _, m := range lst {
				if m.CodeOff == 0 {
					continue
				}
				if !seenCode[m.CodeOff] {
					seenCode[m.CodeOff] = true
					codeOffs = append(codeOffs, m.CodeOff)
				}
				if _, ok := codeName[m.CodeOff]; !ok {
					if ref, err := f.MethodRefAt(m.Idx); err == nil {
						if nm, err := f.String(ref.NameIdx); err == nil {
							codeName[m.CodeOff] = nm
						}
					}
				}
			}
		}
	}
	sort.Slice(codeOffs, func(a, c int) bool { return codeOffs[a] < codeOffs[c] })

	// ---- 1) debug_info ----
	debugMap := map[uint32]uint32{}
	if !b.opts.DropDebugInfo {
		for _, co := range codeOffs {
			dbgOff := binary.LittleEndian.Uint32(d[co+8:])
			if dbgOff == 0 {
				continue
			}
			if _, ok := debugMap[dbgOff]; ok {
				continue
			}
			length, err := b.debugInfoLength(dbgOff)
			if err != nil {
				return nil, err
			}
			blob, err := b.remapDebugInfo(dbgOff, length)
			if err != nil {
				return nil, err
			}
			debugMap[dbgOff] = b.place(0x2003, blob, 1)
		}
	}

	// ---- 2) 注解树 ----
	_, _, _, dirMap, err := b.emitAnnotations()
	if err != nil {
		return nil, err
	}

	// ---- 3) code_item ----
	// A6 的统计在每轮 generate 开头清零：assemble 会迭代多次 generate 以收敛
	// 数据区布局，method 改写是确定性的，但统计若累加会翻倍。
	if pl.controlFlow != nil {
		pl.controlFlow.stats = ControlFlowStats{}
	}
	// A3 的计数同样必须每轮清零：arrayizeCodeItem 是累加式的，
	// 而 assemble 会迭代多次 generate 以收敛数据区布局，累加会把
	// 「实际改写 1 个」记成 2 个（实测：A2→A3 串行时 A3.strings 报 2）。
	if pl.constArr != nil {
		pl.constArr.count = 0
	}
	// 加宽统计每轮清零，理由同 A3/A6（assemble 会多次 generate）。
	pl.widen = WidenStats{}
	codeMap := map[uint32]uint32{}
	for _, co := range codeOffs {
		var blob []byte
		if repl, ok := b.opts.CodeReplacements[co]; ok {
			blob = append([]byte(nil), repl...)
		} else {
			length, err := b.codeItemLength(co)
			if err != nil {
				return nil, err
			}
			blob = append([]byte(nil), d[co:co+uint32(length)]...)
			// skip 汇总「已是新索引、不可再映射」的字位置，交给 remapCode。
			//
			// 坐标系约定：skip 始终是**当前 blob** 的绝对字位置。每一步改写
			// （A2/A3）都会把自己的输出坐标系回传，并在接收上游 skip 时先做
			// 坐标平移（arrayizeCodeItem 的 inSkip 参数 / widenConstStrings 的
			// skip 参数）。绝不能把不同步骤坐标系的位置直接求并集：那会让
			// remapCode 漏跳或错跳，把已是最终值的索引按旧表二次映射，产物静默
			// 损坏（实测报 "method 索引越界 51/46"）。
			var skip map[int]bool
			// A6：控制流混淆。
			//
			// 必须排在 A2/A3 **之前**。A2/A3 返回的是**绝对字位置**，交给后面的
			// remapCode 使用；A6 会插入/替换指令、整体平移后续字位置，若排在
			// A2/A3 之后，那些位置会全部错位。A6 自身不产生任何池引用、
			// 不需要 skip，且不触碰 const-string，对后续 A2/A3 无干扰，因此放在
			// 最前最稳。
			if pl.controlFlow != nil {
				nb, sk, changed, err := b.controlFlowCodeItem(pl, codeName[co], blob)
				if err != nil {
					return nil, err
				}
				if changed {
					blob = nb
					skip = sk
				}
			}
			// A2/A3：改写 const-string。
			//
			// 两者都作用于同一条指令，因此必须串行：先 A2（把明文换成
			// 「密文 + 解密调用」），再 A3（对未被 A2 处理的常量做数组化）。
			// 每一步都会改变指令流长度，而 try/handler 的偏移已由各步内部修正。
			if pl.strEnc != nil {
				nb, sk, changed, err := b.encryptCodeItem(pl, blob)
				if err != nil {
					return nil, err
				}
				if changed {
					blob = nb
					skip = sk
				}
			}
			if pl.constArr != nil {
				// 传入当前 skip（坐标为 blob），arrayizeCodeItem 会把它平移到
				// 自己的产物坐标系并与自身 fresh 合并后返回。
				nb, sk, changed, err := b.arrayizeCodeItem(pl, blob, skip)
				if err != nil {
					return nil, err
				}
				if changed {
					blob = nb
				}
				// 无论是否发生改写，都采用回传的 skip：没有改写时它就是平移后
				// 的上游 skip（坐标系不变，直接沿用）。
				skip = sk
			}
			// 字符串索引越界自动加宽：把新下标 >65535 的 const-string
			// 换成 const-string/jumbo。
			//
			// 必须排在 A2/A3 **之后**：只有这两步改完之后，剩下的 0x1a 才是
			// 真正需要加宽的对象；也必须排在 remapCode **之前**，因为 remapCode
			// 按固定宽度线性遍历，加宽改变了字位置。
			//
			// 本步返回平移后的 skip（按项内相对偏移换算），坐标系为加宽后 blob。
			{
				nb, nsk, changed, err := b.widenConstStrings(pl, blob, skip)
				if err != nil {
					return nil, err
				}
				if changed {
					blob = nb
					skip = nsk
				}
			}
			// 修正 debug_info_off
			oldDbg := binary.LittleEndian.Uint32(blob[8:])
			binary.LittleEndian.PutUint32(blob[8:], debugMap[oldDbg])
			// 重映射字节码中的池引用（含异常处理器的捕获类型）
			nb2, rerr := b.remapCode(blob, skip)
			if rerr != nil {
				return nil, rerr
			}
			blob = nb2
		}
		codeMap[co] = b.place(0x2001, blob, 4)
	}

	// 注入方法的 code_item：键为「类下标<<32 | 方法序号」不必要，直接用指针标识
	injectedCode := map[*CodeBlob]uint32{}
	for i := range pl.classes {
		c := &pl.classes[i]
		if c.spec == nil {
			continue
		}
		for k := range c.spec.Methods {
			cm := &c.spec.Methods[k]
			if cm.Code == nil {
				continue
			}
			if _, ok := injectedCode[cm.Code]; ok {
				continue
			}
			blob, err := cm.Code.Bytes(pl)
			if err != nil {
				return nil, err
			}
			injectedCode[cm.Code] = b.place(0x2001, blob, 4)
		}
	}

	// ---- 4) string_data ----
	strMap := make([]uint32, nStr)
	// 复用原始编码字节，避免 MUTF-8 往返损失
	origBytes := map[string][]byte{}
	for i := uint32(0); i < f.NString; i++ {
		so := binary.LittleEndian.Uint32(d[f.OffString+4*i:])
		_, p, err := ULEB128(d, int(so))
		if err != nil {
			return nil, err
		}
		end := bytesIndexByte(d[p:], 0)
		if end < 0 {
			return nil, fmt.Errorf("%w: string_data 缺少结尾 0", ErrTruncated)
		}
		s, err := f.String(i)
		if err != nil {
			return nil, err
		}
		if _, ok := origBytes[s]; !ok {
			origBytes[s] = d[so : p+end+1]
		}
	}
	for i, s := range pl.pool {
		blob, ok := origBytes[s]
		if !ok {
			blob = append(PutULEB128(nil, uint32(UTF16Len(s))), EncodeMUTF8(s)...)
		}
		strMap[i] = b.place(0x2002, blob, 1)
	}

	// ---- 5) static values ----
	//
	// 必须**按新的静态字段顺序重排**，不能只做原地重映射：
	// static_values 的第 i 个值对应「按 field_idx 升序排列后的第 i 个静态字段」，
	// 而 A1 改名会改变 field_idx 的排序，原顺序的数组会与字段错位。
	// ART 的结构校验器会因此拒绝整个 DEX：
	//   "unexpected static field initial value type: 'L' vs 'I'"
	// （真实案例：RustDesk 加固后 16 个分片中的 d1.dex 被整体拒绝，
	//   其内所有类都无法解析，表现为 NoClassDefFoundError。）
	//
	// valuesMap 按**内容**去重 encoded_array_item。
	//
	// 真实 DEX 里多个类经常共享同一个 static_values（典型是「全是默认值」
	// 的类，dx/d8 会让它们的 class_def.static_values_off 指向同一项）。原实现
	// 对每个 valuesOff != 0 的类各 place 一份，共享被逐类复制——termux 实测
	// +27 KB。与 debugMap / tlCache / cdMap 同一思路加缓存。
	//
	// 键用拼装后的字节而不是旧偏移：A1 会改变 field_idx 排序，两个共享同一旧
	// 数组的类若静态字段集合不同，拼出的 blob 也可能不同；按键值去重只在
	// 内容完全相同时复用，绝不会让两个类指向错误的数组。
	valuesMap := map[string]uint32{}
	for i := range pl.classes {
		c := &pl.classes[i]
		if c.old == noOld || c.valuesOff == 0 {
			continue
		}
		vals, err := b.remapEncodedArrayValues(c.valuesOff)
		if err != nil {
			return nil, err
		}
		pcd := parsedCD[c.dataOff]
		if pcd == nil {
			continue
		}
		// 新顺序：静态字段按新 field_idx 升序（与 emitClassData 一致）。
		type sfEnt struct {
			newIdx uint32
			oldPos int
		}
		ents := make([]sfEnt, 0, len(pcd.StaticFields))
		for oldPos, fl := range pcd.StaticFields {
			ents = append(ents, sfEnt{newIdx: b.R.Field[fl.Idx], oldPos: oldPos})
		}
		sort.SliceStable(ents, func(a, c2 int) bool { return ents[a].newIdx < ents[c2].newIdx })
		// 与 emitClassData 的字段去重保持一致：塌缩后同索引只保留
		// 原始顺序中的第一条，使 static_values 的个数与 class_data 的静态字段数一致。
		if len(ents) > 0 {
			kept := ents[:1]
			for k := 1; k < len(ents); k++ {
				if ents[k].newIdx == kept[len(kept)-1].newIdx {
					continue
				}
				kept = append(kept, ents[k])
			}
			ents = kept
		}

		// 自校验：每个值切片必须自身合法，否则拼出的数组会字节错位。
		for idx, e := range ents {
			if e.oldPos >= len(vals) {
				continue
			}
			if ok, vt := validateEncodedValue(vals[e.oldPos]); !ok {
				return nil, fmt.Errorf(
					"dex: 类 %s（old=%d valuesOff=%d）的 static_values 第 %d 个值（oldPos=%d）不合法（type=0x%02x，%d 字节，值=% x）",
					fullyQualifiedName(pl, c.classIdx), c.old, c.valuesOff, idx, e.oldPos, vt, len(vals[e.oldPos]), vals[e.oldPos])
			}
		}
		blob := PutULEB128(nil, uint32(len(ents)))
		appended := 0
		for _, e := range ents {
			if e.oldPos < len(vals) {
				if len(vals[e.oldPos]) == 0 {
					return nil, fmt.Errorf("dex: 类 %s 第 %d 个值（oldPos=%d）为空切片",
						fullyQualifiedName(pl, c.classIdx), appended, e.oldPos)
				}
				blob = append(blob, vals[e.oldPos]...)
				appended++
				continue
			}
			// 原数组省略了尾部默认值：按字段类型补默认值。
			ft := ""
			if _, typeIdx, _, ferr := b.f.FieldRefAt(pcd.StaticFields[e.oldPos].Idx); ferr == nil {
				if t, terr := b.f.Type(uint32(typeIdx)); terr == nil {
					ft = t
				}
			}
			blob = append(blob, defaultEncodedValue(ft)...)
		}
		// 整体自校验：拼好的数组必须能被完整解析出 len(ents) 个值。
		// 否则写进产物后，ART 会报 "Bogus encoded_value value_type" 并拒绝整个 DEX
		// （真实案例：RustDesk 加固后 d1.dex 被拒，其内所有类都无法解析）。
		if bad, why := validateEncodedArray(blob, len(ents)); bad >= 0 {
			return nil, fmt.Errorf(
				"dex: 类 %s（old=%d）的 static_values 拼装后不合法：%s（共 %d 字节）",
				fullyQualifiedName(pl, c.classIdx), c.old, why, len(blob))
		}
		if off, ok := valuesMap[string(blob)]; ok {
			c.valuesNew = off
			continue
		}
		c.valuesNew = b.place(0x2005, blob, 1)
		valuesMap[string(blob)] = c.valuesNew
	}

	// ---- 6) class_data ----
	cdMap := map[uint32]uint32{}
	injectedData := map[*ClassSpec]uint32{}
	for i := range pl.classes {
		c := &pl.classes[i]
		if c.spec != nil {
			blob, err := emitInjectedClassData(c.spec, pl, injectedCode)
			if err != nil {
				return nil, err
			}
			if blob == nil {
				injectedData[c.spec] = 0
				continue
			}
			injectedData[c.spec] = b.place(0x2000, blob, 1)
			continue
		}
		if c.dataOff == 0 {
			continue
		}
		if _, ok := cdMap[c.dataOff]; ok {
			continue
		}
		blob := emitClassData(parsedCD[c.dataOff], b.R, codeMap)
		cdMap[c.dataOff] = b.place(0x2000, blob, 1)
	}

	// ---- 7) 头部索引表 ----
	stringIDs := make([]byte, nStr*4)
	for i := 0; i < nStr; i++ {
		binary.LittleEndian.PutUint32(stringIDs[4*i:], strMap[i])
	}

	typeIDs := make([]byte, nType*4)
	for i := 0; i < nType; i++ {
		binary.LittleEndian.PutUint32(typeIDs[4*i:], pl.typeStr[i])
	}

	protoIDs := make([]byte, nProto*12)
	for i, p := range pl.protos {
		base := 12 * i
		binary.LittleEndian.PutUint32(protoIDs[base:], p.shorty)
		binary.LittleEndian.PutUint32(protoIDs[base+4:], p.ret)
		binary.LittleEndian.PutUint32(protoIDs[base+8:], protoParamsOff[i])
	}

	fieldIDs := make([]byte, nField*8)
	for i, fl := range pl.fields {
		base := 8 * i
		binary.LittleEndian.PutUint16(fieldIDs[base:], uint16(fl.class))
		binary.LittleEndian.PutUint16(fieldIDs[base+2:], uint16(fl.typ))
		binary.LittleEndian.PutUint32(fieldIDs[base+4:], fl.name)
	}

	methodIDs := make([]byte, nMethod*8)
	for i, m := range pl.methods {
		base := 8 * i
		binary.LittleEndian.PutUint16(methodIDs[base:], uint16(m.class))
		binary.LittleEndian.PutUint16(methodIDs[base+2:], uint16(m.proto))
		binary.LittleEndian.PutUint32(methodIDs[base+4:], m.name)
	}

	classDefs := make([]byte, nClass*32)
	for i := range pl.classes {
		c := &pl.classes[i]
		base := 32 * i
		var interfacesOff uint32
		if c.spec != nil {
			idx := make([]uint32, 0, len(c.ifaces))
			for _, ifc := range c.ifaces {
				idx = append(idx, pl.typeIdx[ifc])
			}
			interfacesOff = makeTypeList(idx)
		} else {
			var ierr error
			interfacesOff, ierr = makeOldTypeList(c.ifaceOff)
			if ierr != nil {
				return nil, ierr
			}
		}
		binary.LittleEndian.PutUint32(classDefs[base:], c.classIdx)
		binary.LittleEndian.PutUint32(classDefs[base+4:], c.access)
		binary.LittleEndian.PutUint32(classDefs[base+8:], c.superIdx)
		binary.LittleEndian.PutUint32(classDefs[base+12:], interfacesOff)
		binary.LittleEndian.PutUint32(classDefs[base+16:], c.sourceIdx)
		// 注解目录偏移：annoOff 为 0 表示无注解（合法，写 0）。非 0 却不在
		// 重映射表里说明注解树与 class_def 不自洽——绝不能静默取 0，那会把
		// 该类的注解目录整体清掉（产物静默丢失注解）。
		annoNew, aerr := resolveAnnoOff(dirMap, c.annoOff)
		if aerr != nil {
			return nil, aerr
		}
		binary.LittleEndian.PutUint32(classDefs[base+20:], annoNew)
		if c.spec != nil {
			binary.LittleEndian.PutUint32(classDefs[base+24:], injectedData[c.spec])
		} else {
			binary.LittleEndian.PutUint32(classDefs[base+24:], cdMap[c.dataOff])
		}
		binary.LittleEndian.PutUint32(classDefs[base+28:], c.valuesNew)
	}

	return &layout{
		stringIDs: stringIDs,
		typeIDs:   typeIDs,
		protoIDs:  protoIDs,
		fieldIDs:  fieldIDs,
		methodIDs: methodIDs,
		classDefs: classDefs,
	}, nil
}

// bytesIndexByte 是 bytes.IndexByte 的本地实现，避免额外的包依赖。
func bytesIndexByte(b []byte, c byte) int {
	for i := 0; i < len(b); i++ {
		if b[i] == c {
			return i
		}
	}
	return -1
}

// emitClassData 重新编码 class_data_item。
func emitClassData(cd *ClassData, R *Remap, codeMap map[uint32]uint32) []byte {
	out := make([]byte, 0, 64)

	// 字段/方法索引重排后必须重新排序；重命名可能把两条 id 塌缩为同一条，
	// 编码要求 class_data 内索引严格递增，因此必须先映射、排序、去重，
	// 再按**去重后**的数量写头部计数（否则头部声明的条目数多于实际写入，
	// 解析器会串读后续字节，产生巨大的越界索引）。
	sf := make([][2]uint32, 0, len(cd.StaticFields))
	for _, fl := range cd.StaticFields {
		sf = append(sf, [2]uint32{R.Field[fl.Idx], fl.Acc})
	}
	sort.SliceStable(sf, func(a, c int) bool { return sf[a][0] < sf[c][0] })
	sf = dedupFieldPairs(sf)
	inf := make([][2]uint32, 0, len(cd.InstanceFields))
	for _, fl := range cd.InstanceFields {
		inf = append(inf, [2]uint32{R.Field[fl.Idx], fl.Acc})
	}
	sort.SliceStable(inf, func(a, c int) bool { return inf[a][0] < inf[c][0] })
	inf = dedupFieldPairs(inf)

	dedupMethods := func(lst []EncodedMethod) []EncodedMethod {
		sorted := make([]EncodedMethod, len(lst))
		copy(sorted, lst)
		for i := range sorted {
			sorted[i].Idx = R.Method[sorted[i].Idx]
		}
		sort.SliceStable(sorted, func(a, c int) bool { return sorted[a].Idx < sorted[c].Idx })
		if len(sorted) == 0 {
			return sorted
		}
		out := sorted[:1]
		for i := 1; i < len(sorted); i++ {
			if sorted[i].Idx == out[len(out)-1].Idx {
				continue
			}
			out = append(out, sorted[i])
		}
		return out
	}
	dm := dedupMethods(cd.DirectMethods)
	vm := dedupMethods(cd.VirtualMethods)

	out = PutULEB128(out, uint32(len(sf)))
	out = PutULEB128(out, uint32(len(inf)))
	out = PutULEB128(out, uint32(len(dm)))
	out = PutULEB128(out, uint32(len(vm)))

	writeFields := func(lst [][2]uint32) {
		var prev uint32
		for _, e := range lst {
			out = PutULEB128(out, e[0]-prev)
			out = PutULEB128(out, e[1])
			prev = e[0]
		}
	}
	writeFields(sf)
	writeFields(inf)

	writeMethods := func(lst []EncodedMethod) {
		var prev uint32
		for _, m := range lst {
			out = PutULEB128(out, m.Idx-prev)
			out = PutULEB128(out, m.Acc)
			newCode := uint32(0)
			if m.CodeOff != 0 {
				newCode = codeMap[m.CodeOff]
			}
			out = PutULEB128(out, newCode)
			prev = m.Idx
		}
	}
	writeMethods(dm)
	writeMethods(vm)
	return out
}

// dedupFieldPairs 去掉排序后相邻的重复字段索引（重命名塌缩所致），保留第一条。
func dedupFieldPairs(in [][2]uint32) [][2]uint32 {
	if len(in) == 0 {
		return in
	}
	out := in[:1]
	for i := 1; i < len(in); i++ {
		if in[i][0] == out[len(out)-1][0] {
			continue
		}
		out = append(out, in[i])
	}
	return out
}

// 访问标志中本工具关心的位。
const (
	accPublic = 0x0001
	// accConstructor 是构造函数（<init>）必须带上的标志位。
	// ART 会检查它，缺失时打印 "<init> didn't have expected constructor access flag"。
	accConstructor = 0x10000
	accPrivate     = 0x0002
	accProtected   = 0x0004
	accStatic      = 0x0008
	accInterface   = 0x0200
	accAnnotation  = 0x2000
	// accNative 标记 JNI 方法：其名称与 native 符号绑定，不可重命名。
	accNative = 0x0100
)

// emitInjectedClassData 依据注入类的描述生成 class_data_item。
//
// 返回 nil 表示该类没有字段与方法（此时 class_data_off 应为 0）。
func emitInjectedClassData(spec *ClassSpec, pl *plan, code map[*CodeBlob]uint32) ([]byte, error) {
	type fe struct {
		idx uint32
		acc uint32
	}
	type me struct {
		idx  uint32
		acc  uint32
		code uint32
	}
	var sf, inf []fe
	var dm, vm []me

	for _, fl := range spec.Fields {
		i, ok := pl.fieldIdx[FieldSpec{Class: spec.Name, Name: fl.Name, Type: fl.Type}.Key()]
		if !ok {
			return nil, fmt.Errorf("dex: 注入字段 %s.%s 未登记", spec.Name, fl.Name)
		}
		e := fe{idx: i, acc: fl.Access}
		if fl.Access&accStatic != 0 {
			sf = append(sf, e)
		} else {
			inf = append(inf, e)
		}
	}
	for _, m := range spec.Methods {
		i, ok := pl.methodIdx[MethodSpec{Class: spec.Name, Name: m.Name, Proto: m.Proto}.Key()]
		if !ok {
			return nil, fmt.Errorf("dex: 注入方法 %s.%s 未登记", spec.Name, m.Name)
		}
		acc := m.Access
		// <init> 与 <clinit> 都必须带 ACC_CONSTRUCTOR（0x10000）：ART 会检查
		// 这一位，缺了会报 "<name> didn't have expected constructor access flag"。
		// 两个名字都补上，比要求每个调用方自己记得更可靠。
		if m.Name == "<init>" || m.Name == "<clinit>" {
			acc |= accConstructor
		}
		e := me{idx: i, acc: acc}
		if m.Code != nil {
			e.code = code[m.Code]
		}
		if m.Access&accStatic != 0 || m.Access&accPrivate != 0 || m.Name == "<init>" || m.Name == "<clinit>" {
			dm = append(dm, e)
		} else {
			vm = append(vm, e)
		}
	}
	if len(sf)+len(inf)+len(dm)+len(vm) == 0 {
		return nil, nil
	}

	sort.Slice(sf, func(a, b int) bool { return sf[a].idx < sf[b].idx })
	sort.Slice(inf, func(a, b int) bool { return inf[a].idx < inf[b].idx })
	sort.Slice(dm, func(a, b int) bool { return dm[a].idx < dm[b].idx })
	sort.Slice(vm, func(a, b int) bool { return vm[a].idx < vm[b].idx })

	out := make([]byte, 0, 64)
	out = PutULEB128(out, uint32(len(sf)))
	out = PutULEB128(out, uint32(len(inf)))
	out = PutULEB128(out, uint32(len(dm)))
	out = PutULEB128(out, uint32(len(vm)))
	var prev uint32
	for _, e := range sf {
		out = PutULEB128(out, e.idx-prev)
		out = PutULEB128(out, e.acc)
		prev = e.idx
	}
	prev = 0
	for _, e := range inf {
		out = PutULEB128(out, e.idx-prev)
		out = PutULEB128(out, e.acc)
		prev = e.idx
	}
	prev = 0
	for _, e := range dm {
		out = PutULEB128(out, e.idx-prev)
		out = PutULEB128(out, e.acc)
		out = PutULEB128(out, e.code)
		prev = e.idx
	}
	prev = 0
	for _, e := range vm {
		out = PutULEB128(out, e.idx-prev)
		out = PutULEB128(out, e.acc)
		out = PutULEB128(out, e.code)
		prev = e.idx
	}
	return out, nil
}

// fullyQualifiedName 返回类型索引对应的类名（仅调试用）。
func fullyQualifiedName(pl *plan, typeIdx uint32) string {
	if int(typeIdx) >= len(pl.typeStr) {
		return "?"
	}
	si := pl.typeStr[typeIdx]
	if int(si) >= len(pl.pool) {
		return "?"
	}
	return pl.pool[si]
}
