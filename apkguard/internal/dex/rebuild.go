package dex

import (
	"encoding/binary"
	"fmt"
	"sort"
)

// noOld 标记「新增条目」，表示该条目没有对应的旧索引。
const noOld = ^uint32(0)

// Remap 描述重建时各索引段的映射关系。
//
// 映射表的下标是旧索引，值是新索引；长度等于旧段条目数。
type Remap struct {
	String []uint32
	Type   []uint32
	Proto  []uint32
	Field  []uint32
	Method []uint32
}

// Identity 构造一个不做任何重排的映射（新索引等于旧索引）。
func Identity(f *File) *Remap {
	mk := func(n uint32) []uint32 {
		out := make([]uint32, n)
		for i := range out {
			out[i] = uint32(i)
		}
		return out
	}
	return &Remap{
		String: mk(f.NString),
		Type:   mk(f.NType),
		Proto:  mk(f.NProto),
		Field:  mk(f.NField),
		Method: mk(f.NMethod),
	}
}

// ---- 追加条目描述 ----

// ProtoSpec 描述一个方法原型（返回类型 + 参数类型）。
type ProtoSpec struct {
	Ret    string
	Params []string
}

// Shorty 返回该原型的 shorty 描述符。
func (p ProtoSpec) Shorty() string { return buildShorty(p.Ret, p.Params) }

// Key 返回该原型的唯一键，用于去重。
func (p ProtoSpec) Key() string { return protoKey(p.Ret, p.Params) }

// MethodSpec 描述一个方法引用。
type MethodSpec struct {
	Class string
	Name  string
	Proto ProtoSpec
}

// Key 返回该方法引用的唯一键。
func (m MethodSpec) Key() string { return methodKey(m.Class, m.Name, m.Proto.Key()) }

// Desc 返回方法的完整描述，形如 "Lcls;->name(I)V"。
func (m MethodSpec) Desc() string { return m.Class + "->" + m.Name + m.Proto.Desc() }

// Desc 返回原型的完整描述，形如 "(ILjava/lang/String;)V"。
func (p ProtoSpec) Desc() string { return BuildProtoDesc(p.Ret, p.Params) }

// FieldSpec 描述一个字段引用。
type FieldSpec struct {
	Class string
	Name  string
	Type  string
}

// Key 返回该字段引用的唯一键。
func (f FieldSpec) Key() string { return fieldKey(f.Class, f.Name, f.Type) }

// ClassField 是注入类中的一个字段。
type ClassField struct {
	Name   string
	Type   string
	Access uint32
}

// ClassMethod 是注入类中的一个方法。
//
// Code 为 nil 表示该方法没有实现（抽象方法或 native 方法）。
type ClassMethod struct {
	Name   string
	Proto  ProtoSpec
	Access uint32
	Code   *CodeBlob
}

// ClassSpec 描述一个注入的类。
type ClassSpec struct {
	Name       string
	Super      string
	Access     uint32
	Interfaces []string
	SourceFile string
	Fields     []ClassField
	Methods    []ClassMethod
}

// Addition 描述重建时要追加的索引表条目与类。
//
// 所有被引用的类型/原型/方法/字段都会自动加入对应的索引表（已存在则复用），
// 所需的字符串也会自动加入字符串池。
type Addition struct {
	Types   []string
	Protos  []ProtoSpec
	Methods []MethodSpec
	Fields  []FieldSpec
	Classes []ClassSpec
}

// RebuildOptions 控制重建行为。
type RebuildOptions struct {
	// Rename 把旧字符串替换为新字符串（未列出的保持不变）。
	// 若多个旧字符串被替换为同一个新值，它们在字符串池中会合并为一项。
	Rename map[string]string
	// NewStrings 是需要额外加入字符串池的字符串。
	NewStrings []string
	// DropDebugInfo 为 true 时移除所有 debug_info（A4）。
	DropDebugInfo bool
	// CodeReplacements 以旧 code_item 偏移为键替换方法体。
	CodeReplacements map[uint32][]byte
	// StringEncrypt 非 nil 时启用 A2 字符串加密。
	StringEncrypt *StringEncrypt
	// ConstantArray 非 nil 时启用 A3 常量数组化。
	ConstantArray *ConstantArray
	// ClassPad 非 nil 时启用 A13 类膨胀。
	ClassPad *ClassPadder
	// Addition 描述要追加的索引表条目与类（A2/A3/A13/B2/B3 等使用）。
	Addition *Addition
	// ClassFilter 非 nil 时，只有名字通过筛选的**原有类**才会被写入产物。
	//
	// 用途是 B4（多 DEX 拆分）：把一份 DEX 的类集合按筛选条件切成若干份，
	// 每份各成一份合法 DEX。
	//
	// 刻意**不裁剪索引表**：字符串/类型/方法/字段/原型一律保持完整。
	// 未使用的条目只是占一点体积，而裁剪它们需要重排所有索引、
	// 并修正全部指令引用——风险远大于收益，且出错的后果是整个 DEX 失效。
	ClassFilter func(className string) bool
}

// plan 保存重建所需的全部索引表信息（均已按新索引排列）。
type plan struct {
	// remap 是旧索引到新索引的映射，供字节码/调试信息/注解的重写使用。
	remap *Remap

	pool      []string
	stringIdx map[string]uint32

	types   []string
	typeIdx map[string]uint32
	typeStr []uint32 // 新类型索引 -> 新字符串索引

	protos   []protoPlan
	protoIdx map[string]uint32

	fields   []fieldPlan
	fieldIdx map[string]uint32

	methods   []methodPlan
	methodIdx map[string]uint32

	classes []classPlan

	// strEnc 非 nil 时启用字符串加密（A2）。
	strEnc *stringEncryptPlan

	// constArr 非 nil 时启用常量数组化（A3）。
	constArr *constantArrayPlan

	// classPad 非 nil 时启用类膨胀（A13）。
	classPad *classPadPlan
}

// classPadPlan 记录 A13 的生成统计。
type classPadPlan struct {
	stats ClassPadStats
	count int
}

type protoPlan struct {
	ret    uint32   // 新类型索引
	params []uint32 // 新类型索引
	shorty uint32   // 新字符串索引
}

type fieldPlan struct {
	class, typ, name uint32
}

type methodPlan struct {
	class, proto, name uint32
}

// classPlan 描述一个 class_def 条目（旧类或注入类）。
type classPlan struct {
	old uint32 // noOld 表示注入类

	classIdx  uint32
	access    uint32
	superIdx  uint32
	ifaceOff  uint32   // 旧 type_list 偏移（注入类为 0）
	ifaces    []string // 注入类的接口描述符
	sourceIdx uint32   // noIndex 表示无
	annoOff   uint32   // 旧 annotations_directory 偏移
	dataOff   uint32   // 旧 class_data 偏移
	valuesOff uint32   // 旧 static values 偏移
	valuesNew uint32   // 重排后的 static values 新偏移（0 表示无）

	spec *ClassSpec
}

// Rebuild 重建 DEX，返回一份新的、校验和自洽的字节流。
//
// 实现策略：完整保留原有数据区的语义，仅重排索引表并修正所有引用，
// 因此调试信息、注解、静态值、异常表都能原样保留；在此基础上支持
// 重命名字符串、加密字符串与追加索引表条目/类。
func Rebuild(f *File, opts RebuildOptions) ([]byte, error) {
	out, _, err := RebuildWithStats(f, opts)
	return out, err
}

// RebuildStats 汇总一次重建的量化结果，供上层输出报告。
type RebuildStats struct {
	// StringsEncrypted 是被加密的字符串数量（A2）。
	StringsEncrypted int
	// StringsReplaced 是明文被彻底移出字符串池的数量（A2）。
	StringsReplaced int
	// StringsArrayized 是被改写为常量数组的数量（A3）。
	StringsArrayized int
	// ClassesPadded 是注入的膨胀类数量（A13）。
	ClassesPadded int
	// ClassPad 是 A13 的明细统计。
	ClassPad ClassPadStats
}

// RebuildWithStats 与 Rebuild 相同，但额外返回量化统计。
func RebuildWithStats(f *File, opts RebuildOptions) ([]byte, RebuildStats, error) {
	pl, err := buildPlan(f, opts)
	if err != nil {
		return nil, RebuildStats{}, err
	}
	b := &builder{f: f, R: pl.remap, opts: opts}
	out, err := b.assemble(pl)
	if err != nil {
		return nil, RebuildStats{}, err
	}
	var st RebuildStats
	if pl.strEnc != nil {
		st.StringsEncrypted = len(pl.strEnc.cipher)
		st.StringsReplaced = len(pl.strEnc.replace)
	}
	if pl.constArr != nil {
		st.StringsArrayized = pl.constArr.count
	}
	if pl.classPad != nil {
		st.ClassesPadded = pl.classPad.count
		st.ClassPad = pl.classPad.stats
	}
	return out, st, nil
}

// buildPlan 计算重建后的全部索引表。
func buildPlan(f *File, opts RebuildOptions) (*plan, error) {
	add := opts.Addition
	pl := &plan{}

	// ---- 1) 新字符串池 ----
	// 先对每个旧字符串应用重命名，再与新增字符串合并去重，最后按 UTF-16 序排列。
	values := make([]string, f.NString)
	for i := uint32(0); i < f.NString; i++ {
		s, err := f.String(i)
		if err != nil {
			return nil, err
		}
		if opts.Rename != nil {
			if nv, ok := opts.Rename[s]; ok {
				s = nv
			}
		}
		values[i] = s
	}

	// A2：在池构建之前确定加密集合。密文只含 0-9a-f，
	// 因此可以安全地把「仅被 const-string 引用」的明文整体替换掉。
	if opts.StringEncrypt != nil {
		decAdd, err := stringDecryptorAddition(opts.StringEncrypt)
		if err != nil {
			return nil, err
		}
		// 解密器自身的字符串常量必须排除，否则会形成「解密前先解密」的死循环。
		se := *opts.StringEncrypt
		inner := se.Skip
		self := map[string]bool{}
		collectAdditionStrings(&decAdd, self)
		se.Skip = func(s string) bool {
			if self[s] {
				return true
			}
			return inner != nil && inner(s)
		}
		cipher, replace, err := planStringEncrypt(f, &se, values)
		if err != nil {
			return nil, err
		}
		for i := range values {
			if ct, ok := replace[values[i]]; ok {
				values[i] = ct
			}
		}
		add = mergeAddition(add, decAdd)
		pl.strEnc = &stringEncryptPlan{
			spec:    se,
			cipher:  cipher,
			replace: replace,
			decrypt: MethodSpec{
				Class: se.Class, Name: se.MethodName,
				Proto: ProtoSpec{Ret: "Ljava/lang/String;", Params: []string{"Ljava/lang/String;"}},
			},
		}
	}

	extra := map[string]bool{}
	for _, s := range opts.NewStrings {
		extra[s] = true
	}
	if pl.strEnc != nil {
		// 密文必须进入池：已替换的明文会被整体改写为密文（此时已在 values 中），
		// 而未替换的（如同时被类型表引用）仍需把密文额外加入。
		for _, ct := range pl.strEnc.cipher {
			extra[ct] = true
		}
	}
	// A3：常量数组化。
	//
	// 与 A2 的关键区别在于**不修改字符串池**：明文仍留在池中（因此类型名、
	// 方法名等引用不受影响），只是把方法体里的 const-string 换成
	// 「构造 byte[] + 调用还原方法」。这样字节码中不再出现明文引用，
	// 但池里的明文仍会被 strings/grep 看到——所以 A3 通常与 A4 或
	// 后续的资源/DEX 加密配合使用。
	if opts.ConstantArray != nil {
		caAdd, err := constantArrayAddition(opts.ConstantArray)
		if err != nil {
			return nil, err
		}
		// 还原方法自身的字符串常量（"UTF-8"）必须排除，否则会自引用。
		ca := *opts.ConstantArray
		inner := ca.Skip
		self := map[string]bool{}
		collectAdditionStrings(&caAdd, self)
		ca.Skip = func(s string) bool {
			if self[s] {
				return true
			}
			return inner != nil && inner(s)
		}
		add = mergeAddition(add, caAdd)
		pl.constArr = &constantArrayPlan{
			spec:          ca,
			skip:          ca.Skip,
			helper:        MethodSpec{Class: ca.Class, Name: ca.MethodName, Proto: ProtoSpec{Ret: "Ljava/lang/String;", Params: []string{"[B"}}},
			byteArrayType: "[B",
		}
	}
	// A13：类膨胀。
	//
	// 膨胀类必须与「本 DEX 已有类型」以及「本次重建要新增的类型」都不重名，
	// 否则 class_defs 中会出现两个 class_idx 相同的条目。
	//
	// 注意：类名由 Pass 层统一分配（跨 DEX 唯一），这里只负责生成类体。
	if opts.ClassPad != nil {
		padClasses, padStats, err := ClassPadPlan(opts.ClassPad)
		if err != nil {
			return nil, err
		}
		pl.classPad = &classPadPlan{stats: padStats, count: len(padClasses)}
		add = mergeAddition(add, ClassPadAdditionOf(padClasses))
	}
	if add != nil {
		// 先补齐方法体引用的类型/方法/字段/原型，再收集字符串：
		// 顺序反了会让新补进来的引用缺少对应的字符串池条目。
		expandAdditionRefs(add)
		collectAdditionStrings(add, extra)
	}
	poolSet := make(map[string]bool, len(values)+len(extra))
	for _, v := range values {
		poolSet[v] = true
	}
	for s := range extra {
		poolSet[s] = true
	}
	pool := make([]string, 0, len(poolSet))
	for s := range poolSet {
		pool = append(pool, s)
	}
	sort.Slice(pool, func(i, j int) bool { return CompareUTF16(pool[i], pool[j]) < 0 })

	pl.pool = pool
	pl.stringIdx = make(map[string]uint32, len(pool))
	for i, s := range pool {
		pl.stringIdx[s] = uint32(i)
	}

	R := Identity(f)
	for i := uint32(0); i < f.NString; i++ {
		R.String[i] = pl.stringIdx[values[i]]
	}
	pl.remap = R

	// ---- 2) 类型（按新字符串索引排序，且不允许重复）----
	seenType := make(map[string]uint32, f.NType)
	types := make([]string, 0, f.NType)
	for i := uint32(0); i < f.NType; i++ {
		desc := values[typeNameIdx(f, i)]
		if _, dup := seenType[desc]; dup {
			return nil, fmt.Errorf("dex: 重命名导致类型描述符冲突 %q", desc)
		}
		seenType[desc] = uint32(i)
		types = append(types, desc)
	}
	if add != nil {
		for _, t := range add.Types {
			if _, dup := seenType[t]; dup {
				continue
			}
			seenType[t] = noOld
			types = append(types, t)
		}
	}
	sort.Slice(types, func(i, j int) bool {
		return pl.stringIdx[types[i]] < pl.stringIdx[types[j]]
	})
	pl.types = types
	pl.typeIdx = make(map[string]uint32, len(types))
	pl.typeStr = make([]uint32, len(types))
	for i, t := range types {
		pl.typeIdx[t] = uint32(i)
		pl.typeStr[i] = pl.stringIdx[t]
	}
	// 统一在索引表建好后回填映射：这样即便重命名导致若干旧条目塌缩为同一条，
	// 它们也会自然地映射到同一个新索引，不会留下未初始化的项。
	for old := uint32(0); old < f.NType; old++ {
		R.Type[old] = pl.typeIdx[values[typeNameIdx(f, old)]]
	}

	// ---- 3) 原型（先按返回类型，再按参数列表逐元素字典序）----
	type protoEntry struct {
		old    uint32
		ret    string
		params []string
		// shorty 是原型的 shorty 字符串。
		//
		// 旧原型一律沿用其原有的 shorty 字符串，而不是按 ret/params 重新推导：
		// 加固样本中确实存在 shorty 与描述符不完全对应的写法（属历史遗留），
		// 重算会引入原文件里不存在的字符串，反而导致构建失败。
		shorty string
	}
	var pentries []protoEntry
	pseen := map[string]uint32{}
	for i := uint32(0); i < f.NProto; i++ {
		base := f.OffProto + 12*i
		shortyIdx := binary.LittleEndian.Uint32(f.data[base:])
		retIdx := binary.LittleEndian.Uint32(f.data[base+4:])
		paramsOff := binary.LittleEndian.Uint32(f.data[base+8:])
		ret := values[typeNameIdx(f, retIdx)]
		var params []string
		if paramsOff != 0 {
			n := binary.LittleEndian.Uint32(f.data[paramsOff:])
			params = make([]string, 0, n)
			for k := uint32(0); k < n; k++ {
				pi := uint32(binary.LittleEndian.Uint16(f.data[paramsOff+4+2*k:]))
				params = append(params, values[typeNameIdx(f, pi)])
			}
		}
		k := protoKey(ret, params)
		if _, dup := pseen[k]; dup {
			continue // 重命名后与其他原型重合，合并
		}
		pseen[k] = i
		pentries = append(pentries, protoEntry{
			old: i, ret: ret, params: params, shorty: values[shortyIdx],
		})
	}
	if add != nil {
		for _, p := range add.Protos {
			k := p.Key()
			if _, dup := pseen[k]; dup {
				continue
			}
			pseen[k] = noOld
			pentries = append(pentries, protoEntry{
				old: noOld, ret: p.Ret, params: p.Params, shorty: p.Shorty(),
			})
		}
	}
	sort.Slice(pentries, func(i, j int) bool {
		ra, rb := pl.typeIdx[pentries[i].ret], pl.typeIdx[pentries[j].ret]
		if ra != rb {
			return ra < rb
		}
		// 参数列表按「逐元素字典序」比较：仅当较短列表是较长列表的前缀时，
		// 较短者才排在前面。不能先比长度，否则 (Landroid/os/Parcelable;)V
		// 会错误地排到 (Landroid/os/Parcel;Ljava/lang/ClassLoader;)V 之前。
		pa, pb := pentries[i].params, pentries[j].params
		n := len(pa)
		if len(pb) < n {
			n = len(pb)
		}
		for k := 0; k < n; k++ {
			ta, tb := pl.typeIdx[pa[k]], pl.typeIdx[pb[k]]
			if ta != tb {
				return ta < tb
			}
		}
		return len(pa) < len(pb)
	})
	pl.protos = make([]protoPlan, len(pentries))
	pl.protoIdx = make(map[string]uint32, len(pentries))
	for i, e := range pentries {
		si, ok := pl.stringIdx[e.shorty]
		if !ok {
			return nil, fmt.Errorf("dex: 缺少 shorty 字符串 %q", e.shorty)
		}
		pp := protoPlan{ret: pl.typeIdx[e.ret], shorty: si}
		for _, q := range e.params {
			pp.params = append(pp.params, pl.typeIdx[q])
		}
		pl.protos[i] = pp
		pl.protoIdx[protoKey(e.ret, e.params)] = uint32(i)
		if e.old != noOld {
			R.Proto[e.old] = uint32(i)
		}
	}

	// ---- 4) 字段（按 class, name, type 排序）----
	type fieldEntry struct {
		old            uint32
		cls, name, typ string
	}
	var fentries []fieldEntry
	fseen := map[string]uint32{}
	for i := uint32(0); i < f.NField; i++ {
		c, t, n, err := f.FieldRefAt(i)
		if err != nil {
			return nil, err
		}
		e := fieldEntry{
			old:  i,
			cls:  values[typeNameIdx(f, uint32(c))],
			typ:  values[typeNameIdx(f, uint32(t))],
			name: values[n],
		}
		k := fieldKey(e.cls, e.name, e.typ)
		if _, dup := fseen[k]; dup {
			continue
		}
		fseen[k] = i
		fentries = append(fentries, e)
	}
	if add != nil {
		for _, fl := range add.Fields {
			k := fl.Key()
			if _, dup := fseen[k]; dup {
				continue
			}
			fseen[k] = noOld
			fentries = append(fentries, fieldEntry{old: noOld, cls: fl.Class, name: fl.Name, typ: fl.Type})
		}
	}
	sort.Slice(fentries, func(i, j int) bool {
		ca, cb := pl.typeIdx[fentries[i].cls], pl.typeIdx[fentries[j].cls]
		if ca != cb {
			return ca < cb
		}
		na, nb := pl.stringIdx[fentries[i].name], pl.stringIdx[fentries[j].name]
		if na != nb {
			return na < nb
		}
		return pl.typeIdx[fentries[i].typ] < pl.typeIdx[fentries[j].typ]
	})
	pl.fields = make([]fieldPlan, len(fentries))
	pl.fieldIdx = make(map[string]uint32, len(fentries))
	for i, e := range fentries {
		pl.fields[i] = fieldPlan{class: pl.typeIdx[e.cls], name: pl.stringIdx[e.name], typ: pl.typeIdx[e.typ]}
		pl.fieldIdx[fieldKey(e.cls, e.name, e.typ)] = uint32(i)
		if e.old != noOld {
			R.Field[e.old] = uint32(i)
		}
	}

	// ---- 5) 方法（按 class, name, proto 排序）----
	type methodEntry struct {
		old             uint32
		cls, name, pkey string
	}
	var mentries []methodEntry
	mseen := map[string]uint32{}
	for i := uint32(0); i < f.NMethod; i++ {
		ref, err := f.MethodRefAt(i)
		if err != nil {
			return nil, err
		}
		cls := values[typeNameIdx(f, uint32(ref.ClassIdx))]
		name := values[ref.NameIdx]
		pk, err := oldProtoKey(f, values, uint32(ref.ProtoIdx))
		if err != nil {
			return nil, err
		}
		k := methodKey(cls, name, pk)
		if _, dup := mseen[k]; dup {
			continue
		}
		mseen[k] = i
		mentries = append(mentries, methodEntry{old: i, cls: cls, name: name, pkey: pk})
	}
	if add != nil {
		for _, m := range add.Methods {
			k := m.Key()
			if _, dup := mseen[k]; dup {
				continue
			}
			mseen[k] = noOld
			mentries = append(mentries, methodEntry{old: noOld, cls: m.Class, name: m.Name, pkey: m.Proto.Key()})
		}
	}
	sort.Slice(mentries, func(i, j int) bool {
		ca, cb := pl.typeIdx[mentries[i].cls], pl.typeIdx[mentries[j].cls]
		if ca != cb {
			return ca < cb
		}
		na, nb := pl.stringIdx[mentries[i].name], pl.stringIdx[mentries[j].name]
		if na != nb {
			return na < nb
		}
		return pl.protoIdx[mentries[i].pkey] < pl.protoIdx[mentries[j].pkey]
	})
	pl.methods = make([]methodPlan, len(mentries))
	pl.methodIdx = make(map[string]uint32, len(mentries))
	for i, e := range mentries {
		pl.methods[i] = methodPlan{class: pl.typeIdx[e.cls], name: pl.stringIdx[e.name], proto: pl.protoIdx[e.pkey]}
		pl.methodIdx[methodKey(e.cls, e.name, e.pkey)] = uint32(i)
		if e.old != noOld {
			R.Method[e.old] = uint32(i)
		}
	}

	// ---- 6) 类定义 ----
	for i := uint32(0); i < f.NClass; i++ {
		cd, err := f.ClassDefAt(i)
		if err != nil {
			return nil, err
		}
		if opts.ClassFilter != nil {
			if !opts.ClassFilter(values[typeNameIdx(f, cd.ClassIdx)]) {
				continue
			}
		}
		cp := classPlan{
			old:       i,
			classIdx:  pl.typeIdx[values[typeNameIdx(f, cd.ClassIdx)]],
			access:    cd.AccessFlags,
			ifaceOff:  cd.InterfacesOff,
			annoOff:   cd.AnnotationsOff,
			dataOff:   cd.ClassDataOff,
			valuesOff: cd.StaticValuesOff,
		}
		if cd.SuperIdx == noIndex {
			cp.superIdx = noIndex
		} else {
			cp.superIdx = pl.typeIdx[values[typeNameIdx(f, cd.SuperIdx)]]
		}
		if cd.SourceFileIdx == noIndex {
			cp.sourceIdx = noIndex
		} else {
			cp.sourceIdx = pl.stringIdx[values[cd.SourceFileIdx]]
		}
		pl.classes = append(pl.classes, cp)
	}
	// class_defs 的顺序按「先原样保留旧类的相对顺序，再追加注入类」处理。
	//
	// DEX 规范建议 class_defs 按 class_idx 升序，但现实中大量 APK（含本项目样本）
	// 并未严格排序，而 dexdump/ART 均能正常加载；此处不做重排以免改变原有语义。
	if add != nil {
		for k := range add.Classes {
			spec := add.Classes[k]
			cp, err := planInjectedClass(pl, spec)
			if err != nil {
				return nil, err
			}
			pl.classes = append(pl.classes, cp)
		}
	}

	return pl, nil
}

// planInjectedClass 校验注入类的引用完整性并生成其 class_def 计划。
func planInjectedClass(pl *plan, spec ClassSpec) (classPlan, error) {
	ci, ok := pl.typeIdx[spec.Name]
	if !ok {
		return classPlan{}, fmt.Errorf("dex: 注入类 %s 的类型未登记", spec.Name)
	}
	cp := classPlan{old: noOld, classIdx: ci, access: spec.Access, sourceIdx: noIndex, spec: &spec}
	if spec.Super == "" {
		cp.superIdx = noIndex
	} else {
		si, ok := pl.typeIdx[spec.Super]
		if !ok {
			return classPlan{}, fmt.Errorf("dex: 注入类 %s 的父类 %s 未登记", spec.Name, spec.Super)
		}
		cp.superIdx = si
	}
	for _, ifc := range spec.Interfaces {
		if _, ok := pl.typeIdx[ifc]; !ok {
			return classPlan{}, fmt.Errorf("dex: 注入类 %s 的接口 %s 未登记", spec.Name, ifc)
		}
		cp.ifaces = append(cp.ifaces, ifc)
	}
	for _, m := range spec.Methods {
		if _, ok := pl.methodIdx[MethodSpec{Class: spec.Name, Name: m.Name, Proto: m.Proto}.Key()]; !ok {
			return classPlan{}, fmt.Errorf("dex: 注入类 %s 的方法 %s%s 未登记", spec.Name, m.Name, m.Proto.Desc())
		}
	}
	for _, fl := range spec.Fields {
		if _, ok := pl.fieldIdx[FieldSpec{Class: spec.Name, Name: fl.Name, Type: fl.Type}.Key()]; !ok {
			return classPlan{}, fmt.Errorf("dex: 注入类 %s 的字段 %s 未登记", spec.Name, fl.Name)
		}
	}
	return cp, nil
}

// expandAdditionRefs 把注入类方法体中出现的符号引用自动登记回 Addition。
//
// 为什么需要它：planInjectedClass 只校验类自身的名字/父类/接口/字段/方法，
// 而方法体里通过 CodeBlob.Patches 引用的类型/方法/字段/原型必须事先出现在
// 索引表里，否则要等到 CodeBlob.Bytes 解析补丁时才报「未登记」——
// 那时错误信息离真正的原因（漏登记）已经很远，且是运行时才炸。
//
// 这里在建索引表之前一次性补齐，使「写壳代码」不再需要手工罗列全部引用。
// 递归是必要的：登记一个方法要连带登记它的原型，登记原型又要登记其返回类型
// 与全部参数类型。
func expandAdditionRefs(add *Addition) {
	if add == nil {
		return
	}
	seenType := make(map[string]bool, len(add.Types))
	seenMethod := make(map[string]bool, len(add.Methods))
	seenField := make(map[string]bool, len(add.Fields))
	seenProto := make(map[string]bool, len(add.Protos))
	for _, t := range add.Types {
		seenType[t] = true
	}
	for _, m := range add.Methods {
		seenMethod[m.Key()] = true
	}
	for _, fl := range add.Fields {
		seenField[fl.Key()] = true
	}
	for _, p := range add.Protos {
		seenProto[p.Key()] = true
	}

	var addType func(string)
	var addProto func(ProtoSpec)
	var addMethod func(MethodSpec)
	var addField func(FieldSpec)

	addType = func(t string) {
		if t == "" || seenType[t] {
			return
		}
		seenType[t] = true
		add.Types = append(add.Types, t)
	}
	addProto = func(p ProtoSpec) {
		addType(p.Ret)
		for _, q := range p.Params {
			addType(q)
		}
		if seenProto[p.Key()] {
			return
		}
		seenProto[p.Key()] = true
		add.Protos = append(add.Protos, p)
	}
	addMethod = func(m MethodSpec) {
		addType(m.Class)
		addProto(m.Proto)
		if seenMethod[m.Key()] {
			return
		}
		seenMethod[m.Key()] = true
		add.Methods = append(add.Methods, m)
	}
	addField = func(fl FieldSpec) {
		addType(fl.Class)
		addType(fl.Type)
		if seenField[fl.Key()] {
			return
		}
		seenField[fl.Key()] = true
		add.Fields = append(add.Fields, fl)
	}

	// 1) 类自身的声明面：类型名、父类、接口、字段、方法签名。
	for i := range add.Classes {
		c := &add.Classes[i]
		addType(c.Name)
		if c.Super != "" {
			addType(c.Super)
		}
		for _, ifc := range c.Interfaces {
			addType(ifc)
		}
		for _, fl := range c.Fields {
			addField(FieldSpec{Class: c.Name, Name: fl.Name, Type: fl.Type})
		}
		for _, m := range c.Methods {
			addMethod(MethodSpec{Class: c.Name, Name: m.Name, Proto: m.Proto})
		}
	}

	// 2) 方法体中的符号引用。
	//
	// 只需扫一遍：这一步只增加索引表条目，不会往 add.Classes 里追加类，
	// 因此被遍历的切片在循环中不会增长。
	for i := range add.Classes {
		for _, m := range add.Classes[i].Methods {
			if m.Code == nil {
				continue
			}
			for _, p := range m.Code.Patches {
				switch p.Ref.Kind {
				case RefType:
					addType(p.Ref.Type)
				case RefProto:
					addProto(p.Ref.Proto)
				case RefMethod:
					addMethod(p.Ref.Method)
				case RefField:
					addField(p.Ref.Field)
				case RefString:
					// 字符串由 collectAdditionStrings 负责
				}
			}
		}
	}
}

// collectAdditionStrings 收集追加条目所需的全部字符串。
func collectAdditionStrings(add *Addition, out map[string]bool) {
	addProto := func(p ProtoSpec) {
		out[p.Ret] = true
		for _, q := range p.Params {
			out[q] = true
		}
		out[p.Shorty()] = true
	}
	// 注入代码中的符号引用也需要对应的字符串/类型/原型/方法/字段条目，
	// 否则 CodeBlob.Bytes 解析引用时会失败。
	addRef := func(r RefSpec) {
		switch r.Kind {
		case RefString:
			out[r.String] = true
		case RefType:
			out[r.Type] = true
		case RefProto:
			addProto(r.Proto)
		case RefMethod:
			out[r.Method.Class] = true
			out[r.Method.Name] = true
			addProto(r.Method.Proto)
		case RefField:
			out[r.Field.Class] = true
			out[r.Field.Name] = true
			out[r.Field.Type] = true
		}
	}
	for _, t := range add.Types {
		out[t] = true
	}
	for _, p := range add.Protos {
		addProto(p)
	}
	for _, m := range add.Methods {
		out[m.Class] = true
		out[m.Name] = true
		addProto(m.Proto)
	}
	for _, fl := range add.Fields {
		out[fl.Class] = true
		out[fl.Name] = true
		out[fl.Type] = true
	}
	for _, c := range add.Classes {
		out[c.Name] = true
		if c.Super != "" {
			out[c.Super] = true
		}
		for _, ifc := range c.Interfaces {
			out[ifc] = true
		}
		if c.SourceFile != "" {
			out[c.SourceFile] = true
		}
		for _, fl := range c.Fields {
			out[fl.Name] = true
			out[fl.Type] = true
		}
		for _, m := range c.Methods {
			out[m.Name] = true
			addProto(m.Proto)
			if m.Code != nil {
				for _, p := range m.Code.Patches {
					addRef(p.Ref)
				}
			}
		}
	}
}

// oldProtoKey 返回第 i 个旧原型在重命名后的键。
func oldProtoKey(f *File, values []string, i uint32) (string, error) {
	if i >= f.NProto {
		return "", fmt.Errorf("dex: proto 索引越界 %d/%d", i, f.NProto)
	}
	base := f.OffProto + 12*i
	retIdx := binary.LittleEndian.Uint32(f.data[base+4:])
	paramsOff := binary.LittleEndian.Uint32(f.data[base+8:])
	ret := values[typeNameIdx(f, retIdx)]
	var params []string
	if paramsOff != 0 {
		n := binary.LittleEndian.Uint32(f.data[paramsOff:])
		params = make([]string, 0, n)
		for k := uint32(0); k < n; k++ {
			pi := uint32(binary.LittleEndian.Uint16(f.data[paramsOff+4+2*k:]))
			params = append(params, values[typeNameIdx(f, pi)])
		}
	}
	return protoKey(ret, params), nil
}

// protoKey 返回原型的唯一键。
func protoKey(ret string, params []string) string {
	out := ret
	out += "\x00"
	for _, p := range params {
		out += p
		out += "\x01"
	}
	return out
}

// fieldKey 返回字段引用的唯一键。
func fieldKey(class, name, typ string) string {
	return class + "\x00" + name + "\x00" + typ
}

// methodKey 返回方法引用的唯一键。
func methodKey(class, name, pkey string) string {
	return class + "\x00" + name + "\x00" + pkey
}

// typeNameIdx 返回第 i 个类型在 string_ids 中的索引。
func typeNameIdx(f *File, i uint32) uint32 {
	return binary.LittleEndian.Uint32(f.data[f.OffType+4*i:])
}

// buildShorty 依据返回类型与参数类型生成 DEX shorty 描述符。
func buildShorty(ret string, params []string) string {
	out := make([]byte, 0, len(params)+1)
	out = append(out, shortyChar(ret))
	for _, p := range params {
		out = append(out, shortyChar(p))
	}
	return string(out)
}

func shortyChar(desc string) byte {
	if desc == "" {
		return 'V'
	}
	switch desc[0] {
	case 'L', '[':
		return 'L'
	default:
		return desc[0]
	}
}
