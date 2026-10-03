package dex

import "fmt"

// ConstantArray 描述 A3 常量数组化的参数。
//
// 方案：把 const-string 常量改写为「在方法体内构造 byte[]（fill-array-data）
// 再调用还原方法」。这样字符串既不出现在字符串池中，也不以明文出现在
// 字节码里，只有按字节存放的原始数据，可绕过仅解析字符串池的扫描器。
type ConstantArray struct {
	// Class 是还原方法所在类的描述符，形如 "Lapkguard/Arr;"。
	Class string
	// MethodName 是还原方法名，签名固定为 ([B)Ljava/lang/String;。
	MethodName string
	// MinLen 是参与数组化的最短字符串长度（按 UTF-8 字节计）。
	MinLen int
	// InjectClass 为 true 时把还原方法类本体写入本 DEX。
	// 多 DEX 场景下只能有一个 DEX 落地该类。
	InjectClass bool
	// Skip 返回 true 表示该字符串不参与数组化；可为 nil。
	Skip func(s string) bool
}

// constantArrayPlan 是数组化方案的最终形态。
type constantArrayPlan struct {
	spec ConstantArray
	// skip 在 spec.Skip 基础上叠加了「还原方法自身的字符串常量」排除规则。
	skip func(string) bool
	// helper 是还原方法的引用。
	helper MethodSpec
	// byteArrayType 是 "[B" 的类型描述符（固定值，便于阅读）。
	byteArrayType string
	// count 是实际数组化的 const-string 数量。
	count int
}

// constantArrayAddition 构造还原方法所需的索引表条目与类定义。
func constantArrayAddition(ca *ConstantArray) (Addition, error) {
	protoB := ProtoSpec{Ret: "Ljava/lang/String;", Params: []string{"[B"}}
	protoInit := ProtoSpec{Ret: "V", Params: []string{"[B", "Ljava/lang/String;"}}
	strInit := MethodSpec{Class: "Ljava/lang/String;", Name: "<init>", Proto: protoInit}
	helper := MethodSpec{Class: ca.Class, Name: ca.MethodName, Proto: protoB}

	add := Addition{
		Types:   []string{ca.Class, "[B", "Ljava/lang/String;"},
		Protos:  []ProtoSpec{protoB, protoInit},
		Methods: []MethodSpec{helper, strInit},
	}
	if !ca.InjectClass {
		return add, nil
	}

	code, err := constantArrayHelperCode(strInit)
	if err != nil {
		return Addition{}, err
	}
	add.Classes = []ClassSpec{{
		Name:  ca.Class,
		Super: "Ljava/lang/Object;",
		// 同上：类级标志不带 STATIC。
		Access: accPublic | accFinal,
		Methods: []ClassMethod{{
			Name:   ca.MethodName,
			Proto:  protoB,
			Access: accPublic | accStatic,
			Code:   code,
		}},
	}}
	return add, nil
}

// constantArrayHelperCode 生成还原方法的字节码。
//
// 等价 Java 源码：
//
//	static String b(byte[] b) {
//	    return new String(b, "UTF-8");
//	}
//
// 寄存器：registers=3、ins=1，入参 b 落在 v2。
//
//	v0 = String 实例    v1 = "UTF-8"    v2 = b（入参）
func constantArrayHelperCode(strInit MethodSpec) (*CodeBlob, error) {
	const (
		rObj = 0
		rEnc = 1
		rB   = 2
	)
	a := NewAsm()
	a.NewInstance(rObj, "Ljava/lang/String;")
	a.ConstString(rEnc, "UTF-8")
	if err := a.InvokeDirect([]int{rObj, rB, rEnc}, strInit); err != nil {
		return nil, err
	}
	a.ReturnObject(rObj)

	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	return &CodeBlob{
		Registers: 3,
		Ins:       1,
		Outs:      3,
		Insns:     insns,
		Patches:   patches,
	}, nil
}

// isStringDecryptPattern 判断「第 i 项之后」是否为 A2 留下的解密调用序列
// （用**旧方法表**判签名；用于对已完成重建的产物做后验检查）。
func (l *InsnList) isStringDecryptPattern(i int, f *File) bool {
	return l.isStringDecryptPatternPlanned(i, nil, f)
}

// isStringDecryptPatternPlanned 是 isStringDecryptPattern 的 plan 感知版本。
//
// A2 会把 const-string 改写为「const-string/jumbo + invoke-static/range + move-result-object」，
// 因此若在 const-string 之后立即看到「单寄存器调用一个 (String)String 方法并接住结果」，
// 说明该常量已由 A2 处理，A3 应跳过以免重复包装。
//
// 关键：**不能只看旧方法表**。同一次 Rebuild 内 A2 写入的调用索引是**最终**索引，
// 用 b.f.MethodDesc（旧表）去判签名会读错方法，判据失效 → A3 拿新索引去旧字符串池
// 取串，嵌入完全错误的明文。因此：
//   - pl.strEnc != nil（同一次 Rebuild 刚跑过 A2）：直接比对 plan 里的解密方法索引；
//   - 否则（A3 单独运行，面对的是上一次 Rebuild 产物）：指令里仍是旧索引，用旧表判签名。
func (l *InsnList) isStringDecryptPatternPlanned(i int, pl *plan, f *File) bool {
	if i+2 >= l.ItemCount() {
		return false
	}
	inv := l.items[i+1]
	res := l.items[i+2]
	if inv.kind != itemInsn || res.kind != itemInsn {
		return false
	}
	if byte(inv.words[0]&0xff) != 0x77 { // invoke-static/range
		return false
	}
	if byte(res.words[0]&0xff) != 0x0c { // move-result-object
		return false
	}
	reg := int(l.items[i].words[0] >> 8)
	// 3rc：word0 的 A 字段是寄存器个数，word2 是首个寄存器
	if int(inv.words[0]>>8) != 1 || int(inv.words[2]) != reg {
		return false
	}
	if int(res.words[0]>>8) != reg {
		return false
	}
	idx := uint32(inv.words[1])
	if pl != nil && pl.strEnc != nil {
		v, ok := pl.methodIdx[pl.strEnc.decrypt.Key()]
		return ok && v == idx
	}
	if f == nil {
		return false
	}
	desc, err := f.MethodDesc(idx)
	if err != nil {
		return false
	}
	return hasStringToStringSignature(desc)
}

// hasStringToStringSignature 判断方法描述符是否为 (Ljava/lang/String;)Ljava/lang/String;。
func hasStringToStringSignature(desc string) bool {
	const want = "(Ljava/lang/String;)Ljava/lang/String;"
	return len(desc) >= len(want) && desc[len(desc)-len(want):] == want
}

// arrayizeCodeItem 把 code_item 中的 const-string 改写为常量数组构造序列。
//
// 输入 src 是「当前形态」的 code_item 字节流（可能是原始字节，也可能是 A2
// 改写后的产物）。inSkip 是上游改写步骤登记的「已是最终索引、不可再映射」的
// **绝对字位置，坐标系是 src**；本函数在返回时把它换算为本步产物坐标系。
//
// 返回的 blob 尚未做索引重映射，skip 给出其中「已是新索引」的字位置（含换算后
// 的上游 skip 与本步自身的 fresh）。
func (b *builder) arrayizeCodeItem(pl *plan, src []byte, inSkip map[int]bool) (blob []byte, skip map[int]bool, changed bool, err error) {
	ca := pl.constArr
	if ca == nil {
		return nil, inSkip, false, nil
	}
	ci, err := ParseCodeItemBytes(src)
	if err != nil {
		return nil, nil, false, err
	}
	helperIdx, ok := pl.methodIdx[ca.helper.Key()]
	if !ok {
		return nil, nil, false, fmt.Errorf("dex: 常量还原方法 %s 未登记", ca.helper.Desc())
	}
	if helperIdx > 0xffff {
		return nil, nil, false, fmt.Errorf("dex: 常量还原方法索引 %d 超出 16 位", helperIdx)
	}
	byteArrIdx, ok := pl.typeIdx[ca.byteArrayType]
	if !ok {
		return nil, nil, false, fmt.Errorf("dex: 类型 %s 未登记", ca.byteArrayType)
	}
	if byteArrIdx > 0xffff {
		return nil, nil, false, fmt.Errorf("dex: 类型 %s 的索引 %d 超出 16 位", ca.byteArrayType, byteArrIdx)
	}

	// try 区间端点必须落在合法指令边界上，否则替换会破坏端点定位
	boundary := map[int]bool{}
	for _, t := range ci.Tries {
		s := int(t.StartAddr)
		boundary[s] = true
		boundary[s+int(t.InsnCount)] = true
	}

	l, err := ParseInsns(ci.Insns)
	if err != nil {
		return nil, nil, false, err
	}
	// 解析后、任何替换前记录各项字长：skip 坐标平移依赖它把「项内相对偏移」
	// 从 src 坐标映到本步产物坐标（与 widenConstStrings 同一做法）。
	oldLens := make([]int, len(l.items))
	for i := range l.items {
		oldLens[i] = len(l.items[i].words)
	}

	replaced := map[int]bool{}
	for i := 0; i < l.ItemCount(); i++ {
		if !l.ItemIsInsn(i) {
			continue
		}
		w := l.ItemWords(i)
		op := byte(w[0] & 0xff)
		if op != 0x1a && op != 0x1b {
			continue
		}
		old := l.ItemOldOffset(i)
		interior := []int{old + 1}
		if op == 0x1b {
			interior = append(interior, old+2)
		}
		blocked := false
		for _, p := range interior {
			if boundary[p] {
				blocked = true
				break
			}
		}
		if blocked {
			continue
		}
		// 已由 A2 加密处理的常量不再重复包装
		if l.isStringDecryptPatternPlanned(i, pl, b.f) {
			continue
		}

		var idx uint32
		if op == 0x1a {
			idx = uint32(w[1])
		} else {
			idx = uint32(w[1]) | uint32(w[2])<<16
		}
		s, err := b.f.String(idx)
		if err != nil {
			continue
		}
		if b.opts.Rename != nil {
			if nv, ok := b.opts.Rename[s]; ok {
				s = nv
			}
		}
		if len(s) < ca.spec.MinLen {
			continue
		}
		if ca.skip != nil && ca.skip(s) {
			continue
		}
		if len(s) == 0 {
			continue
		}
		if !l.ReplaceWithArrayData(i, []byte(s), byteArrIdx, helperIdx) {
			continue // 寄存器编号无法编码，保守跳过
		}
		replaced[i] = true
	}
	if len(replaced) == 0 {
		// 本步无布局变化，src 坐标即产物坐标，上游 skip 原样透传。
		return nil, inSkip, false, nil
	}

	insns, m, fresh, eerr := l.EncodeChecked()
	if eerr != nil {
		return nil, nil, false, eerr
	}
	ca.count += len(replaced)
	// 先换算上游 skip，再并入本步 fresh（两者此时都是本步产物坐标）。
	skip = l.translateSkip(inSkip, oldLens)
	if skip == nil {
		skip = map[int]bool{}
	}
	for k := range fresh {
		skip[k] = true
	}

	ci.Insns = insns
	if ci.Outs < 1 {
		ci.Outs = 1
	}
	// 把地址修正交给 Encode 统一处理：它除了改 try 区间与处理器目标地址，
	// 还会重算 handler_off（异常处理器列表内的字节偏移）——后者必须重算，
	// 否则地址编码长度变化会让偏移失效，ART 判 "Bogus handler offset" 并
	// 丢弃整个 DEX。
	return ci.Encode(func(old uint32) uint32 { return FixAddr(m, old) }), skip, true, nil
}
