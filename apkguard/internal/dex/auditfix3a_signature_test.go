package dex

import (
	"encoding/binary"
	"strings"
	"testing"
)

// 本文件收口 A1 重命名引擎的一条遗留缺口：dalvik.annotation.Signature
// 属性里的复合泛型串不随类改名。
//
// 现象：类改名按字符串池**精确值**匹配生效，而 Signature 的值是复合串
// （如 "Ljava/util/List<Lapp/Bar;>;"），与类描述符 "Lapp/Bar;" 不相等，
// 于是原样留在池里——类改名后泛型签名仍指向旧类名。ART 不校验 Signature，
// 不会崩，但 getGenericSuperclass()、Gson/Retrofit 一类按泛型反射的代码
// 会拿到不存在的类名。
//
// 复现手段：用 Build/Rebuild 造一个含类/字段/方法的 DEX，再把三个
// Signature 注解（分别挂在类、字段、方法上）手工注入 file 末尾。注解树在
// 重建时由 assemble.emitAnnotations 原样搬运，因此该构造足以端到端验证。

// audit3aSignatureDesc 是 Java 泛型签名的系统注解类型描述符。
const audit3aSignatureDesc = "Ldalvik/annotation/Signature;"

// 测试 DEX 中的固定名字。
const (
	audit3aClassName  = "Lapp/Bar;"
	audit3aFieldName  = "holder"
	audit3aMethodName = "m"
)

// audit3aVoidBody 构造一个 public static void 方法体（return-void）。
func audit3aVoidBody(t *testing.T) *CodeBlob {
	t.Helper()
	a := NewAsm()
	a.ReturnVoid()
	insns, patches, err := a.Assemble()
	if err != nil {
		t.Fatalf("汇编测试方法失败: %v", err)
	}
	return &CodeBlob{Registers: 1, Ins: 0, Outs: 0, Insns: insns, Patches: patches}
}

// audit3aBuildDex 构造一个含类 Lapp/Bar;（带一个字段、一个方法）的 DEX，
// 并把 extra 中的字符串预先放进池里（供 Signature 注解引用）。
func audit3aBuildDex(t *testing.T, extra ...string) []byte {
	t.Helper()
	add := Addition{
		Types: []string{audit3aSignatureDesc},
		Classes: []ClassSpec{{
			Name:   audit3aClassName,
			Super:  "Ljava/lang/Object;",
			Access: accPublic,
			Fields: []ClassField{{Name: audit3aFieldName, Type: "I", Access: accPublic}},
			Methods: []ClassMethod{{
				Name: audit3aMethodName, Proto: ProtoSpec{Ret: "V"},
				Access: accPublic | accStatic, Code: audit3aVoidBody(t),
			}},
		}},
	}
	f, err := Parse(Empty())
	if err != nil {
		t.Fatalf("解析空 DEX 失败: %v", err)
	}
	ns := append([]string{"value"}, extra...)
	d, err := Rebuild(f, RebuildOptions{Addition: &add, NewStrings: ns})
	if err != nil {
		t.Fatalf("构造测试 DEX 失败: %v", err)
	}
	if err := Verify(d); err != nil {
		t.Fatalf("构造出的测试 DEX 校验失败: %v", err)
	}
	return d
}

// audit3aPutEncodedString 追加一个 VALUE_STRING 形式的 encoded_value。
func audit3aPutEncodedString(dst []byte, idx uint32) []byte {
	n := 1
	for x := idx; x > 0xff; x >>= 8 {
		n++
	}
	dst = append(dst, 0x17|byte((n-1)<<5))
	for i := 0; i < n; i++ {
		dst = append(dst, byte(idx>>(8*i)))
	}
	return dst
}

// audit3aAttachSignatureAnnotations 在 DEX 末尾注入一个 annotations_directory，
// 把三个 dalvik.annotation.Signature 注解分别挂到类、字段、方法上。
//
// 每个注解的 value 是 String[]（encoded_array of VALUE_STRING）。
func audit3aAttachSignatureAnnotations(t *testing.T, data []byte,
	classSigs, fieldSigs, methodSigs []string) []byte {
	t.Helper()
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析 DEX 失败: %v", err)
	}

	strIdx := map[string]uint32{}
	for i := uint32(0); i < f.NString; i++ {
		s, err := f.String(i)
		if err != nil {
			t.Fatalf("读取字符串 %d 失败: %v", i, err)
		}
		if _, ok := strIdx[s]; !ok {
			strIdx[s] = i
		}
	}
	typeIdx := map[string]uint32{}
	for i := uint32(0); i < f.NType; i++ {
		s, err := f.Type(i)
		if err != nil {
			t.Fatalf("读取类型 %d 失败: %v", i, err)
		}
		if _, ok := typeIdx[s]; !ok {
			typeIdx[s] = i
		}
	}
	needStr := []string{"value"}
	for _, group := range [][]string{classSigs, fieldSigs, methodSigs} {
		needStr = append(needStr, group...)
	}
	for _, s := range needStr {
		if _, ok := strIdx[s]; !ok {
			t.Fatalf("字符串 %q 不在池中，无法构造注解（测试前提不成立）", s)
		}
	}
	annoType, ok := typeIdx[audit3aSignatureDesc]
	if !ok {
		t.Fatalf("类型 %q 不在 type_ids 中（测试前提不成立）", audit3aSignatureDesc)
	}

	// 定位类定义、字段、方法。
	classDef := ^uint32(0)
	for i := uint32(0); i < f.NClass; i++ {
		cd, err := f.ClassDefAt(i)
		if err != nil {
			t.Fatalf("读取 class_def %d 失败: %v", i, err)
		}
		if cd.ClassIdx == typeIdx[audit3aClassName] {
			classDef = i
		}
	}
	if classDef == ^uint32(0) {
		t.Fatalf("未找到类 %s 的 class_def", audit3aClassName)
	}
	fieldIdx := ^uint32(0)
	for i := uint32(0); i < f.NField; i++ {
		c, ty, n, err := f.FieldRefAt(i)
		if err != nil {
			t.Fatalf("读取 field_id %d 失败: %v", i, err)
		}
		cls, _ := f.Type(uint32(c))
		nm, _ := f.String(n)
		ft, _ := f.Type(uint32(ty))
		if cls == audit3aClassName && nm == audit3aFieldName && ft == "I" {
			fieldIdx = i
		}
	}
	if fieldIdx == ^uint32(0) {
		t.Fatalf("未找到字段 %s.%s", audit3aClassName, audit3aFieldName)
	}
	methodIdx := ^uint32(0)
	for i := uint32(0); i < f.NMethod; i++ {
		ref, err := f.MethodRefAt(i)
		if err != nil {
			t.Fatalf("读取 method_id %d 失败: %v", i, err)
		}
		cls, _ := f.Type(uint32(ref.ClassIdx))
		nm, _ := f.String(ref.NameIdx)
		pd, _ := f.ProtoDesc(uint32(ref.ProtoIdx))
		if cls == audit3aClassName && nm == audit3aMethodName && pd == "()V" {
			methodIdx = i
		}
	}
	if methodIdx == ^uint32(0) {
		t.Fatalf("未找到方法 %s.%s()V", audit3aClassName, audit3aMethodName)
	}

	out := append([]byte(nil), data...)
	align4 := func() {
		for len(out)%4 != 0 {
			out = append(out, 0)
		}
	}
	// makeItem 生成 annotation_item（visibility + encoded_annotation）并返回偏移。
	makeItem := func(sigs []string) uint32 {
		blob := []byte{1} // VISIBILITY_RUNTIME
		blob = PutULEB128(blob, annoType)
		blob = PutULEB128(blob, 1) // 1 个元素：value
		blob = PutULEB128(blob, strIdx["value"])
		blob = append(blob, 0x1c) // VALUE_ARRAY
		blob = PutULEB128(blob, uint32(len(sigs)))
		for _, s := range sigs {
			blob = audit3aPutEncodedString(blob, strIdx[s])
		}
		off := uint32(len(out))
		out = append(out, blob...)
		return off
	}
	// makeSet 生成 annotation_set_item（4 字节对齐）并返回偏移。
	makeSet := func(aiOff uint32) uint32 {
		align4()
		off := uint32(len(out))
		out = appendU32(out, 1)
		out = appendU32(out, aiOff)
		return off
	}
	classSet := makeSet(makeItem(classSigs))
	fieldSet := makeSet(makeItem(fieldSigs))
	methodSet := makeSet(makeItem(methodSigs))

	// annotations_directory_item：类注解 + 1 个字段注解 + 1 个方法注解。
	align4()
	dirOff := uint32(len(out))
	out = appendU32(out, classSet)
	out = appendU32(out, 1) // fields_size
	out = appendU32(out, 1) // methods_size
	out = appendU32(out, 0) // parameters_size
	out = appendU32(out, fieldIdx)
	out = appendU32(out, fieldSet)
	out = appendU32(out, methodIdx)
	out = appendU32(out, methodSet)

	binary.LittleEndian.PutUint32(out[f.OffClass+32*classDef+20:], dirOff)
	binary.LittleEndian.PutUint32(out[offFileSize:], uint32(len(out)))
	if dataOff := binary.LittleEndian.Uint32(out[offDataOff:]); dataOff != 0 {
		binary.LittleEndian.PutUint32(out[offDataSize:], uint32(len(out))-dataOff)
	}
	return Finalize(out)
}

// audit3aPool 读取 DEX 的全部字符串池内容（值集合）。
func audit3aPool(t *testing.T, data []byte) map[string]bool {
	t.Helper()
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析 DEX 失败: %v", err)
	}
	all, err := f.AllStrings()
	if err != nil {
		t.Fatalf("读取字符串池失败: %v", err)
	}
	out := map[string]bool{}
	for _, s := range all {
		out[s] = true
	}
	return out
}

// TestAuditFix3ASignatureAnnotationRenamed 回归：类/字段/方法上的
// dalvik.annotation.Signature 复合串必须随类改名，且不含待改名类的
// 签名串必须逐字节不变。
func TestAuditFix3ASignatureAnnotationRenamed(t *testing.T) {
	// 类注解：复合串（泛型实参里含有待改名类）。
	const sigList = "Ljava/util/List<Lapp/Bar;>;"
	// 类注解：嵌套泛型（Map<String, Bar>）。
	const sigMap = "Ljava/util/Map<Ljava/lang/String;Lapp/Bar;>;"
	// 字段注解：待改名类自身是泛型类（类型实参必须保留）。
	const sigField = "Lapp/Bar<Ljava/lang/String;>;"
	// 方法注解：参数与返回类型都含待改名类。
	const sigMethod = "(Lapp/Bar;)Ljava/util/List<Lapp/Bar;>;"
	// 反例：不含待改名类（Lapp/Baz; 未定义）的签名串。
	const sigNeg = "Ljava/util/List<Lapp/Baz;>;"
	// 反例：前缀相似但不同的类名（Lapp/BarInner; 未定义），不得被误伤。
	const sigNegPrefix = "Ljava/util/List<Lapp/BarInner;>;"

	data := audit3aBuildDex(t, sigList, sigMap, sigField, sigMethod, sigNeg, sigNegPrefix)
	data = audit3aAttachSignatureAnnotations(t, data,
		[]string{sigList, sigMap, sigNeg, sigNegPrefix},
		[]string{sigField},
		[]string{sigMethod})

	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析注入注解后的 DEX 失败: %v", err)
	}
	rn, err := NewRenamer(f, RenameConfig{})
	if err != nil {
		t.Fatalf("构造重命名器失败: %v", err)
	}
	plan, err := rn.Plan()
	if err != nil {
		t.Fatalf("生成重命名计划失败: %v", err)
	}

	newDesc, renamed := plan[audit3aClassName]
	if !renamed || newDesc == audit3aClassName {
		t.Fatalf("测试前提不成立：类 %s 未被改名（plan=%q）", audit3aClassName, newDesc)
	}
	newBody := strings.TrimSuffix(strings.TrimPrefix(newDesc, "L"), ";")
	want := map[string]string{
		sigList:   "Ljava/util/List<" + newDesc + ">;",
		sigMap:    "Ljava/util/Map<Ljava/lang/String;" + newDesc + ">;",
		sigField:  "L" + newBody + "<Ljava/lang/String;>;",
		sigMethod: "(" + newDesc + ")Ljava/util/List<" + newDesc + ">;",
	}
	for old, w := range want {
		got, ok := plan[old]
		if !ok {
			t.Errorf("签名串 %q 未随类改名：池里仍是旧类名 %s，泛型反射会拿到不存在的类名", old, audit3aClassName)
			continue
		}
		if got != w {
			t.Errorf("签名串 %q 的新值错误：got %q, want %q", old, got, w)
		}
	}
	for _, neg := range []string{sigNeg, sigNegPrefix} {
		if got, ok := plan[neg]; ok {
			t.Errorf("不含待改名类的签名串被改写（%q -> %q）：产物不稳定", neg, got)
		}
	}

	// 端到端：重建后池里必须只剩新签名串，反例串原样保留。
	out, err := Rebuild(f, RebuildOptions{Rename: plan})
	if err != nil {
		t.Fatalf("按重命名计划重建失败: %v", err)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("重建产物校验失败: %v", err)
	}
	pool := audit3aPool(t, out)
	for old, w := range want {
		if pool[old] {
			t.Errorf("重建后字符串池仍含旧签名串 %q", old)
		}
		if !pool[w] {
			t.Errorf("重建后字符串池缺少新签名串 %q", w)
		}
	}
	for _, neg := range []string{sigNeg, sigNegPrefix} {
		if !pool[neg] {
			t.Errorf("反例签名串 %q 在重建后消失或改变：未被改名的注解字符串必须逐字节保留", neg)
		}
	}
	if !pool[audit3aSignatureDesc] {
		t.Errorf("重建后 %s 字符串消失：注解树未被保留，本测试失去意义", audit3aSignatureDesc)
	}
}

// TestAuditFix3ASignatureCrossDexClassMap 跨 DEX：签名串里出现的是定义在
// 别的 DEX、本 DEX 只引用的类时，ClassMap 给出的全局改名决策同样要落到
// 签名串上（否则多 DEX 产物里签名仍指向旧类名）。
func TestAuditFix3ASignatureCrossDexClassMap(t *testing.T) {
	const sig = "Ljava/util/List<Lother/Ext;>;"
	data := audit3aBuildDex(t, sig)
	data = audit3aAttachSignatureAnnotations(t, data, []string{sig}, nil, nil)

	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析 DEX 失败: %v", err)
	}
	rn, err := NewRenamer(f, RenameConfig{
		ClassMap: map[string]string{"Lother/Ext;": "Lother/New;"},
	})
	if err != nil {
		t.Fatalf("构造重命名器失败: %v", err)
	}
	plan, err := rn.Plan()
	if err != nil {
		t.Fatalf("生成重命名计划失败: %v", err)
	}
	const want = "Ljava/util/List<Lother/New;>;"
	if got, ok := plan[sig]; !ok {
		t.Errorf("跨 DEX 类改名（Lother/Ext; -> Lother/New;）未落到签名串 %q 上", sig)
	} else if got != want {
		t.Errorf("跨 DEX 签名串新值错误：got %q, want %q", got, want)
	}

	out, err := Rebuild(f, RebuildOptions{Rename: plan})
	if err != nil {
		t.Fatalf("重建失败: %v", err)
	}
	pool := audit3aPool(t, out)
	if pool[sig] {
		t.Errorf("重建后池里仍含旧跨 DEX 签名串 %q", sig)
	}
	if !pool[want] {
		t.Errorf("重建后池里缺少新跨 DEX 签名串 %q", want)
	}
}

// TestAuditFix3ASignatureWithoutRenameUnchanged 反例（独立于类改名）：
// 若没有任何待改名类命中签名串，Plan 不得为该串生成任何条目。
func TestAuditFix3ASignatureWithoutRenameUnchanged(t *testing.T) {
	const sig = "Ljava/util/List<Lother/Type;>;"
	data := audit3aBuildDex(t, sig)
	data = audit3aAttachSignatureAnnotations(t, data, []string{sig}, nil, nil)

	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析 DEX 失败: %v", err)
	}
	rn, err := NewRenamer(f, RenameConfig{})
	if err != nil {
		t.Fatalf("构造重命名器失败: %v", err)
	}
	plan, err := rn.Plan()
	if err != nil {
		t.Fatalf("生成重命名计划失败: %v", err)
	}
	if got, ok := plan[sig]; ok {
		t.Errorf("签名串 %q 不含任何待改名类，却被生成改写项（-> %q）", sig, got)
	}
	out, err := Rebuild(f, RebuildOptions{Rename: plan})
	if err != nil {
		t.Fatalf("重建失败: %v", err)
	}
	if !audit3aPool(t, out)[sig] {
		t.Errorf("签名串 %q 在重建后消失或改变", sig)
	}
}

// TestAuditFix3ARewriteSignatureClasses 直接单测描述符级改写函数，覆盖
// 嵌套泛型、类型实参、数组与多类替换等边界。
func TestAuditFix3ARewriteSignatureClasses(t *testing.T) {
	rename := map[string]string{
		"Lcom/foo/Bar;":   "La/a;",
		"Lcom/foo/Qux;":   "La/b;",
		"Lcom/foo/Inner;": "La/c;",
	}
	cases := []struct {
		in    string
		want  string
		found bool
	}{
		{"Lcom/foo/Bar;", "La/a;", true},
		{"Ljava/util/List<Lcom/foo/Bar;>;", "Ljava/util/List<La/a;>;", true},
		{"Ljava/util/Map<Ljava/lang/String;Lcom/foo/Bar;>;",
			"Ljava/util/Map<Ljava/lang/String;La/a;>;", true},
		{"Lcom/foo/Bar<Ljava/lang/String;>;", "La/a<Ljava/lang/String;>;", true},
		{"Ljava/util/List<Ljava/util/Map<Lcom/foo/Bar;Ljava/util/List<Lcom/foo/Qux;>;>;>;",
			"Ljava/util/List<Ljava/util/Map<La/a;Ljava/util/List<La/b;>;>;>;", true},
		{"(Lcom/foo/Bar;[Lcom/foo/Qux;)Lcom/foo/Inner;",
			"(La/a;[La/b;)La/c;", true},
		// 内部类改写按擦除后的完整描述符查表：只命中外层类时保守不动。
		{"Lcom/foo/Outer<TT;>.Inner;", "Lcom/foo/Outer<TT;>.Inner;", false},
		{"Ljava/util/List<Lcom/foo/Outer.Inner;>;",
			"Ljava/util/List<Lcom/foo/Outer.Inner;>;", false},
		{"Ljava/util/List<Lother/Type;>;", "Ljava/util/List<Lother/Type;>;", false},
		{"Lcom/foo/BarInner;", "Lcom/foo/BarInner;", false},
		{"TT;", "TT;", false},
	}
	for _, c := range cases {
		got, found := rewriteSignatureClasses(c.in, rename)
		if got != c.want || found != c.found {
			t.Errorf("rewriteSignatureClasses(%q) = (%q, %v)，want (%q, %v)",
				c.in, got, found, c.want, c.found)
		}
	}
}
