package dex

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"testing"
)

// 本文件钉住 R / R$Type 资源 ID 类的改名能力与护栏。
//
// 背景：样本 APK 的 R 类被彻底混淆（类名进默认包，45 个 static int 字段被
// 抹成短名），而 static_values 里的资源 ID（0x7f08xxxx）原样保留。本工具此前
// 因「内部类与外层类命名强耦合」把 R/R$Type 整类保留，字段名因此泄漏资源用途。
//
// 放行判据（全部取交集）：名字像 R/R$Type、至少一个 static int 字段带资源段
// 常量、字段名只被字段引用使用、整份 DEX 可被安全重建、平台前缀排除。
// 外层 R 只在本 DEX 内全部 R$Type 都放行时才一起改名。

// ---- 构造含 static_values 的测试 DEX ----

// rclassEncodeStaticValue 把一个标量编码为 encoded_value 字节。
func rclassEncodeStaticValue(t *testing.T, typ string, v int64) []byte {
	t.Helper()
	switch typ {
	case "Z":
		if v != 0 {
			return []byte{0x1f | 1<<5} // VALUE_BOOLEAN true（值在 value_arg）
		}
		return []byte{0x1f} // VALUE_BOOLEAN false
	case "B", "S", "C", "I", "J":
		vt := byte(0x04) // VALUE_INT
		switch typ {
		case "B":
			vt = 0x00
		case "S":
			vt = 0x02
		case "C":
			vt = 0x03
		case "J":
			vt = 0x06
		}
		u := uint64(v)
		n := 1
		for n < 8 {
			rest := u >> (8 * n)
			if v >= 0 && rest == 0 {
				break
			}
			if v < 0 && rest == ^uint64(0) {
				break
			}
			n++
		}
		// 正数最高位为 1 时补一字节，避免被解析成负数。
		if v >= 0 && n < 8 && u&(uint64(1)<<(8*n-1)) != 0 {
			n++
		}
		out := []byte{vt | byte((n-1)<<5)}
		for i := 0; i < n; i++ {
			out = append(out, byte(u>>(8*i)))
		}
		return out
	}
	t.Fatalf("测试不支持的字段类型 %s", typ)
	return nil
}

// rclassEncodeIntArray 把一个 []int64 编码为 encoded_array（VALUE_ARRAY）字节。
//
// R$styleable 的 static_values 就是这个形态：元素是资源 ID 的 int[]。
func rclassEncodeIntArray(t *testing.T, elems []int64) []byte {
	t.Helper()
	out := []byte{0x1c} // VALUE_ARRAY，value_arg 必须为 0
	out = append(out, PutULEB128(nil, uint32(len(elems)))...)
	for _, e := range elems {
		out = append(out, rclassEncodeStaticValue(t, "I", e)...)
	}
	return out
}

// rclassBuildDex 构造 DEX，并为指定类的静态字段写入标量 static_values。
func rclassBuildDex(t *testing.T, classes []ClassSpec, values map[string]map[string]int64) []byte {
	t.Helper()
	return rclassBuildDexEnc(t, classes, func(desc, ft, name string) ([]byte, bool) {
		m, ok := values[desc]
		if !ok {
			return nil, false
		}
		v, ok := m[name]
		if !ok {
			return nil, false
		}
		return rclassEncodeStaticValue(t, ft, v), true
	})
}

// rclassBuildDexArrays 构造 DEX，并为指定类的静态 int[] 字段写入
// encoded_array 形态的 static_values（R$styleable 的真实形态）。
func rclassBuildDexArrays(t *testing.T, classes []ClassSpec, values map[string]map[string][]int64) []byte {
	t.Helper()
	return rclassBuildDexEnc(t, classes, func(desc, ft, name string) ([]byte, bool) {
		m, ok := values[desc]
		if !ok {
			return nil, false
		}
		elems, ok := m[name]
		if !ok {
			return nil, false
		}
		return rclassEncodeIntArray(t, elems), true
	})
}

// rclassBuildDexEnc 构造 DEX，并为指定类的静态字段写入 static_values。
//
// Build 不支持静态字段初始值，这里沿用 auditfix2 的做法：先 Build，再在文件
// 末尾追加 encoded_array_item 并回填 class_def.static_values_off，最后 Finalize。
// enc 对「(类描述符, 字段类型, 字段名)」返回该字段的 encoded_value 字节；
// 返回 false 表示该字段没有提供值，按类型补默认值。
func rclassBuildDexEnc(t *testing.T, classes []ClassSpec, enc func(desc, ft, name string) ([]byte, bool)) []byte {
	t.Helper()
	d, err := Build(Addition{Classes: classes})
	if err != nil {
		t.Fatalf("构造测试 DEX 失败: %v", err)
	}
	f, err := Parse(d)
	if err != nil {
		t.Fatalf("解析测试 DEX 失败: %v", err)
	}
	out := append([]byte(nil), d...)
	for len(out)%4 != 0 {
		out = append(out, 0)
	}
	for i := uint32(0); i < f.NClass; i++ {
		desc, err := f.ClassName(i)
		if err != nil {
			continue
		}
		cd, err := f.ClassDefAt(i)
		if err != nil {
			t.Fatalf("读取类定义失败: %v", err)
		}
		if cd.ClassDataOff == 0 {
			continue
		}
		pcd, err := f.ParseClassData(cd.ClassDataOff)
		if err != nil {
			t.Fatalf("解析 class_data 失败: %v", err)
		}
		if len(pcd.StaticFields) == 0 {
			continue
		}
		// static_values 的第 k 个值对应第 k 个静态字段（field_idx 升序）。
		blob := PutULEB128(nil, uint32(len(pcd.StaticFields)))
		any := false
		for _, ef := range pcd.StaticFields {
			_, typeIdx, nameIdx, err := f.FieldRefAt(ef.Idx)
			if err != nil {
				t.Fatalf("读取字段引用失败: %v", err)
			}
			ft, _ := f.Type(uint32(typeIdx))
			nm, _ := f.String(nameIdx)
			ev, ok := enc(desc, ft, nm)
			if !ok {
				blob = append(blob, defaultEncodedValue(ft)...)
				continue
			}
			any = true
			blob = append(blob, ev...)
		}
		if !any {
			// 该类没有任何指定值：不挂 static_values，保持旧行为。
			continue
		}
		off := uint32(len(out))
		out = append(out, blob...)
		binary.LittleEndian.PutUint32(out[int(f.OffClass)+int(i)*32+28:], off)
	}
	return Finalize(out)
}

// rclassStaticValues 返回类中「静态字段名 -> encoded_value 视图」。
func rclassStaticValues(t *testing.T, f *File, classDesc string) map[string]encodedInt {
	t.Helper()
	out := map[string]encodedInt{}
	if err := f.Classes(func(_ uint32, cd ClassDef, cn string) error {
		if cn != classDesc || cd.StaticValuesOff == 0 || cd.ClassDataOff == 0 {
			return nil
		}
		pcd, err := f.ParseClassData(cd.ClassDataOff)
		if err != nil {
			return err
		}
		vals, err := encodedArrayInts(f.data, cd.StaticValuesOff)
		if err != nil {
			return err
		}
		for k, ef := range pcd.StaticFields {
			_, _, ni, err := f.FieldRefAt(ef.Idx)
			if err != nil {
				return err
			}
			nm, _ := f.String(ni)
			if k < len(vals) {
				out[nm] = vals[k]
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("读取 %s 的 static_values 失败: %v", classDesc, err)
	}
	return out
}

// rclassFieldNames 返回类的全部字段名（定义顺序）。
func rclassFieldNames(t *testing.T, f *File, classDesc string) []string {
	t.Helper()
	var out []string
	infos, err := f.ClassInfos()
	if err != nil {
		t.Fatalf("读取类信息失败: %v", err)
	}
	for _, ci := range infos {
		if ci.Desc != classDesc {
			continue
		}
		for _, fl := range ci.Fields() {
			out = append(out, fl.Name)
		}
	}
	if out == nil {
		t.Fatalf("产物中找不到类 %s", classDesc)
	}
	return out
}

// rclassHasClass 判断产物中是否存在该类描述符。
func rclassHasClass(t *testing.T, f *File, desc string) bool {
	t.Helper()
	found := false
	for i := uint32(0); i < f.NClass; i++ {
		if n, err := f.ClassName(i); err == nil && n == desc {
			found = true
		}
	}
	return found
}

// rclassPool 返回字符串池的集合视图。
func rclassPool(f *File) map[string]bool {
	out := map[string]bool{}
	for i := uint32(0); i < f.NString; i++ {
		if s, err := f.String(i); err == nil {
			out[s] = true
		}
	}
	return out
}

// rclassMethodCodeOff 返回类中指定方法的方法体偏移，找不到直接失败。
func rclassMethodCodeOff(t *testing.T, f *File, classDesc, name, proto string) uint32 {
	t.Helper()
	var found uint32
	if err := f.Classes(func(_ uint32, cd ClassDef, cn string) error {
		if cn != classDesc || cd.ClassDataOff == 0 {
			return nil
		}
		pcd, err := f.ParseClassData(cd.ClassDataOff)
		if err != nil {
			return err
		}
		for _, lst := range [][]EncodedMethod{pcd.DirectMethods, pcd.VirtualMethods} {
			for _, m := range lst {
				ref, err := f.MethodRefAt(m.Idx)
				if err != nil {
					continue
				}
				mn, _ := f.String(ref.NameIdx)
				mp, _ := f.ProtoDesc(uint32(ref.ProtoIdx))
				if mn == name && mp == proto {
					found = m.CodeOff
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("遍历类失败: %v", err)
	}
	if found == 0 {
		t.Fatalf("产物中找不到 %s->%s%s 的方法体", classDesc, name, proto)
	}
	return found
}

// rclassFieldRefIdxs 返回方法体内全部静态字段访问指令
// （sget 0x60 / sput 0x67 / sget-object 0x62 / sput-object 0x69）引用的
// field_ids 索引。
func rclassFieldRefIdxs(t *testing.T, f *File, codeOff uint32) []uint32 {
	t.Helper()
	ci, err := f.CodeInsns(codeOff)
	if err != nil {
		t.Fatalf("读取方法体失败: %v", err)
	}
	words := make([]uint16, ci.InsnsSize)
	for i := range words {
		words[i] = binary.LittleEndian.Uint16(f.data[ci.InsnsOff+2*i:])
	}
	var out []uint32
	if err := walkInsns(words, func(op byte, pos int, w []uint16) error {
		switch op { // 均为格式 21c，field@索引在第二个字
		case 0x60, 0x62, 0x67, 0x69:
			out = append(out, uint32(w[pos+1]))
		}
		return nil
	}); err != nil {
		t.Fatalf("遍历指令失败: %v", err)
	}
	return out
}

// rclassShortName 判断新名是否符合仓库短名生成器的风格（a..z、aa..）。
func rclassShortName(s string) bool {
	if s == "" || len(s) > 2 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 'a' || s[i] > 'z' {
			return false
		}
	}
	return true
}

// ---- 主测试 DEX：正例 + 反例 + 混字段边界 ----

// rclassMainDex 返回主测试 DEX。
//
// 类清单：
//
//	Lcom/x/R;              外层 R（无字段）
//	Lcom/x/R$string;       资源 ID 类：app_name / hello（0x7f03xxxx）+ DEBUG(boolean)
//	Lcom/x/R$id;           资源 ID 类：main_text（0x7f08xxxx）
//	Lcom/x/User;           引用上述字段与 R 类型的业务类
//	Landroid/R$string;     反例：平台 R 前缀，必须原样保留
//	Lcom/x/Outer$Inner;    反例：普通内部类，必须原样保留（字段值也在资源段）
func rclassMainDex(t *testing.T) []byte {
	t.Helper()
	a := NewAsm()
	a.ConstClass(2, "Lcom/x/R;")
	a.SGet(0, FieldSpec{Class: "Lcom/x/R$string;", Name: "app_name", Type: "I"})
	a.SGet(1, FieldSpec{Class: "Lcom/x/R$id;", Name: "main_text", Type: "I"})
	a.SPut(0, FieldSpec{Class: "Lcom/x/R$string;", Name: "hello", Type: "I"})
	a.AddInt(0, 0, 1)
	a.Return(0)
	insns, patches, err := a.Assemble()
	if err != nil {
		t.Fatalf("汇编失败: %v", err)
	}
	readBody := &CodeBlob{Registers: 3, Ins: 0, Outs: 0, Insns: insns, Patches: patches}

	return rclassBuildDex(t,
		[]ClassSpec{
			{Name: "Lcom/x/R;", Super: "Ljava/lang/Object;", Access: accPublic},
			{Name: "Lcom/x/R$string;", Super: "Ljava/lang/Object;", Access: accPublic,
				Fields: []ClassField{
					{Name: "app_name", Type: "I", Access: accPublic | accStatic | accFinal},
					{Name: "hello", Type: "I", Access: accPublic | accStatic | accFinal},
					{Name: "DEBUG", Type: "Z", Access: accPublic | accStatic | accFinal},
				}},
			{Name: "Lcom/x/R$id;", Super: "Ljava/lang/Object;", Access: accPublic,
				Fields: []ClassField{
					{Name: "main_text", Type: "I", Access: accPublic | accStatic | accFinal},
				}},
			{Name: "Lcom/x/User;", Super: "Ljava/lang/Object;", Access: accPublic,
				Methods: []ClassMethod{
					{Name: "read", Proto: ProtoSpec{Ret: "I"}, Access: accPublic | accStatic, Code: readBody},
				}},
			{Name: "Landroid/R$string;", Super: "Ljava/lang/Object;", Access: accPublic,
				Fields: []ClassField{
					{Name: "android_app_name", Type: "I", Access: accPublic | accStatic | accFinal},
				}},
			{Name: "Lcom/x/Outer$Inner;", Super: "Ljava/lang/Object;", Access: accPublic,
				Fields: []ClassField{
					{Name: "innerField", Type: "I", Access: accPublic | accStatic | accFinal},
				}},
		},
		map[string]map[string]int64{
			"Lcom/x/R$string;":    {"app_name": 0x7f030000, "hello": 0x7f030001, "DEBUG": 0},
			"Lcom/x/R$id;":        {"main_text": 0x7f080001},
			"Landroid/R$string;":  {"android_app_name": 0x7f030002},
			"Lcom/x/Outer$Inner;": {"innerField": 0x7f030003},
		})
}

// TestRenameResourceIDClassPositive 是端到端正例：R/R$Type 的类名与字段名都被
// 混淆，引用同步改写，static_values 逐字段保持，产物自校验通过，且可复现。
func TestRenameResourceIDClassPositive(t *testing.T) {
	data := rclassMainDex(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	cfg := RenameConfig{RenameResourceIDs: true, ObfuscateFields: true}

	plan, rn, err := rclassPlan(t, f, cfg)
	if err != nil {
		t.Fatalf("生成计划失败: %v", err)
	}
	st := rn.LastStats()
	if st.Classes < 4 {
		t.Fatalf("改名的类过少（%d），R 家族可能未被放行: %v", st.Classes, rn.keepReasons)
	}

	// 1) 类名：R/R$string/R$id 必须改名且互相一致；反例类必须不在计划里。
	newR, okR := plan["Lcom/x/R;"]
	newStr, okStr := plan["Lcom/x/R$string;"]
	newID, okID := plan["Lcom/x/R$id;"]
	if !okR || !okStr || !okID {
		t.Fatalf("R 家族未全部进入改名计划: R=%q(%v) R$string=%q(%v) R$id=%q(%v)",
			newR, okR, newStr, okStr, newID, okID)
	}
	for old, nw := range map[string]string{
		"Lcom/x/R;": newR, "Lcom/x/R$string;": newStr, "Lcom/x/R$id;": newID,
	} {
		if nw == old || !isPlainClassDesc(nw) {
			t.Fatalf("类名未被合法改名: %s -> %s", old, nw)
		}
	}

	// 2) 字段名：三个字段（含混入的 boolean DEBUG）都应被抹成短名。
	fieldPlan := map[string]string{}
	for _, old := range []string{"app_name", "hello", "DEBUG", "main_text"} {
		nw, ok := plan[old]
		if !ok {
			t.Fatalf("字段 %s 未被纳入改名计划", old)
		}
		if !rclassShortName(nw) {
			t.Fatalf("字段新名 %q（原 %s）不符合短名风格", nw, old)
		}
		fieldPlan[old] = nw
	}
	t.Logf("类改名: R=%s->%s R$string=%s->%s R$id=%s->%s User=%s->%s",
		"Lcom/x/R;", newR, "Lcom/x/R$string;", newStr, "Lcom/x/R$id;", newID,
		"Lcom/x/User;", plan["Lcom/x/User;"])
	t.Logf("字段改名: app_name->%s hello->%s DEBUG->%s main_text->%s",
		fieldPlan["app_name"], fieldPlan["hello"], fieldPlan["DEBUG"], fieldPlan["main_text"])

	// 3) 重建 + 产物校验。
	out, err := Rebuild(f, RebuildOptions{Rename: plan})
	if err != nil {
		t.Fatalf("重建失败: %v", err)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("产物校验失败: %v", err)
	}
	if err := ValidateDescriptors(out); err != nil {
		t.Fatalf("产物描述符非法: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("产物无法解析: %v", err)
	}

	// 4) 旧类名/旧字段名在产物中零命中。
	pool := rclassPool(g)
	for _, old := range []string{
		"Lcom/x/R;", "Lcom/x/R$string;", "Lcom/x/R$id;",
		"app_name", "hello", "main_text", "DEBUG",
	} {
		if pool[old] {
			t.Errorf("旧名字 %q 仍留在产物字符串池中（泄漏且可能断链）", old)
		}
	}

	// 5) 产物里新类存在、字段名就是计划里的新名；且 fieldref 指向新描述符。
	if !rclassHasClass(t, g, newStr) || !rclassHasClass(t, g, newID) || !rclassHasClass(t, g, newR) {
		t.Fatalf("产物缺少改名后的 R 家族类: %q %q %q", newR, newStr, newID)
	}
	gotFields := rclassFieldNames(t, g, newStr)
	wantFields := map[string]bool{fieldPlan["app_name"]: true, fieldPlan["hello"]: true, fieldPlan["DEBUG"]: true}
	if len(gotFields) != len(wantFields) {
		t.Fatalf("R$string 字段数变化: %v", gotFields)
	}
	for _, n := range gotFields {
		if !wantFields[n] {
			t.Errorf("R$string 出现意外字段名 %q（期望 %v）", n, wantFields)
		}
	}
	// 旧 (类,字段) 组合必须零命中；新组合必须存在。
	for i := uint32(0); i < g.NField; i++ {
		c, tIdx, nIdx, err := g.FieldRefAt(i)
		if err != nil {
			t.Fatalf("读取字段引用失败: %v", err)
		}
		cd, _ := g.Type(uint32(c))
		td, _ := g.Type(uint32(tIdx))
		nm, _ := g.String(nIdx)
		if cd == "Lcom/x/R$string;" || cd == "Lcom/x/R$id;" {
			t.Errorf("field_id[%d] 仍指向旧类 %s->%s:%s", i, cd, nm, td)
		}
	}
	for oldName, spec := range map[string]struct {
		newName string
		typ     string
	}{
		"app_name": {fieldPlan["app_name"], "I"},
		"hello":    {fieldPlan["hello"], "I"},
		"DEBUG":    {fieldPlan["DEBUG"], "Z"},
	} {
		if _, _, _, err := rclassFindField(g, newStr, spec.newName, spec.typ); err != nil {
			t.Errorf("field_id %s->%s:%s 不存在: %v", newStr, spec.newName, spec.typ, err)
		}
		if _, _, _, err := rclassFindField(g, newStr, oldName, spec.typ); err == nil {
			t.Errorf("field_id %s->%s:%s 仍然存在（旧名未清除）", newStr, oldName, spec.typ)
		}
	}

	// 6) 指令级：User.read 的 sget 必须指向新 fieldref（索引与描述符一致）。
	// 方法名可能也被混淆，从产物类的实际方法名反查（User 只有一个 ()I 方法）。
	userNew := plan["Lcom/x/User;"]
	userMethod := ""
	infos, err := g.ClassInfos()
	if err != nil {
		t.Fatalf("读取产物类信息失败: %v", err)
	}
	for _, ci := range infos {
		if ci.Desc != userNew {
			continue
		}
		for _, m := range ci.Methods() {
			if m.Proto == "()I" {
				userMethod = m.Name
			}
		}
	}
	if userMethod == "" {
		t.Fatalf("产物中找不到 User 的 ()I 方法（类 %s）", userNew)
	}
	codeOff := rclassMethodCodeOff(t, g, userNew, userMethod, "()I")
	idxs := rclassFieldRefIdxs(t, g, codeOff)
	if len(idxs) != 3 {
		t.Fatalf("User.read 的静态字段访问指令应为 3 条（sget x2 + sput x1），实际 %d", len(idxs))
	}
	wantRefs := map[string]bool{
		newStr + "|" + fieldPlan["app_name"] + "|I": true,
		newStr + "|" + fieldPlan["hello"] + "|I":    true, // sput 也必须被改写
		newID + "|" + fieldPlan["main_text"] + "|I": true,
	}
	for _, fi := range idxs {
		c, _, nameIdx, err := g.FieldRefAt(fi)
		if err != nil {
			t.Fatalf("读取 field_id[%d] 失败: %v", fi, err)
		}
		cls, _ := g.Type(uint32(c))
		nm, _ := g.String(nameIdx)
		key := cls + "|" + nm + "|I"
		if !wantRefs[key] {
			t.Errorf("静态字段访问指令指向了非预期的 fieldref: %s (idx=%d)", key, fi)
		}
		delete(wantRefs, key)
	}
	if len(wantRefs) != 0 {
		t.Errorf("有字段引用未被指令命中: %v", wantRefs)
	}

	// 7) static_values 逐字段逐字节保持（资源 ID 不能变）。
	rclassCheckStaticValues(t, f, g, "Lcom/x/R$string;", newStr, fieldPlan)
	rclassCheckStaticValues(t, f, g, "Lcom/x/R$id;", newID, fieldPlan)

	// 8) 同参数两次规划/重建完全一致（确定性）。
	plan2, _, err := rclassPlan(t, f, cfg)
	if err != nil {
		t.Fatalf("第二次规划失败: %v", err)
	}
	if !reflect.DeepEqual(plan, plan2) {
		t.Fatal("同一输入两次规划结果不同，破坏确定性")
	}
	out2, err := Rebuild(f, RebuildOptions{Rename: plan2})
	if err != nil {
		t.Fatalf("第二次重建失败: %v", err)
	}
	if !bytes.Equal(out, out2) {
		t.Fatal("同一输入两次重建字节不同，破坏可复现性")
	}
}

// rclassPlan 构造 Renamer 并返回计划与 Renamer（keepReasons 供诊断）。
func rclassPlan(t *testing.T, f *File, cfg RenameConfig) (map[string]string, *Renamer, error) {
	t.Helper()
	rn, err := NewRenamer(f, cfg)
	if err != nil {
		return nil, nil, err
	}
	plan, err := rn.Plan()
	return plan, rn, err
}

// rclassFindField 在 field_ids 里查找 (类, 名字, 类型)。
func rclassFindField(f *File, classDesc, name, typ string) (uint32, uint32, uint32, error) {
	for i := uint32(0); i < f.NField; i++ {
		c, t, n, err := f.FieldRefAt(i)
		if err != nil {
			return 0, 0, 0, err
		}
		cd, _ := f.Type(uint32(c))
		td, _ := f.Type(uint32(t))
		nm, _ := f.String(n)
		if cd == classDesc && td == typ && nm == name {
			return i, uint32(t), uint32(n), nil
		}
	}
	return 0, 0, 0, fmt.Errorf("field_id %s->%s:%s 不存在", classDesc, name, typ)
}

// rclassCheckStaticValues 断言：旧类每个静态字段的 encoded_value 与
// 新类中「按计划改名后的同名字段」逐字节一致，且资源 ID 数值不变。
func rclassCheckStaticValues(t *testing.T, oldF, newF *File, oldDesc, newDesc string, fieldPlan map[string]string) {
	t.Helper()
	oldVals := rclassStaticValues(t, oldF, oldDesc)
	newVals := rclassStaticValues(t, newF, newDesc)
	if len(oldVals) == 0 {
		t.Fatalf("%s 没有解析出 static_values", oldDesc)
	}
	if len(newVals) != len(oldVals) {
		t.Fatalf("%s static_values 数量变化: %d -> %d", oldDesc, len(oldVals), len(newVals))
	}
	for oldName, ov := range oldVals {
		nw, ok := fieldPlan[oldName]
		if !ok {
			t.Fatalf("字段 %s 没有改名计划", oldName)
		}
		nv, ok := newVals[nw]
		if !ok {
			t.Fatalf("%s 改名后字段 %s（原 %s）没有 static_value", newDesc, nw, oldName)
		}
		if !bytes.Equal(ov.Raw, nv.Raw) || ov.Val != nv.Val || ov.OK != nv.OK {
			t.Errorf("%s 字段 %s 的 static_value 变了: % x -> % x（%d -> %d）",
				oldDesc, oldName, ov.Raw, nv.Raw, ov.Val, nv.Val)
		}
	}
}

// TestRenameResourceIDClassNegative 钉住两条反例：平台 R 与普通内部类绝不动。
func TestRenameResourceIDClassNegative(t *testing.T) {
	data := rclassMainDex(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	plan, _, err := rclassPlan(t, f, RenameConfig{RenameResourceIDs: true, ObfuscateFields: true})
	if err != nil {
		t.Fatalf("生成计划失败: %v", err)
	}
	for _, desc := range []string{"Landroid/R$string;", "Lcom/x/Outer$Inner;"} {
		if nw, ok := plan[desc]; ok {
			t.Errorf("反例类被改名: %s -> %s", desc, nw)
		}
	}
	for _, name := range []string{"android_app_name", "innerField"} {
		if nw, ok := plan[name]; ok {
			t.Errorf("反例字段被改名: %s -> %s", name, nw)
		}
	}

	out, err := Rebuild(f, RebuildOptions{Rename: plan})
	if err != nil {
		t.Fatalf("重建失败: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("产物无法解析: %v", err)
	}
	if !rclassHasClass(t, g, "Landroid/R$string;") || !rclassHasClass(t, g, "Lcom/x/Outer$Inner;") {
		t.Error("反例类在产物中丢失")
	}
	if got := rclassFieldNames(t, g, "Landroid/R$string;"); len(got) != 1 || got[0] != "android_app_name" {
		t.Errorf("平台 R 字段被改动: %v", got)
	}
	if got := rclassFieldNames(t, g, "Lcom/x/Outer$Inner;"); len(got) != 1 || got[0] != "innerField" {
		t.Errorf("普通内部类字段被改动: %v", got)
	}
	// 反例类的 static_values 也必须原样。
	for _, desc := range []string{"Landroid/R$string;", "Lcom/x/Outer$Inner;"} {
		ov := rclassStaticValues(t, f, desc)
		nv := rclassStaticValues(t, g, desc)
		for k, v := range ov {
			if !bytes.Equal(v.Raw, nv[k].Raw) {
				t.Errorf("%s 字段 %s 的 static_value 被改动", desc, k)
			}
		}
	}
}

// TestRenameResourceIDClassGuardedByStringUsage 是护栏反例：R 类的字段名一旦
// 出现在 const-string 里（例如 getIdentifier 用资源名反射查询），该名字的
// 引用完整性无法确认，整个 R 类不改名（宁可漏改）。
func TestRenameResourceIDClassGuardedByStringUsage(t *testing.T) {
	a := NewAsm()
	a.ConstString(0, "dirty_name")
	a.ReturnVoid()
	insns, patches, err := a.Assemble()
	if err != nil {
		t.Fatalf("汇编失败: %v", err)
	}
	body := &CodeBlob{Registers: 1, Ins: 0, Outs: 0, Insns: insns, Patches: patches}

	data := rclassBuildDex(t,
		[]ClassSpec{
			{Name: "Lcom/y/R;", Super: "Ljava/lang/Object;", Access: accPublic},
			{Name: "Lcom/y/R$dirty;", Super: "Ljava/lang/Object;", Access: accPublic,
				Fields: []ClassField{{Name: "dirty_name", Type: "I", Access: accPublic | accStatic | accFinal}}},
			{Name: "Lcom/y/R$clean;", Super: "Ljava/lang/Object;", Access: accPublic,
				Fields: []ClassField{{Name: "clean_name", Type: "I", Access: accPublic | accStatic | accFinal}}},
			{Name: "Lcom/y/Use;", Super: "Ljava/lang/Object;", Access: accPublic,
				Methods: []ClassMethod{{Name: "probe", Proto: ProtoSpec{Ret: "V"}, Access: accPublic | accStatic, Code: body}}},
		},
		map[string]map[string]int64{
			"Lcom/y/R$dirty;": {"dirty_name": 0x7f030010},
			"Lcom/y/R$clean;": {"clean_name": 0x7f030011},
		})
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	plan, rn, err := rclassPlan(t, f, RenameConfig{RenameResourceIDs: true, ObfuscateFields: true})
	if err != nil {
		t.Fatalf("生成计划失败: %v", err)
	}
	if nw, ok := plan["Lcom/y/R$dirty;"]; ok {
		t.Errorf("字段名出现在 const-string 里的 R 类仍被改名: -> %s", nw)
	}
	if nw, ok := plan["dirty_name"]; ok {
		t.Errorf("被 const-string 引用的字段名仍被改名: -> %s", nw)
	}
	if nw, ok := plan["Lcom/y/R;"]; ok {
		t.Errorf("家族中存在不可放行成员时外层 R 仍被改名: -> %s", nw)
	}
	// 同家族的干净成员仍应被改名（逐个成员判定，不因邻居脏而整体放弃）。
	if _, ok := plan["Lcom/y/R$clean;"]; !ok {
		t.Errorf("干净成员 R$clean 未被改名；保留原因=%v", rn.keepReasons)
	}
	out, err := Rebuild(f, RebuildOptions{Rename: plan})
	if err != nil {
		t.Fatalf("重建失败: %v", err)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("产物校验失败: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("产物无法解析: %v", err)
	}
	if got := rclassFieldNames(t, g, "Lcom/y/R$dirty;"); len(got) != 1 || got[0] != "dirty_name" {
		t.Errorf("受护栏保护的字段被改动: %v", got)
	}
}

// TestRenameResourceIDClassDisabled 钉住一键关闭：RenameResourceIDs 为 false 时
// 完全维持旧行为（R/R$Type 整类保留，字段名原样）。
func TestRenameResourceIDClassDisabled(t *testing.T) {
	data := rclassMainDex(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	plan, _, err := rclassPlan(t, f, RenameConfig{ObfuscateFields: true})
	if err != nil {
		t.Fatalf("生成计划失败: %v", err)
	}
	for _, desc := range []string{"Lcom/x/R;", "Lcom/x/R$string;", "Lcom/x/R$id;"} {
		if nw, ok := plan[desc]; ok {
			t.Errorf("关闭开关后 R 类仍被改名: %s -> %s", desc, nw)
		}
	}
	for _, name := range []string{"app_name", "hello", "main_text"} {
		if nw, ok := plan[name]; ok {
			t.Errorf("关闭开关后 R 字段仍被改名: %s -> %s", name, nw)
		}
	}
}

// TestRenameResourceIDClassFamilyPartial 钉住家族一致性策略：R$styleable 这类
// 「纯下标常量」的成员不满足资源 ID 判据时，外层 R 与它一起保留；同家族
// 满足判据的 R$string 仍按成员独立放行（避免一个 styleable 拖垮全部覆盖）。
func TestRenameResourceIDClassFamilyPartial(t *testing.T) {
	data := rclassBuildDex(t,
		[]ClassSpec{
			{Name: "Lcom/z/R;", Super: "Ljava/lang/Object;", Access: accPublic},
			{Name: "Lcom/z/R$string;", Super: "Ljava/lang/Object;", Access: accPublic,
				Fields: []ClassField{{Name: "title", Type: "I", Access: accPublic | accStatic | accFinal}}},
			{Name: "Lcom/z/R$styleable;", Super: "Ljava/lang/Object;", Access: accPublic,
				Fields: []ClassField{{Name: "ActionBar_android_title", Type: "I", Access: accPublic | accStatic | accFinal}}},
		},
		map[string]map[string]int64{
			"Lcom/z/R$string;":    {"title": 0x7f030020},
			"Lcom/z/R$styleable;": {"ActionBar_android_title": 0}, // 下标常量，不是资源 ID
		})
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	plan, _, err := rclassPlan(t, f, RenameConfig{RenameResourceIDs: true, ObfuscateFields: true})
	if err != nil {
		t.Fatalf("生成计划失败: %v", err)
	}
	if nw, ok := plan["Lcom/z/R;"]; ok {
		t.Errorf("家族不齐时外层 R 被改名: -> %s", nw)
	}
	if nw, ok := plan["Lcom/z/R$styleable;"]; ok {
		t.Errorf("非资源 ID 判据的 R$styleable 被改名: -> %s", nw)
	}
	if nw, ok := plan["ActionBar_android_title"]; ok {
		t.Errorf("R$styleable 字段被改名: -> %s", nw)
	}
	if _, ok := plan["Lcom/z/R$string;"]; !ok {
		t.Error("满足判据的 R$string 未改名")
	}
	if _, ok := plan["title"]; !ok {
		t.Error("R$string 的资源字段未改名")
	}
}

// TestIsResourceIDClassDesc 钉住名字判据。
func TestIsResourceIDClassDesc(t *testing.T) {
	yes := []string{"Lcom/x/R;", "Lcom/x/R$string;", "LR;", "LR$id;", "La/b/c/R$styleable;"}
	no := []string{"Lcom/x/R2;", "Lcom/x/T;", "Lcom/x/Rr$string;", "Lcom/x/AR$string;", "Lcom/Rx;", "Lcom/x/Outer$Inner;"}
	for _, d := range yes {
		if !isResourceIDClassDesc(d) {
			t.Errorf("isResourceIDClassDesc(%q) = false，期望 true", d)
		}
	}
	for _, d := range no {
		if isResourceIDClassDesc(d) {
			t.Errorf("isResourceIDClassDesc(%q) = true，期望 false", d)
		}
	}
	if got := resourceFamilyKey("Lcom/x/R$string;"); got != "Lcom/x/R;" {
		t.Errorf("resourceFamilyKey = %q，期望 Lcom/x/R;", got)
	}
	if got := resourceFamilyKey("LR$id;"); got != "LR;" {
		t.Errorf("resourceFamilyKey(默认包) = %q，期望 LR;", got)
	}
}

// TestIsAndroidResourceID 钉住资源段判据。
func TestIsAndroidResourceID(t *testing.T) {
	yes := []int64{0x7f000000, 0x7f030001, 0x7f080001, 0x7fffffff, 0x01000000, 0x0101ffff}
	no := []int64{0x7e000000, 0x80000000, 0x01ffffff + 1, 0, 1, 42, -1}
	for _, v := range yes {
		if !isAndroidResourceID(v) {
			t.Errorf("isAndroidResourceID(0x%x) = false，期望 true", uint64(v))
		}
	}
	for _, v := range no {
		if isAndroidResourceID(v) {
			t.Errorf("isAndroidResourceID(0x%x) = true，期望 false", uint64(v))
		}
	}
}

// rclassStaticFieldOrder 返回类中静态字段名的定义顺序（field_idx 升序）。
func rclassStaticFieldOrder(t *testing.T, f *File, classDesc string) []string {
	t.Helper()
	var out []string
	if err := f.Classes(func(_ uint32, cd ClassDef, cn string) error {
		if cn != classDesc || cd.ClassDataOff == 0 {
			return nil
		}
		pcd, err := f.ParseClassData(cd.ClassDataOff)
		if err != nil {
			return err
		}
		for _, ef := range pcd.StaticFields {
			_, _, ni, err := f.FieldRefAt(ef.Idx)
			if err != nil {
				return err
			}
			nm, _ := f.String(ni)
			out = append(out, nm)
		}
		return nil
	}); err != nil {
		t.Fatalf("读取 %s 静态字段失败: %v", classDesc, err)
	}
	return out
}

// TestRenameResourceIDStaticValuesFollowFieldReorder 专打最关键的风险：
// 字段改名会改变 field_idx 排序，static_values 必须跟着字段重排，否则 ART
// 判 "unexpected static field initial value type" 并拒绝整个 DEX。
//
// 30 个字段让新名跨过 a..z 边界（第 27 个新名是 "aa"，其 UTF-16 序排在 "b"
// 之前），从而**必然**打乱字段顺序——这样测试才真正覆盖重排路径。
func TestRenameResourceIDStaticValuesFollowFieldReorder(t *testing.T) {
	const n = 30
	fields := make([]ClassField, 0, n)
	values := map[string]int64{}
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("res_field_%02d", i)
		fields = append(fields, ClassField{Name: name, Type: "I", Access: accPublic | accStatic | accFinal})
		values[name] = int64(0x7f040000 + i)
	}
	data := rclassBuildDex(t,
		[]ClassSpec{
			{Name: "Lcom/w/R$array;", Super: "Ljava/lang/Object;", Access: accPublic, Fields: fields},
		},
		map[string]map[string]int64{"Lcom/w/R$array;": values})
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	plan, _, err := rclassPlan(t, f, RenameConfig{RenameResourceIDs: true, ObfuscateFields: true})
	if err != nil {
		t.Fatalf("生成计划失败: %v", err)
	}
	newDesc, ok := plan["Lcom/w/R$array;"]
	if !ok {
		t.Fatalf("R$array 未被改名（字段值全部在 0x7f 段）")
	}
	oldOrder := rclassStaticFieldOrder(t, f, "Lcom/w/R$array;")
	if len(oldOrder) != n {
		t.Fatalf("旧静态字段数 %d，期望 %d", len(oldOrder), n)
	}
	out, err := Rebuild(f, RebuildOptions{Rename: plan})
	if err != nil {
		t.Fatalf("重建失败: %v", err)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("产物校验失败: %v", err)
	}
	if err := ValidateDescriptors(out); err != nil {
		t.Fatalf("产物描述符非法: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("产物无法解析: %v", err)
	}
	// 旧名字必须全部消失。
	pool := rclassPool(g)
	for _, name := range oldOrder {
		if pool[name] {
			t.Errorf("旧字段名 %q 仍在池中", name)
		}
	}
	// ART 对齐体检：值类型/数量与静态字段一一对应。
	checkStaticValues(t, "rclass-重排", g)

	// 字段顺序确实变了（否则本测试没有覆盖重排）。
	newOrder := rclassStaticFieldOrder(t, g, newDesc)
	inverse := map[string]string{}
	for _, old := range oldOrder {
		inverse[plan[old]] = old
	}
	mapped := make([]string, 0, len(newOrder))
	for _, nn := range newOrder {
		mapped = append(mapped, inverse[nn])
	}
	if reflect.DeepEqual(oldOrder, mapped) {
		t.Fatalf("字段顺序未变，测试未覆盖 static_values 重排: %v", oldOrder)
	}
	t.Logf("重排示例: 旧第 1 个=%s，新第 1 个=%s（原 %s）", oldOrder[0], newOrder[0], mapped[0])

	// 逐字段绑定：(原字段名 -> 原资源 ID) 在改名后仍由同一个字段承载。
	oldVals := rclassStaticValues(t, f, "Lcom/w/R$array;")
	newVals := rclassStaticValues(t, g, newDesc)
	for oldName, ov := range oldVals {
		nv, ok := newVals[plan[oldName]]
		if !ok {
			t.Fatalf("改名后找不到字段 %s（原 %s）", plan[oldName], oldName)
		}
		if !bytes.Equal(ov.Raw, nv.Raw) || ov.Val != nv.Val {
			t.Errorf("字段 %s（原 %s）的资源 ID 绑定错位: %d -> %d", plan[oldName], oldName, ov.Val, nv.Val)
		}
	}
}

// TestRenameResourceIDStyleableArraysFollowFieldReorder 专打 int[] 形态的重排风险：
// 字段改名会改变 field_idx 排序，每个 int[] 字段的 static_values（整段数组字节）
// 必须跟着字段移动到新位置，一个都不能串位。
//
// 标量形态的同类风险由 TestRenameResourceIDStaticValuesFollowFieldReorder 覆盖；
// 这里用 30 个 int[] 字段让新名跨过 a..z → aa 边界（"aa" 的 UTF-16 序排在 "b"
// 之前），从而**必然**打乱字段顺序，真正走到编码数组的重排路径。
func TestRenameResourceIDStyleableArraysFollowFieldReorder(t *testing.T) {
	const n = 30
	fields := make([]ClassField, 0, n)
	values := map[string][]int64{}
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("res_attrs_%02d", i)
		fields = append(fields, ClassField{Name: name, Type: "[I", Access: accPublic | accStatic | accFinal})
		values[name] = []int64{int64(0x7f0a0000 + i), int64(0x7f0a1000 + i)}
	}
	data := rclassBuildDexArrays(t,
		[]ClassSpec{
			{Name: "Lcom/rr/R$styleable;", Super: "Ljava/lang/Object;", Access: accPublic, Fields: fields},
		},
		map[string]map[string][]int64{"Lcom/rr/R$styleable;": values})
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	plan, rn, err := rclassPlan(t, f, RenameConfig{RenameResourceIDs: true, ObfuscateFields: true})
	if err != nil {
		t.Fatalf("生成计划失败: %v", err)
	}
	newDesc, ok := plan["Lcom/rr/R$styleable;"]
	if !ok {
		t.Fatalf("int[] 形态的 R$styleable 未被改名；保留原因=%v", rn.keepReasons)
	}
	oldOrder := rclassStaticFieldOrder(t, f, "Lcom/rr/R$styleable;")
	if len(oldOrder) != n {
		t.Fatalf("旧静态字段数 %d，期望 %d", len(oldOrder), n)
	}
	fieldPlan := map[string]string{}
	for _, old := range oldOrder {
		nw, ok := plan[old]
		if !ok {
			t.Fatalf("int[] 字段 %s 未被纳入改名计划", old)
		}
		fieldPlan[old] = nw
	}
	out, err := Rebuild(f, RebuildOptions{Rename: plan})
	if err != nil {
		t.Fatalf("重建失败: %v", err)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("产物校验失败: %v", err)
	}
	if err := ValidateDescriptors(out); err != nil {
		t.Fatalf("产物描述符非法: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("产物无法解析: %v", err)
	}
	// 旧字段名必须全部消失。
	pool := rclassPool(g)
	for _, name := range oldOrder {
		if pool[name] {
			t.Errorf("旧 int[] 字段名 %q 仍在池中", name)
		}
	}
	// ART 对齐体检：值类型/数量与静态字段一一对应。
	checkStaticValues(t, "styleable-重排", g)

	// 字段顺序确实变了（否则本测试没有覆盖数组重排）。
	newOrder := rclassStaticFieldOrder(t, g, newDesc)
	inverse := map[string]string{}
	for old, nw := range fieldPlan {
		inverse[nw] = old
	}
	mapped := make([]string, 0, len(newOrder))
	for _, nn := range newOrder {
		mapped = append(mapped, inverse[nn])
	}
	if reflect.DeepEqual(oldOrder, mapped) {
		t.Fatalf("字段顺序未变，测试未覆盖数组重排: %v", oldOrder)
	}
	t.Logf("数组重排示例: 旧第 1 个=%s，新第 1 个=%s（原 %s）", oldOrder[0], newOrder[0], mapped[0])

	// 每个字段的数组逐元素、逐字节不变，且（原字段名 -> 原资源 ID 序列）的绑定
	// 在改名后仍由同一个字段承载。
	rclassCheckArrayStaticValues(t, f, g, "Lcom/rr/R$styleable;", newDesc, fieldPlan)
}

// TestRenameResourceIDClassFrameworkRangeValue 钉住 0x01xxxxxx（框架资源段）
// 数值判据：非 Landroid/ 包名但常量落在 0x01 段时同样放行。
func TestRenameResourceIDClassFrameworkRangeValue(t *testing.T) {
	data := rclassBuildDex(t,
		[]ClassSpec{
			{Name: "Lcom/v/R$string;", Super: "Ljava/lang/Object;", Access: accPublic,
				Fields: []ClassField{{Name: "fw_id", Type: "I", Access: accPublic | accStatic | accFinal}}},
		},
		map[string]map[string]int64{"Lcom/v/R$string;": {"fw_id": 0x01020003}})
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	plan, _, err := rclassPlan(t, f, RenameConfig{RenameResourceIDs: true, ObfuscateFields: true})
	if err != nil {
		t.Fatalf("生成计划失败: %v", err)
	}
	if _, ok := plan["Lcom/v/R$string;"]; !ok {
		t.Fatal("0x01 段资源值的 R$string 未放行")
	}
	if _, ok := plan["fw_id"]; !ok {
		t.Fatal("0x01 段资源值的字段未放行")
	}
	out, err := Rebuild(f, RebuildOptions{Rename: plan})
	if err != nil {
		t.Fatalf("重建失败: %v", err)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("产物校验失败: %v", err)
	}
}

// TestRenameResourceIDOuterRWithDirtyOwnField 钉住外层 R 自身带字段时的护栏：
// 外层字段名出现在 const-string 里时，外层 R 不得因「内部类干净」而被改名，
// 否则会出现「类名变了、字段名留着」的半吊子状态。
func TestRenameResourceIDOuterRWithDirtyOwnField(t *testing.T) {
	a := NewAsm()
	a.ConstString(0, "outer_name")
	a.ReturnVoid()
	insns, patches, err := a.Assemble()
	if err != nil {
		t.Fatalf("汇编失败: %v", err)
	}
	body := &CodeBlob{Registers: 1, Ins: 0, Outs: 0, Insns: insns, Patches: patches}

	data := rclassBuildDex(t,
		[]ClassSpec{
			{Name: "Lcom/q/R;", Super: "Ljava/lang/Object;", Access: accPublic,
				Fields: []ClassField{{Name: "outer_name", Type: "I", Access: accPublic | accStatic | accFinal}}},
			{Name: "Lcom/q/R$string;", Super: "Ljava/lang/Object;", Access: accPublic,
				Fields: []ClassField{{Name: "title", Type: "I", Access: accPublic | accStatic | accFinal}}},
			{Name: "Lcom/q/Use;", Super: "Ljava/lang/Object;", Access: accPublic,
				Methods: []ClassMethod{{Name: "probe", Proto: ProtoSpec{Ret: "V"}, Access: accPublic | accStatic, Code: body}}},
		},
		map[string]map[string]int64{
			"Lcom/q/R;":        {"outer_name": 0x7f030030},
			"Lcom/q/R$string;": {"title": 0x7f030031},
		})
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	plan, _, err := rclassPlan(t, f, RenameConfig{RenameResourceIDs: true, ObfuscateFields: true})
	if err != nil {
		t.Fatalf("生成计划失败: %v", err)
	}
	if nw, ok := plan["Lcom/q/R;"]; ok {
		t.Errorf("外层 R 的字段名被 const-string 引用，外层却仍被改名: -> %s", nw)
	}
	if nw, ok := plan["outer_name"]; ok {
		t.Errorf("受护栏保护的字段仍被改名: -> %s", nw)
	}
	if _, ok := plan["Lcom/q/R$string;"]; !ok {
		t.Error("干净成员 R$string 未改名")
	}
	out, err := Rebuild(f, RebuildOptions{Rename: plan})
	if err != nil {
		t.Fatalf("重建失败: %v", err)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("产物校验失败: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("产物无法解析: %v", err)
	}
	if got := rclassFieldNames(t, g, "Lcom/q/R;"); len(got) != 1 || got[0] != "outer_name" {
		t.Errorf("外层 R 字段被改动: %v", got)
	}
}

// TestRenameResourceIDCrossTypeSameNameAllowed 钉住字段改名语义：
// 同一 R$Type 内字段名互不相同；跨 R$Type 子类的同名字段一起改名、
// 允许共用同一个短名（样本就是大量同名）。
func TestRenameResourceIDCrossTypeSameNameAllowed(t *testing.T) {
	data := rclassBuildDex(t,
		[]ClassSpec{
			{Name: "Lcom/s/R$string;", Super: "Ljava/lang/Object;", Access: accPublic,
				Fields: []ClassField{
					{Name: "shared_name", Type: "I", Access: accPublic | accStatic | accFinal},
					{Name: "only_string", Type: "I", Access: accPublic | accStatic | accFinal},
				}},
			{Name: "Lcom/s/R$id;", Super: "Ljava/lang/Object;", Access: accPublic,
				Fields: []ClassField{
					{Name: "shared_name", Type: "I", Access: accPublic | accStatic | accFinal},
					{Name: "only_id", Type: "I", Access: accPublic | accStatic | accFinal},
				}},
		},
		map[string]map[string]int64{
			"Lcom/s/R$string;": {"shared_name": 0x7f030040, "only_string": 0x7f030041},
			"Lcom/s/R$id;":     {"shared_name": 0x7f080040, "only_id": 0x7f080041},
		})
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	plan, _, err := rclassPlan(t, f, RenameConfig{RenameResourceIDs: true, ObfuscateFields: true})
	if err != nil {
		t.Fatalf("生成计划失败: %v", err)
	}
	newShared, ok := plan["shared_name"]
	if !ok {
		t.Fatal("跨 R$Type 的同名字段 shared_name 未被改名")
	}
	out, err := Rebuild(f, RebuildOptions{Rename: plan})
	if err != nil {
		t.Fatalf("重建失败: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("产物无法解析: %v", err)
	}
	newStr, newID := plan["Lcom/s/R$string;"], plan["Lcom/s/R$id;"]
	for _, desc := range []string{newStr, newID} {
		got := rclassFieldNames(t, g, desc)
		if len(got) != 2 {
			t.Fatalf("%s 字段数变化: %v", desc, got)
		}
		seen := map[string]bool{}
		found := false
		for _, n := range got {
			if seen[n] {
				t.Errorf("%s 内出现重复字段名 %q", desc, n)
			}
			seen[n] = true
			if n == newShared {
				found = true
			}
		}
		if !found {
			t.Errorf("%s 缺少共用短名 %q: %v", desc, newShared, got)
		}
	}
}

// ---- R$styleable：int[] 数组形态的 static_values ----

// rclassCheckArrayStaticValues 断言数组形态的 static_values 在改名前后
// 逐字段、逐元素、逐字节一致。
//
// fieldPlan 为 nil 表示字段名不变（用于未改名类）；否则用「旧字段名 -> 新字段名」
// 建立对应。
func rclassCheckArrayStaticValues(t *testing.T, oldF, newF *File, oldDesc, newDesc string, fieldPlan map[string]string) {
	t.Helper()
	oldVals := rclassStaticValues(t, oldF, oldDesc)
	newVals := rclassStaticValues(t, newF, newDesc)
	if len(oldVals) == 0 {
		t.Fatalf("%s 没有解析出 static_values", oldDesc)
	}
	for oldName, ov := range oldVals {
		nw := oldName
		if fieldPlan != nil {
			var ok bool
			nw, ok = fieldPlan[oldName]
			if !ok {
				t.Fatalf("字段 %s 没有改名计划", oldName)
			}
		}
		nv, ok := newVals[nw]
		if !ok {
			t.Fatalf("%s 改名后字段 %s（原 %s）没有 static_value", newDesc, nw, oldName)
		}
		if !ov.IsArray || !nv.IsArray {
			t.Fatalf("%s 字段 %s 不再是数组形态: old=%v new=%v", oldDesc, oldName, ov.IsArray, nv.IsArray)
		}
		if !bytes.Equal(ov.Raw, nv.Raw) {
			t.Errorf("%s 字段 %s 数组整体字节变化: % x -> % x", oldDesc, oldName, ov.Raw, nv.Raw)
		}
		if len(ov.Elems) != len(nv.Elems) {
			t.Fatalf("%s 字段 %s 元素数变化: %d -> %d", oldDesc, oldName, len(ov.Elems), len(nv.Elems))
		}
		for i := range ov.Elems {
			if !bytes.Equal(ov.Elems[i].Raw, nv.Elems[i].Raw) || ov.Elems[i].Val != nv.Elems[i].Val {
				t.Errorf("%s 字段 %s 第 %d 个元素变化: % x(%d) -> % x(%d)",
					oldDesc, oldName, i, ov.Elems[i].Raw, ov.Elems[i].Val, nv.Elems[i].Raw, nv.Elems[i].Val)
			}
		}
	}
}

// TestRenameResourceIDStyleableArraysPositive 是 int[] 形态（R$styleable）的
// 端到端正例：3 个 int[] 字段（static_values 是资源 ID 数组）与类名一起被混淆，
// 引用被改写、数组逐元素逐字节不变、产物自校验通过且可复现。
func TestRenameResourceIDStyleableArraysPositive(t *testing.T) {
	a := NewAsm()
	// 引用 int[] 字段：sget-object 取 R$styleable 的数组，再取长度返回。
	a.SGetObject(0, FieldSpec{Class: "Lcom/ax/R$styleable;", Name: "MyWidget_attrs", Type: "[I"})
	a.ArrayLength(1, 0)
	a.Return(1)
	insns, patches, err := a.Assemble()
	if err != nil {
		t.Fatalf("汇编失败: %v", err)
	}
	body := &CodeBlob{Registers: 2, Ins: 0, Outs: 0, Insns: insns, Patches: patches}

	values := map[string]map[string][]int64{
		"Lcom/ax/R$styleable;": {
			"MyWidget_attrs": {0x7f040001, 0x7f040002, 0x7f040003},
			"Other_attrs":    {0x7f040004},
			"Z_attrs":        {0x7f040005, 0x7f040006},
		},
	}
	data := rclassBuildDexArrays(t,
		[]ClassSpec{
			{Name: "Lcom/ax/R;", Super: "Ljava/lang/Object;", Access: accPublic},
			{Name: "Lcom/ax/R$styleable;", Super: "Ljava/lang/Object;", Access: accPublic,
				Fields: []ClassField{
					{Name: "MyWidget_attrs", Type: "[I", Access: accPublic | accStatic | accFinal},
					{Name: "Other_attrs", Type: "[I", Access: accPublic | accStatic | accFinal},
					{Name: "Z_attrs", Type: "[I", Access: accPublic | accStatic | accFinal},
				}},
			{Name: "Lcom/ax/User;", Super: "Ljava/lang/Object;", Access: accPublic,
				Methods: []ClassMethod{
					{Name: "count", Proto: ProtoSpec{Ret: "I"}, Access: accPublic | accStatic, Code: body},
				}},
		}, values)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	// 先确认构造出的 static_values 确实是数组形态，否则测试没打在目标路径上。
	oldVals := rclassStaticValues(t, f, "Lcom/ax/R$styleable;")
	if len(oldVals) != 3 {
		t.Fatalf("构造失败：R$styleable 静态字段数 %d，期望 3", len(oldVals))
	}
	for name, v := range oldVals {
		if !v.IsArray || len(v.Elems) != len(values["Lcom/ax/R$styleable;"][name]) {
			t.Fatalf("构造失败：%s 的 static_value 不是预期数组（IsArray=%v Elems=%d）", name, v.IsArray, len(v.Elems))
		}
	}

	cfg := RenameConfig{RenameResourceIDs: true, ObfuscateFields: true}
	plan, rn, err := rclassPlan(t, f, cfg)
	if err != nil {
		t.Fatalf("生成计划失败: %v", err)
	}
	if st := rn.LastStats(); st.Classes < 3 {
		t.Fatalf("改名的类过少（%d），R$styleable 家族可能未被放行: %v", st.Classes, rn.keepReasons)
	}

	// 1) 类名与字段名都进计划。
	newR, okR := plan["Lcom/ax/R;"]
	newSty, okSty := plan["Lcom/ax/R$styleable;"]
	newUser, okUser := plan["Lcom/ax/User;"]
	if !okR || !okSty || !okUser {
		t.Fatalf("R$styleable 家族未全部进入改名计划: R=%q(%v) styleable=%q(%v) User=%q(%v)",
			newR, okR, newSty, okSty, newUser, okUser)
	}
	fieldPlan := map[string]string{}
	for _, old := range []string{"MyWidget_attrs", "Other_attrs", "Z_attrs"} {
		nw, ok := plan[old]
		if !ok {
			t.Fatalf("int[] 字段 %s 未被纳入改名计划", old)
		}
		if !rclassShortName(nw) {
			t.Fatalf("int[] 字段新名 %q（原 %s）不符合短名风格", nw, old)
		}
		fieldPlan[old] = nw
	}
	t.Logf("styleable 类改名: %s -> %s；字段: MyWidget_attrs->%s Other_attrs->%s Z_attrs->%s",
		"Lcom/ax/R$styleable;", newSty, fieldPlan["MyWidget_attrs"], fieldPlan["Other_attrs"], fieldPlan["Z_attrs"])

	// 2) 重建 + 产物校验。
	out, err := Rebuild(f, RebuildOptions{Rename: plan})
	if err != nil {
		t.Fatalf("重建失败: %v", err)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("产物校验失败: %v", err)
	}
	if err := ValidateDescriptors(out); err != nil {
		t.Fatalf("产物描述符非法: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("产物无法解析: %v", err)
	}

	// 3) 旧类名/旧字段名在产物字符串池零命中。
	pool := rclassPool(g)
	for _, old := range []string{
		"Lcom/ax/R;", "Lcom/ax/R$styleable;",
		"MyWidget_attrs", "Other_attrs", "Z_attrs",
	} {
		if pool[old] {
			t.Errorf("旧名字 %q 仍留在产物字符串池中", old)
		}
	}
	if !rclassHasClass(t, g, newSty) || !rclassHasClass(t, g, newR) {
		t.Fatalf("产物缺少改名后的 R 家族类: %q %q", newR, newSty)
	}

	// 4) fieldref：旧 (类,字段) 组合零命中，新组合存在且类型仍是 [I。
	for oldName := range fieldPlan {
		if _, _, _, err := rclassFindField(g, newSty, oldName, "[I"); err == nil {
			t.Errorf("field_id %s->%s:[I 仍然存在（旧名未清除）", newSty, oldName)
		}
	}
	for oldName, nw := range fieldPlan {
		if _, _, _, err := rclassFindField(g, newSty, nw, "[I"); err != nil {
			t.Errorf("field_id %s->%s:[I（原 %s）不存在: %v", newSty, nw, oldName, err)
		}
	}

	// 5) 指令级：User.count 的 sget-object 必须指向新 fieldref。
	userMethod := ""
	infos, err := g.ClassInfos()
	if err != nil {
		t.Fatalf("读取产物类信息失败: %v", err)
	}
	for _, ci := range infos {
		if ci.Desc != newUser {
			continue
		}
		for _, m := range ci.Methods() {
			if m.Proto == "()I" {
				userMethod = m.Name
			}
		}
	}
	if userMethod == "" {
		t.Fatalf("产物中找不到 User 的 ()I 方法（类 %s）", newUser)
	}
	codeOff := rclassMethodCodeOff(t, g, newUser, userMethod, "()I")
	idxs := rclassFieldRefIdxs(t, g, codeOff)
	if len(idxs) != 1 {
		t.Fatalf("User.count 的静态字段访问指令应为 1 条（sget-object），实际 %d", len(idxs))
	}
	cIdx, _, nameIdx, err := g.FieldRefAt(idxs[0])
	if err != nil {
		t.Fatalf("读取 field_id 失败: %v", err)
	}
	gotCls, _ := g.Type(uint32(cIdx))
	gotName, _ := g.String(nameIdx)
	if gotCls != newSty || gotName != fieldPlan["MyWidget_attrs"] {
		t.Errorf("sget-object 指向了非预期 fieldref: %s->%s，期望 %s->%s",
			gotCls, gotName, newSty, fieldPlan["MyWidget_attrs"])
	}

	// 6) 数组逐字段、逐元素、逐字节不变（资源 ID 序列不能变）。
	rclassCheckArrayStaticValues(t, f, g, "Lcom/ax/R$styleable;", newSty, fieldPlan)
	for oldName, nw := range fieldPlan {
		nv := rclassStaticValues(t, g, newSty)[nw]
		t.Logf("数组逐字节保持: %s -> %s raw=% x（%d 个元素）", oldName, nw, nv.Raw, len(nv.Elems))
	}

	// 7) 同参数两次规划/重建完全一致（确定性）。
	plan2, _, err := rclassPlan(t, f, cfg)
	if err != nil {
		t.Fatalf("第二次规划失败: %v", err)
	}
	if !reflect.DeepEqual(plan, plan2) {
		t.Fatal("同一输入两次规划结果不同，破坏确定性")
	}
	out2, err := Rebuild(f, RebuildOptions{Rename: plan2})
	if err != nil {
		t.Fatalf("第二次重建失败: %v", err)
	}
	if !bytes.Equal(out, out2) {
		t.Fatal("同一输入两次重建字节不同，破坏可复现性")
	}
}

// TestRenameResourceIDStyleableArraysThreshold 钉住 int[] 判据的边界与反例：
//   - 元素全部不在资源段：类与字段都不改；
//   - 10 个元素里 9 个在资源段（90%）：放行；
//   - 10 个元素里 8 个在资源段（80%）：不放行（≥90% 不满足）；
//   - 一个类里只要有一个 int[] 字段满足判据就放行（与单值形态一致的逐字段语义），
//     不满足判据的兄弟字段原样保留其数组。
func TestRenameResourceIDStyleableArraysThreshold(t *testing.T) {
	fields := func(names ...string) []ClassField {
		out := make([]ClassField, 0, len(names))
		for _, n := range names {
			out = append(out, ClassField{Name: n, Type: "[I", Access: accPublic | accStatic | accFinal})
		}
		return out
	}
	data := rclassBuildDexArrays(t,
		[]ClassSpec{
			{Name: "Lcom/bad/R$styleable;", Super: "Ljava/lang/Object;", Access: accPublic,
				Fields: fields("bad_attrs")},
			{Name: "Lcom/ok/R$styleable;", Super: "Ljava/lang/Object;", Access: accPublic,
				Fields: fields("ok_attrs")},
			{Name: "Lcom/no/R$styleable;", Super: "Ljava/lang/Object;", Access: accPublic,
				Fields: fields("no_attrs")},
			{Name: "Lcom/mix/R$styleable;", Super: "Ljava/lang/Object;", Access: accPublic,
				Fields: fields("clean_attrs", "dirty_attrs")},
		},
		map[string]map[string][]int64{
			"Lcom/bad/R$styleable;": {"bad_attrs": {0x00110011, 0x00220022, 0x00330033}},
			// 9 个资源 ID + 1 个 0：恰好 90%，放行。
			"Lcom/ok/R$styleable;": {"ok_attrs": {
				0x7f050001, 0x7f050002, 0x7f050003, 0x7f050004, 0x7f050005,
				0x7f050006, 0x7f050007, 0x7f050008, 0x7f050009, 0,
			}},
			// 8 个资源 ID + 2 个非资源（0 与 7）= 80%，不放行。
			"Lcom/no/R$styleable;": {"no_attrs": {
				0x7f060001, 0x7f060002, 0x7f060003, 0x7f060004, 0x7f060005,
				0x7f060006, 0x7f060007, 0x7f060008, 0, 7,
			}},
			// clean 满足判据 → 整个类放行；dirty 不满足，但类放行后它的数组也原样保留。
			"Lcom/mix/R$styleable;": {
				"clean_attrs": {0x7f070001, 0x7f070002},
				"dirty_attrs": {0x12345678, 0x23456789},
			},
		})
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	plan, rn, err := rclassPlan(t, f, RenameConfig{RenameResourceIDs: true, ObfuscateFields: true})
	if err != nil {
		t.Fatalf("生成计划失败: %v", err)
	}

	// 反例：全部非资源元素 → 类与字段都不改。
	if nw, ok := plan["Lcom/bad/R$styleable;"]; ok {
		t.Errorf("非资源元素的 int[] 类被改名: -> %s", nw)
	}
	if nw, ok := plan["bad_attrs"]; ok {
		t.Errorf("非资源元素的 int[] 字段被改名: -> %s", nw)
	}
	// 80% 不放行。
	if nw, ok := plan["Lcom/no/R$styleable;"]; ok {
		t.Errorf("80%% 资源元素的 int[] 类被改名: -> %s（%v）", nw, rn.keepReasons["Lcom/no/R$styleable;"])
	}
	if nw, ok := plan["no_attrs"]; ok {
		t.Errorf("80%% 资源元素的 int[] 字段被改名: -> %s", nw)
	}
	// 90% 放行。
	if _, ok := plan["Lcom/ok/R$styleable;"]; !ok {
		t.Fatalf("90%% 资源元素的 int[] 类未放行；保留原因=%v", rn.keepReasons)
	}
	if _, ok := plan["ok_attrs"]; !ok {
		t.Fatal("90% 资源元素的 int[] 字段未放行")
	}
	// 类内任一字段满足即放行。
	if _, ok := plan["Lcom/mix/R$styleable;"]; !ok {
		t.Fatal("含一个合格 int[] 字段的类未放行")
	}
	for _, n := range []string{"clean_attrs", "dirty_attrs"} {
		if _, ok := plan[n]; !ok {
			t.Errorf("放行类的字段 %s 未改名", n)
		}
	}

	out, err := Rebuild(f, RebuildOptions{Rename: plan})
	if err != nil {
		t.Fatalf("重建失败: %v", err)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("产物校验失败: %v", err)
	}
	if err := ValidateDescriptors(out); err != nil {
		t.Fatalf("产物描述符非法: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("产物无法解析: %v", err)
	}
	// 未改名的反例数组逐字节不变。
	rclassCheckArrayStaticValues(t, f, g, "Lcom/bad/R$styleable;", "Lcom/bad/R$styleable;", nil)
	rclassCheckArrayStaticValues(t, f, g, "Lcom/no/R$styleable;", "Lcom/no/R$styleable;", nil)
	// 90% 与混合类改名后数组逐字节不变。
	rclassCheckArrayStaticValues(t, f, g, "Lcom/ok/R$styleable;", plan["Lcom/ok/R$styleable;"],
		map[string]string{"ok_attrs": plan["ok_attrs"]})
	rclassCheckArrayStaticValues(t, f, g, "Lcom/mix/R$styleable;", plan["Lcom/mix/R$styleable;"],
		map[string]string{"clean_attrs": plan["clean_attrs"], "dirty_attrs": plan["dirty_attrs"]})
}
