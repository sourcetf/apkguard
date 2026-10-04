package dex

import (
	"bytes"
	"reflect"
	"testing"
)

// 本文件钉住 RenameConfig.RenameLibraries（库代码深度改名）的语义与护栏：
//
//   - 开关关闭（默认）：androidx / kotlin / android.support 等三方库类保持原名，
//     应用自身类照常改名；库类被引用的 fieldref/methodref 也不动；
//   - 开关打开：三方库类参与类名/字段名混淆，引用同步改写为库类的新描述符；
//   - 无论开关如何都绝不放行：平台前缀（java/、android/、javax/、dalvik/…），
//     以及类名出现在 const-string 里的反射类（本文件同时是这条回归护栏的
//     钉死测试）。
//
// 其余护栏（清单组件类、native 类、入口类、内部类）由 keepReason 的既有分支
// 负责，已在 rename_rclass_test.go / rename_test.go 中覆盖，这里不重复。

// libTestDex 构造库改名的测试 DEX：
//
//	Landroidx/test/Widget;    库类：静态字段 SIZE + 静态方法 size()
//	Lkotlin/test/Util;        库类
//	Landroid/support/v4/Thing; 旧 support 库类（android/support 前缀）
//	Landroidx/test/Guarded;   库类，类名出现在 const-string 中（反射护栏）
//	Ljava/lang/String;        平台类（必须恒保留）
//	Landroid/app/Activity;    平台类（必须恒保留）
//	Lapp/Main;                应用类，引用 Widget.size / Widget.SIZE 并反射 Guarded
func libTestDex(t *testing.T) []byte {
	t.Helper()

	sizeBody := func() *CodeBlob {
		a := NewAsm()
		a.Const4(0, 0)
		a.Return(0)
		insns, patches, err := a.Assemble()
		if err != nil {
			t.Fatalf("汇编失败: %v", err)
		}
		return &CodeBlob{Registers: 1, Ins: 0, Outs: 0, Insns: insns, Patches: patches}
	}
	mainBody := func() *CodeBlob {
		a := NewAsm()
		if err := a.InvokeStatic(nil, MethodSpec{
			Class: "Landroidx/test/Widget;", Name: "size", Proto: ProtoSpec{Ret: "I"},
		}); err != nil {
			t.Fatalf("汇编失败: %v", err)
		}
		a.MoveResult(0)
		a.SGet(1, FieldSpec{Class: "Landroidx/test/Widget;", Name: "SIZE", Type: "I"})
		a.ConstString(2, "androidx/test/Guarded")
		a.ReturnVoid()
		insns, patches, err := a.Assemble()
		if err != nil {
			t.Fatalf("汇编失败: %v", err)
		}
		return &CodeBlob{Registers: 3, Ins: 0, Outs: 0, Insns: insns, Patches: patches}
	}

	data, err := Build(Addition{Classes: []ClassSpec{
		{Name: "Landroidx/test/Widget;", Super: "Ljava/lang/Object;", Access: accPublic,
			Fields: []ClassField{
				{Name: "SIZE", Type: "I", Access: accPublic | accStatic | accFinal},
			},
			Methods: []ClassMethod{
				{Name: "size", Proto: ProtoSpec{Ret: "I"}, Access: accPublic | accStatic, Code: sizeBody()},
			}},
		{Name: "Lkotlin/test/Util;", Super: "Ljava/lang/Object;", Access: accPublic},
		{Name: "Landroid/support/v4/Thing;", Super: "Ljava/lang/Object;", Access: accPublic},
		{Name: "Landroidx/test/Guarded;", Super: "Ljava/lang/Object;", Access: accPublic},
		{Name: "Ljava/lang/String;", Super: "Ljava/lang/Object;", Access: accPublic},
		{Name: "Landroid/app/Activity;", Super: "Ljava/lang/Object;", Access: accPublic},
		{Name: "Lapp/Main;", Super: "Ljava/lang/Object;", Access: accPublic,
			Methods: []ClassMethod{
				{Name: "probe", Proto: ProtoSpec{Ret: "V"}, Access: accPublic | accStatic, Code: mainBody()},
			}},
	}})
	if err != nil {
		t.Fatalf("构造测试 DEX 失败: %v", err)
	}
	return data
}

// libTypeExists 判断产物类型表中是否存在该描述符。
func libTypeExists(t *testing.T, f *File, desc string) bool {
	t.Helper()
	for i := uint32(0); i < f.NType; i++ {
		if s, err := f.Type(i); err == nil && s == desc {
			return true
		}
	}
	return false
}

// libMethodRefCount 返回 method_ids 中「类描述符为 desc」的条目数。
func libMethodRefCount(t *testing.T, f *File, desc string) int {
	t.Helper()
	n := 0
	for i := uint32(0); i < f.NMethod; i++ {
		ref, err := f.MethodRefAt(i)
		if err != nil {
			t.Fatalf("读取方法引用失败: %v", err)
		}
		if cls, err := f.Type(uint32(ref.ClassIdx)); err == nil && cls == desc {
			n++
		}
	}
	return n
}

// TestRenameLibrariesToggle 是库改名开关的核心钉死测试：
// androidx/kotlin/android.support 在关闭时不变、打开时变化；
// java/lang/String 与 android/app/Activity 两种配置下都不变；
// 类名进 const-string 的库类在打开时也保持不变（回归护栏）。
func TestRenameLibrariesToggle(t *testing.T) {
	data := libTestDex(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	run := func(libs bool) (map[string]string, *Renamer, *File) {
		t.Helper()
		plan, rn, err := rclassPlan(t, f, RenameConfig{ObfuscateFields: true, RenameLibraries: libs})
		if err != nil {
			t.Fatalf("生成计划失败: %v", err)
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
		return plan, rn, g
	}

	libDescs := []string{"Landroidx/test/Widget;", "Lkotlin/test/Util;", "Landroid/support/v4/Thing;"}
	platformDescs := []string{"Ljava/lang/String;", "Landroid/app/Activity;"}

	// ---- 开关关闭（默认）：库类不变，应用类照常改名 ----
	planOff, rnOff, outOff := run(false)
	for _, d := range libDescs {
		if nw, ok := planOff[d]; ok {
			t.Errorf("RenameLibraries=false 时库类被改名: %s -> %s", d, nw)
		}
		if !libTypeExists(t, outOff, d) {
			t.Errorf("RenameLibraries=false 时产物缺少原库类 %s", d)
		}
	}
	if _, ok := planOff["Lapp/Main;"]; !ok {
		t.Error("RenameLibraries=false 时应用类 Lapp/Main; 未被改名")
	}
	for _, d := range append(append([]string{}, platformDescs...), "Landroidx/test/Guarded;") {
		if nw, ok := planOff[d]; ok {
			t.Errorf("RenameLibraries=false 时受保护类被改名: %s -> %s", d, nw)
		}
	}
	// 关闭时库类被引用的 methodref / fieldref 必须原样指向旧描述符。
	// method_ids 去重后「定义 + 调用」共用同一条，故期望恰好 1 条。
	if n := libMethodRefCount(t, outOff, "Landroidx/test/Widget;"); n != 1 {
		t.Errorf("关闭时 Widget.size 的 methodref 数=%d，期望 1（定义与调用共用同一条）", n)
	}
	if _, _, _, err := rclassFindField(outOff, "Landroidx/test/Widget;", "SIZE", "I"); err != nil {
		t.Errorf("关闭时 Widget.SIZE 的 fieldref 被改动: %v", err)
	}
	t.Logf("关闭时保留原因：Widget=%q Guarded=%q", rnOff.keepReasons["Landroidx/test/Widget;"],
		rnOff.keepReasons["Landroidx/test/Guarded;"])

	// ---- 开关打开：库类参与改名，引用指向新描述符 ----
	planOn, rnOn, outOn := run(true)
	libNew := map[string]string{}
	for _, d := range libDescs {
		nw, ok := planOn[d]
		if !ok {
			t.Fatalf("RenameLibraries=true 时库类未被改名: %s（保留原因=%v）", d, rnOn.keepReasons)
		}
		if nw == d || !isPlainClassDesc(nw) {
			t.Fatalf("库类改名非法: %s -> %s", d, nw)
		}
		libNew[d] = nw
	}
	for _, d := range platformDescs {
		if nw, ok := planOn[d]; ok {
			t.Errorf("RenameLibraries=true 时平台类被改名: %s -> %s", d, nw)
		}
		if !libTypeExists(t, outOn, d) {
			t.Errorf("RenameLibraries=true 时产物缺少平台类 %s", d)
		}
	}
	// 回归护栏：类名进 const-string 的库类即使开关打开也不改。
	if nw, ok := planOn["Landroidx/test/Guarded;"]; ok {
		t.Errorf("类名出现在 const-string 的库类被改名: -> %s", nw)
	}
	if !libTypeExists(t, outOn, "Landroidx/test/Guarded;") {
		t.Error("反射护栏库类在产物中丢失")
	}
	// 旧库类描述符从类型表消失，新描述符存在；引用同步改写。
	for old, nw := range libNew {
		if libTypeExists(t, outOn, old) {
			t.Errorf("打开开关后旧库类描述符 %s 仍在类型表中", old)
		}
		if !libTypeExists(t, outOn, nw) {
			t.Errorf("打开开关后产物缺少新库类 %s（原 %s）", nw, old)
		}
	}
	if n := libMethodRefCount(t, outOn, "Landroidx/test/Widget;"); n != 0 {
		t.Errorf("打开开关后仍有 %d 条 methodref 指向旧库类描述符", n)
	}
	newWidget := libNew["Landroidx/test/Widget;"]
	if n := libMethodRefCount(t, outOn, newWidget); n != 1 {
		t.Errorf("打开开关后指向新库类 %s 的 methodref 数=%d，期望 1", newWidget, n)
	}
	if _, _, _, err := rclassFindField(outOn, "Landroidx/test/Widget;", "SIZE", "I"); err == nil {
		t.Error("打开开关后 Widget.SIZE 的旧 fieldref 仍存在")
	}
	// 字段名是否被改由 ObfuscateFields 决定：这里检查 fieldref 指向新类即可。
	foundNewField := false
	for i := uint32(0); i < outOn.NField; i++ {
		cIdx, typeIdx, _, err := outOn.FieldRefAt(i)
		if err != nil {
			t.Fatalf("读取字段引用失败: %v", err)
		}
		cls, _ := outOn.Type(uint32(cIdx))
		typ, _ := outOn.Type(uint32(typeIdx))
		if cls == newWidget && typ == "I" {
			foundNewField = true
		}
	}
	if !foundNewField {
		t.Errorf("打开开关后找不到指向新库类 %s 的 int 字段引用", newWidget)
	}
	t.Logf("打开时改名: Widget %s -> %s；Guarded 保留原因=%q", "Landroidx/test/Widget;", newWidget,
		rnOn.keepReasons["Landroidx/test/Guarded;"])

	// ---- 确定性：同配置两次规划/重建完全一致 ----
	planOn2, _, _ := run(true)
	if !reflect.DeepEqual(planOn, planOn2) {
		t.Fatal("RenameLibraries=true 时同一输入两次规划结果不同")
	}
	if !bytes.Equal(planBytes(t, f, planOn), planBytes(t, f, planOn2)) {
		t.Fatal("RenameLibraries=true 时同一输入两次重建字节不同")
	}
}

// planBytes 按给定计划重建并返回产物字节（确定性对比用）。
func planBytes(t *testing.T, f *File, plan map[string]string) []byte {
	t.Helper()
	out, err := Rebuild(f, RebuildOptions{Rename: plan})
	if err != nil {
		t.Fatalf("重建失败: %v", err)
	}
	return out
}
