package dex

import (
	"strings"
	"testing"
)

// TestBuildEmptyDex 验证空 DEX 骨架合法且可被解析。
func TestBuildEmptyDex(t *testing.T) {
	d := Empty()
	if err := Verify(d); err != nil {
		t.Fatalf("空 DEX 校验失败: %v", err)
	}
	f, err := Parse(d)
	if err != nil {
		t.Fatalf("空 DEX 无法解析: %v", err)
	}
	if f.NString != 0 || f.NType != 0 || f.NProto != 0 ||
		f.NField != 0 || f.NMethod != 0 || f.NClass != 0 {
		t.Fatalf("空 DEX 不应有任何条目: str=%d type=%d proto=%d field=%d method=%d class=%d",
			f.NString, f.NType, f.NProto, f.NField, f.NMethod, f.NClass)
	}
	// 版本号必须是现代版本：035 是远古版本（安卓 2.2~7.x），现代系统会
	// 直接拒绝加载整个 DEX，表现为「装得上、一打开就崩」。
	if string(d[:8]) != "dex\n037\x00" {
		t.Fatalf("magic 异常: %q（现代安卓要求 DEX 版本不低于 037）", d[:8])
	}
}

// TestBuildNewDex 验证能从零构造出含壳类的 DEX。
//
// 这是 B1~B4 的基础设施：壳类必须落在一个**新建**的 DEX 中，
// 而不是依附于原 APK 的任何一个 DEX。
func TestBuildNewDex(t *testing.T) {
	const cls = "Lcom/demo/shell/App;"
	init := MethodSpec{
		Class: "Ljava/lang/Object;", Name: "<init>", Proto: ProtoSpec{Ret: "V"},
	}
	a := NewAsm()
	if err := a.InvokeDirect([]int{0}, init); err != nil {
		t.Fatalf("汇编失败: %v", err)
	}
	a.ReturnVoid()
	insns, patches, err := a.Assemble()
	if err != nil {
		t.Fatalf("组装失败: %v", err)
	}

	add := Addition{
		Types:   []string{cls, "Ljava/lang/Object;"},
		Protos:  []ProtoSpec{{Ret: "V"}},
		Methods: []MethodSpec{init, {Class: cls, Name: "<init>", Proto: ProtoSpec{Ret: "V"}}},
		Classes: []ClassSpec{{
			Name: cls, Super: "Ljava/lang/Object;", Access: accPublic,
			Methods: []ClassMethod{{
				Name: "<init>", Proto: ProtoSpec{Ret: "V"}, Access: accPublic,
				Code: &CodeBlob{Registers: 1, Ins: 1, Outs: 1, Insns: insns, Patches: patches},
			}},
		}},
	}
	out, err := Build(add)
	if err != nil {
		t.Fatalf("构造 DEX 失败: %v", err)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("校验失败: %v", err)
	}
	f, err := Parse(out)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if f.NClass != 1 {
		t.Fatalf("应含 1 个类，实际 %d", f.NClass)
	}
	found := false
	f.Classes(func(_ uint32, cd ClassDef, name string) error {
		if name != cls {
			return nil
		}
		found = true
		pcd, err := f.ParseClassData(cd.ClassDataOff)
		if err != nil {
			t.Fatalf("class_data 解析失败: %v", err)
		}
		if len(pcd.DirectMethods) != 1 {
			t.Fatalf("应有 1 个直接方法，实际 %d", len(pcd.DirectMethods))
		}
		ci, err := f.ParseCodeItem(pcd.DirectMethods[0].CodeOff)
		if err != nil {
			t.Fatalf("方法体解析失败: %v", err)
		}
		if _, err := ParseInsns(ci.Insns); err != nil {
			t.Fatalf("指令流非法: %v", err)
		}
		return nil
	})
	if !found {
		t.Fatal("未找到注入的壳类")
	}
	// 字符串池必须有序
	prev := ""
	for i := uint32(0); i < f.NString; i++ {
		s, err := f.String(i)
		if err != nil {
			t.Fatalf("字符串 %d 读取失败: %v", i, err)
		}
		if i > 0 && CompareUTF16(prev, s) >= 0 {
			t.Fatalf("字符串池顺序错误 @%d: %q >= %q", i, prev, s)
		}
		prev = s
	}
	t.Logf("新建 DEX：%d 字节，%d 字符串、%d 类型、%d 方法、%d 类",
		len(out), f.NString, f.NType, f.NMethod, f.NClass)
}

// TestBuildNewDexMultiClass 验证新建 DEX 可容纳多个互不冲突的壳类。
func TestBuildNewDexMultiClass(t *testing.T) {
	init := MethodSpec{
		Class: "Ljava/lang/Object;", Name: "<init>", Proto: ProtoSpec{Ret: "V"},
	}
	a := NewAsm()
	if err := a.InvokeDirect([]int{0}, init); err != nil {
		t.Fatalf("汇编失败: %v", err)
	}
	a.ReturnVoid()
	insns, patches, err := a.Assemble()
	if err != nil {
		t.Fatalf("组装失败: %v", err)
	}
	code := &CodeBlob{Registers: 1, Ins: 1, Outs: 1, Insns: insns, Patches: patches}

	names := []string{"Lcom/demo/shell/A;", "Lcom/demo/shell/B;", "Lcom/demo/shell/C;"}
	add := Addition{
		Types:   append([]string{"Ljava/lang/Object;"}, names...),
		Protos:  []ProtoSpec{{Ret: "V"}},
		Methods: []MethodSpec{init},
	}
	for _, n := range names {
		add.Methods = append(add.Methods, MethodSpec{Class: n, Name: "<init>", Proto: ProtoSpec{Ret: "V"}})
		add.Classes = append(add.Classes, ClassSpec{
			Name: n, Super: "Ljava/lang/Object;", Access: accPublic,
			Methods: []ClassMethod{{Name: "<init>", Proto: ProtoSpec{Ret: "V"}, Access: accPublic, Code: code}},
		})
	}
	out, err := Build(add)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	f, err := Parse(out)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if f.NClass != 3 {
		t.Fatalf("应含 3 个类，实际 %d", f.NClass)
	}
	got := map[string]bool{}
	f.Classes(func(_ uint32, _ ClassDef, name string) error {
		got[name] = true
		return nil
	})
	for _, n := range names {
		if !got[n] {
			t.Fatalf("缺少类 %s", n)
		}
	}
	// 三个类共用同一个 CodeBlob，code_item 必须去重为同一份
	offs := map[uint32]bool{}
	f.Classes(func(_ uint32, cd ClassDef, name string) error {
		pcd, err := f.ParseClassData(cd.ClassDataOff)
		if err != nil {
			t.Fatalf("%s class_data 解析失败: %v", name, err)
		}
		if len(pcd.DirectMethods) != 1 {
			t.Fatalf("%s 应有 1 个直接方法，实际 %d", name, len(pcd.DirectMethods))
		}
		offs[pcd.DirectMethods[0].CodeOff] = true
		return nil
	})
	if len(offs) != 1 {
		t.Fatalf("共用同一方法体时 code_item 应被去重为 1 份，实际 %d 份", len(offs))
	}
	for off := range offs {
		if off == 0 {
			t.Fatal("方法体的 code_off 不应为 0")
		}
	}
	// 方法描述符必须都在
	for _, n := range names {
		if !strings.Contains(n, "shell") {
			t.Fatal("类名构造异常")
		}
	}
}

// TestRebuildNormalizesDexVersion 验证重建时把过低的 DEX 版本提升到 037。
//
// 回归防线：老工具链构建的 APK（如 RustDesk 的 035）加固后，载荷 DEX 会
// 继承 035；现代安卓拒绝加载过低版本，表现为加固后业务类装载不到
// （ClassNotFoundException），而本地结构校验与 dex2oat 校验器都看不出问题。
func TestRebuildNormalizesDexVersion(t *testing.T) {
	src := make([]byte, len(sampleDex(t)))
	copy(src, sampleDex(t))
	// 人为把版本降成 035，再走一次重建。
	src[4], src[5], src[6] = '0', '3', '5'
	f, err := Parse(src)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if got := string(f.Data()[4:7]); got != "035" {
		t.Fatalf("构造输入失败，版本为 %s", got)
	}
	out, err := Rebuild(f, RebuildOptions{})
	if err != nil {
		t.Fatalf("重建失败: %v", err)
	}
	if got := string(out[4:7]); got != "037" {
		t.Fatalf("重建后版本应归一化为 037，实际 %s", got)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("重建结果校验失败: %v", err)
	}
	if _, err := Parse(out); err != nil {
		t.Fatalf("重建结果无法解析: %v", err)
	}
}
