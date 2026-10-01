package dex

import "testing"

// TestRenamerKeepsInheritedFrameworkMembers 钉住「引用继承自不可见父类的成员不得改名」。
//
// 真实缺陷（实测于 Termux 的 hiddenapibypass 库）：
// 某类 `nc` 继承 `dalvik.system.PathClassLoader`，它调用 `loadClass` 时**静态类型
// 是自己的类**，于是该引用在 method_ids 里是 `Lnc;->loadClass(String)Class`
// ——看起来像「应用内部方法」，但它其实是**从框架父类继承来的**。
// A1 把它改名后运行时解析不到：
//
//	NoSuchMethodError: No virtual method aez(Ljava/lang/String;)Ljava/lang/Class;
//	in class Lorg/lsposed/hiddenapibypass/nc;
//
// 判据：引用若无法在本 DEX 可见的继承链里找到声明，就说明声明在看不见的父类型里，
// 这种名字必须保留。
func TestRenamerKeepsInheritedFrameworkMembers(t *testing.T) {
	const cls = "Lapp/Loader;"
	// 继承一个框架类（不在 DEX 里），并声明一个「自有」方法作对照
	body := func(t *testing.T) *CodeBlob {
		t.Helper()
		a := NewAsm()
		a.InvokeStatic([]int{1}, MethodSpec{
			Class: cls, Name: "loadClass",
			Proto: ProtoSpec{Ret: "Ljava/lang/Class;", Params: []string{"Ljava/lang/String;"}},
		})
		a.MoveResultObject(0)
		a.ReturnObject(0)
		insns, patches, err := a.Assemble()
		if err != nil {
			t.Fatalf("汇编失败: %v", err)
		}
		return &CodeBlob{Registers: 2, Ins: 1, Outs: 1, Insns: insns, Patches: patches}
	}
	d, err := Build(Addition{Classes: []ClassSpec{{
		Name: cls, Super: "Ldalvik/system/PathClassLoader;", Access: 0x0001,
		Methods: []ClassMethod{
			// 正对照：静态方法不参与覆写，应当被改名
			{Name: "wrap", Proto: ProtoSpec{Ret: "Ljava/lang/Class;", Params: []string{"Ljava/lang/String;"}},
				Access: 0x0001 | 0x0008, Code: body(t)},
		},
	}}})
	if err != nil {
		t.Fatalf("构造 DEX 失败: %v", err)
	}
	f, err := Parse(d)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	rn, err := NewRenamer(f, RenameConfig{})
	if err != nil {
		t.Fatalf("构造重命名器失败: %v", err)
	}
	plan, err := rn.Plan()
	if err != nil {
		t.Fatalf("规划失败: %v", err)
	}
	if nw, ok := plan["loadClass"]; ok {
		t.Errorf("继承自框架父类的 loadClass 被改名（-> %q）：运行时 NoSuchMethodError", nw)
	}
	if _, ok := plan["wrap"]; !ok {
		t.Error("同类里的自有静态方法未被改名：保护过于保守")
	}
}
