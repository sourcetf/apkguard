package dex

import (
	"testing"
)

// TestRenamerKeepsOverridesOfInvisibleTypes 钉住「不得改名可能覆写不可见方法的成员」。
//
// 真实缺陷（实测于 Dhizuku）：类的父类型若不在本 DEX 里（框架/未打包的库），
// 它的非私有实例方法就可能是在**实现我们看不见的接口方法**。这类方法在本 DEX
// 中往往没有任何调用点（调用方是系统），因此「引用者是否都在改名集合里」这条
// 判据完全看不见它——名字被改掉后覆写关系断裂，运行时抛
//
//	java.lang.AbstractMethodError: abstract method "...OnAttachStateChangeListener
//	.onViewAttachedToWindow(android.view.View)"
//
// 这里的 onViewAttachedToWindow 不在硬编码白名单里，正是踩中的那个名字。
func TestRenamerKeepsOverridesOfInvisibleTypes(t *testing.T) {
	retVoid := ProtoSpec{Ret: "V"}
	body := func(t *testing.T) *CodeBlob {
		t.Helper()
		a := NewAsm()
		a.ReturnVoid()
		insns, patches, err := a.Assemble()
		if err != nil {
			t.Fatalf("汇编失败: %v", err)
		}
		return &CodeBlob{Registers: 1, Ins: 1, Outs: 0, Insns: insns, Patches: patches}
	}

	d, err := Build(Addition{Classes: []ClassSpec{
		{
			// 实现的接口在 DEX 之外（框架回调）→ 方法名不能被改。
			// 注意这里**不能**选 Activity 这类入口类做父类：那种类本身会被
			// 保留，方法自然也不改名，测试就失去意义了。
			Name:       "Lapp/Child;",
			Super:      "Ljava/lang/Object;",
			Interfaces: []string{"Landroid/view/View$OnAttachStateChangeListener;"},
			Access:     0x0001,
			Methods: []ClassMethod{{
				Name:   "onViewAttachedToWindow",
				Proto:  ProtoSpec{Ret: "V", Params: []string{"Landroid/view/View;"}},
				Access: 0x0001,
				Code:   body(t),
			}},
		},
		{
			// 继承链全在应用内部 → 可以安全改名
			Name:   "Lapp/Internal;",
			Super:  "Ljava/lang/Object;",
			Access: 0x0001,
			Methods: []ClassMethod{{
				Name:   "internalHelper",
				Proto:  retVoid,
				Access: 0x0001,
				Code:   body(t),
			}},
		},
	}})
	if err != nil {
		t.Fatalf("构造 DEX 失败: %v", err)
	}
	f, err := Parse(d)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	rn, err := NewRenamer(f, RenameConfig{ObfuscateFields: true})
	if err != nil {
		t.Fatalf("构造重命名器失败: %v", err)
	}
	plan, err := rn.Plan()
	if err != nil {
		t.Fatalf("生成计划失败: %v", err)
	}

	if nw, ok := plan["onViewAttachedToWindow"]; ok {
		t.Errorf("父类在 DEX 之外的方法被改名（%q -> %q）——"+
			"它可能是框架回调的实现，改名后运行时抛 AbstractMethodError", "onViewAttachedToWindow", nw)
	}
	if _, ok := plan["internalHelper"]; !ok {
		t.Error("继承链全在应用内部的方法未被改名：保护逻辑过于保守，A1 失去价值")
	}
}
