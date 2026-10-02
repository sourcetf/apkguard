package dex

import "testing"

// TestInjectedClinitHasConstructorFlag 钉住「注入类的 <clinit> 必须带 ACC_CONSTRUCTOR」。
//
// ART 会校验构造函数的访问标志。缺失虽不致命，却会在每次加载产物时打印
//
//	W/...: <clinit> didn't have expected constructor access flag in class ...
//
// 这个警告本身说明生成的 class_data_item 不合规范。实测在 Dhizuku 全选项加固
// 产物上出现（见 realworld/实测记录-三应用全选项.md），因此在这里固定住。
func TestInjectedClinitHasConstructorFlag(t *testing.T) {
	a := NewAsm()
	a.ReturnVoid()
	insns, patches, err := a.Assemble()
	if err != nil {
		t.Fatalf("汇编失败: %v", err)
	}
	blob := &CodeBlob{Registers: 1, Ins: 1, Outs: 0, Insns: insns, Patches: patches}

	d, err := Build(Addition{Classes: []ClassSpec{{
		Name:   "Lt/Clinit;",
		Super:  "Ljava/lang/Object;",
		Access: accPublic,
		Methods: []ClassMethod{{
			Name:   "<clinit>",
			Proto:  ProtoSpec{Ret: "V"},
			Access: accStatic,
			Code:   blob,
		}},
	}}})
	if err != nil {
		t.Fatalf("构造 DEX 失败: %v", err)
	}
	f, err := Parse(d)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	found := false
	err = f.Classes(func(_ uint32, cd ClassDef, name string) error {
		if name != "Lt/Clinit;" {
			return nil
		}
		data, derr := f.ParseClassData(cd.ClassDataOff)
		if derr != nil {
			return derr
		}
		for _, m := range data.DirectMethods {
			_, mn, _, _, derr := f.MethodFull(m.Idx)
			if derr != nil {
				return derr
			}
			if mn != "<clinit>" {
				continue
			}
			found = true
			if m.Acc&accStatic == 0 {
				t.Errorf("<clinit> 缺少 ACC_STATIC（Acc=0x%04x）", m.Acc)
			}
			if m.Acc&accConstructor == 0 {
				t.Errorf("<clinit> 缺少 ACC_CONSTRUCTOR（Acc=0x%04x）：ART 会打印 didn't have expected constructor access flag", m.Acc)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("遍历类失败: %v", err)
	}
	if !found {
		t.Fatal("没有找到注入的 <clinit> 方法")
	}
}
