package passes

import (
	"context"
	"testing"

	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/zipx"
)

// TestRenameRewritesCrossDexMemberRefs 钉住「跨 DEX 的成员引用也必须一致改名」。
//
// 真实缺陷（实测于 Termux，30 个 DEX）：
// 成员改名按「名称字符串」生效，若各 DEX 各自决策、各自生成新名，静态常量会
// 出现「A DEX 定义方改名、B DEX 引用方仍旧名」，运行时抛
//
//	NoSuchFieldError: No field TERMUX_HOME_DIR of type Ljava/io/File;
//	 in class Lcom/termux/shared/termux/dt;
//
// 这里用两个 DEX 复现：A 定义 Lapp/Shared;->VALUE，B 只引用它（sget-object）。
func TestRenameRewritesCrossDexMemberRefs(t *testing.T) {
	const sharedDesc = "Lapp/Shared;"
	const fieldName = "VALUE"
	fieldType := "Ljava/lang/String;"

	def, err := dex.Build(dex.Addition{Classes: []dex.ClassSpec{{
		Name: sharedDesc, Super: "Ljava/lang/Object;", Access: 0x0001,
		Fields: []dex.ClassField{{Name: fieldName, Type: fieldType, Access: 0x0001 | 0x0008}},
	}}})
	if err != nil {
		t.Fatalf("构造定义侧 DEX 失败: %v", err)
	}

	// 引用侧：方法体里 sget-object 到 Lapp/Shared;->VALUE
	a := dex.NewAsm()
	a.SGetObject(0, dex.FieldSpec{Class: sharedDesc, Name: fieldName, Type: fieldType})
	a.ReturnVoid()
	insns, patches, err := a.Assemble()
	if err != nil {
		t.Fatalf("汇编失败: %v", err)
	}
	ref, err := dex.Build(dex.Addition{Classes: []dex.ClassSpec{{
		Name: "Lapp/User;", Super: "Ljava/lang/Object;", Access: 0x0001,
		Methods: []dex.ClassMethod{{
			Name: "m", Proto: dex.ProtoSpec{Ret: "V"}, Access: 0x0001,
			Code: &dex.CodeBlob{Registers: 1, Ins: 1, Outs: 0, Insns: insns, Patches: patches},
		}},
	}}})
	if err != nil {
		t.Fatalf("构造引用侧 DEX 失败: %v", err)
	}

	art := newArtifact(
		zipx.NewStored("classes.dex", def),
		zipx.NewStored("classes2.dex", ref),
	)
	if err := (&renameClass{}).Run(context.Background(), art, &config.Options{Seed: "xd"}); err != nil {
		t.Fatalf("A1 执行失败: %v", err)
	}

	defOut := parseEntry(t, art, "classes.dex")
	refOut := parseEntry(t, art, "classes2.dex")

	// 定义侧：改名后该类的描述符与字段名
	defInfos, err := defOut.ClassInfos()
	if err != nil {
		t.Fatalf("读取定义侧类信息失败: %v", err)
	}
	var newDesc string
	fields := map[string]bool{}
	for _, ci := range defInfos {
		newDesc = ci.Desc
		for _, fl := range ci.Fields() {
			fields[fl.Name] = true
		}
	}
	if newDesc == "" || len(fields) == 0 {
		t.Fatalf("定义侧信息不完整：desc=%q fields=%v", newDesc, fields)
	}

	// 引用侧：指向该类的字段引用必须仍然可解析
	n := 0
	for i := uint32(0); i < refOut.NField; i++ {
		classIdx, _, nameIdx, err := refOut.FieldRefAt(i)
		if err != nil {
			t.Fatalf("读取字段引用失败: %v", err)
		}
		cd, err := refOut.Type(uint32(classIdx))
		if err != nil || cd != newDesc {
			continue
		}
		n++
		name, err := refOut.String(nameIdx)
		if err != nil {
			t.Fatalf("读取字段名失败: %v", err)
		}
		if !fields[name] {
			t.Fatalf("跨 DEX 字段引用无法解析：%s->%s（定义侧字段为 %v）——"+
				"运行时 NoSuchFieldError", cd, name, keysOf(fields))
		}
	}
	if n == 0 {
		t.Fatal("引用侧的字段引用丢失或类名不一致（说明跨 DEX 改名断链）")
	}
	t.Logf("跨 DEX 成员改名一致：%s 的字段在引用侧为 %v", newDesc, keysOf(fields))
}

func keysOf(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
