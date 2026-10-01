package passes

import (
	"context"
	"testing"

	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/pipeline"
	"apkguard/internal/zipx"
)

// TestRenameRewritesCrossDexReferences 钉住「跨 DEX 的引用也要跟着改名」。
//
// 真实缺陷（实测于 Termux，它原生就有 30 个 DEX）：
// A1 的改名计划只由「**本 DEX 定义**的类」构成，于是「A 定义、B 引用」的类在
// B 里仍写着旧名，运行时抛
//
//	NoClassDefFoundError: Failed resolution of: Lcom/termux/shared/termux/TermuxConstants;
//
// RustDesk 之所以一直没暴露这个问题：它是单 DEX，多份是 B4 在**改名之后**才拆的。
//
// 这里用两个 DEX 复现：A 定义 Lapp/Shared;，B 只**引用**它（字段类型）。
func TestRenameRewritesCrossDexReferences(t *testing.T) {
	shared := "Lapp/Shared;"
	const oldShared = "Lapp/Shared;"

	def, err := dex.Build(dex.Addition{Classes: []dex.ClassSpec{{
		Name: oldShared, Super: "Ljava/lang/Object;", Access: 0x0001,
	}}})
	if err != nil {
		t.Fatalf("构造定义侧 DEX 失败: %v", err)
	}
	// 引用侧：一个字段的类型是 Lapp/Shared;，但本 DEX 不定义它。
	ref, err := dex.Build(dex.Addition{Classes: []dex.ClassSpec{{
		Name: "Lapp/User;", Super: "Ljava/lang/Object;", Access: 0x0001,
		Fields: []dex.ClassField{{Name: "shared", Type: shared, Access: 0x0001}},
	}}})
	if err != nil {
		t.Fatalf("构造引用侧 DEX 失败: %v", err)
	}
	// 前置条件：引用侧确实有该类型、且不定义它
	rf, err := dex.Parse(ref)
	if err != nil {
		t.Fatalf("解析引用侧失败: %v", err)
	}
	if !typeTableHas(t, rf, oldShared) {
		t.Fatal("构造失败：引用侧类型表里没有 " + oldShared)
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

	// 定义侧：原类名应已被改掉
	if typeTableHas(t, defOut, oldShared) {
		t.Fatal("定义侧的类没有被改名，测试失去意义")
	}
	// 引用侧：不得再出现旧名，且必须出现同一个新名
	if typeTableHas(t, refOut, oldShared) {
		t.Fatal("引用侧仍保留旧类名——运行时 NoClassDefFoundError")
	}
	// 定义侧实际定义的类（改名后）里，必须有一个被引用侧引用到。
	// 不能靠「找任意 L...; 」来猜新名——那样 Ljava/lang/Object; 也会被当成新名，
	// 断言就变成了恒真。
	defs, err := defOut.ClassInfos()
	if err != nil {
		t.Fatalf("读取定义侧类信息失败: %v", err)
	}
	var matched string
	for _, ci := range defs {
		if typeTableHas(t, refOut, ci.Desc) {
			matched = ci.Desc
			break
		}
	}
	if matched == "" {
		var names []string
		for _, ci := range defs {
			names = append(names, ci.Desc)
		}
		t.Fatalf("引用侧没有引用定义侧改名后的任何类 %v（旧名 %s 已被清除，说明改名没有跨 DEX 生效）", names, oldShared)
	}
	t.Logf("跨 DEX 改名生效：%s 改名后为 %s，引用侧已同步", oldShared, matched)
}

func parseEntry(t *testing.T, art *pipeline.Artifact, name string) *dex.File {
	t.Helper()
	e := pipeline.Find(art, name)
	if e == nil {
		t.Fatalf("产物缺少 %s", name)
	}
	data, err := e.Data()
	if err != nil {
		t.Fatalf("读取 %s 失败: %v", name, err)
	}
	f, err := dex.Parse(data)
	if err != nil {
		t.Fatalf("解析 %s 失败: %v", name, err)
	}
	return f
}

func typeTableHas(t *testing.T, f *dex.File, desc string) bool {
	t.Helper()
	for i := uint32(0); i < f.NType; i++ {
		s, err := f.Type(i)
		if err != nil {
			t.Fatalf("读类型失败: %v", err)
		}
		if s == desc {
			return true
		}
	}
	return false
}
