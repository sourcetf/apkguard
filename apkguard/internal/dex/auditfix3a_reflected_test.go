package dex

import (
	"testing"
)

// 本文件收口 A1 重命名引擎的另一条遗留缺口：跨 DEX 反射保护只认「点分名」，
// 漏掉「斜杠名」。
//
// ReflectedNames 由调用方从各 DEX 的 const-string 汇总而来，而同一个类的
// 字符串常量有两种常见写法："com.foo.Bar"（Class.forName / 配置）与
// "com/foo/Bar"（资源名、JNI 注册、部分序列化格式）。若 keep 判定只查点分名，
// 斜杠写法就得不到保护、类会被改名，运行期按名反射即
// ClassNotFoundException。

// audit3aConstBody 构造一个 public static void 方法体：
// const-string v0, text; return-void。
func audit3aConstBody(t *testing.T, text string) *CodeBlob {
	t.Helper()
	a := NewAsm()
	a.ConstString(0, text)
	a.ReturnVoid()
	insns, patches, err := a.Assemble()
	if err != nil {
		t.Fatalf("汇编 const-string 方法失败: %v", err)
	}
	return &CodeBlob{Registers: 1, Ins: 0, Outs: 0, Insns: insns, Patches: patches}
}

// audit3aConstDex 构造一个「仅在字符串常量里出现某名字」的 DEX（模拟另一个 DEX）。
func audit3aConstDex(t *testing.T, text string) []byte {
	t.Helper()
	d, err := Build(Addition{Classes: []ClassSpec{{
		Name:   "Lapp3a/Consts;",
		Super:  "Ljava/lang/Object;",
		Access: accPublic,
		Methods: []ClassMethod{{
			Name: "n", Proto: ProtoSpec{Ret: "V"},
			Access: accPublic | accStatic, Code: audit3aConstBody(t, text),
		}},
	}}})
	if err != nil {
		t.Fatalf("构造常量 DEX 失败: %v", err)
	}
	return d
}

// audit3aConstNamesFromDex 汇总 DEX 中全部 const-string 字符串，
// 模拟 passes 层 constClassNames 的输入来源。
func audit3aConstNamesFromDex(t *testing.T, data []byte) map[string]bool {
	t.Helper()
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析常量 DEX 失败: %v", err)
	}
	u, err := f.StringUsage()
	if err != nil {
		t.Fatalf("扫描字符串用途失败: %v", err)
	}
	out := map[string]bool{}
	for idx := range u.Const {
		s, err := f.String(idx)
		if err != nil {
			t.Fatalf("读取字符串 %d 失败: %v", idx, err)
		}
		out[s] = true
	}
	return out
}

// audit3aTargetDex 构造定义目标类的 DEX：Lcom/foo/Bar; 是待保护目标，
// Lcom/foo/Quux; 是对照组（必须仍可改名）。
func audit3aTargetDex(t *testing.T) []byte {
	t.Helper()
	d, err := Build(Addition{Classes: []ClassSpec{
		{Name: "Lcom/foo/Bar;", Super: "Ljava/lang/Object;", Access: accPublic},
		{Name: "Lcom/foo/Quux;", Super: "Ljava/lang/Object;", Access: accPublic},
	}})
	if err != nil {
		t.Fatalf("构造目标 DEX 失败: %v", err)
	}
	return d
}

// audit3aRenameWithReflected 在目标 DEX 上按给定的 ReflectedNames 生成计划。
func audit3aRenameWithReflected(t *testing.T, data []byte, reflected map[string]bool) (map[string]string, Stats) {
	t.Helper()
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析目标 DEX 失败: %v", err)
	}
	rn, err := NewRenamer(f, RenameConfig{ReflectedNames: reflected})
	if err != nil {
		t.Fatalf("构造重命名器失败: %v", err)
	}
	plan, err := rn.Plan()
	if err != nil {
		t.Fatalf("生成重命名计划失败: %v", err)
	}
	return plan, rn.LastStats()
}

const audit3aReflectedReason = "类名在其它 DEX 的字符串常量中出现（可能被反射）"

// TestAuditFix3AReflectedSlashNameKeepsClass 回归：另一个 DEX 的字符串常量里
// 以斜杠形式（"com/foo/Bar"）出现的类名，其定义类必须被保留。
func TestAuditFix3AReflectedSlashNameKeepsClass(t *testing.T) {
	// A 里以斜杠形式出现 "com/foo/Bar"；B 里定义 Lcom/foo/Bar;。
	reflected := audit3aConstNamesFromDex(t, audit3aConstDex(t, "com/foo/Bar"))
	if !reflected["com/foo/Bar"] {
		t.Fatalf("测试前提不成立：A 的字符串常量未含 com/foo/Bar（%v）", reflected)
	}

	plan, stats := audit3aRenameWithReflected(t, audit3aTargetDex(t), reflected)
	if nw, ok := plan["Lcom/foo/Bar;"]; ok {
		t.Errorf("类名以斜杠形式（com/foo/Bar）出现在其它 DEX 的字符串常量中，"+
			"该类仍被改名（-> %q）：运行期按名反射会 ClassNotFoundException", nw)
	}
	if _, ok := plan["Lcom/foo/Quux;"]; !ok {
		t.Errorf("对照类 Lcom/foo/Quux; 未被改名，测试前提不成立")
	}
	if got := stats.KeepReasons[audit3aReflectedReason]; got < 1 {
		t.Errorf("斜杠形式的跨 DEX 反射保护未产生 keep 原因: %v", stats.KeepReasons)
	}
}

// TestAuditFix3AReflectedDottedNameStillKeepsClass 回归：点分名的既有保护
// 不得退化。
func TestAuditFix3AReflectedDottedNameStillKeepsClass(t *testing.T) {
	reflected := audit3aConstNamesFromDex(t, audit3aConstDex(t, "com.foo.Bar"))
	if !reflected["com.foo.Bar"] {
		t.Fatalf("测试前提不成立：A 的字符串常量未含 com.foo.Bar（%v）", reflected)
	}

	plan, stats := audit3aRenameWithReflected(t, audit3aTargetDex(t), reflected)
	if nw, ok := plan["Lcom/foo/Bar;"]; ok {
		t.Errorf("点分反射名（com.foo.Bar）保护失效：类被改名（-> %q）", nw)
	}
	if got := stats.KeepReasons[audit3aReflectedReason]; got < 1 {
		t.Errorf("点分形式的跨 DEX 反射保护未产生 keep 原因: %v", stats.KeepReasons)
	}
}

// TestAuditFix3AReflectedUnrelatedNameDoesNotKeepClass 反例：字符串常量里
// 出现的是不相干的类名时，目标类必须仍可改名（保护不能扩大化）。
func TestAuditFix3AReflectedUnrelatedNameDoesNotKeepClass(t *testing.T) {
	reflected := audit3aConstNamesFromDex(t, audit3aConstDex(t, "com/other/Nope"))
	if !reflected["com/other/Nope"] {
		t.Fatalf("测试前提不成立：A 的字符串常量未含 com/other/Nope（%v）", reflected)
	}

	plan, stats := audit3aRenameWithReflected(t, audit3aTargetDex(t), reflected)
	if _, ok := plan["Lcom/foo/Bar;"]; !ok {
		t.Errorf("不相干的反射名（com/other/Nope）不应保护 Lcom/foo/Bar;："+
			"该类未被改名，保护范围被错误扩大（keep 原因 %v）", stats.KeepReasons)
	}
	if _, ok := plan["Lcom/foo/Quux;"]; !ok {
		t.Errorf("对照类 Lcom/foo/Quux; 未被改名，测试前提不成立")
	}
}
