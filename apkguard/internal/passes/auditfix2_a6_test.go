package passes

import (
	"bytes"
	"context"
	"strconv"
	"strings"
	"testing"

	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/pipeline"
	"apkguard/internal/zipx"
)

// notesContain 判断产物 Notes 中是否有包含 sub 的条目。
func notesContain(art *pipeline.Artifact, sub string) bool {
	for _, n := range art.Notes {
		if strings.Contains(n, sub) {
			return true
		}
	}
	return false
}

// TestA6ControlFlowRunTraces 是 A6（controlFlow Pass 包装）的 Pass 级回归。
//
// 审计指出 A6 没有任何测试直接调用 Run：若注册/接线写错（例如 Pass 空转、
// 统计键缺失），现有测试全绿也发现不了。这里用最小产物直接调 Run，断言：
//   - 统计键齐全且 A6.dex 为 1；
//   - A6.methods > 0（真的改写了方法，而不是静默空转）；
//   - Note 记录了 A6；
//   - 写回的 DEX 与输入不同、仍可通过 dex.Verify。
func TestA6ControlFlowRunTraces(t *testing.T) {
	// 带真实方法体的类：<init> 会被跳过，check(I)I 至少能走「不可达跳转块」兜底。
	before, err := decoyDex("com/x", []decoyClassReq{{"A", ""}})
	if err != nil {
		t.Fatalf("构造 DEX 失败: %v", err)
	}
	art := newArtifact(zipx.NewStored("classes.dex", before))

	if err := (&controlFlow{}).Run(context.Background(), art, &config.Options{Seed: "auditfix2-a6"}); err != nil {
		t.Fatalf("A6 Run 失败: %v", err)
	}

	for _, k := range []string{"A6.dex", "A6.methods", "A6.preds", "A6.subs", "A6.fake", "A6.skipped", "A6.grow"} {
		if _, ok := art.Stats[k]; !ok {
			t.Errorf("A6 缺少统计键 %s: %v", k, art.Stats)
		}
	}
	if got := art.Stats["A6.dex"]; got != "1" {
		t.Errorf("A6.dex = %q，应为 1", got)
	}
	methods, _ := strconv.Atoi(art.Stats["A6.methods"])
	if methods <= 0 {
		t.Fatalf("A6.methods = %q：控制流混淆一个方法都没改写（Pass 空转）", art.Stats["A6.methods"])
	}
	grow, _ := strconv.Atoi(art.Stats["A6.grow"])
	if grow <= 0 {
		t.Errorf("A6.grow = %q，改写后应至少变大（插入了谓词/跳转）", art.Stats["A6.grow"])
	}
	if !notesContain(art, "A6 控制流混淆") {
		t.Errorf("A6 未在 Notes 中留下说明: %v", art.Notes)
	}

	e := pipeline.Find(art, "classes.dex")
	if e == nil {
		t.Fatal("classes.dex 条目丢失")
	}
	after, err := e.Data()
	if err != nil {
		t.Fatalf("读取写回的 DEX 失败: %v", err)
	}
	if bytes.Equal(after, before) {
		t.Fatal("A6 产物与输入逐字节相同：控制流混淆没有生效")
	}
	if err := dex.Verify(after); err != nil {
		t.Fatalf("A6 写回的 DEX 校验失败: %v", err)
	}
	if _, err := dex.Parse(after); err != nil {
		t.Fatalf("A6 写回的 DEX 无法解析: %v", err)
	}
}
