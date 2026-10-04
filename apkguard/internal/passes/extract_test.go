package passes

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/pack"
	"apkguard/internal/pipeline"
)

// ---- B5 函数抽取：Pass 级守卫 ----

// extractOpts 返回启用 B5 全链路（B1+B2+B3+B5）的配置。
func extractOpts(seed string, methods int) *config.Options {
	return &config.Options{
		Enabled: map[config.FeatureID]bool{
			"B1": true, "B2": true, "B3": true, "B5": true,
		},
		Seed:           seed,
		ExtractMethods: methods,
	}
}

// snapshotAll 记录产物条目名 → 字节（含非 DEX 条目）。
func snapshotAll(t *testing.T, art *pipeline.Artifact) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for _, e := range art.Entries() {
		d, err := e.Data()
		if err != nil {
			t.Fatalf("读取条目 %s 失败: %v", e.NameString(), err)
		}
		out[e.NameString()] = append([]byte(nil), d...)
	}
	return out
}

// TestExtractSafeCoverageRules 逐条锁定「哪些方法一定不被抽取」。
//
// 这些判据是 B5 的安全边界：任何一条失效都可能让 stub 化后的方法在
// ART 上语义错误（锁被绕过、构造器半初始化、异常表失效、反射找不到方法）。
func TestExtractSafeCoverageRules(t *testing.T) {
	base := dex.ExtractInfo{
		Class:      "Lx/A;",
		Name:       "m",
		Proto:      "(I)I",
		Ret:        "I",
		Access:     0,
		Registers:  2,
		InsnsWords: 16,
	}
	cases := []struct {
		name   string
		mut    func(*dex.ExtractInfo)
		reason string
	}{
		{"构造器", func(i *dex.ExtractInfo) { i.Name = "<init>" }, "ctor"},
		{"静态初始化器", func(i *dex.ExtractInfo) { i.Name = "<clinit>" }, "ctor"},
		{"ACC_CONSTRUCTOR", func(i *dex.ExtractInfo) { i.Access |= extractAccConstructor }, "ctor"},
		{"native", func(i *dex.ExtractInfo) { i.Access |= extractAccNative }, "native"},
		{"abstract", func(i *dex.ExtractInfo) { i.Access |= extractAccAbstract }, "abstract"},
		{"synchronized", func(i *dex.ExtractInfo) { i.Access |= extractAccSynchronized }, "sync"},
		{"declared-synchronized", func(i *dex.ExtractInfo) { i.Access |= extractAccDeclSync }, "sync"},
		{"含 try/catch", func(i *dex.ExtractInfo) { i.TriesSize = 1 }, "try"},
		{"共用 code_off", func(i *dex.ExtractInfo) { i.Shared = true }, "shared"},
		{"方法体过短", func(i *dex.ExtractInfo) { i.InsnsWords = 7 }, "small"},
		{"返回类型非法", func(i *dex.ExtractInfo) { i.Ret = "X" }, "ret"},
		{"void 但寄存器为 0", func(i *dex.ExtractInfo) { i.Ret = "V"; i.Registers = 0 }, ""},
		{"非 void 且寄存器为 0", func(i *dex.ExtractInfo) { i.Registers = 0 }, "regs"},
		{"wide 返回但只有 1 个寄存器", func(i *dex.ExtractInfo) { i.Ret = "J"; i.Registers = 1 }, "regs"},
		{"bridge 方法", func(i *dex.ExtractInfo) { i.Access |= extractAccBridge }, "bridge"},
	}
	for _, c := range cases {
		info := base
		c.mut(&info)
		ok, reason := extractSafe(info, nil)
		if c.reason == "" {
			if !ok {
				t.Fatalf("%s 应被判为可抽取，实际跳过原因 %q", c.name, reason)
			}
			continue
		}
		if ok {
			t.Fatalf("%s 应被跳过（%s），实际被判为可抽取", c.name, c.reason)
		}
		if reason != c.reason {
			t.Fatalf("%s 的跳过原因应为 %q，实际 %q", c.name, c.reason, reason)
		}
	}

	// 反射按名引用的方法：A7 登记的成员名内的任何方法都跳过。
	info := base
	if ok, reason := extractSafe(info, map[string]bool{"m": true}); ok || reason != "reflect" {
		t.Fatalf("被反射按名引用的方法应跳过（reflect），实际 ok=%v reason=%q", ok, reason)
	}
}

// TestExtractCodeDisabledIsByteIdentical 验证 ExtractMethods=0（B5 未开启）时
// 产物逐字节零改动、且不写任何 B5 统计/共享状态。
func TestExtractCodeDisabledIsByteIdentical(t *testing.T) {
	art := loadSample(t)
	before := snapshotAll(t, art)

	opts := extractOpts("b5-off", 0)
	if err := (&extractCode{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("B5 关闭时执行失败: %v", err)
	}
	after := snapshotAll(t, art)
	if len(after) != len(before) {
		t.Fatalf("B5 关闭时条目数变化: %d -> %d", len(before), len(after))
	}
	for n, b := range before {
		a, ok := after[n]
		if !ok {
			t.Fatalf("B5 关闭时条目 %s 消失", n)
		}
		if !bytes.Equal(a, b) {
			t.Fatalf("B5 关闭时条目 %s 字节被改动", n)
		}
	}
	if art.Get(sharedKeyExtract) != nil {
		t.Fatal("B5 关闭时不应写共享抽取摘要")
	}
	if _, ok := art.Stats["B5.extracted"]; ok {
		t.Fatal("B5 关闭时不应产生 B5.extracted 统计")
	}
}

// TestExtractCodeRequiresShellChain 验证缺 B2/B3 时在 Run 与 config 两层都报错，
// 而不是产出一个「方法体全是 stub、永远返回默认值」的包。
func TestExtractCodeRequiresShellChain(t *testing.T) {
	ctx := context.Background()
	art := loadSample(t)

	opts := &config.Options{
		Enabled:        map[config.FeatureID]bool{"B1": true, "B5": true},
		Seed:           "b5-missing-shell",
		ExtractMethods: 10,
	}
	err := (&extractCode{}).Run(ctx, art, opts)
	if err == nil {
		t.Fatal("缺 B2/B3 时 B5 必须报错，而不是静默产出 stub 包")
	}
	if !strings.Contains(err.Error(), "B2") || !strings.Contains(err.Error(), "B3") {
		t.Fatalf("错误信息应点明缺 B2/B3，实际: %v", err)
	}
	// 配置层同样要拦下（deps 表）。
	verr := opts.Validate()
	if verr == nil {
		t.Fatal("config.Validate 应拦下 B5 缺 B2/B3 的组合")
	}
	if !strings.Contains(verr.Error(), "B5") {
		t.Fatalf("config.Validate 的错误信息应包含 B5，实际: %v", verr)
	}
	// B2/B3 都在、只缺 B1 时，Run 也必须报错（抽取计划没有运输容器）。
	opts2 := &config.Options{
		Enabled:        map[config.FeatureID]bool{"B2": true, "B3": true, "B5": true},
		Seed:           "b5-missing-b1",
		ExtractMethods: 10,
	}
	if err := (&extractCode{}).Run(ctx, art, opts2); err == nil || !strings.Contains(err.Error(), "B1") {
		t.Fatalf("缺 B1 时应报错并点明 B1，实际: %v", err)
	}
}

// TestExtractCodeDeterministicSameSeed 验证同 seed 两次运行产物逐字节一致。
func TestExtractCodeDeterministicSameSeed(t *testing.T) {
	ctx := context.Background()
	a1 := loadSample(t)
	a2 := loadSample(t)
	opts1 := extractOpts("b5-determinism", 20)
	opts2 := extractOpts("b5-determinism", 20)
	if err := (&extractCode{}).Run(ctx, a1, opts1); err != nil {
		t.Fatalf("第一次抽取失败: %v", err)
	}
	if err := (&extractCode{}).Run(ctx, a2, opts2); err != nil {
		t.Fatalf("第二次抽取失败: %v", err)
	}
	s1, _ := a1.Get(sharedKeyExtract).(*extractSummary)
	s2, _ := a2.Get(sharedKeyExtract).(*extractSummary)
	if s1 == nil || s2 == nil || s1.Selected == 0 {
		t.Fatalf("两次运行都应抽到方法（got %v / %v）", s1, s2)
	}
	if s1.Selected != s2.Selected || len(s1.Methods) != len(s2.Methods) {
		t.Fatalf("同 seed 抽取数量不一致: %d vs %d", s1.Selected, s2.Selected)
	}
	for i := range s1.Methods {
		if s1.Methods[i] != s2.Methods[i] {
			t.Fatalf("同 seed 抽取集合顺序不一致: %q vs %q", s1.Methods[i], s2.Methods[i])
		}
	}
	// 逐条目字节比对（含非 DEX 条目；B5 只应改 DEX）。
	before1 := snapshotAll(t, a1)
	before2 := snapshotAll(t, a2)
	if len(before1) != len(before2) {
		t.Fatalf("两次运行的条目数不同: %d vs %d", len(before1), len(before2))
	}
	for n, b := range before1 {
		if !bytes.Equal(b, before2[n]) {
			t.Fatalf("同 seed 两次运行的条目 %s 字节不同", n)
		}
	}
}

// TestExtractCodeChainRestoresOriginal 是 B5 的端到端链路守卫，走完整顺序：
//
//	抽取（stub + 计划 trailer）→ B1 加密 → B1/B2/B3 加壳
//	→ 解密载荷 → ApplyExtractPlan 回填 → 与原 DEX 逐字节比对。
//
// 通过即证明：产物里被抽方法只剩 stub（静态看不到真实方法体），而壳在运行时
// 能把它恢复成与抽取前完全一致的 DEX（ART 看到的字节与未加固时相同）。
func TestExtractCodeChainRestoresOriginal(t *testing.T) {
	ctx := context.Background()
	art := loadSample(t)

	// 记录抽取前的全部可解析 DEX。
	orig := map[string][]byte{}
	for _, e := range art.Entries() {
		if !isDexEntry(e) {
			continue
		}
		d, err := e.Data()
		if err != nil {
			continue
		}
		if _, err := dex.Parse(d); err != nil {
			continue // A9/A16 的伪 DEX
		}
		orig[e.NameString()] = append([]byte(nil), d...)
	}
	if len(orig) == 0 {
		t.Skip("样本中没有可解析的 DEX")
	}

	opts := extractOpts("b5-chain", 50)
	if err := (&extractCode{}).Run(ctx, art, opts); err != nil {
		t.Fatalf("B5 抽取失败: %v", err)
	}
	sum, _ := art.Get(sharedKeyExtract).(*extractSummary)
	if sum == nil || sum.Selected == 0 {
		t.Fatalf("B5 未抽到任何方法（summary=%+v）", sum)
	}
	if sum.Selected > opts.ExtractMethods {
		t.Fatalf("抽取数 %d 超过上限 %d", sum.Selected, opts.ExtractMethods)
	}
	for _, m := range sum.Methods {
		if strings.Contains(m, "-><init>") || strings.Contains(m, "-><clinit>") {
			t.Fatalf("构造器/静态初始化器不得被抽取: %s", m)
		}
	}

	// 继续加壳（B1 加密会原样加密含 trailer 的 DEX 字节流）。
	runShellChain(t, art, opts)
	sp := payloadsOf(art)
	if sp == nil || len(sp.Items) != len(orig) {
		t.Fatalf("载荷清单异常: %v（原始 DEX %d 个）", sp, len(orig))
	}

	restoredEntries := 0
	withTrailer := 0
	for _, p := range sp.Items {
		dec, err := pack.DecryptNamed(p.Blob, sp.Key, p.Name)
		if err != nil {
			t.Fatalf("载荷 %s 解密失败: %v", p.Asset, err)
		}
		restored, n, err := dex.ApplyExtractPlan(dec)
		if err != nil {
			t.Fatalf("载荷 %s 回填失败: %v", p.Asset, err)
		}
		restoredEntries += n
		if n > 0 {
			withTrailer++
			// 回填前的明文仍然是一份结构合法的 DEX（stub 版本），
			// 且长度含 trailer；这是「静态只能看到 stub」的字节证据。
			if fs := dexFileSize(dec); fs <= 0 || fs >= len(dec) {
				t.Fatalf("载荷 %s 的 stub DEX 缺少 trailer（fs=%d len=%d）", p.Asset, fs, len(dec))
			}
		}
		want, ok := orig[p.Name]
		if !ok {
			t.Fatalf("载荷 %s 的原始名 %s 不在记录中", p.Asset, p.Name)
		}
		if !bytes.Equal(restored, want) {
			t.Fatalf("载荷 %s 回填后与原 DEX 不一致（%d vs %d 字节）", p.Asset, len(restored), len(want))
		}
	}
	if restoredEntries != sum.Selected {
		t.Fatalf("回填命中数 %d 与抽取数 %d 不一致（回填会漏掉方法体）", restoredEntries, sum.Selected)
	}
	if withTrailer == 0 {
		t.Fatal("没有任何载荷带抽取计划 trailer")
	}
	t.Logf("B5 链路：候选 %d、安全候选 %d、抽取 %d、改写 DEX %d 份、原始方法体 %d 字节、计划 %d 字节",
		sum.Candidates, sum.Safe, sum.Selected, sum.DexCount, sum.Bytes, sum.Trailer)
}

// dexFileSize 读取 DEX 头部声明的 file_size（不做完整解析，允许尾部带 trailer）。
func dexFileSize(data []byte) int {
	if len(data) < 36 {
		return -1
	}
	return int(uint32(data[32]) | uint32(data[33])<<8 | uint32(data[34])<<16 | uint32(data[35])<<24)
}
