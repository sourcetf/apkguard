package passes

import (
	"context"
	"sort"
	"strings"
	"testing"

	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/pipeline"
	"apkguard/internal/zipx"
)

// dexClasses 返回某条 DEX 条目里的全部类描述符。
func dexClasses(t *testing.T, e *zipx.Entry) []string {
	t.Helper()
	data, err := e.Data()
	if err != nil {
		t.Fatalf("读取 %s 失败: %v", e.NameString(), err)
	}
	f, err := dex.Parse(data)
	if err != nil {
		t.Fatalf("解析 %s 失败: %v", e.NameString(), err)
	}
	names, err := classNamesOf(f)
	if err != nil {
		t.Fatalf("遍历 %s 的类失败: %v", e.NameString(), err)
	}
	return names
}

// TestSplitDexConservesClasses 验证 B4 拆分**类数守恒**。
//
// 这是本功能唯一不能出错的地方：拆丢一个类，应用会在运行到它时
// NoClassDefFoundError；拆重一个类，多 DEX 加载时会报类重复定义。
// 因此断言必须落在「并集与原集合逐元素相等、且各分片两两不相交」上，
// 而不是「拆出了 N 份」这种表层指标。
func TestSplitDexConservesClasses(t *testing.T) {
	art := loadSample(t)

	// 记录每个原始 DEX 的类集合（样本是多 DEX，必须分别比对）。
	orig := map[string][]string{}
	for _, e := range pipeline.FindAll(art, isDexEntry) {
		orig[e.NameString()] = dexClasses(t, e)
	}
	if len(orig) == 0 {
		t.Skip("样本中没有 DEX")
	}
	total := 0
	for _, v := range orig {
		total += len(v)
	}
	if total < 10 {
		t.Skip("类数过少，拆分无意义")
	}

	opts := &config.Options{
		Enabled:    map[config.FeatureID]bool{"B1": true, "B4": true},
		SplitCount: 3,
	}
	if err := (&splitDex{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("B4 执行失败: %v", err)
	}

	// 原始条目必须已被移除。
	for name := range orig {
		if pipeline.Find(art, name) != nil {
			t.Fatalf("原始 DEX %s 拆分后仍然存在（未移除）", name)
		}
	}

	// 按名字前缀把分片归回各自的来源。
	seen := map[string]int{}
	for _, e := range pipeline.FindAll(art, isDexEntry) {
		n := e.NameString()
		if !strings.Contains(n, splitPartSuffix) {
			t.Fatalf("出现了非拆分产物 %s", n)
		}
		// 状态之一：份数、类数
		seen[n] = len(dexClasses(t, e))
	}
	if len(seen) == 0 {
		t.Fatal("没有产出任何分片")
	}

	// 逐份校验结构与类数守恒。
	byPrefix := map[string][]string{}
	for _, e := range pipeline.FindAll(art, isDexEntry) {
		n := e.NameString()
		data, err := e.Data()
		if err != nil {
			t.Fatalf("读取 %s 失败: %v", n, err)
		}
		if err := dex.Verify(data); err != nil {
			t.Fatalf("分片 %s 校验失败: %v", n, err)
		}
		base := n[:strings.Index(n, splitPartSuffix)]
		byPrefix[base] = append(byPrefix[base], n)
	}

	// 每个原始 DEX 的类必须恰好被切到它的分片里，且不重不漏。
	for name, want := range orig {
		base := strings.TrimSuffix(name, ".dex")
		parts := byPrefix[base]
		if len(parts) < 2 {
			// 类数不足时允许不拆（由 splitPartsFor 决定），但要完整保留。
			if len(parts) == 0 {
				t.Fatalf("%s 既未拆分也未保留", name)
			}
		}
		got := map[string]bool{}
		for _, p := range parts {
			for _, c := range dexClasses(t, pipeline.Find(art, p)) {
				if got[c] {
					t.Fatalf("%s 中的类 %s 在分片间重复出现（会导致多 DEX 类重复定义）", name, c)
				}
				got[c] = true
			}
		}
		if len(got) != len(want) {
			t.Fatalf("%s 类数不守恒：原始 %d，拆分后并集 %d", name, len(want), len(got))
		}
		for _, c := range want {
			if !got[c] {
				t.Fatalf("%s 的类 %s 在拆分后丢失（应用会 NoClassDefFoundError）", name, c)
			}
		}
	}
	t.Logf("B4：%d 个 DEX 的 %d 个类被切分为 %d 份，类集合不重不漏且每份均通过校验",
		len(orig), total, len(seen))
}

// TestSplitDexDeterministic 验证同一输入两次拆分结果完全一致。
//
// 加固产物必须可复现：同一份输入、同一个种子，产出的每个字节都应相同，
// 否则 diff/审计与「按哈希校验产物」都无从谈起。
func TestSplitDexDeterministic(t *testing.T) {
	run := func() map[string]string {
		art := loadSample(t)
		opts := &config.Options{
			Enabled:    map[config.FeatureID]bool{"B1": true, "B4": true},
			SplitCount: 2,
		}
		if err := (&splitDex{}).Run(context.Background(), art, opts); err != nil {
			t.Fatalf("B4 执行失败: %v", err)
		}
		out := map[string]string{}
		for _, e := range pipeline.FindAll(art, isDexEntry) {
			data, err := e.Data()
			if err != nil {
				t.Fatalf("读取失败: %v", err)
			}
			out[e.NameString()] = string(data)
		}
		return out
	}
	a, b := run(), run()
	if len(a) != len(b) {
		t.Fatalf("两次拆分的分片数不同: %d vs %d", len(a), len(b))
	}
	var keysA []string
	for k := range a {
		keysA = append(keysA, k)
	}
	sort.Strings(keysA)
	for _, k := range keysA {
		if a[k] != b[k] {
			t.Fatalf("分片 %s 两次产出不一致", k)
		}
	}
	t.Logf("B4：同一输入两次拆分产出 %d 份且逐字节一致", len(a))
}

// TestSplitPartsFor 验证份数决策的边界。
func TestSplitPartsFor(t *testing.T) {
	cases := []struct {
		classes, want, expect int
	}{
		{0, 0, 0},   // 没有类：不拆
		{1, 0, 0},   // 单个类：不拆
		{10, 0, 2},  // 类少但也要拆成 2 份（下限）
		{300, 0, 2}, // 300/300 = 1 → 抬到下限 2
		{601, 0, 3}, // 600/300 向上取整 = 3（体积与打散的折中）
		{100000, 0, 16},
		{10, 3, 3},  // 显式指定
		{2, 5, 2},   // 指定份数超过类数 → 按类数封顶
		{100, 1, 1}, // 显式 1 份：等于不拆
	}
	for _, c := range cases {
		if got := splitPartsFor(c.classes, c.want); got != c.expect {
			t.Errorf("splitPartsFor(classes=%d, want=%d) = %d，期望 %d",
				c.classes, c.want, got, c.expect)
		}
	}
}

// TestBucketOfStable 验证分区函数确定性且分布不退化。
func TestBucketOfStable(t *testing.T) {
	const parts = 4
	// 同名必须始终落进同一份（否则拆分不可复现）。
	for _, n := range []string{"La;", "Lcom/x/Y;", "Ljd/sv/a;"} {
		first := bucketOf(n, parts)
		for i := 0; i < 8; i++ {
			if bucketOf(n, parts) != first {
				t.Fatalf("%s 的分区不稳定", n)
			}
		}
	}
	// 同包前缀的类应被打散到不同份：这正是「单个分片不含完整业务链」的前提。
	packed := map[int]int{}
	for i := 0; i < 200; i++ {
		packed[bucketOf("Lcom/example/Biz"+string(rune('A'+i%26))+string(rune('a'+i/26))+";", parts)]++
	}
	if len(packed) < 2 {
		t.Fatalf("同包类全部落进同一份（分区退化）：%v", packed)
	}
}
