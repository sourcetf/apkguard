package passes

import (
	"context"
	"fmt"
	"hash/fnv"
	"sort"
	"strings"

	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/pipeline"
	"apkguard/internal/zipx"
)

// ---- B4 多 DEX 拆分 ----

// splitDex 把每个业务 DEX 拆成多份，每份只含原类集合的一个子集。
//
// 目的（按设计文档）：让单点 dump 拿不到完整代码，抬高分析者的拼接成本。
// 拆出来的每一份都会各自成为 B1 的一份加密载荷，因此即使有人 dump 出
// 运行时的其中一份，看到的也只是被切散的一部分类。
//
// 关于「按功能维度拆分」的说明：字节码里并没有可靠的「功能维度」标注，
// 硬去推断（按包名/调用关系聚类）既不可靠又会让产物不可复现。这里改为
// **按类名哈希分区**：确定性、可复现，且能把同包的类打散到不同份里——
// 后者恰恰更贴合「单个 DEX 无完整攻击链」的目标。
//
// 代价与前提：
//   - 拆散后类之间的依赖靠同一个 ClassLoader 的整条 dex 路径解析，
//     因此必须与 B1/B3 同用（Validate 已强制 B4 依赖 B1）；
//   - 类的静态初始化顺序会与原始 DEX 不同。这与 MultiDex 天然的
//     多 DEX 加载顺序差异属于同一类问题，正常应用不受影响。
type splitDex struct{}

func (splitDex) ID() config.FeatureID { return "B4" }
func (splitDex) In() pipeline.Level   { return pipeline.LevelZip }
func (splitDex) Out() pipeline.Level  { return pipeline.LevelZip }

// splitPartSuffix 是拆分后条目名的中缀，形如 classes-part1.dex。
const splitPartSuffix = "-part"

func (s *splitDex) Run(_ context.Context, art *pipeline.Artifact, opts *config.Options) error {
	entries := pipeline.FindAll(art, isDexEntry)
	if len(entries) == 0 {
		return fmt.Errorf("未找到任何 DEX 条目")
	}
	// 排序后处理，保证同一输入产出完全一致。
	sort.Slice(entries, func(i, j int) bool {
		return dexNameOrder(entries[i].NameString()) < dexNameOrder(entries[j].NameString())
	})

	used := map[string]bool{}
	for _, e := range art.Entries() {
		used[e.NameString()] = true
	}

	totalIn, totalOut, splitCount := 0, 0, 0
	var notes []string
	for _, en := range entries {
		data, err := en.Data()
		if err != nil {
			return fmt.Errorf("读取 %s 失败: %w", en.NameString(), err)
		}
		f, err := dex.Parse(data)
		if err != nil {
			continue // 伪装块（A9）不参与拆分
		}
		names, err := classNamesOf(f)
		if err != nil {
			return fmt.Errorf("遍历 %s 的类失败: %w", en.NameString(), err)
		}
		parts := splitPartsFor(len(names), opts.SplitCount)
		if parts < 2 {
			continue // 类太少，拆了没有意义
		}
		totalIn += len(names)

		// 分区：按类名哈希取模，确定性且能把同包类打散。
		buckets := make([][]string, parts)
		keep := make([]map[string]bool, parts)
		for i := range keep {
			keep[i] = map[string]bool{}
		}
		for _, n := range names {
			b := bucketOf(n, parts)
			buckets[b] = append(buckets[b], n)
			keep[b][n] = true
		}

		base := strings.TrimSuffix(en.NameString(), ".dex")
		for i := 0; i < parts; i++ {
			if len(buckets[i]) == 0 {
				continue // 空份不产出；空 DEX 没有意义
			}
			out, err := dex.Rebuild(f, dex.RebuildOptions{ClassFilter: filterOf(keep[i])})
			if err != nil {
				return fmt.Errorf("拆分 %s 第 %d 份失败: %w", en.NameString(), i+1, err)
			}
			if err := dex.Verify(out); err != nil {
				return fmt.Errorf("拆分 %s 第 %d 份校验失败: %w", en.NameString(), i+1, err)
			}
			name := uniqueName(used, fmt.Sprintf("%s%s%d.dex", base, splitPartSuffix, i+1))
			used[name] = true
			pipeline.Add(art, zipx.NewStored(name, out))
			totalOut += len(buckets[i])
			splitCount++
		}
		// 原条目在所有分片写好后移除：先加后删，中途失败不会丢内容。
		pipeline.Remove(art, func(e *zipx.Entry) bool { return e.NameString() == en.NameString() })
		notes = append(notes, fmt.Sprintf("%s→%d 份", en.NameString(), parts))
	}

	if splitCount == 0 {
		art.Note("B4 多 DEX 拆分：类数量不足，未做拆分")
		return nil
	}
	art.Note("B4 多 DEX 拆分：%s，共 %d 个类 → %d 份 DEX（按类名哈希分区，类数守恒 %d）",
		strings.Join(notes, "、"), totalIn, splitCount, totalOut)
	art.Stat("B4.parts", fmt.Sprint(splitCount))
	art.Stat("B4.classes", fmt.Sprint(totalOut))
	return nil
}

// classNamesOf 返回 DEX 中全部类的描述符。
func classNamesOf(f *dex.File) ([]string, error) {
	var names []string
	if err := f.Classes(func(_ uint32, _ dex.ClassDef, name string) error {
		names = append(names, name)
		return nil
	}); err != nil {
		return nil, err
	}
	sort.Strings(names)
	return names, nil
}

// splitPartsFor 决定拆成几份。
//
// 显式指定时用指定值；否则按「每份约 300 个类」估算，并夹在 [2, 16] 区间：
// 份数太少起不到打散作用，太多则每个载荷都带一份完整的索引表，体积会失控。
func splitPartsFor(classes, want int) int {
	if classes < 2 {
		return 0
	}
	if want > 0 {
		if want > classes {
			return classes
		}
		return want
	}
	parts := (classes + 299) / 300
	if parts < 2 {
		parts = 2
	}
	if parts > 16 {
		parts = 16
	}
	if parts > classes {
		parts = classes
	}
	return parts
}

// bucketOf 把类名确定性地映射到某一份。
func bucketOf(name string, parts int) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(name))
	return int(h.Sum32() % uint32(parts))
}

// filterOf 把「保留集合」适配成 RebuildOptions 需要的谓词。
func filterOf(keep map[string]bool) func(string) bool {
	return func(name string) bool { return keep[name] }
}

// uniqueName 在名字已被占用时追加序号，避免与既有条目冲突。
func uniqueName(used map[string]bool, name string) string {
	if !used[name] {
		return name
	}
	stem := strings.TrimSuffix(name, ".dex")
	for i := 2; ; i++ {
		cand := fmt.Sprintf("%s-%d.dex", stem, i)
		if !used[cand] {
			return cand
		}
	}
}
