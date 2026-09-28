package passes

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/pipeline"
)

// ---- A13 类膨胀与类名策略 ----

// classPad 生成大量「真实类」并注入 DEX，用于拖慢类枚举与人工分析。
//
// 关键设计：注入的必须是真实类（字段 + 构造器 + 含循环的方法体）。
// 实测样本中空类率与正常 DEX 相当（4.2%~5.4%），大量空类反而是明显的
// 加固特征，会被扫描器直接筛出。
//
// 类名策略与样本一致：
//   - 默认包类（LA1;）——源码中无法正常声明，属混淆强信号；
//   - 超长类名路径（30+ 层）——使反编译树极难浏览；
//   - 类数量膨胀——拖慢全量类枚举。
//
// 多 DEX 场景：类名必须全局唯一，否则运行时出现「类重复定义」。
// 因此本 Pass 先汇总全部 DEX 的类型名，再按 DEX 顺序依次分配新名，
// 并把已分配的名字累加进「已用集合」。
type classPad struct{}

func (classPad) ID() config.FeatureID { return "A13" }
func (classPad) In() pipeline.Level   { return pipeline.LevelZip }
func (classPad) Out() pipeline.Level  { return pipeline.LevelZip }

func (c *classPad) Run(_ context.Context, art *pipeline.Artifact, opts *config.Options) error {
	total := opts.ClassPadCount
	if total <= 0 {
		return nil // 未指定数量时不做任何事（由 UI 侧给出默认值）
	}

	entries := pipeline.FindAll(art, isDexEntry)
	if len(entries) == 0 {
		return fmt.Errorf("未找到任何 DEX 条目")
	}

	units := make([]*dexUnit, 0, len(entries))
	for _, en := range entries {
		data, err := en.Data()
		if err != nil {
			continue
		}
		f, err := dex.Parse(data)
		if err != nil {
			continue // 伪装文件
		}
		units = append(units, &dexUnit{entry: en, data: data, file: f})
	}
	if len(units) == 0 {
		return fmt.Errorf("没有任何 DEX 条目可被解析")
	}
	sort.Slice(units, func(i, j int) bool {
		return dexNameOrder(units[i].entry.NameString()) < dexNameOrder(units[j].entry.NameString())
	})

	// ① 汇总全部 DEX 已有的类型名：新类名不得与任何一个冲突。
	//    同时也把 A2/A3 将要注入的类名预留出来，避免同一 DEX 内重复定义。
	used := map[string]bool{}
	for _, u := range units {
		for i := uint32(0); i < u.file.NType; i++ {
			d, err := u.file.Type(i)
			if err != nil {
				continue
			}
			used[d] = true
		}
	}
	pkg := shellPkgOf(opts)
	if opts.IsEnabled("A2") {
		used[fmt.Sprintf("L%s/Dec;", pkg)] = true
	}
	if opts.IsEnabled("A3") {
		used[fmt.Sprintf("L%s/Arr;", pkg)] = true
	}

	// ② 按 DEX 均分数量，最后一个 DEX 吃掉余数。
	per := total / len(units)
	rem := total % len(units)

	before, after := 0, 0
	clsTotal, fldTotal, mtdTotal, nameBytes := 0, 0, 0, 0
	kinds := map[string]int{}
	ok := 0
	for idx, u := range units {
		n := per
		if idx == len(units)-1 {
			n += rem
		}
		if n <= 0 {
			continue
		}
		cp := &dex.ClassPadder{
			Count: n,
			// 每个 DEX 使用不同种子，避免生成同名类。
			Seed:     opts.Seed + "/" + u.entry.NameString(),
			Existing: used,
		}
		padClasses, _, err := dex.ClassPadPlan(cp)
		if err != nil {
			return fmt.Errorf("%s 生成膨胀类失败: %w", u.entry.NameString(), err)
		}
		// 把本次分配的名字并入全局已用集合，供后续 DEX 参考。
		for _, pc := range padClasses {
			used[pc.Spec.Name] = true
		}

		out, st, err := dex.RebuildWithStats(u.file, dex.RebuildOptions{
			ClassPad: &dex.ClassPadder{Classes: padClasses},
		})
		if err != nil {
			return fmt.Errorf("重建 %s 失败: %w", u.entry.NameString(), err)
		}
		if err := dex.Verify(out); err != nil {
			return fmt.Errorf("%s 重建后校验失败: %w", u.entry.NameString(), err)
		}
		if err := u.entry.SetData(out, true); err != nil {
			return fmt.Errorf("写回 %s 失败: %w", u.entry.NameString(), err)
		}
		before += len(u.data)
		after += len(out)
		clsTotal += st.ClassesPadded
		fldTotal += st.ClassPad.Fields
		mtdTotal += st.ClassPad.Methods
		nameBytes += st.ClassPad.Bytes
		for k, v := range st.ClassPad.Kinds {
			kinds[k.String()] += v
		}
		ok++
	}

	art.Note("A13 类膨胀：%d 个 DEX，注入 %d 个真实类（字段 %d、方法 %d，类名合计 %d 字节）；%d → %d 字节（增加 %d）",
		ok, clsTotal, fldTotal, mtdTotal, nameBytes, before, after, after-before)
	art.Stat("A13.dex", fmt.Sprint(ok))
	art.Stat("A13.classes", fmt.Sprint(clsTotal))
	art.Stat("A13.fields", fmt.Sprint(fldTotal))
	art.Stat("A13.methods", fmt.Sprint(mtdTotal))
	art.Stat("A13.namebytes", fmt.Sprint(nameBytes))
	art.Stat("A13.grow", fmt.Sprint(after-before))
	art.Stat("A13.kinds", kindsSummary(kinds))
	return nil
}

// kindsSummary 把策略计数拼成「默认包类 8、超长类名路径 1」这样的可读文本。
func kindsSummary(kinds map[string]int) string {
	var parts []string
	for _, k := range []string{"默认包类", "超长类名路径", "常规短名"} {
		if kinds[k] > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", k, kinds[k]))
		}
	}
	return strings.Join(parts, "、")
}
