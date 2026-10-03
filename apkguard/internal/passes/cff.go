package passes

import (
	"context"
	"fmt"
	"sort"

	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/pipeline"
)

// ---- A6 控制流混淆 ----

// controlFlow 注入不透明谓词并做等价指令替换。
//
// 注册由 passes.go 统一维护（见其中的 r.Register(&controlFlow{})），
// 注册位置是 A4（dropDebugInfo）之后、A9（fakeDex）之前，
// 理由见 docs/方案-A6-控制流混淆.md §3：
//   - 必须在 A1 之后（减少重复重建、分支分析更稳定）；
//   - 必须在 A4 之后（A6 会大幅平移指令地址，若 debug_info 还在会指向错位地址）；
//   - 必须在 B1 之前（B1 之后就没有明文 DEX 可改）；
//   - 排在 A13/A8 之后（不处理注入的膨胀/诱饵类，省体积、免改乱）。
//
// 关于实现方式：本 Pass 是独立的一次 dex.Rebuild 调用，而不是把
// ControlFlow 塞进 A2/A3 那次 Rebuild。这样每次 Rebuild 的 skip（绝对字位置）
// 只对应本次输出，不存在跨步骤错位问题。需要与 A2/A3 同一次 Rebuild 时，
// generate 内部也已把 A6 排在 A2/A3 之前（见 assemble.go）。
type controlFlow struct{}

func (controlFlow) ID() config.FeatureID { return "A6" }
func (controlFlow) In() pipeline.Level   { return pipeline.LevelZip }
func (controlFlow) Out() pipeline.Level  { return pipeline.LevelZip }

func (c *controlFlow) Run(_ context.Context, art *pipeline.Artifact, opts *config.Options) error {
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
	// 与 A2/A3 一致：主 DEX 优先处理，顺序稳定便于复现。
	sort.Slice(units, func(i, j int) bool {
		return dexNameOrder(units[i].entry.NameString()) < dexNameOrder(units[j].entry.NameString())
	})

	seed := seedInt64(opts.Seed)
	before, after := 0, 0
	var methods, preds, subs, fakes, skipped int
	ok := 0
	for _, u := range units {
		cf := &dex.ControlFlow{
			Seed:          seed,
			MaxPredicates: 1,    // 最小切片：只注入方法入口 1 组谓词
			Substitute:    true, // 同时做等价指令替换
		}
		out, st, err := dex.RebuildWithStats(u.file, dex.RebuildOptions{ControlFlow: cf})
		if err != nil {
			return fmt.Errorf("重建 %s 失败: %w", u.entry.NameString(), err)
		}
		// 结构自检：校验和/签名自洽 + 描述符合法。
		if err := dex.Verify(out); err != nil {
			return fmt.Errorf("%s 重建后校验失败: %w", u.entry.NameString(), err)
		}
		if err := dex.ValidateDescriptors(out); err != nil {
			return fmt.Errorf("%s 重建后描述符非法: %w", u.entry.NameString(), err)
		}
		if err := u.entry.SetData(out, true); err != nil {
			return fmt.Errorf("写回 %s 失败: %w", u.entry.NameString(), err)
		}
		before += len(u.data)
		after += len(out)
		methods += st.ControlFlow.MethodsRewritten
		preds += st.ControlFlow.Predicates
		subs += st.ControlFlow.Substitutions
		fakes += st.ControlFlow.FakeJumps
		skipped += st.ControlFlow.SkippedTry + st.ControlFlow.SkippedPayload +
			st.ControlFlow.SkippedRegisters + st.ControlFlow.SkippedInit + st.ControlFlow.SkippedShape
		ok++
	}

	art.Note("A6 控制流混淆：%d 个 DEX，改写 %d 个方法（不透明谓词 %d 组、等价指令替换 %d 条、不可达跳转块 %d 个），跳过 %d 个方法；%d → %d 字节（增加 %d）",
		ok, methods, preds, subs, fakes, skipped, before, after, after-before)
	art.Stat("A6.dex", fmt.Sprint(ok))
	art.Stat("A6.methods", fmt.Sprint(methods))
	art.Stat("A6.preds", fmt.Sprint(preds))
	art.Stat("A6.subs", fmt.Sprint(subs))
	art.Stat("A6.fake", fmt.Sprint(fakes))
	art.Stat("A6.skipped", fmt.Sprint(skipped))
	art.Stat("A6.grow", fmt.Sprint(after-before))
	return nil
}

// seedInt64 把字符串种子确定性地折叠为 int64。
//
// 仅用于让谓词常量在「同一种子下可复现、不同种子下有差异」，不用于安全用途。
func seedInt64(s string) int64 {
	var h int64
	for _, c := range s {
		h = h*131 + int64(c)
	}
	return h
}
