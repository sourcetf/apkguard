package passes

import (
	"context"
	"fmt"
	"sort"

	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/pipeline"
)

// ---- A20 无害花指令填充 ----

// nopFill 在方法入口插入 nop 与「不可达前向跳转」，制造反编译噪音。
//
// 与 A6 的分工：
//   - A6 的不透明谓词需要「全方法未被任何指令引用」的空闲寄存器，优化过的 DEX
//     里几乎没有这种寄存器，覆盖面受限，且一旦为省寄存器而复用活跃寄存器就会
//     触发真机 VerifyError（见 internal/dex/cff.go 的记录）；
//   - 本 Pass 的插入**只含 nop 与 goto/16，不写任何寄存器**，因此不存在类型
//     冲突，几乎可对全部方法生效。代价是它不改变控制流图，强度低于谓词。
//
// 两种并存形态：
//   - 入口形态（JunkInsnCount 控制）：方法开头 nop×N + 两条不可达 goto/16；
//   - return 前形态（ReturnNops 开关）：每条 return* 之前 1 条 nop，
//     对齐参考样本 classes.dex/classes2.dex 的 2862/3539 条单发 nop。
//
// 本 Pass **只定义类型，不在 Registry 注册**：注册由 passes.go 统一维护。
// 建议注册位置在 A6（controlFlow）之后、A9（fakeDex）之前，理由与 A6 相同：
//   - 必须在 A4（dropDebugInfo）之后——花指令会平移指令地址，debug_info 若还在
//     会指向错位地址；
//   - 必须在 B1（encryptDex）之前——之后就没有明文 DEX 可改。
type nopFill struct{}

func (nopFill) ID() config.FeatureID { return "A20" }
func (nopFill) In() pipeline.Level   { return pipeline.LevelZip }
func (nopFill) Out() pipeline.Level  { return pipeline.LevelZip }

func (n *nopFill) Run(_ context.Context, art *pipeline.Artifact, opts *config.Options) error {
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
	// 与 A2/A3/A6 一致：主 DEX 优先，顺序稳定便于复现。
	sort.Slice(units, func(i, j int) bool {
		return dexNameOrder(units[i].entry.NameString()) < dexNameOrder(units[j].entry.NameString())
	})

	nops := opts.JunkInsnCount
	before, after := 0, 0
	var methods, totalNops, returnNops, fakes, skipped int
	ok := 0
	for _, u := range units {
		cf := &dex.ControlFlow{
			JunkFill: true,
			JunkNops: nops,
			// 第二种形态：每条 return 前 1 条 nop（参考样本形态），由选项控制。
			ReturnNops: opts.ReturnNops,
			// 关掉谓词与替换：A20 只做花指令，绝不能变成「偷偷开 A6」。
			// 谓词会写 vP/vT，替换会写临时寄存器——两者都不是本功能项的语义，
			// 也都会重新引入「写活跃寄存器」的风险面。
			Substitute:    false,
			MaxPredicates: 0,
			// 花指令不随方法规模增长，放宽方法体上限以提高覆盖面；
			// 单方法插入量另有 JunkNops 的硬上限（8），膨胀可控。
			MaxItems: 4000,
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
		totalNops += st.ControlFlow.Nops
		returnNops += st.ControlFlow.ReturnNops
		fakes += st.ControlFlow.FakeJumps
		skipped += st.ControlFlow.SkippedTry + st.ControlFlow.SkippedPayload +
			st.ControlFlow.SkippedInit + st.ControlFlow.SkippedShape
		ok++
	}

	art.Note("A20 无害花指令填充：%d 个 DEX，改写 %d 个方法（入口 nop %d 条、return 前 nop %d 条、不可达跳转块 %d 个），"+
		"跳过 %d 个方法（含 try/payload/构造器/形状不符）；%d → %d 字节（增加 %d）",
		ok, methods, totalNops-returnNops, returnNops, fakes, skipped, before, after, after-before)
	art.Stat("A20.dex", fmt.Sprint(ok))
	art.Stat("A20.methods", fmt.Sprint(methods))
	art.Stat("A20.nops", fmt.Sprint(totalNops))
	art.Stat("A20.return_nops", fmt.Sprint(returnNops))
	art.Stat("A20.fake_jumps", fmt.Sprint(fakes))
	art.Stat("A20.skipped", fmt.Sprint(skipped))
	return nil
}
