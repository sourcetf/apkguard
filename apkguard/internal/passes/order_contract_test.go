package passes

import (
	"context"
	"testing"

	"apkguard/internal/config"
	"apkguard/internal/pipeline"
)

// TestExecutionOrderSatisfiesDocumentedConstraints 把 passes.go 注释里写明的
// **顺序约束**变成可执行的断言。
//
// 为什么需要：执行顺序就是注册顺序，而注释里的「A14 必须在 B1 之后」「B4 必须
// 在 B1 之前」这类约束是纯语义要求——改错了不会编译失败，只会在特定功能组合下
// 产出错误结果（例如 A14 提前会让新增条目带着 1980 时间戳发布，正好构成它想
// 消除的重打包痕迹）。此前这些约束只存在于注释里，没有任何测试保护。
func TestExecutionOrderSatisfiesDocumentedConstraints(t *testing.T) {
	idx := map[config.FeatureID]int{}
	for i, p := range Registry().Passes() {
		idx[p.ID()] = i
	}

	// before 必须排在 after 之前（约束原文见 passes.go 的注册段注释）。
	type pair struct {
		before, after config.FeatureID
		why           string
	}
	pairs := []pair{
		// L1 混淆段
		{"A4", "A6", "A6 会大幅平移指令地址，必须在清调试信息之后"},
		{"A5", "A11", "A11 是 A5 的完整形态，需先有资源混淆"},
		{"A6", "A9", "A6 需在明文 DEX 阶段完成"},
		{"A16", "A14", "A14 要统一所有新增条目的时间戳"},

		// 加壳段
		{"C2", "B4", "C2 要先移走 lib/ 并记录原始 ABI 集合，B4 再拆 DEX"},
		{"C2", "B1", "同上：C1 依赖 C2 记录的 ABI 集合"},
		{"B4", "B1", "B4 先拆、B1 再逐份加密；反过来 B1 已把明文移出 APK"},
		{"B1", "B2", "B2 要把壳 DEX 放进 B1 腾空的 classes.dex"},
		{"B8", "B3", "B3 生成 Loader 时会把载荷名内联进字节码，故 B8 必须先改名"},
		{"B1", "B8", "B8 要读 B1 产生的加密载荷清单"},
		{"B2", "B3", "B3 往 B2 建好的壳 DEX 里注入 Loader 类体"},
		{"B8", "A17", "A17 要往 B8 建好的容器目录树里放假 APK"},

		// 运行时防护段
		{"B2", "C1", "C1 要往壳 DEX 注入桥接类"},
		{"B2", "D1", "D1 要往壳 DEX 注入签名校验类"},
		{"C2", "C7", "C7 改名会让 C2 把守卫库当业务库加密搬走"},
		{"C1", "C7", "C7 改的是 C1 注入的那份守卫库"},

		// 元数据段
		{"B1", "A14", "A14 统一全部条目（含 B1 的载荷）的时间戳"},
		{"B2", "A14", "A14 统一全部条目（含 B2 的壳 DEX）的时间戳"},
		{"E4", "A14", "A14 统一全部条目（含 E4 的渠道文件）的时间戳"},
		{"E6", "A15", "E6 要读 minSdk，而 A15 会把 Manifest 膨胀到数百 MB"},
	}
	for _, p := range pairs {
		bi, ok1 := idx[p.before]
		ai, ok2 := idx[p.after]
		if !ok1 || !ok2 {
			t.Errorf("约束 %s<%s 引用了不存在的功能项", p.before, p.after)
			continue
		}
		if bi >= ai {
			t.Errorf("顺序约束被破坏：%s（第 %d）必须排在 %s（第 %d）之前——%s",
				p.before, bi, p.after, ai, p.why)
		}
	}

	// A14 必须在**所有**会新增条目的功能项之后；A15 必须在最后。
	last := len(Registry().Passes()) - 1
	if idx["A15"] != last {
		t.Errorf("A15（Manifest 巨型填充）必须在最后执行（当前第 %d，共 %d 个），否则后续每次解析 Manifest 都要多走数十 MB 零",
			idx["A15"], last)
	}
	entryAdders := []config.FeatureID{"A9", "A10", "A12", "A16", "A17", "B1", "B2", "B8", "C1", "C2", "E4"}
	for _, id := range entryAdders {
		if idx[id] >= idx["A14"] {
			t.Errorf("A14 必须排在会新增条目的 %s 之后（A14 第 %d，%s 第 %d），否则新条目会带着默认 1980 时间戳发布",
				id, idx["A14"], id, idx[id])
		}
	}
}

// TestLevelChainIsContinuous 验证注册序列上的层次链是连续的。
//
// Level（In/Out）不决定执行顺序，但它是一份**被校验的声明**：链条断裂时
// pipeline 会直接报错，而不是悄悄按 Level 重排（那样会把「A14 在 B1 之后」
// 这类跨层约束打乱）。这里在注册表层面钉住该不变量。
func TestLevelChainIsContinuous(t *testing.T) {
	ps := Registry().Passes()
	if len(ps) == 0 {
		t.Fatal("注册表为空")
	}
	if got := ps[0].In(); got != pipeline.LevelZip {
		t.Errorf("首个 Pass %s 的输入层次应为 %s，实际 %s", ps[0].ID(), pipeline.LevelZip, got)
	}
	for i := 0; i+1 < len(ps); i++ {
		if out, in := ps[i].Out(), ps[i+1].In(); out != in {
			t.Errorf("层次链断裂：%s 输出 %s，但下一个 %s 需要 %s",
				ps[i].ID(), out, ps[i+1].ID(), in)
		}
	}
}

// TestLevelChainBreaksAreDetected 验证链条断裂会被 pipeline 拒绝执行。
//
// 这是「不再静默重排」这条改动的直接回归：注册一个 In/Out 与邻居不接的 Pass，
// 流水线必须报错而不是照样跑。
func TestLevelChainBreaksAreDetected(t *testing.T) {
	reg := pipeline.NewRegistry()
	reg.Register(chainStub{id: "A1", in: pipeline.LevelZip, out: pipeline.LevelZip})
	reg.Register(chainStub{id: "A2", in: pipeline.LevelDex, out: pipeline.LevelDex})

	err := pipeline.CheckLevelChain(reg.Passes())
	if err == nil {
		t.Fatal("层次链断裂（ZIP 层之后接 DEX 层）应被拒绝")
	}
	if !contains(err.Error(), "层次链") {
		t.Fatalf("错误信息应点明层次链断裂，实际: %v", err)
	}

	// 反例：链条连续时必须通过，避免断言恒真。
	ok := pipeline.NewRegistry()
	ok.Register(chainStub{id: "A1", in: pipeline.LevelZip, out: pipeline.LevelZip})
	ok.Register(chainStub{id: "A2", in: pipeline.LevelZip, out: pipeline.LevelZip})
	if err := pipeline.CheckLevelChain(ok.Passes()); err != nil {
		t.Fatalf("连续链条不应报错，实际: %v", err)
	}
}

// chainStub 是只用来构造层次链的假 Pass。
type chainStub struct {
	id      config.FeatureID
	in, out pipeline.Level
}

func (c chainStub) ID() config.FeatureID { return c.id }
func (c chainStub) In() pipeline.Level   { return c.in }
func (c chainStub) Out() pipeline.Level  { return c.out }
func (c chainStub) Run(_ context.Context, _ *pipeline.Artifact, _ *config.Options) error {
	return nil
}
