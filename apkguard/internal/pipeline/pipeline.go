// Package pipeline 定义加固流水线的执行框架。
//
// 流水线把「读入 APK → 逐项加固 → 对齐 → 签名 → 自检 → 输出」串起来，
// 每个功能项实现为独立的 Pass，由调度器按阶段顺序执行。
package pipeline

import (
	"context"
	"fmt"
	"os"
	"time"

	"apkguard/internal/config"
	"apkguard/internal/zipx"
)

// Level 表示一次产物所处的抽象层次。
//
// Level 表达「产物形态」：Pass 声明自己能处理的输入形态与产出的形态。
//
// **它不决定执行顺序**：顺序由注册顺序决定（见 passes.go 里逐条写明的顺序约束），
// 因为真正要守的约束是「A14 必须在 B1/B8 之后」这类**跨层**关系，而按 Level
// 排序反而会把它们打乱（LevelZip 的全部 Pass 会一起排在 LevelDex 之前）。
// Level 在这里的角色是「被校验的声明」：注册序列上的层次链必须连续
// （前一个 Pass 的 Out 等于后一个的 In，且起点为 LevelZip），否则 pipeline 直接
// 报错——这样 Level 写错时会立刻暴露，而不是悄悄把某个 Pass 挪到别处执行。
type Level int

// 各处理层次。
const (
	LevelZip   Level = iota // 原始 ZIP 条目集合
	LevelDex                // 已解析并可重建的 DEX
	LevelFinal              // 已完成全部加固，待对齐签名
)

// String 返回层次名。
func (l Level) String() string {
	switch l {
	case LevelZip:
		return "ZIP 结构层"
	case LevelDex:
		return "DEX 层"
	case LevelFinal:
		return "最终产物层"
	}
	return "未知"
}

// Artifact 是流水线在 Pass 之间传递的产物。
type Artifact struct {
	// Archive 是当前 APK 的 ZIP 结构。
	Archive *zipx.Archive
	// Notes 记录各 Pass 追加的说明，最终汇总进报告。
	Notes []string
	// Stats 记录各 Pass 的统计指标。
	Stats map[string]string
	// Shared 用于在 Pass 之间传递结构化数据（如 B1 的载荷清单交给 B3 生成壳）。
	//
	// 之所以用 map[string]any 而不是具体类型：pipeline 包不应反向依赖
	// passes 包的具体数据结构，否则会形成循环依赖。键名由写入方以常量形式
	// 定义并加注释说明，读取方必须做类型断言。
	Shared map[string]any
}

// Entries 返回当前全部条目。
func (a *Artifact) Entries() []*zipx.Entry { return a.Archive.Entries }

// Note 追加一条说明。
func (a *Artifact) Note(format string, args ...any) {
	a.Notes = append(a.Notes, fmt.Sprintf(format, args...))
}

// Stat 记录一个统计指标。
func (a *Artifact) Stat(key, val string) {
	if a.Stats == nil {
		a.Stats = map[string]string{}
	}
	a.Stats[key] = val
}

// Put 存入一个跨 Pass 共享的结构化数据。
func (a *Artifact) Put(key string, v any) {
	if a.Shared == nil {
		a.Shared = map[string]any{}
	}
	a.Shared[key] = v
}

// Get 读取跨 Pass 共享的数据；不存在时返回 nil。
func (a *Artifact) Get(key string) any {
	if a.Shared == nil {
		return nil
	}
	return a.Shared[key]
}

// Pass 是一个加固步骤。
type Pass interface {
	// ID 返回对应的功能项 ID，用于从配置判断是否启用。
	ID() config.FeatureID
	// In 返回该 Pass 期望的输入层次。
	In() Level
	// Out 返回该 Pass 产出的层次。
	Out() Level
	// Run 执行加固。
	Run(ctx context.Context, art *Artifact, opts *config.Options) error
}

// Registry 收集所有已注册的 Pass。
type Registry struct {
	passes []Pass
}

// NewRegistry 创建一个空注册表。
func NewRegistry() *Registry { return &Registry{} }

// Register 注册一个 Pass；ID 重复时 panic（属于编程错误）。
func (r *Registry) Register(p Pass) {
	for _, e := range r.passes {
		if e.ID() == p.ID() {
			panic(fmt.Sprintf("pipeline: 功能项 %s 重复注册", p.ID()))
		}
	}
	r.passes = append(r.passes, p)
}

// Passes 返回已注册的全部 Pass（按注册顺序）。
func (r *Registry) Passes() []Pass { return r.passes }

// Result 是一次加固的产物与报告。
type Result struct {
	// APK 是加固后的 APK 字节流（未签名，若启用了 E1 则已签名）。
	APK []byte
	// IDSig 是 v4 签名文件（.idsig）的内容，未启用 v4 时为 nil。
	// 它是独立于 APK 的第二个文件，调用方应当与 APK 一并落盘
	// （约定文件名：<APK 路径>.idsig）。
	IDSig []byte
	// Notes 是各 Pass 的说明汇总。
	Notes []string
	// Stats 是各 Pass 的统计汇总。
	Stats map[string]string
	// Ran 是实际执行的功能项 ID（按执行顺序）。
	Ran []config.FeatureID
	// Skipped 是被跳过的功能项及原因。
	Skipped map[config.FeatureID]string
	// Duration 是总耗时。
	Duration time.Duration
}

// Sink 在流水线的关键节点被调用，便于插入对齐、签名、自检等收尾步骤。
type Sink interface {
	// Finish 接收加固完成的 ZIP 归档，返回最终 APK 字节流。
	Finish(ctx context.Context, art *Artifact, opts *config.Options) ([]byte, error)
}

// Pipeline 串起注册表中的 Pass 并执行。
type Pipeline struct {
	reg  *Registry
	sink Sink
}

// New 创建流水线。
func New(reg *Registry, sink Sink) *Pipeline {
	return &Pipeline{reg: reg, sink: sink}
}

// Run 执行全部启用的 Pass。
//
// 执行顺序：先按 Level 分层（ZIP 层 → DEX 层 → 最终层），
// 同层内按注册顺序；被禁用的 Pass 记入 Skipped。
func (p *Pipeline) Run(ctx context.Context, opts *config.Options) (*Result, error) {
	start := time.Now()

	if err := opts.Validate(); err != nil {
		return nil, err
	}

	art, err := Load(opts.In)
	if err != nil {
		return nil, fmt.Errorf("读取输入 APK 失败: %w", err)
	}

	res := &Result{Skipped: map[config.FeatureID]string{}}

	// 执行顺序 = 注册顺序。
	//
	// 这里**不再**按 Level 排序：所有 Pass 的 In/Out 目前都是 LevelZip，排序是
	// 空操作，却会给人一种「层次会自动排好序」的错觉——一旦有人给某个 Pass
	// 单独改成 LevelDex，它会被静默移到所有 ZIP 层之后，而真正的顺序约束
	// （A14 在 B1 之后、B4 在 B1 之前…）并不体现在 Level 上。
	// 改为校验层次链连续：声明与顺序不一致时直接报错，绝不静默重排。
	order := append([]Pass(nil), p.reg.passes...)
	if err := CheckLevelChain(order); err != nil {
		return nil, err
	}

	for _, ps := range order {
		id := ps.ID()
		if !opts.IsEnabled(id) {
			res.Skipped[id] = "未启用"
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := ps.Run(ctx, art, opts); err != nil {
			return nil, fmt.Errorf("功能项 %s（%s）执行失败: %w", id, nameOf(id), err)
		}
		res.Ran = append(res.Ran, id)
	}

	if p.sink == nil {
		return nil, fmt.Errorf("pipeline: 未配置 Sink，无法产出最终 APK")
	}
	out, err := p.sink.Finish(ctx, art, opts)
	if err != nil {
		return nil, err
	}

	res.APK = out
	if v, ok := art.Get(sharedKeyIDSig).([]byte); ok {
		res.IDSig = v
	}
	res.Notes = art.Notes
	res.Stats = art.Stats
	res.Duration = time.Since(start)
	return res, nil
}

// CheckLevelChain 校验注册序列上的层次链是连续的。
//
// 规则：起点必须是 LevelZip（未加工的条目集合），且每个 Pass 的 Out 必须等于
// 下一个 Pass 的 In。全部声明 LevelZip 时天然成立；一旦有人给某个 Pass 声明了
// 别的层次，就必须同时把相邻 Pass 的 In/Out 一起改对，否则这里会报错。
func CheckLevelChain(order []Pass) error {
	if len(order) == 0 {
		return nil
	}
	if got := order[0].In(); got != LevelZip {
		return fmt.Errorf("pipeline: 首个 Pass %s 的输入层次应为 %s，实际 %s",
			order[0].ID(), LevelZip, got)
	}
	for i := 0; i+1 < len(order); i++ {
		if out, in := order[i].Out(), order[i+1].In(); out != in {
			return fmt.Errorf("pipeline: 层次链断裂——%s 输出 %s，但下一个 %s 需要 %s；"+
				"注册顺序与 In/Out 声明不一致（顺序约束见 passes.go 的注释）",
				order[i].ID(), out, order[i+1].ID(), in)
		}
	}
	return nil
}

func nameOf(id config.FeatureID) string {
	if f, ok := config.ByID()[id]; ok {
		return f.Name
	}
	return string(id)
}

// Load 把一个 APK 文件读成条目集合。
func Load(path string) (*Artifact, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	a, err := zipx.Read(data)
	if err != nil {
		return nil, err
	}
	return &Artifact{Archive: a, Stats: map[string]string{}}, nil
}

// Bytes 把条目集合序列化为 ZIP（不做对齐与签名）。
//
// 为保持既有调用方（多个 passes 包与测试）的签名兼容，本函数不返回错误：
// 内部用 WriteChecked，一旦条目数/字段长度触及 ZIP 上限将 panic。调用方的
// 输入可能触及这些上限时，应改用 BytesChecked 并处理其返回的 error。
func Bytes(art *Artifact) []byte {
	out, err := BytesChecked(art)
	if err != nil {
		panic("pipeline.Bytes: " + err.Error())
	}
	return out
}

// BytesChecked 与 Bytes 相同，但把归档写出的错误向上返回。
func BytesChecked(art *Artifact) ([]byte, error) {
	return zipx.WriteChecked(art.Archive, zipx.AlignOptions{Align: 1, SoAlign: 1})
}

// Find 按名字查找条目，未找到返回 nil。
func Find(art *Artifact, name string) *zipx.Entry {
	return art.Archive.Find(name)
}

// FindAll 按谓词筛选条目。
func FindAll(art *Artifact, pred func(*zipx.Entry) bool) []*zipx.Entry {
	var out []*zipx.Entry
	for _, e := range art.Archive.Entries {
		if pred(e) {
			out = append(out, e)
		}
	}
	return out
}

// Remove 删除满足谓词的条目，返回删除数量。
func Remove(art *Artifact, pred func(*zipx.Entry) bool) int {
	kept := art.Archive.Entries[:0]
	n := 0
	for _, e := range art.Archive.Entries {
		if pred(e) {
			n++
			continue
		}
		kept = append(kept, e)
	}
	art.Archive.Entries = kept
	return n
}

// Add 追加一个条目。
func Add(art *Artifact, e *zipx.Entry) {
	art.Archive.Entries = append(art.Archive.Entries, e)
}
