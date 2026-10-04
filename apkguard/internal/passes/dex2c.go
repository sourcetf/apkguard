package passes

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"apkguard/internal/config"
	"apkguard/internal/dex"
	b7c "apkguard/internal/dex2c"
	"apkguard/internal/pipeline"
	"apkguard/internal/zipx"
)

// ---- B7 Dex2C（Java2C） ----
//
// 已交付（L1）：在编译期把满足受限子集的 Java 方法翻译成 C，用 NDK 交叉编译
// 成 3 个 ABI 的 .so 注入 lib/<abi>/，并把完整翻译计划（方法表、绑定表、
// 编译日志）写入 Artifact.Shared（键 B7.plan）供后续壳集成消费。
//
// **未交付（L2，明确声明）**：DEX 侧把被选中方法改成 ACC_NATIVE、以及壳
// （B3 Loader）在 ClassLoader 就绪后调用 .so 导出的 b7_register_all 完成
// RegisterNatives 绑定。这两步分别需要修改 internal/dex 的 class_data 编码
// 与 B3 的 Loader 生成代码，均不在本功能的允许改动范围内；因此当前产物中
// 被翻译方法仍保留原始字节码，本功能对产物的形态没有影响（只多出 .so）。
// 绝不做「把方法改成 native 却没有注册」的半成品：那会让产物一运行到这些
// 方法就抛 UnsatisfiedLinkError。
//
// 门控与失败语义：
//   - opts.Dex2CMethods <= 0 时与不注册该 Pass 完全等价（产物字节零改动）；
//   - opts.Dex2CMethods > 0 时必须能找到 NDK，否则报错退出（绝不静默跳过）。
const sharedKeyDex2C = "B7.plan"

// dex2cFindNDK / dex2cBuild 是测试注入点（生产行为 = dex2c 包的实现）。
var (
	dex2cFindNDK = b7c.FindNDK
	dex2cBuild   = b7c.Build
)

type dex2c struct{}

func (dex2c) ID() config.FeatureID { return "B7" }
func (dex2c) In() pipeline.Level   { return pipeline.LevelZip }
func (dex2c) Out() pipeline.Level  { return pipeline.LevelZip }

func (p *dex2c) Run(_ context.Context, art *pipeline.Artifact, opts *config.Options) error {
	// 0 = 关闭。这是 B7 的开关本身（-dex2c-methods），未开启时本 Pass 与
	// 不存在完全等价（产物字节零改动），不是「静默跳过」。
	if opts.Dex2CMethods <= 0 {
		return nil
	}

	// 第一步就是解析 NDK：找不到必须立刻失败，不产出「没有 Dex2C 的 Dex2C 产物」。
	ndk, err := dex2cFindNDK(opts.NDKPath)
	if err != nil {
		return err
	}

	entries := pipeline.FindAll(art, isDexEntry)
	if len(entries) == 0 {
		return fmt.Errorf("未找到任何 DEX 条目")
	}
	sort.Slice(entries, func(i, j int) bool {
		return dexNameOrder(entries[i].NameString()) < dexNameOrder(entries[j].NameString())
	})
	var inputs []b7c.DexInput
	unparsable := 0
	for _, en := range entries {
		data, err := en.Data()
		if err != nil {
			return fmt.Errorf("读取 %s 失败: %w", en.NameString(), err)
		}
		f, err := dex.Parse(data)
		if err != nil {
			// 与 B1/B5 同口径：解析失败的 .dex 条目是 A9/A16 的伪装文件。
			unparsable++
			continue
		}
		inputs = append(inputs, b7c.DexInput{Name: en.NameString(), File: f})
	}
	if len(inputs) == 0 {
		return fmt.Errorf("没有任何 DEX 条目可被解析，无法执行 Dex2C 翻译")
	}

	reflected, _ := art.Get(reflectionNameKey).(map[string]bool)
	abis, err := dex2cTargetABIs(art)
	if err != nil {
		return err
	}
	plan, err := dex2cBuild(inputs, b7c.BuildOptions{
		Limit:     opts.Dex2CMethods,
		Seed:      opts.Seed,
		Reflected: reflected,
		NDK:       ndk,
		ABIs:      abis,
	})
	if err != nil {
		return err
	}

	// 注入 .so：与 C1 一样只补 APK 已经支持的 ABI（纯 Java 应用才补齐全部）。
	added := 0
	var addedBytes int
	for _, abi := range plan.ABIs {
		data, ok := plan.SOs[abi]
		if !ok {
			continue
		}
		name := "lib/" + abi + "/" + plan.LibName
		if pipeline.Find(art, name) != nil {
			continue
		}
		pipeline.Add(art, zipx.NewStored(name, data))
		added++
		addedBytes += len(data)
	}
	art.Put(sharedKeyDex2C, plan)

	sel := plan.Selection
	if sel == nil {
		sel = &b7c.Selection{}
	}
	art.Stat("B7.methods", fmt.Sprint(len(plan.Methods)))
	art.Stat("B7.candidates", fmt.Sprint(sel.Candidates))
	art.Stat("B7.libs", fmt.Sprint(added))
	art.Stat("B7.lib", plan.LibName)
	art.Stat("B7.csource", fmt.Sprint(len(plan.CSource)))
	for _, k := range sortedReasonKeys(sel.Skip) {
		art.Stat("B7.skip."+k, fmt.Sprint(sel.Skip[k]))
	}
	if unparsable > 0 {
		art.Note("B7 提示：%d 个 .dex 条目解析失败、未参与翻译（预期为 A9 的伪 DEX）", unparsable)
	}

	if len(plan.Methods) == 0 {
		art.Note("B7 警告：已启用 Dex2C（-dex2c-methods=%d）但没有选中任何方法——候选 %d 个全部"+
			"因构造器/同步/异常表/宽值/不支持指令/非白名单调用等原因跳过；此产物与未启用 B7 等价。"+
			"跳过明细：%s", opts.Dex2CMethods, sel.Candidates, sel.ReasonReport())
		return nil
	}
	art.Note("B7 Dex2C（L1：翻译+编译+注入）：翻译 %d 个方法（候选 %d，上限 %d）为 C，用 NDK 交叉编译出 %d 个 ABI 的 %s（共 %d 字节，C 源 %d 字节）；"+
		"跳过明细：%s",
		len(plan.Methods), sel.Candidates, opts.Dex2CMethods, added, plan.LibName, addedBytes, len(plan.CSource), sel.ReasonReport())
	art.Note("B7 交付边界（重要）：当前未实现 DEX 侧 ACC_NATIVE 改写与运行时 RegisterNatives 绑定" +
		"（需要修改 internal/dex 的 class_data 编码与 B3 Loader 生成代码，不在允许改动范围内）；" +
		"产物中被翻译方法仍为原始 DEX 字节码，注入的 .so 导出 b7_register_all(JNIEnv*, jclass) 供壳集成后启用。")
	return nil
}

// dex2cTargetABIs 返回要编译的 ABI 集合：
//
//	优先 C2 记录的原生库 ABI 集合（C2 会把 lib/ 搬空，直接扫描会得到空）；
//	否则扫描产物里的 lib/<abi>/；APK 完全没有原生库时补齐全部 3 个。
//
// 与 C1 的 ABI 选择逻辑同源：绝不补 APK 不支持的 ABI，否则系统会误判
// 支持架构、把应用装到不兼容设备上。
func dex2cTargetABIs(art *pipeline.Artifact) ([]string, error) {
	own := abisOf(art)
	if c2 := soAbisOf(art); len(c2) > 0 {
		own = c2
	}
	all := b7c.AbiNames()
	if len(own) == 0 {
		return all, nil
	}
	var out []string
	for _, a := range all {
		if own[a] {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		names := abiNames(own)
		sort.Strings(names)
		return nil, fmt.Errorf("APK 自带原生库的 ABI（%s）不在 Dex2C 支持范围内（%s），无法编译",
			strings.Join(names, "、"), strings.Join(all, "、"))
	}
	return out, nil
}

// sortedReasonKeys 返回跳过原因的稳定顺序（数量降序，同数量按字典序）。
func sortedReasonKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]] != m[keys[j]] {
			return m[keys[i]] > m[keys[j]]
		}
		return keys[i] < keys[j]
	})
	return keys
}

// dex2cPlanOf 取出 B7 计划（测试/报告使用）。
func dex2cPlanOf(art *pipeline.Artifact) *b7c.Plan {
	p, _ := art.Get(sharedKeyDex2C).(*b7c.Plan)
	return p
}
