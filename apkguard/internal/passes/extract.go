package passes

import (
	"bytes"
	"context"
	"fmt"
	"hash/fnv"
	"sort"

	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/pipeline"
	"apkguard/internal/zipx"
)

// ---- B5 函数抽取 ----
//
// 与设计文档（docs/方案-B5-函数抽取.md）的差异（本项目的落地形态）：
//
//	产物侧：被抽取方法的 code_item 只剩等长 stub（const/4 v0,#0 + return v0 /
//	        return-void，其余字补 nop），原始 code_item 收集成「抽取计划」，
//	        以 trailer 形式附在该 DEX 字节流之后，随 B1 的载荷一起 AES 加密。
//	        静态反编译只能看到 stub；计划与载荷同容器、同密钥，B8 容器化
//	        不需要额外搬迁（它只重命名载荷条目，trailer 在载荷内部）。
//	运行时：壳 Loader 在 AES 解密之后、落盘与 DexClassLoader 之前解析 trailer，
//	        把原始方法体原地写回内存中的 byte[]，并按 DEX 头部 file_size 截断
//	        落盘——完全不碰 ART 内部结构（无 mprotect、无 ArtMethod hook）。
//	        回填后 DEX 与抽取前逐字节一致（含 checksum/SHA-1），ART 看到的
//	        就是原始文件。
//
// 覆盖边界（哪些方法一定不被抽取，见 extractSafe 的逐项判据）：
//   - 构造器 / 静态初始化器（<init>/<clinit>，含 ACC_CONSTRUCTOR）；
//   - synchronized / declared-synchronized（stub 会绕过锁语义）；
//   - native / abstract（本就没有 code_item）；
//   - 含 try/catch 的方法（v1 缩小语义面）；
//   - 方法体 < 8 个指令字（抽取收益为负且回填失败代价高）；
//   - 与其它方法共用同一 code_off 的方法（抽取会牵连共用者）；
//   - 方法名出现在 A7 登记的「反射按名调用」字符串集合里的方法；
//   - 编译器生成的 bridge 方法。
//
// 反射是**按方法名**过滤而不是整类排除：A7 只能识别「字符串常量直接用作
// 成员名」的反射调用，动态拼接的名字无法识别——这是覆盖率与安全的固有
// 边界，依赖反射的应用应先用小 -extract-methods 值回归。

// sharedKeyExtract 是 B5 交给报告/后续 Pass 的抽取摘要（Artifact.Shared 键）。
//
// 目前没有其它 Pass 消费它；先落在这里供 E3 自检与将来的回填失败诊断引用，
// 也便于测试断言「启用 B5 时确实抽到了方法」。
const sharedKeyExtract = "B5.extract"

// extractSummary 汇总一次 B5 运行的结果。
type extractSummary struct {
	// Candidates 是全部带方法体的方法数。
	Candidates int
	// Safe 是通过全部安全判据的候选数。
	Safe int
	// Selected 是实际抽取的方法数。
	Selected int
	// DexCount 是被改写的 DEX 数。
	DexCount int
	// Bytes 是被抽取的 code_item 原始字节总量。
	Bytes int
	// Trailer 是追加到载荷里的计划字节总量。
	Trailer int
	// Skip 是各跳过原因的方法数。
	Skip map[string]int
	// Methods 是抽取明细（类→方法），仅用于报告与测试。
	Methods []string
}

// 抽取的最小方法体（指令字）。stub 最多 3 字，太短的方法抽取收益为负，
// 且回填失败时更难定位。
const extractMinInsns = 8

// extractSafe 判断一个方法能否被安全 stub 化，返回跳过原因（空串表示可抽取）。
//
// reason 取值（统计口径，会写进报告）：
//
//	ctor / native / abstract / sync / try / small / shared / reflect / bridge / regs / ret
func extractSafe(info dex.ExtractInfo, reflected map[string]bool) (bool, string) {
	if info.Name == "<init>" || info.Name == "<clinit>" || info.Access&extractAccConstructor != 0 {
		return false, "ctor"
	}
	if info.Access&extractAccNative != 0 {
		return false, "native"
	}
	if info.Access&extractAccAbstract != 0 {
		return false, "abstract"
	}
	if info.Access&(extractAccSynchronized|extractAccDeclSync) != 0 {
		return false, "sync"
	}
	if info.TriesSize != 0 {
		return false, "try"
	}
	if info.Shared {
		return false, "shared"
	}
	if info.InsnsWords < extractMinInsns {
		return false, "small"
	}
	stub, err := dex.ExtractStubWords(info.Ret)
	if err != nil {
		return false, "ret"
	}
	if len(stub) > info.InsnsWords {
		return false, "small"
	}
	if info.Ret != "V" && info.Registers < 1 {
		return false, "regs"
	}
	if (info.Ret == "J" || info.Ret == "D") && info.Registers < 2 {
		return false, "regs"
	}
	if reflected[info.Name] {
		return false, "reflect"
	}
	if info.Access&extractAccBridge != 0 {
		return false, "bridge"
	}
	return true, ""
}

// B5 相关的访问标志位。与 dex 包内部常量同值，这里按 DEX 规范字面量声明，
// 避免把内部常量导出成公共 API。
const (
	extractAccSynchronized = 0x00020
	extractAccBridge       = 0x00040
	extractAccNative       = 0x00100
	extractAccAbstract     = 0x00400
	extractAccConstructor  = 0x10000
	extractAccDeclSync     = 0x20000
)

// extractCode 是 B5 的 Pass 实现。
type extractCode struct{}

func (extractCode) ID() config.FeatureID { return "B5" }
func (extractCode) In() pipeline.Level   { return pipeline.LevelZip }
func (extractCode) Out() pipeline.Level  { return pipeline.LevelZip }

// extractCandidate 是一个待选方法（带来源 DEX 下标）。
type extractCandidate struct {
	entry int
	info  dex.ExtractInfo
}

func (e *extractCode) Run(_ context.Context, art *pipeline.Artifact, opts *config.Options) error {
	// 0 = 关闭。这是 B5 的开关本身（-extract-methods），不是「静默跳过」：
	// 未开启时本 Pass 与不存在完全等价（产物字节零改动）。
	if opts.ExtractMethods <= 0 {
		return nil
	}
	// 壳链路依赖：B1 由 config.Validate 强制；B2/B3 决定运行时是否有人回填。
	// 缺任何一个都意味着产物里只剩 stub、方法永远返回默认值——必须在这里
	// 显式报错，而不是产出一个「能装、能启动、结果全错」的包。
	if !opts.IsEnabled("B1") {
		return fmt.Errorf("B5 需要 B1（DEX 整体加密）：载荷是抽取计划与 stub DEX 的运输容器")
	}
	if !opts.IsEnabled("B2") || !opts.IsEnabled("B3") {
		return fmt.Errorf("B5 需要 B2/B3（壳 Application 与 ClassLoader 接管）："+
			"回填由壳 Loader 在解密后、落盘前执行；缺少壳链路时被抽取方法永远不会被还原（当前 B2=%v B3=%v）",
			opts.IsEnabled("B2"), opts.IsEnabled("B3"))
	}

	entries := pipeline.FindAll(art, isDexEntry)
	if len(entries) == 0 {
		return fmt.Errorf("未找到任何 DEX 条目")
	}
	sort.Slice(entries, func(i, j int) bool {
		return dexNameOrder(entries[i].NameString()) < dexNameOrder(entries[j].NameString())
	})

	reflected, _ := art.Get(reflectionNameKey).(map[string]bool)
	sum := extractSummary{Skip: map[string]int{}}

	// 1) 扫描全部 DEX，收集候选与跳过原因。
	type dexData struct {
		idx   int
		entry *zipx.Entry
		data  []byte
	}
	var parsed []dexData
	var cands []extractCandidate
	unparsable := 0
	for i, en := range entries {
		data, err := en.Data()
		if err != nil {
			return fmt.Errorf("读取 %s 失败: %w", en.NameString(), err)
		}
		infos, err := dex.ScanExtractCandidates(data)
		if err != nil {
			// 与 B1 同口径：解析失败的 .dex 条目是 A9/A16 的伪装文件，
			// 不参与抽取；若其中混入真实 DEX，B1 也会把它留成明文并上报。
			unparsable++
			continue
		}
		parsed = append(parsed, dexData{idx: i, entry: en, data: data})
		sum.Candidates += len(infos)
		for _, info := range infos {
			ok, reason := extractSafe(info, reflected)
			if !ok {
				sum.Skip[reason]++
				continue
			}
			sum.Safe++
			cands = append(cands, extractCandidate{entry: i, info: info})
		}
	}
	if len(parsed) == 0 {
		return fmt.Errorf("没有任何 DEX 条目可被解析，无法执行函数抽取")
	}

	// 2) 确定性排序：大方法优先，同长按 hash(seed‖类‖名‖原型) 定序，再按身份。
	//    hash 使不同 seed 的选取集合不同，避免「抽取位置」本身成为指纹。
	sort.SliceStable(cands, func(a, b int) bool {
		ia, ib := cands[a].info, cands[b].info
		if ia.InsnsWords != ib.InsnsWords {
			return ia.InsnsWords > ib.InsnsWords
		}
		ha := extractHash(opts.Seed, ia)
		hb := extractHash(opts.Seed, ib)
		if ha != hb {
			return ha < hb
		}
		return extractIdentity(ia) < extractIdentity(ib)
	})

	// 3) 计算实际抽取数量：min(ExtractMethods, 安全候选 × ratio%)。
	//    ratio=0 视为 100%（CLI 默认值），保证「只开 -extract-methods 不开
	//    -extract-ratio」是最符合直觉的行为。
	ratio := opts.ExtractRatio
	if ratio <= 0 || ratio > 100 {
		ratio = 100
	}
	want := opts.ExtractMethods
	if want > sum.Safe {
		art.Note("B5 提示：-extract-methods=%d 大于可安全抽取的候选数 %d，按上限取全部", opts.ExtractMethods, sum.Safe)
		want = sum.Safe
	}
	if byRatio := (sum.Safe*ratio + 99) / 100; byRatio < want {
		want = byRatio
	}
	if want < 0 {
		want = 0
	}
	chosen := cands[:want]

	// 4) 按来源 DEX 分组并逐一抽取。
	byDex := map[int]map[uint32]bool{}
	for _, c := range chosen {
		if byDex[c.entry] == nil {
			byDex[c.entry] = map[uint32]bool{}
		}
		byDex[c.entry][c.info.CodeOff] = true
	}
	for _, dd := range parsed {
		sel := byDex[dd.idx]
		if len(sel) == 0 {
			continue
		}
		out, plan, err := dex.ExtractCode(dd.data, func(info dex.ExtractInfo) bool {
			return sel[info.CodeOff]
		})
		if err != nil {
			return fmt.Errorf("B5 抽取 %s 失败: %w", dd.entry.NameString(), err)
		}
		if plan == nil {
			continue
		}
		// 回填自检（构建期强校验）：把刚生成的 stub+trailer 按壳侧同一算法
		// 回填一遍，结果必须与抽取前的 DEX 逐字节一致。任何偏移/长度/头部
		// 计算错误都会在这里被拦下，而不是等到真机上方法返回错值。
		restored, n, err := dex.ApplyExtractPlan(out)
		if err != nil {
			return fmt.Errorf("B5 回填自检失败（%s）：%w", dd.entry.NameString(), err)
		}
		if n != len(plan.Entries) {
			return fmt.Errorf("B5 回填自检失败（%s）：计划 %d 条，回填 %d 条",
				dd.entry.NameString(), len(plan.Entries), n)
		}
		if !bytes.Equal(restored, dd.data) {
			return fmt.Errorf("B5 回填自检失败（%s）：回填后与抽取前的 DEX 不一致（偏移/长度或头部修复算错）",
				dd.entry.NameString())
		}
		if err := dd.entry.SetData(out, true); err != nil {
			return fmt.Errorf("B5 写回 %s 失败: %w", dd.entry.NameString(), err)
		}

		sum.DexCount++
		sum.Trailer += len(out) - len(dd.data)
		for _, ent := range plan.Entries {
			sum.Selected++
			sum.Bytes += ent.ByteLen
			sum.Methods = append(sum.Methods, fmt.Sprintf("%s->%s%s", ent.Info.Class, ent.Info.Name, ent.Info.Proto))
		}
	}

	art.Put(sharedKeyExtract, &sum)
	art.Stat("B5.candidates", fmt.Sprint(sum.Candidates))
	art.Stat("B5.safe", fmt.Sprint(sum.Safe))
	art.Stat("B5.extracted", fmt.Sprint(sum.Selected))
	art.Stat("B5.dex", fmt.Sprint(sum.DexCount))
	art.Stat("B5.bytes", fmt.Sprint(sum.Bytes))
	art.Stat("B5.trailer", fmt.Sprint(sum.Trailer))
	for _, k := range []string{"ctor", "sync", "native", "abstract", "try", "small", "shared", "reflect", "bridge", "regs", "ret"} {
		if v := sum.Skip[k]; v > 0 {
			art.Stat("B5.skip."+k, fmt.Sprint(v))
		}
	}

	if sum.Selected == 0 {
		art.Note("B5 警告：已启用函数抽取（-extract-methods=%d）但没有抽到任何方法——"+
			"安全候选 %d 个（总方法 %d 个），其余因构造器/同步/异常表/过短/反射等原因跳过；"+
			"该产物与未启用 B5 等价", opts.ExtractMethods, sum.Safe, sum.Candidates)
		return nil
	}
	art.Note("B5 函数抽取：%d 个方法（候选 %d，安全候选 %d，比例 %d%%，上限 %d）的原始 code_item 已移出 DEX，"+
		"只剩等长 stub；原始方法体 %d 字节作为计划 trailer 附在载荷内随 B1 一同加密，运行时由壳 Loader 在解密后回填（构建期回填自检逐字节通过）；"+
		"被改写的 DEX 共 %d 份，追加计划 %d 字节",
		sum.Selected, sum.Candidates, sum.Safe, ratio, opts.ExtractMethods, sum.Bytes, sum.DexCount, sum.Trailer)
	if sum.Skip["try"] > 0 || sum.Skip["reflect"] > 0 || sum.Skip["shared"] > 0 {
		art.Note("B5 覆盖率边界：跳过 <init>/<clinit> %d、synchronized %d、native/abstract %d、含 try/catch %d、"+
			"方法体<8字 %d、共用 code_off %d、反射按名调用 %d、bridge %d；其中 try/反射/共用者属于 v1 的保守取舍",
			sum.Skip["ctor"], sum.Skip["sync"], sum.Skip["native"]+sum.Skip["abstract"], sum.Skip["try"],
			sum.Skip["small"], sum.Skip["shared"], sum.Skip["reflect"], sum.Skip["bridge"])
	}
	if unparsable > 0 {
		art.Note("B5 提示：%d 个 .dex 条目解析失败、未参与抽取（预期为 A9 的伪 DEX）", unparsable)
	}
	return nil
}

// extractHash 返回方法的确定性哈希（用于同长度候选的排序与 seed 差异化）。
func extractHash(seed string, info dex.ExtractInfo) uint64 {
	h := fnv.New64a()
	h.Write([]byte(seed))
	h.Write([]byte{0})
	h.Write([]byte(info.Class))
	h.Write([]byte{0})
	h.Write([]byte(info.Name))
	h.Write([]byte{0})
	h.Write([]byte(info.Proto))
	return h.Sum64()
}

// extractIdentity 返回方法的稳定身份串（最终兜底排序键）。
func extractIdentity(info dex.ExtractInfo) string {
	return info.Class + "->" + info.Name + info.Proto
}
