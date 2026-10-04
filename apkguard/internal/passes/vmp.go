package passes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/pack"
	"apkguard/internal/pipeline"
	"apkguard/internal/vmp"
	"apkguard/internal/zipx"
)

// ---- B6 VMP 虚拟化 ----
//
// 本 Pass 是 B6 的**最小子集**（覆盖范围与已知边界见文件末尾的注释）：
// 扫描全部 DEX，把符合支持集合的方法体翻译成私有定长字节码（internal/vmp），
// 编成一份私有载荷、用与 B1 相同的密钥加密后作为 assets 条目放进产物，
// 并在报告里给出候选数/实际数/各拒绝原因。
//
// 与 docs/方案-B6-VMP.md 的关键结论一致：私有指令是**数据**，解释器是
// internal/native/csrc/apkguard.c 里的固定 C 代码（含独立 dispatch 循环），
// 因此不需要 NDK、不需要 per-app 编译。
//
// 本次交付的边界（必须在报告里如实说明）：
//   - DEX 侧尚未把被选中方法改成 ACC_NATIVE/桥接 stub，运行时也尚未接线
//     （VM.registerVmMethod / 壳 Loader 调 VM.init）——即当前产物里被选中的
//     方法仍以原始 Dalvik 执行，私有载荷是**为接线准备好的运输形态**。
//     这是任务允许的收窄：先交付「翻译 + 私有字节码 + native 解释器 + 对拍」。
//   - 与 B5/B7 的方法归属表尚未实现，因此同时启用直接报错，避免同一方法被
//     两套机制重复处理（B5 会把方法体改成 stub，而 B6 仍宣称拥有它）。

// sharedKeyVMP 是 B6 交给报告/测试/将来运行时接线的摘要（Artifact.Shared 键）。
const sharedKeyVMP = "B6.vmp"

// vmpSummary 汇总一次 B6 运行的结果。
type vmpSummary struct {
	// Candidates 是候选方法数（扫描到的全部带体方法）。
	Candidates int
	// Selected 是被虚拟化（翻译成功）的方法数。
	Selected int
	// DexCount 是实际扫描并成功解析的 DEX 数。
	DexCount int
	// Unparsable 是解析失败而跳过的 .dex 条目数（预期为 A9/A16 的伪装文件）。
	Unparsable int
	// Plain 是私有字节码明文长度。
	Plain int
	// Blob 是载荷密文长度（含可选 MAC 标签）。
	Blob int
	// Payload 是载荷在 APK 中的条目名。
	Payload string
	// Skip 是各跳过原因的方法数。
	Skip map[string]int
	// Methods 是选中方法签名（类->名+原型），用于报告与测试。
	Methods []string
}

// vmpMethods 是 B6 的 Pass 实现。
type vmpMethods struct{}

func (v *vmpMethods) ID() config.FeatureID { return "B6" }
func (v *vmpMethods) In() pipeline.Level   { return pipeline.LevelZip }
func (v *vmpMethods) Out() pipeline.Level  { return pipeline.LevelZip }

func (v *vmpMethods) Run(_ context.Context, art *pipeline.Artifact, opts *config.Options) error {
	// 0 = 关闭。未开启时与不存在完全等价（产物字节零改动）。
	if opts.VMPMethods <= 0 {
		return nil
	}
	// 依赖防御：config.Validate 已强制 B6→B2/B3，这里再查一次是为了
	// 直接调用 Pass 的测试/内部调用路径也能拿到明确错误。
	if !opts.IsEnabled("B1") {
		return fmt.Errorf("B6 需要 B1（DEX 整体加密）：私有字节码载荷必须与 DEX 载荷同密钥加密运输，" +
			"否则明文私有指令会直接落在 assets 里，且无运行时解密路径")
	}
	if !opts.IsEnabled("B2") || !opts.IsEnabled("B3") {
		return fmt.Errorf("B6 需要 B2/B3（壳 Application 与 ClassLoader 接管）："+
			"VM 桥接类注入与私有载荷解密都挂在壳链路上（当前 B2=%v B3=%v）",
			opts.IsEnabled("B2"), opts.IsEnabled("B3"))
	}
	// 方法归属表（docs/方案-B6-VMP.md §3.1）尚未实现：B5 会把方法体改成 stub，
	// B7 会把方法改成 native，与 B6 对同一方法的处理互斥。没有归属表就同时
	// 启用，会产生「B6 报告虚拟化了 N 个方法、实际产物里它们已被 B5 抽走」
	// 这种自相矛盾的产物——直接拒绝，不静默。
	if opts.ExtractMethods > 0 {
		return fmt.Errorf("B6 与 B5 同时启用暂不支持：方法归属登记表尚未落地（B5 会改写的方法与 B6 的翻译集合可能重叠），" +
			"请只用其中一个（-extract-methods 0 或 -vmp-methods 0）")
	}
	if opts.Dex2CMethods > 0 {
		return fmt.Errorf("B6 与 B7 同时启用暂不支持：方法归属登记表尚未落地，请只用其中一个（-dex2c-methods 0 或 -vmp-methods 0）")
	}

	entries := pipeline.FindAll(art, isDexEntry)
	if len(entries) == 0 {
		return fmt.Errorf("未找到任何 DEX 条目")
	}
	// 按 DEX 名排序：载荷内容与 VMID 分配必须可复现。
	sort.Slice(entries, func(i, j int) bool {
		return dexNameOrder(entries[i].NameString()) < dexNameOrder(entries[j].NameString())
	})

	sum := vmpSummary{Skip: map[string]int{}}
	var progs []*vmp.Program
	for _, en := range entries {
		if len(progs) >= opts.VMPMethods {
			break
		}
		data, err := en.Data()
		if err != nil {
			return fmt.Errorf("读取 %s 失败: %w", en.NameString(), err)
		}
		f, err := dex.Parse(data)
		if err != nil {
			// 与 B5 同口径：解析失败的 .dex 是 A9/A16 的伪装文件。
			sum.Unparsable++
			continue
		}
		sum.DexCount++
		sel := vmp.Select(f, en.NameString(), opts.VMPMethods-len(progs))
		sum.Candidates += sel.Candidates
		for k, n := range sel.SkipReasons {
			sum.Skip[k] += n
		}
		progs = append(progs, sel.Programs...)
	}

	if len(progs) == 0 {
		art.Put(sharedKeyVMP, &sum)
		art.Stat("B6.candidates", fmt.Sprint(sum.Candidates))
		art.Stat("B6.selected", "0")
		for k, n := range sum.Skip {
			art.Stat("B6.skip."+k, fmt.Sprint(n))
		}
		art.Note("B6 警告：已启用 VMP 虚拟化（-vmp-methods=%d）但没有可虚拟化的方法——"+
			"扫描 %d 个 DEX、候选 %d 个方法，全部因构造器/同步/异常表/指令数/寄存器数/不支持指令/浮点类型等原因跳过；"+
			"该产物与未启用 B6 等价。跳过明细：%s",
			opts.VMPMethods, sum.DexCount, sum.Candidates, reasonReport(sum.Skip))
		return nil
	}

	// VMID 全局连续编号：Select 按 DEX 各自从 0 开始，合并后必须重编，
	// 否则不同 DEX 的方法会在注册表里撞号。
	for i, p := range progs {
		p.VMID = uint32(i)
	}
	plain, err := vmp.EncodeBlob(progs)
	if err != nil {
		return fmt.Errorf("B6 序列化私有字节码失败: %w", err)
	}

	// 载荷：完全复用 B1/C2/B5 的加密运输机制（pack.Make / pack.MakeMAC）。
	// 密钥来自 payloadKey（与 B1 共享同一把，C1 启用时由 native 派生函数复算）；
	// PayloadMAC 打开时同样做 encrypt-then-MAC，域内名字固定为 "B6.vmp"。
	key, err := payloadKey(art, opts)
	if err != nil {
		return fmt.Errorf("B6 解析载荷密钥失败: %w", err)
	}
	one := []pack.Dex{{Name: "B6.vmp", Data: plain}}
	var payloads []pack.Payload
	if opts.PayloadMAC {
		payloads, err = pack.MakeMAC(one, key, opts.Seed)
	} else {
		payloads, err = pack.Make(one, key, opts.Seed)
	}
	if err != nil {
		return fmt.Errorf("B6 生成加密载荷失败: %w", err)
	}
	item := payloads[0]

	asset := item.Asset
	if opts.IsEnabled("B8") {
		// B8 只搬迁它自己清单里的载荷（B1/C2 的），不会动 B6 的条目。
		// 为避免顶层 assets 直接暴露载荷、也为了让产物通过 B8 的顶层不变量，
		// B6 直接按 B8 的容器派生规则落进同一目录树。派生公式与
		// container.go 保持一致（有测试对拍两者的目录）。
		asset = vmpContainerName(opts.Seed)
	}
	for i := 1; pipeline.Find(art, asset) != nil; i++ {
		asset = vmpContainerName(opts.Seed + fmt.Sprint(i))
	}
	pipeline.Add(art, zipx.NewStored(asset, item.Blob))

	sum.Selected = len(progs)
	sum.Plain = len(plain)
	sum.Blob = len(item.Blob)
	sum.Payload = asset
	for _, p := range progs {
		sum.Methods = append(sum.Methods, p.Sig())
	}
	art.Put(sharedKeyVMP, &sum)

	art.Stat("B6.candidates", fmt.Sprint(sum.Candidates))
	art.Stat("B6.selected", fmt.Sprint(sum.Selected))
	art.Stat("B6.dex", fmt.Sprint(sum.DexCount))
	art.Stat("B6.plain", fmt.Sprint(sum.Plain))
	art.Stat("B6.blob", fmt.Sprint(sum.Blob))
	art.Stat("B6.payload", asset)
	for k, n := range sum.Skip {
		art.Stat("B6.skip."+k, fmt.Sprint(n))
	}
	if sum.Unparsable > 0 {
		art.Note("B6 提示：%d 个 .dex 条目解析失败、未参与扫描（预期为 A9/A16 的伪装文件）", sum.Unparsable)
	}
	art.Note("B6 VMP 虚拟化：%d 个方法体已翻译为私有定长字节码（候选 %d 个，跳过明细：%s）；"+
		"私有载荷 %d 字节（明文 %d）按 B1 同款 AES-256-CBC%s 加密写入 %s；示例方法：%s",
		sum.Selected, sum.Candidates, reasonReport(sum.Skip),
		sum.Blob, sum.Plain, macSuffix(opts.PayloadMAC), asset,
		sampleMethods(sum.Methods, 5))
	// 如实说明当前未接线，避免「启用即受保护」的误解。
	art.Note("B6 当前为最小子集：仅完成「翻译 + 私有字节码 + native 解释器（宿主自测）+ 对拍」；" +
		"DEX 尚未把被选中方法改写为 ACC_NATIVE/桥接 stub、壳 Loader 也尚未调用 VM 注册与执行接口，" +
		"因此本产物中被选中方法仍以原始 Dalvik 指令执行，私有载荷当前不提供实际防护（接线见后续切片）")
	return nil
}

// vmpContainerName 按 B8 的容器派生规则为 B6 载荷生成条目名。
//
// 与 container.go 的 payloadContainer.Run 使用同一组常量与公式：
//   - 目录树 = assets/<词>/<seed 派生的 8 位 hex>/
//   - 文件名 = <12 位 hex>.<容器扩展名>
//
// B8 尚未把 B6 载荷纳入自己的搬迁清单，因此这里必须自行派生；测试会跑一遍
// B8 并断言两者落在同一目录树，防止公式漂移导致顶层暴露载荷。
func vmpContainerName(seed string) string {
	sum := sha256.Sum256([]byte("apkguard/container/" + seed))
	seg1 := containerWords[int(sum[0])%len(containerWords)]
	seg2 := hex.EncodeToString(sum[1:5])
	d := sha256.Sum256([]byte("apkguard/container/vmp/" + seed))
	ext := containerExts[int(d[6])%len(containerExts)]
	return fmt.Sprintf("assets/%s/%s/%s.%s", seg1, seg2, hex.EncodeToString(d[:6]), ext)
}

// reasonReport 把跳过原因聚合渲染为可读文本（数量降序，同数量按原因字典序）。
func reasonReport(skip map[string]int) string {
	type kv struct {
		k string
		n int
	}
	out := make([]kv, 0, len(skip))
	for k, n := range skip {
		out = append(out, kv{k, n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].n != out[j].n {
			return out[i].n > out[j].n
		}
		return out[i].k < out[j].k
	})
	rep := ""
	for i, e := range out {
		if i > 0 {
			rep += "；"
		}
		rep += fmt.Sprintf("%s×%d", e.k, e.n)
	}
	if rep == "" {
		rep = "无"
	}
	return rep
}

// macSuffix 返回载荷加密方式的报告后缀。
func macSuffix(withMAC bool) string {
	if withMAC {
		return " + HMAC-SHA256"
	}
	return ""
}

// sampleMethods 返回前 n 个方法签名的摘要。
func sampleMethods(ms []string, n int) string {
	if len(ms) <= n {
		return strings.Join(ms, "、")
	}
	return strings.Join(ms[:n], "、") + "…"
}
