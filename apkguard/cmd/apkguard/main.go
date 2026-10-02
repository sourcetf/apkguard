// Command apkguard 是一个纯 Go 实现的 APK 加固工具。
//
// 支持两种使用方式：
//   - CLI：命令行开关逐项启用功能
//   - Web：-web 启动内嵌 Web UI，用复选框按需勾选
//
// 不依赖 JDK、apksigner 或任何外部进程。
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"apkguard/internal/config"
	"apkguard/internal/passes"
	"apkguard/internal/pipeline"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		os.Exit(1)
	}
}

type cliConfig struct {
	in  string
	out string

	ksPath  string
	ksPass  string
	keyPass string
	ksType  string
	alias   string
	noV1    bool
	noV2    bool
	noV3    bool
	withV4  bool
	minSDK  uint
	maxSDK  uint

	enable  string
	disable string
	list    bool
	web     bool
	addr    string

	// 功能项参数
	namePrefix    string
	packageShrink bool
	keepRules     string
	obfStringMin  int
	seed          string
	fakeDexCount  int
	fakeDexSize   int
	junkTopCount  int
	junkDirCount  int
	junkDirDepth  int
	junkMetaCount int
	zipAtkCount   int
	classPadCount int
	stampTime     string
	manifestPadMB int

	dexKey           string
	decoyPkg         string
	decoyCoreCount   int
	decoyAPKMB       int
	decoyMetaCount   int
	strJunkCount     int
	junkInsnCount    int
	libFakeName      string
	libStripSections bool
	payloadMAC       bool
	soEncrypt        bool
	shellPkg         string
	splitCount       int
	extractRatio     int
	debugShell       bool

	channels string
	jobs     int
	sigHash  string
	bindDev  string
}

func run() error {
	var c cliConfig

	flag.StringVar(&c.in, "in", "", "输入 APK 路径")
	flag.StringVar(&c.out, "out", "", "输出 APK 路径（默认 <输入名>-protected.apk）")

	flag.StringVar(&c.ksPath, "ks", "", "密钥库路径（.jks / .pfx / .p12）")
	flag.StringVar(&c.ksPass, "ks-pass", "", "密钥库口令")
	flag.StringVar(&c.keyPass, "key-pass", "", "私钥口令（默认同密钥库口令）")
	flag.StringVar(&c.ksType, "ks-type", "", "密钥库类型：jks / pkcs12（默认自动探测）")
	flag.StringVar(&c.alias, "alias", "", "JKS 条目别名（默认取第一个私钥条目）")
	flag.BoolVar(&c.noV1, "no-v1", false, "禁用 v1 (JAR) 签名")
	flag.BoolVar(&c.noV2, "no-v2", false, "禁用 v2 签名")
	flag.BoolVar(&c.noV3, "no-v3", false, "禁用 v3 签名")
	flag.BoolVar(&c.withV4, "v4", false, "额外生成 v4 签名文件（.idsig）")
	flag.UintVar(&c.minSDK, "min-sdk", 24, "v3 签名块中的 minSdkVersion")
	flag.UintVar(&c.maxSDK, "max-sdk", 0x7fffffff, "v3 签名块中的 maxSdkVersion")

	flag.StringVar(&c.enable, "enable", "", "启用功能项，逗号分隔（如 A1,A2,A4,E1）")
	flag.StringVar(&c.disable, "disable", "", "禁用功能项，逗号分隔")
	flag.BoolVar(&c.list, "list", false, "列出全部功能项后退出")
	flag.BoolVar(&c.web, "web", false, "启动内嵌 Web UI")
	flag.StringVar(&c.addr, "addr", "127.0.0.1:8787", "Web UI 监听地址")

	flag.StringVar(&c.namePrefix, "name-prefix", "", "A1 混淆后名称前缀")
	flag.BoolVar(&c.packageShrink, "package-shrink", false, "A1 把每个原包整体映射为无意义短包名（隐藏包结构线索，保持同包 package-private 访问）")
	flag.StringVar(&c.keepRules, "keep-rules", "", "A1 保留白名单文件（每行一条，支持 * 通配）")
	flag.IntVar(&c.obfStringMin, "obf-string-min", 0, "A2 仅加密长度不小于该值的字符串")
	flag.StringVar(&c.seed, "seed", "", "随机种子（留空则每次随机）")
	flag.IntVar(&c.fakeDexCount, "fake-dex-count", 1, "A9 伪 DEX 块数量")
	flag.IntVar(&c.fakeDexSize, "fake-dex-size", 80000, "A9 每块字节数")
	flag.IntVar(&c.junkTopCount, "junk-top-count", 800, "A10 非 ASCII 顶层文件数（默认对齐参考样本的 884）")
	flag.IntVar(&c.junkDirCount, "junk-dir-count", 400, "A10 随机深目录条目数（每 10 条附带 1 条 64KB 同名深路径，是体积主要来源）")
	flag.IntVar(&c.junkDirDepth, "junk-dir-depth", 16, "A10 深目录最大层数")
	flag.IntVar(&c.junkMetaCount, "junk-meta-count", 20, "A10 畸形 META-INF 条目数")
	flag.IntVar(&c.zipAtkCount, "zip-atk-count", 150, "A12 路径攻击条目数（轮转分给 5 类前缀，故 150 约等于每类 30 条）")
	flag.IntVar(&c.classPadCount, "class-pad-count", 100, "A13 膨胀类数量")
	flag.StringVar(&c.stampTime, "stamp-time", "", "A14 统一时间戳（RFC3339，留空用固定值）")
	flag.IntVar(&c.manifestPadMB, "manifest-pad-mb", 0, "A15 巨型 Manifest 填充量（MB，0=用默认 100）")
	flag.IntVar(&c.decoyCoreCount, "decoy-core-count", 0, "A16 假核心文件组数（0=用默认）")
	flag.IntVar(&c.decoyAPKMB, "decoy-apk-mb", 0, "A17 假内层 APK 体积（MB，0=用默认）")
	flag.IntVar(&c.decoyMetaCount, "decoy-meta-count", 0, "A18 假权限/元数据条数（0=用默认）")
	flag.IntVar(&c.strJunkCount, "str-junk-count", 0, "A19 每个 DEX 注入的垃圾字符串条数（0=用默认）")
	flag.IntVar(&c.junkInsnCount, "junk-insn-count", 0, "A20 每个方法插入的花指令组数（0=用默认）")
	flag.StringVar(&c.libFakeName, "lib-name", "", "C7 把守卫库改成的新名字（如 libsqlite3x.so）")
	flag.BoolVar(&c.libStripSections, "lib-strip-sections", false, "C7 清除守卫库的 ELF 节头（readelf -S 会失败，不影响加载）")

	flag.StringVar(&c.dexKey, "dex-key", "", "B1 加密密钥（留空自动生成）")
	flag.StringVar(&c.decoyPkg, "decoy-pkg", "", "B8 诱饵配置里的假包名（留空用默认 dummy.installed.check）")
	flag.BoolVar(&c.payloadMAC, "payload-mac", false, "B1 密文附加 HMAC-SHA256，壳解密前先校验（纵深防御）")
	flag.BoolVar(&c.soEncrypt, "so-encrypt", false, "C2 原生库整体加密存 assets，启动时解密到私有目录再加载")
	flag.StringVar(&c.shellPkg, "shell-pkg", "com.apkguard.shell", "B2/B3 壳类所在包名")
	flag.IntVar(&c.splitCount, "split-count", 0, "B4 拆分 DEX 个数（0=按原样）")
	flag.IntVar(&c.extractRatio, "extract-ratio", 0, "B5 抽取方法比例（1~100）")
	flag.BoolVar(&c.debugShell, "debug-shell", false, "排障：壳启动时逐步弹 Toast 报告进度（含 ClassLoader 接管回读校验）")

	flag.StringVar(&c.sigHash, "sig-hash", "", "D1 签名证书的 SHA-256（十六进制；留空则取密钥库中的证书）")
	flag.StringVar(&c.bindDev, "bind-device", "", "D5 绑定的设备标识：用 -debug-shell 出排障版，在目标设备上跑一次，从 adb logcat -s APKGUARD-D5 读取（Android 8+ 的 ANDROID_ID 按应用签名作用域化，settings get secure android_id 取到的是原始值，不是应用看到的那个）")
	flag.StringVar(&c.channels, "channels", "", "E4 渠道列表，逗号分隔")
	flag.IntVar(&c.jobs, "jobs", 0, "E5 并发数（0=CPU 核数）")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "apkguard —— 纯 Go APK 加固工具\n\n")
		fmt.Fprintf(os.Stderr, "用法:\n")
		fmt.Fprintf(os.Stderr, "  apkguard -list                                    列出全部功能项\n")
		fmt.Fprintf(os.Stderr, "  apkguard -web                                     启动 Web UI\n")
		fmt.Fprintf(os.Stderr, "  apkguard -in app.apk -ks key.jks -ks-pass <口令>  加固并签名\n")
		fmt.Fprintf(os.Stderr, "      [-enable A1,A2,A4] [-disable B3] [选项]\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	// 无任何参数时进入图形界面：这是双击 exe 的场景。
	//
	// 双击时若只打印用法就退出，用户看到的是「窗口一闪而过」，既不知道
	// 有 GUI，也不知道该怎么用。改成直接起界面并自动打开浏览器。
	if len(os.Args) == 1 {
		fmt.Println("apkguard —— 正在启动图形界面…")
		fmt.Println("若浏览器未自动打开，请手动访问下方地址（Ctrl+C 退出）")
		return serveWeb(c.addr, true)
	}

	if c.list {
		printFeatures()
		return nil
	}
	if c.web {
		return serveWeb(c.addr, true)
	}

	opts, err := buildOptions(c)
	if err != nil {
		return err
	}
	// E5 批量处理：-in 指向目录时逐个子项加固。
	//
	// 必须显式启用 E5：目录输入意味着「一次产出多个包」，与单文件语义差别
	// 很大（输出路径怎么定、失败如何汇总），静默接受容易让人误操作整目录。
	if fi, err := os.Stat(opts.In); err == nil && fi.IsDir() {
		if !opts.IsEnabled("E5") {
			return fmt.Errorf("%s 是目录：批量处理需要显式启用 E5（-enable E5）", opts.In)
		}
		return runBatch(opts, c.jobs)
	}
	// E4 多渠道：每个渠道单独走一遍「写入 → 对齐 → 签名」，产出多个 APK。
	if opts.IsEnabled("E4") && len(opts.Channels) > 0 {
		if opts.Out == "" {
			ext := filepath.Ext(opts.In)
			opts.Out = strings.TrimSuffix(opts.In, ext) + "-protected" + ext
		}
		return runChannels(opts)
	}
	return runOnce(opts)
}

// runChannels 逐个渠道产出已签名 APK。
//
// 必须逐个跑完整流程而不能「签一次再改文件」：v2/v3 签名覆盖整个文件，
// 签完再插入渠道信息会让签名立刻失效。
func runChannels(opts *config.Options) error {
	ext := filepath.Ext(opts.Out)
	base := strings.TrimSuffix(opts.Out, ext)
	for _, ch := range opts.Channels {
		child := *opts
		child.Channels = []string{ch}
		child.Out = base + "-" + sanitizeChannel(ch) + ext
		fmt.Printf("渠道 %s -> %s\n", ch, child.Out)
		if err := runOnce(&child); err != nil {
			return fmt.Errorf("渠道 %s 产出失败: %w", ch, err)
		}
	}
	return nil
}

// sanitizeChannel 把渠道名规整为可安全用于文件名的形式。
func sanitizeChannel(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
	}
	if len(out) == 0 {
		return "channel"
	}
	return string(out)
}

// quietMode 为 true 时抑制单次加固的详细输出（批量模式下由汇总代替）。
var quietMode bool

// runBatch 并发加固目录下的全部 APK。
//
// 并发度默认取 CPU 核数：单个 APK 的加固主要是 CPU 密集（DEX 解析与重建），
// 按核数并行即可跑满，再高只会加剧内存压力（每个任务都会把整个 APK 读进内存）。
func runBatch(opts *config.Options, jobs int) error {
	names, err := listAPKs(opts.In)
	if err != nil {
		return err
	}
	if len(names) == 0 {
		return fmt.Errorf("目录 %s 下没有找到 .apk 文件", opts.In)
	}
	if jobs <= 0 {
		jobs = runtime.NumCPU()
	}
	if jobs > len(names) {
		jobs = len(names)
	}
	if opts.Out != "" {
		if err := os.MkdirAll(opts.Out, 0o755); err != nil {
			return fmt.Errorf("创建输出目录失败: %w", err)
		}
	}
	fmt.Printf("批量加固：%s 下 %d 个 APK，并发 %d\n", opts.In, len(names), jobs)

	type outcome struct {
		name string
		out  string
		err  error
	}
	// 统一在派发前打开静默：并发任务各自写全局变量是数据竞争。
	quietMode = true
	results := make([]outcome, len(names))
	sem := make(chan struct{}, jobs)
	var wg sync.WaitGroup
	for i, name := range names {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, name string) {
			defer wg.Done()
			defer func() { <-sem }()
			// 每个任务一份独立配置副本：路径不同，其余共享（只读）。
			child := *opts
			child.In = filepath.Join(opts.In, name)
			child.Out = batchOutputPath(opts.Out, child.In, opts.In)
			results[i] = outcome{name: name, out: child.Out, err: runOnce(&child)}
		}(i, name)
	}
	wg.Wait()

	okN, failN := 0, 0
	for _, r := range results {
		if r.err != nil {
			failN++
			fmt.Fprintf(os.Stderr, "  失败 %s: %v\n", r.name, r.err)
			continue
		}
		okN++
		fmt.Printf("  完成 %s -> %s\n", r.name, r.out)
	}
	fmt.Printf("批量加固结束：成功 %d，失败 %d\n", okN, failN)
	if failN > 0 {
		return fmt.Errorf("%d 个文件加固失败", failN)
	}
	return nil
}

// listAPKs 列出目录下的 .apk 文件（不递归）。
//
// 跳过本工具自己的产物（*-protected.apk），避免「跑两次目录」时把上次的
// 结果再加固一遍——那既浪费时间，也会产生层层套壳的产物。
func listAPKs(dir string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("读取目录失败: %w", err)
	}
	var names []string
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if !strings.HasSuffix(strings.ToLower(n), ".apk") {
			continue
		}
		if strings.HasSuffix(n, "-protected.apk") {
			continue
		}
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}

// batchOutputPath 计算批量模式下单个产物的输出路径。
//
// outDir 为空时与输入同目录；outDir 非空时必须是一个目录。
func batchOutputPath(outDir, in, srcDir string) string {
	base := strings.TrimSuffix(filepath.Base(in), filepath.Ext(in)) + "-protected.apk"
	if outDir == "" {
		return filepath.Join(srcDir, base)
	}
	return filepath.Join(outDir, base)
}

// buildOptions 把 CLI 参数转换为配置对象。
func buildOptions(c cliConfig) (*config.Options, error) {
	opts := &config.Options{
		Enabled: map[config.FeatureID]bool{},
		In:      c.in,
		Out:     c.out,
		KS:      c.ksPath,
		KSPass:  c.ksPass,
		KeyPass: c.keyPass,
		KSType:  c.ksType,
		Alias:   c.alias,
		NoV1:    c.noV1,
		NoV2:    c.noV2,
		NoV3:    c.noV3,
		V4:      c.withV4,
		MinSDK:  c.minSDK,
		MaxSDK:  c.maxSDK,

		NamePrefix:    c.namePrefix,
		PackageShrink: c.packageShrink,
		ObfStringMin:  c.obfStringMin,
		Seed:          c.seed,
		FakeDexCount:  c.fakeDexCount,
		FakeDexSize:   c.fakeDexSize,
		JunkTopCount:  c.junkTopCount,
		JunkDirCount:  c.junkDirCount,
		JunkDirDepth:  c.junkDirDepth,
		JunkMetaCount: c.junkMetaCount,
		ZipAtkCount:   c.zipAtkCount,
		ClassPadCount: c.classPadCount,
		StampTime:     c.stampTime,
		ManifestPadMB: c.manifestPadMB,

		DexKey:           c.dexKey,
		DecoyPkg:         c.decoyPkg,
		DecoyCoreCount:   c.decoyCoreCount,
		DecoyAPKMB:       c.decoyAPKMB,
		DecoyMetaCount:   c.decoyMetaCount,
		StrJunkCount:     c.strJunkCount,
		JunkInsnCount:    c.junkInsnCount,
		LibFakeName:      c.libFakeName,
		LibStripSections: c.libStripSections,
		PayloadMAC:       c.payloadMAC,
		SOEncrypt:        c.soEncrypt,
		ShellPkg:         c.shellPkg,
		SplitCount:       c.splitCount,
		ExtractRatio:     c.extractRatio,
		DebugShell:       c.debugShell,

		Jobs: c.jobs,
	}
	if c.sigHash != "" {
		opts.SigHashes = []string{c.sigHash}
	}
	opts.BindDevice = c.bindDev

	// 默认：先把所有功能项设为默认值，再按 -enable / -disable 覆盖。
	for _, f := range config.All() {
		opts.Enabled[f.ID] = f.Default
	}
	if err := applyFeatureList(opts, c.enable, true); err != nil {
		return nil, err
	}
	if err := applyFeatureList(opts, c.disable, false); err != nil {
		return nil, err
	}

	if c.keepRules != "" {
		data, err := os.ReadFile(c.keepRules)
		if err != nil {
			return nil, fmt.Errorf("读取保留白名单失败: %w", err)
		}
		opts.KeepRules = string(data)
	}
	// -so-encrypt 是 C2 的便捷开关：它等价于把 C2 加进启用集合。
	//
	// 不能让两者各自独立——Pass 只在 C2 被启用时才会跑，只设置 Options.SOEncrypt
	// 会得到一个「开关打开了但什么都没发生」的静默空操作，正是本项目最忌讳的失败模式。
	if c.soEncrypt {
		if opts.Enabled == nil {
			opts.Enabled = map[config.FeatureID]bool{}
		}
		opts.Enabled["C2"] = true
	}

	if c.channels != "" {
		for _, ch := range strings.Split(c.channels, ",") {
			if ch = strings.TrimSpace(ch); ch != "" {
				opts.Channels = append(opts.Channels, ch)
			}
		}
	}
	return opts, nil
}

// applyFeatureList 解析逗号分隔的功能项列表并设置启用状态。
func applyFeatureList(opts *config.Options, list string, on bool) error {
	if strings.TrimSpace(list) == "" {
		return nil
	}
	byID := config.ByID()
	for _, raw := range strings.Split(list, ",") {
		id := config.FeatureID(strings.ToUpper(strings.TrimSpace(raw)))
		if id == "" {
			continue
		}
		if _, ok := byID[id]; !ok {
			return fmt.Errorf("未知功能项 %q（可用 -list 查看）", id)
		}
		opts.Enabled[id] = on
	}
	return nil
}

// runOnce 执行一次加固。
func runOnce(opts *config.Options) error {
	out := opts.Out
	if out == "" {
		ext := filepath.Ext(opts.In)
		out = strings.TrimSuffix(opts.In, ext) + "-protected" + ext
	}

	if !quietMode {
		fmt.Printf("输入: %s\n", opts.In)
	}
	var on []string
	for _, id := range opts.EnabledIDs() {
		on = append(on, string(id))
	}
	fmt.Printf("启用功能项: %s\n", strings.Join(on, ","))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	reg := passes.Registry()
	pipe := pipeline.New(reg, pipeline.DefaultSink{})
	res, err := pipe.Run(ctx, opts)
	if err != nil {
		return err
	}

	if dir := filepath.Dir(out); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("创建输出目录失败: %w", err)
		}
	}
	if err := os.WriteFile(out, res.APK, 0o644); err != nil {
		return fmt.Errorf("写出 APK 失败: %w", err)
	}
	// v4 的签名文件（.idsig）必须单独落盘：它是供增量安装使用的独立文件。
	// 不写出来则 `-v4` 只是「算了一遍就丢掉」，而 CLI 帮助文本承诺了会生成它。
	if len(res.IDSig) > 0 {
		p := out + ".idsig"
		if err := os.WriteFile(p, res.IDSig, 0o644); err != nil {
			return fmt.Errorf("写出 v4 签名文件失败: %w", err)
		}
		fmt.Printf("v4 签名文件: %s (%d 字节)\n", p, len(res.IDSig))
	}

	fmt.Printf("\n执行了 %d 个功能项，耗时 %s\n", len(res.Ran), res.Duration.Round(time.Millisecond))
	for _, n := range res.Notes {
		fmt.Printf("  - %s\n", n)
	}
	if len(res.Stats) > 0 {
		fmt.Println("统计:")
		for _, k := range sortedStatKeys(res.Stats) {
			fmt.Printf("  %s = %s\n", k, res.Stats[k])
		}
	}
	fmt.Printf("\n输出: %s (%d 字节)\n", out, len(res.APK))
	return nil
}

func sortedStatKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		v := out[i]
		j := i - 1
		for j >= 0 && out[j] > v {
			out[j+1] = out[j]
			j--
		}
		out[j+1] = v
	}
	return out
}

// printFeatures 打印全部功能项。
func printFeatures() {
	n := 0
	for _, f := range config.All() {
		if f.Implemented {
			n++
		}
	}
	fmt.Printf("共 %d 个功能项，其中已实现 %d 个（默认列为默认启用状态）：\n\n", len(config.All()), n)
	for _, g := range config.Groups() {
		fmt.Printf("【%s】\n", g.Name)
		for _, f := range g.Features {
			mark := "  "
			if f.Default {
				mark = "√ "
			}
			risk := ""
			if f.RiskCN == "危险区" {
				risk = " [危险区]"
			}
			// 未实现的功能项必须一眼可辨：启用它会被直接拒绝。
			impl := ""
			if !f.Implemented {
				impl = " 【尚未实现】"
			}
			fmt.Printf("  %s%-4s %-22s %s%s%s\n", mark, f.ID, f.Name, f.StageCN, risk, impl)
			fmt.Printf("        %s\n", f.Desc)
		}
		fmt.Println()
	}
	fmt.Println("提示：启用【尚未实现】的功能项会被拒绝，以免静默地少做防护。")
}
