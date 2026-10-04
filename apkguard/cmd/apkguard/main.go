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
	"crypto/rand"
	"encoding/hex"
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
	namePrefix         string
	packageShrink      bool
	keepRules          string
	renameResourceIDs  bool
	renameLibraries    bool
	obfStringMin       int
	obfStringSingleRef bool
	seed               string
	fakeDexCount       int
	fakeDexSize        int
	junkTopCount       int
	junkDirCount       int
	junkDirDepth       int
	junkMetaCount      int
	zipAtkCount        int
	classPadCount      int
	stampTime          string
	manifestPadMB      int

	dexKey           string
	decoyPkg         string
	decoyCoreCount   int
	decoyAPKMB       int
	decoyMetaCount   int
	strJunkCount     int
	junkInsnCount    int
	returnNops       bool
	libFakeName      string
	libStripSections bool
	zipLocalDecoy    bool
	payloadMAC       bool
	soEncrypt        bool
	shellPkg         string
	splitCount       int
	extractRatio     int
	debugShell       bool

	// 本轮新增：A1 库改名 / B9 双 APK / B5·B6·B7 方法数上限 / B7 NDK 路径
	dualAPK        bool
	extractMethods int
	vmpMethods     int
	dex2cMethods   int
	ndkPath        string

	channels string
	jobs     int
	sigHash  string
	bindDev  string
}

// registerFlags 注册全部 CLI 开关。
//
// 接收 FlagSet 而不是直接用全局 flag，是为了让测试能在独立 FlagSet 上
// 验证默认值——尤其是 -return-nops 的「默认开、显式 -return-nops=false 关」。
func registerFlags(fs *flag.FlagSet, c *cliConfig) {
	fs.StringVar(&c.in, "in", "", "输入 APK 路径")
	fs.StringVar(&c.out, "out", "", "输出 APK 路径（默认 <输入名>-protected.apk）")

	fs.StringVar(&c.ksPath, "ks", "", "密钥库路径（.jks / .pfx / .p12）")
	fs.StringVar(&c.ksPass, "ks-pass", "", "密钥库口令")
	fs.StringVar(&c.keyPass, "key-pass", "", "私钥口令（默认同密钥库口令）")
	fs.StringVar(&c.ksType, "ks-type", "", "密钥库类型：jks / pkcs12（默认自动探测）")
	fs.StringVar(&c.alias, "alias", "", "JKS 条目别名（默认取第一个私钥条目）")
	fs.BoolVar(&c.noV1, "no-v1", false, "禁用 v1 (JAR) 签名")
	fs.BoolVar(&c.noV2, "no-v2", false, "禁用 v2 签名")
	fs.BoolVar(&c.noV3, "no-v3", false, "禁用 v3 签名")
	fs.BoolVar(&c.withV4, "v4", false, "额外生成 v4 签名文件（.idsig）")
	fs.UintVar(&c.minSDK, "min-sdk", 24, "v3 签名块中的 minSdkVersion")
	fs.UintVar(&c.maxSDK, "max-sdk", 0x7fffffff, "v3 签名块中的 maxSdkVersion")

	fs.StringVar(&c.enable, "enable", "", "启用功能项，逗号分隔（如 A1,A2,A4,E1）")
	fs.StringVar(&c.disable, "disable", "", "禁用功能项，逗号分隔")
	fs.BoolVar(&c.list, "list", false, "列出全部功能项后退出")
	fs.BoolVar(&c.web, "web", false, "启动内嵌 Web UI")
	fs.StringVar(&c.addr, "addr", "127.0.0.1:8787", "Web UI 监听地址")

	fs.StringVar(&c.namePrefix, "name-prefix", "", "A1 混淆后名称前缀")
	fs.BoolVar(&c.packageShrink, "package-shrink", false, "A1 把每个原包整体映射为无意义短包名（隐藏包结构线索，保持同包 package-private 访问）")
	fs.StringVar(&c.keepRules, "keep-rules", "", "A1 保留白名单文件（每行一条，支持 * 通配）")
	fs.BoolVar(&c.renameResourceIDs, "rename-resource-ids", true,
		"A1 把 aapt 生成的资源 ID 类（R/R$Type）与字段一起改名，static_values 中的资源 ID 常量保持原样（对齐参考样本）。默认开启，用 -rename-resource-ids=false 关闭；应急可用环境变量 APKGUARD_KEEP_RCLASS_IDS=1 强制关闭")
	fs.BoolVar(&c.renameLibraries, "rename-libraries", false,
		"A1 把第三方库（androidx/Kotlin stdlib 等）也纳入改名。默认关闭：库代码改名可能破坏反射/序列化/ServiceLoader 等按类名查找的机制，开启前请用目标应用回归")
	fs.IntVar(&c.obfStringMin, "obf-string-min", 0, "A2 仅加密长度不小于该值的字符串")
	fs.BoolVar(&c.obfStringSingleRef, "obf-string-single-ref", false,
		"A2 只加密恰好被 1 条 const-string 引用的字符串（对齐参考样本的选择性加密分布；会降低保护强度：多引用串将留明文，仅为形态对齐，不建议常规使用）")
	fs.StringVar(&c.seed, "seed", "", "随机种子（留空则每次随机）")
	fs.IntVar(&c.fakeDexCount, "fake-dex-count", 1, "A9 伪 DEX 块数量")
	fs.IntVar(&c.fakeDexSize, "fake-dex-size", 80000, "A9 每块字节数")
	fs.IntVar(&c.junkTopCount, "junk-top-count", 800, "A10 非 ASCII 顶层文件数（默认对齐参考样本的 884）")
	fs.IntVar(&c.junkDirCount, "junk-dir-count", 400, "A10 随机深目录条目数（每 10 条附带 1 条 64KB 同名深路径，是体积主要来源）")
	fs.IntVar(&c.junkDirDepth, "junk-dir-depth", 16, "A10 深目录最大层数")
	fs.IntVar(&c.junkMetaCount, "junk-meta-count", 20, "A10 畸形 META-INF 条目数")
	fs.IntVar(&c.zipAtkCount, "zip-atk-count", 150, "A12 路径攻击条目数（轮转分给 5 类前缀，故 150 约等于每类 30 条）")
	fs.IntVar(&c.classPadCount, "class-pad-count", 100, "A13 膨胀类数量")
	fs.StringVar(&c.stampTime, "stamp-time", "", "A14 统一时间戳（RFC3339，留空用固定值）")
	fs.IntVar(&c.manifestPadMB, "manifest-pad-mb", 0, "A15 巨型 Manifest 填充量（MB，0=用默认 100，上限 1024）")
	fs.IntVar(&c.decoyCoreCount, "decoy-core-count", 0, "A16 假核心文件组数（0=用默认）")
	fs.IntVar(&c.decoyAPKMB, "decoy-apk-mb", 0, "A17 假内层 APK 体积（MB，0=用默认）")
	fs.IntVar(&c.decoyMetaCount, "decoy-meta-count", 0, "A18 假权限/元数据条数（0=用默认）")
	fs.IntVar(&c.strJunkCount, "str-junk-count", 0, "A19 每个 DEX 注入的垃圾字符串条数（0=用默认）")
	fs.IntVar(&c.junkInsnCount, "junk-insn-count", 0, "A20 每个方法插入的花指令组数（0=用默认）")
	fs.BoolVar(&c.returnNops, "return-nops", true,
		"A20 在每条 return 前插入 1 条 nop（参考样本形态，全部单发、无连续段）。启用 A20 时默认开启，用 -return-nops=false 关闭")
	fs.StringVar(&c.libFakeName, "lib-name", "", "C7 把守卫库改成的新名字（如 libsqlite3x.so）")
	fs.BoolVar(&c.libStripSections, "lib-strip-sections", false, "C7 清除守卫库的 ELF 节头（readelf -S 会失败，不影响加载）")
	fs.BoolVar(&c.zipLocalDecoy, "zip-local-decoy", false,
		"本地头假加密 flag：仅对 AndroidManifest.xml/classes*.dex/resources.arsc 在本地头写 bit0(加密)+bit6(强加密)，中央目录不变。依据：参考样本同款手法，在 Android 16/API 36 实测可正常安装启动，平台按中央目录读取不受影响；但本工具自己的产物尚未在真机验证，默认关闭，开启后请自行验证安装与启动")

	fs.StringVar(&c.dexKey, "dex-key", "", "B1 加密密钥（留空自动生成）")
	fs.StringVar(&c.decoyPkg, "decoy-pkg", "", "B8 诱饵配置里的假包名（留空用默认 dummy.installed.check）")
	fs.BoolVar(&c.payloadMAC, "payload-mac", false, "B1 的 DEX 载荷与 C2 的原生库载荷都附加 HMAC-SHA256，壳解密前先校验（纵深防御）")
	fs.BoolVar(&c.soEncrypt, "so-encrypt", false, "C2 原生库整体加密存 assets，启动时解密到私有目录再加载")
	fs.StringVar(&c.shellPkg, "shell-pkg", "com.apkguard.shell", "B2/B3 壳类所在包名")
	fs.IntVar(&c.splitCount, "split-count", 0, "B4 拆分 DEX 个数（0=按原样）")
	fs.IntVar(&c.extractRatio, "extract-ratio", 0, "B5 抽取方法比例（1~100；B5 的开关是 -extract-methods，本项只调节从候选中选取的比例）")
	fs.BoolVar(&c.dualAPK, "dual-apk", false,
		"B9 双 APK 投放器：产物是宿主，原应用整体加密为插件放进宿主 assets，运行时落地并调起系统安装器。默认关闭：需 REQUEST_INSTALL_PACKAGES，首次需用户在系统安装界面确认，且换包名无法覆盖升级原应用")
	fs.IntVar(&c.extractMethods, "extract-methods", 0, "B5 函数抽取的方法数上限，0=关闭；建议先用小值试（如 10~50）")
	fs.IntVar(&c.vmpMethods, "vmp-methods", 0, "B6 VMP 虚拟化的方法数上限，0=关闭；建议先用小值试")
	fs.IntVar(&c.dex2cMethods, "dex2c-methods", 0, "B7 Dex2C 转 C 的方法数上限，0=关闭；建议先用小值试")
	fs.StringVar(&c.ndkPath, "ndk-path", "", "B7 编译生成的 C 用到的 NDK 根目录（留空自动探测常见位置）")
	fs.BoolVar(&c.debugShell, "debug-shell", false, "排障：壳启动时逐步弹 Toast 报告进度（含 ClassLoader 接管回读校验）")

	fs.StringVar(&c.sigHash, "sig-hash", "", "D1 签名证书的 SHA-256（十六进制；留空则取密钥库中的证书）")
	fs.StringVar(&c.bindDev, "bind-device", "", "D5 绑定的设备标识：用 -debug-shell 出排障版，在目标设备上跑一次，从 adb logcat -s APKGUARD-D5 读取（Android 8+ 的 ANDROID_ID 按应用签名作用域化，settings get secure android_id 取到的是原始值，不是应用看到的那个）")
	fs.StringVar(&c.channels, "channels", "", "E4 渠道列表，逗号分隔")
	fs.IntVar(&c.jobs, "jobs", 0, "E5 并发数（0=CPU 核数）")
}

func run() error {
	var c cliConfig
	registerFlags(flag.CommandLine, &c)

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
	sanitized, err := sanitizeChannels(opts.Channels)
	if err != nil {
		return err
	}
	for i, ch := range opts.Channels {
		child := *opts
		child.Channels = []string{ch}
		child.Out = base + "-" + sanitized[i] + ext
		fmt.Printf("渠道 %s -> %s\n", ch, child.Out)
		if err := runOnce(&child); err != nil {
			return fmt.Errorf("渠道 %s 产出失败: %w", ch, err)
		}
	}
	return nil
}

// sanitizeChannels 清洗渠道名并检测碰撞。
//
// 清洗会把 / \ ? : 等非法字符统一替换为 _，因此 "a/b" 与 "a?b" 都会变成 "a_b"。
// 若不去重，后一个会静默覆盖前一个产物（同名文件），用户以为产出了两个渠道包。
// 原始名相同（"a,a"）同样属于配置错误。两种情况都明确报错，不做静默覆盖。
func sanitizeChannels(channels []string) ([]string, error) {
	seen := make(map[string]string, len(channels))
	out := make([]string, 0, len(channels))
	for _, ch := range channels {
		s := sanitizeChannel(ch)
		if prev, ok := seen[s]; ok {
			return nil, fmt.Errorf("渠道名清洗后重复：%q 与 %q 都映射为 %q，会互相覆盖；请改用不冲突的渠道名", prev, ch, s)
		}
		seen[s] = ch
		out = append(out, s)
	}
	return out, nil
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

// batchJobs 决定批量并发度：显式参数优先，其次 opts.Jobs，最后回退 CPU 核数。
//
// 单次加固主要是 CPU 密集（DEX 解析与重建），按核数并行即可跑满，再高只会
// 加剧内存压力（每个任务都会把整个 APK 读进内存）。
func batchJobs(opts *config.Options, jobs int) int {
	if jobs <= 0 {
		jobs = opts.Jobs
	}
	if jobs <= 0 {
		jobs = runtime.NumCPU()
	}
	return jobs
}

// runBatch 并发加固目录下的全部 APK。
//
// jobs<=0 时依次回退 opts.Jobs、CPU 核数（见 batchJobs）。
func runBatch(opts *config.Options, jobs int) error {
	names, err := listAPKs(opts.In)
	if err != nil {
		return err
	}
	if len(names) == 0 {
		return fmt.Errorf("目录 %s 下没有找到 .apk 文件", opts.In)
	}
	jobs = batchJobs(opts, jobs)
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
// seedOrRandom 返回用户指定的种子；未指定时生成随机种子。
//
// 帮助文本承诺「留空则每次随机」，但此前的实现只是把空串透传下去：载荷 IV、
// 载荷名、垃圾条目名等全部由 seed 派生，空串意味着**每次构建结果完全一致**，
// 攻击者拿到一个产物就能预判另一个。显式给 -seed 时才走可复现路径。
func seedOrRandom(seed string) string {
	if seed != "" {
		return seed
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand 失败属于环境级故障；退化为时间戳而非静默用空种子。
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

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

		NamePrefix:        c.namePrefix,
		PackageShrink:     c.packageShrink,
		RenameResourceIDs: c.renameResourceIDs,
		RenameLibraries:   c.renameLibraries,
		ObfStringMin:      c.obfStringMin,

		ObfStringSingleRefOnly: c.obfStringSingleRef,
		Seed:                   seedOrRandom(c.seed),
		FakeDexCount:           c.fakeDexCount,
		FakeDexSize:            c.fakeDexSize,
		JunkTopCount:           c.junkTopCount,
		JunkDirCount:           c.junkDirCount,
		JunkDirDepth:           c.junkDirDepth,
		JunkMetaCount:          c.junkMetaCount,
		ZipAtkCount:            c.zipAtkCount,
		ClassPadCount:          c.classPadCount,
		StampTime:              c.stampTime,
		ManifestPadMB:          c.manifestPadMB,

		DexKey:            c.dexKey,
		DecoyPkg:          c.decoyPkg,
		DecoyCoreCount:    c.decoyCoreCount,
		DecoyAPKMB:        c.decoyAPKMB,
		DecoyMetaCount:    c.decoyMetaCount,
		StrJunkCount:      c.strJunkCount,
		JunkInsnCount:     c.junkInsnCount,
		ReturnNops:        c.returnNops,
		LibFakeName:       c.libFakeName,
		LibStripSections:  c.libStripSections,
		ZipLocalFlagDecoy: c.zipLocalDecoy,
		PayloadMAC:        c.payloadMAC,
		SOEncrypt:         c.soEncrypt,
		ShellPkg:          c.shellPkg,
		SplitCount:        c.splitCount,
		ExtractRatio:      c.extractRatio,
		DebugShell:        c.debugShell,

		DualAPK:        c.dualAPK,
		ExtractMethods: c.extractMethods,
		VMPMethods:     c.vmpMethods,
		Dex2CMethods:   c.dex2cMethods,
		NDKPath:        c.ndkPath,

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
	fmt.Println("提示：本轮起全部功能项均已实现；若未来新增项带【尚未实现】标记，启用它会被拒绝，以免静默地少做防护。")
}
