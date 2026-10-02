package passes

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/native"
	"apkguard/internal/pipeline"
	"apkguard/internal/zipx"
)

// ---- C7 原生库伪装 ----
//
// 背景：C1/C4/C5/C6/D4 共用同一份 libapkguard.so。库名本身就是「这是加固
// 产物」的强信号——`unzip -l` 一眼可见，`strings libapkguard.so` 还能读到
// C1/C4 的字符串与 .agexpect 摘要。C7 做两件纯静态、无运行时代价的事：
//
//  1. 把产物里 lib/<abi>/libapkguard.so 改名为常见库名（默认 libsqlite3x.so），
//     并同步改写壳 DEX 里 System.loadLibrary 的实参，否则运行时加载不到；
//  2. 可选地清除 ELF 节头（e_shoff/e_shnum/e_shstrndx 等），让 readelf -S /
//     objdump -h 等静态工具失败。dlopen 只用 program header，因此加载不受影响。
//
// 只作用于工具自己注入的 libapkguard.so，绝不触碰用户应用自带的 .so。
//
// 与 C2 的顺序：C2（SO 加密）靠**原始文件名 libapkguard.so** 识别并跳过守卫
// 库（见 soenc.go：base == native.LibFileName 才 continue）。因此 C7 必须在
// C2 之后执行：若 C7 先改名，C2 会把改名后的守卫库当成业务库加密搬进
// assets，壳就再也 loadLibrary 不到了。C7 同时必须在 C1 之后（要改写 C1
// 注入的壳 DEX 字符串）。见 Registry 里推荐注册位置。
type libDisguise struct{}

func (libDisguise) ID() config.FeatureID { return "C7" }
func (libDisguise) In() pipeline.Level   { return pipeline.LevelZip }
func (libDisguise) Out() pipeline.Level  { return pipeline.LevelZip }

// defaultLibFakeName 是未指定 -lib-name 时使用的默认假名。
//
// 选 sqlite3x 这类「常见但非系统核心」的库名：分析者第一眼不会怀疑它，
// 又不像 libc.so 那样被系统预加载而可能引发混淆。派生出的 loadLibrary
// 实参为 "sqlite3x"（去掉 lib 前缀与 .so 后缀）。
const defaultLibFakeName = "libsqlite3x.so"

func (d *libDisguise) Run(_ context.Context, art *pipeline.Artifact, opts *config.Options) error {
	// 与 C2 的开关处理保持一致：功能项未启用且两个选项都没设时，直接留痕返回，
	// 保证「未启用时零副作用」。任一选项显式置位也视为要求执行（便于单测/脚本
	// 在不打开功能项开关的情况下单独验证）。
	// ---- 削节头：已废弃并显式拒绝 ----
	//
	// 曾实现过「把 ELF 节头表置 0，让 readelf -S / objdump -h 失败」。实测证明
	// 这条路在 Android 上行不通，且成本很高：
	//
	//  1. **动态链接器会校验节头表自洽性**。清零 e_shentsize 直接报
	//       UnsatisfiedLinkError: dlopen failed: ... has unsupported e_shentsize: 0x0 (expected 0x40)
	//     清零 e_shstrndx 报
	//       UnsatisfiedLinkError: dlopen failed: ... has invalid e_shstrndx
	//     （两条都在 RustDesk 上实测到。）也就是说"加载只用 program header、
	//     节头随便改"的假设不成立 —— 一改应用就装不上/起不来。
	//  2. 即便只清空 .shstrtab 的内容（能骗过链接器），**C6 的完整性校验也要靠
	//     节名**定位 .text/.rodata；节名读不出来，校验就只能失败关闭（拒绝启动）
	//     或失败开放（静默失效），两者都不比"不做"更好。
	//
	// 因此这里**显式拒绝**而不是静默忽略：静默忽略正是本项目最忌讳的失败模式
	// （用户以为拿到了额外防护）。伪装只保留"改名"这一档，它零风险且确实有效。
	if opts.LibStripSections {
		return fmt.Errorf("不支持清除 ELF 节头：Android 的动态链接器会校验节头表" +
			"（实测清零 e_shentsize/e_shstrndx 会让 dlopen 直接失败），且 C6 的完整性校验" +
			"依赖节名定位 .text/.rodata。请只用 -lib-name 做改名伪装")
	}

	if !opts.IsEnabled("C7") && opts.LibFakeName == "" && !opts.LibStripSections {
		art.Note("C7 原生库伪装：未启用（-enable C7 未置位，且未指定 -lib-name/-lib-strip-sections），未做任何改动")
		return nil
	}

	fakeFile, fakeLib, err := fakeLibNames(opts.LibFakeName)
	if err != nil {
		return err
	}

	// 只收集工具自己注入的守卫库：形如 lib/<abi>/libapkguard.so。
	// 用户应用的 .so 一概不动。
	type target struct {
		entry *zipx.Entry
		abi   string
	}
	var targets []target
	for _, e := range art.Entries() {
		n := e.NameString()
		if !strings.HasPrefix(n, "lib/") || !strings.HasSuffix(n, "/"+native.LibFileName) {
			continue
		}
		parts := strings.Split(n, "/")
		if len(parts) != 3 {
			continue
		}
		targets = append(targets, target{entry: e, abi: parts[1]})
	}
	if len(targets) == 0 {
		art.Note("C7 原生库伪装：产物中没有 C1 注入的 %s，空操作（C7 依赖 C1）", native.LibFileName)
		art.Stat("C7.renamed", "0")
		return nil
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].abi < targets[j].abi })

	// 改名是否必要：显式把假名设成原名（libapkguard.so）时只做削节头。
	rename := fakeFile != native.LibFileName
	renamed := 0

	if rename {
		// 先整体做冲突检查，避免改到一半失败留下半成品。
		for _, t := range targets {
			newName := "lib/" + t.abi + "/" + fakeFile
			if other := pipeline.Find(art, newName); other != nil {
				return fmt.Errorf("C7 假库名 %s 与产物既有条目冲突（ABI %s）：请改用其它 -lib-name",
					newName, t.abi)
			}
		}
		// 同步改写壳 DEX 里 System.loadLibrary 的实参。
		//
		// 采用「改写已注入壳 DEX 字符串池」的路线（而非让 C7 排在 C1 之前传名）：
		// C1 是否启用由用户决定，C7 应能独立作用于任何已注入的守卫库；且 C1 注入
		// 的桥接类 <clinit> 里 ConstString("apkguard") 是字符串池中的一个值，
		// 用 dex.Rebuild 的 Rename（按值替换）即可让所有引用一致更新——字符串池
		// 去重保证只有一项被引用，不存在漏改某条指令的风险。
		if err := rewriteShellLibName(art, native.LibName, fakeLib); err != nil {
			return err
		}
		for _, t := range targets {
			t.entry.Name = []byte("lib/" + t.abi + "/" + fakeFile)
			renamed++
		}
	}

	abis := make([]string, 0, len(targets))
	for _, t := range targets {
		abis = append(abis, t.abi)
	}

	// 未改名时（用户把假名设成原名，或只削节头），统计与说明里应报告真实
	// 文件名，而不是默认假名——否则报告会与实际产物不一致。
	newFile := fakeFile
	if !rename {
		newFile = native.LibFileName
	}

	// 与 C6/D4 的关系：**改名是安全的**。
	//
	// native 侧原先靠「在 /proc/self/maps 里匹配字面文件名 libapkguard.so」定位自身，
	// 改名后就找不到，而那时"取不到就当作完整"（失败开放）会让 C6/D4 静默失效。
	// 现已改为用 dladdr 反查实际加载路径（与文件名无关），并把三处"取不到"
	// 统统改成**失败关闭**（返回不可信）。因此 C7 改名后 C6/D4 依然有效，
	// 两者可以同时启用。
	if opts.IsEnabled("C6") || opts.IsEnabled("D4") {
		art.Note("C7 与 C6/D4 同时启用：native 侧已用 dladdr 反查实际加载路径（与文件名无关），" +
			"改名后自校验仍有效")
	}

	art.Note("C7 原生库伪装：守卫库改名 %d 个 ABI（%s → %s）。"+
		"库名不再暴露加固器身份；壳侧的 loadLibrary 参数已同步改写，C6/D4 的自校验不受影响",
		renamed, native.LibFileName, newFile)
	art.Stat("C7.renamed", fmt.Sprint(renamed))
	art.Stat("C7.new_name", newFile)
	art.Stat("C7.abis", strings.Join(abis, ","))
	return nil
}

// fakeLibNames 把用户给出的假名规范化为 (APK 内文件名, loadLibrary 实参)。
//
// 接受 "libsqlite3x.so" / "sqlite3x.so" / "sqlite3x" 三种写法，统一产出
// 文件 "libsqlite3x.so"、实参 "sqlite3x"。之所以要规范化：Android 的
// System.loadLibrary("x") 只会去找 libx.so，若文件名与实参对不上，运行时
// 必然 UnsatisfiedLinkError。
func fakeLibNames(raw string) (file, lib string, err error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		name = defaultLibFakeName
	}
	if strings.ContainsAny(name, "/\\") {
		return "", "", fmt.Errorf("C7 假库名 %q 含路径分隔符，非法", raw)
	}
	base := strings.TrimSuffix(name, ".so")
	base = strings.TrimPrefix(base, "lib")
	if base == "" {
		return "", "", fmt.Errorf("C7 假库名 %q 无法解析出库名", raw)
	}
	// 只允许库名常见字符（与 libc++_shared.so 这类真实库名兼容）。
	for i := 0; i < len(base); i++ {
		c := base[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '_' || c == '.' || c == '+' || c == '-'
		if !ok {
			return "", "", fmt.Errorf("C7 假库名 %q 含非法字符 %q", raw, string(c))
		}
	}
	return "lib" + base + ".so", base, nil
}

// rewriteShellLibName 把壳 DEX 字符串池中值为 old 的字符串替换为 new。
//
// 壳 DEX 由 B2 注入、C1 往里加了桥接类；桥接类 <clinit> 里的
// System.loadLibrary 实参就是这个字符串。用 dex.Rebuild 的 Rename 按值
// 替换，字符串池去重保证所有引用一致更新。
func rewriteShellLibName(art *pipeline.Artifact, old, new string) error {
	info, _ := art.Get(sharedKeyShell).(*shellInfo)
	if info == nil || info.EntryName == "" {
		return fmt.Errorf("C7 需要 C1 先注入壳 DEX（未找到壳信息），无法同步 loadLibrary 库名")
	}
	entry := pipeline.Find(art, info.EntryName)
	if entry == nil {
		return fmt.Errorf("C7 未找到壳 DEX 条目 %s", info.EntryName)
	}
	data, err := entry.Data()
	if err != nil {
		return fmt.Errorf("读取壳 DEX 失败: %w", err)
	}
	f, err := dex.Parse(data)
	if err != nil {
		return fmt.Errorf("解析壳 DEX 失败: %w", err)
	}
	// 必须确认旧名确实存在：否则改名后的守卫库无人引用，运行时会
	// UnsatisfiedLinkError——这是「壳用旧名加载、产物里只有新名」的必崩组合，
	// 必须在加固阶段就报错，而不是留到设备上。
	strs, err := f.AllStrings()
	if err != nil {
		return fmt.Errorf("读取壳 DEX 字符串池失败: %w", err)
	}
	found := false
	for _, s := range strs {
		if s == old {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("C7 壳 DEX 中未找到 loadLibrary 库名 %q，无法与改名后的守卫库保持一致", old)
	}
	out, err := dex.Rebuild(f, dex.RebuildOptions{Rename: map[string]string{old: new}})
	if err != nil {
		return fmt.Errorf("改写壳 DEX 库名失败: %w", err)
	}
	if err := dex.Verify(out); err != nil {
		return fmt.Errorf("改写库名后壳 DEX 校验失败: %w", err)
	}
	if err := entry.SetData(out, !entry.IsStored()); err != nil {
		return fmt.Errorf("写回壳 DEX 失败: %w", err)
	}
	return nil
}
