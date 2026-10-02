package passes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"apkguard/internal/axml"
	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/keystore"
	"apkguard/internal/native"
	"apkguard/internal/pack"
	"apkguard/internal/pipeline"
	"apkguard/internal/zipx"
)

// ---- B2 Application 替换 ----

// sharedKeyShell 是「壳信息」在 Artifact 中的共享键。
//
// B2 写入，B3 读取：ClassLoader 接管需要把 Loader 类注入到 B2 建好的
// 那个壳 DEX 里，必须知道条目名与壳类名。
const sharedKeyShell = "B2.shell"

// FrameworkComponentFactory 是框架自带的 AppComponentFactory 实现。
//
// 壳会把 Manifest 的 android:appComponentFactory 指向它：原工厂类（通常是
// androidx.core.app.CoreComponentFactory）随业务代码一起进了加密载荷，
// 而系统在壳接管 ClassLoader **之前**就要实例化这个工厂，那时它不可见。
const FrameworkComponentFactory = "android.app.AppComponentFactory"

// shellInfo 是 B2 交给 B3/D1 的壳信息。
type shellInfo struct {
	// Class 是壳 Application 的类描述符（如 "Lcom/x/App;"）。
	Class string
	// JavaName 是壳 Application 的 Java 点分名，Manifest 里写的就是它。
	JavaName string
	// LoaderClass 是 Loader 类的描述符；B3 未启用时为空。
	LoaderClass string
	// Checks 是各运行时检测的类描述符，键为功能项 ID（D1/D2/D3…），
	// 供各自的 Pass 找回自己要注入的那个类名。
	Checks map[string]string
	// CheckOrder 是检测类的调用顺序（元素为类描述符）。
	CheckOrder []string
	// EntryName 是壳 DEX 在 APK 中的条目名。
	EntryName string
	// OrigJavaName 是原 Manifest 声明的 Application 类名（已解析为完整类名）。
	OrigJavaName string
}

// appReplace 把 Manifest 的 android:name 指向壳 Application，并注入壳 DEX。
//
// 这是加壳的前提：系统在创建任何组件之前会先实例化 Application，
// 壳因此获得最早执行时机，可以在此之前完成解密与环境检测。
//
// 壳类一律继承框架的 android.app.Application（而不是原 Application 类）：
// B1 会把原始 DEX 整体加密移除，壳被系统加载时原类尚不存在，
// 静态继承它会在类加载阶段直接失败。
type appReplace struct{}

func (appReplace) ID() config.FeatureID { return "B2" }
func (appReplace) In() pipeline.Level   { return pipeline.LevelZip }
func (appReplace) Out() pipeline.Level  { return pipeline.LevelZip }

func (a *appReplace) Run(_ context.Context, art *pipeline.Artifact, opts *config.Options) error {
	entry := pipeline.Find(art, "AndroidManifest.xml")
	if entry == nil {
		return fmt.Errorf("未找到 AndroidManifest.xml")
	}
	data, err := entry.Data()
	if err != nil {
		return fmt.Errorf("读取 AndroidManifest.xml 失败: %w", err)
	}
	mf, err := axml.Parse(data)
	if err != nil {
		return fmt.Errorf("解析 AndroidManifest.xml 失败: %w", err)
	}
	app := mf.FindElement("application")
	if app == nil {
		return fmt.Errorf("Manifest 中没有 <application> 元素")
	}

	// 原 Application 类名可能是相对名（".MyApp" 或 "MyApp"），
	// 按 Android 约定相对 Manifest 的 package 解析。
	pkg := mf.FindElement("manifest").AttrString("package")
	origRaw := app.AttrString("name")
	origName := resolveAppName(pkg, origRaw)

	pkgSlash := shellPkgOf(opts)
	sh := &ShellAppRef{
		Class: "L" + pkgSlash + "/App;",
		Orig:  origName,
		Debug: opts.DebugShell,
	}
	// Loader 非空表示壳还要负责解密载荷与接管 ClassLoader。
	// 这里只填类名：Loader 的类体由 B3 注入，B2 只生成对它的调用。
	loaderClass := ""
	if opts.IsEnabled("B3") {
		loaderClass = "L" + pkgSlash + "/Loader;"
		sh.LoaderClass = loaderClass
	}
	// C1 生效时载荷密钥不在 DEX 里，改由桥接类在运行时向 native 索取。
	if opts.IsEnabled("C1") {
		sh.NativeKey = dex.NativeBridgeClass
	}
	// 运行时检测类同理：类体由各自的 Pass 注入，B2 只生成调用。
	//
	// 顺序有讲究：签名校验最便宜且最能定性（重打包必然换签名），放最前；
	// Root/模拟器检测次之。任一判定异常都会终止进程，越早退出越省事。
	checks := map[string]string{}
	var checkOrder []string
	for _, d := range runtimeChecks(pkgSlash) {
		if !opts.IsEnabled(config.FeatureID(d.id)) {
			continue
		}
		checks[d.id] = d.class
		checkOrder = append(checkOrder, d.class)
	}
	// C4 走 native：壳只调用桥接类的 debugged()，由原生库判断。
	// 排在 Java 侧检测之后——native 调用要等 System.loadLibrary 完成
	// （由桥接类的 <clinit> 保证），放在最前面没有额外好处。
	// C4/C5/C6 都由同一个桥接类的 a(Context) 统一执行，因此调用清单里
	// 只能出现一次；但每个启用项都要在 checks 里留下自己的类名，
	// 否则对应 Pass 会找不到自己要注入的类。
	//
	// 这里用独立的布尔量记录「是否已登记调用」，不能用 checks["C4"] 之类
	// 的键去充当哨兵——那样在 C4 未启用、只有 C5 启用时会漏登记 C5。
	bridgeAdded := false
	for _, id := range []string{"C4", "C5", "C6", "D4"} {
		if !opts.IsEnabled(config.FeatureID(id)) {
			continue
		}
		checks[id] = dex.NativeBridgeClass
		if !bridgeAdded {
			checkOrder = append(checkOrder, dex.NativeBridgeClass)
			bridgeAdded = true
		}
	}
	sh.Checks = checkOrder

	add, err := dex.ShellAppAddition(sh.spec())
	if err != nil {
		return err
	}
	// 壳放到哪个 DEX，优先选择「并进主 DEX」。
	//
	// 多 DEX 的可见性依赖系统在安装/启动期把 classes*.dex 全部纳入应用的
	// ClassLoader；把壳单独放进 classes2.dex 会引入这个变量——一旦系统没
	// 加载第二个 DEX，Manifest 指向的壳类就根本不存在，表现为「一打开就退、
	// 连日志都没有」。并进 classes.dex 则没有这个不确定性。
	//
	// 只有主 DEX 不存在（B1 已把原始 DEX 全部移走）或并库失败（索引超界等）
	// 时才新建一个 DEX。
	var shellDex []byte
	name := ""
	merged := false
	if main := pipeline.Find(art, "classes.dex"); main != nil {
		if data, derr := main.Data(); derr == nil {
			if f, perr := dex.Parse(data); perr == nil {
				if out, rerr := dex.Rebuild(f, dex.RebuildOptions{Addition: &add}); rerr == nil {
					if verr := dex.Verify(out); verr == nil {
						if serr := main.SetData(out, true); serr == nil {
							merged = true
							name = "classes.dex"
							shellDex = out
						}
					}
				}
			}
		}
	}
	if !merged {
		var err error
		shellDex, err = dex.Build(add)
		if err != nil {
			return fmt.Errorf("生成壳 DEX 失败: %w", err)
		}
		if err := dex.Verify(shellDex); err != nil {
			return fmt.Errorf("壳 DEX 校验失败: %w", err)
		}
		name = nextDexName(art)
		pipeline.Add(art, zipx.NewStored(name, shellDex))
	}

	// 改写 Manifest 的 android:name。
	edits := []axml.AttrValue{{
		Element: "application",
		Index:   0,
		NS:      axml.AndroidNS,
		Name:    "name",
		Value:   ShellJavaNameOf(sh.Class),
	}}

	// android:appComponentFactory 必须一并处理，否则应用**启动即死**。
	//
	// 时序原因：这个工厂类由 LoadedApk 在 `makeApplicationInner` 里实例化，
	// 也就是在壳的 attachBaseContext（我们接管 ClassLoader 的地方）**之前**。
	// 那时业务 DEX 还在加密载荷里，工厂类根本不存在，于是：
	//   E LoadedApk: java.lang.ClassNotFoundException:
	//       Didn't find class "androidx.core.app.CoreComponentFactory"
	// 实测三个真实应用（RustDesk / Termux / Dhizuku）全部声明了这个属性。
	//
	// 处理方式：指向框架默认实现 android.app.AppComponentFactory。它保留了
	// 「按类名实例化组件」的标准语义；丢失的只有 androidx 的 CompatWrapped
	// 包装特性（组件实现该内部接口时返回包装对象），对绝大多数应用没有影响。
	if app := mf.FindElement("application"); app != nil &&
		app.AttrNS(axml.AndroidNS, "appComponentFactory") != nil {
		edits = append(edits, axml.AttrValue{
			Element: "application",
			Index:   0,
			NS:      axml.AndroidNS,
			Name:    "appComponentFactory",
			Value:   FrameworkComponentFactory,
		})
		art.Note("B2：android:appComponentFactory 已指向框架默认实现 %s（原工厂类在载荷里，"+
			"而系统在壳接管 ClassLoader 之前就要实例化它，不改会让应用启动即 ClassNotFoundException）",
			FrameworkComponentFactory)
	}

	out, err := mf.Rewrite(axml.Edit{SetAttr: edits})
	if err != nil {
		return fmt.Errorf("改写 Manifest 失败: %w", err)
	}
	if err := entry.SetData(out, true); err != nil {
		return fmt.Errorf("写回 Manifest 失败: %w", err)
	}

	art.Put(sharedKeyShell, &shellInfo{
		Class:        sh.Class,
		JavaName:     ShellJavaNameOf(sh.Class),
		LoaderClass:  loaderClass,
		Checks:       checks,
		CheckOrder:   checkOrder,
		EntryName:    name,
		OrigJavaName: origName,
	})

	art.Note("B2 Application 替换：壳类 %s 已注入 %s（%d 字节），Manifest android:name 由 %q 改为壳类",
		ShellJavaNameOf(sh.Class), name, len(shellDex), origRaw)
	art.Stat("B2.shell_class", ShellJavaNameOf(sh.Class))
	art.Stat("B2.dex_entry", name)
	art.Stat("B2.shell_bytes", fmt.Sprint(len(shellDex)))
	art.Stat("B2.orig_app", origName)
	return nil
}

// ShellAppRef 是 Pass 层对壳配置的描述。
//
// 单独定义它而不是直接用 dex.ShellApp，是为了让 shellPkgOf 等 Pass 层
// 的约定（比如包名规范化）集中在一处。
type ShellAppRef struct {
	Class string
	Orig  string
	// LoaderClass 非空表示壳会先调用 Loader 完成解密与 ClassLoader 接管。
	LoaderClass string
	// Checks 是壳在启动时要依序调用的检测类描述符。
	Checks []string
	// NativeKey 非空表示载荷密钥由该桥接类在运行时向 native 索取（C1）。
	NativeKey string
	// Debug 为 true 时壳会在每个关键步骤后弹 Toast 报告进度，便于在
	// 没有 adb 的真机上定位闪退点（见 options.DebugShell）。
	Debug bool
}

// spec 把 Pass 层的壳描述转换为 dex 层的构造参数。
func (r *ShellAppRef) spec() *dex.ShellApp {
	sh := &dex.ShellApp{Class: r.Class, Orig: r.Orig, Debug: r.Debug}
	sh.Checks = r.Checks
	sh.NativeKey = r.NativeKey
	if r.LoaderClass != "" {
		// 只提供类名：Loader 的类体由 B3 注入，此处仅让壳生成对它的调用。
		sh.Loader = &dex.LoaderSpec{Class: r.LoaderClass, Debug: r.Debug}
	}
	return sh
}

// ShellJavaNameOf 返回类描述符对应的 Java 点分名。
func ShellJavaNameOf(desc string) string { return dex.ShellJavaName(desc) }

// resolveAppName 把 Manifest 中声明的 Application 类名解析为完整类名。
//
// Android 允许三种写法：完整类名（com.x.Y）、以点开头的相对名（.Y）、
// 以及不含点的相对名（Y）。后两种都要拼上 Manifest 的 package。
func resolveAppName(pkg, name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	if strings.HasPrefix(name, ".") {
		return pkg + name
	}
	if !strings.Contains(name, ".") && pkg != "" {
		return pkg + "." + name
	}
	return name
}

// nextDexName 返回一个尚未被占用的 classes*.dex 条目名。
//
// 优先用 classes.dex：B1 移除原始 DEX 后它是空的，且它是系统最先加载的
// 主 DEX，壳放在这里最稳妥。
func nextDexName(art *pipeline.Artifact) string {
	used := map[string]bool{}
	for _, e := range art.Entries() {
		used[e.NameString()] = true
	}
	if !used["classes.dex"] {
		return "classes.dex"
	}
	for i := 2; ; i++ {
		n := fmt.Sprintf("classes%d.dex", i)
		if !used[n] {
			return n
		}
	}
}

// ---- B3 ClassLoader 接管 ----

// classLoader 把 Loader 类注入 B2 建好的壳 DEX。
//
// Loader 在运行时完成三件事：解密 B1 落在 assets 里的载荷、把明文写成
// 私有目录下的 DEX 文件、构造 DexClassLoader 并替换系统的 ClassLoader。
// 不替换系统加载器的话，Manifest 里声明的 Activity 仍会由旧加载器加载，
// 而业务类全在密文载荷里，结果就是「Application 起来了但界面打不开」。
type classLoader struct{}

func (classLoader) ID() config.FeatureID { return "B3" }
func (classLoader) In() pipeline.Level   { return pipeline.LevelZip }
func (classLoader) Out() pipeline.Level  { return pipeline.LevelZip }

func (c *classLoader) Run(_ context.Context, art *pipeline.Artifact, opts *config.Options) error {
	info, _ := art.Get(sharedKeyShell).(*shellInfo)
	if info == nil || info.LoaderClass == "" {
		return fmt.Errorf("B3 需要 B2 先注入壳 DEX（未找到壳信息）")
	}
	payloads := payloadsOf(art)
	if payloads == nil || len(payloads.Items) == 0 {
		// C2 移走了 lib/ 下的业务 .so，若此时没有 B1 载荷，壳既无法解密
		// DEX 也无法解密 .so，产物必然启动失败。显式报错而不是静默产出。
		if soLibsOf(art) != nil {
			return fmt.Errorf("C2 移除了原生库，但 B3 没有可加载的 DEX 载荷：请同时启用 B1（C2 依赖 B1/B2/B3）")
		}
		// 未启用 B1 时没有密文载荷可加载：壳退化为纯 Application 代理。
		art.Note("B3 ClassLoader 接管：未启用 B1（无加密载荷），壳仅做 Application 代理")
		return nil
	}

	entry := pipeline.Find(art, info.EntryName)
	if entry == nil {
		return fmt.Errorf("未找到 B2 注入的壳 DEX 条目 %s", info.EntryName)
	}
	shellDex, err := entry.Data()
	if err != nil {
		return fmt.Errorf("读取壳 DEX 失败: %w", err)
	}
	f, err := dex.Parse(shellDex)
	if err != nil {
		return fmt.Errorf("解析壳 DEX 失败: %w", err)
	}

	// 载荷按名字排序后落地，保证同一输入的产物可复现。
	items := make([]dex.LoaderItem, 0, len(payloads.Items))
	sorted := append([]pack.Payload(nil), payloads.Items...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Asset < sorted[j].Asset })
	for i, p := range sorted {
		items = append(items, dex.LoaderItem{
			Asset:   p.Asset,
			DexName: fmt.Sprintf("d%d.dex", i),
			Size:    len(p.Blob),
			// MAC 输入必须绑定原始 DEX 名：B8 已把 Asset 改过名，
			// 用 Asset 会让壳侧算出的 MAC 与打包时不一致。
			Name: p.Name,
		})
	}

	ls := &dex.LoaderSpec{
		Class:   info.LoaderClass,
		Key:     payloads.Key,
		Items:   items,
		TempDir: loaderTempDir,
		Debug:   opts.DebugShell,
		// 只读标记只对 targetSdk ≥ 34 有意义（Android 14+ 的加载要求）；
		// 对更低 targetSdk 的应用标记反而会挡住 ART 打开这些文件。
		MarkReadOnly: manifestSDKOf(art, "targetSdkVersion") >= 34,
		// 载荷 MAC：由 B1 决定本批次是否带 tag。关闭时不生成任何 MAC 指令。
		MAC: payloads.MAC,
	}

	// C2：把原生库载荷一并交给 Loader 解密落地。
	//
	// 库落地目录用 loaderTempDir 的子目录（私有目录内，可执行），
	// 并置只读以满足 Android 10+ 的 W^X（targetSdk ≥ 29 即需，早于 DEX 的 34）。
	soLibs := soLibsOf(art)
	if soLibs != nil && len(soLibs.Items) > 0 {
		// 密钥必须一致：C2 与 B1 都通过 payloadKey(opts) 派生，理应相同。
		// 若不一致（例如未来某条路径改了派生公式），这里立刻报错，
		// 而不是产出一个 .so 解密后是垃圾、dlopen 必崩的包。
		if soLibs.Key != payloads.Key {
			return fmt.Errorf("C2 的 SO 载荷密钥与 B1 载荷密钥不一致，无法由同一个壳解密")
		}
		// 目录名必须是**扁平的**（不含 "/"）：Context.getDir(name, mode)
		// 明确拒绝含路径分隔符的名字，传 "app_ag/lib" 会在应用启动时抛出
		//   java.lang.IllegalArgumentException: File app_ag/lib contains a path separator
		// 表现为「一装上就崩」，且崩在壳的 attachBaseContext 里（实测 Termux）。
		ls.LibDir = libTempDir
		for _, it := range soLibs.Items {
			ls.LibItems = append(ls.LibItems, dex.LoaderLibItem{
				Asset: it.Asset,
				Name:  it.Name,
				Abi:   it.Abi,
				Size:  it.Size,
			})
		}
		ls.LibReadOnly = manifestSDKOf(art, "targetSdkVersion") >= 29
	}
	add, err := dex.LoaderAddition(ls)
	if err != nil {
		return err
	}
	out, err := dex.Rebuild(f, dex.RebuildOptions{Addition: &add})
	if err != nil {
		return fmt.Errorf("注入 Loader 失败: %w", err)
	}
	if err := dex.Verify(out); err != nil {
		return fmt.Errorf("注入 Loader 后校验失败: %w", err)
	}
	if err := entry.SetData(out, true); err != nil {
		return fmt.Errorf("写回壳 DEX 失败: %w", err)
	}

	total := 0
	for _, p := range sorted {
		total += len(p.Blob)
	}
	macDesc := "无 MAC"
	if payloads.MAC {
		macDesc = "每份先验 HMAC-SHA256"
	}
	if len(ls.LibItems) > 0 {
		libBytes := 0
		for _, it := range ls.LibItems {
			libBytes += it.Size
		}
		art.Note("B3 ClassLoader 接管：Loader %s 已注入壳 DEX，运行时解密 %d 份 DEX 载荷（%d 字节，%s）"+
			"并解密 %d 份原生库载荷（%d 字节）到 %s，库搜索路径 = 该目录 + \":\" + nativeLibraryDir，再接管 ClassLoader",
			info.LoaderClass, len(items), total, macDesc, len(ls.LibItems), libBytes, ls.LibDir)
		art.Stat("B3.libs", fmt.Sprint(len(ls.LibItems)))
		art.Stat("B3.lib_bytes", fmt.Sprint(libBytes))
	} else {
		art.Note("B3 ClassLoader 接管：Loader %s 已注入壳 DEX，运行时解密 %d 份载荷（%d 字节，%s）并接管 ClassLoader",
			info.LoaderClass, len(items), total, macDesc)
	}
	art.Stat("B3.loader_class", info.LoaderClass)
	art.Stat("B3.payloads", fmt.Sprint(len(items)))
	if payloads.MAC {
		art.Stat("B3.mac", "1")
	} else {
		art.Stat("B3.mac", "0")
	}
	return nil
}

// loaderTempDir 是载荷解密后在应用私有目录下落地的子目录名。
//
// 必须落在私有目录：系统只信任应用数据目录内的代码路径。
const loaderTempDir = "ag"

// libTempDir 是 C2 解密原生库落地的目录名。
//
// 注意必须写成**扁平名**：Context.getDir 拒绝含路径分隔符的名字。
const libTempDir = "aglib"

// ---- D1 签名校验 ----

// sigCheck 把签名校验类注入壳 DEX，并让壳在启动时先调用它。
//
// 这是最廉价却最直接的一道防线：重打包者必然要换签名证书，而内置指纹
// 来自加固时使用的密钥库，因此换过签名的产物会在启动阶段直接退出。
//
// 指纹来源二选一：
//   - 使用方显式给出 -sig-hash（十六进制 SHA-256），适用于「加固与签名
//     分离」的流水线；
//   - 否则用 -ks 指定的密钥库计算签名证书的指纹——这与 E1 实际签名的证书
//     是同一张，因此必须要求 E1 同时启用，否则产物会与自身指纹不符而无法启动。
type sigCheck struct{}

func (sigCheck) ID() config.FeatureID { return "D1" }
func (sigCheck) In() pipeline.Level   { return pipeline.LevelZip }
func (sigCheck) Out() pipeline.Level  { return pipeline.LevelZip }

func (d *sigCheck) Run(_ context.Context, art *pipeline.Artifact, opts *config.Options) error {
	info, _ := art.Get(sharedKeyShell).(*shellInfo)
	cls := checkClassOf(info, "D1")
	if cls == "" {
		return fmt.Errorf("D1 需要 B2 先注入壳 DEX（未找到壳信息）")
	}

	digest, err := expectedSigDigest(opts)
	if err != nil {
		return err
	}

	entry := pipeline.Find(art, info.EntryName)
	if entry == nil {
		return fmt.Errorf("未找到 B2 注入的壳 DEX 条目 %s", info.EntryName)
	}
	shellDex, err := entry.Data()
	if err != nil {
		return fmt.Errorf("读取壳 DEX 失败: %w", err)
	}
	f, err := dex.Parse(shellDex)
	if err != nil {
		return fmt.Errorf("解析壳 DEX 失败: %w", err)
	}
	add, err := dex.SigAddition(&dex.SigSpec{Class: cls, Digest: digest})
	if err != nil {
		return err
	}
	out, err := dex.Rebuild(f, dex.RebuildOptions{Addition: &add})
	if err != nil {
		return fmt.Errorf("注入签名校验类失败: %w", err)
	}
	if err := dex.Verify(out); err != nil {
		return fmt.Errorf("注入签名校验类后校验失败: %w", err)
	}
	if err := entry.SetData(out, true); err != nil {
		return fmt.Errorf("写回壳 DEX 失败: %w", err)
	}

	art.Note("D1 签名校验：%s 已注入，内置指纹 %s（来源：%s）",
		cls, hex.EncodeToString(digest[:8])+"…", digestSource(opts))
	art.Stat("D1.class", cls)
	art.Stat("D1.digest", hex.EncodeToString(digest[:]))
	return nil
}

// expectedSigDigest 确定用于比对的目标指纹。
func expectedSigDigest(opts *config.Options) ([32]byte, error) {
	var out [32]byte
	if len(opts.SigHashes) > 0 {
		raw, err := hex.DecodeString(strings.TrimSpace(opts.SigHashes[0]))
		if err != nil || len(raw) != 32 {
			return out, fmt.Errorf("D1 的签名指纹应为 64 个十六进制字符（SHA-256），实际 %q", opts.SigHashes[0])
		}
		copy(out[:], raw)
		return out, nil
	}
	if !opts.IsEnabled("E1") {
		return out, fmt.Errorf("D1 需要签名才能确定指纹：请启用 E1 并提供 -ks，或用 -sig-hash 显式给出签名证书的 SHA-256")
	}
	m, err := keystore.Load(opts.KS, opts.KSPass, opts.KeyPass, opts.KSType, opts.Alias)
	if err != nil {
		return out, fmt.Errorf("D1 读取密钥库失败: %w", err)
	}
	leaf := m.Leaf()
	if leaf == nil {
		return out, fmt.Errorf("D1 的密钥库中没有证书")
	}
	return sha256.Sum256(leaf.Raw), nil
}

// digestSource 返回指纹来源的可读描述，便于排查「产物启动即退出」。
func digestSource(opts *config.Options) string {
	if len(opts.SigHashes) > 0 {
		return "-sig-hash"
	}
	return "密钥库中的签名证书"
}

// ---- 运行时检测的公共设施 ----

// runtimeCheck 描述一个挂在壳上的运行时检测。
type runtimeCheck struct {
	// id 是功能项 ID，用于按启用状态筛选。
	id string
	// class 是检测类的描述符。
	class string
}

// runtimeChecks 返回全部运行时检测类，顺序即调用顺序。
func runtimeChecks(pkgSlash string) []runtimeCheck {
	return []runtimeCheck{
		{"D1", "L" + pkgSlash + "/Sig;"},
		{"D2", "L" + pkgSlash + "/Rt;"},
		{"D3", "L" + pkgSlash + "/Em;"},
		{"D5", "L" + pkgSlash + "/Dev;"},
	}
}

// checkClassOf 从壳信息里取回某个功能项对应的检测类名；不存在时返回空串。
func checkClassOf(info *shellInfo, id string) string {
	if info == nil || info.Checks == nil {
		return ""
	}
	return info.Checks[id]
}

// injectShellClass 把一段类定义注入 B2 建好的壳 DEX。
//
// D1/D2/D3 干的都是同一件事：解析壳 DEX、追加一个类、校验、写回。
// 集中在这里，避免三份几乎相同的代码各自演化。
func injectShellClass(art *pipeline.Artifact, info *shellInfo, add dex.Addition) error {
	if info == nil {
		return fmt.Errorf("需要 B2 先注入壳 DEX（未找到壳信息）")
	}
	entry := pipeline.Find(art, info.EntryName)
	if entry == nil {
		return fmt.Errorf("未找到 B2 注入的壳 DEX 条目 %s", info.EntryName)
	}
	shellDex, err := entry.Data()
	if err != nil {
		return fmt.Errorf("读取壳 DEX 失败: %w", err)
	}
	f, err := dex.Parse(shellDex)
	if err != nil {
		return fmt.Errorf("解析壳 DEX 失败: %w", err)
	}
	out, err := dex.Rebuild(f, dex.RebuildOptions{Addition: &add})
	if err != nil {
		return fmt.Errorf("注入类失败: %w", err)
	}
	if err := dex.Verify(out); err != nil {
		return fmt.Errorf("注入类后校验失败: %w", err)
	}
	if err := entry.SetData(out, true); err != nil {
		return fmt.Errorf("写回壳 DEX 失败: %w", err)
	}
	return nil
}

// ---- D2 Root 检测 ----

// rootCheck 注入 Root 环境检测。
//
// 判据分两类：su 等提权程序的文件残留，以及测试签名的系统标签。
// 命中任一即终止进程。这是「阻断 Root 环境下的内存修改与 Hook」的第一道
// 门槛——它挡不住有心人，但能让绝大多数改机环境直接跑不起来。
type rootCheck struct{}

func (rootCheck) ID() config.FeatureID { return "D2" }
func (rootCheck) In() pipeline.Level   { return pipeline.LevelZip }
func (rootCheck) Out() pipeline.Level  { return pipeline.LevelZip }

// rootPaths 是常见的 su / 超级用户管理程序路径。
//
// 只做「文件是否存在」的判定，不尝试执行：执行 su 会被部分 ROM 记为异常，
// 而存在性判断已经足够区分改机环境。
var rootPaths = []string{
	"/system/bin/su",
	"/system/xbin/su",
	"/sbin/su",
	"/system/su",
	"/system/bin/.ext/.su",
	"/system/usr/we-need-root/su-backup",
	"/system/xbin/mu",
	"/system/app/Superuser.apk",
	"/system/app/superuser.apk",
	"/system/app/SuperSU",
	"/data/local/su",
	"/data/local/bin/su",
	"/data/local/xbin/su",
	"/su/bin/su",
	"/magisk/.core/bin/su",
	"/sbin/.magisk",
}

func (r *rootCheck) Run(_ context.Context, art *pipeline.Artifact, opts *config.Options) error {
	info, _ := art.Get(sharedKeyShell).(*shellInfo)
	cls := checkClassOf(info, "D2")
	if cls == "" {
		return fmt.Errorf("D2 需要 B2 先注入壳 DEX（未找到壳信息）")
	}
	add, err := dex.EnvCheckAddition(&dex.EnvCheckSpec{
		Class: cls,
		Paths: rootPaths,
		Props: []dex.PropCheck{
			// test-keys 表示系统镜像用测试密钥签名，通常是自编译或改机系统。
			{Field: dex.FieldSpec{Class: "Landroid/os/Build;", Name: "TAGS", Type: "Ljava/lang/String;"}, Sub: "test-keys"},
		},
	})
	if err != nil {
		return err
	}
	if err := injectShellClass(art, info, add); err != nil {
		return err
	}
	art.Note("D2 Root 检测：%s 已注入（%d 条路径判据 + 系统标签判据），命中即终止进程",
		cls, len(rootPaths))
	art.Stat("D2.class", cls)
	art.Stat("D2.paths", fmt.Sprint(len(rootPaths)))
	return nil
}

// ---- D3 模拟器检测 ----

// emulatorCheck 注入模拟器环境检测。
//
// 覆盖常见模拟器的 Build 字段特征。判据用**子串**匹配：各厂商在这些字段里
// 填写的格式差异很大（"sdk"、"sdk_google"、"Android SDK built for x86"…），
// 相等判定几乎一定漏判。
type emulatorCheck struct{}

func (emulatorCheck) ID() config.FeatureID { return "D3" }
func (emulatorCheck) In() pipeline.Level   { return pipeline.LevelZip }
func (emulatorCheck) Out() pipeline.Level  { return pipeline.LevelZip }

// emulatorProps 是模拟器的 Build 字段特征。
var emulatorProps = []struct {
	field string
	sub   string
}{
	{"FINGERPRINT", "generic"},
	{"MODEL", "google_sdk"},
	{"MODEL", "Emulator"},
	{"MODEL", "Android SDK built for"},
	{"MODEL", "sdk_gphone"},
	{"MANUFACTURER", "Genymotion"},
	{"HARDWARE", "goldfish"},
	{"HARDWARE", "ranchu"},
	{"PRODUCT", "sdk"},
	{"PRODUCT", "emulator"},
}

func (e *emulatorCheck) Run(_ context.Context, art *pipeline.Artifact, opts *config.Options) error {
	info, _ := art.Get(sharedKeyShell).(*shellInfo)
	cls := checkClassOf(info, "D3")
	if cls == "" {
		return fmt.Errorf("D3 需要 B2 先注入壳 DEX（未找到壳信息）")
	}
	props := make([]dex.PropCheck, 0, len(emulatorProps))
	for _, p := range emulatorProps {
		props = append(props, dex.PropCheck{
			Field: dex.FieldSpec{Class: "Landroid/os/Build;", Name: p.field, Type: "Ljava/lang/String;"},
			Sub:   p.sub,
		})
	}
	add, err := dex.EnvCheckAddition(&dex.EnvCheckSpec{Class: cls, Props: props})
	if err != nil {
		return err
	}
	if err := injectShellClass(art, info, add); err != nil {
		return err
	}
	art.Note("D3 模拟器检测：%s 已注入（%d 条 Build 字段判据），命中即终止进程",
		cls, len(props))
	art.Stat("D3.class", cls)
	art.Stat("D3.props", fmt.Sprint(len(props)))
	return nil
}

// ---- C1 密钥 native 派生 ----

// nativeKeyDerive 让载荷密钥改由 native 库派生，并注入所需的原生库与桥接类。
//
// 效果：DEX 里再也不含密钥，唯一来源是 libapkguard.so 中的种子；且密钥
// 混入了本 APK 的签名证书摘要，重打包换签名后派生结果不同，密文载荷
// 在密码学层面解不开。
//
// 与 B1 的配合：B1 加密时要算出**同一个**密钥，因此本功能把
// 「由签名摘要派生的密钥」交给 B1 使用（见 sharedKeyDerivedKey）。
type nativeKeyDerive struct{}

func (nativeKeyDerive) ID() config.FeatureID { return "C1" }
func (nativeKeyDerive) In() pipeline.Level   { return pipeline.LevelZip }
func (nativeKeyDerive) Out() pipeline.Level  { return pipeline.LevelZip }

func (d *nativeKeyDerive) Run(_ context.Context, art *pipeline.Artifact, opts *config.Options) error {
	info, _ := art.Get(sharedKeyShell).(*shellInfo)
	if info == nil {
		return fmt.Errorf("C1 需要 B2 先注入壳 DEX（未找到壳信息）")
	}

	// 派生输入是本 APK 的签名证书摘要——必须先确定签名，否则加密与运行时
	// 会用到不同的密钥，产物无法启动自己。
	digest, err := expectedSigDigest(opts)
	if err != nil {
		return fmt.Errorf("C1 需要确定签名证书摘要: %w", err)
	}
	_ = digest // 密钥由 B1 自行派生（同一纯函数），此处只需校验摘要可得

	// 注入原生库。
	//
	// **只补 APK 已经支持的 ABI**：系统是从「lib/<abi>/ 下有没有文件」来判断
	// 一个应用支持哪些架构的。若给一个只有 arm64 库的 APK 补上 armeabi-v7a
	// 的 libapkguard.so，系统就会认为它支持 32 位 ARM，放它装到这类设备上——
	// 而应用自己的 32 位库并不存在，装上就是一启动就崩。
	//
	// 反过来，APK 完全没有原生库时（纯 Java 应用）不存在这个问题，
	// 此时由我们决定支持哪些架构，补齐全部 ABI 即可。
	libs, err := native.Prebuilt()
	if err != nil {
		return err
	}
	target := libs
	// ABI 选择优先用 C2 记录的原生库 ABI 集合：C2 把业务 .so 移出 lib/ 后，
	// abisOf 会返回空集合，于是走「APK 完全没有原生库」分支、给全部 3 个
	// ABI 都注入 libapkguard.so。后果是一个只支持 arm64 的应用被系统判定
	// 为也支持 armeabi-v7a，可能被装到 32 位设备上而业务库不存在，一装就崩。
	//
	// C2 在移除前把原集合写入 Shared，这里优先读取；否则回退到扫描 lib/。
	own := abisOf(art)
	if c2 := soAbisOf(art); len(c2) > 0 {
		own = c2
	}
	if len(own) > 0 {
		target = nil
		for _, l := range libs {
			if own[l.Abi] {
				target = append(target, l)
			}
		}
		if len(target) == 0 {
			return fmt.Errorf("APK 自带原生库的 ABI（%s）不在预编译库覆盖范围内（%s），无法注入",
				strings.Join(abiNames(own), "、"), native.AbiNames())
		}
	}
	added := 0
	for _, l := range target {
		if pipeline.Find(art, l.Entry) != nil {
			continue // 已存在（例如重复执行），不覆盖
		}
		pipeline.Add(art, zipx.NewStored(l.Entry, l.Data))
		added++
	}

	// 注入桥接类（提供 derive/sig，并负责 loadLibrary）。
	bridge := &dex.NativeBridgeSpec{
		Class:      dex.NativeBridgeClass,
		LibName:    dex.NativeLibName,
		NeedDerive: true,
		NeedDebug:  opts.IsEnabled("C4"),
		NeedHooked: opts.IsEnabled("C5"),
		NeedIntact: opts.IsEnabled("C6"),
		NeedWatch:  opts.IsEnabled("D4"),
	}
	add, err := dex.NativeBridgeAddition(bridge)
	if err != nil {
		return err
	}
	if err := injectShellClass(art, info, add); err != nil {
		return err
	}

	art.Note("C1 密钥 native 派生：载荷密钥改由 libapkguard.so 派生（种子仅在 native 层，且混入签名摘要），已注入 %d 个 ABI 的原生库与桥接类 %s",
		added, dex.NativeBridgeJavaName)
	art.Stat("C1.libs", fmt.Sprint(added))
	art.Stat("C1.bytes", fmt.Sprint(native.TotalSize(target)))
	art.Stat("C1.bridge", dex.NativeBridgeJavaName)
	return nil
}

// ---- C4 反调试 ----

// antiDebug 注入 native 反调试检测，并在壳启动时调用。
//
// 与 C1 共用同一份原生库与桥接类：桥接类的 debugged() 由 libapkguard.so
// 实现，读 /proc/self/status 的 TracerPid。判定是「失败开放」的——
// 读不到状态就按「没有调试器」处理，避免因 ROM 差异把正常用户挡住。
type antiDebug struct{}

func (antiDebug) ID() config.FeatureID { return "C4" }
func (antiDebug) In() pipeline.Level   { return pipeline.LevelZip }
func (antiDebug) Out() pipeline.Level  { return pipeline.LevelZip }

func (a *antiDebug) Run(_ context.Context, art *pipeline.Artifact, opts *config.Options) error {
	info, _ := art.Get(sharedKeyShell).(*shellInfo)
	if info == nil {
		return fmt.Errorf("C4 需要 B2 先注入壳 DEX（未找到壳信息）")
	}
	// 原生库与桥接类由 C1 注入（两者共用），C4 只负责让壳去调用它。
	if _, ok := info.Checks["C4"]; !ok {
		return fmt.Errorf("C4 需要与 C1 同时启用（两者共用同一份原生库与桥接类）")
	}
	art.Note("C4 反调试：壳启动时调用 %s.debugged()，检测到 TracerPid 非零即终止进程",
		dex.NativeBridgeJavaName)
	art.Stat("C4.bridge", dex.NativeBridgeJavaName)
	return nil
}

// ---- C5 反注入（反 Hook） ----

// antiHook 让壳在启动时调用原生侧的反注入检测。
//
// 原生侧扫描 /proc/self/maps 查找 frida/xposed/substrate 等注入模块，
// 并探测 Frida 默认端口 27042。与 C4 一样是「失败开放」的：读不到
// maps、建不出 socket 都按未注入处理。
type antiHook struct{}

func (antiHook) ID() config.FeatureID { return "C5" }
func (antiHook) In() pipeline.Level   { return pipeline.LevelZip }
func (antiHook) Out() pipeline.Level  { return pipeline.LevelZip }

func (h *antiHook) Run(_ context.Context, art *pipeline.Artifact, opts *config.Options) error {
	info, _ := art.Get(sharedKeyShell).(*shellInfo)
	if info == nil {
		return fmt.Errorf("C5 需要 B2 先注入壳 DEX（未找到壳信息）")
	}
	if checkClassOf(info, "C5") == "" {
		return fmt.Errorf("C5 需要与 C1 同时启用（两者共用同一份原生库与桥接类）")
	}
	art.Note("C5 反注入：壳启动时调用 %s.hooked()，扫描 maps 中的注入模块并探测 Frida 默认端口",
		dex.NativeBridgeJavaName)
	art.Stat("C5.bridge", dex.NativeBridgeJavaName)
	return nil
}

// ---- C6 完整性自校验 ----

// selfIntegrity 让壳在启动时校验原生库自身的完整性。
//
// 原生侧对自身 .so 的 .text 与 .rodata 求 SHA-256，与编译期写入
// .agexpect 节的期望值比对：改动库中任何一行代码、甚至只改派生种子
// （它在 .rodata 里），都会导致启动即退出。
//
// 期望值由 internal/native/build_native.py 在编译后回填，并由
// internal/native 的 Go 测试用 debug/elf 独立复核。
type selfIntegrity struct{}

func (selfIntegrity) ID() config.FeatureID { return "C6" }
func (selfIntegrity) In() pipeline.Level   { return pipeline.LevelZip }
func (selfIntegrity) Out() pipeline.Level  { return pipeline.LevelZip }

func (si *selfIntegrity) Run(_ context.Context, art *pipeline.Artifact, opts *config.Options) error {
	info, _ := art.Get(sharedKeyShell).(*shellInfo)
	if info == nil {
		return fmt.Errorf("C6 需要 B2 先注入壳 DEX（未找到壳信息）")
	}
	if checkClassOf(info, "C6") == "" {
		return fmt.Errorf("C6 需要与 C1 同时启用（两者共用同一份原生库与桥接类）")
	}
	libs, err := native.Prebuilt()
	if err != nil {
		return err
	}
	art.Note("C6 完整性自校验：壳启动时调用 %s.intact()，校验自身 .text 与 .rodata 的 SHA-256（覆盖 %d 个 ABI 的原生库）",
		dex.NativeBridgeJavaName, len(libs))
	art.Stat("C6.bridge", dex.NativeBridgeJavaName)
	art.Stat("C6.libs", fmt.Sprint(len(libs)))
	return nil
}

// ---- E6 输出兼容性静态自检 ----

// compatCheck 对产物做静态兼容性检查。
//
// 与设计文档里 E6 的差异必须说清楚：文档描述的是「覆盖 Android 5~15、
// 各 ABI、各厂商 ROM 的回归校验」，那需要真机/模拟器矩阵，**本工具无法
// 对 APK 本身执行**。这里实现的是它能做的那一半——静态一致性检查，
// 专抓那些「装机才发现」的确定性错误：
//
//  1. DEX 版本与 minSdk 不匹配：DEX 038 起需要 API 26+，低版本设备直接拒装；
//  2. 原生库的 ABI 覆盖不一致：某 ABI 缺一个 .so 就会在该架构上崩；
//  3. 注入代码用到的 API 高于声明的最低版本；
//  4. 关键条目缺失或重复。
//
// 这些都是静态可判定的，也正是加固产物最常见的线上事故来源。
type compatCheck struct{}

func (compatCheck) ID() config.FeatureID { return "E6" }
func (compatCheck) In() pipeline.Level   { return pipeline.LevelZip }
func (compatCheck) Out() pipeline.Level  { return pipeline.LevelZip }

// injectedMinAPI 是「加固代码自身」用到的最高 API 级别。
//
// 全部为内置 API：System.exit/loadLibrary、File.exists、String.contains、
// MessageDigest、Cipher、AssetManager.open、Context.getDir、
// PackageManager.getPackageInfo、Build 字段——最晚的一个也是 API 1。
// 记录在这里的意义是：一旦将来引入更晚的 API，这条约束会立刻报警。
const injectedMinAPI = 1

func (c *compatCheck) Run(_ context.Context, art *pipeline.Artifact, _ *config.Options) error {
	var problems []string

	minSDK := manifestMinSDKOf(art)
	// 1) DEX 版本 vs minSdk
	for _, e := range art.Entries() {
		name := e.NameString()
		if len(name) < 5 || !strings.HasSuffix(strings.ToLower(name), ".dex") {
			continue
		}
		data, err := e.Data()
		if err != nil {
			continue
		}
		if len(data) < 8 || string(data[:4]) != "dex\n" {
			continue // 伪装块（A9）本就不是真 DEX
		}
		// 版本号是 magic 里的 3 位十进制。
		ver := 0
		for i := 4; i < 7; i++ {
			if data[i] < '0' || data[i] > '9' {
				ver = 0
				break
			}
			ver = ver*10 + int(data[i]-'0')
		}
		if ver >= 38 && minSDK < 26 {
			problems = append(problems, fmt.Sprintf(
				"%s 是 DEX %03d，需要 API 26+，但 Manifest 声明 minSdkVersion=%d", name, ver, minSDK))
		}
		if ver >= 41 && minSDK < 30 {
			problems = append(problems, fmt.Sprintf(
				"%s 是 DEX %03d，需要 API 30+，但 minSdkVersion=%d", name, ver, minSDK))
		}
	}

	// 2) 原生库的 ABI 覆盖一致性
	libsByAbi := map[string]map[string]bool{}
	for _, e := range art.Entries() {
		name := e.NameString()
		if !strings.HasPrefix(name, "lib/") {
			continue
		}
		parts := strings.Split(name, "/")
		if len(parts) < 3 {
			continue
		}
		if libsByAbi[parts[1]] == nil {
			libsByAbi[parts[1]] = map[string]bool{}
		}
		libsByAbi[parts[1]][parts[len(parts)-1]] = true
	}
	if len(libsByAbi) > 1 {
		// 以第一个 ABI 的库集合为基准，其余缺失即报错。
		var abis []string
		for a := range libsByAbi {
			abis = append(abis, a)
		}
		sort.Strings(abis)
		base := abis[0]
		for _, a := range abis[1:] {
			for lib := range libsByAbi[base] {
				if !libsByAbi[a][lib] {
					problems = append(problems, fmt.Sprintf(
						"ABI %s 缺少 %s（%s 有）：该架构上的应用会因缺少原生库而崩溃", a, lib, base))
				}
			}
		}
	}

	// 3) targetSdk 是否低到装不上
	//
	// 这是一条**确定会导致安装失败**的静态问题，而且失败信息出现在设备上
	// （"INSTALL FAILED DEPRECATED SDK VERSION"），排查起来毫无线索可言。
	// Android 14 拒绝安装 targetSdkVersion < 23 的包，Android 15 起阈值提到 24；
	// Manifest 完全没声明 <uses-sdk> 时 targetSdk 退化为 minSdk、再退化为 1，
	// 同样落在被拒范围内。因此这里按 24 判定并在交付前拦下。
	//
	// 仍然要支持「有意面向旧设备分发」的场景：那种情况关闭 E6 即可
	// （-disable E6），而不是让工具替使用者做决定。
	targetSDK := manifestSDKOf(art, "targetSdkVersion")
	if targetSDK < 24 {
		hint := ""
		if targetSDK == 0 {
			hint = "（Manifest 未声明 <uses-sdk>，targetSdk 会退化为 1）"
		}
		problems = append(problems, fmt.Sprintf(
			"targetSdkVersion=%d < 24：Android 15 及以上的系统会直接拒绝安装该包（报 DEPRECATED SDK VERSION）%s；请在构建侧声明 targetSdkVersion，或确认只面向旧系统分发并关闭 E6",
			targetSDK, hint))
	}

	// 4) 注入代码的 API 需求 vs minSdk
	if minSDK > 0 && minSDK < injectedMinAPI {
		problems = append(problems, fmt.Sprintf(
			"加固代码用到 API %d，但 minSdkVersion=%d", injectedMinAPI, minSDK))
	}

	// 5) 关键条目
	if pipeline.Find(art, "AndroidManifest.xml") == nil {
		problems = append(problems, "缺少 AndroidManifest.xml")
	}
	ndex := 0
	for _, e := range art.Entries() {
		if isDexEntry(e) {
			ndex++
		}
	}
	if ndex == 0 {
		problems = append(problems, "归档中没有任何可用 DEX（设备将无法启动）")
	}

	if len(problems) > 0 {
		return fmt.Errorf("E6 兼容性自检未通过：\n  - %s", strings.Join(problems, "\n  - "))
	}
	art.Note("E6 兼容性自检：DEX 版本与 minSdk=%d 匹配、原生库 ABI 覆盖一致（%d 个 ABI）、关键条目完整",
		minSDK, len(libsByAbi))
	art.Stat("E6.min_sdk", fmt.Sprint(minSDK))
	art.Stat("E6.abis", fmt.Sprint(len(libsByAbi)))
	art.Stat("E6.dex", fmt.Sprint(ndex))
	return nil
}

// manifestMinSDKOf 读取产物 Manifest 的 minSdkVersion；0 表示读不到。
//
// 与 pipeline 包里的同名逻辑保持一致的语义（读不到即视为「支持到 API 1」），
// 但这里不能直接复用：pipeline 依赖 passes（经 Sink），反向引用会成环。
func manifestMinSDKOf(art *pipeline.Artifact) int {
	return manifestSDKOf(art, "minSdkVersion")
}

// manifestSDKOf 读取 Manifest 中 <uses-sdk> 的指定字段；0 表示读不到。
//
// 读不到的含义按 Android 的默认语义解释：未声明 <uses-sdk> 时
// minSdkVersion 与 targetSdkVersion 都退化为 1，因此调用方把 0 当作
// 「低于任何有意义的阈值」处理即可。
func manifestSDKOf(art *pipeline.Artifact, field string) int {
	e := pipeline.Find(art, "AndroidManifest.xml")
	if e == nil {
		return 0
	}
	data, err := e.Data()
	if err != nil {
		return 0
	}
	f, err := axml.Parse(data)
	if err != nil {
		return 0
	}
	uses := f.FindElement("uses-sdk")
	if uses == nil {
		return 0
	}
	a := uses.Attr(field)
	if a == nil {
		return 0
	}
	if a.DataType == axml.TypeIntDec {
		return int(a.Data)
	}
	n := 0
	for _, ch := range a.RawValue {
		if ch < '0' || ch > '9' {
			return 0
		}
		n = n*10 + int(ch-'0')
	}
	return n
}

// ---- E4 多渠道打包 ----

// channelMark 把渠道标识写入产物。
//
// 一次运行只处理一个渠道：多渠道意味着产出**多个各自签名的 APK**，
// 而签名覆盖整个文件，所以每换一个渠道都必须重新走一遍「写入 → 对齐 →
// 签名」。由 CLI 循环调用，每次传入单元素 Channels。
//
// 写入位置选 assets/ 而不是 META-INF/：META-INF 下的条目会被 v1 签名
// 视为「不受签名保护」并产生告警，而 assets 是普通条目，行为最干净。
// 渠道文件内容是渠道名的明文字节，便于使用方的渠道 SDK 直接读取。
type channelMark struct{}

func (channelMark) ID() config.FeatureID { return "E4" }
func (channelMark) In() pipeline.Level   { return pipeline.LevelZip }
func (channelMark) Out() pipeline.Level  { return pipeline.LevelZip }

// ChannelAssetName 是渠道信息在 APK 中的条目名。
//
// 固定名字是有意的：使用方的渠道 SDK 要按固定路径读取，
// 每次加固都换名字会让它读不到。
const ChannelAssetName = "assets/apkguard_channel.txt"

func (c *channelMark) Run(_ context.Context, art *pipeline.Artifact, opts *config.Options) error {
	if len(opts.Channels) == 0 {
		return fmt.Errorf("E4 已启用但未指定渠道（用 -channels a,b 指定）")
	}
	if len(opts.Channels) > 1 {
		// 一次运行只能写一个渠道：多渠道必须分多次签名。
		return fmt.Errorf("E4 单次运行只接受一个渠道（实际 %d 个）；多渠道由 CLI 自动逐个产出", len(opts.Channels))
	}
	ch := strings.TrimSpace(opts.Channels[0])
	if ch == "" {
		return fmt.Errorf("E4 的渠道名不能为空")
	}
	// 已存在的同类条目先移除，避免重复运行后出现两个渠道文件。
	pipeline.Remove(art, func(e *zipx.Entry) bool {
		return e.NameString() == ChannelAssetName
	})
	pipeline.Add(art, zipx.NewStored(ChannelAssetName, []byte(ch)))

	art.Note("E4 多渠道打包：渠道 %q 已写入 %s", ch, ChannelAssetName)
	art.Stat("E4.channel", ch)
	return nil
}

// ---- D5 设备绑定 ----

// deviceBind 注入设备绑定校验：只有授权设备能运行。
//
// 绑定值必须由使用方在目标设备上采集后传入（-bind-device），采集方式是
// 「让应用自己报出来」：
//
//	apkguard -debug-shell ... -enable ...D5... -bind-device 占位值
//	# 装机运行一次，然后
//	adb logcat -s APKGUARD-D5        # 打印的就是本机标识
//
// 不能用 `adb shell settings get secure android_id`：Android 8+ 起 ANDROID_ID
// 按「应用签名 + 用户 + 设备」作用域化，它读到的是原始值，与应用内读到的不同。
//
// 工具无法凭空得知目标设备的标识，这是设备绑定固有的前提。
// 与其它运行时检测一致：取不到标识时放行（失败开放），只拦「明确不匹配」。
type deviceBind struct{}

func (deviceBind) ID() config.FeatureID { return "D5" }
func (deviceBind) In() pipeline.Level   { return pipeline.LevelZip }
func (deviceBind) Out() pipeline.Level  { return pipeline.LevelZip }

func (d *deviceBind) Run(_ context.Context, art *pipeline.Artifact, opts *config.Options) error {
	info, _ := art.Get(sharedKeyShell).(*shellInfo)
	cls := checkClassOf(info, "D5")
	if cls == "" {
		return fmt.Errorf("D5 需要 B2 先注入壳 DEX（未找到壳信息）")
	}
	dev := strings.TrimSpace(opts.BindDevice)
	if dev == "" {
		return fmt.Errorf("D5 需要指定要绑定的设备标识（-bind-device）。注意 Android 8+ 起 ANDROID_ID 按应用签名作用域化，`adb shell settings get secure android_id` **取不到**应用内看到的那个值；请先用 -debug-shell 出一个排障版，在目标设备上运行一次，从 `adb logcat -s APKGUARD-D5` 拿到本机标识再绑定")
	}
	digest := sha256.Sum256([]byte(dev))

	add, err := dex.DevAddition(&dex.DevSpec{Class: cls, Digest: digest, Debug: opts.DebugShell})
	if err != nil {
		return err
	}
	if err := injectShellClass(art, info, add); err != nil {
		return err
	}
	art.Note("D5 设备绑定：%s 已注入，绑定目标 %s（设备标识的 SHA-256）",
		cls, hex.EncodeToString(digest[:8])+"…")
	art.Stat("D5.class", cls)
	art.Stat("D5.bound", hex.EncodeToString(digest[:]))
	return nil
}

// abisOf 从产物中提取「APK 自带原生库」覆盖的 ABI 集合。
//
// 只看输入里既有的 lib/<abi>/*.so；注入类条目（如我们自己的 libapkguard.so）
// 在计算时尚未加入，因此不会自我循环。
func abisOf(art *pipeline.Artifact) map[string]bool {
	out := map[string]bool{}
	for _, e := range art.Entries() {
		n := e.NameString()
		if !strings.HasPrefix(n, "lib/") || !strings.HasSuffix(n, ".so") {
			continue
		}
		parts := strings.Split(n, "/")
		if len(parts) >= 3 {
			out[parts[1]] = true
		}
	}
	return out
}

// abiNames 把 ABI 集合转为有序切片，便于报告。
func abiNames(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---- D4 内存完整性校验（运行期周期复检）----

// memWatch 让 native 侧启动一个周期性复检的守护线程。
//
// 与 C6 的分工：C6 是**一次性**自校验，只能证明「启动那一刻没被改」；
// Frida 之类的运行期补丁发生在启动之后，因此需要周期复检（D4）。
// 两者共用同一份原生库与桥接类，D4 只负责让壳在启动时把线程拉起来。
//
// 判定沿用既有的失败开放约定：明确命中（被调试/被注入/完整性破坏）才
// 终止进程；校验本身读不到信息时不误杀。
type memWatch struct{}

func (memWatch) ID() config.FeatureID { return "D4" }
func (memWatch) In() pipeline.Level   { return pipeline.LevelZip }
func (memWatch) Out() pipeline.Level  { return pipeline.LevelZip }

func (m *memWatch) Run(_ context.Context, art *pipeline.Artifact, _ *config.Options) error {
	info, _ := art.Get(sharedKeyShell).(*shellInfo)
	if info == nil {
		return fmt.Errorf("D4 需要 B2 先注入壳 DEX（未找到壳信息）")
	}
	if _, ok := info.Checks["D4"]; !ok {
		return fmt.Errorf("D4 需要与 C1 同时启用（两者共用同一份原生库与桥接类）")
	}
	art.Note("D4 内存完整性校验：壳启动时调用 %s.watch()，native 侧每 3 秒复检一次"+
		"调试器/注入模块/自身代码摘要，命中即终止进程",
		dex.NativeBridgeJavaName)
	art.Stat("D4.bridge", dex.NativeBridgeJavaName)
	return nil
}
