package dex

import (
	"archive/zip"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"apkguard/internal/native"
)

// 本文件对**实际交付的 APK** 做安装前审计：把包里真实的壳 DEX 与真实载荷
// 拿进解释器里跑一遍完整链路。
//
// 为什么值得单独做这一步：单元测试用的是构造出来的载荷，而交付包里载荷的
// 资源名、长度、分片切分、密钥来源都来自真实构建流程。这些环节一旦对不上，
// 表现就是「装上去一开就崩」，而本地静态检查（签名/对齐/结构）全都看不出来。
//
// 判定标准直接对齐 Manifest：Manifest 里声明了 com.agtest.MainActivity 与
// com.agtest.HealthProvider，那么解密后的载荷里就必须真的有这两个类，
// 否则框架实例化组件时必然 ClassNotFoundException。

// apkShellDex 从一个 APK 里取出壳 DEX 与全部 assets 条目。
func apkShellDex(t *testing.T, path string) (*File, map[string][]byte) {
	t.Helper()
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatalf("打开 %s 失败: %v", path, err)
	}
	defer zr.Close()
	var dexBytes []byte
	assets := map[string][]byte{}
	for _, f := range zr.File {
		switch {
		case f.Name == "classes.dex":
			rc, err := f.Open()
			if err != nil {
				t.Fatalf("读取 classes.dex 失败: %v", err)
			}
			dexBytes, err = io.ReadAll(rc)
			rc.Close()
			if err != nil {
				t.Fatalf("读取 classes.dex 失败: %v", err)
			}
		case strings.HasPrefix(f.Name, "assets/"):
			rc, err := f.Open()
			if err != nil {
				t.Fatalf("读取 %s 失败: %v", f.Name, err)
			}
			b, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				t.Fatalf("读取 %s 失败: %v", f.Name, err)
			}
			// Loader 用 AssetManager.open 打开，路径本就相对 assets/。
			assets[strings.TrimPrefix(f.Name, "assets/")] = b
		}
	}
	if dexBytes == nil {
		t.Fatalf("%s 里没有 classes.dex", path)
	}
	g, err := Parse(dexBytes)
	if err != nil {
		t.Fatalf("解析壳 DEX 失败: %v", err)
	}
	if err := Verify(dexBytes); err != nil {
		t.Fatalf("壳 DEX 自校验失败: %v", err)
	}
	return g, assets
}

// hasLoaderClass 判断壳 DEX 里是否真的定义了 Loader 类。
//
// 各产物级守卫原本用「assets 非空」来判断「这是一个加壳包」，但那个假设已经
// 不成立：A10 的垃圾条目也会落在 assets/ 下（参考样本的深目录垃圾同样如此），
// 于是「只开了混淆、没有加壳」的产物会被误判成加壳包，接着去找并不存在的
// Loader 方法而报错。判据必须落在**壳 DEX 里有没有 Loader 类**这个事实上。
func hasLoaderClass(g *File) bool {
	found := false
	_ = g.Classes(func(_ uint32, _ ClassDef, name string) error {
		if name == "Lcom/apkguard/shell/Loader;" {
			found = true
		}
		return nil
	})
	return found
}

// allClassNames 列出 DEX 中的全部类描述符。
func allClassNames(t *testing.T, g *File) []string {
	t.Helper()
	var out []string
	if err := g.Classes(func(_ uint32, _ ClassDef, name string) error {
		out = append(out, name)
		return nil
	}); err != nil {
		t.Fatalf("遍历类失败: %v", err)
	}
	return out
}

// installNativeKeyMocks 让 C1（密钥由 native 派生）在解释器里可用。
//
// 载荷密钥不是内联在字节码里的，而是运行时由 native 库按「签名证书摘要」
// 派生。这里用与 .so 内 C 实现逐字节对拍过的 Go 实现顶替，摘要取自
// apksigner --print-certs（即真实签名证书的 SHA-256）。
func installNativeKeyMocks(t *testing.T, apk string) {
	t.Helper()
	p := filepath.Join(filepath.Dir(apk), "signer-sha256.txt")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("C1 载荷需要签名摘要 %s（用 apksigner --print-certs 生成）: %v", p, err)
	}
	digest, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(digest) != 32 {
		t.Fatalf("%s 内容不是 32 字节十六进制摘要", p)
	}
	fakeCalls[NativeBridgeClass+"->sig(Landroid/content/Context;)[B"] =
		func(*interp, []int) (int32, any, error) {
			return 0, &fakeBytes{b: digest}, nil
		}
	fakeCalls[NativeBridgeClass+"->derive([B)[B"] =
		func(*interp, []int) (int32, any, error) {
			k := native.DeriveKey(digest)
			return 0, &fakeBytes{b: k[:]}, nil
		}
}

// auditAPK 把交付包里的真实载荷解密出来并检查内容。
//
// wanted 是「解密后必须存在」的类描述符（取自 Manifest 声明的组件）。
func auditAPK(t *testing.T, apk string, loaderClass, crashClass string, wanted []string, nativeKey bool, minShards int) {
	t.Helper()
	g, assets := apkShellDex(t, apk)
	if len(assets) == 0 {
		t.Fatalf("%s 里没有 assets 载荷", apk)
	}

	fakeCode = map[string]uint32{}
	defer func() { fakeCode = map[string]uint32{} }()
	registerFakeCode(t, g, allClassNames(t, g)...)

	env := &loaderEnv{assets: assets, fs: map[string][]byte{}}
	restore := installLoaderMocks(env)
	defer restore()
	installActivityThreadMock()
	defer clearActivityThreadMock()
	restore2 := installDebugMocks()
	defer restore2()
	// D1/D2 会装异常处理器、弹 Toast：这些框架调用必须有等价实现。
	for k, h := range crashHandlerDeps() {
		fakeCalls[k] = h
	}
	if nativeKey {
		installNativeKeyMocks(t, apk)
	}
	toastLog = &[]string{}
	defer func() { toastLog = nil }()

	idx, off := findMethod(t, g, loaderClass, "->"+LoaderEntry+"(")
	if _, err := runPadMethod(g, idx, off, &fakeObj{desc: descContext}); err != nil {
		t.Fatalf("%s 的壳链路执行失败: %v", apk, err)
	}

	// ① 载荷必须已解密落地，且每一份都是结构合法的 DEX
	if len(env.fs) == 0 {
		t.Fatalf("%s：没有任何载荷被解密落地", apk)
	}
	paths := make([]string, 0, len(env.fs))
	for p := range env.fs {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	found := map[string]bool{}
	for _, p := range paths {
		blob := env.fs[p]
		if _, err := Parse(blob); err != nil {
			t.Fatalf("%s：落地文件 %s 不是合法 DEX: %v", apk, filepath.Base(p), err)
		}
		if err := Verify(blob); err != nil {
			t.Fatalf("%s：落地文件 %s 自校验失败: %v", apk, filepath.Base(p), err)
		}
		pg, err := Parse(blob)
		if err != nil {
			t.Fatalf("%s：解析落地文件失败: %v", apk, err)
		}
		for _, n := range allClassNames(t, pg) {
			found[n] = true
		}
	}

	// ② Manifest 里声明的组件类必须在解密后的载荷里真的存在
	var missing []string
	for _, w := range wanted {
		if !found[w] {
			missing = append(missing, w)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("%s：解密后的载荷缺少 Manifest 声明的类 %v（实际类数 %d）",
			apk, missing, len(found))
	}

	// ③ 每份落地的 DEX 都必须被标记只读（Android 14+ 的加载前提）
	if len(env.readOnly) != len(paths) {
		t.Fatalf("%s：落地 %d 份 DEX，却有 %d 份被标记只读",
			apk, len(paths), len(env.readOnly))
	}

	// ④ dexPath 必须是「用 : 连接的绝对路径」，且不含空元素
	if env.dexPath == "" {
		t.Fatalf("%s：DexClassLoader 的 dexPath 为空", apk)
	}
	for _, part := range strings.Split(env.dexPath, ":") {
		if part == "" {
			t.Fatalf("%s：dexPath 含空路径元素: %q", apk, env.dexPath)
		}
		if !strings.HasPrefix(part, "/") {
			t.Fatalf("%s：dexPath 含非绝对路径: %q", apk, env.dexPath)
		}
	}
	// ⑤ 各分片的类必须互不重叠（B4 的正确性）。
	// 是否分片取决于功能集，因此份数只做下限判断（由 minShards 给出）。
	if len(paths) < minShards {
		t.Fatalf("%s：应至少有 %d 份载荷，实际 %d 份", apk, minShards, len(paths))
	}
	seen := map[string]string{}
	for _, p := range paths {
		pg, err := Parse(env.fs[p])
		if err != nil {
			t.Fatalf("%s：解析 %s 失败: %v", apk, p, err)
		}
		for _, n := range allClassNames(t, pg) {
			if prev, dup := seen[n]; dup {
				t.Fatalf("%s：类 %s 同时出现在 %s 与 %s", apk, n, filepath.Base(prev), filepath.Base(p))
			}
			seen[n] = p
		}
	}

	// 把解密后的载荷落盘，便于用外部工具（AOSP dexdump）独立复核布局。
	// 只在显式指定目录时写，避免测试留下垃圾文件。
	if dir := os.Getenv("AG_DUMP_PAYLOAD"); dir != "" {
		for _, p := range paths {
			dst := filepath.Join(dir, fmt.Sprintf("%s_%s", filepath.Base(apk), filepath.Base(p)))
			if err := os.WriteFile(dst, env.fs[p], 0o644); err != nil {
				t.Fatalf("导出载荷失败: %v", err)
			}
		}
	}

	names := make([]string, 0, len(found))
	for n := range found {
		names = append(names, n)
	}
	sort.Strings(names)
	t.Logf("%s：解密落地 %d 份 DEX（%d 个类）、只读标记 %d 份、dexPath=%s",
		apk, len(paths), len(found), len(env.readOnly), env.dexPath)
	t.Logf("%s：载荷类清单 %v", apk, names)
}

// TestArtifactShellOnly 审计 1-shell-only.apk。
func TestArtifactShellOnly(t *testing.T) {
	const apk = "../../../deliver/1-shell-only.apk"
	if _, err := os.Stat(apk); err != nil {
		t.Skipf("未找到 %s，跳过（交付包不在本机时属正常）", apk)
	}
	// Helper 是普通类，A1 会改名，因此只要求 Manifest 声明的组件存在。
	auditAPK(t, apk, "Lcom/apkguard/shell/Loader;", "",
		[]string{"Lcom/agtest/MainActivity;", "Lcom/agtest/MyApp;",
			"Lcom/agtest/HealthProvider;"}, false, 2)
}

// TestArtifactDeviceBind 审计 3-device-bind.apk 的壳链路与载荷。
//
// 这个包的**预期行为**是被 D5 拦停（绑定了一个不存在的设备标识），
// 但「被拦停」必须建立在「壳与载荷本身正确」之上，因此同样要审。
func TestArtifactDeviceBind(t *testing.T) {
	const apk = "../../../deliver/3-device-bind.apk"
	if _, err := os.Stat(apk); err != nil {
		t.Skipf("未找到 %s，跳过", apk)
	}
	// 该包未启用 B4（多 DEX 拆分），因此载荷只有 1 份。
	auditAPK(t, apk, "Lcom/apkguard/shell/Loader;", "",
		[]string{"Lcom/agtest/MainActivity;", "Lcom/agtest/MyApp;",
			"Lcom/agtest/HealthProvider;"}, false, 1)
}

// TestArtifactDebugShell 审计 D1-debug-shell.apk（含排障埋点）。
func TestArtifactDebugShell(t *testing.T) {
	const apk = "../../../deliver/D1-debug-shell.apk"
	if _, err := os.Stat(apk); err != nil {
		t.Skipf("未找到 %s，跳过", apk)
	}
	auditAPK(t, apk, "Lcom/apkguard/shell/Loader;", "Lcom/apkguard/shell/Ex;",
		[]string{"Lcom/agtest/MainActivity;", "Lcom/agtest/MyApp;",
			"Lcom/agtest/HealthProvider;"}, false, 2)
}

// TestArtifactFullChecks 审计 2-full-checks.apk（密钥由 native 派生，C1）。
func TestArtifactFullChecks(t *testing.T) {
	const apk = "../../../deliver/2-full-checks.apk"
	if _, err := os.Stat(apk); err != nil {
		t.Skipf("未找到 %s，跳过", apk)
	}
	auditAPK(t, apk, "Lcom/apkguard/shell/Loader;", "",
		[]string{"Lcom/agtest/MainActivity;", "Lcom/agtest/MyApp;",
			"Lcom/agtest/HealthProvider;"}, true, 2)
}

// TestArtifactDebugFull 审计 D2-debug-full.apk（C1 + 全部检测 + 埋点）。
func TestArtifactDebugFull(t *testing.T) {
	const apk = "../../../deliver/D2-debug-full.apk"
	if _, err := os.Stat(apk); err != nil {
		t.Skipf("未找到 %s，跳过", apk)
	}
	auditAPK(t, apk, "Lcom/apkguard/shell/Loader;", "Lcom/apkguard/shell/Ex;",
		[]string{"Lcom/agtest/MainActivity;", "Lcom/agtest/MyApp;",
			"Lcom/agtest/HealthProvider;"}, true, 2)
}

// TestArtifactDebugShellInstallsCrashHandler 验证排障包真的会装异常处理器。
//
// 这是本轮真机排查的命脉：如果包里的壳没装处理器，闪退就又是一个黑盒。
func TestArtifactDebugShellInstallsCrashHandler(t *testing.T) {
	const apk = "../../../deliver/D1-debug-shell.apk"
	if _, err := os.Stat(apk); err != nil {
		t.Skipf("未找到 %s，跳过", apk)
	}
	g, assets := apkShellDex(t, apk)
	fakeCode = map[string]uint32{}
	defer func() { fakeCode = map[string]uint32{} }()
	registerFakeCode(t, g, allClassNames(t, g)...)

	env := &loaderEnv{assets: assets, fs: map[string][]byte{}}
	restore := installLoaderMocks(env)
	defer restore()
	installActivityThreadMock()
	defer clearActivityThreadMock()
	restore2 := installDebugMocks()
	defer restore2()
	for k, h := range crashHandlerDeps() {
		fakeCalls[k] = h
	}
	log := []string{}
	toastLog = &log
	defer func() { toastLog = nil }()
	crashInstalled = false
	defer func() { crashInstalled = false }()

	// 壳会把 Context 与 ClassLoader 委托给原 Application，解释器需要知道
	// 这个类存在（真实设备上它来自解密后的载荷）。
	paramCtx := &fakeCls{name: "android.content.Context"}
	baseApp := &fakeCls{name: "android.app.Application",
		mths: []*fakeMth{{name: "attachBaseContext", params: []*fakeCls{paramCtx}}}}
	fakeClasses["com.agtest.MyApp"] = &fakeCls{name: "com.agtest.MyApp",
		supers: []*fakeCls{baseApp}}
	defer delete(fakeClasses, "com.agtest.MyApp")

	idx, off := findMethod(t, g, "Lcom/apkguard/shell/App;", "->attachBaseContext(")
	if _, err := runPadMethod(g, idx, off, &fakeObj{desc: "Lcom/apkguard/shell/App;"},
		&fakeObj{desc: descContext}); err != nil {
		t.Fatalf("壳 attachBaseContext 执行失败: %v", err)
	}
	if !crashInstalled {
		t.Fatal("排障包未安装全局异常处理器——闪退将无法定位")
	}
	if !containsStr(log, "AG1 壳已启动") {
		t.Fatalf("未看到启动埋点: %v", log)
	}
	t.Logf("埋点序列: %v", log)
}

// TestArtifactShellOnlyNoCrashHandler 验证正式包不含排障痕迹。
func TestArtifactShellOnlyNoCrashHandler(t *testing.T) {
	const apk = "../../../deliver/1-shell-only.apk"
	if _, err := os.Stat(apk); err != nil {
		t.Skipf("未找到 %s，跳过", apk)
	}
	g, _ := apkShellDex(t, apk)
	for _, n := range allClassNames(t, g) {
		if strings.HasSuffix(n, "/Ex;") {
			t.Fatalf("正式产物里出现了排障类 %s", n)
		}
	}
}

// referencedClasses 收集 DEX 中所有指令引用到的类描述符（去重计数）。
//
// 用指令表 insnRefs 逐条解析引用，而不是猜操作码——invoke 引用方法、
// iget/iput 引用字段，两者的第一跳都是「哪个类」。
func referencedClasses(t *testing.T, g *File) map[string]int {
	t.Helper()
	out := map[string]int{}
	err := g.walkAllCode(func(codeOff uint32) error {
		ci, err := g.ParseCodeItem(codeOff)
		if err != nil {
			return err
		}
		return walkInsns(ci.Insns, func(op byte, pos int, w []uint16) error {
			ref, ok := insnRefs[op]
			if !ok || pos+ref.word >= len(w) {
				return nil
			}
			var idx uint32
			if ref.wide {
				if pos+ref.word+1 >= len(w) {
					return nil
				}
				idx = uint32(w[pos+ref.word]) | uint32(w[pos+ref.word+1])<<16
			} else {
				idx = uint32(w[pos+ref.word])
			}
			switch ref.kind {
			case refMethod:
				d, err := g.MethodDesc(idx)
				if err != nil {
					return nil
				}
				if i := strings.Index(d, "->"); i > 0 {
					out[d[:i]]++
				}
			case refField:
				ci2, _, _, err := g.FieldRefAt(idx)
				if err != nil {
					return nil
				}
				d, err := g.Type(uint32(ci2))
				if err != nil {
					return nil
				}
				out[d]++
			case refType:
				d, err := g.Type(idx)
				if err != nil {
					return nil
				}
				out[d]++
			}
			return nil
		})
	})
	if err != nil {
		t.Fatalf("扫描引用失败: %v", err)
	}
	return out
}

// checkDanglingRefs 找出「引用了一个本应存在、却查无此类的类」。
//
// 这是改名（A1）最容易留下的伤：类被改名了，但某处引用没跟着改，
// 运行时就是 NoSuchMethodError / NoClassDefFoundError，表现为静默闪退，
// 而结构校验（dexdump）完全看不出来。判定范围限定在应用自身的包名内，
// 避免把框架类误报成悬空引用。
func checkDanglingRefs(t *testing.T, tag string, g *File, known map[string]bool, appPrefixes []string) {
	t.Helper()
	isApp := func(d string) bool {
		for _, p := range appPrefixes {
			if strings.HasPrefix(d, p) {
				return true
			}
		}
		return false
	}
	var dangling []string
	refs := referencedClasses(t, g)
	for d, n := range refs {
		if !isApp(d) || known[d] {
			continue
		}
		dangling = append(dangling, fmt.Sprintf("%s（被引用 %d 次）", d, n))
	}
	if len(dangling) > 0 {
		sort.Strings(dangling)
		t.Fatalf("%s：存在悬空引用（引用了不存在的类，运行时必然 NoClassDefFound/NoSuchMethod）: %v",
			tag, dangling)
	}
}

// checkMemberRefs 校验产物里的**成员引用**都能在「本 APK 定义的类」里解析到。
//
// 与 checkDanglingRefs（只看类型引用）互补：改名是按名称字符串生效的，若某个
// 成员引用在可见继承链里根本不存在，运行时会抛 NoSuchMethodError /
// NoSuchFieldError —— 这类错误 ART 在加载期**不报**，只在执行到那一行时才崩，
// 静态结构与 dex2oat verify 都看不见。实测就漏过一次（Termux 30 个 DEX 的
// 跨 DEX 成员改名不一致）。
//
// 判定边界（避免误报）：只检查「继承链完全落在本 APK 内」的类。若祖先里有框架
// 类型，其成员声明我们看不见，无从判定——那类问题需要库方法表，见 README 的
// 已知局限。
func checkMemberRefs(t *testing.T, tag string, files []*File) {
	t.Helper()
	type key struct{ name, proto string }
	decl := map[string]map[key]bool{}
	supers := map[string]string{}
	ifaces := map[string][]string{}
	for _, f := range files {
		infos, err := f.ClassInfos()
		if err != nil {
			t.Fatalf("%s：读取类信息失败: %v", tag, err)
		}
		for i := range infos {
			ci := &infos[i]
			if decl[ci.Desc] == nil {
				decl[ci.Desc] = map[key]bool{}
			}
			for _, m := range ci.Methods() {
				decl[ci.Desc][key{m.Name, m.Proto}] = true
			}
			for _, fl := range ci.Fields() {
				decl[ci.Desc][key{fl.Name, fl.Type}] = true
			}
			supers[ci.Desc] = ci.Super
			ifaces[ci.Desc] = ci.Interfaces
		}
	}
	// java.lang.Object 的成员不在 DEX 里重复声明，视作已知（否则全是误报）
	decl["Ljava/lang/Object;"] = map[key]bool{
		{"equals", "(Ljava/lang/Object;)Z"}: true, {"hashCode", "()I"}: true,
		{"toString", "()Ljava/lang/String;"}: true, {"clone", "()Ljava/lang/Object;"}: true,
		{"finalize", "()V"}: true, {"getClass", "()Ljava/lang/Class;"}: true,
		{"notify", "()V"}: true, {"notifyAll", "()V"}: true, {"wait", "()V"}: true,
		{"wait", "(J)V"}: true, {"wait", "(JI)V"}: true,
		{"registerNatives", "()V"}: true, {"<init>", "()V"}: true,
	}
	// 继承链是否完全可见
	invis := map[string]bool{}
	var tainted func(d string, depth int) bool
	tainted = func(d string, depth int) bool {
		if v, ok := invis[d]; ok {
			return v
		}
		invis[d] = false
		if depth > 32 {
			return false
		}
		res := false
		for _, anc := range append([]string{supers[d]}, ifaces[d]...) {
			if anc == "" || anc == "Ljava/lang/Object;" {
				continue
			}
			if _, ok := decl[anc]; !ok {
				res = true
				break
			}
			if tainted(anc, depth+1) {
				res = true
				break
			}
		}
		invis[d] = res
		return res
	}
	resolves := func(cls string, k key) bool {
		seen := map[string]bool{}
		var walk func(d string, depth int) bool
		walk = func(d string, depth int) bool {
			if d == "" || seen[d] || depth > 32 {
				return false
			}
			seen[d] = true
			if decl[d][k] {
				return true
			}
			if walk(supers[d], depth+1) {
				return true
			}
			for _, i := range ifaces[d] {
				if walk(i, depth+1) {
					return true
				}
			}
			return false
		}
		return walk(cls, 0)
	}

	var bad []string
	for _, f := range files {
		for i := uint32(0); i < f.NMethod; i++ {
			ref, err := f.MethodRefAt(i)
			if err != nil {
				continue
			}
			cls, err := f.Type(uint32(ref.ClassIdx))
			if err != nil || decl[cls] == nil || tainted(cls, 0) {
				continue
			}
			n, err1 := f.String(ref.NameIdx)
			pd, err2 := f.ProtoDesc(uint32(ref.ProtoIdx))
			if err1 != nil || err2 != nil {
				continue
			}
			if !resolves(cls, key{n, pd}) {
				bad = append(bad, fmt.Sprintf("方法 %s->%s%s", cls, n, pd))
			}
		}
		for i := uint32(0); i < f.NField; i++ {
			classIdx, typeIdx, nameIdx, err := f.FieldRefAt(i)
			if err != nil {
				continue
			}
			cls, err1 := f.Type(uint32(classIdx))
			ft, err2 := f.Type(uint32(typeIdx))
			n, err3 := f.String(nameIdx)
			if err1 != nil || err2 != nil || err3 != nil || decl[cls] == nil || tainted(cls, 0) {
				continue
			}
			if !resolves(cls, key{n, ft}) {
				bad = append(bad, fmt.Sprintf("字段 %s->%s:%s", cls, n, ft))
			}
		}
	}
	sort.Strings(bad)
	if len(bad) > 0 {
		seen := map[string]bool{}
		var uniq []string
		for _, b := range bad {
			if !seen[b] {
				seen[b] = true
				uniq = append(uniq, b)
			}
		}
		t.Fatalf("%s：存在悬空成员引用 %d 处（运行时 NoSuchMethod/NoSuchFieldError）：%v",
			tag, len(uniq), uniq[:min(len(uniq), 5)])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestArtifactS1NoDanglingRefs 检查纯混淆包（无壳）里有没有改名漏改的引用。
//
// S1 只开 A1/A2/A3/A4/A14 却闪退，而 S0（什么都不开）正常，
// 说明问题出在这些改写里；悬空引用是可能性最高的一种，且本地可查。
func TestArtifactS1NoDanglingRefs(t *testing.T) {
	const apk = "../../../deliver/S1-obf.apk"
	if _, err := os.Stat(apk); err != nil {
		t.Skipf("未找到 %s，跳过", apk)
	}
	g, _ := apkShellDex(t, apk)
	known := map[string]bool{}
	for _, n := range allClassNames(t, g) {
		known[n] = true
	}
	t.Logf("S1 定义的类: %v", allClassNames(t, g))
	checkDanglingRefs(t, "S1-obf", g, known, []string{"Lcom/agtest/"})
	checkMemberRefs(t, "S1-obf", []*File{g})
}

// TestArtifactShellOnlyNoDanglingRefs 检查壳包的载荷里有没有悬空引用。
func TestArtifactShellOnlyNoDanglingRefs(t *testing.T) {
	const apk = "../../../deliver/1-shell-only.apk"
	if _, err := os.Stat(apk); err != nil {
		t.Skipf("未找到 %s，跳过", apk)
	}
	g, assets := apkShellDex(t, apk)
	known := map[string]bool{}
	env := &loaderEnv{assets: assets, fs: map[string][]byte{}}
	restore := installLoaderMocks(env)
	defer restore()
	installActivityThreadMock()
	defer clearActivityThreadMock()
	fakeCode = map[string]uint32{}
	defer func() { fakeCode = map[string]uint32{} }()
	registerFakeCode(t, g, allClassNames(t, g)...)
	idx, off := findMethod(t, g, "Lcom/apkguard/shell/Loader;", "->"+LoaderEntry+"(")
	if _, err := runPadMethod(g, idx, off, &fakeObj{desc: descContext}); err != nil {
		t.Fatalf("壳链路执行失败: %v", err)
	}
	for _, p := range env.fs {
		pg, err := Parse(p)
		if err != nil {
			t.Fatalf("解析载荷失败: %v", err)
		}
		for _, n := range allClassNames(t, pg) {
			known[n] = true
		}
	}
	var payloads []*File
	for _, p := range env.fs {
		pg, err := Parse(p)
		if err != nil {
			t.Fatalf("解析载荷失败: %v", err)
		}
		payloads = append(payloads, pg)
		checkDanglingRefs(t, "1-shell-only 载荷", pg, known, []string{"Lcom/agtest/"})
	}
	// 成员引用要跨全部载荷一起解析（类被拆到不同分片是常态）
	checkMemberRefs(t, "1-shell-only 载荷", payloads)
}

// TestArtifactClassFlagsAreLegal 检查所有产物里的类标志是否落在「类能用的位」上。
//
// 回归防线：A2/A3 注入的还原类一度带着 ACC_STATIC——那是**成员**标志，
// 写在 class_def 上是非法组合（真实工具链产出的五万多个类里一个都没有）。
// 这类标志错误不会被我们自己的结构校验发现，也不会被 dexdump 拒绝，
// 但可能让 ART 在加载该类时直接失败，表现为静默闪退。
func TestArtifactClassFlagsAreLegal(t *testing.T) {
	glob, err := filepath.Glob("../../../deliver/*.apk")
	if err != nil {
		t.Fatalf("扫描交付目录失败: %v", err)
	}
	files := glob
	sort.Strings(files)
	// 类允许出现的位：PUBLIC/PRIVATE/PROTECTED/FINAL/INTERFACE/ABSTRACT/
	// SYNTHETIC/ANNOTATION/ENUM/SUPER。
	const legal = 0x0001 | 0x0002 | 0x0004 | 0x0010 | 0x0200 | 0x0400 |
		0x1000 | 0x2000 | 0x4000 | 0x0020
	checked := 0
	for _, apk := range files {
		g, assets := apkShellDex(t, apk)
		scan := func(tag string, gg *File) {
			if err := gg.Classes(func(i uint32, cd ClassDef, name string) error {
				checked++
				if bad := cd.AccessFlags &^ uint32(legal); bad != 0 {
					t.Errorf("%s 的类 %s 用了非法类标志 0x%04x（位 0x%04x 只能用于成员）",
						tag, name, cd.AccessFlags, bad)
				}
				return nil
			}); err != nil {
				t.Fatalf("%s 遍历类失败: %v", tag, err)
			}
		}
		scan(filepath.Base(apk), g)
		// 壳包里的载荷同样要查：业务类与还原类都在里面。
		if len(assets) > 0 && hasLoaderClass(g) {
			env := &loaderEnv{assets: assets, fs: map[string][]byte{}}
			restore := installLoaderMocks(env)
			installActivityThreadMock()
			fakeCode = map[string]uint32{}
			registerFakeCode(t, g, allClassNames(t, g)...)
			for k, h := range crashHandlerDeps() {
				fakeCalls[k] = h
			}
			if nativeKeyNeeded(g) {
				if raw, err := os.ReadFile("../../../deliver/signer-sha256.txt"); err == nil {
					if d, err := hex.DecodeString(strings.TrimSpace(string(raw))); err == nil && len(d) == 32 {
						fakeCalls[NativeBridgeClass+"->sig(Landroid/content/Context;)[B"] =
							func(*interp, []int) (int32, any, error) { return 0, &fakeBytes{b: d}, nil }
						fakeCalls[NativeBridgeClass+"->derive([B)[B"] =
							func(*interp, []int) (int32, any, error) {
								k := native.DeriveKey(d)
								return 0, &fakeBytes{b: k[:]}, nil
							}
					}
				}
			}
			if idx, off := findMethod(t, g, "Lcom/apkguard/shell/Loader;", "->"+LoaderEntry+"("); off != 0 {
				if _, err := runPadMethod(g, idx, off, &fakeObj{desc: descContext}); err == nil {
					for _, blob := range env.fs {
						if pg, err := Parse(blob); err == nil {
							scan(filepath.Base(apk)+" 载荷", pg)
						}
					}
				}
			}
			restore()
			clearActivityThreadMock()
			fakeCode = map[string]uint32{}
		}
	}
	if checked == 0 {
		t.Skip("交付包不在本机，跳过")
	}
	t.Logf("已检查 %d 个类定义的访问标志", checked)
}

// nativeKeyNeeded 判断该 DEX 里是否存在 native 桥接类（C1 生效的标志）。
func nativeKeyNeeded(g *File) bool {
	found := false
	_ = g.Classes(func(_ uint32, cd ClassDef, name string) error {
		if strings.HasSuffix(name, "/Native;") {
			found = true
		}
		return nil
	})
	return found
}

// TestDexVersionIsModern 验证新建 DEX 不使用远古版本号。
//
// 回归防线：壳 DEX 是「从零新建」的，魔数里的版本号一度写死成 035
// （安卓 2.2~7.x 的版本），而现代安卓对 DEX 版本有最低要求——这种文件
// 装得上、一打开就崩，本地结构校验全通过也看不出来。实测在安卓 16 上
// 原始 DEX 的 037 可用、035 不可用。
func TestDexVersionIsModern(t *testing.T) {
	e := Empty()
	if string(e[4:7]) == "035" {
		t.Fatal("新建 DEX 仍在使用 035 版本：现代安卓会拒绝加载")
	}
	if got := string(e[4:7]); got != "037" {
		t.Fatalf("新建 DEX 版本应为 037，实际 %s", got)
	}
	// 走完整 Build 流程的产物也必须是 037。
	add, err := CrashHandlerAddition("Lcom/x/Ex;")
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	out, err := Build(add)
	if err != nil {
		t.Fatalf("Build 失败: %v", err)
	}
	if got := string(out[4:7]); got != "037" {
		t.Fatalf("Build 产物版本应为 037，实际 %s", got)
	}
	// 重建已有 DEX 时必须沿用输入的版本（跟随原 APK，而不是统一改版）。
	src := sampleDex(t)
	rb, err := Rebuild(mustParse(t, src), RebuildOptions{})
	if err != nil {
		t.Fatalf("重建失败: %v", err)
	}
	if got, want := string(rb[4:7]), string(src[4:7]); got != want {
		t.Fatalf("重建应保留输入版本 %s，实际 %s", want, got)
	}
}

func mustParse(t *testing.T, data []byte) *File {
	t.Helper()
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	return f
}
