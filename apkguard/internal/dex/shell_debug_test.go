package dex

import (
	"strings"
	"testing"
)

// 本文件验证排障埋点（-debug-shell）本身是可信的。
//
// 埋点的意义在于：真机闪退时它是唯一的观察通道。所以这里要证明两件事——
//   1) 干净环境下整条链路的 Toast 会按顺序弹完；
//   2) ClassLoader 接管失败时它能**区分**失败原因，而不是一律说「成功」。
// 第 2 点是重点：Android 9+ 的隐藏 API 限制会让 mClassLoader 的替换静默失效，
// 若不回读校验，产物在真机上只会表现为「一打开就崩」，看不出根因。

// Toast 相关的框架方法签名（与实际生成代码中使用的必须完全一致）。
const (
	toastMakeText = "Landroid/widget/Toast;->makeText(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;"
	toastShow     = "Landroid/widget/Toast;->show()V"
	fieldSetM     = "Ljava/lang/reflect/Field;->set(Ljava/lang/Object;Ljava/lang/Object;)V"
)

// toastLog 非 nil 时记录运行期间弹出的全部 Toast 文本。
var toastLog *[]string

// crashInstalled 记录壳是否安装了全局异常处理器；crashCtx 记录登记的 Context。
var crashInstalled bool
var crashCtx any

// killCalls 记录 killProcess 收到的 pid（崩溃处理器终止进程用）。
var killCalls []int

// fieldSetNoop 为 true 时把 Field.set 变成空操作，
// 用于模拟「字段可见但写入不生效」。
var fieldSetNoop bool

// e2eActivityThreadHook 在 ActivityThread 模拟搭好后执行，用于制造异常反射环境。
var e2eActivityThreadHook func()

// crashHandlerDeps 返回崩溃处理器运行所需的框架方法模拟。
//
// 处理器要读异常的类名与消息、写 logcat、并终止进程；这些都要在测试里
// 用等价的 Go 实现顶替，否则解释器会以「未实现的方法调用」失败。
func crashHandlerDeps() map[string]func(in *interp, regs []int) (int32, any, error) {
	return map[string]func(in *interp, regs []int) (int32, any, error){
		"Ljava/lang/Thread;->setDefaultUncaughtExceptionHandler(Ljava/lang/Thread$UncaughtExceptionHandler;)V": func(in *interp, regs []int) (int32, any, error) {
			if in.objs[regs[0]] == nil {
				return 0, nil, errf("setDefaultUncaughtExceptionHandler 收到 null")
			}
			crashInstalled = true
			return 0, nil, nil
		},
		"Ljava/lang/Throwable;->getMessage()Ljava/lang/String;": func(in *interp, regs []int) (int32, any, error) {
			o, ok := in.objs[regs[0]].(*fakeObj)
			if !ok {
				return 0, nil, errf("getMessage 的接收者不是异常")
			}
			msg, _ := o.aux.(string)
			return 0, &fakeStr{s: msg}, nil
		},
		"Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I": func(in *interp, regs []int) (int32, any, error) {
			tag, _ := in.objs[regs[0]].(*fakeStr)
			msg, _ := in.objs[regs[1]].(*fakeStr)
			if tag != nil && msg != nil && logLines != nil {
				logLines = append(logLines, tag.s+"|"+msg.s)
			}
			return 0, nil, nil
		},
		"Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I": func(in *interp, regs []int) (int32, any, error) {
			tag, _ := in.objs[regs[0]].(*fakeStr)
			msg, _ := in.objs[regs[1]].(*fakeStr)
			if tag != nil && msg != nil {
				logLines = append(logLines, tag.s+"|"+msg.s)
			}
			return 0, nil, nil
		},
		"Landroid/os/Process;->myPid()I": func(in *interp, regs []int) (int32, any, error) { return 4242, nil, nil },
		"Landroid/os/Process;->killProcess(I)V": func(in *interp, regs []int) (int32, any, error) {
			killCalls = append(killCalls, int(in.regs[regs[0]]))
			return 0, nil, nil
		},
	}
}

// logLines 记录处理写入的 logcat 行。
var logLines []string

// installDebugMocks 装好排障测试所需的模拟，返回还原函数。
func installDebugMocks() func() {
	saved := map[string]func(in *interp, regs []int) (int32, any, error){}
	for _, k := range []string{toastMakeText, toastShow, fieldSetM} {
		if h, ok := fakeCalls[k]; ok {
			saved[k] = h
		}
	}
	for k, h := range crashHandlerDeps() {
		if old, ok := fakeCalls[k]; ok {
			saved[k] = old
		}
		fakeCalls[k] = h
	}
	// Field.set 的包装必须在**调用时**读 fieldSetNoop：异常环境由测试在
	// 环境搭好之后才注入，安装时读到的还是 false。
	realSet := saved[fieldSetM]
	fakeCalls[fieldSetM] = func(in *interp, regs []int) (int32, any, error) {
		if fieldSetNoop {
			return 0, nil, nil
		}
		if realSet != nil {
			return realSet(in, regs)
		}
		return 0, nil, nil
	}
	saved[fieldSetM] = fakeCalls[fieldSetM]
	delete(saved, fieldSetM) // 由上方的还原逻辑统一处理
	// Toast 模拟始终安装，是否记录在**调用时**看 toastLog：
	// 测试通常在环境搭好之后才把记录缓冲挂上去，安装时读会永远读到 nil。
	fakeCalls[toastMakeText] = func(in *interp, regs []int) (int32, any, error) {
		if s, ok := in.objs[regs[1]].(*fakeStr); ok && toastLog != nil {
			*toastLog = append(*toastLog, s.s)
		}
		return 0, &fakeObj{desc: "Landroid/widget/Toast;"}, nil
	}
	fakeCalls[toastShow] = func(*interp, []int) (int32, any, error) { return 0, nil, nil }
	return func() {
		for k, h := range saved {
			fakeCalls[k] = h
		}
		for _, k := range []string{toastMakeText, toastShow, fieldSetM} {
			if _, ok := saved[k]; !ok {
				delete(fakeCalls, k)
			}
		}
	}
}

// cleanDevice 返回一个「干净真机」画像，用于让完整链路走到最后一步。
func cleanDevice(cert []byte, deviceID string) deviceProfile {
	return deviceProfile{
		androidID: deviceID, apkCert: cert,
		debugged: false, hooked: false, intact: true,
	}
}

// TestDebugShellToastSequence 验证干净环境下埋点按顺序弹完。
//
// 顺序本身就是诊断信息：哪一条之后没了，故障就在那一步之后。
func TestDebugShellToastSequence(t *testing.T) {
	fx := buildFullShellOpts(t, true)
	log := []string{}
	toastLog = &log
	defer func() { toastLog = nil }()

	code, _, clField, _ := runFullShell(t, fx, cleanDevice(fx.cert, fx.deviceID))
	if code != -1 {
		t.Fatalf("干净环境下不应终止进程，实际 exit=%d", code)
	}
	t.Logf("Toast 序列: %v", log)
	for _, want := range []string{
		"AG1 壳已启动",
		"AG2 环境检测通过",
		"AG-L2 DexClassLoader 就绪",
		"AG-L3 接管成功",
		"AG4 已委托原 Application",
	} {
		if !containsStr(log, want) {
			t.Fatalf("缺少 Toast %q（实际 %v）", want, log)
		}
	}
	// 接管成功必须与字段真实被改写相互印证——埋点说成功但字段没变，
	// 那埋点就是假信号，比没有埋点更糟。
	if clField.val == nil {
		t.Fatal("埋点报告接管成功，但 mClassLoader 并未被写入")
	}
	// 顺序检查：AG1 必须在 AG4 之前。
	if indexOfStr(log, "AG1 壳已启动") > indexOfStr(log, "AG4 已委托原 Application") {
		t.Fatalf("埋点顺序错乱: %v", log)
	}
}

// TestDebugShellReportsHiddenAPI 验证「隐藏 API 过滤」能被埋点明确指出。
//
// 模拟 Android 9+ 的行为：getDeclaredFields() 不再列出 LoadedApk.mClassLoader，
// 于是 setField 找不到字段、静默失败。此时埋点必须报「被隐藏API过滤」，
// 而不是含糊的失败，更不能报成功。
func TestDebugShellReportsHiddenAPI(t *testing.T) {
	fx := buildFullShellOpts(t, true)
	log := []string{}
	toastLog = &log
	defer func() { toastLog = nil }()
	// 抽掉 mClassLoader，等价于被隐藏 API 策略过滤掉。
	e2eActivityThreadHook = func() {
		loaderFields["android.app.LoadedApk"] = nil
		// 字段被过滤时 getDeclaredFields 返回空数组，Field.set 自然无从生效。
		fieldSetNoop = true
	}
	defer func() { e2eActivityThreadHook = nil; fieldSetNoop = false }()

	if _, _, clField, _ := runFullShell(t, fx, cleanDevice(fx.cert, fx.deviceID)); clField.val != nil {
		t.Fatal("字段被过滤的情况下 mClassLoader 不应被写入")
	}
	t.Logf("Toast 序列: %v", log)
	if !containsStr(log, "AG-L3 接管失败：mClassLoader 被隐藏API过滤") {
		t.Fatalf("未报告隐藏 API 过滤（实际 %v）", log)
	}
	if containsStr(log, "AG-L3 接管成功") {
		t.Fatal("接管并未生效，不应报告成功")
	}
}

// TestDebugShellReportsStaleValue 验证「字段看得见但写不进去」被单独报出。
//
// 这是第三种状态：字段在 getDeclaredFields 里（未被过滤），但 set 之后回读
// 仍是旧值——成因可能是 final 字段、或写入被其他机制回滚。它与前两种的
// 处置方式完全不同，因此必须区分。
func TestDebugShellReportsStaleValue(t *testing.T) {
	fx := buildFullShellOpts(t, true)
	log := []string{}
	toastLog = &log
	defer func() { toastLog = nil }()
	e2eActivityThreadHook = func() {
		// 字段可见，但预置一个非空旧值，且写入失效。
		loaderFields["android.app.LoadedApk"][0].val = &fakeObj{desc: "Ldalvik/system/PathClassLoader;"}
		fieldSetNoop = true
	}
	defer func() { e2eActivityThreadHook = nil; fieldSetNoop = false }()

	runFullShell(t, fx, cleanDevice(fx.cert, fx.deviceID))
	t.Logf("Toast 序列: %v", log)
	if !containsStr(log, "AG-L3 接管失败：mClassLoader 未写入") {
		t.Fatalf("未报告「写入未生效」（实际 %v）", log)
	}
}

// TestDebugOffProducesNoToast 验证埋点是可关闭的。
//
// 交付产物里绝不能出现 Toast：它既暴露壳的存在，也干扰用户。
func TestDebugOffProducesNoToast(t *testing.T) {
	fx := buildFullShellOpts(t, false)
	log := []string{}
	toastLog = &log
	defer func() { toastLog = nil }()

	runFullShell(t, fx, cleanDevice(fx.cert, fx.deviceID))
	if len(log) != 0 {
		t.Fatalf("未开启埋点时不应弹 Toast，实际 %v", log)
	}
}

func containsStr(list []string, want string) bool { return indexOfStr(list, want) >= 0 }

func indexOfStr(list []string, want string) int {
	for i, s := range list {
		if strings.Contains(s, want) {
			return i
		}
	}
	return -1
}

// TestCrashHandlerReportsException 验证全局异常处理器能把异常摊到屏幕上。
//
// 这是本轮真机排查的关键工具：注入的字节码没有异常表，壳里无法 try/catch，
// 任何一步抛异常都只表现为「一闪而过」。处理器在进程被杀之前把
// 「异常类名 + 消息」弹成 Toast，因此即使崩在最早期也能留下结论。
func TestCrashHandlerReportsException(t *testing.T) {
	const cls = "Lcom/apkguard/shell/Ex;"
	add, err := CrashHandlerAddition(cls)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	out, err := Build(add)
	if err != nil {
		t.Fatalf("Build 失败: %v", err)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("校验失败: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	// 类必须实现框架接口，否则 setDefaultUncaughtExceptionHandler 会拒绝它。
	if err := g.Classes(func(_ uint32, cd ClassDef, name string) error {
		if name != cls {
			return nil
		}
		got, err := g.typeList(cd.InterfacesOff)
		if err != nil {
			return err
		}
		if len(got) != 1 || got[0] != uncaughtHandlerInterface {
			t.Fatalf("应实现 %s，实际 %v", uncaughtHandlerInterface, got)
		}
		return nil
	}); err != nil {
		t.Fatalf("遍历类失败: %v", err)
	}

	restore := installLoaderMocks(&loaderEnv{})
	defer restore()
	restore2 := installDebugMocks()
	defer restore2()
	fakeCode = map[string]uint32{}
	defer func() { fakeCode = map[string]uint32{} }()
	registerFakeCode(t, g, cls)

	logLines, killCalls = nil, nil
	log := []string{}
	toastLog = &log
	defer func() { toastLog = nil }()

	ctx := &fakeObj{desc: descContext}
	setIdx, setOff := findMethod(t, g, cls, "->"+crashHandlerSetCtx+"(")
	if _, err := runPadMethod(g, setIdx, setOff, ctx); err != nil {
		t.Fatalf("%s 执行失败: %v", crashHandlerSetCtx, err)
	}
	idx, off := findMethod(t, g, cls, "->uncaughtException(")
	// 异常用 desc 表示类型，getClass().getName() 由解释器按类名返回。
	e := &fakeObj{desc: "Ljava/lang/SecurityException;", aux: "文件不可写"}
	if _, err := runPadMethod(g, idx, off, &fakeObj{desc: cls}, &fakeObj{desc: "Ljava/lang/Thread;"}, e); err != nil {
		t.Fatalf("uncaughtException 执行失败: %v", err)
	}
	t.Logf("Toast: %v", log)
	if len(log) != 1 {
		t.Fatalf("应弹 1 条 Toast，实际 %v", log)
	}
	want := "AGX java.lang.SecurityException: 文件不可写"
	if log[0] != want {
		t.Fatalf("Toast 文本不符：实际 %q 期望 %q", log[0], want)
	}
	// 必须同时写 logcat（将来能连 adb 时可直接 grep），并终止进程
	// ——返回而不杀进程会把应用留在主线程已死的半死状态。
	if len(logLines) != 1 || !strings.Contains(logLines[0], want) {
		t.Fatalf("logcat 未记录异常: %v", logLines)
	}
	if len(killCalls) != 1 || killCalls[0] != 4242 {
		t.Fatalf("应调用 killProcess(myPid())，实际 %v", killCalls)
	}
}

// TestCrashHandlerWithoutContext 验证未登记 Context 时不弹 Toast（只记日志）。
//
// 处理器可能在任何时刻被触发，包括壳还没来得及登记 Context 的时候。
// 此时 Context 为 null，若仍去 Toast 就会在处理器内部再抛一次 NPE。
func TestCrashHandlerWithoutContext(t *testing.T) {
	const cls = "Lcom/apkguard/shell/Ex;"
	add, err := CrashHandlerAddition(cls)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	out, err := Build(add)
	if err != nil {
		t.Fatalf("Build 失败: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	restore := installLoaderMocks(&loaderEnv{})
	defer restore()
	restore2 := installDebugMocks()
	defer restore2()
	fakeCode = map[string]uint32{}
	defer func() { fakeCode = map[string]uint32{} }()
	registerFakeCode(t, g, cls)

	logLines, killCalls = nil, nil
	log := []string{}
	toastLog = &log
	defer func() { toastLog = nil }()

	idx, off := findMethod(t, g, cls, "->uncaughtException(")
	e := &fakeObj{desc: "Ljava/lang/NullPointerException;", aux: "boom"}
	if _, err := runPadMethod(g, idx, off, &fakeObj{desc: cls}, &fakeObj{desc: "Ljava/lang/Thread;"}, e); err != nil {
		t.Fatalf("uncaughtException 执行失败: %v", err)
	}
	if len(log) != 0 {
		t.Fatalf("Context 为空时不应弹 Toast，实际 %v", log)
	}
	if len(killCalls) != 1 {
		t.Fatalf("即使不弹 Toast 也必须终止进程，实际 %v", killCalls)
	}
}

// TestShellInstallsCrashHandler 验证壳在 attachBaseContext 里就装好了处理器。
//
// 装机时机很重要：必须早于任何可能抛异常的操作，否则崩了仍然看不到东西。
func TestShellInstallsCrashHandler(t *testing.T) {
	fx := buildFullShellOpts(t, true)
	log := []string{}
	toastLog = &log
	defer func() { toastLog = nil }()
	crashInstalled = false
	defer func() { crashInstalled = false }()

	if _, _, _, _ = runFullShell(t, fx, cleanDevice(fx.cert, fx.deviceID)); !crashInstalled {
		t.Fatal("排障产物未安装全局异常处理器")
	}
	if indexOfStr(log, "AG1 壳已启动") == -1 {
		t.Fatalf("壳未正常启动: %v", log)
	}
	// 关闭埋点时不装处理器，正式产物里不留这个痕迹。
	fx2 := buildFullShellOpts(t, false)
	crashInstalled = false
	crashLog := []string{}
	toastLog = &crashLog
	runFullShell(t, fx2, cleanDevice(fx2.cert, fx2.deviceID))
	if crashInstalled {
		t.Fatal("正式产物（未开埋点）不应安装异常处理器")
	}
}
