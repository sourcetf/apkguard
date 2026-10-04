package dex

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"

	"apkguard/internal/native"
)

// 本文件做一次**完整壳链路**的端到端验证。
//
// 目的与边界都要说清楚：
//   - 目的：把真正的壳字节码（App + Loader + Sig + Rt + Em + Dev + native 桥接类）
//     一次性跑完，验证各段**组合起来**是否正确——此前每个部件都有独立测试，
//     但「组合顺序、寄存器、类间调用」这类问题只有串起来跑才会暴露。
//   - 边界：这是在测试解释器里执行，不是真机。真机的 ART 行为（类加载、
//     DexClassLoader 的路径解析、ActivityThread 字段名）仍未被验证；
//     本轮尝试用 Android 模拟器补齐这一步，但嵌套虚拟化下 guest 无法进入系统，
//     详见交付说明。
//
// 采用的判定标准是「干净真机」：签名一致、无 su、Build 字段像真机、
// 设备标识匹配、无调试器/注入、原生库完整——全链必须放行并把业务 DEX 装好。

// fullShellFixture 汇总一次完整链路运行所需的全部模拟件。
type fullShellFixture struct {
	shellDex    []byte
	shellClass  string
	loaderClass string
	origName    string
	payload     []byte // 加密后的载荷（IV‖密文）
	plain       []byte // 业务 DEX 明文
	key         [32]byte
	cert        []byte
	certDigest  [32]byte
	deviceID    string
	className   []string // 需要登记给解释器的全部类
}

// buildFullShell 构造一个与真实产物等价的壳 DEX。
func buildFullShell(t *testing.T) *fullShellFixture { return buildFullShellOpts(t, false) }

// buildFullShellOpts 与 buildFullShell 相同，但可打开壳的逐步 Toast 埋点。
func buildFullShellOpts(t *testing.T, debug bool) *fullShellFixture {
	t.Helper()
	const (
		shellCls  = "Lcom/apkguard/shell/App;"
		loaderCls = "Lcom/apkguard/shell/Loader;"
		sigCls    = "Lcom/apkguard/shell/Sig;"
		rtCls     = "Lcom/apkguard/shell/Rt;"
		emCls     = "Lcom/apkguard/shell/Em;"
		devCls    = "Lcom/apkguard/shell/Dev;"
		origName  = "com.agtest.MyApp"
	)
	// 业务 DEX：用一个真实的小 DEX（空 DEX 即可，验证的是「密文被正确还原」）。
	plain := Empty()
	key := [32]byte{}
	cert := []byte("test-signing-certificate")
	certDigest := sha256.Sum256(cert)
	key = native.DeriveKey(certDigest[:])
	blob := mustEncrypt(t, plain, key, testPackIV)
	deviceID := "a1b2c3d4e5f6a7b8"

	ls := &LoaderSpec{
		Class:     loaderCls,
		Key:       key,
		TempDir:   "ag",
		NativeKey: NativeBridgeClass, // C1 生效：密钥由 native 派生
		Items:     []LoaderItem{{Asset: "assets/pay.bin", DexName: "d0.dex", Size: len(blob)}},
		Debug:     debug,
	}
	sh := &ShellApp{
		Class:  shellCls,
		Orig:   origName,
		Loader: ls,
		Debug:  debug,
		// 壳会按此顺序调用各检测；任一判定异常即终止进程。
		Checks: []string{sigCls, rtCls, emCls, devCls, NativeBridgeClass},
	}
	add, err := ShellAppAddition(sh)
	if err != nil {
		t.Fatalf("构造壳失败: %v", err)
	}
	merge := func(a Addition) {
		add = *mergeAddition(&add, a)
	}
	sigAdd, err := SigAddition(&SigSpec{Class: sigCls, Digest: certDigest})
	if err != nil {
		t.Fatalf("构造 Sig 失败: %v", err)
	}
	merge(sigAdd)
	rtAdd, err := EnvCheckAddition(&EnvCheckSpec{
		Class: rtCls, Paths: []string{"/system/bin/su", "/sbin/su"},
		Props: []PropCheck{{Field: FieldSpec{Class: descBuild, Name: "TAGS", Type: descStringType}, Sub: "test-keys"}},
	})
	if err != nil {
		t.Fatalf("构造 Rt 失败: %v", err)
	}
	merge(rtAdd)
	emAdd, err := EnvCheckAddition(&EnvCheckSpec{
		Class: emCls,
		Props: []PropCheck{
			{Field: FieldSpec{Class: descBuild, Name: "HARDWARE", Type: descStringType}, Sub: "goldfish"},
			{Field: FieldSpec{Class: descBuild, Name: "HARDWARE", Type: descStringType}, Sub: "ranchu"},
		},
	})
	if err != nil {
		t.Fatalf("构造 Em 失败: %v", err)
	}
	merge(emAdd)
	devAdd, err := DevAddition(&DevSpec{Class: devCls, Digest: sha256.Sum256([]byte(deviceID))})
	if err != nil {
		t.Fatalf("构造 Dev 失败: %v", err)
	}
	merge(devAdd)
	brAdd, err := NativeBridgeAddition(&NativeBridgeSpec{
		Class: NativeBridgeClass, LibName: NativeLibName,
		NeedDerive: true, NeedDecrypt: true, NeedDebug: true, NeedHooked: true, NeedIntact: true,
	})
	if err != nil {
		t.Fatalf("构造桥接类失败: %v", err)
	}
	merge(brAdd)

	out, err := Build(add)
	if err != nil {
		t.Fatalf("Build 失败: %v", err)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("壳 DEX 校验失败: %v", err)
	}
	classes := []string{shellCls, loaderCls, sigCls, rtCls, emCls, devCls, NativeBridgeClass}
	if debug {
		// 排障产物还会注入全局异常处理器，它的方法体也要登记给解释器。
		classes = append(classes, crashHandlerName(shellCls))
	}
	return &fullShellFixture{
		shellDex: out, shellClass: shellCls, loaderClass: loaderCls, origName: origName,
		payload: blob, plain: plain, key: key,
		cert: cert, certDigest: certDigest, deviceID: deviceID,
		className: classes,
	}
}

// deviceProfile 描述模拟的设备环境。
type deviceProfile struct {
	// emulator 为 true 时把 Build 字段设成模拟器特征（ranchu/goldfish）。
	emulator bool
	// rooted 为 true 时让 /system/bin/su 存在。
	rooted bool
	// androidID 是 Settings.Secure 返回的设备标识；空串表示返回 null。
	androidID string
	// apkCert 是 PackageManager 会返回的签名证书内容；
	// 运行时算出的摘要即 sha256(apkCert)，正是 native derive 的输入。
	apkCert []byte
	// debugged / hooked / intact 是 native 侧的检测结果。
	debugged, hooked, intact bool
}

// runFullShell 在一次模拟运行中执行完整壳链路。
//
// 返回 exit 码（-1 表示未终止）、落地文件环境，以及被写入的 mClassLoader 字段。
// 字段必须随返回值带出：本函数退出时它的 defer 会拆掉 ActivityThread 模拟，
// 调用方此时再去查表就查不到了。
func runFullShell(t *testing.T, fx *fullShellFixture, dp deviceProfile) (int, *loaderEnv, *fakeField, *fakeObj) {
	t.Helper()
	g, err := Parse(fx.shellDex)
	if err != nil {
		t.Fatalf("解析壳 DEX 失败: %v", err)
	}
	fakeCode = map[string]uint32{}
	defer func() { fakeCode = map[string]uint32{} }()
	registerFakeCode(t, g, fx.className...)

	// ---- 组合完整的模拟运行时 ----
	loaderEnvV := &loaderEnv{
		assets: map[string][]byte{"pay.bin": fx.payload},
		fs:     map[string][]byte{},
	}
	env := &envEnv{existing: map[string]bool{}, exitCode: -1}
	if dp.rooted {
		env.existing["/system/bin/su"] = true
	}
	devEnvV := &devEnv{exitCode: -1}
	if dp.androidID != "" {
		id := dp.androidID
		devEnvV.androidID = &id
	}
	sigEnvV := &sigEnv{certDER: dp.apkCert, exitCode: -1}

	// 顺序安装：后装的会覆盖同名处理器，因此 exit 用统一的自定义处理器兜底。
	restore1 := installLoaderMocks(loaderEnvV)
	defer restore1()
	restore2 := installEnvMocks(env)
	defer restore2()
	restore3 := installSigMocks(sigEnvV)
	defer restore3()
	restore4 := installDevMocks(devEnvV)
	defer restore4()
	// 接管 ClassLoader 要读 ActivityThread 的字段链。
	installActivityThreadMock()
	defer clearActivityThreadMock()
	// 排障埋点的模拟（Toast 记录 / 字段写入失效），以及按需制造异常反射环境。
	restore5 := installDebugMocks()
	defer restore5()

	// exit 必须真的终止执行：真实的 System.exit 会杀掉进程，之后不会再跑
	// 任何代码。若这里只记录不中断，被拦停的产物会「继续往下跑」，
	// 于是解密一段用错误密钥加密的载荷——测出来的就变成了 padding 错误，
	// 而不是「该检测生效」。
	exitCode := -1
	fakeCalls["Ljava/lang/System;->exit(I)V"] = func(in *interp, regs []int) (int32, any, error) {
		exitCode = int(in.regs[regs[0]])
		return 0, nil, errf("exit(%d)", exitCode)
	}
	// native 桥接类的四个 native 方法在解释器里用等价实现顶替：
	//   sig / derive 走 Go 侧同一实现（.so 内的 C 版本已与 Go 逐字节对拍），
	//   debugged / hooked / intact 用设备画像给定。
	// sig() 返回「本 APK 签名证书的摘要」——与 .so 里的实现同一语义。
	fakeCalls[NativeBridgeClass+"->sig(Landroid/content/Context;)[B"] =
		func(in *interp, regs []int) (int32, any, error) {
			d := sha256.Sum256(dp.apkCert)
			return 0, &fakeBytes{b: d[:]}, nil
		}
	// derive() 用收到的摘要做 KDF；Go 侧实现已与 .so 内的 C 版逐字节对拍。
	fakeCalls[NativeBridgeClass+"->derive([B)[B"] =
		func(in *interp, regs []int) (int32, any, error) {
			d := sha256.Sum256(dp.apkCert)
			k := native.DeriveKey(d[:])
			return 0, &fakeBytes{b: k[:]}, nil
		}
	fakeCalls[NativeBridgeClass+"->debugged()Z"] =
		func(in *interp, regs []int) (int32, any, error) {
			if dp.debugged {
				return 1, nil, nil
			}
			return 0, nil, nil
		}
	fakeCalls[NativeBridgeClass+"->hooked()Z"] =
		func(in *interp, regs []int) (int32, any, error) {
			if dp.hooked {
				return 1, nil, nil
			}
			return 0, nil, nil
		}
	fakeCalls[NativeBridgeClass+"->intact()Z"] =
		func(in *interp, regs []int) (int32, any, error) {
			if dp.intact {
				return 1, nil, nil
			}
			return 0, nil, nil
		}

	// 静态区：A 壳拼路径要的 File.pathSeparator，以及各检测要读的 Build 字段。
	objStatics = map[string]any{
		"Ljava/io/File;->pathSeparator": &fakeStr{s: ":"},
		"Landroid/os/Build;->TAGS":      &fakeStr{s: "release-keys"},
	}
	if dp.emulator {
		objStatics["Landroid/os/Build;->HARDWARE"] = &fakeStr{s: "ranchu"}
		objStatics["Landroid/os/Build;->FINGERPRINT"] = &fakeStr{s: "google/sdk_gphone/generic:11/RSR1/x:user/release-keys"}
	} else {
		objStatics["Landroid/os/Build;->HARDWARE"] = &fakeStr{s: "qcom"}
		objStatics["Landroid/os/Build;->FINGERPRINT"] = &fakeStr{s: "Xiaomi/redmi/redmi:13/TKQ1/x:user/release-keys"}
	}

	clField := loaderFields["android.app.LoadedApk"][0]
	// 异常反射环境（字段被隐藏 / 写入失效）在字段表就绪之后制造。
	if e2eActivityThreadHook != nil {
		e2eActivityThreadHook()
	}

	// 原 Application 类：同样故意不覆写 attachBaseContext，逼壳走父类链扫描。
	paramCtx := &fakeCls{name: "android.content.Context"}
	baseApp := &fakeCls{
		name: "android.app.Application",
		mths: []*fakeMth{{name: "attachBaseContext", params: []*fakeCls{paramCtx}}},
	}
	fakeClasses[fx.origName] = &fakeCls{name: fx.origName, supers: []*fakeCls{baseApp}}
	defer delete(fakeClasses, fx.origName)

	// native 桥接类本身不在 fakeClasses 里：它的 <clinit> 会调
	// System.loadLibrary，而 sig/derive 已被上面的处理器接管，无需真实类。
	fakeClasses[NativeBridgeJavaName] = &fakeCls{name: NativeBridgeJavaName}
	defer delete(fakeClasses, NativeBridgeJavaName)

	idx, off := findMethod(t, g, fx.shellClass, "->attachBaseContext(")
	_, err = runPadMethod(g, idx, off, &fakeObj{desc: fx.shellClass}, &fakeObj{desc: descContext})
	// 已被检测拦停时，栈展开是预期行为，不是失败。
	if err != nil && exitCode == -1 {
		t.Fatalf("壳 attachBaseContext 执行失败: %v", err)
	}
	// 静态区同样会被 defer 还原，因此把壳缓存的原 Application 一并带出。
	orig, _ := objStatics[fx.shellClass+"->"+shellFieldOrig].(*fakeObj)
	return exitCode, loaderEnvV, clField, orig
}

// TestFullShellChainOnCleanDevice 验证干净真机上整条链路放行且业务 DEX 装好。
func TestFullShellChainOnCleanDevice(t *testing.T) {
	fx := buildFullShell(t)
	dp := deviceProfile{
		androidID: fx.deviceID,
		apkCert:   fx.cert,
		intact:    true,
	}
	code, envV, clField, orig := runFullShell(t, fx, dp)
	if code != -1 {
		t.Fatalf("干净真机不应终止进程，实际 exit(%d)", code)
	}
	// 载荷必须被解密落地，且内容与业务 DEX 逐字节一致。
	got, ok := envV.fs["/data/user/0/app/ag/d0.dex"]
	if !ok {
		t.Fatalf("载荷未落地（已写入 %v）", keysOfBytes(envV.fs))
	}
	if !bytes.Equal(got, fx.plain) {
		t.Fatal("解密结果与业务 DEX 不一致")
	}
	// ClassLoader 必须被接管，且父加载器是系统加载器。
	if envV.clObj == nil {
		t.Fatal("未构造 DexClassLoader")
	}
	if !strings.Contains(envV.dexPath, "/ag/d0.dex") {
		t.Fatalf("dexPath 不含落地文件: %q", envV.dexPath)
	}
	if clField.val != envV.clObj {
		t.Fatal("DexClassLoader 未被写入 ActivityThread.mBoundApplication.info.mClassLoader")
	}
	// 原 Application 必须被实例化并收到同一个 Context。
	if orig == nil {
		t.Fatal("未把原 Application 实例写入静态字段")
	}
	cached := orig
	if cached.desc != "L"+strings.ReplaceAll(fx.origName, ".", "/")+";" {
		t.Fatalf("原 Application 类型不符: %s", cached.desc)
	}
	if cached.getField("$attach") != 1 {
		t.Fatalf("原 Application 的 attachBaseContext 应被调用 1 次，实际 %d", cached.getField("$attach"))
	}
	t.Log("完整壳链路：签名校验 → 环境检测 → 载荷解密 → ClassLoader 接管 → 委托原 Application，全部通过")
}

// TestFullShellChainBlocksAbnormalEnvironments 验证各检测在真实异常环境下确实拦停。
//
// 每个子场景只放开一个异常条件，确保「拦截」确实由对应检测触发，
// 而不是被别的检测顺手拦下。
func TestFullShellChainBlocksAbnormalEnvironments(t *testing.T) {
	fx := buildFullShell(t)
	clean := deviceProfile{
		androidID: fx.deviceID,
		apkCert:   fx.cert,
		intact:    true,
	}
	cases := []struct {
		name string
		mut  func(*deviceProfile)
	}{
		{"签名被换", func(d *deviceProfile) { d.apkCert = []byte("attacker-certificate") }},
		{"存在 su", func(d *deviceProfile) { d.rooted = true }},
		{"运行在模拟器", func(d *deviceProfile) { d.emulator = true }},
		{"设备不匹配", func(d *deviceProfile) { d.androidID = "9999999999999999" }},
		{"被调试", func(d *deviceProfile) { d.debugged = true }},
		{"被注入", func(d *deviceProfile) { d.hooked = true }},
		{"原生库被改", func(d *deviceProfile) { d.intact = false }},
	}
	for _, c := range cases {
		dp := clean
		c.mut(&dp)
		code, _, _, _ := runFullShell(t, fx, dp)
		if code != 1 {
			t.Errorf("%s：应 exit(1)，实际 exit(%d)（该检测未生效）", c.name, code)
		} else {
			t.Logf("  %s → 已拦停", c.name)
		}
	}
}
