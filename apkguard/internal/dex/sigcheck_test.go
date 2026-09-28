package dex

import (
	"crypto/sha256"
	"strings"
	"testing"
)

// 本文件验证 D1（签名校验）注入的 Sig 类。
//
// 验证方式是把它真正跑起来：模拟 PackageManager 返回本 APK 的签名证书，
// 分别断言「指纹一致时放行」与「指纹不一致时终止进程」。后者正是这套
// 防护的全部价值所在——重打包必然换签名，换过签名的产物必须起不来。

// sigEnv 汇总一次模拟运行中共享的状态。
type sigEnv struct {
	// certDER 是模拟 PackageManager 返回的签名证书内容。
	certDER []byte
	// exitCode 记录 System.exit 收到的参数；-1 表示未被调用。
	exitCode int
}

// installSigMocks 注册签名校验所需的框架 API 模拟。
func installSigMocks(env *sigEnv) func() {
	prev := map[string]func(in *interp, regs []int) (int32, any, error){}
	for k, v := range fakeCalls {
		prev[k] = v
	}
	h := map[string]func(in *interp, regs []int) (int32, any, error){}

	h["Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;"] =
		func(in *interp, regs []int) (int32, any, error) {
			return 0, &fakeObj{desc: descPackageManager}, nil
		}
	h["Landroid/content/Context;->getPackageName()Ljava/lang/String;"] =
		func(in *interp, regs []int) (int32, any, error) {
			return 0, &fakeStr{s: "com.example.app"}, nil
		}
	h["Landroid/content/pm/PackageManager;->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;"] =
		func(in *interp, regs []int) (int32, any, error) {
			// 校验调用方传入的 flags 就是 GET_SIGNATURES（64）。
			if got := in.regs[regs[2]]; got != pmGetSignatures {
				return 0, nil, errf("getPackageInfo 的 flags 应为 %d，实际 %d", pmGetSignatures, got)
			}
			sig := &fakeObj{desc: "Landroid/content/pm/Signature;", aux: env.certDER}
			pi := &fakeObj{desc: descPackageInfo}
			pi.setObjField("Landroid/content/pm/PackageInfo;->signatures",
				&fakeArr{desc: descSignatureArr, items: []any{sig}})
			return 0, pi, nil
		}
	h["Landroid/content/pm/Signature;->toByteArray()[B"] =
		func(in *interp, regs []int) (int32, any, error) {
			o, ok := in.objs[regs[0]].(*fakeObj)
			if !ok {
				return 0, nil, errf("toByteArray 的接收者不是 Signature")
			}
			b, _ := o.aux.([]byte)
			return 0, &fakeBytes{b: append([]byte(nil), b...)}, nil
		}
	h["Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;"] =
		func(in *interp, regs []int) (int32, any, error) {
			alg, ok := in.objs[regs[0]].(*fakeStr)
			if !ok {
				return 0, nil, errf("MessageDigest.getInstance 的实参不是字符串")
			}
			if alg.s != digestAlg {
				return 0, nil, errf("摘要算法应为 %s，实际 %s", digestAlg, alg.s)
			}
			return 0, &fakeObj{desc: descMessageDigest}, nil
		}
	h["Ljava/security/MessageDigest;->digest([B)[B"] =
		func(in *interp, regs []int) (int32, any, error) {
			b, ok := in.objs[regs[1]].(*fakeBytes)
			if !ok {
				return 0, nil, errf("digest 的实参不是 byte[]")
			}
			sum := sha256.Sum256(b.b)
			return 0, &fakeBytes{b: sum[:]}, nil
		}
	h["Ljava/lang/System;->exit(I)V"] = func(in *interp, regs []int) (int32, any, error) {
		env.exitCode = int(in.regs[regs[0]])
		return 0, nil, nil
	}

	// 合并而不是替换：多个安装器叠加后即得到完整的模拟运行时，
	// 返回值负责把整张表恢复原状（按相反顺序调用即可正确嵌套）。
	for k, v := range h {
		fakeCalls[k] = v
	}
	return func() { fakeCalls = prev }
}

// buildSigDex 构造只含签名校验类的 DEX，并返回其解析结果与类名。
func buildSigDex(t *testing.T, digest [32]byte) (*File, string) {
	t.Helper()
	const cls = "Lcom/apkguard/shell/Sig;"
	add, err := SigAddition(&SigSpec{Class: cls, Digest: digest})
	if err != nil {
		t.Fatalf("构造 Sig 失败: %v", err)
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
	return g, cls
}

// TestSigCheckAcceptsMatchingCert 验证签名一致时放行。
func TestSigCheckAcceptsMatchingCert(t *testing.T) {
	cert := []byte("apkguard-test-certificate-der")
	digest := sha256.Sum256(cert)
	g, cls := buildSigDex(t, digest)

	fakeCode = map[string]uint32{}
	defer func() { fakeCode = map[string]uint32{} }()
	registerFakeCode(t, g, cls)

	env := &sigEnv{certDER: cert, exitCode: -1}
	restore := installSigMocks(env)
	defer restore()

	idx, off := findMethod(t, g, cls, "->"+SigEntry+"(")
	if _, err := runPadMethod(g, idx, off, &fakeObj{desc: descContext}); err != nil {
		t.Fatalf("签名校验执行失败: %v", err)
	}
	if env.exitCode != -1 {
		t.Fatalf("签名一致时不应终止进程，实际 exit(%d)", env.exitCode)
	}
}

// TestSigCheckRejectsMismatchedCert 验证签名被换掉时终止进程。
func TestSigCheckRejectsMismatchedCert(t *testing.T) {
	// 内置指纹对应「原始证书」，运行时拿到的是「重打包者的证书」。
	want := sha256.Sum256([]byte("original-certificate"))
	g, cls := buildSigDex(t, want)

	fakeCode = map[string]uint32{}
	defer func() { fakeCode = map[string]uint32{} }()
	registerFakeCode(t, g, cls)

	env := &sigEnv{certDER: []byte("attacker-certificate"), exitCode: -1}
	restore := installSigMocks(env)
	defer restore()

	idx, off := findMethod(t, g, cls, "->"+SigEntry+"(")
	if _, err := runPadMethod(g, idx, off, &fakeObj{desc: descContext}); err != nil {
		t.Fatalf("签名校验执行失败: %v", err)
	}
	if env.exitCode != 1 {
		t.Fatalf("签名不一致时应 exit(1)，实际 exit(%d)（防护失效）", env.exitCode)
	}
	t.Log("D1：换签名后的产物在启动阶段即终止进程")
}

// TestSigCheckRejectsWrongLength 验证长度不同的指纹同样被拒。
//
// 单独测这一条：长度不同会提前返回，走的是与逐字节比对不同的分支。
func TestSigCheckRejectsWrongLength(t *testing.T) {
	digest := sha256.Sum256([]byte("x"))
	// 把指纹改成 31 字节，使其与运行时算出的 32 字节必然不等。
	short := digest
	digest31 := [32]byte{}
	copy(digest31[:], short[:31])
	g, cls := buildSigDex(t, digest31)

	fakeCode = map[string]uint32{}
	defer func() { fakeCode = map[string]uint32{} }()
	registerFakeCode(t, g, cls)

	env := &sigEnv{certDER: []byte("whatever"), exitCode: -1}
	restore := installSigMocks(env)
	defer restore()

	idx, off := findMethod(t, g, cls, "->"+SigEntry+"(")
	if _, err := runPadMethod(g, idx, off, &fakeObj{desc: descContext}); err != nil {
		t.Fatalf("签名校验执行失败: %v", err)
	}
	if env.exitCode != 1 {
		t.Fatalf("指纹长度不符时应 exit(1)，实际 exit(%d)", env.exitCode)
	}
}

// ---- D2 / D3 环境检测 ----

// envEnv 汇总一次环境检测模拟运行的状态。
type envEnv struct {
	// existing 是「模拟文件系统中存在的路径」。
	existing map[string]bool
	// props 是各静态字段的取值（键为 "类描述符->字段名"）。
	props map[string]any
	// exitCode 记录 System.exit 的参数；-1 表示未被调用。
	exitCode int
}

// installEnvMocks 注册环境检测所需的框架 API 模拟。
func installEnvMocks(env *envEnv) func() {
	prev := map[string]func(in *interp, regs []int) (int32, any, error){}
	for k, v := range fakeCalls {
		prev[k] = v
	}
	h := map[string]func(in *interp, regs []int) (int32, any, error){}

	h["Ljava/io/File;-><init>(Ljava/lang/String;)V"] =
		func(in *interp, regs []int) (int32, any, error) {
			o, ok := in.objs[regs[0]].(*fakeObj)
			if !ok {
				return 0, nil, errf("File 构造的接收者类型不对")
			}
			s, ok := in.objs[regs[1]].(*fakeStr)
			if !ok {
				return 0, nil, errf("File 的路径不是字符串")
			}
			o.aux = s.s
			return 0, nil, nil
		}
	h["Ljava/io/File;->exists()Z"] = func(in *interp, regs []int) (int32, any, error) {
		o, ok := in.objs[regs[0]].(*fakeObj)
		if !ok {
			return 0, nil, errf("exists 的接收者不是 File")
		}
		p, _ := o.aux.(string)
		if env.existing[p] {
			return 1, nil, nil
		}
		return 0, nil, nil
	}
	h["Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z"] =
		func(in *interp, regs []int) (int32, any, error) {
			s, ok := in.objs[regs[0]].(*fakeStr)
			if !ok {
				return 0, nil, errf("contains 的接收者不是字符串")
			}
			sub, ok := in.objs[regs[1]].(*fakeStr)
			if !ok {
				return 0, nil, errf("contains 的实参不是字符串")
			}
			if strings.Contains(s.s, sub.s) {
				return 1, nil, nil
			}
			return 0, nil, nil
		}
	h["Ljava/lang/System;->exit(I)V"] = func(in *interp, regs []int) (int32, any, error) {
		env.exitCode = int(in.regs[regs[0]])
		return 0, nil, nil
	}

	for k, v := range h {
		fakeCalls[k] = v
	}
	prevStatics := objStatics
	objStatics = map[string]any{}
	for k, v := range env.props {
		objStatics[k] = v
	}
	return func() {
		fakeCalls = prev
		objStatics = prevStatics
	}
}

// buildEnvDex 构造只含环境检测类的 DEX。
func buildEnvDex(t *testing.T, spec *EnvCheckSpec) (*File, string) {
	t.Helper()
	add, err := EnvCheckAddition(spec)
	if err != nil {
		t.Fatalf("构造环境检测类失败: %v", err)
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
	return g, spec.Class
}

// runEnvCheck 在模拟环境中执行一次检测，返回 exit 结果（-1 表示放行）。
func runEnvCheck(t *testing.T, spec *EnvCheckSpec, env *envEnv) int {
	t.Helper()
	g, cls := buildEnvDex(t, spec)
	fakeCode = map[string]uint32{}
	defer func() { fakeCode = map[string]uint32{} }()
	registerFakeCode(t, g, cls)
	restore := installEnvMocks(env)
	defer restore()

	idx, off := findMethod(t, g, cls, "->"+EnvCheckEntry+"(")
	if _, err := runPadMethod(g, idx, off, &fakeObj{desc: descContext}); err != nil {
		t.Fatalf("环境检测执行失败: %v", err)
	}
	return env.exitCode
}

// TestRootCheck 验证 Root 检测：干净环境放行，命中任一判据即终止。
func TestRootCheck(t *testing.T) {
	spec := &EnvCheckSpec{
		Class: "Lcom/apkguard/shell/Rt;",
		Paths: []string{"/system/bin/su", "/sbin/su", "/magisk/.core/bin/su"},
		Props: []PropCheck{{
			Field: FieldSpec{Class: descBuild, Name: "TAGS", Type: descStringType}, Sub: "test-keys",
		}},
	}
	// 干净环境：不存在的路径 + 正式版系统标签。
	if got := runEnvCheck(t, spec, &envEnv{existing: map[string]bool{}, exitCode: -1,
		props: map[string]any{"Landroid/os/Build;->TAGS": &fakeStr{s: "release-keys"}}}); got != -1 {
		t.Fatalf("干净环境不应终止进程，实际 exit(%d)", got)
	}
	// 命中文件判据。
	if got := runEnvCheck(t, spec, &envEnv{existing: map[string]bool{"/sbin/su": true}, exitCode: -1,
		props: map[string]any{"Landroid/os/Build;->TAGS": &fakeStr{s: "release-keys"}}}); got != 1 {
		t.Fatalf("存在 su 时应 exit(1)，实际 exit(%d)", got)
	}
	// 命中系统标签判据。
	if got := runEnvCheck(t, spec, &envEnv{existing: map[string]bool{}, exitCode: -1,
		props: map[string]any{"Landroid/os/Build;->TAGS": &fakeStr{s: "test-keys"}}}); got != 1 {
		t.Fatalf("test-keys 系统应 exit(1)，实际 exit(%d)", got)
	}
	// TAGS 为 null 时必须安全放行（不能因空值把应用搞崩）。
	if got := runEnvCheck(t, spec, &envEnv{existing: map[string]bool{}, exitCode: -1,
		props: map[string]any{}}); got != -1 {
		t.Fatalf("TAGS 为 null 时应安全放行，实际 exit(%d)", got)
	}
}

// TestEmulatorCheck 验证模拟器检测。
func TestEmulatorCheck(t *testing.T) {
	spec := &EnvCheckSpec{
		Class: "Lcom/apkguard/shell/Em;",
		Props: []PropCheck{
			{Field: FieldSpec{Class: descBuild, Name: "FINGERPRINT", Type: descStringType}, Sub: "generic"},
			{Field: FieldSpec{Class: descBuild, Name: "HARDWARE", Type: descStringType}, Sub: "goldfish"},
			{Field: FieldSpec{Class: descBuild, Name: "MANUFACTURER", Type: descStringType}, Sub: "Genymotion"},
		},
	}
	real := map[string]any{
		"Landroid/os/Build;->FINGERPRINT":  &fakeStr{s: "Xiaomi/redmi/redmi:13/TKQ1/1234:user/release-keys"},
		"Landroid/os/Build;->HARDWARE":     &fakeStr{s: "qcom"},
		"Landroid/os/Build;->MANUFACTURER": &fakeStr{s: "Xiaomi"},
	}
	if got := runEnvCheck(t, spec, &envEnv{exitCode: -1, props: real}); got != -1 {
		t.Fatalf("真机环境不应终止进程，实际 exit(%d)", got)
	}
	emu := map[string]any{
		"Landroid/os/Build;->FINGERPRINT":  &fakeStr{s: "google/sdk_gphone/generic:11/RSR1/1234:user/release-keys"},
		"Landroid/os/Build;->HARDWARE":     &fakeStr{s: "ranchu"},
		"Landroid/os/Build;->MANUFACTURER": &fakeStr{s: "Google"},
	}
	if got := runEnvCheck(t, spec, &envEnv{exitCode: -1, props: emu}); got != 1 {
		t.Fatalf("模拟器环境应 exit(1)，实际 exit(%d)", got)
	}
	// 字段缺失时必须安全放行。
	if got := runEnvCheck(t, spec, &envEnv{exitCode: -1, props: map[string]any{}}); got != -1 {
		t.Fatalf("Build 字段缺失时应安全放行，实际 exit(%d)", got)
	}
}

// TestNativeBridgeAddition 验证 native 桥接类的生成。
//
// 关注两点：native 方法必须**没有方法体**且带 ACC_NATIVE（否则 Dalvik
// 会把它们当成普通方法，加载时抛 AbstractMethodError 之类的错误），
// 以及 <clinit> 必须存在并调用 System.loadLibrary。
func TestNativeBridgeAddition(t *testing.T) {
	add, err := NativeBridgeAddition(&NativeBridgeSpec{
		Class: NativeBridgeClass, LibName: NativeLibName,
		NeedDerive: true, NeedDebug: true,
	})
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

	var cd ClassDef
	name := ""
	if err := g.Classes(func(_ uint32, c ClassDef, n string) error {
		cd, name = c, n
		return nil
	}); err != nil {
		t.Fatalf("遍历类失败: %v", err)
	}
	if name != NativeBridgeClass {
		t.Fatalf("类名不符: %s", name)
	}
	pcd, err := g.ParseClassData(cd.ClassDataOff)
	if err != nil {
		t.Fatalf("解析 class_data 失败: %v", err)
	}

	seen := map[string]bool{}
	for _, m := range append(append([]EncodedMethod(nil), pcd.DirectMethods...), pcd.VirtualMethods...) {
		d, _ := g.MethodDesc(m.Idx)
		switch {
		case strings.Contains(d, "-><clinit>()"):
			if m.CodeOff == 0 {
				t.Error("<clinit> 必须有方法体（要调用 System.loadLibrary）")
			}
			seen["clinit"] = true
		case strings.Contains(d, "->"+NativeDerive+"("):
			if m.CodeOff != 0 {
				t.Error("native 方法 derive 不应带方法体")
			}
			if m.Acc&accNative == 0 {
				t.Error("derive 缺少 ACC_NATIVE 标志")
			}
			seen["derive"] = true
		case strings.Contains(d, "->"+NativeDebugged+"()"):
			if m.CodeOff != 0 {
				t.Error("native 方法 debugged 不应带方法体")
			}
			if m.Acc&accNative == 0 {
				t.Error("debugged 缺少 ACC_NATIVE 标志")
			}
			seen["debugged"] = true
		case strings.Contains(d, "->"+NativeSig+"("):
			if m.CodeOff == 0 {
				t.Error("sig 是 Java 实现，必须有方法体")
			}
			seen["sig"] = true
		}
	}
	for _, want := range []string{"clinit", "derive", "debugged", "sig"} {
		if !seen[want] {
			t.Fatalf("缺少方法 %s（已见 %v）", want, seen)
		}
	}
	t.Log("C1/C4：native 桥接类结构正确（native 方法无方法体且带 ACC_NATIVE，<clinit> 负责加载库）")
}

// ---- D5 设备绑定 ----

// devEnv 汇总设备绑定模拟运行的状态。
type devEnv struct {
	// androidID 是模拟 Settings.Secure 返回的值；nil 表示返回 null。
	androidID *string
	exitCode  int
}

// installDevMocks 注册设备绑定所需的框架模拟。
func installDevMocks(env *devEnv) func() {
	prev := map[string]func(in *interp, regs []int) (int32, any, error){}
	for k, v := range fakeCalls {
		prev[k] = v
	}
	h := map[string]func(in *interp, regs []int) (int32, any, error){}
	h["Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;"] =
		func(in *interp, regs []int) (int32, any, error) {
			return 0, &fakeObj{desc: descContentResolver}, nil
		}
	h["Landroid/provider/Settings$Secure;->getString(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;"] =
		func(in *interp, regs []int) (int32, any, error) {
			key, ok := in.objs[regs[1]].(*fakeStr)
			if !ok {
				return 0, nil, errf("Settings.Secure.getString 的键不是字符串")
			}
			if key.s != androidIDKey {
				return 0, nil, errf("读取的键应为 %s，实际 %s", androidIDKey, key.s)
			}
			if env.androidID == nil {
				return 0, nil, nil
			}
			return 0, &fakeStr{s: *env.androidID}, nil
		}
	h["Ljava/lang/String;->getBytes()[B"] = func(in *interp, regs []int) (int32, any, error) {
		s, ok := in.objs[regs[0]].(*fakeStr)
		if !ok {
			return 0, nil, errf("getBytes 的接收者不是字符串")
		}
		return 0, &fakeBytes{b: []byte(s.s)}, nil
	}
	h["Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;"] =
		func(in *interp, regs []int) (int32, any, error) {
			return 0, &fakeObj{desc: descMessageDigest}, nil
		}
	h["Ljava/security/MessageDigest;->digest([B)[B"] =
		func(in *interp, regs []int) (int32, any, error) {
			b, ok := in.objs[regs[1]].(*fakeBytes)
			if !ok {
				return 0, nil, errf("digest 的实参不是 byte[]")
			}
			sum := sha256.Sum256(b.b)
			return 0, &fakeBytes{b: sum[:]}, nil
		}
	h["Ljava/lang/System;->exit(I)V"] = func(in *interp, regs []int) (int32, any, error) {
		env.exitCode = int(in.regs[regs[0]])
		return 0, nil, nil
	}
	// 合并而不是替换：多个安装器叠加后即得到完整的模拟运行时，
	// 返回值负责把整张表恢复原状（按相反顺序调用即可正确嵌套）。
	for k, v := range h {
		fakeCalls[k] = v
	}
	return func() { fakeCalls = prev }
}

// runDevCheck 在模拟环境中跑一次设备绑定校验，返回 exit 结果（-1 表示放行）。
func runDevCheck(t *testing.T, digest [32]byte, androidID *string) int {
	t.Helper()
	const cls = "Lcom/apkguard/shell/Dev;"
	add, err := DevAddition(&DevSpec{Class: cls, Digest: digest})
	if err != nil {
		t.Fatalf("构造 Dev 失败: %v", err)
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
	fakeCode = map[string]uint32{}
	defer func() { fakeCode = map[string]uint32{} }()
	registerFakeCode(t, g, cls)
	env := &devEnv{androidID: androidID, exitCode: -1}
	restore := installDevMocks(env)
	defer restore()

	idx, off := findMethod(t, g, cls, "->"+DevEntry+"(")
	if _, err := runPadMethod(g, idx, off, &fakeObj{desc: descContext}); err != nil {
		t.Fatalf("设备校验执行失败: %v", err)
	}
	return env.exitCode
}

// TestDeviceBind 验证设备绑定：授权设备放行，未授权设备终止，取不到标识放行。
func TestDeviceBind(t *testing.T) {
	authorized := "a1b2c3d4e5f6a7b8"
	digest := sha256.Sum256([]byte(authorized))
	other := "0000000000000000"

	if got := runDevCheck(t, digest, &authorized); got != -1 {
		t.Fatalf("授权设备不应终止进程，实际 exit(%d)", got)
	}
	if got := runDevCheck(t, digest, &other); got != 1 {
		t.Fatalf("未授权设备应 exit(1)，实际 exit(%d)（绑定失效）", got)
	}
	// 取不到标识必须放行：部分 ROM 限制读取，若判成未授权会误杀正常用户。
	if got := runDevCheck(t, digest, nil); got != -1 {
		t.Fatalf("取不到设备标识时应放行，实际 exit(%d)", got)
	}
	t.Log("D5：设备绑定生效（授权放行 / 未授权终止 / 信息缺失放行）")
}
