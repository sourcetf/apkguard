package dex

import (
	"fmt"

	"apkguard/internal/native"
)

// NativeBridgeSpec 描述 C1/C4 要注入的 native 桥接类。
//
// 类名固定在 com.apkguard.nativebridge 包下，**不随 ShellPkg 变化**：
// JNI 的静态符号名（Java_com_apkguard_nativebridge_Native_derive）在 .so
// 编译期就已确定，若类名可配置，预编译的 .so 就找不到方法，产物会在
// System.loadLibrary 之后调用 native 方法时抛 UnsatisfiedLinkError。
type NativeBridgeSpec struct {
	// Class 是桥接类的描述符。
	Class string
	// LibName 是传给 System.loadLibrary 的库名（不含 lib 前缀与 .so 后缀）。
	LibName string
	// NeedDerive 为 true 时声明 derive([B)[B（C1 需要）。
	NeedDerive bool
	// NeedDebug 为 true 时声明 debugged()Z（C4 需要）。
	NeedDebug bool
	// NeedHooked 为 true 时声明 hooked()Z（C5 需要）。
	NeedHooked bool
	// NeedIntact 为 true 时声明 intact()Z（C6 需要）。
	NeedIntact bool
	// NeedWatch 为 true 时声明 watch()Z（D4 需要）。
	//
	// D4 的语义是「运行时**定期**复检」：C6 的一次性校验只能挡住启动前
	// 已被修改的情况，而 Frida 之类的运行期补丁发生在启动之后，必须靠
	// 周期复检才能发现。watch() 启动 native 侧的守护线程并返回是否启动成功。
	NeedWatch bool
}

// 桥接类的 native 方法名。
const (
	// NativeHooked 返回是否检测到注入/Hook 框架。
	NativeHooked = "hooked"
	// NativeIntact 返回自身代码与常量是否未被篡改。
	NativeIntact = "intact"
	// NativeWatch 启动运行期周期性复检（D4）。
	NativeWatch = "watch"
)

// 这三个常量取自 native 包，避免与 JNI 符号名中的包路径各写一份而失配。
const (
	// NativeBridgeClass 是桥接类的固定描述符。
	NativeBridgeClass = native.BridgeClassDesc
	// NativeBridgeJavaName 是桥接类的 Java 点分名。
	NativeBridgeJavaName = native.BridgeClass
	// NativeLibName 是原生库名（对应 libapkguard.so）。
	NativeLibName = native.LibName
)

// 桥接类方法名。
const (
	// NativeDerive 返回载荷密钥：SHA-256(种子 ‖ 签名摘要)。
	NativeDerive = "derive"
	// NativeDebugged 返回是否检测到调试器。
	NativeDebugged = "debugged"
	// NativeSig 返回本 APK 签名证书的 SHA-256。
	NativeSig = "sig"
)

// NativeBridgeAddition 构造桥接类定义。
//
// 等价 Java：
//
//	package com.apkguard.nativebridge;
//	public class Native {
//	    static { System.loadLibrary("apkguard"); }
//	    public static native byte[] derive(byte[] sig);
//	    public static native boolean debugged();
//	    public static byte[] sig(Context ctx) { ...取签名证书的 SHA-256... }
//	}
func NativeBridgeAddition(spec *NativeBridgeSpec) (Addition, error) {
	if spec.Class == "" {
		return Addition{}, fmt.Errorf("dex: native 桥接类名为空")
	}
	if spec.LibName == "" {
		return Addition{}, fmt.Errorf("dex: native 库名为空")
	}
	if !spec.NeedDerive && !spec.NeedDebug && !spec.NeedHooked && !spec.NeedIntact && !spec.NeedWatch {
		return Addition{}, fmt.Errorf("dex: native 桥接类 %s 没有任何用途", spec.Class)
	}

	protoCtxBytes := ProtoSpec{Ret: descByteArray, Params: []string{descContext}}
	protoCtxV := ProtoSpec{Ret: "V", Params: []string{descContext}}
	protoBytesBytes := ProtoSpec{Ret: descByteArray, Params: []string{descByteArray}}
	protoBool := ProtoSpec{Ret: "Z"}
	protoV := ProtoSpec{Ret: "V"}

	clinit, err := nativeClinitCode(spec)
	if err != nil {
		return Addition{}, err
	}
	sigM, err := sigDigestCode(spec.Class, NativeSig)
	if err != nil {
		return Addition{}, err
	}

	methods := []ClassMethod{
		{Name: "<clinit>", Proto: protoV, Access: accStatic, Code: clinit},
		{Name: NativeSig, Proto: protoCtxBytes, Access: accPublic | accStatic, Code: sigM},
	}
	addMethods := []MethodSpec{
		{Class: spec.Class, Name: "<clinit>", Proto: protoV},
		{Class: spec.Class, Name: NativeSig, Proto: protoCtxBytes},
	}
	if spec.NeedDebug || spec.NeedHooked || spec.NeedIntact || spec.NeedWatch {
		// 壳按「static void a(Context)」的统一约定调用各项检测，
		// 因此把 native 检测包装成同一签名，壳无需为 native 检测写特例。
		check, err := nativeCheckCode(spec)
		if err != nil {
			return Addition{}, err
		}
		fail, err := sigFailCode(spec.Class)
		if err != nil {
			return Addition{}, err
		}
		methods = append(methods,
			ClassMethod{Name: EnvCheckEntry, Proto: protoCtxV, Access: accPublic | accStatic, Code: check},
			ClassMethod{Name: sigFailName, Proto: protoV, Access: accPrivate | accStatic, Code: fail},
		)
		addMethods = append(addMethods,
			MethodSpec{Class: spec.Class, Name: EnvCheckEntry, Proto: protoCtxV},
			MethodSpec{Class: spec.Class, Name: sigFailName, Proto: protoV},
		)
	}
	if spec.NeedDerive {
		methods = append(methods, ClassMethod{
			Name: NativeDerive, Proto: protoBytesBytes,
			Access: accPublic | accStatic | accNative,
		})
		addMethods = append(addMethods, MethodSpec{Class: spec.Class, Name: NativeDerive, Proto: protoBytesBytes})
	}
	for _, nm := range []struct {
		need bool
		name string
	}{
		{spec.NeedDebug, NativeDebugged},
		{spec.NeedHooked, NativeHooked},
		{spec.NeedIntact, NativeIntact},
		{spec.NeedWatch, NativeWatch},
	} {
		if !nm.need {
			continue
		}
		methods = append(methods, ClassMethod{
			Name: nm.name, Proto: protoBool,
			Access: accPublic | accStatic | accNative,
		})
		addMethods = append(addMethods, MethodSpec{Class: spec.Class, Name: nm.name, Proto: protoBool})
	}

	spec2 := ClassSpec{
		Name:    spec.Class,
		Super:   descObject,
		Access:  accPublic,
		Methods: methods,
	}
	return Addition{Methods: addMethods, Classes: []ClassSpec{spec2}}, nil
}

// nativeClinitCode 生成静态初始化块：加载原生库。
//
// 等价 Java：
//
//	static { System.loadLibrary("apkguard"); }
//
// 放在 <clinit> 里而不是显式调用：类一旦被触碰就必须完成加载，
// 否则 native 方法会以 UnsatisfiedLinkError 崩溃，且崩溃点离原因很远。
func nativeClinitCode(spec *NativeBridgeSpec) (*CodeBlob, error) {
	loadLib := MethodSpec{Class: descSystem, Name: "loadLibrary",
		Proto: ProtoSpec{Ret: "V", Params: []string{descStringType}}}

	a := NewAsm()
	a.ConstString(0, spec.LibName)
	if err := a.InvokeStatic([]int{0}, loadLib); err != nil {
		return nil, err
	}
	a.ReturnVoid()

	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	return &CodeBlob{Registers: 1, Ins: 0, Outs: 1, Insns: insns, Patches: patches}, nil
}

// sigDigestCode 生成「取本 APK 签名证书 SHA-256」的方法体。
//
// 等价 Java：
//
//	static byte[] sig(Context ctx) {
//	    PackageManager pm = ctx.getPackageManager();
//	    PackageInfo pi = pm.getPackageInfo(ctx.getPackageName(),
//	                                       PackageManager.GET_SIGNATURES);
//	    Signature[] ss = pi.signatures;
//	    if (ss == null || ss.length == 0) { return null; }
//	    return MessageDigest.getInstance("SHA-256").digest(ss[0].toByteArray());
//	}
//
// D1 的校验方法与 C1 的密钥派生都要用它，因此抽出来共用一份：
// 两处各写一遍的话，任何一处写错都会导致「指纹与证书不一致」这类
// 只能在真机上暴露的问题。
//
// registers=10、ins=1 → 入参 ctx 落在 v9。
func sigDigestCode(self, methodName string) (*CodeBlob, error) {
	const (
		rPM   = 0 // PackageManager
		rPI   = 1 // PackageInfo
		rSS   = 2 // Signature[]
		rCert = 3 // byte[]
		rGot  = 4 // byte[]
		rT0   = 5
		rT1   = 6
		rNil  = 7
		rCtx  = 9
	)
	getPackageManager := MethodSpec{Class: descContext, Name: "getPackageManager",
		Proto: ProtoSpec{Ret: descPackageManager}}
	getPackageName := MethodSpec{Class: descContext, Name: "getPackageName",
		Proto: ProtoSpec{Ret: descStringType}}
	getPackageInfo := MethodSpec{Class: descPackageManager, Name: "getPackageInfo",
		Proto: ProtoSpec{Ret: descPackageInfo, Params: []string{descStringType, "I"}}}
	fieldSigs := FieldSpec{Class: descPackageInfo, Name: "signatures", Type: descSignatureArr}
	toByteArray := MethodSpec{Class: "Landroid/content/pm/Signature;", Name: "toByteArray",
		Proto: ProtoSpec{Ret: descByteArray}}
	mdGetInstance := MethodSpec{Class: descMessageDigest, Name: "getInstance",
		Proto: ProtoSpec{Ret: descMessageDigest, Params: []string{descStringType}}}
	mdDigest := MethodSpec{Class: descMessageDigest, Name: "digest",
		Proto: ProtoSpec{Ret: descByteArray, Params: []string{descByteArray}}}

	a := NewAsm()
	if err := a.InvokeVirtual([]int{rCtx}, getPackageManager); err != nil {
		return nil, err
	}
	a.MoveResultObject(rPM)
	if err := a.InvokeVirtual([]int{rCtx}, getPackageName); err != nil {
		return nil, err
	}
	a.MoveResultObject(rT0)
	a.Const16(rT1, pmGetSignatures)
	if err := a.InvokeVirtual([]int{rPM, rT0, rT1}, getPackageInfo); err != nil {
		return nil, err
	}
	a.MoveResultObject(rPI)
	if err := a.IGetObject(rSS, rPI, fieldSigs); err != nil {
		return nil, err
	}
	// 取不到签名就返回 null：由调用方决定如何处置（D1 视为失败，
	// C1 则退化为仅用种子派生），不在这里替调用方做判断。
	a.IfEqz(rSS, "nil")
	a.ArrayLength(rT0, rSS)
	a.IfEqz(rT0, "nil")
	a.Const4(rT1, 0)
	a.AGetObject(rT0, rSS, rT1)
	if err := a.InvokeVirtual([]int{rT0}, toByteArray); err != nil {
		return nil, err
	}
	a.MoveResultObject(rCert)
	a.ConstString(rT0, digestAlg)
	if err := a.InvokeStatic([]int{rT0}, mdGetInstance); err != nil {
		return nil, err
	}
	a.MoveResultObject(rT0)
	if err := a.InvokeVirtual([]int{rT0, rCert}, mdDigest); err != nil {
		return nil, err
	}
	a.MoveResultObject(rGot)
	a.ReturnObject(rGot)

	a.Label("nil")
	a.Const4(rNil, 0)
	a.ReturnObject(rNil)

	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	// Outs 必须 >= 方法内任何一次 invoke 的参数字数：这里调用
	// PackageManager.getPackageInfo(String, int)，加上接收者共 3 字。
	// 声明偏小会被 ART 的校验器判 VerifyError（本地解释器不检查这一项）。
	return &CodeBlob{Registers: 10, Ins: 1, Outs: 3, Insns: insns, Patches: patches}, nil
}

// nativeCheckCode 生成 native 检测入口：static void a(Context)。
//
// 等价 Java（以三项全开为例）：
//
//	static void a(Context ctx) {
//	    if (debugged()) { f(); }
//	    if (hooked()) { f(); }
//	    if (!intact()) { f(); }
//	}
//
// 只在有 native 检测启用时生成：只用 C1（密钥派生）的场景不需要这段逻辑，
// 产物里也就不该留一个「检测到异常就退出」的行为。
//
// 各项检测都设计为**失败开放**（读不到状态即视为正常），因此这里不需要
// 额外的容错：误杀的代价远高于漏报。
//
// registers=3、ins=1 → 入参 ctx 落在 v2（本方法不使用它，
// 但保持与其它检测一致的签名，壳可以统一调用）。
func nativeCheckCode(spec *NativeBridgeSpec) (*CodeBlob, error) {
	failM := MethodSpec{Class: spec.Class, Name: sigFailName, Proto: ProtoSpec{Ret: "V"}}
	type check struct {
		name string
		// negate 为 true 表示「返回 false 才算异常」（完整性检测是
		// 「完整为 true」，与「检测到就为 true」的语义相反）。
		negate bool
	}
	var checks []check
	if spec.NeedDebug {
		checks = append(checks, check{name: NativeDebugged})
	}
	if spec.NeedHooked {
		checks = append(checks, check{name: NativeHooked})
	}
	if spec.NeedIntact {
		checks = append(checks, check{name: NativeIntact, negate: true})
	}

	a := NewAsm()
	// D4：启动运行期周期复检的守护线程。
	//
	// 不放在 checks 列表里：它不是「一次性判定」，而是「启动一个后台线程」，
	// 返回值只表示线程是否起来（起不来不影响业务，也不应误判为篡改）。
	if spec.NeedWatch {
		watchM := MethodSpec{Class: spec.Class, Name: NativeWatch, Proto: ProtoSpec{Ret: "Z"}}
		if err := a.InvokeStatic(nil, watchM); err != nil {
			return nil, err
		}
		a.MoveResult(0) // 结果只表示线程是否启动成功，无需处理
	}
	for i, c := range checks {
		m := MethodSpec{Class: spec.Class, Name: c.name, Proto: ProtoSpec{Ret: "Z"}}
		if err := a.InvokeStatic(nil, m); err != nil {
			return nil, err
		}
		a.MoveResult(0)
		done := fmt.Sprintf("ok%d", i)
		if c.negate {
			// if (intact()) return; 即「不完整才退出」。
			a.IfNez(0, done)
		} else {
			a.IfEqz(0, done)
		}
		if err := a.InvokeStatic(nil, failM); err != nil {
			return nil, err
		}
		a.Label(done)
	}
	a.ReturnVoid()

	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	return &CodeBlob{Registers: 3, Ins: 1, Outs: 1, Insns: insns, Patches: patches}, nil
}
