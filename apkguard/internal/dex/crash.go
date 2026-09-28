package dex

import "fmt"

// 全局未捕获异常处理器（排障用）。
//
// 为什么需要它：注入的字节码不支持异常表，壳里无法 try/catch；一旦任何一步
// 抛异常，应用就是「一闪而过」，现场什么也不剩。本类通过
// Thread.setDefaultUncaughtExceptionHandler 抢在进程被杀之前把
// 「异常类名 + 消息」弹成 Toast——Toast 由系统进程渲染，即使我们随后立刻
// 杀掉自己，它依然会显示，因此能看到最终结论。
//
// 真机验证中它已经证明价值：Android 14 起不允许加载「可写」的 DEX 文件，
// 这类失败此前只会表现为闪退，现在会直接显示成
// "AGX java.lang.SecurityException: ..."。
//
// 仅排障产物注入（Debug 打开时），正式产物不含此类。

// crashHandlerField 是缓存 Context 的静态字段名。
const crashHandlerField = "c"

// crashHandlerSetCtx 是壳用来登记 Context 的静态方法名。
const crashHandlerSetCtx = "s"

// crashHandlerName 由壳类名推出处理器类名（同包，名字短且不与被改名的业务类冲突）。
//
// 壳是 ".../App;" → 处理器是 ".../Ex;"。
func crashHandlerName(shellClass string) string {
	base := shellClass
	if len(base) > 0 && base[len(base)-1] == ';' {
		base = base[:len(base)-1]
	}
	for i := len(base) - 1; i >= 0; i-- {
		if base[i] == '/' {
			return base[:i+1] + "Ex;"
		}
	}
	return base + "Ex;"
}

// CrashHandlerAddition 生成全局异常处理器类。
//
// 等价 Java：
//
//	public final class Ex implements Thread.UncaughtExceptionHandler {
//	    static Context c;
//	    public static void s(Context x) { c = x; }
//	    public void uncaughtException(Thread t, Throwable e) {
//	        String m = e.getClass().getName() + ": " + e.getMessage();
//	        if (c != null) Toast.makeText(c, "AGX " + m, 1).show();
//	        Log.e("APKGUARD", "AGX " + m);
//	        Process.killProcess(Process.myPid());   // 与默认处理器一样终止进程
//	    }
//	}
func CrashHandlerAddition(class string) (Addition, error) {
	if class == "" {
		return Addition{}, fmt.Errorf("dex: 异常处理器类名为空")
	}
	ctor, err := crashCtorCode()
	if err != nil {
		return Addition{}, err
	}
	setCtx, err := crashSetCtxCode(class)
	if err != nil {
		return Addition{}, err
	}
	uncaught, err := crashUncaughtCode(class)
	if err != nil {
		return Addition{}, err
	}

	protoV := ProtoSpec{Ret: "V"}
	protoCtxV := ProtoSpec{Ret: "V", Params: []string{descContext}}
	protoUE := ProtoSpec{Ret: "V",
		Params: []string{"Ljava/lang/Thread;", "Ljava/lang/Throwable;"}}

	spec := ClassSpec{
		Name:       class,
		Super:      descObject,
		Access:     accPublic | accFinal,
		Interfaces: []string{uncaughtHandlerInterface},
		Fields: []ClassField{
			{Name: crashHandlerField, Type: descContext, Access: accStatic},
		},
		Methods: []ClassMethod{
			{Name: "<init>", Proto: protoV, Access: accPublic, Code: ctor},
			{Name: crashHandlerSetCtx, Proto: protoCtxV, Access: accPublic | accStatic, Code: setCtx},
			{Name: "uncaughtException", Proto: protoUE, Access: accPublic, Code: uncaught},
		},
	}
	return Addition{
		Types: []string{descContext, "Ljava/lang/Thread;", "Ljava/lang/Throwable;"},
		Methods: []MethodSpec{
			{Class: class, Name: "<init>", Proto: protoV},
			{Class: class, Name: crashHandlerSetCtx, Proto: protoCtxV},
			{Class: class, Name: "uncaughtException", Proto: protoUE},
		},
		Fields:  []FieldSpec{{Class: class, Name: crashHandlerField, Type: descContext}},
		Classes: []ClassSpec{spec},
	}, nil
}

// uncaughtHandlerInterface 是处理器实现的框架接口。
const uncaughtHandlerInterface = "Ljava/lang/Thread$UncaughtExceptionHandler;"

// 本文件用到的两个常量（其余文件未引用，就近定义）。
const (
	// descProcess 是 android.os.Process，用于模拟默认处理器的「终止进程」。
	descProcess = "Landroid/os/Process;"
)

// crashCtorCode 生成 <init>()V：只调用 Object.<init>。
func crashCtorCode() (*CodeBlob, error) {
	objInit := MethodSpec{Class: descObject, Name: "<init>", Proto: ProtoSpec{Ret: "V"}}
	a := NewAsm()
	if err := a.InvokeDirect([]int{0}, objInit); err != nil {
		return nil, err
	}
	a.ReturnVoid()
	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	return &CodeBlob{Registers: 1, Ins: 1, Outs: 1, Insns: insns, Patches: patches}, nil
}

// crashSetCtxCode 生成 s(Context)V：把 Application 的 Context 存进静态字段。
func crashSetCtxCode(class string) (*CodeBlob, error) {
	f := FieldSpec{Class: class, Name: crashHandlerField, Type: descContext}
	a := NewAsm()
	a.SPutObject(0, f)
	a.ReturnVoid()
	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	return &CodeBlob{Registers: 1, Ins: 1, Outs: 0, Insns: insns, Patches: patches}, nil
}

// crashUncaughtCode 生成 uncaughtException(Thread, Throwable)V。
//
// registers=8、ins=3 → this 在 v5、t 在 v6、e 在 v7；v0..v4 为局部。
func crashUncaughtCode(class string) (*CodeBlob, error) {
	const (
		rMsg  = 0 // 最终消息
		rSb   = 1 // StringBuilder
		rT    = 2 // 临时
		rT2   = 3 // 临时
		rThis = 5
		rE    = 7 // 入参异常
	)
	ctxField := FieldSpec{Class: class, Name: crashHandlerField, Type: descContext}
	sbInit := MethodSpec{Class: descStringB, Name: "<init>", Proto: ProtoSpec{Ret: "V"}}
	sbAppend := MethodSpec{Class: descStringB, Name: "append",
		Proto: ProtoSpec{Ret: descStringB, Params: []string{descStringType}}}
	sbToString := MethodSpec{Class: descStringB, Name: "toString", Proto: ProtoSpec{Ret: descStringType}}
	getClass := MethodSpec{Class: descObject, Name: "getClass", Proto: ProtoSpec{Ret: descClass}}
	getName := MethodSpec{Class: descClass, Name: "getName", Proto: ProtoSpec{Ret: descStringType}}
	getMessage := MethodSpec{Class: "Ljava/lang/Throwable;", Name: "getMessage",
		Proto: ProtoSpec{Ret: descStringType}}
	logE := MethodSpec{Class: "Landroid/util/Log;", Name: "e",
		Proto: ProtoSpec{Ret: "I", Params: []string{descStringType, descStringType}}}
	myPid := MethodSpec{Class: descProcess, Name: "myPid", Proto: ProtoSpec{Ret: "I"}}
	kill := MethodSpec{Class: descProcess, Name: "killProcess",
		Proto: ProtoSpec{Ret: "V", Params: []string{"I"}}}
	tm := newToastM()

	a := NewAsm()
	// msg = e.getClass().getName() + ": " + e.getMessage()
	if err := a.InvokeVirtual([]int{rE}, getClass); err != nil {
		return nil, err
	}
	a.MoveResultObject(rT)
	if err := a.InvokeVirtual([]int{rT}, getName); err != nil {
		return nil, err
	}
	a.MoveResultObject(rT2)
	a.NewInstance(rSb, descStringB)
	if err := a.InvokeDirect([]int{rSb}, sbInit); err != nil {
		return nil, err
	}
	a.ConstString(rT, crashToastPrefix)
	if err := a.InvokeVirtual([]int{rSb, rT}, sbAppend); err != nil {
		return nil, err
	}
	if err := a.InvokeVirtual([]int{rSb, rT2}, sbAppend); err != nil {
		return nil, err
	}
	a.ConstString(rT, ": ")
	if err := a.InvokeVirtual([]int{rSb, rT}, sbAppend); err != nil {
		return nil, err
	}
	if err := a.InvokeVirtual([]int{rE}, getMessage); err != nil {
		return nil, err
	}
	a.MoveResultObject(rT)
	if err := a.InvokeVirtual([]int{rSb, rT}, sbAppend); err != nil {
		return nil, err
	}
	if err := a.InvokeVirtual([]int{rSb}, sbToString); err != nil {
		return nil, err
	}
	a.MoveResultObject(rMsg)

	// 有 Context 才弹 Toast：本类可能在壳登记 Context 之前就被用上。
	a.SGetObject(rT, ctxField)
	a.IfEqz(rT, "no_toast")
	if err := emitToastReg(a, tm, rT, rMsg, rT2); err != nil {
		return nil, err
	}
	a.Label("no_toast")

	// 同时写 logcat，便于以后能连 adb 时直接 grep。
	a.ConstString(rT, "APKGUARD")
	if err := a.InvokeStatic([]int{rT, rMsg}, logE); err != nil {
		return nil, err
	}
	// 与默认处理器一样终止进程：否则异常线程死亡后进程可能停在半死状态。
	if err := a.InvokeStatic(nil, myPid); err != nil {
		return nil, err
	}
	a.MoveResult(rT)
	if err := a.InvokeStatic([]int{rT}, kill); err != nil {
		return nil, err
	}
	a.ReturnVoid()

	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	return &CodeBlob{Registers: 8, Ins: 3, Outs: 3, Insns: insns, Patches: patches}, nil
}

// crashToastPrefix 是崩溃提示的前缀，便于在屏幕上一眼认出。
const crashToastPrefix = "AGX "
