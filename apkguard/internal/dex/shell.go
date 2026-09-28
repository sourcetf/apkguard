package dex

import "fmt"

// ShellApp 描述 B2 要注入的壳 Application。
//
// 设计要点：壳类一律继承框架的 android.app.Application，而**不**继承原 APK 的
// Application 类。原因是 B1 会把原始 DEX 整体加密移除，壳 Application 被系统
// 加载时原 Application 类尚不存在（要等 attachBaseContext 里解密后才可加载），
// 若静态继承它，类加载阶段就会直接失败。
//
// 因此对原 Application 的委托改为运行时反射：
//   - attachBaseContext：原方法在 ContextWrapper 中是 protected，且原类
//     未必覆写它，故用「沿父类链扫描 getDeclaredMethods」的方式定位，
//     全程不依赖异常（getDeclaredMethods 不会抛 NoSuchMethodException）；
//   - onCreate：public 方法，直接 invoke-virtual 调用。
//
// 已知限制（需人工确认是否可接受）：
//   - 原 Application 实例由反射新建，未注册到 ActivityThread，
//     因此 getApplication() 返回的是壳实例；少数依赖该实例完成系统绑定的
//     第三方 SDK 可能行为受限；
//   - 反射新建要求原 Application 有可访问的无参构造器（Application 的常规写法）。
type ShellApp struct {
	// Class 是壳 Application 的类描述符，形如 "Lapkguard/App;"。
	Class string
	// Orig 是原 Manifest 中声明的 Application 类名（Java 点分名）。
	//
	// 为空表示原 APK 未声明 android:name，此时壳只调用父类实现，不做委托。
	Orig string
	// Loader 非 nil 时启用 B3：attachBaseContext 先由 Loader 解密载荷并接管
	// ClassLoader，再用接管后的加载器加载原 Application。
	//
	// 为 nil 表示脚本未启用 B3（例如 B1 关闭、原始 DEX 仍在 APK 中），
	// 此时直接用壳自身的 ClassLoader 加载原 Application。
	Loader *LoaderSpec
	// NativeKey 非空时（C1 生效）载荷密钥不在字节码里，而由该桥接类
	// 在运行时向 native 库索取。空串表示密钥仍以内联常量形式存在。
	NativeKey string
	// Debug 为 true 时，壳会在每个关键步骤后用 Toast 把进度显示到屏幕上。
	//
	// 存在的理由：注入代码没有异常表，无法 try/catch 出错误——一旦某步抛异常，
	// 应用直接闪退，现场只剩「一闪而过」。而在没有 adb 的真机上，logcat 也读不到。
	// 用 Toast 逐步打卡，就能让「哪一步没弹出来」直接指出故障位置。
	// 仅用于排障，正常产物不要开启（会向用户暴露壳的存在）。
	Debug bool
	// Checks 是启动时要依序调用的检测类（签名校验、Root 检测、模拟器检测…），
	// 元素为类描述符，每个类都提供 static void a(Context)。
	//
	// 只存类名：类体由各自的 Pass 注入，壳这里只生成调用。任一检测判定
	// 环境异常都会终止进程，因此顺序上把最便宜、最决定性的放在前面。
	Checks []string
}

// 壳 Application 引用的框架类型。
const (
	descApplication = "Landroid/app/Application;"
	descContext     = "Landroid/content/Context;"
	descClass       = "Ljava/lang/Class;"
	descMethod      = "Ljava/lang/reflect/Method;"
	descString      = "Ljava/lang/String;"
	descObject      = "Ljava/lang/Object;"
	descClassArr    = "[Ljava/lang/Class;"
	descMethodArr   = "[Ljava/lang/reflect/Method;"
	descObjectArr   = "[Ljava/lang/Object;"
)

// accSuper 标记「父类不是 Object」，DEX 中非根类都应置位。
const accSuper = 0x0020

// accFinal 标记不可继承的类 / 不可覆盖的成员。
//
// 注意区分：accStatic 是**成员**标志，绝不能写在 class_def 的 access_flags 上。
// 真实工具链产出的 DEX 里五万多个类没有一个带 STATIC（也没有带 SUPER 的），
// 而类标志里出现 STATIC 属于非法组合，某些校验路径会直接拒绝整个类。
const accFinal = 0x0010

// shellFieldOrig 是壳类中保存原 Application 实例的静态字段名。
const shellFieldOrig = "orig"

// shellHelperName 是壳类中执行反射委托的静态辅助方法名。
const shellHelperName = "a"

// ShellAppAddition 构造注入壳 Application 所需的全部条目与类定义。
//
// 启用 B3 时会把 Loader 类一并注入，并让 attachBaseContext 先去调用它。
// 方法体引用的全部符号（类型/原型/方法/字段）由 rebuild 流程在建立索引表前
// 自动登记（见 expandAdditionRefs），因此这里无需手工罗列。
func ShellAppAddition(sh *ShellApp) (Addition, error) {
	if sh.Class == "" {
		return Addition{}, fmt.Errorf("dex: 壳 Application 类名为空")
	}

	protoV := ProtoSpec{Ret: "V"}
	protoCtxV := ProtoSpec{Ret: "V", Params: []string{descContext}}
	// 委托辅助方法的原型：(Context, ClassLoader)V。
	//
	// 第二个参数是接管后的 ClassLoader：B3 生效时它是解密载荷构建出的
	// DexClassLoader，未启用时退化为壳自身的加载器。
	protoCLV := ProtoSpec{Ret: "V", Params: []string{descContext, descClassLoader}}

	appInit := MethodSpec{Class: descApplication, Name: "<init>", Proto: protoV}
	appAttach := MethodSpec{Class: descApplication, Name: "attachBaseContext", Proto: protoCtxV}
	appOnCreate := MethodSpec{Class: descApplication, Name: "onCreate", Proto: protoV}

	fieldOrig := FieldSpec{Class: sh.Class, Name: shellFieldOrig, Type: descApplication}

	ctor, err := shellCtorCode(appInit)
	if err != nil {
		return Addition{}, err
	}
	attach, err := shellAttachCode(sh, appAttach, fieldOrig)
	if err != nil {
		return Addition{}, err
	}
	onCreate, err := shellOnCreateCode(appOnCreate, fieldOrig)
	if err != nil {
		return Addition{}, err
	}

	spec := ClassSpec{
		Name:   sh.Class,
		Super:  descApplication,
		Access: accPublic | accSuper,
		Fields: []ClassField{{Name: shellFieldOrig, Type: descApplication, Access: accPrivate | accStatic}},
		Methods: []ClassMethod{
			{Name: "<init>", Proto: protoV, Access: accPublic, Code: ctor},
			{Name: "attachBaseContext", Proto: protoCtxV, Access: accProtected, Code: attach},
			{Name: "onCreate", Proto: protoV, Access: accPublic, Code: onCreate},
		},
	}

	if sh.Orig != "" {
		helper, err := shellDelegateCode(sh, fieldOrig)
		if err != nil {
			return Addition{}, err
		}
		spec.Methods = append(spec.Methods, ClassMethod{
			Name: shellHelperName, Proto: protoCLV,
			Access: accPrivate | accStatic, Code: helper,
		})
	}

	add := Addition{Classes: []ClassSpec{spec}}
	// 排障产物同时注入全局异常处理器：壳在 attachBaseContext 里会安装它，
	// 之后任何未捕获异常都会先被弹成 Toast 再终止进程。
	if sh.Debug {
		crashAdd, err := CrashHandlerAddition(crashHandlerName(sh.Class))
		if err != nil {
			return Addition{}, err
		}
		add = *mergeAddition(&add, crashAdd)
	}
	// 只有当 LoaderSpec 已完整描述载荷时才在此一并生成 Loader 类体。
	//
	// 分层加壳流程（B2 建壳、B3 注入 Loader）里 B2 只填类名，用来让壳生成
	// 对 Loader.a 的调用；那个方法引用会经由 expandAdditionRefs 自动登记，
	// 而类体留给 B3 注入——否则同一个类会被定义两次。
	if sh.Loader != nil && len(sh.Loader.Items) > 0 {
		loadAdd, err := LoaderAddition(sh.Loader)
		if err != nil {
			return Addition{}, err
		}
		add = *mergeAddition(&add, loadAdd)
	}
	return add, nil
}

// shellCtorCode 生成 <init>()V：仅调用父类构造器。
func shellCtorCode(appInit MethodSpec) (*CodeBlob, error) {
	a := NewAsm()
	if err := a.InvokeDirect([]int{0}, appInit); err != nil {
		return nil, err
	}
	a.ReturnVoid()
	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	return &CodeBlob{Registers: 1, Ins: 1, Outs: 1, Insns: insns, Patches: patches}, nil
}

// shellAttachCode 生成 attachBaseContext(Context)V。
//
// 等价 Java 源码（启用 B3）：
//
//	protected void attachBaseContext(Context base) {
//	    super.attachBaseContext(base);   // 先让框架完成 Context 绑定
//	    ClassLoader cl = Loader.a(base); // 解密载荷并接管 ClassLoader
//	    a(base, cl);                     // 再委托给原 Application
//	}
//
// 顺序不可颠倒：原 Application 的类位于被加密的载荷里，必须等 Loader 把
// ClassLoader 换成能看见解密后 DEX 的那一个，Class.forName 才可能成功。
//
// 未启用 B3（且原始 DEX 仍在 APK 中）时没有载荷需要解密，改用壳自身的
// ClassLoader：此时原 Application 与壳在同一个加载器下，同样可解析。
//
// registers=3、ins=2 → 入参占最高两个寄存器：v1=this、v2=base；v0 为局部。
func shellAttachCode(sh *ShellApp, appAttach MethodSpec, fieldOrig FieldSpec) (*CodeBlob, error) {
	// 寄存器布局随 Debug 变化：排障版本需要 3 个临时寄存器打 Toast，
	// 因此把入参整体上移，避免与局部变量抢占。
	nRegs := uint16(3)
	rCL, rThis, rBase := 0, 1, 2
	rT0, rT2, rH := 0, 0, 0
	if sh.Debug {
		nRegs = 10
		rCL, rT0, rT2, rH = 0, 1, 3, 4
		rThis, rBase = 8, 9
	}
	nOuts := uint16(2)
	if sh.Debug {
		nOuts = 3 // Toast.makeText(Context, CharSequence, int)
	}
	tm := newToastM()
	a := NewAsm()
	toast := func(msg string) error {
		if !sh.Debug {
			return nil
		}
		return emitToast(a, tm, rBase, rT0, rT2, msg)
	}
	if err := a.InvokeSuper([]int{rThis, rBase}, appAttach); err != nil {
		return nil, err
	}
	if err := toast("AG1 壳已启动"); err != nil {
		return nil, err
	}
	// 全局异常处理器必须最先装：注入代码没有异常表，之后任何一步抛异常都会
	// 直接杀进程，只有它能在进程死前把「异常类名 + 消息」弹到屏幕上。
	if sh.Debug {
		handler := crashHandlerName(sh.Class)
		setCtx := MethodSpec{Class: handler, Name: crashHandlerSetCtx,
			Proto: ProtoSpec{Ret: "V", Params: []string{descContext}}}
		ctor := MethodSpec{Class: handler, Name: "<init>", Proto: ProtoSpec{Ret: "V"}}
		setHandler := MethodSpec{Class: "Ljava/lang/Thread;", Name: "setDefaultUncaughtExceptionHandler",
			Proto: ProtoSpec{Ret: "V", Params: []string{uncaughtHandlerInterface}}}
		if err := a.InvokeStatic([]int{rBase}, setCtx); err != nil {
			return nil, err
		}
		a.NewInstance(rH, handler)
		if err := a.InvokeDirect([]int{rH}, ctor); err != nil {
			return nil, err
		}
		if err := a.InvokeStatic([]int{rH}, setHandler); err != nil {
			return nil, err
		}
	}
	// 各项检测最先执行：重打包/异常环境的产物应当立刻退出，而不是先解密
	// 加载一遍业务代码再退出——那既浪费启动时间，也给攻击者留出观察窗口。
	for _, cls := range sh.Checks {
		check := MethodSpec{Class: cls, Name: EnvCheckEntry,
			Proto: ProtoSpec{Ret: "V", Params: []string{descContext}}}
		if err := a.InvokeStatic([]int{rBase}, check); err != nil {
			return nil, err
		}
	}
	if len(sh.Checks) > 0 {
		// 检测不通过时进程会被直接终止（System.exit/Process.killProcess），
		// 因此这条 Toast 没出现本身就说明「被检测拦截了」。
		if err := toast("AG2 环境检测通过"); err != nil {
			return nil, err
		}
	}
	// 解密与 ClassLoader 接管必须**无条件**执行，与原 APK 是否声明
	// android:name 无关：载荷里装的是整个业务 DEX，不接管加载器的话
	// Manifest 中声明的 Activity/Service 依然会由旧加载器加载而找不到类，
	// 表现为「应用能装、一打开就崩」。
	if sh.Loader != nil {
		entry := MethodSpec{Class: sh.Loader.Class, Name: LoaderEntry,
			Proto: ProtoSpec{Ret: descClassLoader, Params: []string{descContext}}}
		if err := a.InvokeStatic([]int{rBase}, entry); err != nil {
			return nil, err
		}
		a.MoveResultObject(rCL)
		if err := toast("AG3 载荷解密并接管返回"); err != nil {
			return nil, err
		}
	}
	if sh.Orig != "" {
		if sh.Loader == nil {
			// 没有载荷要解密（未启用 B1）时，原 Application 与壳同处一个
			// 加载器之下，直接用壳自身的加载器即可。
			a.ConstClass(rCL, sh.Class)
			getCL := MethodSpec{Class: descClass, Name: "getClassLoader",
				Proto: ProtoSpec{Ret: descClassLoader}}
			if err := a.InvokeVirtual([]int{rCL}, getCL); err != nil {
				return nil, err
			}
			a.MoveResultObject(rCL)
		}
		helper := MethodSpec{Class: fieldOrig.Class, Name: shellHelperName,
			Proto: ProtoSpec{Ret: "V", Params: []string{descContext, descClassLoader}}}
		if err := a.InvokeStatic([]int{rBase, rCL}, helper); err != nil {
			return nil, err
		}
		if err := toast("AG4 已委托原 Application"); err != nil {
			return nil, err
		}
	}
	a.ReturnVoid()
	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	return &CodeBlob{Registers: nRegs, Ins: 2, Outs: nOuts, Insns: insns, Patches: patches}, nil
}

// shellOnCreateCode 生成 onCreate()V。
//
// 等价 Java 源码：
//
//	public void onCreate() {
//	    super.onCreate();
//	    Application o = orig;
//	    if (o != null) o.onCreate();
//	}
//
// onCreate 在 Application 中是 public，因此可以直接 invoke-virtual。
// registers=2、ins=1 → 唯一的入参 this 落在最高编号寄存器 v1，v0 留给局部变量。
func shellOnCreateCode(appOnCreate MethodSpec, fieldOrig FieldSpec) (*CodeBlob, error) {
	const (
		rLocal = 0 // 局部变量：缓存 orig
		rThis  = 1 // 入参 this
	)
	a := NewAsm()
	if err := a.InvokeSuper([]int{rThis}, appOnCreate); err != nil {
		return nil, err
	}
	a.SGetObject(rLocal, fieldOrig)
	a.IfEqz(rLocal, "end")
	if err := a.InvokeVirtual([]int{rLocal}, appOnCreate); err != nil {
		return nil, err
	}
	a.Label("end")
	a.ReturnVoid()
	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	return &CodeBlob{Registers: 2, Ins: 1, Outs: 1, Insns: insns, Patches: patches}, nil
}

// shellDelegateCode 生成静态辅助方法 a(Context)V：反射实例化原 Application
// 并调用其 attachBaseContext。
//
// 等价 Java 源码：
//
//	static void a(Context base, ClassLoader cl) {
//	    Class c = Class.forName(ORIG, true, cl);
//	    Application o = (Application) c.newInstance();
//	    orig = o;
//	    while (c != null) {
//	        Method[] ms = c.getDeclaredMethods();
//	        for (int i = 0; i < ms.length; i++) {
//	            Method m = ms[i];
//	            if (m.getName().equals("attachBaseContext")
//	                    && m.getParameterTypes().length == 1) {
//	                m.setAccessible(true);
//	                m.invoke(o, new Object[]{ base });
//	                return;
//	            }
//	        }
//	        c = c.getSuperclass();
//	    }
//	}
//
// 与源码的唯一差异：此处不生成 try/catch（注入方法体不支持异常表），
// 改用「沿父类链扫描 getDeclaredMethods」来规避 NoSuchMethodException——
// 那是唯一一处常规写法会依赖异常的地方。类名来自 Manifest，必然存在。
//
// 第一步的 forName 必须带显式 ClassLoader：壳自身是由系统加载器加载的，
// 而原 Application 位于解密后的 DEX 里，只有接管后的加载器才看得见它。
//
// registers=10、ins=2 → 入参占最高两个寄存器：v8=base、v9=cl。
func shellDelegateCode(sh *ShellApp, fieldOrig FieldSpec) (*CodeBlob, error) {
	const (
		rCls  = 0 // Class
		rMs   = 1 // Method[]
		rI    = 2 // int
		rM    = 3 // Method
		rPt   = 4 // Class[]，也兼作字符串暂存
		rArgs = 5 // Object[]
		rTmp  = 6
		rOrig = 7 // Application
		rBase = 8 // 入参
		rCL   = 9 // 入参
	)
	forName := MethodSpec{Class: descClass, Name: "forName",
		Proto: ProtoSpec{Ret: descClass, Params: []string{descString, "Z", descClassLoader}}}
	newInstance := MethodSpec{Class: descClass, Name: "newInstance",
		Proto: ProtoSpec{Ret: descObject}}
	getDeclaredMethods := MethodSpec{Class: descClass, Name: "getDeclaredMethods",
		Proto: ProtoSpec{Ret: descMethodArr}}
	getSuperclass := MethodSpec{Class: descClass, Name: "getSuperclass",
		Proto: ProtoSpec{Ret: descClass}}
	getName := MethodSpec{Class: descMethod, Name: "getName",
		Proto: ProtoSpec{Ret: descString}}
	getParameterTypes := MethodSpec{Class: descMethod, Name: "getParameterTypes",
		Proto: ProtoSpec{Ret: descClassArr}}
	setAccessible := MethodSpec{Class: descMethod, Name: "setAccessible",
		Proto: ProtoSpec{Ret: "V", Params: []string{"Z"}}}
	invoke := MethodSpec{Class: descMethod, Name: "invoke",
		Proto: ProtoSpec{Ret: descObject, Params: []string{descObject, descObjectArr}}}
	strEquals := MethodSpec{Class: descString, Name: "equals",
		Proto: ProtoSpec{Ret: "Z", Params: []string{descObject}}}

	a := NewAsm()
	// c = Class.forName(ORIG, true, cl); o = (Application) c.newInstance(); orig = o;
	a.ConstString(rTmp, sh.Orig)
	a.Const4(rPt, 1)
	if err := a.InvokeStatic([]int{rTmp, rPt, rCL}, forName); err != nil {
		return nil, err
	}
	a.MoveResultObject(rCls)
	if err := a.InvokeVirtual([]int{rCls}, newInstance); err != nil {
		return nil, err
	}
	a.MoveResultObject(rOrig)
	a.CheckCast(rOrig, descApplication)
	a.SPutObject(rOrig, fieldOrig)

	// while (c != null) { ... c = c.getSuperclass(); }
	a.Label("cls")
	a.IfEqz(rCls, "done")
	if err := a.InvokeVirtual([]int{rCls}, getDeclaredMethods); err != nil {
		return nil, err
	}
	a.MoveResultObject(rMs)
	a.Const4(rI, 0)

	// for (int i = 0; i < ms.length; i++)
	a.Label("scan")
	a.ArrayLength(rTmp, rMs)
	a.IfGe(rI, rTmp, "nextCls")
	a.AGetObject(rM, rMs, rI)

	// if (!m.getName().equals("attachBaseContext")) continue;
	if err := a.InvokeVirtual([]int{rM}, getName); err != nil {
		return nil, err
	}
	a.MoveResultObject(rTmp)
	a.ConstString(rPt, "attachBaseContext")
	if err := a.InvokeVirtual([]int{rTmp, rPt}, strEquals); err != nil {
		return nil, err
	}
	a.MoveResult(rTmp)
	a.IfEqz(rTmp, "next")

	// if (m.getParameterTypes().length != 1) continue;
	if err := a.InvokeVirtual([]int{rM}, getParameterTypes); err != nil {
		return nil, err
	}
	a.MoveResultObject(rPt)
	a.ArrayLength(rTmp, rPt)
	a.Const4(rArgs, 1)
	if err := a.IfNe(rTmp, rArgs, "next"); err != nil {
		return nil, err
	}

	// m.setAccessible(true); m.invoke(o, new Object[]{ base });
	a.Const4(rArgs, 1)
	if err := a.InvokeVirtual([]int{rM, rArgs}, setAccessible); err != nil {
		return nil, err
	}
	a.Const4(rTmp, 1)
	if err := a.NewArray(rArgs, rTmp, descObjectArr); err != nil {
		return nil, err
	}
	a.Const4(rTmp, 0)
	a.APutObject(rBase, rArgs, rTmp)
	if err := a.InvokeVirtual([]int{rM, rOrig, rArgs}, invoke); err != nil {
		return nil, err
	}
	a.MoveResultObject(rTmp)
	a.ReturnVoid()

	a.Label("next")
	a.AddIntLit8(rI, 1)
	a.Goto16("scan")

	a.Label("nextCls")
	if err := a.InvokeVirtual([]int{rCls}, getSuperclass); err != nil {
		return nil, err
	}
	a.MoveResultObject(rCls)
	a.Goto16("cls")

	a.Label("done")
	a.ReturnVoid()

	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	return &CodeBlob{Registers: 10, Ins: 2, Outs: 3, Insns: insns, Patches: patches}, nil
}

// ShellJavaName 把类描述符转为 Java 点分名（"Lcom/a/B;" -> "com.a.B"）。
func ShellJavaName(desc string) string {
	body := desc
	if len(body) > 1 && body[0] == 'L' {
		body = body[1:]
	}
	if n := len(body); n > 0 && body[n-1] == ';' {
		body = body[:n-1]
	}
	out := make([]byte, 0, len(body))
	for i := 0; i < len(body); i++ {
		if body[i] == '/' {
			out = append(out, '.')
			continue
		}
		out = append(out, body[i])
	}
	return string(out)
}

// toastM 描述一次 Toast 调用所需的框架方法。
type toastM struct {
	makeText MethodSpec
	show     MethodSpec
}

// newToastM 构造 Toast 调用所需的符号。
func newToastM() toastM {
	return toastM{
		makeText: MethodSpec{Class: "Landroid/widget/Toast;", Name: "makeText",
			Proto: ProtoSpec{Ret: "Landroid/widget/Toast;",
				Params: []string{descContext, "Ljava/lang/CharSequence;", "I"}}},
		show: MethodSpec{Class: "Landroid/widget/Toast;", Name: "show",
			Proto: ProtoSpec{Ret: "V"}},
	}
}

// emitToast 生成「弹一条 Toast」的指令序列。
//
// 用 Toast 而不是写文件或 logcat：在无 root 的真机上，应用私有目录读不到、
// logcat 需要 adb，而 Toast 直接出现在屏幕上——这是唯一「不依赖任何工具」
// 的观察通道。调用方需要提供三个临时寄存器。
func emitToast(a *Asm, tm toastM, ctx, rMsg, rTmp int, msg string) error {
	a.ConstString(rMsg, msg)
	return emitToastReg(a, tm, ctx, rMsg, rTmp)
}

// emitToastReg 与 emitToast 相同，但弹出的是寄存器里已有的字符串
// （用于消息要到运行时才拼得出来的场合，例如崩溃原因的类名）。
func emitToastReg(a *Asm, tm toastM, ctx, rMsg, rTmp int) error {
	// 与 Toast 同步写一行 logcat：Toast 的内容不会进日志，只有屏幕看得到；
	// 补一行日志后，自动化测试与将来能连 adb 的人都能核对进度序列。
	logI := MethodSpec{Class: "Landroid/util/Log;", Name: "i",
		Proto: ProtoSpec{Ret: "I", Params: []string{descStringType, descStringType}}}
	a.Const4(rTmp, 1) // Toast.LENGTH_LONG
	if err := a.InvokeStatic([]int{ctx, rMsg, rTmp}, tm.makeText); err != nil {
		return err
	}
	a.MoveResultObject(rTmp)
	if err := a.InvokeVirtual([]int{rTmp}, tm.show); err != nil {
		return err
	}
	a.ConstString(rTmp, "APKGUARD")
	if err := a.InvokeStatic([]int{rTmp, rMsg}, logI); err != nil {
		return err
	}
	return nil
}
