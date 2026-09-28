package dex

import "fmt"

// LoaderSpec 描述 B3（ClassLoader 接管）要注入的 Loader 类。
//
// 壳在运行时必须完成三件事：把 assets 里的密文载荷解密、落地成真实 DEX 文件、
// 再让系统用它来加载业务类。这三件事都不是「声明式」的，必须真的执行代码，
// 因此这里用汇编器把它们写成 Dalvik 指令而不是靠 DEX 结构技巧。
//
// 与 ShellApp（B2）的关系：ShellApp 提供最早执行时机（attachBaseContext），
// Loader 在该时机内完成解密与接管，两者由 ShellAppAddition 组装进同一个 DEX。
type LoaderSpec struct {
	// MarkReadOnly 为 true 时，落地的 DEX 会调用 setReadOnly()。
	//
	// 只在**确实需要**时开启：Android 14（API 34）起，targetSdk ≥ 34 的应用
	// 加载「可写」DEX 会被系统拒绝，因此必须标记只读。但对 targetSdk < 34 的
	// 应用，标记反而有害——实测 RustDesk（targetSdk 33）加上标记后，
	// DexPathList 打开这些文件时报 EACCES(Permission denied)，
	// 表现为「应用一启动就因 FileNotFoundException 闪退」。
	MarkReadOnly bool
	// Debug 为 true 时，Loader 会在关键步骤后弹 Toast 报告进度，
	// 并在接管 ClassLoader 后回读 mClassLoader 校验是否真的生效。
	// 与 ShellApp.Debug 配套使用，仅用于排障。
	Debug bool
	// Class 是 Loader 类的描述符，形如 "Lcom/apkguard/shell/Loader;"。
	Class string
	// Key 是 AES-256 载荷密钥。
	Key [32]byte
	// Items 是全部载荷，顺序即加载顺序。
	Items []LoaderItem
	// TempDir 是载荷解密后落地的目录名（相对应用私有目录）。
	//
	// 必须落在私有目录：系统只信任应用数据目录内的代码路径，
	// 放到外部存储会导致 DexClassLoader 拒绝加载。
	TempDir string
	// NativeKey 非空时（C1 生效）密钥不再内联在字节码里，改由该 native
	// 桥接类在运行时派生：先取本 APK 的签名证书摘要，再交给 native 计算
	// SHA-256(种子 ‖ 摘要)。种子只存在于 libapkguard.so 中，DEX 里没有密钥。
	//
	// 附带的安全性质：重打包必然更换签名证书，派生出的密钥随之不同，
	// 密文载荷在密码学层面无法解开——不存在「跳过检测」的绕过路径。
	NativeKey string
}

// LoaderItem 是一份待运行时解密的载荷。
type LoaderItem struct {
	// Asset 是 APK 内的条目名，形如 "assets/config_1a2b.bin"。
	//
	// 注意传给 AssetManager.open 时必须去掉 "assets/" 前缀：
	// AssetManager 的路径本来就相对 assets/ 目录。
	Asset string
	// DexName 是解密后落地使用的文件名（同目录内必须唯一）。
	DexName string
	// Size 是载荷字节数（含前置 IV）。
	//
	// 读取循环需要预知总长才能一次分配到位并避免反复扩容；
	// 该值在加固时已知，因此可以直接内联为常量。
	Size int
}

// 注入代码引用的框架类型。
const (
	descAssetManager = "Landroid/content/res/AssetManager;"
	descInputStream  = "Ljava/io/InputStream;"
	descFile         = "Ljava/io/File;"
	descFileOut      = "Ljava/io/FileOutputStream;"
	descStringB      = "Ljava/lang/StringBuilder;"
	descClassLoader  = "Ljava/lang/ClassLoader;"
	descDexCL        = "Ldalvik/system/DexClassLoader;"
	descCipher       = "Ljavax/crypto/Cipher;"
	descSecretKey    = "Ljavax/crypto/spec/SecretKeySpec;"
	descIvSpec       = "Ljavax/crypto/spec/IvParameterSpec;"
	descField        = "Ljava/lang/reflect/Field;"
	descObjectArray  = "[Ljava/lang/Object;"
	descClassArray   = "[Ljava/lang/Class;"
	descFieldArray   = "[Ljava/lang/reflect/Field;"
	descByteArray    = "[B"
	// descKeyIface / descAlgoSpec 是 Cipher.init 的形参类型。
	//
	// 必须按接口/抽象类书写：SecretKeySpec 实现 Key、IvParameterSpec 实现
	// AlgorithmParameterSpec，若把方法引用写成具体类，Dalvik 校验器会因
	// 方法签名不匹配而拒绝该调用点。
	descKeyIface = "Ljava/security/Key;"
	descAlgoSpec = "Ljava/security/spec/AlgorithmParameterSpec;"
)

// Cipher 的工作模式常量（与 javax.crypto.Cipher 保持一致）。
const cipherDecryptMode = 2

// LoaderEntry 是 Loader 的对外入口方法名。
const LoaderEntry = "a"

// LoaderAddition 构造 Loader 类定义。
func LoaderAddition(ls *LoaderSpec) (Addition, error) {
	if ls.Class == "" {
		return Addition{}, fmt.Errorf("dex: Loader 类名为空")
	}
	if ls.TempDir == "" {
		return Addition{}, fmt.Errorf("dex: Loader 临时目录名为空")
	}
	if len(ls.Items) == 0 {
		return Addition{}, fmt.Errorf("dex: Loader 没有任何载荷")
	}

	// 逐个生成方法体；每个方法的引用会自动登记进 Addition（见 expandAdditionRefs）。
	entry, err := loaderEntryCode(ls)
	if err != nil {
		return Addition{}, err
	}
	readAll, err := loaderReadAllCode()
	if err != nil {
		return Addition{}, err
	}
	decrypt, err := loaderDecryptCode()
	if err != nil {
		return Addition{}, err
	}
	writeAll, err := loaderWriteCode(ls.MarkReadOnly)
	if err != nil {
		return Addition{}, err
	}
	install, err := loaderInstallCode(ls.Class)
	if err != nil {
		return Addition{}, err
	}
	getField, err := loaderGetFieldCode(ls.Class)
	if err != nil {
		return Addition{}, err
	}
	setField, err := loaderSetFieldCode(ls.Class)
	if err != nil {
		return Addition{}, err
	}

	const (
		nameEntry   = LoaderEntry
		nameRead    = "r"
		nameDecrypt = "c"
		nameWrite   = "w"
		nameInstall = "i"
		nameGetF    = "g"
		nameSetF    = "s"
	)

	protoCtxCL := ProtoSpec{Ret: descClassLoader, Params: []string{descContext}}
	protoInBytes := ProtoSpec{Ret: descByteArray, Params: []string{descInputStream, "I"}}
	protoBytes2 := ProtoSpec{Ret: descByteArray, Params: []string{descByteArray, descByteArray}}
	protoFileBytes := ProtoSpec{Ret: "V", Params: []string{descFile, descByteArray}}
	protoCLI := ProtoSpec{Ret: "I", Params: []string{descClassLoader}}
	protoObjStr := ProtoSpec{Ret: descObject, Params: []string{descObject, descStringType}}
	protoObjStrObjBool := ProtoSpec{Ret: "Z", Params: []string{descObject, descStringType, descObject}}

	spec := ClassSpec{
		Name:   ls.Class,
		Super:  descObject,
		Access: accPublic,
		Methods: []ClassMethod{
			{Name: nameEntry, Proto: protoCtxCL, Access: accPublic | accStatic, Code: entry},
			{Name: nameRead, Proto: protoInBytes, Access: accPrivate | accStatic, Code: readAll},
			{Name: nameDecrypt, Proto: protoBytes2, Access: accPrivate | accStatic, Code: decrypt},
			{Name: nameWrite, Proto: protoFileBytes, Access: accPrivate | accStatic, Code: writeAll},
			{Name: nameInstall, Proto: protoCLI, Access: accPrivate | accStatic, Code: install},
			{Name: nameGetF, Proto: protoObjStr, Access: accPrivate | accStatic, Code: getField},
			{Name: nameSetF, Proto: protoObjStrObjBool, Access: accPrivate | accStatic, Code: setField},
		},
	}

	// 类必须自己出现在方法表里，planInjectedClass 会校验注入方法已登记。
	add := Addition{
		Methods: []MethodSpec{
			{Class: ls.Class, Name: nameEntry, Proto: protoCtxCL},
			{Class: ls.Class, Name: nameRead, Proto: protoInBytes},
			{Class: ls.Class, Name: nameDecrypt, Proto: protoBytes2},
			{Class: ls.Class, Name: nameWrite, Proto: protoFileBytes},
			{Class: ls.Class, Name: nameInstall, Proto: protoCLI},
			{Class: ls.Class, Name: nameGetF, Proto: protoObjStr},
			{Class: ls.Class, Name: nameSetF, Proto: protoObjStrObjBool},
		},
		Classes: []ClassSpec{spec},
	}
	return add, nil
}

// descStringType 是 java.lang.String 的类型描述符。
//
// 单独命名是为了与 descString（"Ljava/lang/String;"）区分开语义：
// 这里用在「参数类型」的位置上。
const descStringType = "Ljava/lang/String;"

// Desc 返回 Loader 入口方法的完整描述符。
func (ls *LoaderSpec) Desc() string {
	return ls.Class + "->" + LoaderEntry + "(" + descContext + ")" + descClassLoader
}

// ---- 入口：a(Context) -> ClassLoader ----
//
// 等价 Java：
//
//	static ClassLoader a(Context base) {
//	    File dir = base.getDir(TEMP_DIR, 0);
//	    String opt = dir.getAbsolutePath();
//	    StringBuilder sb = new StringBuilder();
//	    for (每份载荷) {
//	        InputStream in = base.getAssets().open(ASSET);
//	        byte[] blob = r(in, SIZE);
//	        byte[] dex = c(blob);
//	        File f = new File(dir, DEXNAME);
//	        w(f, dex);
//	        sb.append(f.getAbsolutePath()).append(File.pathSeparator);
//	    }
//	    ClassLoader parent = base.getClassLoader();
//	    ClassLoader cl = new DexClassLoader(sb.toString(), opt, null, parent);
//	    i(cl);
//	    return cl;
//	}
//
// registers=16、ins=1 → 入参 base 落在 v15；v0..v14 为局部。
func loaderEntryCode(ls *LoaderSpec) (*CodeBlob, error) {
	const (
		rDir    = 0 // File
		rOpt    = 1 // String
		rSb     = 2 // StringBuilder
		rIn     = 3 // InputStream
		rBlob   = 4 // byte[]
		rDex    = 5 // byte[]
		rFile   = 6 // File
		rParent = 7 // ClassLoader
		rCL     = 8 // ClassLoader
		rT0     = 9
		rT1     = 10
		rKey    = 11 // byte[] 载荷密钥
		rT2     = 12
		rT3     = 13
		rT4     = 14
		rBase   = 15
	)
	tm := newToastM()

	getDir := MethodSpec{Class: descContext, Name: "getDir",
		Proto: ProtoSpec{Ret: descFile, Params: []string{descStringType, "I"}}}
	getAssets := MethodSpec{Class: descContext, Name: "getAssets",
		Proto: ProtoSpec{Ret: descAssetManager}}
	getClassLoader := MethodSpec{Class: descContext, Name: "getClassLoader",
		Proto: ProtoSpec{Ret: descClassLoader}}
	absPath := MethodSpec{Class: descFile, Name: "getAbsolutePath",
		Proto: ProtoSpec{Ret: descStringType}}
	sbInit := MethodSpec{Class: descStringB, Name: "<init>", Proto: ProtoSpec{Ret: "V"}}
	sbAppend := MethodSpec{Class: descStringB, Name: "append",
		Proto: ProtoSpec{Ret: descStringB, Params: []string{descStringType}}}
	sbToString := MethodSpec{Class: descStringB, Name: "toString",
		Proto: ProtoSpec{Ret: descStringType}}
	amOpen := MethodSpec{Class: descAssetManager, Name: "open",
		Proto: ProtoSpec{Ret: descInputStream, Params: []string{descStringType}}}
	fileInit := MethodSpec{Class: descFile, Name: "<init>",
		Proto: ProtoSpec{Ret: "V", Params: []string{descFile, descStringType}}}
	dexInit := MethodSpec{Class: descDexCL, Name: "<init>", Proto: ProtoSpec{Ret: "V",
		Params: []string{descStringType, descStringType, descStringType, descClassLoader}}}
	sepField := FieldSpec{Class: descFile, Name: "pathSeparator", Type: descStringType}
	getAppInfo := MethodSpec{Class: descContext, Name: "getApplicationInfo",
		Proto: ProtoSpec{Ret: "Landroid/content/pm/ApplicationInfo;"}}
	libDirField := FieldSpec{Class: "Landroid/content/pm/ApplicationInfo;",
		Name: "nativeLibraryDir", Type: descStringType}

	readM := MethodSpec{Class: ls.Class, Name: "r",
		Proto: ProtoSpec{Ret: descByteArray, Params: []string{descInputStream, "I"}}}
	decM := MethodSpec{Class: ls.Class, Name: "c",
		Proto: ProtoSpec{Ret: descByteArray, Params: []string{descByteArray, descByteArray}}}
	writeM := MethodSpec{Class: ls.Class, Name: "w",
		Proto: ProtoSpec{Ret: "V", Params: []string{descFile, descByteArray}}}
	instM := MethodSpec{Class: ls.Class, Name: "i",
		Proto: ProtoSpec{Ret: "I", Params: []string{descClassLoader}}}

	// 载荷密钥：要么由 native 派生（C1），要么内联在字节码里。
	bridgeSig := MethodSpec{Class: ls.NativeKey, Name: NativeSig,
		Proto: ProtoSpec{Ret: descByteArray, Params: []string{descContext}}}
	bridgeDerive := MethodSpec{Class: ls.NativeKey, Name: NativeDerive,
		Proto: ProtoSpec{Ret: descByteArray, Params: []string{descByteArray}}}

	a := NewAsm()
	if ls.NativeKey != "" {
		// key = Native.derive(Native.sig(base))
		if err := a.InvokeStatic([]int{rBase}, bridgeSig); err != nil {
			return nil, err
		}
		a.MoveResultObject(rT0)
		if err := a.InvokeStatic([]int{rT0}, bridgeDerive); err != nil {
			return nil, err
		}
		a.MoveResultObject(rKey)
	} else {
		// key = { ... }：逐字节构造，避免在 DEX 里留下可读的密钥字符串。
		a.Const16(rT0, int16(keyLen))
		if err := a.NewArray(rKey, rT0, descByteArray); err != nil {
			return nil, err
		}
		for i, b := range ls.Key {
			a.Const16(rT0, int16(b))
			a.Const16(rT1, int16(i))
			a.APutByte(rT0, rKey, rT1)
		}
	}

	// dir = base.getDir(TEMP_DIR, 0)
	a.ConstString(rT0, ls.TempDir)
	a.Const4(rT1, 0)
	if err := a.InvokeVirtual([]int{rBase, rT0, rT1}, getDir); err != nil {
		return nil, err
	}
	a.MoveResultObject(rDir)
	// opt = dir.getAbsolutePath()
	if err := a.InvokeVirtual([]int{rDir}, absPath); err != nil {
		return nil, err
	}
	a.MoveResultObject(rOpt)
	// sb = new StringBuilder()
	a.NewInstance(rSb, descStringB)
	if err := a.InvokeDirect([]int{rSb}, sbInit); err != nil {
		return nil, err
	}

	// 逐份载荷展开：解密、落地、并把路径追加进 dexPath。
	for i, it := range ls.Items {
		// in = base.getAssets().open(ASSET)
		if err := a.InvokeVirtual([]int{rBase}, getAssets); err != nil {
			return nil, err
		}
		a.MoveResultObject(rT0)
		a.ConstString(rT1, assetKey(it.Asset))
		if err := a.InvokeVirtual([]int{rT0, rT1}, amOpen); err != nil {
			return nil, err
		}
		a.MoveResultObject(rIn)
		// blob = r(in, SIZE)
		a.Const32(rT1, int32(it.Size))
		if err := a.InvokeStatic([]int{rIn, rT1}, readM); err != nil {
			return nil, err
		}
		a.MoveResultObject(rBlob)
		// dex = c(blob, key)
		if err := a.InvokeStatic([]int{rBlob, rKey}, decM); err != nil {
			return nil, err
		}
		a.MoveResultObject(rDex)
		// f = new File(dir, DEXNAME)
		a.NewInstance(rFile, descFile)
		a.ConstString(rT0, it.DexName)
		if err := a.InvokeDirect([]int{rFile, rDir, rT0}, fileInit); err != nil {
			return nil, err
		}
		// w(f, dex)
		if err := a.InvokeStatic([]int{rFile, rDex}, writeM); err != nil {
			return nil, err
		}
		// 分隔符只加在「不是第一份」之前。
		//
		// 不能反过来在每份之后都加：那样末位会留下一个空路径元素，
		// 而部分 Android 版本的 DexPathList 对空元素处理不一致，
		// 可能直接报「No original dex files found」。
		if i > 0 {
			a.SGetObject(rT1, sepField)
			if err := a.InvokeVirtual([]int{rSb, rT1}, sbAppend); err != nil {
				return nil, err
			}
			a.MoveResultObject(rT0)
		}
		// sb.append(f.getAbsolutePath())
		if err := a.InvokeVirtual([]int{rFile}, absPath); err != nil {
			return nil, err
		}
		a.MoveResultObject(rT0)
		if err := a.InvokeVirtual([]int{rSb, rT0}, sbAppend); err != nil {
			return nil, err
		}
	}

	if ls.Debug {
		if err := emitToast(a, tm, rBase, rT2, rT4, "AG-L1 载荷已解密并落地"); err != nil {
			return nil, err
		}
	}
	// lib = base.getApplicationInfo().nativeLibraryDir
	//
	// 必须把应用自己的原生库目录交给 DexClassLoader：我们把接管后的加载器
	// 安装成了应用的 ClassLoader，应用里的 System.loadLibrary 会经它解析。
	// 若第 3 个参数传 null（无库搜索路径），应用加载自己的 .so 会直接
	//   UnsatisfiedLinkError
	// （真实案例：RustDesk 加固后 16 个分片全部加载成功、却卡在 libflutter.so）。
	if err := a.InvokeVirtual([]int{rBase}, getAppInfo); err != nil {
		return nil, err
	}
	a.MoveResultObject(rT0)
	// nativeLibraryDir 是**实例**字段，必须用 iget-object 读取（不是 sget-object）。
	// 复用载荷循环结束后已无用的 rFile 寄存器存放库目录，
	// 以免顶高寄存器总数（invoke 的 35c 格式只编码 v0..v15）。
	if err := a.IGetObject(rFile, rT0, libDirField); err != nil {
		return nil, err
	}

	// parent = base.getClassLoader()
	if err := a.InvokeVirtual([]int{rBase}, getClassLoader); err != nil {
		return nil, err
	}
	a.MoveResultObject(rParent)
	// cl = new DexClassLoader(sb.toString(), opt, null, parent)
	if err := a.InvokeVirtual([]int{rSb}, sbToString); err != nil {
		return nil, err
	}
	a.MoveResultObject(rT0)
	a.NewInstance(rCL, descDexCL)
	if err := a.InvokeDirect([]int{rCL, rT0, rOpt, rFile, rParent}, dexInit); err != nil {
		return nil, err
	}
	if ls.Debug {
		if err := emitToast(a, tm, rBase, rT2, rT4, "AG-L2 DexClassLoader 就绪"); err != nil {
			return nil, err
		}
	}
	// i(cl)：接管 ClassLoader，返回接管结果（2=生效 1=字段被隐藏 0=未写入）
	if err := a.InvokeStatic([]int{rCL}, instM); err != nil {
		return nil, err
	}
	a.MoveResult(rT3)
	if ls.Debug {
		a.Const4(rT2, 2)
		if err := a.IfEq(rT3, rT2, "L_swap_ok"); err != nil {
			return nil, err
		}
		// 0 = 字段可见但写入未生效；1 = 字段被隐藏（两者处置方式不同，必须分开报）
		a.IfEqz(rT3, "L_swap_stale")
		if err := emitToast(a, tm, rBase, rT2, rT4, "AG-L3 接管失败：mClassLoader 被隐藏API过滤"); err != nil {
			return nil, err
		}
		a.Goto("L_swap_done")
		a.Label("L_swap_stale")
		if err := emitToast(a, tm, rBase, rT2, rT4, "AG-L3 接管失败：mClassLoader 未写入"); err != nil {
			return nil, err
		}
		a.Goto("L_swap_done")
		a.Label("L_swap_ok")
		if err := emitToast(a, tm, rBase, rT2, rT4, "AG-L3 接管成功"); err != nil {
			return nil, err
		}
		a.Label("L_swap_done")
	}
	a.ReturnObject(rCL)

	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	return &CodeBlob{Registers: 16, Ins: 1, Outs: 5, Insns: insns, Patches: patches}, nil
}

// assetKey 把 APK 条目名转换为 AssetManager 可接受的路径。
//
// AssetManager 的路径本就相对 assets/ 目录，直接传 "assets/xxx" 会被解析成
// "assets/assets/xxx" 而打开失败，因此必须剥掉前缀。
func assetKey(asset string) string {
	const p = "assets/"
	if len(asset) > len(p) && asset[:len(p)] == p {
		return asset[len(p):]
	}
	return asset
}

// ---- 读取：r(InputStream, int) -> byte[] ----
//
// 等价 Java：
//
//	static byte[] r(InputStream in, int total) {
//	    byte[] out = new byte[total];
//	    int off = 0;
//	    while (off < total) {
//	        int n = in.read(out, off, total - off);
//	        if (n <= 0) break;
//	        off += n;
//	    }
//	    in.close();
//	    return out;
//	}
//
// registers=6、ins=2 → in 在 v4、total 在 v5。
func loaderReadAllCode() (*CodeBlob, error) {
	const (
		rOut   = 0
		rOff   = 1
		rN     = 2
		rZero  = 3
		rIn    = 4
		rTotal = 5
	)
	read := MethodSpec{Class: descInputStream, Name: "read",
		Proto: ProtoSpec{Ret: "I", Params: []string{descByteArray, "I", "I"}}}
	closeM := MethodSpec{Class: descInputStream, Name: "close", Proto: ProtoSpec{Ret: "V"}}

	a := NewAsm()
	if err := a.NewArray(rOut, rTotal, descByteArray); err != nil {
		return nil, err
	}
	a.Const4(rOff, 0)
	a.Const4(rZero, 0)

	a.Label("loop")
	// if (off >= total) break;
	if err := a.IfGe(rOff, rTotal, "end"); err != nil {
		return nil, err
	}
	// n = in.read(out, off, total - off)
	a.SubInt(rN, rTotal, rOff)
	if err := a.InvokeVirtual([]int{rIn, rOut, rOff, rN}, read); err != nil {
		return nil, err
	}
	a.MoveResult(rN)
	// 读满或出错（n <= 0）就结束：改用 if-gt 判断，避免引入 if-le。
	if err := a.IfGt(rN, rZero, "cont"); err != nil {
		return nil, err
	}
	a.Goto("end")
	a.Label("cont")
	a.AddInt(rOff, rOff, rN)
	a.Goto("loop")

	a.Label("end")
	if err := a.InvokeVirtual([]int{rIn}, closeM); err != nil {
		return nil, err
	}
	a.ReturnObject(rOut)

	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	return &CodeBlob{Registers: 6, Ins: 2, Outs: 4, Insns: insns, Patches: patches}, nil
}

// ---- 解密：c(byte[], byte[]) -> byte[] ----
//
// 等价 Java：
//
//	static byte[] c(byte[] blob, byte[] key) {
//	    byte[] iv = new byte[16];
//	    System.arraycopy(blob, 0, iv, 0, 16);
//	    Cipher cp = Cipher.getInstance("AES/CBC/PKCS5Padding");
//	    cp.init(DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
//	    return cp.doFinal(blob, 16, blob.length - 16);
//	}
//
// 密钥由调用方传入而不是在此内联：C1 生效时它来自 native 派生，
// 未启用时才是内联常量。这样解密路径本身与密钥来源解耦。
//
// registers=8、ins=2 → blob 在 v6、key 在 v7。
func loaderDecryptCode() (*CodeBlob, error) {
	const (
		rIv   = 0
		rCp   = 1
		rSks  = 2
		rIvs  = 3
		rT0   = 4
		rT1   = 5
		rBlob = 6
		rKey  = 7
	)
	getInstance := MethodSpec{Class: descCipher, Name: "getInstance",
		Proto: ProtoSpec{Ret: descCipher, Params: []string{descStringType}}}
	cipherInit := MethodSpec{Class: descCipher, Name: "init",
		Proto: ProtoSpec{Ret: "V", Params: []string{"I", descKeyIface, descAlgoSpec}}}
	doFinal := MethodSpec{Class: descCipher, Name: "doFinal",
		Proto: ProtoSpec{Ret: descByteArray, Params: []string{descByteArray, "I", "I"}}}
	sksInit := MethodSpec{Class: descSecretKey, Name: "<init>",
		Proto: ProtoSpec{Ret: "V", Params: []string{descByteArray, descStringType}}}
	ivInit := MethodSpec{Class: descIvSpec, Name: "<init>",
		Proto: ProtoSpec{Ret: "V", Params: []string{descByteArray}}}
	arraycopy := MethodSpec{Class: descSystem, Name: "arraycopy",
		Proto: ProtoSpec{Ret: "V",
			Params: []string{descObject, "I", descObject, "I", "I"}}}

	a := NewAsm()
	// iv = new byte[16]
	a.Const16(rT0, int16(ivLen))
	if err := a.NewArray(rIv, rT0, descByteArray); err != nil {
		return nil, err
	}
	// System.arraycopy(blob, 0, iv, 0, 16)
	a.Const4(rT0, 0)
	a.Const16(rT1, int16(ivLen))
	if err := a.InvokeStatic([]int{rBlob, rT0, rIv, rT0, rT1}, arraycopy); err != nil {
		return nil, err
	}
	// cp = Cipher.getInstance("AES/CBC/PKCS5Padding")
	a.ConstString(rT0, cipherAlg)
	if err := a.InvokeStatic([]int{rT0}, getInstance); err != nil {
		return nil, err
	}
	a.MoveResultObject(rCp)
	// sks = new SecretKeySpec(key, "AES")
	a.NewInstance(rSks, descSecretKey)
	a.ConstString(rT0, keyAlg)
	if err := a.InvokeDirect([]int{rSks, rKey, rT0}, sksInit); err != nil {
		return nil, err
	}
	// ivs = new IvParameterSpec(iv)
	a.NewInstance(rIvs, descIvSpec)
	if err := a.InvokeDirect([]int{rIvs, rIv}, ivInit); err != nil {
		return nil, err
	}
	// cp.init(DECRYPT_MODE, sks, ivs)
	a.Const16(rT0, cipherDecryptMode)
	if err := a.InvokeVirtual([]int{rCp, rT0, rSks, rIvs}, cipherInit); err != nil {
		return nil, err
	}
	// return cp.doFinal(blob, 16, blob.length - 16)
	a.Const16(rT0, int16(ivLen))
	a.ArrayLength(rT1, rBlob)
	a.SubInt(rT1, rT1, rT0)
	if err := a.InvokeVirtual([]int{rCp, rBlob, rT0, rT1}, doFinal); err != nil {
		return nil, err
	}
	a.MoveResultObject(rT1)
	a.ReturnObject(rT1)

	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	return &CodeBlob{Registers: 8, Ins: 2, Outs: 5, Insns: insns, Patches: patches}, nil
}

// 载荷的密码学参数（必须与 internal/pack 一致）。
const (
	keyLen    = 32 // AES-256
	ivLen     = 16 // CBC 分组长度
	cipherAlg = "AES/CBC/PKCS5Padding"
	keyAlg    = "AES"
)

// descSystem 是 java.lang.System 的描述符。
const descSystem = "Ljava/lang/System;"

// ---- 落地：w(File, byte[]) -> void ----
//
// 等价 Java：
//
//	static void w(File f, byte[] data) {
//	    FileOutputStream os = new FileOutputStream(f);
//	    os.write(data);
//	    os.close();
//	    f.setReadOnly();   // Android 14+ 的硬性要求，见下
//	}
//
// **最后那行不是可选项**：Android 14（API 34）起，targetSdk ≥ 34 的应用
// 用 DexClassLoader 加载「可写」的 DEX 文件会被系统拒绝并抛异常
// （「Safer dynamic code loading」行为变更）。本地写的 dex 默认是可写的，
// 不标记只读就会在加载那一步直接崩——而且崩得不留痕迹。
//
// registers=4、ins=2 → f 在 v2、data 在 v3。
func loaderWriteCode(markReadOnly bool) (*CodeBlob, error) {
	const (
		rOs   = 0
		rF    = 2
		rData = 3
	)
	osInit := MethodSpec{Class: descFileOut, Name: "<init>",
		Proto: ProtoSpec{Ret: "V", Params: []string{descFile}}}
	writeM := MethodSpec{Class: descFileOut, Name: "write",
		Proto: ProtoSpec{Ret: "V", Params: []string{descByteArray}}}
	closeM := MethodSpec{Class: descFileOut, Name: "close", Proto: ProtoSpec{Ret: "V"}}
	setRO := MethodSpec{Class: descFile, Name: "setReadOnly", Proto: ProtoSpec{Ret: "Z"}}

	a := NewAsm()
	a.NewInstance(rOs, descFileOut)
	if err := a.InvokeDirect([]int{rOs, rF}, osInit); err != nil {
		return nil, err
	}
	if err := a.InvokeVirtual([]int{rOs, rData}, writeM); err != nil {
		return nil, err
	}
	if err := a.InvokeVirtual([]int{rOs}, closeM); err != nil {
		return nil, err
	}
	// f.setReadOnly()：仅当调用方要求时（targetSdk ≥ 34，见 LoaderSpec）。
	// 返回值（是否成功）不必检查——失败时加载那一步会抛异常。
	if markReadOnly {
		if err := a.InvokeVirtual([]int{rF}, setRO); err != nil {
			return nil, err
		}
	}
	a.ReturnVoid()

	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	return &CodeBlob{Registers: 4, Ins: 2, Outs: 2, Insns: insns, Patches: patches}, nil
}

// ---- 接管：i(ClassLoader) -> void ----
//
// 等价 Java：
//
//	static void i(ClassLoader cl) {
//	    Class at = Class.forName("android.app.ActivityThread");
//	    Method m = at.getDeclaredMethod("currentActivityThread", new Class[0]);
//	    m.setAccessible(true);
//	    Object thread = m.invoke(null, new Object[0]);
//	    Object data = g(thread, "mBoundApplication");
//	    Object apk = g(data, "info");
//	    s(apk, "mClassLoader", cl);
//	}
//
// 路径取自 LoadedApk.mClassLoader：那是系统用来加载 Application 与四大组件的
// 加载器，不替换它的话 Manifest 里的 Activity 仍会由旧加载器加载而找不到类。
//
// registers=10、ins=1 → cl 在 v9。
func loaderInstallCode(self string) (*CodeBlob, error) {
	const (
		rAt = 0
		rM  = 1
		rTh = 2
		rBd = 3
		rAp = 4
		rT0 = 5
		rT1 = 6
		rZ  = 7
		rCl = 9
	)
	forName := MethodSpec{Class: descClass, Name: "forName",
		Proto: ProtoSpec{Ret: descClass, Params: []string{descStringType}}}
	getMethod := MethodSpec{Class: descClass, Name: "getDeclaredMethod",
		Proto: ProtoSpec{Ret: descMethod, Params: []string{descStringType, descClassArray}}}
	setAcc := MethodSpec{Class: descMethod, Name: "setAccessible",
		Proto: ProtoSpec{Ret: "V", Params: []string{"Z"}}}
	invoke := MethodSpec{Class: descMethod, Name: "invoke",
		Proto: ProtoSpec{Ret: descObject, Params: []string{descObject, descObjectArray}}}
	getF := MethodSpec{Class: self, Name: "g",
		Proto: ProtoSpec{Ret: descObject, Params: []string{descObject, descStringType}}}
	setF := MethodSpec{Class: self, Name: "s",
		Proto: ProtoSpec{Ret: "Z", Params: []string{descObject, descStringType, descObject}}}

	a := NewAsm()
	// at = Class.forName("android.app.ActivityThread")
	a.ConstString(rT0, activityThreadClass)
	if err := a.InvokeStatic([]int{rT0}, forName); err != nil {
		return nil, err
	}
	a.MoveResultObject(rAt)
	// m = at.getDeclaredMethod("currentActivityThread", new Class[0])
	a.Const4(rZ, 0)
	if err := a.NewArray(rT1, rZ, descClassArray); err != nil {
		return nil, err
	}
	a.ConstString(rT0, "currentActivityThread")
	if err := a.InvokeVirtual([]int{rAt, rT0, rT1}, getMethod); err != nil {
		return nil, err
	}
	a.MoveResultObject(rM)
	// m.setAccessible(true)
	a.Const4(rT0, 1)
	if err := a.InvokeVirtual([]int{rM, rT0}, setAcc); err != nil {
		return nil, err
	}
	// thread = m.invoke(null, new Object[0])
	if err := a.NewArray(rT1, rZ, descObjectArray); err != nil {
		return nil, err
	}
	a.Const4(rT0, 0)
	if err := a.InvokeVirtual([]int{rM, rT0, rT1}, invoke); err != nil {
		return nil, err
	}
	a.MoveResultObject(rTh)
	// data = g(thread, "mBoundApplication"); apk = g(data, "info")
	a.ConstString(rT0, "mBoundApplication")
	if err := a.InvokeStatic([]int{rTh, rT0}, getF); err != nil {
		return nil, err
	}
	a.MoveResultObject(rBd)
	a.ConstString(rT0, "info")
	if err := a.InvokeStatic([]int{rBd, rT0}, getF); err != nil {
		return nil, err
	}
	a.MoveResultObject(rAp)
	// s(apk, "mClassLoader", cl)
	a.ConstString(rT0, "mClassLoader")
	if err := a.InvokeStatic([]int{rAp, rT0, rCl}, setF); err != nil {
		return nil, err
	}
	// 回读校验：把 mClassLoader 读回来和 cl 比对。
	//
	// 这一步是整个壳里最值得校验的地方。Android 9+ 对非 SDK 接口做了限制，
	// getDeclaredFields() 会**过滤**掉 LoadedApk.mClassLoader 之类的隐藏字段，
	// 于是 s() 找不到字段、静默返回 false，ClassLoader 根本没被替换，
	// 随后框架仍用旧加载器加载 Manifest 里的 Activity，直接 ClassNotFoundException。
	//
	// 光看「代码跑完了」区分不出这种情况，必须回读才知道字段到底写没写进去。
	// 返回值：2=已生效；1=字段不可见（被隐藏 API 过滤）；0=字段可见但未写入。
	a.ConstString(rT1, "mClassLoader")
	if err := a.InvokeStatic([]int{rAp, rT1}, getF); err != nil {
		return nil, err
	}
	a.MoveResultObject(rT0)
	if err := a.IfEq(rT0, rCl, "swap_ok"); err != nil {
		return nil, err
	}
	a.IfEqz(rT0, "swap_hidden")
	a.Const4(rT0, 0)
	a.Return(rT0)
	a.Label("swap_ok")
	a.Const4(rT0, 2)
	a.Return(rT0)
	a.Label("swap_hidden")
	a.Const4(rT0, 1)
	a.Return(rT0)

	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	return &CodeBlob{Registers: 10, Ins: 1, Outs: 3, Insns: insns, Patches: patches}, nil
}

// activityThreadClass 是被反射接管的框架类名。
const activityThreadClass = "android.app.ActivityThread"

// ---- 取字段：g(Object, String) -> Object ----
//
// 等价 Java：
//
//	static Object g(Object o, String n) {
//	    for (Class c = o.getClass(); c != null; c = c.getSuperclass()) {
//	        Field[] fs = c.getDeclaredFields();
//	        for (int i = 0; i < fs.length; i++) {
//	            if (fs[i].getName().equals(n)) {
//	                fs[i].setAccessible(true);
//	                return fs[i].get(o);
//	            }
//	        }
//	    }
//	    return null;
//	}
//
// 用「遍历 getDeclaredFields 比对名字」而不是 getDeclaredField：
// 后者在字段不存在时会抛 NoSuchFieldException，而注入方法体不支持异常表，
// 一旦抛出就会直接崩溃；遍历式查找把「找不到」变成「返回 null」，无需异常。
//
// registers=8、ins=2 → o 在 v6、n 在 v7。
func loaderGetFieldCode(self string) (*CodeBlob, error) {
	const (
		rCls  = 0
		rFs   = 1
		rI    = 2
		rF    = 3
		rT    = 4
		rRes  = 5
		rO    = 6
		rName = 7
	)
	getClass := MethodSpec{Class: descObject, Name: "getClass", Proto: ProtoSpec{Ret: descClass}}
	getFields := MethodSpec{Class: descClass, Name: "getDeclaredFields",
		Proto: ProtoSpec{Ret: descFieldArray}}
	getSuper := MethodSpec{Class: descClass, Name: "getSuperclass", Proto: ProtoSpec{Ret: descClass}}
	fName := MethodSpec{Class: descField, Name: "getName", Proto: ProtoSpec{Ret: descStringType}}
	fSetAcc := MethodSpec{Class: descField, Name: "setAccessible",
		Proto: ProtoSpec{Ret: "V", Params: []string{"Z"}}}
	fGet := MethodSpec{Class: descField, Name: "get",
		Proto: ProtoSpec{Ret: descObject, Params: []string{descObject}}}
	strEq := MethodSpec{Class: descString, Name: "equals",
		Proto: ProtoSpec{Ret: "Z", Params: []string{descObject}}}

	a := NewAsm()
	if err := a.InvokeVirtual([]int{rO}, getClass); err != nil {
		return nil, err
	}
	a.MoveResultObject(rCls)

	a.Label("cls")
	a.IfEqz(rCls, "nil")
	// fs = c.getDeclaredFields(); i = 0
	if err := a.InvokeVirtual([]int{rCls}, getFields); err != nil {
		return nil, err
	}
	a.MoveResultObject(rFs)
	a.Const4(rI, 0)

	a.Label("scan")
	a.ArrayLength(rT, rFs)
	if err := a.IfGe(rI, rT, "nextCls"); err != nil {
		return nil, err
	}
	a.AGetObject(rF, rFs, rI)
	// if (!fs[i].getName().equals(n)) continue;
	if err := a.InvokeVirtual([]int{rF}, fName); err != nil {
		return nil, err
	}
	a.MoveResultObject(rT)
	if err := a.InvokeVirtual([]int{rT, rName}, strEq); err != nil {
		return nil, err
	}
	a.MoveResult(rT)
	a.IfEqz(rT, "next")
	// fs[i].setAccessible(true); return fs[i].get(o);
	a.Const4(rT, 1)
	if err := a.InvokeVirtual([]int{rF, rT}, fSetAcc); err != nil {
		return nil, err
	}
	if err := a.InvokeVirtual([]int{rF, rO}, fGet); err != nil {
		return nil, err
	}
	a.MoveResultObject(rRes)
	a.ReturnObject(rRes)

	a.Label("next")
	a.AddIntLit8(rI, 1)
	a.Goto("scan")

	a.Label("nextCls")
	if err := a.InvokeVirtual([]int{rCls}, getSuper); err != nil {
		return nil, err
	}
	a.MoveResultObject(rCls)
	a.Goto("cls")

	a.Label("nil")
	a.Const4(rRes, 0)
	a.ReturnObject(rRes)

	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	return &CodeBlob{Registers: 8, Ins: 2, Outs: 2, Insns: insns, Patches: patches}, nil
}

// ---- 写字段：s(Object, String, Object) -> boolean ----
//
// 等价 Java：
//
//	static boolean s(Object o, String n, Object val) {
//	    for (Class c = o.getClass(); c != null; c = c.getSuperclass()) {
//	        Field[] fs = c.getDeclaredFields();
//	        for (int i = 0; i < fs.length; i++) {
//	            if (fs[i].getName().equals(n)) {
//	                fs[i].setAccessible(true);
//	                fs[i].set(o, val);
//	                return true;
//	            }
//	        }
//	    }
//	    return false;
//	}
//
// registers=10、ins=3 → o 在 v7、n 在 v8、val 在 v9。
func loaderSetFieldCode(self string) (*CodeBlob, error) {
	const (
		rCls  = 0
		rFs   = 1
		rI    = 2
		rF    = 3
		rT    = 4
		rO    = 7
		rName = 8
		rVal  = 9
	)
	getClass := MethodSpec{Class: descObject, Name: "getClass", Proto: ProtoSpec{Ret: descClass}}
	getFields := MethodSpec{Class: descClass, Name: "getDeclaredFields",
		Proto: ProtoSpec{Ret: descFieldArray}}
	getSuper := MethodSpec{Class: descClass, Name: "getSuperclass", Proto: ProtoSpec{Ret: descClass}}
	fName := MethodSpec{Class: descField, Name: "getName", Proto: ProtoSpec{Ret: descStringType}}
	fSetAcc := MethodSpec{Class: descField, Name: "setAccessible",
		Proto: ProtoSpec{Ret: "V", Params: []string{"Z"}}}
	fSet := MethodSpec{Class: descField, Name: "set",
		Proto: ProtoSpec{Ret: "V", Params: []string{descObject, descObject}}}
	strEq := MethodSpec{Class: descString, Name: "equals",
		Proto: ProtoSpec{Ret: "Z", Params: []string{descObject}}}

	a := NewAsm()
	if err := a.InvokeVirtual([]int{rO}, getClass); err != nil {
		return nil, err
	}
	a.MoveResultObject(rCls)

	a.Label("cls")
	a.IfEqz(rCls, "false")
	if err := a.InvokeVirtual([]int{rCls}, getFields); err != nil {
		return nil, err
	}
	a.MoveResultObject(rFs)
	a.Const4(rI, 0)

	a.Label("scan")
	a.ArrayLength(rT, rFs)
	if err := a.IfGe(rI, rT, "nextCls"); err != nil {
		return nil, err
	}
	a.AGetObject(rF, rFs, rI)
	if err := a.InvokeVirtual([]int{rF}, fName); err != nil {
		return nil, err
	}
	a.MoveResultObject(rT)
	if err := a.InvokeVirtual([]int{rT, rName}, strEq); err != nil {
		return nil, err
	}
	a.MoveResult(rT)
	a.IfEqz(rT, "next")
	a.Const4(rT, 1)
	if err := a.InvokeVirtual([]int{rF, rT}, fSetAcc); err != nil {
		return nil, err
	}
	if err := a.InvokeVirtual([]int{rF, rO, rVal}, fSet); err != nil {
		return nil, err
	}
	a.Const4(rT, 1)
	a.Return(rT)

	a.Label("next")
	a.AddIntLit8(rI, 1)
	a.Goto("scan")

	a.Label("nextCls")
	if err := a.InvokeVirtual([]int{rCls}, getSuper); err != nil {
		return nil, err
	}
	a.MoveResultObject(rCls)
	a.Goto("cls")

	a.Label("false")
	a.Const4(rT, 0)
	a.Return(rT)

	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	return &CodeBlob{Registers: 10, Ins: 3, Outs: 3, Insns: insns, Patches: patches}, nil
}
