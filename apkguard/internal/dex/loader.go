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
	// MAC 为 true 时，每份载荷（含 LibItems 里的原生库载荷）在解密前
	// 先用 HMAC-SHA256 校验完整性（encrypt-then-MAC，见 pack.MAC）。
	// 为 false 时不生成任何 MAC 指令，产物与旧格式完全一致。
	//
	// 库载荷与 DEX 载荷**共用这一个开关**，不另设第二个标志：打包侧 B1 与
	// C2 都只由 -payload-mac（config.Options.PayloadMAC）决定是否追加 tag，
	// 而 C2 依赖 B1/B2/B3（config.Validate 强制），因此合法配置下两者的
	// tag 状态必然一致。库载荷的 MAC 输入绑定原始库名（LoaderLibItem.Name），
	// 与 DEX 载荷绑定原始 DEX 名同理，使不同库的载荷无法互换。
	MAC bool
	// LibItems 是 C2（SO 加壳）留下的原生库载荷：壳在构造 DexClassLoader
	// 之前把它们解密落地到私有目录，并把该目录并入库搜索路径。
	//
	// 为空表示未启用 C2，Loader 生成的字节码与旧版逐字节一致。
	LibItems []LoaderLibItem
	// LibDir 是原生库解密后落地的私有子目录名（相对应用私有目录）。
	//
	// 与 TempDir 同理必须落在私有目录：外部存储通常 noexec，且不在链接器
	// 命名空间内，dlopen 会失败。C2 还要求落盘后置只读（W^X，见 LibReadOnly）。
	LibDir string
	// LibReadOnly 为 true 时，落地后的 .so 调用 setReadOnly()。
	//
	// Android 10（API 29）起强制 W^X：targetSdk ≥ 29 的应用不能 dlopen
	// 「可写」文件。这与 DEX 的只读阈值（API 34）不同，故单独设开关。
	LibReadOnly bool
}

// LoaderLibItem 是一份待运行时解密的原生库载荷（C2）。
type LoaderLibItem struct {
	// Asset 是 APK 内的条目名，形如 "assets/res_ab12.bin"。
	Asset string
	// Name 是解密后落地使用的文件名（如 "libfoo.so"）。
	//
	// 必须是原始文件名：System.loadLibrary 经 ClassLoader.findLibrary 在
	// 库搜索路径里按 "lib<name>.so" 查找，改名会导致找不到。
	//
	// 启用 MAC（LoaderSpec.MAC）时它同时是 HMAC 的绑定输入，必须与打包侧
	// C2 用来计算 tag 的原始库名逐字节一致（见 passes/soenc.go）。
	Name string
	// Abi 是原始 ABI 目录名，仅用于报告与排障。
	Abi string
	// Size 是载荷字节数（含前置 IV）。
	Size int
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
	//
	// 注意：启用载荷 MAC 时 Blob 尾部多 32 字节 tag，此处必须取
	// len(Blob)（B3 已如此）——若仍按旧格式少算 32，r() 会少读尾部字节，
	// 表现为解密后 DEX 校验失败或 MAC 校验必然失败。
	Size int
	// Name 是原始 DEX 名（如 "classes.dex"），仅启用 MAC 时用于绑定校验。
	//
	// 必须是 Payload.Name 而不是容器化后的 Asset 名：B8 会重命名 Asset，
	// 用 Asset 会让壳侧算出的 MAC 与打包时不一致。
	Name string
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
	descMac          = "Ljavax/crypto/Mac;"
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
	if ls.MAC {
		// MAC 校验要把原始 DEX 名内联进字节码；缺失说明 B3 接线漏了
		// Name 字段，必须在打包期就报错，而不是产出一个必然启动失败的壳。
		for _, it := range ls.Items {
			if it.Name == "" {
				return Addition{}, fmt.Errorf("dex: Loader 启用了 MAC 但载荷 %s 缺少原始 DEX 名（无法绑定校验）", it.Asset)
			}
		}
		// 库载荷同理：原始库名既是落地文件名，也是 MAC 的绑定输入。
		for _, it := range ls.LibItems {
			if it.Name == "" {
				return Addition{}, fmt.Errorf("dex: Loader 启用了 MAC 但库载荷 %s 缺少原始库名（无法绑定校验）", it.Asset)
			}
		}
	}
	if len(ls.LibItems) > 0 && ls.LibDir == "" {
		return Addition{}, fmt.Errorf("dex: Loader 有原生库载荷但未指定落地目录 LibDir")
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
	var macVerify *CodeBlob
	if ls.MAC {
		macVerify, err = loaderMACCode(ls.Class)
		if err != nil {
			return Addition{}, err
		}
	}

	const (
		nameEntry   = LoaderEntry
		nameRead    = "r"
		nameDecrypt = "c"
		nameWrite   = "w"
		nameInstall = "i"
		nameGetF    = "g"
		nameSetF    = "s"
		nameMAC     = "v"
	)

	protoCtxCL := ProtoSpec{Ret: descClassLoader, Params: []string{descContext}}
	protoInBytes := ProtoSpec{Ret: descByteArray, Params: []string{descInputStream, "I"}}
	protoBytes2 := ProtoSpec{Ret: descByteArray, Params: []string{descByteArray, descByteArray, "I"}}
	protoFileBytes := ProtoSpec{Ret: "V", Params: []string{descFile, descByteArray}}
	protoCLI := ProtoSpec{Ret: "I", Params: []string{descClassLoader}}
	protoObjStr := ProtoSpec{Ret: descObject, Params: []string{descObject, descStringType}}
	protoObjStrObjBool := ProtoSpec{Ret: "Z", Params: []string{descObject, descStringType, descObject}}
	// v(blob, key, name)：blob=IV‖密文‖tag，key=AES 密钥，name=原始 DEX 名。
	protoMAC := ProtoSpec{Ret: "Z", Params: []string{descByteArray, descByteArray, descStringType}}

	methods := []ClassMethod{
		{Name: nameEntry, Proto: protoCtxCL, Access: accPublic | accStatic, Code: entry},
		{Name: nameRead, Proto: protoInBytes, Access: accPrivate | accStatic, Code: readAll},
		{Name: nameDecrypt, Proto: protoBytes2, Access: accPrivate | accStatic, Code: decrypt},
		{Name: nameWrite, Proto: protoFileBytes, Access: accPrivate | accStatic, Code: writeAll},
		{Name: nameInstall, Proto: protoCLI, Access: accPrivate | accStatic, Code: install},
		{Name: nameGetF, Proto: protoObjStr, Access: accPrivate | accStatic, Code: getField},
		{Name: nameSetF, Proto: protoObjStrObjBool, Access: accPrivate | accStatic, Code: setField},
	}
	// 方法表必须与类体一一对应，planInjectedClass 会校验。
	regMethods := []MethodSpec{
		{Class: ls.Class, Name: nameEntry, Proto: protoCtxCL},
		{Class: ls.Class, Name: nameRead, Proto: protoInBytes},
		{Class: ls.Class, Name: nameDecrypt, Proto: protoBytes2},
		{Class: ls.Class, Name: nameWrite, Proto: protoFileBytes},
		{Class: ls.Class, Name: nameInstall, Proto: protoCLI},
		{Class: ls.Class, Name: nameGetF, Proto: protoObjStr},
		{Class: ls.Class, Name: nameSetF, Proto: protoObjStrObjBool},
	}
	// 未启用 MAC 时**不**生成 v：产物字节与旧版完全一致，也不引入
	// javax.crypto.Mac 相关引用。
	if ls.MAC {
		methods = append(methods, ClassMethod{Name: nameMAC, Proto: protoMAC, Access: accPrivate | accStatic, Code: macVerify})
		regMethods = append(regMethods, MethodSpec{Class: ls.Class, Name: nameMAC, Proto: protoMAC})
	}

	spec := ClassSpec{
		Name:    ls.Class,
		Super:   descObject,
		Access:  accPublic,
		Methods: methods,
	}

	// 类必须自己出现在方法表里，planInjectedClass 会校验注入方法已登记。
	add := Addition{
		Methods: regMethods,
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
		Proto: ProtoSpec{Ret: descByteArray, Params: []string{descByteArray, descByteArray, "I"}}}
	writeM := MethodSpec{Class: ls.Class, Name: "w",
		Proto: ProtoSpec{Ret: "V", Params: []string{descFile, descByteArray}}}
	instM := MethodSpec{Class: ls.Class, Name: "i",
		Proto: ProtoSpec{Ret: "I", Params: []string{descClassLoader}}}
	// MAC 校验（仅在 ls.MAC 时被引用）与失败终止。
	macM := MethodSpec{Class: ls.Class, Name: "v",
		Proto: ProtoSpec{Ret: "Z", Params: []string{descByteArray, descByteArray, descStringType}}}
	exitM := MethodSpec{Class: descSystem, Name: "exit",
		Proto: ProtoSpec{Ret: "V", Params: []string{"I"}}}
	// .so 落地后置只读（W^X，Android 10+ 对 targetSdk ≥ 29 的硬性要求）。
	setROM := MethodSpec{Class: descFile, Name: "setReadOnly", Proto: ProtoSpec{Ret: "Z"}}

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
		// 启用 MAC 时先校验再解密：顺序不可颠倒。
		//
		// 若先解密再比对，攻击者就能从「填充是否合法」的差异里获得
		// 填充 oracle；encrypt-then-MAC 的意义正在于让校验失败与密钥
		// 错误在外部观察上不可区分（都走同一条终止路径）。
		if ls.MAC {
			a.ConstString(rT0, it.Name)
			if err := a.InvokeStatic([]int{rBlob, rKey, rT0}, macM); err != nil {
				return nil, err
			}
			a.MoveResult(rT1)
			a.IfEqz(rT1, "mac_fail")
		}
		// dex = c(blob, key, drop)
		//
		// 启用 MAC 时 blob 尾部有 32 字节 tag，必须把 drop 传给 c 让其排除，
		// 否则 tag 会被当成 CBC 密文，填充校验失败。
		if ls.MAC {
			a.Const16(rT2, int16(tagLen))
		} else {
			a.Const4(rT2, 0)
		}
		if err := a.InvokeStatic([]int{rBlob, rKey, rT2}, decM); err != nil {
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

	// C2：解密原生库载荷到私有目录。
	//
	// 必须在构造 DexClassLoader 之前完成：应用的 System.loadLibrary 在
	// attachBaseContext 之后（onCreate 等）才会被调用，届时库文件必须已就绪。
	//
	// 寄存器复用：DEX 循环结束后 rIn(3)/rBlob(4)/rDex(5)/rFile(6) 都已无用。
	// rIn 改存 libDir(File)、rBlob 改存 libPath(String)，避免顶高寄存器总数
	// （invoke 的 35c 只编码 v0..v15，一旦超过就无法传参）。
	//
	// 载荷 MAC 启用时（ls.MAC），每份库载荷在解密前先调用 v() 校验 HMAC，
	// 失败与 DEX 载荷走同一条硬终止路径（mac_fail → System.exit(1)）；
	// 关闭时该分支不生成任何指令，产物与旧版逐字节一致。
	if len(ls.LibItems) > 0 {
		const (
			rLibDir  = rIn
			rLibPath = rBlob
			rLibIn   = rDex
			rLibBlob = rT0
			rLibSo   = rT1
			rLibFile = rFile
		)
		// libDir = base.getDir(LIBDIR, 0)
		a.ConstString(rT0, ls.LibDir)
		a.Const4(rT1, 0)
		if err := a.InvokeVirtual([]int{rBase, rT0, rT1}, getDir); err != nil {
			return nil, err
		}
		a.MoveResultObject(rLibDir)
		// libPath = libDir.getAbsolutePath()
		if err := a.InvokeVirtual([]int{rLibDir}, absPath); err != nil {
			return nil, err
		}
		a.MoveResultObject(rLibPath)

		for _, it := range ls.LibItems {
			// in = base.getAssets().open(ASSET)
			if err := a.InvokeVirtual([]int{rBase}, getAssets); err != nil {
				return nil, err
			}
			a.MoveResultObject(rT2)
			a.ConstString(rT3, assetKey(it.Asset))
			if err := a.InvokeVirtual([]int{rT2, rT3}, amOpen); err != nil {
				return nil, err
			}
			a.MoveResultObject(rLibIn)
			// blob = r(in, SIZE)
			a.Const32(rT2, int32(it.Size))
			if err := a.InvokeStatic([]int{rLibIn, rT2}, readM); err != nil {
				return nil, err
			}
			a.MoveResultObject(rLibBlob)
			// 启用 MAC 时先校验再解密：与 DEX 载荷走同一条路径、同一个 v()，
			// 绑定的是**原始库名**（it.Name）。顺序不可颠倒——先解密再比对
			// 会从填充是否合法的差异里泄漏填充 oracle。
			if ls.MAC {
				a.ConstString(rT3, it.Name)
				if err := a.InvokeStatic([]int{rLibBlob, rKey, rT3}, macM); err != nil {
					return nil, err
				}
				a.MoveResult(rT2)
				a.IfEqz(rT2, "mac_fail")
			}
			// so = c(blob, key, drop)：复用 DEX 的解密实现（同样是 IV‖AES-CBC）。
			// 启用 MAC 时 blob 尾部有 32 字节 tag，drop 必须为 tagLen，否则 tag
			// 会被当成 CBC 密文，填充校验必然失败；未启用时 drop 传 0，语义与
			// 旧版逐字节一致。
			if ls.MAC {
				a.Const16(rT2, int16(tagLen))
			} else {
				a.Const4(rT2, 0)
			}
			if err := a.InvokeStatic([]int{rLibBlob, rKey, rT2}, decM); err != nil {
				return nil, err
			}
			a.MoveResultObject(rLibSo)
			// f = new File(libDir, NAME)
			a.NewInstance(rLibFile, descFile)
			a.ConstString(rT2, it.Name)
			if err := a.InvokeDirect([]int{rLibFile, rLibDir, rT2}, fileInit); err != nil {
				return nil, err
			}
			// w(f, so)
			if err := a.InvokeStatic([]int{rLibFile, rLibSo}, writeM); err != nil {
				return nil, err
			}
			// f.setReadOnly()：Android 10+ 的 W^X 要求，targetSdk ≥ 29 必须置只读，
			// 否则 dlopen 会报 "is writable by the app"。
			if ls.LibReadOnly {
				if err := a.InvokeVirtual([]int{rLibFile}, setROM); err != nil {
					return nil, err
				}
			}
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

	// C2 启用时把解密目录并入库搜索路径：libPath + ":" + nativeLibraryDir。
	//
	// 解密目录在前、原目录兜底：未被 C2 处理的库（以及 C1 注入的
	// libapkguard.so）仍在原目录可解析。System.loadLibrary 会经
	// ClassLoader.findLibrary 在 nativeLibraryDirectories 里按顺序查找。
	//
	// 注意这只覆盖 Java 层加载路径；native 层裸名 dlopen 与
	// android_dlopen_ext（Flutter/RN/Unity 从 APK 按偏移加载）读不到
	// 这个 Java 字段，无法接管（见 C2 方案文档 §2.2.4）。
	if len(ls.LibItems) > 0 {
		a.NewInstance(rT2, descStringB)
		if err := a.InvokeDirect([]int{rT2}, sbInit); err != nil {
			return nil, err
		}
		// libPath 仍存放在 DEX 循环用的 rBlob 里。
		if err := a.InvokeVirtual([]int{rT2, rBlob}, sbAppend); err != nil {
			return nil, err
		}
		a.SGetObject(rT3, sepField)
		if err := a.InvokeVirtual([]int{rT2, rT3}, sbAppend); err != nil {
			return nil, err
		}
		if err := a.InvokeVirtual([]int{rT2, rFile}, sbAppend); err != nil {
			return nil, err
		}
		if err := a.InvokeVirtual([]int{rT2}, sbToString); err != nil {
			return nil, err
		}
		a.MoveResultObject(rT3)
		a.MoveObject(rFile, rT3)
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

	// MAC 校验失败：硬终止，与 D1 签名校验同一处置方式（System.exit(1)）。
	//
	// 不做静默假路径：注入字节码没有异常表，构造假路径既复杂又可能误伤
	// 合法环境；而 MAC 的不可伪造性不依赖「隐藏校验点」，攻击者知道这里
	// 有校验也改不出合法载荷。返回值仅为满足校验器的控制流要求，
	// 真机上 System.exit 不会返回。
	if ls.MAC {
		a.Label("mac_fail")
		a.Const4(rT0, 1)
		if err := a.InvokeStatic([]int{rT0}, exitM); err != nil {
			return nil, err
		}
		a.Const4(rT0, 0)
		a.ReturnObject(rT0)
	}

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

// ---- 解密：c(byte[], byte[], int) -> byte[] ----
//
// 等价 Java：
//
//	static byte[] c(byte[] blob, byte[] key, int drop) {
//	    byte[] iv = new byte[16];
//	    System.arraycopy(blob, 0, iv, 0, 16);
//	    Cipher cp = Cipher.getInstance("AES/CBC/PKCS5Padding");
//	    cp.init(DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
//	    return cp.doFinal(blob, 16, blob.length - 16 - drop);
//	}
//
// drop 是「载荷尾部需要忽略的字节数」：启用载荷 MAC 时尾部有 32 字节 tag，
// 必须排除在 CBC 密文之外，否则填充校验必然失败（表现为解密后 DEX 校验失败）。
// 未启用 MAC 与 C2 的 .so 载荷都传 0，语义与旧版完全一致。
//
// 密钥由调用方传入而不是在此内联：C1 生效时它来自 native 派生，
// 未启用时才是内联常量。这样解密路径本身与密钥来源解耦。
//
// registers=9、ins=3 → blob 在 v6、key 在 v7、drop 在 v8。
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
		rDrop = 8
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
	// return cp.doFinal(blob, 16, blob.length - 16 - drop)
	a.Const16(rT0, int16(ivLen))
	a.ArrayLength(rT1, rBlob)
	a.SubInt(rT1, rT1, rT0)
	a.SubInt(rT1, rT1, rDrop)
	if err := a.InvokeVirtual([]int{rCp, rBlob, rT0, rT1}, doFinal); err != nil {
		return nil, err
	}
	a.MoveResultObject(rT1)
	a.ReturnObject(rT1)

	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	return &CodeBlob{Registers: 9, Ins: 3, Outs: 5, Insns: insns, Patches: patches}, nil
}

// ---- 载荷 MAC：v(byte[] blob, byte[] key, String name) -> boolean ----
//
// 等价 Java：
//
//	static boolean v(byte[] blob, byte[] key, String name) {
//	    if (blob.length < 16 + 32) return false;             // IV + Tag
//	    MessageDigest md = MessageDigest.getInstance("SHA-256");
//	    md.update(key);
//	    md.update("apkguard/payload-mac".getBytes());
//	    byte[] macKey = md.digest();                          // 域分离
//	    Mac mac = Mac.getInstance("HmacSHA256");
//	    mac.init(new SecretKeySpec(macKey, "HmacSHA256"));
//	    mac.update(name.getBytes());
//	    mac.update(blob, 0, blob.length - 32);               // 覆盖 IV‖密文
//	    byte[] got = mac.doFinal();
//	    int diff = 0;                                        // 常量时间比较
//	    for (int i = 0; i < 32; i++)
//	        diff |= got[i] ^ blob[blob.length - 32 + i];
//	    return diff == 0;
//	}
//
// 评审要点：
//   - 先验 MAC 后解密（调用点在 entry 里位于 c() 之前），消除填充 oracle；
//   - 比较用「逐字节 XOR 累加再判 0」，不提前返回，避免 tag 前缀的定时侧信道；
//   - 长度不足与 tag 不符都返回 false，不做差异化行为；
//   - name 绑定的是**原始 DEX 名**（Payload.Name），不是容器化后的 Asset 名。
//
// 形参类型必须按接口写：Mac.init 的参数是 java.security.Key（SecretKeySpec
// 实现它），写成具体类会被 ART 校验器拒绝（与 loaderDecryptCode 同理）。
//
// registers=14、ins=3 → blob 在 v11、key 在 v12、name 在 v13。
func loaderMACCode(self string) (*CodeBlob, error) {
	const (
		rDom    = 0 // byte[] 域分离串
		rMd     = 1 // MessageDigest
		rMacKey = 2 // byte[]
		rMac    = 3 // Mac
		rNameB  = 4 // byte[] name.getBytes()
		rGot    = 5 // byte[] mac.doFinal()
		rI      = 6 // int
		rDiff   = 7 // int
		rLen    = 8 // int 复用为 blob.length - 32
		rT0     = 9
		rT1     = 10
		rBlob   = 11
		rKey    = 12
		rName   = 13
	)
	strGetBytes := MethodSpec{Class: descString, Name: "getBytes", Proto: ProtoSpec{Ret: descByteArray}}
	mdGetInstance := MethodSpec{Class: descMessageDigest, Name: "getInstance",
		Proto: ProtoSpec{Ret: descMessageDigest, Params: []string{descStringType}}}
	mdUpdate := MethodSpec{Class: descMessageDigest, Name: "update",
		Proto: ProtoSpec{Ret: "V", Params: []string{descByteArray}}}
	mdDigest := MethodSpec{Class: descMessageDigest, Name: "digest", Proto: ProtoSpec{Ret: descByteArray}}
	macGetInstance := MethodSpec{Class: descMac, Name: "getInstance",
		Proto: ProtoSpec{Ret: descMac, Params: []string{descStringType}}}
	macInit := MethodSpec{Class: descMac, Name: "init",
		Proto: ProtoSpec{Ret: "V", Params: []string{descKeyIface}}}
	macUpdate1 := MethodSpec{Class: descMac, Name: "update",
		Proto: ProtoSpec{Ret: "V", Params: []string{descByteArray}}}
	macUpdate3 := MethodSpec{Class: descMac, Name: "update",
		Proto: ProtoSpec{Ret: "V", Params: []string{descByteArray, "I", "I"}}}
	macDoFinal := MethodSpec{Class: descMac, Name: "doFinal", Proto: ProtoSpec{Ret: descByteArray}}
	sksInit := MethodSpec{Class: descSecretKey, Name: "<init>",
		Proto: ProtoSpec{Ret: "V", Params: []string{descByteArray, descStringType}}}

	a := NewAsm()
	// if (blob.length < 48) return false;
	a.ArrayLength(rLen, rBlob)
	a.Const16(rT0, int16(ivLen+tagLen))
	if err := a.IfLt(rLen, rT0, "fail"); err != nil {
		return nil, err
	}
	// dom = "apkguard/payload-mac".getBytes()
	a.ConstString(rT0, macDomain)
	if err := a.InvokeVirtual([]int{rT0}, strGetBytes); err != nil {
		return nil, err
	}
	a.MoveResultObject(rDom)
	// md = MessageDigest.getInstance("SHA-256")
	a.ConstString(rT0, digestAlg)
	if err := a.InvokeStatic([]int{rT0}, mdGetInstance); err != nil {
		return nil, err
	}
	a.MoveResultObject(rMd)
	// md.update(key); md.update(dom); macKey = md.digest()
	if err := a.InvokeVirtual([]int{rMd, rKey}, mdUpdate); err != nil {
		return nil, err
	}
	if err := a.InvokeVirtual([]int{rMd, rDom}, mdUpdate); err != nil {
		return nil, err
	}
	if err := a.InvokeVirtual([]int{rMd}, mdDigest); err != nil {
		return nil, err
	}
	a.MoveResultObject(rMacKey)
	// mac = Mac.getInstance("HmacSHA256")
	a.ConstString(rT0, macAlg)
	if err := a.InvokeStatic([]int{rT0}, macGetInstance); err != nil {
		return nil, err
	}
	a.MoveResultObject(rMac)
	// mac.init(new SecretKeySpec(macKey, "HmacSHA256"))
	a.NewInstance(rT0, descSecretKey)
	a.ConstString(rT1, macAlg)
	if err := a.InvokeDirect([]int{rT0, rMacKey, rT1}, sksInit); err != nil {
		return nil, err
	}
	if err := a.InvokeVirtual([]int{rMac, rT0}, macInit); err != nil {
		return nil, err
	}
	// mac.update(name.getBytes())
	if err := a.InvokeVirtual([]int{rName}, strGetBytes); err != nil {
		return nil, err
	}
	a.MoveResultObject(rNameB)
	if err := a.InvokeVirtual([]int{rMac, rNameB}, macUpdate1); err != nil {
		return nil, err
	}
	// mac.update(blob, 0, blob.length - 32)
	a.Const4(rT0, 0)
	a.Const16(rT1, int16(tagLen))
	a.SubInt(rLen, rLen, rT1)
	if err := a.InvokeVirtual([]int{rMac, rBlob, rT0, rLen}, macUpdate3); err != nil {
		return nil, err
	}
	// got = mac.doFinal()
	if err := a.InvokeVirtual([]int{rMac}, macDoFinal); err != nil {
		return nil, err
	}
	a.MoveResultObject(rGot)
	// diff = 0; i = 0
	a.Const4(rDiff, 0)
	a.Const4(rI, 0)
	a.Label("loop")
	a.Const16(rT0, int16(tagLen))
	if err := a.IfGe(rI, rT0, "done"); err != nil {
		return nil, err
	}
	a.AGetByte(rT1, rGot, rI)
	// 直接读 blob 尾部的 tag，省一次 arraycopy。rLen 已是 len-32。
	a.AddInt(rT0, rLen, rI)
	a.AGetByte(rT0, rBlob, rT0)
	a.XorInt(rT1, rT1, rT0)
	a.OrInt(rDiff, rDiff, rT1)
	a.AddIntLit8(rI, 1)
	a.Goto("loop")
	a.Label("done")
	a.Const4(rT0, 0)
	if err := a.IfEq(rDiff, rT0, "ok"); err != nil {
		return nil, err
	}
	a.Const4(rT0, 0)
	a.Return(rT0)
	a.Label("ok")
	a.Const4(rT0, 1)
	a.Return(rT0)
	a.Label("fail")
	a.Const4(rT0, 0)
	a.Return(rT0)

	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	return &CodeBlob{Registers: 14, Ins: 3, Outs: 4, Insns: insns, Patches: patches}, nil
}

// 这些常量与 internal/pack/pack.go 是两处独立定义，任何一处漂移都会让
// 壳算出的 MAC/解密参数与打包时对不上——且只有真机启动才暴露。
// 除本文件的解释器测试外，pack 侧另有对拍守卫测试钉住同一组值。
const (
	keyLen    = 32 // AES-256
	ivLen     = 16 // CBC 分组长度
	tagLen    = 32 // HMAC-SHA256 标签长度
	cipherAlg = "AES/CBC/PKCS5Padding"
	keyAlg    = "AES"
	macAlg    = "HmacSHA256"
	// macDomain 必须与 pack.macDomain 逐字节一致。
	macDomain = "apkguard/payload-mac"
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

	delM := MethodSpec{Class: descFile, Name: "delete", Proto: ProtoSpec{Ret: "Z"}}

	a := NewAsm()
	// f.delete()：先删掉可能存在的旧文件，再写。
	//
	// 必须删，不能直接覆盖：MarkReadOnly 打开时上一次启动已把 d0.dex 标记为
	// 只读（0444），而 FileOutputStream 对已存在的只读文件**没有写权限**，
	// 于是这次启动抛
	//   java.lang.RuntimeException: Unable to instantiate application
	//     java.io.FileNotFoundException: .../app_ag/d0.dex: open failed:
	//     EACCES (Permission denied)
	// 实测于 RustDesk（targetSdk ≥ 34 会打开 MarkReadOnly）：表现为
	// 「装上第一次能开、第二次就崩」。删除只读文件在应用自己的目录里是允许的
	// （目录可写即可），因此这是正确且最小的修法。
	if err := a.InvokeVirtual([]int{rF}, delM); err != nil {
		return nil, err
	}
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
	// 失败路径（1/0）必须留下 logcat 线索。
	//
	// 非 debug 产物此前对返回值不作任何处理也不记录：Android 9+ 的隐藏 API
	// 限制一旦把字段挡掉，现象就是「载荷解密成功、随后 Activity 找不到类」，
	// 而 logcat 毫无线索，只能靠猜。这里在**失败路径**打印 Log.w（成功不打，
	// 避免正式产物产生噪声）；debug 模式下另有 Toast（见 loaderEntryCode）。
	logW := MethodSpec{Class: descLog, Name: "w",
		Proto: ProtoSpec{Ret: "I", Params: []string{descStringType, descStringType}}}
	a.IfEqz(rT0, "swap_hidden")
	a.ConstString(rT0, loaderLogTag)
	a.ConstString(rT1, loaderSwapStaleMsg)
	if err := a.InvokeStatic([]int{rT0, rT1}, logW); err != nil {
		return nil, err
	}
	a.Const4(rT0, 0)
	a.Return(rT0)
	a.Label("swap_ok")
	a.Const4(rT0, 2)
	a.Return(rT0)
	a.Label("swap_hidden")
	a.ConstString(rT0, loaderLogTag)
	a.ConstString(rT1, loaderSwapHiddenMsg)
	if err := a.InvokeStatic([]int{rT0, rT1}, logW); err != nil {
		return nil, err
	}
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

// loaderLogTag 是 ClassLoader 接管失败时写入 logcat 的标签。
//
// 非 debug 产物里这是唯一的现场线索：Android 9+ 的隐藏 API 限制会让
// mClassLoader 的替换静默失效（字段被 getDeclaredFields 过滤、或写入不生效），
// 现象是「载荷解密成功、随后 Activity ClassNotFoundException」而 logcat
// 毫无痕迹。成功路径不打印，避免正式产物产生噪声。
const loaderLogTag = "APKGUARD"

const (
	// loaderSwapHiddenMsg 对应回读为 null：字段被隐藏 API 过滤或根本不存在。
	loaderSwapHiddenMsg = "ClassLoader 接管失败：mClassLoader 被隐藏 API 过滤或未找到" +
		"（Android 9+ 非 SDK 接口限制），Activity 将由旧加载器加载并抛 ClassNotFoundException"
	// loaderSwapStaleMsg 对应回读值非空但与写入值不一致（如 final 字段、写入被回滚）。
	loaderSwapStaleMsg = "ClassLoader 接管失败：mClassLoader 字段可见但写入未生效" +
		"（回读值不一致），ClassLoader 未被替换"
)

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
