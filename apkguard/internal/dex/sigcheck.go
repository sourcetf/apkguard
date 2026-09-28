package dex

import "fmt"

// SigSpec 描述 D1（签名校验）要注入的校验类。
//
// 运行时通过 PackageManager 取回本 APK 的签名证书，计算 SHA-256 后与内置
// 指纹比对，不符即终止进程。这拦的是「二次打包」：重打包者换掉签名证书后，
// 应用会在启动阶段直接退出，而不是带着被植入的代码照常运行。
//
// 指纹来自加固时使用的密钥库（或使用方显式给出的哈希），因此**必须与 E1
// 实际签名的证书一致**——否则产物会在自己手上就无法启动。
type SigSpec struct {
	// Class 是校验类的描述符，形如 "Lcom/apkguard/shell/Sig;"。
	Class string
	// Digest 是签名证书 DER 的 SHA-256（32 字节）。
	Digest [32]byte
}

// Desc 返回校验入口方法的完整描述符。
func (s *SigSpec) Desc() string {
	return s.Class + "->" + SigEntry + "(" + descContext + ")V"
}

// SigEntry 是签名校验的入口方法名。
const SigEntry = "a"

// 签名校验引用的框架类型与常量。
const (
	descPackageManager = "Landroid/content/pm/PackageManager;"
	descPackageInfo    = "Landroid/content/pm/PackageInfo;"
	descSignatureArr   = "[Landroid/content/pm/Signature;"
	descMessageDigest  = "Ljava/security/MessageDigest;"
	// pmGetSignatures 是 PackageManager.GET_SIGNATURES 的取值。
	//
	// 已核对真实 android.jar：该常量等于 64。它在新版本上被标记为过时，
	// 但仍然受支持且语义不变（返回 APK 的签名证书数组）。
	pmGetSignatures = 64
	// digestAlg 是签名指纹所用的摘要算法。
	digestAlg = "SHA-256"
)

// SigAddition 构造签名校验类定义。
func SigAddition(sp *SigSpec) (Addition, error) {
	if sp.Class == "" {
		return Addition{}, fmt.Errorf("dex: 签名校验类名为空")
	}
	entry, err := sigCheckCode(sp)
	if err != nil {
		return Addition{}, err
	}
	digest, err := sigDigestCode(sp.Class, sigDigestName)
	if err != nil {
		return Addition{}, err
	}
	fail, err := sigFailCode(sp.Class)
	if err != nil {
		return Addition{}, err
	}

	protoCtxV := ProtoSpec{Ret: "V", Params: []string{descContext}}
	protoCtxBytes := ProtoSpec{Ret: descByteArray, Params: []string{descContext}}
	protoV := ProtoSpec{Ret: "V"}

	spec := ClassSpec{
		Name:   sp.Class,
		Super:  descObject,
		Access: accPublic,
		Methods: []ClassMethod{
			{Name: SigEntry, Proto: protoCtxV, Access: accPublic | accStatic, Code: entry},
			{Name: sigDigestName, Proto: protoCtxBytes, Access: accPrivate | accStatic, Code: digest},
			{Name: sigFailName, Proto: protoV, Access: accPrivate | accStatic, Code: fail},
		},
	}
	add := Addition{
		Methods: []MethodSpec{
			{Class: sp.Class, Name: SigEntry, Proto: protoCtxV},
			{Class: sp.Class, Name: sigDigestName, Proto: protoCtxBytes},
			{Class: sp.Class, Name: sigFailName, Proto: protoV},
		},
		Classes: []ClassSpec{spec},
	}
	return add, nil
}

// sigFailName 是校验失败时的处理方法名。
const sigFailName = "f"

// sigCheckCode 生成签名校验方法体。
//
// 等价 Java：
//
//	static void a(Context ctx) {
//	    byte[] want = { ... };                  // 编译期内联的 SHA-256
//	    byte[] got = d(ctx);                    // 取本 APK 的签名证书摘要
//	    if (got == null) { f(); return; }
//	    if (got.length != want.length) { f(); return; }
//	    for (int i = 0; i < want.length; i++) {
//	        if (got[i] != want[i]) { f(); return; }
//	    }
//	}
//
// 取摘要这一步与 C1 共用 sigDigestCode 的实现：两处各写一遍的话，
// 任何一处写错都会得到「指纹与证书不一致」——而这类问题只有在真机上
// 才会暴露，正是我们最没有条件排查的情形。
//
// registers=12、ins=1 → 入参 ctx 落在 v11。
func sigCheckCode(sp *SigSpec) (*CodeBlob, error) {
	const (
		rWant = 0 // byte[]
		rGot  = 1 // byte[]
		rI    = 2 // int
		rT0   = 3
		rLen  = 4
		rT1   = 5
		rCtx  = 11
	)
	digestM := MethodSpec{Class: sp.Class, Name: sigDigestName,
		Proto: ProtoSpec{Ret: descByteArray, Params: []string{descContext}}}
	failM := MethodSpec{Class: sp.Class, Name: sigFailName, Proto: ProtoSpec{Ret: "V"}}

	a := NewAsm()
	// want = { ... }：逐字节构造，避免在 DEX 里留下可读的指纹字符串。
	a.Const16(rT0, int16(len(sp.Digest)))
	if err := a.NewArray(rWant, rT0, descByteArray); err != nil {
		return nil, err
	}
	for i, b := range sp.Digest {
		a.Const16(rT0, int16(b))
		a.Const16(rT1, int16(i))
		a.APutByte(rT0, rWant, rT1)
	}

	// got = d(ctx)
	if err := a.InvokeStatic([]int{rCtx}, digestM); err != nil {
		return nil, err
	}
	a.MoveResultObject(rGot)
	// 取不到证书摘要（无签名信息）按失败处理。
	a.IfEqz(rGot, "fail")
	// if (got.length != want.length) fail;
	a.ArrayLength(rT0, rGot)
	a.ArrayLength(rLen, rWant)
	if err := a.IfNe(rT0, rLen, "fail"); err != nil {
		return nil, err
	}
	// for (int i = 0; i < want.length; i++) if (got[i] != want[i]) fail;
	a.Const4(rI, 0)
	a.Label("loop")
	if err := a.IfGe(rI, rLen, "done"); err != nil {
		return nil, err
	}
	a.AGetByte(rT0, rGot, rI)
	a.AGetByte(rT1, rWant, rI)
	if err := a.IfNe(rT0, rT1, "fail"); err != nil {
		return nil, err
	}
	a.AddIntLit8(rI, 1)
	a.Goto("loop")

	a.Label("done")
	a.ReturnVoid()

	// 失败分支统一处理，避免把 exit 调用重复展开到每个判定点。
	a.Label("fail")
	if err := a.InvokeStatic(nil, failM); err != nil {
		return nil, err
	}
	a.ReturnVoid()

	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	// 同上：内部调用 getPackageInfo(String, int)，加接收者共 3 字。
	return &CodeBlob{Registers: 12, Ins: 1, Outs: 3, Insns: insns, Patches: patches}, nil
}

// sigDigestName 是取签名证书摘要的方法名。
const sigDigestName = "d"

// sigFailCode 生成校验失败的处理：终止进程。
//
// 用 System.exit 而不是抛异常：注入方法体不支持异常表，抛出的异常没人接，
// 会以更难定位的「未捕获异常」形式崩溃；显式退出语义清晰，且不给
// 「捕获异常后继续运行」留下可乘之机。
//
// 等价 Java：
//
//	static void f() { System.exit(1); }
func sigFailCode(self string) (*CodeBlob, error) {
	exit := MethodSpec{Class: descSystem, Name: "exit",
		Proto: ProtoSpec{Ret: "V", Params: []string{"I"}}}

	a := NewAsm()
	a.Const4(0, 1)
	if err := a.InvokeStatic([]int{0}, exit); err != nil {
		return nil, err
	}
	a.ReturnVoid()

	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	return &CodeBlob{Registers: 1, Ins: 0, Outs: 1, Insns: insns, Patches: patches}, nil
}
