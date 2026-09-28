package dex

import "fmt"

// DevSpec 描述 D5（设备绑定）要注入的校验类。
//
// 绑定对象是 ANDROID_ID：它在「同一设备 + 同一签名证书 + 同一用户」下稳定，
// 且重装换签名后会变化——正好符合设备绑定的语义。相比拿 Build.MODEL 之类
// 拼一串指纹，单取 ANDROID_ID 的好处是使用方能一条命令取到它：
//
//	adb shell settings get secure android_id
//
// 这一点很重要：绑定信息必须由使用方在**目标设备**上采集，工具本身
// 无法凭空得知。取值流程越简单，越不容易出错。
type DevSpec struct {
	// Class 是校验类的描述符。
	Class string
	// Digest 是绑定目标的 SHA-256（32 字节）。
	Digest [32]byte
}

// DevEntry 是设备校验的入口方法名。
const DevEntry = "a"

// 设备绑定引用的框架类型。
const (
	descContentResolver = "Landroid/content/ContentResolver;"
	descSettingsSecure  = "Landroid/provider/Settings$Secure;"
	// androidIDKey 是 Settings.Secure 中设备标识的键名。
	androidIDKey = "android_id"
)

// DevAddition 构造设备绑定校验类。
//
// 等价 Java：
//
//	public class Dev {
//	    static void a(Context ctx) {
//	        byte[] want = { ... };
//	        String id = d(ctx);
//	        if (id == null) { return; }        // 取不到即放行（失败开放）
//	        byte[] got = MessageDigest.getInstance("SHA-256")
//	                        .digest(id.getBytes());
//	        if (got.length != want.length) { f(); return; }
//	        for (int i = 0; i < want.length; i++)
//	            if (got[i] != want[i]) { f(); return; }
//	    }
//	    static String d(Context ctx) {
//	        return Settings.Secure.getString(
//	                ctx.getContentResolver(), "android_id");
//	    }
//	    static void f() { System.exit(1); }
//	}
//
// 「取不到即放行」是有意的：部分定制 ROM 会限制读取 android_id，若把
// 「读不到」也判成未授权，正常用户会被挡在门外；绑定要拦的是「明确的
// 不匹配」，而不是「信息缺失」。
func DevAddition(sp *DevSpec) (Addition, error) {
	if sp.Class == "" {
		return Addition{}, fmt.Errorf("dex: 设备绑定类名为空")
	}
	check, err := devCheckCode(sp)
	if err != nil {
		return Addition{}, err
	}
	did, err := devIDCode(sp.Class)
	if err != nil {
		return Addition{}, err
	}
	fail, err := sigFailCode(sp.Class)
	if err != nil {
		return Addition{}, err
	}

	protoCtxV := ProtoSpec{Ret: "V", Params: []string{descContext}}
	protoCtxStr := ProtoSpec{Ret: descStringType, Params: []string{descContext}}
	protoV := ProtoSpec{Ret: "V"}

	spec := ClassSpec{
		Name:   sp.Class,
		Super:  descObject,
		Access: accPublic,
		Methods: []ClassMethod{
			{Name: DevEntry, Proto: protoCtxV, Access: accPublic | accStatic, Code: check},
			{Name: devIDName, Proto: protoCtxStr, Access: accPrivate | accStatic, Code: did},
			{Name: sigFailName, Proto: protoV, Access: accPrivate | accStatic, Code: fail},
		},
	}
	return Addition{
		Methods: []MethodSpec{
			{Class: sp.Class, Name: DevEntry, Proto: protoCtxV},
			{Class: sp.Class, Name: devIDName, Proto: protoCtxStr},
			{Class: sp.Class, Name: sigFailName, Proto: protoV},
		},
		Classes: []ClassSpec{spec},
	}, nil
}

// devIDName 是读取设备标识的方法名。
const devIDName = "d"

// devIDCode 生成读取 ANDROID_ID 的方法。
//
// registers=4、ins=1 → 入参 ctx 落在 v3。
func devIDCode(self string) (*CodeBlob, error) {
	getResolver := MethodSpec{Class: descContext, Name: "getContentResolver",
		Proto: ProtoSpec{Ret: descContentResolver}}
	getString := MethodSpec{Class: descSettingsSecure, Name: "getString",
		Proto: ProtoSpec{Ret: descStringType, Params: []string{descContentResolver, descStringType}}}

	a := NewAsm()
	a.ConstString(0, androidIDKey)
	if err := a.InvokeVirtual([]int{3}, getResolver); err != nil {
		return nil, err
	}
	a.MoveResultObject(1)
	if err := a.InvokeStatic([]int{1, 0}, getString); err != nil {
		return nil, err
	}
	a.MoveResultObject(2)
	a.ReturnObject(2)

	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	return &CodeBlob{Registers: 4, Ins: 1, Outs: 2, Insns: insns, Patches: patches}, nil
}

// devCheckCode 生成设备校验方法体。
//
// registers=8、ins=1 → 入参 ctx 落在 v7。
func devCheckCode(sp *DevSpec) (*CodeBlob, error) {
	const (
		rWant = 0 // byte[]
		rID   = 1 // String
		rGot  = 2 // byte[]
		rI    = 3 // int
		rT0   = 4
		rT1   = 5
		rCtx  = 7
	)
	didM := MethodSpec{Class: sp.Class, Name: devIDName,
		Proto: ProtoSpec{Ret: descStringType, Params: []string{descContext}}}
	getBytes := MethodSpec{Class: descString, Name: "getBytes", Proto: ProtoSpec{Ret: descByteArray}}
	mdGetInstance := MethodSpec{Class: descMessageDigest, Name: "getInstance",
		Proto: ProtoSpec{Ret: descMessageDigest, Params: []string{descStringType}}}
	mdDigest := MethodSpec{Class: descMessageDigest, Name: "digest",
		Proto: ProtoSpec{Ret: descByteArray, Params: []string{descByteArray}}}
	failM := MethodSpec{Class: sp.Class, Name: sigFailName, Proto: ProtoSpec{Ret: "V"}}

	a := NewAsm()
	// want = { ... }
	a.Const16(rT0, int16(len(sp.Digest)))
	if err := a.NewArray(rWant, rT0, descByteArray); err != nil {
		return nil, err
	}
	for i, b := range sp.Digest {
		a.Const16(rT0, int16(b))
		a.Const16(rT1, int16(i))
		a.APutByte(rT0, rWant, rT1)
	}
	// id = d(ctx); if (id == null) return;（取不到就放行）
	if err := a.InvokeStatic([]int{rCtx}, didM); err != nil {
		return nil, err
	}
	a.MoveResultObject(rID)
	a.IfEqz(rID, "done")
	// got = MessageDigest.getInstance("SHA-256").digest(id.getBytes())
	if err := a.InvokeVirtual([]int{rID}, getBytes); err != nil {
		return nil, err
	}
	a.MoveResultObject(rT0)
	a.ConstString(rT1, digestAlg)
	if err := a.InvokeStatic([]int{rT1}, mdGetInstance); err != nil {
		return nil, err
	}
	a.MoveResultObject(rT1)
	if err := a.InvokeVirtual([]int{rT1, rT0}, mdDigest); err != nil {
		return nil, err
	}
	a.MoveResultObject(rGot)
	// if (got.length != want.length) fail;
	a.ArrayLength(rT0, rGot)
	a.ArrayLength(rT1, rWant)
	if err := a.IfNe(rT0, rT1, "fail"); err != nil {
		return nil, err
	}
	a.Const4(rI, 0)
	a.Label("loop")
	if err := a.IfGe(rI, rT1, "done"); err != nil {
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
	a.Label("fail")
	if err := a.InvokeStatic(nil, failM); err != nil {
		return nil, err
	}
	a.ReturnVoid()

	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	return &CodeBlob{Registers: 8, Ins: 1, Outs: 2, Insns: insns, Patches: patches}, nil
}
