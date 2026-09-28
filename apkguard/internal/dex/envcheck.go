package dex

import "fmt"

// EnvCheckSpec 描述一个「运行环境检测」类。
//
// D2（Root 检测）与 D3（模拟器检测）的判定结构完全相同，只是判据不同，
// 因此共用同一套代码生成：一串「成立即为异常环境」的条件，任一条命中就
// 终止进程。条件的两种形式分别对应「文件存在」与「系统属性含特征子串」。
type EnvCheckSpec struct {
	// Class 是检测类的描述符，形如 "Lcom/apkguard/shell/Rt;"。
	Class string
	// Paths 是「存在即判定异常」的路径（su 二进制、Magisk 目录等）。
	Paths []string
	// Props 是「静态字段值含该子串即判定异常」的判据（Build.FINGERPRINT 等）。
	Props []PropCheck
	// PropNote 用于在报告中说明属性判据的来源，便于排查误报。
	PropNote string
}

// PropCheck 是一条属性判据。
type PropCheck struct {
	// Field 是要读取的静态字段，形如 Build.FINGERPRINT。
	Field FieldSpec
	// Sub 是命中即判定异常的**子串**。
	//
	// 用子串而非相等：各厂商在 Build 字段里塞的格式差异极大，
	// 相等判定会漏掉绝大多数模拟器。
	Sub string
}

// descBuild 是 android.os.Build 的描述符。
const descBuild = "Landroid/os/Build;"

// descCharSequence 是 java.lang.CharSequence 的描述符。
//
// String.contains 的形参就是它——必须按接口书写方法引用，
// 写成 Ljava/lang/String; 会导致 Dalvik 校验器拒绝该调用点。
const descCharSequence = "Ljava/lang/CharSequence;"

// EnvCheckEntry 是环境检测的入口方法名（与签名校验保持一致，便于壳统一调用）。
const EnvCheckEntry = "a"

// EnvCheckAddition 构造环境检测类定义。
//
// 等价 Java：
//
//	public class Rt {
//	    static void a(Context ctx) {
//	        if (new File("/system/bin/su").exists()) { f(); return; }   // 逐条展开
//	        ...
//	        if (c(Build.TAGS, "test-keys")) { f(); return; }
//	    }
//	    static boolean c(String s, String sub) { return s != null && s.contains(sub); }
//	    static void f() { System.exit(1); }
//	}
//
// 条件全部**展开为直线代码**而不是放进数组循环：判据数量固定且很小，
// 展开后无需构造字符串数组、无需循环变量，寄存器分配与分支全部是常量，
// 出错面显著更小。
func EnvCheckAddition(spec *EnvCheckSpec) (Addition, error) {
	if spec.Class == "" {
		return Addition{}, fmt.Errorf("dex: 环境检测类名为空")
	}
	if len(spec.Paths) == 0 && len(spec.Props) == 0 {
		return Addition{}, fmt.Errorf("dex: 环境检测类 %s 没有任何判据", spec.Class)
	}
	entry, err := envCheckCode(spec)
	if err != nil {
		return Addition{}, err
	}
	contains, err := envContainsCode()
	if err != nil {
		return Addition{}, err
	}
	fail, err := sigFailCode(spec.Class)
	if err != nil {
		return Addition{}, err
	}

	protoCtxV := ProtoSpec{Ret: "V", Params: []string{descContext}}
	protoV := ProtoSpec{Ret: "V"}
	protoStrStrZ := ProtoSpec{Ret: "Z", Params: []string{descStringType, descStringType}}

	spec2 := ClassSpec{
		Name:   spec.Class,
		Super:  descObject,
		Access: accPublic,
		Methods: []ClassMethod{
			{Name: EnvCheckEntry, Proto: protoCtxV, Access: accPublic | accStatic, Code: entry},
			{Name: envContainsName, Proto: protoStrStrZ, Access: accPrivate | accStatic, Code: contains},
			{Name: sigFailName, Proto: protoV, Access: accPrivate | accStatic, Code: fail},
		},
	}
	add := Addition{
		Methods: []MethodSpec{
			{Class: spec.Class, Name: EnvCheckEntry, Proto: protoCtxV},
			{Class: spec.Class, Name: envContainsName, Proto: protoStrStrZ},
			{Class: spec.Class, Name: sigFailName, Proto: protoV},
		},
		Classes: []ClassSpec{spec2},
	}
	return add, nil
}

// envContainsName 是空安全的子串判定方法名。
const envContainsName = "c"

// envCheckCode 生成检测方法体。
//
// registers=8、ins=1 → 入参 ctx 落在 v7（本方法不使用它，但保持与其他
// 检测类一致的签名，壳可以统一调用）。
func envCheckCode(spec *EnvCheckSpec) (*CodeBlob, error) {
	const (
		rObj = 0 // File 或 String
		rRes = 1 // 判定结果 / 子串
		rCtx = 7
	)
	fileInit := MethodSpec{Class: descFile, Name: "<init>",
		Proto: ProtoSpec{Ret: "V", Params: []string{descStringType}}}
	fileExists := MethodSpec{Class: descFile, Name: "exists", Proto: ProtoSpec{Ret: "Z"}}
	containsM := MethodSpec{Class: spec.Class, Name: envContainsName,
		Proto: ProtoSpec{Ret: "Z", Params: []string{descStringType, descStringType}}}
	failM := MethodSpec{Class: spec.Class, Name: sigFailName, Proto: ProtoSpec{Ret: "V"}}

	a := NewAsm()
	// 每条判据展开为：求值 → 不成立就跳到下一条 → 成立则终止进程。
	for i, p := range spec.Paths {
		a.NewInstance(rObj, descFile)
		a.ConstString(rRes, p)
		if err := a.InvokeDirect([]int{rObj, rRes}, fileInit); err != nil {
			return nil, err
		}
		if err := a.InvokeVirtual([]int{rObj}, fileExists); err != nil {
			return nil, err
		}
		a.MoveResult(rRes)
		next := fmt.Sprintf("p%d", i)
		a.IfEqz(rRes, next)
		if err := a.InvokeStatic(nil, failM); err != nil {
			return nil, err
		}
		a.ReturnVoid()
		a.Label(next)
	}
	for i, p := range spec.Props {
		a.SGetObject(rObj, p.Field)
		a.ConstString(rRes, p.Sub)
		if err := a.InvokeStatic([]int{rObj, rRes}, containsM); err != nil {
			return nil, err
		}
		a.MoveResult(rRes)
		next := fmt.Sprintf("q%d", i)
		a.IfEqz(rRes, next)
		if err := a.InvokeStatic(nil, failM); err != nil {
			return nil, err
		}
		a.ReturnVoid()
		a.Label(next)
	}
	a.ReturnVoid()

	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	return &CodeBlob{Registers: 8, Ins: 1, Outs: 3, Insns: insns, Patches: patches}, nil
}

// envContainsCode 生成空安全的子串判定。
//
// 等价 Java：
//
//	static boolean c(String s, String sub) {
//	    return s != null && s.contains(sub);
//	}
//
// 必须做空判断：各 ROM 对 Build 字段的处理不一致，取到 null 是常态，
// 直接调用 contains 会抛 NullPointerException，而注入方法体不支持异常表，
// 结果是「检测本身把应用搞崩」。
//
// registers=3、ins=2 → 入参占 v1、v2；v0 为局部。
func envContainsCode() (*CodeBlob, error) {
	const (
		rRes = 0 // 返回值
		rS   = 1 // 入参 s
		rSub = 2 // 入参 sub
	)
	containsM := MethodSpec{Class: descString, Name: "contains",
		Proto: ProtoSpec{Ret: "Z", Params: []string{descCharSequence}}}

	a := NewAsm()
	a.IfEqz(rS, "false")
	if err := a.InvokeVirtual([]int{rS, rSub}, containsM); err != nil {
		return nil, err
	}
	a.MoveResult(rRes)
	a.Return(rRes)
	a.Label("false")
	a.Const4(rRes, 0)
	a.Return(rRes)

	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	return &CodeBlob{Registers: 3, Ins: 2, Outs: 2, Insns: insns, Patches: patches}, nil
}
