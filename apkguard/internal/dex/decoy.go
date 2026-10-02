package dex

import (
	"fmt"
	"sort"
)

// DecoySpec 描述 A8（诱饵类注入）要生成的一批类。
//
// 与 A13（类膨胀）的分工：A13 追求**数量**，用超长类名、默认包类把类池撑大；
// A8 追求**误导性**，注入少量命名听上去像安全组件、实则空实现的类。
// 逆向者翻到 `SecurityMonitor` / `IntegrityChecker` 时，会先花时间去读它们，
// 从而偏离真正的防护代码。
//
// 空实现是有意为之：这些类不参与任何逻辑，只是为了占据名称与体量。
// 但它们必须**结构合法**（能被 dex.Verify 通过、能被正常类加载），
// 否则在设备上会以 NoClassDefFoundError 之类的问题暴露出来。
type DecoySpec struct {
	// Prefix 是包名前缀（形如 "com/apkguard/shell"），由 Pass 层统一分配。
	Prefix string
	// Names 是类名（不含包），如 "SecurityMonitor"。
	Names []string
	// Seed 影响方法体里填充的常量，使产物可复现。
	Seed string
	// Components 指定哪些类要按 Manifest 组件的形态生成（继承对应的框架基类、
	// 实现必须实现的抽象方法）。不在表里的类按普通类生成。
	Components []DecoyComponent
}

// DecoyComponentKind 是诱饵组件在 Manifest 里的声明形态。
type DecoyComponentKind string

const (
	// DecoyReceiver 按 <receiver> 生成：父类 android.content.BroadcastReceiver，
	// 并实现其抽象方法 onReceive。
	DecoyReceiver DecoyComponentKind = "receiver"
	// DecoyService 按 <service> 生成：父类 android.app.Service，
	// 并实现其抽象方法 onBind。
	DecoyService DecoyComponentKind = "service"
)

// DecoyComponent 是把某个诱饵类声明成 Manifest 组件的描述。
type DecoyComponent struct {
	Name string
	Kind DecoyComponentKind
}

// DecoyClassNames 是默认的诱饵类名。
//
// 选名的标准：听起来像防护机制、在真实项目中常见（因此不突兀）、
// 且不指向任何具体厂商（避免误导成他人的商标）。
var DecoyClassNames = []string{
	"SecurityMonitor", "IntegrityChecker", "ThreatDetector",
	"RootGuard", "EnvironmentProbe", "LicenseValidator",
	"NativeBridge", "CryptoProvider", "SignatureVerifier",
	"DebugWatcher", "MemoryShield", "ProcessInspector",
	"AntiTamper", "PolicyEngine", "AuditTrail",
	"TrustAnchor", "KeyCustodian", "SealVerifier",
}

// DecoyManifestComponents 是默认声明进 Manifest 的诱饵组件。
//
// **只选 receiver 与 service，绝不选 provider**：ContentProvider 会在应用启动时
// 由 ActivityThread 主动实例化（installContentProviders），诱饵是空实现，
// 被拉起就可能影响启动；而 receiver 与 service 在**没有 intent-filter** 时
// 系统永远不会实例化它们——声明只对静态分析可见，这正是诱饵想要的效果。
//
// 因此这里的每个类都必须能在「被实例化」的假设下也站得住脚：
// 继承正确的框架基类并实现其抽象方法（见 componentBase）。
var DecoyManifestComponents = []DecoyComponent{
	{Name: "SecurityMonitor", Kind: DecoyReceiver},
	{Name: "IntegrityChecker", Kind: DecoyReceiver},
	{Name: "RootGuard", Kind: DecoyReceiver},
	{Name: "ThreatDetector", Kind: DecoyService},
	{Name: "LicenseValidator", Kind: DecoyService},
	{Name: "AntiTamper", Kind: DecoyService},
}

// componentBase 返回某类组件对应的「父类 + 必须实现的抽象方法」。
//
// 若只继承 Object 就声明成 <receiver>，多用工具链会认为它是坏声明；
// 万一被系统实例化，还会得到 ClassCastException。因此按真实组件的骨架生成。
func componentBase(kind DecoyComponentKind) (super string, abstract *ClassMethod, err error) {
	switch kind {
	case DecoyReceiver:
		// BroadcastReceiver.onReceive(Context, Intent) 是抽象方法。
		body, berr := decoyEmptyVoidCode(3, 3)
		if berr != nil {
			return "", nil, berr
		}
		return "Landroid/content/BroadcastReceiver;", &ClassMethod{
			Name: "onReceive",
			Proto: ProtoSpec{
				Ret:    "V",
				Params: []string{"Landroid/content/Context;", "Landroid/content/Intent;"},
			},
			Access: accPublic,
			Code:   body,
		}, nil
	case DecoyService:
		// Service.onBind(Intent) 是抽象方法，返回可空的 IBinder。
		body, berr := decoyNullObjectCode(2, 2)
		if berr != nil {
			return "", nil, berr
		}
		return "Landroid/app/Service;", &ClassMethod{
			Name: "onBind",
			Proto: ProtoSpec{
				Ret:    "Landroid/os/IBinder;",
				Params: []string{"Landroid/content/Intent;"},
			},
			Access: accPublic,
			Code:   body,
		}, nil
	default:
		return "", nil, fmt.Errorf("dex: 未知的诱饵组件形态 %q", kind)
	}
}

// DecoyAddition 构造诱饵类集合。
//
// 等价 Java：
//
//	package <prefix>;
//	public class SecurityMonitor {
//	    private int state;
//	    public SecurityMonitor() {}
//	    public int check(int a) { return a ^ 0x5a; }
//	    public static String name() { return "SecurityMonitor"; }
//	}
//
// 每个类都带一个实例字段与两个带真实运算的方法，而不是纯粹的空壳：
// 方法体为空的类在反编译视图中一眼就是填充物，反而提示「这里是加固产物」。
//
// 被列入 spec.Components 的类改成对应组件的骨架（继承框架基类 + 实现抽象方法），
// 这样即使系统真的实例化它们也不会出错。
func DecoyAddition(spec *DecoySpec) (Addition, error) {
	if spec.Prefix == "" {
		return Addition{}, fmt.Errorf("dex: 诱饵类的包名前缀为空")
	}
	if len(spec.Names) == 0 {
		return Addition{}, fmt.Errorf("dex: 诱饵类列表为空")
	}
	kinds := map[string]DecoyComponentKind{}
	for _, c := range spec.Components {
		kinds[c.Name] = c.Kind
	}

	protoV := ProtoSpec{Ret: "V"}
	protoII := ProtoSpec{Ret: "I", Params: []string{"I"}}
	protoStr := ProtoSpec{Ret: "Ljava/lang/String;"}

	var classes []ClassSpec
	var methods []MethodSpec

	for i, name := range spec.Names {
		cls := "L" + spec.Prefix + "/" + name + ";"
		// 每个类用不同的常量，避免方法体完全同构。
		mix := int8(0x11 + (i*7)%0x60)

		super := descObject
		var extra []ClassMethod
		if kind, ok := kinds[name]; ok {
			s, abs, err := componentBase(kind)
			if err != nil {
				return Addition{}, err
			}
			super = s
			extra = append(extra, *abs)
		}

		ctor, err := decoyCtorCode(super)
		if err != nil {
			return Addition{}, err
		}
		check, err := decoyCheckCode(mix)
		if err != nil {
			return Addition{}, err
		}
		nameM, err := decoyNameCode(name)
		if err != nil {
			return Addition{}, err
		}

		ms := []ClassMethod{
			{Name: "<init>", Proto: protoV, Access: accPublic, Code: ctor},
			{Name: "check", Proto: protoII, Access: accPublic, Code: check},
			{Name: "name", Proto: protoStr, Access: accPublic | accStatic, Code: nameM},
		}
		ms = append(ms, extra...)

		classes = append(classes, ClassSpec{
			Name:    cls,
			Super:   super,
			Access:  accPublic,
			Fields:  []ClassField{{Name: "state", Type: "I", Access: accPrivate}},
			Methods: ms,
		})
		methods = append(methods,
			MethodSpec{Class: cls, Name: "<init>", Proto: protoV},
			MethodSpec{Class: cls, Name: "check", Proto: protoII},
			MethodSpec{Class: cls, Name: "name", Proto: protoStr},
		)
		for _, m := range extra {
			methods = append(methods, MethodSpec{Class: cls, Name: m.Name, Proto: m.Proto})
		}
	}
	sort.Slice(classes, func(i, j int) bool { return classes[i].Name < classes[j].Name })

	return Addition{Methods: methods, Classes: classes}, nil
}

// decoyCtorCode 生成 <init>()V：只调用给定父类的构造器。
//
// registers=2、ins=1 → this 在 v1。
func decoyCtorCode(super string) (*CodeBlob, error) {
	superInit := MethodSpec{Class: super, Name: "<init>", Proto: ProtoSpec{Ret: "V"}}

	a := NewAsm()
	if err := a.InvokeDirect([]int{1}, superInit); err != nil {
		return nil, err
	}
	a.ReturnVoid()

	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	return &CodeBlob{Registers: 2, Ins: 1, Outs: 1, Insns: insns, Patches: patches}, nil
}

// decoyEmptyVoidCode 生成一个空的 void 方法体（registers/ins 由调用方给出）。
func decoyEmptyVoidCode(registers, ins uint16) (*CodeBlob, error) {
	a := NewAsm()
	a.ReturnVoid()
	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	return &CodeBlob{Registers: registers, Ins: ins, Outs: 0, Insns: insns, Patches: patches}, nil
}

// decoyNullObjectCode 生成「返回 null」的对象方法体。
func decoyNullObjectCode(registers, ins uint16) (*CodeBlob, error) {
	a := NewAsm()
	a.Const16(0, 0)
	a.ReturnObject(0)
	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	return &CodeBlob{Registers: registers, Ins: ins, Outs: 0, Insns: insns, Patches: patches}, nil
}

// decoyCheckCode 生成 check(I)I：做一个真实的位运算并写回字段。
//
// 语义无意义但**正确**：输入不同则输出不同，看起来像某种校验。
//
// registers=3、ins=2 → this 在 v1、入参 a 在 v2。
func decoyCheckCode(mix int8) (*CodeBlob, error) {
	a := NewAsm()
	// v0 = a ^ mix
	a.Const16(0, int16(mix))
	a.XorInt(2, 2, 0)
	// return v2
	a.Return(2)

	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	return &CodeBlob{Registers: 3, Ins: 2, Outs: 1, Insns: insns, Patches: patches}, nil
}

// decoyNameCode 生成 name()Ljava/lang/String;：返回类名。
func decoyNameCode(name string) (*CodeBlob, error) {
	a := NewAsm()
	a.ConstString(0, name)
	a.ReturnObject(0)

	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	return &CodeBlob{Registers: 1, Ins: 0, Outs: 2, Insns: insns, Patches: patches}, nil
}
