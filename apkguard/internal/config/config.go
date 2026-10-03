// Package config 定义 APK 加固工具的全部功能项与运行参数。
//
// 设计原则：功能项以「可勾选的独立开关」形式暴露，不预设哪些该开哪些该关；
// 仅对可能破坏兼容性或引入风险的功能标记为「危险区」并默认关闭，
// 使用者可在 Web UI 中显式启用（会二次确认）。
package config

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// FeatureID 是功能项的唯一标识，形如 "A1"、"B3"。
type FeatureID string

// Stage 表示功能项所属的实施阶段。
type Stage int

// 各实施阶段。
const (
	StageSign Stage = 1 // 签名 / 对齐 / 元数据
	StageL1   Stage = 2 // L1 混淆
	StageL2   Stage = 3 // L2 一代壳
	StageL3   Stage = 4 // L3 native 防护
	StageL4   Stage = 5 // L4 增强
	StageLong Stage = 6 // 长期（VMP / Dex2C）
)

// String 返回阶段的中文名。
func (s Stage) String() string {
	switch s {
	case StageSign:
		return "阶段1 签名/对齐基座"
	case StageL1:
		return "阶段2 L1 混淆"
	case StageL2:
		return "阶段3 L2 一代壳"
	case StageL3:
		return "阶段4 L3 native 防护"
	case StageL4:
		return "阶段5 L4 增强"
	case StageLong:
		return "长期（VMP/Dex2C）"
	}
	return "未知阶段"
}

// Risk 表示功能项的风险等级。
type Risk int

// 风险等级。
const (
	// RiskSafe 表示该功能对兼容性影响可控。
	RiskSafe Risk = iota
	// RiskDangerous 表示该功能可能破坏兼容性、显著增大体积或引入安全争议，
	// 归入「危险区」并默认关闭，启用时需二次确认。
	RiskDangerous
)

// String 返回风险等级的中文名。
func (r Risk) String() string {
	if r == RiskDangerous {
		return "危险区"
	}
	return "常规"
}

// Feature 描述一个功能项。
type Feature struct {
	ID      FeatureID `json:"id"`
	Name    string    `json:"name"`
	Group   string    `json:"group"`
	Stage   Stage     `json:"-"`
	StageCN string    `json:"stage"`
	Risk    Risk      `json:"-"`
	RiskCN  string    `json:"risk"`
	Default bool      `json:"default"`
	Desc    string    `json:"desc"`
	Note    string    `json:"note"`
	// Implemented 表示该功能项**已有实际实现**。
	//
	// 设计文档共罗列 46 项能力，但并非全部落地。这个字段的作用是让
	// 「启用了一个还没实现的功能项」变成显式错误，而不是静默地什么都不做——
	// 后者会让使用方以为自己拿到了 Root 检测、反调试等防护，实际却完全没有。
	Implemented bool `json:"implemented"`
}

// implementedIDs 是已落地实现的功能项集合。
//
// 必须与 passes.Registry() 注册的 Pass 一一对应；passes 包中有一条测试
// （TestImplementedMatchesRegistry）会在两边不一致时失败，防止这里变成
// 一份会过期的声明。
var implementedIDs = map[FeatureID]bool{
	// 阶段2 L1 混淆
	"A1": true, "A2": true, "A3": true, "A4": true, "A5": true, "A8": true, "A11": true,
	"A9": true, "A10": true, "A12": true, "A13": true, "A15": true, "A6": true,
	"A16": true, "A17": true, "A18": true, "A19": true, "A20": true,
	// 阶段1 签名 / 对齐 / 元数据
	"A14": true, "E1": true, "E2": true, "E3": true, "E4": true, "E5": true, "E6": true,
	// 阶段3 L2 一代壳
	"B1": true, "B2": true, "B3": true, "B4": true, "B8": true,
	// 阶段2/3 运行时防护
	"D1": true, "D2": true, "D3": true,
	// 阶段4 L3 native 防护（已落地的部分）
	"C1": true, "C2": true, "C4": true, "C5": true, "C6": true, "C7": true,
	"D4": true, "D5": true,
}

// Implemented 判断某功能项是否已实现；未知 ID 返回 false。
func Implemented(id FeatureID) bool { return implementedIDs[id] }

// ImplementedIDs 返回已实现的功能项 ID（按字典序）。
func ImplementedIDs() []FeatureID {
	out := make([]FeatureID, 0, len(implementedIDs))
	for id := range implementedIDs {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// 功能分组名。
const (
	GroupObf      = "混淆"
	GroupPack     = "加壳"
	GroupNative   = "Native 防护"
	GroupRuntime  = "运行时防护"
	GroupDelivery = "工程交付"
)

// All 返回全部功能项定义，顺序与设计文档一致。
func All() []Feature {
	fs := []Feature{
		// ---- 混淆类 ----
		{ID: "A1", Name: "名字混淆", Group: GroupObf, Stage: StageL1, Risk: RiskSafe, Default: true,
			Desc: "将类/方法/字段重命名为无意义短名，保留反射、序列化、JNI、四大组件白名单",
			Note: "反编译后名称不可读，减小 DEX 体积 5~15%"},
		{ID: "A2", Name: "字符串加密", Group: GroupObf, Stage: StageL1, Risk: RiskSafe, Default: true,
			Desc: "将 const-string 常量加密为密文，运行时解密还原；密钥分片存储",
			Note: "strings/grep 静态提串失效"},
		{ID: "A3", Name: "常量数组化", Group: GroupObf, Stage: StageL1, Risk: RiskSafe, Default: true,
			Desc: "将字符串拆成字节数组，通过 fill-array-data 存入方法体，运行时重组",
			Note: "绕过仅解析字符串池的扫描器；成本低收益明确"},
		{ID: "A4", Name: "调试信息清除", Group: GroupObf, Stage: StageL1, Risk: RiskSafe, Default: true,
			Desc: "清除 SourceFile、LineNumberTable、局部变量表",
			Note: "零副作用，体积减小 3~8%；SourceDebugExtension 以注解形式存在，暂未清除（见 README 已知局限）"},
		{ID: "A5", Name: "资源混淆", Group: GroupObf, Stage: StageL2, Risk: RiskSafe, Default: false,
			Desc: "重命名 res/ 目录与文件名，resources.arsc 路径同步改写",
			Note: "可能破坏依赖资源名的第三方 SDK 与热修复框架"},
		{ID: "A6", Name: "控制流混淆", Group: GroupObf, Stage: StageL4, Risk: RiskSafe, Default: false,
			Desc: "基本块平坦化、虚假分支（不透明谓词）、指令替换",
			Note: "仅做可证明安全的两类改写：恒真不透明谓词与不可达前向跳转块；不做基本块平坦化。改寄存器此前会触发 ART 宽值类型冲突，已修为「只选未被任何指令引用的寄存器」并计入宽值相邻格，三个真实应用实测正常"},
		{ID: "A7", Name: "反射化调用", Group: GroupObf, Stage: StageL4, Risk: RiskSafe, Default: false,
			Desc: "将敏感 API 调用改为 Class.forName + getMethod + invoke",
			Note: "性能下降明显，且是逆向者的强信号"},
		{ID: "A8", Name: "诱饵类注入", Group: GroupObf, Stage: StageL4, Risk: RiskDangerous, Default: false,
			Desc: "注入若干命名具误导性的空实现类（如 SecurityMonitor、IntegrityChecker）",
			Note: "增加体积，且可能被识别为刻意混淆"},
		{ID: "A9", Name: "伪 DEX magic 填充块", Group: GroupObf, Stage: StageL1, Risk: RiskDangerous, Default: false,
			Desc: "注入仅伪造 dex magic 的随机数据块，命名与真实 DEX 相似",
			Note: "可能使部分分析工具崩溃；随机数据不可压缩，每块约 80KB"},
		{ID: "A10", Name: "垃圾条目注入", Group: GroupObf, Stage: StageL1, Risk: RiskDangerous, Default: false,
			Desc: "注入非 ASCII 顶层文件、随机名深目录、畸形 META-INF 路径",
			Note: "可能触发 Windows MAX_PATH 与解包工具异常"},
		{ID: "A11", Name: "资源路径全量扁平化", Group: GroupObf, Stage: StageL2, Risk: RiskSafe, Default: false,
			Desc: "将 res/ 下所有语义目录替换为单字母目录名，同步改写 resources.arsc 与 DEX 引用",
			Note: "A5 的完整形态；实证样本已做到零语义残留"},
		{ID: "A12", Name: "ZIP 路径攻击", Group: GroupObf, Stage: StageL1, Risk: RiskDangerous, Default: false,
			Desc: "注入路径前缀滥用条目、绝对路径条目、重复条目名",
			Note: "可能触发解压路径越界（Zip Slip 变体）与工具解析差异"},
		{ID: "A13", Name: "类膨胀与类名策略", Group: GroupObf, Stage: StageL1, Risk: RiskDangerous, Default: false,
			Desc: "生成默认包类、超长类名路径（30+ 层）、类数量膨胀",
			Note: "显著增大体积；注入空类会被识破，需生成真实类"},
		{ID: "A14", Name: "时间戳与元数据统一化", Group: GroupObf, Stage: StageSign, Risk: RiskSafe, Default: true,
			Desc: "统一 ZIP 条目的时间戳与 create_system，并清除条目注释与时间类扩展字段",
			Note: "零体积成本；消除「被重新打包」的取证痕迹。刻意不改 flag_bits——UTF-8 名称位（bit 11）必须保留，否则非 ASCII 条目名会被读方按 CP437 解码"},

		{ID: "A15", Name: "巨型 Manifest 填充", Group: GroupObf, Stage: StageL1, Risk: RiskDangerous, Default: false,
			Desc: "把 AndroidManifest.xml 膨胀到数百 MB（零填充 + 巨型假 chunk，真实内容置于末尾）",
			Note: "解压/解析成本剧增；可能被应用商店或加固检测按体积拒绝，默认关闭"},

		// ---- 加壳类 ----
		{ID: "A16", Name: "诱饵核心文件", Group: GroupObf, Stage: StageL1, Risk: RiskDangerous, Default: false,
			Desc: "注入大小写/同形变体的假 AndroidManifest.xml、假 resources.arsc、假 classes.dex，内容都是可解析的合法结构",
			Note: "参考样本的 ANDROIDMANIFEST.XML 手法；自动化工具会抓到假核心文件"},
		{ID: "A17", Name: "嵌套 APK 诱饵", Group: GroupObf, Stage: StageL1, Risk: RiskDangerous, Default: false,
			Desc: "在 assets 下放一个结构完整、可被 apktool/jadx 打开的假 APK（自带假 Manifest/arsc/dex），与真载荷同构",
			Note: "对样本「内层真 APK」的反向利用：自动化脱壳脚本会满载而归地拿到假应用"},
		{ID: "A18", Name: "Manifest 诱饵元数据", Group: GroupObf, Stage: StageL1, Risk: RiskSafe, Default: false,
			Desc: "向 Manifest 注入假 uses-permission / meta-data / uses-feature（只用系统未定义的自定义权限名，零运行影响）",
			Note: "与 A8 的假组件互补：让权限视图与组件表都充满噪音"},
		{ID: "A19", Name: "字符串池垃圾注入", Group: GroupObf, Stage: StageL2, Risk: RiskSafe, Default: false,
			Desc: "往每个 DEX 的字符串池注入大量未被引用的字符串（形似业务常量/URL/密钥片段），推高 strings 输出噪音",
			Note: "会增大 DEX 体积；池接近 16 位上限的 DEX 会自动跳过"},
		{ID: "A20", Name: "无害花指令填充", Group: GroupObf, Stage: StageL4, Risk: RiskSafe, Default: false,
			Desc: "向方法体插入 nop 填充与不可达前向跳转——不写任何寄存器，因此无类型冲突风险",
			Note: "只增加反编译噪音、不改变控制流图，属低强度手法但覆盖面大"},
		{ID: "B1", Name: "DEX 整体加密", Group: GroupPack, Stage: StageL2, Risk: RiskSafe, Default: false,
			Desc: "将原始 DEX 加密后存入 assets/，壳 DEX 运行时解密并加载",
			Note: "所有加固的第一道防线；必须与 B2/B3 同时启用"},
		{ID: "B2", Name: "Application 替换", Group: GroupPack, Stage: StageL2, Risk: RiskSafe, Default: false,
			Desc: "修改 Manifest 的 android:name 指向壳 Application，接管 attachBaseContext 与 onCreate",
			Note: "B1/B3 的前提；所有加壳方案的必需组件"},
		{ID: "B3", Name: "ClassLoader 接管", Group: GroupPack, Stage: StageL2, Risk: RiskDangerous, Default: false,
			Desc: "用 InMemoryDexClassLoader / DexClassLoader 加载解密后的 DEX，反射替换系统 ClassLoader",
			Note: "技术难点最高，需适配 Android 5~15 各版本 ART 差异"},
		{ID: "B4", Name: "多 DEX 拆分", Group: GroupPack, Stage: StageL2, Risk: RiskSafe, Default: false,
			Desc: "按功能维度将业务 DEX 拆分为多个分别加密",
			Note: "单点 dump 无法获得完整代码"},
		{ID: "B5", Name: "函数抽取", Group: GroupPack, Stage: StageL3, Risk: RiskDangerous, Default: false,
			Desc: "清空方法 CodeItem，运行时由 native 按需回填到内存",
			Note: "需 hook ArtMethod，Android 每个大版本结构都变"},
		{ID: "B6", Name: "VMP 虚拟化", Group: GroupPack, Stage: StageLong, Risk: RiskDangerous, Default: false,
			Desc: "将关键方法字节码翻译为自定义指令集，由私有 VM 解释器执行",
			Note: "防护强度最高，工程复杂度极高"},
		{ID: "B7", Name: "Dex2C / Java2C", Group: GroupPack, Stage: StageLong, Risk: RiskDangerous, Default: false,
			Desc: "将 Java 方法编译期翻译为 C，编译成 SO 通过 JNI 注册调用",
			Note: "需处理多 ABI、JNI 桥接、GC 交互，工程复杂度极高"},

		{ID: "B8", Name: "载荷容器化", Group: GroupPack, Stage: StageL2, Risk: RiskSafe, Default: false,
			Desc: "把加密载荷移入容器目录树，并植入同构的诱饵容器（高熵 .dat + 假包名配置）",
			Note: "对抗「按 assets 顶层逐个解密」的自动化脚本；需先启用 B1"},

		// ---- Native 防护类 ----
		{ID: "C1", Name: "密钥 native 派生", Group: GroupNative, Stage: StageL3, Risk: RiskSafe, Default: false,
			Desc: "密钥由 native 结合设备指纹、APK 签名、编译期随机种子派生，不以明文存在于 Java 层",
			Note: "修复样本密钥硬编码的致命缺陷"},
		{ID: "C2", Name: "SO 加壳", Group: GroupNative, Stage: StageL3, Risk: RiskSafe, Default: false,
			Desc: "原生库整体加密存入 assets，壳启动时解密到应用私有目录，并把该目录并入类加载器的库搜索路径",
			Note: "检测到 native 自加载框架（Flutter/RN/Unity）会整体跳过并给出提示——这类框架用 android_dlopen_ext 从 APK 按偏移加载，移走 lib/ 会让应用启动即崩；C2 开启时 lib/ 下不再有明文 .so"},
		{ID: "C3", Name: "OLLVM 混淆", Group: GroupNative, Stage: StageL3, Risk: RiskSafe, Default: false,
			Desc: "对 native 代码应用控制流平坦化、虚假控制流、指令替换",
			Note: "需外部 OLLVM 工具链"},
		{ID: "C4", Name: "反调试", Group: GroupNative, Stage: StageL3, Risk: RiskSafe, Default: false,
			Desc: "ptrace 自占用、读 TracerPid、检测 SIGTRAP 与调试端口",
			Note: "gdb/IDA/lldb 无法 attach"},
		{ID: "C5", Name: "反注入（反 Hook）", Group: GroupNative, Stage: StageL3, Risk: RiskSafe, Default: false,
			Desc: "扫描 /proc/self/maps 查找 frida/xposed/substrate，探测 Frida 默认端口与内存特征",
			Note: "对抗脱壳工具与运行时篡改"},
		{ID: "C6", Name: "完整性自校验", Group: GroupNative, Stage: StageL3, Risk: RiskSafe, Default: false,
			Desc: "SO 自身 CRC 校验、JNI_OnLoad 内校验 APK 签名、关键代码段运行时校验",
			Note: "篡改 SO 或重打包后无法运行"},

		// ---- 运行时防护类 ----
		{ID: "C7", Name: "原生库伪装", Group: GroupNative, Stage: StageL3, Risk: RiskSafe, Default: false,
			Desc: "把守卫库改名为常见库名（如 libsqlite3x.so），并同步改写壳侧的 loadLibrary 参数",
			Note: "库名不再暴露加固器身份；不支持清除 ELF 节头——实测 Android 链接器会校验节头表，改动会导致 dlopen 失败"},
		{ID: "D1", Name: "签名校验", Group: GroupRuntime, Stage: StageL2, Risk: RiskSafe, Default: false,
			Desc: "运行时读取 PackageInfo.signatures 与内置签名指纹（SHA-256）比对",
			Note: "实现成本极低，防二次打包基础防护"},
		{ID: "D2", Name: "Root 检测", Group: GroupRuntime, Stage: StageL2, Risk: RiskSafe, Default: false,
			Desc: "检测 su 二进制、magisk/Superuser 路径、ro.debuggable、ro.secure、危险挂载",
			Note: "Root 环境拒绝运行或降级"},
		{ID: "D3", Name: "模拟器检测", Group: GroupRuntime, Stage: StageL2, Risk: RiskSafe, Default: false,
			Desc: "检测 ro.build 特征、传感器数量、IMEI/IMSI 异常、CPU 架构、文件系统特征",
			Note: "阻断自动化批量分析"},
		{ID: "D4", Name: "内存完整性校验", Group: GroupRuntime, Stage: StageL4, Risk: RiskSafe, Default: false,
			Desc: "运行时定期校验关键方法字节码是否被篡改",
			Note: "对抗 Frida 运行时修改逻辑"},
		{ID: "D5", Name: "设备绑定", Group: GroupRuntime, Stage: StageL4, Risk: RiskSafe, Default: false,
			Desc: "用设备指纹派生密钥，绑定特定设备",
			Note: "加固后的 APK 只能在授权设备运行"},

		// ---- 工程交付类 ----
		{ID: "E1", Name: "APK 签名（jks/pfx）", Group: GroupDelivery, Stage: StageSign, Risk: RiskSafe, Default: true,
			Desc: "支持 JKS/PKCS12 密钥库，签名方案 v1+v2+v3（可选 v4）",
			Note: "加固必然破坏原签名，必须重新签名"},
		{ID: "E2", Name: "zipalign 对齐", Group: GroupDelivery, Stage: StageSign, Risk: RiskSafe, Default: true,
			Desc: "未压缩资源按 4 字节对齐，.so 按 4096 字节对齐",
			Note: "必须在签名前执行"},
		{ID: "E3", Name: "加固后自检", Group: GroupDelivery, Stage: StageL2, Risk: RiskSafe, Default: true,
			Desc: "模拟加载流程验证 DEX 能否解析、Manifest 是否合法、壳入口是否正确、签名是否有效",
			Note: "降低线上崩溃率"},
		{ID: "E4", Name: "多渠道打包", Group: GroupDelivery, Stage: StageL4, Risk: RiskSafe, Default: false,
			Desc: "将渠道信息写入 APK（v2 签名块 ID-value 区或 META-INF）",
			Note: "一次加固批量产出多渠道包"},
		{ID: "E5", Name: "批量处理", Group: GroupDelivery, Stage: StageL4, Risk: RiskSafe, Default: false,
			Desc: "支持目录级批量加固，多线程并发",
			Note: "企业级 CI 流水线集成"},
		{ID: "E6", Name: "兼容性自检", Group: GroupDelivery, Stage: StageL2, Risk: RiskSafe, Default: true,
			Desc: "对产物做静态兼容性检查：DEX 版本与 minSdk 是否匹配、原生库 ABI 覆盖是否一致、关键条目是否完整",
			Note: "只覆盖静态可判定的问题；真机/模拟器矩阵回归仍需人工执行"},
	}
	for i := range fs {
		fs[i].StageCN = fs[i].Stage.String()
		fs[i].RiskCN = fs[i].Risk.String()
		fs[i].Implemented = implementedIDs[fs[i].ID]
	}
	return fs
}

// ByID 返回功能项索引表。
func ByID() map[FeatureID]Feature {
	m := make(map[FeatureID]Feature)
	for _, f := range All() {
		m[f.ID] = f
	}
	return m
}

// Group 是一组功能项。
type Group struct {
	Name     string    `json:"name"`
	Features []Feature `json:"features"`
}

// Groups 返回按分组聚合的功能项，分组顺序固定。
func Groups() []Group {
	order := []string{GroupObf, GroupPack, GroupNative, GroupRuntime, GroupDelivery}
	byGroup := map[string][]Feature{}
	for _, f := range All() {
		byGroup[f.Group] = append(byGroup[f.Group], f)
	}
	out := make([]Group, 0, len(order))
	for _, g := range order {
		out = append(out, Group{Name: g, Features: byGroup[g]})
	}
	return out
}

// Options 是一次加固任务的完整参数。
type Options struct {
	// Enabled 记录每个功能项的启用状态。未出现的 ID 视为使用默认值。
	Enabled map[FeatureID]bool `json:"enabled"`

	// 输入输出
	In  string `json:"in"`
	Out string `json:"out"`

	// 签名参数
	KS      string `json:"ks"`
	KSPass  string `json:"ks_pass"`
	KeyPass string `json:"key_pass"`
	KSType  string `json:"ks_type"`
	Alias   string `json:"alias"`
	NoV1    bool   `json:"no_v1"`
	NoV2    bool   `json:"no_v2"`
	NoV3    bool   `json:"no_v3"`
	V4      bool   `json:"v4"`
	MinSDK  uint   `json:"min_sdk"`
	MaxSDK  uint   `json:"max_sdk"`

	// 混淆参数
	NamePrefix    string `json:"name_prefix"`     // A1 混淆后名称前缀
	PackageShrink bool   `json:"package_shrink"`  // A1 每个原包整体压成无意义短包名（隐藏包结构）
	KeepRules     string `json:"keep_rules"`      // A1 保留白名单（每行一条，支持通配）
	ObfStringMin  int    `json:"obf_string_min"`  // A2 仅加密长度 >= 该值的字符串
	Seed          string `json:"seed"`            // 随机种子（留空则随机）
	FakeDexCount  int    `json:"fake_dex_count"`  // A9 伪 DEX 块数量
	FakeDexSize   int    `json:"fake_dex_size"`   // A9 每块字节数
	JunkTopCount  int    `json:"junk_top_count"`  // A10 非 ASCII 顶层文件数
	JunkDirCount  int    `json:"junk_dir_count"`  // A10 随机深目录条目数
	JunkDirDepth  int    `json:"junk_dir_depth"`  // A10 深目录最大层数
	JunkMetaCount int    `json:"junk_meta_count"` // A10 畸形 META-INF 条目数
	ZipAtkCount   int    `json:"zip_atk_count"`   // A12 每类路径攻击条目数
	ClassPadCount int    `json:"class_pad_count"` // A13 膨胀类数量
	StampTime     string `json:"stamp_time"`      // A14 统一时间戳（RFC3339，留空用固定值）
	ManifestPadMB int    `json:"manifest_pad_mb"` // A15 巨型 Manifest 填充量（MB，0=默认 100）

	// ---- 欺骗类手法（A16~A20 / C7）的参数 ----

	// DecoyCoreCount 是 A16 注入的「假核心文件」组数（每组含假 Manifest/arsc/dex）。
	DecoyCoreCount int `json:"decoy_core_count"`
	// DecoyAPKMB 是 A17 假内层 APK 的目标体积（MB）。0 表示用默认值。
	DecoyAPKMB int `json:"decoy_apk_mb"`
	// DecoyMetaCount 是 A18 注入的假 uses-permission / meta-data / uses-feature 条数。
	DecoyMetaCount int `json:"decoy_meta_count"`
	// StrJunkCount 是 A19 往每个 DEX 字符串池注入的垃圾字符串条数。
	StrJunkCount int `json:"str_junk_count"`
	// JunkInsnCount 是 A20 每个方法插入的花指令组数。
	JunkInsnCount int `json:"junk_insn_count"`
	// LibFakeName 是 C7 把守卫库改成的新名字（形如 "libsqlite3x.so"；留空用默认）。
	LibFakeName string `json:"lib_fake_name"`
	// LibStripSections 是**已废弃**的选项：曾用于清除 ELF 节头，但实测证明
	// Android 的动态链接器会校验节头表（清零 e_shentsize/e_shstrndx 会让 dlopen
	// 直接失败），且 C6 的完整性校验依赖节名定位 .text/.rodata。
	// 保留字段只为让显式请求能被**拒绝并给出原因**，而不是静默忽略。
	LibStripSections bool `json:"lib_strip_sections"`

	// 加壳参数
	DexKey   string `json:"dex_key"`   // B1 加密密钥（留空自动生成）
	DecoyPkg string `json:"decoy_pkg"` // B8 诱饵配置里的假包名（留空用默认）
	// PayloadMAC 让 B1 在密文后附加 HMAC-SHA256，壳在解密前先校验。
	//
	// 默认关闭：完整性目前由 APK 签名（E1）与运行时签名校验（D1）保证，
	// 载荷自带 MAC 属于纵深防御——即使攻击者绕过 D1，也无法在不知道
	// 密钥的情况下改出「能通过校验」的载荷。代价是壳侧多一次 HMAC 与一小段字节码。
	PayloadMAC bool `json:"payload_mac"`
	// SOEncrypt 把 APK 里的原生库整体加密存进 assets，壳在启动时解密到应用
	// 私有目录，并把该目录作为 ClassLoader 的库搜索路径。
	//
	// 默认关闭：它改变了应用加载 .so 的来源，对「用 nativeLibraryDir 拼绝对
	// 路径自行 System.load」的应用不兼容，必须逐个应用验证。
	SOEncrypt    bool   `json:"so_encrypt"`
	ShellPkg     string `json:"shell_pkg"`     // B2/B3 壳类所在包名
	SplitCount   int    `json:"split_count"`   // B4 拆分 DEX 个数（0=按原样）
	ExtractRatio int    `json:"extract_ratio"` // B5 抽取方法比例（1~100）

	// DebugShell 让壳在启动的每个关键步骤后弹 Toast 报告进度（排障用）。
	//
	// 存在的理由：注入的字节码没有异常表，无法 try/catch 出错误，一旦某步
	// 抛异常应用直接闪退；在无法连 adb 的真机上连 logcat 都读不到，
	// 现象只剩「一打开就崩」。开启后「哪一步的 Toast 没弹出来」直接指出
	// 故障位置，并且会回读 mClassLoader 校验 ClassLoader 接管是否真的生效
	// （Android 9+ 的隐藏 API 限制会让那次替换静默失败）。
	// 会向用户暴露壳的存在，只应出现在排障产物里。
	DebugShell bool `json:"debug_shell"`

	// 运行时防护参数
	SigHashes  []string `json:"sig_hashes"`  // D1 允许的签名 SHA-256（留空则用本次签名）
	BindDevice string   `json:"bind_device"` // D5 绑定设备指纹（留空则运行时采集）

	// 工程参数
	Channels []string `json:"channels"` // E4 渠道列表
	Jobs     int      `json:"jobs"`     // E5 并发数（0=CPU 核数）
}

// DefaultStamp 是 A14 未指定 -stamp-time 时使用的固定时间戳。
//
// 它必须是**全局唯一**的时间来源：A14 统一元数据之后，E1 签名还会往里
// 追加 MANIFEST.MF / CERT.SF / CERT.RSA 三个条目，这三个条目若用各自
// 的默认值（1980-01-01），产物就会出现「唯独签名文件是 1980」这一枚
// 重打包指纹——恰好与 A14 的目的相反。因此签名侧必须能拿到同一个时间。
var DefaultStamp = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

// UnifiedStamp 返回 A14 元数据统一化使用的时间戳。
//
// StampTime 非空时按 RFC3339 解析；否则退回 DefaultStamp。
func (o *Options) UnifiedStamp() (time.Time, error) {
	if o.StampTime == "" {
		return DefaultStamp, nil
	}
	t, err := time.Parse(time.RFC3339, o.StampTime)
	if err != nil {
		return time.Time{}, fmt.Errorf("时间戳格式非法（应为 RFC3339）: %w", err)
	}
	return t, nil
}

// IsEnabled 判断某功能项是否启用；未显式设置时取默认值。
func (o *Options) IsEnabled(id FeatureID) bool {
	if o.Enabled == nil {
		return DefaultOf(id)
	}
	if v, ok := o.Enabled[id]; ok {
		return v
	}
	return DefaultOf(id)
}

// SetEnabled 显式设置某功能项的启用状态。
func (o *Options) SetEnabled(id FeatureID, v bool) {
	if o.Enabled == nil {
		o.Enabled = map[FeatureID]bool{}
	}
	o.Enabled[id] = v
}

// DefaultOf 返回功能项的默认启用状态。
func DefaultOf(id FeatureID) bool {
	if f, ok := ByID()[id]; ok {
		return f.Default
	}
	return false
}

// EnabledIDs 返回当前启用的全部功能项 ID（按字典序）。
func (o *Options) EnabledIDs() []FeatureID {
	var out []FeatureID
	for _, f := range All() {
		if o.IsEnabled(f.ID) {
			out = append(out, f.ID)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Validate 校验参数组合的合法性，返回人类可读的错误。
func (o *Options) Validate() error {
	var errs []string

	// 功能项依赖关系
	type dep struct {
		need FeatureID
		why  string
	}
	deps := map[FeatureID][]dep{
		"B1": {{"B2", "DEX 整体加密需要壳 Application 才能解密加载"},
			{"B3", "DEX 整体加密需要 ClassLoader 接管才能加载解密后的 DEX"}},
		// B3 必须同时依赖 B1：没有加密载荷时 B3 会提前返回、**不注入 Loader
		// 类体**，只在 Note 里说「退化为纯 Application 代理」；但 B2 只要看到
		// B3 启用就会让壳生成对 Loader.a 的调用。结果产物引用一个从未定义的
		// Loader 类，应用一启动就 NoClassDefFoundError——而 Validate 与 CLI
		// 都报成功。把 B1 写进依赖表，从配置层就堵死这个组合。
		"B3": {{"B1", "ClassLoader 接管需要加密载荷，否则壳不会注入 Loader 类体"},
			{"B2", "ClassLoader 接管需要壳 Application 提供最早执行时机"}},
		"B4": {{"B1", "多 DEX 拆分需要 DEX 加密才能体现防护价值"}},
		"B8": {{"B1", "载荷容器化需要先有加密载荷"}},
		// C2 把 lib/<abi>/*.so 整体移进 assets，应用再也拿不到这些库，
		// 必须由壳在启动时解密到私有目录、并把该目录并入类加载器的库搜索路径。
		"C2":  {{"B1", "原生库加密需要壳的解密载荷机制"}, {"B2", "需要壳 Application 提供最早执行时机"}, {"B3", "需要 ClassLoader 接管（库搜索路径由它承载）"}},
		"B5":  {{"B1", "函数抽取需要 DEX 加密作为基础"}},
		"B6":  {{"B2", "VMP 需要壳 Application"}, {"B3", "VMP 需要 ClassLoader 接管"}},
		"B7":  {{"B2", "Dex2C 需要壳 Application"}, {"B3", "Dex2C 需要 ClassLoader 接管"}},
		"A11": {{"A5", "资源路径全量扁平化是资源混淆的完整形态，需先启用资源混淆"}},
		// D1 必须挂在壳 Application 上：签名校验要跑在应用启动的最早时机，
		// 而那个时机只有壳能提供。
		"D1": {{"B2", "签名校验需要壳 Application 提供启动时机"}},
		"D2": {{"B2", "Root 检测需要壳 Application 提供启动时机"}},
		"D3": {{"B2", "模拟器检测需要壳 Application 提供启动时机"}},
		// C1 要往壳 DEX 注入 native 桥接类；密钥派生依赖签名证书，
		// 因此还必须有签名（否则运行时算不出与加密一致的密钥）。
		"C1": {{"B2", "密钥 native 派生需要壳 Application 挂载桥接类"}, {"E1", "派生输入包含签名证书摘要，需要启用签名"}},
		"C7": {{"C1", "原生库伪装作用于 C1/C4/C5/C6 注入的那一份守卫库"}},
		"C4": {{"B2", "反调试需要壳 Application 提供启动时机"}, {"C1", "反调试与密钥派生共用同一份原生库与桥接类"}},
		"C5": {{"B2", "反注入需要壳 Application 提供启动时机"}, {"C1", "反注入与密钥派生共用同一份原生库与桥接类"}},
		"C6": {{"B2", "完整性自校验需要壳 Application 提供启动时机"}, {"C1", "完整性自校验与密钥派生共用同一份原生库与桥接类"}},
		"D4": {{"B2", "运行期复检需要壳 Application 提供启动时机"}, {"C1", "运行期复检与密钥派生共用同一份原生库与桥接类"}},
		"D5": {{"B2", "设备绑定需要壳 Application 提供启动时机"}},
	}
	// 选项级依赖：PayloadMAC 只有 B1 会消费，单独打开等于静默无效果。
	// 这里是「选项」而不是「功能项」，故不进 deps 表。
	if o.PayloadMAC && !o.IsEnabled("B1") {
		errs = append(errs, "已指定 -payload-mac，但未启用 B1（DEX 整体加密）：载荷 MAC 由 B1 生成、由壳校验，单独打开不会产生任何效果")
	}

	for id, ds := range deps {
		if !o.IsEnabled(id) {
			continue
		}
		for _, d := range ds {
			if !o.IsEnabled(d.need) {
				errs = append(errs, fmt.Sprintf("%s（%s）已启用，但依赖的 %s（%s）未启用：%s",
					id, nameOf(id), d.need, nameOf(d.need), d.why))
			}
		}
	}

	// 未实现的功能项不允许启用。
	//
	// 这是最重要的一条校验：设计文档罗列的 46 项能力并非全部落地，
	// 而「启用后什么都不做」是最危险的失败模式——使用方会以为自己拿到了
	// Root 检测、反调试、签名校验等防护，实际产物里一个都没有。
	// 宁可让命令失败，也不能静默地产出一个防护与预期不符的 APK。
	var unimplemented []string
	for _, f := range All() {
		if o.IsEnabled(f.ID) && !f.Implemented {
			unimplemented = append(unimplemented, fmt.Sprintf("%s（%s）", f.ID, f.Name))
		}
	}
	if len(unimplemented) > 0 {
		errs = append(errs, fmt.Sprintf(
			"以下功能项尚未实现，无法启用（否则会静默地什么都不做）：%s",
			strings.Join(unimplemented, "、")))
	}

	// 已废弃 / 尚未实现的能力：必须显式拒绝，绝不能静默忽略。
	//
	//   - LibStripSections：实测 Android 动态链接器会校验 ELF 节头表，
	//     清零会让 dlopen 直接失败；见 passes/libdisguise.go 的说明。
	//   - LibFakeName：只有 C7 才能消费它，单独设置会「开关打开了但什么都没发生」。
	//   - ExtractRatio：B5（函数抽取）未实现，且不属于已实现集合；单独设置同样静默无效。
	if o.LibStripSections {
		errs = append(errs,
			"-lib-strip-sections 已废弃：Android 的动态链接器会校验 ELF 节头表"+
				"（实测清零 e_shentsize/e_shstrndx 会让 dlopen 直接失败），且 C6 的完整性校验"+
				"依赖节名定位 .text/.rodata。该选项不再提供，请只用 -lib-name 做改名伪装")
	}
	if o.LibFakeName != "" && !o.IsEnabled("C7") {
		errs = append(errs,
			"已指定 -lib-name，但未启用 C7（原生库伪装）：请用 -enable C7 启用后再指定假库名，"+
				"否则改名不会发生")
	}
	if o.ExtractRatio != 0 {
		errs = append(errs, "B5（函数抽取）尚未实现，-extract-ratio 不可用")
	}

	// 参数范围
	if o.ObfStringMin < 0 {
		errs = append(errs, "A2 最小加密长度不能为负")
	}
	if o.ExtractRatio < 0 || o.ExtractRatio > 100 {
		errs = append(errs, "B5 抽取比例须在 0~100 之间")
	}
	// 上限取 4095：4096<<20 == 2^32，会让填充量的字节运算在 uint32 上回绕为 0。
	if o.ManifestPadMB < 0 || o.ManifestPadMB > 4095 {
		errs = append(errs, "A15 填充量须在 0~4095 MB 之间（4096MB 会使 uint32 字节数溢出）")
	}
	if o.FakeDexCount < 0 || o.JunkTopCount < 0 || o.JunkDirCount < 0 || o.ClassPadCount < 0 {
		errs = append(errs, "数量类参数不能为负")
	}
	if o.SplitCount < 0 {
		errs = append(errs, "B4 拆分个数不能为负")
	}

	// 必要参数
	if o.In == "" {
		errs = append(errs, "必须指定输入 APK")
	}
	// 只有启用签名时才需要密钥库：未启用 E1 时产物本就是未签名 APK，
	// 此时强制要求密钥库会让「只做加固、自行签名」这一正当用法无法执行。
	if o.IsEnabled("E1") && o.KS == "" {
		errs = append(errs, "已启用签名（E1），必须指定密钥库（.jks/.pfx）")
	}

	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("%s", strings.Join(errs, "\n"))
}

func nameOf(id FeatureID) string {
	if f, ok := ByID()[id]; ok {
		return f.Name
	}
	return string(id)
}
