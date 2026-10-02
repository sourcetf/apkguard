package passes

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"strings"

	"apkguard/internal/axml"
	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/pipeline"
	"apkguard/internal/zipx"
)

// ---- A16 诱饵核心文件 ----
//
// 参考样本 sample.apk 用了一招很阴的手法：它带一个 382 字节的 `ANDROIDMANIFEST.XML`
// （**大写变体**），内容是一份「看起来像真的」的 Manifest；另外还有 884 个非 ASCII
// 命名的顶层 `.xml`。A9 覆盖了假 DEX magic，A10 覆盖了非 ASCII 顶层垃圾，但都没有
// 「假核心文件」这一类：大小写/同形变体的假 AndroidManifest.xml、假 resources.arsc、
// 以及**结构完整**的假 classes.dex。
//
// 本 Pass 的设计目标不是「放一堆解析不了的垃圾」——那种东西扫描器一次解析失败就整类
// 丢弃，反而帮分析者更快定位真文件。这里注入的每个假核心文件都必须是**可被解析的完整
// 结构**：
//
//   - 假 Manifest 是含 <manifest>/<application>/<activity>/<intent-filter> 与
//     package、versionName、versionCode 等属性的合法 AXML（aapt2/androguard 能解析出
//     完整的元素树，而不是只有头部）；
//   - 假 classes.dex 是能被 dex.Parse / dex.Verify 通过的**真正最小 DEX**（含一个类、
//     构造器与带真实位运算的方法），jadx/apktool 会真的把它当 DEX 加载并反编译；
//   - 假 resources.arsc 是「ResTable_header + 全局字符串池」的合法最小形态（局限见
//     decoyArsc 的注释，诚实标注：aapt2/apktool 需要 package 块才会认作完整资源表）。
//
// 自动化工具（apktool 批量解包、jadx 目录扫描、按 magic 判定的脱壳脚本）会把它们
// 全部当成核心文件读一遍，只有逐个读完才能判定是假的——这正是本功能消耗分析时间的
// 价值所在。命名一律用大小写/同形变体，因为 Android 只按**精确名**读取核心文件，
// 变体不会影响运行。

// decoyCoreDefaultGroups 是未指定 DecoyCoreCount 时的默认组数（每组含假 Manifest/arsc/dex）。
const decoyCoreDefaultGroups = 4

// realCoreNames 是三个真核心文件的**精确名**。
//
// 硬约束：绝不能注入与之完全同名的条目。Android 的 PackageParser 只按精确名
// （大小写敏感）读取 AndroidManifest.xml / resources.arsc / classes.dex，因此
// 大小写/同形变体是安全的；但精确同名会让系统读到假文件、应用直接死。
// 这里做精确匹配（不是 EqualFold）正是为了允许变体、拒绝真名。
var realCoreNames = map[string]bool{
	manifestName:  true, // AndroidManifest.xml
	arscName:      true, // resources.arsc
	"classes.dex": true,
}

// 假核心文件的命名变体。全部与真名**不完全相同**（Android 只读精确名），
// 但大小写/同形上足以让按名匹配的工具把它们当核心文件。
var (
	decoyManifestNames = []string{
		"ANDROIDMANIFEST.XML", // 参考样本用的就是这一档
		"androidmanifest.xml",
		"AndroidManifest.XML",
		"ANDROIDManifest.xml",
		"androidmanifest.XML",
		"Androidmanifest.XML",
		"ANDROIDMANIFEST.xml",
		"androidManifest.XML",
	}
	decoyArscNames = []string{
		"RESOURCES.ARSC",
		"resources.Arsc",
		"Resources.ARSC",
		"RESOURCES.arsc",
		"resources.ARSC",
		"Resources.Arsc",
	}
	decoyDexNames = []string{
		"CLASSES.DEX",
		"Classes.Dex",
		"classes.DEX",
		"CLASSES.dex",
		"Classes.DEX",
		"CLASSES.Dex",
	}
)

// decoyCore 注入若干组「大小写/同形变体的假核心文件」。
type decoyCore struct{}

func (decoyCore) ID() config.FeatureID { return "A16" }
func (decoyCore) In() pipeline.Level   { return pipeline.LevelZip }
func (decoyCore) Out() pipeline.Level  { return pipeline.LevelZip }

func (d *decoyCore) Run(_ context.Context, art *pipeline.Artifact, opts *config.Options) error {
	groups := opts.DecoyCoreCount
	if groups <= 0 {
		groups = decoyCoreDefaultGroups
	}
	rnd := newRand(opts.Seed)

	// 与既有条目去重：A9（伪 DEX）、A10（垃圾 XML）、A12（路径攻击）也会注入条目，
	// 其中 A9 的 CLASSES.DEX 等名字与本 Pass 的候选完全重合，必须避开。
	used := map[string]bool{}
	for _, e := range art.Entries() {
		used[e.NameString()] = true
	}

	bytesAdded := 0
	add := func(name string, data []byte) bool {
		// 硬约束①：绝不注入与真核心文件完全同名的条目（见 realCoreNames）。
		// 硬约束②：所有注入条目必须过 manifestCollision 守卫，否则可能破坏 v1
		//   签名校验（实测 RustDesk 报 SecurityException: Invalid signature file
		//   digest for Manifest main attributes）。
		// 硬约束③：与既有条目去重。
		if name == "" || used[name] || realCoreNames[name] || manifestCollision(name) {
			return false
		}
		used[name] = true
		pipeline.Add(art, zipx.NewStored(name, data))
		bytesAdded += len(data)
		return true
	}

	mfAdded, arscAdded, dexAdded := 0, 0, 0
	for i := 0; i < groups; i++ {
		// ① 假 Manifest：内容是可解析的合法 AXML（含 manifest/application/activity）。
		if name, ok := pickDecoyName(decoyManifestNames, i, used); ok {
			if add(name, decoyManifestAXML(rnd)) {
				mfAdded++
			}
		}
		// ② 假 arsc：头部 + 字符串池的合法最小形态。
		if name, ok := pickDecoyName(decoyArscNames, i, used); ok {
			if add(name, decoyArsc(rnd)) {
				arscAdded++
			}
		}
		// ③ 假 DEX：结构完整、能通过 dex.Parse/dex.Verify 的最小 DEX。
		//    注意与 A9 的分工：A9 只伪造 magic（解析必失败），本 Pass 这一档
		//    连索引表、类定义、方法体都是真的，工具必须反编译完才知道是假的。
		if name, ok := pickDecoyName(decoyDexNames, i, used); ok {
			blob, err := decoyDexBody(rnd)
			if err != nil {
				return fmt.Errorf("构造假 DEX 失败: %w", err)
			}
			if add(name, blob) {
				dexAdded++
			}
		}
	}

	art.Note("A16 诱饵核心文件：注入 %d 组（假 Manifest %d、假 resources.arsc %d、假 classes.dex %d，共 %d 字节）。"+
		"每个文件都是结构完整、可被解析的合法结构——假 Manifest 含 manifest/application/activity 元素树，"+
		"假 DEX 能通过 dex.Parse/dex.Verify（含类定义与带真实位运算的方法体），"+
		"假 arsc 为 ResTable_header+全局字符串池的合法最小形态（aapt2/apktool 需 package 块才认作完整表，见代码注释）。"+
		"命名一律用大小写/同形变体：Android 只读精确名，变体不影响运行，但自动化工具必须逐个读完才知道是假的；"+
		"绝不与真核心文件同名",
		groups, mfAdded, arscAdded, dexAdded, bytesAdded)
	art.Stat("A16.manifests", fmt.Sprint(mfAdded))
	art.Stat("A16.arcs", fmt.Sprint(arscAdded))
	art.Stat("A16.dex", fmt.Sprint(dexAdded))
	art.Stat("A16.bytes", fmt.Sprint(bytesAdded))
	return nil
}

// pickDecoyName 为第 i 组从候选变体里挑一个尚未占用的名字。
//
// 先按 i 顺序扫描候选表，全部被占用（例如 A9 已用了 CLASSES.DEX）时才在扩展名前
// 插入序号兜底，保证组数可扩展且产物名始终与真名不同。
func pickDecoyName(bases []string, i int, used map[string]bool) (string, bool) {
	for k := 0; k < len(bases); k++ {
		cand := bases[(i+k)%len(bases)]
		if !used[cand] {
			return cand, true
		}
	}
	base := bases[i%len(bases)]
	dot := strings.LastIndexByte(base, '.')
	if dot < 0 {
		return "", false
	}
	stem, ext := base[:dot], base[dot:]
	for k := 2; ; k++ {
		name := fmt.Sprintf("%s_%d%s", stem, k, ext)
		if !used[name] {
			return name, true
		}
	}
}

// ---- 假 Manifest：结构完整的合法 AXML ----

// decoyElemAttr 描述假 Manifest 中某元素的一个属性。
//
// 与 axml.NewAttr 的区别：这里直接携带字符串池索引，因为本文件是从零构造整棵
// 元素树（连字符串池一起），索引在建池前就已分配，无需再做 intern。
type decoyElemAttr struct {
	ns    uint32 // 命名空间字符串索引；noIndex 表示无
	name  uint32 // 属性名索引
	raw   uint32 // 原始文本索引；noIndex 表示无（int/bool 直接放 data）
	dtype byte   // Res_value.dataType
	data  uint32 // Res_value.data
}

// decoyElemBody 组装 ResXMLTree_attrExt + 属性表。
//
// 布局与 axml/write.go 的 encodeStartElement 一致：attributeStart 恒为 20
// （attrExt 自身长度），attributeSize 为 20。写错这两个字段会让解析器按错误
// 步长遍历，出现「解析成功但元素/属性为空」。
func decoyElemBody(ns, name uint32, attrs []decoyElemAttr) []byte {
	ext := make([]byte, 20)
	binary.LittleEndian.PutUint32(ext[0:], ns)
	binary.LittleEndian.PutUint32(ext[4:], name)
	binary.LittleEndian.PutUint16(ext[8:], 20)  // attributeStart
	binary.LittleEndian.PutUint16(ext[10:], 20) // attributeSize
	binary.LittleEndian.PutUint16(ext[12:], uint16(len(attrs)))
	binary.LittleEndian.PutUint16(ext[14:], 0)              // idIndex
	binary.LittleEndian.PutUint16(ext[16:], noIndex&0xffff) // classIndex
	binary.LittleEndian.PutUint16(ext[18:], noIndex&0xffff) // styleIndex
	out := append([]byte(nil), ext...)
	for _, a := range attrs {
		e := make([]byte, 20)
		binary.LittleEndian.PutUint32(e[0:], a.ns)
		binary.LittleEndian.PutUint32(e[4:], a.name)
		binary.LittleEndian.PutUint32(e[8:], a.raw)
		binary.LittleEndian.PutUint16(e[12:], 8) // Res_value.size
		e[15] = a.dtype
		binary.LittleEndian.PutUint32(e[16:], a.data)
		out = append(out, e...)
	}
	return out
}

// decoyManifestAXML 生成一份**结构完整、可被解析**的假 AndroidManifest.xml。
//
// 与 realisticAXML 的区别：后者只有一个随机根元素（用于垃圾 XML 足够），
// 而假核心文件必须像真 Manifest 那样有 <manifest>/<application>/<activity>
// 与 package/versionName/versionCode/name 等属性——aapt2/jadx 解析后能看到
// 完整的组件表，分析者必须逐个读完才能判定是假的。
//
// 返回的字节流不补零：顶层 XML chunk 的 size 恰好等于文件长度，元素块首尾配对，
// 是一份自洽的最小 Manifest。比参考样本的 382 字节略大，但结构真实性优先。
func decoyManifestAXML(rnd *rand.Rand) []byte {
	// 字符串池：下标与下面各元素/属性里引用的索引必须严格对应。
	// 约定：0=空串、1=android 前缀、2=android 命名空间 URI（与 aapt2 产物一致）。
	strs := []string{
		"", "android", axml.AndroidNS,
		"manifest", "application", "activity", "intent-filter", "action", "category",
		"package", "versionName", "versionCode", "name", "label", "icon", "theme", "allowBackup",
	}
	idx := map[string]int{}
	for i, s := range strs {
		idx[s] = i
	}
	intern := func(s string) uint32 {
		if i, ok := idx[s]; ok {
			return uint32(i)
		}
		i := len(strs)
		idx[s] = i
		strs = append(strs, s)
		return uint32(i)
	}

	nsNone := uint32(noIndex)
	nsAndroid := uint32(idx[axml.AndroidNS])

	strAttr := func(ns uint32, name string, val uint32) decoyElemAttr {
		return decoyElemAttr{ns: ns, name: uint32(idx[name]), raw: val, dtype: axml.TypeString, data: val}
	}
	boolAttr := func(name string, v bool) decoyElemAttr {
		var d uint32
		if v {
			d = 1
		}
		return decoyElemAttr{ns: nsAndroid, name: uint32(idx[name]), raw: noIndex, dtype: axml.TypeIntBoolean, data: d}
	}
	intAttr := func(name string, v uint32) decoyElemAttr {
		return decoyElemAttr{ns: nsAndroid, name: uint32(idx[name]), raw: noIndex, dtype: axml.TypeIntDec, data: v}
	}

	pkg := "com." + pkgSeg(rnd, 6) + "." + pkgSeg(rnd, 5)
	verName := fmt.Sprintf("%d.%d.%d", 1+rnd.Intn(9), rnd.Intn(20), rnd.Intn(50))
	verCode := uint32(100 + rnd.Intn(9000))
	appClass := pkg + "." + titleSeg(rnd, 8)
	label := titleSeg(rnd, 7)
	actCount := 2 + rnd.Intn(3) // 2~4 个 activity

	pkgIdx := intern(pkg)
	verNameIdx := intern(verName)
	appClassIdx := intern(appClass)
	labelIdx := intern(label)
	iconIdx := intern("@mipmap/ic_launcher")
	themeIdx := intern("@style/AppTheme")
	launcherIdx := intern(pkg + "." + titleSeg(rnd, 9) + "Activity")
	actionIdx := intern("android.intent.action.MAIN")
	categoryIdx := intern("android.intent.category.LAUNCHER")

	// 命名空间块：prefix 用池里的 "android"，uri 用 android 命名空间 URI。
	nsPrefixIdx := uint32(idx["android"])
	nsURIIndex := uint32(idx[axml.AndroidNS])
	msgs := []uint32{noIndex, noIndex, noIndex, noIndex}
	line := func() int { return 1 + rnd.Intn(6) }
	startEl := func(name string, attrs []decoyElemAttr) []byte {
		return node(chunkStartElem, line(), msgs, decoyElemBody(nsNone, uint32(idx[name]), attrs))
	}
	endEl := func(name string) []byte {
		return node(chunkEndElem, line(), msgs, le32(nsNone, uint32(idx[name])))
	}
	startNS := node(chunkStartNS, 1, msgs, le32(nsPrefixIdx, nsURIIndex))
	endNS := node(chunkEndNS, 1, msgs, le32(nsPrefixIdx, nsURIIndex))

	manifestAttrs := []decoyElemAttr{
		strAttr(nsNone, "package", pkgIdx),
		intAttr("versionCode", verCode),
		strAttr(nsAndroid, "versionName", verNameIdx),
	}
	appAttrs := []decoyElemAttr{
		strAttr(nsAndroid, "name", appClassIdx),
		strAttr(nsAndroid, "label", labelIdx),
		strAttr(nsAndroid, "icon", iconIdx),
		strAttr(nsAndroid, "theme", themeIdx),
		boolAttr("allowBackup", rnd.Intn(2) == 0),
	}

	body := make([]byte, 0, 512)
	body = append(body, startNS...)
	body = append(body, startEl("manifest", manifestAttrs)...)
	body = append(body, startEl("application", appAttrs)...)
	for k := 0; k < actCount; k++ {
		var aAttrs []decoyElemAttr
		if k == 0 {
			aAttrs = []decoyElemAttr{
				strAttr(nsAndroid, "name", launcherIdx),
				boolAttr("exported", true),
			}
		} else {
			n := intern(pkg + "." + titleSeg(rnd, 9) + "Activity")
			aAttrs = []decoyElemAttr{
				strAttr(nsAndroid, "name", n),
				boolAttr("exported", false),
			}
		}
		body = append(body, startEl("activity", aAttrs)...)
		if k == 0 {
			// 启动 Activity 带 MAIN/LAUNCHER intent-filter，与真 Manifest 的形态一致。
			body = append(body, startEl("intent-filter", nil)...)
			body = append(body, startEl("action", []decoyElemAttr{strAttr(nsNone, "name", actionIdx)})...)
			body = append(body, endEl("action")...)
			body = append(body, startEl("category", []decoyElemAttr{strAttr(nsNone, "name", categoryIdx)})...)
			body = append(body, endEl("category")...)
			body = append(body, endEl("intent-filter")...)
		}
		body = append(body, endEl("activity")...)
	}
	body = append(body, endEl("application")...)
	body = append(body, endEl("manifest")...)
	body = append(body, endNS...)

	// 字符串池必须在全部 intern 之后编码（顺序错了元素名会指向错误字符串）。
	pool := encodePool(strs)
	out := make([]byte, 8, 8+len(pool)+len(body))
	binary.LittleEndian.PutUint16(out[0:], chunkXML)
	binary.LittleEndian.PutUint16(out[2:], 8)
	out = append(out, pool...)
	out = append(out, body...)
	// 顶层 XML chunk 的 size 必须等于文件总长（与 axml/write.go 的约定一致）。
	binary.LittleEndian.PutUint32(out[4:], uint32(len(out)))
	return out
}

// ---- 假 resources.arsc ----

// decoyArsc 生成一个「头部 + 全局字符串池」的合法最小 arsc。
//
// 诚实说明取舍：真实 resources.arsc 在全局字符串池之后还有 ResTable_package
// （内含 typeStrings/keyStrings/TypeSpec/Type 块），甚至多包。这里**只构造到
// 字符串池**，原因与局限如下：
//
//   - arsc.Parse（本项目）以及只读全局字符串池的工具（按字符串池提 res/ 路径的
//     脚本、部分 androguard 版本）能正常解析它；
//   - aapt2 / apktool 需要至少一个 package + TypeSpec/Type 块才会认作完整资源表，
//     对 packageCount=0 的表会报 empty/invalid table。要构造它们接受的完整表，
//     需复刻 package→typeStrings/keyStrings→TypeSpec→Type→entry 整条链并保证
//     所有相对偏移自洽，成本与出错风险都远超本诱饵的收益（诱饵目标是消耗分析时间，
//     不是真正参与资源解析）。
//
// 因此这里明确是「合法最小形态」而非「aapt2 完整表」；这一点在 Pass 的 Note 里
// 如实标注，不夸大能力。字符串池里放的是形如 res/... 的真实资源路径，让按字符串池
// 做资源枚举的工具能捞到一堆看似正常的路径。
func decoyArsc(rnd *rand.Rand) []byte {
	strs := []string{
		"res/layout/activity_main.xml",
		"res/layout/fragment_home.xml",
		"res/drawable/ic_launcher_background.xml",
		"res/drawable-hdpi/ic_launcher.png",
		"res/mipmap-xxhdpi/ic_launcher.png",
		"res/values/strings.xml",
		"res/values/colors.xml",
		"res/values/styles.xml",
		"res/xml/network_security_config.xml",
		"res/raw/config.json",
	}
	// 追加若干随机 res 路径，让池有真实资源表的规模感。
	for i := 0; i < 3+rnd.Intn(5); i++ {
		strs = append(strs, "res/"+pkgSeg(rnd, 6)+"/"+randSeg(rnd, 8)+".xml")
	}
	pool := encodePool(strs)
	out := make([]byte, 12+len(pool))
	binary.LittleEndian.PutUint16(out[0:], 0x0002) // RES_TABLE_TYPE
	binary.LittleEndian.PutUint16(out[2:], 12)     // ResTable_header 长度
	binary.LittleEndian.PutUint32(out[4:], uint32(len(out)))
	binary.LittleEndian.PutUint32(out[8:], 0) // packageCount=0（见上方局限说明）
	copy(out[12:], pool)
	return out
}

// ---- 假 classes.dex ----

// decoyDexBody 构造一个**真正合法**的最小 DEX：一个类 + 构造器 + 一个带真实位运算的方法。
//
// 与 A9 的 fakeDexBody 是互补的两档：
//   - A9：只伪造 magic 与部分头部字段，数据区随机——解析必失败，用于拖慢「按 magic
//     判定」的工具；
//   - A16（本函数）：索引表、字符串池、类定义、方法体全部由 dex.Build 真实生成，
//     dex.Parse/dex.Verify 都能通过，jadx/apktool 会把它当正常 DEX 反编译。分析者
//     必须读完方法体才能发现里面没有业务逻辑。
//
// 方法体不是空壳（decoyCheckBlob 做了真实的异或运算），因为空方法在反编译视图里
// 一眼就是填充物，反而提示「这里是加固产物」。
func decoyDexBody(rnd *rand.Rand) ([]byte, error) {
	cls := "Lcom/" + pkgSeg(rnd, 6) + "/" + pkgSeg(rnd, 5) + "/" + titleSeg(rnd, 8) + ";"
	objInit := dex.MethodSpec{Class: "Ljava/lang/Object;", Name: "<init>", Proto: dex.ProtoSpec{Ret: "V"}}

	ctor, err := decoyCtorBlob(objInit)
	if err != nil {
		return nil, err
	}
	check, err := decoyCheckBlob(rnd)
	if err != nil {
		return nil, err
	}

	add := dex.Addition{
		// objInit 是方法体引用的外部符号，必须显式登记；类自身的方法/字段/类型
		// 由 dex 的 expandAdditionRefs 自动补齐。
		Methods: []dex.MethodSpec{objInit},
		Classes: []dex.ClassSpec{{
			Name:   cls,
			Super:  "Ljava/lang/Object;",
			Access: 0x0001, // ACC_PUBLIC
			Fields: []dex.ClassField{{Name: "value", Type: "I", Access: 0x0001}},
			Methods: []dex.ClassMethod{
				{Name: "<init>", Proto: dex.ProtoSpec{Ret: "V"}, Access: 0x0001, Code: ctor},
				{Name: "check", Proto: dex.ProtoSpec{Ret: "I", Params: []string{"I"}}, Access: 0x0001, Code: check},
			},
		}},
	}
	return dex.Build(add)
}

// decoyCtorBlob 生成 <init>()V：只调用父类构造器（registers=2、ins=1 → this 在 v1）。
func decoyCtorBlob(superInit dex.MethodSpec) (*dex.CodeBlob, error) {
	a := dex.NewAsm()
	if err := a.InvokeDirect([]int{1}, superInit); err != nil {
		return nil, err
	}
	a.ReturnVoid()
	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	return &dex.CodeBlob{Registers: 2, Ins: 1, Outs: 1, Insns: insns, Patches: patches}, nil
}

// decoyCheckBlob 生成 check(I)I：做一次真实的异或并返回。
//
// registers=3、ins=2 → this 在 v1、入参在 v2；v0 作临时寄存器。
func decoyCheckBlob(rnd *rand.Rand) (*dex.CodeBlob, error) {
	mix := int16(0x11 + rnd.Intn(0x60))
	a := dex.NewAsm()
	a.Const16(0, mix)
	a.XorInt(2, 2, 0)
	a.Return(2)
	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	return &dex.CodeBlob{Registers: 3, Ins: 2, Outs: 0, Insns: insns, Patches: patches}, nil
}

// ---- 命名辅助 ----

// pkgSeg 生成一个合法的小写包名段（首字符保证是字母，避免 "com.3x" 这类非法包名）。
func pkgSeg(r *rand.Rand, n int) string {
	s := strings.ToLower(randSeg(r, n))
	if s[0] >= '0' && s[0] <= '9' {
		s = "a" + s
	}
	return s
}

// titleSeg 生成一个首字母大写的标识符（用于类名/标签）。
func titleSeg(r *rand.Rand, n int) string {
	s := randSeg(r, n)
	return strings.ToUpper(s[:1]) + s[1:]
}
