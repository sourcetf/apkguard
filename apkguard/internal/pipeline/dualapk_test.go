package pipeline

import (
	"bytes"
	"context"
	"encoding/binary"
	"math"
	"strings"
	"testing"

	"apkguard/internal/axml"
	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/pack"
	"apkguard/internal/zipx"
)

// b9TestOptions 构造启用 B9（DualAPK）+ 签名的收尾参数。
func b9TestOptions(ksPath string, dual bool) *config.Options {
	return &config.Options{
		In:      "in.apk",
		KS:      ksPath,
		KSPass:  "pass",
		DualAPK: dual,
		Seed:    "b9-test-seed",
		DexKey:  "b9-test-key",
		Enabled: map[config.FeatureID]bool{
			"E1": true, "E2": true, "E3": true,
		},
	}
}

// TestDualAPKHostStructure 验证 B9 产出的宿主 APK 结构完整、可解析：
// Manifest（包名/权限/launcher）、宿主 DEX（可被 internal/dex 解析且不含
// dalvik/system 引用）、加密插件（能解回原插件 APK）、签名块齐全。
func TestDualAPKHostStructure(t *testing.T) {
	sample := sampleAPK(t)
	ks := writeTestKeystore(t, "pass")

	art, err := Load(sample)
	if err != nil {
		t.Fatalf("读取样本失败: %v", err)
	}
	pluginPkg := manifestPkgOf(t, art)
	if pluginPkg == "" {
		t.Fatalf("样本 Manifest 没有包名")
	}

	opts := b9TestOptions(ks, true)
	out, err := (DefaultSink{}).Finish(context.Background(), art, opts)
	if err != nil {
		t.Fatalf("B9 收尾失败: %v", err)
	}

	a, err := zipx.Read(out)
	if err != nil {
		t.Fatalf("宿主 APK 无法解析: %v", err)
	}
	hostMfEntry := a.Find("AndroidManifest.xml")
	if hostMfEntry == nil {
		t.Fatalf("宿主缺少 AndroidManifest.xml")
	}
	hostDexEntry := a.Find("classes.dex")
	if hostDexEntry == nil {
		t.Fatalf("宿主缺少 classes.dex")
	}

	// 插件条目：assets/<随机名>.zip，密文不可压缩（STORED）。
	var pluginEntry *zipx.Entry
	for _, e := range a.Entries {
		if strings.HasPrefix(e.NameString(), "assets/") && strings.HasSuffix(e.NameString(), ".zip") {
			if pluginEntry != nil {
				t.Fatalf("宿主 assets 里出现多个插件候选: %s / %s", pluginEntry.NameString(), e.NameString())
			}
			pluginEntry = e
		}
	}
	if pluginEntry == nil {
		t.Fatalf("宿主 assets 里没有插件条目，条目: %v", entryNames(a))
	}
	if !pluginEntry.IsStored() {
		t.Fatalf("插件密文应以 STORED 存放（密文不可压缩）: method=%d", pluginEntry.Method)
	}
	// 绝不允许出现第二份 Manifest/arsc（双 APK 的两份核心文件只允许在外层）。
	for _, e := range a.Entries {
		n := e.NameString()
		if n == "resources.arsc" || (strings.EqualFold(n, "resources.arsc") && n != "resources.arsc") {
			t.Fatalf("宿主不应包含 resources.arsc（宿主不引用任何资源）: %s", n)
		}
	}

	// ---- 宿主 Manifest ----
	mfData, err := hostMfEntry.Data()
	if err != nil {
		t.Fatalf("读取宿主 Manifest 失败: %v", err)
	}
	mf, err := axml.Parse(mfData)
	if err != nil {
		t.Fatalf("宿主 Manifest 不可解析: %v", err)
	}
	root := mf.FindElement("manifest")
	if root == nil {
		t.Fatalf("宿主 Manifest 缺少 <manifest>")
	}
	hostPkg := root.AttrString("package")
	if !strings.HasPrefix(hostPkg, "com.") || hostPkg == pluginPkg {
		t.Fatalf("宿主包名异常: %q（插件 %q）", hostPkg, pluginPkg)
	}
	// 权限与取值都进字符串池；解析树按首元素断言（宿主 Manifest 由本工具生成，
	// 结构固定：一个 uses-permission 对应一个权限）。
	pool := map[string]bool{}
	for _, s := range mf.Strings() {
		pool[s] = true
	}
	for _, want := range []string{"android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.INTERNET"} {
		if !pool[want] {
			t.Fatalf("宿主 Manifest 字符串池缺少权限 %s", want)
		}
	}
	app := mf.FindElement("application")
	if app == nil || app.Attr("name") == nil {
		t.Fatalf("宿主 Manifest 的 application 未指向宿主自己的类")
	}
	act := mf.FindElement("activity")
	if act == nil || act.Attr("name") == nil {
		t.Fatalf("宿主 Manifest 缺少 launcher activity")
	}
	if a := act.Attr("exported"); a == nil || a.Data != 1 {
		t.Fatalf("宿主 launcher activity 必须 exported=true")
	}
	usesSDK := mf.FindElement("uses-sdk")
	if usesSDK == nil {
		t.Fatalf("宿主 Manifest 缺少 uses-sdk")
	}
	if a := usesSDK.Attr("minSdkVersion"); a == nil || a.Data != dualAPKHostMinSDK {
		t.Fatalf("宿主 minSdkVersion 应为 %d", dualAPKHostMinSDK)
	}
	// launcher intent-filter 的 action/category：name 必须带 android 命名空间。
	// 框架用 getAttributeValue(ANDROID_NS, "name") 读取，ns=无时读不到，
	// 结果是包能装上、启动器里却没有入口。
	actionEl := mf.FindElement("action")
	if actionEl == nil {
		t.Fatalf("宿主 Manifest 缺少 <action>")
	}
	if a := actionEl.AttrNS(axml.AndroidNS, "name"); a == nil || a.RawValue != "android.intent.action.MAIN" {
		t.Fatalf("launcher action 缺少 android:name=android.intent.action.MAIN")
	}
	categoryEl := mf.FindElement("category")
	if categoryEl == nil {
		t.Fatalf("宿主 Manifest 缺少 <category>")
	}
	if a := categoryEl.AttrNS(axml.AndroidNS, "name"); a == nil || a.RawValue != "android.intent.category.LAUNCHER" {
		t.Fatalf("launcher category 缺少 android:name=android.intent.category.LAUNCHER")
	}
	if lm := act.Attr("launchMode"); lm == nil || lm.DataType != axml.TypeIntDec || lm.Data != 1 {
		t.Fatalf("launchMode 必须编码为 enum int（singleTop=1），否则框架 TypedArray.getInt 会失败")
	}

	// ---- 宿主 DEX ----
	dexData, err := hostDexEntry.Data()
	if err != nil {
		t.Fatalf("读取宿主 DEX 失败: %v", err)
	}
	f, err := dex.Parse(dexData)
	if err != nil {
		t.Fatalf("宿主 DEX 无法被 internal/dex 解析: %v", err)
	}
	if err := dex.Verify(dexData); err != nil {
		t.Fatalf("宿主 DEX 结构校验失败: %v", err)
	}
	if err := dex.ValidateDescriptors(dexData); err != nil {
		t.Fatalf("宿主 DEX 描述符校验失败: %v", err)
	}
	// 与参考样本一致：宿主 DEX 不引用 dalvik/system/*（不是内存加载壳）。
	strs, err := f.AllStrings()
	if err != nil {
		t.Fatalf("读取宿主 DEX 字符串池失败: %v", err)
	}
	for _, s := range strs {
		if strings.Contains(s, "dalvik/system") {
			t.Fatalf("宿主 DEX 不应引用 dalvik/system/*：%q", s)
		}
	}
	// CBC→SIV：宿主不得再引用任何 JCA 加解密类型/算法串。
	has := func(want string) bool {
		for _, s := range strs {
			if s == want {
				return true
			}
		}
		return false
	}
	if has("AES/CBC/PKCS5Padding") || has("javax/crypto/Cipher") || has("Ljavax/crypto/Cipher;") {
		t.Fatalf("宿主 DEX 仍含 CBC/JCA-Cipher 引用，解密未切到 Native.sivDecrypt")
	}
	// 解密调用与库加载必须都在宿主 DEX 的字符串池里。
	for _, want := range []string{dex.NativeDecrypt, "loadLibrary", dex.NativeLibName, dex.NativeBridgeClass} {
		if !has(want) {
			t.Fatalf("宿主 DEX 字符串池缺少 %q（sivDecrypt/loadLibrary 链路不完整）", want)
		}
	}

	// ---- 宿主自带守卫库：3 个 ABI 全量嵌入 ----
	libCount := 0
	for _, e := range a.Entries {
		n := e.NameString()
		if strings.HasPrefix(n, "lib/") && strings.HasSuffix(n, "/libapkguard.so") {
			libCount++
		}
	}
	if libCount != 3 {
		t.Fatalf("宿主应内嵌 3 个 ABI 的守卫库，实际 %d 个（条目: %v）", libCount, entryNames(a))
	}

	// ---- 插件解密：能还原出「被加密前的那份已签名插件 APK」----
	pluginPlain, _ := art.Get(sharedKeyPluginAPK).([]byte)
	if len(pluginPlain) == 0 {
		t.Fatalf("Sink 未把插件 APK 放进 Artifact.Shared")
	}
	key, err := pack.Key("b9-test-key|apkguard/b9/plugin")
	if err != nil {
		t.Fatalf("派生插件密钥失败: %v", err)
	}
	blob, err := pluginEntry.Data()
	if err != nil {
		t.Fatalf("读取插件密文失败: %v", err)
	}
	// SIV 的 ad 绑定宿主 assets 条目名（不带 assets/ 前缀的逻辑名）。
	ad := strings.TrimPrefix(pluginEntry.NameString(), "assets/")
	got, err := pack.DecryptNamed(blob, key, ad)
	if err != nil {
		t.Fatalf("插件密文解密失败: %v", err)
	}
	if !bytes.Equal(got, pluginPlain) {
		t.Fatalf("解密结果与 Shared 里的插件不一致（%d vs %d 字节）", len(got), len(pluginPlain))
	}
	pa, err := zipx.Read(got)
	if err != nil {
		t.Fatalf("解出的插件不是合法 ZIP/APK: %v", err)
	}
	if pe := pa.Find("AndroidManifest.xml"); pe == nil {
		t.Fatalf("解出的插件缺少 AndroidManifest.xml")
	} else if d, err := pe.Data(); err == nil {
		pf, err := axml.Parse(d)
		if err != nil {
			t.Fatalf("插件 Manifest 不可解析: %v", err)
		}
		if root := pf.FindElement("manifest"); root == nil || root.AttrString("package") != pluginPkg {
			t.Fatalf("解出的插件包名与原应用不一致")
		}
	}

	// ---- 密文形态：高熵、无明文 ZIP 结构 ----
	//
	// 结构校验（STORED、能解回去）不能说明「静态不可读」：如果加密退化或
	// SIV 标签前留有明文，条目仍能解密成功。这里对密文本体做形态断言。
	if len(blob) <= pack.BlockSize {
		t.Fatalf("插件密文过短: %d 字节", len(blob))
	}
	cipherBody := blob[pack.BlockSize:]
	if bytes.HasPrefix(cipherBody, []byte("PK\x03\x04")) {
		t.Fatalf("IV 之后以明文 ZIP 本地头开头，插件疑似未加密")
	}
	for _, marker := range [][]byte{[]byte("AndroidManifest.xml"), []byte("classes.dex"), []byte("resources.arsc")} {
		if bytes.Contains(blob, marker) {
			t.Fatalf("插件密文里出现明文结构标记 %q", marker)
		}
	}
	if len(cipherBody) >= 4096 {
		if e := shannonEntropy(cipherBody); e < 7.9 {
			t.Fatalf("插件密文熵偏低（%.4f bit/byte），加密形态可疑", e)
		}
	}

	// ---- 宿主 DEX 的语义级断言（结构合法 ≠ 语义正确）----
	//
	// 这些缺陷都能通过 dex.Verify/Parse（结构自洽），只在设备上执行时才暴露：
	//   - drop 少读一个密文分组 → 解密必败；
	//   - openWrite 未改写成 3rc → 两个 long 形参装不进 35c，执行到就崩；
	//   - status 用错 PENDING_USER_ACTION → 安装界面永远不出现。
	dropCI := hostMethod(t, f, "drop")
	if !insnsContainConst32(dropCI, int32(len(blob))) {
		t.Fatalf("drop 未按完整 blob 长度（%d）读取 assets", len(blob))
	}
	if count, ok := findOpenWriteRange(f, hostMethod(t, f, "install")); !ok || count != 6 {
		t.Fatalf("install 的 openWrite 未改写为 6 寄存器 invoke-virtual/range: count=%d ok=%v", count, ok)
	}
	if !insnsContainConst4(hostMethod(t, f, "status"), -1) {
		t.Fatalf("status 未按 STATUS_PENDING_USER_ACTION=-1 判断，安装界面不会被拉起")
	}

	// ---- 宿主签名块 ----
	sec, err := zipx.Split(out)
	if err != nil {
		t.Fatalf("宿主签名块解析失败: %v", err)
	}
	if !sec.HasSigningBlock() {
		t.Fatalf("宿主 APK 未签名（缺少签名块）")
	}
	// stat 记账
	for _, k := range []string{"B9.host_pkg", "B9.plugin_pkg", "B9.plugin_bytes", "B9.plugin_sha256", "B9.asset"} {
		if art.Stats[k] == "" {
			t.Errorf("缺少统计 %s", k)
		}
	}
	if art.Stats["B9.plugin_pkg"] != pluginPkg {
		t.Errorf("B9.plugin_pkg=%q，期望 %q", art.Stats["B9.plugin_pkg"], pluginPkg)
	}
}

// TestDualAPKDisabledZeroImpact 验证 -dual-apk 关闭时收尾行为不变：
// 产物里没有任何宿主结构（无 assets 插件、无第二个 Manifest），
// 且与不启用 B9 的既有签名路径完全一致（对同一输入可逐字节复现）。
func TestDualAPKDisabledZeroImpact(t *testing.T) {
	sample := sampleAPK(t)
	ks := writeTestKeystore(t, "pass")

	run := func(dual bool) []byte {
		art, err := Load(sample)
		if err != nil {
			t.Fatalf("读取样本失败: %v", err)
		}
		opts := b9TestOptions(ks, dual)
		out, err := (DefaultSink{}).Finish(context.Background(), art, opts)
		if err != nil {
			t.Fatalf("收尾失败（dual=%v）: %v", dual, err)
		}
		return out
	}
	off1 := run(false)
	off2 := run(false)
	if !bytes.Equal(off1, off2) {
		t.Fatalf("关闭 B9 时同一输入的产物不可复现（%d vs %d 字节）", len(off1), len(off2))
	}
	a, err := zipx.Read(off1)
	if err != nil {
		t.Fatalf("产物不可解析: %v", err)
	}
	ndex, nmf := 0, 0
	for _, e := range a.Entries {
		switch e.NameString() {
		case "AndroidManifest.xml":
			nmf++
		case "classes.dex":
			ndex++
		}
		if strings.HasPrefix(e.NameString(), "assets/") {
			t.Fatalf("关闭 B9 时不应产生 assets 插件条目: %s", e.NameString())
		}
	}
	if nmf != 1 || ndex != 1 {
		t.Fatalf("关闭 B9 时产物应仍是单 Manifest/单 classes.dex 的普通 APK: mf=%d dex=%d", nmf, ndex)
	}
}

// TestDualAPKRequiresSigning 验证「启用 -dual-apk 但关闭 E1」时 fail-fast，
// 而不是产出一个装不上的未签名插件。
func TestDualAPKRequiresSigning(t *testing.T) {
	sample := sampleAPK(t)
	art, err := Load(sample)
	if err != nil {
		t.Fatalf("读取样本失败: %v", err)
	}
	opts := &config.Options{In: "in.apk", DualAPK: true, Seed: "s"}
	if _, err := (DefaultSink{}).Finish(context.Background(), art, opts); err == nil {
		t.Fatalf("未启用 E1 时应报错")
	}
}

// TestDualAPKRequiresInstallableSignature 验证「-dual-apk 且 v1/v2/v3 全禁」时
// fail-fast：E1 此时实际什么都没签，宿主里的插件一定装不上。
func TestDualAPKRequiresInstallableSignature(t *testing.T) {
	sample := sampleAPK(t)
	art, err := Load(sample)
	if err != nil {
		t.Fatalf("读取样本失败: %v", err)
	}
	ks := writeTestKeystore(t, "pass")
	opts := b9TestOptions(ks, true)
	opts.NoV1, opts.NoV2, opts.NoV3 = true, true, true
	if _, err := (DefaultSink{}).Finish(context.Background(), art, opts); err == nil {
		t.Fatalf("v1/v2/v3 全禁时应报错（插件无法被安装器接受）")
	}
}

// manifestPkgOf 读取 Artifact 里的包名。
func manifestPkgOf(t *testing.T, art *Artifact) string {
	t.Helper()
	e := Find(art, "AndroidManifest.xml")
	if e == nil {
		t.Fatalf("Artifact 缺少 Manifest")
	}
	d, err := e.Data()
	if err != nil {
		t.Fatalf("读取 Manifest 失败: %v", err)
	}
	f, err := axml.Parse(d)
	if err != nil {
		t.Fatalf("解析 Manifest 失败: %v", err)
	}
	return f.FindElement("manifest").AttrString("package")
}

func entryNames(a *zipx.Archive) []string {
	out := make([]string, 0, len(a.Entries))
	for _, e := range a.Entries {
		out = append(out, e.NameString())
	}
	return out
}

// TestDualAPKHostManifestAttrs 独立断言宿主 Manifest 的取值类型与命名空间。
//
// 这类错误本项目/ apktool 的宽松解析器照样读得出来（属性按名字匹配），但系统
// PackageParser 按资源 ID + 命名空间读取：类型错 → 解析抛异常/整包拒装，
// 命名空间错 → 属性被静默忽略（如 launcher 入口消失）。
func TestDualAPKHostManifestAttrs(t *testing.T) {
	const (
		pkg = "com.example.host"
		app = pkg + ".A"
		act = pkg + ".B"
	)
	mf, err := axml.Parse(dualAPKManifest(dualAPKManifestSpec{
		Pkg: pkg, Label: "组件更新", AppClass: app, ActClass: act,
		Perms:     []string{"android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.INTERNET"},
		MinSDK:    dualAPKHostMinSDK,
		TargetSDK: 33,
	}))
	if err != nil {
		t.Fatalf("宿主 Manifest 不可解析: %v", err)
	}
	root := mf.FindElement("manifest")
	if root == nil || root.AttrString("package") != pkg {
		t.Fatalf("package 属性错误")
	}
	// package 是 manifest 的普通属性（无命名空间）；挂上 android 命名空间后
	// 系统按无命名空间查找会读不到，包名直接为空。
	if a := root.Attr("package"); a == nil || a.NSName != "" {
		t.Fatalf("package 属性不应带命名空间")
	}
	nperm := 0
	for _, e := range mf.Elements {
		if e.Name != "uses-permission" {
			continue
		}
		nperm++
		if e.AttrNS(axml.AndroidNS, "name") == nil {
			t.Fatalf("uses-permission 的 name 缺少 android 命名空间")
		}
	}
	if nperm != 2 {
		t.Fatalf("uses-permission 数量 = %d，期望 2", nperm)
	}
	appEl := mf.FindElement("application")
	if a := appEl.AttrNS(axml.AndroidNS, "name"); a == nil || a.RawValue != app {
		t.Fatalf("application 的 android:name 错误")
	}
	actEl := mf.FindElement("activity")
	if a := actEl.AttrNS(axml.AndroidNS, "name"); a == nil || a.RawValue != act {
		t.Fatalf("activity 的 android:name 错误")
	}
	if a := actEl.Attr("exported"); a == nil || a.DataType != axml.TypeIntBoolean || a.Data != 1 {
		t.Fatalf("exported 必须是 TYPE_INT_BOOLEAN data=1")
	}
	if a := actEl.Attr("launchMode"); a == nil || a.DataType != axml.TypeIntDec || a.Data != 1 {
		t.Fatalf("launchMode 必须是 TYPE_INT_DEC=1（enum，而不是字符串）")
	}
	action := mf.FindElement("action")
	if action == nil || action.AttrNS(axml.AndroidNS, "name") == nil ||
		action.AttrNS(axml.AndroidNS, "name").RawValue != "android.intent.action.MAIN" {
		t.Fatalf("action 的 android:name 缺失或错误")
	}
	category := mf.FindElement("category")
	if category == nil || category.AttrNS(axml.AndroidNS, "name") == nil ||
		category.AttrNS(axml.AndroidNS, "name").RawValue != "android.intent.category.LAUNCHER" {
		t.Fatalf("category 的 android:name 缺失或错误")
	}
	// 属性名在资源映射表里的 ID 必须与公开 SDK 常量一致，否则框架按资源 ID
	// 读取时会得到 0（属性被忽略）。
	rm := dualAPKResourceMap(mf.Strings())
	strs := mf.Strings()
	for name, want := range map[string]uint32{
		"label": 0x01010001, "name": 0x01010003, "exported": 0x01010010,
		"launchMode": 0x0101001d, "allowBackup": 0x01010280,
		"minSdkVersion": 0x0101020c, "targetSdkVersion": 0x01010270,
	} {
		idx := -1
		for i, s := range strs {
			if s == name {
				idx = i
				break
			}
		}
		if idx < 0 {
			t.Fatalf("字符串池缺少属性名 %q", name)
		}
		got := binary.LittleEndian.Uint32(rm[8+4*idx:])
		if got != want {
			t.Fatalf("资源映射中 %q 的 ID=0x%08x，期望 0x%08x", name, got, want)
		}
	}
}

// TestDualAPKHostDexSemantics 对宿主 DEX 做指令级断言：这三处一旦回归，
// dex.Verify/Parse 全部照过，只在设备执行时才崩或无反应。
func TestDualAPKHostDexSemantics(t *testing.T) {
	key, err := pack.Key("b9-unit-key")
	if err != nil {
		t.Fatalf("派生密钥失败: %v", err)
	}
	const readSize = 12345
	code, err := dualAPKBuildHostDex(dualAPKDexSpec{
		ActClass:   "Lcom/example/host/B;",
		AssetKey:   "abcdefghijklmn.zip",
		PluginFile: "abcdefghijklmn.apk",
		PluginSize: readSize,
		Key:        key,
		TextUpdate: "u", TextDone: "d", TextFail: "f",
	})
	if err != nil {
		t.Fatalf("生成宿主 DEX 失败: %v", err)
	}
	f, err := dex.Parse(code)
	if err != nil {
		t.Fatalf("宿主 DEX 不可解析: %v", err)
	}
	if !insnsContainConst32(hostMethod(t, f, "drop"), readSize) {
		t.Fatalf("drop 未使用给定 PluginSize=%d 读取 assets", readSize)
	}
	if count, ok := findOpenWriteRange(f, hostMethod(t, f, "install")); !ok || count != 6 {
		t.Fatalf("openWrite 未改写为 3rc/6 寄存器: count=%d ok=%v", count, ok)
	}
	// PendingIntent flags：必须是 UPDATE_CURRENT|MUTABLE，绝不能含
	// FLAG_IMMUTABLE（0x04000000）——同时设置两者时 API 31+ 直接抛异常。
	if dualAPKPendingFlags != 0x0A000000 || dualAPKPendingFlags&0x04000000 != 0 {
		t.Fatalf("PendingIntent flags=0x%08x，期望 0x0A000000（UPDATE_CURRENT|MUTABLE）", dualAPKPendingFlags)
	}
	if !insnsContainConst32(hostMethod(t, f, "install"), dualAPKPendingFlags) {
		t.Fatalf("install 未使用 dualAPKPendingFlags")
	}
	if !insnsContainConst4(hostMethod(t, f, "status"), -1) {
		t.Fatalf("status 未使用 STATUS_PENDING_USER_ACTION=-1")
	}
	// decrypt 的入参寄存器基址：ins=3 时 blob/key/drop 在 registers-3..registers-1。
	// 写错这一处会读到未初始化的局部寄存器，dex.Verify/Parse 全部照过，只有
	// 真机执行才崩。这里用「第一条 array-length 的源寄存器」钉住入参基址。
	{
		ci := hostMethod(t, f, "decrypt")
		base := int(ci.Registers) - int(ci.Ins)
		l, err := dex.ParseInsns(ci.Insns)
		if err != nil || l.ItemCount() == 0 {
			t.Fatalf("解析 decrypt 字节码失败: %v", err)
		}
		w := l.ItemWords(0)
		if len(w) < 1 || byte(w[0]&0xff) != 0x21 || int(w[0]>>12) != base {
			t.Fatalf("decrypt 的首条 array-length 未以入参基址 v%d 为源（word=0x%04x）: SIV 解密会读到未初始化寄存器", base, w[0])
		}
	}
	// 关键字符串必须都进池：ConstString 走 jumbo 补丁，索引错位会静默
	// 指向别的字符串，结构校验发现不了。
	strs, err := f.AllStrings()
	if err != nil {
		t.Fatalf("读取宿主 DEX 字符串池失败: %v", err)
	}
	want := map[string]bool{
		"abcdefghijklmn.zip": true, "abcdefghijklmn.apk": true,
		"plugins": true, "base.apk": true,
		// SIV 解密走 native：算法串不再是 JCA 的 CBC，而是原生方法名与库名。
		dex.NativeDecrypt: true, "loadLibrary": true, dex.NativeLibName: true,
	}
	for _, s := range strs {
		delete(want, s)
	}
	if len(want) != 0 {
		t.Fatalf("宿主 DEX 字符串池缺少: %v", want)
	}
}

// hostMethod 在宿主 DEX 里按方法名找到并解析字节码。
func hostMethod(t *testing.T, f *dex.File, name string) *dex.CodeItemFull {
	t.Helper()
	var ci *dex.CodeItemFull
	err := f.AllMethods(func(_ string, desc string, m dex.EncodedMethod) error {
		if ci != nil || !strings.Contains(desc, "->"+name+"(") {
			return nil
		}
		c, err := f.ParseCodeItem(m.CodeOff)
		if err != nil {
			return err
		}
		ci = c
		return nil
	})
	if err != nil {
		t.Fatalf("遍历宿主 DEX 方法失败: %v", err)
	}
	if ci == nil {
		t.Fatalf("宿主 DEX 中找不到方法 %s", name)
	}
	return ci
}

// insnsContainConst32 判断字节码里是否有值为 want 的 const（31i）。
func insnsContainConst32(ci *dex.CodeItemFull, want int32) bool {
	l, err := dex.ParseInsns(ci.Insns)
	if err != nil {
		return false
	}
	for i := 0; i < l.ItemCount(); i++ {
		if !l.ItemIsInsn(i) {
			continue
		}
		w := l.ItemWords(i)
		if len(w) >= 3 && byte(w[0]&0xff) == 0x14 &&
			int32(uint32(w[1])|uint32(w[2])<<16) == want {
			return true
		}
	}
	return false
}

// insnsContainConst4 判断字节码里是否有值为 want 的 const/4。
func insnsContainConst4(ci *dex.CodeItemFull, want int8) bool {
	l, err := dex.ParseInsns(ci.Insns)
	if err != nil {
		return false
	}
	for i := 0; i < l.ItemCount(); i++ {
		if !l.ItemIsInsn(i) {
			continue
		}
		w := l.ItemWords(i)
		if len(w) < 1 || byte(w[0]&0xff) != 0x12 {
			continue
		}
		// 4 位立即数是有符号的：0xf 表示 -1，必须做符号扩展。
		if int8(byte(w[0]>>12)<<4)>>4 == want {
			return true
		}
	}
	return false
}

// findOpenWriteRange 找到指向 PackageInstaller$Session.openWrite 的
// invoke-virtual/range，返回其寄存器计数。
func findOpenWriteRange(f *dex.File, ci *dex.CodeItemFull) (count int, ok bool) {
	l, err := dex.ParseInsns(ci.Insns)
	if err != nil {
		return 0, false
	}
	for i := 0; i < l.ItemCount(); i++ {
		if !l.ItemIsInsn(i) {
			continue
		}
		w := l.ItemWords(i)
		if len(w) >= 3 && byte(w[0]&0xff) == 0x74 {
			if _, name, _, _, err := f.MethodFull(uint32(w[1])); err == nil && name == "openWrite" {
				return int(w[0] >> 8), true
			}
		}
	}
	return 0, false
}

// shannonEntropy 计算字节流的 Shannon 熵（bit/byte）。
func shannonEntropy(b []byte) float64 {
	var freq [256]int
	for _, c := range b {
		freq[c]++
	}
	n := float64(len(b))
	var e float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		e -= p * math.Log2(p)
	}
	return e
}

// hostDexForTest 生成一份宿主 DEX，供字段操作码等结构断言复用。
func hostDexForTest(t *testing.T) []byte {
	t.Helper()
	key, err := pack.Key("b9-unit-key")
	if err != nil {
		t.Fatalf("派生密钥失败: %v", err)
	}
	code, err := dualAPKBuildHostDex(dualAPKDexSpec{
		ActClass:   "Lcom/example/host/B;",
		AssetKey:   "abcdefghijklmn.zip",
		PluginFile: "abcdefghijklmn.apk",
		PluginSize: 12345,
		Key:        key,
		TextUpdate: "u", TextDone: "d", TextFail: "f",
	})
	if err != nil {
		t.Fatalf("生成宿主 DEX 失败: %v", err)
	}
	return code
}

// TestDualAPKHostDexFieldOpcodes 钉住「字段操作码必须与字段声明类型匹配」。
//
// 宿主类只有一个静态字段 s:Z（boolean）。曾经 SGet/SPut 无脑生成 int 家族的
// sget(0x60)/sput(0x67)，产物能签名、能安装、结构校验全过，但真机上 ART 直接
//
//	java.lang.VerifyError: Verifier rejected class …B:
//	  void …B.run(Context): expected field boolean …B.s to have type descriptor
//	  starting with 'I' or 'F' but found 'Z' in sget
//
// 秒退且不打业务日志——`dex.Verify`/`ValidateDescriptors` 这类结构校验看不出
// 「操作码与字段类型不匹配」，只有 ART 的校验器会拒绝。因此这里按操作码直接断言：
// 必须出现 sget-boolean(0x63)/sput-boolean(0x6a)，且不得出现 int 家族的 0x60/0x67。
func TestDualAPKHostDexFieldOpcodes(t *testing.T) {
	code := hostDexForTest(t)
	f, err := dex.Parse(code)
	if err != nil {
		t.Fatalf("宿主 DEX 不可解析: %v", err)
	}
	counts := map[int]int{}
	err = f.AllMethods(func(_ string, _ string, m dex.EncodedMethod) error {
		if m.CodeOff == 0 {
			return nil
		}
		ci, err := f.ParseCodeItem(m.CodeOff)
		if err != nil {
			return nil
		}
		l, err := dex.ParseInsns(ci.Insns)
		if err != nil {
			return nil
		}
		for i := 0; i < l.ItemCount(); i++ {
			if !l.ItemIsInsn(i) {
				continue
			}
			w := l.ItemWords(i)
			if len(w) == 0 {
				continue
			}
			counts[int(w[0]&0xff)]++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("遍历宿主方法失败: %v", err)
	}
	if counts[0x63] == 0 || counts[0x6a] == 0 {
		t.Fatalf("宿主未使用 sget-boolean(0x63)/sput-boolean(0x6a) 访问 boolean 字段：%v", counts)
	}
	if counts[0x60] != 0 || counts[0x67] != 0 {
		t.Fatalf("宿主仍用 int 家族的 sget/sput(0x60/0x67) 访问 boolean 字段，真机会被 ART 判 VerifyError：%v", counts)
	}
}
