package passes

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"apkguard/internal/axml"
	"apkguard/internal/config"
	"apkguard/internal/pipeline"
)

// ---- A18 Manifest 诱饵元数据 ----

// decoyMeta 往 AndroidManifest.xml 追加一批「像广泛集成第三方 SDK」的
// 权限、元数据、软硬件特性与包可见性声明。
//
// 为什么要做：A8 只丰富了组件表（<receiver>/<service>）。人工分析一个 APK 时，
// 权限视图（<uses-permission>）、元数据（<meta-data>）、特性（<uses-feature>）
// 与 <queries> 同样是第一眼入口。一个「接入了大量第三方 SDK」的应用，这些维度
// 本该同样杂乱；如果只有组件表热闹，反而自相矛盾、立刻暴露 A8 是填充。
//
// 实现方式与 A8 的 declareDecoyComponents 同构：axml.NewElement + axml.Rewrite
// **追加**新元素，绝不 SetAttr / Replace，因此不会覆盖 A8/B2 已写过的
// package / android:name / exported / uses-sdk 等语义关键属性。
//
// 全部四类注入都刻意选成「零运行影响」的形态，逐类的安全理由见 Run 内注释。
// 在通用 meta-data 之外，还刻意复刻参考样本的三组标志性噪音：
//   - 构建水印 cfg_mark_<UTC 时间戳>_<序号>_<随机串>（12~16 条）；
//   - 同名不同值四组 cfg_nonce / build_lane / seq_mark(int) / compile_ms；
//   - 9 条 com.<随机>.<随机>。名字在 DEX 里零引用，纯噪音。
type decoyMeta struct{}

func (decoyMeta) ID() config.FeatureID { return "A18" }
func (decoyMeta) In() pipeline.Level   { return pipeline.LevelZip }
func (decoyMeta) Out() pipeline.Level  { return pipeline.LevelZip }

// defaultDecoyMetaCount 是未指定 -decoy-meta-count 时的默认注入总量。
//
// 20~40 是「像集成方」与「不至于大到离谱」之间的折中：太少看不出 SDK 生态，
// 太多会让权限表长得不合常理。
const defaultDecoyMetaCount = 30

func (d *decoyMeta) Run(_ context.Context, art *pipeline.Artifact, opts *config.Options) error {
	entry := pipeline.Find(art, "AndroidManifest.xml")
	if entry == nil {
		// 与 A8 一致：没有 Manifest 就无从注入，交由 E3 自检去报错。
		return nil
	}
	data, err := entry.Data()
	if err != nil {
		return fmt.Errorf("A18 读取 Manifest 失败: %w", err)
	}
	mf, err := axml.Parse(data)
	if err != nil {
		return fmt.Errorf("A18 解析 Manifest 失败: %w", err)
	}
	if mf.FindElement("manifest") == nil {
		return nil
	}
	// <meta-data> 是 <application> 的子元素；application 缺失时只跳过这一类。
	hasApp := mf.FindElement("application") != nil

	rnd := newRand(opts.Seed)
	n := opts.DecoyMetaCount
	if n <= 0 {
		n = defaultDecoyMetaCount
	}
	permWant, metaWant, featWant, queryWant := splitDecoyMeta(n)

	// 收集既有名字，避免与真实声明重名/重复注入。
	usedPerm := map[string]bool{}
	usedFeat := map[string]bool{}
	usedMeta := map[string]bool{}
	usedPkg := map[string]bool{}
	// origMeta 只记录**原 Manifest 已有**的 meta-data 名：同名不同值四组
	// 需要故意重复，但若应用本来就有同名键，再多插一条不同值会让读取方
	// 拿到不确定的值，因此对这类键整组跳过（见 decoyMetaExtras）。
	origMeta := map[string]bool{}
	for _, e := range mf.Elements {
		switch e.Name {
		case "uses-permission":
			usedPerm[e.AttrString("name")] = true
		case "uses-feature":
			usedFeat[e.AttrString("name")] = true
		case "meta-data":
			usedMeta[e.AttrString("name")] = true
			origMeta[e.AttrString("name")] = true
		case "package":
			usedPkg[e.AttrString("name")] = true
		}
	}

	var add []axml.NewElement
	addedPerm, addedMeta, addedFeat, addedQuery := 0, 0, 0, 0
	markCount, dupeCount, comCount := 0, 0, 0
	var intPatches []intMetaPatch
	budget := func(want int) int { return want*50 + 100 }

	// ① <uses-permission android:name="com.<假包名>.permission.<大写名>">
	//
	// **必须只用系统未定义的自定义权限名，这是不可妥协的安全约束。**
	// 真实危险权限（READ_CONTACTS、ACCESS_FINE_LOCATION 等）一旦出现在清单里，
	// 系统会在安装/运行时要求用户授权，并可能真的改变运行时行为（权限弹窗、
	// 权限拒绝导致的逻辑分支）；而「系统未定义的权限名」找不到任何定义方，
	// 安装器会把它当成普通声明**完全忽略**，不弹窗、不授权、零运行影响。
	// 因此这里的名字一律用第三方 SDK 风格的假命名空间 com.<vendor>.permission.XXX，
	// 绝不使用 android.permission.* 前缀。
	for tries := 0; addedPerm < permWant && tries < budget(permWant); tries++ {
		name := fmt.Sprintf("%s.permission.%s",
			fakePermVendors[rnd.Intn(len(fakePermVendors))],
			fakePermSuffixes[rnd.Intn(len(fakePermSuffixes))])
		if usedPerm[name] {
			continue
		}
		usedPerm[name] = true
		add = append(add, axml.NewElement{
			Parent:      "manifest",
			ParentIndex: 0,
			Name:        "uses-permission",
			Attrs:       []axml.NewAttr{axml.StringAttr(axml.AndroidNS, "name", name)},
		})
		addedPerm++
	}

	// ② <uses-feature android:name="android.hardware.xxx" android:required="false">
	//
	// **required="false" 是关键，绝不能用 true。** Play 商店按 required="true"
	// 的特性做设备兼容性过滤：一旦把相机/GPS/NFC 之类声明成必需，没有对应硬件的
	// 设备就会被商店判定为不兼容、直接无法安装。required="false" 只作为
	// 「可选使用」的信息记录，不参与任何过滤，对运行也没有影响。
	for i := 0; addedFeat < featWant && i < len(decoyFeatureNames)+budget(featWant); i++ {
		var name string
		if i < len(decoyFeatureNames) {
			name = decoyFeatureNames[i]
		} else {
			// 列表用尽（真实应用已占满同名特性）时退化为合成名，避免死循环。
			name = fmt.Sprintf("android.hardware.%s.probe", randSeg(rnd, 8))
		}
		if usedFeat[name] {
			continue
		}
		usedFeat[name] = true
		add = append(add, axml.NewElement{
			Parent:      "manifest",
			ParentIndex: 0,
			Name:        "uses-feature",
			Attrs: []axml.NewAttr{
				axml.StringAttr(axml.AndroidNS, "name", name),
				axml.BoolAttr(axml.AndroidNS, "required", false),
			},
		})
		addedFeat++
	}

	// ③ <meta-data android:name="..." android:value="...">
	//
	// 名字要「听起来像常见 SDK 的配置键」，否则一眼就假；但**不能伪造会被
	// 系统或已有 SDK 真的读取的键**，否则会改变行为甚至启动报错。取舍如下：
	//   - 明确回避那些确定被读取的键：com.google.android.gms.version（GMS 会
	//     校验其版本资源，值不对会报错）、com.google.android.gms.ads.APPLICATION_ID
	//     （AdMob 会校验格式）、firebase_analytics_collection_enabled、
	//     com.facebook.sdk.ApplicationId 等；
	//   - 只选「看起来像、但实际不是任何 SDK 读取的那个精确键」——例如真实
	//     Umeng 推送键是 UMENG_APPKEY，这里用带命名空间的小写 com.umeng.message.appkey；
	//     真实 Bugly 版本键是全大写 BUGLY_APP_VERSION，这里用 bugly_app_version；
	//   - 值一律给成对应厂商期望的**合法形态**（hex 串 / URL / 版本号 / 布尔 /
	//     base64 / 数字），因此即使某个键偶然被某个 SDK 读到，拿到的也是格式
	//     正确、不会被解析器拒收的值，而不是畸形数据。
	// 这份清单与"零运行影响"的残余风险在代码评审时需重新确认，见文件末尾说明。
	if hasApp {
		for i := 0; addedMeta < metaWant && i < len(decoyMetaKeys)+budget(metaWant); i++ {
			var key, kind string
			if i < len(decoyMetaKeys) {
				key, kind = decoyMetaKeys[i].key, decoyMetaKeys[i].kind
			} else {
				key = fmt.Sprintf("%s.%s.sdk", fakePermVendors[rnd.Intn(len(fakePermVendors))], randSeg(rnd, 6))
				kind = "hex"
			}
			if usedMeta[key] {
				continue
			}
			usedMeta[key] = true
			add = append(add, axml.NewElement{
				Parent:      "application",
				ParentIndex: 0,
				Name:        "meta-data",
				Attrs: []axml.NewAttr{
					axml.StringAttr(axml.AndroidNS, "name", key),
					axml.StringAttr(axml.AndroidNS, "value", metaValue(rnd, kind)),
				},
			})
			addedMeta++
		}

		// ③b 样本标志性的三组额外 meta-data（构建水印 / 同名不同值 / 随机
		// 命名空间）。时间戳必须取 opts.UnifiedStamp()——用 time.Now() 会破坏
		// 「同 seed 完全可复现」，也会与 A14 统一后的 ZIP 时间线脱节。
		stamp, serr := opts.UnifiedStamp()
		if serr != nil {
			return fmt.Errorf("A18 获取统一时间戳失败: %w", serr)
		}
		extras, cnt := decoyMetaExtras(rnd, stamp, origMeta)
		for _, ex := range extras {
			add = append(add, axml.NewElement{
				Parent:      "application",
				ParentIndex: 0,
				Name:        "meta-data",
				Attrs: []axml.NewAttr{
					axml.StringAttr(axml.AndroidNS, "name", ex.name),
					axml.StringAttr(axml.AndroidNS, "value", ex.value),
				},
			})
			usedMeta[ex.name] = true
			if ex.asInt {
				intPatches = append(intPatches, intMetaPatch{name: ex.name, val: ex.intv})
			}
		}
		addedMeta += len(extras)
		markCount, dupeCount, comCount = cnt.marks, cnt.dupes, cnt.coms
	}

	// ④ <queries><package android:name="..."/></queries>
	//
	// <queries> 声明的是 Android 11+ 的包可见性：查询一个**不存在的包名**
	// 不会报错、不会授予额外可见性、也没有任何副作用，只是让静态分析者看到
	// 「这里探测过一堆第三方包」。反之若填入真实存在的包名，会真的改变本应用
	// 对它们的可见性判断，属于语义改动，因此**只插不存在的包名**：用带随机
	// token 的合成名保证设备上不可能存在同名包。
	queryNames := make([]string, 0, queryWant)
	for tries := 0; len(queryNames) < queryWant && tries < budget(queryWant); tries++ {
		name := fmt.Sprintf("%s.%s.sdk",
			decoyQueryVendors[rnd.Intn(len(decoyQueryVendors))], randSeg(rnd, 8))
		if usedPkg[name] {
			continue
		}
		usedPkg[name] = true
		queryNames = append(queryNames, name)
	}

	existingQueries := mf.FindElement("queries")
	if len(queryNames) > 0 {
		if existingQueries == nil {
			// 先建空的 <queries> 容器；<package> 子元素在第二遍写入。
			add = append(add, axml.NewElement{Parent: "manifest", ParentIndex: 0, Name: "queries"})
		} else {
			// 已有 <queries> 就追加到它里面，避免出现重复容器。
			for _, q := range queryNames {
				add = append(add, axml.NewElement{Parent: "queries", ParentIndex: 0, Name: "package",
					Attrs: []axml.NewAttr{axml.StringAttr(axml.AndroidNS, "name", q)}})
			}
			addedQuery = len(queryNames)
		}
	}

	// 所有新元素都插在父元素的结束块之前（matchingEnd 按 start/end 配对定位），
	// 因此 <uses-permission>/<uses-feature>/<queries> 落在 </manifest> 前、
	// <meta-data> 落在 </application> 前。既有的元素块原样搬运，不被动到。
	out, err := mf.Rewrite(axml.Edit{AddElements: add})
	if err != nil {
		return fmt.Errorf("A18 写入 Manifest 失败: %w", err)
	}

	// NewElement 只能表达「没有子元素的单个元素」，无法一次生成嵌套结构；
	// 因此 <queries> 的 <package> 子元素需要等容器写入后、重新解析再写第二遍。
	if existingQueries == nil && len(queryNames) > 0 {
		mf2, err := axml.Parse(out)
		if err != nil {
			return fmt.Errorf("A18 写入 <queries> 后无法重新解析: %w", err)
		}
		pkgs := make([]axml.NewElement, 0, len(queryNames))
		for _, q := range queryNames {
			pkgs = append(pkgs, axml.NewElement{Parent: "queries", ParentIndex: 0, Name: "package",
				Attrs: []axml.NewAttr{axml.StringAttr(axml.AndroidNS, "name", q)}})
		}
		out, err = mf2.Rewrite(axml.Edit{AddElements: pkgs})
		if err != nil {
			return fmt.Errorf("A18 写入 <queries> 子元素失败: %w", err)
		}
		addedQuery = len(queryNames)
	}

	// int 型 meta-data（seq_mark）需要把已按字符串写入的属性就地改成
	// Res_value.dataType=TYPE_INT_DEC：axml 包的 NewAttr 目前只支持字符串与
	// 布尔属性，而 int 是样本里最「不像诱饵」的细节，必须在最终字节上回填。
	// 必须排在 <queries> 第二遍 Rewrite 之后（那时 out 的布局才会定型）。
	out, err = patchIntMetaValue(out, intPatches)
	if err != nil {
		return fmt.Errorf("A18 写入 int 型 meta-data 失败: %w", err)
	}

	// 硬约束：写回后必须能用 axml.Parse 重新解析。Manifest 一旦写坏（字符串池
	// 越界、块长度错位），系统在启动时解析失败会让应用启动即死（实测样本与
	// 真实应用都出现过 ClassNotFoundException 一类的一启动就崩），因此这里在
	// 落盘前再解析一次，宁可报错也不产出坏包。int 回填后的 dataType=0x10
	// 也在这次解析的覆盖范围内。
	if _, err := axml.Parse(out); err != nil {
		return fmt.Errorf("A18 写入后 Manifest 无法解析（拒绝产出坏包）: %w", err)
	}
	if err := entry.SetData(out, true); err != nil {
		return fmt.Errorf("A18 写回 Manifest 失败: %w", err)
	}

	art.Note("A18 Manifest 诱饵元数据：自定义权限 %d 条（系统未定义、安装器完全忽略，零运行影响）、"+
		"meta-data %d 条（通用键 %d 条只选无人读取的；构建水印 cfg_mark_<UTC 时间戳>_… %d 条；"+
		"同名不同值四组 %d 条：cfg_nonce/build_lane/seq_mark(int)/compile_ms；com.<随机>.<随机> %d 条）、"+
		"uses-feature %d 条（全部 required=false，不影响商店设备筛选）、"+
		"<queries> 包名 %d 条（均为不存在的包名）；只追加，不改动 A8/B2 已写入的元素",
		addedPerm, addedMeta, addedMeta-markCount-dupeCount-comCount, markCount, dupeCount, comCount,
		addedFeat, addedQuery)
	art.Stat("A18.perms", fmt.Sprint(addedPerm))
	art.Stat("A18.meta", fmt.Sprint(addedMeta))
	art.Stat("A18.mark", fmt.Sprint(markCount))
	art.Stat("A18.dupes", fmt.Sprint(dupeCount))
	art.Stat("A18.commeta", fmt.Sprint(comCount))
	art.Stat("A18.features", fmt.Sprint(addedFeat))
	art.Stat("A18.queries", fmt.Sprint(addedQuery))
	return nil
}

// splitDecoyMeta 把总量 n 拆成四类注入的条数。
//
// 权重近似「权限 > 元数据 > 特性 > 包可见性」，与真实应用里各维度的常见
// 规模一致；n 足够大时保证四类都至少出现一条，避免某一维度完全缺席而
// 与「广泛集成 SDK」的叙事矛盾。
func splitDecoyMeta(n int) (perm, meta, feat, query int) {
	perm = n * 35 / 100
	meta = n * 30 / 100
	feat = n * 20 / 100
	query = n - perm - meta - feat
	if n >= 4 {
		if perm == 0 {
			perm = 1
		}
		if meta == 0 {
			meta = 1
		}
		if feat == 0 {
			feat = 1
		}
		query = n - perm - meta - feat
		if query < 1 {
			query = 1
		}
	}
	return perm, meta, feat, query
}

// fakePermVendors 是用于构造「假自定义权限命名空间」的第三方 SDK 包名。
//
// 用第三方 SDK 风格而不是应用自身包名：分析者看到 com.umeng.sdk.permission.X
// 会认为「接了某推送/统计 SDK」，正是我们要营造的形态。
var fakePermVendors = []string{
	"com.umeng.sdk",
	"com.tencent.sdk",
	"com.baidu.sdk",
	"com.alibaba.sdk",
	"com.google.fcm",
	"com.huawei.hms",
	"com.xiaomi.sdk",
	"com.meizu.sdk",
	"com.vivo.sdk",
	"com.oppo.sdk",
	"com.qcloud.sdk",
	"com.bytedance.sdk",
	"com.netease.sdk",
	"com.amap.sdk",
}

// fakePermSuffixes 是权限名的后半段，全大写以符合 Android 权限命名习惯。
var fakePermSuffixes = []string{
	"ACCESS_SDK_SERVICE", "PUSH_MESSAGE", "READ_ANALYTICS",
	"DEVICE_ID", "NETWORK_STATUS", "LOCATION_SERVICE",
	"BACKGROUND_SYNC", "UPDATE_CONFIG", "CRASH_REPORT",
	"STATISTICS_WRITE", "DOWNLOAD_CACHE", "REMOTE_CONFIG",
	"OAUTH_TOKEN", "AD_TRACKING", "CLOUD_SYNC",
	"ACCOUNT_BIND", "SESSION_DATA", "TELEMETRY_SEND",
}

// decoyFeatureNames 是注入的 <uses-feature android:name>。
//
// 全部使用真实存在的硬件特性名（required=false 时只多一条信息，不触发过滤），
// 这样特性视图看起来与真实应用完全一致；合成一个不存在的特性名反而更可疑。
var decoyFeatureNames = []string{
	"android.hardware.camera",
	"android.hardware.camera.autofocus",
	"android.hardware.bluetooth",
	"android.hardware.bluetooth_le",
	"android.hardware.location",
	"android.hardware.location.gps",
	"android.hardware.location.network",
	"android.hardware.wifi",
	"android.hardware.microphone",
	"android.hardware.nfc",
	"android.hardware.sensor.accelerometer",
	"android.hardware.sensor.gyroscope",
	"android.hardware.sensor.light",
	"android.hardware.sensor.proximity",
	"android.hardware.telephony",
	"android.hardware.touchscreen",
	"android.hardware.usb.host",
	"android.hardware.screen.portrait",
	"android.hardware.screen.landscape",
	"android.hardware.fingerprint",
}

// decoyMetaKey 描述一条待注入的 <meta-data>：键名与值的形态。
type decoyMetaKey struct {
	key  string
	kind string // num / hex / wx / url / b64 / ver / bool / channel
}

// decoyMetaKeys 是注入的 meta-data 键清单。
//
// 选键原则（与 Run 中 ③ 的注释一致）：名字要像常见 SDK 的配置键，但刻意避开
// 那些**确定会被读取**的精确键；值按厂商习惯给成合法形态。清单刻意混入
// 统计/推送/崩溃上报/地图/云存储等不同门类，让元数据视图更像真实的多 SDK 集成。
var decoyMetaKeys = []decoyMetaKey{
	// Umeng：真实推送键是 UMENG_APPKEY（全大写无命名空间），这里用命名空间小写形式。
	{"com.umeng.message.appkey", "hex"},
	{"com.umeng.analytics.report_url", "url"},
	// Bugly：真实版本键是全大写 BUGLY_APP_VERSION；小写形态不是被读取的那个键。
	{"bugly_app_version", "ver"},
	{"bugly_report_url", "url"},
	{"com.tencent.bugly.app_key", "hex"},
	// 支付宝：真实键带 API_KEY 形态，这里用 appkey 后缀以区分。
	{"com.alipay.android.app.appkey", "hex"},
	// 高德：真实键是 com.amap.api.v2.apikey，这里换成 location 段。
	{"com.amap.api.location.apikey", "hex"},
	// 百度：真实键是 com.baidu.lbsapi.API_KEY，这里少一个下划线。
	{"com.baidu.lbsapi.APIKEY", "hex"},
	{"com.sina.weibo.sdk.appkey", "hex"},
	// 微信：真实键是 com.tencent.mm.opensdk.open_appid，这里省略 open_。
	{"com.tencent.mm.opensdk.appid", "wx"},
	{"com.huawei.hianalytics.appkey", "hex"},
	{"com.huawei.hms.push.appid", "num"},
	// 推送厂商：用 sdk_version（纯信息性键）而非 app_id/app_key，避免影响推送初始化。
	{"com.xiaomi.push.sdk_version", "ver"},
	{"com.meizu.flyme.push.sdk_version", "ver"},
	{"com.vivo.push.sdk_version", "ver"},
	{"com.oppo.push.sdk_version", "ver"},
	{"com.alibaba.sdk.android.appkey", "hex"},
	{"com.netease.nim.appkey", "hex"},
	{"com.qcloud.cos.appid", "num"},
	{"com.tencent.tinker.app_version", "ver"},
	// Firebase/Crashlytics：真实开关键是 firebase_crashlytics_collection_enabled /
	// firebase_analytics_collection_enabled，这里用不会被读取的 build_tags / session_timeout。
	{"com.google.firebase.crashlytics.build_tags", "channel"},
	{"com.google.firebase.analytics.session_timeout", "num"},
	// 旧版 GMS Analytics（v3，早已废弃）的 campaign 参数；现代应用不会读取。
	{"com.google.android.gms.analytics.campaign", "b64"},
	{"com.google.android.gms.measurement.enabled", "bool"},
}

// decoyQueryVendors 是 <queries> 里合成包名使用的厂商前缀。
//
// 包名再拼一个随机 token（如 com.tencent.ab12cd34.sdk），保证设备上不可能
// 存在同名应用——满足「只插不存在的包名」的硬要求。
var decoyQueryVendors = []string{
	"com.umeng", "com.tencent", "com.baidu", "com.alibaba",
	"com.huawei", "com.xiaomi", "com.meizu", "com.vivo",
	"com.oppo", "com.netease",
}

// ---- 样本标志性的三组额外 meta-data ----

const (
	// decoyMarkTimeLayout 是构建水印时间戳的格式，对齐样本
	// cfg_mark_20260919220102_…。时间取 UTC，来源必须是 opts.UnifiedStamp()。
	decoyMarkTimeLayout = "20060102150405"
	// decoyMarkMin/decoyMarkSpan：水印条数 = 12 + rnd.Intn(5) ∈ [12,16]，
	// 与样本的 12+ 条一致。
	decoyMarkMin  = 12
	decoyMarkSpan = 5
	// decoyComMetaCount 是 com.<随机>.<随机> 形式的条数（样本 9 条）。
	decoyComMetaCount = 9
)

// decoyMetaExtra 是一条额外 meta-data。
type decoyMetaExtra struct {
	name  string
	value string // 十进制文本；asInt 为 true 时同值按 int32 写入
	asInt bool
	intv  int32
}

// decoyMetaCounts 汇总额外 meta-data 的分类条数（写入统计与日志）。
type decoyMetaCounts struct {
	marks, dupes, coms int
}

// reservedMetaKeys 是「确定会被系统或流行 SDK 读取」的 meta-data 精确键名。
// 注入的任何名字（含随机合成的 com.<x>.<y>）都不得命中这些键，否则会改变
// 真实行为甚至导致启动失败。
var reservedMetaKeys = []string{
	"com.google.android.gms.version",
	"com.google.android.gms.ads.APPLICATION_ID",
	"com.google.android.gms.ads.AD_MANAGER_APP",
	"firebase_analytics_collection_enabled",
	"firebase_crashlytics_collection_enabled",
	"com.facebook.sdk.ApplicationId",
	"com.facebook.sdk.ClientToken",
	"UMENG_APPKEY",
	"UMENG_CHANNEL",
	"BUGLY_APP_VERSION",
	"BUGLY_APPID",
	"com.amap.api.v2.apikey",
	"com.baidu.lbsapi.API_KEY",
	"com.tencent.mm.opensdk.open_appid",
	"com.google.firebase.messaging.default_notification_channel_id",
}

// reservedMetaPrefixes 是保留命名空间前缀：随机生成的名字一旦落入这些前缀，
// 即便不是已知精确键也可能被对应 SDK 扫描，直接换名。
var reservedMetaPrefixes = []string{
	"com.google.android.gms.",
	"com.google.firebase.",
	"com.facebook.",
	"com.tencent.mm.opensdk.",
	"com.amap.api.",
	"com.baidu.lbsapi.",
	"com.umeng.",
	"com.tencent.bugly.",
}

// metaKeyReserved 报告 meta-data 键名是否落在保留名单内。
// 大小写不敏感比较：aapt/读取方对键名大小写的处理并不一致，保守取严。
func metaKeyReserved(name string) bool {
	low := strings.ToLower(name)
	for _, k := range reservedMetaKeys {
		if low == strings.ToLower(k) {
			return true
		}
	}
	for _, p := range reservedMetaPrefixes {
		if strings.HasPrefix(low, p) {
			return true
		}
	}
	return false
}

// decoyMetaExtras 构造参考样本的三组额外 meta-data：
//
//	① 构建水印 cfg_mark_<UTC 时间戳>_<序号>_<随机串>，值也是随机串；
//	② 同名不同值四组：cfg_nonce / build_lane / seq_mark(int) / compile_ms；
//	③ 9 条 com.<随机>.<随机>，值为 28~50 字符随机串。
//
// 全部由 seed 与 stamp 确定性派生（不能用 time.Now()，否则同 seed 不可复现）；
// origMeta 是原 Manifest 已有的 meta-data 名，四组重名键若与它撞名则整组跳过
// ——那属于应用的真实配置，插不同值会让读取方拿到不确定的结果。
func decoyMetaExtras(rnd *rand.Rand, stamp time.Time, origMeta map[string]bool) ([]decoyMetaExtra, decoyMetaCounts) {
	var out []decoyMetaExtra
	var cnt decoyMetaCounts
	markTS := stamp.UTC().Format(decoyMarkTimeLayout)

	// ① 构建水印：同一条水印的时间戳与序号都相同（样本 12+ 条共用
	// 20260919220102），用随机后缀保证条目之间不重名。
	marks := decoyMarkMin + rnd.Intn(decoyMarkSpan)
	for i := 0; i < marks; i++ {
		out = append(out, decoyMetaExtra{
			name:  fmt.Sprintf("cfg_mark_%s_%02d_%s", markTS, i+1, randSeg(rnd, 6)),
			value: randSeg(rnd, 28+rnd.Intn(23)), // 28~50 字符
		})
	}
	cnt.marks = marks

	// ② 同名不同值四组，名字取样本同款语义名。
	appendPair := func(name string, a, b decoyMetaExtra) {
		if origMeta[name] {
			return
		}
		a.name, b.name = name, name
		out = append(out, a, b)
		cnt.dupes += 2
	}
	hexVal := func() string { return hex.EncodeToString(randBytes(rnd, 16)) }
	appendPair("cfg_nonce", decoyMetaExtra{value: hexVal()}, decoyMetaExtra{value: hexVal()})
	laneVal := func() string { return "lane_" + hex.EncodeToString(randBytes(rnd, 4)) }
	appendPair("build_lane", decoyMetaExtra{value: laneVal()}, decoyMetaExtra{value: laneVal()})
	// seq_mark 必须是 int 类型（TYPE_INT_DEC）——样本里最「不像诱饵」的细节。
	seq1 := 100000 + rnd.Int31n(900000)
	seq2 := 100000 + rnd.Int31n(900000)
	for seq2 == seq1 {
		seq2 = 100000 + rnd.Int31n(900000)
	}
	appendPair("seq_mark",
		decoyMetaExtra{value: strconv.FormatInt(int64(seq1), 10), asInt: true, intv: seq1},
		decoyMetaExtra{value: strconv.FormatInt(int64(seq2), 10), asInt: true, intv: seq2})
	// compile_ms 与统一时间戳同一条时间线，偏差控制在 ±45 秒内，两个值不同。
	base := stamp.UnixMilli()
	ms1 := base + int64(rnd.Intn(91)-45)*1000
	ms2 := base + int64(rnd.Intn(91)-45)*1000
	for ms2 == ms1 {
		ms2 = base + int64(rnd.Intn(91)-45)*1000
	}
	msVal := func(v int64) decoyMetaExtra {
		return decoyMetaExtra{value: strconv.FormatInt(v, 10)}
	}
	appendPair("compile_ms", msVal(ms1), msVal(ms2))

	// ③ com.<随机>.<随机>：小写字母段，避开保留 SDK 命名空间与已有名字。
	for i := 0; i < decoyComMetaCount; {
		name := fmt.Sprintf("com.%s.%s", randLower(rnd, 5+rnd.Intn(6)), randLower(rnd, 5+rnd.Intn(6)))
		if origMeta[name] || metaKeyReserved(name) {
			continue
		}
		out = append(out, decoyMetaExtra{name: name, value: randSeg(rnd, 28+rnd.Intn(23))})
		i++
	}
	cnt.coms = decoyComMetaCount
	return out, cnt
}

// randLower 生成由小写字母组成的随机段（用于包名段，保证是合法 Java 包片段）。
func randLower(r *rand.Rand, n int) string {
	const alpha = "abcdefghijklmnopqrstuvwxyz"
	out := make([]byte, n)
	for i := range out {
		out[i] = alpha[r.Intn(len(alpha))]
	}
	return string(out)
}

// intMetaPatch 描述一条要编码成 TYPE_INT_DEC 的 <meta-data>。
// 同名条目按 Manifest 中的出现顺序依次匹配（seq_mark 两条值不同）。
type intMetaPatch struct {
	name string
	val  int32
}

// patchIntMetaValue 把已写入 Manifest 的指定 <meta-data> 的 android:value
// 从字符串就地改成十进制整数（Res_value.dataType = TYPE_INT_DEC，0x10）。
//
// 为什么走字节级回填：internal/axml 的 NewAttr 目前只支持字符串/布尔属性，
// 而 seq_mark 用 int 是参考样本里最难伪装的细节之一（同名不同值 + 类型多样）。
// 属性区布局由 AXML 规范固定：start element 块 = 16 字节 node + attrExt
// （attributeStart 通常 20）+ 每条属性 20 字节；Element.HeaderOff 是公开字段。
// 只改 Res_value 的 rawValue/size/dataType/data 四个字段，字符串池与
// resource map 完全不受影响；写完后调用方还会用 axml.Parse 再校验一次。
func patchIntMetaValue(data []byte, patches []intMetaPatch) ([]byte, error) {
	if len(patches) == 0 {
		return data, nil
	}
	f, err := axml.Parse(data)
	if err != nil {
		return nil, err
	}
	queue := map[string][]int32{}
	for _, p := range patches {
		queue[p.name] = append(queue[p.name], p.val)
	}
	for _, e := range f.Elements {
		if e.Name != "meta-data" {
			continue
		}
		name := e.AttrString("name")
		q := queue[name]
		if len(q) == 0 {
			continue
		}
		val := q[0]
		queue[name] = q[1:]

		idx := -1
		for i := range e.Attrs {
			if e.Attrs[i].Name == "value" {
				idx = i
				break
			}
		}
		if idx < 0 {
			return nil, fmt.Errorf("int 型 meta-data %q 缺少 android:value", name)
		}
		if e.HeaderOff+36 > len(data) {
			return nil, fmt.Errorf("int 型 meta-data %q 的块偏移越界", name)
		}
		attrStart := int(binary.LittleEndian.Uint16(data[e.HeaderOff+24:]))
		off := e.HeaderOff + 16 + attrStart + idx*20
		if off+20 > len(data) {
			return nil, fmt.Errorf("int 型 meta-data %q 的属性越界", name)
		}
		if data[off+15] != axml.TypeString {
			return nil, fmt.Errorf("int 型 meta-data %q 的 value 不是字符串（type=0x%02x），拒绝改写",
				name, data[off+15])
		}
		binary.LittleEndian.PutUint32(data[off+8:], 0xffffffff) // rawValue 无原始文本
		binary.LittleEndian.PutUint16(data[off+12:], 8)         // Res_value.size
		data[off+14] = 0                                        // res0
		data[off+15] = axml.TypeIntDec
		binary.LittleEndian.PutUint32(data[off+16:], uint32(val))
	}
	for name, q := range queue {
		if len(q) > 0 {
			return nil, fmt.Errorf("有 %d 条 int 型 meta-data %q 未找到可改写的元素", len(q), name)
		}
	}
	return data, nil
}

// metaValue 按形态生成一个「合法但随机」的 meta-data 值。
func metaValue(r *rand.Rand, kind string) string {
	switch kind {
	case "num":
		return fmt.Sprint(100000 + r.Int63n(900000000))
	case "hex":
		return hex.EncodeToString(randBytes(r, 16)) // 32 位 hex，像 API key / appkey
	case "wx":
		return "wx" + hex.EncodeToString(randBytes(r, 8)) // 微信 AppID 形态
	case "url":
		return fmt.Sprintf("https://%s/v%d/%s.json",
			metaHosts[r.Intn(len(metaHosts))], 1+r.Intn(3), randSeg(r, 8))
	case "b64":
		return base64.StdEncoding.EncodeToString(randBytes(r, 18))
	case "ver":
		return fmt.Sprintf("%d.%d.%d", 1+r.Intn(9), r.Intn(20), r.Intn(50))
	case "bool":
		if r.Intn(2) == 0 {
			return "false"
		}
		return "true"
	case "channel":
		return []string{"release", "official", "appstore"}[r.Intn(3)]
	default:
		return fmt.Sprint(r.Int63())
	}
}

// metaHosts 是 URL 型 meta-data 值使用的假配置域名。
var metaHosts = []string{
	"conf.sdkcfg.net",
	"api.tracker-service.com",
	"cfg.pushcloud.cn",
	"sdkconf.analytics.io",
	"api.mobstat.cn",
}

// randBytes 生成 n 个随机字节（仅用于制造形态合理的假数据，非安全用途）。
func randBytes(r *rand.Rand, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.Intn(256))
	}
	return b
}

// 残余风险说明（供评审复核）：
//
// meta-data 键的"无人读取"无法用代码静态证明——任何 SDK 都可以读取任意键名。
// 本实现的取舍是「非精确匹配 + 合法值形态」：列出的键都刻意与已知功能键
// （GMS 版本、AdMob 应用 ID、Firebase 采集开关、Facebook ApplicationId 等）
// 存在差异，且即使被读取，值也是对应厂商期望的格式，不会因解析失败而崩溃。
// 若后续发现某个键确被广泛读取，应把它从 decoyMetaKeys 中移除。
