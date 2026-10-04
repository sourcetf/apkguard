package dex

import (
	"fmt"
	"sort"
	"strings"
)

// RenameConfig 控制名字混淆的行为。
type RenameConfig struct {
	// Prefix 是生成名称的字母表起点（默认 "a"），仅影响可读性。
	Prefix string
	// Keep 是保留规则：命中任一规则的类/成员不会被重命名。
	Keep []string
	// ObfuscateFields 为 true 时同时重命名字段。
	ObfuscateFields bool
	// RenameResourceIDs 为 true 时，aapt 生成的资源 ID 类（简单名为 R 或
	// R$<Type>，且静态字段带资源段常量）参与类名与字段名混淆。
	//
	// 为什么可以安全改名：DEX 对 R 类字段的引用走 field_ids 的显式引用，
	// 改名由既有的字段引用改写通道（planFields + 重建重排）统一完成；字段的
	// static_values（资源 ID 常量）由重建器逐值保留并按新字段顺序重排，
	// 因此「字段名 -> 资源 ID」的绑定不变。
	//
	// 放行仍是保守的（宁少勿多）：
	//   - Landroid/...（平台 R）与一切命中原有 keep 规则的类照旧保留；
	//   - R$Type 需至少一个 static 字段满足下列之一才放行：
	//     a) static int 字段的 static_values 常量落在 0x7f/0x01 资源段；
	//     b) static int[] 字段（R$styleable 的形态）的 static_values 是数组，
	//     元素全部为数值型且 ≥90% 落在资源段——数组必须逐字节原样保留；
	//     非数值元素会让重建走索引重映射、无法保证逐字节，因此直接判不满足；
	//   - 外层 R 只有在本 DEX 内全部 R$Type 都放行时才一起放行；
	//   - 字段名若出现在 const-string、注解等非字段引用处，整个类不改
	//     （引用完整性无法确认，见 resourceFieldNamesSafe）；
	//   - DEX 含本工具无法重建的 call_site_ids / method_handles 段时，
	//     全部 R 类不改（见 checkRebuildSupported）。
	//
	// 默认 false（dex 库 API 保持旧行为）；A1 pass 默认打开，可用环境变量
	// APKGUARD_KEEP_RCLASS_IDS=1 一键关闭。
	RenameResourceIDs bool
	// RenameLibraries 为 true 时，第三方库类（androidx/、android/support/、
	// kotlin/、kotlinx/、com/google/ 等）也参与类名混淆。
	//
	// 默认 false：库类保留原名（仅应用自身与其余非前缀类改名），避免破坏
	// 库内部的反射、序列化与热修复约定。开启后这些库类与其内部引用会被
	// 一起改写，但以下护栏**无论开关如何**都保持：
	//   - 平台前缀一律保留：java/、javax/、jdk/、sun/、dalvik/、libcore/、
	//     org/apache/、org/json/、org/w3c/、org/xml/、org/xmlpull/；
	//   - 类名出现在 const-string / 其它 DEX 的字符串常量里的反射类；
	//   - 清单声明的组件类、含 native 方法的类、Android 组件/入口类；
	//   - 内部类（名字含 '$'）与其外层类照旧成对保留。
	//
	// 风险提示：开启后产物与依赖「反射 / 序列化 / 热修复」的框架
	// （Gson、Kotlin 反射、Tinker/Patch 类名匹配等）兼容风险上升，
	// 这是设计取舍，应按需开启。
	RenameLibraries bool
	// ShrinkPackage 为 true 时，新类名不再保留原包前缀，而是落到**默认包**
	// （如 Lcom/foo/Bar; -> La;）。
	//
	// 参考样本就是这样：955 个类被压成默认包里的 A0 / A1$a 这类名字，
	// 于是从类名完全读不出模块划分。
	//
	// 注意：这是**单 DEX 内**的粗粒度开关，它对「包」一无所知——把不同包的类
	// 压进同一个默认包，会让原本同包的 package-private 访问（如内部类
	// CrashUtils$1 与同包普通类之间）变成跨包访问，运行时报
	//
	//	IllegalAccessError: Illegal class access: 'ac' attempting to access
	//	'com.termux.app.utils.CrashUtils$1'
	//
	// 因此 CLI 的 -package-shrink 并不使用它，而是在 passes 层做「按包压缩」
	// （每个原包整体映射为一个无意义短包名，保持包内同包语义）。
	// 本开关仅作为库 API 保留，供调用方在确知无跨包 package-private 依赖时使用。
	ShrinkPackage bool
	// ExtraKeepClasses 是额外强制保留的类（Java 名，形如 "com.foo.Bar"）。
	// 用于传入从 AndroidManifest.xml 解析出的四大组件类名。
	ExtraKeepClasses []string

	// ClassMap 是「外部指定的类重命名表」（旧描述符 -> 新描述符）。
	//
	// 多 DEX 场景下必须由调用方先做一次全局决策再传进来：
	// 同一个类可能被多个 DEX 交叉引用，若各 DEX 独立决策就会出现
	// 「A 改了名而 B 仍引用旧名」的断链。ClassMap 非空时，
	// 本 DEX 定义的类一律按此表改名，不再自行决策。
	ClassMap map[string]string
	// MemberMap 是「外部指定的成员改名表」（旧名称 -> 新名称），键是名称字符串
	// 本身（方法名与字段名共表）；命中时优先采用。
	//
	// 与 ClassMap 同理：多 DEX 场景下同一个名称（例如静态常量 TERMUX_HOME_DIR）
	// 可能在 A DEX 定义、在 B DEX 引用。各 DEX 独立生成新名会取到不同结果，
	// 运行时抛
	//   NoSuchFieldError: No field TERMUX_HOME_DIR of type ... in class ...
	// 所以成员改名的**决策与命名都必须全局做一次**。表里没有的名称仍按本 DEX
	// 自己的规则处理（单 DEX 场景照旧）。
	MemberMap map[string]string
	// MemberKeep 是「全局禁止改名的成员名」集合。
	//
	// 当某个名称被多个 DEX 共用、而其中至少一个 DEX 不同意改名时，必须**一致地
	// 保留**：只让它不出现在 MemberMap 里是不够的——那样各 DEX 会退回本地决策，
	// 同意改名的那个 DEX 仍会改名，反而制造出不一致（实测就是这个坑）。
	MemberKeep map[string]bool
	// ReflectedNames 是「其它 DEX 中出现过的类名」（Java 名形式）。
	//
	// 跨 DEX 的 Class.forName 无法通过本 DEX 的字符串池发现，
	// 因此需要调用方汇总后传入，避免把被反射的类改名。
	ReflectedNames map[string]bool
}

// androidEntryPoints 是 Android 平台按名称反射调用的基类，
// 其子类会被系统实例化，重命名会破坏运行。
var androidEntryPoints = []string{
	"android/app/Application",
	"android/app/Activity",
	"android/app/Service",
	"android/content/ContentProvider",
	"android/content/BroadcastReceiver",
	"android/app/backup/BackupAgent",
	"android/app/backup/BackupAgentHelper",
	"android/app/IntentService",
	"android/app/Fragment",
	"androidx/fragment/app/Fragment",
	"android/app/DialogFragment",
	"android/preference/PreferenceFragment",
	"android/inputmethodservice/InputMethodService",
	"android/accessibilityservice/AccessibilityService",
	"android/service/notification/NotificationListenerService",
	"android/service/wallpaper/WallpaperService",
	"android/service/dreams/DreamService",
	"android/service/chooser/ChooserTargetService",
	"android/service/autofill/AutofillService",
	"android/service/carrier/CarrierMessagingService",
	"android/service/media/MediaBrowserService",
	"android/service/quickaccesswallet/QuickAccessWalletService",
	"android/service/controls/ControlsProviderService",
	"android/service/credentials/CredentialProviderService",
	"android/app/VoiceInteractionService",
	"android/service/vr/VrListenerService",
	"android/service/trust/TrustAgentService",
	"android/service/timezone/TimeZoneProviderService",
	"android/app/job/JobService",
	"android/app/admin/DeviceAdminReceiver",
	"android/accounts/AbstractAccountAuthenticator",
	"android/widget/RemoteViewsService",
	"android/appwidget/AppWidgetProvider",
	"android/media/MediaBrowserService",
	"android/speech/RecognitionService",
	"android/text/service/TextClassificationService",
	"android/printservice/PrintService",
	"android/nfc/cardemulation/HostApduService",
	"android/nfc/cardemulation/OffHostApduService",
	"android/companion/CompanionDeviceService",
	"android/app/slice/SliceProvider",
	"android/view/inputmethod/InputMethod",
	"android/service/notification/ConditionProviderService",
	"androidx/lifecycle/ViewModel",
	"androidx/lifecycle/AndroidViewModel",
	"androidx/work/Worker",
	"androidx/work/ListenableWorker",
	"androidx/room/RoomDatabase",
	"androidx/multidex/MultiDexApplication",
	"android/app/Application$ActivityLifecycleCallbacks",
}

// keepMethodNames 是必须保留名称的方法（按名称匹配，与所属类无关）。
//
// 这些方法由运行时或框架按名称调用，改名会导致行为改变或崩溃。
var keepMethodNames = []string{
	// Java 语言层
	"<init>", "<clinit>",
	"main", "run", "call", "equals", "hashCode", "toString",
	"clone", "finalize", "values", "valueOf", "readObject", "writeObject",
	"readResolve", "writeReplace", "readExternal", "writeExternal",
	"compareTo", "iterator", "next", "hasNext", "size", "get", "set",
	// Android 生命周期与回调
	"onCreate", "onStart", "onResume", "onPause", "onStop", "onDestroy",
	"onRestart", "onSaveInstanceState", "onRestoreInstanceState",
	"onCreateView", "onViewCreated", "onDestroyView", "onActivityCreated",
	"onAttach", "onDetach", "onAttachFragment", "onCreateOptionsMenu",
	"onPrepareOptionsMenu", "onOptionsItemSelected", "onCreateContextMenu",
	"onContextItemSelected", "onConfigurationChanged", "onLowMemory",
	"onTrimMemory", "onNewIntent", "onActivityResult", "onRequestPermissionsResult",
	"onBackPressed", "onKeyDown", "onKeyUp", "onTouchEvent", "onClick",
	"onLongClick", "onFocusChange", "onCreateDialog", "onPrepareDialog",
	"onReceive", "onBind", "onUnbind", "onStartCommand", "onRebind",
	"onHandleIntent", "onBindViewHolder", "onCreateViewHolder",
	"onBindView", "getView", "getItem", "getCount", "getItemId", "getItemViewType",
	"getViewTypeCount", "isViewFromObject", "instantiateItem", "destroyItem",
	"attachBaseContext", "onTerminate", "onProvideAssistData",
	"onPreExecute", "doInBackground", "onPostExecute", "onProgressUpdate",
	"onCancelled", "onAnimationEnd", "onAnimationStart", "onAnimationRepeat",
	"onDraw", "onMeasure", "onLayout", "onSizeChanged", "onFinishInflate",
	"onInterceptTouchEvent", "onTouch", "onScroll", "onFling",
	"onCreatePanelMenu", "onMenuItemClick", "onPreferenceChange", "onPreferenceClick",
	"onSharedPreferenceChanged", "onSensorChanged", "onAccuracyChanged",
	"onLocationChanged", "onStatusChanged", "onProviderEnabled", "onProviderDisabled",
	"onServiceConnected", "onServiceDisconnected", "onReceiveResult",
	"onLoadFinished", "onLoaderReset", "onCreateLoader",
	"onQueryTextSubmit", "onQueryTextChange", "onDateSet", "onTimeSet",
	"onDismiss", "onCancel", "onShow", "onItemClick", "onNothingSelected",
	"onChildClick", "onGroupClick", "onGroupCollapse", "onGroupExpand",
	"onItemSelected", "onPictureInPictureModeChanged",
	"onMultiWindowModeChanged", "onWindowFocusChanged", "onUserLeaveHint",
	"onPostCreate", "onPostResume", "onEnterAnimationComplete",
	"onProvideKeyboardShortcuts", "onActivityReenter", "onTopResumedActivityChanged",
	"onPictureInPictureUiStateChanged", "onBackInvoked",
	// 常见框架回调
	"onMessage", "handleMessage", "onEvent", "onSuccess",
	"onFailure", "onError", "onResponse", "onComplete", "onNext",
	"onSubscribe", "onResult", "onCallback", "onProgress",
	// 序列化 / 反射约定
	"writeToParcel", "describeContents",
	// JNI 约定
	"onLoad",
}

// keepFieldNames 是必须保留名称的字段。
var keepFieldNames = []string{
	"CREATOR", "INSTANCE", "serialVersionUID", "Companion", "TAG",
}

// platformPrefixes 是**永远**必须保留的平台包前缀（RenameLibraries 也不能放行）。
//
// 这些类由 JDK / Android 运行时提供，名字由系统按名解析或与 ART 约定绑定，
// 改名必然破坏运行时链接。
var platformPrefixes = []string{
	"Ljava/", "Ljavax/", "Ljdk/", "Lsun/", "Ldalvik/", "Llibcore/",
	"Lorg/w3c/", "Lorg/xml/", "Lorg/json/", "Lorg/apache/", "Lorg/xmlpull/",
	"Landroid/",
}

// libraryPrefixes 是「第三方库」包前缀：默认保留（保守），
// RenameConfig.RenameLibraries 打开时放行参与混淆。
//
// 注意 Landroid/support/：它同时命中 Landroid/（平台）与库前缀，判定顺序上
// 库前缀优先——只有 RenameLibraries 打开时才放行 support 库；关掉时照旧保留。
var libraryPrefixes = []string{
	"Landroidx/", "Landroid/support/", "Lcom/google/", "Lkotlin/", "Lkotlinx/",
	"Lorg/jetbrains/", "Lokhttp3/", "Lokio/", "Lretrofit2/", "Lio/reactivex/",
	"Lorg/slf4j/", "Lcom/squareup/", "Lcom/bumptech/", "Lcom/facebook/",
	"Lio/flutter/", "Lcom/tencent/", "Lcom/alibaba/", "Lcom/taobao/",
	"Lcom/umeng/", "Lcom/baidu/", "Lcom/iflytek/", "Lcom/amap/", "Lcom/qq/",
	"Lorg/bouncycastle/", "Lcom/nostra13/", "Lorg/greenrobot/",
}

// prefixKeepReason 返回类因平台/三方库前缀而必须保留的原因；空串表示可改名。
//
// 判定顺序：库前缀优先于平台前缀。这样 Landroid/support/... 在
// RenameLibraries 打开时会走「库，放行」分支，而真正的平台类
// （Landroid/app/Activity;、Ljava/lang/String; 等）在任何配置下都保留。
func (r *Renamer) prefixKeepReason(desc string) string {
	if hasAnyPrefix(desc, libraryPrefixes) {
		if r.cfg.RenameLibraries {
			return ""
		}
		return "三方库类（未开启 RenameLibraries）"
	}
	if hasAnyPrefix(desc, platformPrefixes) {
		return "平台类（系统按名解析）"
	}
	return ""
}

// keptByPrefix 是 prefixKeepReason 的布尔形式，供放行候选预筛使用
// （与 keepReason 同一套语义，避免两处规则分叉）。
func (r *Renamer) keptByPrefix(desc string) bool {
	return r.prefixKeepReason(desc) != ""
}

// Renamer 依据 DEX 的引用关系计算重命名映射。
//
// 设计原则：只重命名「在本 DEX 中定义、且不被外部按名称引用」的标识符。
type Renamer struct {
	f     *File
	cfg   RenameConfig
	usage *StringUsage
	infos []ClassInfo

	// strIdx 是「字符串 -> 池索引」的反查表，避免反复线性扫描字符串池。
	strIdx map[string]uint32

	// classRename 是「旧描述符 -> 新描述符」。
	classRename map[string]string
	// methodRename / fieldRename 是「旧名称字符串索引 -> 新名称」。
	methodRename map[uint32]string
	fieldRename  map[uint32]string

	// used 保证生成的名称不与既有名称冲突。
	used map[string]map[string]bool
	seq  int

	// keepReasons 记录被保留的类及其原因，用于报告。
	keepReasons map[string]string

	// defOf 是「类描述符 -> class_def 下标」，读取 static_values 用。
	defOf map[string]uint32
	// resIDOK 是「允许参与改名的资源 ID 类描述符」集合，仅在
	// RenameConfig.RenameResourceIDs 开启且本 DEX 含 R 类候选时计算
	// （见 planResourceIDClasses）。nil 表示不启用。
	resIDOK map[string]bool

	// byDesc 是「类描述符 -> 类定义」，用于查父类型与成员访问标志。
	byDesc map[string]*ClassInfo
	// res 是在 byDesc 上做继承解析的只读视图（可复用于跨 DEX 的全局视图）。
	res *typeResolver
}

// typeResolver 在一组可见类定义上做继承解析。
//
// 之所以抽成独立类型：跨 DEX 成员改名必须先汇总**全部 DEX**的类定义再解析
// （同一个静态成员可能 A DEX 定义、B DEX 引用，B 自己看不到声明类），
// 而单 DEX 的 Renamer 也需要同一套逻辑。抽出来后两边共用，避免行为分叉。
//
// 这里的判据全部是保守的：遇到本集合之外的父类型一律视为「看不见」，
// 宁可不改名，也不能猜。
type typeResolver struct {
	byDesc map[string]*ClassInfo
	// invisCache 缓存「该类（传递地）是否有集合之外的父类型」。
	invisCache map[string]bool
}

// newTypeResolver 用给定的类定义集合构造解析器。
func newTypeResolver(infos []ClassInfo) *typeResolver {
	t := &typeResolver{
		byDesc:     make(map[string]*ClassInfo, len(infos)),
		invisCache: map[string]bool{},
	}
	for i := range infos {
		// 重复描述符（合法多 DEX 中不应出现）保留第一个，调用方另行保守处理。
		if _, ok := t.byDesc[infos[i].Desc]; !ok {
			t.byDesc[infos[i].Desc] = &infos[i]
		}
	}
	return t
}

// NewRenamer 构造一个重命名器。
func NewRenamer(f *File, cfg RenameConfig) (*Renamer, error) {
	usage, err := f.StringUsage()
	if err != nil {
		return nil, fmt.Errorf("扫描字符串用途失败: %w", err)
	}
	infos, err := f.ClassInfos()
	if err != nil {
		return nil, fmt.Errorf("读取类信息失败: %w", err)
	}
	r := &Renamer{
		f:            f,
		cfg:          cfg,
		usage:        usage,
		infos:        infos,
		strIdx:       make(map[string]uint32, f.NString),
		classRename:  map[string]string{},
		methodRename: map[uint32]string{},
		fieldRename:  map[uint32]string{},
		used:         map[string]map[string]bool{"C": {}, "M": {}, "F": {}},
	}
	r.res = newTypeResolver(infos)
	r.byDesc = r.res.byDesc
	for i := uint32(0); i < f.NString; i++ {
		s, err := f.String(i)
		if err != nil {
			return nil, err
		}
		r.strIdx[s] = i
	}
	// 预占全部既有名称，避免新名与任何现存标识符碰撞。
	//
	// 注意：类型必须按 type_ids 全量登记，而不是只登记 class_defs——
	// DEX 中大量类型（数组、被引用的外部类）没有 class_def，但同样是合法类型，
	// 新类名一旦与之重合就会导致类型描述符冲突。
	for i := uint32(0); i < f.NType; i++ {
		d, err := f.Type(i)
		if err != nil {
			return nil, err
		}
		r.used["C"][d] = true
	}
	for i := range infos {
		r.used["C"][infos[i].Desc] = true
		for _, m := range infos[i].Methods() {
			r.used["M"][m.Name] = true
		}
		for _, fl := range infos[i].Fields() {
			r.used["F"][fl.Name] = true
		}
	}
	// class_def 下标表：static_values 挂在 class_def 上，判据需要按描述符回查。
	r.defOf = make(map[string]uint32, len(infos))
	for i := range infos {
		if _, ok := r.defOf[infos[i].Desc]; !ok {
			r.defOf[infos[i].Desc] = uint32(i)
		}
	}
	// 资源 ID 类的放行集合必须在构造期一次算清：keepReason 会被每个类调用，
	// 而它涉及 static_values 解析与整文件的 checkRebuildSupported 扫描。
	// 先做一次廉价的名字预筛，普通 DEX（没有 R 类）完全不付这笔代价。
	if cfg.RenameResourceIDs && r.hasResourceIDClassCandidate() {
		r.resIDOK = r.planResourceIDClasses()
	}
	return r, nil
}

// Plan 计算并返回重命名映射（旧字符串 -> 新字符串）。
//
// 返回值可直接用于 RebuildOptions.Rename。
func (r *Renamer) Plan() (map[string]string, error) {
	kept := r.planClasses()
	if err := r.planMethods(kept); err != nil {
		return nil, err
	}
	if err := r.planFields(kept); err != nil {
		return nil, err
	}

	out := map[string]string{}
	for old, nw := range r.classRename {
		out[old] = nw
	}
	for idx, nw := range r.methodRename {
		s, err := r.f.String(idx)
		if err != nil {
			return nil, err
		}
		out[s] = nw
	}
	for idx, nw := range r.fieldRename {
		s, err := r.f.String(idx)
		if err != nil {
			return nil, err
		}
		out[s] = nw
	}
	// 跨 DEX 引用：本 DEX 里可能引用「定义在别的 DEX」的类，本 DEX 无法看到
	// 它们的 class_def。这类引用同样必须跟着改名，否则本 DEX 里仍写着旧名，
	// 运行时报
	//   NoClassDefFoundError: Failed resolution of: Lcom/foo/Bar;
	// 真实案例：Termux（原生 30 个 DEX），另外 RustDesk 能跑通是因为它是单 DEX，
	// 多份是 B4 在**改名之后**才拆出来的，因此碰不到这个问题。
	//
	// 只补「不在本 DEX 定义」的类：本 DEX 定义的类由 classRename 决定（它已经
	// 尊重了本地的保留决策，例如声明了 native 方法的类绝不能改名）。
	for old, nw := range r.cfg.ClassMap {
		if old == nw {
			continue
		}
		if _, definedHere := r.byDesc[old]; definedHere {
			continue
		}
		if _, exists := out[old]; !exists {
			out[old] = nw
		}
	}

	// 数组描述符必须跟着元素类一起改名。
	//
	// DEX 里 "[Lfoo;"（foo 的数组）是**独立于 "Lfoo;" 的类型字符串**，
	// 不是从类名派生的。只改元素类会让数组类型指向一个已不存在的类，
	// ART 校验时报
	//   "can't resolve returned type 'Unresolved Reference: z7.c[]'"
	// 并拒绝整个类（真实案例：RustDesk 加固后启动即崩在
	//   VerificationError: Verifier rejected class y7.czz）。
	//
	// 维度取到 8 足够覆盖实际用法；多出的条目不会匹配到任何池内字符串，
	// 因此是无害的。
	for old, nw := range r.classRename {
		for dim := 1; dim <= 8; dim++ {
			po := strings.Repeat("[", dim) + old
			pn := strings.Repeat("[", dim) + nw
			if _, exists := out[po]; !exists {
				out[po] = pn
			}
		}
	}
	// 跨 DEX 的数组类型同理（引用方可能只写了 "[Lcom/foo/Bar;"）。
	// 先取出类描述符条目再展开，避免边遍历边插入同一个 map。
	var classEntries [][2]string
	for old, nw := range out {
		// 只有类描述符才派生数组形式（L...;）
		if strings.HasPrefix(old, "L") && strings.HasSuffix(old, ";") {
			classEntries = append(classEntries, [2]string{old, nw})
		}
	}
	for _, e := range classEntries {
		for dim := 1; dim <= 8; dim++ {
			po := strings.Repeat("[", dim) + e[0]
			pn := strings.Repeat("[", dim) + e[1]
			if _, exists := out[po]; !exists {
				out[po] = pn
			}
		}
	}
	// 泛型 Signature 属性里的复合串必须单独登记（见 planSignatureRenames）。
	// 放在数组展开之后：签名串本身不是类描述符，不应派生数组形式。
	if err := r.planSignatureRenames(out); err != nil {
		return nil, err
	}
	for k, v := range out {
		if k == v {
			delete(out, k)
		}
	}
	return out, nil
}

// Stats 返回重命名统计。
type Stats struct {
	Classes     int
	Methods     int
	Fields      int
	KeptCls     int
	KeepReasons map[string]int
}

// LastStats 返回上一次 Plan 的统计（便于在报告中输出）。
func (r *Renamer) LastStats() Stats {
	st := Stats{KeepReasons: map[string]int{}}
	st.Classes = len(r.classRename)
	st.Methods = len(r.methodRename)
	st.Fields = len(r.fieldRename)
	for _, why := range r.keepReasons {
		st.KeepReasons[why]++
	}
	st.KeptCls = len(r.keepReasons)
	return st
}

// planClasses 决定类的重命名，返回「被保留的类描述符 -> 原因」。
func (r *Renamer) planClasses() map[string]string {
	reflected := r.reflectedClasses()
	// hasInner 的键必须是**外层类的完整描述符**（查询处用的是 ci.Desc，
	// 形如 "Lapp/Outer;"）。这里曾写成 ci.Desc[:i+1]（截到 '$' 且含它），
	// 得到 "Lapp/Outer$"，与任何 ci.Desc 都不相等，于是 keepReason 里
	// 「含内部类」这条分支永远不命中：外层类被改名、内部类却因含 '$' 被保留，
	// 运行期用 outer.getName()+"$Inner" 或 Kotlin/Gson 按名反射嵌套类时，
	// 拼出来的名字在 DEX 里不存在 → ClassNotFoundException。
	hasInner := map[string]bool{}
	for _, ci := range r.infos {
		if i := strings.Index(ci.Desc, "$"); i > 0 {
			hasInner[ci.Desc[:i]+";"] = true
		}
	}
	extra := map[string]bool{}
	for _, n := range r.cfg.ExtraKeepClasses {
		extra["L"+strings.ReplaceAll(strings.TrimSpace(n), ".", "/")+";"] = true
	}

	kept := map[string]string{}
	for i := range r.infos {
		ci := &r.infos[i]
		why := r.keepReason(ci, extra, reflected, hasInner)
		if why != "" {
			kept[ci.Desc] = why
			continue
		}
		// 外部已给出全局决策时直接采用，保证多 DEX 之间的一致性。
		if r.cfg.ClassMap != nil {
			if nw, ok := r.cfg.ClassMap[ci.Desc]; ok && nw != ci.Desc {
				r.classRename[ci.Desc] = nw
				r.used["C"][nw] = true
				continue
			}
		}
		r.classRename[ci.Desc] = r.freshClassName(ci.Desc)
	}
	r.keepReasons = kept
	return kept
}

// keepReason 返回该类必须保留的原因；返回空串表示可以重命名。
func (r *Renamer) keepReason(ci *ClassInfo, extra, reflected, hasInner map[string]bool) string {
	switch {
	case declaresNative(ci):
		// 带 native 方法的类不能改名：JNI 符号名是**按类名动态推导**的
		// （Java_<包名下划线化>_<类名>_<方法名>），改了类名就再也找不到实现，
		// 运行时直接
		//   UnsatisfiedLinkError: No implementation found for void ffi.zl.cc(...)
		// （真实案例：RustDesk/Flutter 的 ffi.zl 类）。
		// 用 RegisterNatives 注册的库不受影响，但无法从 DEX 判断，
		// 因此一律保守保留。
		return "含 native 方法（JNI 符号按类名解析）"
	case extra[ci.Desc]:
		return "清单中的组件类"
	case r.isKeptClass(ci.Desc):
		return "命中保留规则"
	case r.keptByPrefix(ci.Desc):
		return r.prefixKeepReason(ci.Desc)
	case ci.Access&accAnnotation != 0:
		return "注解类（按名称反射读取）"
	case reflected[ci.Desc]:
		return "类名出现在字符串常量中（可能被反射）"
	case r.reflectedInOtherDex(ci.Desc):
		return "类名在其它 DEX 的字符串常量中出现（可能被反射）"
	case isEntryPoint(ci):
		return "Android 组件/入口类"
	case r.resIDOK[ci.Desc]:
		// 资源 ID 类（R / R$Type）：类名可混淆，字段名走既有字段引用改写通道，
		// static_values 原样保留（见 planResourceIDClasses 的判据与护栏）。
		// 必须排在下面两个案例之前：R$Type 含 '$'、外层 R 含内部类，
		// 那两条旧规则会整类拦下它们。
		return ""
	case strings.Contains(ci.Desc, "$"):
		return "内部类（与外层类命名强耦合）"
	case hasInner[ci.Desc]:
		return "含内部类（需整体处理）"
	case !strings.HasPrefix(ci.Desc, "L"):
		return "非类描述符"
	}
	return ""
}

// ---- 资源 ID 类（aapt 生成的 R / R$Type）----
//
// 参考样本对 R 类的做法是：类名与字段名全部抹成短名，字段的 static_values
// （资源 ID 常量 0x7f08xxxx）原样保留。DEX 对 R 字段的引用是 field_ids 的显式
// 引用，改名由既有字段引用改写通道统一完成，因此「字段名 -> 资源 ID」的绑定
// 不会断——前提是只对**能证明是资源 ID 类、且引用完整性可确认**的类放行。
//
// 下面这组判据全部取交集（宁少勿多）：名字像 R 只是入场券，还要字段常量确实
// 落在 Android 资源 ID 段、字段名没有被其它语义占用、整份 DEX 可被完整重建。

// isResourceIDClassDesc 判断描述符的简单名是否为 R 或 R$<Type>
// （aapt 生成的资源 ID 类命名，如 Lcom/x/R;、Lcom/x/R$string;）。
func isResourceIDClassDesc(desc string) bool {
	if len(desc) < 3 || desc[0] != 'L' || desc[len(desc)-1] != ';' {
		return false
	}
	body := desc[1 : len(desc)-1]
	if i := strings.LastIndexByte(body, '/'); i >= 0 {
		body = body[i+1:]
	}
	return body == "R" || strings.HasPrefix(body, "R$")
}

// resourceFamilyKey 返回资源 ID 类所属「家族」的键（外层 R 类的描述符）。
//
//	Lcom/x/R$string; -> Lcom/x/R;
//	Lcom/x/R;        -> Lcom/x/R;
func resourceFamilyKey(desc string) string {
	body := strings.TrimSuffix(strings.TrimPrefix(desc, "L"), ";")
	start := 0
	if i := strings.LastIndexByte(body, '/'); i >= 0 {
		start = i + 1
	}
	if i := strings.IndexByte(body[start:], '$'); i >= 0 {
		body = body[:start+i]
	}
	return "L" + body + ";"
}

// isAndroidResourceID 判断常量是否落在 Android 资源 ID 区间。
//
//	0x7f000000..0x7fffffff  应用资源包（aapt 给第三方应用固定分配 0x7f）
//	0x01000000..0x01ffffff  框架资源包（android.R 的 0x01 段）
//
// 0x01 段只作数值判据：Landroid/ 包前缀在 planResourceIDClasses 里一律排除，
// 平台 R 不会被放行。
func isAndroidResourceID(v int64) bool {
	return (v >= 0x7f000000 && v <= 0x7fffffff) ||
		(v >= 0x01000000 && v <= 0x01ffffff)
}

// encodedInt 是一个 encoded_value 的整数视图。
type encodedInt struct {
	// Val 仅当 OK 为 true（数值型：byte/short/char/int/long）时有效。
	Val int64
	// OK 表示该值是否为数值型。
	OK bool
	// Raw 是该 encoded_value 的原始字节（含头字节），用于逐字节比对。
	Raw []byte
	// IsArray 表示该值是否为 encoded_array（VALUE_ARRAY）。
	IsArray bool
	// Elems 仅当 IsArray 时非 nil：按位置给出数组元素的视图。
	// R$styleable 的 static_values 就是「元素为资源 ID 的 int[]」。
	Elems []encodedInt
}

// encodedArrayInts 解析一个 encoded_array，逐位置返回取值视图。
//
// 非数值型（字符串/数组/注解/…）OK=false，但仍会跳过其全部字节，保证
// 后续位置的字段对齐。解析失败返回 error，调用方按「无法确认」保守处理。
func encodedArrayInts(d []byte, off uint32) ([]encodedInt, error) {
	p := int(off)
	if p < 0 || p >= len(d) {
		return nil, fmt.Errorf("%w: encoded_array 偏移越界 %d", ErrTruncated, off)
	}
	size, np, err := ULEB128(d, p)
	if err != nil {
		return nil, err
	}
	p = np
	out := make([]encodedInt, 0, size)
	for i := uint32(0); i < size; i++ {
		var v encodedInt
		v, p, err = decodeEncodedInt(d, p)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// decodeEncodedInt 解析一个 encoded_value，返回其整数视图与新位置。
//
// 取值类型码遵循 DEX 规范：0x00/0x02/0x03/0x04/0x06 为数值，0x10/0x11
// （float/double）与 0x15-0x1b（含索引类型）载荷均为 value_arg+1 字节，
// 0x1c 数组 / 0x1d 注解递归跳过，0x1e/0x1f（null/boolean）无载荷。
func decodeEncodedInt(d []byte, p int) (encodedInt, int, error) {
	if p < 0 || p >= len(d) {
		return encodedInt{}, p, fmt.Errorf("%w: encoded_value 越界", ErrTruncated)
	}
	start := p
	head := d[p]
	p++
	vt := head & 0x1f
	va := int((head >> 5) & 0x7)
	switch vt {
	case 0x00, 0x02, 0x03, 0x04, 0x06: // byte / short / char / int / long
		n := va + 1
		if p+n > len(d) {
			return encodedInt{}, p, fmt.Errorf("%w: encoded_value 载荷越界", ErrTruncated)
		}
		var u uint64
		for i := 0; i < n; i++ {
			u |= uint64(d[p+i]) << (8 * i)
		}
		if vt != 0x03 { // char 无符号；其余按最高位做符号扩展
			bits := uint(8 * n)
			if bits < 64 && u&(uint64(1)<<(bits-1)) != 0 {
				u |= ^uint64(0) << bits
			}
		}
		return encodedInt{Val: int64(u), OK: true, Raw: d[start : p+n]}, p + n, nil
	case 0x1c: // array：逐元素解析（元素视图供资源 ID 比例判据统计）
		size, np, err := ULEB128(d, p)
		if err != nil {
			return encodedInt{}, p, err
		}
		p = np
		elems := make([]encodedInt, 0, size)
		for i := uint32(0); i < size; i++ {
			var ev encodedInt
			if ev, p, err = decodeEncodedInt(d, p); err != nil {
				return encodedInt{}, p, err
			}
			elems = append(elems, ev)
		}
		return encodedInt{Raw: d[start:p], IsArray: true, Elems: elems}, p, nil
	case 0x1d: // annotation：type_idx + size + (name_idx, value)*
		_, np, err := ULEB128(d, p)
		if err != nil {
			return encodedInt{}, p, err
		}
		size, np2, err := ULEB128(d, np)
		if err != nil {
			return encodedInt{}, p, err
		}
		p = np2
		for i := uint32(0); i < size; i++ {
			_, np3, err := ULEB128(d, p)
			if err != nil {
				return encodedInt{}, p, err
			}
			p = np3
			if _, p, err = decodeEncodedInt(d, p); err != nil {
				return encodedInt{}, p, err
			}
		}
		return encodedInt{Raw: d[start:p]}, p, nil
	case 0x1e, 0x1f: // null / boolean：无载荷（boolean 的值在 value_arg 里）
		return encodedInt{Raw: d[start:p]}, p, nil
	default:
		// 0x10/0x11（float/double）与 0x15-0x1b（含索引类型）：载荷 va+1 字节。
		n := va + 1
		if p+n > len(d) {
			return encodedInt{}, p, fmt.Errorf("%w: encoded_value 载荷越界", ErrTruncated)
		}
		return encodedInt{Raw: d[start : p+n]}, p + n, nil
	}
}

// hasResourceIDClassCandidate 廉价预筛：本 DEX 是否定义了名字像 R/R$Type
// 且不属于当前生效的保留前缀（平台恒保留；库前缀仅在未开启 RenameLibraries
// 时保留）的类。没有候选时完全不执行静态值解析与整文件扫描。
func (r *Renamer) hasResourceIDClassCandidate() bool {
	for i := range r.infos {
		d := r.infos[i].Desc
		if isResourceIDClassDesc(d) && !r.keptByPrefix(d) {
			return true
		}
	}
	return false
}

// hasResourceIDStaticField 判断类是否带「资源 ID 常量」，满足任一形态即可：
//
//	a) 至少一个 static int 字段的 static_values 取值落在资源段（R$string 等）；
//	b) 至少一个 static int[] 字段的 static_values 是数组，元素全部为数值型且
//	   ≥90% 落在资源段（R$styleable 的形态：数组元素就是资源 ID 序列）。
//
// static_values 的第 i 个值对应按 field_idx 升序的第 i 个静态字段；
// ClassInfos 给出的 StaticFields 就是该顺序，按位置对齐即可。
//
// 为什么要求数组元素「全部为数值型」：重建器对数组逐元素重映射，数值型原样
// 复制（逐字节不变），而字符串/类型等含索引的取值会被重新映射——一旦数组里
// 混入这类元素，就无法保证「逐元素逐字节不变」这条硬约束，因此判不满足
// （比例条件自然也就不成立）。
func (r *Renamer) hasResourceIDStaticField(ci *ClassInfo) bool {
	di, ok := r.defOf[ci.Desc]
	if !ok {
		return false
	}
	cd, err := r.f.ClassDefAt(di)
	if err != nil || cd.StaticValuesOff == 0 {
		return false
	}
	vals, err := encodedArrayInts(r.f.data, cd.StaticValuesOff)
	if err != nil {
		// 畸形 static_values：无法确认字段绑定，不放行。
		return false
	}
	for k, fl := range ci.StaticFields {
		if k >= len(vals) {
			continue
		}
		v := vals[k]
		switch {
		case fl.Type == "I" && v.OK && isAndroidResourceID(v.Val):
			return true
		case fl.Type == "[I" && resourceIDArrayDominant(v):
			return true
		}
	}
	return false
}

// resourceIDArrayDominant 判断一个 encoded_array 是否「以资源 ID 为主」：
// 元素必须全部是数值型，且至少 90% 落在 Android 资源 ID 区间。
//
// 空数组不算满足（没有可证明的资源 ID 证据）；比例用整数乘法比较，
// 避免浮点误差：in*100 >= n*90。
func resourceIDArrayDominant(v encodedInt) bool {
	if !v.IsArray || len(v.Elems) == 0 {
		return false
	}
	inRange := 0
	for _, e := range v.Elems {
		if !e.OK {
			return false
		}
		if isAndroidResourceID(e.Val) {
			inRange++
		}
	}
	return inRange*100 >= len(v.Elems)*90
}

// resourceFieldNamesSafe 判断类中字段名没有被「字段引用」之外的语义使用。
//
// 值键改名通道按字符串值整体替换：字段名若同时出现在 const-string、注解、
// 类型/方法名或源文件名里，planFields 会跳过它（改一个池项会波及那些语义
// 不同的字符串）。此时若仍改类名，字段名保持旧值，达不到隐藏资源用途的
// 目的；强行改写又会破坏其它语义。两种做法都无法证明引用完整，因此整类
// 不改（宁可漏改）。
func (r *Renamer) resourceFieldNamesSafe(ci *ClassInfo) bool {
	for _, fl := range ci.Fields() {
		idx, ok := r.strIdx[fl.Name]
		if !ok {
			continue
		}
		if r.usage.Type[idx] || r.usage.MethodName[idx] || r.usage.Const[idx] ||
			r.usage.Anno[idx] || r.usage.SourceFile[idx] {
			return false
		}
	}
	return true
}

// planResourceIDClasses 计算本 DEX 内允许参与改名的资源 ID 类集合。
//
// 判据（全部取交集）：
//  1. 整份 DEX 可被安全重建（checkRebuildSupported）：含 call_site_ids /
//     method_handles 段或 0xfa-0xfe 指令时，这些结构里的字段引用无法确认，
//     全部 R 类不改；
//  2. 类名形如 R / R$<Type>，且不属于当前生效的保留前缀
//     （Landroid/ 等平台前缀恒排除；库前缀仅在未开启 RenameLibraries 时排除）；
//  3. R$Type 满足 hasResourceIDStaticField 的任一形态：
//     static int 字段带资源段常量，或 static int[] 字段（R$styleable）
//     的数组元素全部为数值型且 ≥90% 落在资源段；数组经重建器逐字节保留；
//     外层 R：本 DEX 内它的全部 R$Type 都满足第 3 条时才一起放行
//     （外层与内部类进同一个计划，避免半个家族改名）；
//  4. 字段名只被字段引用使用（resourceFieldNamesSafe）。
func (r *Renamer) planResourceIDClasses() map[string]bool {
	out := map[string]bool{}
	if err := checkRebuildSupported(r.f); err != nil {
		return out
	}
	members := map[string][]string{}
	qualifies := map[string]bool{}
	for i := range r.infos {
		ci := &r.infos[i]
		if !isResourceIDClassDesc(ci.Desc) || r.keptByPrefix(ci.Desc) {
			continue
		}
		fam := resourceFamilyKey(ci.Desc)
		members[fam] = append(members[fam], ci.Desc)
		if r.hasResourceIDStaticField(ci) && r.resourceFieldNamesSafe(ci) {
			qualifies[ci.Desc] = true
		}
	}
	for i := range r.infos {
		ci := &r.infos[i]
		if !isResourceIDClassDesc(ci.Desc) || r.keptByPrefix(ci.Desc) {
			continue
		}
		fam := resourceFamilyKey(ci.Desc)
		if fam == ci.Desc {
			// 外层 R：要求家族内全部 R$Type 都放行（外层与内部类进同一个计划）。
			// aapt 的常态是外层 R 自身无字段；若它确实带字段，字段判据与
			// 名称护栏对它同样生效，不得因「成员干净」而绕过。
			all, others := true, 0
			for _, m := range members[fam] {
				if m == ci.Desc {
					continue
				}
				others++
				if !qualifies[m] {
					all = false
					break
				}
			}
			if all && ((others > 0 && len(ci.Fields()) == 0) || qualifies[ci.Desc]) {
				out[ci.Desc] = true
			}
			continue
		}
		if qualifies[ci.Desc] {
			out[ci.Desc] = true
		}
	}
	return out
}

// planMethods 决定方法名的重命名。
//
// 关键约束：DEX 中方法名以字符串形式存放在字符串池，同一个名称字符串
// 可能被多个类的 method_ids 共用，因此只有当「引用该名称的全部类都被重命名」
// 时才能改写该字符串，否则会误改未混淆类的成员名。
func (r *Renamer) planMethods(kept map[string]string) error {
	// 名称字符串索引 -> 引用它的 (类, 原型) 列表。
	//
	// 必须取自 **method_ids 全表**，而不是「本 DEX 声明的方法」：
	// DEX 的字符串池是去重的，一个方法名（如 getString）往往同时被本 DEX 的
	// 业务类和框架类（android.content.Context 等）引用，而后者的类定义不在
	// 本 DEX 里。若只统计本 DEX 声明的方法，就会误判「这个名字只被待改名的
	// 类引用」并允许改名；改名是按字符串值生效的，于是框架方法的引用
	// （Context.getString）被一并改掉，运行时必然
	//   NoSuchMethodError: No virtual method <新名> in class Landroid/content/Context;
	byName := map[uint32][]memberRef{}
	for i := uint32(0); i < r.f.NMethod; i++ {
		ref, err := r.f.MethodRefAt(i)
		if err != nil {
			return err
		}
		cls, err := r.f.Type(uint32(ref.ClassIdx))
		if err != nil {
			return err
		}
		proto, err := r.f.ProtoDesc(uint32(ref.ProtoIdx))
		if err != nil {
			proto = ""
		}
		byName[ref.NameIdx] = append(byName[ref.NameIdx], memberRef{class: cls, sig: proto})
	}

	idxList := make([]uint32, 0, len(byName))
	for idx := range byName {
		idxList = append(idxList, idx)
	}
	sort.Slice(idxList, func(a, b int) bool { return idxList[a] < idxList[b] })

	// 待定重命名：名称字符串索引 -> 新名
	pending := map[uint32]string{}
	for _, idx := range idxList {
		refs := byName[idx]
		// 名称字符串不得同时用于其它语义
		if r.usage.Type[idx] || r.usage.FieldName[idx] || r.usage.Const[idx] ||
			r.usage.Anno[idx] || r.usage.SourceFile[idx] {
			continue
		}
		name, err := r.f.String(idx)
		if err != nil {
			return err
		}
		if r.isAlwaysKeepMethodName(name) {
			continue
		}
		// 跨 DEX 的统一决策优先于本地判断：
		//   MemberKeep —— 一致保留（某个共用它的 DEX 不同意改名）；
		//   MemberMap  —— 一致改名（新名也由调用方统一指定）。
		if r.cfg.MemberKeep[name] {
			continue
		}
		if nw, ok := r.cfg.MemberMap[name]; ok {
			pending[idx] = nw
			continue
		}
		// 引用该名称的类必须全部处于重命名集合中
		all := true
		for _, rf := range refs {
			if _, ok := r.classRename[rf.class]; !ok {
				all = false
				break
			}
			// 可能覆写「看不见的」父类型方法时也不能改。
			if r.mayOverrideInvisible(name, rf.class, rf.sig) {
				all = false
				break
			}
			// 引用若在**可见继承链**里找不到声明，说明它来自本 DEX 之外的父类型
			// （框架/未打包的库），改名后运行时解析不到：
			//   NoSuchMethodError: No virtual method aez(Ljava/lang/String;)
			//   Ljava/lang/Class; in class Lorg/lsposed/hiddenapibypass/nc;
			// 实测就是这么崩的：nc 的父类是 dalvik.system.PathClassLoader，
			// loadClass 是**继承来的框架方法**，调用点的静态类型却是应用子类，
			// 于是被误当成「应用内部方法」改了名。
			if !r.resolvesVisibly(rf.class, name, rf.sig) {
				all = false
				break
			}
			if r.isKeptMember(rf.class, name) {
				all = false
				break
			}
		}
		if !all {
			continue
		}
		pending[idx] = r.fresh("M")
	}

	// 冲突检测：重命名后同一类内不得出现重复的 (名称, 原型)
	if err := r.checkConflicts(byName, pending, "方法"); err != nil {
		return err
	}
	r.methodRename = pending
	return nil
}

// hasInvisibleSuper 判断类（沿本 DEX 内的继承链传递地）是否继承了本 DEX 之外的
// 父类或接口。
//
// 为什么重要：DEX 里只有应用的类定义，框架与未打包进来的库类不在其中。
// 若某类的父类型在 DEX 之外，那么它的非私有实例方法可能在**覆写我们看不见的
// 方法**——接口方法的实现就是最典型的一种（框架回调尤其如此：调用方在系统里，
// 本 DEX 中根本没有该方法的引用，因此「引用者是否都被改名」这条判据看不见它）。
// 把这类方法改名，覆写关系就断了，运行时抛
//
//	java.lang.AbstractMethodError: abstract method "...View$OnAttachStateChangeListener
//	.onViewAttachedToWindow(android.view.View)" on receiver ...
//
// 实测就是这样崩的（Dhizuku：View.OnAttachStateChangeListener）。
//
// 判定是保守的：只要继承链上有一环落在 DEX 之外，就认为该类的方法「可能覆写
// 不可见方法」。纯应用内部的类（父类、接口都在同一 DEX 里）不受影响，仍然改名。
func (t *typeResolver) hasInvisibleSuper(desc string) bool {
	if v, ok := t.invisCache[desc]; ok {
		return v
	}
	// 先占位，避免继承链出现环时无限递归。
	t.invisCache[desc] = false
	ci := t.byDesc[desc]
	if ci == nil {
		return false
	}
	supers := make([]string, 0, 1+len(ci.Interfaces))
	supers = append(supers, ci.Super)
	supers = append(supers, ci.Interfaces...)
	res := false
	for _, s := range supers {
		if s == "" || s == "Ljava/lang/Object;" {
			continue
		}
		if _, ok := t.byDesc[s]; !ok {
			// 父类型不在本 DEX 里 → 看不见它的方法表
			res = true
			break
		}
		if t.hasInvisibleSuper(s) {
			res = true
			break
		}
	}
	t.invisCache[desc] = res
	return res
}

// hasInvisibleSuper 是 Renamer 对 typeResolver 的转发，保持既有调用点不变。
func (r *Renamer) hasInvisibleSuper(desc string) bool { return r.res.hasInvisibleSuper(desc) }

// mayOverrideInvisible 判断「类 classDesc 上名为 name、签名为 sig 的方法」
// 是否可能覆写本 DEX 之外的方法（私有/静态方法不参与覆写，不算）。
func (t *typeResolver) mayOverrideInvisible(name, classDesc, sig string) bool {
	ci := t.byDesc[classDesc]
	if ci == nil {
		return false
	}
	if !t.hasInvisibleSuper(classDesc) {
		return false
	}
	for _, m := range ci.Methods() {
		if m.Name != name || m.Proto != sig {
			continue
		}
		if m.Access&accPrivate != 0 || m.Access&accStatic != 0 {
			return false
		}
		return true
	}
	return false
}

// mayOverrideInvisible 是 Renamer 对 typeResolver 的转发。
func (r *Renamer) mayOverrideInvisible(name, classDesc, sig string) bool {
	return r.res.mayOverrideInvisible(name, classDesc, sig)
}

// memberRef 描述一个「名称字符串」被哪个类的哪个成员签名引用。
type memberRef struct {
	class string
	sig   string
}

// checkConflicts 校验重命名后各类内部不出现成员签名冲突。
//
// 冲突来源：某名称因被未混淆类引用而保留，另一个成员被改名成了同一个名字。
func (r *Renamer) checkConflicts(byName map[uint32][]memberRef, pending map[uint32]string, kind string) error {
	seen := map[string]map[string]bool{}
	for idx, refs := range byName {
		name, err := r.f.String(idx)
		if err != nil {
			return err
		}
		if nw, ok := pending[idx]; ok {
			name = nw
		}
		for _, rf := range refs {
			m, ok := seen[rf.class]
			if !ok {
				m = map[string]bool{}
				seen[rf.class] = m
			}
			key := name + "\x00" + rf.sig
			if m[key] {
				return fmt.Errorf("dex: 重命名后%s冲突 %s.%s%s", kind, rf.class, name, rf.sig)
			}
			m[key] = true
		}
	}
	return nil
}

// planFields 决定字段名的重命名，规则与方法一致。
func (r *Renamer) planFields(kept map[string]string) error {
	if !r.cfg.ObfuscateFields {
		return nil
	}
	// 同 planMethods：必须取自 field_ids 全表，否则框架字段的同名引用
	// 会被一并改名，运行时 NoSuchFieldError。
	byName := map[uint32][]memberRef{}
	for i := uint32(0); i < r.f.NField; i++ {
		classIdx, typeIdx, nameIdx, err := r.f.FieldRefAt(i)
		if err != nil {
			return err
		}
		cls, err := r.f.Type(uint32(classIdx))
		if err != nil {
			return err
		}
		ft, err := r.f.Type(uint32(typeIdx))
		if err != nil {
			ft = ""
		}
		byName[nameIdx] = append(byName[nameIdx], memberRef{class: cls, sig: ft})
	}
	idxList := make([]uint32, 0, len(byName))
	for idx := range byName {
		idxList = append(idxList, idx)
	}
	sort.Slice(idxList, func(a, b int) bool { return idxList[a] < idxList[b] })

	pending := map[uint32]string{}
	for _, idx := range idxList {
		refs := byName[idx]
		if r.usage.Type[idx] || r.usage.MethodName[idx] || r.usage.Const[idx] ||
			r.usage.Anno[idx] || r.usage.SourceFile[idx] {
			continue
		}
		name, err := r.f.String(idx)
		if err != nil {
			return err
		}
		skip := false
		for _, k := range keepFieldNames {
			if name == k {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		// 跨 DEX 的统一决策优先（与 planMethods 一致）
		if r.cfg.MemberKeep[name] {
			continue
		}
		if nw, ok := r.cfg.MemberMap[name]; ok {
			pending[idx] = nw
			continue
		}
		all := true
		for _, rf := range refs {
			if _, ok := r.classRename[rf.class]; !ok {
				all = false
				break
			}
			if r.isKeptMember(rf.class, name) {
				all = false
				break
			}
			// 同 planMethods：可见链里找不到声明的字段引用同样不能改名。
			// 注意这里必须用**字段**解析器：rf.sig 是字段类型（"I" 等），
			// 误用方法解析器会永远找不到声明，字段改名整体失效。
			if !r.resolvesVisiblyField(rf.class, name, rf.sig) {
				all = false
				break
			}
		}
		if !all {
			continue
		}
		pending[idx] = r.fresh("F")
	}

	if err := r.checkConflicts(byName, pending, "字段"); err != nil {
		return err
	}
	r.fieldRename = pending
	return nil
}

// isAlwaysKeepMethodName 判断方法名是否命中「永远保留」清单。
func (r *Renamer) isAlwaysKeepMethodName(name string) bool {
	return isAlwaysKeepMethodName(name)
}

// isAlwaysKeepMethodName 是包级实现，供跨 DEX 成员覆盖轮次复用。
func isAlwaysKeepMethodName(name string) bool {
	for _, k := range keepMethodNames {
		if name == k {
			return true
		}
	}
	// 以 < 开头的是编译器生成的特殊方法
	return strings.HasPrefix(name, "<")
}

// isKeepFieldName 判断字段名是否命中「永远保留」清单。
func isKeepFieldName(name string) bool {
	for _, k := range keepFieldNames {
		if name == k {
			return true
		}
	}
	return false
}

// isKeptClass 判断类是否命中用户保留规则。
func (r *Renamer) isKeptClass(desc string) bool {
	name := descToJava(desc)
	for _, rule := range r.cfg.Keep {
		rule = strings.TrimSpace(rule)
		if rule == "" || strings.HasPrefix(rule, "#") {
			continue
		}
		if matchKeepRule(rule, name, desc) {
			return true
		}
	}
	return false
}

// matchKeepRule 判断一条保留规则是否命中给定的类名。
//
// 支持的写法：
//
//	com.foo.Bar   精确类名
//	com.foo.**    包及其子包下全部类
//	com.foo.*     仅该包下一级类
//	*.Bar         任意包下的 Bar
func matchKeepRule(rule, javaName, desc string) bool {
	switch {
	case strings.HasSuffix(rule, ".**"):
		prefix := strings.TrimSuffix(rule, "**")
		return strings.HasPrefix(javaName, prefix)
	case strings.HasSuffix(rule, ".*"):
		prefix := strings.TrimSuffix(rule, "*")
		if !strings.HasPrefix(javaName, prefix) {
			return false
		}
		rest := javaName[len(prefix):]
		return rest != "" && !strings.Contains(rest, ".")
	case strings.HasPrefix(rule, "*."):
		return strings.HasSuffix(javaName, rule[1:])
	case strings.Contains(rule, "*"):
		return wildcardMatch(rule, javaName)
	default:
		return javaName == rule || desc == rule
	}
}

// wildcardMatch 实现简单的 * 通配匹配。
func wildcardMatch(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	pos := 0
	for i, p := range parts {
		if p == "" {
			continue
		}
		idx := strings.Index(s[pos:], p)
		if idx < 0 {
			return false
		}
		if i == 0 && idx != 0 {
			return false
		}
		pos += idx + len(p)
	}
	if !strings.HasSuffix(pattern, "*") && pos != len(s) {
		return false
	}
	return true
}

// isEntryPoint 判断类是否为 Android 组件或平台回调入口。
func isEntryPoint(ci *ClassInfo) bool {
	for _, base := range androidEntryPoints {
		if ci.Super == "L"+base+";" || ci.Desc == "L"+base+";" {
			return true
		}
		for _, ifc := range ci.Interfaces {
			if ifc == "L"+base+";" {
				return true
			}
		}
	}
	return false
}

// isKeptMember 判断「类名.成员名」是否命中保留规则。
func (r *Renamer) isKeptMember(classDesc, member string) bool {
	return isKeptMemberRule(r.cfg.Keep, classDesc, member)
}

// isKeptMemberRule 判断「类名.成员名」是否命中保留规则（-keep-rules）。
// 抽成独立函数以便跨 DEX 的成员覆盖轮次复用同一套匹配语义。
func isKeptMemberRule(keep []string, classDesc, member string) bool {
	full := descToJava(classDesc) + "." + member
	for _, rule := range keep {
		rule = strings.TrimSpace(rule)
		if rule == "" || strings.HasPrefix(rule, "#") {
			continue
		}
		if strings.Contains(rule, ".") && wildcardMatch(rule, full) {
			return true
		}
	}
	return false
}

// stringIndexOf 返回字符串在池中的索引（未找到返回 false）。
func (r *Renamer) stringIndexOf(s string) (uint32, bool) {
	i, ok := r.strIdx[s]
	return i, ok
}

// reflectedClasses 返回出现在字符串常量中的类名集合。
//
// 判断依据：字符串形如 "com/foo/Bar" 或 "com.foo.Bar"，且 DEX 中确实定义了
// 对应的类。这类类名很可能被 Class.forName 使用。
func (r *Renamer) reflectedClasses() map[string]bool {
	out := map[string]bool{}
	if r.usage == nil {
		return out
	}
	javaToDesc := map[string]string{}
	for _, ci := range r.infos {
		javaToDesc[descToJava(ci.Desc)] = ci.Desc
	}
	for i := uint32(0); i < r.f.NString; i++ {
		if !r.usage.Const[i] {
			continue
		}
		s, err := r.f.String(i)
		if err != nil {
			continue
		}
		if d, ok := javaToDesc[s]; ok {
			out[d] = true
		}
		if d, ok := javaToDesc[strings.ReplaceAll(s, "/", ".")]; ok {
			out[d] = true
		}
	}
	return out
}

// freshClassName 生成一个新的类描述符：保留原包名，替换简单名。
//
// 去重按「完整描述符」进行，避免新名与任何既有类（含被保留的类）重名。
// 注意默认包（如 "LBar;"）没有 '/'，此时包前缀就是 "L" 本身。
func (r *Renamer) freshClassName(old string) string {
	body := strings.TrimSuffix(strings.TrimPrefix(old, "L"), ";")
	if body == "" {
		return old
	}
	pkg := "L"
	if !r.cfg.ShrinkPackage {
		if slash := strings.LastIndex(body, "/"); slash >= 0 {
			pkg = "L" + body[:slash+1]
		}
	}
	for {
		r.seq++
		desc := pkg + encodeName(r.seq, r.cfg.Prefix) + ";"
		if !r.used["C"][desc] {
			r.used["C"][desc] = true
			return desc
		}
	}
}

// fresh 生成一个新的唯一标识符。
func (r *Renamer) fresh(ns string) string {
	for {
		r.seq++
		name := encodeName(r.seq, r.cfg.Prefix)
		if !r.used[ns][name] {
			r.used[ns][name] = true
			return name
		}
	}
}

// encodeName 把序号编码为短标识符（a、b、…、z、aa、ab、…）。
func encodeName(n int, prefix string) string {
	if prefix == "" {
		prefix = "a"
	}
	base := byte(prefix[0])
	if base < 'a' || base > 'z' {
		base = 'a'
	}
	var buf []byte
	for n > 0 {
		n--
		buf = append([]byte{base + byte(n%26)}, buf...)
		n /= 26
	}
	if len(buf) == 0 {
		buf = []byte{base}
	}
	return string(buf)
}

// descToJava 把类型描述符转为 Java 类名（"Lcom/foo/Bar;" -> "com.foo.Bar"）。
func descToJava(desc string) string {
	body := strings.TrimSuffix(strings.TrimPrefix(desc, "L"), ";")
	return strings.ReplaceAll(body, "/", ".")
}

// reflectedInOtherDex 判断类名是否以点分或斜杠形式出现在其它 DEX 的字符串
// 常量中（ReflectedNames 由调用方从各 DEX 的 const-string 汇总）。
//
// 同一个类的字符串常量有两种常见写法："com.foo.Bar"（Class.forName / 配置）
// 与 "com/foo/Bar"（资源名、JNI 注册等）。只查点分名会让斜杠写法得不到保护：
// 类被改名后，运行期按名反射即 ClassNotFoundException。
func (r *Renamer) reflectedInOtherDex(desc string) bool {
	if r.cfg.ReflectedNames[descToJava(desc)] {
		return true
	}
	// 斜杠形式 = 类描述符去掉首尾的 L;。
	if len(desc) >= 3 && desc[0] == 'L' && desc[len(desc)-1] == ';' {
		return r.cfg.ReflectedNames[desc[1:len(desc)-1]]
	}
	return false
}

// isPlainClassDesc 判断字符串是否为「不含泛型实参/数组」的普通类描述符。
func isPlainClassDesc(s string) bool {
	return len(s) >= 3 && s[0] == 'L' && s[len(s)-1] == ';' &&
		!strings.ContainsAny(s[1:len(s)-1], "<>[")
}

// planSignatureRenames 把 dalvik.annotation.Signature 注解里的复合泛型串
// 改写为「旧串 -> 新串」的精确匹配项，交给重建阶段的字符串值改名通道。
//
// 为什么走这条通道：重建时字符串池按**字符串值**替换（见 buildPlan 中
// opts.Rename 的应用处），而 Signature 的值与类描述符不相等，必须显式把整条
// 复合串登记为改名项，重建才会替换池里的那一条——不另造池改写通道。
//
// 只处理**确实含有待改名描述符**的签名串；没有任何命中的串不会产生条目，
// 保证产物稳定。
func (r *Renamer) planSignatureRenames(out map[string]string) error {
	descs := map[string]string{}
	for old, nw := range r.classRename {
		if old != nw && isPlainClassDesc(old) {
			descs[old] = nw
		}
	}
	// 跨 DEX 引用（定义在别的 DEX、本 DEX 只引用）同样要覆盖。
	for old, nw := range r.cfg.ClassMap {
		if old == nw || !isPlainClassDesc(old) {
			continue
		}
		if _, definedHere := r.byDesc[old]; definedHere {
			continue
		}
		if _, exists := descs[old]; !exists {
			descs[old] = nw
		}
	}
	if len(descs) == 0 {
		return nil
	}
	sigs, err := r.f.signatureStrings()
	if err != nil {
		return fmt.Errorf("dex: 扫描泛型签名注解失败: %w", err)
	}
	for _, sig := range sigs {
		nw, changed := rewriteSignatureClasses(sig, descs)
		if !changed {
			continue
		}
		// 签名串恰好等于某个类描述符时，类改名通道已覆盖它，保持原条目。
		if _, exists := out[sig]; !exists {
			out[sig] = nw
		}
	}
	return nil
}

// scanSigClassType 从 sig[i]（必须是 'L'）开始扫描一个 JVM 签名中的类类型，
// 返回结束下标（配对 ';' 之后）与首个顶层 '<' 的下标（无类型实参时为 -1）。
// 找不到配对的 ';' 时 ok 为 false，调用方按普通字符处理。
func scanSigClassType(sig string, i int) (end, argsStart int, ok bool) {
	depth := 0
	argsStart = -1
	for j := i + 1; j < len(sig); j++ {
		switch sig[j] {
		case '<':
			if depth == 0 && argsStart < 0 {
				argsStart = j
			}
			depth++
		case '>':
			if depth == 0 {
				return 0, -1, false
			}
			depth--
		case ';':
			if depth == 0 {
				return j + 1, argsStart, true
			}
		}
	}
	return 0, -1, false
}

// erasedClassDesc 返回一个类类型 token 的「擦除后描述符」：丢掉泛型实参，
// 并把内部类的 '.' 分隔写成 '$'。
func erasedClassDesc(token string) string {
	var b strings.Builder
	b.Grow(len(token))
	b.WriteByte('L')
	depth := 0
	for i := 1; i < len(token)-1; i++ {
		switch c := token[i]; c {
		case '<':
			depth++
		case '>':
			depth--
		case '.':
			if depth == 0 {
				b.WriteByte('$')
			}
		default:
			if depth == 0 {
				b.WriteByte(c)
			}
		}
	}
	b.WriteByte(';')
	return b.String()
}

// hasTopLevelDot 判断类类型 token 的名字中是否存在顶层 '.' 分隔（即内部类的
// Outer.Inner 写法；类型实参内部的 '.' 不算）。
func hasTopLevelDot(token string) bool {
	depth := 0
	for i := 1; i < len(token)-1; i++ {
		switch token[i] {
		case '<':
			depth++
		case '>':
			depth--
		case '.':
			if depth == 0 {
				return true
			}
		}
	}
	return false
}

// rewriteSignatureClasses 对一条泛型签名字符串做**描述符级**替换：扫描其中
// 每个 "L...;" 形式的类型（正确处理泛型实参的 <> 嵌套），把命中 rename 表的
// 旧描述符换为新描述符，类型实参原样保留。
//
// 返回替换后的串与是否发生替换。没有任何命中的串返回原串与 false。
//
// 例子（rename: Lcom/foo/Bar;->La/a;）：
//
//	Ljava/util/List<Lcom/foo/Bar;>;                   -> Ljava/util/List<La/a;>;
//	Ljava/util/Map<Ljava/lang/String;Lcom/foo/Bar;>;  -> ...<Ljava/lang/String;La/a;>;
//	Lcom/foo/Bar<Ljava/lang/String;>;                 -> La/a<Ljava/lang/String;>;
//
// 保守之处：内部类写法（Lcom/foo/Outer.Inner;）按**擦除后的完整描述符**
// （Lcom/foo/Outer$Inner;）查表。只命中外层类时不改写——内部类的名字与
// 外层强耦合，单独换外层会拼出错误的二进制名。
func rewriteSignatureClasses(sig string, rename map[string]string) (string, bool) {
	var b strings.Builder
	b.Grow(len(sig))
	changed := false
	for i := 0; i < len(sig); {
		if sig[i] != 'L' {
			b.WriteByte(sig[i])
			i++
			continue
		}
		end, argsStart, ok := scanSigClassType(sig, i)
		if !ok {
			b.WriteByte(sig[i])
			i++
			continue
		}
		token := sig[i:end]
		if argsStart < 0 {
			// 无类型实参：整段就是普通类描述符（可能含内部类的 '.' 分隔）。
			if nw, hit := rename[erasedClassDesc(token)]; hit {
				b.WriteString(nw)
				changed = true
			} else {
				b.WriteString(token)
			}
			i = end
			continue
		}
		// 有类型实参：擦除实参后按完整描述符比对；实参内部仍需递归替换。
		nw, hit := rename[erasedClassDesc(token)]
		if !hit {
			// 未命中：只消费 'L'，让主循环继续处理实参里的类描述符。
			b.WriteByte('L')
			i++
			continue
		}
		if hasTopLevelDot(token) {
			// 内部类的名字分布在 '.' 两侧，无法只换名字主体：直接换成新
			// 描述符（类型实参被丢弃）。引擎不会重命名内部类，此分支只在
			// 调用方通过 ClassMap 显式给出内部类映射时可达。
			b.WriteString(nw)
		} else {
			args, _ := rewriteSignatureClasses(sig[argsStart:end-1], rename)
			b.WriteString("L")
			b.WriteString(strings.TrimSuffix(strings.TrimPrefix(nw, "L"), ";"))
			b.WriteString(args)
			b.WriteString(";")
		}
		changed = true
		i = end
	}
	return b.String(), changed
}

// hasAnyPrefix 判断 s 是否以任一前缀开头。
func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// declaresNative 判断类是否声明了 native 方法。
func declaresNative(ci *ClassInfo) bool {
	for _, m := range ci.Methods() {
		if m.Native {
			return true
		}
	}
	return false
}

// resolvesVisibly 判断「类 classDesc 上的 (name, proto) 成员」能否在本 DEX 可见的
// 继承链（自身 + 父类 + 接口，传递地）里找到声明。
//
// 找不到就意味着声明在本 DEX 之外（框架或未打包的库）：这种成员名**绝不能改**，
// 因为调用点用的静态类型可能是应用子类，而实现来自看不见的父类。真实案例：
// 某库的类继承 dalvik.system.PathClassLoader，它调用 loadClass 时用的是自己的
// 静态类型，A1 把 loadClass 改了名 → 运行时
//
//	NoSuchMethodError: No virtual method aez(Ljava/lang/String;)Ljava/lang/Class;
//	in class Lorg/lsposed/hiddenapibypass/nc;
//
// java/lang/Object 的成员视作已知（所有类的公共祖先，DEX 里不重复声明）。
func (t *typeResolver) resolveMethodDecl(classDesc, name, proto string) (string, *MemberInfo, bool) {
	seen := map[string]bool{}
	var walk func(d string, depth int) (string, *MemberInfo, bool)
	walk = func(d string, depth int) (string, *MemberInfo, bool) {
		if d == "" || seen[d] || depth > 32 {
			return "", nil, false
		}
		seen[d] = true
		ci := t.byDesc[d]
		if ci == nil {
			// java/lang/Object 的已知成员视作可达的「外部声明」；返回描述符
			// 让调用方看到它不在本 DEX 集合里（ClassMap 查不到），从而跳过改名。
			if d == "Ljava/lang/Object;" && objectHasMember(name, proto) {
				return d, nil, true
			}
			return "", nil, false
		}
		for i := range ci.DirectMethods {
			if ci.DirectMethods[i].Name == name && ci.DirectMethods[i].Proto == proto {
				return d, &ci.DirectMethods[i], true
			}
		}
		for i := range ci.VirtualMethods {
			if ci.VirtualMethods[i].Name == name && ci.VirtualMethods[i].Proto == proto {
				return d, &ci.VirtualMethods[i], true
			}
		}
		if dd, m, ok := walk(ci.Super, depth+1); ok {
			return dd, m, true
		}
		for _, i := range ci.Interfaces {
			if dd, m, ok := walk(i, depth+1); ok {
				return dd, m, true
			}
		}
		return "", nil, false
	}
	return walk(classDesc, 0)
}

// resolveFieldDecl 解析字段引用到的声明类（沿父链找最近声明）。
//
// 字段没有虚派发，解析顺序（自身 -> 父类 -> 接口）与 JVM 字段解析一致：
// 子类隐藏父类同名字段时，引用按静态类型解析到最近的那个声明。
func (t *typeResolver) resolveFieldDecl(classDesc, name, typ string) (string, *MemberInfo, bool) {
	seen := map[string]bool{}
	var walk func(d string, depth int) (string, *MemberInfo, bool)
	walk = func(d string, depth int) (string, *MemberInfo, bool) {
		if d == "" || seen[d] || depth > 32 {
			return "", nil, false
		}
		seen[d] = true
		ci := t.byDesc[d]
		if ci == nil {
			return "", nil, false
		}
		for i := range ci.StaticFields {
			if ci.StaticFields[i].Name == name && ci.StaticFields[i].Type == typ {
				return d, &ci.StaticFields[i], true
			}
		}
		for i := range ci.InstanceFields {
			if ci.InstanceFields[i].Name == name && ci.InstanceFields[i].Type == typ {
				return d, &ci.InstanceFields[i], true
			}
		}
		if dd, m, ok := walk(ci.Super, depth+1); ok {
			return dd, m, true
		}
		for _, i := range ci.Interfaces {
			if dd, m, ok := walk(i, depth+1); ok {
				return dd, m, true
			}
		}
		return "", nil, false
	}
	return walk(classDesc, 0)
}

// resolvesVisibly 判断「类 classDesc 上的 (name, proto) 成员」能否在本集合可见的
// 继承链里找到声明。找不到就意味着声明在集合之外（框架或未打包的库），这种成员名
// 绝不能改。实现复用 resolveMethodDecl，保证与全局解析同一套语义。
func (t *typeResolver) resolvesVisibly(classDesc, name, proto string) bool {
	_, _, ok := t.resolveMethodDecl(classDesc, name, proto)
	return ok
}

// resolvesVisibly 是 Renamer 对 typeResolver 的转发。
func (r *Renamer) resolvesVisibly(classDesc, name, proto string) bool {
	return r.res.resolvesVisibly(classDesc, name, proto)
}

// resolvesVisiblyField 判断「类 classDesc 上的 (name, typ) 字段」能否在本集合
// 可见的继承链里找到声明。
//
// 字段引用必须用**字段**解析器（resolveFieldDecl，按 (name, 字段类型) 在
// StaticFields/InstanceFields 里找）。此前 planFields 误用了方法解析器
// resolvesVisibly，把字段类型（"I" 等）当方法原型传进去，按 (name, proto)
// 在 DirectMethods/VirtualMethods 里查找——字段名永远匹配不到任何方法声明，
// 于是值键路径下 all 恒为 false，一个字段都改不了，ObfuscateFields 形同虚设。
// 语义与方法侧一致：可见链里找不到声明就不能改名（声明在框架/未打包库里）。
func (t *typeResolver) resolvesVisiblyField(classDesc, name, typ string) bool {
	_, _, ok := t.resolveFieldDecl(classDesc, name, typ)
	return ok
}

// resolvesVisiblyField 是 Renamer 对 typeResolver 的转发。
func (r *Renamer) resolvesVisiblyField(classDesc, name, typ string) bool {
	return r.res.resolvesVisiblyField(classDesc, name, typ)
}

// resolveMethodDecl 是 Renamer 对 typeResolver 的转发。
func (r *Renamer) resolveMethodDecl(classDesc, name, proto string) (string, *MemberInfo, bool) {
	return r.res.resolveMethodDecl(classDesc, name, proto)
}

// resolveFieldDecl 是 Renamer 对 typeResolver 的转发。
func (r *Renamer) resolveFieldDecl(classDesc, name, typ string) (string, *MemberInfo, bool) {
	return r.res.resolveFieldDecl(classDesc, name, typ)
}

// objectHasMember 判断名称/签名是否属于 java.lang.Object 的已知成员。
func objectHasMember(name, proto string) bool {
	switch name {
	case "equals":
		return proto == "(Ljava/lang/Object;)Z"
	case "hashCode":
		return proto == "()I"
	case "toString":
		return proto == "()Ljava/lang/String;"
	case "clone":
		return proto == "()Ljava/lang/Object;"
	case "finalize", "notify", "notifyAll", "registerNatives":
		return proto == "()V"
	case "getClass":
		return proto == "()Ljava/lang/Class;"
	case "wait":
		return proto == "()V" || proto == "(J)V" || proto == "(JI)V"
	case "<init>":
		return proto == "()V"
	}
	return false
}

// 成员覆盖改名关心的额外访问标志（其余标志见 assemble.go）。
const (
	// accEnum 是类/字段的 ACC_ENUM 位。枚举常量字段名即语义（name()/valueOf()/
	// switch map 都依赖它），枚举类整体不参与成员改名。
	accEnum = 0x4000
	// accBridge / accSynthetic 标记编译器生成的桥接/合成成员。它们可能被
	// 反序列化、lambda 元工厂等按名字引用，默认保留（见方案文档 B5）。
	accBridge    = 0x0040
	accSynthetic = 0x1000
)

// isSyntheticMemberName 判断名字是否像编译器/desugar 生成的合成名。
//
// 这类名字被框架或生成代码按名字引用，即使访问标志漏标 synthetic 也不能改：
//   - lambda 反序列化的方法名以 "lambda$" 开头；
//   - desugar / nestmate 访问器形如 "x-$$Lambda$..."、"x-$$Nest$m..."。
func isSyntheticMemberName(name string) bool {
	if strings.HasPrefix(name, "lambda$") {
		return true
	}
	return strings.Contains(name, "-$$")
}

// memberClassRenamable 判断成员声明类本身是否在类改名集合里（方案文档 A2）。
//
// 只改「声明类也会被改名」的成员，是一道很硬的前置门禁：被保留的类（入口组件、
// native 类、反射类、命中 -keep 的类）其成员一律不动，一刀切掉 JNI/反射/组件
// 回调的大部分风险。
func memberClassRenamable(classMap map[string]string, desc string) bool {
	nw, ok := classMap[desc]
	return ok && nw != "" && nw != desc
}

// classUnrenameableForMembers 判断类是否因特殊语义而必须整体保留成员。
func classUnrenameableForMembers(ci *ClassInfo) bool {
	switch {
	case ci.Access&accEnum != 0 || ci.Super == "Ljava/lang/Enum;":
		return true // 枚举：常量字段名即语义
	case ci.Access&accAnnotation != 0:
		return true // 注解：元素名被反射读取
	case declaresNative(ci):
		return true // JNI：GetMethodID/GetFieldID 按名字回调
	}
	return false
}

// classImplementsSerializable 判断类是否（可见地）实现 java/io/Serializable。
//
// 默认序列化按字段名读写，因此 Serializable 类的实例字段绝不能改名。
// 继承闭包不可见的类无法排除「隐藏地实现了 Serializable」，调用方会另行
// 用 hasInvisibleSuper 保守跳过（见 PlanMemberRenames 的字段判据）。
func classImplementsSerializable(t *typeResolver, desc string) bool {
	seen := map[string]bool{}
	var walk func(d string, depth int) bool
	walk = func(d string, depth int) bool {
		if d == "" || seen[d] || depth > 32 {
			return false
		}
		seen[d] = true
		if d == "Ljava/io/Serializable;" {
			return true
		}
		ci := t.byDesc[d]
		if ci == nil {
			return false
		}
		if walk(ci.Super, depth+1) {
			return true
		}
		for _, i := range ci.Interfaces {
			if walk(i, depth+1) {
				return true
			}
		}
		return false
	}
	return walk(desc, 0)
}

// MemberRenameConfig 是跨 DEX 成员覆盖改名的全局输入。
type MemberRenameConfig struct {
	// ClassMap 是已决定的类改名表（旧描述符 -> 新描述符）。成员改名只作用于
	// 「声明类本身也在本表里」的成员（A2 门禁）。
	ClassMap map[string]string
	// NameKeep 是调用方额外要求全局保留的成员名（例如布局 android:onClick
	// 引用的方法名）。const-string / 注解字符串由本函数自行汇总。
	NameKeep map[string]bool
	// Keep 是 -keep-rules（类.成员 通配）。
	Keep []string
	// ExcludeNames 是「已由值键改名路径处理」的名字集合。
	//
	// 值键路径（RebuildOptions.Rename）按字符串值改名，会一并改写所有同名引用。
	// 若同一个名字既走值键又走按条目覆盖，两条通道会打架（同一定义被两个名字
	// 引用），因此这里显式排除，保证互斥。
	ExcludeNames map[string]bool
	// Reserved 是值键路径/其它模块已经分配的新名字，生成器必须避开。
	Reserved map[string]bool
	// Prefix 是新名首字母（默认 "a"）。
	Prefix string
}

// MemberRenameResult 是每个 DEX 的「旧索引 -> 新名」覆盖表。
type MemberRenameResult struct {
	// MethodByID / FieldByID 与输入 files 同序。
	MethodByID []map[uint32]string
	FieldByID  []map[uint32]string
	// Methods / Fields 是分配了新名的**定义**数（去重后的 (类,名字,原型) 数）。
	Methods, Fields int
	// MethodRefs / FieldRefs 是被改写的 method_id / field_id 引用条目数。
	MethodRefs, FieldRefs int
}

// PlanMemberRenames 在全部 DEX 的全局视图上，为「可证明安全」的成员决定按条目
// 覆盖改名。
//
// 本实现严格收敛到方案文档的最小可落地子集（Phase 1）：
//
//  1. 私有方法 / 私有字段：ACC_PRIVATE 成员不参与虚方法派发，也不可能被外部类
//     按名字调用，只要引用点都在我们处理的 DEX 集合内，改名就是安全的。
//  2. 静态方法 / 静态字段：静态成员没有覆写语义（只有隐藏，且引用会一起改写）。
//
// 硬不变量（唯一会崩溃的点是覆写关系被破坏）：
//
//	私有/静态成员不参与虚派发，因此改名不会破坏任何覆写关系；且新名由全局
//	唯一生成器分配（避开所有既有字符串），不会让两个原本不同名的方法撞成同名，
//	也就不会凭空创造新的覆写链。
//
// 实例非私有成员（需要虚方法族并查集才能证明安全）**本实现一律不改**，
// 宁可少改不可改错：那正是 Dhizuku onViewAttachedToWindow 崩溃的根源。
func PlanMemberRenames(files []*File, cfg MemberRenameConfig) (*MemberRenameResult, error) {
	res := &MemberRenameResult{
		MethodByID: make([]map[uint32]string, len(files)),
		FieldByID:  make([]map[uint32]string, len(files)),
	}
	if len(files) == 0 {
		return res, nil
	}

	// ---- 1) 全局类定义视图（跨 DEX 解析静态成员的声明）----
	var allInfos []ClassInfo
	seenDesc := map[string]bool{}
	dupDesc := map[string]bool{}
	for _, f := range files {
		infos, err := f.ClassInfos()
		if err != nil {
			return nil, fmt.Errorf("dex: 读取类信息失败: %w", err)
		}
		for _, ci := range infos {
			if seenDesc[ci.Desc] {
				// 同一类被两个 DEX 定义是非法 MultiDex；无法判断以谁为准，
				// 保守地整类跳过（不改它的任何成员）。
				dupDesc[ci.Desc] = true
				continue
			}
			seenDesc[ci.Desc] = true
			allInfos = append(allInfos, ci)
		}
	}
	resolver := newTypeResolver(allInfos)

	// ---- 2) 名称级保留并集（C1/C2）----
	//
	// 名字只要在**任一** DEX 的 const-string / 注解字符串里出现，就全局保留：
	// getDeclaredMethod("foo") / getField("foo") / JNI 都按字符串找名字，而我们
	// 无法区分它是反射还是普通文案，只能保守。
	nameKeep := map[string]bool{}
	for n := range cfg.NameKeep {
		nameKeep[n] = true
	}
	for _, f := range files {
		u, err := f.StringUsage()
		if err != nil {
			return nil, fmt.Errorf("dex: 扫描字符串用途失败: %w", err)
		}
		for idx := range u.Const {
			if s, err := f.String(idx); err == nil {
				nameKeep[s] = true
			}
		}
		for idx := range u.Anno {
			if s, err := f.String(idx); err == nil {
				nameKeep[s] = true
			}
		}
	}

	// ---- 3) 生成器占用集合：全部既有字符串 + 调用方保留 ----
	used := map[string]bool{}
	for _, f := range files {
		for i := uint32(0); i < f.NString; i++ {
			if s, err := f.String(i); err == nil {
				used[s] = true
			}
		}
	}
	for n := range cfg.Reserved {
		used[n] = true
	}

	// ---- 4) 逐 DEX 收集候选：索引 -> 定义键 ----
	type keyRef struct{ key, name string }
	methodKeys := make([][]keyRef, len(files))
	fieldKeys := make([][]keyRef, len(files))
	methodDefs := map[string]bool{}
	fieldDefs := map[string]bool{}

	for fi, f := range files {
		methodKeys[fi] = make([]keyRef, f.NMethod)
		for i := uint32(0); i < f.NMethod; i++ {
			ref, err := f.MethodRefAt(i)
			if err != nil {
				return nil, err
			}
			cls, err := f.Type(uint32(ref.ClassIdx))
			if err != nil {
				continue
			}
			name, err := f.String(ref.NameIdx)
			if err != nil {
				continue
			}
			if nameKeep[name] || cfg.ExcludeNames[name] || isAlwaysKeepMethodName(name) ||
				isSyntheticMemberName(name) {
				continue
			}
			proto, err := f.ProtoDesc(uint32(ref.ProtoIdx))
			if err != nil {
				continue
			}
			declDesc, decl, ok := resolver.resolveMethodDecl(cls, name, proto)
			if !ok || decl == nil || dupDesc[declDesc] {
				continue
			}
			if !memberClassRenamable(cfg.ClassMap, declDesc) {
				continue
			}
			// 只改私有/静态方法：它们不参与虚派发，不可能是覆写。
			if decl.Access&accPrivate == 0 && decl.Access&accStatic == 0 {
				continue
			}
			if decl.Native || decl.Access&(accBridge|accSynthetic) != 0 {
				continue
			}
			if ci := resolver.byDesc[declDesc]; ci == nil || classUnrenameableForMembers(ci) {
				continue
			}
			if isKeptMemberRule(cfg.Keep, declDesc, name) {
				continue
			}
			key := methodDefKey(declDesc, name, proto)
			methodKeys[fi][i] = keyRef{key: key, name: name}
			methodDefs[key] = true
		}

		fieldKeys[fi] = make([]keyRef, f.NField)
		for i := uint32(0); i < f.NField; i++ {
			classIdx, typeIdx, nameIdx, err := f.FieldRefAt(i)
			if err != nil {
				return nil, err
			}
			cls, err := f.Type(uint32(classIdx))
			if err != nil {
				continue
			}
			name, err := f.String(nameIdx)
			if err != nil {
				continue
			}
			typ, err := f.Type(uint32(typeIdx))
			if err != nil {
				continue
			}
			if nameKeep[name] || cfg.ExcludeNames[name] || isKeepFieldName(name) ||
				isSyntheticMemberName(name) {
				continue
			}
			declDesc, decl, ok := resolver.resolveFieldDecl(cls, name, typ)
			if !ok || decl == nil || dupDesc[declDesc] {
				continue
			}
			if !memberClassRenamable(cfg.ClassMap, declDesc) {
				continue
			}
			if decl.Access&accPrivate == 0 && decl.Access&accStatic == 0 {
				continue
			}
			if decl.Access&(accSynthetic|accEnum) != 0 {
				continue
			}
			ci := resolver.byDesc[declDesc]
			if ci == nil || classUnrenameableForMembers(ci) {
				continue
			}
			// 实例字段可能被默认序列化按字段名读写：可见地实现 Serializable
			// 的类不改；继承闭包不可见时无法排除隐藏实现，也保守不改。
			// 静态字段不参与序列化，不受此限。
			if decl.Access&accStatic == 0 {
				if classImplementsSerializable(resolver, declDesc) || resolver.hasInvisibleSuper(declDesc) {
					continue
				}
			}
			if isKeptMemberRule(cfg.Keep, declDesc, name) {
				continue
			}
			key := fieldDefKey(declDesc, name, typ)
			fieldKeys[fi][i] = keyRef{key: key, name: name}
			fieldDefs[key] = true
		}
	}

	// ---- 5) 全局统一命名（跨 DEX 同一 (类,名字,原型) 取同一个新名）----
	namesM := assignMemberNames(methodDefs, used, cfg.Prefix)
	namesF := assignMemberNames(fieldDefs, used, cfg.Prefix)
	res.Methods = len(namesM)
	res.Fields = len(namesF)

	// ---- 6) 回填每个 DEX 的索引覆盖表 ----
	for fi := range files {
		for i := range methodKeys[fi] {
			k := methodKeys[fi][i].key
			if k == "" {
				continue
			}
			if res.MethodByID[fi] == nil {
				res.MethodByID[fi] = map[uint32]string{}
			}
			res.MethodByID[fi][uint32(i)] = namesM[k]
			res.MethodRefs++
		}
		for i := range fieldKeys[fi] {
			k := fieldKeys[fi][i].key
			if k == "" {
				continue
			}
			if res.FieldByID[fi] == nil {
				res.FieldByID[fi] = map[uint32]string{}
			}
			res.FieldByID[fi][uint32(i)] = namesF[k]
			res.FieldRefs++
		}
	}
	return res, nil
}

// methodDefKey / fieldDefKey 是跨 DEX 稳定的成员定义标识。
//
// 键里用**旧描述符**而不是新描述符：类名在各 DEX 上统一改名，但成员决策必须在
// 改名之前汇总，用旧名才能让「定义方」与「引用方」指向同一个键。
func methodDefKey(declDesc, name, proto string) string {
	return "M\x00" + declDesc + "\x00" + name + "\x00" + proto
}

func fieldDefKey(declDesc, name, typ string) string {
	return "F\x00" + declDesc + "\x00" + name + "\x00" + typ
}

// assignMemberNames 为一组定义键分配全局唯一新名。
//
// 排序保证确定性；生成器避开 used 里的全部既有字符串，因此新名不会与任何现存
// 成员名/类型名碰撞，也不会让两个定义撞成同名（方案文档 B8：不新建覆写）。
func assignMemberNames(defs map[string]bool, used map[string]bool, prefix string) map[string]string {
	keys := make([]string, 0, len(defs))
	for k := range defs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make(map[string]string, len(keys))
	seq := 0
	for _, k := range keys {
		for {
			seq++
			n := encodeName(seq, prefix)
			if used[n] {
				continue
			}
			used[n] = true
			out[k] = n
			break
		}
	}
	return out
}
