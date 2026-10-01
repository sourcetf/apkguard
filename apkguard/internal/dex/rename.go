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

// javaPrefixes 是必须保留的包前缀。
//
// 这些类由 JDK / Android 框架 / 主流三方库提供，通常不在本 DEX 中定义，
// 但会被本 DEX 引用；改名会破坏运行时链接。
var javaPrefixes = []string{
	"Ljava/", "Ljavax/", "Ljdk/", "Lsun/", "Ldalvik/", "Lorg/w3c/",
	"Lorg/xml/", "Lorg/json/", "Lorg/apache/", "Lorg/xmlpull/",
	"Landroid/", "Landroidx/", "Lcom/google/", "Lkotlin/", "Lkotlinx/",
	"Lorg/jetbrains/", "Lokhttp3/", "Lokio/", "Lretrofit2/", "Lio/reactivex/",
	"Lorg/slf4j/", "Lcom/squareup/", "Lcom/bumptech/", "Lcom/facebook/",
	"Lio/flutter/", "Lcom/tencent/", "Lcom/alibaba/", "Lcom/taobao/",
	"Lcom/umeng/", "Lcom/baidu/", "Lcom/iflytek/", "Lcom/amap/", "Lcom/qq/",
	"Lorg/bouncycastle/", "Lcom/nostra13/", "Lorg/greenrobot/",
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

	// byDesc 是「类描述符 -> 类定义」，用于查父类型与成员访问标志。
	byDesc map[string]*ClassInfo
	// invisCache 缓存「该类（传递地）是否有本 DEX 之外的父类型」。
	invisCache map[string]bool
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
		byDesc:       make(map[string]*ClassInfo, len(infos)),
		invisCache:   map[string]bool{},
	}
	for i := range r.infos {
		r.byDesc[r.infos[i].Desc] = &r.infos[i]
	}
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
	hasInner := map[string]bool{}
	for _, ci := range r.infos {
		if i := strings.Index(ci.Desc, "$"); i > 0 {
			hasInner[ci.Desc[:i+1]] = true
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
	case hasAnyPrefix(ci.Desc, javaPrefixes):
		return "平台/三方库类"
	case ci.Access&accAnnotation != 0:
		return "注解类（按名称反射读取）"
	case reflected[ci.Desc]:
		return "类名出现在字符串常量中（可能被反射）"
	case r.cfg.ReflectedNames[descToJava(ci.Desc)]:
		return "类名在其它 DEX 的字符串常量中出现（可能被反射）"
	case isEntryPoint(ci):
		return "Android 组件/入口类"
	case strings.Contains(ci.Desc, "$"):
		return "内部类（与外层类命名强耦合）"
	case hasInner[ci.Desc]:
		return "含内部类（需整体处理）"
	case !strings.HasPrefix(ci.Desc, "L"):
		return "非类描述符"
	}
	return ""
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
func (r *Renamer) hasInvisibleSuper(desc string) bool {
	if v, ok := r.invisCache[desc]; ok {
		return v
	}
	// 先占位，避免继承链出现环时无限递归。
	r.invisCache[desc] = false
	ci := r.byDesc[desc]
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
		if _, ok := r.byDesc[s]; !ok {
			// 父类型不在本 DEX 里 → 看不见它的方法表
			res = true
			break
		}
		if r.hasInvisibleSuper(s) {
			res = true
			break
		}
	}
	r.invisCache[desc] = res
	return res
}

// mayOverrideInvisible 判断「类 classDesc 上名为 name、签名为 sig 的方法」
// 是否可能覆写本 DEX 之外的方法（私有/静态方法不参与覆写，不算）。
func (r *Renamer) mayOverrideInvisible(name, classDesc, sig string) bool {
	ci := r.byDesc[classDesc]
	if ci == nil {
		return false
	}
	if !r.hasInvisibleSuper(classDesc) {
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
			// 同 planMethods：可见链里找不到声明的字段引用同样不能改名
			if !r.resolvesVisibly(rf.class, name, rf.sig) {
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
	for _, k := range keepMethodNames {
		if name == k {
			return true
		}
	}
	// 以 < 开头的是编译器生成的特殊方法
	return strings.HasPrefix(name, "<")
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
	full := descToJava(classDesc) + "." + member
	for _, rule := range r.cfg.Keep {
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
	if slash := strings.LastIndex(body, "/"); slash >= 0 {
		pkg = "L" + body[:slash+1]
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
func (r *Renamer) resolvesVisibly(classDesc, name, proto string) bool {
	seen := map[string]bool{}
	var walk func(d string, depth int) bool
	walk = func(d string, depth int) bool {
		if d == "" || seen[d] || depth > 32 {
			return false
		}
		seen[d] = true
		ci := r.byDesc[d]
		if ci == nil {
			return d == "Ljava/lang/Object;" && objectHasMember(name, proto)
		}
		for _, m := range ci.Methods() {
			if m.Name == name && m.Proto == proto {
				return true
			}
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
	return walk(classDesc, 0)
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
