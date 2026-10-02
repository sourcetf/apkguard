package passes

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"unicode/utf16"

	"apkguard/internal/axml"
	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/pipeline"
	"apkguard/internal/zipx"
)

// ---- A17 嵌套 APK 诱饵 ----
//
// 攻击场景（对参考样本手法的**反向利用**）：
//
// 参考样本 `sample.apk` 是「双层 APK」——外层薄壳把一个 14.4 MB、含 8 个 DEX、
// 22366 个类的完整内层 APK 加密后塞进 `assets/*.zip`，运行时用 PackageInstaller
// 二次安装。自动化脱壳脚本面对这种样本，最常用的启发式是：
//
//	① 遍历 assets，挑出体积最大 / 魔数为 PK\x03\x04（zip/APK 形态）的条目；
//	② 把它当内层 APK 解包；
//	③ 在解出的东西上继续静态分析。
//
// A17 反过来喂给这套脚本一个「看起来完全正常」的假应用：在 assets 下（与真实
// 载荷**同一目录树、同一命名形态**）放一个结构完整的真 APK，里面自带合法的
// AndroidManifest.xml、resources.arsc、多个可被 dex.Parse 通过的 classes*.dex、
// assets/ 与 META-INF/。脚本「成功解包」后拿到的是一个有 Manifest、有资源、
// 有多个 DEX 的应用，于是把大量分析时间花在假目标上；而真载荷是 AES 加密的
// 非 zip 密文，无法被同一套启发式识别。
//
// 与 B8（载荷容器化）的关系：
//   - B8 已经把真实载荷改名进 `assets/<seg1>/<seg2>/<hex>.<ext>` 目录树，并植入
//     一个「高熵 .dat + 假包名 json」的诱饵 zip；
//   - A17 是它的**加强版**：诱饵从「装了一堆高熵字节的容器」升级为「一个结构
//     完整、能被 apktool/jadx 直接打开的完整假 APK」。两者互不冲突：
//     B8 动的是真实载荷的条目名，A17 只往同一目录树里**新增**一个条目，
//     既不覆盖真载荷也不改壳/Manifest。同时启用时脚本会看到两个同构候选。
//
// 硬约束（都已在实现里落实）：
//   - 只新增条目，绝不改动任何真载荷 / 壳 DEX / Manifest（应用照常启动）；
//   - 新增的外层条目名必须过 manifestCollision，且不与既有条目重名
//     （否则会撞 v1 签名关键文件或破坏 apksigner 校验）；
//   - 同 seed 完全可复现（newRand(opts.Seed)）。
type nestedDecoyAPK struct{}

func (nestedDecoyAPK) ID() config.FeatureID { return "A17" }
func (nestedDecoyAPK) In() pipeline.Level   { return pipeline.LevelZip }
func (nestedDecoyAPK) Out() pipeline.Level  { return pipeline.LevelZip }

// nestedAPKPadSlack 是「为体积对齐预留的 ZIP 结构开销」估算值。
//
// 内层 zip 的属性名、本地头、中央目录合计约 100~200 字节；多留一点避免
// 反复补写。最终体积略有出入不影响欺骗效果。
const nestedAPKPadSlack = 512

func (n *nestedDecoyAPK) Run(_ context.Context, art *pipeline.Artifact, opts *config.Options) error {
	pkg := decoyPkgForAPK(opts)
	size := decoyAPKTargetSize(art, opts)

	used := map[string]bool{}
	for _, e := range art.Entries() {
		used[e.NameString()] = true
	}
	name := nestedAPKEntryName(opts.Seed, used)

	blob, entries, err := buildDecoyAPK(opts.Seed, pkg, size)
	if err != nil {
		return fmt.Errorf("A17：构造嵌套诱饵 APK 失败: %w", err)
	}
	// 双保险：外层条目名不得撞签名关键文件（name 以 assets/ 开头，本就不会，
	// 但这里显式校验，避免将来改动命名后静默引入风险）。
	if manifestCollision(name) {
		return fmt.Errorf("A17：诱饵条目名 %q 会与签名关键文件冲突", name)
	}
	if used[name] {
		return fmt.Errorf("A17：诱饵条目名 %q 与现有条目重名（会导致 apksigner 拒绝归档）", name)
	}

	pipeline.Add(art, zipx.NewStored(name, blob))

	art.Note("A17 嵌套 APK 诱饵：在 %s 植入一个结构完整的假 APK（%d 条目、%d 字节、包名 %q，含合法 Manifest/arsc/classes*.dex）；"+
		"它与真载荷同一目录树、命名同构，按「assets 最大条目」或「PK 形态」抓载荷的自动化脱壳脚本会先拿到它，解包后得到一个看起来完全正常的假应用",
		name, entries, len(blob), pkg)
	art.Stat("A17.bytes", fmt.Sprint(len(blob)))
	art.Stat("A17.entries", fmt.Sprint(entries))
	art.Stat("A17.name", name)
	art.Stat("A17.pkg", pkg)
	return nil
}

// decoyPkgForAPK 返回假 APK 使用的包名。
//
// 与 B8 共用 `-decoy-pkg`：两者措辞一致时，脚本看到的「假包名」在同一条线索上
// 自洽，误导更强。未指定时退回 B8 的默认假包名。
func decoyPkgForAPK(opts *config.Options) string {
	p := strings.TrimSpace(opts.DecoyPkg)
	if p == "" {
		p = defaultDecoyPkg
	}
	return sanitizePkg(p)
}

// sanitizePkg 把用户输入规整成一个合法的 Java 包名。
//
// 包名会同时写进假 Manifest、假 resources.arsc 的包块和假 DEX 的类描述符，
// 一旦含非法字符（空格、/、非 ASCII 等），假 APK 内部就会自相矛盾、
// 被工具一眼看穿。这里只保留字母/数字/下划线与点，非法则退回默认值。
func sanitizePkg(p string) string {
	var b strings.Builder
	for _, r := range p {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '.':
			b.WriteRune(r)
		}
	}
	out := strings.Trim(b.String(), ".")
	if out == "" {
		return defaultDecoyPkg
	}
	// 逐段校验：不能有空段、不能以数字开头。
	for _, s := range strings.Split(out, ".") {
		if s == "" {
			return defaultDecoyPkg
		}
		if c := s[0]; c >= '0' && c <= '9' {
			return defaultDecoyPkg
		}
	}
	return out
}

// decoyAPKTargetSize 计算假 APK 的目标体积（字节）。
//
// 默认值：优先取真实载荷总量的 1/4（让诱饵成为 assets 里**最大的单个条目**，
// 从而被「挑最大条目」的脚本优先命中），再钳到 1~4 MB；没有载荷（未启用 B1）
// 时用 2 MB。用户显式指定 `-decoy-apk-mb` 时以它为准，并钳在 1~64 MB
// 之间防止误填造成产物失控。
func decoyAPKTargetSize(art *pipeline.Artifact, opts *config.Options) int {
	if opts.DecoyAPKMB > 0 {
		mb := opts.DecoyAPKMB
		if mb < 1 {
			mb = 1
		}
		if mb > 64 {
			mb = 64
		}
		return mb << 20
	}
	size := 2 << 20
	if sp := payloadsOf(art); sp != nil && len(sp.Items) > 0 {
		size = packTotal(sp) / 4
	}
	if size < 1<<20 {
		size = 1 << 20
	}
	if size > 4<<20 {
		size = 4 << 20
	}
	return size
}

// nestedAPKEntryName 派生外层诱饵条目名，使其与 B8 的真实载荷**同构**。
//
// B8 把真实载荷放进 `assets/<word>/<hex4>/`（目录由
// sha256("apkguard/container/"+seed) 派生），文件名是 `<hex6>.<dat|bin|res|pack>`。
// A17 复用完全相同的目录派生与扩展名池，只换一个哈希域，因此从路径与命名上
// 无法区分「这是真载荷还是诱饵」——只能逐个打开内容，而真正载荷是密文。
func nestedAPKEntryName(seed string, used map[string]bool) string {
	sum := sha256.Sum256([]byte("apkguard/container/" + seed))
	seg1 := containerWords[int(sum[0])%len(containerWords)]
	seg2 := hex.EncodeToString(sum[1:5])
	for i := 0; ; i++ {
		d := sha256.Sum256([]byte(fmt.Sprintf("apkguard/nestedapk/%s/%d", seed, i)))
		name := fmt.Sprintf("assets/%s/%s/%s.%s", seg1, seg2,
			hex.EncodeToString(d[:6]), containerExts[int(d[6])%len(containerExts)])
		if !used[name] && !manifestCollision(name) {
			return name
		}
	}
}

// buildDecoyAPK 在内存里拼出一个结构完整的假 APK（zip 字节流）。
//
// 返回 (字节流, 条目数, error)。target 是目标体积；实际内容由真实结构 + 一个
// 高熵填充条目撑起来，写完后校验长度并按需再补一次，使产物体积贴近 target。
func buildDecoyAPK(seed, pkg string, target int) ([]byte, int, error) {
	// 先用「无填充」的条目集算一次基线，据此决定填充量。
	base, _, err := decoyAPKArchive(seed, pkg, 0)
	if err != nil {
		return nil, 0, err
	}
	baseBlob := zipx.Write(base, zipx.DefaultAlign())
	pad := target - len(baseBlob) - nestedAPKPadSlack
	if pad < 0 {
		pad = 0
	}

	var blob []byte
	entries := 0
	for i := 0; i < 3; i++ {
		a, n, err := decoyAPKArchive(seed, pkg, pad)
		if err != nil {
			return nil, 0, err
		}
		blob = zipx.Write(a, zipx.DefaultAlign())
		entries = n
		if len(blob) >= target || pad == 0 {
			break
		}
		pad += target - len(blob) + 256
	}
	return blob, entries, nil
}

// decoyAPKArchive 构造假 APK 的全部 ZIP 条目。
//
// pad 为 assets 内高熵填充条目的字节数（0 表示不填充）。
func decoyAPKArchive(seed, pkg string, pad int) (*zipx.Archive, int, error) {
	rnd := newRand(seed + "/nestedapk")
	pkgPath := strings.ReplaceAll(pkg, ".", "/")

	// 三个 DEX，每个放几个 R8 风格类：给静态分析者一个「多 DEX 的真实应用」
	// 观感，而不是单文件空壳。App 继承 android.app.Application、两个 Activity
	// 继承 android.app.Activity（与假 Manifest 的声明一致），其余继承 Object；
	// 每个类都带字段/构造器/做真实位运算的方法，不是一眼假空壳。
	dex1, err := decoyDex(pkgPath, []decoyClassReq{
		{"App", superApplication},
		{"MainActivity", superActivity},
		{"SettingsActivity", superActivity},
		{"Utils", ""},
	})
	if err != nil {
		return nil, 0, err
	}
	dex2, err := decoyDex(pkgPath, []decoyClassReq{
		{"NetworkClient", ""},
		{"DataRepository", ""},
		{"ApiService", ""},
	})
	if err != nil {
		return nil, 0, err
	}
	dex3, err := decoyDex(pkgPath, []decoyClassReq{
		{"ImageLoader", ""},
		{"CacheManager", ""},
		{"CryptoUtils", ""},
	})
	if err != nil {
		return nil, 0, err
	}

	base := decoyAssetBase(seed)
	manifest := nestedAPKManifestAXML(rnd, pkg)
	arsc := decoyResourcesARSC(pkg)
	mf := decoyJarManifest()

	// 假 assets：一个与 B8 容器内同构的假配置 JSON + 一个看起来像资源的顺序
	// 字节文件；填充条目单独追加。
	cfg, err := json.MarshalIndent(decoyConfig{
		PackageName: pkg,
		AppName:     base,
		APKFileName: base + ".dat",
	}, "", "  ")
	if err != nil {
		return nil, 0, fmt.Errorf("生成假 APK 配置失败: %w", err)
	}
	assetBin := sequentialBytes(8<<10 + rnd.Intn(8<<10))

	archive := &zipx.Archive{}
	archive.Entries = append(archive.Entries, zipx.NewStored("AndroidManifest.xml", manifest))
	archive.Entries = append(archive.Entries, zipx.NewStored("classes.dex", dex1))
	archive.Entries = append(archive.Entries, zipx.NewStored("classes2.dex", dex2))
	archive.Entries = append(archive.Entries, zipx.NewStored("classes3.dex", dex3))
	archive.Entries = append(archive.Entries, zipx.NewStored("assets/"+base+".json", cfg))
	archive.Entries = append(archive.Entries, zipx.NewStored("assets/"+base+"_d.bin", assetBin))
	archive.Entries = append(archive.Entries, zipx.NewStored("resources.arsc", arsc))
	archive.Entries = append(archive.Entries, zipx.NewStored("META-INF/MANIFEST.MF", mf))
	if pad > 0 {
		blob := make([]byte, pad)
		for i := range blob {
			blob[i] = byte(rnd.Intn(256))
		}
		archive.Entries = append(archive.Entries, zipx.NewStored("assets/"+base+".dat", blob))
	}
	return archive, len(archive.Entries), nil
}

// 假应用里的 framework 基类描述符。
//
// 这些类**不在假 APK 的 DEX 里**，只是类型/方法引用——DEX 规范允许引用
// 未随包提供的类（真实应用也大量引用 android.* 框架类）。让 App/MainActivity
// 继承正确的框架基类，是为了让假应用在人类分析者眼里也「像真的」：
// 一个继承 Object 的 MainActivity 是一眼可辨的填充物。
const (
	superApplication = "Landroid/app/Application;"
	superActivity    = "Landroid/app/Activity;"
)

// decoyClassReq 描述假 DEX 里的一个类：类名（不含包）与父类（空串=Object）。
type decoyClassReq struct {
	name  string
	super string
}

// decoyDex 生成一个只含指定类的合法 DEX。
func decoyDex(prefix string, reqs []decoyClassReq) ([]byte, error) {
	specs := make([]dex.ClassSpec, 0, len(reqs))
	for i, r := range reqs {
		s, err := decoyClassSpec("L"+prefix+"/"+r.name+";", r.super, int8(0x11+(i*7)%0x60))
		if err != nil {
			return nil, err
		}
		specs = append(specs, s)
	}
	return dex.Build(dex.Addition{Classes: specs})
}

// decoyClassSpec 生成一个「形似 R8 产物」的类规格。
//
// 内容：一个私有 int 字段 state、一个调用 super.<init>() 的构造器、一个做真实
// 异或位运算的 check(I)I 方法（输入不同则输出不同，看起来像某种校验）。
// 这些方法体都是合法可校验的字节码，反编译视图不会一眼看出是填充物。
func decoyClassSpec(name, super string, mix int8) (dex.ClassSpec, error) {
	if super == "" {
		super = "Ljava/lang/Object;"
	}
	ctor, err := decoySuperCtor(super)
	if err != nil {
		return dex.ClassSpec{}, err
	}
	check, err := decoyBitwiseCheck(mix)
	if err != nil {
		return dex.ClassSpec{}, err
	}
	return dex.ClassSpec{
		Name:   name,
		Super:  super,
		Access: 0x0001, // public
		Fields: []dex.ClassField{{Name: "state", Type: "I", Access: 0x0002 /* private */}},
		Methods: []dex.ClassMethod{
			{Name: "<init>", Proto: dex.ProtoSpec{Ret: "V"}, Access: 0x0001, Code: ctor},
			{Name: "check", Proto: dex.ProtoSpec{Ret: "I", Params: []string{"I"}}, Access: 0x0001, Code: check},
		},
	}, nil
}

// decoySuperCtor 生成 <init>()V：只调用给定父类的构造器。
// registers=2、ins=1 → this 在 v1。
func decoySuperCtor(super string) (*dex.CodeBlob, error) {
	a := dex.NewAsm()
	if err := a.InvokeDirect([]int{1}, dex.MethodSpec{
		Class: super, Name: "<init>", Proto: dex.ProtoSpec{Ret: "V"},
	}); err != nil {
		return nil, err
	}
	a.ReturnVoid()
	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	return &dex.CodeBlob{Registers: 2, Ins: 1, Outs: 1, Insns: insns, Patches: patches}, nil
}

// decoyBitwiseCheck 生成 check(I)I：做一个真实的异或位运算并返回。
// registers=3、ins=2 → this 在 v1、入参 a 在 v2。
func decoyBitwiseCheck(mix int8) (*dex.CodeBlob, error) {
	a := dex.NewAsm()
	a.Const16(0, int16(mix)) // v0 = mix
	a.XorInt(2, 2, 0)        // v2 = a ^ mix
	a.Return(2)
	insns, patches, err := a.Assemble()
	if err != nil {
		return nil, err
	}
	return &dex.CodeBlob{Registers: 3, Ins: 2, Outs: 1, Insns: insns, Patches: patches}, nil
}

// decoyAssetBase 为假 APK 内部的 asset 文件名派生一个词基。
//
// 复用 B8 的容器词表，使假 APK 内部的 asset 名看起来像普通缓存/资源文件。
func decoyAssetBase(seed string) string {
	sum := sha256.Sum256([]byte("apkguard/nestedapk/base/" + seed))
	return containerWords[int(sum[0])%len(containerWords)] + "_" + hex.EncodeToString(sum[1:5])
}

// decoyJarManifest 返回假 APK 内 META-INF/MANIFEST.MF 的合法内容。
//
// 这是一份**未被签名**的主清单（没有配套 .SF/.RSA），因此不会触发 v1 校验。
// 关键点：它位于假 APK **内部**，不是外层产物的条目——外层 zipx.Write 会把
// 假 APK 整体当作一个 Stored 条目的原始字节写入，绝不会把内层条目「展平」
// 到外层，因此不可能与外层真实的 META-INF/MANIFEST.MF 冲突。
func decoyJarManifest() []byte {
	var b strings.Builder
	b.WriteString("Manifest-Version: 1.0\r\n")
	b.WriteString("Created-By: 1.0 (Android)\r\n")
	b.WriteString("Built-By: R8\r\n")
	b.WriteString("\r\n")
	return []byte(b.String())
}

// decoyResourcesARSC 构造一个**结构合法的最小 resources.arsc**。
//
// 取舍：这里生成的是「表头 + 全局字符串池 + 一个空的资源包块」——能被
// arsc.Parse 接受，包名与假 Manifest 一致；但不含任何真实类型/资源条目
// （TypeSpec/Type 为空）。原因是：凭空生成带真实资源项的 arsc 需要构造
// TypeSpec/Type/entry 全套结构，风险高、收益低；而脱壳脚本抓的是
// 「Manifest + DEX」，「资源表存在且合法」已足以让它相信这是个正常应用。
// 诚实的局限：apktool 能打开它，但反编译出的资源表是空的。
func decoyResourcesARSC(pkg string) []byte {
	global := axml.EncodeStringPool([]string{"", pkg, "res/", "res/layout/", "res/xml/"}, true)
	typePool := axml.EncodeStringPool(nil, true)
	keyPool := axml.EncodeStringPool(nil, true)

	// ResTable_package（headerSize = 288，含 typeIdOffset）。
	pkgChunk := make([]byte, 288)
	binary.LittleEndian.PutUint16(pkgChunk[0:], 0x0200) // RES_TABLE_PACKAGE_TYPE
	binary.LittleEndian.PutUint16(pkgChunk[2:], 288)    // headerSize
	binary.LittleEndian.PutUint32(pkgChunk[8:], 0x7f)   // id（应用资源包）
	putUTF16Field(pkgChunk[12:268], pkg, 128)
	binary.LittleEndian.PutUint32(pkgChunk[268:], 288)                       // typeStrings（相对包块）
	binary.LittleEndian.PutUint32(pkgChunk[272:], 0)                         // lastPublicType
	binary.LittleEndian.PutUint32(pkgChunk[276:], uint32(288+len(typePool))) // keyStrings
	binary.LittleEndian.PutUint32(pkgChunk[280:], 0)                         // lastPublicKey
	binary.LittleEndian.PutUint32(pkgChunk[284:], 0)                         // typeIdOffset
	pkgChunk = append(pkgChunk, typePool...)
	pkgChunk = append(pkgChunk, keyPool...)
	binary.LittleEndian.PutUint32(pkgChunk[4:], uint32(len(pkgChunk)))

	out := make([]byte, 12)
	binary.LittleEndian.PutUint16(out[0:], 0x0002) // RES_TABLE_TYPE
	binary.LittleEndian.PutUint16(out[2:], 12)     // headerSize
	binary.LittleEndian.PutUint32(out[8:], 1)      // packageCount
	out = append(out, global...)
	out = append(out, pkgChunk...)
	binary.LittleEndian.PutUint32(out[4:], uint32(len(out)))
	return out
}

// putUTF16Field 把 s 以 UTF-16LE 写进 dst，最多 maxUnits 个码元，其余补零。
func putUTF16Field(dst []byte, s string, maxUnits int) {
	units := utf16.Encode([]rune(s))
	n := len(units)
	if n > maxUnits {
		n = maxUnits
	}
	for i := 0; i < n; i++ {
		binary.LittleEndian.PutUint16(dst[2*i:], units[i])
	}
}

// ---- 假 Manifest 的二进制 AXML 构造 ----
//
// 复用 junk.go 的 node/le32/encodePool（同包工具），保证生成的是**合法** AXML：
// 字符串池 + 命名空间声明 + 嵌套的 manifest/application/activity 元素。
// 这正是 A17 的核心价值——假 APK 自带一个能被 axml.Parse（以及 aapt/jadx）
// 正常解析的 Manifest，而不是一段假装是 XML 的垃圾字节。

type mfAttr struct {
	ns   string // "" 表示无命名空间；"android" 表示 AndroidNS
	name string
	kind byte // 0=string 1=int 2=bool
	s    string
	i    int32
	b    bool
}

type mfNode struct {
	name  string
	attrs []mfAttr
	kids  []*mfNode
}

func mfString(ns, name, v string) mfAttr { return mfAttr{ns: ns, name: name, kind: 0, s: v} }
func mfInt(ns, name string, v int32) mfAttr {
	return mfAttr{ns: ns, name: name, kind: 1, i: v}
}
func mfBool(ns, name string, v bool) mfAttr {
	return mfAttr{ns: ns, name: name, kind: 2, b: v}
}

// nestedAPKManifestAXML 生成假 APK 的 AndroidManifest.xml。
//
// 名字带 nestedAPK 前缀以避免与 A16（decoycore.go 的 decoyManifestAXML）冲突。
func nestedAPKManifestAXML(rnd *rand.Rand, pkg string) []byte {
	root := &mfNode{
		name: "manifest",
		attrs: []mfAttr{
			mfString("", "package", pkg),
			mfInt("android", "versionCode", int32(10+rnd.Intn(90))),
			mfString("android", "versionName", fmt.Sprintf("1.%d.%d", rnd.Intn(9), rnd.Intn(20))),
		},
		kids: []*mfNode{
			{
				name: "uses-sdk",
				attrs: []mfAttr{
					mfInt("android", "minSdkVersion", 24),
					mfInt("android", "targetSdkVersion", 34),
				},
			},
			{
				name: "application",
				attrs: []mfAttr{
					mfString("android", "name", pkg+".App"),
					mfString("android", "label", pkg+".App"),
					mfBool("android", "allowBackup", false),
					mfBool("android", "debuggable", false),
				},
				kids: []*mfNode{
					{
						name: "activity",
						attrs: []mfAttr{
							mfString("android", "name", pkg+".MainActivity"),
							mfBool("android", "exported", true),
						},
						kids: []*mfNode{
							{
								name: "intent-filter",
								kids: []*mfNode{
									{name: "action", attrs: []mfAttr{mfString("android", "name", "android.intent.action.MAIN")}},
									{name: "category", attrs: []mfAttr{mfString("android", "name", "android.intent.category.LAUNCHER")}},
								},
							},
						},
					},
					{
						name: "activity",
						attrs: []mfAttr{
							mfString("android", "name", pkg+".SettingsActivity"),
							mfBool("android", "exported", false),
						},
					},
				},
			},
		},
	}
	return encodeMF(root)
}

// encodeMF 把元素树序列化成合法的 RES_XML 字节流。
//
// 两趟：先遍历整棵树把全部字符串登记进池，编码字符串池后，再把各元素/属性
// 引用写成对应的池下标。
func encodeMF(root *mfNode) []byte {
	w := &mfWriter{idx: map[string]uint32{}}
	w.intern("") // 池首项固定为空串（与 aapt 一致）
	w.prepare(root)

	pool := encodePool(w.strs)
	startNS := node(axml.TypeXMLStartNS, 1, []uint32{noIndex}, le32(w.idx["android"], w.idx[axml.AndroidNS]))
	endNS := node(axml.TypeXMLEndNS, 1, []uint32{noIndex}, le32(w.idx["android"], w.idx[axml.AndroidNS]))

	body := w.emit(root, nil)
	out := make([]byte, 8)
	binary.LittleEndian.PutUint16(out[0:], axml.TypeXML)
	binary.LittleEndian.PutUint16(out[2:], 8)
	out = append(out, pool...)
	out = append(out, startNS...)
	out = append(out, body...)
	out = append(out, endNS...)
	binary.LittleEndian.PutUint32(out[4:], uint32(len(out)))
	return out
}

type mfWriter struct {
	strs []string
	idx  map[string]uint32
}

func (w *mfWriter) intern(s string) uint32 {
	if i, ok := w.idx[s]; ok {
		return i
	}
	i := uint32(len(w.strs))
	w.idx[s] = i
	w.strs = append(w.strs, s)
	return i
}

func (w *mfWriter) prepare(n *mfNode) {
	w.intern("android")
	w.intern(axml.AndroidNS)
	w.intern(n.name)
	for _, a := range n.attrs {
		if a.ns == "android" {
			w.intern(axml.AndroidNS)
		}
		w.intern(a.name)
		if a.kind == 0 {
			w.intern(a.s)
		}
	}
	for _, k := range n.kids {
		w.prepare(k)
	}
}

func (w *mfWriter) emit(n *mfNode, out []byte) []byte {
	out = append(out, w.start(n)...)
	for _, k := range n.kids {
		out = w.emit(k, out)
	}
	out = append(out, node(axml.TypeXMLEndElem, 1, []uint32{noIndex}, le32(noIndex, w.idx[n.name]))...)
	return out
}

func (w *mfWriter) start(n *mfNode) []byte {
	body := make([]byte, 20)
	binary.LittleEndian.PutUint32(body[0:], noIndex) // 元素自身无命名空间
	binary.LittleEndian.PutUint32(body[4:], w.idx[n.name])
	binary.LittleEndian.PutUint16(body[8:], 20) // attributeStart
	binary.LittleEndian.PutUint16(body[10:], 20)
	binary.LittleEndian.PutUint16(body[12:], uint16(len(n.attrs)))
	binary.LittleEndian.PutUint16(body[14:], 0)      // idIndex
	binary.LittleEndian.PutUint16(body[16:], 0xffff) // classIndex
	binary.LittleEndian.PutUint16(body[18:], 0xffff) // styleIndex
	for _, a := range n.attrs {
		at := make([]byte, 20)
		if a.ns == "android" {
			binary.LittleEndian.PutUint32(at[0:], w.idx[axml.AndroidNS])
		} else {
			binary.LittleEndian.PutUint32(at[0:], noIndex)
		}
		binary.LittleEndian.PutUint32(at[4:], w.idx[a.name])
		binary.LittleEndian.PutUint16(at[12:], 20)
		switch a.kind {
		case 0:
			binary.LittleEndian.PutUint32(at[8:], w.idx[a.s]) // rawValue
			at[15] = axml.TypeString
			binary.LittleEndian.PutUint32(at[16:], w.idx[a.s])
		case 1:
			binary.LittleEndian.PutUint32(at[8:], noIndex)
			at[15] = axml.TypeIntDec
			binary.LittleEndian.PutUint32(at[16:], uint32(a.i))
		case 2:
			binary.LittleEndian.PutUint32(at[8:], noIndex)
			at[15] = axml.TypeIntBoolean
			v := uint32(0)
			if a.b {
				v = 0xffffffff
			}
			binary.LittleEndian.PutUint32(at[16:], v)
		}
		body = append(body, at...)
	}
	return node(axml.TypeXMLStartElem, 1, []uint32{noIndex}, body)
}
