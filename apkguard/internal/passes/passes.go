// Package passes 实现各个加固功能项。
//
// 每个功能项对应一个 Pass 实现，通过 Registry() 统一注册。
package passes

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"time"

	"apkguard/internal/axml"
	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/pipeline"
	"apkguard/internal/zipx"
)

// Registry 返回注册了全部功能项的注册表。
//
// 注册顺序即执行顺序（同层内按注册序稳定排序），有两处顺序是**语义要求**
// 而不仅是习惯，改动前请先看下面的注释。
func Registry() *pipeline.Registry {
	r := pipeline.NewRegistry()

	// ---- 阶段2：L1 混淆 ----
	r.Register(&renameClass{})
	// A7 只扫描并登记「反射成员名」字符串（不改写 DEX），必须排在 A2 之前：
	// A2 是唯一消费方，会对登记的串无条件加密（不受 ObfStringMin 限制）。
	r.Register(&reflectNames{})
	r.Register(&encryptString{})
	r.Register(&constantArray{})
	r.Register(&classPad{})
	r.Register(&dropDebugInfo{})
	// A6 控制流混淆。当前只启用**可证明安全**的两类插入：不透明谓词（仅用
	// 「全方法未被任何指令引用」的寄存器）与不可达前向跳转。早期版本曾复用
	// 任意局部寄存器，在 RustDesk/Dhizuku 上触发 ART 的宽值类型冲突
	// （VerifyError: wide register ... Low-half Constant/Conflict），已移除那条路径。
	r.Register(&controlFlow{})
	// A20 花指令填充与 A6 同族（都改写方法体），紧跟其后。它只插入 nop 与
	// 不可达前向跳转、不写任何寄存器，因此不存在 A6 那种宽值类型冲突。
	r.Register(&nopFill{})
	// A19 只往字符串池追加垃圾串、不触碰指令流，放在混淆段末尾即可。
	r.Register(&strJunk{})
	// 注：A6 已在上方注册（见 r.Register(&controlFlow{})），此处不再重复。
	// 早期它确实不注册——当时在真实应用上会触发 ART 的宽值类型冲突
	// （VerifyError: wide register ... Low-half Constant/Conflict）。该缺陷已在
	// 修掉「32x 格式漏报源寄存器」后消失，三个真实应用（Dhizuku/Termux/RustDesk）
	// 全选项加固后均可正常运行，见 realworld/实测记录-三应用全选项.md。
	r.Register(&fakeDex{})
	r.Register(&junkEntries{})
	r.Register(&zipPathAttack{})
	r.Register(&resourceObf{})
	r.Register(&resourceFlatten{})
	r.Register(&decoyClass{})
	// A18 与 A8 同构（都是往 Manifest 追加元素），放一起。
	r.Register(&decoyMeta{})
	// A16 假核心文件：纯 ZIP 层注入，位置不敏感，但必须在 A14 之前
	// （A14 要统一所有新增条目的时间戳）。
	r.Register(&decoyCore{})

	// ---- 阶段3：L2 一代壳 ----
	//
	// 顺序同样不可调换：
	//   B1 先按类名排序取出全部可解析 DEX，加密成 assets 载荷并**移除**明文条目；
	//   B2 再把壳 DEX 补进去（此时 classes.dex 已被 B1 腾空）并改写 Manifest；
	//   B3 最后把 Loader 类体注入 B2 建好的那个壳 DEX。
	// B4 必须排在 B1 **之前**：它先把业务 DEX 拆成多份，B1 再把每一份
	// 各自加密成独立载荷。反过来则拆分无从下手（B1 已把明文移出 APK）。
	// C2 必须在 B4/B1 之前：它要把 lib/<abi>/*.so 从 APK 里移走并加密成载荷，
	// 同时记录原始 ABI 集合（C1 依赖它决定给哪些 ABI 注入守卫库——
	// lib/ 被移走后 abisOf 会返回空，那会让 C1 给全部 ABI 都注入）。
	r.Register(&encryptNativeLibs{})
	r.Register(&splitDex{})
	r.Register(&encryptDex{})
	// B8 必须排在 B1 之后（要读加密载荷清单）、B3 之前（要改载荷条目名，
	// 而 B3 生成 Loader 时会把这些名字内联进字节码）。
	r.Register(&payloadContainer{})
	// A17 假内层 APK：排在 B8 之后（B8 已建好同构的容器目录树，A17 往里放
	// 一个「能被 apktool/jadx 打开的完整假 APK」，与真载荷同构）。
	r.Register(&nestedDecoyAPK{})
	r.Register(&appReplace{})
	r.Register(&classLoader{})

	// ---- 阶段2/3：运行时防护 ----
	//
	// D1 同样把类注入 B2 建好的壳 DEX，因此必须排在 B2 之后；
	// 与 B3 的先后无所谓（两者写的是不同的类）。
	// C1 必须在 B2 之后（要往壳 DEX 注入桥接类），
	// 同时它决定的密钥被 B1 使用——但 B1 是自行复算同一纯函数，
	// 不依赖执行顺序。
	r.Register(&nativeKeyDerive{})
	// C7 必须排在 C2 与 C1 之后：C2 靠原始文件名识别并跳过守卫库（先改名会让它
	// 把守卫库当业务库加密搬走），C1 才是注入守卫库与桥接类的那个 Pass，
	// 而 C7 要改写 C1 写进壳 DEX 的库名。
	r.Register(&libDisguise{})
	r.Register(&antiDebug{})
	r.Register(&antiHook{})
	r.Register(&selfIntegrity{})
	r.Register(&memWatch{})
	r.Register(&deviceBind{})
	r.Register(&sigCheck{})
	r.Register(&rootCheck{})
	r.Register(&emulatorCheck{})

	// ---- 阶段1：签名 / 对齐 / 元数据 ----
	//
	// A14 必须排在**所有会新增条目的功能项之后**：它统一的是全部条目的
	// 时间戳与 create_system，而 B1 的载荷、B2 的壳 DEX、A9/A10/A12 的
	// 垃圾条目都是加固过程中才加进来的。排在前面的话，这些新条目会带着
	// 默认的 1980-01-01 时间戳发布出去，恰恰构成 A14 想消除的「重打包痕迹」。
	r.Register(&channelMark{})
	r.Register(&compatCheck{})
	r.Register(&metaUnify{})

	// A15 必须排在**最后**：它会把 Manifest 膨胀到数百 MB，
	// 而 B2（改 android:name）、E6（读 minSdk）、A14 都不再需要读它；
	// 反过来若排在前面，后续任何一次 Manifest 解析都要多走几十 MB 零。
	r.Register(&manifestPad{})

	return r
}

// newRand 构造随机源：给定 seed 时确定性可复现，否则用当前时间。
//
// 这里的随机性只用于「制造不可预测的垃圾数据」，不用于任何安全用途，
// 因此使用 math/rand 即可（加密密钥另有 crypto/rand 来源）。
func newRand(seed string) *rand.Rand {
	if seed != "" {
		var h int64
		for _, c := range seed {
			h = h*131 + int64(c)
		}
		return rand.New(rand.NewSource(h))
	}
	return rand.New(rand.NewSource(time.Now().UnixNano()))
}

// ---- A14 时间戳与元数据统一化 ----

// metaUnify 统一全部 ZIP 条目的时间戳与元数据，消除重打包痕迹。
//
// 时间戳不是「全部同一秒」而是**三组**：样本的三次注入阶段分别落在
// 22:01:08 / 22:01:40 / 22:01:52（基准、+32s、+44s）。全部条目同一秒本身
// 就是一枚重打包指纹——真实构建的各文件时间总有先后；而样本恰好用三段时间
// 把「原始条目 / 路径与畸形名注入 / 假内容诱饵」分开。
//
// 分组由 A10/A12 注入时写入 Artifact.Shared 的提示（stampHintsKey）决定，
// 同 seed 完全可复现；没有提示的条目按名字特征兜底（A9 伪 DEX、A16 假核心
// 文件等），其余原始条目一律基准组。
//
// 签名三件套（MANIFEST.MF/CERT.SF/CERT.RSA）由 sink.go 用**基准**时间戳写入，
// 与基准组一致；这里不触碰签名侧。
type metaUnify struct{}

func (metaUnify) ID() config.FeatureID { return "A14" }
func (metaUnify) In() pipeline.Level   { return pipeline.LevelZip }
func (metaUnify) Out() pipeline.Level  { return pipeline.LevelZip }

// defaultStamp 是未指定时间戳时使用的固定时间；来源见 config.DefaultStamp。
var defaultStamp = config.DefaultStamp

func (m *metaUnify) Run(_ context.Context, art *pipeline.Artifact, opts *config.Options) error {
	stamp, err := opts.UnifiedStamp()
	if err != nil {
		return err
	}
	// 三段时间戳：基准、+32s、+44s（与样本 22:01:08/22:01:40/22:01:52 一致）。
	// 派生自基准 stamp，不用任何「当前时间」，保证产物可复现、可用 -stamp-time 控制。
	stamps := [3]time.Time{stamp, stamp.Add(32 * time.Second), stamp.Add(44 * time.Second)}
	var dos [3][2]uint16
	for i, t := range stamps {
		tm, dt := zipx.DOSDateTime(t)
		dos[i] = [2]uint16{tm, dt}
	}

	hints, _ := art.Get(stampHintsKey).(map[string]int)
	var counts [3]int

	for _, e := range art.Entries() {
		g := stampGroupOf(hints, e.NameString())
		e.ModTime, e.ModDate = dos[g][0], dos[g][1]
		// create_system 位于 VersionMade 的高字节，统一为 0（MS-DOS）。
		e.VersionMade &^= 0xff00
		// 清除条目注释，避免泄露打包工具信息。
		e.Comment = nil
		// 清除**带时间的**扩展字段记录：0x5455（扩展时间戳，含 mtime/atime/ctime）
		// 与 0x000a（NTFS 时间）会原样保留原始的打包时刻，覆盖掉上面对
		// ModTime/ModDate 的统一——留着它们等于统一没做。
		// 其余记录（对齐、uid/gid 等）不动。
		e.LocalExtra = stripTimeExtra(e.LocalExtra)
		e.CentralExtra = stripTimeExtra(e.CentralExtra)
		counts[g]++
	}

	art.Note("A14 元数据统一化：%d 个条目按注入阶段分 3 组时间戳——基准 %s ×%d 条、+32s ×%d 条（路径/畸形名注入）、+44s ×%d 条（假内容诱饵）；三组对齐样本 22:01:08/22:01:40/22:01:52",
		len(art.Entries()), stamps[0].UTC().Format("2006-01-02 15:04:05"), counts[0], counts[1], counts[2])
	art.Stat("A14.entries", fmt.Sprint(len(art.Entries())))
	art.Stat("A14.stamp0", fmt.Sprint(counts[0]))
	art.Stat("A14.stamp1", fmt.Sprint(counts[1]))
	art.Stat("A14.stamp2", fmt.Sprint(counts[2]))
	return nil
}

// stripTimeExtra 移除扩展字段里「携带时间戳」的记录（0x5455 / 0x000a）。
//
// ZIP 的扩展时间戳（Extended Timestamp，ID 0x5455）与 NTFS（ID 0x000a）
// 记录里存着原始打包时刻，且**独立于**中央目录的 DOS 时间字段。A14 若只改
// DOS 时间，这些记录仍会暴露真实时间，统一就形同虚设。
func stripTimeExtra(extra []byte) []byte {
	if len(extra) == 0 {
		return extra
	}
	out := make([]byte, 0, len(extra))
	p := 0
	for p+4 <= len(extra) {
		id := binary.LittleEndian.Uint16(extra[p:])
		n := int(binary.LittleEndian.Uint16(extra[p+2:]))
		if p+4+n > len(extra) {
			// 声明长度超出剩余字节：残尾，原样保留（交给 sanitizeExtra 处理）。
			out = append(out, extra[p:]...)
			break
		}
		if id != 0x5455 && id != 0x000a {
			out = append(out, extra[p:p+4+n]...)
		}
		p += 4 + n
	}
	if p < len(extra) && len(out) == 0 {
		return extra
	}
	return out
}

// ---- A9 伪 DEX magic 填充块 ----

// fakeDex 注入仅伪造 DEX magic 的随机数据块。
//
// 随机数据熵值接近 8，压缩比约 1:1，因此不会被解压工具「看穿」；
// 同时基于 magic 判定的工具会尝试解析并因头部字段非法而失败。
type fakeDex struct{}

func (fakeDex) ID() config.FeatureID { return "A9" }
func (fakeDex) In() pipeline.Level   { return pipeline.LevelZip }
func (fakeDex) Out() pipeline.Level  { return pipeline.LevelZip }

func (f *fakeDex) Run(_ context.Context, art *pipeline.Artifact, opts *config.Options) error {
	n := opts.FakeDexCount
	if n <= 0 {
		n = 1
	}
	size := opts.FakeDexSize
	if size < 4096 {
		size = 4096
	}

	rnd := newRand(opts.Seed)

	// 与真实 DEX 命名相似，但用大写以区分（样本手法）。
	names := []string{"CLASSES.DEX", "Classes.Dex", "classes.DEX"}
	used := map[string]bool{}
	for _, e := range art.Entries() {
		used[e.NameString()] = true
	}

	// DEX 版本号与真实产物一致（我们新建/重建后都是 037）：
	// 样本的伪块写 035，反而成了「这一块不是我们生成的」的指纹。
	// 版本号越高越像真实产物，但也不能高到超出目标设备支持的范围——
	// 037 是 d8 的常规输出，最自然。
	version := dexVersionForFake()

	added := 0
	for i := 0; added < n; i++ {
		base := names[i%len(names)]
		name := base
		if i >= len(names) {
			name = fmt.Sprintf("%s.%d", base, i/len(names)+1)
		}
		if used[name] {
			continue
		}
		used[name] = true

		blob := fakeDexBody(rnd, size, version)
		pipeline.Add(art, zipx.NewStored(name, blob))
		added++
	}

	art.Note("A9 伪 DEX 填充块：注入 %d 个（每个 %d 字节，随机不可压缩，magic dex\\n%03d）", added, size, version)
	art.Stat("A9.count", fmt.Sprint(added))
	art.Stat("A9.bytes", fmt.Sprint(added*size))
	return nil
}

// dexVersionForFake 返回伪 DEX 块使用的版本号。
//
// 用 037 与真实产物一致（样本写 035，而 035 在现代设备上加载即崩，
// 反而暴露「这不是真 DEX」）。
func dexVersionForFake() int { return 37 }

// fakeDexBody 构造一个伪 DEX 块：合法的 magic + **合理范围内的头部字段** + 随机数据。
//
// 早期实现是「magic + 纯随机」，头部的 header_size/map_off 等字段全是垃圾，
// 任何工具一秒就能判定它不是 DEX。这里把头部字段写成合法值（header_size=0x70、
// endian_tag、checksum 等按规范填），只有数据区是随机的——基于 magic 判定的工具
// 会真的尝试解析，然后才在 data 段失败。
func fakeDexBody(rnd *rand.Rand, size int, version int) []byte {
	blob := make([]byte, size)
	for k := range blob {
		blob[k] = byte(rnd.Intn(256))
	}
	copy(blob, fmt.Sprintf("dex\n%03d\x00", version))
	if size >= 0x70 {
		// header_size 固定 0x70；endian_tag 为 DEX 常量 0x12345678。
		binary.LittleEndian.PutUint32(blob[0x24:], 0x70)
		binary.LittleEndian.PutUint32(blob[0x28:], 0x12345678)
		// 把各段大小写成「看起来合理但互相不自洽」的值：让按 magic 判定的
		// 工具真的走一遍解析路径，而不是靠一个字段就否定它。
		for _, off := range []int{0x38, 0x40, 0x48, 0x50, 0x58, 0x60} {
			binary.LittleEndian.PutUint32(blob[off:], uint32(1+rnd.Intn(1<<16)))
		}
	}
	return blob
}

// ---- A10 垃圾条目注入 ----

// manifestCollision 判断条目名是否会被运行时/工具当成 v1 签名的关键文件。
//
// 这类名字一律禁止注入。ZIP 条目名在 Android 的 JarFile/ZipUtils 中是**大小写
// 不敏感**地比较 `META-INF/MANIFEST.MF`；而 ServiceLoader 等会经 JarFile 读
// `META-INF/services/*`，从而触发 v1 签名校验。只要注入第二个「看起来像
// MANIFEST.MF」的条目，校验器就可能读到错误的主属性并抛
//
//	java.lang.SecurityException: Invalid signature file digest for Manifest main attributes
//
// 实测于 RustDesk 1.5.0（Flutter）：首次 attach 即崩。同理不得注入
// *.SF / *.RSA / *.DSA / *.EC —— 它们会被当作签名文件解析。
//
// 归一化会折叠重复斜杠、消解 '.'/'..' 段并统一大小写，因此
// `META-INF//MANIFEST.MF`、`META-INF/./MANIFEST.MF`、`meta-inf/MANIFEST.MF`、
// `META-INF/../META-INF/MANIFEST.MF` 都能被识别出来。
func manifestCollision(name string) bool {
	segs := make([]string, 0, 4)
	for _, s := range strings.Split(name, "/") {
		switch s {
		case "", ".":
			continue
		case "..":
			if len(segs) > 0 {
				segs = segs[:len(segs)-1]
			}
		default:
			segs = append(segs, s)
		}
	}
	norm := strings.ToUpper(strings.Join(segs, "/"))
	if norm == "META-INF/MANIFEST.MF" {
		return true
	}
	if base, ok := strings.CutPrefix(norm, "META-INF/"); ok && !strings.Contains(base, "/") {
		for _, ext := range []string{".SF", ".RSA", ".DSA", ".EC"} {
			if strings.HasSuffix(base, ext) {
				return true
			}
		}
	}
	return false
}

// junkEntries 注入无意义 ZIP 条目：非 ASCII 顶层假 AXML、空格填充深目录、
// 随机名深目录、畸形 META-INF / 近重名 / 空格名 / 伪装构件名、kotlin/ 伪装、
// 「真资源路径当目录」的畸形变体。
//
// 各族的内容与命名都对齐参考样本实测（见 junk.go 顶部注释）：族 A 共用 176B
// 随机载荷（与 A12 同一份字节）、族 B 全空格、族 C 合法 AXML、族 D kotlin/
// 共用载荷。样本的证据规模：884 条顶层假 AXML、837 条空格深目录、24 条
// kotlin/ 假货、323 条共用载荷。
type junkEntries struct{}

func (junkEntries) ID() config.FeatureID { return "A10" }
func (junkEntries) In() pipeline.Level   { return pipeline.LevelZip }
func (junkEntries) Out() pipeline.Level  { return pipeline.LevelZip }

func (j *junkEntries) Run(_ context.Context, art *pipeline.Artifact, opts *config.Options) error {
	rnd := newRand(opts.Seed)
	// 族 A：一份 176 字节随机载荷，A10 的畸形/近重名族与 A12 共用（样本 323 条）。
	payload := sharedJunkPayload(art, opts.Seed)

	used := map[string]bool{}
	for _, e := range art.Entries() {
		used[e.NameString()] = true
	}
	normIdx := normalizedPathIndex(art)
	add := func(name string, data []byte) bool {
		// normIdx 只含**注入前**的既有条目：注入条目之间允许归一化后同路径
		// （样本有 35 组，最大一组 13 条），但不能归一化到真实文件上。
		if name == "" || used[name] || manifestCollision(name) || coreCollision(name, normIdx) {
			return false
		}
		used[name] = true
		pipeline.Add(art, newJunkEntry(name, data))
		return true
	}
	addAs := func(name string, data []byte, group int) bool {
		if !add(name, data) {
			return false
		}
		stampHint(art, name, group)
		return true
	}
	// addStrict 用于新增名字族：除 add 的守卫外，还拒绝空段、`.`/`..` 段与
	// 以分隔符结尾的目录条目（样本里没有这种条目）。
	addStrict := func(name string, data []byte, group int) bool {
		if !safeJunkPath(name) {
			return false
		}
		return addAs(name, data, group)
	}

	// ① 非 ASCII 顶层文件：用易混字符集构造合法但难读的名字，内容是**可解析的**
	//    真 AXML。对齐样本（884 条共用同一份 388 字节模板、每条恰好 1 个随机
	//    差异字节）：本次运行只生成一份模板，每条复制后写入恰好 1 个盐字节；
	//    约 8% 的条目（条数 = max(1, N*8%)，选点与类别由 seed 决定，三类字段
	//    轮转）额外把字符串池头部字段高位加盐——严格解析器失败，Android 平台
	//    不受影响。毒化条目名记录进 Artifact.Shared（a10PoisonedKey），
	//    自检/测试按名字身份跳过，而不是靠「解析失败容忍」。
	topAdded := 0
	tpl := a10AXMLTemplate(opts.Seed)
	saltRnd := newRand(opts.Seed + "/a10top")
	saltedPairs := map[uint64]bool{}
	poisonCount := (opts.JunkTopCount * 8) / 100
	if opts.JunkTopCount > 0 && poisonCount < 1 {
		poisonCount = 1
	}
	poisonIdx := map[int]bool{}
	if poisonCount > 0 {
		step := opts.JunkTopCount / poisonCount
		if step < 1 {
			step = 1
		}
		start := saltRnd.Intn(opts.JunkTopCount)
		for k := 0; k < poisonCount; k++ {
			poisonIdx[(start+k*step)%opts.JunkTopCount] = true
		}
	}
	poisoned := map[string]int{}
	poisonOrd := 0
	for i := 0; i < opts.JunkTopCount; i++ {
		name := confusableName(rnd, 3+i%6) + ".xml"
		data := append([]byte(nil), tpl...)
		if !saltAXMLOneByte(saltRnd, data, saltedPairs) {
			art.Note("A10：假 AXML 模板没有可加盐的字符串内容，条目 %q 未加盐", name)
		}
		class := -1
		if poisonIdx[i] {
			class = poisonOrd % 3
			poisonAXMLStringPool(saltRnd, data, class)
			poisonOrd++
		}
		if addStrict(name, data, stampGroupDecoy) {
			topAdded++
			if class >= 0 {
				poisoned[name] = class
			}
		}
	}
	art.Put(a10PoisonedKey, poisoned)

	// ② 随机名深目录条目：内容是**清一色 0x20**（80~400 字节），对齐样本的
	//    837 条空格文件。deflate 后只有几字节，体积开销可忽略。
	dirAdded := 0
	depth := opts.JunkDirDepth
	if depth < 1 {
		depth = 1
	}
	for i := 0; i < opts.JunkDirCount; i++ {
		d := 1 + rnd.Intn(depth)
		parts := make([]string, 0, d+1)
		for k := 0; k < d; k++ {
			parts = append(parts, randSeg(rnd, 1+rnd.Intn(8)))
		}
		parts = append(parts, randSeg(rnd, 4)+".tmp")
		if addStrict(joinPath(parts), junkSpaceFile(rnd), stampGroupDecoy) {
			dirAdded++
		}
	}

	// ③ 同名单目录深层路径：参考样本用 76 层同名目录制造超长路径，
	//    这类路径会触发解包工具的路径长度/递归问题，而对真实文件毫无影响。
	//    只在与 ② 同量级的规模下生成（每 10 个深目录配 1 条），且与 ② 一样用
	//    空格内容（早先的 64KB 顺序字节是体积主要来源，收益却低）。
	aliasAdded := 0
	for i := 0; i < opts.JunkDirCount/10; i++ {
		depth := 60 + rnd.Intn(20)
		leaf := randSeg(rnd, 3+rnd.Intn(8))
		p := deepAliasPath(rnd, 2+rnd.Intn(4), depth, leaf)
		if addStrict(p, junkSpaceFile(rnd), stampGroupDecoy) {
			aliasAdded++
		}
	}

	// ④ 畸形 META-INF 路径：用前缀、双斜杠、点段等使签名状态判定产生歧义。
	//    内容用族 A 的共用载荷（样本 META-INF/ 下 35 条属于这一族）。
	//
	// 但**绝不注入任何会被当成 MANIFEST.MF / 签名文件的名字**（见 manifestCollision）：
	// 假 manifest 会让 JarVerifier 读到错误的主属性，运行时报
	//   java.lang.SecurityException: Invalid signature file digest for Manifest main attributes
	// ZIP 条目名在 Android 的 JarFile/ZipUtils 里是**大小写不敏感**地比较
	// `META-INF/MANIFEST.MF`，所以 `meta-inf/MANIFEST.MF` 也算撞名。
	// 实测于 RustDesk 1.5.0（Flutter）：ServiceLoader 经 JarFile 读
	// META-INF/services 触发 v1 校验，首次 attach 即崩。
	// 注：这批旧名单里的 `./`、`../` 形态被既有测试钉住，保留；但**不再保留
	// 尾部 `/` 的目录形态**：两个「目录名 + 176B 数据」的条目（META-INF/、
	// META-INF/sub/）已改为等价的非目录路径 META-INF、META-INF/sub——名字仍属
	// 易混族、载荷不变，但不再有「以 / 结尾却带数据」的条目（参考样本 2418 个
	// 条目里目录条目为 0；个别解包工具对带内容的目录条目行为不一致）。
	// 新增族一律走 addStrict 不再产生尾部斜杠。
	metaAdded := 0
	malformed := []string{
		"META-INF",
		"META-INF//MANIFEST.MFx",
		"META-INF/./MANIFEST.MFx",
		"META-INF/../META-INF/x.MF",
		"META-INF/.hidden",
		"meta-inf/MANIFEST.MFx",
		"META-INF/sub",
	}
	for i := 0; i < opts.JunkMetaCount; i++ {
		name := malformed[i%len(malformed)]
		if i >= len(malformed) {
			name = fmt.Sprintf("%s%d", malformed[i%len(malformed)], i/len(malformed))
		}
		if addAs(name, payload, stampGroupInjected) {
			metaAdded++
		}
	}

	// ⑤ 4 位 hex 后缀近重名：样本用 4 位随机 hex 给同一基础名去重
	//    （META-INF///.xml629c 这类），CD 里精确名字互不相同。
	hexAdded := 0
	for i := 0; i < 3*len(junkHexSuffixBases); i++ {
		base := junkHexSuffixBases[i%len(junkHexSuffixBases)]
		for try := 0; try < 8; try++ {
			if addStrict(base+hex4(rnd), payload, stampGroupInjected) {
				hexAdded++
				break
			}
		}
	}

	// ⑥ 空格名与伪装构件名：ZIP 条目名允许空格（`META-INF/ .idx`），不少工具
	//    trim 后会把它当成 `META-INF/.idx`；module.map.xml / package.hint /
	//    table.blob.xml 则伪装成 kotlin/desugar/AGP 的构建元数据。
	spaceAdded, trustedAdded := 0, 0
	for _, name := range junkSpaceNames {
		if addStrict(name, payload, stampGroupInjected) {
			spaceAdded++
		}
	}
	for _, name := range junkTrustedNames {
		data := payload
		if strings.HasSuffix(name, ".xml") {
			// `.xml` 结尾的条目必须是可解析的真 AXML（既有契约，见 junk_test.go）。
			data = realisticAXML(rnd, 320+rnd.Intn(80))
		}
		if addStrict(name, data, stampGroupInjected) {
			trustedAdded++
		}
	}

	// ⑦ kotlin/ 目录伪装：名字像 Kotlin 内置元数据/资源，内容是族 A 的共用载荷。
	//    样本在 kotlin/ 下 31 条里有 24 条是这种假货——分析者按目录白名单
	//    （kotlin/、lib/）跳过时，它们就活了下来。
	kotlinAdded := 0
	for i := 0; i < 24; i++ {
		for try := 0; try < 8; try++ {
			if addStrict(junkKotlinName(rnd, i), payload, stampGroupDecoy) {
				kotlinAdded++
				break
			}
		}
	}

	// ⑧ 「真资源路径当目录」的畸形变体：样本 res/ 下 85+ 条，把 aapt2 源文件名
	//    （integers.xml 等）当目录名，再拼 `\`/`/` 混排与随机扩展名。内容是
	//    **合法可解析的 AXML**：分析者按 res/ 白名单批量解析时会全部读入。
	resAdded := 0
	for i := 0; i < 3*len(junkResSourceNames); i++ {
		name := junkResPathName(rnd, i)
		data := realisticAXML(rnd, 300+rnd.Intn(120))
		if addStrict(name, data, stampGroupInjected) {
			resAdded++
			continue
		}
		if addStrict(name+hex4(rnd), data, stampGroupInjected) {
			resAdded++
		}
	}

	art.Note("A10 垃圾条目：顶层易混名 %d 条（同一份合法 AXML 模板 + 每条 1 个随机盐字节，sha256 全不同；其中毒化子集 %d 条，池头高位加盐、严格解析器失败）、深目录 %d 条（空格内容 80~400B）、同名深层目录 %d 条、畸形 META-INF %d 条（176B 共用载荷）、4hex 近重名 %d 条、空格名 %d 条、伪装构件名 %d 条、kotlin/ 伪装 %d 条（共用载荷）、res/ 真路径变体 %d 条（可解析 AXML）；对齐样本 884/837/24/323 的族规模",
		topAdded, len(poisoned), dirAdded, aliasAdded, metaAdded, hexAdded, spaceAdded, trustedAdded, kotlinAdded, resAdded)
	art.Stat("A10.top", fmt.Sprint(topAdded))
	art.Stat("A10.top_poisoned", fmt.Sprint(len(poisoned)))
	art.Stat("A10.dir", fmt.Sprint(dirAdded))
	art.Stat("A10.alias", fmt.Sprint(aliasAdded))
	art.Stat("A10.meta", fmt.Sprint(metaAdded))
	art.Stat("A10.hex4", fmt.Sprint(hexAdded))
	art.Stat("A10.spacename", fmt.Sprint(spaceAdded))
	art.Stat("A10.trusted", fmt.Sprint(trustedAdded))
	art.Stat("A10.kotlin", fmt.Sprint(kotlinAdded))
	art.Stat("A10.respath", fmt.Sprint(resAdded))
	return nil
}

// ---- A12 ZIP 路径攻击 ----

// zipPathAttack 注入三类路径攻击条目。
//
// 内容与 A10 的畸形 META-INF 族共用同一份 176 字节载荷（样本的 323 条共用载荷
// 正好横跨「关键文件当目录」「绝对路径」与「META-INF/」三个命名空间）。
type zipPathAttack struct{}

func (zipPathAttack) ID() config.FeatureID { return "A12" }
func (zipPathAttack) In() pipeline.Level   { return pipeline.LevelZip }
func (zipPathAttack) Out() pipeline.Level  { return pipeline.LevelZip }

func (z *zipPathAttack) Run(_ context.Context, art *pipeline.Artifact, opts *config.Options) error {
	n := opts.ZipAtkCount
	if n <= 0 {
		n = 10
	}
	rnd := newRand(opts.Seed)
	// 族 A：与 A10 完全相同的 176 字节随机载荷。样本按内容哈希聚类时，这 323 条
	// 会先被当成「重复数据」整族丢弃，从而漏掉内容各不相同的假 AXML 等族。
	payload := sharedJunkPayload(art, opts.Seed)

	used := map[string]bool{}
	for _, e := range art.Entries() {
		used[e.NameString()] = true
	}
	normIdx := normalizedPathIndex(art)
	// add 复用 A10 的守卫：manifestCollision（v1 签名关键名）之外，还要过
	// coreCollision（归一化后撞上 AndroidManifest.xml / classes*.dex /
	// resources.arsc / 任何**注入前**既有条目都不行——注入条目彼此之间允许，
	// 样本自身就有 35 组归一化同路径）。
	add := func(name string, data []byte) (*zipx.Entry, bool) {
		if name == "" || used[name] || manifestCollision(name) || coreCollision(name, normIdx) {
			return nil, false
		}
		used[name] = true
		e := newJunkEntry(name, data)
		pipeline.Add(art, e)
		stampHint(art, name, stampGroupInjected)
		return e, true
	}

	// ① 路径前缀滥用：用关键文件名当目录名，内容是与 A10 共用的 176B 载荷
	//    （旧实现是 1 字节 "0"，反而成了「这一族是生成物」的指纹）。
	prefixes := junkPathPrefixes
	// junk 收集本 Pass 自己注入的条目，供 ③ 复制使用。
	var junk []*zipx.Entry
	p1 := 0
	for i := 0; i < n; i++ {
		name := prefixes[i%len(prefixes)] + randSeg(rnd, 6)
		if e, ok := add(name, payload); ok {
			junk = append(junk, e)
			p1++
		}
	}

	// ② 绝对路径条目：混入**分隔符变体**，让不同工具的解压/规范化行为分叉
	//
	// 参考样本的绝对路径条目并不只是 "/随机名"：它带混合分隔符与转义
	// （`/AndroidManifest.xml\/\.xml`、`/AndroidManifest.xml/////.9.png`），
	// 且内容同样属于共用载荷族（样本绝对路径 84 条）。
	// 这些形态专打「按 / 切分目录」与「按 \ 切分」两种实现之间的差异，
	// 以及「重复斜杠是否折叠」「.9.png 是否按图处理」的判定分歧。
	forms := []func() string{
		func() string { return "/" + randSeg(rnd, 8) },
		func() string {
			return "/" + randSeg(rnd, 5) + "\\/" + "\\." + randSeg(rnd, 3)
		},
		func() string {
			return "/" + randSeg(rnd, 6) + strings.Repeat("/", 2+rnd.Intn(4)) + ".9.png"
		},
		func() string {
			return "//" + randSeg(rnd, 5) + "/" + randSeg(rnd, 5)
		},
		func() string {
			return "/" + randSeg(rnd, 4) + "/./" + randSeg(rnd, 4) + "/../" + randSeg(rnd, 4)
		},
	}
	p2 := 0
	for i := 0; i < n; i++ {
		name := forms[i%len(forms)]()
		if e, ok := add(name, payload); ok {
			junk = append(junk, e)
			p2++
		}
	}

	// ③ 重复条目名：同一名字出现多次，不同工具解出的内容不同。
	//
	// 目标是复制本 Pass 自己刚注入的**绝对路径**垃圾条目——参考样本的重名
	// 条目正是这个形态（/resources.arsc/////.9.png ×5）。有两条硬约束：
	//
	//   1) 绝不复制既有条目：那可能命中 AndroidManifest.xml / classes.dex
	//      这类关键文件，等于直接破坏产物；
	//   2) **启用签名时不注入**。v1（JAR）签名要为每个条目名写一段
	//      META-INF/MANIFEST.MF，重名会让 apksigner 直接报「Duplicate entry」
	//      并拒绝整个归档（实测普通名与 / 开头名都一样），产物将完全无法
	//      安装——这与加固的目的正好相反。
	//
	// 关闭 E1 时保留该手法：那种场景下产物本就要交由使用方自行签名，
	// 是否接受该手法由使用方评估。
	p3 := 0
	var absJunk []*zipx.Entry
	for _, e := range junk {
		if strings.HasPrefix(e.NameString(), "/") {
			absJunk = append(absJunk, e)
		}
	}
	switch {
	case len(absJunk) == 0:
		// 没有可复制的绝对路径垃圾条目，跳过。
	case opts.IsEnabled("E1"):
		art.Note("A12 重名条目：已跳过（apksigner 会以 Duplicate entry 拒绝含重名条目的归档，产物将无法通过校验与安装；如需该手法请关闭签名 E1 自行签名）")
	default:
		for i := 0; i < n; i++ {
			src := absJunk[i%len(absJunk)]
			dup := *src
			dup.Name = append([]byte(nil), src.Name...)
			dup.Raw = append([]byte(nil), src.Raw...)
			pipeline.Add(art, &dup)
			p3++
		}
	}

	art.Note("A12 ZIP 路径攻击：前缀滥用 %d 条、绝对路径 %d 条、重名 %d 条；其中 %d 条与 A10 共用同一份 176B 载荷（样本 323 条共用载荷族）",
		p1, p2, p3, p1+p2)
	art.Stat("A12.prefix", fmt.Sprint(p1))
	art.Stat("A12.absolute", fmt.Sprint(p2))
	art.Stat("A12.dup", fmt.Sprint(p3))
	art.Stat("A12.shared", fmt.Sprint(p1+p2))
	return nil
}

// ---- 辅助 ----

// confusableName 生成由易混字符组成的文件名。
//
// 字符取自切罗基文补充（U+13A0-U+13F5）与提非纳文（U+2D30-U+2D67），
// 二者字形相近且与拉丁字母难以区分，与样本手法一致。
func confusableName(r *rand.Rand, n int) string {
	out := make([]rune, 0, n)
	for i := 0; i < n; i++ {
		if r.Intn(2) == 0 {
			out = append(out, rune(0x13A0+r.Intn(0x56)))
		} else {
			out = append(out, rune(0x2D30+r.Intn(0x38)))
		}
	}
	return string(out)
}

// randSeg 生成由 ASCII 字母数字组成的随机路径段。
func randSeg(r *rand.Rand, n int) string {
	const alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	out := make([]byte, n)
	for i := range out {
		out[i] = alpha[r.Intn(len(alpha))]
	}
	return string(out)
}

// joinPath 用 "/" 连接路径段。
func joinPath(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += "/"
		}
		out += p
	}
	return out
}

// ---- A8 诱饵类注入 ----

// decoyClass 注入一批命名具误导性的空实现类。
//
// 与 A13（类膨胀）互补：A13 靠数量与超长类名增加体量，A8 靠**名字的叙事**
// 把逆向者的注意力引开——翻到 CoreAtlas、SignalBeacon 时很难不去读它们。
// 这些类结构合法且方法体带真实位运算，不是一眼假的空壳。
//
// 命名完全由 seed 派生：既有实现把诱饵放在写死的 com.apkguard.shell 下，
// 等于把产品名变成产物的固定指纹；现在的主题包（形如 vault.monitor）与
// 三个名族（形如 Core*/Signal*/Quiet*）都随 seed 变化，形态对齐参考样本。
type decoyClass struct{}

func (decoyClass) ID() config.FeatureID { return "A8" }
func (decoyClass) In() pipeline.Level   { return pipeline.LevelZip }
func (decoyClass) Out() pipeline.Level  { return pipeline.LevelZip }

// A8 的命名与分组参数。
//
// 数量沿用既有实现：18 个诱饵类、6 个 Manifest 组件声明。三个名族分别对应
// activity/receiver/service 三种组件形态；组件声明按参考样本 6/6/5 的比例
// 折算到既有的 6 个上，即每族声明前 2 个（2/2/2）。
const (
	decoyFamilyCount   = 3
	decoyFamilySize    = 6 // 3 族 × 6 = 18 个类，与既有 A8 的类数一致
	decoyDeclarePerFam = 2 // 每族声明进 Manifest 的组件数，合计 6
)

// decoyPkgHeads/decoyPkgTails 拼出「一个普通名词 + 一个功能名词」的两段式
// 主题包（样本为 vault.monitor）。词表固定、组合由 seed 挑选，因此产物里
// 不会出现任何产品名，也不会退回 com.example / com.apkguard 这类占位包。
var (
	decoyPkgHeads = []string{
		"vault", "core", "atlas", "beacon",
		"quiet", "signal", "harbor", "nexus",
	}
	decoyPkgTails = []string{
		"monitor", "guard", "watch", "stat",
		"ops", "audit", "sentinel",
	}
)

// decoyFamilyHeads 是名族共享前缀的候选（每族取一个），decoyNouns 是族内
// 名词的候选（每族取 decoyFamilySize 个）。族内名 = 前缀 + 名词，与样本的
// CoreAtlas / SignalBeacon / QuietAnnex 同构。
var (
	decoyFamilyHeads = []string{
		"Core", "Signal", "Quiet", "Vertex", "Prism",
		"Relay", "Cipher", "Lumen", "Pivot", "Terra",
	}
	decoyNouns = []string{
		"Atlas", "Forge", "Hatch", "Orbit", "Ridge", "Spire",
		"Beacon", "Courier", "Drift", "Echo", "Flux", "Gauge",
		"Annex", "Basin", "Creek", "Dune", "Field", "Lattice",
	}
)

// decoyKinds 固定「第 i 个名族 = 第 i 种组件形态」的对应关系，与样本的
// activity/receiver/service 三族一一对应。
var decoyKinds = []string{"activity", "receiver", "service"}

// decoyFamily 是一个名族：共享前缀、组件形态与族内全部类名（不含包）。
type decoyFamily struct {
	prefix string
	kind   string // "activity" / "receiver" / "service"
	names  []string
}

// decoyTheme 是 A8 由 seed 派生出的完整命名方案。
type decoyTheme struct {
	pkg      string // 点分主题包名，如 "vault.monitor"
	slash    string // 斜杠形式，如 "vault/monitor"
	families []decoyFamily
}

// decoyThemeOf 由 seed 确定性派生命名方案：同一个 seed 必须得到同一个主题包、
// 同一批名族与类名（测试会断言），因此随机数的消费顺序是契约的一部分。
func decoyThemeOf(opts *config.Options) decoyTheme {
	rnd := newRand(opts.Seed)
	pkg := decoyPkgHeads[rnd.Intn(len(decoyPkgHeads))] + "." +
		decoyPkgTails[rnd.Intn(len(decoyPkgTails))]
	heads := pickWords(rnd, decoyFamilyHeads, decoyFamilyCount)
	nouns := pickWords(rnd, decoyNouns, decoyFamilySize)

	th := decoyTheme{pkg: pkg, slash: strings.ReplaceAll(pkg, ".", "/")}
	for i, kind := range decoyKinds {
		fam := decoyFamily{prefix: heads[i], kind: kind}
		for _, noun := range nouns {
			fam.names = append(fam.names, heads[i]+noun)
		}
		th.families = append(th.families, fam)
	}
	return th
}

// pickWords 从词表里确定性挑选 n 个互不相同的词（按 rnd 的排列取前 n 个）。
func pickWords(rnd *rand.Rand, pool []string, n int) []string {
	if n > len(pool) {
		n = len(pool)
	}
	perm := rnd.Perm(len(pool))
	out := make([]string, 0, n)
	for _, i := range perm[:n] {
		out = append(out, pool[i])
	}
	return out
}

// allNames 返回全部类名（不含包），顺序固定（名族序 × 族内序）。
func (th decoyTheme) allNames() []string {
	out := make([]string, 0, decoyFamilyCount*decoyFamilySize)
	for _, f := range th.families {
		out = append(out, f.names...)
	}
	return out
}

// declared 返回要写进 Manifest 的组件（每族前 decoyDeclarePerFam 个）。
//
// activity 不在 dex.DecoyComponentKind 的既有枚举里（dex 包只生成
// receiver/service 骨架），但 Kind 的底层类型就是 string，声明侧按元素名
// 直接使用；activity 的类体由 applyDecoyActivities 后处理成 Activity 骨架。
func (th decoyTheme) declared() []dex.DecoyComponent {
	out := make([]dex.DecoyComponent, 0, decoyFamilyCount*decoyDeclarePerFam)
	for _, f := range th.families {
		for _, n := range f.names[:decoyDeclarePerFam] {
			out = append(out, dex.DecoyComponent{Name: n, Kind: dex.DecoyComponentKind(f.kind)})
		}
	}
	return out
}

// dexComponents 返回交给 dex.DecoyAddition 的 receiver/service 类。
func (th decoyTheme) dexComponents() []dex.DecoyComponent {
	var out []dex.DecoyComponent
	for _, f := range th.families {
		if f.kind == "activity" {
			continue
		}
		for _, n := range f.names {
			out = append(out, dex.DecoyComponent{Name: n, Kind: dex.DecoyComponentKind(f.kind)})
		}
	}
	return out
}

// activityNames 返回 activity 名族里的全部类名。
func (th decoyTheme) activityNames() []string {
	for _, f := range th.families {
		if f.kind == "activity" {
			return f.names
		}
	}
	return nil
}

// classDesc 返回类名对应的 DEX 描述符。
func (th decoyTheme) classDesc(name string) string {
	return "L" + th.slash + "/" + name + ";"
}

func (d *decoyClass) Run(_ context.Context, art *pipeline.Artifact, opts *config.Options) error {
	entries := pipeline.FindAll(art, isDexEntry)
	if len(entries) == 0 {
		return fmt.Errorf("未找到任何 DEX 条目")
	}
	// 与 A13 一样，注入类必须全局唯一：每个 DEX 都有同名类会导致
	// MultiDex 加载时报「类重复定义」。因此只注入到主 DEX。
	sort.Slice(entries, func(i, j int) bool {
		return dexNameOrder(entries[i].NameString()) < dexNameOrder(entries[j].NameString())
	})
	host := entries[0]

	data, err := host.Data()
	if err != nil {
		return fmt.Errorf("读取 %s 失败: %w", host.NameString(), err)
	}
	f, err := dex.Parse(data)
	if err != nil {
		return fmt.Errorf("解析 %s 失败: %w", host.NameString(), err)
	}

	// 与已有类型去重：万一某个诱饵名与真实类同名，注入会产生
	// class_defs 中 class_idx 重复的非法 DEX。
	existing := map[string]bool{}
	if err := f.Classes(func(_ uint32, _ dex.ClassDef, name string) error {
		existing[name] = true
		return nil
	}); err != nil {
		return fmt.Errorf("遍历类失败: %w", err)
	}

	// 主题包与类名全部来自 seed；刻意不使用 ShellPkg：CLI 默认值
	// com.apkguard.shell 会把产品名重新写进诱饵命名（见类型头注释）。
	theme := decoyThemeOf(opts)
	var names []string
	for _, n := range theme.allNames() {
		if !existing[theme.classDesc(n)] {
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		return fmt.Errorf("诱饵类名与现有类全部冲突，无可注入")
	}

	// Manifest 声明与 DEX 必须一致：只声明「实际注入成功」的类
	// （名字可能与现有类冲突而被剔除）。
	injected := map[string]bool{}
	for _, n := range names {
		injected[n] = true
	}
	var comps []dex.DecoyComponent
	for _, c := range theme.dexComponents() {
		if injected[c.Name] {
			comps = append(comps, c)
		}
	}
	var declared []dex.DecoyComponent
	for _, c := range theme.declared() {
		if injected[c.Name] {
			declared = append(declared, c)
		}
	}

	add, err := dex.DecoyAddition(&dex.DecoySpec{
		Prefix:     theme.slash,
		Names:      names,
		Seed:       opts.Seed,
		Components: comps,
	})
	if err != nil {
		return err
	}
	acts := map[string]bool{}
	for _, n := range theme.activityNames() {
		if injected[n] {
			acts[n] = true
		}
	}
	if err := applyDecoyActivities(&add, theme.slash, acts); err != nil {
		return err
	}

	out, err := dex.Rebuild(f, dex.RebuildOptions{Addition: &add})
	if err != nil {
		return fmt.Errorf("注入诱饵类失败: %w", err)
	}
	if err := dex.Verify(out); err != nil {
		return fmt.Errorf("注入诱饵类后校验失败: %w", err)
	}
	if err := host.SetData(out, true); err != nil {
		return fmt.Errorf("写回 %s 失败: %w", host.NameString(), err)
	}

	declaredN, err := declareDecoyComponents(art, theme.pkg, declared)
	if err != nil {
		return err
	}

	art.Note("A8 诱饵类注入：向 %s 注入 %d 个具误导性命名的类（主题包 %s，名族 %s*/%s*/%s*，方法体带真实位运算）；"+
		"其中 %d 个（%s）已按 activity/receiver/service 三类声明进 Manifest",
		host.NameString(), len(names), theme.pkg,
		theme.families[0].prefix, theme.families[1].prefix, theme.families[2].prefix,
		declaredN, strings.Join(compNames(declared), "、"))
	art.Stat("A8.classes", fmt.Sprint(len(names)))
	art.Stat("A8.dex", host.NameString())
	art.Stat("A8.components", fmt.Sprint(declaredN))
	art.Stat("A8.pkg", theme.pkg)
	return nil
}

// decoyAccPublic 是方法访问标志 public（0x0001）。
//
// dex 包的 access 常量未导出（见 internal/dex/assemble.go），而这里构造的
// onCreate 覆写必须是 public，故按 DEX 规范取字面值。
const decoyAccPublic = 0x0001

// applyDecoyActivities 把 activity 名族的注入类改造成 android.app.Activity 骨架。
//
// dex.DecoyAddition 的组件骨架只覆盖 receiver/service（internal/dex/decoy.go
// 的 componentBase 没有 activity 分支，该包不在本次改动范围内），但样本的三族
// 里 activity 占三分之一。若只声明 <activity> 而让类直接继承 Object，任何静态
// 工具都会判定为坏组件；这里在 Addition 落盘前把对应 ClassSpec 的父类换成
// Activity、构造器改为调用 Activity.<init>、并补一个空的 onCreate(Bundle)。
func applyDecoyActivities(add *dex.Addition, slash string, activities map[string]bool) error {
	if len(activities) == 0 {
		return nil
	}
	for i := range add.Classes {
		c := &add.Classes[i]
		name := strings.TrimSuffix(strings.TrimPrefix(c.Name, "L"+slash+"/"), ";")
		if !activities[name] {
			continue
		}
		c.Super = "Landroid/app/Activity;"
		// 构造器必须调用**直接父类**的 <init>：调用 Object.<init> 会让 ART
		// 校验报「构造器未调用 super()」，整个类被判非法。
		for j := range c.Methods {
			if c.Methods[j].Name != "<init>" {
				continue
			}
			body, err := decoyCtorCallCode(c.Super)
			if err != nil {
				return err
			}
			c.Methods[j].Code = body
		}
		onCreate, err := decoyOnCreateMethod()
		if err != nil {
			return err
		}
		c.Methods = append(c.Methods, onCreate)
	}
	return nil
}

// decoyCtorCallCode 生成 <init>()V：调用指定父类的无参构造器。
// registers=2、ins=1 → this 在 v1，与 dex 包的同名辅助实现一致。
func decoyCtorCallCode(super string) (*dex.CodeBlob, error) {
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

// decoyOnCreateMethod 生成 onCreate(Landroid/os/Bundle;)V 的空实现：
// 覆写框架方法、不写任何寄存器，最小且合法。
func decoyOnCreateMethod() (dex.ClassMethod, error) {
	a := dex.NewAsm()
	a.ReturnVoid()
	insns, patches, err := a.Assemble()
	if err != nil {
		return dex.ClassMethod{}, err
	}
	return dex.ClassMethod{
		Name:   "onCreate",
		Proto:  dex.ProtoSpec{Ret: "V", Params: []string{"Landroid/os/Bundle;"}},
		Access: decoyAccPublic,
		Code:   &dex.CodeBlob{Registers: 2, Ins: 2, Insns: insns, Patches: patches},
	}, nil
}

// compNames 返回组件名列表（用于日志）。
func compNames(cs []dex.DecoyComponent) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.Name)
	}
	return out
}

// declareDecoyComponents 把诱饵类声明成 Manifest 里的 <activity>/<receiver>/<service>。
//
// 为什么值得做：只注入类时，静态分析者扫一遍 Manifest 就能看到「组件表里没有
// 任何安全相关类」，于是立刻知道诱饵是填充物；把它们**真的声明成组件**，这些
// 名字才会出现在组件表、权限视图、导出组件清单里，与真实应用的形态一致。
// 组件形态与名族一一对应（activity/receiver/service），与参考样本的
// Core*/Signal*/Quiet* 三族一致。
//
// 两条安全约束（都不是可选项）：
//   - 只声明三类组件，**绝不声明 provider**：ContentProvider 会在应用启动时
//     被 ActivityThread 主动实例化，而诱饵是空实现，被拉起就可能干扰启动。
//   - 不加 intent-filter，并把 enabled/exported 都写成 false（样本同款）：
//     系统永远不会实例化或启动它们，声明只对静态分析可见。
//
// 返回实际写入的组件数。
func declareDecoyComponents(art *pipeline.Artifact, pkg string, comps []dex.DecoyComponent) (int, error) {
	if len(comps) == 0 {
		return 0, nil
	}
	entry := pipeline.Find(art, "AndroidManifest.xml")
	if entry == nil {
		return 0, nil // 没有 Manifest 就无从声明，交由 E3 自检去报错
	}
	data, err := entry.Data()
	if err != nil {
		return 0, fmt.Errorf("读取 Manifest 失败: %w", err)
	}
	mf, err := axml.Parse(data)
	if err != nil {
		return 0, fmt.Errorf("解析 Manifest 失败: %w", err)
	}
	if mf.FindElement("application") == nil {
		return 0, nil
	}

	edit := axml.Edit{}
	for _, c := range comps {
		edit.AddElements = append(edit.AddElements, axml.NewElement{
			Parent:      "application",
			ParentIndex: 0,
			Name:        string(c.Kind),
			Attrs: []axml.NewAttr{
				// 用全限定名而不是 ".CoreAtlas"：诱饵类落在 seed 派生的主题包下，
				// 写成相对名会指向应用自身包，声明与实际类对不上。
				axml.StringAttr(axml.AndroidNS, "name", pkg+"."+c.Name),
				axml.BoolAttr(axml.AndroidNS, "exported", false),
				axml.BoolAttr(axml.AndroidNS, "enabled", false),
			},
		})
	}
	out, err := mf.Rewrite(edit)
	if err != nil {
		return 0, fmt.Errorf("写入诱饵组件失败: %w", err)
	}
	// 写回后必须能重新解析：组件声明一旦写坏，应用会启动即死。
	if _, err := axml.Parse(out); err != nil {
		return 0, fmt.Errorf("诱饵组件写入后 Manifest 无法解析: %w", err)
	}
	if err := entry.SetData(out, true); err != nil {
		return 0, fmt.Errorf("写回 Manifest 失败: %w", err)
	}
	return len(comps), nil
}
