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
	r.Register(&encryptString{})
	r.Register(&constantArray{})
	r.Register(&classPad{})
	r.Register(&dropDebugInfo{})
	r.Register(&fakeDex{})
	r.Register(&junkEntries{})
	r.Register(&zipPathAttack{})
	r.Register(&resourceObf{})
	r.Register(&resourceFlatten{})
	r.Register(&decoyClass{})

	// ---- 阶段3：L2 一代壳 ----
	//
	// 顺序同样不可调换：
	//   B1 先按类名排序取出全部可解析 DEX，加密成 assets 载荷并**移除**明文条目；
	//   B2 再把壳 DEX 补进去（此时 classes.dex 已被 B1 腾空）并改写 Manifest；
	//   B3 最后把 Loader 类体注入 B2 建好的那个壳 DEX。
	// B4 必须排在 B1 **之前**：它先把业务 DEX 拆成多份，B1 再把每一份
	// 各自加密成独立载荷。反过来则拆分无从下手（B1 已把明文移出 APK）。
	r.Register(&splitDex{})
	r.Register(&encryptDex{})
	// B8 必须排在 B1 之后（要读加密载荷清单）、B3 之前（要改载荷条目名，
	// 而 B3 生成 Loader 时会把这些名字内联进字节码）。
	r.Register(&payloadContainer{})
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
type metaUnify struct{}

func (metaUnify) ID() config.FeatureID { return "A14" }
func (metaUnify) In() pipeline.Level   { return pipeline.LevelZip }
func (metaUnify) Out() pipeline.Level  { return pipeline.LevelZip }

// defaultStamp 是未指定时间戳时使用的固定时间。
var defaultStamp = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

func (m *metaUnify) Run(_ context.Context, art *pipeline.Artifact, opts *config.Options) error {
	stamp := defaultStamp
	if opts.StampTime != "" {
		t, err := time.Parse(time.RFC3339, opts.StampTime)
		if err != nil {
			return fmt.Errorf("时间戳格式非法（应为 RFC3339）: %w", err)
		}
		stamp = t
	}
	dosTime, dosDate := toDOSDateTime(stamp)

	for _, e := range art.Entries() {
		e.ModTime = dosTime
		e.ModDate = dosDate
		// create_system 位于 VersionMade 的高字节，统一为 0（MS-DOS）。
		e.VersionMade &^= 0xff00
		// 清除条目注释，避免泄露打包工具信息。
		e.Comment = nil
	}

	art.Note("A14 元数据统一化：%d 个条目的时间戳统一为 %s",
		len(art.Entries()), stamp.Format("2006-01-02 15:04:05"))
	art.Stat("A14.entries", fmt.Sprint(len(art.Entries())))
	return nil
}

// toDOSDateTime 把 time.Time 转换为 ZIP 使用的 DOS 时间与日期字段。
func toDOSDateTime(t time.Time) (uint16, uint16) {
	t = t.UTC()
	if t.Year() < 1980 {
		t = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	dosTime := uint16(t.Hour())<<11 | uint16(t.Minute())<<5 | uint16(t.Second()/2)
	dosDate := uint16(t.Year()-1980)<<9 | uint16(t.Month())<<5 | uint16(t.Day())
	return dosTime, dosDate
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

// junkEntries 注入无意义 ZIP 条目：非 ASCII 顶层文件、随机名深目录、畸形 META-INF。
type junkEntries struct{}

func (junkEntries) ID() config.FeatureID { return "A10" }
func (junkEntries) In() pipeline.Level   { return pipeline.LevelZip }
func (junkEntries) Out() pipeline.Level  { return pipeline.LevelZip }

func (j *junkEntries) Run(_ context.Context, art *pipeline.Artifact, opts *config.Options) error {
	rnd := newRand(opts.Seed)

	used := map[string]bool{}
	for _, e := range art.Entries() {
		used[e.NameString()] = true
	}
	add := func(name string, data []byte) bool {
		if name == "" || used[name] || manifestCollision(name) {
			return false
		}
		used[name] = true
		pipeline.Add(art, zipx.NewStored(name, data))
		return true
	}

	// ① 非 ASCII 顶层文件：用易混字符集构造合法但难读的名字，内容是**可解析的**
	//    真 AXML（约 400 字节，与参考样本的 388 字节一致）。
	//
	// 早期实现只放 8 字节头部：扫描器一次解析失败就把整类丢弃，反而更快定位真文件。
	// 现在每个垃圾 XML 都能被 aapt/jadx 正常解析，分析者必须逐个读完才知道是空的。
	topAdded := 0
	for i := 0; i < opts.JunkTopCount; i++ {
		size := 300 + rnd.Intn(200)
		if add(confusableName(rnd, 3+i%6)+".xml", realisticAXML(rnd, size)) {
			topAdded++
		}
	}

	// ② 随机名深目录条目（内容为顺序字节，像某种格式，比随机数据更耐看且可压缩）
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
		if add(joinPath(parts), sequentialBytes(512+rnd.Intn(2048))) {
			dirAdded++
		}
	}

	// ③ 同名单目录深层路径：参考样本用 76 层同名目录制造超长路径，
	//    这类路径会触发解包工具的路径长度/递归问题，而对真实文件毫无影响。
	//    只在与 ② 同量级的规模下生成（每 10 个深目录配 1 条），避免体积失控。
	aliasAdded := 0
	for i := 0; i < opts.JunkDirCount/10; i++ {
		depth := 60 + rnd.Intn(20)
		leaf := randSeg(rnd, 3+rnd.Intn(8))
		p := deepAliasPath(rnd, 2+rnd.Intn(4), depth, leaf)
		if add(p, sequentialBytes(64<<10)) {
			aliasAdded++
		}
	}

	// ④ 畸形 META-INF 路径：用前缀、双斜杠、点段等使签名状态判定产生歧义。
	//
	// 但**绝不注入任何会被当成 MANIFEST.MF / 签名文件的名字**（见 manifestCollision）：
	// 假 manifest 会让 JarVerifier 读到错误的主属性，运行时报
	//   java.lang.SecurityException: Invalid signature file digest for Manifest main attributes
	// ZIP 条目名在 Android 的 JarFile/ZipUtils 里是**大小写不敏感**地比较
	// `META-INF/MANIFEST.MF`，所以 `meta-inf/MANIFEST.MF` 也算撞名。
	// 实测于 RustDesk 1.5.0（Flutter）：ServiceLoader 经 JarFile 读
	// META-INF/services 触发 v1 校验，首次 attach 即崩。
	metaAdded := 0
	malformed := []string{
		"META-INF/",
		"META-INF//MANIFEST.MFx",
		"META-INF/./MANIFEST.MFx",
		"META-INF/../META-INF/x.MF",
		"META-INF/.hidden",
		"meta-inf/MANIFEST.MFx",
		"META-INF/sub/",
	}
	for i := 0; i < opts.JunkMetaCount; i++ {
		name := malformed[i%len(malformed)]
		if i >= len(malformed) {
			name = fmt.Sprintf("%s%d", malformed[i%len(malformed)], i/len(malformed))
		}
		if add(name, []byte("Manifest-Version: 1.0\r\n\r\n")) {
			metaAdded++
		}
	}

	art.Note("A10 垃圾条目：顶层易混名 %d 条（内容为可解析的真 AXML）、深目录 %d 条、同名深层目录 %d 条、畸形 META-INF %d 条",
		topAdded, dirAdded, aliasAdded, metaAdded)
	art.Stat("A10.top", fmt.Sprint(topAdded))
	art.Stat("A10.dir", fmt.Sprint(dirAdded))
	art.Stat("A10.alias", fmt.Sprint(aliasAdded))
	art.Stat("A10.meta", fmt.Sprint(metaAdded))
	return nil
}

// ---- A12 ZIP 路径攻击 ----

// zipPathAttack 注入三类路径攻击条目。
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

	used := map[string]bool{}
	for _, e := range art.Entries() {
		used[e.NameString()] = true
	}

	// ① 路径前缀滥用：用关键文件名当目录名
	prefixes := []string{
		"classes.dex/", "AndroidManifest.xml/", "resources.arsc/",
		"classes2.dex/", "lib/",
	}
	// junk 收集本 Pass 自己注入的条目，供 ③ 复制使用。
	var junk []*zipx.Entry
	p1 := 0
	for i := 0; i < n; i++ {
		name := prefixes[i%len(prefixes)] + randSeg(rnd, 6)
		if used[name] || manifestCollision(name) {
			continue
		}
		used[name] = true
		e := zipx.NewStored(name, []byte("0"))
		pipeline.Add(art, e)
		junk = append(junk, e)
		p1++
	}

	// ② 绝对路径条目：混入**分隔符变体**，让不同工具的解压/规范化行为分叉
	//
	// 参考样本的绝对路径条目并不只是 "/随机名"：它带混合分隔符与转义
	// （`/AndroidManifest.xml\/\.xml`、`/AndroidManifest.xml/////.9.png`）。
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
		if used[name] || manifestCollision(name) {
			continue
		}
		used[name] = true
		e := zipx.NewStored(name, []byte("0"))
		pipeline.Add(art, e)
		junk = append(junk, e)
		p2++
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

	art.Note("A12 ZIP 路径攻击：前缀滥用 %d 条、绝对路径 %d 条、重名 %d 条", p1, p2, p3)
	art.Stat("A12.prefix", fmt.Sprint(p1))
	art.Stat("A12.absolute", fmt.Sprint(p2))
	art.Stat("A12.dup", fmt.Sprint(p3))
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
// 与 A13（类膨胀）互补：A13 靠数量与超长类名增加体量，A8 靠**名字**把
// 逆向者的注意力引开——翻到 SecurityMonitor、IntegrityChecker 时很难
// 不去读它们。这些类结构合法且方法体带真实位运算，不是一眼假的空壳。
type decoyClass struct{}

func (decoyClass) ID() config.FeatureID { return "A8" }
func (decoyClass) In() pipeline.Level   { return pipeline.LevelZip }
func (decoyClass) Out() pipeline.Level  { return pipeline.LevelZip }

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
	prefix := shellPkgOf(opts)
	var names []string
	for _, n := range dex.DecoyClassNames {
		if !existing["L"+prefix+"/"+n+";"] {
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		return fmt.Errorf("诱饵类名与现有类全部冲突，无可注入")
	}

	// 挑出「实际被注入」的诱饵组件（名字可能与现有类冲突而被剔除）。
	injected := map[string]bool{}
	for _, n := range names {
		injected[n] = true
	}
	var comps []dex.DecoyComponent
	for _, c := range dex.DecoyManifestComponents {
		if injected[c.Name] {
			comps = append(comps, c)
		}
	}

	add, err := dex.DecoyAddition(&dex.DecoySpec{
		Prefix:     prefix,
		Names:      names,
		Seed:       opts.Seed,
		Components: comps,
	})
	if err != nil {
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

	declared, err := declareDecoyComponents(art, prefix, comps)
	if err != nil {
		return err
	}

	art.Note("A8 诱饵类注入：向 %s 注入 %d 个具误导性命名的类（如 %s.%s），方法体带真实位运算；"+
		"其中 %d 个（%s）已作为 <receiver>/<service> 声明进 Manifest",
		host.NameString(), len(names), prefix, names[0], declared, strings.Join(compNames(comps), "、"))
	art.Stat("A8.classes", fmt.Sprint(len(names)))
	art.Stat("A8.dex", host.NameString())
	art.Stat("A8.components", fmt.Sprint(declared))
	return nil
}

// compNames 返回组件名列表（用于日志）。
func compNames(cs []dex.DecoyComponent) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.Name)
	}
	return out
}

// declareDecoyComponents 把诱饵类声明成 Manifest 里的 <receiver>/<service>。
//
// 为什么值得做：只注入类时，静态分析者扫一遍 Manifest 就能看到「组件表里没有
// 任何安全相关的类」，于是立刻知道 SecurityMonitor 之类的类是填充物；
// 把它们**真的声明成组件**，这些名字才会出现在组件表、权限视图、导出组件清单里，
// 与真实应用的形态一致。
//
// 两条安全约束（都不是可选项）：
//   - 只声明 receiver / service，**不声明 provider**：ContentProvider 会在应用启动时
//     被 ActivityThread 主动实例化，而诱饵是空实现，被拉起就可能干扰启动。
//   - 不加 intent-filter：没有过滤器时系统永远不会实例化它们，声明只对静态分析可见。
//
// 返回实际写入的组件数。
func declareDecoyComponents(art *pipeline.Artifact, prefix string, comps []dex.DecoyComponent) (int, error) {
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

	javaPkg := strings.ReplaceAll(prefix, "/", ".")
	edit := axml.Edit{}
	for _, c := range comps {
		edit.AddElements = append(edit.AddElements, axml.NewElement{
			Parent:      "application",
			ParentIndex: 0,
			Name:        string(c.Kind),
			Attrs: []axml.NewAttr{
				// 用全限定名而不是 ".SecurityMonitor"：诱饵类实际落在壳包下，
				// 写成相对名会指向应用自身包，声明与实际类对不上。
				axml.StringAttr(axml.AndroidNS, "name", javaPkg+"."+c.Name),
				axml.BoolAttr(axml.AndroidNS, "exported", false),
				axml.BoolAttr(axml.AndroidNS, "enabled", true),
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
