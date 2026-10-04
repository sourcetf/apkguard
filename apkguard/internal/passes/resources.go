package passes

import (
	"context"
	"fmt"
	"hash/fnv"
	"os"
	"sort"
	"strconv"
	"strings"

	"apkguard/internal/arsc"
	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/pipeline"
	"apkguard/internal/zipx"
)

// ---- A5 资源混淆 / A11 资源路径全量扁平化 ----

// resourceObf 重命名 res/ 下的资源文件，并同步改写 resources.arsc 中的路径。
//
// A5 与 A11 是同一套机制的两种强度，因此共用一份实现：
//   - A5：重命名**文件名**，保留目录结构（res/drawable-hdpi/icon.png → res/drawable-hdpi/a1b2.png）
//   - A11：在 A5 基础上把所有目录压成单字母（res/drawable-hdpi/ → res/a/），
//     消除“res/layout/”“res/drawable-xxhdpi/”这类语义残留
//
// 为什么只需要改字符串池：资源引用走的是资源 ID（整数），路径只作为**字符串值**
// 存在于 resources.arsc 的全局字符串池里。改路径因此等价于改池中若干条目，
// 而 ARSC 是按块顺序解析的（表头没有任何绝对偏移），替换池之后只需回填
// 池块与表头两处长度字段，其余字节原样搬运——不需要任何重定位。
//
// 已知代价（与设计文档一致）：
//   - 依赖 `getIdentifier("icon","drawable",pkg)` 这类**按名字**查资源的代码会失效；
//     为此条目名（keyStrings）随机化会把「原始输入 APK 或当前产物中任何 DEX
//     字符串池里出现过的名字」全部保留原名（见 collectDexStrings）。
//     之所以必须扫原始输入：A1（改 R 类字段名）与 A2（字符串加密，默认启用）
//     排在 A5/A11 之前，会把按名查表的字面量从产物 DEX 池里抹掉——只扫产物时
//     实测 testapp 全默认组合下 A11.keysdex=0、sample 保留数从 12 掉到 10。
//     输入 APK 不可读时退化为只扫产物，并在报告中如实说明保留集可能偏小。
//     运行时按规则拼出来的名字仍然看不到（无法静态覆盖的固有残余风险）；
//   - 依赖资源名的第三方 SDK 与热修复框架可能受影响，因此默认关闭。
type resourceObf struct{}

func (resourceObf) ID() config.FeatureID { return "A5" }
func (resourceObf) In() pipeline.Level   { return pipeline.LevelZip }
func (resourceObf) Out() pipeline.Level  { return pipeline.LevelZip }

// arscName 是资源表的固定条目名。
const arscName = "resources.arsc"

func (r *resourceObf) Run(_ context.Context, art *pipeline.Artifact, opts *config.Options) error {
	// A11 是 A5 的**完整形态**：它同样会重命名文件，并额外压平目录。
	// 因此两者同时启用时由 A11 单独完成即可——否则同一批资源会被连着改两次名，
	// 结果虽然自洽，但白做一遍且日志会让人误以为改了两批资源。
	if opts.IsEnabled("A11") {
		art.Note("A5 资源混淆：A11 已启用，其命名策略完全覆盖 A5，由 A11 单独执行（避免重复改名）")
		return nil
	}
	return renameResources(art, opts, false, "A5")
}

// ---- A11 资源路径全量扁平化 ----

// resourceFlatten 是 A5 的完整形态：目录全部压成单字母。
//
// 依赖 A5（Validate 已强制）：两者是同一机制的不同强度，A11 在其之上进一步
// 抹掉目录名。分开注册是为了让「只改名、不动目录结构」这个更保守的选项
// 仍然可用——目录结构本身有时是某些 ROM 或工具的隐含依赖。
type resourceFlatten struct{}

func (resourceFlatten) ID() config.FeatureID { return "A11" }
func (resourceFlatten) In() pipeline.Level   { return pipeline.LevelZip }
func (resourceFlatten) Out() pipeline.Level  { return pipeline.LevelZip }

func (f *resourceFlatten) Run(_ context.Context, art *pipeline.Artifact, opts *config.Options) error {
	return renameResources(art, opts, true, "A11")
}

// renameResources 执行资源改名；flatten 为 true 时同时压平目录。
//
// 除路径改名外，本函数还执行 A5/A11 的子行为「条目名（keyStrings）随机化」，
// 两者共用同一个 resources.arsc 解析结果与一次写回。
func renameResources(art *pipeline.Artifact, opts *config.Options, flatten bool, tag string) error {
	entry := pipeline.Find(art, arscName)
	if entry == nil {
		return fmt.Errorf("未找到 %s", arscName)
	}
	data, err := entry.Data()
	if err != nil {
		return fmt.Errorf("读取 %s 失败: %w", arscName, err)
	}
	tbl, err := arsc.Parse(data)
	if err != nil {
		return fmt.Errorf("解析 %s 失败: %w", arscName, err)
	}
	paths := tbl.ResPaths()

	// 1) 生成 res/ 路径 → 新路径映射。没有路径时不改路径，但 keyStrings
	//    随机化照常执行（它是独立子行为）。
	mapping := map[string]string{}
	if len(paths) > 0 {
		// 既有条目名集合：新名字绝不能与任何现存条目（含 assets/、lib/ 等）冲突。
		used := map[string]bool{}
		for _, e := range art.Entries() {
			used[e.NameString()] = true
		}
		// 映射的生成必须与顺序无关：先排序再生成，保证同一输入产出可复现。
		sort.Strings(paths)
		for _, p := range paths {
			n := newResPath(p, flatten, opts.Seed)
			for used[n] || mappingConflicts(mapping, n) {
				n = newResPath(p+"#", flatten, opts.Seed)
			}
			mapping[p] = n
			used[n] = true
		}
	}

	// 2) 改写 ARSC 里的路径字符串，再随机化条目名（keyStrings）。
	changed := 0
	for old, nw := range mapping {
		changed += tbl.Replace(old, nw)
	}
	out, err := tbl.Encode()
	if err != nil {
		return fmt.Errorf("重写 %s 失败: %w", arscName, err)
	}
	// A5/A11 的三个 ARSC 子行为，各自有 Shared 幂等标记、默认开启：
	// 条目名随机化（keyStrings）、资源值零宽副本（全局池末尾追加）、
	// 未使用 typeId 的占位名（typeStrings）。
	out, err = randomizeArscKeys(art, opts, out, tag)
	if err != nil {
		return err
	}
	out, err = padArscValues(art, opts, out, tag)
	if err != nil {
		return err
	}
	out, err = placeholderArscTypeNames(art, out, tag)
	if err != nil {
		return err
	}
	// 压缩方式必须保持原样，**不能**强制压缩：
	// Android 11+（targetSdk ≥ 30）要求 resources.arsc 以未压缩方式存放，
	// 否则安装时直接失败——
	//   Failure [-124] ... requires the resources.arsc of installed APKs
	//   to be stored uncompressed and aligned on a 4-byte boundary
	// 而 zipalign -c -p 4 查不出来（它只看未压缩条目的对齐）。
	if err := entry.SetData(out, !entry.IsStored()); err != nil {
		return fmt.Errorf("写回 %s 失败: %w", arscName, err)
	}

	// 3) 同步改名 ZIP 条目。
	renamed := 0
	for _, e := range art.Entries() {
		n := e.NameString()
		if !strings.HasPrefix(n, "res/") {
			continue
		}
		if nw, ok := mapping[n]; ok {
			e.Name = []byte(nw)
			renamed++
		}
	}
	// res/ 下「不被 ARSC 引用」的条目：本 Pass 不动它们。
	//
	// 这类条目要么是死资源，要么是 A10/A12 注入的垃圾条目（样本里就有
	// res/values/anims.xml////\.png 这种畸形名）。改写它们既没有防护收益，
	// 又可能破坏那些条目本身的设计意图，因此原样保留并如实报数。
	untouched := 0
	for _, n := range resZipEntryNames(art) {
		if _, ok := mapping[n]; !ok {
			untouched++
		}
	}

	if len(paths) == 0 {
		art.Note("%s 资源混淆：%s 中没有 res/ 路径，跳过路径改名（条目名随机化单独执行）", tag, arscName)
	} else {
		mode := "重命名"
		if flatten {
			mode = "全量扁平化"
		}
		if renamed != len(mapping) {
			art.Note("%s 提示：ARSC 中有 %d 条 res/ 路径，实际改名的条目为 %d 条（其余路径在 APK 中没有对应文件）",
				tag, len(mapping), renamed)
		}
		art.Note("%s 资源路径%s：改写 %d 条路径（ARSC 中替换 %d 处），同步改名 %d 个条目；另有 %d 个 res/ 条目不被 ARSC 引用，按原样保留",
			tag, mode, len(mapping), changed, renamed, untouched)
	}
	art.Stat(tag+".paths", fmt.Sprint(len(mapping)))
	art.Stat(tag+".entries", fmt.Sprint(renamed))
	art.Stat(tag+".untouched", fmt.Sprint(untouched))
	return nil
}

// arscKeysDoneKey 标记本产物已完成 keyStrings 随机化。
//
// A5 与 A11 是同一机制的两种强度，可能先后被调用（例如流水线把两者都启用，
// 或调用方手工各跑一次）；标记存于 Artifact.Shared，保证条目名只随机化一次。
const arscKeysDoneKey = "A5.keysdone"

// arscPadDoneKey / arscTypeDoneKey 是另外两个 A5/A11 子行为的幂等标记：
// 资源值零宽副本、未使用 typeId 的 typeStrings 占位名。同样存于
// Artifact.Shared，保证同一产物上只执行一次。
const (
	arscPadDoneKey  = "A5.paddone"
	arscTypeDoneKey = "A5.typedone"
)

// randomizeArscKeys 执行资源条目名（keyStrings）随机化——A5/A11 的子行为，
// 默认开启，无需单独开关（随 A5/A11 一起启用/关闭）。
//
// 保留集合来自两处只读扫描（取并集，见 collectDexStrings）：
//   - **原始输入 APK**（opts.In，未经任何 Pass 改写）的全部 DEX 字符串池，
//     这是主来源，A1/A2 的改写抹不掉它；
//   - 当前产物中可解析 DEX 的池，作为兜底（输入缺失/不可读时退化，并可覆盖
//     输入之后新产生的字符串）。
//
// B1 加密 DEX 的 Pass 排在 A5/A11 之后，因此产物侧通常能读到明文；读不到的
// 条目（伪装 DEX、已加密载荷）自然拿不到字符串，其引用无法被保护——这是
// 必须如实说明的残余风险。
func randomizeArscKeys(art *pipeline.Artifact, opts *config.Options, data []byte, tag string) ([]byte, error) {
	if done, _ := art.Get(arscKeysDoneKey).(bool); done {
		art.Note("%s 资源条目名：本产物已执行过 keyStrings 随机化，跳过（幂等）", tag)
		return data, nil
	}
	keep := collectDexStrings(art, opts)
	out, st, err := arsc.RandomizeKeys(data, arsc.KeyRenameOptions{
		Seed: opts.Seed + "/arsckeys",
		Keep: keep.set,
	})
	if err != nil {
		return nil, fmt.Errorf("随机化 %s 的 keyStrings 失败: %w", arscName, err)
	}
	art.Put(arscKeysDoneKey, true)
	if keep.inErr != nil {
		art.Note("%s 资源条目名：输入 APK 不可读（%v），退化为仅扫描运行时产物 DEX，保留集可能偏小", tag, keep.inErr)
	}
	art.Note("%s 资源条目名随机化：keyStrings 改写 %d 条 / 保留 %d 条（DEX 引用 %d 条、库名/点分等 %d 条；%d 个包，其中 %d 条带 vx_*_ 类型前缀）；保留集来源 = 输入 APK %d 条 + 运行时产物 %d 条（并集 %d 条）",
		tag, st.Renamed, st.Kept, st.KeptDex, st.KeptShape, st.Packages, st.Prefixed,
		keep.fromIn, keep.fromArt, len(keep.set))
	art.Stat(tag+".keys", fmt.Sprint(st.Renamed))
	art.Stat(tag+".keyskept", fmt.Sprint(st.Kept))
	// keysdex 报告保留集的来源构成「输入N+运行时M」（N+M 即去重后的保留集大小）；
	// keysdexhit 保留旧口径：命中保留集而未被改名的 ARSC 条目数。
	art.Stat(tag+".keysdex", fmt.Sprintf("%d+%d", keep.fromIn, keep.fromArt))
	art.Stat(tag+".keysdexhit", fmt.Sprint(st.KeptDex))
	art.Stat(tag+".keysprefixed", fmt.Sprint(st.Prefixed))
	return out, nil
}

// padArscValues 执行「资源值零宽副本」——A5/A11 的子行为，默认开启，
// 无独立开关（随 A5/A11 一起启用/关闭）。
//
// 只往全局字符串池**末尾**追加带 U+200E/U+200F 的副本，且不被任何 entry
// 引用：目的与样本一致——同一逻辑值在池里不再有唯一字节形态，按内容做
// 签名/去重/白名单的规则被稀释；同时已有条目下标不动，运行时资源解析
// 完全不受影响。
func padArscValues(art *pipeline.Artifact, opts *config.Options, data []byte, tag string) ([]byte, error) {
	if done, _ := art.Get(arscPadDoneKey).(bool); done {
		art.Note("%s 资源值零宽副本：本产物已执行过，跳过（幂等）", tag)
		return data, nil
	}
	out, st, err := arsc.PadValues(data, arsc.ValuePadOptions{Seed: opts.Seed + "/arscpad"})
	if err != nil {
		return nil, fmt.Errorf("生成 %s 的资源值零宽副本失败: %w", arscName, err)
	}
	art.Put(arscPadDoneKey, true)
	art.Note("%s 资源值零宽副本：%d 条（覆盖 %d 个逻辑值，%d 条重前缀 + %d 条单标记；全部追加在全局字符串池末尾，均未被任何 entry 引用）；另有 %d 条被引用值因 res/ 路径或形状不适合复制而排除",
		tag, st.Appended, st.Originals, st.Heavy, st.Single, st.ExcludedShape)
	art.Stat(tag+".padstrings", fmt.Sprint(st.Appended))
	art.Stat(tag+".padvalues", fmt.Sprint(st.Originals))
	return out, nil
}

// placeholderArscTypeNames 执行「未使用 typeId 的占位名」——A5/A11 的子行为，
// 默认开启：未使用 id 的 typeStrings 槽位改名为 ?<id>（与样本一致），
// 已使用的类型名保持原样，不影响 getIdentifier 与 aapt2 的类型名解析。
func placeholderArscTypeNames(art *pipeline.Artifact, data []byte, tag string) ([]byte, error) {
	if done, _ := art.Get(arscTypeDoneKey).(bool); done {
		art.Note("%s typeStrings 占位名：本产物已执行过，跳过（幂等）", tag)
		return data, nil
	}
	out, st, err := arsc.PlaceholderTypeNames(data)
	if err != nil {
		return nil, fmt.Errorf("改写 %s 的 typeStrings 占位名失败: %w", arscName, err)
	}
	art.Put(arscTypeDoneKey, true)
	ids := make([]string, 0, len(st.IDs))
	for _, id := range st.IDs {
		ids = append(ids, strconv.Itoa(id))
	}
	art.Note("%s typeStrings 占位名：%d 个（未使用 id：%s；已使用的类型名保持原样，getIdentifier/aapt2 不受影响）",
		tag, st.Placeholders, strings.Join(ids, ","))
	art.Stat(tag+".typetokens", fmt.Sprint(st.Placeholders))
	return out, nil
}

// dexKeepSources 是保留集合的两个来源及其计数。
//
// 计数口径：先把输入 APK 的字符串并入集合（fromIn = 输入池大小），再并入
// 产物字符串（fromArt = 产物新增、输入中不存在的条数）。因此 fromIn+fromArt
// 恰好等于去重后的保留集大小，不会把两边都出现的名字重复计数。
type dexKeepSources struct {
	set     map[string]bool
	fromIn  int
	fromArt int
	// inErr 非 nil 表示输入 APK 不可读/解析失败，已退化为只扫产物。
	inErr error
}

// collectDexStrings 收集 keyStrings 保留集合：原始输入 APK ∪ 当前产物。
//
// 顺序固定为「先输入、后产物」，保证同一输入下统计口径可复现。
func collectDexStrings(art *pipeline.Artifact, opts *config.Options) dexKeepSources {
	src := dexKeepSources{set: map[string]bool{}}
	if in, err := inputDexStrings(opts.In); err != nil {
		src.inErr = err
	} else {
		src.fromIn = addStrings(src.set, in)
	}
	src.fromArt = addArtifactDexStrings(src.set, art)
	return src
}

// addStrings 把 strs 并入 dst，返回新增（原先不存在）的条数。
func addStrings(dst map[string]bool, strs map[string]bool) int {
	n := 0
	for s := range strs {
		if !dst[s] {
			dst[s] = true
			n++
		}
	}
	return n
}

// inputDexStrings 只读扫描**原始输入 APK**（opts.In）中全部 DEX 的字符串池。
//
// 这是保留集的主来源：执行到这里时，产物 DEX 里的
// `Resources.getIdentifier("app_name", ...)` 一类字面量已被排在前面的
// A1/A2 改名或加密，只有输入文件仍保有原始池。
//
// 任何不可读/不可解析的情况都返回错误而不中断：调用方据此退化为只扫产物，
// 并写入 art.Note 说明保留集可能偏小。
func inputDexStrings(path string) (map[string]bool, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("未提供输入 APK 路径")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	a, err := zipx.Read(data)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	parsed := 0
	for _, e := range a.Entries {
		if !isDexEntry(e) {
			continue
		}
		raw, err := e.Data()
		if err != nil {
			continue
		}
		f, err := dex.Parse(raw)
		if err != nil {
			continue
		}
		strs, err := f.AllStrings()
		if err != nil {
			continue
		}
		parsed++
		for _, s := range strs {
			out[s] = true
		}
	}
	if parsed == 0 {
		return nil, fmt.Errorf("输入 APK 中没有可解析的 DEX")
	}
	return out, nil
}

// addArtifactDexStrings 把当前产物中全部可解析 DEX 的字符串池并入 dst，
// 返回新增条数。解析失败（伪装 DEX、加密载荷、损坏文件）时跳过该条目，
// 不阻断资源混淆。
func addArtifactDexStrings(dst map[string]bool, art *pipeline.Artifact) int {
	n := 0
	for _, e := range art.Entries() {
		if !isDexEntry(e) {
			continue
		}
		data, err := e.Data()
		if err != nil {
			continue
		}
		f, err := dex.Parse(data)
		if err != nil {
			continue
		}
		strs, err := f.AllStrings()
		if err != nil {
			continue
		}
		for _, s := range strs {
			if !dst[s] {
				dst[s] = true
				n++
			}
		}
	}
	return n
}

// mappingConflicts 判断新路径是否已被本次映射占用。
//
// 除了「不同旧路径映射到同一新路径」，还要挡住「新路径是另一条旧路径本身」——
// 后者会在改名过程中互相覆盖。
func mappingConflicts(mapping map[string]string, nw string) bool {
	for _, v := range mapping {
		if v == nw {
			return true
		}
	}
	_, isOld := mapping[nw]
	return isOld
}

// newResPath 由原路径派生新路径。
//
// 保留扩展名：`.9.png`（nine-patch）与 `.xml` 的扩展名参与系统判定，
// 改掉会破坏九图拉伸与资源编译产物的识别。
//
// 新名字用「种子 + 原路径」的哈希派生，因此确定性可复现，且与原名无语义关联。
func newResPath(p string, flatten bool, seed string) string {
	dir, base := splitResPath(p)
	ext := resExt(base)
	stem := resStem(base, ext)
	_ = stem

	h := fnv.New32a()
	_, _ = h.Write([]byte(seed + "|" + p))
	name := shortName(h.Sum32()) + ext

	if !flatten {
		return dir + "/" + name
	}
	// 扁平化：整个目录部分压成一个字母，由目录名哈希决定，保证同一目录
	// 下的所有文件落进同一个字母目录（否则同一目录会被拆散成多个，体积更差）。
	dh := fnv.New32a()
	_, _ = dh.Write([]byte(seed + "|dir|" + dir))
	return "res/" + letterDir(dh.Sum32()) + "/" + name
}

// splitResPath 把 "res/drawable-hdpi/icon.png" 拆成 ("res/drawable-hdpi", "icon.png")。
func splitResPath(p string) (dir, base string) {
	i := strings.LastIndex(p, "/")
	if i < 0 {
		return "res", p
	}
	return p[:i], p[i+1:]
}

// resExt 返回文件名中的扩展名（含 `.9.png` 这种复合扩展名）。
func resExt(base string) string {
	// 九图必须以 .9.png 结尾，整体视为扩展名。
	if strings.HasSuffix(base, ".9.png") {
		return ".9.png"
	}
	if i := strings.LastIndex(base, "."); i > 0 {
		return base[i:]
	}
	return ""
}

// resStem 返回去掉扩展名的部分（当前未直接使用，保留以便将来加长名字）。
func resStem(base, ext string) string { return strings.TrimSuffix(base, ext) }

// shortName 由 32 位哈希生成 6 位小写字母数字名。
//
// 长度取 6：36^6 ≈ 21.7 亿，对十万级资源量级的碰撞概率可忽略；
// 且显式做了去重兜底（见 renameResources）。
func shortName(h uint32) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	out := make([]byte, 6)
	for i := 0; i < 6; i++ {
		out[i] = alphabet[h%36]
		h /= 36
	}
	return string(out)
}

// letterDir 由哈希生成单字母目录名。
func letterDir(h uint32) string {
	return string(rune('a' + h%26))
}

// resZipEntryNames 返回产物中全部 res/ 条目名（用于报告与测试）。
func resZipEntryNames(art *pipeline.Artifact) []string {
	var out []string
	for _, e := range art.Entries() {
		if n := e.NameString(); strings.HasPrefix(n, "res/") {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}
