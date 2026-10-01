package passes

import (
	"context"
	"fmt"
	"hash/fnv"
	"sort"
	"strings"

	"apkguard/internal/arsc"
	"apkguard/internal/config"
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
//     本实现不动 arsc 内部的 keyStrings（资源条目名），因此按名字查仍然可用，
//     失效的只是「按路径拼字符串」这种少见写法；
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
	if len(paths) == 0 {
		art.Note("%s 资源混淆：%s 中没有 res/ 路径，跳过", tag, arscName)
		return nil
	}

	// 既有条目名集合：新名字绝不能与任何现存条目（含 assets/、lib/ 等）冲突。
	used := map[string]bool{}
	for _, e := range art.Entries() {
		used[e.NameString()] = true
	}
	// 映射的生成必须与顺序无关：先排序再生成，保证同一输入产出可复现。
	sort.Strings(paths)
	mapping := map[string]string{}
	for _, p := range paths {
		n := newResPath(p, flatten, opts.Seed)
		for used[n] || mappingConflicts(mapping, n) {
			n = newResPath(p+"#", flatten, opts.Seed)
		}
		mapping[p] = n
		used[n] = true
	}

	// 1) 改写 ARSC 里的路径字符串。
	changed := 0
	for old, nw := range mapping {
		changed += tbl.Replace(old, nw)
	}
	out, err := tbl.Encode()
	if err != nil {
		return fmt.Errorf("重写 %s 失败: %w", arscName, err)
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

	// 2) 同步改名 ZIP 条目。
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
	art.Stat(tag+".paths", fmt.Sprint(len(mapping)))
	art.Stat(tag+".entries", fmt.Sprint(renamed))
	art.Stat(tag+".untouched", fmt.Sprint(untouched))
	return nil
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

// 保证 zipx 仍被引用（本文件在部分构建组合下可能只用到其类型）。
var _ = zipx.NewStored
