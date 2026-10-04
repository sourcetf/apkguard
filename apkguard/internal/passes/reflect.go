package passes

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/pipeline"
)

// ---- A7 反射成员名强制加密 ----

// reflectionNameKey 是 A7 写入、A2 读取的 Artifact.Shared 键。
//
// 约定：值为 map[string]bool，键是「被直接用作反射成员名参数」的明文字符串。
// A2 在加密时会无条件放行这些串（不受 ObfStringMin / SingleRefOnly 限制）。
// 之所以经 Shared 而不是直接在 A7 里加密：加密属于 A2 的职责，A7 只做识别，
// 两者解耦后 A2 未启用时 A7 不会偷偷改写 DEX。
const reflectionNameKey = "a7.forcestrings"

// reflectNames 识别「反射用的成员名」字符串并登记给 A2 强制加密。
//
// 背景（参考样本实证）：样本对反射成员名做了字符串加密，池里是 Base64 密文，
// 运行期解密后用于 Class.getDeclaredMethod / getField 等；解出的明文包括
// addFontFromAssetManager、mMainThread、performStopActivity、asyncTraceBegin、
// isTagEnabled 等。这些名字的共同弱点是**短**——低于 A2 的 ObfStringMin 时会被
// 留在明文，grep 就能还原反射目标。本 Pass 补的就是这个洞。
//
// 职责边界（与注册表 Desc 一致）：
//   - 只扫描、只登记，绝不改写 DEX；产物字节由 A2 决定；
//   - 类名入口（Class.forName / ClassLoader.loadClass）不算：样本里类名明文；
//   - A2 未启用时**不报错、不静默**：Note 写明已识别的条数与未加密的事实。
type reflectNames struct{}

func (reflectNames) ID() config.FeatureID { return "A7" }
func (reflectNames) In() pipeline.Level   { return pipeline.LevelZip }
func (reflectNames) Out() pipeline.Level  { return pipeline.LevelZip }

func (r *reflectNames) Run(_ context.Context, art *pipeline.Artifact, opts *config.Options) error {
	entries := pipeline.FindAll(art, isDexEntry)
	if len(entries) == 0 {
		return fmt.Errorf("未找到任何 DEX 条目")
	}

	found := map[string]bool{}
	scanned, unparsable := 0, 0
	for _, en := range entries {
		data, err := en.Data()
		if err != nil {
			unparsable++
			continue
		}
		f, err := dex.Parse(data)
		if err != nil {
			unparsable++ // 伪装文件（A9/A16 的假 DEX）
			continue
		}
		names, err := dex.ReflectionNames(f)
		if err != nil {
			return fmt.Errorf("扫描 %s 的反射成员名失败: %w", en.NameString(), err)
		}
		for s := range names {
			found[s] = true
		}
		scanned++
	}
	if scanned == 0 {
		return fmt.Errorf("没有任何 DEX 条目可被解析")
	}

	// 登记：无论 A2 是否启用都登记（A2 先于本 Pass 的场景不存在，本 Pass 必须
	// 排在 A2 之前；登记本身零副作用）。
	art.Put(reflectionNameKey, found)

	sample := reflectionNameSample(found, 5)
	a2 := opts.IsEnabled("A2")
	switch {
	case len(found) == 0:
		art.Note("A7 反射成员名识别：%d 个 DEX 中未发现被用作反射成员名（getMethod/getDeclaredMethod/getField/getDeclaredField 的字符串参数）的明文常量%s",
			scanned, unparsableNote(unparsable))
	case !a2:
		art.Note("A7 已识别 %d 条反射成员名（%s），但 A2（字符串加密）未启用，未加密：这些名字仍以明文留在字符串池，grep 即可还原反射目标；启用 A2 后会被无条件加密（不受最短长度限制）%s",
			len(found), sample, unparsableNote(unparsable))
	default:
		art.Note("A7 反射成员名识别：%d 个 DEX 中登记 %d 条反射成员名（%s），由 A2 无条件加密（不受 -obf-string-min 限制）%s",
			scanned, len(found), sample, unparsableNote(unparsable))
	}
	art.Stat("A7.dex", fmt.Sprint(scanned))
	art.Stat("A7.strings", fmt.Sprint(len(found)))
	return nil
}

// reflectionNameSample 返回排序后的前 n 条名字，用于报告（确定性输出）。
func reflectionNameSample(m map[string]bool, n int) string {
	all := make([]string, 0, len(m))
	for s := range m {
		all = append(all, s)
	}
	sort.Strings(all)
	if len(all) > n {
		all = all[:n]
	}
	quoted := make([]string, len(all))
	for i, s := range all {
		quoted[i] = fmt.Sprintf("%q", s)
	}
	if len(m) > n {
		return strings.Join(quoted, "、") + fmt.Sprintf("…（共 %d 条）", len(m))
	}
	return strings.Join(quoted, "、")
}

// unparsableNote 统一「跳过多少个不可解析条目」的说明。
func unparsableNote(n int) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("；跳过 %d 个不可解析条目（伪 DEX）", n)
}
