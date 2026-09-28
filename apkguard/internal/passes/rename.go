package passes

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"apkguard/internal/axml"
	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/pipeline"
	"apkguard/internal/zipx"
)

// ---- A1 名字混淆 ----

// renameClass 重命名类、方法与字段。
//
// 多 DEX 场景的关键难点：同一个类可能被多个 DEX 交叉引用。
// 因此实现分两轮：
//
//	第一轮：遍历全部 DEX，汇总「可重命名类集合」与「被反射引用的类名」，
//	        由主 DEX 统一分配新名，形成全局 ClassMap；
//	第二轮：各 DEX 按同一份 ClassMap 应用重命名，保证引用不断链。
type renameClass struct{}

func (renameClass) ID() config.FeatureID { return "A1" }
func (renameClass) In() pipeline.Level   { return pipeline.LevelZip }
func (renameClass) Out() pipeline.Level  { return pipeline.LevelZip }

func (r *renameClass) Run(_ context.Context, art *pipeline.Artifact, opts *config.Options) error {
	entries := pipeline.FindAll(art, isDexEntry)
	if len(entries) == 0 {
		return fmt.Errorf("未找到任何 DEX 条目")
	}

	// 读取全部 DEX 内容（保留条目指针以便写回）
	type dexUnit struct {
		entry *zipx.Entry
		data  []byte
		file  *dex.File
	}
	var units []dexUnit
	for _, e := range entries {
		data, err := e.Data()
		if err != nil {
			continue
		}
		f, err := dex.Parse(data)
		if err != nil {
			continue // 伪装文件
		}
		units = append(units, dexUnit{entry: e, data: data, file: f})
	}
	if len(units) == 0 {
		return fmt.Errorf("没有任何 DEX 条目可被解析")
	}

	keep := splitKeepRules(opts.KeepRules)
	keepClasses := manifestComponents(art)

	// ---- 第一轮：全局决策 ----
	classMap := map[string]string{}
	reflected := map[string]bool{}
	used := map[string]bool{}
	seq := 0

	// 1) 汇总全部 DEX 中出现过的「类名常量」，作为跨 DEX 反射保护依据
	for _, u := range units {
		names, err := constClassNames(u.file)
		if err != nil {
			return fmt.Errorf("%s 扫描字符串常量失败: %w", u.entry.NameString(), err)
		}
		for n := range names {
			reflected[n] = true
		}
	}

	// 2) 逐 DEX 决策哪些类可改，并按需分配新名
	type cand struct {
		desc string
		pkg  string
	}
	var cands []cand
	seen := map[string]bool{}
	// 先登记全部 DEX 中已存在的类描述符，避免新名与「未参与重命名的类」碰撞
	for _, u := range units {
		for i := uint32(0); i < u.file.NType; i++ {
			d, err := u.file.Type(i)
			if err != nil {
				continue
			}
			used[d] = true
		}
	}
	for _, u := range units {
		rn, err := dex.NewRenamer(u.file, dex.RenameConfig{
			Keep:             keep,
			ExtraKeepClasses: keepClasses,
			ReflectedNames:   reflected,
			ObfuscateFields:  true,
		})
		if err != nil {
			return fmt.Errorf("%s 构造重命名器失败: %w", u.entry.NameString(), err)
		}
		plan, err := rn.Plan()
		if err != nil {
			return fmt.Errorf("%s 生成重命名计划失败: %w", u.entry.NameString(), err)
		}
		for old := range plan {
			// 只处理类描述符；方法名/字段名留给第二轮
			if !isClassDesc(old) || seen[old] {
				continue
			}
			seen[old] = true
			pkg := ""
			if i := strings.LastIndex(old, "/"); i > 0 {
				pkg = old[:i+1]
			}
			cands = append(cands, cand{desc: old, pkg: pkg})
		}
	}
	sort.Slice(cands, func(a, b int) bool { return cands[a].desc < cands[b].desc })

	// 3) 统一分配新名：同一包内的类共享新名序号空间，避免冲突
	for _, c := range cands {
		for {
			seq++
			desc := c.pkg + encodeShortName(seq) + ";"
			if used[desc] {
				continue
			}
			used[desc] = true
			classMap[c.desc] = desc
			break
		}
	}

	// ---- 第二轮：各 DEX 应用重命名 ----
	totalCls, totalM, totalF := 0, 0, 0
	ok := 0
	before, after := 0, 0
	for _, u := range units {
		rn, err := dex.NewRenamer(u.file, dex.RenameConfig{
			Keep:             keep,
			ExtraKeepClasses: keepClasses,
			ReflectedNames:   reflected,
			ObfuscateFields:  true,
			ClassMap:         classMap,
		})
		if err != nil {
			return fmt.Errorf("%s 构造重命名器失败: %w", u.entry.NameString(), err)
		}
		plan, err := rn.Plan()
		if err != nil {
			return fmt.Errorf("%s 生成重命名计划失败: %w", u.entry.NameString(), err)
		}
		if len(plan) == 0 {
			continue
		}
		st := rn.LastStats()
		out, err := dex.Rebuild(u.file, dex.RebuildOptions{Rename: plan})
		if err != nil {
			return fmt.Errorf("重建 %s 失败: %w", u.entry.NameString(), err)
		}
		if err := dex.Verify(out); err != nil {
			return fmt.Errorf("%s 重建后校验失败: %w", u.entry.NameString(), err)
		}
		if err := u.entry.SetData(out, true); err != nil {
			return fmt.Errorf("写回 %s 失败: %w", u.entry.NameString(), err)
		}
		totalCls += st.Classes
		totalM += st.Methods
		totalF += st.Fields
		before += len(u.data)
		after += len(out)
		ok++
	}

	if ok == 0 {
		art.Note("A1 名字混淆：没有可安全重命名的类（全部命中保留规则）")
		return nil
	}
	saved := before - after
	art.Note("A1 名字混淆：%d 个 DEX，重命名类 %d、方法 %d、字段 %d；%d → %d 字节（减少 %d，%.1f%%）",
		ok, totalCls, totalM, totalF, before, after, saved, pct(saved, before))
	art.Stat("A1.dex", fmt.Sprint(ok))
	art.Stat("A1.classes", fmt.Sprint(totalCls))
	art.Stat("A1.methods", fmt.Sprint(totalM))
	art.Stat("A1.fields", fmt.Sprint(totalF))
	art.Stat("A1.saved", fmt.Sprint(saved))
	return nil
}

// constClassNames 返回 DEX 中「出现在字符串常量里、且形如类名」的字符串集合。
//
// 用于识别可能被 Class.forName 使用的类名，避免误改。
func constClassNames(f *dex.File) (map[string]bool, error) {
	u, err := f.StringUsage()
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for idx := range u.Const {
		s, err := f.String(idx)
		if err != nil {
			continue
		}
		if looksLikeJavaClass(s) {
			out[s] = true
		}
	}
	return out, nil
}

// looksLikeJavaClass 判断字符串是否形如 Java 类名（点分或斜杠分）。
func looksLikeJavaClass(s string) bool {
	if len(s) < 3 || strings.ContainsAny(s, " \t\n\r") {
		return false
	}
	sep := "."
	if strings.Contains(s, "/") {
		sep = "/"
	}
	segs := strings.Split(s, sep)
	if len(segs) < 2 {
		return false
	}
	for _, seg := range segs {
		if seg == "" {
			return false
		}
		c := seg[0]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || c == '$') {
			return false
		}
	}
	return true
}

// isClassDesc 判断字符串是否为类描述符（L...;）。
func isClassDesc(s string) bool {
	return len(s) > 2 && s[0] == 'L' && s[len(s)-1] == ';' && !strings.Contains(s, "[")
}

// encodeShortName 把序号编码为短名（a、b、…、z、aa、…）。
func encodeShortName(n int) string {
	if n <= 0 {
		return "a"
	}
	var buf []byte
	for n > 0 {
		n--
		buf = append([]byte{'a' + byte(n%26)}, buf...)
		n /= 26
	}
	return string(buf)
}

// splitKeepRules 把多行保留规则拆成切片。
func splitKeepRules(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" {
			continue
		}
		out = append(out, line)
	}
	return out
}

// manifestComponents 从 AndroidManifest.xml 中提取组件类名。
//
// 解析失败（例如样本的畸形 Manifest）时返回空列表，不阻断流程——
// 此时 A1 会退化为「仅依赖内置白名单」，仍然安全（更保守）。
func manifestComponents(art *pipeline.Artifact) []string {
	e := pipeline.Find(art, "AndroidManifest.xml")
	if e == nil {
		return nil
	}
	data, err := e.Data()
	if err != nil {
		return nil
	}
	f, err := axml.Parse(data)
	if err != nil {
		return nil
	}
	return f.ComponentClasses()
}
