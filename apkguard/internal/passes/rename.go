package passes

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"apkguard/internal/arsc"
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

// classPkgOf 返回类描述符所属的「包前缀」，用于给新类名分配前缀。
//
// 返回值一定包含开头的 'L' 与结尾的 '/'（默认包只有 'L'）：
//
//	Lcom/a/B;  ->  Lcom/a/
//	Lkf;       ->  L        ← 默认包
//
// 默认包这一支曾经返回空串，于是生成的新描述符是 "auo;" 这样
// **缺 L** 的非法类型名，数组形式更会变成 "[[auo;"。ART 校验时报
//
//	Invalid type descriptor: '[[auo;'
//
// 并丢弃整个 DEX（表现同样是 ClassNotFoundException）。
// 混淆过的应用（类名常被压成默认包里的 Lkf; 之类）必然踩到，而类都在包内的
// 应用（如 RustDesk）则完全不会——所以这个缺陷藏得很深。
func classPkgOf(desc string) string {
	if i := strings.LastIndex(desc, "/"); i > 0 {
		return desc[:i+1]
	}
	return "L"
}

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
	// 非 DEX 内容里按名字引用的类（布局中的自定义 View、资源字符串、assets 里的
	// 类名等）也必须保留：这些引用是字符串，改类名不会同步改到它们。
	dexFiles := make([]*dex.File, 0, len(units))
	for _, u := range units {
		dexFiles = append(dexFiles, u.file)
	}
	keepClasses = append(keepClasses, passiveClassRefs(art, dexFiles)...)

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
			cands = append(cands, cand{desc: old, pkg: classPkgOf(old)})
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

	// ---- 第二轮前的全局成员名决策 ----
	//
	// 成员改名是按「名称字符串」生效的：同一个名字可能被多个 DEX 交叉引用
	// （Termux 有 30 个 DEX，静态常量 TERMUX_HOME_DIR 正是如此）。若各 DEX
	// 各自决策、各自生成新名，就会出现「定义方改了名、引用方仍是旧名」：
	//   NoSuchFieldError: No field TERMUX_HOME_DIR of type ... in class ...
	// 因此：① 先问每个 DEX 自己愿意改哪些成员名；② 只保留「所有用到它的 DEX
	// 都愿意改」的名称；③ 由一份全局生成器统一命名，保证各 DEX 拿到同一个新名。
	usedNames := map[string]bool{}
	for _, u := range units {
		for i := uint32(0); i < u.file.NType; i++ {
			if t, err := u.file.Type(i); err == nil {
				usedNames[t] = true
			}
		}
	}
	uses := make([]map[string]bool, len(units))
	accept := make([]map[string]bool, len(units))
	for i, u := range units {
		uses[i] = u.file.MemberNameStrings()
		for n := range uses[i] {
			usedNames[n] = true
		}
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
		acc := map[string]bool{}
		for old := range plan {
			// 只取成员名；类描述符与数组描述符交给 ClassMap
			if uses[i][old] && !isClassDesc(old) && !strings.HasPrefix(old, "[") {
				acc[old] = true
			}
		}
		accept[i] = acc
	}

	memberMap := map[string]string{}
	memberKeep := map[string]bool{}
	mseq := 0
	allAccepted := map[string]bool{}
	for _, acc := range accept {
		for n := range acc {
			allAccepted[n] = true
		}
	}
	for name := range allAccepted {
		globally := true
		declined := false
		for i := range units {
			if !uses[i][name] {
				continue
			}
			if !accept[i][name] {
				globally = false
				declined = true
			}
		}
		if !globally {
			// 有 DEX 不同意改名：必须**一致地保留**这个名称。
			// 只把它排除在 MemberMap 之外是不够的——那样同意改名的 DEX 仍会
			// 自行改名，制造出「定义方改了、引用方没改」的不一致。
			if declined {
				memberKeep[name] = true
			}
			continue
		}
		for {
			mseq++
			nw := encodeShortName(mseq)
			if usedNames[nw] {
				continue
			}
			usedNames[nw] = true
			memberMap[name] = nw
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
			MemberMap:        memberMap,
			MemberKeep:       memberKeep,
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
		// 生成新类名是本功能的核心动作，必须立刻确认产物里的类型描述符合法：
		// 默认包类被算错前缀时会产生 "auo;" 这类非法名字，ART 会丢弃整个 DEX。
		if err := dex.ValidateDescriptors(out); err != nil {
			return fmt.Errorf("%s 重命名后描述符非法: %w", u.entry.NameString(), err)
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

// passiveClassRefs 返回「被非 DEX 内容按名字引用」的类（Java 点分名）。
//
// 这些引用是**字符串**，与 DEX 里的类型引用无关，改类名不会同步改到它们：
//
//   - 布局中的自定义 View：`<com.foo.MyView .../>`。改名后布局解析直接失败
//     InflateException: Error inflating class com.foo.MyView
//     （实测 Termux：com.termux.app.terminal.TermuxActivityRootView）
//   - resources.arsc 的字符串、assets 里的配置/清单里的类名同理
//
// 只保留「确实存在对应类」的名字，避免把普通字符串误当成类名而白白削弱混淆。
func passiveClassRefs(art *pipeline.Artifact, files []*dex.File) []string {
	types := map[string]bool{}
	for _, f := range files {
		for i := uint32(0); i < f.NType; i++ {
			if t, err := f.Type(i); err == nil {
				types[t] = true
			}
		}
	}
	found := map[string]bool{}
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || found[s] || !looksLikeJavaClass(s) {
			return
		}
		if types["L"+strings.ReplaceAll(s, ".", "/")+";"] {
			found[s] = true
		}
	}
	for _, e := range art.Entries() {
		if isDexEntry(e) {
			continue
		}
		name := e.NameString()
		data, err := e.Data()
		if err != nil {
			continue
		}
		switch {
		case name == "AndroidManifest.xml":
			if f, err := axml.Parse(data); err == nil {
				for _, s := range f.Strings() {
					add(s)
				}
			}
		case name == "resources.arsc":
			if t, err := arsc.Parse(data); err == nil {
				for _, s := range t.Strings() {
					add(s)
				}
			}
		case strings.HasPrefix(name, "res/") && strings.HasSuffix(strings.ToLower(name), ".xml"):
			if f, err := axml.Parse(data); err == nil {
				for _, s := range f.Strings() {
					add(s)
				}
			}
		case strings.HasPrefix(name, "assets/"):
			for _, tok := range classLikeTokens(data) {
				add(tok)
			}
		}
	}
	out := make([]string, 0, len(found))
	for s := range found {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// classLikeTokens 从任意字节流中抽出「像类名」的 token（用于 assets 等文本内容）。
func classLikeTokens(data []byte) []string {
	const maxLen = 300
	var out []string
	start := -1
	for i := 0; i <= len(data); i++ {
		var c byte
		if i < len(data) {
			c = data[i]
		}
		isName := c == '_' || c == '$' || c == '.' ||
			(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if isName {
			if start < 0 {
				start = i
			}
			if i-start > maxLen {
				start = -1
			}
			continue
		}
		if start >= 0 {
			if s := string(data[start:i]); looksLikeJavaClass(s) {
				out = append(out, s)
			}
			start = -1
		}
	}
	return out
}
