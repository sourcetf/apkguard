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

	// -name-prefix 是用户指定的新名前缀。它必须落在合法的 Java 标识符字符集里，
	// 否则生成的类/成员名在 DEX 里非法（ART 会拒绝整个类）。这里统一规范化：
	// 只保留 [A-Za-z0-9_$]，且不让数字开头。
	pfx := sanitizeNamePrefix(opts.NamePrefix)
	if opts.NamePrefix != "" && pfx != opts.NamePrefix {
		art.Note("A1 名称前缀 %q 含非法字符，已规范化为 %q", opts.NamePrefix, pfx)
	}

	// 2) 逐 DEX 决策哪些类可改，并按需分配新名
	type cand struct {
		desc string
		pkg  string
	}
	var cands []cand
	seen := map[string]bool{}
	// existingPkgs 记录全部 DEX 中已存在的包前缀，供包压缩时避让；
	// keptPkgs 记录「含有保留类」的包——这些包不能压缩（见下）。
	existingPkgs := map[string]bool{}
	keptPkgs := map[string]bool{}
	// 先登记全部 DEX 中已存在的类描述符，避免新名与「未参与重命名的类」碰撞
	for _, u := range units {
		for i := uint32(0); i < u.file.NType; i++ {
			d, err := u.file.Type(i)
			if err != nil {
				continue
			}
			used[d] = true
			if isClassDesc(d) {
				existingPkgs[classPkgOf(d)] = true
			}
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
		// 未出现在 plan 里的类定义就是「被保留的类」（内部类、入口类、反射类…）。
		// 它们留在原包，因此其所在包必须整体保留包名：把可改名类搬离该包会切断
		// package-private 访问，运行时报
		//   IllegalAccessError: Illegal class access: 'ac' attempting to access
		//   'com.termux.app.utils.CrashUtils$1'
		// （实测于 Termux：$ 内部类因「内外层命名强耦合」被保留，而普通类被压到默认包。）
		if err := u.file.Classes(func(_ uint32, _ dex.ClassDef, name string) error {
			if !isClassDesc(name) {
				return nil
			}
			if _, renamed := plan[name]; !renamed {
				keptPkgs[classPkgOf(name)] = true
			}
			return nil
		}); err != nil {
			return fmt.Errorf("%s 枚举类定义失败: %w", u.entry.NameString(), err)
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

	// 3) 统一分配新名：同一包内的类共享新名序号空间，避免冲突。
	//
	// -package-shrink 把「每个原包」整体映射到一个无意义短包名（Lpa/、Lpb/…）：
	//   - 原来同包的类压缩后仍然同包，package-private 访问不被切断；
	//   - 包名不再泄露模块划分，达到参考样本「类名里读不出结构」的效果。
	// 不用「统一压成默认包」那种做法：它会把所有类丢进同一个包，看似更彻底，
	// 却会让 package-private 跨包化——那正是 Termux 上的 IllegalAccessError。
	// 含保留类的包整体保持原包名（提前让开后由 used 保证不碰撞）。
	pkgAlias := map[string]string{}
	if opts.PackageShrink {
		var pkgs []string
		assigned := map[string]bool{}
		for _, c := range cands {
			if keptPkgs[c.pkg] || assigned[c.pkg] {
				continue
			}
			assigned[c.pkg] = true
			pkgs = append(pkgs, c.pkg)
		}
		sort.Strings(pkgs)
		for i, p := range pkgs {
			alias := "L" + pfx + "p" + encodeShortName(i+1) + "/"
			// 短包名不得与任何现存包（含保留类所在的包）重名。
			for existingPkgs[alias] {
				i++
				alias = "L" + pfx + "p" + encodeShortName(i+1) + "/"
			}
			pkgAlias[p] = alias
			existingPkgs[alias] = true
		}
	}
	for _, c := range cands {
		for {
			seq++
			pkg := c.pkg
			if opts.PackageShrink {
				if a := pkgAlias[c.pkg]; a != "" {
					pkg = a
				}
			}
			desc := pkg + pfx + encodeShortName(seq) + ";"
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
	// **必须按名称排序后再分配序号**：allAccepted 是 map，Go 的 map 迭代顺序
	// 是随机的，直接 range 会让同一个成员名在两次运行里拿到不同的短名，
	// 产物 sha256 随之漂移——「同 -seed 可复现」的承诺就此失效。
	acceptedNames := make([]string, 0, len(allAccepted))
	for n := range allAccepted {
		acceptedNames = append(acceptedNames, n)
	}
	sort.Strings(acceptedNames)
	for _, name := range acceptedNames {
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
			nw := pfx + encodeShortName(mseq)
			if usedNames[nw] {
				continue
			}
			usedNames[nw] = true
			memberMap[name] = nw
			break
		}
	}

	// ---- 第二轮半：成员名「按 (类, 名字) 引用」覆盖（Phase 1）----
	//
	// 第二轮按「名称字符串」全局决策：只要有一个引用者不同意改名，整个名字保留。
	// 但私有/静态成员不参与虚派发，改名只需重写它们各自的 method_id/field_id，
	// 旧名字字符串原样留给其它引用即可。于是那些「恰好与框架方法同名」的业务
	// 私有/静态成员也能被改掉——这正是当前字段改名为 0、方法几乎不动的原因。
	//
	// 与值键路径互斥：memberMap 里的名字交给值键路径（它会改写所有同名引用），
	// 这里用 ExcludeNames 排除，避免同一定义被两条通道改成两个名字。
	excludeNames := make(map[string]bool, len(memberMap))
	reservedNames := make(map[string]bool, len(memberMap))
	for n, v := range memberMap {
		excludeNames[n] = true
		reservedNames[v] = true
	}
	// 布局 android:onClick / android:onLongClick 的属性值是**方法名**，由框架反射
	// 调用，DEX 里没有对应字符串常量（除非也被 const-string 引用）。静态回调方法
	// 若被改名会直接崩，必须按名字保留。
	passiveMethods := passiveMethodRefs(art)

	// 成员覆盖改名的规划。
	//
	// 这里曾经有一条「池已达 16 位上限就整体跳过」的降级分支：追加字符串会把
	// 字符串池推过 65535，而 const-string 的索引只有 16 位，越界时重建直接失败
	// （实测 Termux 的 classes.dex 有 65866 个字符串）。**该降级已移除**——
	// dex 层现在会把越界的 const-string 自动加宽成 const-string/jumbo
	// （见 internal/dex/widen.go），于是追加字符串不再有 16 位越界风险。
	memberRes, err := dex.PlanMemberRenames(dexFiles, dex.MemberRenameConfig{
		ClassMap:     classMap,
		NameKeep:     passiveMethods,
		Keep:         keep,
		ExcludeNames: excludeNames,
		Reserved:     reservedNames,
	})
	if err != nil {
		return fmt.Errorf("成员覆盖改名规划失败: %w", err)
	}

	// ---- 第二轮：各 DEX 应用重命名 ----
	totalCls, totalM, totalF := 0, 0, 0
	ok := 0
	before, after := 0, 0
	byIDMethods, byIDFields := 0, 0
	for ui, u := range units {
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
		var mByID, fByID map[uint32]string
		if memberRes != nil {
			mByID = memberRes.MethodByID[ui]
			fByID = memberRes.FieldByID[ui]
		}
		// 值键计划与按条目覆盖都可能为空：两者同时为空才跳过重建。
		if len(plan) == 0 && len(mByID) == 0 && len(fByID) == 0 {
			continue
		}
		st := rn.LastStats()
		out, err := dex.Rebuild(u.file, dex.RebuildOptions{
			Rename:         plan,
			MethodNameByID: mByID,
			FieldNameByID:  fByID,
		})
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
		byIDMethods += len(mByID)
		byIDFields += len(fByID)
		before += len(u.data)
		after += len(out)
		ok++
	}

	if ok == 0 {
		art.Note("A1 名字混淆：没有可安全重命名的类（全部命中保留规则）")
		return nil
	}
	saved := before - after
	// totalM/totalF 里既包含值键路径按「名字」计的改名，也包含按条目覆盖路径
	// 按「引用」计的改名；后者是本次覆盖率提升的主要来源。
	totalM += byIDMethods
	totalF += byIDFields
	art.Note("A1 名字混淆：%d 个 DEX，重命名类 %d、方法 %d、字段 %d；%d → %d 字节（减少 %d，%.1f%%）",
		ok, totalCls, totalM, totalF, before, after, saved, pct(saved, before))
	art.Stat("A1.dex", fmt.Sprint(ok))
	art.Stat("A1.classes", fmt.Sprint(totalCls))
	art.Stat("A1.methods", fmt.Sprint(totalM))
	art.Stat("A1.fields", fmt.Sprint(totalF))
	art.Stat("A1.methods_byid", fmt.Sprint(byIDMethods))
	art.Stat("A1.fields_byid", fmt.Sprint(byIDFields))
	if memberRes != nil {
		art.Stat("A1.member_defs", fmt.Sprint(memberRes.Methods+memberRes.Fields))
	}
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

// sanitizeNamePrefix 把用户给的名称前缀规范成合法的 Java 标识符前缀。
//
// 只保留 [A-Za-z0-9_$]；首位不允许是数字；首字符 '$' 虽合法但容易被
// 反编译器当成合成名，保留用户原意不改。全部被滤掉时返回空串（等于不加前缀）。
func sanitizeNamePrefix(p string) string {
	var b []byte
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c == '_' || c == '$',
			c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z':
			b = append(b, c)
		case c >= '0' && c <= '9' && len(b) > 0:
			b = append(b, c)
		}
	}
	return string(b)
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

// manifestComponents 从 AndroidManifest.xml 中提取组件类名（Java 点分名）。
//
// 解析失败（例如样本的畸形 Manifest）时返回空列表，不阻断流程——
// 此时 A1 会退化为「仅依赖内置白名单」，仍然安全（更保守）。
//
// **必须把相对名按 manifest 的 package 归一化**：Android 允许组件名写成
// ".MainActivity"（相对 package）甚至 "MainActivity"（不带点，同样相对），
// 运行时由 PackageParser.buildClassName 补全。下游（internal/dex 的重命名器）
// 用 `"L" + strings.ReplaceAll(n, ".", "/") + ";"` 把返回的名字转成描述符，
// 若这里原样返回 ".MainActivity"，会得到与真实类不匹配的 "L/MainActivity;"，
// 组件类因此进不了保留集、被 A1 改名，应用启动即 ClassNotFoundException。
//
// 除各组件元素的 android:name 外，activity-alias 的 android:targetActivity
// 也是组件类名（别名真正指向的 Activity），同样必须保留。
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

	pkg := ""
	if m := f.FindElement("manifest"); m != nil {
		pkg = strings.TrimSpace(m.AttrString("package"))
	}

	seen := map[string]bool{}
	var out []string
	add := func(name string) {
		n := resolveComponentName(pkg, name)
		if n == "" || seen[n] {
			return
		}
		seen[n] = true
		out = append(out, n)
	}
	// android:name 覆盖 application 与 activity/service/receiver/provider 等。
	for _, n := range f.ComponentClasses() {
		add(n)
	}
	// targetActivity 只出现在 <activity-alias> 上，且不在 ComponentClasses 的覆盖内。
	for _, el := range f.Elements {
		if el.Name != "activity-alias" {
			continue
		}
		if a := el.Attr("targetActivity"); a != nil {
			add(a.RawValue)
		}
	}
	sort.Strings(out)
	return out
}

// resolveComponentName 把 Manifest 中声明的组件名解析为完整 Java 类名。
//
// 语义与 AOSP 的 PackageParser.buildClassName 一致：
//   - ".X"   -> pkg + ".X"
//   - "X"    -> pkg + "." + X（不含点即视为相对名）
//   - "a.b.C" -> 原样（绝对名）
//
// pkg 为空（Manifest 没有 package 属性）时相对名无法补全，返回空串由调用方丢弃；
// 此时保留集会退化为「仅内置白名单」，仍比保留一个匹配不上任何类的错误名字更安全。
func resolveComponentName(pkg, name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	if strings.HasPrefix(name, ".") {
		if pkg == "" {
			return ""
		}
		return pkg + name
	}
	if !strings.Contains(name, ".") {
		if pkg == "" {
			return ""
		}
		return pkg + "." + name
	}
	return name
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
		case strings.HasPrefix(name, "META-INF/services/"):
			// ServiceLoader 的两半都要保住，缺一半都会让运行时加载不到实现：
			//   - 文件**名**是服务接口的类名（ServiceLoader.load(X.class) 会查
			//     META-INF/services/<X 的运行时类名>），改了接口名就找不到文件；
			//   - 文件**内容**是各提供者的类名，改了提供者名就实例化不出来。
			// 这两处引用都只存在于资源里，DEX 中没有对应字符串常量，因此
			// reflectedClasses 看不见它们。实测 RustDesk 1.5.0（R8 混淆过的
			// 文件名 j3.t / 内容 f3.a，即 kotlinx 的 MainDispatcherFactory 与
			// AndroidDispatcherFactory）：改任意一半都会在 UI 首次 attach 时抛
			//   IllegalStateException: Module with the Main dispatcher is missing.
			// 文件格式：每行一个全限定类名，'#' 起注释。
			add(strings.TrimPrefix(name, "META-INF/services/"))
			for _, line := range strings.Split(string(data), "\n") {
				if i := strings.IndexByte(line, '#'); i >= 0 {
					line = line[:i]
				}
				add(line)
			}
		case strings.HasPrefix(name, "res/"):
			// res/ 下的非 XML 资源（如 res/raw/*.json、*.txt）同样可能按名字引用类。
			for _, tok := range classLikeTokens(data) {
				add(tok)
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

// passiveMethodRefs 返回「被非 DEX 内容按名字引用的方法名」。
//
// 目前只覆盖确定性最高、漏掉必崩的一类：布局 XML 的
// `android:onClick` / `android:onLongClick`。它们的属性值就是**方法名**，
// 由框架反射调用；方法既可能是实例方法，也可能是**静态方法**（后者正是
// 本方案会改的对象），而 DEX 中通常没有对应字符串常量，扫描不到。
//
// 属性值形如 `@{...}` 的数据绑定表达式不是方法名，跳过。
func passiveMethodRefs(art *pipeline.Artifact) map[string]bool {
	out := map[string]bool{}
	for _, e := range art.Entries() {
		name := e.NameString()
		if isDexEntry(e) {
			continue
		}
		isXML := name == "AndroidManifest.xml" ||
			(strings.HasPrefix(name, "res/") && strings.HasSuffix(strings.ToLower(name), ".xml"))
		if !isXML {
			continue
		}
		data, err := e.Data()
		if err != nil {
			continue
		}
		f, err := axml.Parse(data)
		if err != nil {
			continue
		}
		for _, el := range f.Elements {
			for i := range el.Attrs {
				a := &el.Attrs[i]
				switch a.Name {
				case "onClick", "onLongClick":
					if v := strings.TrimSpace(a.RawValue); looksLikeMemberIdentifier(v) {
						out[v] = true
					}
				}
			}
		}
	}
	return out
}

// looksLikeMemberIdentifier 判断 s 是否为单个 Java 标识符（不含点/空格/@ 等）。
func looksLikeMemberIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c == '_' || c == '$' ||
			(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(i > 0 && c >= '0' && c <= '9')
		if !ok {
			return false
		}
	}
	return true
}
