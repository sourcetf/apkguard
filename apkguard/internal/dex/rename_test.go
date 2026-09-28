package dex

import (
	"strings"
	"testing"
)

// TestStringUsage 验证字符串用途扫描能识别类型、方法名、字段名与常量。
func TestStringUsage(t *testing.T) {
	data := sampleDex(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	u, err := f.StringUsage()
	if err != nil {
		t.Fatalf("扫描字符串用途失败: %v", err)
	}
	// 每个类型描述符都应被标记为 Type
	nType := 0
	for i := uint32(0); i < f.NType; i++ {
		idx := typeNameIdx(f, i)
		if !u.Type[idx] {
			t.Fatalf("类型字符串 %d 未被标记", idx)
		}
		nType++
	}
	if nType != int(f.NType) {
		t.Fatalf("类型数量不符: %d != %d", nType, f.NType)
	}
	if len(u.MethodName) == 0 || len(u.FieldName) == 0 {
		t.Fatal("方法名/字段名集合为空")
	}
	if len(u.Const) == 0 {
		t.Fatal("未发现任何 const-string 引用")
	}
	t.Logf("用途统计：类型=%d 方法名=%d 字段名=%d 常量=%d 注解=%d",
		len(u.Type), len(u.MethodName), len(u.FieldName), len(u.Const), len(u.Anno))
}

// TestClassInfos 验证类信息解析覆盖全部类且成员可读。
func TestClassInfos(t *testing.T) {
	data := sampleDex(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	infos, err := f.ClassInfos()
	if err != nil {
		t.Fatalf("读取类信息失败: %v", err)
	}
	if len(infos) != int(f.NClass) {
		t.Fatalf("类数量不符: %d != %d", len(infos), f.NClass)
	}
	nMethod, nField := 0, 0
	withSuper := 0
	for _, ci := range infos {
		if ci.Desc == "" {
			t.Fatal("存在空类描述符")
		}
		if ci.Super != "" {
			withSuper++
		}
		nMethod += len(ci.Methods())
		nField += len(ci.Fields())
		for _, m := range ci.Methods() {
			if m.Name == "" || m.Proto == "" {
				t.Fatalf("类 %s 存在不完整的方法信息", ci.Desc)
			}
		}
	}
	if withSuper == 0 {
		t.Fatal("没有任何类解析出父类")
	}
	t.Logf("解析 %d 个类：方法定义 %d 个、字段定义 %d 个", len(infos), nMethod, nField)
}

// TestRenamerPlan 验证重命名计划的完整性与安全性约束。
func TestRenamerPlan(t *testing.T) {
	data := sampleDex(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	infos, err := f.ClassInfos()
	if err != nil {
		t.Fatalf("读取类信息失败: %v", err)
	}

	rn, err := NewRenamer(f, RenameConfig{Keep: []string{"com.example.KeepMe"}})
	if err != nil {
		t.Fatalf("构造重命名器失败: %v", err)
	}
	plan, err := rn.Plan()
	if err != nil {
		t.Fatalf("生成重命名计划失败: %v", err)
	}
	if len(plan) == 0 {
		t.Fatal("重命名计划为空")
	}
	st := rn.LastStats()
	t.Logf("重命名计划：类 %d、方法名 %d、字段名 %d；保留类 %d 个（%v）",
		st.Classes, st.Methods, st.Fields, st.KeptCls, st.KeepReasons)

	// 关键约束 1：平台/框架类绝不能被改名
	for _, ci := range infos {
		if !hasAnyPrefix(ci.Desc, javaPrefixes) {
			continue
		}
		if nw, ok := plan[ci.Desc]; ok {
			t.Fatalf("平台/框架类被改名: %s -> %s", ci.Desc, nw)
		}
	}
	// 关键约束 2：Android 组件类绝不能被改名
	for _, ci := range infos {
		if !isEntryPoint(&ci) {
			continue
		}
		if nw, ok := plan[ci.Desc]; ok {
			t.Fatalf("Android 组件类被改名: %s -> %s", ci.Desc, nw)
		}
	}
	// 关键约束 3：重命名结果必须唯一
	seen := map[string]string{}
	for old, nw := range plan {
		if prev, ok := seen[nw]; ok {
			t.Fatalf("重命名结果重复: %q 与 %q 都变为 %q", prev, old, nw)
		}
		seen[nw] = old
	}
	// 关键约束 4：新类名不得与任何既有类描述符相同
	existingCls := map[string]bool{}
	for _, ci := range infos {
		existingCls[ci.Desc] = true
	}
	for old, nw := range plan {
		if !strings.HasPrefix(nw, "L") || !strings.HasSuffix(nw, ";") {
			continue // 方法名/字段名不参与本项检查
		}
		if existingCls[nw] && nw != old {
			t.Fatalf("新类名 %q 与既有类冲突（来自 %q）", nw, old)
		}
	}
	// 关键约束 5：新方法名不得与任何既有方法名相同
	existingMethod := map[string]bool{}
	for _, ci := range infos {
		for _, m := range ci.Methods() {
			existingMethod[m.Name] = true
		}
	}
	for old, nw := range plan {
		if strings.HasPrefix(nw, "L") && strings.HasSuffix(nw, ";") {
			continue
		}
		if existingMethod[nw] && nw != old {
			t.Fatalf("新方法名 %q 与既有方法名冲突（来自 %q）", nw, old)
		}
	}
}

// TestRenamerRebuild 验证重命名计划应用到重建后 DEX 仍然自洽可解析。
//
// 这是 A1 的端到端测试：计划 → 重建 → 校验 → 重新解析 → 名称核对。
func TestRenamerRebuild(t *testing.T) {
	data := sampleDex(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	rn, err := NewRenamer(f, RenameConfig{})
	if err != nil {
		t.Fatalf("构造重命名器失败: %v", err)
	}
	plan, err := rn.Plan()
	if err != nil {
		t.Fatalf("生成重命名计划失败: %v", err)
	}
	st := rn.LastStats()

	out, err := Rebuild(f, RebuildOptions{Rename: plan})
	if err != nil {
		t.Fatalf("重命名重建失败: %v", err)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("重建后校验失败: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("重建结果无法解析: %v", err)
	}
	// 索引表条目数必须不变（重命名不增删类型/原型/字段/方法/类）
	if g.NType != f.NType || g.NProto != f.NProto ||
		g.NField != f.NField || g.NMethod != f.NMethod || g.NClass != f.NClass {
		t.Fatalf("条目数量变化: 原(%d,%d,%d,%d) 新(%d,%d,%d,%d)",
			f.NType, f.NProto, f.NField, f.NMethod,
			g.NType, g.NProto, g.NField, g.NMethod)
	}
	// 字符串池只可能因「多个旧字符串被重命名为同一新值」而收缩，不会增长
	if g.NString > f.NString {
		t.Fatalf("字符串池不应增长: %d -> %d", f.NString, g.NString)
	}
	// 未参与重命名的字符串必须原样保留
	pool := map[string]bool{}
	for i := uint32(0); i < g.NString; i++ {
		s, _ := g.String(i)
		pool[s] = true
	}
	for i := uint32(0); i < f.NString; i++ {
		s, _ := f.String(i)
		if _, renamed := plan[s]; renamed {
			continue
		}
		if !pool[s] {
			t.Fatalf("未参与重命名的字符串 %q 在结果中丢失", s)
		}
	}
	// 字符串池必须保持 UTF-16 升序
	prev := ""
	for i := uint32(0); i < g.NString; i++ {
		s, _ := g.String(i)
		if i > 0 && CompareUTF16(prev, s) >= 0 {
			t.Fatalf("字符串池顺序错误 @%d: %q >= %q", i, prev, s)
		}
		prev = s
	}
	// 重命名后的类必须存在，未在计划中的类必须保持原名
	renamed := 0
	for i := uint32(0); i < g.NClass; i++ {
		old, _ := f.ClassName(i)
		nw, _ := g.ClassName(i)
		if want, ok := plan[old]; ok {
			if nw != want {
				t.Fatalf("类 %d 重命名不符: %q -> %q（期望 %q）", i, old, nw, want)
			}
			renamed++
			continue
		}
		if nw != old {
			t.Fatalf("类 %d 不应被改名: %q -> %q", i, old, nw)
		}
	}
	if renamed != st.Classes {
		t.Fatalf("实际改名的类数 %d 与统计 %d 不符", renamed, st.Classes)
	}
	// 所有方法体必须仍然完整可读
	nMethod := 0
	for i := uint32(0); i < g.NClass; i++ {
		cd, err := g.ClassDefAt(i)
		if err != nil {
			t.Fatalf("读取类定义失败: %v", err)
		}
		if cd.ClassDataOff == 0 {
			continue
		}
		pcd, err := g.ParseClassData(cd.ClassDataOff)
		if err != nil {
			t.Fatalf("解析 class_data 失败: %v", err)
		}
		for _, m := range append(append([]EncodedMethod{}, pcd.DirectMethods...), pcd.VirtualMethods...) {
			if m.CodeOff == 0 {
				continue
			}
			ci, err := g.CodeInsns(m.CodeOff)
			if err != nil {
				t.Fatalf("读取方法体失败: %v", err)
			}
			if ci.InsnsSize == 0 {
				t.Fatalf("方法体为空 @%d", m.CodeOff)
			}
			nMethod++
		}
	}
	t.Logf("重命名重建成功：类 %d 个（改名 %d）、方法体 %d 个、输出 %d 字节（原 %d）",
		g.NClass, renamed, nMethod, len(out), len(data))
}

// TestRenamerKeepRules 验证保留规则的各种写法。
func TestRenamerKeepRules(t *testing.T) {
	data := sampleDex(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	infos, err := f.ClassInfos()
	if err != nil {
		t.Fatalf("读取类信息失败: %v", err)
	}
	// 找一个业务包名（非平台前缀、非组件类），用它的包名构造保留规则
	pkg := ""
	for _, ci := range infos {
		if hasAnyPrefix(ci.Desc, javaPrefixes) || isEntryPoint(&ci) || strings.Contains(ci.Desc, "$") {
			continue
		}
		j := descToJava(ci.Desc)
		if k := strings.LastIndex(j, "."); k > 0 {
			pkg = j[:k]
			break
		}
	}
	if pkg == "" {
		t.Skip("样本中没有可用于测试的包名")
	}

	rn, err := NewRenamer(f, RenameConfig{Keep: []string{pkg + ".**"}})
	if err != nil {
		t.Fatalf("构造重命名器失败: %v", err)
	}
	plan, err := rn.Plan()
	if err != nil {
		t.Fatalf("生成重命名计划失败: %v", err)
	}
	for _, ci := range infos {
		if !strings.HasPrefix(descToJava(ci.Desc), pkg+".") {
			continue
		}
		if _, ok := plan[ci.Desc]; ok {
			t.Fatalf("保留规则 %s.** 未生效，类 %s 仍被改名", pkg, ci.Desc)
		}
	}
	t.Logf("保留规则 %s.** 生效，重命名计划共 %d 项", pkg, len(plan))
}

// TestEncodeName 验证名称生成序列。
func TestEncodeName(t *testing.T) {
	cases := []struct {
		n    int
		want string
	}{
		{1, "a"}, {2, "b"}, {26, "z"}, {27, "aa"}, {28, "ab"}, {52, "az"},
		{53, "ba"}, {702, "zz"}, {703, "aaa"},
	}
	for _, c := range cases {
		if got := encodeName(c.n, "a"); got != c.want {
			t.Errorf("encodeName(%d) = %q，期望 %q", c.n, got, c.want)
		}
	}
	// 序号必须两两不同
	seen := map[string]int{}
	for i := 1; i <= 3000; i++ {
		n := encodeName(i, "a")
		if prev, ok := seen[n]; ok {
			t.Fatalf("encodeName 冲突：%d 与 %d 都生成 %q", prev, i, n)
		}
		seen[n] = i
	}
}

// TestMatchKeepRule 验证保留规则匹配。
func TestMatchKeepRule(t *testing.T) {
	cases := []struct {
		rule string
		name string
		want bool
	}{
		{"com.foo.Bar", "com.foo.Bar", true},
		{"com.foo.Bar", "com.foo.Baz", false},
		{"com.foo.**", "com.foo.Bar", true},
		{"com.foo.**", "com.foo.sub.Bar", true},
		{"com.foo.**", "com.bar.Baz", false},
		{"com.foo.*", "com.foo.Bar", true},
		{"com.foo.*", "com.foo.sub.Bar", false},
		{"*.Bar", "com.any.Bar", true},
		{"*.Bar", "com.any.Bar$Inner", false},
		{"com.*.Bar", "com.foo.Bar", true},
		{"com.*.Bar", "com.foo.Baz", false},
	}
	for _, c := range cases {
		if got := matchKeepRule(c.rule, c.name, "L"+strings.ReplaceAll(c.name, ".", "/")+";"); got != c.want {
			t.Errorf("matchKeepRule(%q, %q) = %v，期望 %v", c.rule, c.name, got, c.want)
		}
	}
}
