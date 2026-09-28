package dex

import (
	"strings"
	"testing"
)

// TestPadClassNameStrategies 验证三种类名策略的形态。
func TestPadClassNameStrategies(t *testing.T) {
	cp := &ClassPadder{Count: 30, Seed: "pad-1"}
	cls, st, err := ClassPadPlan(cp)
	if err != nil {
		t.Fatalf("生成失败: %v", err)
	}
	if len(cls) != 30 {
		t.Fatalf("应生成 30 个类，实际 %d", len(cls))
	}
	seen := map[string]bool{}
	for _, c := range cls {
		name := c.Spec.Name
		if seen[name] {
			t.Fatalf("类名重复: %s", name)
		}
		seen[name] = true
		if name[0] != 'L' || name[len(name)-1] != ';' {
			t.Fatalf("类名不是合法描述符: %s", name)
		}
		// 每个类都必须是「真实类」：2 个字段 + 6 个方法
		if len(c.Spec.Fields) != 2 {
			t.Fatalf("%s 的字段数应为 2，实际 %d", name, len(c.Spec.Fields))
		}
		if len(c.Spec.Methods) != 6 {
			t.Fatalf("%s 的方法数应为 6，实际 %d", name, len(c.Spec.Methods))
		}
		for _, m := range c.Spec.Methods {
			if m.Code == nil {
				t.Fatalf("%s 的方法 %s 缺少方法体（空类会被识破）", name, m.Name)
			}
		}
	}
	if st.Kinds[PadDefaultPkg] == 0 {
		t.Fatal("未生成默认包类")
	}
	if st.Kinds[PadLongPath] == 0 {
		t.Fatal("未生成超长类名路径")
	}
	// 超长类名必须达到 30 层以上
	longest := 0
	for _, c := range cls {
		if n := strings.Count(c.Spec.Name, "/"); n > longest {
			longest = n
		}
	}
	if longest < padLongDepth {
		t.Fatalf("最长类名路径只有 %d 层，应至少 %d 层", longest, padLongDepth)
	}
	t.Logf("A13：%d 个类，字段 %d、方法 %d，类名合计 %d 字节；最长路径 %d 层；分布 %v",
		len(cls), st.Fields, st.Methods, st.Bytes, longest, st.Kinds)
}

// TestPadClassNameAvoidsExisting 验证生成的名字不与既有类型冲突。
func TestPadClassNameAvoidsExisting(t *testing.T) {
	// 用一个「几乎覆盖全部可能名」的集合仍应能生成（生成器会重试）
	exist := map[string]bool{}
	cls, _, err := ClassPadPlan(&ClassPadder{Count: 5, Seed: "s", Existing: exist})
	if err != nil {
		t.Fatalf("生成失败: %v", err)
	}
	for _, c := range cls {
		if exist[c.Spec.Name] {
			t.Fatalf("与既有类型冲突: %s", c.Spec.Name)
		}
		exist[c.Spec.Name] = true
	}
	// 同一种子必须可复现
	a, _, _ := ClassPadPlan(&ClassPadder{Count: 5, Seed: "s"})
	b, _, _ := ClassPadPlan(&ClassPadder{Count: 5, Seed: "s"})
	if len(a) != len(b) {
		t.Fatal("同种子生成数量不一致")
	}
	for i := range a {
		if a[i].Spec.Name != b[i].Spec.Name {
			t.Fatalf("同种子生成的名字不一致: %s vs %s", a[i].Spec.Name, b[i].Spec.Name)
		}
	}
	// 不同种子应产生不同的名字集合
	c, _, _ := ClassPadPlan(&ClassPadder{Count: 5, Seed: "s2"})
	same := 0
	for i := range a {
		if i < len(c) && a[i].Spec.Name == c[i].Spec.Name {
			same++
		}
	}
	if same == len(a) {
		t.Fatal("不同种子产生了完全相同的类名")
	}
}

// TestRebuildClassPad 端到端验证 A13：DEX 自洽、类体可执行。
func TestRebuildClassPad(t *testing.T) {
	data := sampleDex(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	const n = 12
	padClasses, _, err := ClassPadPlan(&ClassPadder{Count: n, Seed: "e2e"})
	if err != nil {
		t.Fatalf("生成膨胀类失败: %v", err)
	}
	out, st, err := RebuildWithStats(f, RebuildOptions{
		ClassPad: &ClassPadder{Classes: padClasses},
	})
	if err != nil {
		t.Fatalf("类膨胀重建失败: %v", err)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("重建后校验失败: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("重建结果无法解析: %v", err)
	}
	if g.NClass != f.NClass+n {
		t.Fatalf("类数量应为 %d，实际 %d", f.NClass+n, g.NClass)
	}
	if st.ClassesPadded != n {
		t.Fatalf("统计应为 %d，实际 %d", n, st.ClassesPadded)
	}
	// class_idx 不得重复（否则 class_defs 中出现重复定义）
	seen := map[uint32]string{}
	g.Classes(func(_ uint32, cd ClassDef, name string) error {
		if prev, ok := seen[cd.ClassIdx]; ok {
			t.Fatalf("class_idx %d 重复定义: %s 与 %s", cd.ClassIdx, prev, name)
		}
		seen[cd.ClassIdx] = name
		return nil
	})

	// 逐个类验证：a()/b() 读写同一字段、c(n) 循环求和、d() 自增
	checked := 0
	for _, pc := range padClasses {
		desc := pc.Spec.Name
		var found bool
		var getIdx, setIdx, sumIdx, bumpIdx uint32
		var getOff, setOff, sumOff, bumpOff uint32
		g.Classes(func(_ uint32, cd ClassDef, name string) error {
			if name != desc {
				return nil
			}
			pcd, err := g.ParseClassData(cd.ClassDataOff)
			if err != nil {
				t.Fatalf("%s class_data 解析失败: %v", desc, err)
			}
			for _, m := range pcd.DirectMethods {
				d, _ := g.MethodDesc(m.Idx)
				switch {
				case strings.Contains(d, "->c("):
					sumIdx, sumOff = m.Idx, m.CodeOff
				case strings.Contains(d, "->d("):
					bumpIdx, bumpOff = m.Idx, m.CodeOff
				}
			}
			for _, m := range pcd.VirtualMethods {
				d, _ := g.MethodDesc(m.Idx)
				switch {
				case strings.Contains(d, "->a("):
					getIdx, getOff = m.Idx, m.CodeOff
				case strings.Contains(d, "->b("):
					setIdx, setOff = m.Idx, m.CodeOff
				}
			}
			found = true
			return nil
		})
		if !found {
			t.Fatalf("未找到注入的类 %s", desc)
		}

		// b(7) 后 a() 必须返回 7
		obj := &fakeObj{desc: desc}
		if _, err := runPadMethod(g, setIdx, setOff, obj, int32(7)); err != nil {
			t.Fatalf("%s.b(7) 执行失败: %v", desc, err)
		}
		got, err := runPadMethod(g, getIdx, getOff, obj)
		if err != nil {
			t.Fatalf("%s.a() 执行失败: %v", desc, err)
		}
		if got != int32(7) {
			t.Fatalf("%s.a() 应返回 7，实际 %v", desc, got)
		}
		// c(5) 必须返回 0+1+2+3+4 = 10
		sum, err := runPadMethod(g, sumIdx, sumOff, int32(5))
		if err != nil {
			t.Fatalf("%s.c(5) 执行失败: %v", desc, err)
		}
		if sum != int32(10) {
			t.Fatalf("%s.c(5) 应返回 10，实际 %v", desc, sum)
		}
		// d() 使静态字段自增
		key := desc + "->" + padFieldStat
		before := padStatics[key]
		if _, err := runPadMethod(g, bumpIdx, bumpOff); err != nil {
			t.Fatalf("%s.d() 执行失败: %v", desc, err)
		}
		if padStatics[key] != before+1 {
			t.Fatalf("%s.d() 未使静态字段自增：%d -> %d", desc, before, padStatics[key])
		}
		checked++
	}
	t.Logf("A13：注入 %d 个类（字段 %d、方法 %d），类 %d->%d，全部类体可执行",
		n, st.ClassPad.Fields, st.ClassPad.Methods, f.NClass, g.NClass)
	if checked != n {
		t.Fatalf("仅验证了 %d/%d 个类", checked, n)
	}
}

// TestRebuildClassPadNoDuplicateWithExisting 验证与既有类型不冲突。
func TestRebuildClassPadNoDuplicateWithExisting(t *testing.T) {
	data := sampleDex(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	// 把全部既有类型设为「已用」：生成器必须避开它们
	exist := map[string]bool{}
	for i := uint32(0); i < f.NType; i++ {
		d, err := f.Type(i)
		if err != nil {
			continue
		}
		exist[d] = true
	}
	padClasses, _, err := ClassPadPlan(&ClassPadder{Count: 8, Seed: "dup", Existing: exist})
	if err != nil {
		t.Fatalf("生成失败: %v", err)
	}
	for _, pc := range padClasses {
		if exist[pc.Spec.Name] {
			t.Fatalf("膨胀类 %s 与既有类型重名", pc.Spec.Name)
		}
	}
	out, _, err := RebuildWithStats(f, RebuildOptions{ClassPad: &ClassPadder{Classes: padClasses}})
	if err != nil {
		t.Fatalf("重建失败: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("重建结果无法解析: %v", err)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("校验失败: %v", err)
	}
	// 全部类型描述符必须唯一
	seen := map[string]bool{}
	for i := uint32(0); i < g.NType; i++ {
		d, err := g.Type(i)
		if err != nil {
			t.Fatalf("类型 %d 读取失败: %v", i, err)
		}
		if seen[d] {
			t.Fatalf("类型描述符重复: %s", d)
		}
		seen[d] = true
	}
}

// TestRebuildClassPadComposes 验证 A13 与 A2/A3 可同时启用。
func TestRebuildClassPadComposes(t *testing.T) {
	data := sampleDex(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	padClasses, _, err := ClassPadPlan(&ClassPadder{Count: 6, Seed: "mix"})
	if err != nil {
		t.Fatalf("生成失败: %v", err)
	}
	se := &StringEncrypt{
		Class: "Lapkguard/Dec;", MethodName: "a", Key: 0x33,
		MinLen: 4, InjectClass: true,
	}
	ca := &ConstantArray{
		Class: "Lapkguard/Arr;", MethodName: "b", MinLen: 4, InjectClass: true,
	}
	out, st, err := RebuildWithStats(f, RebuildOptions{
		StringEncrypt: se, ConstantArray: ca,
		ClassPad: &ClassPadder{Classes: padClasses},
	})
	if err != nil {
		t.Fatalf("A2+A3+A13 同时启用时重建失败: %v", err)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("重建后校验失败: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("重建结果无法解析: %v", err)
	}
	if g.NClass != f.NClass+2+6 {
		t.Fatalf("应注入 8 个类（解密器 + 还原器 + 6 膨胀）: %d -> %d", f.NClass, g.NClass)
	}
	if st.ClassesPadded != 6 {
		t.Fatalf("膨胀类统计应为 6，实际 %d", st.ClassesPadded)
	}
	// 全部类体必须可解析，指令流必须合法
	n := 0
	err = g.walkAllCode(func(codeOff uint32) error {
		ci, err := g.ParseCodeItem(codeOff)
		if err != nil {
			return err
		}
		if _, err := ParseInsns(ci.Insns); err != nil {
			return err
		}
		n++
		return nil
	})
	if err != nil {
		t.Fatalf("方法体校验失败: %v", err)
	}
	t.Logf("A2+A3+A13 组合：%d 个方法体全部合法，类 %d->%d", n, f.NClass, g.NClass)
}
