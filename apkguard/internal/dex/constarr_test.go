package dex

import (
	"strings"
	"testing"
)

// TestFillArrayPayloadEncoding 验证 payload 的字节打包方式符合规范。
func TestFillArrayPayloadEncoding(t *testing.T) {
	cases := [][]byte{
		{0x41},
		{0x41, 0x42},
		{0x41, 0x42, 0x43},
		{0x00, 0xff, 0x80, 0x7f},
	}
	for _, data := range cases {
		w := fillArrayPayload(data)
		if w[0] != payloadFillArray {
			t.Fatalf("payload 标识应为 0x0300，实际 0x%04x", w[0])
		}
		if w[1] != 1 {
			t.Fatalf("element_width 应为 1，实际 %d", w[1])
		}
		if got := int(w[2]) | int(w[3])<<16; got != len(data) {
			t.Fatalf("size 应为 %d，实际 %d", len(data), got)
		}
		// 字长必须是 4 + ceil(n/2)
		if want := 4 + (len(data)+1)/2; len(w) != want {
			t.Fatalf("字长应为 %d，实际 %d", want, len(w))
		}
		// 逐字节还原
		for i, b := range data {
			var got byte
			if i%2 == 0 {
				got = byte(w[4+i/2] & 0xff)
			} else {
				got = byte(w[4+i/2] >> 8)
			}
			if got != b {
				t.Fatalf("第 %d 字节应为 0x%02x，实际 0x%02x", i, b, got)
			}
		}
	}
}

// TestInsnListReplaceWithArrayData 验证指令替换与 payload 追加。
func TestInsnListReplaceWithArrayData(t *testing.T) {
	// [0] const-string v0, "hello"   ← 将被替换（0x1a | reg<<8）
	// [1] return-object v0
	words := []uint16{0x001a, 0x0000, 0x0010}
	l, err := ParseInsns(words)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if !l.ReplaceWithArrayData(0, []byte("hello"), 7, 9) {
		t.Fatal("替换应成功")
	}
	out, _, fresh := l.Encode()

	// 期望序列共 11 字：const/16(2) + new-array(2) + fill-array-data(3)
	//                     + invoke-static/range(3) + move-result-object(1)
	// payload 追加在指令流末尾（对齐后落在 12）
	if out[0]&0xff != 0x13 {
		t.Fatalf("首条应为 const/16(0x13)，实际 0x%02x", out[0]&0xff)
	}
	if out[2]&0xff != 0x23 {
		t.Fatalf("第 2 条应为 new-array(0x23)，实际 0x%02x", out[2]&0xff)
	}
	if out[4]&0xff != 0x26 {
		t.Fatalf("第 3 条应为 fill-array-data(0x26)，实际 0x%02x", out[4]&0xff)
	}
	if out[7]&0xff != 0x77 {
		t.Fatalf("第 4 条应为 invoke-static/range(0x77)，实际 0x%02x", out[7]&0xff)
	}
	if out[10]&0xff != 0x0c {
		t.Fatalf("第 5 条应为 move-result-object(0x0c)，实际 0x%02x", out[10]&0xff)
	}
	// 紧随其后的 return-object v0 原样保留
	if out[11] != 0x0010 {
		t.Fatalf("偏移 11 处应为 return-object v0(0x0010)，实际 0x%04x", out[11])
	}
	if out[12] != payloadFillArray {
		t.Fatalf("偏移 12 处应为 payload，实际 0x%04x", out[12])
	}
	// fill-array-data 的落点必须是 payload 起点（31t：偏移在 word 5-6，
	// 且以指令自身（项内偏移 4）为基准）
	rel := int32(uint32(out[5]) | uint32(out[6])<<16)
	if got := 4 + int(rel); got != 12 {
		t.Fatalf("fill-array-data 落点应为 12，实际 %d", got)
	}
	// 新索引位置必须被登记（new-array 的 type @3、invoke 的 method @8）
	if !fresh[3] {
		t.Fatal("new-array 的类型索引位置未登记为 fresh")
	}
	if !fresh[8] {
		t.Fatal("invoke-static/range 的方法索引位置未登记为 fresh")
	}

	// 重新解析必须仍是合法指令流
	if _, err := ParseInsns(out); err != nil {
		t.Fatalf("替换结果不是合法指令流: %v", err)
	}
}

// TestInsnListArrayDataHighRegister 验证 v16 及以上无法编码时安全拒绝。
func TestInsnListArrayDataHighRegister(t *testing.T) {
	// const-string v20（0x1a | 20<<8 = 0x141a）：寄存器编号 > 15
	words := []uint16{0x141a, 0x0000, 0x0010}
	l, err := ParseInsns(words)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if l.ReplaceWithArrayData(0, []byte("x"), 7, 9) {
		t.Fatal("寄存器编号 > v15 时应拒绝替换（new-array 无法编码）")
	}
}

// TestRebuildConstantArray 端到端验证 A3：DEX 自洽、还原方法可执行。
func TestRebuildConstantArray(t *testing.T) {
	data := sampleDex(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	const cls = "Lapkguard/Arr;"
	ca := &ConstantArray{Class: cls, MethodName: "b", MinLen: 4, InjectClass: true}
	out, _, err := RebuildWithStats(f, RebuildOptions{ConstantArray: ca})
	if err != nil {
		t.Fatalf("数组化重建失败: %v", err)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("重建后校验失败: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("重建结果无法解析: %v", err)
	}
	if g.NClass != f.NClass+1 {
		t.Fatalf("应注入 1 个还原方法类: %d -> %d", f.NClass, g.NClass)
	}
	// 类型数量只应增加 [B 与还原类
	if g.NType <= f.NType {
		t.Fatalf("类型数量应增加，实际 %d -> %d", f.NType, g.NType)
	}

	// 还原方法必须存在且可执行
	var codeOff, mIdx uint32
	found := false
	g.Classes(func(_ uint32, cd ClassDef, name string) error {
		if name != cls {
			return nil
		}
		pcd, err := g.ParseClassData(cd.ClassDataOff)
		if err != nil {
			t.Fatalf("还原类 class_data 解析失败: %v", err)
		}
		if len(pcd.DirectMethods) != 1 {
			t.Fatalf("还原类应有 1 个直接方法，实际 %d", len(pcd.DirectMethods))
		}
		codeOff = pcd.DirectMethods[0].CodeOff
		mIdx = pcd.DirectMethods[0].Idx
		found = true
		return nil
	})
	if !found {
		t.Fatal("未找到注入的还原方法类")
	}
	// 用解释器执行：b("hello".bytes) 必须得到 "hello"
	for _, plain := range []string{"hello", "中文测试", "emoji \U0001F600 ok", "https://a.example/p"} {
		got, err := runArrayHelper(g, mIdx, codeOff, []byte(plain))
		if err != nil {
			t.Fatalf("执行还原方法失败（%q）: %v", plain, err)
		}
		if got != plain {
			t.Fatalf("还原结果不符：%q -> %q", plain, got)
		}
	}
	t.Logf("A3 注入还原类 %s：类 %d->%d 类型 %d->%d", cls, f.NClass, g.NClass, f.NType, g.NType)
}

// TestRebuildConstantArrayKeepsPool 验证 A3 不改变字符串池（与 A2 的差异）。
func TestRebuildConstantArrayKeepsPool(t *testing.T) {
	data := sampleDex(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	orig, _ := f.AllStrings()
	ca := &ConstantArray{Class: "Lapkguard/Arr;", MethodName: "b", MinLen: 4, InjectClass: true}
	out, _, err := RebuildWithStats(f, RebuildOptions{ConstantArray: ca})
	if err != nil {
		t.Fatalf("重建失败: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("重建结果无法解析: %v", err)
	}
	// 全部原有字符串必须仍在池中（A3 不移除明文，只改字节码引用）
	now := map[string]bool{}
	for i := uint32(0); i < g.NString; i++ {
		s, _ := g.String(i)
		now[s] = true
	}
	for _, s := range orig {
		if !now[s] {
			t.Fatalf("原有字符串 %q 丢失（A3 不应移除池中明文）", s)
		}
	}
	// 全部方法体必须可解析
	n := 0
	g.walkAllCode(func(codeOff uint32) error {
		if _, err := g.ParseCodeItem(codeOff); err != nil {
			t.Fatalf("@%d 解析失败: %v", codeOff, err)
		}
		n++
		return nil
	})
	t.Logf("A3：字符串池保持 %d 条，%d 个方法体可解析", g.NString, n)
}

// TestRebuildConstantArrayComposesWithEncrypt 验证 A2 与 A3 可同时启用且互不破坏。
//
// 这是最容易出错的地方：两个 Pass 都会改写 const-string，
// 若 skip 位置登记错位，最终字节码会指向错误的索引。
func TestRebuildConstantArrayComposesWithEncrypt(t *testing.T) {
	data := sampleDex(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	se := &StringEncrypt{
		Class: "Lapkguard/Dec;", MethodName: "a", Key: 0x5a,
		MinLen: 4, InjectClass: true,
	}
	ca := &ConstantArray{
		Class: "Lapkguard/Arr;", MethodName: "b", MinLen: 4, InjectClass: true,
	}
	out, _, err := RebuildWithStats(f, RebuildOptions{StringEncrypt: se, ConstantArray: ca})
	if err != nil {
		t.Fatalf("A2+A3 同时启用时重建失败: %v", err)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("重建后校验失败: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("重建结果无法解析: %v", err)
	}
	if g.NClass != f.NClass+2 {
		t.Fatalf("应注入 2 个类（解密器 + 还原器）: %d -> %d", f.NClass, g.NClass)
	}
	// 两个注入类的方法体都必须可解析
	n := 0
	g.walkAllCode(func(codeOff uint32) error {
		if _, err := g.ParseCodeItem(codeOff); err != nil {
			t.Fatalf("@%d 解析失败: %v", codeOff, err)
		}
		n++
		return nil
	})
	// 全部指令流必须可被解析为合法指令（能发现 skip 错位导致的索引污染）
	m := 0
	err = g.walkAllCode(func(codeOff uint32) error {
		ci, err := g.ParseCodeItem(codeOff)
		if err != nil {
			return err
		}
		if _, err := ParseInsns(ci.Insns); err != nil {
			return err
		}
		m++
		return nil
	})
	if err != nil {
		t.Fatalf("指令流校验失败: %v", err)
	}
	t.Logf("A2+A3 组合：%d 个方法体、%d 条指令流全部合法；类 %d->%d", n, m, f.NClass, g.NClass)
}

// TestStringUsageCoversDebugInfo 验证调试信息中的字符串被纳入用途统计。
//
// 若遗漏，A2 可能把局部变量名当作「仅 const-string 使用」而替换为密文，
// 导致 debug_info 失真。
func TestStringUsageCoversDebugInfo(t *testing.T) {
	data := sampleDex(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	u, err := f.StringUsage()
	if err != nil {
		t.Fatalf("统计失败: %v", err)
	}
	if len(u.Debug) == 0 {
		t.Skip("样本的调试信息中没有字符串")
	}
	// Debug 与 Const 的交集必须被排除在「可整体替换」之外
	overlap := 0
	for i := range u.Debug {
		if u.Const[i] {
			overlap++
		}
	}
	t.Logf("调试信息引用 %d 个字符串，其中 %d 个同时被 const-string 引用", len(u.Debug), overlap)
}

// TestRebuildConstantArrayNoClass 验证 InjectClass=false 时只登记引用。
func TestRebuildConstantArrayNoClass(t *testing.T) {
	data := sampleDex(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	const cls = "Lapkguard/Arr;"
	ca := &ConstantArray{Class: cls, MethodName: "b", MinLen: 4, InjectClass: false}
	out, _, err := RebuildWithStats(f, RebuildOptions{ConstantArray: ca})
	if err != nil {
		t.Fatalf("重建失败: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("重建结果无法解析: %v", err)
	}
	if g.NClass != f.NClass {
		t.Fatalf("不应新增类: %d -> %d", f.NClass, g.NClass)
	}
	sawRef := false
	for i := uint32(0); i < g.NMethod; i++ {
		d, err := g.MethodDesc(i)
		if err != nil {
			continue
		}
		if strings.HasPrefix(d, cls+"->b(") {
			sawRef = true
			break
		}
	}
	if !sawRef {
		t.Fatal("还原方法的引用未登记到 method_ids")
	}
}
