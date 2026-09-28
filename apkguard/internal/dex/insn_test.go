package dex

import (
	"testing"
)

// TestParseCodeItemRoundTrip 验证 code_item 完整解析后原样编码可复原。
//
// 这是异常表支持的基础：若编码结果与原始字节不一致，
// 说明 try/handler 的布局理解有误。
func TestParseCodeItemRoundTrip(t *testing.T) {
	data := sampleDex(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	n, withTries := 0, 0
	err = f.Classes(func(_ uint32, cd ClassDef, name string) error {
		if cd.ClassDataOff == 0 {
			return nil
		}
		pcd, err := f.ParseClassData(cd.ClassDataOff)
		if err != nil {
			return err
		}
		for _, m := range append(append([]EncodedMethod{}, pcd.DirectMethods...), pcd.VirtualMethods...) {
			if m.CodeOff == 0 {
				continue
			}
			ci, err := f.ParseCodeItem(m.CodeOff)
			if err != nil {
				t.Fatalf("%s 解析 code_item 失败: %v", name, err)
			}
			blob := ci.Encode(nil)
			orig, err := f.rawCodeItem(m.CodeOff)
			if err != nil {
				t.Fatalf("读取原始 code_item 失败: %v", err)
			}
			if len(blob) != len(orig) {
				t.Fatalf("%s 编码长度不符: %d != %d", name, len(blob), len(orig))
			}
			for i := range blob {
				if blob[i] != orig[i] {
					t.Fatalf("%s code_item @%d 第 %d 字节不符: 0x%02x != 0x%02x",
						name, m.CodeOff, i, blob[i], orig[i])
				}
			}
			n++
			if len(ci.Tries) > 0 {
				withTries++
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("遍历失败: %v", err)
	}
	if n == 0 {
		t.Skip("样本中没有方法体")
	}
	t.Logf("逐字节校验 %d 个 code_item（其中 %d 个含异常表）", n, withTries)
}

// rawCodeItem 返回指定偏移处 code_item 的原始字节。
func (f *File) rawCodeItem(off uint32) ([]byte, error) {
	b := &builder{f: f, R: Identity(f), opts: RebuildOptions{}}
	length, err := b.codeItemLength(off)
	if err != nil {
		return nil, err
	}
	return f.data[off : off+uint32(length)], nil
}

// TestInsnListRoundTrip 验证指令流解析后原样编码可复原。
//
// 这是 A2/A3 插入指令的基础：重定位逻辑必须保证「不插入时零改动」。
func TestInsnListRoundTrip(t *testing.T) {
	data := sampleDex(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	n, nBranch, nPayload := 0, 0, 0
	err = f.walkAllCode(func(codeOff uint32) error {
		ci, err := f.ParseCodeItem(codeOff)
		if err != nil {
			return err
		}
		l, err := ParseInsns(ci.Insns)
		if err != nil {
			return err
		}
		out, old2new, _ := l.Encode()
		if len(out) != len(ci.Insns) {
			t.Fatalf("@%d 编码长度不符: %d != %d", codeOff, len(out), len(ci.Insns))
		}
		for i := range out {
			if out[i] != ci.Insns[i] {
				t.Fatalf("@%d 第 %d 字不符: 0x%04x != 0x%04x（op=0x%02x）",
					codeOff, i, out[i], ci.Insns[i], ci.Insns[i]&0xff)
			}
		}
		for old, nw := range old2new {
			if old != nw {
				t.Fatalf("@%d 恒等编码下偏移发生变化: %d -> %d", codeOff, old, nw)
			}
		}
		for _, it := range l.items {
			if it.kind != itemInsn {
				nPayload++
			}
		}
		nBranch += len(l.branches)
		n++
		return nil
	})
	if err != nil {
		t.Fatalf("遍历失败: %v", err)
	}
	if n == 0 {
		t.Skip("样本中没有方法体")
	}
	t.Logf("逐字节校验 %d 条指令流：分支引用 %d 处、payload %d 个", n, nBranch, nPayload)
	if nBranch == 0 {
		t.Fatal("样本中未发现任何分支指令，测试失去意义")
	}
}

// checkBranches 校验重定位后每条分支的绝对落点与预期一致。
//
// 这是插入指令时最关键的安全性保证：所有原有分支必须仍然指向
// 「语义上原本的那条指令」，而不能落到插入的指令中间。
func checkBranches(t *testing.T, l *InsnList, out []uint16, old2new map[int]int) {
	t.Helper()
	for _, b := range l.branches {
		want, ok := old2new[b.target]
		if !ok {
			continue // 目标不在流内
		}
		it := l.items[b.item]
		base := it.new
		var rel int
		switch b.form {
		case form10t:
			rel = int(int8(out[base] >> 8))
		case form20t, form22t:
			rel = int(int16(out[base+b.word]))
		case form30t, form31t, formPayload:
			rel = int(int32(uint32(out[base+b.word]) | uint32(out[base+b.word+1])<<16))
		}
		if got := base + rel; got != want {
			t.Fatalf("分支落点错误: 得到 %d，期望 %d（form=%d base=%d rel=%d）",
				got, want, b.form, base, rel)
		}
	}
}

// TestInsnListInsert 验证在流首插入指令后分支被正确重定位。
func TestInsnListInsert(t *testing.T) {
	// [0] const/4 v0, #0
	// [1] if-eqz v0, +2  → 落点 3
	// [3] return-void
	// [4] return-void
	words := []uint16{0x0012, 0x0038, 0x02, 0x000e, 0x000e}
	l, err := ParseInsns(words)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if l.ItemCount() != 4 {
		t.Fatalf("指令项数应为 4，实际 %d", l.ItemCount())
	}
	l.InsertBefore(0, []uint16{0x0112}) // const/4 v1, #0
	out, old2new, _ := l.Encode()
	if len(out) != 6 {
		t.Fatalf("插入后长度应为 6，实际 %d", len(out))
	}
	if out[0] != 0x0112 {
		t.Fatalf("插入的指令应在最前，实际 0x%04x", out[0])
	}
	// 锚定项（原偏移 0）应映射到插入项之后
	if old2new[0] != 1 {
		t.Fatalf("原偏移 0 应映射为 1，实际 %d", old2new[0])
	}
	if old2new[3] != 4 {
		t.Fatalf("原偏移 3 应映射为 4，实际 %d", old2new[3])
	}
	checkBranches(t, l, out, old2new)
}

// TestInsnListInsertAtBranchTarget 验证在分支目标处插入时分支仍指向原指令。
func TestInsnListInsertAtBranchTarget(t *testing.T) {
	// [0] const/4 v0, #0
	// [1] if-eqz v0, +2  → 落点 3
	// [3] return-void
	// [4] return-void
	words := []uint16{0x0012, 0x0038, 0x02, 0x000e, 0x000e}
	l, err := ParseInsns(words)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	// 第 2 项即偏移 3 处的 return-void，正是分支目标
	if l.ItemOldOffset(2) != 3 {
		t.Fatalf("第 2 项的旧偏移应为 3，实际 %d", l.ItemOldOffset(2))
	}
	l.InsertBefore(2, []uint16{0x0112})
	out, old2new, _ := l.Encode()
	if len(out) != 6 {
		t.Fatalf("插入后长度应为 6，实际 %d", len(out))
	}
	// 分支目标仍应指向原来的 return-void（新偏移 4）
	if old2new[3] != 4 {
		t.Fatalf("原偏移 3 应映射为 4，实际 %d", old2new[3])
	}
	// 插入的指令落在新偏移 3
	if out[3] != 0x0112 {
		t.Fatalf("新偏移 3 处应为插入的指令，实际 0x%04x", out[3])
	}
	checkBranches(t, l, out, old2new)
}

// TestInsnListInsertBeforeBranch 验证在分支指令之前插入时的重定位。
func TestInsnListInsertBeforeBranch(t *testing.T) {
	words := []uint16{0x0012, 0x0038, 0x02, 0x000e, 0x000e}
	l, err := ParseInsns(words)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	l.InsertBefore(1, []uint16{0x0112})
	out, old2new, _ := l.Encode()
	if old2new[1] != 2 {
		t.Fatalf("原偏移 1 应映射为 2，实际 %d", old2new[1])
	}
	if out[2]&0xff != 0x38 {
		t.Fatalf("新偏移 2 处应为 if-eqz，实际 0x%02x", out[2]&0xff)
	}
	checkBranches(t, l, out, old2new)
}

// TestInsnListPayloadAlign 验证 payload 对齐由编码器自动补齐。
func TestInsnListPayloadAlign(t *testing.T) {
	// [0] nop
	// [1] const/4 v0, #0
	// [2..4] fill-array-data v0, +4  → 落点 6
	// [5] return-void
	// [6..9] fill-array-data-payload
	words := []uint16{
		0x0000,
		0x0012,
		0x0026, 0x04, 0x0000,
		0x000e,
		0x0300, 0x01, 0x0000, 0x0000,
	}
	l, err := ParseInsns(words)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	out, old2new, _ := l.Encode()
	if len(out) != len(words) {
		t.Fatalf("已对齐的 payload 不应改变长度: %d != %d", len(out), len(words))
	}
	for i := range out {
		if out[i] != words[i] {
			t.Fatalf("第 %d 字变化: 0x%04x != 0x%04x", i, out[i], words[i])
		}
	}
	checkBranches(t, l, out, old2new)

	// 插入一条指令使 payload 失去对齐
	l2, err := ParseInsns(words)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	l2.InsertBefore(1, []uint16{0x0000})
	out2, old2new2, _ := l2.Encode()
	// payload 原在偶数偏移 6，插入 1 字后需补 nop 对齐到 8
	if got := old2new2[6]; got != 8 {
		t.Fatalf("payload 应移到偏移 8，实际 %d", got)
	}
	if out2[7] != 0x0000 {
		t.Fatalf("偏移 7 处应为补齐用的 nop，实际 0x%04x", out2[7])
	}
	if out2[8] != 0x0300 {
		t.Fatalf("偏移 8 处应为 payload 标识，实际 0x%04x", out2[8])
	}
	checkBranches(t, l2, out2, old2new2)
}

// TestInsnListGotoForms 验证三种 goto 格式的重定位。
func TestInsnListGotoForms(t *testing.T) {
	cases := []struct {
		name  string
		words []uint16
		// insert 是插入的指令条数（每条 1 字 nop）
		insert int
	}{
		{"10t", []uint16{0x0128, 0x000e, 0x000e}, 1},
		{"20t", []uint16{0x0029, 0x0001, 0x000e, 0x000e}, 2},
		{"30t", []uint16{0x002a, 0x0001, 0x0000, 0x000e, 0x000e}, 3},
	}
	for _, c := range cases {
		l, err := ParseInsns(c.words)
		if err != nil {
			t.Fatalf("%s 解析失败: %v", c.name, err)
		}
		// 恒等编码必须逐字不变
		out0, idMap, _ := l.Encode()
		if len(out0) != len(c.words) {
			t.Fatalf("%s 恒等编码长度变化: %d != %d", c.name, len(out0), len(c.words))
		}
		for i := range out0 {
			if out0[i] != c.words[i] {
				t.Fatalf("%s 恒等编码第 %d 字变化: 0x%04x != 0x%04x",
					c.name, i, out0[i], c.words[i])
			}
		}
		checkBranches(t, l, out0, idMap)

		// 插入后重定位必须仍然正确
		ins := make([][]uint16, 0, c.insert)
		for k := 0; k < c.insert; k++ {
			ins = append(ins, []uint16{0x0000})
		}
		l.InsertBefore(0, ins...)
		out, m, _ := l.Encode()
		if out[c.insert]&0xff != c.words[0]&0xff {
			t.Fatalf("%s 跳转指令应移到偏移 %d，实际 0x%02x",
				c.name, c.insert, out[c.insert]&0xff)
		}
		checkBranches(t, l, out, m)
	}
}

// TestInsnListSwitchPayload 验证 packed-switch 的重定位。
func TestInsnListSwitchPayload(t *testing.T) {
	// [0] const/4 v0, #0
	// [1..3] packed-switch v0, +5  → 落点 6（payload 起点）
	// [4] return-void
	// [5] nop（对齐填充）
	// [6..] payload: ident, size=2, first_key=0, target[0]=-2 → 4, target[1]=+2 → 8
	words := []uint16{
		0x0012,
		0x002b, 0x05, 0x0000,
		0x000e,
		0x0000,
		0x0100, 0x0002, 0x0000, 0x0000,
		0xfffe, 0xffff, // target[0] = -2 → 6-2 = 4
		0x0002, 0x0000, // target[1] = +2 → 6+2 = 8
		0x000e, 0x000e,
	}
	l, err := ParseInsns(words)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	out, idMap, _ := l.Encode()
	if len(out) != len(words) {
		t.Fatalf("恒等编码长度应不变: %d != %d", len(out), len(words))
	}
	for i := range out {
		if out[i] != words[i] {
			t.Fatalf("第 %d 字变化: 0x%04x != 0x%04x", i, out[i], words[i])
		}
	}
	checkBranches(t, l, out, idMap)

	// 在 packed-switch 前插入，payload 与其 target 表都应整体后移
	l.InsertBefore(1, []uint16{0x0000})
	out2, m, _ := l.Encode()
	// payload 原在偏移 6，插入 1 字后需补 nop 对齐到 8
	if got := m[6]; got != 8 {
		t.Fatalf("payload 应移到偏移 8，实际 %d", got)
	}
	if out2[8] != 0x0100 {
		t.Fatalf("偏移 8 处应为 packed-switch payload 标识，实际 0x%04x", out2[8])
	}
	checkBranches(t, l, out2, m)
}

// TestInsnListSparseSwitchPayload 验证 sparse-switch 的重定位。
func TestInsnListSparseSwitchPayload(t *testing.T) {
	// [0] const/4 v0, #0
	// [1..3] sparse-switch v0, +5  → 落点 6（payload 起点）
	// [4] return-void
	// [5] nop（对齐填充）
	// [6..] payload: ident, size=1, keys[0], targets[0]
	words := []uint16{
		0x0012,
		0x002c, 0x05, 0x0000,
		0x000e,
		0x0000,
		0x0200, 0x0001,
		0x0007, 0x0000, // keys[0] = 7
		0xfffe, 0xffff, // target[0] = -2 → 6-2 = 4
		0x000e,
	}
	l, err := ParseInsns(words)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	out, idMap, _ := l.Encode()
	if len(out) != len(words) {
		t.Fatalf("恒等编码长度应不变: %d != %d", len(out), len(words))
	}
	for i := range out {
		if out[i] != words[i] {
			t.Fatalf("第 %d 字变化: 0x%04x != 0x%04x", i, out[i], words[i])
		}
	}
	checkBranches(t, l, out, idMap)

	l.InsertBefore(1, []uint16{0x0000})
	out2, m, _ := l.Encode()
	if got := m[6]; got != 8 {
		t.Fatalf("payload 应移到偏移 8，实际 %d", got)
	}
	if out2[8] != 0x0200 {
		t.Fatalf("偏移 8 处应为 sparse-switch payload 标识，实际 0x%04x", out2[8])
	}
	checkBranches(t, l, out2, m)
}

// TestInsnListReplace 验证替换单条指令。
func TestInsnListReplace(t *testing.T) {
	// const/4 v0, #0（1 字）→ 替换为 const/16 v0, #0（2 字）
	words := []uint16{0x0012, 0x000e}
	l, err := ParseInsns(words)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	l.Replace(0, []uint16{0x0013, 0x0000}) // const/16 v0, #0
	out, m, _ := l.Encode()
	if len(out) != 3 {
		t.Fatalf("替换为 2 字指令后长度应为 3，实际 %d", len(out))
	}
	if out[0] != 0x0013 || out[1] != 0x0000 {
		t.Fatalf("替换结果不符: 0x%04x 0x%04x", out[0], out[1])
	}
	if out[2] != 0x000e {
		t.Fatalf("后续指令应后移，实际 0x%04x", out[2])
	}
	if m[1] != 2 {
		t.Fatalf("原偏移 1 应映射为 2，实际 %d", m[1])
	}
}
