package dex

import (
	"fmt"
	"testing"
)

// bigPoolExtras 造一批「排在所有正常字符串之前」的额外字符串，用来把池推过 65535。
//
// 为什么用前缀 U+0001：DEX 的 string_ids 按 UTF-16 序排列，而真实 DEX 里的
// 字符串（类型描述符、方法名、常量）首字符都 >= 0x20。以 U+0001 开头的字符串
// 必然排在它们之前，于是所有原有字符串的新下标都会 >= len(extras)，稳定越界。
func bigPoolExtras(n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, fmt.Sprintf("\x01%06d", i))
	}
	return out
}

// collectJumboRefs 返回产物里全部 const-string/jumbo 引用的字符串及次数。
func collectJumboRefs(t *testing.T, tag string, f *File) map[string]int {
	t.Helper()
	out := map[string]int{}
	err := f.walkAllCode(func(codeOff uint32) error {
		ci, err := f.ParseCodeItem(codeOff)
		if err != nil {
			return err
		}
		l, err := ParseInsns(ci.Insns)
		if err != nil {
			return err
		}
		for i := 0; i < l.ItemCount(); i++ {
			if !l.ItemIsInsn(i) {
				continue
			}
			w := l.ItemWords(i)
			if byte(w[0]&0xff) != 0x1b {
				continue
			}
			idx := uint32(w[1]) | uint32(w[2])<<16
			s, err := f.String(idx)
			if err != nil {
				return fmt.Errorf("%s: jumbo 指令 @%d 的索引 %d 越界: %w", tag, l.ItemOldOffset(i), idx, err)
			}
			out[s]++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("%s: 遍历产物失败: %v", tag, err)
	}
	return out
}

// TestWidenLargePoolRebuild 构造一个字符串池超过 65535 的 DEX，断言重建成功、
// 产物校验通过，且原本会越界的 const-string 已变成 0x1b，索引仍指向正确字符串。
//
// 这是缺陷的直接回归：修复前会报
//
//	dex: 指令 0x1a @word 23 引用索引 65592 超出 16 位，需要指令加宽
func TestWidenLargePoolRebuild(t *testing.T) {
	data := sampleDex(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析样本失败: %v", err)
	}

	opts := RebuildOptions{ExtraStrings: bigPoolExtras(65540)}
	out, st, err := RebuildWithStats(f, opts)
	if err != nil {
		t.Fatalf("大池重建失败: %v", err)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("大池重建后校验失败: %v", err)
	}
	if st.WidenedStrings == 0 {
		t.Fatalf("期望有 const-string 被加宽，实际 WidenedStrings=0（统计未接通？）")
	}
	if st.WidenSkipped != 0 {
		t.Fatalf("期望无跳过，实际 WidenSkipped=%d", st.WidenSkipped)
	}
	t.Logf("加宽 %d 条，跳过 %d 条", st.WidenedStrings, st.WidenSkipped)

	g, err := Parse(out)
	if err != nil {
		t.Fatalf("解析产物失败: %v", err)
	}
	// 产物结构体检：分支目标、try/handler、outs、shorty 都必须自洽。
	checkBranchTargets(t, "widen-large", g)
	checkTryHandlers(t, "widen-large", g)
	checkOutsOf(t, "widen-large", g)
	checkShortyStrings(t, "widen-large", g)

	// 索引正确性：样本里原本被 const-string 引用的常量，现在必须以 jumbo
	// 形式引用到**同一个字符串**（内容不变，只是下标变大、指令加宽）。
	jumbo := collectJumboRefs(t, "widen-large", g)
	for _, want := range []string{":", "AGTEST", "OK-跨分片"} {
		if jumbo[want] == 0 {
			t.Errorf("期望字符串 %q 以 const-string/jumbo 被引用，实际未找到（jumbo 引用：%v）", want, jumbo)
		}
	}
	// 反向确认：这些字符串必须仍能按内容读回（索引没有指向别的串）。
	for s := range jumbo {
		if s == "" {
			t.Errorf("jumbo 引用到了空字符串")
		}
	}
}

// TestWidenSkipTranslationWithStringEncrypt 是本任务最核心的产物：
// 同时触发 A2 字符串加密（会产生 skip）与加宽，断言 A2 写入的密文索引
// 在产物里仍然指向密文。
//
// skip 是「已是最终索引、不可再映射」的绝对字位置。加宽插入字后若不把
// skip 精确平移，remapCode 会把密文索引当旧索引再映射一次——轻则报索引越界，
// 重则静默指向别的字符串，解密出垃圾。因此这里必须实际跑通并校验。
func TestWidenSkipTranslationWithStringEncrypt(t *testing.T) {
	data := sampleDex(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析样本失败: %v", err)
	}

	var key [32]byte
	for i := range key {
		key[i] = byte(i*7 + 3)
	}
	opts := RebuildOptions{
		ExtraStrings: bigPoolExtras(65540),
		StringEncrypt: &StringEncrypt{
			Class:       "Lx/Dec;",
			MethodName:  "a",
			Key:         key,
			MinLen:      1,
			InjectClass: true,
			// 排除 AGTEST：让它的 const-string 保持 0x1a 从而被加宽，
			// 同时同方法内更靠后的常量被 A2 加密（产生位于加宽点之后的 skip），
			// 这样 skip 平移才真正被覆盖到。
			Skip: func(s string) bool { return s == "AGTEST" },
		},
	}

	// 直接走 buildPlan + assemble，以便取到 cipher（明文 -> 密文）做校验。
	pl, err := buildPlan(f, opts)
	if err != nil {
		t.Fatalf("buildPlan 失败: %v", err)
	}
	b := &builder{f: f, R: pl.remap, opts: opts}
	out, err := b.assemble(pl)
	if err != nil {
		t.Fatalf("A2+加宽 重建失败: %v", err)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("A2+加宽 重建后校验失败: %v", err)
	}
	if pl.strEnc == nil || len(pl.strEnc.cipher) == 0 {
		t.Fatalf("前置条件不成立：A2 没有加密任何字符串")
	}
	if pl.widen.Widened == 0 {
		t.Fatalf("前置条件不成立：没有指令被加宽（大池应触发加宽）")
	}
	if pl.widen.Skipped != 0 {
		t.Fatalf("期望无跳过，实际 WidenSkipped=%d", pl.widen.Skipped)
	}
	t.Logf("A2 加密 %d 条，加宽 %d 条", len(pl.strEnc.cipher), pl.widen.Widened)

	g, err := Parse(out)
	if err != nil {
		t.Fatalf("解析产物失败: %v", err)
	}
	checkBranchTargets(t, "widen-a2", g)
	checkTryHandlers(t, "widen-a2", g)
	checkOutsOf(t, "widen-a2", g)

	// 密文集合。
	cipherVals := map[string]bool{}
	for _, ct := range pl.strEnc.cipher {
		cipherVals[ct] = true
	}

	// 逐方法扫描：凡是「jumbo + 解密调用」形态的 const-string，其引用的
	// 字符串必须是密文。若 skip 平移错误，remapCode 会二次映射该索引，
	// 要么直接报错（rebuild 已失败），要么指向非密文——两者都会被这里抓住。
	checked := 0
	err = g.walkAllCode(func(codeOff uint32) error {
		ci, err := g.ParseCodeItem(codeOff)
		if err != nil {
			return err
		}
		l, err := ParseInsns(ci.Insns)
		if err != nil {
			return err
		}
		for i := 0; i < l.ItemCount(); i++ {
			if !l.ItemIsInsn(i) {
				continue
			}
			w := l.ItemWords(i)
			if byte(w[0]&0xff) != 0x1b {
				continue
			}
			if !l.isStringDecryptPattern(i, g) {
				continue
			}
			idx := uint32(w[1]) | uint32(w[2])<<16
			s, err := g.String(idx)
			if err != nil {
				return fmt.Errorf("code@%d jumbo@%d 索引 %d 读回失败: %w", codeOff, l.ItemOldOffset(i), idx, err)
			}
			if !cipherVals[s] {
				return fmt.Errorf("code@%d jumbo@%d 的解密调用引用了非密文 %q（索引 %d）——skip 平移错误",
					codeOff, l.ItemOldOffset(i), s, idx)
			}
			checked++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatalf("未找到任何「jumbo + 解密调用」指令，A2 改写未生效")
	}
	t.Logf("校验了 %d 条加密常量引用，全部指向密文", checked)

	// 同时确认 AGTEST 确实被加宽成了 jumbo。
	jumbo := collectJumboRefs(t, "widen-a2", g)
	if jumbo["AGTEST"] == 0 {
		t.Errorf("期望 AGTEST 被加宽为 jumbo，实际未找到")
	}
}

// TestWidenSmallPoolNoOp 断言池远小于 65535 时加宽是严格的 no-op：
// 不改变任何 code_item 字节，也不产生任何 jumbo。
func TestWidenSmallPoolNoOp(t *testing.T) {
	data := sampleDex(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析样本失败: %v", err)
	}
	if f.NString > maxStringIdx16 {
		t.Fatalf("样本池 %d 已超过 16 位上限，测试前提不成立", f.NString)
	}

	pl, err := buildPlan(f, RebuildOptions{})
	if err != nil {
		t.Fatalf("buildPlan 失败: %v", err)
	}
	b := &builder{f: f, R: pl.remap, opts: RebuildOptions{}}

	// 逐个 code_item 直接调用加宽：必须全部 changed=false 且不返回新字节。
	items := 0
	err = f.walkAllCode(func(codeOff uint32) error {
		ci, err := f.ParseCodeItem(codeOff)
		if err != nil {
			return err
		}
		blob := ci.Encode(nil)
		nb, nsk, changed, werr := b.widenConstStrings(pl, blob, nil)
		if werr != nil {
			return werr
		}
		if changed || nb != nil || nsk != nil {
			t.Errorf("小池 code@%d 不应被加宽（changed=%v）", codeOff, changed)
		}
		items++
		return nil
	})
	if err != nil {
		t.Fatalf("遍历失败: %v", err)
	}
	if items == 0 {
		t.Fatalf("没有扫描到 code_item")
	}

	// 完整重建：统计为 0，产物里不应出现任何新的 jumbo。
	out, st, err := RebuildWithStats(f, RebuildOptions{})
	if err != nil {
		t.Fatalf("重建失败: %v", err)
	}
	if st.WidenedStrings != 0 || st.WidenSkipped != 0 {
		t.Fatalf("小池不应有加宽统计：Widened=%d Skipped=%d", st.WidenedStrings, st.WidenSkipped)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("解析产物失败: %v", err)
	}
	if got := collectJumboRefs(t, "widen-small", g); len(got) != 0 {
		t.Fatalf("小池产物出现了 jumbo 引用：%v", got)
	}

	// 确定性：同样输入两次重建必须逐字节一致（加宽不引入随机性）。
	out2, _, err := RebuildWithStats(f, RebuildOptions{})
	if err != nil {
		t.Fatalf("第二次重建失败: %v", err)
	}
	if string(out) != string(out2) {
		t.Fatalf("两次重建结果不一致")
	}
	t.Logf("小池 no-op 校验通过，共 %d 个 code_item", items)
}
