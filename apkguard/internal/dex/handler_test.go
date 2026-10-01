package dex

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// checkTryHandlers 校验 try_item 与异常处理器列表的结构自洽性。
//
// 这是 ART **结构校验器**（dex_file_verifier）的规则，dex2oat 的 verify 模式
// 并不检查——本项目就因此漏掉过一个真实缺陷：改写后地址的 ULEB128 编码变长，
// 使处理器在列表中的字节位置后移，而 try_item 的 handler_off 仍指向旧位置，
// ART 判 "Bogus handler offset" 并**丢弃整个 DEX**，
// 表现为 DexPathList 为空、业务类全部 ClassNotFoundException。
//
// 三类检查：
//  1. handler_off 必须等于某个处理器在列表中的起始字节偏移；
//  2. try 区间必须落在指令流范围内；
//  3. 处理器目标地址必须是指令边界。
func checkTryHandlers(t *testing.T, tag string, f *File) int {
	t.Helper()
	checked := 0
	err := f.walkAllCode(func(codeOff uint32) error {
		ci, err := f.ParseCodeItem(codeOff)
		if err != nil {
			return err
		}
		if len(ci.Tries) == 0 {
			return nil
		}
		// 合法起点必须取自**解析出的字节事实**（ci.HandlerOffs）。
		//
		// 早期实现是「用 encodeHandlerList 重算一遍」，也就是拿同一个编码器
		// 校验自己：编码器若在「类型索引跨 ULEB128 边界」时算错偏移，重算出的
		// 「合法集合」会跟着一起错，守卫恒为真——这个真缺陷正是这样躲过了整套
		// 守卫（只有 Dhizuku 这种类型索引 >127 的大应用才会触发）。
		valid := map[uint32]bool{}
		if len(ci.HandlerOffs) == len(ci.Handlers) {
			for _, o := range ci.HandlerOffs {
				valid[uint32(o)] = true
			}
		} else {
			_, offs := encodeHandlerList(ci.Handlers, func(v uint32) uint32 { return v })
			for _, o := range offs {
				valid[uint32(o)] = true
			}
		}
		// 指令边界集合（含 payload 起始）。
		l, err := ParseInsns(ci.Insns)
		if err != nil {
			return err
		}
		starts := map[uint32]bool{}
		for i := 0; i < l.ItemCount(); i++ {
			starts[uint32(l.ItemOldOffset(i))] = true
		}
		for _, tr := range ci.Tries {
			checked++
			if !valid[uint32(tr.HandlerOff)] {
				t.Errorf("%s：code@%d 的 try_item.handler_off=%d 未指向任何处理器起点"+
					"（ART 会判 Bogus handler offset 并拒绝整个 DEX）",
					tag, codeOff, tr.HandlerOff)
			}
			if end := int(tr.StartAddr) + int(tr.InsnCount); end > len(ci.Insns) {
				t.Errorf("%s：code@%d 的 try 区间 [%d,%d) 越出指令流长度 %d",
					tag, codeOff, tr.StartAddr, end, len(ci.Insns))
			}
		}
		for _, h := range ci.Handlers {
			for _, a := range h.Addrs {
				if !starts[a] {
					t.Errorf("%s：code@%d 的处理器目标地址 %d 不是指令边界", tag, codeOff, a)
				}
			}
			if h.CatchAll && !starts[h.AllAddr] {
				t.Errorf("%s：code@%d 的 catch-all 地址 %d 不是指令边界", tag, codeOff, h.AllAddr)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("%s 遍历失败: %v", tag, err)
	}
	return checked
}

// TestEncodeHandlerOffAfterTypeIndexGrowth 复现并钉住一个真实缺陷。
//
// 场景：重命名会把捕获类型的索引推大，一旦跨过 ULEB128 的 127→128 边界，
// 该处理器在列表里就多占 1 字节，**后续处理器整体后移**。此时 try_item 的
// handler_off 必须跟着改。
//
// 早期实现用「把内存里的 handler 重新编码一遍」推算旧偏移，而那时索引已经被
// 改名改写过了，算出的「旧偏移」不是文件里的真值 → 映射键对不上 → 代码静默
// 沿用旧偏移，产物被 ART 判 "Bogus handler offset" 并丢弃整个 DEX。
// 索引小的应用碰不到这个边界，因此这个缺陷只在大应用上出现（实测 Dhizuku）。
func TestEncodeHandlerOffAfterTypeIndexGrowth(t *testing.T) {
	// 原始布局（HandlerOffs 记录的是解析时的字节事实）：
	//   size(1) | handler0: size(1) type(1) addr(1) | handler1: size(-1) type(1) addr(1) all(1)
	//   → handler0 在偏移 1，handler1 在偏移 4
	ci := &CodeItemFull{
		Registers: 2, Ins: 1, Outs: 1,
		Insns: []uint16{0x000e, 0x0000, 0x000e, 0x0000},
		// try 指向 handler1（会移动的那个）
		Tries: []TryItem{{StartAddr: 0, InsnCount: 2, HandlerOff: 4}},
		Handlers: []CatchHandler{
			{Types: []uint32{1}, Addrs: []uint32{0}},
			{Types: []uint32{2}, Addrs: []uint32{0}, CatchAll: true, AllAddr: 0},
		},
		HandlerOffs: []uint16{1, 4},
	}
	// 模拟重命名：把 handler0 的类型索引推到需要 2 字节 ULEB 的值
	ci.Handlers[0].Types[0] = 300

	out := ci.Encode(nil)
	got, err := ParseCodeItemBytes(out)
	if err != nil {
		t.Fatalf("重新解析产物失败: %v", err)
	}
	if len(got.HandlerOffs) != 2 {
		t.Fatalf("处理器数量应仍为 2，实际 %d", len(got.HandlerOffs))
	}
	// handler0 未动（偏移 1），handler1 因前面变长而移到 5
	if got.HandlerOffs[0] != 1 || got.HandlerOffs[1] != 5 {
		t.Fatalf("处理器新偏移应为 [1 5]，实际 %v", got.HandlerOffs)
	}
	valid := map[uint16]bool{}
	for _, o := range got.HandlerOffs {
		valid[o] = true
	}
	for _, tr := range got.Tries {
		if !valid[tr.HandlerOff] {
			t.Fatalf("try_item.handler_off=%d 未指向处理器起点 %v"+
				"（ART 会判 Bogus handler offset 并拒绝整个 DEX）", tr.HandlerOff, got.HandlerOffs)
		}
	}
	if tr := got.Tries[0].HandlerOff; tr != 5 {
		t.Fatalf("指向 handler1 的 try_item.handler_off 应随之后移到 5，实际 %d", tr)
	}
}

// TestArtifactTryHandlers 对全部交付包（含解密后的载荷）检查 try/handler 结构。
func TestArtifactTryHandlers(t *testing.T) {
	files, err := filepath.Glob("../../../deliver/*.apk")
	if err != nil || len(files) == 0 {
		t.Skip("交付包不在本机，跳过")
	}
	sort.Strings(files)
	total := 0
	for _, apk := range files {
		g, assets := apkShellDex(t, apk)
		total += checkTryHandlers(t, filepath.Base(apk), g)
		if len(assets) == 0 {
			continue
		}
		env := &loaderEnv{assets: assets, fs: map[string][]byte{}}
		restore := installLoaderMocks(env)
		installActivityThreadMock()
		fakeCode = map[string]uint32{}
		registerFakeCode(t, g, allClassNames(t, g)...)
		for k, h := range crashHandlerDeps() {
			fakeCalls[k] = h
		}
		if idx, off := findMethod(t, g, "Lcom/apkguard/shell/Loader;", "->"+LoaderEntry+"("); off != 0 {
			if _, rerr := runPadMethod(g, idx, off, &fakeObj{desc: descContext}); rerr == nil {
				for name, blob := range env.fs {
					if pg, perr := Parse(blob); perr == nil {
						total += checkTryHandlers(t, filepath.Base(apk)+" 载荷 "+filepath.Base(name), pg)
					}
				}
			}
		}
		restore()
		clearActivityThreadMock()
		fakeCode = map[string]uint32{}
	}
	t.Logf("检查了 %d 个 try_item", total)
}

// TestRealWorldPayloadTryHandlers 检查真实应用（RustDesk）加固产物解密后的载荷。
//
// 这条路专门守「自研样本覆盖不到」的场景：真实应用遍布 try/catch，
// 而测试样本里没有，因此只有真实包才能暴露 handler_off 这类缺陷。
func TestRealWorldPayloadTryHandlers(t *testing.T) {
	apk := os.Getenv("RD_APK")
	if apk == "" {
		apk = "../../../realworld/rd-v20.apk"
	}
	if _, err := os.Stat(apk); err != nil {
		t.Skipf("未找到 %s，跳过", apk)
	}
	g, assets := apkShellDex(t, apk)
	env := &loaderEnv{assets: assets, fs: map[string][]byte{}}
	restore := installLoaderMocks(env)
	defer restore()
	installActivityThreadMock()
	defer clearActivityThreadMock()
	fakeCode = map[string]uint32{}
	defer func() { fakeCode = map[string]uint32{} }()
	registerFakeCode(t, g, allClassNames(t, g)...)
	idx, off := findMethod(t, g, "Lcom/apkguard/shell/Loader;", "->"+LoaderEntry+"(")
	if _, err := runPadMethod(g, idx, off, &fakeObj{desc: descContext}); err != nil {
		t.Fatalf("壳链路执行失败: %v", err)
	}
	total := 0
	for name, blob := range env.fs {
		pg, err := Parse(blob)
		if err != nil {
			t.Fatalf("解析 %s 失败: %v", name, err)
		}
		total += checkTryHandlers(t, filepath.Base(apk)+" "+filepath.Base(name), pg)
	}
	t.Logf("RustDesk 载荷共检查 %d 个 try_item", total)
	if total < 100 {
		t.Fatalf("真实应用应有大量 try/catch，只检查到 %d 个，样本可能不对", total)
	}
}

// TestEncodeRecalculatesHandlerOffsets 直接验证 Encode 会重算 handler_off。
//
// 构造两个处理器：第一个的目标地址在「修正」后 ULEB128 编码变长，
// 使第二个处理器在列表中的字节位置后移。若 try_item 沿用旧的 handler_off，
// ART 会判 Bogus handler offset 并拒绝整个 DEX——这正是真实应用
// （RustDesk）加固后类全部找不到的根因。
func TestEncodeRecalculatesHandlerOffsets(t *testing.T) {
	handlers := []CatchHandler{
		{Types: []uint32{1}, Addrs: []uint32{4}},                                 // 地址 4，ULEB128 占 1 字节
		{Types: []uint32{2}, Addrs: []uint32{40000}, CatchAll: true, AllAddr: 8}, // 地址 40000，占 3 字节
	}
	_, oldOffs := encodeHandlerList(handlers, func(v uint32) uint32 { return v })
	if len(oldOffs) != 2 {
		t.Fatalf("处理器数量异常: %v", oldOffs)
	}
	ci := &CodeItemFull{
		Registers: 4,
		Insns:     make([]uint16, 8),
		// 引用**第二个**处理器：它的位置会因为前一个地址变长而移动。
		Tries:    []TryItem{{StartAddr: 0, InsnCount: 8, HandlerOff: uint16(oldOffs[1])}},
		Handlers: handlers,
	}
	// 修正：把第一个处理器的地址编码长度从 1 字节涨到 3 字节。
	fix := func(v uint32) uint32 {
		if v == 4 {
			return 400000
		}
		return v
	}
	_, newOffs := encodeHandlerList(handlers, fix)
	if oldOffs[1] == newOffs[1] {
		t.Fatalf("构造无效：第二个处理器的位置未移动（旧 %d 新 %d）", oldOffs[1], newOffs[1])
	}
	out := ci.Encode(fix)
	got, err := ParseCodeItemBytes(out)
	if err != nil {
		t.Fatalf("解析编码结果失败: %v", err)
	}
	valid := map[uint32]bool{}
	for _, o := range newOffs {
		valid[uint32(o)] = true
	}
	for i, tr := range got.Tries {
		if !valid[uint32(tr.HandlerOff)] {
			t.Fatalf("try[%d] 的 handler_off=%d 未指向处理器起点（应为 %v）——"+
				"ART 会判 Bogus handler offset", i, tr.HandlerOff, newOffs)
		}
	}
	if got.Tries[0].HandlerOff != uint16(newOffs[1]) {
		t.Fatalf("handler_off 应为重算后的 %d，实际 %d", newOffs[1], got.Tries[0].HandlerOff)
	}
	t.Logf("偏移已重算：旧 %d → 新 %d", oldOffs[1], newOffs[1])
}
