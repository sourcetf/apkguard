package arsc

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"strconv"
	"testing"
)

// firstPkgOff 返回表中第一个包块的偏移。
func firstPkgOff(t *testing.T, data []byte) int {
	t.Helper()
	hdr := int(binary.LittleEndian.Uint16(data[2:]))
	total := int(binary.LittleEndian.Uint32(data[4:]))
	for p := hdr; p+8 <= total; {
		tp := binary.LittleEndian.Uint16(data[p:])
		sz := int(binary.LittleEndian.Uint32(data[p+4:]))
		if sz < 8 || p+sz > total {
			t.Fatalf("顶层块长度非法: type=%#x size=%d", tp, sz)
		}
		if tp == 0x0200 {
			return p
		}
		p += sz
	}
	t.Fatal("表里没有包块")
	return 0
}

// pkgTypePool 解析包内 typeStrings 池。
func pkgTypePool(t *testing.T, data []byte, pkgOff int) *stringPool {
	t.Helper()
	off := pkgOff + int(binary.LittleEndian.Uint32(data[pkgOff+268:]))
	p, err := parseStringPool(data, off)
	if err != nil {
		t.Fatalf("解析 typeStrings 失败: %v", err)
	}
	return p
}

// pkgKeyPool 解析包内 keyStrings 池；没有时返回 nil。
func pkgKeyPool(t *testing.T, data []byte, pkgOff int) *stringPool {
	t.Helper()
	rel := int(binary.LittleEndian.Uint32(data[pkgOff+276:]))
	if rel == 0 {
		return nil
	}
	p, err := parseStringPool(data, pkgOff+rel)
	if err != nil {
		t.Fatalf("解析 keyStrings 失败: %v", err)
	}
	return p
}

// TestPlaceholderTypeNamesRewritesUnused 是需求 1 的核心判据：
// 未使用 id 的槽位改成 ?<id>，已使用 id 原样，槽位数不变，
// keyStrings 相对偏移与各级 size 自洽，entry 的 key 索引逐条不变。
func TestPlaceholderTypeNamesRewritesUnused(t *testing.T) {
	fx := keyFixture{
		utf8Keys:  true,
		typeNames: []string{"anim", "string", "legacy_name", "layout"},
		keys:      []string{"k0", "k1", "k2", "k3"},
		entries: map[int][]int{
			1: {0},
			2: {1},
			4: {2}, // id 3 没有任何 Type/TypeSpec → 未使用
		},
		global: []string{"res/layout/main.xml", "hello"},
	}
	raw := buildKeyTable(t, fx)
	beforePkg := firstPkgOff(t, raw)
	beforeType := pkgTypePool(t, raw, beforePkg)
	beforeKey := pkgKeyPool(t, raw, beforePkg)
	beforeEntries := entryKeysOf(t, raw)
	beforeGlobal, err := Parse(raw)
	if err != nil {
		t.Fatalf("原始表解析失败: %v", err)
	}

	out, st, err := PlaceholderTypeNames(raw)
	if err != nil {
		t.Fatalf("PlaceholderTypeNames 失败: %v", err)
	}
	if st.Packages != 1 || st.Slots != 4 || st.Unused != 1 || st.Placeholders != 1 {
		t.Fatalf("统计不符: %+v（期望 packages=1 slots=4 unused=1 placeholders=1）", st)
	}
	if !reflect.DeepEqual(st.IDs, []int{3}) {
		t.Fatalf("未使用 id 列表应为 [3]，实际 %v", st.IDs)
	}

	afterPkg := firstPkgOff(t, out)
	afterType := pkgTypePool(t, out, afterPkg)
	if want := []string{"anim", "string", "?3", "layout"}; !reflect.DeepEqual(afterType.strings, want) {
		t.Fatalf("typeStrings 不符:\n实际 %q\n期望 %q", afterType.strings, want)
	}
	if len(afterType.strings) != len(beforeType.strings) {
		t.Fatal("槽位数变化（必须只改内容、不增删）")
	}
	if afterType.utf8 != beforeType.utf8 {
		t.Fatal("池编码被改变")
	}
	// 已使用的类型名必须原样（改了就破坏 getIdentifier）。
	for _, i := range []int{0, 1, 3} {
		if afterType.strings[i] != beforeType.strings[i] {
			t.Fatalf("已使用类型名被改动（索引 %d）: %q → %q", i, beforeType.strings[i], afterType.strings[i])
		}
	}
	// 全局池与 keyStrings 内容不变；entry 的 key 索引逐条不变。
	afterGlobal, err := Parse(out)
	if err != nil {
		t.Fatalf("改写后表解析失败: %v", err)
	}
	if !reflect.DeepEqual(beforeGlobal.Strings(), afterGlobal.Strings()) {
		t.Fatal("全局字符串池被改动")
	}
	afterKey := pkgKeyPool(t, out, afterPkg)
	if afterKey == nil || !reflect.DeepEqual(beforeKey.strings, afterKey.strings) {
		t.Fatalf("keyStrings 内容被改动: %q → %v", beforeKey.strings, afterKey)
	}
	if !reflect.DeepEqual(beforeEntries, entryKeysOf(t, out)) {
		t.Fatal("entry 的 key 索引发生变化")
	}
	// 包块 size 与表头 size 自洽：单包夹具下包块应正好到表尾。
	psz := int(binary.LittleEndian.Uint32(out[afterPkg+4:]))
	if afterPkg+psz != len(out) {
		t.Fatalf("包块 size 未同步: %d + %d ≠ %d", afterPkg, psz, len(out))
	}
	if int(binary.LittleEndian.Uint32(out[4:])) != len(out) {
		t.Fatal("表头 size 未同步")
	}
	// keyStrings 相对偏移随 typeStrings 增长平移后仍指向同一内容。
	if got := int(binary.LittleEndian.Uint32(out[afterPkg+276:])); afterPkg+got+poolHeaderLen > len(out) {
		t.Fatalf("keyStrings 偏移未同步: %d", got)
	}
	if delta := afterType.size - beforeType.size; len(out)-len(raw) != delta {
		t.Fatalf("表长变化 %d ≠ typeStrings 池增量 %d", len(out)-len(raw), delta)
	}

	// 幂等：对产物再跑一次应无占位名可写、逐字节不变。
	out2, st2, err := PlaceholderTypeNames(out)
	if err != nil {
		t.Fatalf("第二次执行失败: %v", err)
	}
	if !bytes.Equal(out, out2) {
		t.Fatal("第二次执行改动了字节（已 ?<id> 的槽位不应重复改写）")
	}
	if st2.Placeholders != 0 || st2.Unused != 1 {
		t.Fatalf("第二次统计异常: %+v", st2)
	}
	t.Logf("占位名改写 %d 个（id %v），池 %d → %d 字节", st.Placeholders, st.IDs, beforeType.size, afterType.size)
}

// TestPlaceholderTypeNamesTypeIdOffset 校验 typeIdOffset 参与槽位 → id 映射。
func TestPlaceholderTypeNamesTypeIdOffset(t *testing.T) {
	raw := buildValueTable(t, valueFixture{
		utf8Global:   true,
		global:       []string{"v0", "v1"},
		typeNames:    []string{"two_name", "legacy_three", "four_name"},
		keys:         []string{"k0", "k1"},
		typeIDOffset: 1, // 槽位 0/1/2 ↔ typeId 2/3/4
		entries: map[int][]valEntry{
			2: {{key: 0, dataType: 0x10, data: 1}}, // slot 0
			4: {{key: 1, dataType: 0x10, data: 2}}, // slot 2；slot 1 ↔ id 3 未使用
		},
	})

	out, st, err := PlaceholderTypeNames(raw)
	if err != nil {
		t.Fatalf("失败: %v", err)
	}
	if !reflect.DeepEqual(st.IDs, []int{3}) || st.Placeholders != 1 {
		t.Fatalf("统计不符: %+v（期望 ids=[3] placeholders=1）", st)
	}
	after := pkgTypePool(t, out, firstPkgOff(t, out))
	if want := []string{"two_name", "?3", "four_name"}; !reflect.DeepEqual(after.strings, want) {
		t.Fatalf("typeStrings 不符: %q", after.strings)
	}
}

// TestPlaceholderTypeNamesNoop 校验无未使用 id、或未使用槽位已是 ?<id> 时
// 是逐字节空操作，同时统计如实报告识别到的未使用 id。
func TestPlaceholderTypeNamesNoop(t *testing.T) {
	// 全部使用：无改动。
	used := buildKeyTable(t, keyFixture{
		utf8Keys:  true,
		typeNames: []string{"anim", "string"},
		keys:      []string{"k0", "k1"},
		entries:   map[int][]int{1: {0}, 2: {1}},
	})
	out, st, err := PlaceholderTypeNames(used)
	if err != nil {
		t.Fatalf("失败: %v", err)
	}
	if !bytes.Equal(used, out) || st.Unused != 0 || st.Placeholders != 0 {
		t.Fatalf("全部使用时不应改动: %+v", st)
	}

	// 未使用但已经是 ?2（样本的 ?15 形态）：统计识别，但不改字节。
	already := buildKeyTable(t, keyFixture{
		utf8Keys:  true,
		typeNames: []string{"anim", "?2"},
		keys:      []string{"k0"},
		entries:   map[int][]int{1: {0}},
	})
	out2, st2, err := PlaceholderTypeNames(already)
	if err != nil {
		t.Fatalf("失败: %v", err)
	}
	if !bytes.Equal(already, out2) {
		t.Fatal("已是 ?<id> 的槽位不应产生字节改动")
	}
	if st2.Unused != 1 || st2.Placeholders != 0 || !reflect.DeepEqual(st2.IDs, []int{2}) {
		t.Fatalf("统计不符: %+v（期望 unused=1 placeholders=0 ids=[2]）", st2)
	}
}

// TestPlaceholderTypeNamesErrors 校验结构性错误被明确拒绝。
func TestPlaceholderTypeNamesErrors(t *testing.T) {
	if _, _, err := PlaceholderTypeNames([]byte{1, 2, 3}); err == nil {
		t.Error("过短输入应报错")
	}
	raw := buildKeyTable(t, keyFixture{
		utf8Keys:  true,
		typeNames: []string{"anim", "string"},
		keys:      []string{"k0"},
		entries:   map[int][]int{1: {0}},
	})
	bad := append([]byte(nil), raw...)
	bad[0] = 0x03
	if _, _, err := PlaceholderTypeNames(bad); err == nil {
		t.Error("非资源表应报错")
	}
	bad = append([]byte(nil), raw...)
	binary.LittleEndian.PutUint32(bad[4:], uint32(len(bad)+8))
	if _, _, err := PlaceholderTypeNames(bad); err == nil {
		t.Error("表长度越界应报错")
	}
	bad = append([]byte(nil), raw...)
	pkg := firstPkgOff(t, bad)
	binary.LittleEndian.PutUint32(bad[pkg+268:], 0x00ffffff) // typeStrings 偏移越界
	if _, _, err := PlaceholderTypeNames(bad); err == nil {
		t.Error("typeStrings 偏移越界应报错")
	}
}

// TestPlaceholderTypeNamesRealArsc 用真实产物验证：改写后表仍可完整解析，
// 未使用槽位全部是 ?<id>，已使用的类型名原样，且对产物再跑一次逐字节不变。
func TestPlaceholderTypeNamesRealArsc(t *testing.T) {
	data := realArscBytes(t)
	if data == nil {
		t.Skip("没有可用的真实 resources.arsc")
	}
	before, err := Parse(data)
	if err != nil {
		t.Fatalf("解析真实资源表失败: %v", err)
	}
	out, st, err := PlaceholderTypeNames(data)
	if err != nil {
		t.Fatalf("PlaceholderTypeNames(real) 失败: %v", err)
	}
	after, err := Parse(out)
	if err != nil {
		t.Fatalf("改写后真实资源表解析失败: %v", err)
	}
	if !reflect.DeepEqual(before.Strings(), after.Strings()) {
		t.Fatal("全局字符串池被改动")
	}
	// 每个包：未使用 id 的槽位名必须是 ?<id>，已使用的保持原名。
	hdr, total, _ := tableSpan(out)
	checked := 0
	err = forEachTopChunk(out, hdr, total, func(tp uint16, p, sz int) bool {
		if tp != typePackage {
			return true
		}
		phdr := int(binary.LittleEndian.Uint16(out[p+2:]))
		if phdr < pkgTypeStringsOff+4 {
			return true
		}
		pool := pkgTypePool(t, out, p)
		used, ok := usedTypeIDs(out, p+phdr, p+sz)
		if !ok {
			return true
		}
		idOff := 0
		if phdr >= pkgTypeIdOffsetOff+4 {
			idOff = int(binary.LittleEndian.Uint32(out[p+pkgTypeIdOffsetOff:]))
		}
		for i, s := range pool.strings {
			id := i + 1 + idOff
			if used[id] {
				continue
			}
			checked++
			if s != "?"+strconv.Itoa(id) {
				t.Fatalf("包（偏移 %d）未使用槽位 %d 的名字不是 ?%d: %q", p, i, id, s)
			}
		}
		return true
	})
	if err != nil {
		t.Fatalf("遍历失败: %v", err)
	}
	if st.Unused != checked {
		t.Fatalf("统计 Unused=%d 与实际识别 %d 不符", st.Unused, checked)
	}
	// 幂等。
	out2, st2, err := PlaceholderTypeNames(out)
	if err != nil {
		t.Fatalf("第二次执行失败: %v", err)
	}
	if !bytes.Equal(out, out2) || st2.Placeholders != 0 {
		t.Fatalf("对产物再跑一次不幂等: placeholders=%d", st2.Placeholders)
	}
	t.Logf("真实资源表：%d 个包，未使用槽位 %d 个（其中本次改写 %d 个），全局池条目 %d 条不变",
		st.Packages, st.Unused, st.Placeholders, len(before.Strings()))
}
