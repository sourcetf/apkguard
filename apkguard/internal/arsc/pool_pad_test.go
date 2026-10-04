package arsc

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"apkguard/internal/axml"
)

// realArscBytes 读取一个真实 APK 里的 resources.arsc；样本不存在时返回 nil。
//
// 优先用开发机上的大样本（池大、引用多、正是本手法的来源），
// 回退到仓库固件 testdata/sample.apk（干净检出也能跑）。
func realArscBytes(t *testing.T) []byte {
	t.Helper()
	for _, apk := range []string{
		filepath.Join("..", "..", "..", "sample.apk"),
		filepath.Join("..", "..", "..", "testdata", "sample.apk"),
	} {
		zr, err := zip.OpenReader(apk)
		if err != nil {
			continue
		}
		for _, f := range zr.File {
			if f.Name != "resources.arsc" {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				continue
			}
			b, err := io.ReadAll(rc)
			rc.Close()
			if err == nil && len(b) > 0 {
				zr.Close()
				return b
			}
		}
		zr.Close()
	}
	return nil
}

// ---- 合成含「字符串值 entry」的完整资源表 ----
//
// 与 keys_test.go 的 buildKeyTable 同布局（表头 → 全局池 → 包头 → typeStrings
// → keyStrings → TypeSpec/Type），额外支持在 entry 里写 Res_value（简单值、
// 复合 map）与 compact entry，用来验证零宽副本的引用收集与追加。

type valMap struct {
	name     uint32
	dataType byte
	data     uint32
}

type valEntry struct {
	key      int
	dataType byte
	data     uint32
	complex  bool
	compact  bool
	maps     []valMap
}

type valueFixture struct {
	utf8Global   bool
	global       []string
	styles       *axml.Styles
	typeNames    []string
	keys         []string
	typeIDOffset int
	// entries：typeId → 该类型的 entry 列表。
	entries map[int][]valEntry
}

func buildValueTable(t *testing.T, f valueFixture) []byte {
	t.Helper()
	var global []byte
	var err error
	if f.styles != nil {
		global, err = axml.EncodeStringPoolWithStyles(f.global, f.utf8Global, f.styles)
		if err != nil {
			t.Fatalf("编码带 style 的全局池失败: %v", err)
		}
	} else {
		global = axml.EncodeStringPool(f.global, f.utf8Global)
	}
	typePool := axml.EncodeStringPool(f.typeNames, false)
	keyPool := axml.EncodeStringPool(f.keys, true)

	var sub []byte
	for id := 1; id <= len(f.typeNames)+f.typeIDOffset; id++ {
		ents := f.entries[id]
		if len(ents) == 0 {
			continue
		}
		ts := make([]byte, 16+4*len(ents))
		binary.LittleEndian.PutUint16(ts[0:], 0x0202)
		binary.LittleEndian.PutUint16(ts[2:], 16)
		binary.LittleEndian.PutUint32(ts[4:], uint32(len(ts)))
		ts[8] = byte(id)
		binary.LittleEndian.PutUint32(ts[12:], uint32(len(ents)))
		sub = append(sub, ts...)

		const hdr = 84
		var body []byte
		offs := make([]uint32, len(ents))
		for i, e := range ents {
			offs[i] = uint32(len(body))
			body = append(body, encodeValEntry(e)...)
		}
		es := hdr + 4*len(ents)
		size := es + len(body)
		tc := make([]byte, size)
		binary.LittleEndian.PutUint16(tc[0:], 0x0201)
		binary.LittleEndian.PutUint16(tc[2:], hdr)
		binary.LittleEndian.PutUint32(tc[4:], uint32(size))
		tc[8] = byte(id)
		binary.LittleEndian.PutUint32(tc[12:], uint32(len(ents)))
		binary.LittleEndian.PutUint32(tc[16:], uint32(es))
		copy(tc[es:], body)
		for i, o := range offs {
			binary.LittleEndian.PutUint32(tc[hdr+4*i:], o)
		}
		sub = append(sub, tc...)
	}

	pkg := make([]byte, 288+len(typePool)+len(keyPool)+len(sub))
	binary.LittleEndian.PutUint16(pkg[0:], 0x0200)
	binary.LittleEndian.PutUint16(pkg[2:], 288)
	binary.LittleEndian.PutUint32(pkg[4:], uint32(len(pkg)))
	binary.LittleEndian.PutUint32(pkg[8:], 0x7f)
	binary.LittleEndian.PutUint32(pkg[268:], 288)
	binary.LittleEndian.PutUint32(pkg[276:], uint32(288+len(typePool)))
	binary.LittleEndian.PutUint32(pkg[284:], uint32(f.typeIDOffset))
	copy(pkg[288:], typePool)
	copy(pkg[288+len(typePool):], keyPool)
	copy(pkg[288+len(typePool)+len(keyPool):], sub)

	out := make([]byte, 12+len(global)+len(pkg))
	binary.LittleEndian.PutUint16(out[0:], 0x0002)
	binary.LittleEndian.PutUint16(out[2:], 12)
	binary.LittleEndian.PutUint32(out[4:], uint32(len(out)))
	copy(out[12:], global)
	copy(out[12+len(global):], pkg)
	return out
}

// encodeValEntry 生成一个 entry 的字节（4 字节对齐）。
func encodeValEntry(e valEntry) []byte {
	if e.compact {
		b := make([]byte, 8)
		binary.LittleEndian.PutUint16(b[0:], uint16(e.key))
		binary.LittleEndian.PutUint16(b[2:], entryFlagCompact|uint16(e.dataType)<<8)
		binary.LittleEndian.PutUint32(b[4:], e.data)
		return b
	}
	if e.complex {
		b := make([]byte, 16+12*len(e.maps))
		binary.LittleEndian.PutUint16(b[0:], 16)
		binary.LittleEndian.PutUint16(b[2:], 2|entryFlagComplex) // PUBLIC|COMPLEX
		binary.LittleEndian.PutUint32(b[4:], uint32(e.key))
		binary.LittleEndian.PutUint32(b[12:], uint32(len(e.maps)))
		for i, m := range e.maps {
			mv := 16 + 12*i
			binary.LittleEndian.PutUint32(b[mv:], m.name)
			binary.LittleEndian.PutUint16(b[mv+4:], 8) // Res_value.size
			b[mv+7] = m.dataType
			binary.LittleEndian.PutUint32(b[mv+8:], m.data)
		}
		return b
	}
	b := make([]byte, 16)
	binary.LittleEndian.PutUint16(b[0:], 8) // ResTable_entry.size
	binary.LittleEndian.PutUint16(b[2:], 2) // PUBLIC
	binary.LittleEndian.PutUint32(b[4:], uint32(e.key))
	binary.LittleEndian.PutUint16(b[8:], 8) // Res_value.size
	b[11] = e.dataType
	binary.LittleEndian.PutUint32(b[12:], e.data)
	return b
}

// globalPoolAt 解析 data 中 offset 处的池。
func globalPoolAt(t *testing.T, data []byte, off int) *stringPool {
	t.Helper()
	p, err := parseStringPool(data, off)
	if err != nil {
		t.Fatalf("解析偏移 %d 的字符串池失败: %v", off, err)
	}
	return p
}

// poolLayout 直接从池字节读出布局字段，独立于 parseStringPool 做自洽性断言。
func poolLayout(t *testing.T, data []byte, off int) (count, stringsStart, stylesStart, size int) {
	t.Helper()
	count = int(binary.LittleEndian.Uint32(data[off+8:]))
	stringsStart = int(binary.LittleEndian.Uint32(data[off+20:]))
	stylesStart = int(binary.LittleEndian.Uint32(data[off+24:]))
	size = int(binary.LittleEndian.Uint32(data[off+4:]))
	return
}

// markerRuns 返回字符串首部/尾部连续零宽标记的数量，以及去掉标记后的核心值。
func markerRuns(s string) (lead, trail int, core string) {
	r := []rune(s)
	i := 0
	for i < len(r) && (r[i] == padLRM || r[i] == padRLM) {
		i++
	}
	lead = i
	j := len(r)
	for j > i && (r[j-1] == padLRM || r[j-1] == padRLM) {
		j--
	}
	trail = len(r) - j
	return lead, trail, string(r[i:j])
}

// padRefFixture 构造「全局池 400 条 + 300 个字符串值 entry」的夹具。
func padRefFixture(t *testing.T) (data []byte, refs []uint32, global []string) {
	t.Helper()
	global = []string{"res/drawable/icon.png"} // 0：路径，应被排除
	for i := 1; i <= 397; i++ {
		global = append(global, fmt.Sprintf("value_%03d", i))
	}
	global = append(global, strings.Repeat("L", 2048)) // 398：超长，应被排除
	global = append(global, "already\u200edone")       // 399：已含标记，应被排除
	keys := make([]string, 0, 303)
	ents := make([]valEntry, 0, 303)
	for i := 0; i < 300; i++ {
		keys = append(keys, fmt.Sprintf("key_%03d", i))
		ents = append(ents, valEntry{key: i, dataType: valueTypeString, data: uint32(1 + i)})
		refs = append(refs, uint32(1+i))
	}
	// 3 条「被引用但应被排除」的值：res/ 路径、超长、已含零宽标记。
	for i, idx := range []uint32{0, 398, 399} {
		keys = append(keys, fmt.Sprintf("excl_%d", i))
		ents = append(ents, valEntry{key: 300 + i, dataType: valueTypeString, data: idx})
		refs = append(refs, idx)
	}
	data = buildValueTable(t, valueFixture{
		utf8Global: true,
		global:     global,
		typeNames:  []string{"string", "color"},
		keys:       keys,
		entries:    map[int][]valEntry{1: ents},
	})
	return data, refs, global
}

// TestPadValuesAppendOnlyAndUnreferenced 是需求 2 的核心判据：
// 追加只发生在池尾、原条目逐字节不变、副本形态符合四种组合之一、
// 没有任何 entry 引用追加区间、同 seed 可复现、池结构自洽。
func TestPadValuesAppendOnlyAndUnreferenced(t *testing.T) {
	data, fixtureRefs, global := padRefFixture(t)
	before := globalPoolAt(t, data, 12)
	beforeCount := len(before.strings)

	out, st, err := PadValues(data, ValuePadOptions{Seed: "pad-core"})
	if err != nil {
		t.Fatalf("PadValues 失败: %v", err)
	}
	if st.PoolBefore != beforeCount {
		t.Fatalf("PoolBefore=%d，期望 %d", st.PoolBefore, beforeCount)
	}
	// 池 400 条 → 自适应上限 100，候选 300+ 条：条数应落在默认 20~40。
	if st.Originals < 20 || st.Originals > 40 {
		t.Fatalf("覆盖逻辑值数 %d 不在默认区间 [20,40]", st.Originals)
	}
	if st.Appended < st.Originals || st.Appended > 3*st.Originals {
		t.Fatalf("追加条数 %d 与覆盖值数 %d 不符（每个值 1~3 条）", st.Appended, st.Originals)
	}
	if st.Single+st.Heavy != st.Appended {
		t.Fatalf("形态统计不平：single=%d heavy=%d appended=%d", st.Single, st.Heavy, st.Appended)
	}
	if st.ExcludedShape != 3 {
		t.Fatalf("路径/超长/已带标记的 3 条引用值应被排除，实际 ExcludedShape=%d", st.ExcludedShape)
	}
	if st.Candidates < 200 {
		t.Fatalf("候选数异常: %d", st.Candidates)
	}

	// 原条目逐字节不变、数量 = 原条目 + 追加。
	after := globalPoolAt(t, out, 12)
	if len(after.strings) != beforeCount+st.Appended {
		t.Fatalf("池条目数 %d ≠ %d + %d", len(after.strings), beforeCount, st.Appended)
	}
	if !reflect.DeepEqual(after.strings[:beforeCount], before.strings) {
		t.Fatal("已有池条目被改动（必须 append-only）")
	}
	if st.PoolAfter != len(after.strings) {
		t.Fatalf("PoolAfter=%d 与实际 %d 不符", st.PoolAfter, len(after.strings))
	}

	// 追加条目的字节形态：1 前缀 / 1 后缀 / 90~100 前缀 + 6 后缀。
	coreSeen := map[string]int{}
	for i, s := range after.strings[beforeCount:] {
		lead, trail, core := markerRuns(s)
		switch {
		case lead == 1 && trail == 0:
		case lead == 0 && trail == 1:
		case lead >= 90 && lead <= 100 && trail == 6:
		default:
			t.Fatalf("追加条目 %d 形态不符（前 %d 后 %d）: %q", i, lead, trail, s)
		}
		if core == "" {
			t.Fatalf("追加条目 %d 没有核心值: %q", i, s)
		}
		if !containsString(global, core) {
			t.Fatalf("追加条目 %d 的核心值不在原池引用值中: %q", i, core)
		}
		coreSeen[core]++
	}
	// 覆盖的每个逻辑值都至少有一条副本（Skipped 才可能缺），
	// 且每个核心在池里至少出现 2 种字节形态。
	for core, n := range coreSeen {
		if n == 0 {
			t.Fatalf("逻辑值 %q 没有副本", core)
		}
		forms := map[string]bool{}
		for _, s := range after.strings {
			if _, _, c := markerRuns(s); c == core {
				forms[s] = true
			}
		}
		if len(forms) < 2 {
			t.Fatalf("逻辑值 %q 在池里仍只有一种字节形态（去重打散失效）", core)
		}
	}

	// 没有任何 entry 引用追加区间：用夹具里已知的引用值 + 独立遍历双重验证。
	maxRef := uint32(0)
	for _, r := range fixtureRefs {
		if r > maxRef {
			maxRef = r
		}
	}
	if int(maxRef) >= beforeCount {
		t.Fatalf("夹具引用越界: %d", maxRef)
	}
	var want []int
	for _, r := range fixtureRefs {
		want = append(want, int(r))
	}
	got := map[int]bool{}
	collectAllStringRefs(t, out, got)
	for idx := range got {
		if idx >= beforeCount {
			t.Fatalf("entry 引用了追加区间（下标 %d ≥ %d）", idx, beforeCount)
		}
	}
	for _, idx := range want {
		if !got[idx] {
			t.Fatalf("改写后丢失了对原值 %d 的引用", idx)
		}
	}

	// 池结构自洽：offset 表单调、stringsStart/size 与布局自洽、表头 size 同步。
	count, stringsStart, stylesStart, size := poolLayout(t, out, 12)
	if count != beforeCount+st.Appended {
		t.Fatalf("stringCount=%d 不符", count)
	}
	if stylesStart != 0 {
		t.Fatalf("无 style 池的 stylesStart 应为 0，实际 %d", stylesStart)
	}
	if stringsStart != poolHeaderLen+count*4 {
		t.Fatalf("stringsStart=%d ≠ %d", stringsStart, poolHeaderLen+count*4)
	}
	offs := make([]uint32, count)
	for i := range offs {
		offs[i] = binary.LittleEndian.Uint32(out[12+poolHeaderLen+4*i:])
	}
	if offs[0] != 0 {
		t.Fatalf("首个字符串偏移应为 0，实际 %d", offs[0])
	}
	for i := 1; i < count; i++ {
		if offs[i] <= offs[i-1] {
			t.Fatalf("偏移表非单调（%d: %d ≤ %d）", i, offs[i], offs[i-1])
		}
	}
	if int(binary.LittleEndian.Uint32(out[4:])) != len(out) {
		t.Fatal("表头 size 与实际长度不符")
	}
	// 池块之后必须正好是包块（单包夹具）：12+size 处是 0x0200，且包块到表尾。
	if off := 12 + size; off+8 > len(out) || binary.LittleEndian.Uint16(out[off:]) != typePackage {
		t.Fatalf("池块 size 与后续包块位置不自洽（池尾偏移 %d）", off)
	} else if psz := int(binary.LittleEndian.Uint32(out[off+4:])); off+psz != len(out) {
		t.Fatalf("包块 size 与表尾不自洽: %d + %d ≠ %d", off, psz, len(out))
	}

	// 同 seed 可复现。
	out2, st2, err := PadValues(data, ValuePadOptions{Seed: "pad-core"})
	if err != nil {
		t.Fatalf("第二次 PadValues 失败: %v", err)
	}
	if !bytes.Equal(out, out2) || !reflect.DeepEqual(st, st2) {
		t.Fatal("同 seed 两次产出不一致")
	}
	// 不同 seed 产出不同（随机性生效）。
	out3, _, err := PadValues(data, ValuePadOptions{Seed: "pad-other"})
	if err != nil {
		t.Fatalf("不同 seed PadValues 失败: %v", err)
	}
	if bytes.Equal(out, out3) {
		t.Fatal("不同 seed 产出相同（随机性失效）")
	}
	t.Logf("追加 %d 条（覆盖 %d 个逻辑值，重前缀 %d / 单标记 %d），池 %d → %d 条",
		st.Appended, st.Originals, st.Heavy, st.Single, st.PoolBefore, st.PoolAfter)
}

// containsString 判断切片里是否有 s（线性扫描，仅测试用）。
func containsString(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// collectAllStringRefs 用生产的遍历器收集全部字符串引用（用于「追加区间未被引用」断言）。
func collectAllStringRefs(t *testing.T, data []byte, out map[int]bool) {
	t.Helper()
	hdr, total, err := tableSpan(data)
	if err != nil {
		t.Fatalf("tableSpan: %v", err)
	}
	err = forEachTopChunk(data, hdr, total, func(typ uint16, p, sz int) bool {
		if typ != typePackage {
			return true
		}
		forEachPackageChunk(data, p, sz, func(ct uint16, q, csz int) {
			if ct == typeType {
				collectTypeStringRefs(data, q, csz, out)
			}
		})
		return true
	})
	if err != nil {
		t.Fatalf("遍历顶层块: %v", err)
	}
}

// TestPadValuesUTF16 校验 UTF-16 全局池同样可追加、可回读。
func TestPadValuesUTF16(t *testing.T) {
	var global []string
	for i := 0; i < 60; i++ {
		global = append(global, fmt.Sprintf("文本值_%02d", i))
	}
	var ents []valEntry
	for i := 0; i < 40; i++ {
		ents = append(ents, valEntry{key: i, dataType: valueTypeString, data: uint32(i)})
	}
	data := buildValueTable(t, valueFixture{
		utf8Global: false,
		global:     global,
		typeNames:  []string{"string"},
		keys:       []string{"k0", "k1"},
		entries:    map[int][]valEntry{1: ents},
	})
	out, st, err := PadValues(data, ValuePadOptions{Seed: "u16", MinValues: 5, MaxValues: 5})
	if err != nil {
		t.Fatalf("PadValues(UTF-16) 失败: %v", err)
	}
	if st.Appended < 5 || st.Appended > 15 {
		t.Fatalf("UTF-16 追加条数异常: %+v", st)
	}
	pool := globalPoolAt(t, out, 12)
	if pool.utf8 {
		t.Fatal("UTF-16 池被改成 UTF-8")
	}
	if !reflect.DeepEqual(pool.strings[:len(global)], global) {
		t.Fatal("UTF-16 池原有条目被改动")
	}
	if len(pool.strings) != len(global)+st.Appended {
		t.Fatalf("UTF-16 池条目数不符: %d", len(pool.strings))
	}
	for _, s := range pool.strings[len(global):] {
		lead, trail, core := markerRuns(s)
		ok := (lead == 1 && trail == 0) || (lead == 0 && trail == 1) ||
			(lead >= 90 && lead <= 100 && trail == 6)
		if !ok || !strings.HasPrefix(core, "文本值_") {
			t.Fatalf("UTF-16 追加条目形态不符: %q（前 %d 后 %d）", s, lead, trail)
		}
	}
}

// TestPadValuesPreservesStyles 校验带 style 的全局池在追加后样式数据原样保留。
func TestPadValuesPreservesStyles(t *testing.T) {
	global := []string{"alpha", "beta", "gamma", "delta"}
	styles := &axml.Styles{
		Count:   2,
		Offsets: []uint32{0, 4},
		Data:    []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04},
	}
	var ents []valEntry
	for i := 0; i < 4; i++ {
		ents = append(ents, valEntry{key: i, dataType: valueTypeString, data: uint32(i)})
	}
	data := buildValueTable(t, valueFixture{
		utf8Global: true,
		global:     global,
		styles:     styles,
		typeNames:  []string{"string"},
		keys:       []string{"k0", "k1"},
		entries:    map[int][]valEntry{1: ents},
	})
	before := globalPoolAt(t, data, 12)
	if before.styles == nil {
		t.Fatal("夹具没有 style 数据")
	}
	out, st, err := PadValues(data, ValuePadOptions{Seed: "styled", MinValues: 2, MaxValues: 2})
	if err != nil {
		t.Fatalf("PadValues(styles) 失败: %v", err)
	}
	if st.Appended == 0 {
		t.Fatal("没有追加任何副本")
	}
	after := globalPoolAt(t, out, 12)
	if after.styles == nil {
		t.Fatal("追加后 style 数据丢失")
	}
	if after.styles.Count != styles.Count || !reflect.DeepEqual(after.styles.Offsets, styles.Offsets) ||
		!bytes.Equal(after.styles.Data, styles.Data) {
		t.Fatalf("style 数据被改动: %+v → %+v", styles, after.styles)
	}
	if !reflect.DeepEqual(after.strings[:len(global)], global) {
		t.Fatal("带 style 的池原有条目被改动")
	}
	// stylesStart 必须仍指向 style 数据。
	if after.styles.Count != int(binary.LittleEndian.Uint32(out[12+12:])) {
		t.Fatal("styleCount 字段不符")
	}
}

// TestPadValuesAdaptiveSmallPool 校验小池按 1/4 自适应下调条数。
func TestPadValuesAdaptiveSmallPool(t *testing.T) {
	global := []string{"v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7"}
	var ents []valEntry
	for i := 0; i < 8; i++ {
		ents = append(ents, valEntry{key: i % 2, dataType: valueTypeString, data: uint32(i)})
	}
	data := buildValueTable(t, valueFixture{
		utf8Global: true,
		global:     global,
		typeNames:  []string{"string"},
		keys:       []string{"k0", "k1"},
		entries:    map[int][]valEntry{1: ents},
	})
	_, st, err := PadValues(data, ValuePadOptions{Seed: "small"})
	if err != nil {
		t.Fatalf("PadValues(small) 失败: %v", err)
	}
	// 池 8 条 → 上限 2 个逻辑值。
	if st.Originals > 2 {
		t.Fatalf("小池未自适应下调: Originals=%d（池 8 条，上限应为 2）", st.Originals)
	}
	if st.Appended == 0 || st.Appended > 6 {
		t.Fatalf("小池追加条数异常: %+v", st)
	}
}

// TestPadValuesComplexCompactAndNonString 校验复杂 map / compact entry 的
// 字符串引用都被收集，非字符串值不参与。
func TestPadValuesComplexCompactAndNonString(t *testing.T) {
	global := make([]string, 20)
	for i := range global {
		global[i] = fmt.Sprintf("g%02d", i)
	}
	ents := []valEntry{
		// 简单字符串值 → 3
		{key: 0, dataType: valueTypeString, data: 3},
		// 复合 map：一个字符串 + 一个整数
		{key: 1, complex: true, maps: []valMap{
			{name: 0x01010000, dataType: valueTypeString, data: 7},
			{name: 0x01010001, dataType: 0x10, data: 42},
		}},
		// compact 字符串值 → 11
		{key: 2, compact: true, dataType: valueTypeString, data: 11},
		// 非字符串（int）→ 不参与
		{key: 3, dataType: 0x10, data: 3},
	}
	data := buildValueTable(t, valueFixture{
		utf8Global: true,
		global:     global,
		typeNames:  []string{"string"},
		keys:       []string{"k0", "k1", "k2", "k3"},
		entries:    map[int][]valEntry{1: ents},
	})
	out, st, err := PadValues(data, ValuePadOptions{Seed: "mixed", MinValues: 3, MaxValues: 3})
	if err != nil {
		t.Fatalf("PadValues(mixed) 失败: %v", err)
	}
	if st.Candidates != 3 {
		t.Fatalf("候选应为 3 条（g03/g07/g11），实际 %d", st.Candidates)
	}
	if st.Originals != 3 {
		t.Fatalf("应选中全部 3 条候选，实际 %d", st.Originals)
	}
	pool := globalPoolAt(t, out, 12)
	cores := map[string]bool{}
	for _, s := range pool.strings[len(global):] {
		_, _, core := markerRuns(s)
		cores[core] = true
	}
	for _, want := range []string{"g03", "g07", "g11"} {
		if !cores[want] {
			t.Fatalf("复杂/compact entry 引用的 %s 未被复制", want)
		}
	}
}

// TestPadValuesNoRefs 校验没有任何字符串引用时是逐字节空操作。
func TestPadValuesNoRefs(t *testing.T) {
	data := buildValueTable(t, valueFixture{
		utf8Global: true,
		global:     []string{"a", "b", "c"},
		typeNames:  []string{"integer"},
		keys:       []string{"k0"},
		entries: map[int][]valEntry{1: {
			{key: 0, dataType: 0x10, data: 1},
			{key: 0, dataType: 0x11, data: 2},
		}},
	})
	out, st, err := PadValues(data, ValuePadOptions{Seed: "norefs"})
	if err != nil {
		t.Fatalf("PadValues(no refs) 失败: %v", err)
	}
	if !bytes.Equal(data, out) {
		t.Fatal("没有字符串引用时不应改动字节")
	}
	if st.Appended != 0 || st.Originals != 0 {
		t.Fatalf("统计应为零: %+v", st)
	}
}

// TestPadValuesErrors 校验结构性错误被明确拒绝。
func TestPadValuesErrors(t *testing.T) {
	if _, _, err := PadValues([]byte{1, 2, 3}, ValuePadOptions{}); err == nil {
		t.Error("过短输入应报错")
	}
	data, _, _ := padRefFixture(t)
	bad := append([]byte(nil), data...)
	bad[0] = 0x03
	if _, _, err := PadValues(bad, ValuePadOptions{}); err == nil {
		t.Error("非资源表应报错")
	}
	bad = append([]byte(nil), data...)
	binary.LittleEndian.PutUint32(bad[4:], uint32(len(bad)+16))
	if _, _, err := PadValues(bad, ValuePadOptions{}); err == nil {
		t.Error("表长度越界应报错")
	}
	bad = append([]byte(nil), data...)
	binary.LittleEndian.PutUint32(bad[12+4:], uint32(len(bad))) // 池 size 越界
	if _, _, err := PadValues(bad, ValuePadOptions{}); err == nil {
		t.Error("池长度越界应报错")
	}
}

// TestPadValuesRealArsc 用仓库固件/开发机样本的真实 resources.arsc 跑一遍：
// 真实产物必须仍可被 internal/arsc 的读路径完整读出，且所有 entry 的值不变。
func TestPadValuesRealArsc(t *testing.T) {
	data := realArscBytes(t)
	if data == nil {
		t.Skip("没有可用的真实 resources.arsc")
	}
	before, err := Parse(data)
	if err != nil {
		t.Fatalf("解析真实资源表失败: %v", err)
	}
	beforeRefs := map[int]bool{}
	collectAllStringRefs(t, data, beforeRefs)
	if len(beforeRefs) == 0 {
		t.Skip("真实资源表没有字符串值引用")
	}
	out, st, err := PadValues(data, ValuePadOptions{Seed: "real"})
	if err != nil {
		t.Fatalf("PadValues(real) 失败: %v", err)
	}
	after, err := Parse(out)
	if err != nil {
		t.Fatalf("改写后真实资源表解析失败: %v", err)
	}
	if len(after.Strings()) != len(before.Strings())+st.Appended {
		t.Fatalf("池条目数不符: %d + %d ≠ %d", len(before.Strings()), st.Appended, len(after.Strings()))
	}
	if !reflect.DeepEqual(after.Strings()[:len(before.Strings())], before.Strings()) {
		t.Fatal("真实表已有池条目被改动")
	}
	afterRefs := map[int]bool{}
	collectAllStringRefs(t, out, afterRefs)
	if !reflect.DeepEqual(beforeRefs, afterRefs) {
		t.Fatalf("entry 的字符串引用集合被改动:\n前 %d 条\n后 %d 条", len(beforeRefs), len(afterRefs))
	}
	// 逐个引用值逐字节等于改写前。
	for idx := range beforeRefs {
		if after.Strings()[idx] != before.Strings()[idx] {
			t.Fatalf("引用值 %d 被改动: %q → %q", idx, before.Strings()[idx], after.Strings()[idx])
		}
	}
	t.Logf("真实资源表：池 %d → %d 条（追加 %d，覆盖 %d 个逻辑值），引用 %d 处逐条不变",
		len(before.Strings()), len(after.Strings()), st.Appended, st.Originals, len(beforeRefs))
}
