package arsc

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"io"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"apkguard/internal/axml"
)

// ---- 合成含 keyStrings 的完整资源表 ----
//
// 真实资源表的结构是：表头 → 全局字符串池 → 包块（包头 → typeStrings 池
// → keyStrings 池 → TypeSpec/Type 块）。这里按同样布局构造最小样本，
// 让 keyStrings 随机化的解析与重建走的是与真实产物一致的路径。

type keyFixture struct {
	utf8Keys  bool
	typeNames []string
	keys      []string
	// entries：typeId → 该类型的条目依次引用的 key 索引。
	entries map[int][]int
	global  []string
}

func buildKeyTable(t *testing.T, f keyFixture) []byte {
	t.Helper()
	global := axml.EncodeStringPool(f.global, true)
	typePool := axml.EncodeStringPool(f.typeNames, false)
	keyPool := axml.EncodeStringPool(f.keys, f.utf8Keys)

	var sub []byte
	for id := 1; id <= len(f.typeNames); id++ {
		keyIdxs := f.entries[id]
		if len(keyIdxs) == 0 {
			continue
		}
		// TypeSpec：prod 不读它，仅为让包内结构与真实表一致。
		ts := make([]byte, 16+4*len(keyIdxs))
		binary.LittleEndian.PutUint16(ts[0:], 0x0202)
		binary.LittleEndian.PutUint16(ts[2:], 16)
		binary.LittleEndian.PutUint32(ts[4:], uint32(len(ts)))
		ts[8] = byte(id)
		binary.LittleEndian.PutUint32(ts[12:], uint32(len(keyIdxs)))
		sub = append(sub, ts...)

		const hdr = 84
		es := hdr + 4*len(keyIdxs)
		size := es + 8*len(keyIdxs)
		tc := make([]byte, size)
		binary.LittleEndian.PutUint16(tc[0:], 0x0201)
		binary.LittleEndian.PutUint16(tc[2:], hdr)
		binary.LittleEndian.PutUint32(tc[4:], uint32(size))
		tc[8] = byte(id)
		binary.LittleEndian.PutUint32(tc[12:], uint32(len(keyIdxs)))
		binary.LittleEndian.PutUint32(tc[16:], uint32(es))
		for i, ki := range keyIdxs {
			binary.LittleEndian.PutUint32(tc[hdr+4*i:], uint32(8*i))
			eo := es + 8*i
			binary.LittleEndian.PutUint16(tc[eo:], 8)            // ResTable_entry.size
			binary.LittleEndian.PutUint16(tc[eo+2:], 2)          // FLAG_PUBLIC
			binary.LittleEndian.PutUint32(tc[eo+4:], uint32(ki)) // key 索引
		}
		sub = append(sub, tc...)
	}

	pkg := make([]byte, 288+len(typePool)+len(keyPool)+len(sub))
	binary.LittleEndian.PutUint16(pkg[0:], 0x0200)
	binary.LittleEndian.PutUint16(pkg[2:], 288)
	binary.LittleEndian.PutUint32(pkg[4:], uint32(len(pkg)))
	binary.LittleEndian.PutUint32(pkg[8:], 0x7f)
	binary.LittleEndian.PutUint32(pkg[268:], 288)                       // typeStrings
	binary.LittleEndian.PutUint32(pkg[276:], uint32(288+len(typePool))) // keyStrings
	binary.LittleEndian.PutUint32(pkg[284:], 0)                         // typeIdOffset
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

// firstKeyPool 解析表中第一个包的 keyStrings 池。
func firstKeyPool(t *testing.T, data []byte) *stringPool {
	t.Helper()
	p := 12
	globalSize := int(binary.LittleEndian.Uint32(data[p+4:]))
	p += globalSize
	if binary.LittleEndian.Uint16(data[p:]) != 0x0200 {
		t.Fatalf("第一个顶层块不是包块: %#x", binary.LittleEndian.Uint16(data[p:]))
	}
	keyOff := int(binary.LittleEndian.Uint32(data[p+276:]))
	pool, err := parseStringPool(data, p+keyOff)
	if err != nil {
		t.Fatalf("解析 keyStrings 失败: %v", err)
	}
	return pool
}

// entryKey 是一个条目的 key 引用（用于逐条比对改写前后不变）。
type entryKey struct {
	TypeID, Index, Key int
}

// entryKeysOf 解析表中全部 Type 的 (typeId, entry 下标, key 索引)。
func entryKeysOf(t *testing.T, data []byte) []entryKey {
	t.Helper()
	hdr := int(binary.LittleEndian.Uint16(data[2:]))
	total := int(binary.LittleEndian.Uint32(data[4:]))
	var out []entryKey
	for p := hdr; p+8 <= total; {
		tp := binary.LittleEndian.Uint16(data[p:])
		sz := int(binary.LittleEndian.Uint32(data[p+4:]))
		if sz < 8 || p+sz > total {
			t.Fatalf("顶层块长度非法: type=%#x size=%d", tp, sz)
		}
		if tp == 0x0200 {
			phdr := int(binary.LittleEndian.Uint16(data[p+2:]))
			pend := p + sz
			for q := p + phdr; q+8 <= pend; {
				st := binary.LittleEndian.Uint16(data[q:])
				ssz := int(binary.LittleEndian.Uint32(data[q+4:]))
				if ssz < 8 || q+ssz > pend {
					t.Fatalf("包内子块长度非法: type=%#x size=%d", st, ssz)
				}
				if st == 0x0201 {
					id := int(data[q+8])
					cnt := int(binary.LittleEndian.Uint32(data[q+12:]))
					es := int(binary.LittleEndian.Uint32(data[q+16:]))
					th := int(binary.LittleEndian.Uint16(data[q+2:]))
					for i := 0; i < cnt; i++ {
						o := int(binary.LittleEndian.Uint32(data[q+th+4*i:]))
						if o == 0xffffffff {
							continue
						}
						ki := int(binary.LittleEndian.Uint32(data[q+es+o+4:]))
						out = append(out, entryKey{TypeID: id, Index: i, Key: ki})
					}
				}
				q += ssz
			}
		}
		p += sz
	}
	return out
}

var (
	plainKeyRE    = regexp.MustCompile(`^[a-z0-9]{6,14}$`)
	prefixedKeyRE = regexp.MustCompile(`^vx_[a-z]_[a-z0-9]{6,10}$`)
)

// TestRandomizeKeysKeepsAndShape 校验核心契约：保留规则、新名形态、
// entry 的 key 索引与「资源 ID → key」映射逐条不变、全局字符串池不受影响。
func TestRandomizeKeysKeepsAndShape(t *testing.T) {
	keys := []string{
		"app_name",                 // 0: DEX 引用 → 保留
		"ic_launcher",              // 1: 可改
		"hello",                    // 2: 可改
		"ab",                       // 3: 太短 → 保留
		"Widget.AppCompat.Toolbar", // 4: 点分库名 → 保留
		"actionBarDivider",         // 5: 无点号、不在 DEX → 可改
		"名字",                       // 6: 非 ASCII → 保留
		"keep_me",                  // 7: DEX 引用 → 保留
		"res/x",                    // 8: 含 / → 保留
		"short",                    // 9: 可改
	}
	fx := keyFixture{
		utf8Keys:  true,
		typeNames: []string{"id", "layout", "string", "color"},
		keys:      keys,
		entries: map[int][]int{
			1: {0},
			2: {2},
			3: {1, 3, 4, 5, 6, 7, 8, 9},
		},
		global: []string{"res/layout/main.xml", "hello"},
	}
	raw := buildKeyTable(t, fx)
	beforeEntries := entryKeysOf(t, raw)
	beforeGlobal, err := Parse(raw)
	if err != nil {
		t.Fatalf("原始表解析失败: %v", err)
	}

	keep := map[string]bool{"app_name": true, "keep_me": true}
	out, st, err := RandomizeKeys(raw, KeyRenameOptions{Seed: "shape", Keep: keep})
	if err != nil {
		t.Fatalf("随机化失败: %v", err)
	}

	// 统计口径：10 条中 2 条 DEX 保留、4 条形状保留、4 条改写。
	if st.Total != 10 || st.KeptDex != 2 || st.KeptShape != 4 || st.Renamed != 4 || st.Kept != 6 {
		t.Fatalf("统计不符: %+v（期望 total=10 dex=2 shape=4 renamed=4 kept=6）", st)
	}
	if st.Packages != 1 {
		t.Fatalf("包数不符: %d", st.Packages)
	}

	after := firstKeyPool(t, out)
	if len(after.strings) != len(keys) {
		t.Fatalf("key 数量变化: %d → %d", len(keys), len(after.strings))
	}
	if after.utf8 != true {
		t.Fatal("原 UTF-8 池被改成 UTF-16")
	}
	// 保留项逐条原位不动。
	for _, i := range []int{0, 3, 4, 6, 7, 8} {
		if after.strings[i] != keys[i] {
			t.Fatalf("应保留原名（索引 %d）: %q → %q", i, keys[i], after.strings[i])
		}
	}
	// 改写项形态正确且全表唯一。
	seen := map[string]bool{}
	for _, s := range after.strings {
		if seen[s] {
			t.Fatalf("新名重复: %q", s)
		}
		seen[s] = true
	}
	for _, i := range []int{1, 2, 5, 9} {
		s := after.strings[i]
		if !plainKeyRE.MatchString(s) && !prefixedKeyRE.MatchString(s) {
			t.Fatalf("新名形态不符（索引 %d）: %q", i, s)
		}
		if s == keys[i] {
			t.Fatalf("索引 %d 未改写: %q", i, s)
		}
	}

	// 表仍合法；entry 的 key 索引与「类型/条目 → key」映射逐条不变。
	again, err := Parse(out)
	if err != nil {
		t.Fatalf("改写后表解析失败: %v", err)
	}
	if !reflect.DeepEqual(beforeGlobal.Strings(), again.Strings()) {
		t.Fatalf("全局字符串池被改动:\n前 %q\n后 %q", beforeGlobal.Strings(), again.Strings())
	}
	if !reflect.DeepEqual(beforeGlobal.ResPaths(), again.ResPaths()) {
		t.Fatalf("res/ 路径集合被改动: %q → %q", beforeGlobal.ResPaths(), again.ResPaths())
	}
	if got := entryKeysOf(t, out); !reflect.DeepEqual(beforeEntries, got) {
		t.Fatalf("entry 的 key 索引发生变化:\n前 %+v\n后 %+v", beforeEntries, got)
	}
	t.Logf("改写 %d 条：%v", st.Renamed, after.strings)
}

// TestRandomizeKeysPrefixMapping 校验约 13% 的类型前缀子集：
// 比例落在合理区间，且每个前缀都与该 key 所属 entry 的 typeId 对应。
func TestRandomizeKeysPrefixMapping(t *testing.T) {
	typeNames := []string{"string", "color", "dimen", "integer", "bool", "layout"}
	wantPrefix := map[int]string{1: "vx_s_", 2: "vx_c_", 3: "vx_d_", 4: "vx_i_", 5: "vx_b_", 6: "vx_x_"}

	const perType = 120
	var keys []string
	entries := map[int][]int{}
	keyOwner := map[int]int{} // key 索引 → typeId
	for id := 1; id <= len(typeNames); id++ {
		for j := 0; j < perType; j++ {
			ki := len(keys)
			keys = append(keys, "key_name_"+string(rune('a'+id-1))+string(rune('a'+j%26))+string(rune('a'+j/26)))
			entries[id] = append(entries[id], ki)
			keyOwner[ki] = id
		}
	}
	raw := buildKeyTable(t, keyFixture{utf8Keys: true, typeNames: typeNames, keys: keys, entries: entries})
	out, st, err := RandomizeKeys(raw, KeyRenameOptions{Seed: "prefix"})
	if err != nil {
		t.Fatalf("随机化失败: %v", err)
	}
	if st.Renamed != len(keys) {
		t.Fatalf("应全部改写: %d/%d", st.Renamed, len(keys))
	}
	after := firstKeyPool(t, out)
	prefixed := 0
	seenPrefix := map[string]bool{}
	for _, ek := range entryKeysOf(t, out) {
		s := after.strings[ek.Key]
		if !strings.HasPrefix(s, "vx_") {
			if !plainKeyRE.MatchString(s) {
				t.Fatalf("新名形态不符: %q", s)
			}
			continue
		}
		prefixed++
		if !prefixedKeyRE.MatchString(s) {
			t.Fatalf("带前缀新名形态不符: %q", s)
		}
		want := wantPrefix[keyOwner[ek.Key]]
		if !strings.HasPrefix(s, want) {
			t.Fatalf("前缀与 typeId 不符: key=%d type=%d 名=%q 期望前缀 %q",
				ek.Key, keyOwner[ek.Key], s, want)
		}
		seenPrefix[want] = true
	}
	ratio := float64(prefixed) / float64(len(keys))
	if ratio < 0.05 || ratio > 0.25 {
		t.Fatalf("前缀比例 %d/%d=%.3f 偏离约 13%%", prefixed, len(keys), ratio)
	}
	// 6 种类型 × 120 条，13% 比例下「某类型一条前缀都没有」的概率 ~1e-7，
	// 因此要求 6 种前缀都出现过是稳定判据（同时证明映射逐类型正确）。
	if len(seenPrefix) != len(wantPrefix) {
		t.Fatalf("前缀种类不全: 实际 %v，期望覆盖 %v", seenPrefix, wantPrefix)
	}
	if st.Prefixed != prefixed {
		t.Fatalf("统计的 Prefixed=%d 与实际 %d 不符", st.Prefixed, prefixed)
	}
	t.Logf("前缀 %d/%d=%.1f%%，覆盖 %v", prefixed, len(keys), ratio*100, seenPrefix)
}

// TestRandomizeKeysDeterministic 校验同 seed 可复现、不同 seed 结果不同。
func TestRandomizeKeysDeterministic(t *testing.T) {
	keys := make([]string, 40)
	entries := map[int][]int{}
	for i := range keys {
		keys[i] = "name_number_" + strings.Repeat("x", i%7) + string(rune('a'+i%26))
		entries[1] = append(entries[1], i)
	}
	raw := buildKeyTable(t, keyFixture{utf8Keys: true, typeNames: []string{"string"}, keys: keys, entries: entries})

	a, _, err := RandomizeKeys(raw, KeyRenameOptions{Seed: "det"})
	if err != nil {
		t.Fatalf("第一次失败: %v", err)
	}
	b, _, err := RandomizeKeys(raw, KeyRenameOptions{Seed: "det"})
	if err != nil {
		t.Fatalf("第二次失败: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("同 seed 两次产出不一致")
	}
	c, _, err := RandomizeKeys(raw, KeyRenameOptions{Seed: "det2"})
	if err != nil {
		t.Fatalf("第三次失败: %v", err)
	}
	if bytes.Equal(a, c) {
		t.Fatal("不同 seed 产出相同（随机性失效）")
	}

	// 对已改写的产物再跑一次：ARSC 层不做「已随机化」判定（那需要猜测名字
	// 是否是随机串，不可靠），幂等由 Pass 层的 Shared 标记保证（见
	// internal/passes 的 TestArscKeysIdempotent）。这里只要求重复改写仍然
	// 是语义安全的：表合法、key 数量与 entry 映射不变、新名形态一致。
	a2, st2, err := RandomizeKeys(a, KeyRenameOptions{Seed: "det"})
	if err != nil {
		t.Fatalf("对产物再跑一次失败: %v", err)
	}
	if _, err := Parse(a2); err != nil {
		t.Fatalf("二次改写后表解析失败: %v", err)
	}
	if len(firstKeyPool(t, a2).strings) != len(keys) {
		t.Fatal("二次改写改变了 key 数量")
	}
	if !reflect.DeepEqual(entryKeysOf(t, a), entryKeysOf(t, a2)) {
		t.Fatal("二次改写改变了 entry 的 key 索引")
	}
	if st2.Renamed != len(keys) {
		t.Fatalf("二次改写统计异常: %+v", st2)
	}
}

// TestRandomizeKeysUTF16 校验 UTF-16 keyStrings 池同样可解析、可改写。
func TestRandomizeKeysUTF16(t *testing.T) {
	keys := []string{"app_name", "ic_launcher", "main_text", "hello_world", "ab", "名字"}
	raw := buildKeyTable(t, keyFixture{
		utf8Keys:  false,
		typeNames: []string{"string", "bool"},
		keys:      keys,
		entries: map[int][]int{
			1: {0, 1, 2},
			2: {3, 4, 5},
		},
	})
	out, st, err := RandomizeKeys(raw, KeyRenameOptions{Seed: "u16", Keep: map[string]bool{"app_name": true}})
	if err != nil {
		t.Fatalf("随机化失败: %v", err)
	}
	if st.Renamed != 3 || st.KeptDex != 1 || st.KeptShape != 2 {
		t.Fatalf("统计不符: %+v", st)
	}
	pool := firstKeyPool(t, out)
	if pool.utf8 {
		t.Fatal("UTF-16 池被改成 UTF-8")
	}
	if pool.strings[0] != "app_name" || pool.strings[4] != "ab" || pool.strings[5] != "名字" {
		t.Fatalf("保留项不符: %q", pool.strings)
	}
	for _, i := range []int{1, 2, 3} {
		if !plainKeyRE.MatchString(pool.strings[i]) && !prefixedKeyRE.MatchString(pool.strings[i]) {
			t.Fatalf("UTF-16 池新名形态不符（索引 %d）: %q", i, pool.strings[i])
		}
	}
	// 逐条比对 entry 映射不变。
	if !reflect.DeepEqual(entryKeysOf(t, raw), entryKeysOf(t, out)) {
		t.Fatal("UTF-16 池改写改变了 entry 的 key 索引")
	}
}

// TestRandomizeKeysNoPackages 校验没有包时是安全的空操作（逐字节返回副本）。
func TestRandomizeKeysNoPackages(t *testing.T) {
	raw := wrapPool(t, []string{"res/a/a.xml", "hello"}, true)
	out, st, err := RandomizeKeys(raw, KeyRenameOptions{Seed: "empty"})
	if err != nil {
		t.Fatalf("失败: %v", err)
	}
	if !bytes.Equal(raw, out) {
		t.Fatal("无包时不应改动字节")
	}
	if st != (KeyRenameStats{}) {
		t.Fatalf("无包时统计应为零: %+v", st)
	}
}

// TestRandomizeKeysErrors 校验结构性错误被明确拒绝。
func TestRandomizeKeysErrors(t *testing.T) {
	fx := keyFixture{
		utf8Keys:  true,
		typeNames: []string{"string"},
		keys:      []string{"app_name", "ic_launcher"},
		entries:   map[int][]int{1: {0, 1}},
	}
	raw := buildKeyTable(t, fx)

	// 非 RES_TABLE。
	if _, _, err := RandomizeKeys([]byte{1, 2, 3}, KeyRenameOptions{}); err == nil {
		t.Error("过短输入应报错")
	}
	bad := append([]byte(nil), raw...)
	bad[0] = 0x03
	if _, _, err := RandomizeKeys(bad, KeyRenameOptions{}); err == nil {
		t.Error("非资源表应报错")
	}
	// 表长度越界。
	bad = append([]byte(nil), raw...)
	binary.LittleEndian.PutUint32(bad[4:], uint32(len(bad)+16))
	if _, _, err := RandomizeKeys(bad, KeyRenameOptions{}); err == nil {
		t.Error("表长度越界应报错")
	}
	// keyStrings 偏移越界。
	bad = append([]byte(nil), raw...)
	pkgOff := 12 + int(binary.LittleEndian.Uint32(raw[16:]))
	binary.LittleEndian.PutUint32(bad[pkgOff+276:], 0x00ffffff)
	if _, _, err := RandomizeKeys(bad, KeyRenameOptions{}); err == nil {
		t.Error("keyStrings 偏移越界应报错")
	}
	// 顶层块长度非法。
	bad = append([]byte(nil), raw...)
	pkgSizeOff := pkgOff + 4
	binary.LittleEndian.PutUint32(bad[pkgSizeOff:], uint32(len(raw))) // 超过表尾
	if _, _, err := RandomizeKeys(bad, KeyRenameOptions{}); err == nil {
		t.Error("块长度越界应报错")
	}
}

// TestRandomizeKeysRealArsc 用仓库固件里的真实 resources.arsc 跑一遍。
//
// 这里 Keep 为空（arsc 层不知道 DEX），因此 testapp 的 4 个条目名应全部
// 被改写，同时资源路径与 entry 映射逐条不变。
func TestRandomizeKeysRealArsc(t *testing.T) {
	const apk = "../../../testdata/sample.apk"
	zr, err := zip.OpenReader(apk)
	if err != nil {
		t.Skipf("样本 APK 不在，跳过: %v", err)
	}
	defer zr.Close()
	var data []byte
	for _, f := range zr.File {
		if f.Name != "resources.arsc" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("读取 resources.arsc 失败: %v", err)
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("读取 resources.arsc 失败: %v", err)
		}
		data = b
	}
	if data == nil {
		t.Skip("样本 APK 里没有 resources.arsc")
	}
	before, err := Parse(data)
	if err != nil {
		t.Fatalf("解析真实 resources.arsc 失败: %v", err)
	}
	beforePool := firstKeyPool(t, data)
	beforeEntries := entryKeysOf(t, data)
	if len(beforePool.strings) == 0 {
		t.Skip("真实资源表没有 keyStrings")
	}

	out, st, err := RandomizeKeys(data, KeyRenameOptions{Seed: "real"})
	if err != nil {
		t.Fatalf("随机化失败: %v", err)
	}
	if st.Renamed+st.Kept != st.Total || st.Total != len(beforePool.strings) {
		t.Fatalf("统计不符: %+v（池内 %d 条）", st, len(beforePool.strings))
	}
	after, err := Parse(out)
	if err != nil {
		t.Fatalf("改写后解析失败: %v", err)
	}
	if !reflect.DeepEqual(before.Strings(), after.Strings()) {
		t.Fatal("全局字符串池被改动")
	}
	if !reflect.DeepEqual(before.ResPaths(), after.ResPaths()) {
		t.Fatal("res/ 路径集合被改动")
	}
	if !reflect.DeepEqual(beforeEntries, entryKeysOf(t, out)) {
		t.Fatal("entry 的 key 索引发生变化")
	}
	afterPool := firstKeyPool(t, out)
	if len(afterPool.strings) != len(beforePool.strings) {
		t.Fatalf("key 数量变化: %d → %d", len(beforePool.strings), len(afterPool.strings))
	}
	changed := 0
	for i, s := range afterPool.strings {
		if s != beforePool.strings[i] {
			changed++
			if !prefixedKeyRE.MatchString(s) && !plainKeyRE.MatchString(s) {
				t.Fatalf("第 %d 条新名形态不符: %q", i, s)
			}
		}
	}
	if changed != st.Renamed {
		t.Fatalf("实际改动 %d 条与统计 %d 不符", changed, st.Renamed)
	}
	t.Logf("真实资源表：keyStrings %d 条，改写 %d 条 / 保留 %d 条（DEX 引用 %d、形状 %d），%d 条带前缀；资源表与 entry 映射逐条不变（%d 字节 → %d 字节）",
		st.Total, st.Renamed, st.Kept, st.KeptDex, st.KeptShape, st.Prefixed, len(data), len(out))
}
