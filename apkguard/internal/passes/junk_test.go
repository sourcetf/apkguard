package passes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"apkguard/internal/axml"
	"apkguard/internal/config"
	"apkguard/internal/pipeline"
	"apkguard/internal/zipx"
)

// TestJunkXMLIsParsableAXML 钉住「垃圾 XML 必须是能被解析的真 AXML」。
//
// 参考样本的顶层垃圾 .xml 每一个都是 388 字节的合法 AXML；而早期实现只塞了
// 8 字节头（magic + headerSize + chunkSize），扫描器一次解析失败就把整类丢弃，
// 反而更快定位到真文件。垃圾条目的价值在于**消耗分析者的时间**，因此它必须：
//   - 能被 axml.Parse 解析出元素（不是坏文件）；
//   - 有像样的体积（不是一眼假的最小头）。
//
// 例外一：kotlin/ 下的 24 条伪装条目与样本一致，是 176 字节共用载荷（样本实测
// 也不是 AXML），它们是「目录白名单」手法的诱饵，不参与本契约。
//
// 例外二：A10 顶层族里约 8% 的「毒化」条目（a10PoisonedKey 记录）刻意把字符串池
// 头部字段高位加盐，对齐参考样本——这类条目按**身份**跳过解析，改用纯数值判据
// 断言「严格解析器必然失败」，绝不容忍「解析失败但没被标记」的漏网条目。
func TestJunkXMLIsParsableAXML(t *testing.T) {
	art := newArtifact(zipx.NewStored("AndroidManifest.xml", []byte{0}))
	opts := &config.Options{
		Enabled:      map[config.FeatureID]bool{"A10": true},
		Seed:         "junk",
		JunkTopCount: 20,
		JunkDirCount: 20,
		JunkDirDepth: 6,
	}
	if err := (&junkEntries{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A10 执行失败: %v", err)
	}
	poisoned := a10Poisoned(art)

	checked, poisonChecked, minSize := 0, 0, 1<<30
	for _, e := range art.Entries() {
		n := e.NameString()
		if !bytes.HasSuffix([]byte(n), []byte(".xml")) || n == "AndroidManifest.xml" {
			continue
		}
		if strings.HasPrefix(n, "kotlin/") {
			// 与样本一致的目录伪装族：内容是共用载荷而非 AXML。
			continue
		}
		data, err := e.Data()
		if err != nil {
			t.Fatalf("读取 %s 失败: %v", n, err)
		}
		if class, ok := poisoned[n]; ok {
			if err := strictAXMLHeaderErr(data); err == nil {
				t.Fatalf("%s 被标记为毒化（类别 %d），但严格解析判据没有失败", n, class)
			}
			poisonChecked++
			continue
		}
		f, err := axml.Parse(data)
		if err != nil {
			t.Fatalf("%s 不是可解析的 AXML: %v（垃圾 XML 必须能通过解析，否则会被扫描器整类丢弃）", n, err)
		}
		if len(f.Elements) == 0 {
			t.Fatalf("%s 解析成功但没有任何元素，仍会被判定为「空壳」", n)
		}
		// 语义也要对：元素名非空、属性带正确的 android 命名空间。
		// 下标算错时 aapt2 仍能「解析」（它只是按索引取字符串），但取到的是
		// 乱七八糟的名字——那种垃圾 XML 一眼就能看出是生成的。
		el := f.Elements[0]
		if el.Name == "" || el.Name == "TextView" {
			t.Fatalf("%s 的元素名解析成了 %q（应为随机根元素名）", n, el.Name)
		}
		for _, a := range el.Attrs {
			if a.NSName != "http://schemas.android.com/apk/res/android" {
				t.Fatalf("%s 的属性 %q 命名空间为 %q，应为 android 命名空间 URI（下标错位）",
					n, a.Name, a.NSName)
			}
			if a.Name == "" {
				t.Fatalf("%s 存在空属性名", n)
			}
		}
		if len(data) < minSize {
			minSize = len(data)
		}
		checked++
	}
	if checked < 10 {
		t.Fatalf("只生成了 %d 个垃圾 XML，覆盖不足", checked)
	}
	if poisonChecked == 0 {
		t.Fatal("A10 未生成毒化子集（约 8% 的条目应被池头高位加盐并记录进 Artifact.Shared）")
	}
	if minSize < 200 {
		t.Fatalf("最小的垃圾 XML 只有 %d 字节，太小容易被一眼识破（参考样本是 388 字节）", minSize)
	}
	t.Logf("已生成 %d 个可解析的垃圾 AXML（另 %d 个毒化条目按身份跳过、严格判据均失败），最小 %d 字节",
		checked, poisonChecked, minSize)
}

// strictAXMLHeaderErr 用纯数值判据模拟「严格解析器必失败」。
//
// 不做任何解析或大内存分配：只读字符串池头部声明值。任何一项成立，严格实现
// （按声明值预分配偏移表 / 直接按声明 size 读取）都会崩溃或耗尽内存：
//   - 池 size 远超实际数据（会按声明值读取/分配）；
//   - stringCount 超过 2^20 上限（会按声明值分配）；
//   - flags 出现已知位以外的未知位（严格校验器会拒绝）。
func strictAXMLHeaderErr(data []byte) error {
	if len(data) < 28 {
		return fmt.Errorf("AXML 过短 %d 字节", len(data))
	}
	declaredPool := binary.LittleEndian.Uint32(data[12:])
	count := binary.LittleEndian.Uint32(data[16:])
	flags := binary.LittleEndian.Uint32(data[24:])
	if declaredPool > uint32(len(data)-8)*1000 {
		return fmt.Errorf("声明的池大小 %d 超过实际数据 %d 的 1000 倍", declaredPool, len(data)-8)
	}
	if count > 1<<20 {
		return fmt.Errorf("声明的字符串数 %d 超过 2^20 上限", count)
	}
	if flags&^uint32(0x101) != 0 {
		return fmt.Errorf("字符串池 flags 含未知位 0x%x", flags)
	}
	return nil
}

// TestJunkAXMLSaltPlacement 钉住「同一模板 + 每条恰好 1 个盐字节」。
//
// A10 顶层假 AXML 全部由 a10AXMLTemplate 生成的唯一 388 字节模板复制而来；
// 盐必须落在字符串池数据区（不碰 chunk 头、长度前缀与 NUL），因此条目仍可解析
// 且语义不变；(位置,取值) 由 used 集合去重，保证 sha256 两两不同。
func TestJunkAXMLSaltPlacement(t *testing.T) {
	const seed = "saltplace"
	tpl := a10AXMLTemplate(seed)
	if len(tpl) < a10TopAXMLTarget {
		t.Fatalf("模板应不少于目标 %d 字节，实际 %d", a10TopAXMLTarget, len(tpl))
	}
	if !bytes.Equal(tpl, a10AXMLTemplate(seed)) {
		t.Fatal("同 seed 两次生成的模板不一致")
	}

	used := map[uint64]bool{}
	salted := append([]byte(nil), tpl...)
	if !saltAXMLOneByte(newRand(seed+"/salt"), salted, used) {
		t.Fatal("模板池数据区没有可加盐的 ASCII 内容")
	}
	diff := diffOffsets(tpl, salted)
	if len(diff) != 1 {
		t.Fatalf("盐应恰好改写 1 个字节，实际 %d 个（位置 %v）", len(diff), diff)
	}
	off := diff[0]
	dataStart := 8 + int(binary.LittleEndian.Uint32(salted[20:]))
	poolEnd := 8 + int(binary.LittleEndian.Uint32(salted[12:]))
	if off < dataStart || off >= poolEnd {
		t.Fatalf("盐字节偏移 %d 不在池数据区 [%d,%d)", off, dataStart, poolEnd)
	}
	bf, err := axml.Parse(tpl)
	if err != nil {
		t.Fatalf("模板本应可解析: %v", err)
	}
	sf, err := axml.Parse(salted)
	if err != nil {
		t.Fatalf("加盐后应仍可解析: %v", err)
	}
	if bf.Elements[0].Name != sf.Elements[0].Name {
		t.Fatalf("盐改动了元素名：%q → %q", bf.Elements[0].Name, sf.Elements[0].Name)
	}
	// 用同一随机源再产一条：即便随机源给出相同的 (位置,取值)，used 去重也必须
	// 让第二条与第一条不同——这是「sha256 两两不同」的机制保证。
	salted2 := append([]byte(nil), tpl...)
	if !saltAXMLOneByte(newRand(seed+"/salt"), salted2, used) {
		t.Fatal("第二次加盐失败")
	}
	if bytes.Equal(salted, salted2) {
		t.Fatal("两条副本的盐字节相同（used 去重未生效）")
	}
	if _, err := axml.Parse(salted2); err != nil {
		t.Fatalf("第二条加盐副本应仍可解析: %v", err)
	}
}

// diffOffsets 返回 a 与 b 中不同字节的偏移；长度不同时返回 nil。
func diffOffsets(a, b []byte) []int {
	if len(a) != len(b) {
		return nil
	}
	var out []int
	for i := range a {
		if a[i] != b[i] {
			out = append(out, i)
		}
	}
	return out
}

// poisonFieldRange 返回毒化类别对应的 4 字节字段在文件里的 [lo,hi) 区间。
func poisonFieldRange(class int) (int, int) {
	switch class {
	case poisonStringCount:
		return 16, 20
	case poisonFlags:
		return 24, 28
	default: // poisonPoolSize
		return 12, 16
	}
}

// TestPoisonAXMLStringPoolFormula 钉住三类毒化字段的「只改高位、保留低位」公式，
// 并确认毒化只落在对应字段的 4 个字节上、字段值必然改变（不存在假毒化）。
func TestPoisonAXMLStringPoolFormula(t *testing.T) {
	tpl := a10AXMLTemplate("unit")
	cases := []struct {
		class int
		field string
		lo    int
		hi    int
	}{
		{poisonStringCount, "stringCount", 16, 20},
		{poisonFlags, "flags", 24, 28},
		{poisonPoolSize, "poolSize", 12, 16},
	}
	for _, c := range cases {
		data := append([]byte(nil), tpl...)
		field, orig, salted := poisonAXMLStringPool(newRand("poison"), data, c.class)
		if field != c.field {
			t.Fatalf("类别 %d 应毒化 %s，实际 %s", c.class, c.field, field)
		}
		if salted == orig {
			t.Fatalf("类别 %d（%s）毒化后字段值未变化（假毒化）", c.class, c.field)
		}
		switch c.class {
		case poisonStringCount:
			if salted&0xffff != orig&0xffff {
				t.Fatalf("stringCount 低位未保留：0x%08x → 0x%08x", orig, salted)
			}
			if salted>>16 == 0 || salted <= orig {
				t.Fatalf("stringCount 高位盐为零或值未增大：0x%08x → 0x%08x", orig, salted)
			}
			if salted <= 1<<20 {
				t.Fatalf("声明的 stringCount 0x%08x 未超过 2^20", salted)
			}
		case poisonFlags:
			if salted&0xff != orig&0xff {
				t.Fatalf("flags 低 8 位未保留：0x%08x → 0x%08x", orig, salted)
			}
			if salted>>8 == 0 {
				t.Fatalf("flags 高位盐为零：0x%08x → 0x%08x", orig, salted)
			}
			if salted&0x100 == 0 {
				t.Fatalf("flags 的 UTF-8 位（bit8）应保留：0x%08x", salted)
			}
			if salted&^uint32(0x101) == 0 {
				t.Fatalf("flags 0x%08x 未置起任何已知位之外的位，严格校验器不会拒绝", salted)
			}
		case poisonPoolSize:
			if salted&0xfffff != orig&0xfffff {
				t.Fatalf("poolSize 低 20 位未保留：0x%08x → 0x%08x", orig, salted)
			}
			if salted>>20 == 0 || salted <= orig {
				t.Fatalf("poolSize 高位盐为零或值未增大：0x%08x → 0x%08x", orig, salted)
			}
		}
		changed := diffOffsets(tpl, data)
		if len(changed) == 0 || len(changed) > 4 {
			t.Fatalf("类别 %d 改动了 %d 个字节（应只在 4 字节字段内且至少 1 个）", c.class, len(changed))
		}
		for _, i := range changed {
			if i < c.lo || i >= c.hi {
				t.Fatalf("类别 %d 改动了目标字段之外的字节 offset=%d", c.class, i)
			}
		}
		if err := strictAXMLHeaderErr(data); err == nil {
			t.Fatalf("类别 %d 毒化后严格解析判据应失败", c.class)
		}
		t.Logf("毒化样例：%s 0x%08x → 0x%08x（高位加盐、低位保留）", field, orig, salted)
	}
}

// TestJunkTopAXMLUniqueAndPoisoned 是 A10 顶层族的决定性判据（规模对齐样本 884）：
//
//   - 884 条假 AXML 全部是同一份 388 字节模板的副本、各自恰好 1 个盐字节，
//     sha256 两两不同（防内容哈希聚类/白名单）；
//   - 毒化条数 = max(1, N*8%)，且三类池头字段都有覆盖；
//   - 毒化条目逐条解码：三类字段高位非零、低位与真实值一致（恢复低位/已知位后
//     能正常解析），毒化只影响目标字段 + 那个盐字节；
//   - 非毒化条目全部能被 axml.Parse 正常解析；
//   - 毒化条目只用**纯数值判据**证明严格解析器必然失败（声明计数/长度远超实际、
//     flags 出现已知位之外的位），绝不对毒化字节做解析（避免按声明值分配大内存）。
func TestJunkTopAXMLUniqueAndPoisoned(t *testing.T) {
	art := newArtifact(zipx.NewStored("AndroidManifest.xml", []byte{0}))
	opts := &config.Options{
		Enabled:      map[config.FeatureID]bool{"A10": true},
		Seed:         "a10poison",
		JunkTopCount: 884,
		JunkDirDepth: 1,
	}
	if err := (&junkEntries{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A10 执行失败: %v", err)
	}
	poisoned := a10Poisoned(art)
	tpl := a10AXMLTemplate(opts.Seed)
	saltLo := 8 + int(binary.LittleEndian.Uint32(tpl[20:])) // 盐区间：池数据区
	saltHi := 8 + int(binary.LittleEndian.Uint32(tpl[12:]))

	top := 0
	hashes := map[[32]byte]string{}
	for _, e := range art.Entries() {
		n := e.NameString()
		if strings.Contains(n, "/") || !strings.HasSuffix(n, ".xml") || isASCII(n) {
			continue // 只看 A10 的顶层非 ASCII 假 AXML
		}
		top++
		data := entryData(t, e)
		if len(data) != len(tpl) {
			t.Fatalf("顶层假 AXML %q 长 %d 字节，应为同一模板的 %d 字节", n, len(data), len(tpl))
		}
		sum := sha256.Sum256(data)
		if prev, dup := hashes[sum]; dup {
			t.Fatalf("假 AXML %q 与 %q 的 sha256 相同（盐未生效）", n, prev)
		}
		hashes[sum] = n
		if _, isPoison := poisoned[n]; !isPoison {
			// 非毒化：与模板恰好差池数据区内的 1 个盐字节。
			diff := diffOffsets(tpl, data)
			if len(diff) != 1 || diff[0] < saltLo || diff[0] >= saltHi {
				t.Fatalf("%q 与模板的差异 %v 不是「池数据区内的恰好 1 个盐字节」", n, diff)
			}
			if _, err := axml.Parse(data); err != nil {
				t.Fatalf("非毒化条目 %q 应可解析: %v", n, err)
			}
		}
	}
	if top != 884 {
		t.Fatalf("顶层假 AXML 应为 884 条，实际 %d", top)
	}
	if len(hashes) != top {
		t.Fatalf("sha256 去重后只剩 %d 条", len(hashes))
	}

	wantPoison := 884 * 8 / 100 // 70
	if len(poisoned) != wantPoison {
		t.Fatalf("毒化条数应为 max(1, N*8%%) = %d，实际 %d", wantPoison, len(poisoned))
	}
	classSeen := map[int]int{}
	for name, class := range poisoned {
		classSeen[class]++
		e := pipeline.Find(art, name)
		if e == nil {
			t.Fatalf("毒化条目 %q 不在产物中", name)
		}
		data := entryData(t, e)
		// 毒化条目 = 模板 + 1 个盐字节 + 目标字段的 1~4 个高位字节。
		fieldLo, fieldHi := poisonFieldRange(class)
		diff := diffOffsets(tpl, data)
		if len(diff) < 2 || len(diff) > 5 {
			t.Fatalf("毒化条目 %q 与模板差 %d 个字节（应为 1 个盐字节 + 1~4 字节字段）: %v", name, len(diff), diff)
		}
		salts := 0
		for _, off := range diff {
			switch {
			case off >= fieldLo && off < fieldHi:
			case off >= saltLo && off < saltHi:
				salts++
			default:
				t.Fatalf("毒化条目 %q 改动了字段与池数据区之外的字节 offset=%d", name, off)
			}
		}
		if salts != 1 {
			t.Fatalf("毒化条目 %q 的盐字节数为 %d，应为 1: %v", name, salts, diff)
		}
		if err := strictAXMLHeaderErr(data); err == nil {
			t.Fatalf("毒化条目 %q（类别 %d）严格判据应失败", name, class)
		}
		switch class {
		case poisonStringCount:
			got := binary.LittleEndian.Uint32(data[16:])
			if got>>16 == 0 {
				t.Fatalf("%q：stringCount 高位盐为零（0x%08x）", name, got)
			}
			if got&0xffff != 17 { // 模板固定 17 个字符串
				t.Fatalf("%q：stringCount 低位 %d 应为真实值 17", name, got&0xffff)
			}
			if got <= 1<<20 || got <= 17*1000 {
				t.Fatalf("%q：声明的 stringCount %d 未远超真实的 17 个字符串（严格解析器会按声明值分配）", name, got)
			}
			fixed := append([]byte(nil), data...)
			binary.LittleEndian.PutUint32(fixed[16:], got&0xffff)
			if _, err := axml.Parse(fixed); err != nil {
				t.Fatalf("%q：恢复低位后应可解析（低位即真实值）: %v", name, err)
			}
		case poisonFlags:
			got := binary.LittleEndian.Uint32(data[24:])
			if got>>8 == 0 {
				t.Fatalf("%q：flags 高位盐为零（0x%08x）", name, got)
			}
			if got&0xff != 0 { // 模板真实 flags 为 0x100，低 8 位为 0
				t.Fatalf("%q：flags 低 8 位 %#x 应保留真实值的低 8 位 0", name, got&0xff)
			}
			if got&0x100 == 0 {
				t.Fatalf("%q：flags 的 UTF-8 位（bit8）应保留", name)
			}
			if got == 0x100 || got&^uint32(0x101) == 0 {
				t.Fatalf("%q：flags 0x%08x 未置起任何已知位之外的位，严格校验器不会拒绝", name, got)
			}
			// 我们的解析器只读 UTF-8 位，未知高位不影响它；严格校验器的拒绝
			// 已由上面的 strictAXMLHeaderErr（纯数值）证明。
			fixed := append([]byte(nil), data...)
			binary.LittleEndian.PutUint32(fixed[24:], got&0x101) // 清掉盐位、保留 UTF-8 位
			if _, err := axml.Parse(fixed); err != nil {
				t.Fatalf("%q：清除高位盐后应可解析: %v", name, err)
			}
		case poisonPoolSize:
			got := binary.LittleEndian.Uint32(data[12:])
			if got>>20 == 0 {
				t.Fatalf("%q：poolSize 高位盐为零（0x%08x）", name, got)
			}
			if uint64(got) <= uint64(len(data))*1000 {
				t.Fatalf("%q：声明的池大小 %d 未远超实际数据 %d", name, got, len(data))
			}
			low := got & 0xfffff
			if low < 28+17*4 || int(low) > len(data)-8 {
				t.Fatalf("%q：池大小低 20 位 %d 不是真实池大小（应在 [%d,%d]）", name, low, 28+17*4, len(data)-8)
			}
			fixed := append([]byte(nil), data...)
			binary.LittleEndian.PutUint32(fixed[12:], low)
			if _, err := axml.Parse(fixed); err != nil {
				t.Fatalf("%q：恢复低位后应可解析（低位即真实值）: %v", name, err)
			}
		default:
			t.Fatalf("毒化条目 %q 的类别 %d 非法", name, class)
		}
	}
	for class := 0; class < 3; class++ {
		if classSeen[class] == 0 {
			t.Fatalf("毒化类别 %d 未覆盖（三类池头字段必须都出现）: %v", class, classSeen)
		}
	}
	t.Logf("A10 顶层：%d 条 sha256 全不同，毒化 %d 条（stringCount=%d/flags=%d/poolSize=%d）",
		top, len(poisoned), classSeen[poisonStringCount], classSeen[poisonFlags], classSeen[poisonPoolSize])
}

// TestJunkTopAXMLDeterministic 钉住顶层盐/毒化子集同 seed 完全可复现：
// 两次运行必须得到相同的毒化名单（名字 → 类别）、相同的 A10 统计与逐条字节；
// 同时钉住小 N 时毒化条数 = max(1, N*8%) 的下限。
func TestJunkTopAXMLDeterministic(t *testing.T) {
	const seed = "a10det"
	build := func(n int) *pipeline.Artifact {
		art := newArtifact(zipx.NewStored("AndroidManifest.xml", []byte{0}))
		opts := &config.Options{
			Enabled:      map[config.FeatureID]bool{"A10": true},
			Seed:         seed,
			JunkTopCount: n,
			JunkDirDepth: 1,
		}
		if err := (&junkEntries{}).Run(context.Background(), art, opts); err != nil {
			t.Fatalf("A10 执行失败: %v", err)
		}
		return art
	}
	a, b := build(40), build(40)
	pa, pb := a10Poisoned(a), a10Poisoned(b)
	if len(pa) != 3 { // max(1, 40*8%) = 3
		t.Fatalf("N=40 的毒化条数应为 max(1, N*8%%) = 3，实际 %d", len(pa))
	}
	if len(pa) != len(pb) {
		t.Fatalf("两次运行的毒化条数不同：%d vs %d", len(pa), len(pb))
	}
	for n, c := range pa {
		if pb[n] != c {
			t.Fatalf("毒化名单不可复现：%q 类别 %d vs %d", n, c, pb[n])
		}
	}
	for _, e := range a.Entries() {
		n := e.NameString()
		if strings.Contains(n, "/") || !strings.HasSuffix(n, ".xml") || isASCII(n) {
			continue
		}
		eb := pipeline.Find(b, n)
		if eb == nil {
			t.Fatalf("第二次运行缺少条目 %q", n)
		}
		if !bytes.Equal(entryData(t, e), entryData(t, eb)) {
			t.Fatalf("条目 %q 的字节不可复现", n)
		}
	}
	if a.Stats["A10.top"] != b.Stats["A10.top"] || a.Stats["A10.top_poisoned"] != b.Stats["A10.top_poisoned"] {
		t.Fatalf("A10 统计不可复现：%v vs %v", a.Stats, b.Stats)
	}
	if got := len(a10Poisoned(build(10))); got != 1 { // max(1, 10*8%) = 1
		t.Fatalf("N=10 的毒化条数应为 max(1, N*8%%) = 1，实际 %d", got)
	}
	t.Logf("A10 顶层 N=40：毒化 %d 条，同 seed 两次运行毒化名单与逐条字节一致", len(pa))
}

// TestJunkHasDeepAliasDirs 钉住「同名单目录深层路径」的存在。
//
// 样本用 76 层同名目录制造超长路径，触发解包工具的路径长度/递归问题。
func TestJunkHasDeepAliasDirs(t *testing.T) {
	art := newArtifact(zipx.NewStored("AndroidManifest.xml", []byte{0}))
	opts := &config.Options{
		Enabled:      map[config.FeatureID]bool{"A10": true},
		Seed:         "deep",
		JunkDirCount: 20, // 每 10 条配 1 条同名深层目录
		JunkDirDepth: 4,
	}
	if err := (&junkEntries{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A10 执行失败: %v", err)
	}
	maxDepth, maxLen := 0, 0
	for _, e := range art.Entries() {
		n := e.NameString()
		if !bytes.HasPrefix([]byte(n), []byte("assets/")) {
			continue
		}
		seg := bytes.Split([]byte(n), []byte("/"))
		if len(seg)-2 > maxDepth {
			maxDepth = len(seg) - 2
		}
		if len(n) > maxLen {
			maxLen = len(n)
		}
	}
	if maxDepth < 40 {
		t.Fatalf("最深的目录只有 %d 层，未达到「同名深层路径」的规模（参考样本 76 层）", maxDepth)
	}
	t.Logf("已生成同名深层目录：最深 %d 层、最长路径 %d 字节", maxDepth, maxLen)
}

// TestPathAttackHasSeparatorVariants 钉住 A12 的分隔符变体。
//
// 只生成 "/随机名" 会漏掉「混合分隔符 / 重复斜杠 / .9.png 伪装」这几类形态，
// 而它们正是不同工具规范化行为分叉的地方（参考样本就用了 `\/`、`/////`、`.9.png`）。
func TestPathAttackHasSeparatorVariants(t *testing.T) {
	art := newArtifact(zipx.NewStored("AndroidManifest.xml", []byte{0}))
	opts := &config.Options{
		Enabled:     map[config.FeatureID]bool{"A12": true},
		Seed:        "atk",
		ZipAtkCount: 20,
	}
	if err := (&zipPathAttack{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A12 执行失败: %v", err)
	}
	var hasBackslash, hasRepeatedSlash, hasNinePatch, hasDotDot bool
	for _, e := range art.Entries() {
		n := e.NameString()
		if !bytes.HasPrefix([]byte(n), []byte("/")) {
			continue
		}
		if bytes.Contains([]byte(n), []byte(`\/`)) {
			hasBackslash = true
		}
		if bytes.Contains([]byte(n), []byte("////")) {
			hasRepeatedSlash = true
		}
		if bytes.HasSuffix([]byte(n), []byte(".9.png")) {
			hasNinePatch = true
		}
		if bytes.Contains([]byte(n), []byte("/../")) {
			hasDotDot = true
		}
	}
	if !hasBackslash || !hasRepeatedSlash || !hasNinePatch || !hasDotDot {
		t.Fatalf("路径攻击形态不全：混合分隔符=%v 重复斜杠=%v .9.png=%v 点段=%v",
			hasBackslash, hasRepeatedSlash, hasNinePatch, hasDotDot)
	}
	t.Log("路径攻击已覆盖：混合分隔符、重复斜杠、.9.png 伪装、点段穿越")
}
