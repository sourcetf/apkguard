package passes

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"apkguard/internal/axml"
	"apkguard/internal/config"
	"apkguard/internal/pipeline"
	"apkguard/internal/zipx"
)

// ---- A10/A12/A14 垃圾条目族测试 ----
//
// 钉住与参考样本同级的「成族设计」：族 A 共用 176B 载荷（A10 畸形族 + A12 路径
// 攻击）、族 B 全空格深目录、族 C 真资源路径下的合法 AXML、族 D kotlin/ 伪装；
// 以及名字族（4hex 近重名、空格名、伪装构件名）与 A14 的三段时间戳。

// runJunkPasses 构造一个只含 classes.dex 的产物并依次跑 A10、A12。
func runJunkPasses(t *testing.T, seed string, top, dirs, depth, meta, atk int) *pipeline.Artifact {
	t.Helper()
	art := newArtifact(zipx.NewStored("classes.dex", []byte("dex\n035\x00")))
	opts := &config.Options{
		// E1 显式启用：重名族在签名场景下本就会跳过，这里只测内容族。
		Enabled:       map[config.FeatureID]bool{"A10": true, "A12": true, "E1": true},
		Seed:          seed,
		JunkTopCount:  top,
		JunkDirCount:  dirs,
		JunkDirDepth:  depth,
		JunkMetaCount: meta,
		ZipAtkCount:   atk,
	}
	if err := (&junkEntries{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A10 执行失败: %v", err)
	}
	if err := (&zipPathAttack{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A12 执行失败: %v", err)
	}
	return art
}

// entryData 读取条目内容，失败即 Fatal。
func entryData(t *testing.T, e *zipx.Entry) []byte {
	t.Helper()
	data, err := e.Data()
	if err != nil {
		t.Fatalf("读取 %s 失败: %v", e.NameString(), err)
	}
	return data
}

// TestJunkSharedPayloadFamily 钉住族 A：A10 的畸形/近重名族与 A12 的路径攻击
// 共用**同一份** 176 字节随机载荷（样本 323 条共用载荷的分布里，绝对路径 84、
// META-INF/ 35、classes.dex/ 32、resources.arsc/ 31、AndroidManifest.xml/ 28
// 都属于这一族）。内容哈希聚类会先命中这一大族，从而漏掉内容各异的其他族——
// 这正是样本的设计意图，我们复刻它。
func TestJunkSharedPayloadFamily(t *testing.T) {
	const seed = "fam"
	art := runJunkPasses(t, seed, 5, 10, 4, 40, 60)

	payload := sharedJunkPayload(art, seed)
	if len(payload) != junkPayloadSize || junkPayloadSize != 176 {
		t.Fatalf("共用载荷应为 176 字节，实际 %d", len(payload))
	}

	shared, prefixHave := 0, 0
	prefixTotal := 0
	for _, e := range art.Entries() {
		data := entryData(t, e)
		if bytes.Equal(data, payload) {
			shared++
		}
		for _, p := range junkPathPrefixes {
			if strings.HasPrefix(e.NameString(), p) {
				prefixTotal++
				if bytes.Equal(data, payload) {
					prefixHave++
				}
			}
		}
	}
	if shared < 100 {
		t.Fatalf("族 A 只有 %d 条，样本量级为 323（要求 ≥100）", shared)
	}
	if prefixTotal != 60 || prefixHave != 60 {
		t.Fatalf("A12 前缀滥用条目 %d 条，其中 %d 条使用共用载荷，应全部使用", prefixTotal, prefixHave)
	}
	// 绝对路径条目（A12 另一种路径攻击）也应在族 A 内。
	absShared, absTotal := 0, 0
	for _, e := range art.Entries() {
		if strings.HasPrefix(e.NameString(), "/") {
			absTotal++
			if bytes.Equal(entryData(t, e), payload) {
				absShared++
			}
		}
	}
	if absTotal != 60 || absShared != absTotal {
		t.Fatalf("绝对路径条目 %d 条，其中 %d 条使用共用载荷，应全部使用", absTotal, absShared)
	}
	// 同族条目的 CRC 必须完全一致（样本 323 条 CRC 统一 0x9422BC80 的对应物）。
	var crc uint32
	for _, e := range art.Entries() {
		if bytes.Equal(entryData(t, e), payload) {
			crc = e.CRC32
			break
		}
	}
	if crc == 0 {
		t.Fatal("未找到族 A 条目")
	}
	t.Logf("族 A：%d 条共用同一份 %d 字节载荷（CRC 0x%08X），其中 A12 前缀 %d + 绝对路径 %d",
		shared, len(payload), crc, prefixHave, absShared)
}

// TestJunkNoTrailingSlashEntries 钉住 A10/A12 不产出「以 / 结尾」的条目。
//
// 旧实现注入 META-INF/ 与 META-INF/sub/ 两个目录形态却带 176 字节数据；
// 参考样本 2418 个条目里目录条目为 0，且个别解包工具对「有内容的目录条目」
// 行为不一致。改名后（META-INF、META-INF/sub）仍必须留在 176B 共用载荷族内，
// 精确重名保持 0，核心文件保持唯一。
func TestJunkNoTrailingSlashEntries(t *testing.T) {
	const seed = "nodir"
	art := runJunkPasses(t, seed, 20, 30, 5, 30, 40)
	payload := sharedJunkPayload(art, seed)

	seen := map[string]int{}
	for _, e := range art.Entries() {
		name := e.NameString()
		seen[name]++
		if strings.HasSuffix(name, "/") || strings.HasSuffix(name, `\`) {
			t.Fatalf("产物存在以分隔符结尾的目录形态条目 %q", name)
		}
	}
	for name, n := range seen {
		if n != 1 {
			t.Fatalf("条目名 %q 出现 %d 次（精确重名必须为 0）", name, n)
		}
	}
	if seen["classes.dex"] != 1 {
		t.Fatalf("核心条目 classes.dex 必须保持唯一，实际 %d 份", seen["classes.dex"])
	}
	for _, name := range []string{"META-INF", "META-INF/sub"} {
		e := pipeline.Find(art, name)
		if e == nil {
			t.Fatalf("改名后的畸形条目 %q 缺失", name)
		}
		if !bytes.Equal(entryData(t, e), payload) {
			t.Fatalf("畸形条目 %q 应保留 176B 共用载荷", name)
		}
	}
}

// TestJunkSpaceFamily 钉住族 B：深目录（随机名深目录与同名深路径）内容为
// 清一色 0x20、长度 80~400——样本 837 条空格文件，deflate 后仅 5~8 字节。
func TestJunkSpaceFamily(t *testing.T) {
	art := runJunkPasses(t, "space", 0, 40, 6, 0, 1)

	tmpCount, aliasCount := 0, 0
	for _, e := range art.Entries() {
		name := e.NameString()
		isDeep := strings.HasSuffix(name, ".tmp") && strings.Contains(name, "/")
		isAlias := strings.HasPrefix(name, "assets/") && strings.Count(name, "/") >= 30
		if !isDeep && !isAlias {
			continue
		}
		if isDeep {
			tmpCount++
		} else {
			aliasCount++
		}
		data := entryData(t, e)
		if len(data) < 80 || len(data) > 400 {
			t.Fatalf("%s 的空格文件长度 %d，应在 80~400", name, len(data))
		}
		for i, b := range data {
			if b != 0x20 {
				t.Fatalf("%s 第 %d 字节为 0x%02x，应为 0x20（样本深目录内容全是空格）", name, i, b)
			}
		}
	}
	if tmpCount != 40 {
		t.Fatalf("随机深目录条目应为 40，实际 %d", tmpCount)
	}
	if aliasCount == 0 {
		t.Fatal("缺少同名深层路径（assets/ 下 60+ 层）条目")
	}
	t.Logf("族 B：空格文件 %d 条随机深目录 + %d 条同名深路径，全部为 0x20（80~400B）", tmpCount, aliasCount)
}

// TestJunkResPathAXML 钉住族 C：把真资源源文件名当目录名（res/values/<真名>.xml
// 后接 `\`/`/` 混排与随机扩展名），内容是**合法可解析的 AXML**（样本 res/ 下
// 85+ 条畸形路径的对应物）。
func TestJunkResPathAXML(t *testing.T) {
	art := runJunkPasses(t, "resaxml", 0, 0, 1, 0, 0)

	added := 0
	hasBackslash, hasRepeatedSlash, hasNinePatch := false, false, false
	for _, e := range art.Entries() {
		name := e.NameString()
		if !strings.HasPrefix(name, "res/values/") {
			continue
		}
		added++
		if strings.Contains(name, `\`) {
			hasBackslash = true
		}
		if strings.Contains(name, "///") {
			hasRepeatedSlash = true
		}
		if strings.HasSuffix(name, ".9.png") {
			hasNinePatch = true
		}
		// 新增族的硬约束：非空、非目录条目、无 . / .. 段。
		if !safeJunkPath(name) {
			t.Fatalf("族 C 路径 %q 违反硬约束（空段 / 点段 / 目录条目）", name)
		}
		f, err := axml.Parse(entryData(t, e))
		if err != nil {
			t.Fatalf("族 C 条目 %q 不是可解析的 AXML: %v", name, err)
		}
		if len(f.Elements) == 0 || f.Elements[0].Name == "" {
			t.Fatalf("族 C 条目 %q 解析后没有元素", name)
		}
	}
	if added < 32 {
		t.Fatalf("族 C 只生成了 %d 条（16 个真资源名 × 3 形态 = 48）", added)
	}
	if !hasBackslash || !hasRepeatedSlash || !hasNinePatch {
		t.Fatalf("族 C 形态不全：反斜杠=%v 重复斜杠=%v .9.png=%v", hasBackslash, hasRepeatedSlash, hasNinePatch)
	}
	t.Logf("族 C：真资源路径畸形变体 %d 条（内容均为可解析 AXML，覆盖 \\ 混排 / 重复斜杠 / .9.png）", added)
}

// TestJunkKotlinFamily 钉住族 D：kotlin/<词>/<词>.<xml|bin|png> 共 24 条
// （样本 kotlin/ 31 条里 24 条假货），内容与族 A 共用同一份载荷。
func TestJunkKotlinFamily(t *testing.T) {
	const seed = "kotlin"
	art := runJunkPasses(t, seed, 0, 0, 1, 0, 0)
	payload := sharedJunkPayload(art, seed)

	n := 0
	exts := map[string]bool{"xml": false, "bin": false, "png": false}
	for _, e := range art.Entries() {
		name := e.NameString()
		if !strings.HasPrefix(name, "kotlin/") {
			continue
		}
		n++
		if strings.Count(name, "/") != 2 {
			t.Fatalf("kotlin/ 条目 %q 不是 kotlin/<词>/<词>.<ext> 形态", name)
		}
		ext := name[strings.LastIndexByte(name, '.')+1:]
		if _, ok := exts[ext]; !ok {
			t.Fatalf("kotlin/ 条目 %q 的扩展名 %q 不在 {xml,bin,png}", name, ext)
		}
		exts[ext] = true
		if !bytes.Equal(entryData(t, e), payload) {
			t.Fatalf("kotlin/ 条目 %q 的内容不是族 A 的共用载荷", name)
		}
	}
	if n < 12 {
		t.Fatalf("kotlin/ 伪装条目只有 %d 条，样本为 24（要求 ≥12）", n)
	}
	for ext, seen := range exts {
		if !seen {
			t.Fatalf("kotlin/ 族缺少 .%s 扩展名条目", ext)
		}
	}
	t.Logf("族 D：kotlin/ 伪装 %d 条，内容全部为 %dB 共用载荷", n, len(payload))
}

// TestJunkHexSuffixNamesUnique 钉住 4 位 hex 近重名族：至少 10 条，精确名字互不
// 相同（样本用 4 位随机 hex 做后缀去重，如 META-INF///.xml629c）。
func TestJunkHexSuffixNamesUnique(t *testing.T) {
	art := runJunkPasses(t, "hex", 0, 0, 1, 0, 0)

	isHex := func(b byte) bool {
		return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f')
	}
	seen := map[string]bool{}
	count := 0
	for _, e := range art.Entries() {
		name := e.NameString()
		for _, base := range junkHexSuffixBases {
			suffix, ok := strings.CutPrefix(name, base)
			if !ok || len(suffix) != 4 {
				continue
			}
			allHex := true
			for i := 0; i < len(suffix); i++ {
				if !isHex(suffix[i]) {
					allHex = false
					break
				}
			}
			if !allHex {
				continue
			}
			if seen[name] {
				t.Fatalf("4hex 后缀条目名重复: %q", name)
			}
			seen[name] = true
			count++
		}
	}
	if count < 10 {
		t.Fatalf("4hex 后缀近重名只有 %d 条，要求 ≥10", count)
	}
	t.Logf("4hex 后缀近重名 %d 条，精确名字互不相同（如 %s）", count, firstKey(seen))
}

// TestJunkTrustedAndSpaceNames 钉住可信构件名与空格名，并确认它们都不撞 v1
// 签名关键名、也不等于真核心文件。
func TestJunkTrustedAndSpaceNames(t *testing.T) {
	art := runJunkPasses(t, "names", 0, 0, 1, 0, 0)

	names := map[string]*zipx.Entry{}
	for _, e := range art.Entries() {
		names[e.NameString()] = e
	}
	for _, want := range append(append([]string{}, junkTrustedNames[:]...), junkSpaceNames[:]...) {
		e, ok := names[want]
		if !ok {
			t.Fatalf("缺少名字族条目 %q", want)
		}
		if manifestCollision(want) {
			t.Fatalf("名字族条目 %q 会被当成 v1 签名关键文件", want)
		}
		if coreCollision(want, nil) {
			t.Fatalf("名字族条目 %q 归一化后撞上真核心文件", want)
		}
		if len(entryData(t, e)) == 0 {
			t.Fatalf("名字族条目 %q 内容为空", want)
		}
	}
	for _, want := range junkSpaceNames {
		e, ok := names[want]
		if !ok {
			t.Fatalf("缺少空格名条目 %q", want)
		}
		if len(entryData(t, e)) != junkPayloadSize {
			t.Fatalf("空格名条目 %q 应是 %d 字节共用载荷", want, junkPayloadSize)
		}
	}
	t.Log("名字族：module.map.xml / package.hint(.xml) / table.blob.xml / .idx / 两个空格名齐全")
}

// TestMetaUnifyThreeStamps 钉住 A14 的三段时间戳：基准、+32s、+44s（对齐样本
// 的 22:01:08 / 22:01:40 / 22:01:52），三组都存在且计数 > 0，同 seed 可复现。
func TestMetaUnifyThreeStamps(t *testing.T) {
	const seed = "stamps"
	art := runJunkPasses(t, seed, 8, 12, 4, 20, 30)
	// 再加几条「原始条目」验证基准组。
	pipeline.Add(art, zipx.NewStored("res/drawable/icon.png", []byte("png")))
	pipeline.Add(art, zipx.NewStored("assets/data.bin", []byte("bin")))
	pipeline.Add(art, zipx.NewStored("lib/arm64-v8a/libx.so", []byte("so")))

	opts := &config.Options{Seed: seed}
	if err := (&metaUnify{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A14 执行失败: %v", err)
	}

	var want [3][2]uint16
	for i, d := range []time.Duration{0, 32 * time.Second, 44 * time.Second} {
		tm, dt := zipx.DOSDateTime(config.DefaultStamp.Add(d))
		want[i] = [2]uint16{tm, dt}
	}
	counts := map[[2]uint16]int{}
	for _, e := range art.Entries() {
		counts[[2]uint16{e.ModTime, e.ModDate}]++
	}
	if len(counts) != 3 {
		t.Fatalf("时间戳组数应为 3，实际 %d: %v", len(counts), counts)
	}
	for i := range want {
		if counts[want[i]] == 0 {
			t.Fatalf("第 %d 组（基准/+32s/+44s 中第 %d 个）计数为 0: %v", i, i, counts)
		}
	}
	// 原始四条（classes.dex + res/assets/lib 各一）必须落在基准组。
	if counts[want[0]] != 4 {
		t.Fatalf("基准组应有 4 条原始条目，实际 %d（%v）", counts[want[0]], counts)
	}
	for i, key := range []string{"A14.stamp0", "A14.stamp1", "A14.stamp2"} {
		if got := art.Stats[key]; got != itoa(counts[want[i]]) {
			t.Fatalf("%s = %s，期望 %d", key, got, counts[want[i]])
		}
	}
	t.Logf("A14 三组时间戳计数：基准 %d、+32s %d、+44s %d", counts[want[0]], counts[want[1]], counts[want[2]])
}

// TestJunkFamiliesDeterministic 钉住同 seed 两次运行的产物字节完全一致
// （含 A14 的三组时间戳）。
func TestJunkFamiliesDeterministic(t *testing.T) {
	build := func() []byte {
		art := runJunkPasses(t, "det", 6, 8, 3, 12, 20)
		if err := (&metaUnify{}).Run(context.Background(), art, &config.Options{Seed: "det"}); err != nil {
			t.Fatalf("A14 执行失败: %v", err)
		}
		return pipeline.Bytes(art)
	}
	a, b := build(), build()
	if !bytes.Equal(a, b) {
		t.Fatal("同 seed 两次运行产物不一致（族内容或三段时间戳引入了非确定性）")
	}
}

// itoa 避免为测试额外引入 strconv。
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// firstKey 返回 map 中任意一个键（仅用于日志）。
func firstKey(m map[string]bool) string {
	for k := range m {
		return k
	}
	return ""
}
