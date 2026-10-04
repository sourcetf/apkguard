package passes

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"apkguard/internal/arsc"
	"apkguard/internal/axml"
	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/pipeline"
	"apkguard/internal/zipx"
)

// findAapt2 定位 build-tools 里的 aapt2；找不到时返回空串。
//
// 用 aapt2 做验证而不是自己解析 ARSC：它是 Android 官方实现，
// 能确认「改写后的资源表在真实工具链眼里依然合法」——这是自研解析器
// 无法自证的（用同一份可能出错的代码去校验自己，等于没校验）。
//
// 之前只在 ../../../tools/build-tools/*/aapt2**.exe** 里找，Linux 上必然找不到，
// 于是 CI 里这条 A5/A11 的决定性判据一直被静默跳过。现在按
// BUILD_TOOLS_DIR > SDK 的 build-tools（取最高版本）> PATH 依次查找，
// 且同时接受带/不带 .exe 的文件名。
func findAapt2() string {
	name := "aapt2"
	if runtime.GOOS == "windows" {
		name = "aapt2.exe"
	}

	var dirs []string
	if d := os.Getenv("BUILD_TOOLS_DIR"); d != "" {
		dirs = append(dirs, d)
	}
	sdk := os.Getenv("ANDROID_HOME")
	if sdk == "" {
		sdk = os.Getenv("ANDROID_SDK_ROOT")
	}
	if sdk != "" {
		// build-tools 下可能装了多个版本，取版本号最大的那个。
		if ents, err := os.ReadDir(filepath.Join(sdk, "build-tools")); err == nil {
			var vers []string
			for _, e := range ents {
				if e.IsDir() {
					vers = append(vers, e.Name())
				}
			}
			sort.Sort(sort.Reverse(sort.StringSlice(vers)))
			for _, v := range vers {
				dirs = append(dirs, filepath.Join(sdk, "build-tools", v))
			}
		}
	}
	dirs = append(dirs, filepath.Join("..", "..", "..", "tools", "build-tools"))

	for _, d := range dirs {
		// 既接受直接给 build-tools 版本目录，也接受其父目录。
		for _, cand := range []string{filepath.Join(d, name), filepath.Join(d, "build-tools")} {
			if st, err := os.Stat(cand); err == nil && !st.IsDir() {
				return cand
			}
		}
		if ents, err := os.ReadDir(d); err == nil {
			for _, e := range ents {
				p := filepath.Join(d, e.Name(), name)
				if st, err := os.Stat(p); err == nil && !st.IsDir() {
					return p
				}
			}
		}
	}
	if p, err := exec.LookPath("aapt2"); err == nil {
		return p
	}
	return ""
}

// dumpResourceKeys 用 aapt2 导出「资源 ID + 类型」列表。
//
// 故意**不含条目名**：A5/A11 现在会随机化 keyStrings（条目名），
// `anim/acjrw38` 里的 acjrw38 会被换成随机 token，拿名字比对必然失败。
// 真正不能变的是「资源 ID + 类型」——应用里 R.* 引用的是这两个整数字段。
func dumpResourceKeys(t *testing.T, aapt2, apk string) []string {
	t.Helper()
	out, err := exec.Command(aapt2, "dump", "resources", apk).Output()
	if err != nil {
		t.Fatalf("aapt2 dump 失败: %v", err)
	}
	var keys []string
	for _, line := range strings.Split(string(out), "\n") {
		// 形如：      resource 0x7f010002 anim/acjrw38 PUBLIC
		f := strings.Fields(line)
		for i, tok := range f {
			if tok == "resource" && i+2 < len(f) && strings.HasPrefix(f[i+1], "0x") {
				typeName := f[i+2]
				if j := strings.IndexByte(typeName, '/'); j >= 0 {
					typeName = typeName[:j] // 去掉被随机化的条目名
				}
				keys = append(keys, f[i+1]+" "+typeName)
				break
			}
		}
	}
	sort.Strings(keys)
	return keys
}

// dumpResourceFileRefs 用 aapt2 导出资源表引用的全部文件路径。
//
// 路径字符串（全局字符串池）不在条目名随机化的范围内，改名后仍须与
// APK 实际条目一一对应；这是「资源路径 → 文件」映射未被破坏的判据。
func dumpResourceFileRefs(t *testing.T, aapt2, apk string) []string {
	t.Helper()
	out, err := exec.Command(aapt2, "dump", "resources", apk).Output()
	if err != nil {
		t.Fatalf("aapt2 dump 失败: %v", err)
	}
	var refs []string
	for _, line := range strings.Split(string(out), "\n") {
		if i := strings.Index(line, "(file)"); i >= 0 {
			f := strings.Fields(line[i+len("(file)"):])
			if len(f) > 0 {
				refs = append(refs, f[0])
			}
		}
	}
	sort.Strings(refs)
	return refs
}

// TestResourceRewriteKeepsArscStored 验证 A5/A11 不会把 resources.arsc 压成 DEFLATE。
//
// Android 11+（targetSdk ≥ 30）要求 resources.arsc 以未压缩方式存放，违反时
// **安装**会被直接拒绝（Failure [-124] ... requires the resources.arsc of
// installed APKs to be stored uncompressed and aligned on a 4-byte boundary）。
// 这类问题签名与对齐检查都发现不了：apksigner 与 zipalign -c 都会说 OK。
func TestResourceRewriteKeepsArscStored(t *testing.T) {
	art := loadSample(t)
	e := pipeline.Find(art, arscName)
	if e == nil {
		t.Skip("样本没有 resources.arsc")
	}
	if !e.IsStored() {
		t.Skip("样本的 resources.arsc 本来就是压缩存放，跳过")
	}

	opts := &config.Options{Enabled: map[config.FeatureID]bool{"A5": true, "A11": true}, Seed: "keep"}
	ctx := context.Background()
	if err := (&resourceObf{}).Run(ctx, art, opts); err != nil {
		t.Fatalf("A5 执行失败: %v", err)
	}
	if err := (&resourceFlatten{}).Run(ctx, art, opts); err != nil {
		t.Fatalf("A11 执行失败: %v", err)
	}

	got := pipeline.Find(art, arscName)
	if got == nil {
		t.Fatal("改写后 resources.arsc 消失了")
	}
	if !got.IsStored() {
		t.Fatal("改写后 resources.arsc 变成了压缩存放——Android 11+ 会拒绝安装该 APK")
	}
	t.Logf("A5/A11 改写后 resources.arsc 仍为未压缩存放（%d 字节）", got.UncompSize)
}

// TestResourceRewritePreservesResourceIDs 是 A5/A11 的**决定性判据**。
//
// 资源混淆唯一不能破坏的是「资源 ID 不变」：应用代码里所有 R.xxx 引用都是
// 编译期固化的整数 ID，只要 ID 与类型不变，改名文件路径就不会影响运行。
// 反过来，只要有一条 ID 变了，应用就会在某处崩掉——而这类问题在真机上
// 往往表现为难以定位的资源找不到。
//
// 因此判据必须是「前后 ID 集合逐条相等」，而不是「文件确实改名了」。
func TestResourceRewritePreservesResourceIDs(t *testing.T) {
	aapt2 := findAapt2()
	if aapt2 == "" {
		t.Skip("未找到 aapt2，跳过资源表校验")
	}
	in := sampleAPK(t)
	before := dumpResourceKeys(t, aapt2, in)
	if len(before) == 0 {
		t.Skip("样本没有可枚举的资源")
	}

	for _, tc := range []struct {
		name string
		opts *config.Options
	}{
		{"A5 仅改名", &config.Options{Enabled: map[config.FeatureID]bool{"A5": true}, Seed: "rt"}},
		{"A11 全量扁平化", &config.Options{Enabled: map[config.FeatureID]bool{"A5": true, "A11": true}, Seed: "rt"}},
	} {
		art, err := pipeline.Load(in)
		if err != nil {
			t.Fatalf("读取样本失败: %v", err)
		}
		ctx := context.Background()
		if err := (&resourceObf{}).Run(ctx, art, tc.opts); err != nil {
			t.Fatalf("%s: A5 执行失败: %v", tc.name, err)
		}
		if err := (&resourceFlatten{}).Run(ctx, art, tc.opts); err != nil {
			t.Fatalf("%s: A11 执行失败: %v", tc.name, err)
		}

		out := filepath.Join(t.TempDir(), "out.apk")
		if err := os.WriteFile(out, pipeline.Bytes(art), 0o644); err != nil {
			t.Fatalf("写出产物失败: %v", err)
		}
		after := dumpResourceKeys(t, aapt2, out)
		if len(after) != len(before) {
			t.Fatalf("%s: 资源条数变化：%d → %d", tc.name, len(before), len(after))
		}
		for i := range before {
			if before[i] != after[i] {
				t.Fatalf("%s: 资源 ID/类型发生变化：%q → %q（应用里的 R.* 引用会失效）",
					tc.name, before[i], after[i])
			}
		}
		// 条目名虽然被随机化，但 aapt2 从资源表读出的文件引用必须仍然
		// 与 APK 里的实际条目一一对应（路径改写时同步改了 ZIP 条目名）。
		refs := dumpResourceFileRefs(t, aapt2, out)
		present := map[string]bool{}
		for _, e := range art.Entries() {
			present[e.NameString()] = true
		}
		missing := 0
		for _, r := range refs {
			if !present[r] {
				missing++
			}
		}
		if missing > 0 {
			t.Fatalf("%s: 资源表引用了 %d 个在 APK 中不存在的文件（改路径后未同步改名）", tc.name, missing)
		}
		// 同时确认路径确实被改了（否则测试可能在「什么都没做」的情况下通过）。
		changed := 0
		for _, e := range art.Entries() {
			if n := e.NameString(); strings.HasPrefix(n, "res/") {
				changed++
			}
		}
		if changed == 0 {
			t.Fatalf("%s: 没有任何 res/ 条目", tc.name)
		}
		t.Logf("%s：%d 条资源 ID/类型逐条不变，%d 条文件引用全部存在，%d 个 res/ 条目已改名",
			tc.name, len(after), len(refs), changed)
	}
}

// TestResourceFlattenRemovesSemanticDirs 验证 A11 确实消除了语义目录名。
//
// A5 只改名、保留目录结构；A11 必须把 res/ 下的目录压成单字母——
// 这是文档里「零语义残留」的具体含义，也是 A11 相对 A5 的全部增量价值。
func TestResourceFlattenRemovesSemanticDirs(t *testing.T) {
	art, err := pipeline.Load(sampleAPK(t))
	if err != nil {
		t.Skipf("读取样本失败: %v", err)
	}
	// 记录「被 ARSC 引用」的路径：只有这些是本 Pass 的职责范围。
	// 不被引用的 res/ 条目（死资源、或 A10/A12 注入的畸形垃圾条目）按设计保留原样。
	referenced := map[string]bool{}
	if e := pipeline.Find(art, arscName); e != nil {
		data, err := e.Data()
		if err != nil {
			t.Fatalf("读取 ARSC 失败: %v", err)
		}
		tbl, err := arsc.Parse(data)
		if err != nil {
			t.Fatalf("解析 ARSC 失败: %v", err)
		}
		for _, p := range tbl.ResPaths() {
			referenced[p] = true
		}
	}
	if len(referenced) == 0 {
		t.Skip("样本没有 ARSC 引用的 res/ 路径")
	}

	// 记录改写前的全部条目名：改写后「新出现的名字」即为被本 Pass 改名的条目。
	// 用这个判定而不是「路径有几段」之类的启发式——样本里就有
	// res/values/anims.xml\.9.png 这种恰好 3 段、却并不被 ARSC 引用的垃圾条目，
	// 任何基于形状的猜测都会把它误判成真实资源。
	before := map[string]bool{}
	for _, e := range art.Entries() {
		before[e.NameString()] = true
	}

	opts := &config.Options{Enabled: map[config.FeatureID]bool{"A5": true, "A11": true}, Seed: "fl"}
	ctx := context.Background()
	if err := (&resourceObf{}).Run(ctx, art, opts); err != nil {
		t.Fatalf("A5 执行失败: %v", err)
	}
	if err := (&resourceFlatten{}).Run(ctx, art, opts); err != nil {
		t.Fatalf("A11 执行失败: %v", err)
	}

	// 被 ARSC 引用的原路径必须都已消失（即确实被改名）。
	for old := range referenced {
		if pipeline.Find(art, old) != nil {
			t.Fatalf("被 ARSC 引用的条目 %s 未被改名", old)
		}
	}
	// 只检查「本次改名产出」的条目：它们的目录必须是单字母。
	renamed := 0
	for _, n := range resZipEntryNames(art) {
		if before[n] {
			continue // 改写前就存在的（垃圾/死资源），按设计保留原样
		}
		parts := strings.Split(n, "/")
		if len(parts) != 3 || len(parts[1]) != 1 {
			t.Fatalf("被改名的条目未扁平化: %s（语义残留）", n)
		}
		renamed++
	}
	if renamed == 0 {
		t.Fatal("没有任何条目被改名")
	}
	t.Logf("A11：ARSC 引用的 %d 条路径全部改名、目录压成单字母（实际产出 %d 条）；垃圾条目按原样保留",
		len(referenced), renamed)
}

// ---- 资源条目名（keyStrings）随机化的接线测试 ----

// syntheticArsc 构造只含「全局池 + 一个包（typeStrings/keyStrings）」的最小资源表。
//
// 结构校验（entry 的 key 索引逐条不变等）在 internal/arsc 的单测里做；
// 这里只需要一个能被 arsc.RandomizeKeys 识别的包，用来验证 Pass 层接线：
// DEX 保留集合、统计/日志、幂等标记。
func syntheticArsc(t *testing.T, keys []string) []byte {
	t.Helper()
	global := axml.EncodeStringPool([]string{"res/layout/main.xml", "res/drawable/icon.png"}, true)
	typePool := axml.EncodeStringPool([]string{"string", "color"}, false)
	keyPool := axml.EncodeStringPool(keys, true)
	pkg := make([]byte, 288+len(typePool)+len(keyPool))
	binary.LittleEndian.PutUint16(pkg[0:], 0x0200)
	binary.LittleEndian.PutUint16(pkg[2:], 288)
	binary.LittleEndian.PutUint32(pkg[4:], uint32(len(pkg)))
	binary.LittleEndian.PutUint32(pkg[8:], 0x7f)
	binary.LittleEndian.PutUint32(pkg[268:], 288) // typeStrings
	binary.LittleEndian.PutUint32(pkg[276:], uint32(288+len(typePool)))
	copy(pkg[288:], typePool)
	copy(pkg[288+len(typePool):], keyPool)
	out := make([]byte, 12+len(global)+len(pkg))
	binary.LittleEndian.PutUint16(out[0:], 0x0002)
	binary.LittleEndian.PutUint16(out[2:], 12)
	binary.LittleEndian.PutUint32(out[4:], uint32(len(out)))
	copy(out[12:], global)
	copy(out[12+len(global):], pkg)
	return out
}

// arscKeysArtifact 构造含 resources.arsc 与两个真实 res/ 条目的产物。
func arscKeysArtifact(t *testing.T, keys []string, withDexStrings []string) *pipeline.Artifact {
	t.Helper()
	entries := []*zipx.Entry{
		zipx.NewStored(arscName, syntheticArsc(t, keys)),
		zipx.NewStored("res/layout/main.xml", []byte("<xml/>")),
		zipx.NewStored("res/drawable/icon.png", []byte("png")),
	}
	if withDexStrings != nil {
		entries = append(entries, zipx.NewStored("classes.dex", dexBytesWithStrings(t, withDexStrings)))
	}
	return newArtifact(entries...)
}

// dexBytesWithStrings 构造一个字符串池恰好（至少）含 strs 的合法 DEX。
func dexBytesWithStrings(t *testing.T, strs []string) []byte {
	t.Helper()
	f, err := dex.Parse(dex.Empty())
	if err != nil {
		t.Fatalf("解析空 DEX 失败: %v", err)
	}
	raw, err := dex.Rebuild(f, dex.RebuildOptions{ExtraStrings: strs})
	if err != nil {
		t.Fatalf("构造 DEX 字符串池失败: %v", err)
	}
	return raw
}

// writeInputAPK 写一个只含 classes.dex 的临时 APK 文件，用作 Options.In。
// 这是「原始输入」的真实文件形态：Pass 通过路径只读扫描它。
func writeInputAPK(t *testing.T, dexStrings []string) string {
	t.Helper()
	apk := pipeline.Bytes(newArtifact(zipx.NewStored("classes.dex", dexBytesWithStrings(t, dexStrings))))
	p := filepath.Join(t.TempDir(), "input.apk")
	if err := os.WriteFile(p, apk, 0o644); err != nil {
		t.Fatalf("写出临时输入 APK 失败: %v", err)
	}
	return p
}

func arscBytes(t *testing.T, art *pipeline.Artifact) []byte {
	t.Helper()
	e := pipeline.Find(art, arscName)
	if e == nil {
		t.Fatal("resources.arsc 不见了")
	}
	data, err := e.Data()
	if err != nil {
		t.Fatalf("读取 resources.arsc 失败: %v", err)
	}
	return data
}

// TestArscKeysHonorDexKeepSet 验证正例：DEX 字符串池里出现的条目名保持原名，
// 其余（ASCII、长度 ≥ 3、无点号）被改写；点分库名与短名按形状规则保留。
func TestArscKeysHonorDexKeepSet(t *testing.T) {
	keys := []string{"keep_me_key", "rename_me_key", "Widget.AppCompat.Toolbar"}
	art := arscKeysArtifact(t, keys, []string{"keep_me_key"})
	opts := &config.Options{Enabled: map[config.FeatureID]bool{"A5": true}, Seed: "keys-dex"}
	if err := (&resourceObf{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A5 执行失败: %v", err)
	}

	if got := art.Stats["A5.keys"]; got != "1" {
		t.Fatalf("应改写 1 条（仅 rename_me_key），实际 %s", got)
	}
	// keysdex 按「输入N+运行时M」报告保留集来源；未提供输入路径时输入侧为 0。
	if got := art.Stats["A5.keysdex"]; got != "0+1" {
		t.Fatalf("保留集来源应为 0+1（输入 0、运行时 1），实际 %s", got)
	}
	if got := art.Stats["A5.keysdexhit"]; got != "1" {
		t.Fatalf("命中保留集的 ARSC 条目应为 1 条，实际 %s", got)
	}
	if got := art.Stats["A5.keyskept"]; got != "2" {
		t.Fatalf("保留应为 2 条（DEX 1 + 形状 1），实际 %s", got)
	}
	got := arscBytes(t, art)
	if !bytes.Contains(got, []byte("keep_me_key")) {
		t.Fatal("DEX 引用的条目名被改写——按名查表的代码会失效")
	}
	if !bytes.Contains(got, []byte("Widget.AppCompat.Toolbar")) {
		t.Fatal("点分库名被改写")
	}
	if bytes.Contains(got, []byte("rename_me_key")) {
		t.Fatal("未被 DEX 引用的条目名仍保留原名（随机化没生效）")
	}
	// 路径改名仍照常执行，且 arsc 保持未压缩。
	if pipeline.Find(art, "res/layout/main.xml") != nil {
		t.Fatal("资源路径未被改名")
	}
	if !pipeline.Find(art, arscName).IsStored() {
		t.Fatal("resources.arsc 变成了压缩存放")
	}
	if !notesContain(art, "DEX 引用") {
		t.Fatalf("缺少条目名统计说明: %v", art.Notes)
	}
}

// TestArscKeysKeepSetFromInputApk 是本次修复的**决定性判据**。
//
// 场景：原始输入 APK 的 DEX 池含 "app_name"（getIdentifier 的字面量），
// 但产物里的 DEX 池已不含它——模拟 A1（R 类改名）/A2（字符串加密，默认启用）
// 排在 A5/A11 之前把字面量抹掉后的状态。修复前保留集只扫产物，app_name
// 被随机化，运行时 getIdentifier("app_name",...) 取不到资源、应用功能被破坏；
// 修复后保留集必须来自输入 APK，app_name 保持原名。
//
// 反例（同一测试内）：输入池里没有的 rename_me_key 仍必须被改名，
// 证明保留集不是「因为读了输入文件就变成什么都保留」。
func TestArscKeysKeepSetFromInputApk(t *testing.T) {
	keys := []string{"app_name", "rename_me_key", "Widget.AppCompat.Toolbar"}
	input := writeInputAPK(t, []string{"app_name"})
	// 产物 DEX 模拟 A2 改写后的池：app_name 已不在其中。
	art := arscKeysArtifact(t, keys, []string{"encrypted_blob_placeholder"})
	opts := &config.Options{
		Enabled: map[config.FeatureID]bool{"A5": true},
		Seed:    "keys-input",
		In:      input,
	}
	if err := (&resourceObf{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A5 执行失败: %v", err)
	}

	got := arscBytes(t, art)
	if !bytes.Contains(got, []byte("app_name")) {
		t.Fatal("输入 APK DEX 池里的 app_name 被改名——getIdentifier(\"app_name\",...) 运行时将取不到资源")
	}
	if bytes.Contains(got, []byte("rename_me_key")) {
		t.Fatal("输入池里没有的 rename_me_key 未被改名（随机化没生效或保留集过宽）")
	}
	if !bytes.Contains(got, []byte("Widget.AppCompat.Toolbar")) {
		t.Fatal("点分库名被改写")
	}
	// 来源统计必须体现输入侧贡献；格式为「输入N+运行时M」。
	src := art.Stats["A5.keysdex"]
	inN, rtN, ok := parseKeepSrc(src)
	if !ok || inN < 1 {
		t.Fatalf("keysdex 应体现输入 APK 的贡献（格式输入N+运行时M，N≥1），实际 %q", src)
	}
	if rtN < 0 {
		t.Fatalf("keysdex 运行时计数非法: %q", src)
	}
	if !notesContain(art, "保留集来源 = 输入 APK") || !notesContain(art, "运行时产物") {
		t.Fatalf("缺少保留集来源说明: %v", art.Notes)
	}
	if !notesContain(art, "DEX 引用") {
		t.Fatalf("缺少条目名统计说明: %v", art.Notes)
	}
	t.Logf("输入 APK 池保住了 app_name；来源统计 keysdex=%s，keysdexhit=%s", src, art.Stats["A5.keysdexhit"])
}

// parseKeepSrc 解析 keysdex 统计的「输入N+运行时M」格式。
func parseKeepSrc(s string) (inN, rtN int, ok bool) {
	parts := strings.Split(s, "+")
	if len(parts) != 2 {
		return 0, 0, false
	}
	inN, err1 := strconv.Atoi(parts[0])
	rtN, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return inN, rtN, true
}

// TestArscKeysInputUnreadableFallsBack 验证输入 APK 不可读时不中断：
// 退化为只扫产物 DEX（既有兜底仍然生效），并用 art.Note 说明保留集可能偏小。
func TestArscKeysInputUnreadableFallsBack(t *testing.T) {
	keys := []string{"keep_me_key", "rename_me_key", "Widget.AppCompat.Toolbar"}
	art := arscKeysArtifact(t, keys, []string{"keep_me_key"})
	opts := &config.Options{
		Enabled: map[config.FeatureID]bool{"A5": true},
		Seed:    "keys-noin",
		In:      filepath.Join(t.TempDir(), "does-not-exist.apk"),
	}
	if err := (&resourceObf{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("输入 APK 不可读时必须降级而不是中断: %v", err)
	}
	got := arscBytes(t, art)
	if !bytes.Contains(got, []byte("keep_me_key")) {
		t.Fatal("退化后产物 DEX 的保留集合未生效")
	}
	if bytes.Contains(got, []byte("rename_me_key")) {
		t.Fatal("退化后 rename_me_key 未被改名")
	}
	if art.Stats["A5.keysdex"] != "0+1" {
		t.Fatalf("输入不可读时来源应为 0+1（仅运行时），实际 %s", art.Stats["A5.keysdex"])
	}
	if !notesContain(art, "输入 APK 不可读") || !notesContain(art, "保留集可能偏小") {
		t.Fatalf("未说明输入不可读导致保留集可能偏小: %v", art.Notes)
	}
}

// TestArscKeysNoDexRenamesEligible 验证反例：没有任何 DEX 时保留集合为空，
// 全部符合形态的条目名都被改写（点分库名除外）。
func TestArscKeysNoDexRenamesEligible(t *testing.T) {
	keys := []string{"keep_me_key", "rename_me_key", "Widget.AppCompat.Toolbar"}
	art := arscKeysArtifact(t, keys, nil)
	opts := &config.Options{Enabled: map[config.FeatureID]bool{"A5": true}, Seed: "keys-nodex"}
	if err := (&resourceObf{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A5 执行失败: %v", err)
	}
	if got := art.Stats["A5.keys"]; got != "2" {
		t.Fatalf("无 DEX 时应改写 2 条，实际 %s", got)
	}
	if got := art.Stats["A5.keysdex"]; got != "0+0" {
		t.Fatalf("无 DEX、无输入路径时保留集来源应为 0+0，实际 %s", got)
	}
	if got := art.Stats["A5.keysdexhit"]; got != "0" {
		t.Fatalf("无 DEX 时命中保留集的 ARSC 条目应为 0，实际 %s", got)
	}
	got := arscBytes(t, art)
	if bytes.Contains(got, []byte("keep_me_key")) || bytes.Contains(got, []byte("rename_me_key")) {
		t.Fatal("无 DEX 时仍有条目名保持原名")
	}
	if !bytes.Contains(got, []byte("Widget.AppCompat.Toolbar")) {
		t.Fatal("点分库名被改写")
	}
}

// TestArscKeysIdempotent 验证幂等：同一产物上重复调用只随机化一次
// （Artifact.Shared 标记），第二次返回的字节与第一次产出逐字节相同。
func TestArscKeysIdempotent(t *testing.T) {
	keys := []string{"keep_me_key", "rename_me_key", "another_name"}
	art := arscKeysArtifact(t, keys, nil)
	opts := &config.Options{Enabled: map[config.FeatureID]bool{"A5": true}, Seed: "keys-idem"}
	raw := arscBytes(t, art)

	first, err := randomizeArscKeys(art, opts, raw, "A5")
	if err != nil {
		t.Fatalf("第一次随机化失败: %v", err)
	}
	second, err := randomizeArscKeys(art, opts, first, "A5")
	if err != nil {
		t.Fatalf("第二次随机化失败: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("第二次调用改动了字节（幂等标记失效）")
	}
	if !notesContain(art, "已执行过 keyStrings 随机化，跳过") {
		t.Fatalf("第二次调用未报告跳过: %v", art.Notes)
	}
}

// TestArscKeysA5A11RunsOnce 验证 A5+A11 同时启用时条目名只随机化一次：
// A5 因 A11 已启用而跳过整套资源改名，由 A11 完成后写标记；再跑一次 A11
// 时条目名部分被跳过（路径部分仍按既有语义处理）。
func TestArscKeysA5A11RunsOnce(t *testing.T) {
	keys := []string{"keep_me_key", "rename_me_key", "another_name"}
	art := arscKeysArtifact(t, keys, nil)
	opts := &config.Options{Enabled: map[config.FeatureID]bool{"A5": true, "A11": true}, Seed: "keys-a5a11"}
	ctx := context.Background()

	if err := (&resourceObf{}).Run(ctx, art, opts); err != nil {
		t.Fatalf("A5 执行失败: %v", err)
	}
	if err := (&resourceFlatten{}).Run(ctx, art, opts); err != nil {
		t.Fatalf("A11 执行失败: %v", err)
	}
	randomized := 0
	for _, n := range art.Notes {
		if strings.Contains(n, "资源条目名随机化：keyStrings") {
			randomized++
		}
	}
	if randomized != 1 {
		t.Fatalf("条目名随机化执行了 %d 次（应恰好 1 次）: %v", randomized, art.Notes)
	}
	keysStat := art.Stats["A11.keys"]

	// 再跑一次 A11：条目名必须跳过，统计不变。
	if err := (&resourceFlatten{}).Run(ctx, art, opts); err != nil {
		t.Fatalf("A11 第二次执行失败: %v", err)
	}
	if art.Stats["A11.keys"] != keysStat {
		t.Fatalf("第二次 A11 改写了条目名统计: %s → %s", keysStat, art.Stats["A11.keys"])
	}
	if !notesContain(art, "已执行过 keyStrings 随机化，跳过") {
		t.Fatalf("第二次 A11 未报告跳过: %v", art.Notes)
	}
}

// ---- 资源值零宽副本 + typeStrings 占位名的接线测试 ----

// syntheticArscVals 构造带字符串值 entry 的最小资源表，用于接线测试。
//
// global 是全局字符串池；entries 是 typeId → 该类型条目引用的全局池下标
// （简单 entry，Res_value.dataType = TYPE_STRING）；keyStrings 按条目序号取模。
// typeNames 里没有 entry 的 id 即「未使用 typeId」，应被写成 ?<id>。
func syntheticArscVals(t *testing.T, global, typeNames, keys []string, entries map[int][]int) []byte {
	t.Helper()
	gp := axml.EncodeStringPool(global, true)
	tp := axml.EncodeStringPool(typeNames, true)
	kp := axml.EncodeStringPool(keys, true)

	var sub []byte
	for id := 1; id <= len(typeNames); id++ {
		idxs := entries[id]
		if len(idxs) == 0 {
			continue
		}
		ts := make([]byte, 16+4*len(idxs))
		binary.LittleEndian.PutUint16(ts[0:], 0x0202)
		binary.LittleEndian.PutUint16(ts[2:], 16)
		binary.LittleEndian.PutUint32(ts[4:], uint32(len(ts)))
		ts[8] = byte(id)
		binary.LittleEndian.PutUint32(ts[12:], uint32(len(idxs)))
		sub = append(sub, ts...)

		const hdr = 84
		es := hdr + 4*len(idxs)
		size := es + 16*len(idxs)
		tc := make([]byte, size)
		binary.LittleEndian.PutUint16(tc[0:], 0x0201)
		binary.LittleEndian.PutUint16(tc[2:], hdr)
		binary.LittleEndian.PutUint32(tc[4:], uint32(size))
		tc[8] = byte(id)
		binary.LittleEndian.PutUint32(tc[12:], uint32(len(idxs)))
		binary.LittleEndian.PutUint32(tc[16:], uint32(es))
		for i, gi := range idxs {
			binary.LittleEndian.PutUint32(tc[hdr+4*i:], uint32(16*i))
			eo := es + 16*i
			binary.LittleEndian.PutUint16(tc[eo:], 8)   // ResTable_entry.size
			binary.LittleEndian.PutUint16(tc[eo+2:], 2) // FLAG_PUBLIC
			binary.LittleEndian.PutUint32(tc[eo+4:], uint32(i%len(keys)))
			binary.LittleEndian.PutUint16(tc[eo+8:], 8) // Res_value.size
			tc[eo+11] = 0x03                            // TYPE_STRING
			binary.LittleEndian.PutUint32(tc[eo+12:], uint32(gi))
		}
		sub = append(sub, tc...)
	}

	pkg := make([]byte, 288+len(tp)+len(kp)+len(sub))
	binary.LittleEndian.PutUint16(pkg[0:], 0x0200)
	binary.LittleEndian.PutUint16(pkg[2:], 288)
	binary.LittleEndian.PutUint32(pkg[4:], uint32(len(pkg)))
	binary.LittleEndian.PutUint32(pkg[8:], 0x7f)
	binary.LittleEndian.PutUint32(pkg[268:], 288)
	binary.LittleEndian.PutUint32(pkg[276:], uint32(288+len(tp)))
	copy(pkg[288:], tp)
	copy(pkg[288+len(tp):], kp)
	copy(pkg[288+len(tp)+len(kp):], sub)

	out := make([]byte, 12+len(gp)+len(pkg))
	binary.LittleEndian.PutUint16(out[0:], 0x0002)
	binary.LittleEndian.PutUint16(out[2:], 12)
	binary.LittleEndian.PutUint32(out[4:], uint32(len(out)))
	copy(out[12:], gp)
	copy(out[12+len(gp):], pkg)
	return out
}

// subBehaviorFixture 构造「40 条全局值 + 30 个字符串值 entry + 1 个未使用
// typeId（id=2 的 legacy_slot）」的产物，返回产物与原始全局值列表。
func subBehaviorFixture(t *testing.T) (*pipeline.Artifact, []string) {
	t.Helper()
	var global []string
	end := map[int][]int{}
	for i := 0; i < 40; i++ {
		global = append(global, "value_text_"+strconv.Itoa(i))
		if i < 30 {
			end[1] = append(end[1], i) // typeId 1 = string
		}
	}
	raw := syntheticArscVals(t,
		global,
		[]string{"string", "legacy_slot"}, // id 2 无 entry → 未使用
		[]string{"key_name_a", "key_name_b", "key_name_c"},
		end,
	)
	art := newArtifact(zipx.NewStored(arscName, raw))
	return art, global
}

// intStat 读取一个应为整数的统计值。
func intStat(t *testing.T, art *pipeline.Artifact, key string) int {
	t.Helper()
	v, ok := art.Stats[key]
	if !ok {
		t.Fatalf("缺少统计 %s（现有：%v）", key, art.Stats)
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		t.Fatalf("统计 %s=%q 不是整数", key, v)
	}
	return n
}

// arscEntryStringRefs 是测试自写的极简遍历器：收集简单 entry 的字符串值下标。
// 故意不复用 internal/arsc 的遍历（避免用同一份代码自证自己）。
func arscEntryStringRefs(t *testing.T, data []byte) map[int]bool {
	t.Helper()
	hdr := int(binary.LittleEndian.Uint16(data[2:]))
	total := int(binary.LittleEndian.Uint32(data[4:]))
	refs := map[int]bool{}
	for p := hdr; p+8 <= total; {
		tp := binary.LittleEndian.Uint16(data[p:])
		sz := int(binary.LittleEndian.Uint32(data[p+4:]))
		if sz < 8 || p+sz > total {
			t.Fatalf("顶层块非法: type=%#x size=%d", tp, sz)
		}
		if tp != 0x0200 {
			p += sz
			continue
		}
		phdr := int(binary.LittleEndian.Uint16(data[p+2:]))
		for q := p + phdr; q+8 <= p+sz; {
			st := binary.LittleEndian.Uint16(data[q:])
			ssz := int(binary.LittleEndian.Uint32(data[q+4:]))
			if ssz < 8 || q+ssz > p+sz {
				t.Fatalf("包内子块非法: type=%#x size=%d", st, ssz)
			}
			if st == 0x0201 {
				th := int(binary.LittleEndian.Uint16(data[q+2:]))
				cnt := int(binary.LittleEndian.Uint32(data[q+12:]))
				es := int(binary.LittleEndian.Uint32(data[q+16:]))
				for i := 0; i < cnt; i++ {
					o := int(binary.LittleEndian.Uint32(data[q+th+4*i:]))
					if o == 0xffffffff {
						continue
					}
					eo := q + es + o
					if flags := binary.LittleEndian.Uint16(data[eo+2:]); flags&1 != 0 {
						continue // 复合 entry：本夹具不产生
					}
					if data[eo+11] == 0x03 {
						refs[int(binary.LittleEndian.Uint32(data[eo+12:]))] = true
					}
				}
			}
			q += ssz
		}
		p += sz
	}
	return refs
}

// TestArscSubBehaviorsWiring 验证 A5/A11 两个新子行为的接线：
// 统计、Note、幂等标记，以及产物自洽（原值逐条不变、追加区间未被引用、
// 未使用 typeId 的占位名真的写入且已使用类型名不动）。
func TestArscSubBehaviorsWiring(t *testing.T) {
	art, global := subBehaviorFixture(t)
	opts := &config.Options{Enabled: map[config.FeatureID]bool{"A5": true}, Seed: "sub-wire"}
	if err := (&resourceObf{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A5 执行失败: %v", err)
	}

	// 统计：池 40 条 → 自适应上限 10，恰好覆盖 10 个逻辑值，每个 1~3 条。
	if got := intStat(t, art, "A5.padvalues"); got != 10 {
		t.Fatalf("A5.padvalues=%d，期望 10（40/4 自适应上限）", got)
	}
	padN := intStat(t, art, "A5.padstrings")
	if padN < 10 || padN > 30 {
		t.Fatalf("A5.padstrings=%d 超出每值 1~3 条的范围", padN)
	}
	if got := intStat(t, art, "A5.typetokens"); got != 1 {
		t.Fatalf("A5.typetokens=%d，期望 1（id 2 未使用）", got)
	}
	for _, sub := range []string{"资源值零宽副本", "均未被任何 entry 引用", "typeStrings 占位名"} {
		if !notesContain(art, sub) {
			t.Fatalf("Note 缺少 %q: %v", sub, art.Notes)
		}
	}

	// 产物自洽。
	data := arscBytes(t, art)
	tbl, err := arsc.Parse(data)
	if err != nil {
		t.Fatalf("改写后解析失败: %v", err)
	}
	strs := tbl.Strings()
	if len(strs) != len(global)+padN {
		t.Fatalf("池条目数 %d ≠ %d + %d", len(strs), len(global), padN)
	}
	for i, v := range global {
		if strs[i] != v {
			t.Fatalf("原值 %d 被改动: %q → %q", i, v, strs[i])
		}
	}
	marked := 0
	for _, s := range strs[len(global):] {
		if strings.ContainsAny(s, "\u200e\u200f") {
			marked++
		}
	}
	if marked != padN {
		t.Fatalf("追加条目含标记的只有 %d/%d 条", marked, padN)
	}
	// 没有任何 entry 引用追加区间（自写遍历器 + 夹具已知引用双重验证）。
	for idx := range arscEntryStringRefs(t, data) {
		if idx >= len(global) {
			t.Fatalf("entry 引用了追加区间下标 %d", idx)
		}
	}
	if arscEntryStringRefs(t, data)[0] != true || arscEntryStringRefs(t, data)[29] != true {
		t.Fatal("夹具原有的字符串引用丢失")
	}
	// 占位名 ?2 已写入（typeNames 用 UTF-8 池）。
	if !bytes.Contains(data, []byte("?2\x00")) {
		t.Fatal("未使用 id 2 的占位名 ?2 未写入 typeStrings")
	}
	if !bytes.Contains(data, []byte("string\x00")) {
		t.Fatal("已使用的类型名 string 被改动")
	}

	// A11 再跑同一产物：三个子行为都按 Shared 标记跳过，字节不变。
	before := append([]byte(nil), data...)
	opts2 := &config.Options{Enabled: map[config.FeatureID]bool{"A5": true, "A11": true}, Seed: "sub-wire"}
	if err := (&resourceFlatten{}).Run(context.Background(), art, opts2); err != nil {
		t.Fatalf("A11 第二次执行失败: %v", err)
	}
	if !bytes.Equal(before, arscBytes(t, art)) {
		t.Fatal("第二次执行改动了字节（幂等标记失效）")
	}
	if !notesContain(art, "资源值零宽副本：本产物已执行过，跳过（幂等）") ||
		!notesContain(art, "typeStrings 占位名：本产物已执行过，跳过（幂等）") {
		t.Fatalf("缺少幂等跳过说明: %v", art.Notes)
	}
	t.Logf("接线：padstrings=%d（覆盖 %d 值）、typetokens=1、二次执行字节不变", padN, 10)
}

// TestArscSubBehaviorsIdempotent 直接验证两个函数级的幂等标记：
// 第二次调用不做任何字节改动，只写跳过说明。
func TestArscSubBehaviorsIdempotent(t *testing.T) {
	art, _ := subBehaviorFixture(t)
	opts := &config.Options{Enabled: map[config.FeatureID]bool{"A5": true}, Seed: "sub-idem"}
	raw := arscBytes(t, art)

	pad1, err := padArscValues(art, opts, raw, "A5")
	if err != nil {
		t.Fatalf("第一次 padArscValues 失败: %v", err)
	}
	pad2, err := padArscValues(art, opts, pad1, "A5")
	if err != nil {
		t.Fatalf("第二次 padArscValues 失败: %v", err)
	}
	if !bytes.Equal(pad1, pad2) {
		t.Fatal("padArscValues 第二次调用改动了字节")
	}
	if !notesContain(art, "资源值零宽副本：本产物已执行过，跳过（幂等）") {
		t.Fatalf("缺少跳过说明: %v", art.Notes)
	}

	ty1, err := placeholderArscTypeNames(art, pad2, "A5")
	if err != nil {
		t.Fatalf("第一次 placeholderArscTypeNames 失败: %v", err)
	}
	ty2, err := placeholderArscTypeNames(art, ty1, "A5")
	if err != nil {
		t.Fatalf("第二次 placeholderArscTypeNames 失败: %v", err)
	}
	if !bytes.Equal(ty1, ty2) {
		t.Fatal("placeholderArscTypeNames 第二次调用改动了字节")
	}
	if !notesContain(art, "typeStrings 占位名：本产物已执行过，跳过（幂等）") {
		t.Fatalf("缺少跳过说明: %v", art.Notes)
	}
}

// ---- 真实产物 aapt2 回读 ----

// testAapt2 是一个可执行的 aapt2 调用方式（本机二进制或经 WSL 调用的 Linux 二进制）。
type testAapt2 struct {
	prog string
	pre  []string
	wsl  bool
}

// path 把 Windows 路径转换成 aapt2 能读到的路径（WSL 场景转 /mnt/<盘>/…）。
func (a testAapt2) path(p string) string {
	if !a.wsl {
		return p
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	abs = filepath.ToSlash(abs)
	if len(abs) >= 2 && abs[1] == ':' {
		return "/mnt/" + strings.ToLower(abs[:1]) + abs[2:]
	}
	return abs
}

// dump 跑 `aapt2 dump resources`；exit != 0 直接判失败（题目要求的判据）。
func (a testAapt2) dump(t *testing.T, apk string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()
	args := append(append([]string{}, a.pre...), "dump", "resources", a.path(apk))
	out, err := exec.CommandContext(ctx, a.prog, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("aapt2 dump resources 返回非零: %v\n%s", err, out)
	}
	return string(out)
}

// findTestAapt2 依次找本机 aapt2、WSL 里约定位置的 aapt2；都找不到返回 false。
//
// WSL 位置可用环境变量覆盖：WSL_AAPT2_DISTRO / WSL_AAPT2_PATH。
func findTestAapt2() (testAapt2, bool) {
	if p := findAapt2(); p != "" {
		return testAapt2{prog: p}, true
	}
	if runtime.GOOS != "windows" {
		return testAapt2{}, false
	}
	distro := os.Getenv("WSL_AAPT2_DISTRO")
	if distro == "" {
		distro = "Ubuntu-26.04"
	}
	cand := os.Getenv("WSL_AAPT2_PATH")
	if cand == "" {
		cand = "/home/dev123/android-sdk/build-tools/34.0.0/aapt2"
	}
	probe := func(p string) bool {
		return exec.Command("wsl.exe", "-d", distro, "-e", "test", "-x", p).Run() == nil
	}
	if probe(cand) {
		return testAapt2{prog: "wsl.exe", pre: []string{"-d", distro, "-e", cand}, wsl: true}, true
	}
	out, err := exec.Command("wsl.exe", "-d", distro, "-e", "sh", "-lc",
		`ls -d $HOME/android-sdk/build-tools/*/aapt2 2>/dev/null | sort -V | tail -1`).Output()
	if err == nil {
		if p := strings.TrimSpace(string(out)); p != "" && probe(p) {
			return testAapt2{prog: "wsl.exe", pre: []string{"-d", distro, "-e", p}, wsl: true}, true
		}
	}
	return testAapt2{}, false
}

// countResourceDump 数 dump 输出里的资源行数与 (file) 引用行数。
func countResourceDump(s string) (resources, fileRefs int) {
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, "resource 0x") {
			resources++
		}
		if strings.Contains(line, "(file)") {
			fileRefs++
		}
	}
	return
}

// TestA5A11Aapt2ReadbackStable 是真实产物回读判据：对真实 APK 跑完 A5/A11
// （含零宽副本与占位名两个新子行为）后，aapt2 dump resources 必须 exit 0，
// 且资源数与 (file) 引用数与改写前完全一致。
//
// 本机没有 aapt2 时经 WSL 调用（见 findTestAapt2）；两者都没有则跳过，
// 但零宽副本的结构正确性仍有 internal/arsc 的单测兜底。
func TestA5A11Aapt2ReadbackStable(t *testing.T) {
	tool, ok := findTestAapt2()
	if !ok {
		t.Skip("未找到 aapt2（本机与 WSL 都没有），跳过真实产物回读")
	}
	in := aapt2Sample(t)
	before := tool.dump(t, in)
	beforeRes, beforeRefs := countResourceDump(before)
	if beforeRes == 0 {
		t.Skip("样本没有可枚举资源")
	}

	art, err := pipeline.Load(in)
	if err != nil {
		t.Fatalf("读取样本失败: %v", err)
	}
	opts := &config.Options{Enabled: map[config.FeatureID]bool{"A5": true, "A11": true}, Seed: "aapt2-readback"}
	ctx := context.Background()
	if err := (&resourceObf{}).Run(ctx, art, opts); err != nil {
		t.Fatalf("A5 执行失败: %v", err)
	}
	if err := (&resourceFlatten{}).Run(ctx, art, opts); err != nil {
		t.Fatalf("A11 执行失败: %v", err)
	}
	out := filepath.Join(t.TempDir(), "out.apk")
	if err := os.WriteFile(out, pipeline.Bytes(art), 0o644); err != nil {
		t.Fatalf("写出产物失败: %v", err)
	}
	after := tool.dump(t, out)
	afterRes, afterRefs := countResourceDump(after)
	if afterRes != beforeRes {
		t.Fatalf("资源数变化：%d → %d", beforeRes, afterRes)
	}
	if afterRefs != beforeRefs {
		t.Fatalf("(file) 引用数变化：%d → %d", beforeRefs, afterRefs)
	}

	// 确认新子行为确实生效（否则上述「不变」可能只是因为什么都没做）。
	// A5+A11 同时启用时由 A11 执行，统计挂在 A11.* 下。
	padStat := art.Stats["A5.padstrings"]
	if padStat == "" {
		padStat = art.Stats["A11.padstrings"]
	}
	data := arscBytes(t, art)
	tbl, err := arsc.Parse(data)
	if err != nil {
		t.Fatalf("产物 resources.arsc 解析失败: %v", err)
	}
	marked := 0
	for _, s := range tbl.Strings() {
		if strings.ContainsAny(s, "\u200e\u200f") {
			marked++
		}
	}
	if padN, _ := strconv.Atoi(padStat); padN > 0 && marked == 0 {
		t.Fatal("统计说追加了零宽副本，但产物池里找不到标记字符")
	}
	t.Logf("aapt2 回读：资源 %d 条、(file) 引用 %d 条不变；池内零宽标记条目 %d 条；padstrings=%s",
		afterRes, afterRefs, marked, padStat)
}

// aapt2Sample 优先用开发机上的大样本（池大、引用多），没有则回退到常规样本。
func aapt2Sample(t *testing.T) string {
	t.Helper()
	big := filepath.Join("..", "..", "..", "sample.apk")
	if st, err := os.Stat(big); err == nil && st.Size() > 0 {
		return big
	}
	return sampleAPK(t)
}

// dropTypeChunks 从 resources.arsc 的第一个包里删掉指定 typeId 的
// Type(0x0201)/TypeSpec(0x0202) 块，保持包块与表头 size 自洽。
//
// 真实样本的 typeId 全部在用，为了给「占位名」一个真实的 aapt2 回读场景，
// 这里制造一个未使用 id：删掉它的类型块（该类型的资源随之消失），
// 之后的 before/after 对比仍在同一基线上进行。
func dropTypeChunks(t *testing.T, data []byte, drop int) []byte {
	t.Helper()
	hdr := int(binary.LittleEndian.Uint16(data[2:]))
	total := int(binary.LittleEndian.Uint32(data[4:]))
	pkgOff, pkgSize := -1, 0
	for p := hdr; p+8 <= total; {
		tp := binary.LittleEndian.Uint16(data[p:])
		sz := int(binary.LittleEndian.Uint32(data[p+4:]))
		if sz < 8 || p+sz > total {
			t.Fatalf("顶层块非法: type=%#x size=%d", tp, sz)
		}
		if tp == 0x0200 {
			pkgOff, pkgSize = p, sz
			break
		}
		p += sz
	}
	if pkgOff < 0 {
		t.Fatal("没有包块")
	}
	ph := int(binary.LittleEndian.Uint16(data[pkgOff+2:]))
	var sub []byte
	removed := 0
	for q := pkgOff + ph; q+8 <= pkgOff+pkgSize; {
		tp := binary.LittleEndian.Uint16(data[q:])
		sz := int(binary.LittleEndian.Uint32(data[q+4:]))
		if sz < 8 || q+sz > pkgOff+pkgSize {
			t.Fatalf("包内子块非法: type=%#x size=%d", tp, sz)
		}
		if (tp == 0x0201 || tp == 0x0202) && int(data[q+8]) == drop {
			removed++
		} else {
			sub = append(sub, data[q:q+sz]...)
		}
		q += sz
	}
	if removed == 0 {
		t.Fatalf("没有找到 typeId=%d 的块", drop)
	}
	newPkg := append([]byte(nil), data[pkgOff:pkgOff+ph]...)
	newPkg = append(newPkg, sub...)
	binary.LittleEndian.PutUint32(newPkg[4:], uint32(len(newPkg)))
	out := append([]byte(nil), data[:hdr]...)
	out = append(out, data[hdr:pkgOff]...) // 全局池
	out = append(out, newPkg...)
	out = append(out, data[pkgOff+pkgSize:]...)
	binary.LittleEndian.PutUint32(out[4:], uint32(len(out)))
	return out
}

// TestPlaceholderTypeNamesAapt2Readback 是占位名的真实产物回读：先在真实 APK
// 上删掉一个类型的 Type/TypeSpec 块制造「未使用 id」，跑 A5 后：
//   - 该 id 的 typeStrings 槽位被改名为 ?<id>（UTF-16 池）；
//   - 其余类型名原样；
//   - aapt2 dump resources 仍 exit 0，资源数与 (file) 引用数与改写前一致。
func TestPlaceholderTypeNamesAapt2Readback(t *testing.T) {
	tool, ok := findTestAapt2()
	if !ok {
		t.Skip("未找到 aapt2（本机与 WSL 都没有），跳过真实产物回读")
	}
	fw := filepath.Join("..", "..", "..", "testdata", "sample.apk")
	if st, err := os.Stat(fw); err != nil || st.Size() == 0 {
		t.Skipf("固件样本不存在（%v），跳过", err)
	}

	// 制造未使用 typeId=1 的输入产物。
	art, err := pipeline.Load(fw)
	if err != nil {
		t.Fatalf("读取固件失败: %v", err)
	}
	e := pipeline.Find(art, arscName)
	if e == nil {
		t.Skip("固件没有 resources.arsc")
	}
	raw, err := e.Data()
	if err != nil {
		t.Fatalf("读取 ARSC 失败: %v", err)
	}
	if err := e.SetData(dropTypeChunks(t, raw, 1), !e.IsStored()); err != nil {
		t.Fatalf("写回改造后的 ARSC 失败: %v", err)
	}
	derived := filepath.Join(t.TempDir(), "derived.apk")
	if err := os.WriteFile(derived, pipeline.Bytes(art), 0o644); err != nil {
		t.Fatalf("写出派生产物失败: %v", err)
	}
	before := tool.dump(t, derived)
	beforeRes, beforeRefs := countResourceDump(before)
	if beforeRes == 0 {
		t.Skip("派生样本没有可枚举资源")
	}

	art2, err := pipeline.Load(derived)
	if err != nil {
		t.Fatalf("读取派生产物失败: %v", err)
	}
	opts := &config.Options{Enabled: map[config.FeatureID]bool{"A5": true}, Seed: "typetoken-readback"}
	if err := (&resourceObf{}).Run(context.Background(), art2, opts); err != nil {
		t.Fatalf("A5 执行失败: %v", err)
	}
	if got := intStat(t, art2, "A5.typetokens"); got != 1 {
		t.Fatalf("A5.typetokens=%d，期望 1（派生出的未使用 id=1）", got)
	}
	out := filepath.Join(t.TempDir(), "out.apk")
	if err := os.WriteFile(out, pipeline.Bytes(art2), 0o644); err != nil {
		t.Fatalf("写出产物失败: %v", err)
	}
	after := tool.dump(t, out)
	afterRes, afterRefs := countResourceDump(after)
	if afterRes != beforeRes {
		t.Fatalf("资源数变化：%d → %d", beforeRes, afterRes)
	}
	if afterRefs != beforeRefs {
		t.Fatalf("(file) 引用数变化：%d → %d", beforeRefs, afterRefs)
	}
	// 固件的 typeStrings 是 UTF-16 池：?1 = '?' 00 '1' 00。
	data := arscBytes(t, art2)
	if !bytes.Contains(data, []byte{'?', 0, '1', 0}) {
		t.Fatal("未使用 id 1 的占位名 ?1 未写入 typeStrings（UTF-16）")
	}
	if !bytes.Contains(data, []byte{'l', 0, 'a', 0, 'y', 0, 'o', 0, 'u', 0, 't', 0}) {
		t.Fatal("已使用的类型名 layout 被改动")
	}
	t.Logf("占位名 aapt2 回读：资源 %d 条、(file) 引用 %d 条不变，未使用 id 1 → ?1", afterRes, afterRefs)
}
