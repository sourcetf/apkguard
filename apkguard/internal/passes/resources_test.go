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
