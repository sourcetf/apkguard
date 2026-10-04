package passes

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/pack"
	"apkguard/internal/pipeline"
)

// soTestData 是三段可区分的「伪 ELF」字节，避免退化成全等比较。
func soTestData(seed byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = seed + byte(i%31)
	}
	copy(b, []byte("\x7fELF\x02\x01\x01\x00"))
	return b
}

// TestSoEncRoundTrip 验证 C2 的正向语义：
// lib/ 下明文 .so 被移除、assets 下出现密文、可解密还原、原 ABI 集合被记录。
func TestSoEncRoundTrip(t *testing.T) {
	fooA := soTestData(0x10, 400)
	fooB := soTestData(0x20, 512)
	art := newArtifact(
		zipxStored("classes.dex", []byte("dex\n035\x00")),
		zipxStored("lib/x86_64/libfoo.so", fooA),
		zipxStored("lib/arm64-v8a/libfoo.so", fooB),
	)
	opts := &config.Options{SOEncrypt: true, DexKey: "c2-key", Seed: "c2-seed"}
	p := &encryptNativeLibs{}
	if err := p.Run(context.Background(), art, opts); err != nil {
		t.Fatalf("执行失败: %v", err)
	}

	// ① lib/ 下不再有业务明文 .so
	for _, e := range art.Entries() {
		n := e.NameString()
		if strings.HasPrefix(n, "lib/") && strings.HasSuffix(n, ".so") {
			t.Fatalf("lib/ 下仍存在明文 .so: %s", n)
		}
	}
	// ② 清单与载荷
	sl := soLibsOf(art)
	if sl == nil {
		t.Fatal("未写入 C2 清单")
	}
	if len(sl.Items) != 2 {
		t.Fatalf("应加密 2 个 .so，实际 %d", len(sl.Items))
	}
	if strings.Join(sl.Abis, ",") != "arm64-v8a,x86_64" {
		t.Fatalf("原 ABI 集合记录错误: %v", sl.Abis)
	}
	// ③ 每个载荷可解密还原且内容不是 ELF
	wantByEntry := map[string][]byte{
		"lib/x86_64/libfoo.so":    fooA,
		"lib/arm64-v8a/libfoo.so": fooB,
	}
	seen := map[string]bool{}
	for _, it := range sl.Items {
		e := pipeline.Find(art, it.Asset)
		if e == nil {
			t.Fatalf("载荷条目 %s 不存在", it.Asset)
		}
		if !e.IsStored() {
			t.Fatalf("载荷 %s 应未压缩存储", it.Asset)
		}
		blob, err := e.Data()
		if err != nil {
			t.Fatalf("读取载荷 %s 失败: %v", it.Asset, err)
		}
		if len(blob) >= 4 && string(blob[:4]) == "\x7fELF" {
			t.Fatalf("载荷 %s 仍是明文 ELF", it.Asset)
		}
		got, err := pack.DecryptNamed(blob, sl.Key, it.Name)
		if err != nil {
			t.Fatalf("解密载荷 %s 失败: %v", it.Asset, err)
		}
		want := wantByEntry[it.Entry]
		if !bytes.Equal(got, want) {
			t.Fatalf("载荷 %s 还原结果不符", it.Asset)
		}
		if it.Size != len(blob) {
			t.Fatalf("Size 记录 %d 与实际 %d 不符", it.Size, len(blob))
		}
		seen[it.Entry] = true
	}
	if len(seen) != 2 {
		t.Fatalf("载荷未覆盖全部原始 .so: %v", seen)
	}
	// ④ 空操作缺陷已修：必须有 Note/Stat 证据，且开关确实生效。
	if art.Stats["C2.libs"] != "2" {
		t.Fatalf("C2.libs 统计不符: %v", art.Stats)
	}
	if art.Stats["C2.abis"] != "arm64-v8a,x86_64" {
		t.Fatalf("C2.abis 统计不符: %v", art.Stats)
	}
	if len(art.Notes) == 0 {
		t.Fatal("C2 未留下任何 Note")
	}
}

// TestSoEncNoOpWhenDisabled 验证 C2 关闭时对产物零副作用。
func TestSoEncNoOpWhenDisabled(t *testing.T) {
	before := soTestData(0x33, 256)
	art := newArtifact(zipxStored("lib/x86_64/libbar.so", before))
	p := &encryptNativeLibs{}
	if err := p.Run(context.Background(), art, &config.Options{}); err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	e := pipeline.Find(art, "lib/x86_64/libbar.so")
	if e == nil {
		t.Fatal("关闭 C2 时不应移除 lib/ 条目")
	}
	got, _ := e.Data()
	if !bytes.Equal(got, before) {
		t.Fatal("关闭 C2 时不应改动 lib/ 条目内容")
	}
	if soLibsOf(art) != nil {
		t.Fatal("关闭 C2 时不应写入清单")
	}
	if len(art.Entries()) != 1 {
		t.Fatalf("关闭 C2 时不应新增条目，实际 %d", len(art.Entries()))
	}
}

// TestSoEncEmptyAPKNoOp 验证无原生库的纯 Java 应用走合法空操作（不报错）。
func TestSoEncEmptyAPKNoOp(t *testing.T) {
	art := newArtifact(zipxStored("classes.dex", []byte("dex\n035\x00")))
	p := &encryptNativeLibs{}
	if err := p.Run(context.Background(), art, &config.Options{SOEncrypt: true}); err != nil {
		t.Fatalf("无原生库时不应报错: %v", err)
	}
	if soLibsOf(art) != nil {
		t.Fatal("无原生库时不应写入清单")
	}
	if art.Stats["C2.libs"] != "0" {
		t.Fatalf("应记录 0 个库: %v", art.Stats)
	}
}

// TestSoEncSkipsHighRiskFramework 验证框架特征审计：
// 命中 Flutter/RN/Unity 等 native 自加载框架时整体跳过，不破坏应用。
func TestSoEncSkipsHighRiskFramework(t *testing.T) {
	foo := soTestData(0x44, 300)
	art := newArtifact(
		zipxStored("lib/x86_64/libfoo.so", foo),
		zipxStored("lib/x86_64/libflutter.so", soTestData(0x55, 300)),
	)
	p := &encryptNativeLibs{}
	if err := p.Run(context.Background(), art, &config.Options{SOEncrypt: true, Seed: "s"}); err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	if soLibsOf(art) != nil {
		t.Fatal("命中高危框架时不应加密任何库")
	}
	if pipeline.Find(art, "lib/x86_64/libfoo.so") == nil {
		t.Fatal("命中高危框架时不应移除业务 .so")
	}
	if !strings.Contains(art.Stats["C2.skipped_frameworks"], "libflutter.so") {
		t.Fatalf("未记录跳过的框架: %v", art.Stats)
	}
}

// TestSoEncSkipsBridgeLib 验证工具自己的 libapkguard.so 不被加密/移除。
func TestSoEncSkipsBridgeLib(t *testing.T) {
	foo := soTestData(0x66, 200)
	bridge := soTestData(0x77, 100)
	art := newArtifact(
		zipxStored("lib/x86_64/libfoo.so", foo),
		zipxStored("lib/x86_64/libapkguard.so", bridge),
	)
	p := &encryptNativeLibs{}
	if err := p.Run(context.Background(), art, &config.Options{SOEncrypt: true, DexKey: "k", Seed: "s"}); err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	e := pipeline.Find(art, "lib/x86_64/libapkguard.so")
	if e == nil {
		t.Fatal("libapkguard.so 必须保留在 lib/（壳自身要用）")
	}
	got, _ := e.Data()
	if !bytes.Equal(got, bridge) {
		t.Fatal("libapkguard.so 内容不应被改动")
	}
	sl := soLibsOf(art)
	if sl == nil || len(sl.Items) != 1 || sl.Items[0].Name != "libfoo.so" {
		t.Fatalf("应只加密 libfoo.so: %+v", sl)
	}
	// 记录的原 ABI 集合应仍含 x86_64（供 C1 使用）。
	if strings.Join(sl.Abis, ",") != "x86_64" {
		t.Fatalf("ABI 集合记录错误: %v", sl.Abis)
	}
	// soAbisOf 应可供 C1 读取。
	if !soAbisOf(art)["x86_64"] {
		t.Fatal("soAbisOf 未返回记录的 ABI")
	}
}

// TestSoEncB3Wiring 在真实样本上跑 C2→B1→B2→B3，验证 B3 把 SO 载荷与
// 私有落地目录接进了 Loader 字节码（否则 .so 解密与库搜索路径都不会生效）。
func TestSoEncB3Wiring(t *testing.T) {
	art := loadSample(t)
	// 样本本身可能没有原生库，显式注入一个业务 .so 以便覆盖该路径。
	pipeline.Add(art, zipxStored("lib/x86_64/libfoo.so", soTestData(0x22, 256)))

	opts := shellOpts()
	opts.SOEncrypt = true
	opts.DexKey = "k"

	p := &encryptNativeLibs{}
	if err := p.Run(context.Background(), art, opts); err != nil {
		t.Fatalf("C2 执行失败: %v", err)
	}
	if sl := soLibsOf(art); sl == nil || len(sl.Items) != 1 {
		t.Fatalf("C2 未产出载荷: %+v", sl)
	}
	if pipeline.Find(art, "lib/x86_64/libfoo.so") != nil {
		t.Fatal("lib/ 下的业务 .so 未被移除")
	}

	runShellChain(t, art, opts)

	if art.Stats["B3.libs"] != "1" {
		t.Fatalf("B3 未接线 SO 载荷: %v", art.Stats)
	}
	e := pipeline.Find(art, "classes.dex")
	if e == nil {
		t.Fatal("未找到壳 DEX")
	}
	data, err := e.Data()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(libTempDir)) {
		t.Fatal("壳 DEX 不含 SO 落地目录名：B3 未接线 C2")
	}
	// 目录名必须是扁平的：Context.getDir 拒绝含路径分隔符的名字，传 "ag/lib"
	// 会让应用启动即抛
	//   java.lang.IllegalArgumentException: File ag/lib contains a path separator
	// （实测 Termux：C2 一开就崩，改成扁平名后正常）。这条断言把该约束钉住。
	if strings.ContainsRune(libTempDir, '/') || strings.ContainsRune(libTempDir, rune(92)) {
		t.Fatalf("SO 落地目录名 %q 含路径分隔符，会让 Context.getDir 抛异常", libTempDir)
	}
	if err := dex.Verify(data); err != nil {
		t.Fatalf("壳 DEX 校验失败: %v", err)
	}
}
