package passes

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/pipeline"
	"apkguard/internal/zipx"
)

// ---- 测试辅助 ----

// sampleAPK 返回样本 APK 路径；不存在时跳过。
//
// 顺序：刚构建的 testapp（e2e 会生成，与装机产物一致）→ 仓库内固件
// testdata/sample.apk（保证干净检出下不跳过）→ 开发机上的历史样本。
func sampleAPK(t *testing.T) string {
	t.Helper()
	candidates := []string{
		filepath.Join("..", "..", "..", "testapp", "testapp-signed.apk"),
		filepath.Join("..", "..", "..", "testdata", "sample.apk"),
		filepath.Join("..", "..", "..", "payload_apk", "payload.apk"),
		filepath.Join("..", "..", "..", "iterator.apk.apk"),
		filepath.Join("..", "..", "..", "iterator.apk"),
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && st.Size() > 0 {
			return p
		}
	}
	t.Skip("未找到测试用 APK，跳过")
	return ""
}

// loadSample 载入样本 APK 并返回产物；失败时跳过测试。
func loadSample(t *testing.T) *pipeline.Artifact {
	t.Helper()
	art, err := pipeline.Load(sampleAPK(t))
	if err != nil {
		t.Skipf("读取样本 APK 失败（%v），跳过", err)
	}
	return art
}

// newArtifact 构造一个只含指定条目的产物。
func newArtifact(entries ...*zipx.Entry) *pipeline.Artifact {
	return &pipeline.Artifact{
		Archive: &zipx.Archive{Entries: entries},
		Stats:   map[string]string{},
	}
}

// ---- A14 元数据统一化 ----

func TestMetaUnify(t *testing.T) {
	art := newArtifact(
		zipx.NewStored("a.txt", []byte("a")),
		zipx.NewStored("b/c.txt", []byte("bc")),
	)
	// 制造差异：不同时间戳、不同 create_system、带注释
	art.Entries()[0].ModTime = 0x1234
	art.Entries()[0].ModDate = 0x5678
	art.Entries()[0].VersionMade = 0x0314
	art.Entries()[0].Comment = []byte("built by tool")
	art.Entries()[1].ModTime = 0xabcd
	art.Entries()[1].VersionMade = 0x0014

	p := &metaUnify{}
	if err := p.Run(context.Background(), art, &config.Options{}); err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	// 全部时间戳必须一致
	mt, md := art.Entries()[0].ModTime, art.Entries()[0].ModDate
	for _, e := range art.Entries() {
		if e.ModTime != mt || e.ModDate != md {
			t.Fatalf("时间戳未统一: %v vs %v", e, art.Entries()[0])
		}
		if e.VersionMade&0xff00 != 0 {
			t.Fatalf("create_system 未清零: 0x%04x", e.VersionMade)
		}
		if len(e.Comment) != 0 {
			t.Fatalf("注释未清除: %q", e.Comment)
		}
	}
	// 默认时间戳应为 2024-01-01 00:00:00
	wantT, wantD := toDOSDateTime(defaultStamp)
	if mt != wantT || md != wantD {
		t.Fatalf("默认时间戳不符: got(0x%04x,0x%04x) want(0x%04x,0x%04x)", mt, md, wantT, wantD)
	}
	if art.Stats["A14.entries"] != "2" {
		t.Fatalf("统计不符: %v", art.Stats)
	}
}

func TestMetaUnifyCustomStamp(t *testing.T) {
	art := newArtifact(zipx.NewStored("a.txt", []byte("a")))
	p := &metaUnify{}
	if err := p.Run(context.Background(), art, &config.Options{StampTime: "2020-06-15T12:30:00Z"}); err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	wantT, wantD := toDOSDateTime(mustTime(t, "2020-06-15T12:30:00Z"))
	if art.Entries()[0].ModTime != wantT || art.Entries()[0].ModDate != wantD {
		t.Fatalf("自定义时间戳不符")
	}
	// 非法格式必须报错
	if err := p.Run(context.Background(), art, &config.Options{StampTime: "not-a-time"}); err == nil {
		t.Error("非法时间戳应报错")
	}
}

// ---- A9 伪 DEX ----

func TestFakeDex(t *testing.T) {
	art := newArtifact(zipx.NewStored("classes.dex", []byte("dex\n035\x00real")))
	p := &fakeDex{}
	opts := &config.Options{Seed: "s1", FakeDexCount: 3, FakeDexSize: 8192}
	if err := p.Run(context.Background(), art, opts); err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	added := pipeline.FindAll(art, func(e *zipx.Entry) bool {
		n := e.NameString()
		return strings.EqualFold(n, "classes.dex") && n != "classes.dex"
	})
	if len(added) != 3 {
		t.Fatalf("应注入 3 个伪 DEX，实际 %d", len(added))
	}
	for _, e := range added {
		if e.UncompSize != 8192 {
			t.Fatalf("大小应为 8192，实际 %d", e.UncompSize)
		}
		if !e.IsStored() {
			t.Fatal("伪 DEX 必须未压缩存储（保证不可压缩）")
		}
		// magic 必须被伪造
		if string(e.Raw[:4]) != "dex\n" {
			t.Fatalf("magic 未伪造: %q", e.Raw[:8])
		}
		// 但不能是合法 DEX：解析必须失败
		if _, err := dex.Parse(e.Raw); err == nil {
			t.Fatal("伪 DEX 不应能被解析")
		}
		// 随机数据的取值分布应接近均匀：4096 字节中每个取值都应出现
		var hist [256]int
		for _, b := range e.Raw {
			hist[b]++
		}
		missing := 0
		for _, c := range hist {
			if c == 0 {
				missing++
			}
		}
		if missing > 0 {
			t.Fatalf("随机性不足：256 种取值中有 %d 种未出现", missing)
		}
	}
	if art.Stats["A9.count"] != "3" {
		t.Fatalf("统计不符: %v", art.Stats)
	}
}

func TestFakeDexDeterministic(t *testing.T) {
	build := func() []byte {
		art := newArtifact(zipx.NewStored("classes.dex", []byte("dex\n035\x00")))
		p := &fakeDex{}
		if err := p.Run(context.Background(), art, &config.Options{Seed: "fixed", FakeDexCount: 1, FakeDexSize: 4096}); err != nil {
			t.Fatalf("执行失败: %v", err)
		}
		return art.Entries()[1].Raw
	}
	a, b := build(), build()
	if !bytes.Equal(a, b) {
		t.Fatal("相同种子应产生相同结果")
	}
}

// ---- A10 垃圾条目 ----

func TestJunkEntries(t *testing.T) {
	art := newArtifact(zipx.NewStored("classes.dex", []byte("dex\n035\x00")))
	p := &junkEntries{}
	opts := &config.Options{
		Seed: "j1", JunkTopCount: 5, JunkDirCount: 4, JunkDirDepth: 3, JunkMetaCount: 7,
	}
	if err := p.Run(context.Background(), art, opts); err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	if art.Stats["A10.top"] != "5" || art.Stats["A10.dir"] != "4" || art.Stats["A10.meta"] != "7" {
		t.Fatalf("统计不符: %v", art.Stats)
	}
	// 顶层易混名必须含非 ASCII 字符
	nTop := 0
	for _, e := range art.Entries() {
		name := e.NameString()
		if !strings.HasSuffix(name, ".xml") || strings.Contains(name, "/") {
			continue
		}
		nTop++
		nonASCII := false
		for _, r := range name {
			if r > 127 {
				nonASCII = true
				break
			}
		}
		if !nonASCII {
			t.Fatalf("顶层垃圾文件 %q 不含非 ASCII 字符", name)
		}
		// 内容必须是可解析的 AXML（避免一眼假）
		if len(e.Raw) < 8 {
			t.Fatalf("垃圾 xml 内容过短: %d", len(e.Raw))
		}
	}
	if nTop != 5 {
		t.Fatalf("顶层垃圾文件数应为 5，实际 %d", nTop)
	}
	// 深目录条目的层数必须达标
	nDeep := 0
	for _, e := range art.Entries() {
		name := e.NameString()
		if !strings.HasSuffix(name, ".tmp") {
			continue
		}
		nDeep++
		if d := strings.Count(name, "/"); d < 1 {
			t.Fatalf("深目录条目 %q 层数不足", name)
		}
	}
	if nDeep != 4 {
		t.Fatalf("深目录条目数应为 4，实际 %d", nDeep)
	}
	// 畸形 META-INF 必须存在
	meta := map[string]bool{}
	for _, e := range art.Entries() {
		meta[e.NameString()] = true
	}
	for _, want := range []string{"META-INF/", "META-INF//MANIFEST.MFx", "META-INF/./MANIFEST.MFx"} {
		if !meta[want] {
			t.Errorf("缺少畸形 META-INF 条目 %q", want)
		}
	}
	// 变异名不得碰 `META-INF/MANIFEST.MF`（大小写不敏感）或签名文件后缀，
	// 否则 v1 校验会拿到假主属性并抛 Invalid signature file digest。
	for _, e := range art.Entries() {
		if manifestCollision(e.NameString()) {
			t.Errorf("注入了会被当成签名关键文件的条目 %q", e.NameString())
		}
	}
}

// ---- A12 ZIP 路径攻击 ----

func TestZipPathAttack(t *testing.T) {
	art := newArtifact(zipx.NewStored("classes.dex", []byte("dex\n035\x00")))
	p := &zipPathAttack{}
	// 默认配置启用签名（E1），此时不得注入重名条目：apksigner 会以
	// 「Duplicate entry」拒绝整个归档，产物将无法安装。
	if err := p.Run(context.Background(), art, &config.Options{Seed: "z1", ZipAtkCount: 3}); err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	if art.Stats["A12.prefix"] != "3" || art.Stats["A12.absolute"] != "3" || art.Stats["A12.dup"] != "0" {
		t.Fatalf("统计不符: %v", art.Stats)
	}
	nPrefix, nAbs, nDex := 0, 0, 0
	for _, e := range art.Entries() {
		name := e.NameString()
		for _, p := range []string{"classes.dex/", "AndroidManifest.xml/", "resources.arsc/", "classes2.dex/", "lib/"} {
			if strings.HasPrefix(name, p) {
				nPrefix++
				break
			}
		}
		if strings.HasPrefix(name, "/") {
			nAbs++
		}
		if name == "classes.dex" {
			nDex++
		}
	}
	if nPrefix != 3 || nAbs != 3 {
		t.Fatalf("前缀滥用 %d、绝对路径 %d，期望各 3", nPrefix, nAbs)
	}
	// 关键条目必须始终唯一——旧实现复制的是归档里的第一个条目，
	// 而它通常正是 classes.dex 或 AndroidManifest.xml。
	if nDex != 1 {
		t.Fatalf("关键条目 classes.dex 必须保持唯一，实际 %d 份", nDex)
	}

	// 关闭签名后重名手法应恢复可用。
	art2 := newArtifact(zipx.NewStored("classes.dex", []byte("dex\n035\x00")))
	opts2 := &config.Options{
		Seed: "z1", ZipAtkCount: 3,
		Enabled: map[config.FeatureID]bool{"E1": false},
	}
	if err := p.Run(context.Background(), art2, opts2); err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	if art2.Stats["A12.dup"] != "3" {
		t.Fatalf("关闭签名时应注入 3 条重名，实际 %s", art2.Stats["A12.dup"])
	}
}

// ---- A4 调试信息清除（端到端） ----

func TestDropDebugInfoE2E(t *testing.T) {
	art := loadSample(t)
	before := 0
	for _, e := range pipeline.FindAll(art, isDexEntry) {
		d, err := e.Data()
		if err != nil {
			continue
		}
		if _, err := dex.Parse(d); err != nil {
			continue
		}
		before += len(d)
	}
	if before == 0 {
		t.Skip("样本中没有可解析的 DEX")
	}

	p := &dropDebugInfo{}
	if err := p.Run(context.Background(), art, &config.Options{}); err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	after := 0
	for _, e := range pipeline.FindAll(art, isDexEntry) {
		d, err := e.Data()
		if err != nil {
			continue
		}
		f, err := dex.Parse(d)
		if err != nil {
			continue
		}
		if err := dex.Verify(d); err != nil {
			t.Fatalf("%s 校验失败: %v", e.NameString(), err)
		}
		// 全部 debug_info_off 必须为 0
		bad := 0
		f.Classes(func(_ uint32, cd dex.ClassDef, _ string) error {
			if cd.ClassDataOff == 0 {
				return nil
			}
			pcd, err := f.ParseClassData(cd.ClassDataOff)
			if err != nil {
				return err
			}
			for _, m := range append(append([]dex.EncodedMethod{}, pcd.DirectMethods...), pcd.VirtualMethods...) {
				if m.CodeOff == 0 {
					continue
				}
				ci, err := f.CodeInsns(m.CodeOff)
				if err != nil {
					return err
				}
				if ci.DebugInfoOff != 0 {
					bad++
				}
			}
			return nil
		})
		if bad > 0 {
			t.Fatalf("%s 仍有 %d 个方法带调试信息", e.NameString(), bad)
		}
		// class_def 的 source_file_idx 也必须清空。
		//
		// 它与 code_item 的 debug_info_off 是两处独立数据：只清后者时，
		// 反编译器仍会显示 "MainActivity.java"，A4 的目标就没达成。
		infos, err := f.ClassInfos()
		if err != nil {
			t.Fatalf("读取类信息失败: %v", err)
		}
		for _, ci := range infos {
			if ci.SourceFile != "" {
				t.Fatalf("%s 的类 %s 仍带源文件名 %q", e.NameString(), ci.Desc, ci.SourceFile)
			}
		}
		after += len(d)
	}
	if after > before {
		t.Fatalf("体积不应增大: %d -> %d", before, after)
	}
	t.Logf("A4：%d -> %d 字节（减少 %d，%.2f%%）", before, after, before-after, pct(before-after, before))
}

// ---- A1 名字混淆（端到端） ----

func TestRenameClassE2E(t *testing.T) {
	art := loadSample(t)
	p := &renameClass{}
	if err := p.Run(context.Background(), art, &config.Options{Seed: "r1"}); err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	// 重建后的全部 DEX 必须校验通过且可解析
	n := 0
	for _, e := range pipeline.FindAll(art, isDexEntry) {
		d, err := e.Data()
		if err != nil {
			continue
		}
		f, err := dex.Parse(d)
		if err != nil {
			continue
		}
		if err := dex.Verify(d); err != nil {
			t.Fatalf("%s 校验失败: %v", e.NameString(), err)
		}
		// 字符串池必须保持升序
		prev := ""
		for i := uint32(0); i < f.NString; i++ {
			s, err := f.String(i)
			if err != nil {
				t.Fatalf("%s 字符串 %d 读取失败: %v", e.NameString(), i, err)
			}
			if i > 0 && dex.CompareUTF16(prev, s) >= 0 {
				t.Fatalf("%s 字符串池顺序错误 @%d: %q >= %q", e.NameString(), i, prev, s)
			}
			prev = s
		}
		// 方法体必须完整
		f.Classes(func(_ uint32, cd dex.ClassDef, _ string) error {
			if cd.ClassDataOff == 0 {
				return nil
			}
			pcd, err := f.ParseClassData(cd.ClassDataOff)
			if err != nil {
				return err
			}
			for _, m := range append(append([]dex.EncodedMethod{}, pcd.DirectMethods...), pcd.VirtualMethods...) {
				if m.CodeOff == 0 {
					continue
				}
				if _, err := f.CodeInsns(m.CodeOff); err != nil {
					return err
				}
			}
			return nil
		})
		n++
	}
	if n == 0 {
		t.Skip("样本中没有可解析的 DEX")
	}
	// Android 组件类名必须保留（从 Manifest 提取）
	comps := manifestComponents(art)
	if len(comps) == 0 {
		t.Log("提示：样本 Manifest 无法解析组件，跳过组件保留检查")
	}
	t.Logf("A1 处理 %d 个 DEX；统计 %v", n, art.Stats)
}

// ---- A2 字符串加密（端到端） ----

func TestEncryptStringE2E(t *testing.T) {
	art := loadSample(t)
	// 先数出样本中可解析的 DEX
	parsable := 0
	for _, e := range pipeline.FindAll(art, isDexEntry) {
		d, err := e.Data()
		if err != nil {
			continue
		}
		if _, err := dex.Parse(d); err == nil {
			parsable++
		}
	}
	if parsable == 0 {
		t.Skip("样本中没有可解析的 DEX")
	}

	p := &encryptString{}
	opts := &config.Options{DexKey: "e2e-key", ObfStringMin: 4, ShellPkg: "com.demo.shell"}
	if err := p.Run(context.Background(), art, opts); err != nil {
		t.Fatalf("执行失败: %v", err)
	}

	// 重建后的全部 DEX 必须校验通过、可解析、字符串池有序
	n, injected := 0, 0
	for _, e := range pipeline.FindAll(art, isDexEntry) {
		d, err := e.Data()
		if err != nil {
			continue
		}
		f, err := dex.Parse(d)
		if err != nil {
			continue
		}
		if err := dex.Verify(d); err != nil {
			t.Fatalf("%s 校验失败: %v", e.NameString(), err)
		}
		prev := ""
		for i := uint32(0); i < f.NString; i++ {
			s, err := f.String(i)
			if err != nil {
				t.Fatalf("%s 字符串 %d 读取失败: %v", e.NameString(), i, err)
			}
			if i > 0 && dex.CompareUTF16(prev, s) >= 0 {
				t.Fatalf("%s 字符串池顺序错误 @%d: %q >= %q", e.NameString(), i, prev, s)
			}
			prev = s
		}
		// 全部方法体必须可解析
		f.Classes(func(_ uint32, cd dex.ClassDef, _ string) error {
			if cd.ClassDataOff == 0 {
				return nil
			}
			pcd, err := f.ParseClassData(cd.ClassDataOff)
			if err != nil {
				return err
			}
			for _, m := range append(append([]dex.EncodedMethod{}, pcd.DirectMethods...), pcd.VirtualMethods...) {
				if m.CodeOff == 0 {
					continue
				}
				if _, err := f.CodeInsns(m.CodeOff); err != nil {
					return err
				}
			}
			return nil
		})
		// 解密器类只应出现在主 DEX 中（多 DEX 场景下不得重复定义）
		f.Classes(func(_ uint32, _ dex.ClassDef, name string) error {
			if name == "Lcom/demo/shell/Dec;" {
				injected++
			}
			return nil
		})
		n++
	}
	if injected != 1 {
		t.Fatalf("解密器类应恰好注入 1 次（实际 %d），否则多 DEX 会重复定义", injected)
	}
	if art.Stats["A2.strings"] == "" || art.Stats["A2.strings"] == "0" {
		t.Fatalf("未加密任何字符串: %v", art.Stats)
	}
	t.Logf("A2 处理 %d 个 DEX；统计 %v", n, art.Stats)
}

// TestEncryptStringDeterministic 验证同一密钥的两次加固结果一致。
func TestEncryptStringDeterministic(t *testing.T) {
	run := func() []byte {
		art := loadSample(t)
		p := &encryptString{}
		opts := &config.Options{DexKey: "same-key", ObfStringMin: 4, ShellPkg: "com.demo.shell"}
		if err := p.Run(context.Background(), art, opts); err != nil {
			t.Fatalf("执行失败: %v", err)
		}
		for _, e := range pipeline.FindAll(art, isDexEntry) {
			if e.NameString() != "classes.dex" {
				continue
			}
			d, err := e.Data()
			if err != nil {
				t.Fatal(err)
			}
			return d
		}
		return nil
	}
	a, b := run(), run()
	if a == nil || b == nil {
		t.Skip("样本中没有 classes.dex")
	}
	if !bytes.Equal(a, b) {
		t.Fatal("相同密钥下两次加固结果不一致，说明存在未受控的随机性")
	}
}

// ---- A3 常量数组化（端到端） ----

// TestConstantArrayE2E 验证 A3 在真实样本上的端到端行为。
func TestConstantArrayE2E(t *testing.T) {
	art := loadSample(t)
	parsable := 0
	for _, e := range pipeline.FindAll(art, isDexEntry) {
		d, err := e.Data()
		if err != nil {
			continue
		}
		if _, err := dex.Parse(d); err == nil {
			parsable++
		}
	}
	if parsable == 0 {
		t.Skip("样本中没有可解析的 DEX")
	}

	p := &constantArray{}
	opts := &config.Options{ObfStringMin: 4, ShellPkg: "com.demo.shell"}
	if err := p.Run(context.Background(), art, opts); err != nil {
		t.Fatalf("执行失败: %v", err)
	}

	n, injected := 0, 0
	for _, e := range pipeline.FindAll(art, isDexEntry) {
		d, err := e.Data()
		if err != nil {
			continue
		}
		f, err := dex.Parse(d)
		if err != nil {
			continue
		}
		if err := dex.Verify(d); err != nil {
			t.Fatalf("%s 校验失败: %v", e.NameString(), err)
		}
		// 全部方法体必须可解析，且指令流必须合法
		// （skip 位置登记错误会让索引字被误当作操作码）
		f.Classes(func(_ uint32, cd dex.ClassDef, _ string) error {
			if cd.ClassDataOff == 0 {
				return nil
			}
			pcd, err := f.ParseClassData(cd.ClassDataOff)
			if err != nil {
				return err
			}
			for _, m := range append(append([]dex.EncodedMethod{}, pcd.DirectMethods...), pcd.VirtualMethods...) {
				if m.CodeOff == 0 {
					continue
				}
				ci, err := f.ParseCodeItem(m.CodeOff)
				if err != nil {
					return err
				}
				if _, err := dex.ParseInsns(ci.Insns); err != nil {
					return err
				}
			}
			return nil
		})
		// 还原器类只应出现在主 DEX 中
		f.Classes(func(_ uint32, _ dex.ClassDef, name string) error {
			if name == "Lcom/demo/shell/Arr;" {
				injected++
			}
			return nil
		})
		n++
	}
	if injected != 1 {
		t.Fatalf("还原器类应恰好注入 1 次（实际 %d）", injected)
	}
	if art.Stats["A3.strings"] == "" || art.Stats["A3.strings"] == "0" {
		t.Fatalf("未数组化任何字符串: %v", art.Stats)
	}
	t.Logf("A3 处理 %d 个 DEX；统计 %v", n, art.Stats)
}

// TestEncryptThenArrayE2E 验证 A2 与 A3 两个 Pass 串行执行时的协作。
//
// 这是最容易出错的地方：两个 Pass 都改写 const-string 且各自触发一次重建，
// A3 必须在 A2 之后运行，并识别出已被 A2 换成「密文 + 解密调用」的常量，
// 否则会把密文再数组化，运行时先数组还原出密文、再解密，虽能工作但会
// 白增体积；更糟的是若 skip 位置登记错位，索引字会被误当作操作码。
func TestEncryptThenArrayE2E(t *testing.T) {
	art := loadSample(t)
	parsable := 0
	for _, e := range pipeline.FindAll(art, isDexEntry) {
		d, err := e.Data()
		if err != nil {
			continue
		}
		if _, err := dex.Parse(d); err == nil {
			parsable++
		}
	}
	if parsable == 0 {
		t.Skip("样本中没有可解析的 DEX")
	}

	opts := &config.Options{DexKey: "combo-key", ObfStringMin: 4, ShellPkg: "com.demo.shell"}
	// 顺序必须与注册表一致：A2 在前，A3 在后。
	if err := (&encryptString{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A2 执行失败: %v", err)
	}
	if err := (&constantArray{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A3 执行失败: %v", err)
	}

	// 两个注入类都必须恰好出现 1 次（多 DEX 场景下不得重复定义）
	decCount, arrCount := 0, 0
	for _, e := range pipeline.FindAll(art, isDexEntry) {
		d, err := e.Data()
		if err != nil {
			continue
		}
		f, err := dex.Parse(d)
		if err != nil {
			continue
		}
		if err := dex.Verify(d); err != nil {
			t.Fatalf("%s 校验失败: %v", e.NameString(), err)
		}
		f.Classes(func(_ uint32, _ dex.ClassDef, name string) error {
			switch name {
			case "Lcom/demo/shell/Dec;":
				decCount++
			case "Lcom/demo/shell/Arr;":
				arrCount++
			}
			return nil
		})
		// 全部方法体与指令流必须合法
		f.Classes(func(_ uint32, cd dex.ClassDef, _ string) error {
			if cd.ClassDataOff == 0 {
				return nil
			}
			pcd, err := f.ParseClassData(cd.ClassDataOff)
			if err != nil {
				return err
			}
			for _, m := range append(append([]dex.EncodedMethod{}, pcd.DirectMethods...), pcd.VirtualMethods...) {
				if m.CodeOff == 0 {
					continue
				}
				ci, err := f.ParseCodeItem(m.CodeOff)
				if err != nil {
					return err
				}
				if _, err := dex.ParseInsns(ci.Insns); err != nil {
					return err
				}
			}
			return nil
		})
	}
	if decCount != 1 {
		t.Fatalf("解密器类应恰好 1 个，实际 %d", decCount)
	}
	if arrCount != 1 {
		t.Fatalf("还原器类应恰好 1 个，实际 %d", arrCount)
	}
	// A2 与 A3 的最短长度相同时，A2 已覆盖全部「仅被 const-string 引用」的
	// 常量，因此 A3 应当一个都不再处理——这正是「不重复包装」的证据。
	if art.Stats["A3.strings"] != "0" {
		t.Fatalf("A2 已处理全部常量时 A3 不应再改写，实际改写 %s 个", art.Stats["A3.strings"])
	}
	// 作为对照：A3 单独作用时必须确实改写常量，否则上面的 0 说明不了问题。
	art2 := loadSample(t)
	if err := (&constantArray{}).Run(context.Background(), art2, opts); err != nil {
		t.Fatalf("A3 单独执行失败: %v", err)
	}
	if art2.Stats["A3.strings"] == "" || art2.Stats["A3.strings"] == "0" {
		t.Fatalf("A3 单独执行时应改写常量，实际 %v", art2.Stats)
	}
	t.Logf("A2→A3 串行：%v；A3 单独：改写 %s 个", art.Stats, art2.Stats["A3.strings"])
}

// ---- A13 类膨胀（端到端） ----

// TestClassPadE2E 验证 A13 在真实样本上的端到端行为。
func TestClassPadE2E(t *testing.T) {
	art := loadSample(t)
	parsable := 0
	for _, e := range pipeline.FindAll(art, isDexEntry) {
		d, err := e.Data()
		if err != nil {
			continue
		}
		if _, err := dex.Parse(d); err == nil {
			parsable++
		}
	}
	if parsable == 0 {
		t.Skip("样本中没有可解析的 DEX")
	}

	const n = 30
	p := &classPad{}
	opts := &config.Options{Seed: "pad-e2e", ClassPadCount: n, ShellPkg: "com.demo.shell"}
	if err := p.Run(context.Background(), art, opts); err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	if art.Stats["A13.classes"] != fmt.Sprint(n) {
		t.Fatalf("应注入 %d 个类，实际 %s", n, art.Stats["A13.classes"])
	}

	// 全部 DEX 必须校验通过；注入的膨胀类名必须全局唯一；类体可解析
	//
	// 注意：不能断言「所有类型全局唯一」——原样本本身就可能把同一个
	// 类型（如 B、I）放进多个 DEX，这是合法的。只有**注入类**必须唯一，
	// 否则会在 class_defs 中形成重复定义。
	allTypes := map[string]string{} // 描述符 -> 所在 DEX
	total := 0
	for _, e := range pipeline.FindAll(art, isDexEntry) {
		d, err := e.Data()
		if err != nil {
			continue
		}
		f, err := dex.Parse(d)
		if err != nil {
			continue
		}
		if err := dex.Verify(d); err != nil {
			t.Fatalf("%s 校验失败: %v", e.NameString(), err)
		}
		f.Classes(func(_ uint32, cd dex.ClassDef, name string) error {
			if prev, ok := allTypes[name]; ok {
				t.Fatalf("类 %s 在 %s 与 %s 中重复定义", name, prev, e.NameString())
			}
			allTypes[name] = e.NameString()
			return nil
		})
		f.Classes(func(_ uint32, cd dex.ClassDef, _ string) error {
			if cd.ClassDataOff == 0 {
				return nil
			}
			pcd, err := f.ParseClassData(cd.ClassDataOff)
			if err != nil {
				return err
			}
			for _, m := range append(append([]dex.EncodedMethod{}, pcd.DirectMethods...), pcd.VirtualMethods...) {
				if m.CodeOff == 0 {
					continue
				}
				ci, err := f.ParseCodeItem(m.CodeOff)
				if err != nil {
					return err
				}
				if _, err := dex.ParseInsns(ci.Insns); err != nil {
					return err
				}
				total++
			}
			return nil
		})
	}
	t.Logf("A13 处理 %d 个 DEX；class_def 全局唯一（共 %d 个），%d 个方法体合法；统计 %v",
		parsable, len(allTypes), total, art.Stats)
}

// TestClassPadDeterministic 验证同种子可复现。
func TestClassPadDeterministic(t *testing.T) {
	run := func() []byte {
		art := loadSample(t)
		p := &classPad{}
		opts := &config.Options{Seed: "fixed", ClassPadCount: 12, ShellPkg: "com.demo.shell"}
		if err := p.Run(context.Background(), art, opts); err != nil {
			t.Fatalf("执行失败: %v", err)
		}
		for _, e := range pipeline.FindAll(art, isDexEntry) {
			if e.NameString() != "classes.dex" {
				continue
			}
			d, err := e.Data()
			if err != nil {
				t.Fatal(err)
			}
			return d
		}
		return nil
	}
	a, b := run(), run()
	if a == nil || b == nil {
		t.Skip("样本中没有 classes.dex")
	}
	if !bytes.Equal(a, b) {
		t.Fatal("相同种子下两次加固结果不一致")
	}
}

// ---- 辅助 ----

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	tt, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("解析时间失败: %v", err)
	}
	return tt
}
