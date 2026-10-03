package passes

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"apkguard/internal/axml"
	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/native"
	"apkguard/internal/pack"
	"apkguard/internal/pipeline"
	"apkguard/internal/zipx"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// shellOpts 返回启用 L2 一代壳三件套的配置。
func shellOpts() *config.Options {
	return &config.Options{
		Enabled: map[config.FeatureID]bool{"B1": true, "B2": true, "B3": true},
		Seed:    "shelltest",
	}
}

// runShellChain 按 B1 → B2 → B3 的顺序执行加壳链路。
func runShellChain(t *testing.T, art *pipeline.Artifact, opts *config.Options) {
	t.Helper()
	ctx := context.Background()
	for _, p := range []pipeline.Pass{&encryptDex{}, &appReplace{}, &classLoader{}} {
		if err := p.Run(ctx, art, opts); err != nil {
			t.Fatalf("功能项 %s 执行失败: %v", p.ID(), err)
		}
	}
}

// TestShellChainOnSample 在真实样本上跑完整加壳链路并核对产物结构。
//
// 覆盖四件事，缺一不可：
//  1. Manifest 的 android:name 确实被改成了壳类；
//  2. 原始 DEX 全部从 APK 中消失，密文载荷出现在 assets/；
//  3. 壳 DEX 成为 classes.dex，且同时含 App 与 Loader 两个类；
//  4. 载荷用 B1 的密钥能**还原出与原始 DEX 逐字节一致**的明文。
func TestShellChainOnSample(t *testing.T) {
	art := loadSample(t)

	// 记录加壳前的原始 DEX，稍后用于验证载荷可被还原。
	before := map[string][]byte{}
	for _, e := range art.Entries() {
		if !isDexEntry(e) {
			continue
		}
		d, err := e.Data()
		if err != nil {
			continue
		}
		if _, err := dex.Parse(d); err != nil {
			continue
		}
		before[e.NameString()] = d
	}
	if len(before) == 0 {
		t.Skip("样本中没有可解析的 DEX")
	}

	opts := shellOpts()
	runShellChain(t, art, opts)

	// ---- 1) Manifest 指向壳类 ----
	mfEntry := pipeline.Find(art, "AndroidManifest.xml")
	if mfEntry == nil {
		t.Fatal("产物中缺少 AndroidManifest.xml")
	}
	mfData, err := mfEntry.Data()
	if err != nil {
		t.Fatalf("读取 Manifest 失败: %v", err)
	}
	mf, err := axml.Parse(mfData)
	if err != nil {
		t.Fatalf("解析 Manifest 失败: %v", err)
	}
	app := mf.FindElement("application")
	if app == nil {
		t.Fatal("Manifest 中没有 <application>")
	}
	gotName := app.AttrString("name")
	const wantName = "com.apkguard.shell.App"
	if gotName != wantName {
		t.Fatalf("android:name = %q，期望 %q", gotName, wantName)
	}

	// ---- 2) 原始 DEX 的**明文**不再存在于产物中，载荷已就位 ----
	//
	// 不能只按名字判断：B2 会把壳 DEX 命名为 classes.dex，正好复用原始
	// 主 DEX 的名字。要证明的是「原始明文已消失」，因此按内容比对。
	for _, e := range art.Entries() {
		d, err := e.Data()
		if err != nil {
			continue
		}
		for name, raw := range before {
			if bytes.Equal(d, raw) {
				t.Fatalf("原始 DEX %s 的明文仍以条目 %s 存在于产物中（B1 未移除）",
					name, e.NameString())
			}
		}
	}
	payloads := payloadsOf(art)
	if payloads == nil || len(payloads.Items) == 0 {
		t.Fatal("未找到 B1 生成的载荷清单")
	}
	if len(payloads.Items) != len(before) {
		t.Fatalf("载荷数 %d 与原始 DEX 数 %d 不符", len(payloads.Items), len(before))
	}
	for _, p := range payloads.Items {
		if pipeline.Find(art, p.Asset) == nil {
			t.Fatalf("载荷条目 %s 不在产物中", p.Asset)
		}
	}

	// ---- 3) 壳 DEX 成为 classes.dex，且含 App 与 Loader ----
	shellEntry := pipeline.Find(art, "classes.dex")
	if shellEntry == nil {
		t.Fatal("产物中没有 classes.dex（壳 DEX 未注入）")
	}
	shellData, err := shellEntry.Data()
	if err != nil {
		t.Fatalf("读取壳 DEX 失败: %v", err)
	}
	if err := dex.Verify(shellData); err != nil {
		t.Fatalf("壳 DEX 校验失败: %v", err)
	}
	g, err := dex.Parse(shellData)
	if err != nil {
		t.Fatalf("解析壳 DEX 失败: %v", err)
	}
	classes := map[string]bool{}
	if err := g.Classes(func(_ uint32, _ dex.ClassDef, name string) error {
		classes[name] = true
		return nil
	}); err != nil {
		t.Fatalf("遍历壳 DEX 的类失败: %v", err)
	}
	for _, want := range []string{"Lcom/apkguard/shell/App;", "Lcom/apkguard/shell/Loader;"} {
		if !classes[want] {
			t.Fatalf("壳 DEX 缺少类 %s（已有 %v）", want, classNames(classes))
		}
	}

	// ---- 4) 载荷可被还原为原始 DEX ----
	for _, p := range payloads.Items {
		plain, err := pack.Decrypt(p.Blob, payloads.Key)
		if err != nil {
			t.Fatalf("解密载荷 %s 失败: %v", p.Asset, err)
		}
		want, ok := before[p.Name]
		if !ok {
			t.Fatalf("载荷 %s 声称来自 %s，但该 DEX 不在原 APK 中", p.Asset, p.Name)
		}
		if !bytes.Equal(plain, want) {
			t.Fatalf("载荷 %s 还原结果与原始 %s 不一致（%d vs %d 字节）",
				p.Asset, p.Name, len(plain), len(want))
		}
	}

	t.Logf("L2 一代壳链路验证通过：%d 个 DEX 被加密为载荷，壳 DEX（%d 字节）含 App 与 Loader，Manifest 指向 %s",
		len(payloads.Items), len(shellData), wantName)
}

// TestShellChainWithoutB1 UNUSED 占位，见下方 TestAppReplaceAloneKeepsOriginalDex。
func classNames(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestAppReplaceAloneKeepsOriginalDex 验证只启用 B2（不启用 B1/B3）时：
// 原始 DEX 保持不动，壳 DEX 另取一个空闲名字，且壳不调用 Loader。
//
// 这是「B2 单独可用」这一约定的回归保护：没有 B1 就没有载荷需要解密，
// 壳退化为纯 Application 代理，产物仍应是可运行的 APK。
func TestAppReplaceAloneKeepsOriginalDex(t *testing.T) {
	art := loadSample(t)
	var originalDex []string
	before := map[string]bool{}
	for _, e := range art.Entries() {
		if isDexEntry(e) {
			originalDex = append(originalDex, e.NameString())
			b, err := e.Data()
			if err != nil {
				t.Fatalf("读取 %s 失败: %v", e.NameString(), err)
			}
			f, err := dex.Parse(b)
			if err != nil {
				t.Fatalf("解析 %s 失败: %v", e.NameString(), err)
			}
			if err := f.Classes(func(_ uint32, _ dex.ClassDef, name string) error {
				before[name] = true
				return nil
			}); err != nil {
				t.Fatalf("遍历 %s 的类失败: %v", e.NameString(), err)
			}
		}
	}
	if len(originalDex) == 0 {
		t.Skip("样本中没有 DEX")
	}

	opts := &config.Options{Enabled: map[config.FeatureID]bool{"B2": true}}
	if err := (&appReplace{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("B2 执行失败: %v", err)
	}

	for _, n := range originalDex {
		if pipeline.Find(art, n) == nil {
			t.Fatalf("未启用 B1 时原始 DEX %s 不应被移除", n)
		}
	}
	info, _ := art.Get(sharedKeyShell).(*shellInfo)
	if info == nil {
		t.Fatal("B2 未写入壳信息")
	}
	// 壳应当**并进主 DEX**，而不是另起 classes2.dex：多 DEX 会引入
	// 「系统是否加载了第二个 DEX」这一不确定性，而并库没有。
	// 并库的代价是索引空间，因此真正要守的不变量是「原有类一个都不能少」，
	// 而不是条目名——下面的类集合比对就是在守这条。
	if info.EntryName != "classes.dex" {
		t.Fatalf("原始 classes.dex 仍在时应优先并进主 DEX，实际写入 %s", info.EntryName)
	}
	if info.LoaderClass != "" {
		t.Fatal("未启用 B3 时壳不应引用 Loader")
	}
	if pipeline.Find(art, info.EntryName) == nil {
		t.Fatalf("壳 DEX 条目 %s 不在产物中", info.EntryName)
	}
	// 原有类必须一个不少：并库把壳类追加进主 DEX，绝不能挤掉业务类。
	after := map[string]bool{}
	for _, n := range originalDex {
		e := pipeline.Find(art, n)
		if e == nil {
			t.Fatalf("原始 DEX %s 不应被移除", n)
		}
		b, err := e.Data()
		if err != nil {
			t.Fatalf("读取 %s 失败: %v", n, err)
		}
		f, err := dex.Parse(b)
		if err != nil {
			t.Fatalf("解析 %s 失败: %v", n, err)
		}
		if err := f.Classes(func(_ uint32, _ dex.ClassDef, name string) error {
			after[name] = true
			return nil
		}); err != nil {
			t.Fatalf("遍历 %s 的类失败: %v", n, err)
		}
	}
	for name := range before {
		if !after[name] {
			t.Fatalf("并库后丢失了原有类 %s", name)
		}
	}
}

// TestShellChainRejectsB3WithoutB1 验证「启用 B3 但未启用 B1」被明确拒绝。
//
// 这条组合曾经被当成「安全跳过」并写进测试：B3 只记一行说明就返回。但 B2 当时
// 仍会引用 Loader 类，而那个类从未被注入——产物引用未定义的类，应用一启动
// NoClassDefFoundError，工具却报成功。因此正确行为是**报错**，而不是跳过。
func TestShellChainRejectsB3WithoutB1(t *testing.T) {
	art := loadSample(t)
	opts := &config.Options{Enabled: map[config.FeatureID]bool{"B2": true, "B3": true}}
	ctx := context.Background()
	if err := (&appReplace{}).Run(ctx, art, opts); err != nil {
		t.Fatalf("B2 执行失败: %v", err)
	}
	// 壳不得引用 Loader（没有 B1 就没有 Loader 类体）。
	info, _ := art.Get(sharedKeyShell).(*shellInfo)
	if info == nil {
		t.Fatal("未找到壳信息")
	}
	if info.LoaderClass != "" {
		t.Fatalf("未启用 B1 时壳不应引用 Loader，实际 %q", info.LoaderClass)
	}
	// B3 必须报错，而不是静默跳过。
	err := (&classLoader{}).Run(ctx, art, opts)
	if err == nil {
		t.Fatal("未启用 B1 时 B3 应报错（否则产物会引用未定义的 Loader 类）")
	}
	// 错误信息要指出缺的是 B1。
	if !strings.Contains(err.Error(), "B1") {
		t.Fatalf("错误信息应指出缺少 B1，实际: %v", err)
	}
}

// TestRegistryNormalizesAllEntries 验证整条流水线跑完后，**全部**条目共享
// 同一套时间戳与 create_system。
//
// 这是对 A14 注册位置的回归保护：它必须排在 B1/B2 以及 A9/A10/A12 之后。
// 排在前面的话，加固过程中新增的条目会带着默认的 1980-01-01 时间戳发布出去，
// 反而成为「这个包被重新打包过」的证据——正好与 A14 的目的相反。
func TestRegistryNormalizesAllEntries(t *testing.T) {
	opts := &config.Options{
		Enabled: map[config.FeatureID]bool{
			"A1": true, "A2": true, "A3": true, "A4": true,
			"A9": true, "A10": true, "A12": true, "A13": true, "A14": true,
			"B1": true, "B2": true, "B3": true,
			// 不启用签名：本用例只关心 ZIP 元数据，避免依赖密钥库。
			"E1": false, "E2": true, "E3": true,
		},
		Seed: "stamptest",
		In:   sampleAPK(t),
	}
	res, err := pipeline.New(Registry(), pipeline.DefaultSink{}).Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("流水线执行失败: %v", err)
	}
	za, err := zipx.Read(res.APK)
	if err != nil {
		t.Fatalf("解析产物失败: %v", err)
	}
	if len(za.Entries) == 0 {
		t.Fatal("产物为空")
	}
	first := za.Entries[0]
	var bad []string
	for _, e := range za.Entries {
		if e.ModTime != first.ModTime || e.ModDate != first.ModDate ||
			(e.VersionMade&0xff00) != (first.VersionMade&0xff00) {
			bad = append(bad, e.NameString())
			if len(bad) >= 5 {
				break
			}
		}
	}
	if len(bad) > 0 {
		t.Fatalf("以下条目未与整体统一时间戳（A14 注册位置不对）: %v", bad)
	}
	t.Logf("A14：%d 个条目的时间戳与来源系统已全部统一，且加固新增条目在内", len(za.Entries))
}

// 确保 zipx 与 bytes 仍被引用（新增测试若全部跳过，仍能编译）。
var _ = zipx.NewStored

// countDupNames 返回归档中「出现次数 > 1」的条目名个数，以及各关键条目名
// 的出现次数。
func countDupNames(art *pipeline.Artifact) (int, map[string]int) {
	seen := map[string]int{}
	for _, e := range art.Entries() {
		seen[e.NameString()]++
	}
	n := 0
	for _, v := range seen {
		if v > 1 {
			n++
		}
	}
	return n, seen
}

// TestZipPathAttackNeverDuplicatesWhenSigning 验证启用签名时不注入重名条目，
// 且任何情况下都不会复制关键条目。
//
// 背景：apksigner 对含重名条目的归档会直接报「Duplicate entry」并拒绝整个
// 包（v1 的 META-INF/MANIFEST.MF 每个条目名只能有一段），因此带签名的产物
// 一旦注入重名条目就完全无法安装。这里同时守住两端：
//   - 启用 E1 时不得新增任何重名；
//   - 关闭 E1 时该手法仍可用，避免悄悄砍掉一个功能项。
func TestZipPathAttackNeverDuplicatesWhenSigning(t *testing.T) {
	art := loadSample(t)
	base, baseSeen := countDupNames(art)

	opts := &config.Options{
		Enabled:     map[config.FeatureID]bool{"A12": true, "E1": true},
		ZipAtkCount: 5,
	}
	if err := (&zipPathAttack{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A12 执行失败: %v", err)
	}
	got, seen := countDupNames(art)
	if got != base {
		t.Fatalf("启用签名时不得新增重名条目：%d → %d", base, got)
	}
	// 关键条目必须始终唯一。
	for _, name := range []string{"AndroidManifest.xml", "classes.dex", "resources.arsc"} {
		if seen[name] > 1 {
			t.Fatalf("关键条目 %s 被复制成了 %d 份", name, seen[name])
		}
	}
	_ = baseSeen

	// 关闭签名后应恢复注入（否则等于把该手法静默砍掉）。
	art2 := loadSample(t)
	opts2 := &config.Options{
		Enabled:     map[config.FeatureID]bool{"A12": true, "E1": false},
		ZipAtkCount: 5,
	}
	if err := (&zipPathAttack{}).Run(context.Background(), art2, opts2); err != nil {
		t.Fatalf("A12 执行失败: %v", err)
	}
	got2, _ := countDupNames(art2)
	if got2 <= base {
		t.Fatalf("关闭签名时应注入重名条目：%d → %d", base, got2)
	}
}

// TestImplementedMatchesRegistry 保证 config 声明的「已实现」集合与
// Registry 实际注册的 Pass 完全一致。
//
// 这两份信息分处两个包（config 不能反向依赖 passes），极易在新增功能项时
// 只改一边：漏标会让已实现的功能被拒绝启用，多标则会让「启用后什么都不做」
// 重新变成静默失败。这条测试就是两者的粘合剂。
func TestImplementedMatchesRegistry(t *testing.T) {
	registered := map[config.FeatureID]bool{}
	for _, p := range Registry().Passes() {
		registered[p.ID()] = true
	}
	// E1/E2/E3 由 Sink 收尾流程实现，E5 由 CLI 的批量入口实现，
	// 都不在 Pass 注册表里。
	for _, id := range []config.FeatureID{"E1", "E2", "E3", "E5"} {
		registered[id] = true
	}

	declared := map[config.FeatureID]bool{}
	for _, id := range config.ImplementedIDs() {
		declared[id] = true
	}

	for id := range registered {
		if !declared[id] {
			t.Errorf("%s 已有实现（Pass/Sink 存在），但 config.implementedIDs 未标记", id)
		}
	}
	for id := range declared {
		if !registered[id] {
			t.Errorf("%s 在 config.implementedIDs 中被标为已实现，但没有对应的 Pass/Sink 实现", id)
		}
	}
	// 未实现的功能项必须被 Validate 拒绝启用。
	for _, f := range config.All() {
		if f.Implemented {
			continue
		}
		o := &config.Options{
			Enabled: map[config.FeatureID]bool{f.ID: true},
			In:      "a.apk", KS: "k.jks",
		}
		if err := o.Validate(); err == nil {
			t.Errorf("%s 未实现，但启用时 Validate 未报错（会静默地什么都不做）", f.ID)
		}
	}
}

// TestSigCheckInjectedIntoShell 验证 D1 把签名校验类注入壳 DEX，
// 且壳会在启动时调用它；同时核对内置指纹与密钥库中的证书一致。
//
// 指纹与证书必须一致是硬要求：不一致的产物会在自己手上就无法启动，
// 这是比「防护失效」更糟的失败模式（用户会以为加固把包改坏了）。
func TestSigCheckInjectedIntoShell(t *testing.T) {
	art := loadSample(t)

	// 用一份临时 PKCS12 作为签名材料，取其证书指纹作为期望值。
	key, cert := testKeyMaterial(t)
	pfx, err := pkcs12.Modern.Encode(key, cert, nil, "123456")
	if err != nil {
		t.Fatalf("生成 PKCS12 失败: %v", err)
	}
	ksPath := filepath.Join(t.TempDir(), "k.pfx")
	if err := os.WriteFile(ksPath, pfx, 0o600); err != nil {
		t.Fatalf("写出密钥库失败: %v", err)
	}
	want := sha256.Sum256(cert.Raw)

	opts := &config.Options{
		Enabled: map[config.FeatureID]bool{"B2": true, "D1": true, "E1": true, "E2": true},
		KS:      ksPath, KSPass: "123456",
	}
	ctx := context.Background()
	if err := (&appReplace{}).Run(ctx, art, opts); err != nil {
		t.Fatalf("B2 执行失败: %v", err)
	}
	if err := (&sigCheck{}).Run(ctx, art, opts); err != nil {
		t.Fatalf("D1 执行失败: %v", err)
	}

	info, _ := art.Get(sharedKeyShell).(*shellInfo)
	sigCls := checkClassOf(info, "D1")
	if sigCls == "" {
		t.Fatal("B2 未登记签名校验类名")
	}
	e := pipeline.Find(art, info.EntryName)
	data, err := e.Data()
	if err != nil {
		t.Fatalf("读取壳 DEX 失败: %v", err)
	}
	g, err := dex.Parse(data)
	if err != nil {
		t.Fatalf("解析壳 DEX 失败: %v", err)
	}
	found := false
	if err := g.Classes(func(_ uint32, _ dex.ClassDef, name string) error {
		if name == sigCls {
			found = true
		}
		return nil
	}); err != nil {
		t.Fatalf("遍历类失败: %v", err)
	}
	if !found {
		t.Fatalf("壳 DEX 中缺少 %s", sigCls)
	}

	// 指纹必须等于密钥库证书的 SHA-256。
	if got := art.Stats["D1.digest"]; got != hex.EncodeToString(want[:]) {
		t.Fatalf("内置指纹与密钥库证书不一致:\n  实际 %s\n  期望 %s", got, hex.EncodeToString(want[:]))
	}
}

// TestSigCheckRequiresHashWithoutSigning 验证未启用签名时必须显式给出指纹。
func TestSigCheckRequiresHashWithoutSigning(t *testing.T) {
	opts := &config.Options{Enabled: map[config.FeatureID]bool{"E1": false}}
	if _, err := expectedSigDigest(opts); err == nil {
		t.Fatal("未启用 E1 且未给 -sig-hash 时应报错")
	}
	// 给出合法指纹后应可用。
	good := strings.Repeat("ab", 32)
	opts.SigHashes = []string{good}
	got, err := expectedSigDigest(opts)
	if err != nil {
		t.Fatalf("给出指纹后不应报错: %v", err)
	}
	if hex.EncodeToString(got[:]) != good {
		t.Fatalf("指纹解析不符: %s", hex.EncodeToString(got[:]))
	}
	// 长度不对必须被拒。
	opts.SigHashes = []string{"abcd"}
	if _, err := expectedSigDigest(opts); err == nil {
		t.Fatal("长度非 64 的指纹应被拒绝")
	}
}

// testKeyMaterial 生成一把自签名密钥与其证书，供 D1 测试构造密钥库。
func testKeyMaterial(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "apkguard test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("生成证书失败: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("解析证书失败: %v", err)
	}
	return key, cert
}

// TestC1PayloadKeyComesFromNativeDerivation 验证 C1 的核心性质：
// 载荷是用「native 派生函数的同一实现」算出的密钥加密的。
//
// 这是 C1 唯一重要的正确性断言——如果 Go 侧加密用的密钥与运行时
// libapkguard.so 算出的不一致，产物会在真机上解不开自己的载荷；
// 而 C/Go 两侧实现的一致性由 internal/native 的 TCC 对拍保证，
// 这里再把「B1 确实用了派生密钥」钉死。
func TestC1PayloadKeyComesFromNativeDerivation(t *testing.T) {
	art := loadSample(t)

	before := map[string][]byte{}
	for _, e := range art.Entries() {
		if !isDexEntry(e) {
			continue
		}
		d, err := e.Data()
		if err != nil {
			continue
		}
		if _, err := dex.Parse(d); err != nil {
			continue
		}
		before[e.NameString()] = d
	}
	if len(before) == 0 {
		t.Skip("样本中没有可解析的 DEX")
	}

	key, cert := testKeyMaterial(t)
	pfx, err := pkcs12.Modern.Encode(key, cert, nil, "123456")
	if err != nil {
		t.Fatalf("生成 PKCS12 失败: %v", err)
	}
	ksPath := filepath.Join(t.TempDir(), "k.pfx")
	if err := os.WriteFile(ksPath, pfx, 0o600); err != nil {
		t.Fatalf("写出密钥库失败: %v", err)
	}
	wantDigest := sha256.Sum256(cert.Raw)

	opts := &config.Options{
		Enabled: map[config.FeatureID]bool{"B1": true, "B2": true, "C1": true, "E1": true, "E2": true},
		KS:      ksPath, KSPass: "123456",
		Seed: "c1test",
	}
	ctx := context.Background()
	// 与注册顺序一致：B1 加密 → B2 建壳 → C1 注入原生库与桥接类。
	for _, p := range []pipeline.Pass{&encryptDex{}, &appReplace{}, &nativeKeyDerive{}} {
		if err := p.Run(ctx, art, opts); err != nil {
			t.Fatalf("功能项 %s 执行失败: %v", p.ID(), err)
		}
	}

	// 原生库必须三个 ABI 齐全：缺任一 ABI 都意味着对应架构装不上。
	libs, err := native.Prebuilt()
	if err != nil {
		t.Fatalf("读取预编译库失败: %v", err)
	}
	for _, l := range libs {
		if pipeline.Find(art, l.Entry) == nil {
			t.Fatalf("产物中缺少原生库条目 %s", l.Entry)
		}
	}

	// 桥接类必须在壳 DEX 里，且壳要引用它取密钥。
	info, _ := art.Get(sharedKeyShell).(*shellInfo)
	if info == nil {
		t.Fatal("B2 未写入壳信息")
	}
	shellEntry := pipeline.Find(art, info.EntryName)
	shellData, err := shellEntry.Data()
	if err != nil {
		t.Fatalf("读取壳 DEX 失败: %v", err)
	}
	g, err := dex.Parse(shellData)
	if err != nil {
		t.Fatalf("解析壳 DEX 失败: %v", err)
	}
	found := false
	if err := g.Classes(func(_ uint32, _ dex.ClassDef, name string) error {
		if name == dex.NativeBridgeClass {
			found = true
		}
		return nil
	}); err != nil {
		t.Fatalf("遍历类失败: %v", err)
	}
	if !found {
		t.Fatalf("壳 DEX 中缺少 native 桥接类 %s", dex.NativeBridgeClass)
	}

	// 关键断言：用 native 派生密钥能还原出原始 DEX。
	derived := native.DeriveKey(wantDigest[:])
	payloads := payloadsOf(art)
	if payloads == nil || len(payloads.Items) == 0 {
		t.Fatal("未找到载荷清单")
	}
	for _, p := range payloads.Items {
		plain, err := pack.Decrypt(p.Blob, derived)
		if err != nil {
			t.Fatalf("用 native 派生密钥解密载荷 %s 失败: %v（说明 B1 未使用派生密钥）", p.Asset, err)
		}
		want, ok := before[p.Name]
		if !ok {
			t.Fatalf("载荷 %s 声称来自 %s，但该 DEX 不在原 APK 中", p.Asset, p.Name)
		}
		if !bytes.Equal(plain, want) {
			t.Fatalf("载荷 %s 用派生密钥还原的结果与原始 DEX 不一致", p.Asset)
		}
	}
	t.Logf("C1：%d 份载荷均由 native 派生密钥（种子 + 签名摘要）正确还原", len(payloads.Items))
}

// TestC1InjectsOnlySupportedAbis 验证 C1 只给 APK 已支持的 ABI 补原生库。
//
// 这条防的是一个会「造出坏包」的问题：系统依据 lib/<abi>/ 下有无文件判断
// 应用支持哪些架构。若给只有 arm64 库的 APK 补上 armeabi-v7a 的壳库，
// 系统会放它装到 32 位 ARM 设备上，而应用自己的 32 位库并不存在——
// 结果是一启动就崩，且崩因与加固看起来毫无关系。
func TestC1InjectsOnlySupportedAbis(t *testing.T) {
	key, cert := testKeyMaterial(t)
	pfx, err := pkcs12.Modern.Encode(key, cert, nil, "123456")
	if err != nil {
		t.Fatalf("生成 PKCS12 失败: %v", err)
	}
	ksPath := filepath.Join(t.TempDir(), "k.pfx")
	if err := os.WriteFile(ksPath, pfx, 0o600); err != nil {
		t.Fatalf("写出密钥库失败: %v", err)
	}

	// 造一个「只有 arm64 原生库」的产物：只有一条 arm64 的 .so。
	art := loadSample(t)
	// 先清掉样本自带的 lib/ 条目，确保 ABI 集合完全由我们设定。
	pipeline.Remove(art, func(e *zipx.Entry) bool {
		return strings.HasPrefix(e.NameString(), "lib/")
	})
	pipeline.Add(art, zipx.NewStored("lib/arm64-v8a/libapp.so", []byte("fake")))

	opts := &config.Options{
		Enabled: map[config.FeatureID]bool{"B2": true, "C1": true, "E1": true},
		KS:      ksPath, KSPass: "123456",
	}
	ctx := context.Background()
	if err := (&appReplace{}).Run(ctx, art, opts); err != nil {
		t.Fatalf("B2 执行失败: %v", err)
	}
	if err := (&nativeKeyDerive{}).Run(ctx, art, opts); err != nil {
		t.Fatalf("C1 执行失败: %v", err)
	}

	got := map[string]bool{}
	for _, e := range art.Entries() {
		n := e.NameString()
		if strings.Contains(n, "libapkguard.so") {
			got[strings.Split(n, "/")[1]] = true
		}
	}
	if !got["arm64-v8a"] {
		t.Fatal("应给 arm64-v8a 注入壳库")
	}
	for _, abi := range []string{"armeabi-v7a", "x86_64"} {
		if got[abi] {
			t.Fatalf("APK 未声明支持 %s，不应注入该 ABI 的壳库（会让系统误判架构支持，装到该架构即崩）", abi)
		}
	}
	t.Log("C1：只给 APK 已支持的 ABI 注入壳库，未扩大声明的架构范围")
}
