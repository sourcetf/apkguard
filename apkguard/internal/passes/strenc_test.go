package passes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/pipeline"
	"apkguard/internal/zipx"
)

// ---- 测试数据构造 ----

// constRef 描述一个待注入的 const-string 常量及其被引用次数。
type constRef struct {
	s string
	n int
}

// dexWithConstStrings 构造一个只含指定类的最小 DEX：类的每个方法体
// 只做 const-string + return-object。引用次数 n>1 时生成 n 个方法分别引用，
// 从而产生「同一字符串被多条 const-string 指令引用」的形态。
func dexWithConstStrings(t *testing.T, cls string, refs []constRef) []byte {
	t.Helper()
	var methods []dex.ClassMethod
	for ri, cr := range refs {
		for k := 0; k < cr.n; k++ {
			a := dex.NewAsm()
			a.ConstString(0, cr.s)
			a.ReturnObject(0)
			insns, patches, err := a.Assemble()
			if err != nil {
				t.Fatalf("组装方法体失败: %v", err)
			}
			methods = append(methods, dex.ClassMethod{
				Name:   fmt.Sprintf("m%d_%d", ri, k),
				Proto:  dex.ProtoSpec{Ret: "Ljava/lang/String;"},
				Access: 0x0001 | 0x0008, // public static
				Code:   &dex.CodeBlob{Registers: 1, Ins: 0, Insns: insns, Patches: patches},
			})
		}
	}
	data, err := dex.Build(dex.Addition{Classes: []dex.ClassSpec{{
		Name: cls, Super: "Ljava/lang/Object;", Access: 0x0001, Methods: methods,
	}}})
	if err != nil {
		t.Fatalf("构造 DEX 失败: %v", err)
	}
	return data
}

// a2RandomClassPat 是 A2 解密器类名的随机形态：L<随机包1>/<随机包2>/<随机短名>;
var a2RandomClassPat = regexp.MustCompile(`^L[a-z]{5,9}/[a-z]{2,6}/[a-z]{4,10};$`)

// decryptorClassNames 返回 DEX 中全部 A2 解密器类名。
//
// 类名与方法名都已随机化，不能按名字找；识别依据是「随机形态类名 +
// 唯一的静态方法 (String)String + 有方法体」这一 A2 解密器的完整形态。
func decryptorClassNames(t *testing.T, data []byte) []string {
	t.Helper()
	f, err := dex.Parse(data)
	if err != nil {
		t.Fatalf("解析 DEX 失败: %v", err)
	}
	var out []string
	err = f.Classes(func(_ uint32, cd dex.ClassDef, name string) error {
		if cd.ClassDataOff == 0 || !a2RandomClassPat.MatchString(name) {
			return nil
		}
		pcd, err := f.ParseClassData(cd.ClassDataOff)
		if err != nil {
			return err
		}
		// A2 解密器只有一个 static 的直接方法，没有虚方法。
		if len(pcd.DirectMethods) != 1 || len(pcd.VirtualMethods) != 0 {
			return nil
		}
		m := pcd.DirectMethods[0]
		desc, err := f.MethodDesc(m.Idx)
		if err != nil {
			return nil
		}
		rest, ok := strings.CutPrefix(desc, name+"->")
		if !ok || !strings.HasSuffix(rest, "(Ljava/lang/String;)Ljava/lang/String;") {
			return nil
		}
		if m.Acc&0x0008 != 0 && m.CodeOff != 0 {
			out = append(out, name)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("遍历类失败: %v", err)
	}
	return out
}

// checkPerDexDecryptors 断言每个给定 DEX 都**自带**恰好一个解密器类，
// 且类名两两不同（需求 1 的核心不变量）。
//
// 注意：它只对「含密文的 DEX」使用。没有可加密串的 DEX 不应有解密器，
// 由调用方另行断言。
func checkPerDexDecryptors(t *testing.T, dexes [][]byte) error {
	t.Helper()
	seen := map[string]int{}
	var all []string
	for i, data := range dexes {
		names := decryptorClassNames(t, data)
		if len(names) != 1 {
			return fmt.Errorf("第 %d 个 DEX 应恰好自带 1 个解密器类，实际 %d 个", i, len(names))
		}
		seen[names[0]]++
		all = append(all, names[0])
	}
	for n, c := range seen {
		if c > 1 {
			return fmt.Errorf("解密器类名 %s 在 %d 个 DEX 中重复（运行期会类重复定义）", n, c)
		}
	}
	return nil
}

// a2Encrypt 独立复刻 A2 的密文算法（Base64(nonce ‖ SHA-256 密钥流异或)）。
//
// 刻意不复用 internal/dex 的未导出实现：这里用它算出「已知密钥下某个明文的
// 期望密文」，从而验证两个 DEX 的密文确实由同一把密钥产生（跨 DEX 密钥共享）。
func a2Encrypt(plain string, key [32]byte) string {
	p := []byte(plain)
	h := sha256.New()
	h.Write(key[:])
	h.Write([]byte{0x00})
	h.Write(p)
	nonce := h.Sum(nil)[:8]
	buf := make([]byte, 8+len(p))
	copy(buf, nonce)
	for i, c := range p {
		var idx [4]byte
		binary.LittleEndian.PutUint32(idx[:], uint32(i))
		kh := sha256.New()
		kh.Write(key[:])
		kh.Write([]byte{0x01})
		kh.Write(nonce)
		kh.Write(idx[:])
		buf[8+i] = c ^ kh.Sum(nil)[0]
	}
	return base64.StdEncoding.EncodeToString(buf)
}

// poolOf 返回 DEX 字符串池的内容集合。
func poolOf(t *testing.T, data []byte) map[string]bool {
	t.Helper()
	f, err := dex.Parse(data)
	if err != nil {
		t.Fatalf("解析 DEX 失败: %v", err)
	}
	out := map[string]bool{}
	for i := uint32(0); i < f.NString; i++ {
		s, err := f.String(i)
		if err != nil {
			t.Fatalf("字符串 %d 读取失败: %v", i, err)
		}
		out[s] = true
	}
	return out
}

// ---- 需求 1：每个含密文 DEX 自带随机类名解密器 ----

// TestA2PerDexDecryptors 是需求 1 的主证据：
//   - 两个含密文的 DEX 各自定义了自己的解密器类，且类名（随机形态）两两不同；
//   - 两 DEX 之间零交叉引用（对方类名不出现在本 DEX 的字符串/类型池）；
//   - 类名不是固定值 Lx/Dec; 也不是壳包下的固定名（防回退）；
//   - 同 seed 两次运行类名一致（可复现）；
//   - 密钥跨 DEX 共享：同一明文在两个 DEX 中被加密成**同一个**密文；
//   - 无密文的 DEX 不注入解密器，字节保持原样。
func TestA2PerDexDecryptors(t *testing.T) {
	const shared = "shared-plaintext-value"
	buildEntries := func() []*zipx.Entry {
		return []*zipx.Entry{
			zipx.NewStored("classes.dex", dexWithConstStrings(t, "Lapp/A;", []constRef{
				{"https://api.example.com/v1/pay", 1},
				{shared, 1},
				{"short", 1}, // 长度不足，不参与加密
			})),
			zipx.NewStored("classes2.dex", dexWithConstStrings(t, "Lapp/B;", []constRef{
				{"com.example.app.SecretToken", 2},
				{shared, 1},
			})),
			// 第三个 DEX 只有长度不足的串：密文数为 0，不应被注入解密器。
			zipx.NewStored("classes3.dex", dexWithConstStrings(t, "Lapp/C;", []constRef{
				{"abc", 1},
			})),
		}
	}
	newOpts := func() *config.Options {
		return &config.Options{
			Enabled:      map[config.FeatureID]bool{"A2": true},
			DexKey:       "perdex-key",
			Seed:         "perdex-seed",
			ObfStringMin: 8,
			ShellPkg:     "com.demo.shell",
		}
	}
	run := func() (names []string, data map[string][]byte, stats map[string]string) {
		t.Helper()
		art := newArtifact(buildEntries()...)
		if err := (&encryptString{}).Run(context.Background(), art, newOpts()); err != nil {
			t.Fatalf("A2 执行失败: %v", err)
		}
		data = map[string][]byte{}
		for _, e := range art.Entries() {
			d, err := e.Data()
			if err != nil {
				t.Fatalf("读取 %s 失败: %v", e.NameString(), err)
			}
			data[e.NameString()] = d
		}
		ns := decryptorClassNames(t, data["classes.dex"])
		names = append(names, ns...)
		ns2 := decryptorClassNames(t, data["classes2.dex"])
		names = append(names, ns2...)
		return names, data, art.Stats
	}

	names, data, stats := run()
	if len(names) != 2 {
		t.Fatalf("两个含密文 DEX 应各有 1 个解密器类，实际共 %d 个（%v）", len(names), names)
	}
	if names[0] == names[1] {
		t.Fatalf("两个 DEX 的解密器类名相同（%s），运行期会类重复定义", names[0])
	}
	pat := a2RandomClassPat
	for _, n := range names {
		if !pat.MatchString(n) {
			t.Fatalf("解密器类名 %q 不是随机形态 L<包1>/<包2>/<短名>;", n)
		}
		if n == "Lx/Dec;" {
			t.Fatalf("解密器类名回退到固定值 %s", n)
		}
		if n == "Lcom/demo/shell/Dec;" {
			t.Fatalf("解密器类名回退到壳包固定名 %s", n)
		}
	}

	// 核心：每个含密文 DEX 自带解密器、名字两两不同。
	if err := checkPerDexDecryptors(t, [][]byte{data["classes.dex"], data["classes2.dex"]}); err != nil {
		t.Fatal(err)
	}

	// 跨 DEX 零引用（双向）：任一 DEX 的字符串池与类型池都不得出现对方的
	// 解密器类名。这正是参考样本的强指纹（样本两 DEX 双向 0 命中）。
	for i, src := range []string{"classes.dex", "classes2.dex"} {
		other := names[1-i]
		f, err := dex.Parse(data[src])
		if err != nil {
			t.Fatalf("解析 %s 失败: %v", src, err)
		}
		for k := uint32(0); k < f.NString; k++ {
			s, _ := f.String(k)
			if s == other {
				t.Fatalf("%s 的字符串池出现了另一个 DEX 的解密器类名 %s（跨 DEX 引用）", src, other)
			}
		}
		for k := uint32(0); k < f.NType; k++ {
			s, _ := f.Type(k)
			if s == other {
				t.Fatalf("%s 的类型池出现了另一个 DEX 的解密器类名 %s（跨 DEX 引用）", src, other)
			}
		}
	}

	// 密钥跨 DEX 共享：用 Pass 同一把派生密钥算出 shared 的期望密文，
	// 它必须同时出现在两个 DEX 的池中（密钥不同则密文不同）。
	key, err := deriveKey("perdex-key", "perdex-seed")
	if err != nil {
		t.Fatal(err)
	}
	wantCT := a2Encrypt(shared, key)
	for _, src := range []string{"classes.dex", "classes2.dex"} {
		pool := poolOf(t, data[src])
		if !pool[wantCT] {
			t.Fatalf("%s 的池中找不到期望密文 %s（该 DEX 未使用同一把密钥）", src, wantCT)
		}
		if pool[shared] {
			t.Fatalf("%s 仍含明文 %q", src, shared)
		}
	}

	// 无密文 DEX：不注入解密器，且字节完全不变。
	if got := decryptorClassNames(t, data["classes3.dex"]); len(got) != 0 {
		t.Fatalf("无密文 DEX 被注入了 %d 个解密器（%v）", len(got), got)
	}
	orig3, err := buildEntries()[2].Data()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data["classes3.dex"], orig3) {
		t.Fatal("无密文 DEX 的字节被改写（应原样跳过）")
	}

	// 统计口径：A2.dex 只计含密文的 DEX，A2.decryptors 等于解密器类数。
	if stats["A2.dex"] != "2" || stats["A2.decryptors"] != "2" {
		t.Fatalf("A2 统计应为 2 个含密文 DEX / 2 个解密器，实际 %v", stats)
	}

	// 同 seed 可复现：第二次运行的类名必须与第一次一致。
	names2, _, _ := run()
	if names2[0] != names[0] || names2[1] != names[1] {
		t.Fatalf("同 seed 两次运行类名不一致：%v vs %v", names, names2)
	}
}

// TestA2HostOnlyNegativeControl 是需求 1 的反例对照：
// 用旧语义（只有主 DEX InjectClass=true）直接重建两个 DEX 时，
// 「每个 DEX 自带解密器」的检查必须失败。
//
// 不修改生产代码，而是在测试里用 dex 层 API 复刻旧行为，证明
// checkPerDexDecryptors 的断言确实能抓住「其余 DEX 只引用不落地」的形态。
func TestA2HostOnlyNegativeControl(t *testing.T) {
	dexA := dexWithConstStrings(t, "Lapp/A;", []constRef{{"https://api.example.com/v1/pay", 1}})
	dexB := dexWithConstStrings(t, "Lapp/B;", []constRef{{"com.example.app.SecretToken", 1}})
	key := [32]byte{0x5a}
	// 用符合随机形态的类名，确保反例失败的原因是「非主 DEX 没落地类体」，
	// 而不是识别规则不认这个旧名字。
	const cls = "Lqwertyui/ab/cdefg;"
	var out [][]byte
	for i, data := range [][]byte{dexA, dexB} {
		f, err := dex.Parse(data)
		if err != nil {
			t.Fatal(err)
		}
		se := &dex.StringEncrypt{
			Class: cls, MethodName: "a", Key: key, MinLen: 8,
			InjectClass: i == 0, // 旧语义：只有主 DEX 落地类体
		}
		o, _, err := dex.RebuildWithStats(f, dex.RebuildOptions{StringEncrypt: se})
		if err != nil {
			t.Fatalf("旧语义重建失败: %v", err)
		}
		out = append(out, o)
	}
	if err := checkPerDexDecryptors(t, out); err == nil {
		t.Fatal("旧语义（仅主 DEX InjectClass）下断言竟通过：反例对照失效")
	} else {
		t.Logf("反例对照按预期失败: %v", err)
	}
}

// ---- 需求 2：单引用串开关 ----

// TestA2SingleRefOnlyOption 验证 obf_string_single_ref 开关：
//   - false（默认）：单引用与多引用串都被加密（默认强度不变）；
//   - true：只加密单引用串，多引用串明文留在池中，且加密串数量下降。
func TestA2SingleRefOnlyOption(t *testing.T) {
	single := "single-ref-secret-value"
	multi := "multi-ref-shared-value"
	build := func() *zipx.Entry {
		return zipx.NewStored("classes.dex", dexWithConstStrings(t, "Lapp/S;", []constRef{
			{single, 1},
			{multi, 2},
		}))
	}
	run := func(singleOnly bool) (pool map[string]bool, stats map[string]string) {
		t.Helper()
		art := newArtifact(build())
		opts := &config.Options{
			Enabled:                map[config.FeatureID]bool{"A2": true},
			DexKey:                 "single-ref-key",
			Seed:                   "single-ref-seed",
			ObfStringMin:           8,
			ObfStringSingleRefOnly: singleOnly,
		}
		if err := (&encryptString{}).Run(context.Background(), art, opts); err != nil {
			t.Fatalf("A2 执行失败: %v", err)
		}
		d, err := pipeline.Find(art, "classes.dex").Data()
		if err != nil {
			t.Fatal(err)
		}
		return poolOf(t, d), art.Stats
	}

	poolAll, statsAll := run(false)
	poolOne, statsOne := run(true)

	// 默认（false）：两类串都被加密、明文都移出池——现状不变。
	if poolAll[single] {
		t.Fatalf("默认模式下单引用串 %q 仍留明文", single)
	}
	if poolAll[multi] {
		t.Fatalf("默认模式下多引用串 %q 仍留明文（默认强度被削弱）", multi)
	}
	if statsAll["A2.strings"] != "2" {
		t.Fatalf("默认模式应加密 2 个串，实际 %s", statsAll["A2.strings"])
	}

	// 开启（true）：只加密单引用串；多引用串逐条断言必须留明文。
	if poolOne[single] {
		t.Fatalf("单引用模式下单引用串 %q 仍留明文", single)
	}
	if !poolOne[multi] {
		t.Fatalf("单引用模式下多引用串 %q 被加密（应留明文）", multi)
	}
	if statsOne["A2.strings"] != "1" {
		t.Fatalf("单引用模式应只加密 1 个串，实际 %s", statsOne["A2.strings"])
	}
	if statsAll["A2.strings"] == statsOne["A2.strings"] {
		t.Fatal("开关 true/false 的加密串数量相同，开关未生效")
	}

	// 两种模式都必须有且只有一个解密器类（本 DEX 有密文）；
	// 原始 DEX 里则没有任何解密器——确认识别依据不会把业务类误判成解密器。
	orig, err := build().Data()
	if err != nil {
		t.Fatal(err)
	}
	if got := decryptorClassNames(t, orig); len(got) != 0 {
		t.Fatalf("构造的原始 DEX 不该含解密器，实际 %v", got)
	}
	if err := checkPerDexDecryptors(t, [][]byte{orig}); err == nil {
		t.Fatal("原始 DEX 无解密器，checkPerDexDecryptors 竟通过")
	}
}
