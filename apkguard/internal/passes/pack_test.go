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
	"apkguard/internal/zipx"
)

// zipxStored 是 zipx.NewStored 的短别名，便于在测试中构造条目。
func zipxStored(name string, data []byte) *zipx.Entry { return zipx.NewStored(name, data) }

// ---- B1 DEX 整体加密（端到端） ----

// TestEncryptDexE2E 验证 B1 的核心语义：
// 明文 DEX 必须从归档中消失，载荷必须可被正确解密还原。
func TestEncryptDexE2E(t *testing.T) {
	art := loadSample(t)

	// 先记录原始可解析 DEX 的明文，供解密后逐字节比对。
	orig := map[string][]byte{}
	for _, e := range pipeline.FindAll(art, isDexEntry) {
		d, err := e.Data()
		if err != nil {
			continue
		}
		if _, err := dex.Parse(d); err != nil {
			continue
		}
		orig[e.NameString()] = d
	}
	if len(orig) == 0 {
		t.Skip("样本中没有可解析的 DEX")
	}

	p := &encryptDex{}
	opts := &config.Options{DexKey: "b1-key", Seed: "b1-seed"}
	if err := p.Run(context.Background(), art, opts); err != nil {
		t.Fatalf("执行失败: %v", err)
	}

	// ① 明文 DEX 必须全部消失
	for _, e := range pipeline.FindAll(art, isDexEntry) {
		t.Fatalf("明文 DEX %s 仍存在于产物中", e.NameString())
	}

	// ② 载荷必须存在、未压缩存储、且无法被当作 DEX 解析
	sp := payloadsOf(art)
	if sp == nil {
		t.Fatal("未写入载荷清单")
	}
	if len(sp.Items) != len(orig) {
		t.Fatalf("载荷数应为 %d，实际 %d", len(orig), len(sp.Items))
	}
	for _, p := range sp.Items {
		e := pipeline.Find(art, p.Asset)
		if e == nil {
			t.Fatalf("载荷条目 %s 不存在", p.Asset)
		}
		if !e.IsStored() {
			t.Fatalf("载荷 %s 应未压缩存储", p.Asset)
		}
		if _, err := dex.Parse(e.Raw); err == nil {
			t.Fatalf("载荷 %s 竟然仍是合法 DEX（未被加密）", p.Asset)
		}
		// ③ 用清单中的密钥必须能还原出原始明文
		got, err := pack.Decrypt(p.Blob, sp.Key)
		if err != nil {
			t.Fatalf("载荷 %s 解密失败: %v", p.Asset, err)
		}
		want, ok := orig[p.Name]
		if !ok {
			t.Fatalf("载荷 %s 的原始名 %s 不在记录中", p.Asset, p.Name)
		}
		if len(got) != len(want) {
			t.Fatalf("载荷 %s 还原长度不符: %d vs %d", p.Asset, len(got), len(want))
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("载荷 %s 第 %d 字节不符", p.Asset, i)
			}
		}
		// 还原出来的必须是一个自洽的 DEX
		if err := dex.Verify(got); err != nil {
			t.Fatalf("还原的 %s 校验失败: %v", p.Name, err)
		}
	}

	// ④ 载荷名不得泄露用途
	for _, p := range sp.Items {
		if strings.Contains(strings.ToLower(p.Asset), "dex") {
			t.Fatalf("载荷名泄露用途: %s", p.Asset)
		}
	}
	if art.Stats["B1.dex"] != "" && art.Stats["B1.dex"] != "0" {
		t.Logf("B1：%d 个 DEX 已加密为载荷；统计 %v", len(sp.Items), art.Stats)
	} else {
		t.Fatalf("统计缺失: %v", art.Stats)
	}
}

// TestEncryptDexKeepsFakeDex 验证伪装文件不被加密也不被删除。
//
// 伪装文件（magic 不符的 .dex）本就是干扰项，加密它既无防护价值，
// 又会让「一眼假」的迷惑效果消失；直接保留更合理。
func TestEncryptDexKeepsFakeDex(t *testing.T) {
	real, err := dex.Build(dex.Addition{
		Types:   []string{"Lcom/x/A;", "Ljava/lang/Object;"},
		Protos:  []dex.ProtoSpec{{Ret: "V"}},
		Methods: []dex.MethodSpec{{Class: "Ljava/lang/Object;", Name: "<init>", Proto: dex.ProtoSpec{Ret: "V"}}},
		Classes: []dex.ClassSpec{{
			Name: "Lcom/x/A;", Super: "Ljava/lang/Object;", Access: 1,
		}},
	})
	if err != nil {
		t.Fatalf("构造 DEX 失败: %v", err)
	}
	fake := append([]byte("dex\n035\x00"), []byte("this is not a real dex at all")...)

	art := newArtifact(
		zipxStored("classes.dex", real),
		zipxStored("CLASSES.DEX", fake),
	)
	p := &encryptDex{}
	if err := p.Run(context.Background(), art, &config.Options{DexKey: "k", Seed: "s"}); err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	if pipeline.Find(art, "classes.dex") != nil {
		t.Fatal("真实 DEX 应被移除")
	}
	if pipeline.Find(art, "CLASSES.DEX") == nil {
		t.Fatal("伪装文件应被保留")
	}
	sp := payloadsOf(art)
	if sp == nil || len(sp.Items) != 1 {
		t.Fatalf("应只加密 1 个真实 DEX，实际 %v", sp)
	}
}

// TestEncryptDexDeterministic 验证同参数可复现。
func TestEncryptDexDeterministic(t *testing.T) {
	real, err := dex.Build(dex.Addition{
		Types:   []string{"Lcom/x/A;", "Ljava/lang/Object;"},
		Protos:  []dex.ProtoSpec{{Ret: "V"}},
		Methods: []dex.MethodSpec{{Class: "Ljava/lang/Object;", Name: "<init>", Proto: dex.ProtoSpec{Ret: "V"}}},
		Classes: []dex.ClassSpec{{Name: "Lcom/x/A;", Super: "Ljava/lang/Object;", Access: 1}},
	})
	if err != nil {
		t.Fatalf("构造 DEX 失败: %v", err)
	}
	run := func() []byte {
		art := newArtifact(zipxStored("classes.dex", real))
		p := &encryptDex{}
		if err := p.Run(context.Background(), art, &config.Options{DexKey: "k", Seed: "s"}); err != nil {
			t.Fatalf("执行失败: %v", err)
		}
		sp := payloadsOf(art)
		return sp.Items[0].Blob
	}
	a, b := run(), run()
	if len(a) != len(b) {
		t.Fatalf("长度不一致: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatal("同参数两次加密结果不一致")
		}
	}
}

// TestEncryptDexNoParsable 验证没有可解析 DEX 时必须报错（而非静默产出空壳）。
func TestEncryptDexNoParsable(t *testing.T) {
	art := newArtifact(zipxStored("classes.dex", []byte("dex\n035\x00garbage")))
	p := &encryptDex{}
	if err := p.Run(context.Background(), art, &config.Options{DexKey: "k"}); err == nil {
		t.Fatal("没有可解析 DEX 时应报错")
	}
}

// simpleDexBytes 构造一个最小可解析 DEX，供 MAC 用例使用。
func simpleDexBytes(t *testing.T) []byte {
	t.Helper()
	real, err := dex.Build(dex.Addition{
		Types:   []string{"Lcom/x/A;", "Ljava/lang/Object;"},
		Protos:  []dex.ProtoSpec{{Ret: "V"}},
		Methods: []dex.MethodSpec{{Class: "Ljava/lang/Object;", Name: "<init>", Proto: dex.ProtoSpec{Ret: "V"}}},
		Classes: []dex.ClassSpec{{Name: "Lcom/x/A;", Super: "Ljava/lang/Object;", Access: 1}},
	})
	if err != nil {
		t.Fatalf("构造 DEX 失败: %v", err)
	}
	return real
}

// ---- 载荷 MAC 接线 ----

// TestPackMACB1 验证 -payload-mac 不再是空操作：
// B1 产出的载荷带 tag、清单标记 MAC、能经 DecryptMAC 还原、且有 Note/Stat 证据。
func TestPackMACB1(t *testing.T) {
	real := simpleDexBytes(t)
	art := newArtifact(zipxStored("classes.dex", real))
	opts := &config.Options{DexKey: "mac-key", Seed: "mac-seed", PayloadMAC: true}
	p := &encryptDex{}
	if err := p.Run(context.Background(), art, opts); err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	sp := payloadsOf(art)
	if sp == nil {
		t.Fatal("未写入载荷清单")
	}
	if !sp.MAC {
		t.Fatal("启用 PayloadMAC 后清单未标记 MAC")
	}
	if len(sp.Items) != 1 {
		t.Fatalf("应有 1 份载荷，实际 %d", len(sp.Items))
	}
	it := sp.Items[0]
	if !it.Tagged {
		t.Fatal("载荷未标记 Tagged")
	}
	if len(it.Blob) < pack.BlockSize+pack.TagSize {
		t.Fatalf("带 MAC 载荷过短: %d", len(it.Blob))
	}
	got, err := pack.DecryptMAC(it.Blob, sp.Key, it.Name)
	if err != nil {
		t.Fatalf("DecryptMAC 失败: %v", err)
	}
	if !bytes.Equal(got, real) {
		t.Fatal("带 MAC 载荷还原结果与原始 DEX 不一致")
	}
	// 不带 tag 的旧式 Decrypt 必须失败（否则说明 tag 没被排除在 CBC 之外）。
	if _, err := pack.Decrypt(it.Blob, sp.Key); err == nil {
		t.Fatal("未剥离 tag 时 Decrypt 不应成功")
	}
	// 空操作缺陷已修：必须有统计与 Note 证据。
	if art.Stats["B1.mac"] != "1" {
		t.Fatalf("B1.mac 统计不符: %v", art.Stats)
	}
	if art.Stats["B1.mac_bytes"] != "32" {
		t.Fatalf("B1.mac_bytes 应为 32: %v", art.Stats)
	}
	if len(art.Notes) == 0 || !strings.Contains(art.Notes[len(art.Notes)-1], "HMAC") {
		t.Fatalf("B1 未在 Note 中说明 MAC: %v", art.Notes)
	}
}

// TestPackNoMACCompatDisabled 验证 PayloadMAC=false 时与旧格式逐字节一致，
// 且清单标记为无 MAC（壳据此不生成任何校验指令）。
func TestPackNoMACCompatDisabled(t *testing.T) {
	real := simpleDexBytes(t)
	art := newArtifact(zipxStored("classes.dex", real))
	opts := &config.Options{DexKey: "k", Seed: "s"}
	p := &encryptDex{}
	if err := p.Run(context.Background(), art, opts); err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	sp := payloadsOf(art)
	if sp == nil || len(sp.Items) != 1 {
		t.Fatalf("载荷清单异常: %+v", sp)
	}
	it := sp.Items[0]
	if sp.MAC || it.Tagged {
		t.Fatal("未启用 MAC 时清单/载荷不应标记 MAC")
	}
	// 与 pack.Make 的旧格式产物逐字节比对。
	k, err := pack.Key("k")
	if err != nil {
		t.Fatal(err)
	}
	want, err := pack.Make([]pack.Dex{{Name: "classes.dex", Data: real}}, k, "s")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(it.Blob, want[0].Blob) {
		t.Fatal("未启用 MAC 的产物格式与旧版不一致")
	}
	if got, err := pack.Decrypt(it.Blob, sp.Key); err != nil || !bytes.Equal(got, real) {
		t.Fatal("未启用 MAC 时解密行为应不变")
	}
	if art.Stats["B1.mac"] != "0" {
		t.Fatalf("B1.mac 应为 0: %v", art.Stats)
	}
}

// TestPackMACB3Wiring 在真实样本上跑 B1→B2→B3，验证 B3 把载荷 MAC 开关
// 真的接进了壳 DEX（而不是只在 B1 打了标记）。
//
// 没有这条，B1 与 B3 之间任何一处字段漏接都会让壳对带 tag 的载荷
// 要么不校验（防护失效）、要么对未带 tag 的载荷误校验（合法产物启动即死）。
func TestPackMACB3Wiring(t *testing.T) {
	art := loadSample(t)
	opts := shellOpts()
	opts.PayloadMAC = true
	runShellChain(t, art, opts)

	sp := payloadsOf(art)
	if sp == nil || !sp.MAC {
		t.Fatalf("B1 载荷清单未标记 MAC: %+v", sp)
	}
	if art.Stats["B3.mac"] != "1" {
		t.Fatalf("B3 未记录 MAC 已接线: %v", art.Stats)
	}
	e := pipeline.Find(art, "classes.dex")
	if e == nil {
		t.Fatal("未找到壳 DEX")
	}
	data, err := e.Data()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte("HmacSHA256")) || !bytes.Contains(data, []byte("apkguard/payload-mac")) {
		t.Fatal("壳 DEX 不含 MAC 校验指令：B3 未接线 PayloadMAC")
	}
	if err := dex.Verify(data); err != nil {
		t.Fatalf("壳 DEX 校验失败: %v", err)
	}
}

// TestPackNoMACB3Wiring 对照：未启用 MAC 时壳 DEX 不应含 MAC 引用。
func TestPackNoMACB3Wiring(t *testing.T) {
	art := loadSample(t)
	opts := shellOpts()
	runShellChain(t, art, opts)

	if sp := payloadsOf(art); sp == nil || sp.MAC {
		t.Fatalf("未启用 MAC 时清单不应标记: %+v", sp)
	}
	e := pipeline.Find(art, "classes.dex")
	if e == nil {
		t.Fatal("未找到壳 DEX")
	}
	data, err := e.Data()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("HmacSHA256")) {
		t.Fatal("未启用 MAC 时壳 DEX 不应含 HmacSHA256")
	}
	if art.Stats["B3.mac"] != "0" {
		t.Fatalf("B3.mac 应为 0: %v", art.Stats)
	}
}

// TestPackMACWithB8 验证 B8（载荷容器化改名）之后 MAC 仍然对得上。
//
// 这是方案文档点名的最高风险陷阱：B8 在 B1 之后重命名 Payload.Asset，
// 若 MAC 绑定的是 Asset 而不是 Name，容器化后的合法产物会在壳侧校验失败、
// 启动即终止。这里显式跑 B1→B8→B2→B3 并用改名后的载荷做参考解。
func TestPackMACWithB8(t *testing.T) {
	art := loadSample(t)
	opts := shellOpts()
	opts.PayloadMAC = true
	ctx := context.Background()

	for _, p := range []pipeline.Pass{&encryptDex{}, &payloadContainer{}, &appReplace{}, &classLoader{}} {
		if err := p.Run(ctx, art, opts); err != nil {
			t.Fatalf("功能项 %s 执行失败: %v", p.ID(), err)
		}
	}

	sp := payloadsOf(art)
	if sp == nil || !sp.MAC {
		t.Fatalf("载荷清单未标记 MAC: %+v", sp)
	}
	for _, it := range sp.Items {
		// B8 必须已把 Asset 移入容器目录（不再是顶层）。
		if !strings.HasPrefix(it.Asset, "assets/") || strings.Count(it.Asset, "/") < 2 {
			t.Fatalf("B8 未完成容器化改名: %s", it.Asset)
		}
		// 用原始 DEX 名（Name）才能解开；这正是壳侧内联的那个值。
		plain, err := pack.DecryptMAC(it.Blob, sp.Key, it.Name)
		if err != nil {
			t.Fatalf("容器化后载荷 %s 的 MAC/解密失败（说明 MAC 绑定了 Asset 而非 Name）: %v", it.Asset, err)
		}
		// 用改名后的 Asset 作为 name 必须失败（反证绑定的是 Name）。
		if _, err := pack.DecryptMAC(it.Blob, sp.Key, it.Asset); err == nil {
			t.Fatalf("用 Asset 名竟然通过了 MAC：绑定对象错误")
		}
		_ = plain
	}
}
