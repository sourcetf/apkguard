package passes

import (
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
