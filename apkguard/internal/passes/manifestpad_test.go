package passes

import (
	"context"
	"encoding/binary"
	"testing"

	"apkguard/internal/axml"
	"apkguard/internal/config"
	"apkguard/internal/zipx"
)

// TestManifestPadKeepsManifestParsable 是 A15 的**决定性判据**。
//
// 填充的价值来自「撑大体积但保持可解析」：一旦真实内容读不到，应用就装不上，
// 属于自伤。因此这里断言：
//   - 体积确实被撑大（否则没起到作用）；
//   - 我们的 axml 解析器仍能读出 root 元素（证明填充 chunk 的声明长度串到了真实内容上）；
//   - 顶层 XML chunk 的 size 被更新为整个新文件长度。
func TestManifestPadKeepsManifestParsable(t *testing.T) {
	// 用 xmlish 构造一份最小但真实的 AXML：直接复用垃圾 XML 生成器，
	// 它的结构与我们真实产物的 Manifest 同构（XML chunk + 池 + 元素）。
	raw := realisticAXML(newRand("pad"), 512)
	before, err := axml.Parse(raw)
	if err != nil || len(before.Elements) == 0 {
		t.Fatalf("构造的基准 AXML 无法解析：err=%v 元素=%d", err, len(before.Elements))
	}

	art := newArtifact(zipx.NewStored(manifestName, raw))
	// 用 1 MB 做测试（默认 100 MB 太慢），逻辑与参数无关
	opts := &config.Options{
		Enabled:       map[config.FeatureID]bool{"A15": true},
		ManifestPadMB: 1,
	}
	if err := (&manifestPad{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A15 执行失败: %v", err)
	}

	e := art.Entries()[0]
	data, err := e.Data()
	if err != nil {
		t.Fatalf("读取产物失败: %v", err)
	}
	if len(data) < 1<<20 {
		t.Fatalf("填充后体积只有 %d 字节，未达到 1 MB", len(data))
	}

	// 顶层 XML chunk 的 size 必须等于整个新文件长度
	if typ := binary.LittleEndian.Uint16(data[0:]); typ != 0x0003 {
		t.Fatalf("顶层类型应为 XML chunk，实际 0x%04x", typ)
	}
	if sz := int(binary.LittleEndian.Uint32(data[4:])); sz != len(data) {
		t.Fatalf("顶层 size=%d 应等于文件长度 %d", sz, len(data))
	}

	// 关键：解析器必须仍能找到真实内容
	after, err := axml.Parse(data)
	if err != nil {
		t.Fatalf("填充后无法解析（应用会装不上）：%v", err)
	}
	if len(after.Elements) != len(before.Elements) {
		t.Fatalf("填充前后元素数不同：%d -> %d", len(before.Elements), len(after.Elements))
	}
	if len(after.Elements) > 0 && after.Elements[0].Name != before.Elements[0].Name {
		t.Fatalf("填充后元素名被破坏：%q -> %q", before.Elements[0].Name, after.Elements[0].Name)
	}
	t.Logf("A15：%d -> %d 字节，填充后仍能解析出 %d 个元素（%s）",
		len(raw), len(data), len(after.Elements), after.Elements[0].Name)
}

// TestManifestPadIsCompressed 钉住「填充条目必须压缩存放」。
//
// 【为什么这条断言的语义与旧版相反】旧实现断言的是 IsStored（未压缩），
// 因为当时认为压缩会把几十 MB 的零压成几百 KB、从而抹掉体积压力。但实测
// 参考样本 sample.apk 推翻了这一点：它的 AndroidManifest.xml 解压后
// 369,623,060 字节，压缩后仅 367,318 字节（压缩比约 0.001），中央目录里
// 的压缩方式字段是 8（deflate）。既然 **Android 系统接受压缩存储的
// AndroidManifest.xml**，压缩就是纯收益：解压后体积与读取压力分毫不减，
// 包体却省约 1000 倍。因此断言反转为「必须是压缩存放」。
func TestManifestPadIsCompressed(t *testing.T) {
	raw := realisticAXML(newRand("pad2"), 512)
	art := newArtifact(zipx.NewStored(manifestName, raw))
	opts := &config.Options{Enabled: map[config.FeatureID]bool{"A15": true}, ManifestPadMB: 1}
	if err := (&manifestPad{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A15 执行失败: %v", err)
	}
	got := art.Entries()[0]
	if got.IsStored() {
		t.Fatalf("填充后的 Manifest 是未压缩存放（method=%d），包体会被填充实打实撑大", got.Method)
	}
	if got.Method != 8 {
		t.Fatalf("填充后的 Manifest 压缩方式应为 8（deflate），实际 %d", got.Method)
	}
	// 解压后体积必须仍是「巨型」：压缩不能成为偷工减料的借口。
	data, err := got.Data()
	if err != nil {
		t.Fatalf("解压产物失败: %v", err)
	}
	if len(data) < 1<<20 {
		t.Fatalf("解压后仅 %d 字节，未达到 1 MB 填充量", len(data))
	}
	// 防回归断言：填充内容是零，deflate 压缩比必须远小于 0.01。
	// 若有人为了「让包体更小」把零填充换成随机数据，随机数据不可压缩，
	// 压缩比会立刻逼近 1，这条断言就会失败。
	ratio := float64(got.CompSize) / float64(got.UncompSize)
	if ratio >= 0.01 {
		t.Fatalf("压缩比 %.5f 未达标（应 < 0.01）：填充内容可能不是零，而是随机数据", ratio)
	}
	t.Logf("A15：解压 %d 字节 / 压缩 %d 字节，压缩比 %.5f", got.UncompSize, got.CompSize, ratio)
}

// TestManifestPadDefaultSize 校验未指定尺寸时用默认值（100 MB）。
func TestManifestPadDefaultSize(t *testing.T) {
	raw := realisticAXML(newRand("pad3"), 256)
	art := newArtifact(zipx.NewStored(manifestName, raw))
	opts := &config.Options{Enabled: map[config.FeatureID]bool{"A15": true}}
	if err := (&manifestPad{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A15 执行失败: %v", err)
	}
	data, _ := art.Entries()[0].Data()
	want := defaultManifestPadMB << 20
	if len(data) < want {
		t.Fatalf("默认填充应至少 %d 字节，实际 %d", want, len(data))
	}
	t.Logf("默认填充量 = %d MB", defaultManifestPadMB)
}
