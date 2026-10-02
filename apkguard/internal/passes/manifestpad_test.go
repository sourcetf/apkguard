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

// TestManifestPadIsStoredNotCompressed 钉住「填充条目必须未压缩存放」。
//
// A15 的目的是让**包内**体积与读取成本都变大；若被 Deflate 压成几百 KB，
// 体积压力就消失了（参考样本压缩后仅 367 KB，其实削弱了自己的效果）。
func TestManifestPadIsStoredNotCompressed(t *testing.T) {
	raw := realisticAXML(newRand("pad2"), 512)
	art := newArtifact(zipx.NewStored(manifestName, raw))
	opts := &config.Options{Enabled: map[config.FeatureID]bool{"A15": true}, ManifestPadMB: 1}
	if err := (&manifestPad{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A15 执行失败: %v", err)
	}
	if got := art.Entries()[0]; !got.IsStored() {
		t.Fatalf("填充后的 Manifest 是压缩存放（method=%d），体积压力被抹掉", got.Method)
	}
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
