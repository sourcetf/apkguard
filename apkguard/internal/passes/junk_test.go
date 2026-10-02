package passes

import (
	"bytes"
	"context"
	"testing"

	"apkguard/internal/axml"
	"apkguard/internal/config"
	"apkguard/internal/zipx"
)

// TestJunkXMLIsParsableAXML 钉住「垃圾 XML 必须是能被解析的真 AXML」。
//
// 参考样本的 885 个顶层垃圾文件每一个都是 388 字节的合法 AXML；而早期实现只塞了
// 8 字节头（magic + headerSize + chunkSize），扫描器一次解析失败就把整类丢弃，
// 反而更快定位到真文件。垃圾条目的价值在于**消耗分析者的时间**，因此它必须：
//   - 能被 axml.Parse 解析出元素（不是坏文件）；
//   - 有像样的体积（不是一眼假的最小头）。
func TestJunkXMLIsParsableAXML(t *testing.T) {
	art := newArtifact(zipx.NewStored("AndroidManifest.xml", []byte{0}))
	opts := &config.Options{
		Enabled:      map[config.FeatureID]bool{"A10": true},
		Seed:         "junk",
		JunkTopCount: 20,
		JunkDirCount: 20,
		JunkDirDepth: 6,
	}
	if err := (&junkEntries{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A10 执行失败: %v", err)
	}

	checked, minSize := 0, 1<<30
	for _, e := range art.Entries() {
		n := e.NameString()
		if !bytes.HasSuffix([]byte(n), []byte(".xml")) || n == "AndroidManifest.xml" {
			continue
		}
		data, err := e.Data()
		if err != nil {
			t.Fatalf("读取 %s 失败: %v", n, err)
		}
		f, err := axml.Parse(data)
		if err != nil {
			t.Fatalf("%s 不是可解析的 AXML: %v（垃圾 XML 必须能通过解析，否则会被扫描器整类丢弃）", n, err)
		}
		if len(f.Elements) == 0 {
			t.Fatalf("%s 解析成功但没有任何元素，仍会被判定为「空壳」", n)
		}
		// 语义也要对：元素名非空、属性带正确的 android 命名空间。
		// 下标算错时 aapt2 仍能「解析」（它只是按索引取字符串），但取到的是
		// 乱七八糟的名字——那种垃圾 XML 一眼就能看出是生成的。
		el := f.Elements[0]
		if el.Name == "" || el.Name == "TextView" {
			t.Fatalf("%s 的元素名解析成了 %q（应为随机根元素名）", n, el.Name)
		}
		for _, a := range el.Attrs {
			if a.NSName != "http://schemas.android.com/apk/res/android" {
				t.Fatalf("%s 的属性 %q 命名空间为 %q，应为 android 命名空间 URI（下标错位）",
					n, a.Name, a.NSName)
			}
			if a.Name == "" {
				t.Fatalf("%s 存在空属性名", n)
			}
		}
		if len(data) < minSize {
			minSize = len(data)
		}
		checked++
	}
	if checked < 10 {
		t.Fatalf("只生成了 %d 个垃圾 XML，覆盖不足", checked)
	}
	if minSize < 200 {
		t.Fatalf("最小的垃圾 XML 只有 %d 字节，太小容易被一眼识破（参考样本是 388 字节）", minSize)
	}
	t.Logf("已生成 %d 个可解析的垃圾 AXML，最小 %d 字节", checked, minSize)
}

// TestJunkHasDeepAliasDirs 钉住「同名单目录深层路径」的存在。
//
// 样本用 76 层同名目录制造超长路径，触发解包工具的路径长度/递归问题。
func TestJunkHasDeepAliasDirs(t *testing.T) {
	art := newArtifact(zipx.NewStored("AndroidManifest.xml", []byte{0}))
	opts := &config.Options{
		Enabled:      map[config.FeatureID]bool{"A10": true},
		Seed:         "deep",
		JunkDirCount: 20, // 每 10 条配 1 条同名深层目录
		JunkDirDepth: 4,
	}
	if err := (&junkEntries{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A10 执行失败: %v", err)
	}
	maxDepth, maxLen := 0, 0
	for _, e := range art.Entries() {
		n := e.NameString()
		if !bytes.HasPrefix([]byte(n), []byte("assets/")) {
			continue
		}
		seg := bytes.Split([]byte(n), []byte("/"))
		if len(seg)-2 > maxDepth {
			maxDepth = len(seg) - 2
		}
		if len(n) > maxLen {
			maxLen = len(n)
		}
	}
	if maxDepth < 40 {
		t.Fatalf("最深的目录只有 %d 层，未达到「同名深层路径」的规模（参考样本 76 层）", maxDepth)
	}
	t.Logf("已生成同名深层目录：最深 %d 层、最长路径 %d 字节", maxDepth, maxLen)
}

// TestPathAttackHasSeparatorVariants 钉住 A12 的分隔符变体。
//
// 只生成 "/随机名" 会漏掉「混合分隔符 / 重复斜杠 / .9.png 伪装」这几类形态，
// 而它们正是不同工具规范化行为分叉的地方（参考样本就用了 `\/`、`/////`、`.9.png`）。
func TestPathAttackHasSeparatorVariants(t *testing.T) {
	art := newArtifact(zipx.NewStored("AndroidManifest.xml", []byte{0}))
	opts := &config.Options{
		Enabled:     map[config.FeatureID]bool{"A12": true},
		Seed:        "atk",
		ZipAtkCount: 20,
	}
	if err := (&zipPathAttack{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A12 执行失败: %v", err)
	}
	var hasBackslash, hasRepeatedSlash, hasNinePatch, hasDotDot bool
	for _, e := range art.Entries() {
		n := e.NameString()
		if !bytes.HasPrefix([]byte(n), []byte("/")) {
			continue
		}
		if bytes.Contains([]byte(n), []byte(`\/`)) {
			hasBackslash = true
		}
		if bytes.Contains([]byte(n), []byte("////")) {
			hasRepeatedSlash = true
		}
		if bytes.HasSuffix([]byte(n), []byte(".9.png")) {
			hasNinePatch = true
		}
		if bytes.Contains([]byte(n), []byte("/../")) {
			hasDotDot = true
		}
	}
	if !hasBackslash || !hasRepeatedSlash || !hasNinePatch || !hasDotDot {
		t.Fatalf("路径攻击形态不全：混合分隔符=%v 重复斜杠=%v .9.png=%v 点段=%v",
			hasBackslash, hasRepeatedSlash, hasNinePatch, hasDotDot)
	}
	t.Log("路径攻击已覆盖：混合分隔符、重复斜杠、.9.png 伪装、点段穿越")
}
