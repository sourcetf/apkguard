package pipeline

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"apkguard/internal/config"
	"apkguard/internal/zipx"
)

// 本文件是「不在 Pass 注册表里、却标为已实现」那几个功能项的**功能性守卫**。
//
// 背景：E1/E2/E3 由收尾流程（DefaultSink）实现，E5 由 CLI 的批量入口实现，
// 因此都不出现在 passes.Registry() 里。passes 包的
// TestImplementedMatchesRegistry 为了不误报，只能把它们**无条件**当作已实现，
// 于是「实现被删掉、implementedIDs 还留着」这种失败模式它发现不了。
//
// 这里用真实运行补上这道缺口：删掉 sink 里对应分支，下面的断言就会失败。
// 每一项都做**正例 + 反例**——只断言「不报错」是抓不到静默失效的。

// localHeaderOffsets 扫描本地文件头，返回「条目名 → 数据区起始偏移」。
//
// 不搜索 PK\x03\x04 而是按头部声明的长度**顺序推进**：搜索会被条目内容里
// 恰好出现的同样字节骗到，顺序推进不会。本项目的写方总是把长度写在本地头里
// （不使用数据描述符），因此这条路径与真实读方一致。
func localHeaderOffsets(data []byte) map[string]int {
	out := map[string]int{}
	p := 0
	for p+30 <= len(data) {
		if !bytes.Equal(data[p:p+4], []byte("PK\x03\x04")) {
			break
		}
		csize := int(binary.LittleEndian.Uint32(data[p+18:]))
		nlen := int(binary.LittleEndian.Uint16(data[p+26:]))
		elen := int(binary.LittleEndian.Uint16(data[p+28:]))
		if p+30+nlen+elen > len(data) {
			break
		}
		name := string(data[p+30 : p+30+nlen])
		out[name] = p + 30 + nlen + elen
		p += 30 + nlen + elen + csize
	}
	return out
}

// unsignedInput 摘掉样本里的签名条目后写出临时 APK，返回其路径。
func unsignedInput(t *testing.T) string {
	t.Helper()
	art, err := Load(sampleAPK(t))
	if err != nil {
		t.Fatalf("读取样本失败: %v", err)
	}
	Remove(art, func(e *zipx.Entry) bool {
		return strings.HasPrefix(e.NameString(), "META-INF/")
	})
	raw := zipx.Write(art.Archive, zipx.AlignOptions{Align: 1, SoAlign: 1})
	p := filepath.Join(t.TempDir(), "unsigned.apk")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatalf("写出临时输入失败: %v", err)
	}
	return p
}

// TestE1SigningIsActuallyImplemented 验证 E1 真的产出了签名（v1 + v2/v3 签名块）。
//
// 判据取自产物字节本身；同时做反例：关掉 E1 时这两样都必须不存在，
// 否则说明「E1 开关并没有真正控制签名」。
func TestE1SigningIsActuallyImplemented(t *testing.T) {
	ks := writeTestKeystore(t, "123456")
	// 输入必须是**未签名**的：样本自带 META-INF，拿它当输入时「关掉 E1 就没有
	// MANIFEST.MF」这条反例不成立（E1 关闭时收尾流程原样返回，不会剥掉输入里
	// 已有的签名文件）。这里先把签名条目摘掉，再写出临时输入。
	in := unsignedInput(t)
	run := func(e1 bool) []byte {
		pipe := New(NewRegistry(), DefaultSink{})
		res, err := pipe.Run(context.Background(), &config.Options{
			In:      in,
			Enabled: map[config.FeatureID]bool{"E1": e1, "E2": true, "E3": false},
			KS:      ks, KSPass: "123456",
		})
		if err != nil {
			t.Fatalf("执行失败（E1=%v）: %v", e1, err)
		}
		return res.APK
	}

	on := run(true)
	if !bytes.Contains(on, []byte("APK Sig Block 42")) {
		t.Fatal("启用 E1 后产物里没有 v2/v3 签名块——签名实现缺失")
	}
	zr, err := zipx.Read(on)
	if err != nil {
		t.Fatalf("解析签名产物失败: %v", err)
	}
	if zr.Find("META-INF/MANIFEST.MF") == nil {
		t.Fatal("启用 E1 后产物里没有 META-INF/MANIFEST.MF——v1 签名实现缺失")
	}

	off := run(false)
	if bytes.Contains(off, []byte("APK Sig Block 42")) {
		t.Fatal("未启用 E1 的产物却有签名块（E1 开关没有真正控制签名）")
	}
	zr2, err := zipx.Read(off)
	if err != nil {
		t.Fatalf("解析未签名产物失败: %v", err)
	}
	if zr2.Find("META-INF/MANIFEST.MF") != nil {
		t.Fatal("未启用 E1 的产物却有 MANIFEST.MF")
	}
}

// TestE2AlignmentIsActuallyImplemented 验证 E2 真的做了对齐。
//
// 判据：启用 E2 时全部未压缩条目的数据偏移都对齐到 4 字节；
// 反例：关掉 E2 时，一个刻意造出的未对齐输入必须**保持**未对齐。
func TestE2AlignmentIsActuallyImplemented(t *testing.T) {
	ks := writeTestKeystore(t, "123456")
	build := func() *Artifact {
		art, err := Load(sampleAPK(t))
		if err != nil {
			t.Fatalf("读取样本失败: %v", err)
		}
		// 长度取质数，确保数据区起点不是 4 的倍数。
		Add(art, zipx.NewStored("assets/odd.bin", []byte(strings.Repeat("x", 3))))
		return art
	}
	run := func(e2 bool) []byte {
		out, err := DefaultSink{}.Finish(context.Background(), build(), &config.Options{
			Enabled: map[config.FeatureID]bool{"E1": true, "E2": e2, "E3": false},
			KS:      ks, KSPass: "123456",
		})
		if err != nil {
			t.Fatalf("收尾失败（E2=%v）: %v", e2, err)
		}
		return out
	}
	unaligned := func(data []byte) []string {
		zr, err := zipx.Read(data)
		if err != nil {
			t.Fatalf("解析产物失败: %v", err)
		}
		offs := localHeaderOffsets(data)
		var out []string
		for _, e := range zr.Entries {
			if !e.IsStored() || e.IsDir() {
				continue
			}
			off, ok := offs[e.NameString()]
			if !ok {
				continue
			}
			if off%4 != 0 {
				out = append(out, e.NameString())
			}
		}
		return out
	}

	if got := unaligned(run(true)); len(got) != 0 {
		t.Fatalf("启用 E2 后仍有未 4 字节对齐的条目：%v（对齐实现缺失）", got)
	}
	if got := unaligned(run(false)); len(got) == 0 {
		t.Fatal("关掉 E2 后产物仍然全部对齐（E2 开关没有真正控制对齐）")
	}
}

// TestE3SelfCheckIsActuallyImplemented 验证 E3 真的在自检。
//
// 判据用**反例**：缺 AndroidManifest.xml 的产物在启用 E3 时必须报错，
// 且错误来自 E3 自检（而不是签名阶段的其它错误）——所以先确认同一份产物
// 在**关掉 E3** 时不报错。若 E3 的实现被删掉（永远不报错），正例会失败。
func TestE3SelfCheckIsActuallyImplemented(t *testing.T) {
	ks := writeTestKeystore(t, "123456")
	broken := func() *Artifact {
		art, err := Load(sampleAPK(t))
		if err != nil {
			t.Fatalf("读取样本失败: %v", err)
		}
		if Remove(art, func(e *zipx.Entry) bool { return e.NameString() == "AndroidManifest.xml" }) == 0 {
			t.Fatal("构造失败：样本里没有 AndroidManifest.xml 可移除")
		}
		return art
	}
	finish := func(e3 bool) error {
		_, err := DefaultSink{}.Finish(context.Background(), broken(), &config.Options{
			Enabled: map[config.FeatureID]bool{"E1": true, "E2": true, "E3": e3},
			KS:      ks, KSPass: "123456",
		})
		return err
	}

	off := finish(false)
	if off != nil {
		t.Fatalf("关掉 E3 时不应报错（说明下面的失败来自别处，判据不成立）: %v", off)
	}
	on := finish(true)
	if on == nil {
		t.Fatal("产物缺 AndroidManifest.xml，启用 E3 却没有报错——自检实现缺失")
	}
	if !strings.Contains(on.Error(), "AndroidManifest.xml") {
		t.Fatalf("E3 的报错应点名缺失的条目，实际: %v", on)
	}
}
