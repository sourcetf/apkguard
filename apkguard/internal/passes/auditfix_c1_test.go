package passes

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/pipeline"
	"apkguard/internal/zipx"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// TestC1KeyNotInlinedAndDerivedFromNative 是 C1 接线的决定性回归。
//
// 修前：B2 只把桥接类名写进 ShellAppRef.NativeKey（一个 dex 层从未读取的
// 死字段），B3 构造 LoaderSpec 时也没有设置 NativeKey，于是 dex 层走 else
// 分支把 32 字节 AES 密钥逐字节内联进壳字节码——安全声明与实现相反。
//
// 修后：壳信息把 NativeKey 传给 LoaderSpec，字节码里必须存在对 native 桥接类
// 的 invoke-static，且密钥不可再从常量指令里还原。
func TestC1KeyNotInlinedAndDerivedFromNative(t *testing.T) {
	key, cert := testKeyMaterial(t)
	pfx, err := pkcs12.Modern.Encode(key, cert, nil, "123456")
	if err != nil {
		t.Fatalf("生成 PKCS12 失败: %v", err)
	}
	ksPath := filepath.Join(t.TempDir(), "k.pfx")
	if err := os.WriteFile(ksPath, pfx, 0o600); err != nil {
		t.Fatalf("写出密钥库失败: %v", err)
	}

	// 自足产物：真实结构的清单（含 <application android:name>）与一个可解析 DEX。
	art := newArtifact(
		zipx.NewStored("AndroidManifest.xml", nestedAPKManifestAXML(newRand("audit-c1"), "com.agtest")),
		zipx.NewStored("classes.dex", smallDexWithClass(t, "Lcom/agtest/MainActivity;")),
	)
	opts := &config.Options{
		Enabled: map[config.FeatureID]bool{
			"B1": true, "B2": true, "B3": true, "C1": true, "E1": true, "E2": true,
		},
		KS: ksPath, KSPass: "123456",
		Seed: "audit-c1",
	}
	ctx := context.Background()
	// 顺序与注册表一致：B1 加密 → B2 建壳 → B3 注入 Loader → C1 注入桥接类。
	for _, p := range []pipeline.Pass{&encryptDex{}, &appReplace{}, &classLoader{}, &nativeKeyDerive{}} {
		if err := p.Run(ctx, art, opts); err != nil {
			t.Fatalf("功能项 %s 执行失败: %v", p.ID(), err)
		}
	}

	sp := payloadsOf(art)
	if sp == nil || len(sp.Items) == 0 {
		t.Fatal("B1 未产出载荷清单")
	}
	key32 := sp.Key // B1 在 C1 下用的就是 native 派生密钥

	info, _ := art.Get(sharedKeyShell).(*shellInfo)
	if info == nil {
		t.Fatal("B2 未写入壳信息")
	}
	// 接线第一环：B2 必须把 C1 的桥接类名带进壳信息。
	if info.NativeKey == "" {
		t.Fatalf("壳信息 NativeKey 为空：C1 的 native 派生未从 B2 接线到 B3")
	}
	e := pipeline.Find(art, info.EntryName)
	if e == nil {
		t.Fatalf("壳 DEX 条目 %s 不存在", info.EntryName)
	}
	data, err := e.Data()
	if err != nil {
		t.Fatalf("读取壳 DEX 失败: %v", err)
	}
	f, err := dex.Parse(data)
	if err != nil {
		t.Fatalf("解析壳 DEX 失败: %v", err)
	}

	// (a1) 字面连续字节里不得出现完整 32 字节密钥。
	if bytes.Contains(data, key32[:]) {
		t.Fatalf("壳 DEX 中出现了完整的 32 字节内联密钥（C1 的 native 派生未生效）: %x", key32[:])
	}
	// (a2) 关键：密钥也不得能通过读取 const/16 常量指令还原。
	// dex 层的 else 分支用「每个密钥字节一条 const/16 + 一条 const/16 下标 +
	// aput-byte」把密钥写进字节码；这里模拟攻击者按常量对还原密钥。
	if got, ok := recoverConst16Key(f); ok {
		t.Fatalf("壳 DEX 的常量指令可还原出 AES 密钥（C1 的 native 派生未接线）: %x", got)
	}
	// (b) 必须存在对 native 桥接类 derive 的 invoke-static 调用。
	if n := countInvokeStaticTo(t, f, dex.NativeBridgeClass, dex.NativeDerive); n == 0 {
		t.Fatalf("壳字节码里找不到对 %s->%s 的 invoke-static（未生成 native 派生调用）",
			dex.NativeBridgeClass, dex.NativeDerive)
	}
	t.Logf("C1 已接线：壳 DEX 常量里无法还原密钥，且存在 %s->%s 的 invoke-static",
		dex.NativeBridgeClass, dex.NativeDerive)
}

// recoverConst16Key 尝试从 DEX 的 const/16 指令对里还原出「32 字节密钥 + 下标」
// 的逐字节内联序列。返回还原出的密钥与是否成功。
//
// 这是 dex 层 NativeKey == "" 时 else 分支的字节码指纹：
//
//	const/16 vA, #byte      （0x13, 1:byte）
//	const/16 vB, #index     （0x13, 2:index）
//	aput-byte vA, vKey, vB
//
// 若某处按 index = 0..31 各出现一次且 byte 依次构成一把 32 字节密钥，即判为命中。
func recoverConst16Key(f *dex.File) ([32]byte, bool) {
	var out [32]byte
	seen := map[int]byte{}
	data := f.Data()
	_ = f.AllMethods(func(_ string, _ string, m dex.EncodedMethod) error {
		if m.CodeOff == 0 {
			return nil
		}
		ci, err := f.CodeInsns(m.CodeOff)
		if err != nil {
			return nil
		}
		insns := data[ci.InsnsOff : ci.InsnsOff+int(ci.InsnsSize)*2]
		for i := 0; i+3 < len(insns)/2; i++ {
			w := binary.LittleEndian.Uint16(insns[i*2:])
			if w&0xff != 0x13 {
				continue
			}
			bVal := binary.LittleEndian.Uint16(insns[(i+1)*2:])
			w2 := binary.LittleEndian.Uint16(insns[(i+2)*2:])
			if w2&0xff != 0x13 {
				continue
			}
			idx := binary.LittleEndian.Uint16(insns[(i+3)*2:])
			if idx < 32 {
				seen[int(idx)] = byte(bVal)
			}
		}
		return nil
	})
	for i := 0; i < 32; i++ {
		b, ok := seen[i]
		if !ok {
			return out, false
		}
		out[i] = b
	}
	return out, true
}

// countInvokeStaticTo 统计 DEX 中 invoke-static 指向 (class, name) 的次数。
func countInvokeStaticTo(t *testing.T, f *dex.File, wantClass, wantName string) int {
	t.Helper()
	data := f.Data()
	count := 0
	err := f.AllMethods(func(_ string, _ string, m dex.EncodedMethod) error {
		if m.CodeOff == 0 {
			return nil
		}
		ci, err := f.CodeInsns(m.CodeOff)
		if err != nil {
			return nil
		}
		words := int(ci.InsnsSize)
		insns := data[ci.InsnsOff : ci.InsnsOff+words*2]
		for i := 0; i+1 < words; i++ {
			w := binary.LittleEndian.Uint16(insns[i*2:])
			if w&0xff != 0x71 { // invoke-static
				continue
			}
			idx := binary.LittleEndian.Uint16(insns[(i+1)*2:])
			cls, name, _, _, err := f.MethodFull(uint32(idx))
			if err == nil && cls == wantClass && name == wantName {
				count++
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("遍历 DEX 方法失败: %v", err)
	}
	return count
}
