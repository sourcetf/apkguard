package dex

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// 本文件是「C2 原生库载荷纳入 -payload-mac」这一收口的测试。
//
// 背景：-payload-mac 此前只保护 B1 的 DEX 载荷（pack.MakeMAC 在密文尾部追加
// HMAC-SHA256，壳侧解密前校验），而 C2 加密的原生库载荷没有 MAC、壳侧库解密
// 路径也不校验。启用该开关的使用方会误以为「载荷都被保护了」。
//
// 修后：LoaderSpec.MAC 为真时，Loader 对**每一份库载荷**也在解密前调用同一个
// v() 做 HMAC 校验，绑定原始库名（如 "libfoo.so"，与 DEX 绑定原始 DEX 名同理）；
// 关闭时生成的字节码与旧版逐字节一致（见 TestAuditfix3bLibMACDisabled*）。

// auditfix3bLibIV 是库载荷测试用的固定 IV（与 DEX 载荷 IV 不同，
// 以暴露「IV/载荷错位」这类错误）。
var auditfix3bLibIV = [16]byte{0xaa, 0xbb, 0xcc, 0xdd, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}

// auditfix3bLibPlain 是库载荷的明文（形如 ELF，避免与 DEX 混淆）。
var auditfix3bLibPlain = []byte("\x7fELF\x02\x01\x01\x00libfoo-for-c2-mac-test-payload")

// auditfix3bLibSpec 构造「DEX 载荷 + 库载荷都带 MAC」的 Loader 规格。
func auditfix3bLibSpec(key [32]byte, dexBlob, libBlob []byte, libName string) *LoaderSpec {
	return &LoaderSpec{
		Class: "Lcom/apkguard/shell/Loader;", Key: key, TempDir: "ag", MAC: true,
		LibDir: "aglib", LibReadOnly: true,
		Items: []LoaderItem{{
			Asset: "assets/d.bin", Name: "classes.dex", DexName: "d0.dex", Size: len(dexBlob),
		}},
		LibItems: []LoaderLibItem{{
			Asset: "assets/l.bin", Name: libName, Abi: "x86_64", Size: len(libBlob),
		}},
	}
}

// TestAuditfix3bLoaderLibMACRoundTrip 验证启用 MAC 时库载荷的正向链路：
// 合法（带 tag）的库载荷通过壳侧 HMAC 校验，并被正确解密落地。
func TestAuditfix3bLoaderLibMACRoundTrip(t *testing.T) {
	key := testPackKey
	dexPlain := Empty()
	dexBlob := mustEncryptMAC(t, dexPlain, key, testPackIV, "classes.dex")
	libBlob := mustEncryptMAC(t, auditfix3bLibPlain, key, auditfix3bLibIV, "libfoo.so")

	ls := auditfix3bLibSpec(key, dexBlob, libBlob, "libfoo.so")
	env := &loaderEnv{
		assets: map[string][]byte{"d.bin": dexBlob, "l.bin": libBlob},
		fs:     map[string][]byte{},
	}
	runLoaderEntry(t, ls, env)

	if env.exited {
		t.Fatalf("合法库载荷不应触发 MAC 失败终止（exit=%v）", env.exitCodes)
	}
	const libPath = "/data/user/0/app/aglib/libfoo.so"
	got, ok := env.fs[libPath]
	if !ok {
		t.Fatalf("库载荷未解密落地到 %s，已有文件: %v", libPath, keysOfBytes(env.fs))
	}
	if !bytes.Equal(got, auditfix3bLibPlain) {
		t.Fatalf("库载荷解密结果不符（%d vs %d 字节）", len(got), len(auditfix3bLibPlain))
	}
	// DEX 载荷也必须照常落地：库路径的改动不得影响 DEX 路径。
	if _, ok := env.fs["/data/user/0/app/ag/d0.dex"]; !ok {
		t.Fatal("DEX 载荷未落地")
	}
	t.Logf("C2 MAC 正向：%d 字节库载荷通过 HMAC 校验并解密还原", len(libBlob))
}

// TestAuditfix3bLoaderLibMACTamperFails 是 MAC 存在的全部意义：
// 篡改库载荷的任意一个字节，壳都必须在**解密之前**检出并硬终止，
// 而不是解出垃圾数据继续跑（或把垃圾 .so 写进私有目录）。
func TestAuditfix3bLoaderLibMACTamperFails(t *testing.T) {
	key := testPackKey
	dexPlain := Empty()
	dexBlob := mustEncryptMAC(t, dexPlain, key, testPackIV, "classes.dex")
	base := mustEncryptMAC(t, auditfix3bLibPlain, key, auditfix3bLibIV, "libfoo.so")

	tampers := []struct {
		label  string
		mutate func([]byte)
	}{
		{"密文字节", func(b []byte) { b[ivLen+20] ^= 0x01 }},   // SIV 标签(16) 之后的密文区
		{"tag 字节", func(b []byte) { b[len(b)-1] ^= 0x01 }}, // 尾部 HMAC
		{"SIV 标签字节", func(b []byte) { b[0] ^= 0x01 }},      // SIV 标签必须被 MAC 覆盖
	}
	for _, tc := range tampers {
		t.Run(tc.label, func(t *testing.T) {
			blob := append([]byte(nil), base...)
			tc.mutate(blob)
			ls := auditfix3bLibSpec(key, dexBlob, blob, "libfoo.so")
			env := &loaderEnv{
				assets: map[string][]byte{"d.bin": dexBlob, "l.bin": blob},
				fs:     map[string][]byte{},
			}
			runLoaderEntry(t, ls, env)

			if !env.exited {
				t.Fatal("篡改库载荷后壳未调用 System.exit：库载荷 MAC 未被真正校验")
			}
			if _, ok := env.fs["/data/user/0/app/aglib/libfoo.so"]; ok {
				t.Fatal("MAC 校验失败后仍写出了库文件（先解密后校验？）")
			}
			if env.clObj != nil {
				t.Fatal("MAC 校验失败后仍构造了 ClassLoader")
			}
		})
	}

	// 换一个库名：字节没变但身份不符，MAC 必须失败（证明绑定的是原始库名）。
	ls := auditfix3bLibSpec(key, dexBlob, base, "libbar.so")
	env := &loaderEnv{
		assets: map[string][]byte{"d.bin": dexBlob, "l.bin": base},
		fs:     map[string][]byte{},
	}
	runLoaderEntry(t, ls, env)
	if !env.exited {
		t.Fatal("库名不符时 MAC 应失败，否则不同库的载荷可被互换")
	}
}

// TestAuditfix3bLibMACDisabledNoMACInstructions 是回归防线：
// 未启用 MAC 时，即使产物含 C2 库载荷，壳字节码里也不得出现任何 MAC 引用
// （否则即违反「关闭时产物与旧版逐字节一致」的承诺）。
func TestAuditfix3bLibMACDisabledNoMACInstructions(t *testing.T) {
	key := testPackKey
	// 未启用 MAC，但载荷名仍参与 SIV 的 ad，因此必须按同一个名字加密。
	dexBlob := mustEncryptAd(t, Empty(), key, "classes.dex")
	libBlob := mustEncryptAd(t, auditfix3bLibPlain, key, "libfoo.so")

	ls := auditfix3bLibSpec(key, dexBlob, libBlob, "libfoo.so")
	ls.MAC = false
	add, err := LoaderAddition(ls)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	out, err := Build(add)
	if err != nil {
		t.Fatalf("Build 失败: %v", err)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("校验失败: %v", err)
	}
	if bytes.Contains(out, []byte(macAlg)) {
		t.Fatalf("未启用 MAC 的壳不应含算法名 %q（含 C2 库载荷时也不得引入）", macAlg)
	}
	if bytes.Contains(out, []byte(macDomain)) {
		t.Fatalf("未启用 MAC 的壳不应含域串 %q", macDomain)
	}
}

// auditfix3bLibGolden 是「未启用 MAC、含 C2 库载荷」时壳 DEX 的 SHA-256。
//
// 该值把「关闭 -payload-mac 时壳不引入 MAC 相关指令/常量」这条承诺钉死
// （另有 TestAuditfix3bLibMACDisabledNoMACInstructions 从字符串面复核）。
// 若将来有人在库解析路径上无条件加了常量或指令，这里立刻报警。
//
// 2026-10（B5 函数抽取）：Loader 新增了抽取计划回填的 3 个辅助方法
// （q/p/t，见 loader.go）。它们对所有载荷 unconditional 生成，但以 trailer
// 魔数（ExtractPlanMagic）为判据，未启用 B5 的载荷走到即原样返回，属于
// **行为等价**的字节变化；因此这里重新基线化 golden，而不是保留旧值。
//
// 2026-10（CBC→SIV）：解密从 javax.crypto 的 "AES/CBC/PKCS5Padding" 换成
// Native.sivDecrypt，壳 DEX 指令流必然变化（新增 loadLibrary、getBytes、
// sivDecrypt 调用与 null 终止分支），golden 随之下一次重新基线化。
const auditfix3bLibGolden = "85b822110f62c2c4bfc9ec39c7ad3836a5995ae84482117d2e508f7918c0ac87"

// TestAuditfix3bLibMACDisabledGolden 用 golden 摘要比对关闭 MAC 时的壳 DEX。
func TestAuditfix3bLibMACDisabledGolden(t *testing.T) {
	key := testPackKey
	// 未启用 MAC，但载荷名仍参与 SIV 的 ad，因此必须按同一个名字加密。
	dexBlob := mustEncryptAd(t, Empty(), key, "classes.dex")
	libBlob := mustEncryptAd(t, auditfix3bLibPlain, key, "libfoo.so")

	ls := auditfix3bLibSpec(key, dexBlob, libBlob, "libfoo.so")
	ls.MAC = false
	add, err := LoaderAddition(ls)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	out, err := Build(add)
	if err != nil {
		t.Fatalf("Build 失败: %v", err)
	}
	sum := sha256.Sum256(out)
	got := hex.EncodeToString(sum[:])
	if got != auditfix3bLibGolden {
		t.Fatalf("未启用 MAC 的壳 DEX 字节发生变化（golden 回归）：\n  期望 %s\n  实际 %s", auditfix3bLibGolden, got)
	}
}
