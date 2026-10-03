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
		{"密文字节", func(b []byte) { b[ivLen+20] ^= 0x01 }},   // IV(16) 之后的密文区
		{"tag 字节", func(b []byte) { b[len(b)-1] ^= 0x01 }}, // 尾部 HMAC
		{"IV 字节", func(b []byte) { b[0] ^= 0x01 }},         // IV 必须被 MAC 覆盖
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
	dexBlob := mustEncrypt(t, Empty(), key, testPackIV)
	libBlob := mustEncrypt(t, auditfix3bLibPlain, key, auditfix3bLibIV)

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
// 该值取自本改动**之前**的代码：它把「关闭 -payload-mac 时产物字节不变」
// 这条承诺钉死。若将来有人在库解析路径上无条件加了常量或指令，这里立刻报警。
const auditfix3bLibGolden = "9d687a4fe1f84c0ae84598a89cd5d5e8a27683b625b9b39d2a98ca69ab5c1c49"

// TestAuditfix3bLibMACDisabledGolden 用 golden 摘要比对关闭 MAC 时的壳 DEX。
func TestAuditfix3bLibMACDisabledGolden(t *testing.T) {
	key := testPackKey
	dexBlob := mustEncrypt(t, Empty(), key, testPackIV)
	libBlob := mustEncrypt(t, auditfix3bLibPlain, key, auditfix3bLibIV)

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
