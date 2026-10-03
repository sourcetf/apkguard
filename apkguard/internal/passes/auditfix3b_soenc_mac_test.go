package passes

import (
	"bytes"
	"context"
	"testing"

	"apkguard/internal/config"
	"apkguard/internal/pack"
	"apkguard/internal/pipeline"
	"apkguard/internal/zipx"
)

// 本文件覆盖 C2（SO 加壳）库载荷接入 -payload-mac 的打包侧行为：
// 开启时追加与 B1 同规格的 HMAC-SHA256（绑定原始库名），关闭时字节不变。

// auditfix3bEncrypt 用与 C2 相同的参数与 IV 派生规则独立算出「IV‖密文」，
// 便于断言开启 MAC 只是在其尾部追加 tag、关闭 MAC 时与之逐字节一致。
func auditfix3bEncrypt(t *testing.T, data []byte, seed, abi, name string, key [32]byte) []byte {
	t.Helper()
	blob, err := pack.Encrypt(data, key, pack.IVFromSeed(seed+"/so/"+abi+"/"+name))
	if err != nil {
		t.Fatalf("参照加密失败: %v", err)
	}
	return blob
}

// TestAuditfix3bSoEncPayloadMAC 验证开启 -payload-mac 时：
// C2 的每份库载荷尾部带合法 HMAC（绑定原始库名），可被壳侧的
// 先验 MAC 再解密路径还原，且记录进清单供报告/测试核对。
func TestAuditfix3bSoEncPayloadMAC(t *testing.T) {
	data := soTestData(0x10, 401) // 奇数长度：覆盖非整分组填充
	art := newArtifact(
		zipxStored("classes.dex", []byte("dex\n035\x00")),
		zipxStored("lib/x86_64/libfoo.so", data),
	)
	opts := &config.Options{SOEncrypt: true, PayloadMAC: true, DexKey: "c2-mac-key", Seed: "c2-mac-seed"}
	if err := (&encryptNativeLibs{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("C2 执行失败: %v", err)
	}
	sl := soLibsOf(art)
	if sl == nil || len(sl.Items) != 1 {
		t.Fatalf("C2 未产出预期载荷: %+v", sl)
	}
	if !sl.MAC {
		t.Fatal("shellSOLibs.MAC 未记录：打包侧无法证明库载荷带了 MAC")
	}
	it := sl.Items[0]
	e := pipeline.Find(art, it.Asset)
	if e == nil {
		t.Fatalf("载荷条目 %s 不存在", it.Asset)
	}
	blob, err := e.Data()
	if err != nil {
		t.Fatalf("读取载荷失败: %v", err)
	}

	// ① tag 是「在 IV‖密文之后追加」的，不是别的格式。
	body := auditfix3bEncrypt(t, data, opts.Seed, it.Abi, it.Name, sl.Key)
	if len(blob) != len(body)+pack.TagSize {
		t.Fatalf("带 MAC 载荷长度应为 %d（含 %d 字节 tag），实际 %d", len(body)+pack.TagSize, pack.TagSize, len(blob))
	}
	if !bytes.Equal(blob[:len(body)], body) {
		t.Fatal("tag 未追加在 IV‖密文之后（加密结果本身被改动）")
	}
	// ② 壳侧的 VerifyMAC/DecryptMAC 参考实现必须接受它。
	if !pack.VerifyMAC(blob, sl.Key, it.Name) {
		t.Fatal("库载荷未带合法 MAC：C2 未接入 -payload-mac")
	}
	if pack.VerifyMAC(blob, sl.Key, "libbar.so") {
		t.Fatal("MAC 未绑定原始库名：换名后仍能通过校验")
	}
	got, err := pack.DecryptMAC(blob, sl.Key, it.Name)
	if err != nil {
		t.Fatalf("带 MAC 的库载荷解密失败: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("带 MAC 的库载荷还原结果不符")
	}
	// ③ 清单里的 Size 必须含 tag（壳侧 r() 依赖它读满字节）。
	if it.Size != len(blob) {
		t.Fatalf("Size 记录 %d 与实际载荷 %d 不符（漏算 tag 会让壳少读 32 字节）", it.Size, len(blob))
	}
	// ④ 报告口径。
	if art.Stats["C2.mac"] != "1" {
		t.Fatalf("C2.mac 统计不符: %v", art.Stats["C2.mac"])
	}
	if art.Stats["C2.mac_bytes"] != "32" {
		t.Fatalf("C2.mac_bytes 统计不符: %v", art.Stats["C2.mac_bytes"])
	}
}

// TestAuditfix3bSoEncNoMACByteIdentical 是回归防线：关闭 -payload-mac 时
// C2 产物必须与旧版逐字节一致（不追加任何尾部字节、不引入任何新常量）。
func TestAuditfix3bSoEncNoMACByteIdentical(t *testing.T) {
	data := soTestData(0x33, 333)
	art := newArtifact(
		zipxStored("classes.dex", []byte("dex\n035\x00")),
		zipxStored("lib/x86_64/libfoo.so", data),
	)
	opts := &config.Options{SOEncrypt: true, DexKey: "c2-nomac-key", Seed: "c2-nomac-seed"}
	if err := (&encryptNativeLibs{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("C2 执行失败: %v", err)
	}
	sl := soLibsOf(art)
	if sl == nil || len(sl.Items) != 1 {
		t.Fatalf("C2 未产出预期载荷: %+v", sl)
	}
	if sl.MAC {
		t.Fatal("未启用 -payload-mac 时 shellSOLibs.MAC 不应为真")
	}
	it := sl.Items[0]
	blob, err := pipeline.Find(art, it.Asset).Data()
	if err != nil {
		t.Fatalf("读取载荷失败: %v", err)
	}
	want := auditfix3bEncrypt(t, data, opts.Seed, it.Abi, it.Name, sl.Key)
	if !bytes.Equal(blob, want) {
		t.Fatalf("未启用 MAC 时载荷字节变化：长度 %d vs %d", len(blob), len(want))
	}
	if it.Size != len(blob) {
		t.Fatalf("Size 记录 %d 与实际载荷 %d 不符", it.Size, len(blob))
	}
	if art.Stats["C2.mac"] != "0" {
		t.Fatalf("C2.mac 统计不符: %v", art.Stats["C2.mac"])
	}
	if _, ok := art.Stats["C2.mac_bytes"]; ok {
		t.Fatalf("未启用 MAC 时不应报 mac_bytes: %v", art.Stats)
	}
}

// TestAuditfix3bSoEncMACFullChain 在合成的完整产物上跑 C2→B1→B2→B3，
// 验证开启 MAC 时库载荷标记为带 tag、B1/B3 的 MAC 记录一致，且壳 DEX
// 里出现 HMAC 相关引用（关闭时的「零引用」回归见 dex 包的同名测试）。
func TestAuditfix3bSoEncMACFullChain(t *testing.T) {
	art := newArtifact(
		zipx.NewStored("AndroidManifest.xml", nestedAPKManifestAXML(newRand("auditfix3b-chain"), "com.agtest")),
		zipx.NewStored("classes.dex", smallDexWithClass(t, "Lcom/agtest/MainActivity;")),
		zipxStored("lib/x86_64/libfoo.so", soTestData(0x22, 257)),
	)
	opts := shellOpts()
	opts.SOEncrypt = true
	opts.PayloadMAC = true
	opts.DexKey = "k"

	if err := (&encryptNativeLibs{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("C2 执行失败: %v", err)
	}
	runShellChain(t, art, opts)

	sl := soLibsOf(art)
	if sl == nil || len(sl.Items) != 1 {
		t.Fatalf("C2 清单不符: %+v", sl)
	}
	blob, err := pipeline.Find(art, sl.Items[0].Asset).Data()
	if err != nil {
		t.Fatalf("读取库载荷失败: %v", err)
	}
	if !pack.VerifyMAC(blob, sl.Key, sl.Items[0].Name) {
		t.Fatal("链路上库载荷未带合法 MAC")
	}
	if art.Stats["B1.mac"] != "1" || art.Stats["B3.mac"] != "1" {
		t.Fatalf("B1/B3 的 MAC 记录不符: B1.mac=%q B3.mac=%q", art.Stats["B1.mac"], art.Stats["B3.mac"])
	}
	if art.Stats["B3.libs"] != "1" {
		t.Fatalf("B3 未接线库载荷: %v", art.Stats)
	}
	// 壳 DEX 必须真的引用了 HMAC（说明 MAC 分支被生成，而不是只改了统计）。
	info, _ := art.Get(sharedKeyShell).(*shellInfo)
	data, err := pipeline.Find(art, info.EntryName).Data()
	if err != nil {
		t.Fatalf("读取壳 DEX 失败: %v", err)
	}
	if !bytes.Contains(data, []byte("HmacSHA256")) || !bytes.Contains(data, []byte("apkguard/payload-mac")) {
		t.Fatal("启用 MAC 的壳 DEX 不含 HMAC 引用")
	}
}
