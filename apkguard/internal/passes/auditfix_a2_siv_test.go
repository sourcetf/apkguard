package passes

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"

	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/pack"
	"apkguard/internal/pipeline"
)

// 本文件是 A2 换成 AES-256-SIV 后的 Pass/产物级证据。
//
// 与 internal/dex 的解释器级测试互补：这里跑真实的 A2 Pass，断言
//   1) 产物里带 lib/<abi>/libapkguard.so（默认启用集合因此会变大）；
//   2) 池里的密文是 Base64([SIV 16B][CTR 密文])，用 pack.DecryptNamed 能还原；
//   3) DEX 里出现 sivDecrypt / loadLibrary / 桥接类；
//   4) 逃生开关（-strenc-legacy-keystream）回到旧形态且**不带** lib/；
//   5) A2 关闭时产物不带 lib/。

// dexBytesOf 汇总产物中全部可解析 DEX 的字节数。
func dexBytesOf(t *testing.T, art *pipeline.Artifact) int {
	t.Helper()
	total := 0
	for _, e := range pipeline.FindAll(art, isDexEntry) {
		d, err := e.Data()
		if err != nil {
			continue
		}
		if _, err := dex.Parse(d); err != nil {
			continue
		}
		total += len(d)
	}
	return total
}

// libEntryBytes 返回产物里守卫库条目的个数与总字节数。
func libEntryBytes(t *testing.T, art *pipeline.Artifact) (int, int) {
	t.Helper()
	n, b := 0, 0
	for _, e := range art.Entries() {
		name := e.NameString()
		if !strings.HasPrefix(name, "lib/") || !strings.HasSuffix(name, "/libapkguard.so") {
			continue
		}
		d, err := e.Data()
		if err != nil {
			continue
		}
		n++
		b += len(d)
	}
	return n, b
}

// recoverPoolCiphertexts 在产物的全部 DEX 池里找出能由 pack.DecryptNamed 还原的
// 密文，返回 (明文 -> 解出的 blob 长度)。
func recoverPoolCiphertexts(t *testing.T, art *pipeline.Artifact, key [32]byte) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, e := range pipeline.FindAll(art, isDexEntry) {
		d, err := e.Data()
		if err != nil {
			continue
		}
		f, err := dex.Parse(d)
		if err != nil {
			continue
		}
		for i := uint32(0); i < f.NString; i++ {
			s, err := f.String(i)
			if err != nil || len(s) < 24 {
				continue
			}
			raw, err := base64.StdEncoding.DecodeString(s)
			if err != nil || len(raw) < pack.BlockSize {
				continue
			}
			plain, err := pack.DecryptNamed(raw, key, "")
			if err != nil {
				continue
			}
			out[string(plain)] = len(raw)
		}
	}
	return out
}

// TestA2SIVProductShape 是需求 4 的核心证据（默认 SIV 路径）。
func TestA2SIVProductShape(t *testing.T) {
	before := dexBytesOf(t, loadSample(t))

	art := loadSample(t)
	opts := &config.Options{
		Enabled:      map[config.FeatureID]bool{"A2": true},
		DexKey:       "siv-product-key",
		Seed:         "siv-product-seed",
		ObfStringMin: 4,
	}
	if err := (&encryptString{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A2 执行失败: %v", err)
	}
	after := dexBytesOf(t, art)

	// 1) 守卫库必须进产物。
	nLib, libBytes := libEntryBytes(t, art)
	if nLib == 0 {
		t.Fatal("A2 走 SIV 时必须嵌入守卫库，实际产物里没有 lib/*/libapkguard.so")
	}

	// 2) 密文形态：Base64([SIV][CTR 密文])，pack.DecryptNamed 可还原。
	key, err := deriveKey(opts.DexKey, opts.Seed)
	if err != nil {
		t.Fatal(err)
	}
	recovered := recoverPoolCiphertexts(t, art, key)
	if len(recovered) == 0 {
		t.Fatal("产物池里找不到任何可由 pack.DecryptNamed 还原的 SIV 密文")
	}
	for plain, blobLen := range recovered {
		if blobLen != pack.BlockSize+len(plain) {
			t.Fatalf("密文 blob 长度应为 16+n=%d，实际 %d（明文 %q）", pack.BlockSize+len(plain), blobLen, plain)
		}
	}

	// 3) DEX 里出现 sivDecrypt / loadLibrary / 桥接类；且明文已被移出池。
	sawSiv, sawLoad, sawBridge := false, false, false
	sawPlainMissing := false
	for _, e := range pipeline.FindAll(art, isDexEntry) {
		d, err := e.Data()
		if err != nil {
			continue
		}
		f, err := dex.Parse(d)
		if err != nil {
			continue
		}
		pool := map[string]bool{}
		for i := uint32(0); i < f.NString; i++ {
			s, _ := f.String(i)
			pool[s] = true
		}
		if pool[dex.NativeDecrypt] {
			sawSiv = true
		}
		if pool["loadLibrary"] {
			sawLoad = true
		}
		for i := uint32(0); i < f.NType; i++ {
			if n, _ := f.Type(i); n == dex.NativeBridgeClass {
				sawBridge = true
			}
		}
		for plain := range recovered {
			if !pool[plain] {
				sawPlainMissing = true
			}
		}
	}
	if !sawSiv || !sawLoad || !sawBridge {
		t.Fatalf("DEX 缺少 SIV 链路：sivDecrypt=%v loadLibrary=%v bridge=%v", sawSiv, sawLoad, sawBridge)
	}
	if !sawPlainMissing {
		t.Fatal("没有任何已知明文被移出字符串池（加密未生效）")
	}

	t.Logf("SIV 产物：守卫库 %d 个 / %d 字节；被测 DEX 池体积 %d → %d 字节（增加 %d）；可还原密文样本 %d 条",
		nLib, libBytes, before, after, after-before, len(recovered))
}

// legacyEncryptLocal 复刻旧 keystream 加密：Base64(nonce(8) ‖ 异或结果)。
//
// 用它算出「已知明文在旧算法下的期望密文」，从而强证明逃生开关走的确实是旧格式。
func legacyEncryptLocal(plain string, key [32]byte) string {
	p := []byte(plain)
	h := sha256.New()
	h.Write(key[:])
	h.Write([]byte{0x00})
	h.Write(p)
	nonce := h.Sum(nil)[:8]
	buf := make([]byte, 8+len(p))
	copy(buf, nonce)
	for i, c := range p {
		var idx [4]byte
		binary.LittleEndian.PutUint32(idx[:], uint32(i))
		kh := sha256.New()
		kh.Write(key[:])
		kh.Write([]byte{0x01})
		kh.Write(nonce)
		kh.Write(idx[:])
		buf[8+i] = c ^ kh.Sum(nil)[0]
	}
	return base64.StdEncoding.EncodeToString(buf)
}

// TestA2LegacyKeystreamProductShape 是逃生开关路径的证据：旧形态、不嵌库。
func TestA2LegacyKeystreamProductShape(t *testing.T) {
	// 先记录原始 DEX 的明文池，用于「已知明文 → 期望旧密文」的强断言。
	origPool := map[string]bool{}
	for _, e := range pipeline.FindAll(loadSample(t), isDexEntry) {
		d, err := e.Data()
		if err != nil {
			continue
		}
		if f, err := dex.Parse(d); err == nil {
			for i := uint32(0); i < f.NString; i++ {
				if s, err := f.String(i); err == nil {
					origPool[s] = true
				}
			}
		}
	}

	art := loadSample(t)
	opts := &config.Options{
		Enabled:               map[config.FeatureID]bool{"A2": true},
		DexKey:                "legacy-product-key",
		Seed:                  "legacy-product-seed",
		ObfStringMin:          4,
		StrencLegacyKeystream: true,
	}
	if err := (&encryptString{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A2(legacy) 执行失败: %v", err)
	}

	// 不带守卫库。
	if nLib, _ := libEntryBytes(t, art); nLib != 0 {
		t.Fatalf("旧 keystream 路径不应嵌入守卫库，实际 %d 个", nLib)
	}
	if v := art.Stats["A2.guard_libs"]; v != "" {
		t.Fatalf("旧路径不应报告 A2.guard_libs，实际 %q", v)
	}

	key, err := deriveKey(opts.DexKey, opts.Seed)
	if err != nil {
		t.Fatal(err)
	}
	newPool := map[string]bool{}
	sawSiv := false
	for _, e := range pipeline.FindAll(art, isDexEntry) {
		d, err := e.Data()
		if err != nil {
			continue
		}
		f, err := dex.Parse(d)
		if err != nil {
			continue
		}
		for i := uint32(0); i < f.NString; i++ {
			if s, err := f.String(i); err == nil {
				newPool[s] = true
				if s == dex.NativeDecrypt || s == "loadLibrary" {
					sawSiv = true
				}
			}
		}
		for i := uint32(0); i < f.NType; i++ {
			if n, _ := f.Type(i); n == dex.NativeBridgeClass {
				t.Fatal("旧 keystream 路径不应注入 native 桥接类")
			}
		}
	}
	if sawSiv {
		t.Fatal("旧 keystream 路径的 DEX 出现 sivDecrypt/loadLibrary（应为纯 JCA）")
	}

	// 已知明文强断言：原始池里长度达标的串，其「旧算法期望密文」必须出现在新池里，
	// 且明文本身被移出池——证明逃生开关确实回到旧格式。
	found, movedOut := 0, 0
	for s := range origPool {
		if len(s) < 4 {
			continue
		}
		if newPool[legacyEncryptLocal(s, key)] {
			found++
			if !newPool[s] {
				movedOut++
			}
		}
	}
	if found == 0 {
		t.Fatal("新池里找不到任何「旧算法期望密文」（未走旧 keystream 路径）")
	}
	if movedOut == 0 {
		t.Fatal("旧路径下没有任何明文被移出池（加密未生效）")
	}
	t.Logf("legacy 产物：无 lib/、无 SIV 链路；旧格式密文命中 %d 条，其中 %d 条明文被移出池", found, movedOut)
}

// TestA2SIVDeterministicProduct 验证同 seed/密钥两次加固逐字节一致（需求 6）。
//
// SIV 是确定性的（无随机 IV/nonce），AD 为空，因此同一明文得到同一密文；
// 类名与方法名也由 seed 派生，产物整体应完全相同。
func TestA2SIVDeterministicProduct(t *testing.T) {
	run := func() map[string][]byte {
		art := loadSample(t)
		opts := &config.Options{
			Enabled:      map[config.FeatureID]bool{"A2": true},
			DexKey:       "det-key",
			Seed:         "det-seed",
			ObfStringMin: 4,
		}
		if err := (&encryptString{}).Run(context.Background(), art, opts); err != nil {
			t.Fatalf("A2 执行失败: %v", err)
		}
		out := map[string][]byte{}
		for _, e := range art.Entries() {
			d, err := e.Data()
			if err != nil {
				continue
			}
			out[e.NameString()] = append([]byte(nil), d...)
		}
		return out
	}
	a, b := run(), run()
	if len(a) != len(b) {
		t.Fatalf("两次产物条目数不同：%d vs %d", len(a), len(b))
	}
	for name, da := range a {
		db, ok := b[name]
		if !ok {
			t.Fatalf("第二次产物缺少条目 %s", name)
		}
		if !bytes.Equal(da, db) {
			t.Fatalf("同 seed 两次产物条目 %s 不一致", name)
		}
	}
	t.Logf("同 seed 两次 A2(SIV) 产物逐字节一致（%d 个条目）", len(a))
}

// TestA2DisabledNoGuardLibs 是零回归证据：A2 关闭时产物不带任何守卫库。
//
// 走完整 pipeline（默认启用集合里去掉 A2），断言最终 APK 的条目里没有
// lib/<abi>/libapkguard.so。C1/ensurePayloadGuard 只在 B1/B2 链路下嵌入守卫库，
// 本用例不启用它们，因此唯一的注入来源就是 A2。
func TestA2DisabledNoGuardLibs(t *testing.T) {
	in := sampleAPK(t)
	opts := &config.Options{
		// 显式关掉 A2 与 E1（E1 默认开、需要密钥库，此处不签名）。
		Enabled: map[config.FeatureID]bool{
			"A2": false, "E1": false,
			"A1": true, "A3": true, "A4": true, "E2": true, "E3": true,
		},
		In:   in,
		Seed: "a2off-seed",
	}
	res, err := pipeline.New(Registry(), pipeline.DefaultSink{}).Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("pipeline 运行失败: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(res.APK), int64(len(res.APK)))
	if err != nil {
		t.Fatalf("产物不是合法 ZIP: %v", err)
	}
	for _, f := range zr.File {
		if strings.HasPrefix(f.Name, "lib/") && strings.HasSuffix(f.Name, ".so") {
			t.Fatalf("A2 关闭时不应出现原生库条目，实际 %s", f.Name)
		}
	}
}
