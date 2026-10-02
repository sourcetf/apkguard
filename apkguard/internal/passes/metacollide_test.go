package passes

import (
	"context"
	"testing"

	"apkguard/internal/config"
	"apkguard/internal/zipx"
)

// TestManifestCollisionGuard 覆盖归一化识别的各种写法。
func TestManifestCollisionGuard(t *testing.T) {
	bad := []string{
		"META-INF/MANIFEST.MF",
		"meta-inf/MANIFEST.MF", // 大小写不敏感 → 撞名
		"META-INF//MANIFEST.MF",
		"META-INF/./MANIFEST.MF",
		"META-INF/../META-INF/MANIFEST.MF",
		"META-INF/CERT.SF",
		"META-INF/key.RSA",
		"META-INF/x.dsa",
		"META-INF/y.EC",
	}
	for _, n := range bad {
		if !manifestCollision(n) {
			t.Errorf("%q 应被判定为撞名（会破坏 v1 签名校验）", n)
		}
	}
	ok := []string{
		"META-INF//MANIFEST.MFx",
		"META-INF/.hidden",
		"META-INF/sub/",
		"META-INF/x.MF",
		"meta-inf/MANIFEST.MFx",
		"META-INF/services/j3.t",
		"META-INF/androidx.core_core.version",
		"classes.dex/abc",
	}
	for _, n := range ok {
		if manifestCollision(n) {
			t.Errorf("%q 不应被判定为撞名", n)
		}
	}
}

// TestJunkEntriesNeverInjectManifestCollision 钉住 A10/A12 不会新增撞名条目。
//
// 真实缺陷（实测于 RustDesk 1.5.0，Flutter）：A10 曾注入 `meta-inf/MANIFEST.MF`
// 与 `META-INF//MANIFEST.MF`。ServiceLoader 经 JarFile 读 META-INF/services 时触发
// v1 签名校验，校验器读到**假 manifest 的主属性**，抛
//
//	java.lang.SecurityException: Invalid signature file digest for Manifest main attributes
//
// 应用首次 attach 即崩。这里断言：注入前后「撞名条目」集合完全不变
// （既有的真 MANIFEST.MF 保持唯一，也不新增任何假签名文件）。
func TestJunkEntriesNeverInjectManifestCollision(t *testing.T) {
	art := newArtifact(
		zipx.NewStored("classes.dex", []byte("dex\n035\x00")),
		zipx.NewStored("META-INF/MANIFEST.MF", []byte("Manifest-Version: 1.0\r\n\r\n")),
		zipx.NewStored("META-INF/CERT.SF", []byte("Signature-Version: 1.0\r\n")),
	)
	collisions := func() map[string]int {
		out := map[string]int{}
		for _, e := range art.Entries() {
			if manifestCollision(e.NameString()) {
				out[e.NameString()]++
			}
		}
		return out
	}
	before := collisions()

	opts := &config.Options{
		Enabled:       map[config.FeatureID]bool{"A10": true, "A12": true},
		Seed:          "junk",
		JunkTopCount:  40,
		JunkDirCount:  40,
		JunkDirDepth:  8,
		JunkMetaCount: 60,
		ZipAtkCount:   30,
	}
	if err := (&junkEntries{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A10 执行失败: %v", err)
	}
	if err := (&zipPathAttack{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A12 执行失败: %v", err)
	}

	after := collisions()
	for name, n := range after {
		if before[name] != n {
			t.Fatalf("A10/A12 新增了会破坏 v1 签名校验的条目 %q（%d → %d）", name, before[name], n)
		}
	}
	if len(after) != len(before) {
		t.Fatalf("撞名条目集合发生变化：%v → %v", before, after)
	}
	if n := after["META-INF/MANIFEST.MF"]; n != 1 {
		t.Fatalf("MANIFEST.MF 应恰好 1 条，实际 %d 条", n)
	}
}
