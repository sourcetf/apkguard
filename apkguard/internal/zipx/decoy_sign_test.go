// 本文件属于 zipx 的**外部**测试包：它把 zipx 的写出行为放回真实收尾链路
// （pipeline.DefaultSink → zipx.WriteChecked → sign.Sign 的 v1 重写 → v2/v3
// 签名块）里验证，覆盖「本地头假加密 flag 在 v1 重写后必须仍然存在」这一
// 关键集成点。放在 package zipx_test 里是为了避免 zipx 与 sign/pipeline 的
// 测试导入成环。
package zipx_test

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"apkguard/internal/config"
	"apkguard/internal/pipeline"
	"apkguard/internal/zipx"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

const (
	testLocalHeaderLen = 30
	testDataDescriptor = 16
	testFlagDataDesc   = 0x0008
	testLocalDecoyMask = 0x0001 | 0x0040
	testSigDataDescr   = 0x08074b50
)

type testLocal struct {
	name    string
	flags   uint16
	csize   uint32
	lho     int
	dataOff int
	dataEnd int
	hasDD   bool
}

// walkTestLocals 顺序遍历本地头（计入数据描述符）。
func walkTestLocals(t *testing.T, data []byte) []testLocal {
	t.Helper()
	var out []testLocal
	p := 0
	for p+testLocalHeaderLen <= len(data) && binary.LittleEndian.Uint32(data[p:]) == 0x04034b50 {
		li := testLocal{lho: p}
		li.flags = binary.LittleEndian.Uint16(data[p+6:])
		li.csize = binary.LittleEndian.Uint32(data[p+18:])
		nlen := int(binary.LittleEndian.Uint16(data[p+26:]))
		elen := int(binary.LittleEndian.Uint16(data[p+28:]))
		if p+testLocalHeaderLen+nlen+elen > len(data) {
			t.Fatalf("本地头越界 @%d", p)
		}
		li.name = string(data[p+testLocalHeaderLen : p+testLocalHeaderLen+nlen])
		li.dataOff = p + testLocalHeaderLen + nlen + elen
		li.dataEnd = li.dataOff + int(li.csize)
		if li.dataEnd > len(data) {
			t.Fatalf("条目 %q 数据越界", li.name)
		}
		p = li.dataEnd
		if li.flags&testFlagDataDesc != 0 {
			if p+testDataDescriptor > len(data) || binary.LittleEndian.Uint32(data[p:]) != testSigDataDescr {
				t.Fatalf("条目 %q 声明 bit3 但数据后没有数据描述符", li.name)
			}
			li.hasDD = true
			p += testDataDescriptor
		}
		out = append(out, li)
	}
	return out
}

func testDeflated(t *testing.T, name string, data []byte) *zipx.Entry {
	t.Helper()
	e := &zipx.Entry{VersionMade: 20, VersionNeed: 20, Name: []byte(name)}
	if err := e.SetData(data, true); err != nil {
		t.Fatalf("构造 Deflate 条目 %q 失败: %v", name, err)
	}
	return e
}

// writeTestP12 生成一个 PKCS12 密钥库文件。
func writeTestP12(t *testing.T, pass string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "apkguard zipx test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("自签证书失败: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("解析证书失败: %v", err)
	}
	blob, err := pkcs12.Modern.Encode(key, cert, nil, pass)
	if err != nil {
		t.Fatalf("编码 PKCS12 失败: %v", err)
	}
	p := filepath.Join(t.TempDir(), "test.p12")
	if err := os.WriteFile(p, blob, 0o600); err != nil {
		t.Fatalf("写出密钥库失败: %v", err)
	}
	return p
}

func signTestArchive(t *testing.T) (*zipx.Archive, map[string][]byte) {
	t.Helper()
	want := map[string][]byte{
		"AndroidManifest.xml": bytes.Repeat([]byte("manifest!"), 60),
		"classes.dex":         bytes.Repeat([]byte("dex-bytes-"), 220),
		"classes2.dex":        bytes.Repeat([]byte("dex2-bytes-"), 180),
		"resources.arsc":      bytes.Repeat([]byte{0x5A}, 96),
		"res/raw/x.bin":       bytes.Repeat([]byte("blob-"), 120),
	}
	a := &zipx.Archive{Entries: []*zipx.Entry{
		testDeflated(t, "AndroidManifest.xml", want["AndroidManifest.xml"]),
		testDeflated(t, "classes.dex", want["classes.dex"]),
		testDeflated(t, "classes2.dex", want["classes2.dex"]),
		zipx.NewStored("resources.arsc", want["resources.arsc"]),
		testDeflated(t, "res/raw/x.bin", want["res/raw/x.bin"]),
	}}
	return a, want
}

func runSink(t *testing.T, a *zipx.Archive, ksPath string, decoy bool) []byte {
	t.Helper()
	opts := &config.Options{
		Enabled:           map[config.FeatureID]bool{"E1": true, "E2": true, "E3": false},
		KS:                ksPath,
		KSPass:            "123456",
		ZipLocalFlagDecoy: decoy,
	}
	out, err := (pipeline.DefaultSink{}).Finish(context.Background(),
		&pipeline.Artifact{Archive: a, Stats: map[string]string{}}, opts)
	if err != nil {
		t.Fatalf("收尾失败（decoy=%v）: %v", decoy, err)
	}
	return out
}

// TestSinkDecoyFlagsSurviveV1V2V3Signing 验证需求 2 的端到端行为：
//
//   - 开启 ZipLocalFlagDecoy 后，四个核心条目的**本地头**带 bit0+bit6，
//     中央目录不带；非核心条目不受影响；Deflate 条目的 bit3/DD 保持；
//   - 完整跑通 v1（MANIFEST.MF/CERT.SF/CERT.RSA 重写）+ v2/v3 签名块插入，
//     即假加密 flag 必须穿得过 v1 的「读中央目录后重写」而出现在最终产物里；
//   - 产物仍能被 Go archive/zip 与 zipx.Read 正确读出全部内容；
//   - 关闭开关时不出现任何 bit0/bit6。
func TestSinkDecoyFlagsSurviveV1V2V3Signing(t *testing.T) {
	ksPath := writeTestP12(t, "123456")

	on := runSink(t, mustArchive(t), ksPath, true)

	// 签名确实发生了：v1 条目 + v2/v3 签名块。
	zr, err := zipx.Read(on)
	if err != nil {
		t.Fatalf("zipx.Read 解析签名产物失败: %v", err)
	}
	if zr.Find("META-INF/MANIFEST.MF") == nil || zr.Find("META-INF/CERT.SF") == nil || zr.Find("META-INF/CERT.RSA") == nil {
		t.Fatal("产物缺少 v1 签名条目——v1 签名未跑通")
	}
	sec, err := zipx.Split(on)
	if err != nil {
		t.Fatalf("切分产物失败: %v", err)
	}
	if !sec.HasSigningBlock() {
		t.Fatal("产物缺少 v2/v3 签名块——签名未跑通")
	}
	// 签名块里必须同时含 v2 与 v3 的 signer 块 ID（小端）。
	if !bytes.Contains(sec.SigningBlock, []byte{0x1a, 0x87, 0x09, 0x71}) {
		t.Error("签名块里缺少 v2 signer（ID 0x7109871a）")
	}
	if !bytes.Contains(sec.SigningBlock, []byte{0xc0, 0x68, 0x53, 0xf0}) {
		t.Error("签名块里缺少 v3 signer（ID 0xf05368c0）")
	}

	// 本地头：核心条目带假加密位，其他（含 v1 新条目）不带。
	locals := walkTestLocals(t, on)
	names := map[string]bool{}
	core := map[string]bool{
		"AndroidManifest.xml": true,
		"resources.arsc":      true,
		"classes.dex":         true,
		"classes2.dex":        true,
	}
	for _, li := range locals {
		names[li.name] = true
		if core[li.name] {
			if li.flags&testLocalDecoyMask != testLocalDecoyMask {
				t.Errorf("核心条目 %q 本地头缺少 bit0+bit6（v1 重写把它丢了？），flags=0x%04x", li.name, li.flags)
			}
		} else if li.flags&testLocalDecoyMask != 0 {
			t.Errorf("非核心条目 %q 不应带假加密位，flags=0x%04x", li.name, li.flags)
		}
	}
	for _, n := range []string{"AndroidManifest.xml", "resources.arsc", "classes.dex", "classes2.dex", "res/raw/x.bin", "META-INF/MANIFEST.MF"} {
		if !names[n] {
			t.Fatalf("本地头遍历缺少条目 %q（数据描述符处理有误？）", n)
		}
	}

	// 中央目录不得含假加密位；Deflate 条目的 bit3/DD 保持。
	for _, e := range zr.Entries {
		if e.Flags&testLocalDecoyMask != 0 {
			t.Errorf("中央目录条目 %q 不应含假加密位，flags=0x%04x", e.NameString(), e.Flags)
		}
		if !e.IsStored() && e.Flags&testFlagDataDesc == 0 {
			t.Errorf("签名产物里 Deflate 条目 %q 丢了 bit3", e.NameString())
		}
	}
	for _, li := range locals {
		if li.name == "res/raw/x.bin" && !li.hasDD {
			t.Error("非核心的 Deflate 条目也应有数据描述符")
		}
	}

	// 内容（含被假加密的核心条目）必须可按正常读路径取出。
	_, want := signTestArchive(t)
	for _, e := range zr.Entries {
		data, err := e.Data()
		if err != nil {
			t.Fatalf("读取条目 %q 失败: %v", e.NameString(), err)
		}
		if w, ok := want[e.NameString()]; ok && !bytes.Equal(data, w) {
			t.Errorf("条目 %q 内容不符", e.NameString())
		}
	}
	zrd, err := zip.NewReader(bytes.NewReader(on), int64(len(on)))
	if err != nil {
		t.Fatalf("archive/zip 打开签名产物失败: %v", err)
	}
	for _, f := range zrd.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("archive/zip 打开 %q 失败: %v", f.Name, err)
		}
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(rc); err != nil {
			rc.Close()
			t.Fatalf("archive/zip 读取 %q 失败: %v", f.Name, err)
		}
		rc.Close()
		if w, ok := want[f.Name]; ok && !bytes.Equal(buf.Bytes(), w) {
			t.Errorf("archive/zip 读出的 %q 内容不符", f.Name)
		}
	}

	// 反例：关闭开关时任何条目都不含 bit0/bit6。
	off := runSink(t, mustArchive(t), ksPath, false)
	for _, li := range walkTestLocals(t, off) {
		if li.flags&testLocalDecoyMask != 0 {
			t.Errorf("关闭开关后条目 %q 不应带假加密位，flags=0x%04x", li.name, li.flags)
		}
	}
}

func mustArchive(t *testing.T) *zipx.Archive {
	t.Helper()
	a, _ := signTestArchive(t)
	return a
}
