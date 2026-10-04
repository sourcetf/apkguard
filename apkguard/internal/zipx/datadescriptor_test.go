package zipx

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// ---- 测试工具 ----

// newDeflated 构造一个 Deflate 条目。
func newDeflated(t *testing.T, name string, data []byte) *Entry {
	t.Helper()
	e := &Entry{VersionMade: 20, VersionNeed: 20, Name: []byte(name)}
	if err := e.SetData(data, true); err != nil {
		t.Fatalf("构造 Deflate 条目 %q 失败: %v", name, err)
	}
	return e
}

// localInfo 是从本地头顺序解析出的一个条目。
type localInfo struct {
	name     string
	flags    uint16
	method   uint16
	crc      uint32
	csize    uint32
	usize    uint32
	lho      int
	extraLen int
	dataOff  int
	dataEnd  int
	hasDD    bool
	ddOff    int
	ddCRC    uint32
	ddCS     uint32
	ddUS     uint32
}

// walkLocals 从偏移 0 起顺序遍历本地头，按声明长度推进（不搜索 magic），
// 并把数据描述符计入推进量。返回条目列表与「本地头区域结束偏移」。
func walkLocals(t *testing.T, data []byte) ([]localInfo, int) {
	t.Helper()
	var out []localInfo
	p := 0
	for p+localHeaderLen <= len(data) && binary.LittleEndian.Uint32(data[p:]) == sigLocal {
		var li localInfo
		li.lho = p
		li.flags = binary.LittleEndian.Uint16(data[p+6:])
		li.method = binary.LittleEndian.Uint16(data[p+8:])
		li.crc = binary.LittleEndian.Uint32(data[p+14:])
		li.csize = binary.LittleEndian.Uint32(data[p+18:])
		li.usize = binary.LittleEndian.Uint32(data[p+22:])
		nlen := int(binary.LittleEndian.Uint16(data[p+26:]))
		elen := int(binary.LittleEndian.Uint16(data[p+28:]))
		if p+localHeaderLen+nlen+elen > len(data) {
			t.Fatalf("本地头可变长字段越界 @%d", p)
		}
		li.name = string(data[p+localHeaderLen : p+localHeaderLen+nlen])
		li.extraLen = elen
		li.dataOff = p + localHeaderLen + nlen + elen
		li.dataEnd = li.dataOff + int(li.csize)
		if li.dataEnd > len(data) {
			t.Fatalf("条目 %q 数据越界", li.name)
		}
		p = li.dataEnd
		if li.flags&flagDataDescriptor != 0 {
			li.hasDD = true
			li.ddOff = p
			if p+dataDescriptorLen > len(data) {
				t.Fatalf("条目 %q 声明 bit3 但数据描述符越界", li.name)
			}
			if binary.LittleEndian.Uint32(data[p:]) != sigDataDescriptor {
				t.Fatalf("条目 %q 数据后不是 PK\\x07\\x08 @%d", li.name, p)
			}
			li.ddCRC = binary.LittleEndian.Uint32(data[p+4:])
			li.ddCS = binary.LittleEndian.Uint32(data[p+8:])
			li.ddUS = binary.LittleEndian.Uint32(data[p+12:])
			p += dataDescriptorLen
		}
		out = append(out, li)
	}
	return out, p
}

// findLocal 按名字返回本地头信息。
func findLocal(t *testing.T, ls []localInfo, name string) localInfo {
	t.Helper()
	for _, l := range ls {
		if l.name == name {
			return l
		}
	}
	t.Fatalf("未找到本地头条目 %q", name)
	return localInfo{}
}

// sampleArchiveWithDeflate 构造一个同时含 Stored 与 Deflate 条目的归档。
func sampleArchiveWithDeflate(t *testing.T) (*Archive, map[string][]byte) {
	t.Helper()
	want := map[string][]byte{
		"AndroidManifest.xml":        bytes.Repeat([]byte("manifest-content!"), 40),
		"resources.arsc":             bytes.Repeat([]byte{0xA5}, 100),
		"classes.dex":                bytes.Repeat([]byte("dex-byte-"), 200),
		"classes2.dex":               bytes.Repeat([]byte("second-dex-"), 150),
		"res/raw/blob.bin":           bytes.Repeat([]byte("blob-data-"), 90),
		"assets/empty-stored.bin":    {},
		"META-INF/MANIFEST.MF.dummy": []byte("not-a-signature"),
	}
	a := &Archive{Entries: []*Entry{
		newDeflated(t, "AndroidManifest.xml", want["AndroidManifest.xml"]),
		NewStored("resources.arsc", want["resources.arsc"]),
		newDeflated(t, "classes.dex", want["classes.dex"]),
		newDeflated(t, "classes2.dex", want["classes2.dex"]),
		newDeflated(t, "res/raw/blob.bin", want["res/raw/blob.bin"]),
		NewStored("assets/empty-stored.bin", want["assets/empty-stored.bin"]),
		NewStored("META-INF/MANIFEST.MF.dummy", want["META-INF/MANIFEST.MF.dummy"]),
	}}
	return a, want
}

// TestDataDescriptorIsWrittenByDefault 验证默认写出的归档对全部非 Stored
// 条目置 bit3 并追加 16 字节数据描述符，Stored 条目没有，且本地头中的
// CRC/大小字段保持正确值、中央目录偏移把描述符计入。
func TestDataDescriptorIsWrittenByDefault(t *testing.T) {
	a, want := sampleArchiveWithDeflate(t)
	out := Write(a, DefaultAlign())

	locals, cdOff := walkLocals(t, out)
	if len(locals) != len(a.Entries) {
		t.Fatalf("本地头条目数 %d，期望 %d（数据描述符可能让遍历提前中断）", len(locals), len(a.Entries))
	}

	for i, e := range a.Entries {
		li := locals[i]
		if li.name != e.NameString() {
			t.Fatalf("第 %d 个条目名不符: got %q want %q", i, li.name, e.NameString())
		}
		// 本地头里的 CRC/大小必须是真值（样本同款），而不是规范允许的 0。
		if li.crc != e.CRC32 || li.csize != e.CompSize || li.usize != e.UncompSize {
			t.Errorf("条目 %q 本地头 CRC/大小不是真值: got crc=%08x cs=%d us=%d want crc=%08x cs=%d us=%d",
				li.name, li.crc, li.csize, li.usize, e.CRC32, e.CompSize, e.UncompSize)
		}
		if e.IsStored() {
			if li.hasDD || li.flags&flagDataDescriptor != 0 {
				t.Errorf("Stored 条目 %q 不应有数据描述符（样本里 160 个 STORED 全部没有）", li.name)
			}
			continue
		}
		if !li.hasDD || li.flags&flagDataDescriptor == 0 {
			t.Errorf("Deflate 条目 %q 应置 bit3 并带数据描述符", li.name)
			continue
		}
		if li.ddCRC != e.CRC32 || li.ddCS != e.CompSize || li.ddUS != e.UncompSize {
			t.Errorf("条目 %q 的数据描述符字段与本地头不一致: crc=%08x cs=%d us=%d",
				li.name, li.ddCRC, li.ddCS, li.ddUS)
		}
		if li.lho != 0 && i > 0 {
			prev := locals[i-1]
			wantLHO := prev.dataEnd
			if prev.hasDD {
				wantLHO += dataDescriptorLen
			}
			if li.lho != wantLHO {
				t.Errorf("条目 %q 的本地头偏移 %d，期望 %d（前一条目数据 + 描述符）",
					li.name, li.lho, wantLHO)
			}
		}
	}

	// 本地头区域结束后应立刻是中央目录，且 EOCD 里的偏移与之一致。
	if cdOff+4 > len(out) || binary.LittleEndian.Uint32(out[cdOff:]) != sigCentral {
		t.Fatalf("本地头区域结束偏移 %d 处不是中央目录签名", cdOff)
	}
	eocd := findEOCD(out)
	if eocd < 0 {
		t.Fatal("找不到 EOCD")
	}
	if got := int(binary.LittleEndian.Uint32(out[eocd+16:])); got != cdOff {
		t.Errorf("EOCD 中央目录偏移 = %d，实际中央目录在 %d（数据描述符未被计入）", got, cdOff)
	}

	// (c) 仓库自己的 zipx 读回：内容与 flags 都必须正确。
	got, err := Read(out)
	if err != nil {
		t.Fatalf("zipx.Read 解析失败: %v", err)
	}
	if len(got.Entries) != len(a.Entries) {
		t.Fatalf("读回条目数 %d，期望 %d", len(got.Entries), len(a.Entries))
	}
	for _, e := range got.Entries {
		data, err := e.Data()
		if err != nil {
			t.Fatalf("读回条目 %q 解压失败: %v", e.NameString(), err)
		}
		if !bytes.Equal(data, want[e.NameString()]) {
			t.Errorf("读回条目 %q 内容不符", e.NameString())
		}
		if e.IsStored() {
			continue
		}
		if e.Flags&flagDataDescriptor == 0 {
			t.Errorf("中央目录里的 Deflate 条目 %q 应保留 bit3（样本 CD flags=0x0808）", e.NameString())
		}
	}

	// (a) Go 标准库 archive/zip 必须能正确读出每个条目的内容。
	zr, err := zip.NewReader(bytes.NewReader(out), int64(len(out)))
	if err != nil {
		t.Fatalf("archive/zip 打开失败: %v", err)
	}
	if len(zr.File) != len(a.Entries) {
		t.Fatalf("archive/zip 条目数 %d，期望 %d", len(zr.File), len(a.Entries))
	}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("archive/zip 打开条目 %q 失败: %v", f.Name, err)
		}
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(rc); err != nil {
			rc.Close()
			t.Fatalf("archive/zip 读取条目 %q 失败: %v", f.Name, err)
		}
		rc.Close()
		if !bytes.Equal(buf.Bytes(), want[f.Name]) {
			t.Errorf("archive/zip 读出的条目 %q 内容不符", f.Name)
		}
	}
}

// TestDataDescriptorDisabled 验证 NoDataDescriptors 能完全恢复旧行为：
// 无描述符、bit3 清除，本地头与中央目录 flags 一致。
func TestDataDescriptorDisabled(t *testing.T) {
	a, want := sampleArchiveWithDeflate(t)
	out := Write(a, AlignOptions{Align: 4, SoAlign: 16384, NoDataDescriptors: true})

	locals, cdOff := walkLocals(t, out)
	if len(locals) != len(a.Entries) {
		t.Fatalf("本地头条目数 %d，期望 %d", len(locals), len(a.Entries))
	}
	if cdOff+4 > len(out) || binary.LittleEndian.Uint32(out[cdOff:]) != sigCentral {
		t.Fatalf("关闭描述符后本地头区域结束偏移 %d 处不是中央目录", cdOff)
	}
	for _, li := range locals {
		if li.hasDD || li.flags&flagDataDescriptor != 0 {
			t.Errorf("关闭开关后条目 %q 仍有数据描述符/bit3", li.name)
		}
	}
	got, err := Read(out)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	for _, e := range got.Entries {
		data, err := e.Data()
		if err != nil {
			t.Fatalf("读取 %q 失败: %v", e.NameString(), err)
		}
		if !bytes.Equal(data, want[e.NameString()]) {
			t.Errorf("条目 %q 内容不符", e.NameString())
		}
		if e.Flags&flagDataDescriptor != 0 {
			t.Errorf("关闭开关后中央目录条目 %q 仍有 bit3", e.NameString())
		}
	}
}

// TestDataDescriptorCountsTowardSoAlignment 验证前缀条目的数据描述符被计入
// 后续 .so 的偏移计算：.so 的数据起点仍严格对齐到 SoAlign。
func TestDataDescriptorCountsTowardSoAlignment(t *testing.T) {
	pre := newDeflated(t, "classes.dex", bytes.Repeat([]byte("payload-"), 300))
	so := NewStored("lib/arm64-v8a/libx.so", bytes.Repeat([]byte{7}, 256))
	a := &Archive{Entries: []*Entry{pre, so}}
	out := Write(a, DefaultAlign())

	locals, _ := walkLocals(t, out)
	preL := findLocal(t, locals, "classes.dex")
	soL := findLocal(t, locals, "lib/arm64-v8a/libx.so")

	// .so 的本地头必须紧跟前一条目的数据 + 16 字节描述符之后。
	wantLHO := preL.dataEnd + dataDescriptorLen
	if soL.lho != wantLHO {
		t.Fatalf(".so 本地头偏移 %d，期望 %d（描述符未被计入）", soL.lho, wantLHO)
	}
	if soL.dataOff%16384 != 0 {
		t.Fatalf(".so 数据偏移 %d 未对齐到 16384", soL.dataOff)
	}
	if mult, ok := alignmentMultiple(out[soL.dataOff-soL.extraLen : soL.dataOff]); !ok || mult != 16384 {
		t.Fatalf(".so 的 0xd935 对齐记录缺失或倍数不对: mult=%d ok=%v", mult, ok)
	}

	// 对照：前缀条目换成 Stored（无描述符）时，.so 的数据起点同样应
	// 对齐到 16384，证明对齐算法本身工作正常。
	a2 := &Archive{Entries: []*Entry{
		NewStored("classes.dex", bytes.Repeat([]byte("payload-"), 300)),
		NewStored("lib/arm64-v8a/libx.so", bytes.Repeat([]byte{7}, 256)),
	}}
	out2 := Write(a2, DefaultAlign())
	locals2, _ := walkLocals(t, out2)
	soL2 := findLocal(t, locals2, "lib/arm64-v8a/libx.so")
	if soL2.dataOff%16384 != 0 {
		t.Fatalf("对照组 .so 数据偏移 %d 未对齐到 16384", soL2.dataOff)
	}
}

// TestLocalFlagDecoy 验证本地头假加密 flag：
//   - 只有核心条目（Manifest/arsc/classes*.dex）的**本地头**被置 bit0+bit6；
//   - 中央目录不含这些位，本地/中央其余 flags 一致；
//   - 非核心条目（含大小写/同形诱饵名）不受影响；
//   - 开关关闭时任何条目都不含这些位。
func TestLocalFlagDecoy(t *testing.T) {
	core := []string{"AndroidManifest.xml", "resources.arsc", "classes.dex", "classes2.dex", "classes12.dex"}
	nonCore := []string{"classesx.dex", "ANDROIDMANIFEST.XML", "res/AndroidManifest.xml", "classes1.dex.bak", "a.bin"}
	a := &Archive{}
	for _, n := range core {
		if n == "resources.arsc" {
			a.Entries = append(a.Entries, NewStored(n, []byte("core-"+n)))
		} else {
			a.Entries = append(a.Entries, newDeflated(t, n, []byte("core-"+n)))
		}
	}
	for _, n := range nonCore {
		a.Entries = append(a.Entries, newDeflated(t, n, []byte("other-"+n)))
	}

	opts := DefaultAlign()
	opts.LocalFlagDecoy = true
	out := Write(a, opts)

	locals, _ := walkLocals(t, out)
	cd, err := Read(out)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	cdFlags := map[string]uint16{}
	for _, e := range cd.Entries {
		cdFlags[e.NameString()] = e.Flags
	}

	isCore := map[string]bool{}
	for _, n := range core {
		isCore[n] = true
	}
	for _, li := range locals {
		if isCore[li.name] {
			if li.flags&LocalDecoyMask != LocalDecoyMask {
				t.Errorf("核心条目 %q 本地头应含 bit0+bit6，实际 flags=0x%04x", li.name, li.flags)
			}
		} else if li.flags&LocalDecoyMask != 0 {
			t.Errorf("非核心条目 %q 不应被写入假加密位，实际 flags=0x%04x", li.name, li.flags)
		}
		cf := cdFlags[li.name]
		if cf&LocalDecoyMask != 0 {
			t.Errorf("条目 %q 的中央目录不应含假加密位，实际 flags=0x%04x", li.name, cf)
		}
		// 除仅本地位以外，本地与中央 flags 必须一致。
		if li.flags&^uint16(LocalDecoyMask) != cf {
			t.Errorf("条目 %q 本地/中央 flags 除假加密位外不一致: local=0x%04x central=0x%04x",
				li.name, li.flags, cf)
		}
	}

	// 内容仍可正常读出（读路径不因 flag 位拒读）。
	for _, e := range cd.Entries {
		if _, err := e.Data(); err != nil {
			t.Fatalf("带假加密 flag 的条目 %q 读不出内容: %v", e.NameString(), err)
		}
	}

	// 关闭开关：与现状一致，任何条目都不含 bit0/bit6，且本地/中央 flags 完全一致。
	out2 := Write(a, DefaultAlign())
	locals2, _ := walkLocals(t, out2)
	cd2, err := Read(out2)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	cdFlags2 := map[string]uint16{}
	for _, e := range cd2.Entries {
		cdFlags2[e.NameString()] = e.Flags
	}
	for _, li := range locals2 {
		if li.flags&LocalDecoyMask != 0 {
			t.Errorf("关闭开关后条目 %q 不应含假加密位，实际 flags=0x%04x", li.name, li.flags)
		}
		if li.flags != cdFlags2[li.name] {
			t.Errorf("关闭开关后条目 %q 本地 flags=0x%04x 与中央目录 0x%04x 不一致",
				li.name, li.flags, cdFlags2[li.name])
		}
	}
}

// TestDataDescriptorExternalReaders 用 Python zipfile 与 unzip -t
// 独立验证带数据描述符的产物（两者都按中央目录读取）。
func TestDataDescriptorExternalReaders(t *testing.T) {
	a, want := sampleArchiveWithDeflate(t)
	out := Write(a, DefaultAlign())

	p := filepath.Join(t.TempDir(), "dd.apk")
	if err := os.WriteFile(p, out, 0o644); err != nil {
		t.Fatalf("写出临时 APK 失败: %v", err)
	}

	// ---- Python zipfile ----
	py, err := exec.LookPath("python3")
	if err != nil {
		py, err = exec.LookPath("python")
	}
	if err != nil {
		t.Log("未找到 python3/python，跳过 Python zipfile 校验")
	} else {
		script := `import sys, zipfile, hashlib
p = sys.argv[1]
expect = dict(a.split('=', 1) for a in sys.argv[2:])
z = zipfile.ZipFile(p)
assert z.testzip() is None, "CRC mismatch"
assert sorted(z.namelist()) == sorted(expect), z.namelist()
for n, h in expect.items():
    got = hashlib.sha256(z.read(n)).hexdigest()
    assert got == h, (n, got, h)
print("PYOK", len(expect))
`
		args := []string{"-c", script, p}
		for name, data := range want {
			sum := sha256.Sum256(data)
			args = append(args, name+"="+hex.EncodeToString(sum[:]))
		}
		cmd := exec.Command(py, args...)
		outb, err := cmd.CombinedOutput()
		if err != nil {
			msg := string(outb)
			if strings.Contains(msg, "not found") || strings.Contains(msg, "not recognized") {
				t.Logf("python 不可执行（%v），跳过: %s", err, msg)
			} else {
				t.Fatalf("Python zipfile 校验失败: %v\n%s", err, outb)
			}
		} else if !bytes.Contains(outb, []byte("PYOK")) {
			t.Fatalf("Python zipfile 校验输出异常: %s", outb)
		} else {
			t.Logf("Python zipfile 校验通过: %s", bytes.TrimSpace(outb))
		}
	}

	// ---- unzip -t ----
	if unz, err := exec.LookPath("unzip"); err == nil {
		cmd := exec.Command(unz, "-t", p)
		outb, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("unzip -t 失败: %v\n%s", err, outb)
		}
		if !bytes.Contains(outb, []byte("No errors detected")) {
			t.Fatalf("unzip -t 未报告无错误:\n%s", outb)
		}
		t.Logf("unzip -t 通过: %s", bytes.TrimSpace(outb))
	} else {
		t.Log("未找到 unzip，跳过 unzip -t 校验")
	}
}
