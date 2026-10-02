package passes

import (
	"bytes"
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/native"
	"apkguard/internal/pipeline"
	"apkguard/internal/zipx"
)

// ---- C7 测试辅助 ----

// c7BridgeDex 构造一个含 native 桥接类的壳 DEX。
// 桥接类 <clinit> 里 System.loadLibrary 的实参就是 dex.NativeLibName（"apkguard"）。
func c7BridgeDex(t *testing.T) []byte {
	t.Helper()
	add, err := dex.NativeBridgeAddition(&dex.NativeBridgeSpec{
		Class:      dex.NativeBridgeClass,
		LibName:    dex.NativeLibName,
		NeedDerive: true,
	})
	if err != nil {
		t.Fatalf("构造桥接类失败: %v", err)
	}
	out, err := dex.Build(add)
	if err != nil {
		t.Fatalf("生成壳 DEX 失败: %v", err)
	}
	return out
}

// c7Prebuilt 返回指定 ABI 的预编译守卫库（来自 native 的 go:embed）。
func c7Prebuilt(t *testing.T, abi string) native.AbiLib {
	t.Helper()
	libs, err := native.Prebuilt()
	if err != nil {
		t.Fatalf("读取预编译守卫库失败: %v", err)
	}
	for _, l := range libs {
		if l.Abi == abi {
			return l
		}
	}
	t.Fatalf("预编译库不含 ABI %s", abi)
	return native.AbiLib{}
}

// c7ShellArtifact 构造含壳 DEX 与指定 ABI 守卫库的产物，并登记壳信息。
func c7ShellArtifact(t *testing.T, abis ...string) *pipeline.Artifact {
	t.Helper()
	entries := []*zipx.Entry{zipxStored("classes.dex", c7BridgeDex(t))}
	for _, abi := range abis {
		l := c7Prebuilt(t, abi)
		entries = append(entries, zipxStored(l.Entry, l.Data))
	}
	art := newArtifact(entries...)
	art.Put(sharedKeyShell, &shellInfo{EntryName: "classes.dex"})
	return art
}

// c7DexStrings 返回 DEX 字符串池的全部字符串。
func c7DexStrings(t *testing.T, data []byte) []string {
	t.Helper()
	f, err := dex.Parse(data)
	if err != nil {
		t.Fatalf("解析 DEX 失败: %v", err)
	}
	ss, err := f.AllStrings()
	if err != nil {
		t.Fatalf("读取字符串池失败: %v", err)
	}
	return ss
}

func c7HasExact(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// c7ELFInfo 汇总 ELF 头与 PT_LOAD 对齐，用于断言「只动节头字段」。
type c7ELFInfo struct {
	is64             bool
	ident            []byte
	phoff            uint64
	phnum            uint16
	shoff            uint64
	shentsize, shnum uint16
	shstrndx         uint16
	loadAligns       []uint64
	rawHeaderBytes   []byte // 头部前 0x40 字节，逐字段比对用
}

// c7ReadELF 解析 ELF 头与 program header 对齐（偏移依据 System V ABI，
// 与实现及 build_native.py 一致）。
func c7ReadELF(t *testing.T, data []byte) c7ELFInfo {
	t.Helper()
	if len(data) < 0x40 {
		t.Fatalf("ELF 过短: %d", len(data))
	}
	info := c7ELFInfo{is64: data[4] == 2}
	info.ident = append([]byte(nil), data[:16]...)
	n := 0x40
	if len(data) < n {
		n = len(data)
	}
	info.rawHeaderBytes = append([]byte(nil), data[:n]...)

	var phentsize uint16
	if info.is64 {
		info.shoff = binary.LittleEndian.Uint64(data[0x28:])
		info.shentsize = binary.LittleEndian.Uint16(data[0x3A:])
		info.shnum = binary.LittleEndian.Uint16(data[0x3C:])
		info.shstrndx = binary.LittleEndian.Uint16(data[0x3E:])
		info.phoff = binary.LittleEndian.Uint64(data[0x20:])
		phentsize = binary.LittleEndian.Uint16(data[0x36:])
		info.phnum = binary.LittleEndian.Uint16(data[0x38:])
	} else {
		info.shoff = uint64(binary.LittleEndian.Uint32(data[0x20:]))
		info.shentsize = binary.LittleEndian.Uint16(data[0x2E:])
		info.shnum = binary.LittleEndian.Uint16(data[0x30:])
		info.shstrndx = binary.LittleEndian.Uint16(data[0x32:])
		info.phoff = uint64(binary.LittleEndian.Uint32(data[0x1C:]))
		phentsize = binary.LittleEndian.Uint16(data[0x2A:])
		info.phnum = binary.LittleEndian.Uint16(data[0x2C:])
	}
	for i := uint16(0); i < info.phnum; i++ {
		off := int(info.phoff) + int(i)*int(phentsize)
		if off+int(phentsize) > len(data) {
			t.Fatalf("program header %d 越界", i)
		}
		if binary.LittleEndian.Uint32(data[off:]) != 1 { // PT_LOAD
			continue
		}
		if info.is64 {
			info.loadAligns = append(info.loadAligns, binary.LittleEndian.Uint64(data[off+0x30:]))
		} else {
			info.loadAligns = append(info.loadAligns, uint64(binary.LittleEndian.Uint32(data[off+0x1C:])))
		}
	}
	return info
}

// ---- 测试 ----

// TestLibDisguiseRename 验证改名生效、内容逐字节不变、壳侧 loadLibrary 同步。
func TestLibDisguiseRename(t *testing.T) {
	const fake = "libsqlite3x.so"
	art := c7ShellArtifact(t, "arm64-v8a", "armeabi-v7a")
	orig64 := c7Prebuilt(t, "arm64-v8a").Data
	orig32 := c7Prebuilt(t, "armeabi-v7a").Data

	opts := &config.Options{
		Enabled:     map[config.FeatureID]bool{"C7": true, "C1": true},
		LibFakeName: fake,
	}
	if err := (&libDisguise{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("C7 执行失败: %v", err)
	}

	// ① 旧名消失、新名存在、内容逐字节相同。
	for _, abi := range []string{"arm64-v8a", "armeabi-v7a"} {
		if pipeline.Find(art, "lib/"+abi+"/"+native.LibFileName) != nil {
			t.Fatalf("%s 的旧守卫库名仍存在", abi)
		}
		e := pipeline.Find(art, "lib/"+abi+"/"+fake)
		if e == nil {
			t.Fatalf("%s 未出现新假名 %s", abi, fake)
		}
		want := orig64
		if abi == "armeabi-v7a" {
			want = orig32
		}
		got, err := e.Data()
		if err != nil {
			t.Fatalf("读取 %s 失败: %v", e.NameString(), err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s 改名后内容被改动（改名不应改内容）", abi)
		}
	}

	// ② 壳 DEX 的 loadLibrary 实参已是新名；旧名不得再被引用。
	shell := pipeline.Find(art, "classes.dex")
	sd, err := shell.Data()
	if err != nil {
		t.Fatal(err)
	}
	ss := c7DexStrings(t, sd)
	if !c7HasExact(ss, "sqlite3x") {
		t.Fatalf("壳 DEX 未出现新库名 sqlite3x: %v", ss)
	}
	if c7HasExact(ss, native.LibName) {
		t.Fatalf("壳 DEX 字符串池仍含旧库名 %q（改名后必须消失）", native.LibName)
	}
	if err := dex.Verify(sd); err != nil {
		t.Fatalf("改写库名后壳 DEX 非法: %v", err)
	}

	// ③ 统计。
	if art.Stats["C7.renamed"] != "2" || art.Stats["C7.new_name"] != fake {
		t.Fatalf("C7 统计不符: %v", art.Stats)
	}
	if art.Stats["C7.abis"] != "arm64-v8a,armeabi-v7a" {
		t.Fatalf("C7.abis 不符: %v", art.Stats)
	}
}

// TestLibDisguiseRejectsSectionStrip 钉住「削节头被显式拒绝」。
//
// 曾经实现过削节头（把 ELF 节头表置 0，让 readelf -S 失败），但实测证明在
// Android 上不可行，且是两次真机崩溃的来源：
//
//	清零 e_shentsize → dlopen failed: has unsupported e_shentsize: 0x0 (expected 0x40)
//	清零 e_shstrndx  → dlopen failed: has invalid e_shstrndx
//
// 即便只清空 .shstrtab 的内容能骗过链接器，C6 的完整性校验也要靠节名定位
// .text/.rodata，节名不可读就只能失败关闭（拒绝启动）或失败开放（静默失效），
// 两者都不比不做更好。
//
// 因此这里断言：请求削节头时**显式报错**，而不是静默忽略——静默忽略正是
// 本项目最忌讳的失败模式（用户以为拿到了额外防护）。
func TestLibDisguiseRejectsSectionStrip(t *testing.T) {
	art := c7ShellArtifact(t, "arm64-v8a")
	opts := &config.Options{
		Enabled:          map[config.FeatureID]bool{"C7": true, "C1": true},
		LibStripSections: true,
	}
	err := (&libDisguise{}).Run(context.Background(), art, opts)
	if err == nil {
		t.Fatal("请求削节头时应显式报错，而不是静默不做")
	}
	if !strings.Contains(err.Error(), "节头") {
		t.Fatalf("错误信息应说明不支持削节头及其原因，实际: %v", err)
	}
	// 报错即中止：不应留下任何改动。
	if e := pipeline.Find(art, "lib/arm64-v8a/"+native.LibFileName); e == nil {
		t.Fatal("报错时不应改动守卫库条目")
	}
	t.Logf("削节头被正确拒绝: %v", err)
}

// TestLibDisguiseFakeNameNormalization 验证假名规范化。
func TestLibDisguiseFakeNameNormalization(t *testing.T) {
	cases := []struct {
		in       string
		wantFile string
		wantLib  string
		wantErr  bool
	}{
		{"", "libsqlite3x.so", "sqlite3x", false},
		{"libfoo.so", "libfoo.so", "foo", false},
		{"foo.so", "libfoo.so", "foo", false},
		{"libfoo", "libfoo.so", "foo", false},
		{"libc++_shared.so", "libc++_shared.so", "c++_shared", false},
		{"a/b.so", "", "", true},
		{"lib.so", "", "", true},
		{"liba b.so", "", "", true},
	}
	for _, c := range cases {
		f, l, err := fakeLibNames(c.in)
		if c.wantErr {
			if err == nil {
				t.Fatalf("fakeLibNames(%q) 应报错", c.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("fakeLibNames(%q) 意外报错: %v", c.in, err)
		}
		if f != c.wantFile || l != c.wantLib {
			t.Fatalf("fakeLibNames(%q) = (%q,%q)，期望 (%q,%q)", c.in, f, l, c.wantFile, c.wantLib)
		}
	}
}

// c7ShstrtabCleared 判断 .shstrtab 指向的区域是否已被清零（ELF32/64 都支持）。
func c7ShstrtabCleared(data []byte) bool {
	if len(data) < 0x40 || data[0] != 0x7f {
		return false
	}
	var shoff uint64
	var shent, shnum, shstr uint16
	var offOff, szOff, fieldLen int
	switch data[4] {
	case 2: // ELFCLASS64
		shoff = binary.LittleEndian.Uint64(data[0x28:])
		shent = binary.LittleEndian.Uint16(data[0x3A:])
		shnum = binary.LittleEndian.Uint16(data[0x3C:])
		shstr = binary.LittleEndian.Uint16(data[0x3E:])
		offOff, szOff, fieldLen = 0x18, 0x20, 8
	case 1: // ELFCLASS32
		shoff = uint64(binary.LittleEndian.Uint32(data[0x20:]))
		shent = binary.LittleEndian.Uint16(data[0x2E:])
		shnum = binary.LittleEndian.Uint16(data[0x30:])
		shstr = binary.LittleEndian.Uint16(data[0x32:])
		offOff, szOff, fieldLen = 0x10, 0x14, 4
	default:
		return false
	}
	if shoff == 0 || shnum == 0 || shstr >= shnum || shent == 0 {
		return false
	}
	hdr := int(shoff) + int(shstr)*int(shent)
	if hdr+szOff+fieldLen > len(data) {
		return false
	}
	var off, size uint64
	if fieldLen == 8 {
		off = binary.LittleEndian.Uint64(data[hdr+offOff:])
		size = binary.LittleEndian.Uint64(data[hdr+szOff:])
	} else {
		off = uint64(binary.LittleEndian.Uint32(data[hdr+offOff:]))
		size = uint64(binary.LittleEndian.Uint32(data[hdr+szOff:]))
	}
	if off == 0 || size == 0 || off+size > uint64(len(data)) {
		return false
	}
	for i := off; i < off+size; i++ {
		if data[i] != 0 {
			return false
		}
	}
	return true
}
