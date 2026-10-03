package sign

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf8"

	"apkguard/internal/zipx"
)

const auditLocalHeaderLen = 30

type auditLocal struct {
	name     string
	lho      int
	dataOff  int
	extraLen int
	compSize int
}

// auditWalkLocals 从偏移 0 起顺序遍历本地头（Write 产出的归档本地头连续排列）。
func auditWalkLocals(t *testing.T, data []byte) []auditLocal {
	t.Helper()
	var out []auditLocal
	off := 0
	for off+auditLocalHeaderLen <= len(data) &&
		binary.LittleEndian.Uint32(data[off:]) == 0x04034b50 {
		nameLen := int(binary.LittleEndian.Uint16(data[off+26:]))
		extraLen := int(binary.LittleEndian.Uint16(data[off+28:]))
		compSize := int(binary.LittleEndian.Uint32(data[off+18:]))
		if off+auditLocalHeaderLen+nameLen+extraLen+compSize > len(data) {
			t.Fatalf("本地头越界 @%d", off)
		}
		name := string(data[off+auditLocalHeaderLen : off+auditLocalHeaderLen+nameLen])
		dataOff := off + auditLocalHeaderLen + nameLen + extraLen
		out = append(out, auditLocal{name, off, dataOff, extraLen, compSize})
		off = dataOff + compSize
	}
	return out
}

func auditFindLocal(t *testing.T, data []byte, name string) auditLocal {
	t.Helper()
	for _, l := range auditWalkLocals(t, data) {
		if l.name == name {
			return l
		}
	}
	t.Fatalf("未找到本地头条目 %q", name)
	return auditLocal{}
}

// auditSplitLines 把内容按物理行切分（去掉行尾 \r）。
func auditSplitLines(data []byte) [][]byte {
	var out [][]byte
	for _, ln := range bytes.Split(data, []byte("\n")) {
		out = append(out, bytes.TrimRight(ln, "\r"))
	}
	return out
}

// auditUnfold 还原以单个空格开头的续行。
func auditUnfold(lines [][]byte) [][]byte {
	var out [][]byte
	for _, ln := range lines {
		if len(ln) > 0 && ln[0] == ' ' && len(out) > 0 {
			out[len(out)-1] = append(out[len(out)-1], ln[1:]...)
			continue
		}
		out = append(out, append([]byte(nil), ln...))
	}
	return out
}

// TestV1ManifestFoldIsCharSafe 验证 MANIFEST.MF / CERT.SF 的折行不会切断
// 多字节 UTF-8 字符：每个物理行都是合法 UTF-8，且还原折行后的 Name 与原始
// 条目名逐字节相等。
func TestV1ManifestFoldIsCharSafe(t *testing.T) {
	name := "res/" + strings.Repeat("中", 30) + "/" + strings.Repeat("😀", 3) + "/assets.bin"
	a := &zipx.Archive{Entries: []*zipx.Entry{
		zipx.NewStored("AndroidManifest.xml", []byte("m")),
		zipx.NewStored(name, []byte("payload-data")),
	}}
	in := zipx.Write(a, zipx.DefaultAlign())

	mat := testMaterial(t, false)
	res, err := Sign(in, mat, Options{V1: true})
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	got, err := zipx.Read(res.APK)
	if err != nil {
		t.Fatalf("解析签名产物失败: %v", err)
	}

	for _, fn := range []string{"META-INF/MANIFEST.MF", "META-INF/CERT.SF"} {
		e := got.Find(fn)
		if e == nil {
			t.Fatalf("缺少 %s", fn)
		}
		data, err := e.Data()
		if err != nil {
			t.Fatalf("读取 %s 失败: %v", fn, err)
		}

		lines := auditSplitLines(data)
		sawFold := false
		for i, ln := range lines {
			if !utf8.Valid(ln) {
				t.Fatalf("%s 第 %d 个物理行非法 UTF-8: %q", fn, i, ln)
			}
			if len(ln) > 72 {
				t.Errorf("%s 第 %d 个物理行 %d 字节，超过 72", fn, i, len(ln))
			}
			if i > 0 && len(ln) > 0 && ln[0] == ' ' {
				sawFold = true
			}
		}
		if !sawFold {
			t.Fatalf("%s 未发生折行，测试未覆盖折行逻辑", fn)
		}

		var gotName []byte
		for _, ln := range auditUnfold(lines) {
			if bytes.HasPrefix(ln, []byte("Name: ")) {
				gotName = ln[len("Name: "):]
				if bytes.Equal(gotName, []byte(name)) {
					break
				}
			}
		}
		if !bytes.Equal(gotName, []byte(name)) {
			t.Fatalf("%s 还原折行后的 Name 与原始条目名不符:\n got  % x\n want % x",
				fn, gotName, []byte(name))
		}
	}
}

// TestSignRespectsCallerAlignOption 验证签名阶段沿用调用方给定的对齐参数：
// E2 关闭（Align:1,SoAlign:1）时 .so 不被重新对齐；默认（零值 Align）时
// 按 DefaultAlign 对齐到 16384 的倍数。
func TestSignRespectsCallerAlignOption(t *testing.T) {
	a := &zipx.Archive{Entries: []*zipx.Entry{
		zipx.NewStored("lib/arm64-v8a/liba.so", bytes.Repeat([]byte{1}, 100)),
		zipx.NewStored("a.txt", []byte("hello")),
	}}
	pre := zipx.Write(a, zipx.AlignOptions{Align: 1, SoAlign: 1})
	mat := testMaterial(t, false)

	// E2 关闭：不得追加对齐记录，数据区偏移仍为「本地头 + 名」。
	res, err := Sign(pre, mat, Options{V1: true, Align: zipx.AlignOptions{Align: 1, SoAlign: 1}})
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	so := auditFindLocal(t, res.APK, "lib/arm64-v8a/liba.so")
	if so.extraLen != 0 {
		t.Errorf("E2 关闭时 .so 不应被对齐，extraLen=%d dataOff=%d", so.extraLen, so.dataOff)
	}
	if so.dataOff-so.lho != auditLocalHeaderLen+len(so.name) {
		t.Errorf("E2 关闭时 .so 数据偏移被改变：dataOff-lho=%d，期望 %d",
			so.dataOff-so.lho, auditLocalHeaderLen+len(so.name))
	}

	// E2 开启（零值 Align = DefaultAlign）：.so 对齐到 16384 的倍数。
	res2, err := Sign(pre, mat, Options{V1: true})
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	so2 := auditFindLocal(t, res2.APK, "lib/arm64-v8a/liba.so")
	if so2.extraLen == 0 {
		t.Fatal("默认对齐时 .so 应追加对齐记录")
	}
	if so2.dataOff%16384 != 0 {
		t.Errorf("默认对齐时 .so 数据偏移 %d 不是 16384 的倍数", so2.dataOff)
	}
}
