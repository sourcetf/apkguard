package zipx

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

// alignmentMultiple 解析扩展字段中 0xd935 记录声明的对齐倍数。
func alignmentMultiple(extra []byte) (uint16, bool) {
	p := 0
	for p+4 <= len(extra) {
		id := binary.LittleEndian.Uint16(extra[p:])
		n := int(binary.LittleEndian.Uint16(extra[p+2:]))
		if id == 0 && n == 0 {
			break
		}
		if p+4+n > len(extra) {
			break
		}
		if id == 0xd935 {
			if n < 2 {
				return 0, true
			}
			return binary.LittleEndian.Uint16(extra[p+4:]), true
		}
		p += 4 + n
	}
	return 0, false
}

// TestWriteCheckedEntryLimit 验证条目数超过 65535 时返回错误，而不是让 EOCD
// 计数静默回绕、产出读回 0 个条目的坏归档；65535 个则必须成功且可读回。
func TestWriteCheckedEntryLimit(t *testing.T) {
	big := &Archive{}
	for i := 0; i < 65536; i++ {
		big.Entries = append(big.Entries, NewStored(fmt.Sprintf("f%d", i), []byte{byte(i)}))
	}
	if _, err := WriteChecked(big, AlignOptions{Align: 1, SoAlign: 1}); err == nil {
		t.Fatal("65536 个条目必须返回 error（否则 EOCD 计数回绕为 0）")
	}

	ok := &Archive{}
	for i := 0; i < 65535; i++ {
		ok.Entries = append(ok.Entries, NewStored(fmt.Sprintf("f%d", i), []byte{byte(i)}))
	}
	out, err := WriteChecked(ok, AlignOptions{Align: 1, SoAlign: 1})
	if err != nil {
		t.Fatalf("65535 个条目应成功写出: %v", err)
	}
	got, err := Read(out)
	if err != nil {
		t.Fatalf("65535 个条目的归档应可读回: %v", err)
	}
	if len(got.Entries) != 65535 {
		t.Fatalf("读回条目数 = %d，期望 65535", len(got.Entries))
	}
}

// TestWriteCheckedRejectsOversizedFields 验证条目名/注释超过 0xFFFF 时返回错误。
func TestWriteCheckedRejectsOversizedFields(t *testing.T) {
	name := NewStored("x", []byte("y"))
	name.Name = bytes.Repeat([]byte("a"), 0x10000)
	if _, err := WriteChecked(&Archive{Entries: []*Entry{name}}, AlignOptions{Align: 1, SoAlign: 1}); err == nil {
		t.Error("条目名长度 > 65535 应返回 error")
	}

	cmt := NewStored("x", []byte("y"))
	cmt.Comment = bytes.Repeat([]byte("c"), 0x10000)
	if _, err := WriteChecked(&Archive{Entries: []*Entry{cmt}}, AlignOptions{Align: 1, SoAlign: 1}); err == nil {
		t.Error("条目注释长度 > 65535 应返回 error")
	}
}

// TestWritePreservesCentralExtra 验证中央目录独有的扩展字段（如 0x5455
// 扩展时间戳）在重写后被保留，而不是被本地扩展字段整体覆盖。
func TestWritePreservesCentralExtra(t *testing.T) {
	e := NewStored("resources.arsc", []byte("arsc-data"))
	central := []byte{0x55, 0x54, 0x01, 0x00, 0x7f} // 0x5455 扩展时间戳
	e.CentralExtra = append([]byte(nil), central...)

	out := Write(&Archive{Entries: []*Entry{e}}, DefaultAlign())
	got, err := Read(out)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if !bytes.HasPrefix(got.Entries[0].CentralExtra, central) {
		t.Fatalf("中央目录扩展字段丢失：got % x，期望前缀 % x", got.Entries[0].CentralExtra, central)
	}
}

// TestAlignmentExtraCarriesMultiple 验证 0xd935 对齐扩展字段载荷的前 2 字节
// 写入该条目的对齐倍数（普通条目 4，.so 16384）。
func TestAlignmentExtraCarriesMultiple(t *testing.T) {
	a := &Archive{Entries: []*Entry{
		NewStored("lib/arm64-v8a/libx.so", bytes.Repeat([]byte{1}, 64)),
		NewStored("classes.dex", []byte("dex")),
	}}
	out := Write(a, DefaultAlign())
	got, err := Read(out)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	for _, e := range got.Entries {
		want := uint16(4)
		if strings.HasSuffix(strings.ToLower(e.NameString()), ".so") {
			want = 16384
		}
		mult, ok := alignmentMultiple(e.LocalExtra)
		if !ok {
			t.Fatalf("%s 缺少 0xd935 对齐记录", e.NameString())
		}
		if mult != want {
			t.Errorf("%s 对齐倍数 = %d，期望 %d", e.NameString(), mult, want)
		}
	}
}

// TestSoSuffixCaseInsensitiveAnd16K 验证 .so 判定大小写不敏感（LIB.SO 也按 so
// 对齐），且 .so 数据偏移是 16384 的倍数。
func TestSoSuffixCaseInsensitiveAnd16K(t *testing.T) {
	a := &Archive{Entries: []*Entry{
		NewStored("lib/arm64-v8a/LIB.SO", bytes.Repeat([]byte{1}, 64)),
	}}
	out := Write(a, DefaultAlign())
	got, err := Read(out)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	mult, ok := alignmentMultiple(got.Entries[0].LocalExtra)
	if !ok {
		t.Fatalf("LIB.SO 缺少对齐记录")
	}
	if mult != 16384 {
		t.Errorf("LIB.SO 应按 .so 对齐到 16384，实际 %d", mult)
	}
	nameLen := len(a.Entries[0].Name)
	extraLen := int(binary.LittleEndian.Uint16(out[28:]))
	dataOff := localHeaderLen + nameLen + extraLen
	if dataOff%16384 != 0 {
		t.Errorf("LIB.SO 数据偏移 %d 不是 16384 的倍数", dataOff)
	}
}
