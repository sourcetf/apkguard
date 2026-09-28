package zipx

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// TestAlignAndRoundTrip 验证重写后的归档满足对齐要求，且内容可完整还原。
func TestAlignAndRoundTrip(t *testing.T) {
	a := &Archive{}
	a.Entries = append(a.Entries,
		NewStored("AndroidManifest.xml", []byte("manifest-data")),
		NewStored("resources.arsc", []byte("arsc")),
		NewStored("lib/arm64-v8a/libnative.so", bytes.Repeat([]byte{0xAA}, 5000)),
		NewStored("res/drawable/icon.png", bytes.Repeat([]byte{0xBB}, 777)),
	)

	out := Write(a, DefaultAlign())

	got, err := Read(out)
	if err != nil {
		t.Fatalf("重新解析失败: %v", err)
	}
	if len(got.Entries) != len(a.Entries) {
		t.Fatalf("条目数不符: got %d want %d", len(got.Entries), len(a.Entries))
	}

	// 逐个条目校验名称与数据一致性
	for i, want := range a.Entries {
		g := got.Entries[i]
		if g.NameString() != want.NameString() {
			t.Errorf("条目 %d 名称不符: got %q want %q", i, g.NameString(), want.NameString())
		}
		if !bytes.Equal(g.Raw, want.Raw) {
			t.Errorf("条目 %d 数据不符", i)
		}
	}
}

// TestAlignmentOffsets 验证数据区偏移确实对齐到预期字节数。
func TestAlignmentOffsets(t *testing.T) {
	a := &Archive{}
	a.Entries = append(a.Entries,
		NewStored("a.txt", []byte("x")),
		NewStored("lib/arm64-v8a/libfoo.so", bytes.Repeat([]byte{1}, 100)),
		NewStored("b.bin", bytes.Repeat([]byte{2}, 33)),
	)
	out := Write(a, DefaultAlign())

	// 遍历本地头，检查每个 Stored 条目的数据区偏移
	off := 0
	for i, e := range a.Entries {
		if binary.LittleEndian.Uint32(out[off:]) != sigLocal {
			t.Fatalf("条目 %d 本地头签名错误 @%d", i, off)
		}
		nameLen := int(binary.LittleEndian.Uint16(out[off+26:]))
		extraLen := int(binary.LittleEndian.Uint16(out[off+28:]))
		dataOff := off + localHeaderLen + nameLen + extraLen

		wantAlign := 4
		if hasSuffix(e.Name, ".so") {
			wantAlign = 4096
		}
		if dataOff%wantAlign != 0 {
			t.Errorf("条目 %q 数据偏移 %d 未对齐到 %d", e.NameString(), dataOff, wantAlign)
		}
		off = dataOff + int(e.CompSize)
	}
}

// TestSplitAndStripSigningBlock 验证签名块的识别与剥离。
func TestSplitAndStripSigningBlock(t *testing.T) {
	a := &Archive{}
	a.Entries = append(a.Entries, NewStored("AndroidManifest.xml", []byte("m")))
	base := Write(a, DefaultAlign())

	// 构造一个假的签名块：body 为一段可识别的填充
	body := bytes.Repeat([]byte{0x5A}, 64)
	block := assembleTestBlock(body)

	signed := make([]byte, 0, len(base)+len(block))
	signed = append(signed, base...)
	// 把签名块插到中央目录之前
	cdStart := bytes.Index(base, []byte{'P', 'K', 1, 2})
	signed = append(signed[:0], base[:cdStart]...)
	signed = append(signed, block...)
	signed = append(signed, base[cdStart:]...)
	// 修正 EOCD 的中央目录偏移
	eocd := bytes.LastIndex(signed, []byte{'P', 'K', 5, 6})
	binary.LittleEndian.PutUint32(signed[eocd+16:], uint32(cdStart+len(block)))

	sec, err := Split(signed)
	if err != nil {
		t.Fatalf("Split 失败: %v", err)
	}
	if !sec.HasSigningBlock() {
		t.Fatal("未能识别签名块")
	}
	if !bytes.Equal(sec.SigningBlock, block) {
		t.Error("签名块内容不符")
	}

	stripped, err := StripSigningBlock(signed)
	if err != nil {
		t.Fatalf("StripSigningBlock 失败: %v", err)
	}
	if _, err := Read(stripped); err != nil {
		t.Fatalf("剥离后无法解析: %v", err)
	}
	if s2, _ := Split(stripped); s2.HasSigningBlock() {
		t.Error("剥离后仍检测到签名块")
	}
}

// TestFindEOCDWithComment 验证带注释的归档仍能正确定位 EOCD。
func TestFindEOCDWithComment(t *testing.T) {
	a := &Archive{Comment: []byte("hello-comment")}
	a.Entries = append(a.Entries, NewStored("f.txt", []byte("data")))
	out := Write(a, DefaultAlign())

	got, err := Read(out)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if string(got.Comment) != "hello-comment" {
		t.Errorf("注释不符: got %q", got.Comment)
	}
}

// assembleTestBlock 按 APK 签名块格式包装测试数据。
func assembleTestBlock(body []byte) []byte {
	magic := []byte("APK Sig Block 42")
	blockLen := uint64(len(body) + 8 + len(magic))
	out := make([]byte, 0, 8+len(body)+8+len(magic))
	var hdr [8]byte
	binary.LittleEndian.PutUint64(hdr[:], blockLen)
	out = append(out, hdr[:]...)
	out = append(out, body...)
	binary.LittleEndian.PutUint64(hdr[:], blockLen)
	out = append(out, hdr[:]...)
	out = append(out, magic...)
	return out
}

// TestSanitizeExtraTruncatesGarbage 验证扩展字段中的残尾会被截掉。
func TestSanitizeExtraTruncatesGarbage(t *testing.T) {
	// 一条合法记录：ID 0xd935、长度 4、4 字节载荷。
	good := []byte{0x35, 0xd9, 0x04, 0x00, 0, 0, 0, 0}
	if got := sanitizeExtra(good); !bytes.Equal(got, good) {
		t.Errorf("合法扩展字段不应被改动: % x", got)
	}
	// 样本里 resources.arsc 的本地扩展字段：孤立的 1 个 0x00。
	if got := sanitizeExtra([]byte{0x00}); len(got) != 0 {
		t.Errorf("孤立残尾应被截掉，实际留下 % x", got)
	}
	// 合法记录后跟一个声明长度越界的残尾：只保留前面的合法部分。
	bad := append(append([]byte{}, good...), 0x35, 0xd9, 0xff, 0x00)
	if got := sanitizeExtra(bad); !bytes.Equal(got, good) {
		t.Errorf("越界残尾应被截掉: % x", got)
	}
	// 空记录是终止标记，其后内容忽略。
	term := append(append([]byte{}, good...), 0, 0, 0, 0, 1, 2, 3, 4)
	if got := sanitizeExtra(term); !bytes.Equal(got, good) {
		t.Errorf("终止标记之后的内容应被忽略: % x", got)
	}
}

// TestWriteRepairsMalformedLocalExtra 验证带残尾扩展字段的条目
// 经过重写后产出**结构合法**的扩展字段。
//
// 这是对真实样本的回归保护：样本中 resources.arsc 的本地扩展字段只有
// 1 个孤立的 0x00 字节，若原样保留再追加对齐记录，读方会把该字节当成
// 新记录的字段 ID，报「扩展字段损坏」而拒收整个 APK。
func TestWriteRepairsMalformedLocalExtra(t *testing.T) {
	e := NewStored("resources.arsc", []byte("arsc-data"))
	e.LocalExtra = []byte{0x00}

	a := &Archive{Entries: []*Entry{e}}
	out := Write(a, DefaultAlign())

	got, err := Read(out)
	if err != nil {
		t.Fatalf("重新解析失败: %v", err)
	}
	if len(got.Entries) != 1 {
		t.Fatalf("条目数不符: %d", len(got.Entries))
	}
	extra := got.Entries[0].LocalExtra
	// 逐条解析扩展字段，任何一条越界都说明结构非法。
	p := 0
	for p+4 <= len(extra) {
		id := binary.LittleEndian.Uint16(extra[p:])
		n := int(binary.LittleEndian.Uint16(extra[p+2:]))
		if id == 0 && n == 0 {
			break
		}
		if p+4+n > len(extra) {
			t.Fatalf("扩展字段结构非法：ID 0x%04x 声明长度 %d，剩余仅 %d 字节",
				id, n, len(extra)-p-4)
		}
		p += 4 + n
	}
	if !bytes.Equal(got.Entries[0].Raw, []byte("arsc-data")) {
		t.Error("条目数据在重写后发生了变化")
	}
}

// TestWriteSetsUTF8FlagForNonASCII 验证含非 ASCII 字节的条目名会带上
// UTF-8 标志（bit 11）。
//
// 缺这个标志时读方按 CP437 解码文件名，非 ASCII 名字会变成乱码；
// 参考样本中全部非 ASCII 条目都带该标志。
func TestWriteSetsUTF8FlagForNonASCII(t *testing.T) {
	cjk := NewStored("res/\u9ad8\u9ad8/ic.xml", []byte("x"))
	ascii := NewStored("res/plain/ic.xml", []byte("x"))
	a := &Archive{Entries: []*Entry{cjk, ascii}}
	out := Write(a, DefaultAlign())

	got, err := Read(out)
	if err != nil {
		t.Fatalf("重新解析失败: %v", err)
	}
	if got.Entries[0].Flags&0x0800 == 0 {
		t.Errorf("非 ASCII 条目名应置 UTF-8 标志，实际 flags=0x%04x", got.Entries[0].Flags)
	}
	if got.Entries[0].NameString() != cjk.NameString() {
		t.Errorf("条目名在往返后发生了变化: %q", got.Entries[0].NameString())
	}
	// 纯 ASCII 名不应被无端加上该标志（保持与输入一致）。
	if got.Entries[1].Flags&0x0800 != 0 {
		t.Errorf("纯 ASCII 条目名不应置 UTF-8 标志，实际 flags=0x%04x", got.Entries[1].Flags)
	}
}
