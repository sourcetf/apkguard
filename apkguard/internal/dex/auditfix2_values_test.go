package dex

import (
	"encoding/binary"
	"testing"
)

// 本文件覆盖 auditfix2 的第 5 条（体积优化）：static_values 共享被放大。
//
// 真实 DEX 里多个类经常共享同一个 encoded_array_item（典型是「静态值全是
// 默认值」的类，dx/d8 让它们的 class_def.static_values_off 指向同一项）。
// 原实现对每个 valuesOff != 0 的类各 place 一份，共享被逐类复制
// （termux 实测 +27 KB）。修复后按拼装内容去重。
//
// 没有可用的真实样本（testdata 为空），这里手工构造：先用 Build 造三个含
// 静态字段的类，再在文件末尾追加两个 encoded_array_item，让 A/B 的
// class_def.static_values_off 指向同一项、C 指向另一项，最后重建并检查
// 产物里 encoded_array_item 的条目数。

// audit2ClassDefOff 返回指定类名在 class_defs 中的字节偏移。
func audit2ClassDefOff(t *testing.T, f *File, desc string) int {
	t.Helper()
	for i := uint32(0); i < f.NClass; i++ {
		name, err := f.ClassName(i)
		if err != nil {
			t.Fatalf("读取类名失败: %v", err)
		}
		if name == desc {
			return int(f.OffClass) + int(i)*32
		}
	}
	t.Fatalf("找不到类 %s", desc)
	return 0
}

// audit2DexWithSharedStaticValues 构造含共享 static_values 的 DEX。
//
// 返回的 DEX 中 A/B 指向值为 7 的同一数组，C 指向值为 9 的数组。
func audit2DexWithSharedStaticValues(t *testing.T) []byte {
	t.Helper()
	body := audit2StaticMethod(t)
	mkClass := func(name string) ClassSpec {
		return ClassSpec{
			Name:   name,
			Super:  "Ljava/lang/Object;",
			Access: accPublic,
			Fields: []ClassField{{Name: "n", Type: "I", Access: accPublic | accStatic}},
			Methods: []ClassMethod{
				{Name: "m", Proto: ProtoSpec{Ret: "V"}, Access: accPublic | accStatic, Code: body},
			},
		}
	}
	d, err := Build(Addition{Classes: []ClassSpec{
		mkClass("Lapp2/SA;"), mkClass("Lapp2/SB;"), mkClass("Lapp2/SC;"),
	}})
	if err != nil {
		t.Fatalf("构造测试 DEX 失败: %v", err)
	}
	f, err := Parse(d)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	out := append([]byte(nil), d...)
	for len(out)%4 != 0 {
		out = append(out, 0)
	}
	// 两个 encoded_array_item：size=1，值分别是 int 7 与 int 9。
	// encoded_value 头字节 = (size-1)<<5 | VALUE_INT(0x04)。
	off7 := uint32(len(out))
	out = append(out, 0x01, 0x04, 0x07)
	out = append(out, 0, 0) // 4 字节对齐填充，便于第二个数组有独立偏移
	out = append(out, 0, 0)
	off9 := uint32(len(out))
	out = append(out, 0x01, 0x04, 0x09)

	for _, e := range []struct {
		desc string
		off  uint32
	}{
		{"Lapp2/SA;", off7}, {"Lapp2/SB;", off7}, {"Lapp2/SC;", off9},
	} {
		cd := audit2ClassDefOff(t, f, e.desc)
		binary.LittleEndian.PutUint32(out[cd+28:], e.off)
	}
	return Finalize(out)
}

// audit2SectionCount 返回产物 map_list 中某类型段的条目数（不存在返回 0）。
func audit2SectionCount(t *testing.T, data []byte, typ uint16) uint32 {
	t.Helper()
	mapOff := binary.LittleEndian.Uint32(data[offMapList:])
	if int(mapOff)+4 > len(data) {
		t.Fatalf("map_list 越界")
	}
	n := binary.LittleEndian.Uint32(data[mapOff:])
	for i := uint32(0); i < n; i++ {
		base := int(mapOff) + 4 + 12*int(i)
		if binary.LittleEndian.Uint16(data[base:]) == typ {
			return binary.LittleEndian.Uint32(data[base+4:])
		}
	}
	return 0
}

// TestAuditFix2StaticValuesShared 钉住「共享的 encoded_array 只落一份」。
func TestAuditFix2StaticValuesShared(t *testing.T) {
	f, err := Parse(audit2DexWithSharedStaticValues(t))
	if err != nil {
		t.Fatalf("解析手工构造的 DEX 失败: %v", err)
	}
	out, err := Rebuild(f, RebuildOptions{})
	if err != nil {
		t.Fatalf("重建失败: %v", err)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("产物自校验失败: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("产物无法解析: %v", err)
	}
	// 产物里的 static_values 必须仍与静态字段类型/数量对齐
	//（checkStaticValues 内部失败时用 t.Errorf 报告）。
	checkStaticValues(t, "auditfix2-共享静态值", g)

	// A/B 必须指向同一项，C 指向另一项。
	offA := binary.LittleEndian.Uint32(out[audit2ClassDefOff(t, g, "Lapp2/SA;")+28:])
	offB := binary.LittleEndian.Uint32(out[audit2ClassDefOff(t, g, "Lapp2/SB;")+28:])
	offC := binary.LittleEndian.Uint32(out[audit2ClassDefOff(t, g, "Lapp2/SC;")+28:])
	if offA == 0 || offB == 0 || offC == 0 {
		t.Fatalf("static_values 偏移被清空: A=%d B=%d C=%d", offA, offB, offC)
	}
	if offA != offB {
		t.Errorf("共享同一 encoded_array 的 A/B 在产物里被拆成了两份: A=%d B=%d", offA, offB)
	}
	if offA == offC {
		t.Errorf("内容不同的 static_values 被错误合并: A=%d C=%d", offA, offC)
	}
	if n := audit2SectionCount(t, out, 0x2005); n != 2 {
		t.Errorf("encoded_array_item 应为 2 项（7 共享一份 + 9 一份），实际 %d——"+
			"共享的 static_values 被逐类复制（termux 实测 +27 KB）", n)
	}
}
