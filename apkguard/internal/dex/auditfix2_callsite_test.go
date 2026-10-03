package dex

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// 本文件收口 auditfix2 的第 3 条缺陷：call_site_ids（0x0007）与
// method_handles（0x0008）段在重建时被丢弃。
//
// dataSectionOrder 只列了 10 个段，不含这两段；map_list 也不登记它们。
// 而 0xfa-0xfe（invoke-polymorphic/invoke-custom/const-method-handle）的
// 索引正指向这两段：任何含 invoke-custom / const-method-handle 的输入 DEX
// 经任一改写（A2/A3/A4/A6…）重建后，段消失、指令索引悬空，
// ART 结构校验必然拒绝加载。
//
// 修复策略不是「保留」（正确保留需要一并重排这两段的索引，工作量大且难以
// 验证），而是按项目原则「宁可失败也不静默产出坏文件」显式拒绝。

// audit2InjectMapSection 在 DEX 末尾追加一个指定类型的空段，并在 map_list
// 里登记它（count 非 0），用于构造本工具尚未支持的输入。
func audit2InjectMapSection(t *testing.T, data []byte, typ uint16, count uint32) []byte {
	t.Helper()
	if _, err := Parse(data); err != nil {
		t.Fatalf("注入前 DEX 无法解析: %v", err)
	}
	mapOff := binary.LittleEndian.Uint32(data[offMapList:])
	if int(mapOff)+4 > len(data) {
		t.Fatalf("map_list 偏移越界 %d", mapOff)
	}
	n := binary.LittleEndian.Uint32(data[mapOff:])
	if int(mapOff)+4+int(n)*12 > len(data) {
		t.Fatalf("map_list 内容越界（%d 项 @%d）", n, mapOff)
	}

	out := append([]byte(nil), data...)
	for len(out)%4 != 0 {
		out = append(out, 0)
	}
	secOff := uint32(len(out))
	out = append(out, make([]byte, 4*count)...)

	nm := make([]byte, 4+12*(int(n)+1))
	copy(nm, data[mapOff:int(mapOff)+4+12*int(n)])
	binary.LittleEndian.PutUint32(nm, n+1) // 条目数 +1，否则新段不会被登记
	base := 4 + 12*int(n)
	binary.LittleEndian.PutUint16(nm[base:], typ)
	binary.LittleEndian.PutUint32(nm[base+4:], count)
	binary.LittleEndian.PutUint32(nm[base+8:], secOff)

	newMapOff := uint32(len(out))
	out = append(out, nm...)
	binary.LittleEndian.PutUint32(out[offMapList:], newMapOff)
	binary.LittleEndian.PutUint32(out[offFileSize:], uint32(len(out)))
	return Finalize(out)
}

// audit2SmallDex 构造一个含类/方法/字段的普通 DEX，供重建测试使用。
func audit2SmallDex(t *testing.T) []byte {
	t.Helper()
	body := audit2StaticMethod(t)
	d, err := Build(Addition{Classes: []ClassSpec{
		{
			Name:   "Lapp2/A;",
			Super:  "Ljava/lang/Object;",
			Access: accPublic,
			Fields: []ClassField{{Name: "n", Type: "I", Access: accPublic}},
			Methods: []ClassMethod{
				{Name: "m", Proto: ProtoSpec{Ret: "V"}, Access: accPublic | accStatic, Code: body},
			},
		},
		{
			Name:   "Lapp2/B;",
			Super:  "Lapp2/A;",
			Access: accPublic,
			Methods: []ClassMethod{
				{Name: "m", Proto: ProtoSpec{Ret: "V"}, Access: accPublic | accStatic, Code: body},
			},
		},
	}})
	if err != nil {
		t.Fatalf("构造测试 DEX 失败: %v", err)
	}
	return d
}

// TestAuditFix2RebuildRejectsUnsupportedSections 断言：含 call_site_ids /
// method_handles 段（非空 count）的输入必须被显式拒绝，且错误信息点明原因。
func TestAuditFix2RebuildRejectsUnsupportedSections(t *testing.T) {
	cases := []struct {
		name    string
		section uint16
		want    string
	}{
		{"call_site_ids", 0x0007, "call_site_ids"},
		{"method_handles", 0x0008, "method_handles"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := audit2InjectMapSection(t, audit2SmallDex(t), c.section, 1)
			f, err := Parse(d)
			if err != nil {
				t.Fatalf("解析注入后的 DEX 失败: %v", err)
			}
			out, err := Rebuild(f, RebuildOptions{})
			if err == nil {
				t.Fatalf("含 %s 段的 DEX 被静默重建（%d 字节产物）——段被丢弃、"+
					"指令索引悬空，ART 必然拒绝加载", c.name, len(out))
			}
			if !errors.Is(err, ErrUnsupportedCallSite) {
				t.Errorf("错误类型不符: %v（应可用 errors.Is 命中 ErrUnsupportedCallSite）", err)
			}
			if got := err.Error(); !containsAll(got, c.want, "invoke-custom") {
				t.Errorf("错误信息未点明原因（应含 %q 与 invoke-custom）: %s", c.want, got)
			}
		})
	}
}

// TestAuditFix2RebuildRejectsInvokeCustomInsn 断言：即使 map_list 里没有这两段
// （畸形或手工构造的输入），只要指令流里出现 0xfa-0xfe 也必须拒绝。
func TestAuditFix2RebuildRejectsInvokeCustomInsn(t *testing.T) {
	// 先构造一个 4 字方法体（nop;nop;nop;return-void），再把首字改成
	// invoke-custom（0xfc，35c 格式，3 字），使指令流里出现 0xfc。
	a := NewAsm()
	a.emit(0x0000)
	a.emit(0x0000)
	a.emit(0x0000)
	a.ReturnVoid()
	insns, patches, err := a.Assemble()
	if err != nil {
		t.Fatalf("汇编失败: %v", err)
	}
	d, err := Build(Addition{Classes: []ClassSpec{{
		Name:   "Lapp2/C;",
		Super:  "Ljava/lang/Object;",
		Access: accPublic,
		Methods: []ClassMethod{{
			Name: "run", Proto: ProtoSpec{Ret: "V"}, Access: accPublic | accStatic,
			Code: &CodeBlob{Registers: 0, Ins: 0, Outs: 0, Insns: insns, Patches: patches},
		}},
	}}})
	if err != nil {
		t.Fatalf("构造测试 DEX 失败: %v", err)
	}
	f, err := Parse(d)
	if err != nil {
		t.Fatalf("解析测试 DEX 失败: %v", err)
	}
	_, codeOff := findMethod(t, f, "Lapp2/C;", "->run(")
	patched := append([]byte(nil), d...)
	binary.LittleEndian.PutUint16(patched[codeOff+16:], 0x00fc) // invoke-custom v0..
	patched = Finalize(patched)

	g, err := Parse(patched)
	if err != nil {
		t.Fatalf("解析补丁后的 DEX 失败: %v", err)
	}
	out, err := Rebuild(g, RebuildOptions{})
	if err == nil {
		t.Fatalf("含 invoke-custom(0xfc) 指令的 DEX 被静默重建（%d 字节产物）", len(out))
	}
	if !errors.Is(err, ErrUnsupportedCallSite) {
		t.Errorf("错误类型不符: %v", err)
	}
	if got := err.Error(); !containsAll(got, "invoke-custom") {
		t.Errorf("错误信息未点明是指令而非段: %s", got)
	}
}

// TestAuditFix2RebuildAcceptsPlainDex 防守卫误伤：不含这两段/指令的普通 DEX
// 必须照常重建成功。
func TestAuditFix2RebuildAcceptsPlainDex(t *testing.T) {
	f, err := Parse(audit2SmallDex(t))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	out, err := Rebuild(f, RebuildOptions{})
	if err != nil {
		t.Fatalf("普通 DEX 被守卫误伤: %v", err)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("产物自校验失败: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("产物无法解析: %v", err)
	}
	if err := ValidateDescriptors(out); err != nil {
		t.Fatalf("产物描述符非法: %v", err)
	}
	if g.NClass != 2 {
		t.Fatalf("产物类数不符: %d", g.NClass)
	}
}

// containsAll 判断 s 是否包含全部子串。
func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}
