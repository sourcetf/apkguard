package dex

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// sampleDex 返回一个用于测试的真实 DEX 文件路径。
//
// 优先使用样本 APK 解出的 classes2.dex（classes.dex 是样本用于伪装的畸形文件）；
// 不存在时跳过测试。
func sampleDex(t *testing.T) []byte {
	t.Helper()
	candidates := []string{
		filepath.Join("..", "..", "..", "dex_tmp", "classes2.dex"),
		filepath.Join("..", "..", "..", "dex_tmp", "classes3.dex"),
	}
	for _, p := range candidates {
		if data, err := os.ReadFile(p); err == nil && len(data) > 0 {
			return data
		}
	}
	t.Skip("未找到测试用 DEX 文件，跳过")
	return nil
}

// TestParseHeader 验证 DEX 头部解析。
func TestParseHeader(t *testing.T) {
	data := sampleDex(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	t.Logf("字符串=%d 类型=%d 原型=%d 字段=%d 方法=%d 类=%d",
		f.NString, f.NType, f.NProto, f.NField, f.NMethod, f.NClass)
	if f.NString == 0 || f.NClass == 0 {
		t.Fatal("头部计数异常")
	}
}

// TestVerifyChecksum 验证样本 DEX 的校验和自洽。
func TestVerifyChecksum(t *testing.T) {
	data := sampleDex(t)
	if err := Verify(data); err != nil {
		t.Fatalf("校验失败: %v", err)
	}
}

// TestRebuildIdentity 验证「原样重建」不改变 DEX 语义。
//
// 这是重建引擎最关键的测试：若索引重排或引用修正有误，
// 重建后的文件将无法通过校验，或字符串/类数量发生变化。
func TestRebuildIdentity(t *testing.T) {
	data := sampleDex(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	out, err := Rebuild(f, RebuildOptions{})
	if err != nil {
		t.Fatalf("重建失败: %v", err)
	}

	// 1) 校验和必须自洽
	if err := Verify(out); err != nil {
		t.Fatalf("重建后校验失败: %v", err)
	}

	// 2) 重新解析，条目数量必须一致
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("重建结果无法解析: %v", err)
	}
	if g.NString != f.NString || g.NType != f.NType || g.NProto != f.NProto ||
		g.NField != f.NField || g.NMethod != f.NMethod || g.NClass != f.NClass {
		t.Fatalf("条目数量不一致: 原(%d,%d,%d,%d,%d,%d) 新(%d,%d,%d,%d,%d,%d)",
			f.NString, f.NType, f.NProto, f.NField, f.NMethod, f.NClass,
			g.NString, g.NType, g.NProto, g.NField, g.NMethod, g.NClass)
	}

	// 3) 全部字符串必须一一对应（DEX 要求字符串池有序，顺序应当保持不变）
	for i := uint32(0); i < f.NString; i++ {
		a, err := f.String(i)
		if err != nil {
			t.Fatalf("原字符串 %d 读取失败: %v", i, err)
		}
		b, err := g.String(i)
		if err != nil {
			t.Fatalf("新字符串 %d 读取失败: %v", i, err)
		}
		if a != b {
			t.Fatalf("字符串 %d 不一致: %q != %q", i, a, b)
		}
	}

	// 4) 全部类型描述符必须一致
	for i := uint32(0); i < f.NType; i++ {
		a, _ := f.Type(i)
		b, err := g.Type(i)
		if err != nil {
			t.Fatalf("新类型 %d 读取失败: %v", i, err)
		}
		if a != b {
			t.Fatalf("类型 %d 不一致: %q != %q", i, a, b)
		}
	}

	// 5) 全部类名必须一致
	for i := uint32(0); i < f.NClass; i++ {
		a, _ := f.ClassName(i)
		b, err := g.ClassName(i)
		if err != nil {
			t.Fatalf("新类 %d 读取失败: %v", i, err)
		}
		if a != b {
			t.Fatalf("类 %d 不一致: %q != %q", i, a, b)
		}
	}

	// 6) 全部方法签名必须一致
	for i := uint32(0); i < f.NMethod; i++ {
		a, _ := f.MethodDesc(i)
		b, err := g.MethodDesc(i)
		if err != nil {
			t.Fatalf("新方法 %d 读取失败: %v", i, err)
		}
		if a != b {
			t.Fatalf("方法 %d 不一致: %q != %q", i, a, b)
		}
	}
	t.Logf("往返一致：字符串=%d 类型=%d 方法=%d 类=%d，输出 %d 字节",
		g.NString, g.NType, g.NMethod, g.NClass, len(out))
}

// TestRebuildDropDebugInfo 验证移除调试信息后仍可正常解析。
func TestRebuildDropDebugInfo(t *testing.T) {
	data := sampleDex(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	out, err := Rebuild(f, RebuildOptions{DropDebugInfo: true})
	if err != nil {
		t.Fatalf("重建失败: %v", err)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("重建后校验失败: %v", err)
	}

	g, err := Parse(out)
	if err != nil {
		t.Fatalf("重建结果无法解析: %v", err)
	}
	// 移除调试信息后体积应减小或持平
	t.Logf("原 %d 字节 -> 去调试信息后 %d 字节", len(data), len(out))
	if len(out) > len(data) {
		t.Errorf("移除调试信息后体积反而增大: %d -> %d", len(data), len(out))
	}
	if g.NClass != f.NClass || g.NMethod != f.NMethod {
		t.Error("移除调试信息不应改变类与方法数量")
	}
}

// TestEncodeDecodeMUTF8 验证 MUTF-8 编解码往返。
func TestEncodeDecodeMUTF8(t *testing.T) {
	cases := []string{
		"hello",
		"",
		"中文测试",
		"emoji \U0001F600 test",
		"mixed 中文 and ascii",
		"a\x00b", // 内嵌 NUL，MUTF-8 用双字节表示
	}
	for _, s := range cases {
		enc := EncodeMUTF8(s)
		if enc[len(enc)-1] != 0 {
			t.Errorf("%q: 编码结果缺少结尾 0", s)
			continue
		}
		got, err := DecodeMUTF8(enc[:len(enc)-1])
		if err != nil {
			t.Errorf("%q: 解码失败 %v", s, err)
			continue
		}
		if got != s {
			t.Errorf("%q: 往返不一致，得到 %q", s, got)
		}
		if n := UTF16Len(s); n < 0 {
			t.Errorf("%q: UTF16Len 异常 %d", s, n)
		}
	}
}

// TestLEB128RoundTrip 验证 LEB128 编解码往返。
func TestLEB128RoundTrip(t *testing.T) {
	vals := []uint32{0, 1, 127, 128, 255, 16383, 16384, 0xffff, 0x10000, 0xffffffff}
	for _, v := range vals {
		enc := PutULEB128(nil, v)
		got, n, err := ULEB128(enc, 0)
		if err != nil {
			t.Errorf("ULEB128(%d) 解码失败: %v", v, err)
			continue
		}
		if got != v || n != len(enc) {
			t.Errorf("ULEB128(%d) 往返不一致: got=%d consumed=%d/%d", v, got, n, len(enc))
		}
	}

	svals := []int32{0, 1, -1, 63, -64, 64, -65, 8191, -8192, 0x7fffffff, -0x80000000}
	for _, v := range svals {
		enc := PutSLEB128(nil, v)
		got, n, err := SLEB128(enc, 0)
		if err != nil {
			t.Errorf("SLEB128(%d) 解码失败: %v", v, err)
			continue
		}
		if got != v || n != len(enc) {
			t.Errorf("SLEB128(%d) 往返不一致: got=%d consumed=%d/%d", v, got, n, len(enc))
		}
	}
}

// TestRebuildAddString 验证向字符串池追加新字符串后仍保持有序可解析。
func TestRebuildAddString(t *testing.T) {
	data := sampleDex(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	out, err := Rebuild(f, RebuildOptions{
		NewStrings: []string{"zz_apkguard_test_string"},
	})
	if err != nil {
		t.Fatalf("重建失败: %v", err)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("重建后校验失败: %v", err)
	}

	g, err := Parse(out)
	if err != nil {
		t.Fatalf("重建结果无法解析: %v", err)
	}
	if g.NString != f.NString+1 {
		t.Fatalf("字符串数量应为 %d，实际 %d", f.NString+1, g.NString)
	}
	// 字符串池必须保持 UTF-16 升序
	prev := ""
	for i := uint32(0); i < g.NString; i++ {
		s, _ := g.String(i)
		if i > 0 && CompareUTF16(prev, s) >= 0 {
			t.Fatalf("字符串池顺序错误 @%d: %q >= %q", i, prev, s)
		}
		prev = s
	}
	found := false
	for i := uint32(0); i < g.NString; i++ {
		s, _ := g.String(i)
		if s == "zz_apkguard_test_string" {
			found = true
			break
		}
	}
	if !found {
		t.Error("新字符串未出现在结果中")
	}

	// 原有类的名称必须保持不变
	for i := uint32(0); i < f.NClass; i++ {
		a, _ := f.ClassName(i)
		b, _ := g.ClassName(i)
		if a != b {
			t.Fatalf("类 %d 名称变化: %q -> %q", i, a, b)
		}
	}
}

// TestRebuildMethodBodiesIntact 验证重建后所有方法的字节码长度不变。
func TestRebuildMethodBodiesIntact(t *testing.T) {
	data := sampleDex(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	type sig struct {
		name string
		regs uint16
		size uint32
	}
	collect := func(x *File) map[string]sig {
		m := map[string]sig{}
		x.Classes(func(_ uint32, cd ClassDef, name string) error {
			if cd.ClassDataOff == 0 {
				return nil
			}
			pcd, err := x.ParseClassData(cd.ClassDataOff)
			if err != nil {
				return err
			}
			for _, lst := range [][]EncodedMethod{pcd.DirectMethods, pcd.VirtualMethods} {
				for _, mm := range lst {
					if mm.CodeOff == 0 {
						continue
					}
					desc, _ := x.MethodDesc(mm.Idx)
					ci, err := x.CodeInsns(mm.CodeOff)
					if err != nil {
						continue
					}
					m[desc] = sig{name: name, regs: ci.Registers, size: ci.InsnsSize}
				}
			}
			return nil
		})
		return m
	}

	before := collect(f)
	out, err := Rebuild(f, RebuildOptions{})
	if err != nil {
		t.Fatalf("重建失败: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("重建结果无法解析: %v", err)
	}
	after := collect(g)

	if len(before) != len(after) {
		t.Fatalf("方法数量变化: %d -> %d", len(before), len(after))
	}
	for k, v := range before {
		w, ok := after[k]
		if !ok {
			t.Fatalf("方法 %q 在重建后丢失", k)
		}
		if v.regs != w.regs || v.size != w.size {
			t.Fatalf("方法 %q 字节码变化: regs %d->%d size %d->%d",
				k, v.regs, w.regs, v.size, w.size)
		}
	}
	t.Logf("校验了 %d 个方法的字节码完整性", len(before))
}

// TestRebuildRename 验证重命名类名后 DEX 仍自洽，且引用关系正确跟随。
func TestRebuildRename(t *testing.T) {
	data := sampleDex(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	// 挑一个业务类（非 java/ 与 android/ 前缀），把它重命名为无意义短名
	target := ""
	for i := uint32(0); i < f.NClass; i++ {
		n, _ := f.ClassName(i)
		if len(n) > 2 && n[0] == 'L' && !strings.HasPrefix(n, "Ljava/") &&
			!strings.HasPrefix(n, "Landroid/") && !strings.HasPrefix(n, "Lkotlin/") {
			target = n
			break
		}
	}
	if target == "" {
		t.Skip("样本中没有可重命名的业务类")
	}
	// 目标名必须与既有字符串池中的任何字符串都不同，否则会与其它类型冲突
	renamed := "Lzq/zzq;"

	out, err := Rebuild(f, RebuildOptions{Rename: map[string]string{target: renamed}})
	if err != nil {
		t.Fatalf("重命名重建失败: %v", err)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("重建后校验失败: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("重建结果无法解析: %v", err)
	}

	// 类型总数不变（重命名不新增类型）
	if g.NType != f.NType {
		t.Fatalf("类型数量变化: %d -> %d", f.NType, g.NType)
	}
	// 旧名必须完全消失，新名必须存在
	sawNew := false
	for i := uint32(0); i < g.NType; i++ {
		n, _ := g.Type(i)
		if n == target {
			t.Fatalf("旧类型名 %q 仍然存在", target)
		}
		if n == renamed {
			sawNew = true
		}
	}
	if !sawNew {
		t.Fatalf("新类型名 %q 未出现", renamed)
	}
	// 类定义中原来指向 target 的那一项必须改为 renamed
	found := false
	for i := uint32(0); i < g.NClass; i++ {
		n, _ := g.ClassName(i)
		if n == renamed {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("类定义未跟随重命名")
	}
	// 类/方法/字段数量不变
	if g.NClass != f.NClass || g.NMethod != f.NMethod || g.NField != f.NField {
		t.Fatalf("索引表条目数变化: 类 %d->%d 方法 %d->%d 字段 %d->%d",
			f.NClass, g.NClass, f.NMethod, g.NMethod, f.NField, g.NField)
	}
	t.Logf("已把 %s 重命名为 %s", target, renamed)
}

// TestRebuildInjectClass 验证注入一个完整类（含方法体与字段）后 DEX 仍可解析。
func TestRebuildInjectClass(t *testing.T) {
	data := sampleDex(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	const cls = "Lapkguard/TestShell;"
	protoV := ProtoSpec{Ret: "V"}
	protoS := ProtoSpec{Ret: "Ljava/lang/String;"}
	objInit := MethodSpec{Class: "Ljava/lang/Object;", Name: "<init>", Proto: protoV}

	add := &Addition{
		Types: []string{cls, "Ljava/lang/Object;", "Ljava/lang/String;"},
		Protos: []ProtoSpec{
			protoV,
			protoS,
		},
		Methods: []MethodSpec{
			{Class: cls, Name: "<init>", Proto: protoV},
			{Class: cls, Name: "a", Proto: protoS},
			{Class: cls, Name: "b", Proto: protoV},
			objInit,
		},
		Fields: []FieldSpec{
			{Class: cls, Name: "x", Type: "Ljava/lang/String;"},
		},
		Classes: []ClassSpec{{
			Name:   cls,
			Super:  "Ljava/lang/Object;",
			Access: 0x0001, // public
			Fields: []ClassField{
				{Name: "x", Type: "Ljava/lang/String;", Access: 0x0002}, // private
			},
			Methods: []ClassMethod{
				// <init>: 调用 Object.<init>() 后返回
				{Name: "<init>", Proto: protoV, Access: 0x0001, Code: &CodeBlob{
					Registers: 1,
					Ins:       1,
					Outs:      1,
					Insns: []uint16{
						0x1070, 0x0000, // invoke-direct {v0}, method@0
						0x000e, // return-void
					},
					Patches: []InsnPatch{{At: 1, Ref: RefSpec{Kind: RefMethod, Method: objInit}}},
				}},
				// a(): 返回 null
				{Name: "a", Proto: protoS, Access: 0x0001, Code: &CodeBlob{
					Registers: 1,
					Insns:     []uint16{0x0012, 0x000e}, // const/4 v0, #0 ; return-object v0
				}},
				// b(): 空方法
				{Name: "b", Proto: protoV, Access: 0x0001, Code: &CodeBlob{
					Registers: 0,
					Insns:     []uint16{0x000e},
				}},
			},
		}},
	}

	out, err := Rebuild(f, RebuildOptions{Addition: add})
	if err != nil {
		t.Fatalf("注入重建失败: %v", err)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("重建后校验失败: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("重建结果无法解析: %v", err)
	}
	if g.NClass != f.NClass+1 {
		t.Fatalf("类数量应为 %d，实际 %d", f.NClass+1, g.NClass)
	}
	if g.NMethod != f.NMethod+3 {
		t.Fatalf("方法数量应为 %d，实际 %d", f.NMethod+3, g.NMethod)
	}
	if g.NField != f.NField+1 {
		t.Fatalf("字段数量应为 %d，实际 %d", f.NField+1, g.NField)
	}

	// 新类必须可被找到，且方法体可读出
	saw := false
	g.Classes(func(_ uint32, cd ClassDef, name string) error {
		if name != cls {
			return nil
		}
		saw = true
		pcd, err := g.ParseClassData(cd.ClassDataOff)
		if err != nil {
			t.Fatalf("新类 class_data 解析失败: %v", err)
		}
		if len(pcd.DirectMethods) != 1 || len(pcd.VirtualMethods) != 2 {
			t.Fatalf("新类方法分布异常: 直接 %d 虚 %d（<init> 应为直接方法，a/b 为虚方法）",
				len(pcd.DirectMethods), len(pcd.VirtualMethods))
		}
		for _, m := range append(append([]EncodedMethod{}, pcd.DirectMethods...), pcd.VirtualMethods...) {
			if m.CodeOff == 0 {
				continue
			}
			ci, err := g.CodeInsns(m.CodeOff)
			if err != nil {
				t.Fatalf("新类方法体读取失败: %v", err)
			}
			if ci.InsnsSize == 0 {
				t.Fatal("新类方法体为空")
			}
		}
		return nil
	})
	if !saw {
		t.Fatal("注入的类未出现在 class_defs 中")
	}
	t.Logf("已注入 %s：类 %d->%d 方法 %d->%d", cls, f.NClass, g.NClass, f.NMethod, g.NMethod)
}

// TestRebuildRenameKeepsPoolSorted 验证大量重命名后字符串池仍严格升序。
func TestRebuildRenameKeepsPoolSorted(t *testing.T) {
	data := sampleDex(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	orig, err := f.AllStrings()
	if err != nil {
		t.Fatalf("读取字符串失败: %v", err)
	}
	// 把所有业务类型描述符改写为各不相同的短名：既触发池顺序重排，
	// 又不会让两个类型塌缩成同一个描述符（DEX 要求类型唯一）。
	rename := map[string]string{}
	n := 0
	for _, s := range orig {
		if len(s) > 2 && s[0] == 'L' && s[len(s)-1] == ';' && !strings.HasPrefix(s, "Ljava/") {
			n++
			rename[s] = "Lzq/" + itoa(n) + ";"
		}
	}
	if len(rename) == 0 {
		t.Skip("没有可重命名的类型描述符")
	}
	out, err := Rebuild(f, RebuildOptions{Rename: rename})
	if err != nil {
		t.Fatalf("重命名重建失败: %v", err)
	}
	if err := Verify(out); err != nil {
		t.Fatalf("重建后校验失败: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("重建结果无法解析: %v", err)
	}
	if g.NType != f.NType {
		t.Fatalf("类型数量应不变: %d -> %d", f.NType, g.NType)
	}
	prev := ""
	for i := uint32(0); i < g.NString; i++ {
		s, _ := g.String(i)
		if i > 0 && CompareUTF16(prev, s) >= 0 {
			t.Fatalf("字符串池顺序错误 @%d: %q >= %q", i, prev, s)
		}
		prev = s
	}
	// 旧名必须全部消失
	gone := map[string]bool{}
	for k := range rename {
		gone[k] = true
	}
	for i := uint32(0); i < g.NType; i++ {
		s, _ := g.Type(i)
		if gone[s] {
			t.Fatalf("旧类型名 %q 仍然存在", s)
		}
	}
	t.Logf("重命名 %d 个描述符，字符串池 %d -> %d", len(rename), f.NString, g.NString)
}

// itoa 是 strconv.Itoa 的本地实现，避免为测试引入额外依赖。
func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

// canonCode 为一段 code_item 生成「语义规范化描述」。
//
// 它把每条指令的操作码、池引用（解析为实际文本）、分支落点（解析为绝对字偏移）
// 全部展开成文本。重建只允许重排索引表、不允许改变语义，因此
// 「原文件」与「重建结果」的规范化描述必须逐字相同。
//
// 这个不变量比「条目数量一致」强得多：像 fill-array-data 这类
// 把相对偏移误当池索引改写的错误，只有在这里才会暴露。
func canonCode(f *File, codeOff uint32) (string, error) {
	ci, err := f.ParseCodeItem(codeOff)
	if err != nil {
		return "", err
	}
	l, err := ParseInsns(ci.Insns)
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "regs=%d ins=%d outs=%d tries=%d;", ci.Registers, ci.Ins, ci.Outs, len(ci.Tries))

	for i := 0; i < l.ItemCount(); i++ {
		at := l.ItemOldOffset(i)
		if !l.ItemIsInsn(i) {
			fmt.Fprintf(&sb, " |%d:payload", at)
			continue
		}
		w := l.ItemWords(i)
		op := byte(w[0] & 0xff)
		fmt.Fprintf(&sb, " |%d:%02x", at, op)
		if ref, ok := insnRefs[op]; ok {
			var idx uint32
			if ref.wide {
				idx = uint32(w[ref.word]) | uint32(w[ref.word+1])<<16
			} else {
				idx = uint32(w[ref.word])
			}
			txt, err := refText(f, ref.kind, idx)
			if err != nil {
				return "", fmt.Errorf("@%d 指令 0x%02x 的引用: %w", at, op, err)
			}
			fmt.Fprintf(&sb, "(%s)", txt)
		}
		if pw, ok := protoRefInsns[op]; ok {
			txt, err := f.ProtoDesc(uint32(w[pw]))
			if err != nil {
				return "", err
			}
			fmt.Fprintf(&sb, "{%s}", txt)
		}
	}
	// 分支落点：按「所在项偏移 → 目标偏移」的稳定顺序输出
	type bt struct {
		from, to int
		form     branchForm
	}
	var bts []bt
	for _, b := range l.branches {
		bts = append(bts, bt{from: l.ItemOldOffset(b.item), to: b.target, form: b.form})
	}
	sort.Slice(bts, func(i, j int) bool {
		if bts[i].from != bts[j].from {
			return bts[i].from < bts[j].from
		}
		return bts[i].to < bts[j].to
	})
	for _, b := range bts {
		fmt.Fprintf(&sb, " <%d->%d/%d>", b.from, b.to, b.form)
	}
	// 异常表
	for _, t := range ci.Tries {
		fmt.Fprintf(&sb, " T[%d+%d]", t.StartAddr, t.InsnCount)
	}
	for _, h := range ci.Handlers {
		fmt.Fprintf(&sb, " H[")
		for i, ty := range h.Types {
			// 捕获类型必须解析为「名字」再比较，而不是打印原始索引：
			// 改名会重排 type_ids，索引变化属预期，打印数字会把
			// 「语义相同、只是编号变了」误判为语义变化。
			txt, err := refText(f, refType, ty)
			if err != nil {
				return "", fmt.Errorf("处理器捕获类型 %d: %w", ty, err)
			}
			fmt.Fprintf(&sb, "%s:%d,", txt, h.Addrs[i])
		}
		if h.CatchAll {
			fmt.Fprintf(&sb, "all:%d", h.AllAddr)
		}
		fmt.Fprintf(&sb, "]")
	}
	return sb.String(), nil
}

// refText 把某个池索引解析为可读文本，用于跨文件比较。
func refText(f *File, kind refKind, idx uint32) (string, error) {
	switch kind {
	case refString:
		return f.String(idx)
	case refType:
		return f.Type(idx)
	case refField:
		c, t, n, err := f.FieldRefAt(idx)
		if err != nil {
			return "", err
		}
		cn, err := f.Type(uint32(c))
		if err != nil {
			return "", err
		}
		tn, err := f.Type(uint32(t))
		if err != nil {
			return "", err
		}
		nn, err := f.String(n)
		if err != nil {
			return "", err
		}
		return cn + "->" + nn + ":" + tn, nil
	case refMethod:
		return f.MethodDesc(idx)
	case refProto:
		return f.ProtoDesc(idx)
	}
	return "", fmt.Errorf("未知引用类型 %d", kind)
}

// TestRebuildPreservesCodeSemantics 验证重建后全部方法体的语义完全不变。
//
// 这是重建引擎最强的正确性约束：任何「索引重映射写错位置」的问题
// （例如把 31t 的相对偏移当成池索引改写）都会在这里立刻暴露。
func TestRebuildPreservesCodeSemantics(t *testing.T) {
	data := sampleDex(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	out, err := Rebuild(f, RebuildOptions{})
	if err != nil {
		t.Fatalf("重建失败: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("重建结果无法解析: %v", err)
	}

	before := map[string]string{}
	err = f.walkAllCode(func(codeOff uint32) error {
		s, err := canonCode(f, codeOff)
		if err != nil {
			return fmt.Errorf("@%d: %w", codeOff, err)
		}
		before[fmt.Sprint(codeOff)] = s
		return nil
	})
	if err != nil {
		t.Fatalf("生成原文件语义描述失败: %v", err)
	}
	if len(before) == 0 {
		t.Skip("样本中没有方法体")
	}

	// 重建后 code_item 的偏移会变，因此按「遍历顺序」配对比较。
	var offs []uint32
	if err := f.walkAllCode(func(codeOff uint32) error {
		offs = append(offs, codeOff)
		return nil
	}); err != nil {
		t.Fatalf("收集 code_item 偏移失败: %v", err)
	}
	i := 0
	err = g.walkAllCode(func(codeOff uint32) error {
		want, ok := before[fmt.Sprint(offs[i])]
		if !ok {
			return fmt.Errorf("第 %d 个 code_item 缺少基线", i)
		}
		got, err := canonCode(g, codeOff)
		if err != nil {
			return err
		}
		if got != want {
			t.Fatalf("第 %d 个 code_item（原 @%d，新 @%d）语义变化：\n原: %s\n新: %s",
				i, offs[i], codeOff, want, got)
		}
		i++
		return nil
	})
	if err != nil {
		t.Fatalf("生成重建结果语义描述失败: %v", err)
	}
	if i != len(before) {
		t.Fatalf("方法体数量变化: %d -> %d", len(before), i)
	}
	t.Logf("逐条校验 %d 个方法体的指令语义（含池引用与分支落点）", i)
}

// TestFillArrayDataNotMistakenForTypeRef 回归测试：fill-array-data 是 31t 分支，
// 其 word1-2 是相对偏移，绝不能被当作类型索引改写。
func TestFillArrayDataNotMistakenForTypeRef(t *testing.T) {
	data := sampleDex(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if _, ok := insnRefs[0x26]; ok {
		t.Fatal("fill-array-data(0x26) 不应登记为池引用指令")
	}
	form, ok := insnBranchForm(0x26)
	if !ok || form != form31t {
		t.Fatalf("fill-array-data 应为 31t 分支，实际 form=%d ok=%v", form, ok)
	}

	// 全量扫描：确认样本中确实存在该指令，否则本测试无意义
	n := 0
	err = f.walkAllCode(func(codeOff uint32) error {
		ci, err := f.ParseCodeItem(codeOff)
		if err != nil {
			return err
		}
		return walkInsns(ci.Insns, func(op byte, pos int, w []uint16) error {
			if op == 0x26 {
				n++
				// 其落点必须是 payload 标识
				rel := int32(uint32(w[pos+1]) | uint32(w[pos+2])<<16)
				tgt := pos + int(rel)
				if tgt < 0 || tgt+1 > len(w) {
					return fmt.Errorf("@%d 的 fill-array-data 落点越界 %d", codeOff, tgt)
				}
				if w[tgt] != payloadFillArray {
					return fmt.Errorf("@%d 的 fill-array-data 落点 %d 不是 payload（0x%04x）",
						codeOff, tgt, w[tgt])
				}
			}
			return nil
		})
	})
	if err != nil {
		t.Fatalf("扫描失败: %v", err)
	}
	if n == 0 {
		t.Skip("样本中没有 fill-array-data 指令")
	}
	t.Logf("样本中存在 %d 条 fill-array-data 指令", n)
}

// TestRebuildRenamePreservesCodeSemantics 验证重命名后指令语义不变。
//
// 注意：重命名会改变 method_ids 的排序，从而改变 class_data 中方法的排列顺序
// （方法在 class_data 里是按索引升序存放的）。因此这里不能按遍历顺序配对，
// 必须按「方法身份」配对——用重命名后的描述符作为键。
func TestRebuildRenamePreservesCodeSemantics(t *testing.T) {
	data := sampleDex(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	rename := map[string]string{}
	for i := uint32(0); i < f.NClass; i++ {
		n, _ := f.ClassName(i)
		if strings.HasPrefix(n, "Ljava/") || strings.HasPrefix(n, "Landroid/") ||
			strings.HasPrefix(n, "Lkotlin/") {
			continue
		}
		rename[n] = n
	}
	if len(rename) == 0 {
		t.Skip("没有可重命名的类")
	}
	seq := 0
	for k := range rename {
		seq++
		rename[k] = "Lzq/" + itoa(seq) + ";"
	}
	out, err := Rebuild(f, RebuildOptions{Rename: rename})
	if err != nil {
		t.Fatalf("重建失败: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("重建结果无法解析: %v", err)
	}

	// 语义描述里把新旧类名统一替换为占位符，消除重命名带来的文本差异。
	normalize := func(s string) string {
		for old, nw := range rename {
			s = strings.ReplaceAll(s, old, "<R>")
			s = strings.ReplaceAll(s, nw, "<R>")
		}
		return s
	}

	// 按「方法身份」配对：类描述符 + 方法名 + 原型。
	// 这三者在重命名前后会同步改写，规范化后即为稳定键；
	// 用身份而非「遍历顺序」是因为 class_data 内方法按索引升序排列，
	// 重命名会改变索引从而改变顺序。
	collect := func(x *File) (map[string]string, error) {
		m := map[string]string{}
		err := x.Classes(func(_ uint32, cd ClassDef, cls string) error {
			if cd.ClassDataOff == 0 {
				return nil
			}
			pcd, err := x.ParseClassData(cd.ClassDataOff)
			if err != nil {
				return err
			}
			lst := append(append([]EncodedMethod{}, pcd.DirectMethods...), pcd.VirtualMethods...)
			for _, mm := range lst {
				if mm.CodeOff == 0 {
					continue
				}
				desc, err := x.MethodDesc(mm.Idx)
				if err != nil {
					return err
				}
				s, err := canonCode(x, mm.CodeOff)
				if err != nil {
					return fmt.Errorf("%s: %w", desc, err)
				}
				m[normalize(cls+"#"+desc)] = s
			}
			return nil
		})
		return m, err
	}
	before, err := collect(f)
	if err != nil {
		t.Fatalf("收集原语义失败: %v", err)
	}
	after, err := collect(g)
	if err != nil {
		t.Fatalf("收集新语义失败: %v", err)
	}
	if len(before) != len(after) {
		t.Fatalf("方法体数量变化: %d -> %d", len(before), len(after))
	}
	for k, want := range before {
		got, ok := after[k]
		if !ok {
			t.Fatalf("重命名后找不到等价方法体: %s", truncate(k, 200))
		}
		if normalize(got) != normalize(want) {
			t.Fatalf("重命名后方法体语义变化：\n原: %s\n新: %s", want, got)
		}
	}
	t.Logf("重命名 %d 个类后，%d 个方法体语义保持一致", len(rename), len(before))
}

// truncate 截断过长文本，便于输出可读的失败信息。
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// TestCodeBlobBytes 验证方法体编码格式符合 code_item 布局。
func TestCodeBlobBytes(t *testing.T) {
	pl := &plan{stringIdx: map[string]uint32{}, typeIdx: map[string]uint32{}, protoIdx: map[string]uint32{}, fieldIdx: map[string]uint32{}, methodIdx: map[string]uint32{}}
	c := &CodeBlob{Registers: 3, Ins: 2, Outs: 1, Insns: []uint16{0x000e, 0x0000}}
	b, err := c.Bytes(pl)
	if err != nil {
		t.Fatalf("编码失败: %v", err)
	}
	if len(b) != 16+4 {
		t.Fatalf("长度应为 20，实际 %d", len(b))
	}
	if got := binary.LittleEndian.Uint16(b[0:]); got != 3 {
		t.Errorf("registers = %d", got)
	}
	if got := binary.LittleEndian.Uint32(b[12:]); got != 2 {
		t.Errorf("insns_size = %d", got)
	}
	if got := binary.LittleEndian.Uint32(b[8:]); got != 0 {
		t.Errorf("debug_info_off 应为 0，实际 %d", got)
	}
	// 补丁越界必须报错
	bad := &CodeBlob{Insns: []uint16{0x000e}, Patches: []InsnPatch{{At: 9}}}
	if _, err := bad.Bytes(pl); err == nil {
		t.Error("越界补丁应返回错误")
	}
}
