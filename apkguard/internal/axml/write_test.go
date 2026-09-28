package axml

import (
	"encoding/binary"
	"strings"
	"testing"
)

// TestRewriteReplace 验证「只替换池中已有文本」的行为。
func TestRewriteReplace(t *testing.T) {
	data := sampleManifest(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	before := f.Strings()

	// 找一个「组件类名」作为替换目标，保证它确实被引用。
	classes := f.ComponentClasses()
	if len(classes) == 0 {
		t.Skip("样本 Manifest 没有组件类名，跳过")
	}
	target := classes[0]
	replacement := "com.example.shell.Holder"

	out, err := f.Rewrite(Edit{Replace: map[string]string{target: replacement}})
	if err != nil {
		t.Fatalf("Rewrite 失败: %v", err)
	}

	nf, err := Parse(out)
	if err != nil {
		t.Fatalf("改写结果无法重新解析: %v", err)
	}
	// 字符串数量必须不变（只改文本，不增删项）
	if nf.Count() != f.Count() {
		t.Fatalf("字符串数量变化: %d -> %d", f.Count(), nf.Count())
	}
	// 旧文本必须消失，新文本必须出现
	after := nf.Strings()
	for _, s := range after {
		if s == target {
			t.Fatalf("旧文本 %q 仍存在于池中", target)
		}
	}
	found := false
	for _, s := range after {
		if s == replacement {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("新文本 %q 未出现在池中", replacement)
	}
	// 其它文本必须逐项保持（索引顺序不变，故可直接按下标比对）
	if len(before) != len(after) {
		t.Fatalf("长度不一致 %d != %d", len(before), len(after))
	}
	for i := range before {
		if before[i] == target {
			if after[i] != replacement {
				t.Fatalf("索引 %d 应为 %q，实际 %q", i, replacement, after[i])
			}
			continue
		}
		if before[i] != after[i] {
			t.Fatalf("索引 %d 意外变化: %q -> %q", i, before[i], after[i])
		}
	}
}

// TestRewriteReplaceUpdatesReferences 验证引用（属性值）随文本一起变化。
func TestRewriteReplaceUpdatesReferences(t *testing.T) {
	data := sampleManifest(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	app := f.FindElement("application")
	if app == nil {
		t.Skip("样本 Manifest 无 <application>，跳过")
	}
	old := app.AttrString("name")
	if old == "" {
		t.Skip("样本 <application> 未声明 android:name，跳过")
	}
	replacement := "com.example.shell.Application"

	out, err := f.Rewrite(Edit{Replace: map[string]string{old: replacement}})
	if err != nil {
		t.Fatalf("Rewrite 失败: %v", err)
	}
	nf, err := Parse(out)
	if err != nil {
		t.Fatalf("改写结果无法重新解析: %v", err)
	}
	napp := nf.FindElement("application")
	if napp == nil {
		t.Fatal("改写后找不到 <application>")
	}
	if got := napp.AttrString("name"); got != replacement {
		t.Fatalf("application 的 name 应为 %q，实际 %q", replacement, got)
	}
	// 元素数量必须保持不变
	if len(nf.Elements) != len(f.Elements) {
		t.Fatalf("元素数量变化: %d -> %d", len(f.Elements), len(nf.Elements))
	}
}

// TestRewriteSetAttrExisting 验证对已存在的属性改值。
func TestRewriteSetAttrExisting(t *testing.T) {
	data := sampleManifest(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	app := f.FindElement("application")
	if app == nil {
		t.Skip("样本 Manifest 无 <application>，跳过")
	}
	if app.AttrString("name") == "" {
		t.Skip("样本 <application> 未声明 android:name，跳过")
	}
	value := "com.example.shell.Existing"

	out, err := f.Rewrite(Edit{SetAttr: []AttrValue{{
		Element: "application",
		NS:      AndroidNS,
		Name:    "name",
		Value:   value,
	}}})
	if err != nil {
		t.Fatalf("Rewrite 失败: %v", err)
	}
	nf, err := Parse(out)
	if err != nil {
		t.Fatalf("改写结果无法重新解析: %v", err)
	}
	napp := nf.FindElement("application")
	if napp == nil {
		t.Fatal("改写后找不到 <application>")
	}
	if got := napp.AttrString("name"); got != value {
		t.Fatalf("application 的 name 应为 %q，实际 %q", value, got)
	}
	// 属性数量不应变化
	if len(napp.Attrs) != len(app.Attrs) {
		t.Fatalf("属性数量变化: %d -> %d", len(app.Attrs), len(napp.Attrs))
	}
}

// TestRewriteSetAttrInsert 验证对不存在的属性执行插入。
func TestRewriteSetAttrInsert(t *testing.T) {
	data := sampleManifest(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	app := f.FindElement("application")
	if app == nil {
		t.Skip("样本 Manifest 无 <application>，跳过")
	}
	before := len(app.Attrs)
	value := "com.example.shell.Inserted"

	out, err := f.Rewrite(Edit{SetAttr: []AttrValue{{
		Element: "application",
		NS:      AndroidNS,
		Name:    "zygoteName", // 刻意使用一个几乎不可能已存在的属性名
		Value:   value,
	}}})
	if err != nil {
		t.Fatalf("Rewrite 失败: %v", err)
	}
	nf, err := Parse(out)
	if err != nil {
		t.Fatalf("改写结果无法重新解析: %v", err)
	}
	napp := nf.FindElement("application")
	if napp == nil {
		t.Fatal("改写后找不到 <application>")
	}
	if len(napp.Attrs) != before+1 {
		t.Fatalf("属性数量应为 %d，实际 %d", before+1, len(napp.Attrs))
	}
	a := napp.AttrNS(AndroidNS, "zygoteName")
	if a == nil {
		t.Fatal("未找到新插入的属性")
	}
	if a.RawValue != value {
		t.Fatalf("新属性值应为 %q，实际 %q", value, a.RawValue)
	}
	if a.DataType != TypeString {
		t.Fatalf("新属性类型应为 string(0x03)，实际 0x%02x", a.DataType)
	}
	// 其它元素必须完好
	if len(nf.Elements) != len(f.Elements) {
		t.Fatalf("元素数量变化: %d -> %d", len(f.Elements), len(nf.Elements))
	}
}

// TestRewriteNoop 验证空改写原样返回。
func TestRewriteNoop(t *testing.T) {
	data := sampleManifest(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	out, err := f.Rewrite(Edit{})
	if err != nil {
		t.Fatalf("Rewrite 失败: %v", err)
	}
	if len(out) != len(data) {
		t.Fatalf("空改写应原样返回，长度 %d != %d", len(out), len(data))
	}
	for i := range out {
		if out[i] != data[i] {
			t.Fatalf("空改写在第 %d 字节发生变化", i)
		}
	}
}

// TestRewriteMissingElement 验证找不到元素时报错而非静默成功。
func TestRewriteMissingElement(t *testing.T) {
	data := sampleManifest(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	_, err = f.Rewrite(Edit{SetAttr: []AttrValue{{
		Element: "definitely-not-an-element",
		Name:    "name",
		Value:   "x",
	}}})
	if err == nil {
		t.Fatal("目标元素不存在时应返回错误")
	}
	if !strings.Contains(err.Error(), "找不到元素") {
		t.Fatalf("错误信息应说明找不到元素，实际 %v", err)
	}
}

// TestRewriteAllComponents 验证把全部组件类名一次性改写后仍可解析，
// 且旧类名全部消失。这是 B2/A5 的真实使用形态。
func TestRewriteAllComponents(t *testing.T) {
	data := sampleManifest(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	classes := f.ComponentClasses()
	if len(classes) == 0 {
		t.Skip("样本 Manifest 没有组件类名，跳过")
	}
	rep := make(map[string]string, len(classes))
	for i, c := range classes {
		rep[c] = "com.example.shell.C" + itoa(i)
	}
	out, err := f.Rewrite(Edit{Replace: rep})
	if err != nil {
		t.Fatalf("Rewrite 失败: %v", err)
	}
	nf, err := Parse(out)
	if err != nil {
		t.Fatalf("改写结果无法重新解析: %v", err)
	}
	if nf.Count() != f.Count() {
		t.Fatalf("字符串数量变化: %d -> %d", f.Count(), nf.Count())
	}
	// 所有被替换的旧类名都必须消失
	after := nf.Strings()
	set := map[string]bool{}
	for _, s := range after {
		set[s] = true
	}
	for _, c := range classes {
		if set[c] {
			t.Fatalf("旧类名 %q 仍存在", c)
		}
	}
	// 元素数量不变
	if len(nf.Elements) != len(f.Elements) {
		t.Fatalf("元素数量变化: %d -> %d", len(f.Elements), len(nf.Elements))
	}
}

// TestEncodeStringPoolRoundTrip 验证字符串池编码后能被解析器正确读回。
func TestEncodeStringPoolRoundTrip(t *testing.T) {
	for _, utf8Pool := range []bool{false, true} {
		strs := []string{"", "a", "manifest", "com.example.Foo", "中文测试", "emoji😀", strings.Repeat("x", 200)}
		blob := encodeStringPool(strs, utf8Pool)
		if len(blob)%4 != 0 {
			t.Errorf("utf8=%v: 池长度 %d 未 4 字节对齐", utf8Pool, len(blob))
		}
		// 拼一个最小的 AXML 容器以便复用解析器
		wrapped := wrapPool(blob)
		f, err := Parse(wrapped)
		if err != nil {
			t.Fatalf("utf8=%v: 解析失败: %v", utf8Pool, err)
		}
		if f.Count() != len(strs) {
			t.Fatalf("utf8=%v: 数量 %d != %d", utf8Pool, f.Count(), len(strs))
		}
		for i, want := range strs {
			got, err := f.String(uint32(i))
			if err != nil {
				t.Fatalf("utf8=%v: 读取 %d 失败: %v", utf8Pool, i, err)
			}
			if got != want {
				t.Errorf("utf8=%v: 字符串 %d = %q，期望 %q", utf8Pool, i, got, want)
			}
		}
	}
}

// TestIsSortedUTF16 验证有序判定。
func TestIsSortedUTF16(t *testing.T) {
	cases := []struct {
		strs []string
		want bool
	}{
		{[]string{"a", "b", "c"}, true},
		{[]string{"a", "a"}, false},  // 必须严格递增
		{[]string{"b", "a"}, false},  // 逆序
		{[]string{"A", "a"}, true},   // 'A'(0x41) < 'a'(0x61)
		{[]string{"a", "ab"}, true},  // 前缀更短者在前
		{[]string{"ab", "a"}, false}, // 前缀更长者在后
		{[]string{""}, true},
		{nil, true},
	}
	for i, c := range cases {
		if got := isSortedUTF16(c.strs); got != c.want {
			t.Errorf("用例 %d: isSortedUTF16(%v) = %v，期望 %v", i, c.strs, got, c.want)
		}
	}
}

// TestRewriteClearsSortedFlagWhenUnordered 验证打乱顺序后 SORTED 标志被清除。
func TestRewriteClearsSortedFlagWhenUnordered(t *testing.T) {
	data := sampleManifest(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	// 追加一个排序后必然「不在正确位置」的新字符串（属性插入会 intern 新文本）
	out, err := f.Rewrite(Edit{SetAttr: []AttrValue{{
		Element: "manifest",
		Name:    "zzzGuardTest",
		Value:   "aaaaaaaaaa",
	}}})
	if err != nil {
		t.Fatalf("Rewrite 失败: %v", err)
	}
	nf, err := Parse(out)
	if err != nil {
		t.Fatalf("改写结果无法重新解析: %v", err)
	}
	flags := binaryFlags(out, nf.poolStart)
	// SORTED 标志必须与实际有序性一致，否则系统二分查找会返回错误结果。
	got := flags&flagSorted != 0
	want := isSortedUTF16(nf.Strings())
	if got != want {
		t.Fatalf("SORTED 标志 %v 与实际有序性 %v 不一致", got, want)
	}
}

// itoa 是 strconv.Itoa 的极简替身，避免为测试引入额外 import。
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	p := len(buf)
	for i > 0 {
		p--
		buf[p] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[p:])
}

// wrapPool 把字符串池块包进一个最小的 AXML 根块，便于复用解析器做回环校验。
func wrapPool(pool []byte) []byte {
	out := make([]byte, 8+len(pool))
	binary.LittleEndian.PutUint16(out[0:], TypeXML)
	binary.LittleEndian.PutUint16(out[2:], 8)
	binary.LittleEndian.PutUint32(out[4:], uint32(len(out)))
	copy(out[8:], pool)
	return out
}

// binaryFlags 读取字符串池块的 flags 字段。
func binaryFlags(data []byte, poolStart int) uint32 {
	if poolStart+20 > len(data) {
		return 0
	}
	return binary.LittleEndian.Uint32(data[poolStart+16:])
}
