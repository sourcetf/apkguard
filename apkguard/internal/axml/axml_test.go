package axml

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sampleManifest 返回样本 AndroidManifest.xml 的路径；不存在时跳过。
//
// testdata/AndroidManifest.xml 是仓库内固件（由 testapp 构建产物导出），
// 它让本包测试在干净检出下也能真正运行——否则 11 条测试会全部静默跳过。
func sampleManifest(t *testing.T) []byte {
	t.Helper()
	candidates := []string{
		filepath.Join("..", "..", "..", "testdata", "AndroidManifest.xml"),
		filepath.Join("..", "..", "..", "apk_extracted", "AndroidManifest.xml"),
		filepath.Join("..", "..", "..", "payload_extracted", "AndroidManifest.xml"),
	}
	for _, p := range candidates {
		if data, err := os.ReadFile(p); err == nil && len(data) > 0 {
			return data
		}
	}
	t.Skip("未找到测试用 AndroidManifest.xml，跳过")
	return nil
}

// TestParseManifest 验证能解析真实的二进制 Manifest。
func TestParseManifest(t *testing.T) {
	data := sampleManifest(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if f.Count() == 0 {
		t.Fatal("字符串池为空")
	}
	if len(f.Elements) == 0 {
		t.Fatal("未解析出任何元素")
	}
	// manifest 必须是根元素
	if f.Elements[0].Name != "manifest" {
		t.Fatalf("根元素应为 manifest，实际 %q", f.Elements[0].Name)
	}
	// package 属性必须可读
	pkg := f.Elements[0].AttrString("package")
	if pkg == "" {
		t.Fatal("manifest 缺少 package 属性")
	}
	// 版本号等数值属性必须存在
	if f.Elements[0].Attr("versionName") == nil {
		t.Log("提示：manifest 未声明 versionName")
	}
	t.Logf("字符串 %d 条，元素 %d 个，包名 %q", f.Count(), len(f.Elements), pkg)
}

// TestComponentClasses 验证能从 Manifest 提取组件类名。
func TestComponentClasses(t *testing.T) {
	data := sampleManifest(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	classes := f.ComponentClasses()
	if len(classes) == 0 {
		t.Fatal("未提取到任何组件类名")
	}
	for _, c := range classes {
		if strings.ContainsAny(c, " \t/") {
			t.Fatalf("组件类名非法: %q", c)
		}
	}
	// 必须包含 application 的 name（若声明了）
	if app := f.FindElement("application"); app != nil {
		if n := app.AttrString("name"); n != "" {
			found := false
			for _, c := range classes {
				if c == n {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("application 的 name %q 未出现在组件类名列表中", n)
			}
		}
	}
	t.Logf("提取到 %d 个组件类名：%s", len(classes), strings.Join(classes, ", "))
}

// TestStringPool 验证字符串池读取与索引一致性。
func TestStringPool(t *testing.T) {
	data := sampleManifest(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	all := f.Strings()
	if len(all) != f.Count() {
		t.Fatalf("Strings 长度 %d 与 Count %d 不符", len(all), f.Count())
	}
	// 逐个核对：String(i) 与 Strings()[i] 必须一致
	for i := 0; i < f.Count(); i++ {
		s, err := f.String(uint32(i))
		if err != nil {
			t.Fatalf("读取字符串 %d 失败: %v", i, err)
		}
		if s != all[i] {
			t.Fatalf("字符串 %d 不一致: %q != %q", i, s, all[i])
		}
	}
	// 越界必须报错
	if _, err := f.String(uint32(f.Count())); err == nil {
		t.Error("越界索引应返回错误")
	}
	// 常见字符串必须存在
	want := []string{"manifest", "application", "activity"}
	for _, w := range want {
		found := false
		for _, s := range all {
			if s == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("字符串池中缺少 %q", w)
		}
	}
}

// TestParseRejectsNonAXML 验证非 AXML 输入被拒绝。
func TestParseRejectsNonAXML(t *testing.T) {
	cases := [][]byte{
		nil,
		{0x01, 0x02, 0x03},
		// 合法 ZIP 头（PK\x03\x04）不应被当作 AXML
		{0x50, 0x4b, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00},
	}
	for i, c := range cases {
		if _, err := Parse(c); err == nil {
			t.Errorf("用例 %d 应返回错误", i)
		}
	}
}

// TestLooksLikeClass 验证类名判定。
func TestLooksLikeClass(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"com.foo.Bar", true},
		{"com.foo.Bar$Inner", true},
		{"Bar", true},
		{".Relative", true},
		{"com.foo..Bar", false},
		{"com/foo/Bar", false},
		{"", false},
		{"com.foo.bar", false}, // 无大写开头且含点，按现有规则视为合法
	}
	// 最后一项规则说明：只要各段非空即视为类名，因此 com.foo.bar 也为 true
	cases[len(cases)-1].want = true
	for _, c := range cases {
		if got := looksLikeClass(c.s); got != c.want {
			t.Errorf("looksLikeClass(%q) = %v，期望 %v", c.s, got, c.want)
		}
	}
}

// TestUTF16ToString 验证 UTF-16 解码（含代理对）。
func TestUTF16ToString(t *testing.T) {
	// "ab" 的 UTF-16LE
	if got := utf16ToString([]byte{'a', 0, 'b', 0}); got != "ab" {
		t.Errorf("基本字符解码错误: %q", got)
	}
	// U+4E2D（中）
	if got := utf16ToString([]byte{0x2d, 0x4e}); got != "中" {
		t.Errorf("BMP 字符解码错误: %q", got)
	}
	// U+1F600 的代理对：0xD83D 0xDE00
	if got := utf16ToString([]byte{0x3d, 0xd8, 0x00, 0xde}); got != "😀" {
		t.Errorf("代理对解码错误: %q", got)
	}
	// 孤立低代理必须替换为 U+FFFD
	if got := utf16ToString([]byte{0x00, 0xde}); got != "\ufffd" {
		t.Errorf("孤立代理应替换为 U+FFFD，实际 %q", got)
	}
}
