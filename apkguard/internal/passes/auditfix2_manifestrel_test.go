package passes

import (
	"strings"
	"testing"

	"apkguard/internal/zipx"
)

// manifestWithRelativeComponents 构造一份「组件名写成相对名」的 Manifest：
//
//	package="com.demo"
//	<application android:name=".DemoApp">
//	  <activity android:name=".MainActivity"/>
//	  <activity-alias android:name=".Alias" android:targetActivity=".AliasTarget"/>
//	  <service android:name="com.demo.FullyQualifiedService"/>
//
// Android 允许组件名以 "." 开头（相对 package）、甚至完全不带点（也是相对），
// 运行时由 PackageParser.buildClassName 补全。A1 的保留集必须做同样的归一化。
func manifestWithRelativeComponents() []byte {
	root := &mfNode{
		name: "manifest",
		attrs: []mfAttr{
			mfString("", "package", "com.demo"),
		},
		kids: []*mfNode{
			{
				name: "application",
				attrs: []mfAttr{
					mfString("android", "name", ".DemoApp"),
				},
				kids: []*mfNode{
					{
						name:  "activity",
						attrs: []mfAttr{mfString("android", "name", ".MainActivity")},
					},
					{
						name: "activity-alias",
						attrs: []mfAttr{
							mfString("android", "name", ".Alias"),
							mfString("android", "targetActivity", ".AliasTarget"),
						},
					},
					{
						name:  "service",
						attrs: []mfAttr{mfString("android", "name", "com.demo.FullyQualifiedService")},
					},
				},
			},
		},
	}
	return encodeMF(root)
}

// TestManifestComponentsResolvesRelativeNames 回归审计发现：manifestComponents
// 把 Manifest 里的组件名**原样**返回，而 dex 层用
// `"L" + ReplaceAll(n, ".", "/") + ";"` 转描述符。相对名 ".MainActivity" 于是
// 被转成 "L/MainActivity;"，与真实描述符 "Lcom/demo/MainActivity;" 不相等，
// 组件类进不了保留集 → A1 会把它改名 → 启动即 ClassNotFoundException。
//
// 本测试要求：以 "." 开头的相对名先拼上 manifest 的 package；绝对名原样；
// activity-alias 的 android:targetActivity（同样是组件类名，此前完全没被保护）
// 也必须收进保留集。
func TestManifestComponentsResolvesRelativeNames(t *testing.T) {
	art := newArtifact(
		zipx.NewStored("AndroidManifest.xml", manifestWithRelativeComponents()),
	)
	got := manifestComponents(art)
	set := map[string]bool{}
	for _, c := range got {
		set[c] = true
	}

	want := []string{
		"com.demo.DemoApp",
		"com.demo.MainActivity",
		"com.demo.AliasTarget",
		"com.demo.FullyQualifiedService",
	}
	for _, w := range want {
		if !set[w] {
			t.Errorf("保留集缺少 %q（相对名未按 package 归一化，或 targetActivity 未收集）\n实际: %v", w, got)
		}
	}

	// 归一化后的名字必须能直接转成真实类描述符（这是 dex 层消费它的方式）。
	desc := func(java string) string {
		return "L" + strings.ReplaceAll(java, ".", "/") + ";"
	}
	if !set["com.demo.MainActivity"] || desc("com.demo.MainActivity") != "Lcom/demo/MainActivity;" {
		t.Errorf("com.demo.MainActivity 未出现在保留集中，组件类会被 A1 改名: %v", got)
	}

	// 不得再把未归一化的相对名交给保留集：".MainActivity" → "L/MainActivity;"，
	// 永远匹配不上任何真实类，等于没保留。
	for _, bad := range []string{".MainActivity", "MainActivity", ".DemoApp", ".AliasTarget"} {
		if set[bad] {
			t.Errorf("保留集不应包含未归一化的名字 %q: %v", bad, got)
		}
	}
}

// TestResolveComponentNameSemantics 钉住名字归一化的三种形态（与 AOSP
// PackageParser.buildClassName 一致）：带点前缀、不带点的相对名、绝对名；
// 以及 manifest 无 package 时相对名无法补全（丢弃而不是产出错误名字）。
func TestResolveComponentNameSemantics(t *testing.T) {
	cases := []struct {
		pkg, in, want string
	}{
		{"com.demo", ".MainActivity", "com.demo.MainActivity"},
		{"com.demo", "MainActivity", "com.demo.MainActivity"},
		{"com.demo", "com.other.Abs", "com.other.Abs"},
		{"com.demo", ".a.b.C", "com.demo.a.b.C"},
		{"", ".MainActivity", ""}, // 无 package：相对名补全不了，必须丢弃
		{"", "MainActivity", ""},
		{"", "com.other.Abs", "com.other.Abs"},
	}
	for _, c := range cases {
		if got := resolveComponentName(c.pkg, c.in); got != c.want {
			t.Errorf("resolveComponentName(%q, %q) = %q，应为 %q", c.pkg, c.in, got, c.want)
		}
	}
}
