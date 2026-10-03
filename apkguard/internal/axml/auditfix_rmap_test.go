package axml

import (
	"testing"
)

// TestRewriteExtendsResourceMapForNewAttrs 断言注入的新属性名能拿到 android 资源 ID。
//
// 背景（这是一次真实的装机失败）：Android 解析属性名用的是**资源 ID**，而 AXML
// 里那张「字符串索引 → 资源 ID」的表（RES_XML_RESOURCE_MAP）只覆盖池的前若干条。
// 往 Manifest 里插 `<meta-data android:value="…">` 时，`value` 往往是新字符串、
// 落在表覆盖范围之外，框架就认不出 android:value，安装直接被拒：
//
//	INSTALL_PARSE_FAILED_MANIFEST_MALFORMED:
//	  <meta-data> requires an android:value or android:resource attribute
//
// 大应用不会暴露（它们的 Manifest 早已用过 value/required/enabled），
// 只有 Manifest 属性少的小应用会中招——testapp 正是这样发现了它。
func TestRewriteExtendsResourceMapForNewAttrs(t *testing.T) {
	f, err := Parse(sampleManifest(t))
	if err != nil {
		t.Fatalf("解析样本 Manifest 失败: %v", err)
	}
	// 前置条件：样本此时**没有** android:value 属性。否则本测试就没走到
	// 「新属性名需要补资源 ID」这条路径上，等于白测。
	before := f.origResourceIDs()
	if i := poolIndex(f, "value"); i >= 0 && i < len(before) {
		t.Skipf("样本 Manifest 已含 value（索引 %d，已在 resource map 内），本测试需要一份不含它的固件", i)
	}

	out, err := f.Rewrite(Edit{AddElements: []NewElement{{
		Parent:      "application",
		ParentIndex: 0,
		Name:        "meta-data",
		Attrs: []NewAttr{
			StringAttr(AndroidNS, "name", "com.example.probe"),
			StringAttr(AndroidNS, "value", "probe-value"),
			BoolAttr(AndroidNS, "enabled", true),
		},
	}}})
	if err != nil {
		t.Fatalf("改写失败: %v", err)
	}

	g, err := Parse(out)
	if err != nil {
		t.Fatalf("解析改写结果失败: %v", err)
	}
	ids := g.origResourceIDs()

	// 断言不变量：输出里每个「带 android 命名空间、且名字是已知框架属性」的
	// 属性，其字符串索引都必须在 resource map 内并映射到正确的资源 ID。
	checked := map[string]bool{}
	for _, el := range g.Elements {
		for _, a := range el.Attrs {
			if a.NS == noEntry {
				continue
			}
			want, known := androidAttrResID[a.Name]
			if !known {
				continue
			}
			checked[a.Name] = true
			if int(a.NameIdx) >= len(ids) {
				t.Errorf("属性 %s（索引 %d）超出 resource map 长度 %d：(<%s> 会被框架当成未知属性)",
					a.Name, a.NameIdx, len(ids), el.Name)
				continue
			}
			if got := ids[a.NameIdx]; got != want {
				t.Errorf("属性 %s 的资源 ID 不对：resource_map[%d]=0x%08x，期望 0x%08x",
					a.Name, a.NameIdx, got, want)
			}
		}
	}
	// 三个注入的属性都必须被检查到，否则断言可能一行都没跑。
	for _, n := range []string{"name", "value", "enabled"} {
		if !checked[n] {
			t.Errorf("未检查到注入属性 %s——断言没有真正生效", n)
		}
	}
}

// poolIndex 返回字符串在池中的索引；不存在返回 -1。
func poolIndex(f *File, s string) int {
	for i, v := range f.Strings() {
		if v == s {
			return i
		}
	}
	return -1
}
