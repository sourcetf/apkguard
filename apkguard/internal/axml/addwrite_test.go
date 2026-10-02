package axml

import (
	"strings"
	"testing"
)

// TestRewriteAddElement 验证「在指定父元素末尾插入新元素」。
//
// 用途是 A8 把诱饵类声明成 Manifest 组件，因此断言重点在于：
//   - 新元素确实与声明的一一对应（名字 + 属性值）；
//   - 原有元素与组件类名一个都不少（插入绝不能破坏既有结构）；
//   - 结果能被自己重新解析（结构自洽），且父元素配对正确。
func TestRewriteAddElement(t *testing.T) {
	data := sampleManifest(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	beforeClasses := f.ComponentClasses()
	if f.FindElement("application") == nil {
		t.Skip("样本 Manifest 没有 <application>，跳过")
	}

	const recv = "com.example.shell.SecurityMonitor"
	const svc = "com.example.shell.ThreatDetector"
	edit := Edit{AddElements: []NewElement{
		{
			Parent: "application", ParentIndex: 0, Name: "receiver",
			Attrs: []NewAttr{
				StringAttr(AndroidNS, "name", recv),
				BoolAttr(AndroidNS, "exported", false),
				BoolAttr(AndroidNS, "enabled", true),
			},
		},
		{
			Parent: "application", ParentIndex: 0, Name: "service",
			Attrs: []NewAttr{
				StringAttr(AndroidNS, "name", svc),
				BoolAttr(AndroidNS, "exported", false),
			},
		},
	}}

	out, err := f.Rewrite(edit)
	if err != nil {
		t.Fatalf("改写失败: %v", err)
	}
	nf, err := Parse(out)
	if err != nil {
		t.Fatalf("改写结果无法重新解析（结构不自洽）: %v", err)
	}

	// 新元素必须成对出现，且属性正确。
	check := func(name, cls string, wantExported bool) {
		t.Helper()
		var el *Element
		for _, e := range nf.Elements {
			if e.Name == name && e.AttrString("name") == cls {
				el = e
				break
			}
		}
		if el == nil {
			t.Fatalf("没有找到新插入的 <%s android:name=%q>", name, cls)
		}
		exp := el.AttrNS(AndroidNS, "exported")
		if exp == nil {
			t.Fatalf("<%s %s> 缺少 android:exported", name, cls)
		}
		if exp.DataType != TypeIntBoolean {
			t.Fatalf("<%s %s> 的 exported 应是布尔型，实际 dataType=0x%02x", name, cls, exp.DataType)
		}
		gotExp := exp.Data != 0
		if gotExp != wantExported {
			t.Fatalf("<%s %s> 的 exported 应为 %v，实际 %v", name, cls, wantExported, gotExp)
		}
	}
	check("receiver", recv, false)
	check("service", svc, false)

	// 原有的组件类名必须一个不少。
	after := map[string]bool{}
	for _, c := range nf.ComponentClasses() {
		after[c] = true
	}
	for _, c := range beforeClasses {
		if !after[c] {
			t.Errorf("插入后原有组件类名丢失: %s", c)
		}
	}
	if !after[recv] || !after[svc] {
		t.Errorf("新组件类名未被识别为组件: %v", nf.ComponentClasses())
	}

	// 结构层面：每个 start element 都必须有配对的 end element。
	depth := 0
	for off := 8; off+8 <= len(out); {
		size := int(le32(out[off+4:]))
		if size < 8 || off+size > len(out) {
			break
		}
		switch le16(out[off:]) {
		case TypeXMLStartElem:
			depth++
		case TypeXMLEndElem:
			depth--
			if depth < 0 {
				t.Fatal("出现了没有配对 start 的 end element")
			}
		}
		off += size
	}
	if depth != 0 {
		t.Fatalf("start/end element 不成对，剩余深度 %d", depth)
	}
}

// TestRewriteAddElementMissingParent 钉住「父元素不存在时报错而不是静默跳过」。
func TestRewriteAddElementMissingParent(t *testing.T) {
	data := sampleManifest(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	_, err = f.Rewrite(Edit{AddElements: []NewElement{{
		Parent: "no-such-element", ParentIndex: 0, Name: "receiver",
		Attrs: []NewAttr{StringAttr(AndroidNS, "name", "X")},
	}}})
	if err == nil {
		t.Fatal("父元素不存在时应报错")
	}
	if !strings.Contains(err.Error(), "no-such-element") {
		t.Fatalf("错误信息应指出缺失的父元素，实际: %v", err)
	}
}

func le16(b []byte) int { return int(b[0]) | int(b[1])<<8 }
func le32(b []byte) int {
	return int(b[0]) | int(b[1])<<8 | int(b[2])<<16 | int(b[3])<<24
}
