package passes

import (
	"context"
	"strings"
	"testing"

	"apkguard/internal/axml"
	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/pipeline"
)

// TestDecoyComponentsDeclaredInManifest 钉住 A8 把诱饵类真的声明成 Manifest 组件。
//
// 只注入类是不够的：静态分析者扫一遍组件表就能看出「没有任何安全相关组件」，
// 于是立刻判定 SecurityMonitor 之类是填充物。把它们真的声明成 <receiver>/<service>，
// 这些名字才会出现在组件表、权限视图与导出组件清单里。
//
// 同时钉住两条安全约束：
//   - 声明必须指向**实际存在的类**，且这些类继承正确的框架基类（否则万一被
//     实例化就是 ClassCastException / 找不到类）；
//   - 只声明 receiver / service，**不声明 provider**（ContentProvider 会在应用
//     启动时被 ActivityThread 主动实例化）。
func TestDecoyComponentsDeclaredInManifest(t *testing.T) {
	art := loadSample(t)
	if pipeline.Find(art, "AndroidManifest.xml") == nil {
		t.Skip("样本没有 AndroidManifest.xml")
	}
	if pipeline.FindAll(art, isDexEntry) == nil {
		t.Skip("样本没有 DEX")
	}

	opts := &config.Options{
		Enabled:  map[config.FeatureID]bool{"A8": true},
		Seed:     "decoy",
		ShellPkg: "com.apkguard.shell",
	}
	if err := (&decoyClass{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A8 执行失败: %v", err)
	}

	// ---- 1) Manifest 里出现了声明 ----
	mfData, err := pipeline.Find(art, "AndroidManifest.xml").Data()
	if err != nil {
		t.Fatalf("读取 Manifest 失败: %v", err)
	}
	mf, err := axml.Parse(mfData)
	if err != nil {
		t.Fatalf("产物 Manifest 无法解析（写坏了会启动即死）: %v", err)
	}
	app := mf.FindElement("application")
	if app == nil {
		t.Fatal("Manifest 中没有 <application>")
	}
	var declared []axml.Element
	for _, e := range mf.Elements {
		switch e.Name {
		case "receiver", "service":
			if strings.HasPrefix(e.AttrString("name"), "com.apkguard.shell.") {
				declared = append(declared, *e)
			}
		case "provider":
			if strings.HasPrefix(e.AttrString("name"), "com.apkguard.shell.") {
				t.Fatalf("A8 不得把诱饵声明成 provider（会在启动时被实例化）: %s", e.AttrString("name"))
			}
		}
	}
	if len(declared) == 0 {
		t.Fatal("Manifest 里没有任何诱饵组件声明")
	}
	// 声明的组件必须导出一致为 false 且显式声明（targetSdk 31+ 的要求）。
	for _, e := range declared {
		exp := e.AttrNS(axml.AndroidNS, "exported")
		if exp == nil {
			t.Fatalf("<%s %s> 缺少 android:exported", e.Name, e.AttrString("name"))
		}
		if exp.DataType != axml.TypeIntBoolean || exp.Data != 0 {
			t.Fatalf("<%s %s> 的 exported 应为布尔 false", e.Name, e.AttrString("name"))
		}
	}

	// ---- 2) 声明的类必须真的存在，且继承正确的框架基类 ----
	var dexData []byte
	for _, e := range pipeline.FindAll(art, isDexEntry) {
		if d, derr := e.Data(); derr == nil {
			if _, perr := dex.Parse(d); perr == nil {
				dexData = d
				break
			}
		}
	}
	if dexData == nil {
		t.Fatal("产物里没有可解析的 DEX")
	}
	f, err := dex.Parse(dexData)
	if err != nil {
		t.Fatalf("解析产物 DEX 失败: %v", err)
	}
	supers := map[string]string{}
	if err := f.Classes(func(_ uint32, cd dex.ClassDef, name string) error {
		s, serr := f.Type(cd.SuperIdx)
		if serr != nil {
			return serr
		}
		supers[name] = s
		return nil
	}); err != nil {
		t.Fatalf("遍历类失败: %v", err)
	}

	wantBase := map[string]string{
		"receiver": "Landroid/content/BroadcastReceiver;",
		"service":  "Landroid/app/Service;",
	}
	for _, e := range declared {
		desc := "L" + strings.ReplaceAll(e.AttrString("name"), ".", "/") + ";"
		got, ok := supers[desc]
		if !ok {
			t.Fatalf("Manifest 声明了组件 %s，但产物 DEX 里没有这个类", e.AttrString("name"))
		}
		if got != wantBase[e.Name] {
			t.Fatalf("%s 的父类应为 %s，实际 %s", e.AttrString("name"), wantBase[e.Name], got)
		}
	}
	t.Logf("A8 声明了 %d 个诱饵组件：%v", len(declared), compNamesFromElems(declared))
}

// compNamesFromElems 提取元素上的 android:name（用于日志）。
func compNamesFromElems(es []axml.Element) []string {
	out := make([]string, 0, len(es))
	for _, e := range es {
		out = append(out, e.Name+":"+e.AttrString("name"))
	}
	return out
}
