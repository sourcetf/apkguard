package passes

import (
	"context"
	"strings"
	"testing"

	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/pipeline"
	"apkguard/internal/zipx"
)

// TestRenameClassDefaultPackage 钉住「默认包类被改名后，类型描述符仍合法」。
//
// 真实缺陷（实测于 Dhizuku）：A1 分配新名时把「包前缀」算成 `LastIndex('/')`
// 之前的部分，默认包类（混淆后极常见的 `Lkf;`）算出空前缀，于是新名字变成
// `auo;`——**缺了开头的 `L`**，数组形式更会变成 `[[auo;`。ART 校验时报
//
//	Invalid type descriptor: '[[auo;'
//
// 并丢弃整个 DEX，表现为启动即 ClassNotFoundException。
//
// 类都在包内的应用（如 RustDesk）完全碰不到，所以这个缺陷藏了很久。
// 这里用一个默认包类做端到端验证：造 DEX → 跑 A1 → 校验产物描述符。
func TestRenameClassDefaultPackage(t *testing.T) {
	// 造一个只含默认包类的 DEX。
	data, err := dex.Build(dex.Addition{Classes: []dex.ClassSpec{{
		Name:   "LSecurityMonitor;",
		Super:  "Ljava/lang/Object;",
		Access: 0x0001, // ACC_PUBLIC
	}}})
	if err != nil {
		t.Fatalf("构造测试 DEX 失败: %v", err)
	}
	art := newArtifact(zipx.NewStored("classes.dex", data))

	if err := (&renameClass{}).Run(context.Background(), art, &config.Options{Seed: "dp"}); err != nil {
		t.Fatalf("A1 执行失败: %v", err)
	}

	e := pipeline.Find(art, "classes.dex")
	if e == nil {
		t.Fatal("产物里没有 classes.dex")
	}
	out, err := e.Data()
	if err != nil {
		t.Fatalf("读取产物失败: %v", err)
	}
	if err := dex.ValidateDescriptors(out); err != nil {
		t.Fatalf("默认包类改名后类型描述符非法: %v", err)
	}

	// 这个测试必须真的发生了改名，否则失去意义。
	f, err := dex.Parse(out)
	if err != nil {
		t.Fatalf("产物无法解析: %v", err)
	}
	renamed := false
	for i := uint32(0); i < f.NType; i++ {
		s, err := f.Type(i)
		if err != nil {
			t.Fatalf("读取类型失败: %v", err)
		}
		if s == "LSecurityMonitor;" {
			t.Fatalf("默认包类未被改名，测试失去意义（类型表：%v）", s)
		}
		if strings.HasPrefix(s, "L") && !strings.Contains(s, "/") && s != "LSecurityMonitor;" {
			renamed = true
		}
	}
	if !renamed {
		t.Fatal("没有观察到任何默认包短名，测试可能未覆盖目标路径")
	}
}

// TestClassPkgOf 直接钉住包前缀的推导规则。
func TestClassPkgOf(t *testing.T) {
	cases := map[string]string{
		"Lcom/agtest/MainActivity;": "Lcom/agtest/",
		"Lkf;":                      "L", // 默认包：必须带 L
		"La/b/c/D;":                 "La/b/c/",
		"Lz;":                       "L",
	}
	for in, want := range cases {
		if got := classPkgOf(in); got != want {
			t.Errorf("classPkgOf(%q) = %q，期望 %q", in, got, want)
		}
	}
}
