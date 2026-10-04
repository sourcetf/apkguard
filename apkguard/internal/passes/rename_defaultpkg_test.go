package passes

import (
	"context"
	"encoding/binary"
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

// buildRClassDex 构造一个只含 Lcom/x/R$string; 的 DEX，并给其静态 int 字段
// app_name 写入资源 ID 常量 0x7f030001 的 static_values——这是 A1 R 类改名的
// 放行判据（见 internal/dex/rename.go 的 planResourceIDClasses）。
//
// dex.Build 不支持静态字段初值，这里沿用 internal/dex 测试的做法：Build 后
// 在文件末尾追加 encoded_array_item 并回填 class_def.static_values_off，最后
// Finalize。
func buildRClassDex(t *testing.T) []byte {
	t.Helper()
	data, err := dex.Build(dex.Addition{Classes: []dex.ClassSpec{{
		Name:   "Lcom/x/R$string;",
		Super:  "Ljava/lang/Object;",
		Access: 0x0001, // ACC_PUBLIC
		Fields: []dex.ClassField{{
			Name:   "app_name",
			Type:   "I",
			Access: 0x0001 | 0x0008 | 0x0010, // PUBLIC | STATIC | FINAL
		}},
	}}})
	if err != nil {
		t.Fatalf("构造测试 DEX 失败: %v", err)
	}
	f, err := dex.Parse(data)
	if err != nil {
		t.Fatalf("解析测试 DEX 失败: %v", err)
	}
	idx := uint32(0)
	found := false
	for i := uint32(0); i < f.NClass; i++ {
		if n, err := f.ClassName(i); err == nil && n == "Lcom/x/R$string;" {
			idx, found = i, true
			break
		}
	}
	if !found {
		t.Fatal("构造失败：找不到 Lcom/x/R$string; 的 class_def")
	}
	cd, err := f.ClassDefAt(idx)
	if err != nil {
		t.Fatalf("读取类定义失败: %v", err)
	}
	if cd.ClassDataOff == 0 {
		t.Fatal("构造失败：测试类没有 class_data（静态字段缺失）")
	}
	out := append([]byte(nil), data...)
	for len(out)%4 != 0 {
		out = append(out, 0)
	}
	// encoded_array_item：size=1；VALUE_INT 4 字节 = 0x7f030001（资源段）。
	off := uint32(len(out))
	out = append(out, 0x01, 0x04|(3<<5), 0x01, 0x00, 0x03, 0x7f)
	binary.LittleEndian.PutUint32(out[int(f.OffClass)+int(idx)*32+28:], off)
	return dex.Finalize(out)
}

// fieldTableHas 判断 field_ids 中是否存在该字段名。
func fieldTableHas(t *testing.T, f *dex.File, name string) bool {
	t.Helper()
	for i := uint32(0); i < f.NField; i++ {
		_, _, n, err := f.FieldRefAt(i)
		if err != nil {
			t.Fatalf("读字段引用失败: %v", err)
		}
		if s, err := f.String(n); err == nil && s == name {
			return true
		}
	}
	return false
}

// TestRenameResourceIDsOptionWiring 钉住 A1 R 类改名开关在 pass 层的三条路径与
// 优先级：Options.RenameResourceIDs=true 时 R 类与字段都被改名；零值（JSON/API
// 未设置）时保持原样（与 ReturnNops 的零值语义一致）；环境变量
// APKGUARD_KEEP_RCLASS_IDS=1 是应急通道，即使字段为 true 也强制关闭（优先级最高）。
func TestRenameResourceIDsOptionWiring(t *testing.T) {
	t.Setenv("APKGUARD_KEEP_RCLASS_IDS", "")
	raw := buildRClassDex(t)

	run := func(opts *config.Options) (hasClass, hasField bool) {
		t.Helper()
		art := newArtifact(zipx.NewStored("classes.dex", append([]byte(nil), raw...)))
		if err := (&renameClass{}).Run(context.Background(), art, opts); err != nil {
			t.Fatalf("A1 执行失败: %v", err)
		}
		f := parseEntry(t, art, "classes.dex")
		return typeTableHas(t, f, "Lcom/x/R$string;"), fieldTableHas(t, f, "app_name")
	}

	// 1) 显式开启（CLI/Web 的默认路径）：R 类与字段都被改名。
	if hasClass, hasField := run(&config.Options{Seed: "rclass", RenameResourceIDs: true}); hasClass || hasField {
		t.Fatalf("RenameResourceIDs=true 时 R 类/字段应被改名，实际 hasClass=%v hasField=%v", hasClass, hasField)
	}

	// 2) 零值：与 ReturnNops 同语义 = 关闭（API 调用方不传该键时的实际默认）。
	if hasClass, hasField := run(&config.Options{Seed: "rclass"}); !hasClass || !hasField {
		t.Fatalf("Options 零值时 R 类/字段应保持原样，实际 hasClass=%v hasField=%v", hasClass, hasField)
	}

	// 3) 环境变量应急关闭：字段为 true 也必须让位。
	t.Setenv("APKGUARD_KEEP_RCLASS_IDS", "1")
	if hasClass, hasField := run(&config.Options{Seed: "rclass", RenameResourceIDs: true}); !hasClass || !hasField {
		t.Fatalf("环境变量为真时应强制关闭 R 类改名，实际 hasClass=%v hasField=%v", hasClass, hasField)
	}
}
