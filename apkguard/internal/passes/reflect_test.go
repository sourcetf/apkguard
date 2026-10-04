package passes

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/pipeline"
	"apkguard/internal/zipx"
)

// ---- A7 反射成员名强制加密（Pass 层回归） ----
//
// 覆盖四条硬要求：
//  1. 反射成员名（含短串 "a"）在 A7+A2 后不再以明文留在池里；
//  2. 不在反射位置/不是成员名的等长串仍保持明文（判据按位置，不按长度）；
//  3. Class.forName 的类名不加密（样本里类名就是明文）；
//  4. A7 单独运行不改一个字节，只产生 Note/Stat；同 seed 可复现。

// reflectFixtureConst 是构造用到的描述符。
const (
	reflectClassDesc  = "Ljava/lang/Class;"
	reflectMethodDesc = "Ljava/lang/reflect/Method;"
	reflectFieldDesc  = "Ljava/lang/reflect/Field;"
	reflectClassArr   = "[Ljava/lang/Class;"
)

// reflectFixtureCode 构造一段方法体并组装。
func reflectFixtureCode(t *testing.T, fn func(*dex.Asm), registers, ins, outs int) *dex.CodeBlob {
	t.Helper()
	a := dex.NewAsm()
	fn(a)
	insns, patches, err := a.Assemble()
	if err != nil {
		t.Fatalf("汇编反射测试方法失败: %v", err)
	}
	return &dex.CodeBlob{Registers: uint16(registers), Ins: uint16(ins), Outs: uint16(outs), Insns: insns, Patches: patches}
}

// reflectFixtureDex 构造一个带 5 个方法的测试 DEX：
//
//	m1: getDeclaredMethod("isTagEnabled")          → 应被 A7 识别（12 字节）
//	m2: 经 move-object 传参 getField("a")           → 应被 A7 识别（1 字节，低于门槛）
//	m3: 只加载 "isPlainName!" 就返回                 → 等长对照，必须留明文
//	m4: Class.forName("com/example/Keep")           → 类名入口，必须留明文
//	m5: getDeclaredField("isEnabled")               → 短名正例（9 字节）
//
// 注意 "a" 同时是 A2 注入解密器的方法名（解密器需要池里保留这个字符串），
// 因此池中可能仍存在 "a" 这一项；断言改为「没有任何 const-string 再引用明文 a」。
func reflectFixtureDex(t *testing.T) []byte {
	t.Helper()
	getDeclaredMethod := dex.MethodSpec{Class: reflectClassDesc, Name: "getDeclaredMethod",
		Proto: dex.ProtoSpec{Ret: reflectMethodDesc, Params: []string{"Ljava/lang/String;", reflectClassArr}}}
	getField := dex.MethodSpec{Class: reflectClassDesc, Name: "getField",
		Proto: dex.ProtoSpec{Ret: reflectFieldDesc, Params: []string{"Ljava/lang/String;"}}}
	forName := dex.MethodSpec{Class: reflectClassDesc, Name: "forName",
		Proto: dex.ProtoSpec{Ret: reflectClassDesc, Params: []string{"Ljava/lang/String;"}}}

	// m1：const-string v0, "isTagEnabled"；new Class[0]；invoke-virtual {v2,v0,v2}
	m1 := reflectFixtureCode(t, func(a *dex.Asm) {
		a.ConstString(0, "isTagEnabled")
		a.Const4(1, 0)
		if err := a.NewArray(2, 1, reflectClassArr); err != nil {
			t.Fatal(err)
		}
		if err := a.InvokeVirtual([]int{2, 0, 2}, getDeclaredMethod); err != nil {
			t.Fatal(err)
		}
		a.ReturnVoid()
	}, 3, 0, 3)

	// m2：const-string v0, "a"；move-object v1, v0；invoke-virtual {v2,v1} getField
	//    覆盖「短串」与「经 move 传播」两条判据。
	m2 := reflectFixtureCode(t, func(a *dex.Asm) {
		a.ConstString(0, "a")
		a.MoveObject(1, 0)
		if err := a.InvokeVirtual([]int{2, 1}, getField); err != nil {
			t.Fatal(err)
		}
		a.ReturnVoid()
	}, 3, 0, 2)

	// m3：等长对照串，不在任何反射调用的成员名位置。
	m3 := reflectFixtureCode(t, func(a *dex.Asm) {
		a.ConstString(0, "isPlainName!")
		a.ReturnVoid()
	}, 1, 0, 0)

	// m4：类名入口（forName），A7 明确不认。
	m4 := reflectFixtureCode(t, func(a *dex.Asm) {
		a.ConstString(0, "com/example/Keep")
		if err := a.InvokeStatic([]int{0}, forName); err != nil {
			t.Fatal(err)
		}
		a.MoveResultObject(0)
		a.ReturnVoid()
	}, 1, 0, 1)

	// m5：短名正例（9 字节），与 A2 解密器无任何命名冲突。
	getDeclaredField := dex.MethodSpec{Class: reflectClassDesc, Name: "getDeclaredField",
		Proto: dex.ProtoSpec{Ret: reflectFieldDesc, Params: []string{"Ljava/lang/String;"}}}
	m5 := reflectFixtureCode(t, func(a *dex.Asm) {
		a.ConstString(0, "isEnabled")
		if err := a.InvokeVirtual([]int{2, 0}, getDeclaredField); err != nil {
			t.Fatal(err)
		}
		a.ReturnVoid()
	}, 3, 0, 2)

	d, err := dex.Build(dex.Addition{Classes: []dex.ClassSpec{{
		Name: "Lapp7/Reflect;", Super: "Ljava/lang/Object;", Access: 0x0001,
		Methods: []dex.ClassMethod{
			{Name: "m1", Proto: dex.ProtoSpec{Ret: "V"}, Access: 0x0009, Code: m1},
			{Name: "m2", Proto: dex.ProtoSpec{Ret: "V"}, Access: 0x0009, Code: m2},
			{Name: "m3", Proto: dex.ProtoSpec{Ret: "V"}, Access: 0x0009, Code: m3},
			{Name: "m4", Proto: dex.ProtoSpec{Ret: "V"}, Access: 0x0009, Code: m4},
			{Name: "m5", Proto: dex.ProtoSpec{Ret: "V"}, Access: 0x0009, Code: m5},
		},
	}}})
	if err != nil {
		t.Fatalf("构造反射测试 DEX 失败: %v", err)
	}
	return d
}

// reflectFixtureStrings 返回 DEX 字符串池内容集合。
func reflectFixtureStrings(t *testing.T, data []byte) map[string]bool {
	t.Helper()
	f, err := dex.Parse(data)
	if err != nil {
		t.Fatalf("解析 DEX 失败: %v", err)
	}
	out := map[string]bool{}
	for i := uint32(0); i < f.NString; i++ {
		s, err := f.String(i)
		if err != nil {
			t.Fatalf("读取字符串 %d 失败: %v", i, err)
		}
		out[s] = true
	}
	return out
}

// reflectConstStrings 返回被 const-string 指令引用到的字符串集合。
//
// 「池里是否还有明文」对多数串等价于「const 引用是否还是明文」，但对
// A2 解密器自身需要的串（方法名 "a"）不同：解密器要求池中保留该条目，
// 因此只能断言 const-string 引用已不再指向明文。
func reflectConstStrings(t *testing.T, data []byte) map[string]bool {
	t.Helper()
	f, err := dex.Parse(data)
	if err != nil {
		t.Fatalf("解析 DEX 失败: %v", err)
	}
	u, err := f.StringUsage()
	if err != nil {
		t.Fatalf("扫描字符串用途失败: %v", err)
	}
	out := map[string]bool{}
	for idx := range u.Const {
		s, err := f.String(idx)
		if err != nil {
			t.Fatalf("读取字符串 %d 失败: %v", idx, err)
		}
		out[s] = true
	}
	return out
}

// TestA7ScanOnlyDoesNotTouchDex 断言 A7 单独运行（A2 关）时：零字节改动、有 Note/Stat。
func TestA7ScanOnlyDoesNotTouchDex(t *testing.T) {
	fixture := reflectFixtureDex(t)
	art := newArtifact(zipx.NewStored("classes.dex", fixture))
	opts := &config.Options{Enabled: map[config.FeatureID]bool{"A7": true, "A2": false}}
	if err := (&reflectNames{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A7 执行失败: %v", err)
	}
	got, err := pipeline.Find(art, "classes.dex").Data()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, fixture) {
		t.Fatal("A7 只应扫描登记，不得改写 DEX 字节")
	}
	if art.Stats["A7.strings"] != "3" {
		t.Fatalf("A7 应识别 3 条反射成员名，实际 %s（%v）", art.Stats["A7.strings"], art.Stats)
	}
	if art.Stats["A7.dex"] != "1" {
		t.Fatalf("A7.dex 应为 1，实际 %s", art.Stats["A7.dex"])
	}
	joined := strings.Join(art.Notes, "\n")
	if !strings.Contains(joined, "未加密") || !strings.Contains(joined, "A2") {
		t.Fatalf("A2 未启用时 A7 必须在 Note 中写明未加密，实际: %s", joined)
	}
	v, ok := art.Get(reflectionNameKey).(map[string]bool)
	if !ok {
		t.Fatalf("A7 未把结果登记进 Shared[%q]", reflectionNameKey)
	}
	for _, want := range []string{"isTagEnabled", "a", "isEnabled"} {
		if !v[want] {
			t.Fatalf("A7 登记集合缺少 %q: %v", want, v)
		}
	}
	for _, bad := range []string{"isPlainName!", "com/example/Keep"} {
		if v[bad] {
			t.Fatalf("A7 误登记了 %q（等长对照/类名入口都不应被识别）", bad)
		}
	}
}

// TestA7ForcesShortReflectionNamesThroughA2 是本功能的核心断言：
// 低于 ObfStringMin 的反射成员名也必须被 A2 加密并移出字符串池。
func TestA7ForcesShortReflectionNamesThroughA2(t *testing.T) {
	fixture := reflectFixtureDex(t)
	opts := &config.Options{
		Enabled: map[config.FeatureID]bool{"A7": true, "A2": true},
		Seed:    "a7-seed",
		DexKey:  "a7-key",
		// 门槛设到 64：除强制集合外，没有任何串应被加密——反例因此有意义。
		ObfStringMin: 64,
		ShellPkg:     "com.demo.shell",
	}
	run := func() []byte {
		art := newArtifact(zipx.NewStored("classes.dex", fixture))
		if err := (&reflectNames{}).Run(context.Background(), art, opts); err != nil {
			t.Fatalf("A7 执行失败: %v", err)
		}
		if err := (&encryptString{}).Run(context.Background(), art, opts); err != nil {
			t.Fatalf("A2 执行失败: %v", err)
		}
		d, err := pipeline.Find(art, "classes.dex").Data()
		if err != nil {
			t.Fatal(err)
		}
		if err := dex.Verify(d); err != nil {
			t.Fatalf("A7+A2 产物 Verify 失败: %v", err)
		}
		if art.Stats["A2.strings"] != "3" {
			t.Fatalf("A2 应只加密 A7 强制的 3 条串（门槛 64 排除其余），实际 %s", art.Stats["A2.strings"])
		}
		return append([]byte(nil), d...)
	}
	out := run()

	pool := reflectFixtureStrings(t, out)
	consts := reflectConstStrings(t, out)
	if pool["isTagEnabled"] {
		t.Error("反射成员名 isTagEnabled 仍以明文留在字符串池（A7 强制加密失效）")
	}
	if pool["isEnabled"] {
		t.Error("短反射成员名 isEnabled 仍以明文留在字符串池——这正是 A7 要补的洞（A2 的 MinLen 门槛未被打通）")
	}
	// "a" 与 A2 解密器方法名重名，池中必须保留该条目（否则 method_ids 指向
	// 不存在的字符串）；但所有 const-string 引用都必须已改为密文。
	for _, leaked := range []string{"isTagEnabled", "isEnabled", "a"} {
		if consts[leaked] {
			t.Errorf("反射成员名 %q 仍被 const-string 以明文引用（A7 强制加密失效）", leaked)
		}
	}
	// 反例：等长对照串与类名入口必须保持明文（判据是位置而非长度）。
	if !pool["isPlainName!"] {
		t.Error("不在反射位置、与 \"isTagEnabled\" 等长的对照串被误加密（判据扩大化）")
	}
	if !pool["com/example/Keep"] {
		t.Error("Class.forName 的类名被误加密（类名入口不应被 A7 识别）")
	}

	// 同 seed/密钥可复现。
	if again := run(); !bytes.Equal(out, again) {
		t.Fatal("同 seed 下 A7+A2 两次产物不一致，存在未受控随机性")
	}
}
