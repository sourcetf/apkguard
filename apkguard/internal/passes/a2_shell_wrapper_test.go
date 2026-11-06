package passes

import (
	"context"
	"testing"

	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/pack"
	"apkguard/internal/pipeline"
)

// 本文件是「业务 DEX 里发起的原生调用在 extractNativeLibs=false 的应用上也能
// 工作」这一修复的 Pass/产物级证据。
//
// 方案：业务 DEX 的字符串解密器不再自己 loadLibrary + 直接调 Native.sivDecrypt，
// 而是调用壳 DEX（系统类加载器命名空间）里的纯 Java 包装类 Siv.d；原生绑定
// 发生在能解析 APK 内 lib/<abi>/*.so 的那一侧。加壳后业务 DEX 里因此既没有
// loadLibrary、也不出现对桥接类的直接引用。

// runA2WithShell 跑 A2 → B1 → B2 → B3 的加壳链路（A2 先于加壳）。
func runA2WithShell(t *testing.T, art *pipeline.Artifact, opts *config.Options) {
	t.Helper()
	ctx := context.Background()
	for _, p := range []pipeline.Pass{&encryptString{}, &encryptDex{}, &appReplace{}, &classLoader{}} {
		if err := p.Run(ctx, art, opts); err != nil {
			t.Fatalf("功能项 %s 执行失败: %v", p.ID(), err)
		}
	}
}

// TestA2ShellWrapperProductShape 断言加壳产物：
//   - 业务 DEX（解密后的载荷）里解密器调用壳包装类 Siv.d，且**没有** loadLibrary /
//     桥接类引用；
//   - 壳 DEX 里有 Siv 包装类、桥接类与 loadLibrary。
func TestA2ShellWrapperProductShape(t *testing.T) {
	art := loadSample(t)
	opts := &config.Options{
		Enabled:      map[config.FeatureID]bool{"A2": true, "B1": true, "B2": true, "B3": true},
		DexKey:       "shell-wrapper-key",
		Seed:         "shell-wrapper-seed",
		ObfStringMin: 4,
	}
	runA2WithShell(t, art, opts)

	const wrapper = "Lcom/apkguard/shell/Siv;"

	// 业务 DEX 在密文载荷里，解密后逐份检查。
	payloads := payloadsOf(art)
	if payloads == nil || len(payloads.Items) == 0 {
		t.Fatal("未找到 B1 生成的载荷清单")
	}
	bizDex := 0
	for _, p := range payloads.Items {
		plain, err := pack.DecryptNamed(p.Blob, payloads.Key, p.Name)
		if err != nil {
			t.Fatalf("解密载荷 %s 失败: %v", p.Asset, err)
		}
		f, err := dex.Parse(plain)
		if err != nil {
			continue
		}
		bizDex++
		strs := stringPool(f)
		types := typePool(f)
		if strs["loadLibrary"] {
			t.Fatalf("业务 DEX %s 仍含 loadLibrary（应改为调用壳包装类）", p.Name)
		}
		if types[dex.NativeBridgeClass] {
			t.Fatalf("业务 DEX %s 仍直接引用桥接类 %s", p.Name, dex.NativeBridgeClass)
		}
		// 解密器必须真的登记了对包装类 d 的方法引用（由解密器的 invoke-static 产生）。
		if !hasMethodRef(f, wrapper+"->"+dex.SivWrapperMethod+"([B[B[B)[B") {
			t.Fatalf("业务 DEX %s 没有任何对 %s->%s 的调用", p.Name, wrapper, dex.SivWrapperMethod)
		}
	}
	if bizDex == 0 {
		t.Fatal("载荷中没有可解析的业务 DEX")
	}

	// 壳 DEX（classes.dex）必须有包装类、桥接类与 loadLibrary。
	shell := pipeline.Find(art, "classes.dex")
	if shell == nil {
		t.Fatal("产物中没有壳 DEX（classes.dex）")
	}
	sd, err := shell.Data()
	if err != nil {
		t.Fatal(err)
	}
	sf, err := dex.Parse(sd)
	if err != nil {
		t.Fatalf("解析壳 DEX 失败: %v", err)
	}
	classes := map[string]bool{}
	if err := sf.Classes(func(_ uint32, _ dex.ClassDef, name string) error {
		classes[name] = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !classes[wrapper] {
		t.Fatalf("壳 DEX 缺少 Siv 包装类 %s（已有 %v）", wrapper, classNames(classes))
	}
	sstrs := stringPool(sf)
	stypes := typePool(sf)
	if !sstrs["loadLibrary"] {
		t.Fatal("壳 DEX 缺少 loadLibrary（桥接类应在此加载守卫库）")
	}
	if !stypes[dex.NativeBridgeClass] {
		t.Fatalf("壳 DEX 缺少桥接类 %s", dex.NativeBridgeClass)
	}
	t.Logf("加壳产物：%d 份业务 DEX 均只经包装类转发；壳 DEX 含 %s 与桥接类", bizDex, wrapper)
}

// TestA2NoShellWrapperInBusinessDex 是零回归证据：不加壳（只 A2）时，包装类与
// 桥接类注入业务 DEX，业务 DEX 由系统类加载器加载，因此仍带 loadLibrary、仍可解密。
func TestA2NoShellWrapperInBusinessDex(t *testing.T) {
	art := loadSample(t)
	opts := &config.Options{
		Enabled:      map[config.FeatureID]bool{"A2": true},
		DexKey:       "no-shell-key",
		Seed:         "no-shell-seed",
		ObfStringMin: 4,
	}
	if err := (&encryptString{}).Run(context.Background(), art, opts); err != nil {
		t.Fatalf("A2 执行失败: %v", err)
	}

	// 无壳：Shared 里不应登记壳包装类。
	if v, _ := art.Get(sharedKeyA2SivWrapper).(string); v != "" {
		t.Fatalf("无壳时不应登记壳包装类，实际 %q", v)
	}

	sawWrapper, sawBridge, sawLoad := false, false, false
	for _, e := range pipeline.FindAll(art, isDexEntry) {
		d, err := e.Data()
		if err != nil {
			continue
		}
		f, err := dex.Parse(d)
		if err != nil {
			continue
		}
		if typePool(f)["Lcom/apkguard/shell/Siv;"] {
			sawWrapper = true
		}
		if typePool(f)[dex.NativeBridgeClass] {
			sawBridge = true
		}
		if stringPool(f)["loadLibrary"] {
			sawLoad = true
		}
	}
	if !sawWrapper || !sawBridge || !sawLoad {
		t.Fatalf("无壳产物应把包装类+桥接类注入业务 DEX 并带 loadLibrary：wrapper=%v bridge=%v load=%v",
			sawWrapper, sawBridge, sawLoad)
	}
	// 仍带守卫库（可解密的前提）。
	if n, _ := libEntryBytes(t, art); n == 0 {
		t.Fatal("A2 走 SIV 时必须嵌入守卫库")
	}
}

// stringPool 返回 DEX 字符串池集合。
func stringPool(f *dex.File) map[string]bool {
	out := map[string]bool{}
	for i := uint32(0); i < f.NString; i++ {
		if s, err := f.String(i); err == nil {
			out[s] = true
		}
	}
	return out
}

// typePool 返回 DEX 类型池集合。
func typePool(f *dex.File) map[string]bool {
	out := map[string]bool{}
	for i := uint32(0); i < f.NType; i++ {
		if n, err := f.Type(i); err == nil {
			out[n] = true
		}
	}
	return out
}

// hasMethodRef 判断 DEX 的 method_ids 里是否存在指定描述符的方法引用。
//
// 解密器对包装类 d 的 invoke-static 会在重建时登记这条 method_id，因此
// 它的存在等价于「某处调用了包装类 d」。
func hasMethodRef(f *dex.File, want string) bool {
	for i := uint32(0); i < f.NMethod; i++ {
		if d, err := f.MethodDesc(i); err == nil && d == want {
			return true
		}
	}
	return false
}
