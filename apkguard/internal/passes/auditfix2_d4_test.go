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

// accNativeFlag 是 DEX 方法访问标志 ACC_NATIVE（0x0100）。
//
// 不直接引用 dex 包内的 accNative 常量——它未导出；这里按 DEX 规范写字面量。
const accNativeFlag = 0x0100

// d4Artifact 构造 D4 测试用的最小产物：可解析的 Manifest + 一个 DEX。
func d4Artifact(t *testing.T) *pipeline.Artifact {
	t.Helper()
	return newArtifact(
		zipx.NewStored("AndroidManifest.xml", nestedAPKManifestAXML(newRand("audit-d4"), "com.agtest")),
		zipx.NewStored("classes.dex", smallDexWithClass(t, "Lcom/agtest/MainActivity;")),
	)
}

// d4Opts 返回 B2+C1+D4 的最小配置；提供 -sig-hash 以免依赖 E1/密钥库。
func d4Opts() *config.Options {
	return &config.Options{
		Enabled:   map[config.FeatureID]bool{"B2": true, "C1": true, "D4": true},
		SigHashes: []string{strings.Repeat("ab", 32)},
		Seed:      "audit-d4",
	}
}

// runD4Chain 按 B2 → C1 （→ D4）顺序执行，并返回壳 DEX 的解析结果。
func runD4Chain(t *testing.T, art *pipeline.Artifact, opts *config.Options, withD4 bool) *dex.File {
	t.Helper()
	ctx := context.Background()
	passes := []pipeline.Pass{&appReplace{}, &nativeKeyDerive{}}
	if withD4 {
		passes = append(passes, &memWatch{})
	}
	for _, p := range passes {
		if err := p.Run(ctx, art, opts); err != nil {
			t.Fatalf("功能项 %s 执行失败: %v", p.ID(), err)
		}
	}
	info, _ := art.Get(sharedKeyShell).(*shellInfo)
	if info == nil {
		t.Fatal("B2 未写入壳信息")
	}
	e := pipeline.Find(art, info.EntryName)
	if e == nil {
		t.Fatalf("壳 DEX 条目 %s 不存在", info.EntryName)
	}
	data, err := e.Data()
	if err != nil {
		t.Fatalf("读取壳 DEX 失败: %v", err)
	}
	f, err := dex.Parse(data)
	if err != nil {
		t.Fatalf("解析壳 DEX 失败: %v", err)
	}
	return f
}

// methodsOfClass 返回指定类描述符下「方法名 -> 访问标志」的表。
func methodsOfClass(t *testing.T, f *dex.File, cls string) map[string]uint32 {
	t.Helper()
	out := map[string]uint32{}
	found := false
	err := f.Classes(func(_ uint32, cd dex.ClassDef, name string) error {
		if name != cls {
			return nil
		}
		found = true
		pcd, err := f.ParseClassData(cd.ClassDataOff)
		if err != nil {
			return err
		}
		all := append(append([]dex.EncodedMethod{}, pcd.DirectMethods...), pcd.VirtualMethods...)
		for _, m := range all {
			_, mn, _, _, err := f.MethodFull(m.Idx)
			if err != nil {
				return err
			}
			out[mn] = m.Acc
		}
		return nil
	})
	if err != nil {
		t.Fatalf("枚举 %s 的方法失败: %v", cls, err)
	}
	if !found {
		t.Fatalf("壳 DEX 中找不到桥接类 %s", cls)
	}
	return out
}

// TestD4MemWatchWiringDeclaresAndCallsNativeWatch 是 D4（memWatch）的 Pass 级回归。
//
// 审计指出 D4 没有任何测试直接调用 Run：若接线写错（例如 C1 构造
// NativeBridgeSpec 时 D4 的 NeedWatch 未置位、或 B2 未把 D4 登记进 checks），
// 现有测试全绿也发现不了，产物里根本不会启动周期复检。
//
// 这里直接跑 B2 → C1 → D4，断言 Run 成功、产物痕迹与统计键，并钉住两个
// 产物级事实：
//   - 桥接类声明了 native 方法 watch()Z（NeedWatch 生效）；
//   - 桥接类的检测入口里存在对 watch() 的 invoke-static（壳启动时会调用它）。
func TestD4MemWatchWiringDeclaresAndCallsNativeWatch(t *testing.T) {
	art := d4Artifact(t)
	f := runD4Chain(t, art, d4Opts(), true)

	if got := art.Stats["D4.bridge"]; got != dex.NativeBridgeJavaName {
		t.Errorf("D4.bridge = %q，应为 %q", got, dex.NativeBridgeJavaName)
	}
	if !notesContain(art, "D4 内存完整性校验") || !notesContain(art, dex.NativeBridgeJavaName) {
		t.Errorf("D4 未在 Notes 中说明调用 %s.watch(): %v", dex.NativeBridgeJavaName, art.Notes)
	}

	methods := methodsOfClass(t, f, dex.NativeBridgeClass)
	acc, ok := methods[dex.NativeWatch]
	if !ok {
		t.Fatalf("桥接类 %s 未声明 %s()（D4 的 NeedWatch 未接线）: %v",
			dex.NativeBridgeClass, dex.NativeWatch, methods)
	}
	if acc&accNativeFlag == 0 {
		t.Errorf("桥接类 %s.%s 未声明为 native（Acc=%#x）", dex.NativeBridgeClass, dex.NativeWatch, acc)
	}
	if n := countInvokeStaticTo(t, f, dex.NativeBridgeClass, dex.NativeWatch); n == 0 {
		t.Fatalf("壳字节码里找不到对 %s->%s 的 invoke-static（周期复检不会被启动）",
			dex.NativeBridgeClass, dex.NativeWatch)
	}
}

// TestD4DisabledDoesNotDeclareNativeWatch 是对照组：D4 未启用时，C1 不得声明
// 或调用 watch()。否则「只开 C1」的产物会凭空多出一个启动守护线程的行为。
func TestD4DisabledDoesNotDeclareNativeWatch(t *testing.T) {
	art := d4Artifact(t)
	opts := d4Opts()
	opts.SetEnabled("D4", false)
	f := runD4Chain(t, art, opts, false)

	methods := methodsOfClass(t, f, dex.NativeBridgeClass)
	if _, ok := methods[dex.NativeWatch]; ok {
		t.Errorf("D4 未启用，桥接类不应声明 %s(): %v", dex.NativeWatch, methods)
	}
	if n := countInvokeStaticTo(t, f, dex.NativeBridgeClass, dex.NativeWatch); n != 0 {
		t.Errorf("D4 未启用，壳不应调用 %s（找到 %d 处 invoke-static）", dex.NativeWatch, n)
	}
}
