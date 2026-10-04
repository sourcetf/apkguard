package passes

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"apkguard/internal/config"
	"apkguard/internal/dex"
	b7c "apkguard/internal/dex2c"
	"apkguard/internal/pipeline"
	"apkguard/internal/zipx"
)

// buildDex2CFixture 造一个含 2 个可翻译静态方法的 DEX 条目。
func buildDex2CFixture(t *testing.T) *zipx.Entry {
	t.Helper()
	mk := func(name string, regs, ins int, f func(a *dex.Asm) error) dex.ClassMethod {
		a := dex.NewAsm()
		if err := f(a); err != nil {
			t.Fatalf("汇编失败: %v", err)
		}
		insns, patches, err := a.Assemble()
		if err != nil {
			t.Fatalf("汇编失败: %v", err)
		}
		return dex.ClassMethod{
			Name: name, Proto: dex.ProtoSpec{Ret: "I", Params: []string{"I", "I"}},
			Access: 0x0009,
			Code:   &dex.CodeBlob{Registers: uint16(regs), Ins: uint16(ins), Insns: insns, Patches: patches},
		}
	}
	data, err := dex.Build(dex.Addition{
		Types: []string{"Lcom/t/B7;", "Ljava/lang/Object;"},
		Classes: []dex.ClassSpec{{
			Name: "Lcom/t/B7;", Super: "Ljava/lang/Object;", Access: 0x0001,
			Methods: []dex.ClassMethod{
				mk("add2", 3, 2, func(a *dex.Asm) error { a.AddInt(0, 1, 2); a.Return(0); return nil }),
				mk("xor2", 3, 2, func(a *dex.Asm) error { a.XorInt(0, 1, 2); a.Return(0); return nil }),
			},
		}},
	})
	if err != nil {
		t.Fatalf("构造 DEX 失败: %v", err)
	}
	return zipx.NewStored("classes.dex", data)
}

// stubDex2CBuild 替换真实 NDK 构建，返回固定的产物计划。
func stubDex2CBuild(t *testing.T, libName string, abis []string) {
	t.Helper()
	oldFind, oldBuild := dex2cFindNDK, dex2cBuild
	t.Cleanup(func() { dex2cFindNDK, dex2cBuild = oldFind, oldBuild })
	dex2cFindNDK = func(string) (*b7c.NDK, error) { return &b7c.NDK{Root: "/stub"}, nil }
	dex2cBuild = func(_ []b7c.DexInput, o b7c.BuildOptions) (*b7c.Plan, error) {
		plan := &b7c.Plan{
			Methods: []*b7c.Method{{
				Entry: "classes.dex", Class: "Lcom/t/B7;", Name: "add2", Proto: "(II)I",
				Access: 0x0009, Static: true, Registers: 3, Ins: 2,
				Source: "classes.dex@0x100", FnName: "b7_fn_stub",
			}},
			Selection:  &b7c.Selection{Candidates: 2, Skip: map[string]int{}},
			LibName:    libName,
			CName:      "stub.c",
			CSource:    []byte("/* stub */\n"),
			SOs:        map[string][]byte{},
			ABIs:       abis,
			CompileLog: []string{"[stub] compile ok"},
		}
		for _, a := range abis {
			plan.SOs[a] = []byte("ELF-stub-" + a)
		}
		return plan, nil
	}
}

// TestDex2CZeroImpact 验证 -dex2c-methods=0 时产物字节零改动。
func TestDex2CZeroImpact(t *testing.T) {
	art := newArtifact(buildDex2CFixture(t))
	before := pipeline.Bytes(art)
	statsBefore := len(art.Stats)
	notesBefore := len(art.Notes)

	if err := (&dex2c{}).Run(context.Background(), art, &config.Options{Dex2CMethods: 0}); err != nil {
		t.Fatalf("关闭时不应报错: %v", err)
	}
	after := pipeline.Bytes(art)
	if !bytes.Equal(before, after) {
		t.Fatal("-dex2c-methods=0 时产物字节必须零改动")
	}
	if len(art.Stats) != statsBefore || len(art.Notes) != notesBefore {
		t.Fatalf("关闭时不应产生统计/说明: stats %d->%d notes %d->%d",
			statsBefore, len(art.Stats), notesBefore, len(art.Notes))
	}
	if pipeline.Find(art, "lib/arm64-v8a/libstub.so") != nil {
		t.Fatal("关闭时不应注入任何 .so")
	}
}

// TestDex2CMissingNDK 验证 NDK 不可用时明确报错（文案含「NDK」）。
func TestDex2CMissingNDK(t *testing.T) {
	art := newArtifact(buildDex2CFixture(t))
	err := (&dex2c{}).Run(context.Background(), art, &config.Options{
		Dex2CMethods: 10,
		NDKPath:      "/nonexistent-apkguard-ndk",
	})
	if err == nil {
		t.Fatal("NDK 不可用且 -dex2c-methods>0 时必须报错")
	}
	if !strings.Contains(err.Error(), "NDK") {
		t.Fatalf("错误文案必须包含「NDK」：%v", err)
	}
	// 失败时不得留下半成品条目。
	if len(pipeline.FindAll(art, func(e *zipx.Entry) bool {
		return strings.HasPrefix(e.NameString(), "lib/")
	})) != 0 {
		t.Fatal("构建失败时不应注入任何 .so")
	}
}

// TestDex2CInjectsLibs 验证按 ABI 注入 .so、写入计划与统计。
func TestDex2CInjectsLibs(t *testing.T) {
	stubDex2CBuild(t, "libdeadbeef.so", []string{"arm64-v8a", "armeabi-v7a", "x86_64"})
	art := newArtifact(buildDex2CFixture(t))
	if err := (&dex2c{}).Run(context.Background(), art, &config.Options{Dex2CMethods: 10, Seed: "s"}); err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	for _, abi := range []string{"arm64-v8a", "armeabi-v7a", "x86_64"} {
		name := "lib/" + abi + "/libdeadbeef.so"
		e := pipeline.Find(art, name)
		if e == nil {
			t.Fatalf("缺少 %s", name)
		}
		if !e.IsStored() {
			t.Fatalf("%s 必须未压缩存储（16KB 对齐与 extractNativeLibs=false 需要）", name)
		}
		if string(e.Raw) != "ELF-stub-"+abi {
			t.Fatalf("%s 内容不符: %q", name, e.Raw)
		}
	}
	if art.Stats["B7.lib"] != "libdeadbeef.so" || art.Stats["B7.libs"] != "3" {
		t.Fatalf("统计不符: %v", art.Stats)
	}
	if dex2cPlanOf(art) == nil {
		t.Fatal("未把 B7 计划写入 Artifact.Shared")
	}
	if len(art.Notes) == 0 || !strings.Contains(strings.Join(art.Notes, "\n"), "B7") {
		t.Fatalf("缺少 B7 说明: %v", art.Notes)
	}
	// 说明必须明确 L2 未完成，避免使用方误以为方法已变成 native。
	joined := strings.Join(art.Notes, "\n")
	if !strings.Contains(joined, "未实现") || !strings.Contains(joined, "ACC_NATIVE") {
		t.Fatalf("说明必须声明 ACC_NATIVE/注册未交付: %v", art.Notes)
	}
}

// TestDex2CTargetABIsFollowsAPK 验证只给 APK 已支持的 ABI 注入（不多不少）。
func TestDex2CTargetABIsFollowsAPK(t *testing.T) {
	stubDex2CBuild(t, "libcafebabe.so", []string{"armeabi-v7a"})
	art := newArtifact(
		buildDex2CFixture(t),
		zipx.NewStored("lib/armeabi-v7a/libfoo.so", []byte("x")),
	)
	if err := (&dex2c{}).Run(context.Background(), art, &config.Options{Dex2CMethods: 10}); err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	if pipeline.Find(art, "lib/armeabi-v7a/libcafebabe.so") == nil {
		t.Fatal("缺少 APK 已支持 ABI 的 Dex2C 库")
	}
	if pipeline.Find(art, "lib/arm64-v8a/libcafebabe.so") != nil {
		t.Fatal("不得给 APK 不支持的 ABI 注入库（会让系统误判架构）")
	}
}
