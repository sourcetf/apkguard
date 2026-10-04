package dex2c

import (
	"bytes"
	"debug/elf"
	"os"
	"strings"
	"testing"

	"apkguard/internal/dex"
)

// ---- NDK 缺失必须报错 ----

func TestFindNDKMissingPath(t *testing.T) {
	_, err := FindNDK("/nonexistent-ndk-dir-apkguard-test")
	if err == nil {
		t.Fatal("不存在的 -ndk-path 必须报错")
	}
	if !strings.Contains(err.Error(), "NDK") {
		t.Fatalf("错误文案必须包含「NDK」：%v", err)
	}
}

// TestBuildRequiresNDK 验证有可翻译方法但缺 NDK 时 Build 明确失败。
func TestBuildRequiresNDK(t *testing.T) {
	data := buildDex(t, staticMethod("f", dex.ProtoSpec{Ret: "I"}, blobOf(t, 1, 0, 0, func(a *dex.Asm) error {
		a.Const4(0, 1)
		a.Return(0)
		return nil
	})))
	f, err := dex.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Build([]DexInput{{Name: "classes.dex", File: f}}, BuildOptions{Limit: 10, Seed: "s"})
	if err == nil {
		t.Fatal("有可翻译方法但无 NDK 时必须报错")
	}
	if !strings.Contains(err.Error(), "NDK") {
		t.Fatalf("错误文案必须包含「NDK」：%v", err)
	}
}

// ---- 真实 NDK 编译（可选） ----

// TestCompileWithRealNDK 用真实 NDK 编译 3 个 ABI，并断言 ELF 合法。
//
// 设置 APKGUARD_TEST_NDK=<NDK 根目录> 启用。Windows 上可指定 WSL 内的
// Linux 路径（如 /home/user/android-sdk/ndk/26.1.10909125），并用
// APKGUARD_WSL_DISTRO 指定发行版。产物保留在临时目录并打印 readelf 输出，
// 供报告取证。
func TestCompileWithRealNDK(t *testing.T) {
	ndkPath := os.Getenv("APKGUARD_TEST_NDK")
	if ndkPath == "" {
		t.Skip("未设置 APKGUARD_TEST_NDK，跳过真实 NDK 编译测试")
	}
	data := buildDex(t,
		staticMethod("addmul", dex.ProtoSpec{Ret: "I", Params: []string{"I", "I"}}, blobOf(t, 3, 2, 0, func(a *dex.Asm) error {
			a.AddInt(0, 1, 2)
			a.MulInt(0, 0, 2)
			a.Return(0)
			return nil
		})),
		staticMethod("clamp", dex.ProtoSpec{Ret: "I", Params: []string{"I", "I", "I"}}, blobOf(t, 4, 3, 0, func(a *dex.Asm) error {
			// if (x < lo) return lo; if (x > hi) return hi; return x;
			if err := a.IfLt(1, 2, "lo"); err != nil {
				return err
			}
			if err := a.IfGt(1, 3, "hi"); err != nil {
				return err
			}
			a.Return(1)
			a.Label("lo")
			a.Return(2)
			a.Label("hi")
			a.Return(3)
			return nil
		})),
		staticMethod("noopv", dex.ProtoSpec{Ret: "V"}, blobOf(t, 1, 0, 0, func(a *dex.Asm) error {
			a.ReturnVoid()
			return nil
		})),
		// 下面这些方法覆盖 JNI 代码生成的全部形态（字符串/静态调用/虚调用/字段），
		// 让真实 NDK 编译也验证它们能通过 clang 的类型检查。
		staticMethod("absm", dex.ProtoSpec{Ret: "I", Params: []string{"I"}}, blobOf(t, 2, 1, 1, func(a *dex.Asm) error {
			if err := a.InvokeStatic([]int{1}, dex.MethodSpec{Class: "Ljava/lang/Math;", Name: "abs", Proto: dex.ProtoSpec{Ret: "I", Params: []string{"I"}}}); err != nil {
				return err
			}
			a.MoveResult(0)
			a.Return(0)
			return nil
		})),
		staticMethod("strlen2", dex.ProtoSpec{Ret: "I", Params: []string{"Ljava/lang/String;"}}, blobOf(t, 2, 1, 1, func(a *dex.Asm) error {
			if err := a.InvokeVirtual([]int{1}, dex.MethodSpec{Class: "Ljava/lang/String;", Name: "length", Proto: dex.ProtoSpec{Ret: "I"}}); err != nil {
				return err
			}
			a.MoveResult(0)
			a.Return(0)
			return nil
		})),
		staticMethod("setn", dex.ProtoSpec{Ret: "V", Params: []string{"Lcom/t/A;", "I"}}, blobOf(t, 3, 2, 0, func(a *dex.Asm) error {
			if err := a.IPut(2, 1, dex.FieldSpec{Class: "Lcom/t/A;", Name: "n", Type: "I"}); err != nil {
				return err
			}
			a.ReturnVoid()
			return nil
		})),
		staticMethod("strf", dex.ProtoSpec{Ret: "Ljava/lang/String;"}, blobOf(t, 1, 0, 0, func(a *dex.Asm) error {
			a.ConstString(0, "b7")
			a.ReturnObject(0)
			return nil
		})),
	)
	f, err := dex.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	ndk, err := FindNDK(ndkPath)
	if err != nil {
		t.Fatalf("定位 NDK 失败: %v", err)
	}
	plan, err := Build([]DexInput{{Name: "classes.dex", File: f}}, BuildOptions{
		Limit: 10, Seed: "ndk-evidence", NDK: ndk, KeepTemp: true,
	})
	if err != nil {
		t.Fatalf("Build 失败: %v", err)
	}
	defer os.RemoveAll(plan.TempDir)
	if len(plan.Methods) != 7 {
		t.Fatalf("应翻译 7 个方法，实际 %d（跳过 %v）", len(plan.Methods), plan.Selection.Skip)
	}
	if len(plan.SOs) != 3 {
		t.Fatalf("应产出 3 个 ABI 的 .so，实际 %d", len(plan.SOs))
	}
	for _, abi := range AbiNames() {
		so := plan.SOs[abi]
		if err := VerifyELF(so, abi); err != nil {
			t.Fatalf("%s: %v", abi, err)
		}
		aligns, err := ReadLoadAlignments(so)
		if err != nil {
			t.Fatalf("%s: %v", abi, err)
		}
		for _, a := range aligns {
			if a < 0x4000 {
				t.Fatalf("%s: p_align=0x%x < 0x4000", abi, a)
			}
		}
		// b7_register_all 必须出现在动态符号表（壳集成入口）。
		ef, err := elf.NewFile(bytes.NewReader(so))
		if err != nil {
			t.Fatal(err)
		}
		syms, err := ef.DynamicSymbols()
		ef.Close()
		if err != nil {
			t.Fatalf("%s: 读取动态符号失败: %v", abi, err)
		}
		found := false
		for _, s := range syms {
			if s.Name == "b7_register_all" {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s: 动态符号表中缺少 b7_register_all", abi)
		}
		t.Logf("%s: ELF 合法，p_align=%v，符号 b7_register_all 存在", abi, aligns)
	}
	for _, l := range plan.CompileLog {
		t.Log(strings.TrimSpace(l))
	}

	// 同 seed 复现：C 源与 .so 都必须逐字节一致。
	f2, err := dex.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	plan2, err := Build([]DexInput{{Name: "classes.dex", File: f2}}, BuildOptions{
		Limit: 10, Seed: "ndk-evidence", NDK: ndk,
	})
	if err != nil {
		t.Fatalf("第二次 Build 失败: %v", err)
	}
	if !bytes.Equal(plan.CSource, plan2.CSource) {
		t.Fatal("同 seed 的 C 源不一致")
	}
	for _, abi := range AbiNames() {
		if !bytes.Equal(plan.SOs[abi], plan2.SOs[abi]) {
			t.Fatalf("%s: 同 seed 的 .so 不一致（不可复现）", abi)
		}
	}
	t.Logf("确定性：C 源 %d 字节、3 个 ABI 的 .so 两次构建逐字节一致；临时目录 %s",
		len(plan.CSource), plan.TempDir)

	// readelf 取证（仅当显式要求时执行，避免测试依赖 readelf）。
	if os.Getenv("APKGUARD_TEST_READELF") == "1" {
		distro := os.Getenv(WSLDistroEnv)
		if distro == "" {
			distro = "Ubuntu-26.04"
		}
		dir, err := wslPathOf(t, distro, plan.TempDir)
		if err != nil {
			t.Logf("readelf 取证跳过: %v", err)
			return
		}
		for _, abi := range AbiNames() {
			out, err := wslRun(distro, "readelf -hW -lW "+shq(dir+"/"+strings.TrimSuffix(plan.LibName, ".so")+"."+abi+".so")+
				" | grep -E 'Machine|LOAD'")
			if err != nil {
				t.Logf("readelf %s 失败: %v\n%s", abi, err, out)
				continue
			}
			t.Logf("[%s] readelf -hW -lW:\n%s", abi, out)
		}
	}
}
