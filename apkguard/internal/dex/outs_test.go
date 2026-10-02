package dex

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"apkguard/internal/native"
)

// TestOutsSizeIsSufficient 检查所有注入方法的 outs_size 是否够用。
//
// ART 的校验器要求 outs_size ≥ 方法内任何一次 invoke 的参数字数；
// 不足会直接判 VerifyError，而本地解释器并不检查这一项——属于
// 「本地全绿、真机崩」的典型盲区。这里扫描全部生成方法体，把
// invoke 指令的实参个数与所属方法声明的 Outs 对比。
func TestOutsSizeIsSufficient(t *testing.T) {
	adds := map[string]Addition{}
	mk := func(name string, f func() (Addition, error)) {
		a, err := f()
		if err != nil {
			t.Fatalf("%s 构造失败: %v", name, err)
		}
		adds[name] = a
	}
	mk("shell", func() (Addition, error) {
		return ShellAppAddition(&ShellApp{Class: "Lx/App;", Orig: "com.a.MyApp", Debug: true,
			Checks: []string{"Lx/Sig;"},
			Loader: &LoaderSpec{Class: "Lx/L;", Key: [32]byte{1}, TempDir: "ag",
				Items: []LoaderItem{{Asset: "assets/p", DexName: "d0.dex", Size: 64}}, Debug: true},
		})
	})
	mk("loader", func() (Addition, error) {
		return LoaderAddition(&LoaderSpec{Class: "Lx/L;", Key: [32]byte{1}, TempDir: "ag",
			Items: []LoaderItem{{Asset: "assets/p", DexName: "d0.dex", Size: 64}}})
	})
	mk("sig", func() (Addition, error) { return SigAddition(&SigSpec{Class: "Lx/Sig;", Digest: [32]byte{1}}) })
	mk("env", func() (Addition, error) {
		return EnvCheckAddition(&EnvCheckSpec{Class: "Lx/Rt;", Paths: []string{"/sbin/su"}})
	})
	mk("dev", func() (Addition, error) { return DevAddition(&DevSpec{Class: "Lx/Dev;"}) })
	mk("bridge", func() (Addition, error) {
		return NativeBridgeAddition(&NativeBridgeSpec{Class: NativeBridgeClass, LibName: NativeLibName,
			NeedDerive: true, NeedDebug: true, NeedHooked: true, NeedIntact: true})
	})
	mk("crash", func() (Addition, error) { return CrashHandlerAddition("Lx/Ex;") })
	mk("dec", func() (Addition, error) {
		return stringDecryptorAddition(&StringEncrypt{Class: "Lx/Dec;", MethodName: "a", Key: [32]byte{5}, InjectClass: true})
	})
	mk("arr", func() (Addition, error) {
		return constantArrayAddition(&ConstantArray{Class: "Lx/Arr;", MethodName: "b", InjectClass: true})
	})
	mk("pad", func() (Addition, error) {
		cls, _, err := ClassPadPlan(&ClassPadder{Count: 3, Seed: "outs-check"})
		if err != nil {
			return Addition{}, err
		}
		return ClassPadAdditionOf(cls), nil
	})

	type bad struct {
		cls, meth string
		need, got uint16
	}
	var probs []bad
	total := 0
	for name, add := range adds {
		out, err := Build(add)
		if err != nil {
			t.Fatalf("%s 构建失败: %v", name, err)
		}
		f, err := Parse(out)
		if err != nil {
			t.Fatalf("%s 解析失败: %v", name, err)
		}
		if err := f.walkAllCode(func(codeOff uint32) error {
			ci, err := f.ParseCodeItem(codeOff)
			if err != nil {
				return err
			}
			total++
			maxArgs := uint16(0)
			err = walkInsns(ci.Insns, func(op byte, pos int, w []uint16) error {
				switch op {
				case 0x6e, 0x6f, 0x70, 0x71, 0x72: // 35c
					n := uint16(w[pos] >> 12)
					if n > maxArgs {
						maxArgs = n
					}
				case 0x74, 0x75, 0x76, 0x77, 0x78: // 3rc
					n := uint16(w[pos] >> 8)
					if n > maxArgs {
						maxArgs = n
					}
				}
				return nil
			})
			if err != nil {
				return err
			}
			if maxArgs > ci.Outs {
				probs = append(probs, bad{name, fmt.Sprintf("code@%d(op=%d)", codeOff, len(ci.Insns)), maxArgs, ci.Outs})
			}
			return nil
		}); err != nil {
			t.Fatalf("%s 遍历失败: %v", name, err)
		}
	}
	sort.Slice(probs, func(i, j int) bool { return probs[i].cls < probs[j].cls })
	if len(probs) > 0 {
		var b strings.Builder
		for _, p := range probs {
			fmt.Fprintf(&b, "\n  %s %s: 需要 outs>=%d，实际 %d", p.cls, p.meth, p.need, p.got)
		}
		t.Fatalf("有 %d 个方法体的 outs_size 不足（ART 会判 VerifyError）:%s", len(probs), b.String())
	}
	t.Logf("检查了 %d 个方法体，outs_size 全部够用", total)
}

// checkOutsOf 校验一个 DEX 中每个方法体的 outs_size 是否足够。
func checkOutsOf(t *testing.T, tag string, f *File) int {
	t.Helper()
	n := 0
	if err := f.walkAllCode(func(codeOff uint32) error {
		ci, err := f.ParseCodeItem(codeOff)
		if err != nil {
			return err
		}
		n++
		maxArgs := uint16(0)
		if err := walkInsns(ci.Insns, func(op byte, pos int, w []uint16) error {
			switch op {
			case 0x6e, 0x6f, 0x70, 0x71, 0x72:
				if v := uint16(w[pos] >> 12); v > maxArgs {
					maxArgs = v
				}
			case 0x74, 0x75, 0x76, 0x77, 0x78:
				if v := uint16(w[pos] >> 8); v > maxArgs {
					maxArgs = v
				}
			}
			return nil
		}); err != nil {
			return err
		}
		if maxArgs > ci.Outs {
			t.Errorf("%s：code@%d 需要 outs>=%d，实际 %d（ART 会判 VerifyError）",
				tag, codeOff, maxArgs, ci.Outs)
		}
		return nil
	}); err != nil {
		t.Fatalf("%s 遍历失败: %v", tag, err)
	}
	return n
}

// TestArtifactOutsSize 对全部交付包（含解密后的载荷）做 outs_size 体检。
//
// 这是「本地全绿、真机崩」最典型的一类：outs_size 声明偏小时，解释器照跑不误，
// 而 ART 的校验器直接判 VerifyError，类一加载就崩且不留痕迹。
func TestArtifactOutsSize(t *testing.T) {
	files, err := filepath.Glob("../../../deliver/*.apk")
	if err != nil || len(files) == 0 {
		t.Skip("交付包不在本机，跳过")
	}
	sort.Strings(files)
	total := 0
	for _, apk := range files {
		g, assets := apkShellDex(t, apk)
		total += checkOutsOf(t, filepath.Base(apk), g)
		if len(assets) == 0 || !hasLoaderClass(g) {
			continue
		}
		// 壳包：解密后的载荷同样要查。
		env := &loaderEnv{assets: assets, fs: map[string][]byte{}}
		restore := installLoaderMocks(env)
		installActivityThreadMock()
		fakeCode = map[string]uint32{}
		registerFakeCode(t, g, allClassNames(t, g)...)
		for k, h := range crashHandlerDeps() {
			fakeCalls[k] = h
		}
		if nativeKeyNeeded(g) {
			if raw, rerr := os.ReadFile("../../../deliver/signer-sha256.txt"); rerr == nil {
				if d, derr := hex.DecodeString(strings.TrimSpace(string(raw))); derr == nil && len(d) == 32 {
					fakeCalls[NativeBridgeClass+"->sig(Landroid/content/Context;)[B"] =
						func(*interp, []int) (int32, any, error) { return 0, &fakeBytes{b: d}, nil }
					fakeCalls[NativeBridgeClass+"->derive([B)[B"] =
						func(*interp, []int) (int32, any, error) {
							k := native.DeriveKey(d)
							return 0, &fakeBytes{b: k[:]}, nil
						}
				}
			}
		}
		if idx, off := findMethod(t, g, "Lcom/apkguard/shell/Loader;", "->"+LoaderEntry+"("); off != 0 {
			if _, rerr := runPadMethod(g, idx, off, &fakeObj{desc: descContext}); rerr == nil {
				for name, blob := range env.fs {
					if pg, perr := Parse(blob); perr == nil {
						total += checkOutsOf(t, filepath.Base(apk)+" 载荷 "+filepath.Base(name), pg)
					}
				}
			}
		}
		restore()
		clearActivityThreadMock()
		fakeCode = map[string]uint32{}
	}
	t.Logf("体检了 %d 个方法体的 outs_size", total)
}
