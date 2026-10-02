package dex

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// checkShortyStrings 校验全部 proto 的 shorty 字符串仍然合法。
//
// ART 的结构校验器要求 shorty 只含 VZBSCIJFD 或 L；被字符串加密改成
// 十六进制串后会被判 "Bad shorty character" 并**拒绝整个 DEX**。
// shorty 不被任何指令引用，只看「是否被 const-string 使用」会把它误判为
// 可整体替换——本项目就因此踩过一次（真实应用 RustDesk 全部分片被拒）。
func checkShortyStrings(t *testing.T, tag string, f *File) int {
	t.Helper()
	checked := 0
	for i := uint32(0); i < f.NProto; i++ {
		base := f.OffProto + 12*i
		if base+4 > uint32(len(f.data)) {
			break
		}
		si := readU32At(f.data, base)
		s, err := f.String(si)
		if err != nil {
			t.Errorf("%s：proto[%d] 的 shorty 索引 %d 无法解析: %v", tag, i, si, err)
			continue
		}
		checked++
		if s == "" {
			t.Errorf("%s：proto[%d] 的 shorty 为空", tag, i)
			continue
		}
		for k := 0; k < len(s); k++ {
			switch s[k] {
			case 'V', 'Z', 'B', 'S', 'C', 'I', 'J', 'F', 'D', 'L':
			default:
				t.Errorf("%s：proto[%d] 的 shorty %q 含非法字符 %q"+
					"（ART 会判 Bad shorty character 并拒绝整个 DEX）",
					tag, i, s, string(s[k]))
			}
		}
	}
	return checked
}

func readU32At(b []byte, off uint32) uint32 {
	return uint32(b[off]) | uint32(b[off+1])<<8 | uint32(b[off+2])<<16 | uint32(b[off+3])<<24
}

// TestArtifactShortyStrings 对全部交付包（含解密后的载荷）检查 shorty。
func TestArtifactShortyStrings(t *testing.T) {
	files, err := filepath.Glob("../../../deliver/*.apk")
	if err != nil || len(files) == 0 {
		t.Skip("交付包不在本机，跳过")
	}
	sort.Strings(files)
	total := 0
	for _, apk := range files {
		g, assets := apkShellDex(t, apk)
		total += checkShortyStrings(t, filepath.Base(apk), g)
		if len(assets) == 0 || !hasLoaderClass(g) {
			continue
		}
		env := &loaderEnv{assets: assets, fs: map[string][]byte{}}
		restore := installLoaderMocks(env)
		installActivityThreadMock()
		fakeCode = map[string]uint32{}
		registerFakeCode(t, g, allClassNames(t, g)...)
		for k, h := range crashHandlerDeps() {
			fakeCalls[k] = h
		}
		if idx, off := findMethod(t, g, "Lcom/apkguard/shell/Loader;", "->"+LoaderEntry+"("); off != 0 {
			if _, rerr := runPadMethod(g, idx, off, &fakeObj{desc: descContext}); rerr == nil {
				for name, blob := range env.fs {
					if pg, perr := Parse(blob); perr == nil {
						total += checkShortyStrings(t, filepath.Base(apk)+" 载荷 "+filepath.Base(name), pg)
					}
				}
			}
		}
		restore()
		clearActivityThreadMock()
		fakeCode = map[string]uint32{}
	}
	t.Logf("检查了 %d 个原型 shorty", total)
}

// TestRealWorldPayloadShorty 检查真实应用载荷的 shorty（自研样本覆盖不到）。
func TestRealWorldPayloadShorty(t *testing.T) {
	apk := os.Getenv("RD_APK")
	if apk == "" {
		apk = "../../../realworld/rd-v20.apk"
	}
	if _, err := os.Stat(apk); err != nil {
		t.Skipf("未找到 %s，跳过", apk)
	}
	g, assets := apkShellDex(t, apk)
	env := &loaderEnv{assets: assets, fs: map[string][]byte{}}
	restore := installLoaderMocks(env)
	defer restore()
	installActivityThreadMock()
	defer clearActivityThreadMock()
	fakeCode = map[string]uint32{}
	defer func() { fakeCode = map[string]uint32{} }()
	registerFakeCode(t, g, allClassNames(t, g)...)
	idx, off := findMethod(t, g, "Lcom/apkguard/shell/Loader;", "->"+LoaderEntry+"(")
	if _, err := runPadMethod(g, idx, off, &fakeObj{desc: descContext}); err != nil {
		t.Fatalf("壳链路执行失败: %v", err)
	}
	total := 0
	for name, blob := range env.fs {
		pg, err := Parse(blob)
		if err != nil {
			t.Fatalf("解析 %s 失败: %v", name, err)
		}
		total += checkShortyStrings(t, filepath.Base(apk)+" "+filepath.Base(name), pg)
	}
	t.Logf("RustDesk 载荷共检查 %d 个原型 shorty", total)
	if total < 1000 {
		t.Fatalf("真实应用原型数量异常（只检查到 %d 个）", total)
	}
}

// TestShortyNotReplacedByStringEncrypt 验证字符串加密不会替换 shorty 字符串。
func TestShortyNotReplacedByStringEncrypt(t *testing.T) {
	src := sampleDex(t)
	f, err := Parse(src)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	usage, err := f.StringUsage()
	if err != nil {
		t.Fatalf("扫描字符串用途失败: %v", err)
	}
	if len(usage.Shorty) == 0 {
		t.Fatal("样本中应存在 shorty 字符串，扫描结果为空说明收集逻辑失效")
	}
	out, _, err := RebuildWithStats(f, RebuildOptions{
		StringEncrypt: &StringEncrypt{Class: "Lx/Dec;", MethodName: "a", Key: [32]byte{0x33},
			MinLen: 0, InjectClass: true},
	})
	if err != nil {
		t.Fatalf("加密重建失败: %v", err)
	}
	g, err := Parse(out)
	if err != nil {
		t.Fatalf("重建结果无法解析: %v", err)
	}
	checkShortyStrings(t, "加密重建结果", g)
}
