package dex

import (
	"os"
	"strings"
	"testing"
)

// TestRustDeskPayloadHasApplication 检查真实应用加固后，
// 解密出来的载荷里是否包含 Manifest 声明的 Application 类。
//
// 背景：RustDesk 加固后启动报
//
//	ClassNotFoundException: com.carriez.flutter_hbb.MainApplication
//
// 需要区分两种可能：①分片把该类丢了（B4 划分错误）；
// ②类在载荷里但加载器看不到（路径/时机问题）。
func TestRustDeskPayloadHasApplication(t *testing.T) {
	apk := os.Getenv("RD_APK")
	if apk == "" {
		apk = "../../../realworld/rd-noA1.apk"
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
	t.Logf("落地 %d 份载荷，dexPath=%s", len(env.fs), truncStr(env.dexPath, 200))

	// 按需把解密后的分片落盘，便于用外部工具（dex2oat）独立复核。
	if dir := os.Getenv("AG_DUMP_PAYLOAD"); dir != "" {
		for name, blob := range env.fs {
			dst := dir + "/" + name[strings.LastIndex(name, "/")+1:]
			if err := os.WriteFile(dst, blob, 0o644); err != nil {
				t.Fatalf("导出分片失败: %v", err)
			}
		}
	}

	want := "Lcom/carriez/flutter_hbb/MainApplication;"
	total := 0
	found := ""
	for name, blob := range env.fs {
		pg, err := Parse(blob)
		if err != nil {
			t.Fatalf("解析 %s 失败: %v", name, err)
		}
		for _, n := range allClassNames(t, pg) {
			total++
			if n == want {
				found = name
			}
		}
	}
	if found == "" {
		t.Fatalf("载荷里没有 %s（共 %d 个类）—— 分片划分漏了这个类", want, total)
	}
	t.Logf("命中：%s 在 %s（载荷共 %d 个类）", want, found, total)
}

func truncStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
