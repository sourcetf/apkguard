package native

// C3（native 控制流混淆）的自动化验收，全部断言都作用在**构建产物**上，
// 而不是「读代码觉得对」：
//
//  1. TestPrebuiltHidesSensitiveStrings：3 个 ABI 的 .so 里不再出现敏感明文
//     （与 strings -a 等价的可见串扫描；UTF-8 中文用原始字节匹配）；
//  2. TestPrebuiltExportsJNISymbols：-fvisibility=hidden 与 -Wl,-s 没有把
//     JNI 符号藏过头（藏过头会让 System.loadLibrary 后抛 UnsatisfiedLinkError）；
//  3. TestObfuscatedStringsDecryptToPlaintext：宿主 C 自测把每串密文解密后的
//     hex 打出来，与本文件保存的期望明文对拍——证明密文与 salt 一一对应，
//     且 C 侧的不透明谓词在 100 万组输入下恒真/恒假（自测输出 FAIL 即失败）。
//
// 期望明文只存在于本测试文件，C 源码与被编译进 .so 的那份代码里没有明文。

import (
	"bytes"
	"debug/elf"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// expectedPlaintext 是 apkguard.c 中每个 AG_DEFSTR 密文串对应的原文。
// 键名与 C 侧 encdec() 打印的 ENCDEC_<键名> 一致。
var expectedPlaintext = map[string]string{
	"ag_s_status":       "/proc/self/status",
	"ag_s_maps":         "/proc/self/maps",
	"ag_s_frida":        "frida",
	"ag_s_xposed":       "xposed",
	"ag_s_substrate":    "substrate",
	"ag_s_linjector":    "linjector",
	"ag_s_libhook":      "libhook",
	"ag_s_hookzz":       "hookzz",
	"ag_s_whale":        "whale",
	"ag_s_ddi":          "ddi",
	"ag_s_epic":         "epic",
	"ag_s_magisk":       "magisk",
	"ag_s_tag":          "APKGUARD",
	"ag_s_tpid":         "TracerPid:",
	"ag_s_log_nopath":   "C6: 无法定位自身文件，自校验跳过",
	"ag_s_log_openfail": "C6: 打开自身文件失败（%s，原因 %s），自校验跳过",
	"ag_s_log_nosec":    "C6: 自身文件缺少 .text/.rodata 节名（原因 %s），自校验跳过",
}

// prebuiltSensitiveASCII 是不应再出现在 .so 可见串（strings 等价物）里的
// ASCII 敏感词。长度 <= 4 的短词要求「整条可见串恰好等于它」——它们在源码里
// 原本是 NUL 结尾的独立字面量；用子串匹配会被随机指令字节误伤。
var prebuiltSensitiveASCII = []string{
	"/proc/self/status",
	"/proc/self/maps",
	"frida",
	"xposed",
	"substrate",
	"linjector",
	"libhook",
	"hookzz",
	"whale",
	"magisk",
	"TracerPid",
	"APKGUARD",
	"C6:",
	"gum",
	"ddi",
	"epic",
}

// prebuiltSensitiveUTF8 是中文日志片段：UTF-8 字节序列足够长，直接全文件匹配。
var prebuiltSensitiveUTF8 = []string{
	"无法定位自身文件",
	"自校验跳过",
}

// printableRuns 提取与 `strings -a -n 3` 等价的可见 ASCII 串（0x20..0x7e）。
func printableRuns(data []byte) [][]byte {
	var out [][]byte
	start := -1
	for i, b := range data {
		if b >= 0x20 && b <= 0x7e {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 && i-start >= 3 {
			out = append(out, data[start:i])
		}
		start = -1
	}
	if start >= 0 && len(data)-start >= 3 {
		out = append(out, data[start:])
	}
	return out
}

// runHostSelfTest 用宿主编译器编译并运行 C 自测，返回输出。
// 未找到宿主编译器时跳过（与 TestDeriveMatchesNativeC 的策略一致）。
func runHostSelfTest(t *testing.T) string {
	t.Helper()
	cc := findHostCC()
	if cc.path == "" {
		t.Skip("未找到宿主编译器（tcc/cc/gcc/clang），跳过 C 侧混淆自测")
	}
	src := filepath.Join("csrc", "apkguard.c")
	if _, err := os.Stat(src); err != nil {
		t.Skipf("找不到 C 源码 %s: %v", src, err)
	}
	var out []byte
	var err error
	if cc.tiny {
		cmd := exec.Command(cc.path, "-DAG_HOST_TEST", "-run", src)
		cmd.Dir = "."
		out, err = cmd.CombinedOutput()
	} else {
		bin := filepath.Join(t.TempDir(), "apkguard-hosttest")
		build := exec.Command(cc.path, "-DAG_HOST_TEST", "-O1", "-o", bin, src)
		build.Dir = "."
		if bout, berr := build.CombinedOutput(); berr != nil {
			t.Fatalf("编译 C 自测失败（%s）: %v\n%s", cc.path, berr, bout)
		}
		cmd := exec.Command(bin)
		cmd.Dir = "."
		out, err = cmd.CombinedOutput()
	}
	if err != nil {
		t.Fatalf("运行 C 自测失败: %v\n%s", err, out)
	}
	text := string(out)
	if !strings.Contains(text, "RESULT OK") || strings.Contains(text, "FAIL") {
		t.Fatalf("C 侧自测未通过：\n%s", text)
	}
	return text
}

// TestObfuscatedStringsDecryptToPlaintext 验证每串密文都能解回期望明文。
func TestObfuscatedStringsDecryptToPlaintext(t *testing.T) {
	text := runHostSelfTest(t)
	got := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "ENCDEC_") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			t.Fatalf("ENCDEC 行格式非法: %q", line)
		}
		name := strings.TrimPrefix(fields[0], "ENCDEC_")
		if _, err := hex.DecodeString(fields[1]); err != nil {
			t.Fatalf("ENCDEC_%s 不是合法 hex: %q", name, fields[1])
		}
		got[name] = fields[1]
	}
	for name, want := range expectedPlaintext {
		if _, ok := got[name]; !ok {
			t.Errorf("C 自测输出缺少 ENCDEC_%s", name)
			continue
		}
		if wantHex := hex.EncodeToString([]byte(want)); got[name] != wantHex {
			t.Errorf("密文串 %s 解密结果不符:\n  C   %s\n  want %s", name, got[name], wantHex)
		}
	}
	if len(got) != len(expectedPlaintext) {
		t.Errorf("ENCDEC 行数 %d 与期望串数 %d 不一致", len(got), len(expectedPlaintext))
	}
}

// TestPrebuiltHidesSensitiveStrings 断言三个 ABI 的 .so 里没有任何敏感明文。
func TestPrebuiltHidesSensitiveStrings(t *testing.T) {
	libs, err := Prebuilt()
	if err != nil {
		t.Fatalf("读取预编译库失败: %v", err)
	}
	for _, l := range libs {
		runs := printableRuns(l.Data)
		for _, pat := range prebuiltSensitiveASCII {
			for _, run := range runs {
				hit := false
				if len(pat) <= 4 {
					hit = string(run) == pat
				} else {
					hit = bytes.Contains(run, []byte(pat))
				}
				if hit {
					t.Errorf("%s: 可见串里仍有敏感明文 %q（run=%q）", l.Abi, pat, run)
					break
				}
			}
		}
		for _, pat := range prebuiltSensitiveUTF8 {
			if bytes.Contains(l.Data, []byte(pat)) {
				t.Errorf("%s: 二进制里仍有敏感中文片段 %q", l.Abi, pat)
			}
		}
		t.Logf("%s: 敏感明文扫描通过（%d 条可见串）", l.Abi, len(runs))
	}
}

// TestPrebuiltExportsJNISymbols 断言 JNI 入口仍存在于动态符号表。
//
// C3 的强化编译标志里 -fvisibility=hidden 只隐藏内部符号（JNIEXPORT 在
// jni.h 里就是 default visibility），-Wl,-s 只去掉静态符号表；这条测试防的是
// 「某天把 JNI 符号也藏了/剥了」——那会让所有启用 C1/C4/C5/C6 的产物在
// System.loadLibrary 之后直接 UnsatisfiedLinkError。
func TestPrebuiltExportsJNISymbols(t *testing.T) {
	libs, err := Prebuilt()
	if err != nil {
		t.Fatalf("读取预编译库失败: %v", err)
	}
	want := []string{
		"JNI_OnLoad",
		"Java_com_apkguard_nativebridge_Native_derive",
		"Java_com_apkguard_nativebridge_Native_debugged",
		"Java_com_apkguard_nativebridge_Native_hooked",
		"Java_com_apkguard_nativebridge_Native_intact",
		"Java_com_apkguard_nativebridge_Native_watch",
	}
	for _, l := range libs {
		f, err := elf.NewFile(bytes.NewReader(l.Data))
		if err != nil {
			t.Fatalf("%s: 解析 ELF 失败: %v", l.Abi, err)
		}
		syms, err := f.DynamicSymbols()
		f.Close()
		if err != nil {
			t.Fatalf("%s: 读取动态符号表失败: %v", l.Abi, err)
		}
		have := map[string]bool{}
		for _, s := range syms {
			have[s.Name] = true
		}
		for _, w := range want {
			if !have[w] {
				t.Errorf("%s: 动态符号表缺少 %s", l.Abi, w)
			}
		}
	}
}
