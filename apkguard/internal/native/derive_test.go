package native

import (
	"bytes"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// tccCandidates 是可用于对拍 C 实现的宿主编译器位置。
//
// TinyCC 很小、可直接编译并运行 C 代码，非常适合做这件事：它让我们能
// 用真正的 C 编译产物去验证 native/apkguard.c，而不是靠「读代码觉得对」。
var tccCandidates = []string{
	filepath.Join("..", "..", "..", "tools", "tcc", "tcc.exe"),
	filepath.Join("..", "..", "..", "tools", "tcc", "tcc", "tcc.exe"),
	"tcc",
}

// findTCC 返回可用的宿主编译器路径；找不到时返回空串。
//
// 返回的必须是绝对路径：Windows 的 CreateProcess 不会替调用方解析
// 带 ".." 的相对路径，直接传相对路径会得到「找不到指定的路径」。
func findTCC() string {
	for _, p := range tccCandidates {
		st, err := os.Stat(p)
		if err != nil || st.IsDir() {
			continue
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			continue
		}
		return abs
	}
	if p, err := exec.LookPath("tcc"); err == nil {
		return p
	}
	return ""
}

// TestDeriveMatchesNativeC 用 C 实现自测的输出对拍 Go 实现。
//
// 这是本包最重要的一条测试：Go 侧负责加密载荷，C 侧负责运行时解密，
// 两者只要有 1 bit 差异，产物就会在真机上解不开自己的载荷——而这种错误
// 在没有设备的环境里根本无法通过其他手段发现。
//
// C 代码同时会用 NIST 测试向量自检 SHA-256（见 apkguard.c 的 AG_HOST_TEST
// 分支），因此这条对拍是建立在「C 的 SHA-256 本身已被验证」之上的。
func TestDeriveMatchesNativeC(t *testing.T) {
	tcc := findTCC()
	if tcc == "" {
		t.Skip("未找到 TCC，跳过 C/Go 派生一致性对拍（安装方式见 native/README.md）")
	}
	src := "apkguard.c"   // 与 derive.go 同目录
	if _, err := os.Stat(src); err != nil {
		t.Skipf("找不到 C 源码 %s: %v", src, err)
	}

	cmd := exec.Command(tcc, "-DAG_HOST_TEST", "-run", "apkguard.c")
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("运行 C 自测失败: %v\n%s", err, out)
	}
	text := string(out)

	// C 侧的自检必须先全部通过。
	if !strings.Contains(text, "RESULT OK") {
		t.Fatalf("C 侧自检未通过：\n%s", text)
	}
	if strings.Contains(text, "FAIL") {
		t.Fatalf("C 侧存在失败项：\n%s", text)
	}

	// 取回 C 侧算出的两个派生结果。
	withSig := parseDeriveLine(t, text, "DERIVE_WITH_SIG ")
	noSig := parseDeriveLine(t, text, "DERIVE_NO_SIG ")

	// 与 C 侧相同的输入：sig[i] = i*7+3。
	sig := make([]byte, 32)
	for i := range sig {
		sig[i] = byte(i*7 + 3)
	}

	gotWith := DeriveKey(sig)
	if hex.EncodeToString(gotWith[:]) != withSig {
		t.Fatalf("带签名摘要的派生结果不一致：\n  Go %s\n  C  %s", hex.EncodeToString(gotWith[:]), withSig)
	}
	gotNo := DeriveKey(nil)
	if hex.EncodeToString(gotNo[:]) != noSig {
		t.Fatalf("不带签名摘要的派生结果不一致：\n  Go %s\n  C  %s", hex.EncodeToString(gotNo[:]), noSig)
	}
	t.Logf("C/Go 派生一致性验证通过：带签名 %s…，无签名 %s…", withSig[:16], noSig[:16])
}

// parseDeriveLine 从 C 自测输出里取出指定前缀后面的十六进制串。
func parseDeriveLine(t *testing.T, text, prefix string) string {
	t.Helper()
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			v := strings.TrimSpace(strings.TrimPrefix(line, prefix))
			if _, err := hex.DecodeString(v); err != nil || len(v) != 64 {
				t.Fatalf("C 输出中的摘要格式非法: %q", line)
			}
			return v
		}
	}
	t.Fatalf("C 输出中缺少 %q：\n%s", prefix, text)
	return ""
}

// TestSeedIsNotPlaintext 验证种子不是以明文常量形式存放的。
//
// 这条测试防的是「有人为了省事把种子换成明文数组」：那样一条 strings
// 就能把它捞出来，C1 的防护价值直接归零。
func TestSeedIsNotPlaintext(t *testing.T) {
	seed := Seed()
	if bytes.Equal(seed[:], seedObf[:]) {
		t.Fatal("种子与存放的常量相同——说明掩码没有生效，种子等于明文存储")
	}
	// 种子必须不为全零（否则派生结果退化为「只跟签名有关」）。
	allZero := true
	for _, b := range seed {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("种子为全零")
	}
	// 掩码必须真的改变了每一个字节，否则部分字节仍是明文。
	same := 0
	for i := range seed {
		if seed[i] == seedObf[i] {
			same++
		}
	}
	if same > 0 {
		t.Fatalf("有 %d 个种子字节未被掩码覆盖（等于明文存放）", same)
	}
}
