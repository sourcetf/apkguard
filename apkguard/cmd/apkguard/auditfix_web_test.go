package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"apkguard/internal/config"
)

// optionJSONTags 返回 config.Options 的全部 JSON tag。
func optionJSONTags() []string {
	rt := reflect.TypeOf(config.Options{})
	var out []string
	for i := 0; i < rt.NumField(); i++ {
		tag := rt.Field(i).Tag.Get("json")
		name := strings.Split(tag, ",")[0]
		if name == "" || name == "-" {
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// collectBody 从 index.html 中截取 collect() 函数体。
func collectBody(t *testing.T, html string) string {
	t.Helper()
	re := regexp.MustCompile(`(?s)function collect\(\)\s*\{([\s\S]*?)\n\}`)
	m := re.FindStringSubmatch(html)
	if m == nil {
		t.Fatalf("index.html 中未找到 collect() 函数")
	}
	return m[1]
}

// collectKeys 提取 collect() 对象字面量里出现的键名。
//
// 这是前后端契约的「唯一事实来源」：每个 Options JSON tag 都必须在这里被发出，
// 否则对应的功能项在 Web 路径下会拿到 Go 零值——数值项为零即空操作。
func collectKeys(t *testing.T, body string) []string {
	t.Helper()
	re := regexp.MustCompile(`([a-z_][a-z0-9_]*)\s*:`)
	seen := map[string]bool{}
	var out []string
	for _, m := range re.FindAllStringSubmatch(body, -1) {
		k := m[1]
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// TestWebFormCoversAllOptions 守住 Web 表单与 config.Options 的字段契约。
//
// 历史缺陷：Options 有 48 个 JSON tag，collect() 只发 20 个，导致 A9/A10/A12/A13
// 等整项静默失效（缺键 → Go 零值 → pass 内 total<=0 直接 return），或默认值被
// 悄悄降级（如 A12 从 CLI 的 150 降到 pass 默认）。这条测试断言两边的集合完全相等。
func TestWebFormCoversAllOptions(t *testing.T) {
	raw, err := os.ReadFile("index.html")
	if err != nil {
		t.Fatalf("读取 index.html 失败: %v", err)
	}
	body := collectBody(t, string(raw))
	got := collectKeys(t, body)
	want := optionJSONTags()

	gotSet := map[string]bool{}
	for _, k := range got {
		gotSet[k] = true
	}
	wantSet := map[string]bool{}
	for _, k := range want {
		wantSet[k] = true
	}

	var missing, extra []string
	for _, k := range want {
		if !gotSet[k] {
			missing = append(missing, k)
		}
	}
	for _, k := range got {
		if !wantSet[k] {
			extra = append(extra, k)
		}
	}
	if len(missing) > 0 {
		t.Errorf("collect() 缺少 %d 个 Options 字段（这些功能项在 Web 路径下会拿到零值/空操作）：%s",
			len(missing), strings.Join(missing, ", "))
	}
	if len(extra) > 0 {
		t.Errorf("collect() 发出了 %d 个 Options 中不存在的键（后端会静默忽略）：%s",
			len(extra), strings.Join(extra, ", "))
	}
}

// --- 安全：Host / Origin 校验 ---

// TestLoopbackGuard 校验非本机 Host/Origin 被拒绝。
func TestLoopbackGuard(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := loopbackGuard(next, "127.0.0.1:8787")

	cases := []struct {
		name   string
		host   string
		origin string
		want   int
	}{
		{"回环 IPv4", "127.0.0.1:8787", "", http.StatusOK},
		{"localhost", "localhost:8787", "", http.StatusOK},
		{"回环 IPv6", "[::1]:8787", "", http.StatusOK},
		{"伪造 Host", "evil.example", "", http.StatusForbidden},
		{"非回环 Origin", "127.0.0.1:8787", "http://evil.example", http.StatusForbidden},
		{"Origin: null", "127.0.0.1:8787", "null", http.StatusForbidden},
		{"回环 Origin", "localhost:8787", "http://localhost:8787", http.StatusOK},
		{"实际监听地址", "192.168.1.9:8787", "", http.StatusOK},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Host = c.host
			if c.origin != "" {
				req.Header.Set("Origin", c.origin)
			}
			rec := httptest.NewRecorder()
			// 监听地址换成 192.168.1.9:8787 时，「实际监听地址」用例才可通过。
			guard := h
			if c.name == "实际监听地址" {
				guard = loopbackGuard(next, "192.168.1.9:8787")
			}
			guard.ServeHTTP(rec, req)
			if rec.Code != c.want {
				t.Errorf("Host=%q Origin=%q：HTTP %d，期望 %d（body=%s）",
					c.host, c.origin, rec.Code, c.want, rec.Body.String())
			}
		})
	}
}

// TestWebRunRejectsOutputEscape 校验输出路径不能逃出输入所在目录。
func TestWebRunRejectsOutputEscape(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.apk") // 不必存在：越界校验发生在流水线之前
	escaped := filepath.Join(dir, "..", "ESCAPED.apk")

	payload := uiPayload(t, in, escaped, nil, map[string]bool{})
	code, resp := postRun(t, payload)
	if code != http.StatusBadRequest {
		t.Fatalf("越界输出应返回 400，实际 %d（ok=%v err=%q）", code, resp.OK, resp.Error)
	}
	if !strings.Contains(resp.Error, "逃出") && !strings.Contains(resp.Error, "根目录") {
		t.Fatalf("错误信息应点明越界，实际: %q", resp.Error)
	}
	if _, err := os.Stat(filepath.Join(dir, "..", "ESCAPED.apk")); err == nil {
		t.Fatal("越界文件竟被创建")
	}
}

// TestWebRunRejectsOversizedBody 校验请求体上限。
func TestWebRunRejectsOversizedBody(t *testing.T) {
	big := bytes.Repeat([]byte("x"), maxRequestBody+1024)
	req := httptest.NewRequest("POST", "/api/run", bytes.NewReader(big))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handleRun(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("超大请求体应返回 400，实际 %d（body=%s）", rec.Code, rec.Body.String())
	}

	req2 := httptest.NewRequest("POST", "/api/validate", bytes.NewReader(big))
	rec2 := httptest.NewRecorder()
	handleValidate(rec2, req2)
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("超大请求体（validate）应返回 400，实际 %d", rec2.Code)
	}
}

// TestWebRunValidationErrorIs400 校验参数错误返回 400（而非 200+ok:false）。
func TestWebRunValidationErrorIs400(t *testing.T) {
	payload := uiPayload(t, "in.apk", "", nil, map[string]bool{"B1": true})
	code, resp := postRun(t, payload)
	if code != http.StatusBadRequest {
		t.Fatalf("依赖校验失败应返回 400，实际 %d（err=%q）", code, resp.Error)
	}
	if resp.OK {
		t.Fatal("校验失败时 ok 不应为 true")
	}
}

// TestWebRunDirectoryRequiresE5 校验目录输入未启用 E5 时给出明确错误。
func TestWebRunDirectoryRequiresE5(t *testing.T) {
	dir := t.TempDir()
	payload := uiPayload(t, dir, filepath.Join(dir, "out"), nil, map[string]bool{})
	code, resp := postRun(t, payload)
	if code != http.StatusBadRequest {
		t.Fatalf("目录 + 未启用 E5 应返回 400，实际 %d（err=%q）", code, resp.Error)
	}
	if !strings.Contains(resp.Error, "E5") {
		t.Fatalf("错误信息应提示启用 E5，实际: %q", resp.Error)
	}
}

// TestWebRunBatchDirectory 校验 Web 的 E5 批量分支真的产出多个包。
func TestWebRunBatchDirectory(t *testing.T) {
	src := fixtureAPK(t)
	in := t.TempDir()
	out := filepath.Join(in, "out")
	for _, name := range []string{"a.apk", "b.apk"} {
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatalf("读取样本失败: %v", err)
		}
		if err := os.WriteFile(filepath.Join(in, name), b, 0o644); err != nil {
			t.Fatalf("写出 %s 失败: %v", name, err)
		}
	}
	// 只启用 E5，关掉需要密钥库的签名项。
	payload := uiPayload(t, in, out, nil, map[string]bool{"E5": true})
	code, resp := postRun(t, payload)
	if code != http.StatusOK {
		t.Fatalf("批量应返回 200，实际 %d（err=%q）", code, resp.Error)
	}
	if !resp.OK || len(resp.Outs) != 2 {
		t.Fatalf("应产出 2 个包，实际 ok=%v outs=%v err=%q", resp.OK, resp.Outs, resp.Error)
	}
	for _, p := range resp.Outs {
		if st, err := os.Stat(p); err != nil || st.Size() == 0 {
			t.Errorf("产出缺失或为空: %s (%v)", p, err)
		}
	}
}

// TestSanitizeChannelsRejectsCollision 校验清洗后重复的渠道名被拒绝。
func TestSanitizeChannelsRejectsCollision(t *testing.T) {
	if _, err := sanitizeChannels([]string{"a/b", "a?b"}); err == nil {
		t.Fatal("a/b 与 a?b 清洗后都为 a_b，应报重复")
	}
	if _, err := sanitizeChannels([]string{"a", "a"}); err == nil {
		t.Fatal("完全相同的渠道名应报重复")
	}
	got, err := sanitizeChannels([]string{"huawei", "xiaomi"})
	if err != nil || len(got) != 2 || got[0] != "huawei" || got[1] != "xiaomi" {
		t.Fatalf("正常渠道名不应报错，实际 got=%v err=%v", got, err)
	}
}

// TestWebRunChannelCollisionIs400 校验 Web 多渠道碰撞返回 400。
func TestWebRunChannelCollisionIs400(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.apk")
	payload := uiPayload(t, in, filepath.Join(dir, "out.apk"), []string{"a/b", "a?b"}, map[string]bool{"E4": true})
	code, resp := postRun(t, payload)
	if code != http.StatusBadRequest {
		t.Fatalf("渠道碰撞应返回 400，实际 %d（err=%q）", code, resp.Error)
	}
	if !strings.Contains(resp.Error, "重复") {
		t.Fatalf("错误信息应点明重复，实际: %q", resp.Error)
	}
}

// TestBatchJobsFallback 校验并发度回退链：显式参数 > opts.Jobs > CPU 核数。
func TestBatchJobsFallback(t *testing.T) {
	o := &config.Options{Jobs: 3}
	if got := batchJobs(o, 0); got != 3 {
		t.Fatalf("jobs=0 时应使用 opts.Jobs=3，实际 %d", got)
	}
	if got := batchJobs(o, 2); got != 2 {
		t.Fatalf("显式 jobs=2 应优先，实际 %d", got)
	}
	if got := batchJobs(&config.Options{}, 0); got <= 0 {
		t.Fatalf("无任何指定时应回退到正整数 CPU 核数，实际 %d", got)
	}
}

// TestWebFormNumericDefaultsMatchCLI 守住「勾选即生效」：非零 CLI 默认值必须
// 同时出现在控件的 value 属性与 collect() 的 num() 回退值里。
func TestWebFormNumericDefaultsMatchCLI(t *testing.T) {
	raw, err := os.ReadFile("index.html")
	if err != nil {
		t.Fatalf("读取 index.html 失败: %v", err)
	}
	html := string(raw)
	body := collectBody(t, html)
	cases := []struct {
		id  string
		def int
	}{
		{"class_pad_count", 100},
		{"fake_dex_count", 1},
		{"fake_dex_size", 80000},
		{"junk_top_count", 800},
		{"junk_dir_count", 400},
		{"junk_dir_depth", 16},
		{"junk_meta_count", 20},
		{"zip_atk_count", 150},
		{"min_sdk", 24},
	}
	for _, c := range cases {
		valRe := regexp.MustCompile(`id="` + regexp.QuoteMeta(c.id) + `"[^>]*value="(\d+)"`)
		m := valRe.FindStringSubmatch(html)
		if m == nil {
			t.Errorf("%s 缺少带默认值的控件（value=%d）", c.id, c.def)
			continue
		}
		if m[1] != strconv.Itoa(c.def) {
			t.Errorf("%s 控件默认值为 %s，应为 CLI 默认值 %d", c.id, m[1], c.def)
		}
		numRe := regexp.MustCompile(`num\('` + regexp.QuoteMeta(c.id) + `',\s*` + strconv.Itoa(c.def) + `\)`)
		if !numRe.MatchString(body) {
			t.Errorf("collect() 中 %s 未用 num('%s', %d) 回退到 CLI 默认值", c.id, c.id, c.def)
		}
	}
}

// TestWebSOEncryptMirrorsCLI 校验 Web 的 so_encrypt 与 CLI 一样会带上 C2，
// 从而触发 C2 的依赖校验，而不是绕过校验得到一个能力不完整的产物。
func TestWebSOEncryptMirrorsCLI(t *testing.T) {
	dir := t.TempDir()
	payload := uiPayload(t, filepath.Join(dir, "in.apk"), "", nil, map[string]bool{})
	payload["so_encrypt"] = true
	code, resp := postRun(t, payload)
	if code != http.StatusBadRequest {
		t.Fatalf("so_encrypt 缺少 C2 依赖时应返回 400，实际 %d（err=%q）", code, resp.Error)
	}
	if !strings.Contains(resp.Error, "C2") {
		t.Fatalf("错误信息应提到 C2 依赖，实际: %q", resp.Error)
	}
}
