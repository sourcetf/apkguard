package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixtureAPK 返回一个可用的测试 APK；找不到时跳过。
//
// 优先用 testdata/sample.apk（仓库内固件，干净检出下也有），
// 其次用刚构建的 testapp 产物。
func fixtureAPK(t *testing.T) string {
	t.Helper()
	for _, p := range []string{
		filepath.Join("..", "..", "..", "testdata", "sample.apk"),
		filepath.Join("..", "..", "..", "testapp", "testapp-signed.apk"),
	} {
		if st, err := os.Stat(p); err == nil && st.Size() > 0 {
			abs, err := filepath.Abs(p)
			if err != nil {
				t.Fatalf("取绝对路径失败: %v", err)
			}
			return abs
		}
	}
	t.Skip("未找到测试 APK（testdata/sample.apk 或 testapp 产物），跳过")
	return ""
}

// channelAssetOf 读取 APK 里的渠道标记（E4 写入的固定条目）。
func channelAssetOf(t *testing.T, apk string) string {
	t.Helper()
	zr, err := zip.OpenReader(apk)
	if err != nil {
		t.Fatalf("打开 %s 失败: %v", apk, err)
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.Name != "assets/apkguard_channel.txt" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("读取渠道文件失败: %v", err)
		}
		defer rc.Close()
		b, err := io.ReadAll(rc)
		if err != nil {
			t.Fatalf("读取渠道文件失败: %v", err)
		}
		return strings.TrimSpace(string(b))
	}
	t.Fatalf("%s 里没有渠道文件 assets/apkguard_channel.txt", apk)
	return ""
}

// uiPayload 复刻 Web 前端 collect() 发出的请求体形状。
//
// 这条形状本身就是被测对象：前端曾把 channels 当字符串发（`""`），
// 而后端 Options.Channels 是 []string，于是**每一次**点「开始加固」
// 都在 json.Decode 阶段失败。这个测试把「前后端字段类型必须一致」钉住。
func uiPayload(t *testing.T, in, out string, channels []string, enable map[string]bool) map[string]any {
	t.Helper()
	enabled := map[string]bool{}
	for _, id := range allFeatureIDs() {
		enabled[id] = enable[id]
	}
	p := map[string]any{
		"enabled": enabled,
		"in":      in,
		"out":     out,
		"ks":      "",
		"ks_pass": "",
		"seed":    "webtest",
	}
	if channels != nil {
		p["channels"] = channels
	}
	return p
}

func allFeatureIDs() []string {
	// 由 handleFeatures 提供的数据源推导，避免手工维护一份会过期的清单。
	rec := httptest.NewRecorder()
	handleFeatures(rec, httptest.NewRequest("GET", "/api/features", nil))
	var body struct {
		Groups []struct {
			Features []struct {
				ID string `json:"id"`
			} `json:"features"`
		} `json:"groups"`
		Total int `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		panic(err)
	}
	var ids []string
	for _, g := range body.Groups {
		for _, f := range g.Features {
			ids = append(ids, f.ID)
		}
	}
	return ids
}

func postRun(t *testing.T, payload any) (int, runResponse) {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("序列化请求失败: %v", err)
	}
	req := httptest.NewRequest("POST", "/api/run", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handleRun(rec, req)

	var resp runResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析响应失败（HTTP %d）：%s\n%v", rec.Code, rec.Body.String(), err)
	}
	return rec.Code, resp
}

// TestFeaturesEndpointExposesAllFeatures 守住功能表本身的完整性。
func TestFeaturesEndpointExposesAllFeatures(t *testing.T) {
	rec := httptest.NewRecorder()
	handleFeatures(rec, httptest.NewRequest("GET", "/api/features", nil))
	var body struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if body.Total != 38 {
		t.Fatalf("功能项总数应为 38，实际 %d", body.Total)
	}
	if n := len(allFeatureIDs()); n != 38 {
		t.Fatalf("分组里的功能项应为 38 个，实际 %d", n)
	}
}

// TestUIPayloadDecodes 是一致性回归：前端形状的请求体必须能解码。
//
// 这里故意使用**空字符串**（界面留空时发送的正是空串）与真实的 enabled 映射，
// 这正是当初失败的那个形状。
func TestUIPayloadDecodes(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "missing.apk") // 文件不存在：只验证解码与参数校验
	payload := uiPayload(t, in, filepath.Join(dir, "out.apk"), nil, map[string]bool{})
	payload["channels"] = []string{} // 界面在多渠道留空时不发送，这里显式给空数组

	code, resp := postRun(t, payload)
	if code != http.StatusOK {
		t.Fatalf("HTTP 码应为 200，实际 %d", code)
	}
	if strings.Contains(resp.Error, "请求体解析失败") {
		t.Fatalf("前端形状的请求体解码失败：%s", resp.Error)
	}
	// 输入不存在，应当在流水线阶段报「读取输入 APK 失败」，而不是静默成功。
	if resp.OK || !strings.Contains(resp.Error, "读取输入 APK 失败") {
		t.Fatalf("期望「读取输入 APK 失败」，实际 ok=%v error=%q", resp.OK, resp.Error)
	}
}

// TestChannelsAsStringIsRejected 记录 channels 的接口契约。
//
// 后端字段是 []string，收到字符串会解码失败——这是**故意的**：与其
// 悄悄把 "a,b" 当成一个渠道名，不如直接报错。前端负责按逗号切分。
func TestChannelsAsStringIsRejected(t *testing.T) {
	dir := t.TempDir()
	payload := uiPayload(t, filepath.Join(dir, "in.apk"), filepath.Join(dir, "out.apk"), nil, map[string]bool{})
	payload["channels"] = "huawei,xiaomi"

	_, resp := postRun(t, payload)
	if !strings.Contains(resp.Error, "请求体解析失败") {
		t.Fatalf("channels 传字符串应当解码失败，实际 error=%q", resp.Error)
	}
}

// TestRunMultiChannel 验证 E4 多渠道确实逐个产出、各自带上自己的渠道标记。
//
// 走真实的流水线（只启用 E4，不启用签名，因此不需要密钥库）：
// 多渠道必须产出多个各自独立的 APK，而不是一个文件里写多个渠道。
func TestRunMultiChannel(t *testing.T) {
	in := fixtureAPK(t)
	dir := t.TempDir()
	out := filepath.Join(dir, "app-protected.apk")

	payload := uiPayload(t, in, out, []string{"huawei", "xiaomi"}, map[string]bool{"E4": true})
	code, resp := postRun(t, payload)
	if code != http.StatusOK {
		t.Fatalf("HTTP 码应为 200，实际 %d", code)
	}
	if !resp.OK {
		t.Fatalf("多渠道加固失败: %s", resp.Error)
	}
	if len(resp.Outs) != 2 {
		t.Fatalf("应产出 2 个渠道包，实际 %d 个（outs=%v）", len(resp.Outs), resp.Outs)
	}
	for i, ch := range []string{"huawei", "xiaomi"} {
		p := resp.Outs[i]
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("渠道包不存在 %s: %v", p, err)
		}
		if !strings.HasSuffix(p, "-"+ch+".apk") {
			t.Errorf("渠道 %s 的产物名不符合约定: %s", ch, p)
		}
		got := channelAssetOf(t, p)
		if got != ch {
			t.Errorf("产物 %s 的渠道标记为 %q，期望 %q", p, got, ch)
		}
	}
	// 单渠道时不应出现 outs（保持旧前端兼容）。
	single := uiPayload(t, in, filepath.Join(dir, "one.apk"), []string{"huawei"}, map[string]bool{"E4": true})
	if _, r := postRun(t, single); !r.OK || len(r.Outs) != 0 {
		t.Fatalf("单渠道不应返回 outs，实际 ok=%v outs=%v err=%s", r.OK, r.Outs, r.Error)
	}
}
