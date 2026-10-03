package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"apkguard/internal/config"
	"apkguard/internal/passes"
	"apkguard/internal/pipeline"
)

//go:embed index.html
var indexHTML string

// maxRequestBody 限制单次 API 请求体大小（1MB）。
//
// 正常请求只是几十个字段的 JSON，1MB 绰绰有余；没有上限时一个恶意/失控的
// 请求体可以轻易耗尽内存。
const maxRequestBody = 1 << 20

// serveWeb 启动内嵌 Web UI。
//
// 界面提供全部功能项的复选框（危险区单独分组并需二次确认），
// 提交后同步执行加固并把产物写回本地。
func serveWeb(addr string, openBrowser bool) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/api/features", handleFeatures)
	mux.HandleFunc("/api/validate", handleValidate)
	mux.HandleFunc("/api/run", handleRun)

	url := "http://" + addr + "/"
	fmt.Printf("图形界面已就绪：%s\n", url)
	if openBrowser {
		go openInBrowser(url)
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           loopbackGuard(mux, addr),
		ReadHeaderTimeout: 10 * time.Second,
	}

	fmt.Printf("apkguard Web UI 已启动: http://%s\n", addr)
	fmt.Println("按 Ctrl+C 退出")
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// handleIndex 返回内嵌的单页界面。
func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, indexHTML)
}

// loopbackGuard 拒绝非本机来源的请求。
//
// 本工具会读取本地密钥库并在本地写文件，因此只应服务于本机浏览器：
//   - Host 必须是回环地址，或正是本次监听地址（避免 DNS rebinding 把
//     外部域名解析到 127.0.0.1 后绕过浏览器同源策略）；
//   - 若浏览器带 Origin（跨站请求），其主机也必须是回环地址。
//
// 这两条能挡住「恶意网页用用户浏览器向本机 API 发请求」的 CSRF 路径。
func loopbackGuard(next http.Handler, listenAddr string) http.Handler {
	listenHost := hostOnly(listenAddr)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := hostOnly(r.Host)
		if !isLoopbackHost(host) && !strings.EqualFold(host, listenHost) {
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": "仅允许本机访问：Host 不是回环地址",
			})
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" && !isLoopbackOrigin(origin) {
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": "拒绝跨站请求：Origin 不是本机来源",
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// mirrorConvenienceSwitches 让 Web 的便捷选项与 CLI 的 buildOptions 行为一致。
//
// -so-encrypt 等价于把 C2 加进启用集合：只设置 Options.SOEncrypt 会绕过 C2 的
// 依赖校验（B1/B2/B3），得到一个「开关打开了但壳能力不完整」的产物。
func mirrorConvenienceSwitches(opts *config.Options) {
	if opts.SOEncrypt {
		opts.SetEnabled("C2", true)
	}
}

// hostOnly 去掉 host 中的端口与方括号，返回裸主机名。
func hostOnly(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.Trim(host, "[]")
}

// isLoopbackHost 判断主机名是否为回环地址（localhost / 127.x / ::1）。
func isLoopbackHost(host string) bool {
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// isLoopbackOrigin 判断 Origin 头是否指向本机。
func isLoopbackOrigin(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return isLoopbackHost(hostOnly(u.Host))
}

// outputRoot 返回本次任务允许写出的根目录。
//
// 契约：产物必须落在输入所在目录内。文件输入时是它所在的目录；目录输入（E5
// 批量）时就是这个目录本身——批量产物默认写在每个 APK 旁边，因此根就是它。
// 这样既禁止了 ../../ 逃逸到任意路径，又保留了默认行为。
func outputRoot(opts *config.Options) (string, error) {
	absIn, err := filepath.Abs(opts.In)
	if err != nil {
		return "", fmt.Errorf("解析输入路径失败: %w", err)
	}
	if fi, err := os.Stat(absIn); err == nil && fi.IsDir() {
		return absIn, nil
	}
	return filepath.Dir(absIn), nil
}

// confineOut 校验并规整输出路径，确保其位于 root 之下。
//
// 拒绝：解析后逃出 root（典型 `out/../ESCAPED.apk`）、跨盘符、绝对路径越界。
func confineOut(root, p string) (string, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("解析输出根目录失败: %w", err)
	}
	abs := p
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(absRoot, abs)
	}
	abs = filepath.Clean(abs)
	rel, err := filepath.Rel(absRoot, abs)
	if err != nil {
		return "", fmt.Errorf("输出路径 %q 不在允许的输出根目录 %q 内", p, absRoot)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("输出路径 %q 逃出了允许的输出根目录 %q（禁止 .. 越界）", p, absRoot)
	}
	return abs, nil
}

// handleFeatures 返回全部功能项定义。
func handleFeatures(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"groups": config.Groups(),
		"total":  len(config.All()),
	})
}

// handleValidate 校验参数组合。
func handleValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "仅支持 POST"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var opts config.Options
	if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求体解析失败: " + err.Error()})
		return
	}
	mirrorConvenienceSwitches(&opts)
	if err := opts.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// runResponse 是加固接口的返回体。
type runResponse struct {
	OK       bool              `json:"ok"`
	Error    string            `json:"error,omitempty"`
	Out      string            `json:"out,omitempty"`
	Outs     []string          `json:"outs,omitempty"`
	Size     int               `json:"size,omitempty"`
	Ran      []string          `json:"ran,omitempty"`
	Notes    []string          `json:"notes,omitempty"`
	Stats    map[string]string `json:"stats,omitempty"`
	Duration string            `json:"duration,omitempty"`
}

// resolveOut 返回未显式指定输出路径时的默认值。
func resolveOut(opts *config.Options) string {
	if opts.Out != "" {
		return opts.Out
	}
	ext := filepath.Ext(opts.In)
	return strings.TrimSuffix(opts.In, ext) + "-protected" + ext
}

// runAndWrite 跑一次完整流水线并把产物写到 out（按需创建目录）。
func runAndWrite(ctx context.Context, opts *config.Options, out string) (int, *pipeline.Result, error) {
	res, err := pipeline.New(passes.Registry(), pipeline.DefaultSink{}).Run(ctx, opts)
	if err != nil {
		return 0, nil, err
	}
	if dir := filepath.Dir(out); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return 0, nil, fmt.Errorf("创建输出目录失败: %w", err)
		}
	}
	if err := os.WriteFile(out, res.APK, 0o644); err != nil {
		return 0, nil, fmt.Errorf("写出 APK 失败: %w", err)
	}
	// v4 的签名文件是独立文件，必须一并落盘（约定 <APK>.idsig）。
	if len(res.IDSig) > 0 {
		if err := os.WriteFile(out+".idsig", res.IDSig, 0o644); err != nil {
			return 0, nil, fmt.Errorf("写出 v4 签名文件失败: %w", err)
		}
	}
	return len(res.APK), res, nil
}

// handleRun 执行一次加固。
//
// 错误码约定：参数/校验类错误 400，流水线等内部错误 500，成功 200。
// 过去一律返回 200 + ok:false，调用方无法区分「请求写错了」与「服务端炸了」。
func handleRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, runResponse{Error: "仅支持 POST"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var opts config.Options
	if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
		writeJSON(w, http.StatusBadRequest, runResponse{Error: "请求体解析失败: " + err.Error()})
		return
	}
	// 与 CLI 的 -keep-rules 保持一致：该字段是**文件路径**，这里读成规则内容。
	if opts.KeepRules != "" {
		data, err := os.ReadFile(opts.KeepRules)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, runResponse{Error: "读取保留白名单失败: " + err.Error()})
			return
		}
		opts.KeepRules = string(data)
	}
	mirrorConvenienceSwitches(&opts)
	if err := opts.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, runResponse{Error: err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Minute)
	defer cancel()

	// E5 目录批量：与 CLI 的 run() 一致，目录输入必须显式启用 E5。
	if fi, err := os.Stat(opts.In); err == nil && fi.IsDir() {
		if !opts.IsEnabled("E5") {
			writeJSON(w, http.StatusBadRequest, runResponse{
				Error: opts.In + " 是目录：批量处理需要显式启用 E5（-enable E5）",
			})
			return
		}
		outs, err := runBatchWeb(&opts)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, runResponse{OK: false, Error: err.Error(), Outs: outs})
			return
		}
		log.Printf("批量加固完成: %s -> %d 个包", opts.In, len(outs))
		writeJSON(w, http.StatusOK, runResponse{OK: true, Out: outs[0], Outs: outs})
		return
	}

	// 输出路径必须落在允许的根目录内（输入所在目录），拒绝 .. 逃逸。
	root, err := outputRoot(&opts)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, runResponse{Error: err.Error()})
		return
	}
	out, err := confineOut(root, resolveOut(&opts))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, runResponse{Error: err.Error()})
		return
	}

	// 多渠道：与 CLI 的 runChannels 一致，每个渠道单独跑完整流程。
	// 不能「签一次再改文件」——v2/v3 签名覆盖整个文件，签完再插入渠道信息会立刻失效。
	if opts.IsEnabled("E4") && len(opts.Channels) > 0 {
		sanitized, err := sanitizeChannels(opts.Channels)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, runResponse{Error: err.Error()})
			return
		}
		ext := filepath.Ext(out)
		base := strings.TrimSuffix(out, ext)
		outs := make([]string, 0, len(opts.Channels))
		var lastRes *pipeline.Result
		var lastSize int
		for i, ch := range opts.Channels {
			child := opts
			child.Channels = []string{ch}
			p := base + "-" + sanitized[i] + ext
			size, res, err := runAndWrite(ctx, &child, p)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, runResponse{Error: "渠道 " + ch + " 产出失败: " + err.Error()})
				return
			}
			outs = append(outs, p)
			lastRes, lastSize = res, size
		}
		log.Printf("多渠道加固完成: %s -> %d 个包 (%v)", opts.In, len(outs), outs)
		writeJSON(w, http.StatusOK, buildRunResponse(lastRes, outs, lastSize))
		return
	}

	size, res, err := runAndWrite(ctx, &opts, out)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, runResponse{Error: err.Error()})
		return
	}
	log.Printf("加固完成: %s -> %s (%d 字节, %d 项)", opts.In, out, size, len(res.Ran))
	writeJSON(w, http.StatusOK, buildRunResponse(res, []string{out}, size))
}

// runBatchWeb 在 Web 请求内执行 E5 目录批量，返回各产物的输出路径。
//
// 复用 CLI 的 listAPKs / batchOutputPath / runBatch，保证两条路径行为一致。
// 失败时仍返回已推导出的路径（可能部分成功），供前端展示。
func runBatchWeb(opts *config.Options) ([]string, error) {
	names, err := listAPKs(opts.In)
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("目录 %s 下没有找到 .apk 文件", opts.In)
	}
	// 若指定了输出目录，它也必须落在允许的根目录（输入目录）内。
	if opts.Out != "" {
		root, err := outputRoot(opts)
		if err != nil {
			return nil, err
		}
		outDir, err := confineOut(root, opts.Out)
		if err != nil {
			return nil, err
		}
		opts.Out = outDir
	}
	outs := make([]string, 0, len(names))
	for _, n := range names {
		outs = append(outs, batchOutputPath(opts.Out, filepath.Join(opts.In, n), opts.In))
	}
	if err := runBatch(opts, opts.Jobs); err != nil {
		return outs, err
	}
	return outs, nil
}

// buildRunResponse 把一次（或一批同渠道）执行结果整理成返回体。
func buildRunResponse(res *pipeline.Result, outs []string, size int) runResponse {
	ran := make([]string, 0, len(res.Ran))
	for _, id := range res.Ran {
		ran = append(ran, string(id))
	}
	out := runResponse{
		OK:       true,
		Out:      outs[0],
		Size:     size,
		Ran:      ran,
		Notes:    res.Notes,
		Stats:    res.Stats,
		Duration: res.Duration.Round(time.Millisecond).String(),
	}
	if len(outs) > 1 {
		out.Outs = outs
	}
	return out
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// openInBrowser 尽最大努力打开系统默认浏览器。
//
// 打不开不算错误：地址已经打印在控制台，用户手动访问即可。
func openInBrowser(url string) {
	time.Sleep(300 * time.Millisecond) // 等监听就绪
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		log.Printf("未能自动打开浏览器（请手动访问 %s）：%v", url, err)
	}
}
