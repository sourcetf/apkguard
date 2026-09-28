package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
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
		Handler:           mux,
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
	var opts config.Options
	if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求体解析失败: " + err.Error()})
		return
	}
	if err := opts.Validate(); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// runResponse 是加固接口的返回体。
type runResponse struct {
	OK       bool              `json:"ok"`
	Error    string            `json:"error,omitempty"`
	Out      string            `json:"out,omitempty"`
	Size     int               `json:"size,omitempty"`
	Ran      []string          `json:"ran,omitempty"`
	Notes    []string          `json:"notes,omitempty"`
	Stats    map[string]string `json:"stats,omitempty"`
	Duration string            `json:"duration,omitempty"`
}

// handleRun 执行一次加固。
func handleRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, runResponse{Error: "仅支持 POST"})
		return
	}
	var opts config.Options
	if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
		writeJSON(w, http.StatusBadRequest, runResponse{Error: "请求体解析失败: " + err.Error()})
		return
	}
	if err := opts.Validate(); err != nil {
		writeJSON(w, http.StatusOK, runResponse{Error: err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Minute)
	defer cancel()

	res, err := pipeline.New(passes.Registry(), pipeline.DefaultSink{}).Run(ctx, &opts)
	if err != nil {
		writeJSON(w, http.StatusOK, runResponse{Error: err.Error()})
		return
	}

	out := opts.Out
	if out == "" {
		ext := filepath.Ext(opts.In)
		out = strings.TrimSuffix(opts.In, ext) + "-protected" + ext
	}
	if err := os.WriteFile(out, res.APK, 0o644); err != nil {
		writeJSON(w, http.StatusOK, runResponse{Error: "写出 APK 失败: " + err.Error()})
		return
	}

	ran := make([]string, 0, len(res.Ran))
	for _, id := range res.Ran {
		ran = append(ran, string(id))
	}
	log.Printf("加固完成: %s -> %s (%d 字节, %d 项)", opts.In, out, len(res.APK), len(res.Ran))

	writeJSON(w, http.StatusOK, runResponse{
		OK:       true,
		Out:      out,
		Size:     len(res.APK),
		Ran:      ran,
		Notes:    res.Notes,
		Stats:    res.Stats,
		Duration: res.Duration.Round(time.Millisecond).String(),
	})
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
