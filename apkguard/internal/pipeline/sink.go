package pipeline

import (
	"context"
	"fmt"

	"apkguard/internal/axml"
	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/keystore"
	"apkguard/internal/sign"
	"apkguard/internal/zipx"
)

// DefaultSink 是标准的收尾步骤：对齐 → 签名 → 自检。
//
// 顺序不可颠倒：v2+ 签名覆盖整个文件，签名后再做任何字节修改都会使签名失效。
type DefaultSink struct{}

// Finish 实现 Sink 接口。
func (DefaultSink) Finish(ctx context.Context, art *Artifact, opts *config.Options) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// v1 与 v2/v3 的覆盖面不同：Android 7.0（API 24）以下的系统只认 v1 的
	// JAR 签名。若 APK 自己声明支持更低版本、却又禁用了 v1，产物在那些
	// 设备上根本装不上——这是必须提前拦住的组合，而不是等装机失败才发现。
	if opts.IsEnabled("E1") && opts.NoV1 {
		if m := manifestMinSDK(art); m < 24 {
			return nil, fmt.Errorf(
				"已禁用 v1 签名（-no-v1），但 AndroidManifest.xml 声明的 minSdkVersion=%d：Android 7.0 以下的系统只认 v1 签名，产物在这些设备上无法安装；请去掉 -no-v1，或确认不再支持 API 24 以下", m)
		}
	}

	// ---- E2: zipalign ----
	var raw []byte
	if opts.IsEnabled("E2") {
		raw = zipx.Write(art.Archive, zipx.DefaultAlign())
		art.Note("E2 zipalign：按 4 字节（.so 4096 字节）对齐重写归档")
	} else {
		raw = zipx.Write(art.Archive, zipx.AlignOptions{Align: 1, SoAlign: 1})
	}

	// ---- E1: 签名 ----
	if !opts.IsEnabled("E1") {
		art.Note("E1 签名：未启用，输出未签名 APK")
		return raw, nil
	}

	ks, err := keystore.Load(opts.KS, opts.KSPass, opts.KeyPass, opts.KSType, opts.Alias)
	if err != nil {
		return nil, fmt.Errorf("加载密钥库失败: %w", err)
	}

	// 输入可能带有旧签名块，必须先剥离，否则新签名块的插入位置会错乱。
	clean, err := zipx.StripSigningBlock(raw)
	if err != nil {
		return nil, fmt.Errorf("剥离旧签名块失败: %w", err)
	}

	sr, err := sign.Sign(clean, ks, sign.Options{
		V1:     !opts.NoV1,
		V2:     !opts.NoV2,
		V3:     !opts.NoV3,
		V4:     opts.V4,
		MinSDK: uint32(opts.MinSDK),
		MaxSDK: uint32(opts.MaxSDK),
	})
	if err != nil {
		return nil, fmt.Errorf("签名失败: %w", err)
	}
	signed := sr.APK

	var schemes []string
	if !opts.NoV1 {
		schemes = append(schemes, "v1")
	}
	if !opts.NoV2 {
		schemes = append(schemes, "v2")
	}
	if !opts.NoV3 {
		schemes = append(schemes, "v3")
	}
	if opts.V4 {
		schemes = append(schemes, "v4")
	}
	// 别名只有 JKS 才有意义（PKCS12 用公文包口令定位条目，不暴露别名），
	// 因此为空时改为报告来源类型，避免出现「（别名 ）」这样的空占位。
	if ks.Alias != "" {
		art.Note("E1 签名：%s（%s 密钥库，别名 %s）", join(schemes, "+"), ks.Source, ks.Alias)
	} else {
		art.Note("E1 签名：%s（%s 密钥库）", join(schemes, "+"), ks.Source)
	}

	// ---- E3: 加固后自检 ----
	if opts.IsEnabled("E3") {
		if err := selfCheck(signed, art); err != nil {
			return nil, fmt.Errorf("E3 自检未通过: %w", err)
		}
		art.Note("E3 自检：归档结构、DEX 校验和、签名块均通过")
	}

	return signed, nil
}

// selfCheck 校验最终 APK 的结构完整性。
func selfCheck(data []byte, art *Artifact) error {
	a, err := zipx.Read(data)
	if err != nil {
		return fmt.Errorf("归档无法重新解析: %w", err)
	}
	if len(a.Entries) == 0 {
		return fmt.Errorf("归档条目为空")
	}

	// 必需的入口文件
	for _, want := range []string{"AndroidManifest.xml"} {
		if a.Find(want) == nil {
			return fmt.Errorf("缺少必需条目 %s", want)
		}
	}

	// 每个 .dex 条目的头部与校验和
	ndex := 0
	for _, e := range a.Entries {
		if !isDexName(e.NameString()) {
			continue
		}
		ndex++
		if err := checkDexEntry(e); err != nil {
			return fmt.Errorf("条目 %s 校验失败: %w", e.NameString(), err)
		}
	}
	if ndex == 0 {
		return fmt.Errorf("归档中没有任何 DEX 条目")
	}
	art.Stat("E3.dex_count", fmt.Sprint(ndex))

	// 签名块可识别
	sec, err := zipx.Split(data)
	if err != nil {
		return fmt.Errorf("签名块解析失败: %w", err)
	}
	if !sec.HasSigningBlock() {
		return fmt.Errorf("未找到 APK 签名块")
	}
	art.Stat("E3.signing_block", fmt.Sprint(len(sec.SigningBlock)))
	return nil
}

// isDexName 判断条目名是否为 classes*.dex。
func isDexName(name string) bool {
	if len(name) < 11 || name[:7] != "classes" {
		return false
	}
	return len(name) > 4 && name[len(name)-4:] == ".dex"
}

// checkDexEntry 校验一个 DEX 条目的头部与校验和自洽。
func checkDexEntry(e *zipx.Entry) error {
	data, err := e.Data()
	if err != nil {
		return err
	}
	if len(data) < 8 || string(data[:4]) != "dex\n" {
		return fmt.Errorf("magic 非法")
	}
	if err := dex.Verify(data); err != nil {
		return err
	}
	return nil
}

func join(ss []string, sep string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += sep
		}
		out += s
	}
	return out
}

// manifestMinSDK 读取 AndroidManifest.xml 中声明的 minSdkVersion。
//
// 返回值 0 表示「读不到」：Manifest 缺失、解析失败，或未声明 <uses-sdk>。
// 这三种情况按 Android 的默认语义都等同于「支持到 API 1」，因此调用方
// 把 0 视作「低于任何有意义的阈值」即可。
func manifestMinSDK(art *Artifact) int {
	e := Find(art, "AndroidManifest.xml")
	if e == nil {
		return 0
	}
	data, err := e.Data()
	if err != nil {
		return 0
	}
	f, err := axml.Parse(data)
	if err != nil {
		return 0
	}
	uses := f.FindElement("uses-sdk")
	if uses == nil {
		return 0
	}
	a := uses.Attr("minSdkVersion")
	if a == nil {
		return 0
	}
	// minSdkVersion 可能是十进制整数（常见）或字符串（少数构建工具写出）。
	if a.DataType == axml.TypeIntDec {
		return int(a.Data)
	}
	n := 0
	for _, c := range a.RawValue {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}
