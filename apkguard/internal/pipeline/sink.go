package pipeline

import (
	"context"
	"fmt"
	"time"

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

// sharedKeyIDSig 是 v4 签名文件（.idsig）在 Artifact.Shared 中的键。
// Sink 的返回值只有 APK 字节流，而 .idsig 是必须单独落盘的第二个文件，
// 因此通过 Shared 交给调用方。
const sharedKeyIDSig = "sign.idsig"

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

	// ---- resources.arsc 必须以未压缩方式存放 ----
	//
	// 这是 Android 11+（targetSdk ≥ 30）的安装硬要求，违反时报
	//   Failure [-124] ... requires the resources.arsc of installed APKs
	//   to be stored uncompressed and aligned on a 4-byte boundary
	// 注意 zipalign -c 查不出这个问题（它只检查未压缩条目的对齐），
	// 所以必须在收尾处统一兜底，而不是指望各功能项自觉。
	if err := storeResourceTable(art); err != nil {
		return nil, err
	}

	// ---- E2: zipalign ----
	//
	// 用 WriteChecked 而非 Write：生产路径的条目数/字段长度可能触及 ZIP 上限，
	// 静默回绕会产出不可解析的坏包，必须把错误向上返回。
	// 这里记录实际使用的对齐参数并交给签名阶段，避免 v1 重写时又按默认值
	// 强制对齐（那样 E2 关闭时产物仍会被对齐）。
	var raw []byte
	var alignOpts zipx.AlignOptions
	if opts.IsEnabled("E2") {
		alignOpts = zipx.DefaultAlign()
	} else {
		alignOpts = zipx.AlignOptions{Align: 1, SoAlign: 1}
	}
	// 本地头假加密 flag 必须随对齐参数一起传给 zipx：它同时会经
	// sign.Options.Align 流入 v1 签名阶段的重写，逐条目字段在那次
	// 「读中央目录后重写」中会丢失，只有写在选项里的策略能保留到最终产物。
	if opts.ZipLocalFlagDecoy {
		alignOpts.LocalFlagDecoy = true
		art.Note("本地头假加密 flag：AndroidManifest.xml/classes*.dex/resources.arsc 的本地头写入 bit0+bit6（中央目录不变；读本地头的工具会索要口令）")
	}
	raw, err := zipx.WriteChecked(art.Archive, alignOpts)
	if err != nil {
		return nil, fmt.Errorf("重写归档失败: %w", err)
	}
	if opts.IsEnabled("E2") {
		art.Note("E2 zipalign：按 4 字节（.so 16384 字节）对齐重写归档")
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

	// v3 签名块里的 SDK 区间必须覆盖真实设备，否则平台会跳过该 signer；
	// apksig/AOSP 对「区间不含当前 SDK」的处理是抛 NoSupportedSignatures，
	// 而不是悄悄回退到 v2——实测区间为 [0,0] 的包在 API 24 与 API 28 上
	// 都是 `DOES NOT VERIFY`，也就是**根本装不上**。
	//
	// MinSDK/MaxSDK 为 0 表示「调用方没指定」（CLI 的 flag 有默认值，但
	// Web UI 与任何库调用都只给零值）。这里按 apksig 的语义补齐：
	// 下界取 Manifest 声明的 minSdkVersion（读不到则退到 24），上界取 INT_MAX。
	def := sign.DefaultOptions()
	minSDK := uint32(opts.MinSDK)
	if minSDK == 0 {
		if m := manifestMinSDK(art); m > 0 {
			minSDK = uint32(m)
		} else {
			minSDK = def.MinSDK
		}
	}
	maxSDK := uint32(opts.MaxSDK)
	if maxSDK == 0 {
		maxSDK = def.MaxSDK
	}
	if minSDK > maxSDK {
		return nil, fmt.Errorf("v3 签名区间非法：minSdk=%d 大于 maxSdk=%d", minSDK, maxSDK)
	}

	// 签名阶段会新增 MANIFEST.MF / CERT.SF / CERT.RSA 三个条目，它们晚于
	// A14 元数据统一化。启用 A14 时把同一个统一时间戳一并交给签名器，否则
	// 这三个条目会退回 ZIP 的 1980 默认值，在产物里留下一枚独有的重打包
	// 指纹；A14 未启用时则不干预，保持与既有条目各自的原始时间无关。
	var stamp time.Time
	if opts.IsEnabled("A14") {
		stamp, err = opts.UnifiedStamp()
		if err != nil {
			return nil, err
		}
	}

	sr, err := sign.Sign(clean, ks, sign.Options{
		V1:     !opts.NoV1,
		V2:     !opts.NoV2,
		V3:     !opts.NoV3,
		V4:     opts.V4,
		MinSDK: minSDK,
		MaxSDK: maxSDK,
		Stamp:  stamp,
		Align:  alignOpts,
	})
	if err != nil {
		return nil, fmt.Errorf("签名失败: %w", err)
	}
	signed := sr.APK
	// v4 的签名文件（.idsig）是独立于 APK 的一个文件，必须交给调用方落盘——
	// 否则 `-v4` 只是「算了一遍但没交给任何人」，CLI 的帮助文本却写着会生成它。
	// 这里借 Shared 传给 pipeline.Result（Sink 的返回值只有 APK 字节流）。
	if len(sr.IDSig) > 0 {
		art.Put(sharedKeyIDSig, sr.IDSig)
	}

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

// storeResourceTable 确保 resources.arsc 以未压缩方式存放。
//
// 任何改写资源表的功能项（A5/A11 会重写字符串池）都可能把它变成 DEFLATE，
// 而 Android 11+ 的安装期校验明确要求它未压缩——不满足时安装会被直接拒绝，
// 且现象是「装不上」而不是「跑起来崩」，很容易被误判成签名问题。
func storeResourceTable(art *Artifact) error {
	e := Find(art, "resources.arsc")
	if e == nil || e.IsStored() {
		return nil
	}
	data, err := e.Data()
	if err != nil {
		return fmt.Errorf("读取 resources.arsc 失败: %w", err)
	}
	if err := e.SetData(data, false); err != nil {
		return fmt.Errorf("把 resources.arsc 改为未压缩存放失败: %w", err)
	}
	art.Note("resources.arsc 已改为未压缩存放（Android 11+ 的安装要求）")
	return nil
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

	// resources.arsc 必须未压缩（Android 11+ 的安装要求）
	if e := a.Find("resources.arsc"); e != nil && !e.IsStored() {
		return fmt.Errorf("resources.arsc 必须未压缩存放，否则 Android 11+ 会拒绝安装")
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
	// 类型描述符必须合法：改名/注入类都会生成新描述符，出错时 ART 会丢弃
	// 整个 DEX（表现为 ClassNotFoundException），而校验和是自洽的。
	if err := dex.ValidateDescriptors(data); err != nil {
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
