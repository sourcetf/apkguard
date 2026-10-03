package passes

import (
	"context"
	"fmt"
	"math/rand"
	"sort"
	"strings"

	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/pipeline"
)

// ---- A19 字符串池垃圾注入 ----

// strJunk 往每个 DEX 的字符串池注入一批「看起来像真实业务常量」的垃圾字符串。
//
// 这些字符串**不被任何指令引用**（走 RebuildOptions.ExtraStrings 的 extra 通道），
// 只出现在字符串池里，因此：
//   - 不改变任何索引引用、不触碰指令流，风险极低；
//   - 静态分析工具（strings/grep/jadx/JEB）的字符串视图会被大量噪音淹没，
//     「哪些常量才是真正的业务配置/接口/密钥」变得难以一眼分辨。
//
// 代价是产物变大：每条字符串约占「string_id 4 字节 + string_data（ULEB 长度 +
// MUTF-8 字节 + 结尾 0）」；中文/emoji 的 MUTF-8 比等长 ASCII 更贵。默认条数
// 取 300 是噪音效果与体积的折中。
//
// 字符串池按 UTF-16 序排序，追加字符串会整体平移既有索引；池接近 16 位上限时
// const-string 可能越界。本轮已落地 const-string 自动加宽（internal/dex/widen.go），
// 但仍**保守跳过**超大池，以控制体积与加宽带来的指令膨胀。
//
// 本 Pass **只定义类型，不在 Registry 注册**：注册由 passes.go 统一维护。
// 建议注册位置在 A19 字符串加密 A2 之后、A9 之前（它需要明文 DEX，且应排在
// A6/A20 之前或之后均可——它不触碰指令，只改池）。
type strJunk struct{}

func (strJunk) ID() config.FeatureID { return "A19" }
func (strJunk) In() pipeline.Level   { return pipeline.LevelZip }
func (strJunk) Out() pipeline.Level  { return pipeline.LevelZip }

const (
	// strJunkDefault 是每个 DEX 默认注入的垃圾字符串条数（StrJunkCount=0 时）。
	strJunkDefault = 300
	// strJunkMax 是单 DEX 的条数上限，防止误配导致体积失控。
	strJunkMax = 4096
	// strJunkPoolLimit 是「池接近 16 位上限」的判定阈值（保留 1024 条余量）。
	strJunkPoolLimit = 0xFFFF - 1024
)

// strJunkPoolTooBig 判断字符串池是否已接近 16 位索引上限。
//
// 该判据同时无条件适用于「已加宽」的场景：即便加宽可用，超大池的排序平移也会
// 让大量既有 const-string 集体加宽，体积与校验开销都不划算，因此保守跳过。
func strJunkPoolTooBig(nString uint32) bool { return nString > strJunkPoolLimit }

func (s *strJunk) Run(_ context.Context, art *pipeline.Artifact, opts *config.Options) error {
	entries := pipeline.FindAll(art, isDexEntry)
	if len(entries) == 0 {
		return fmt.Errorf("未找到任何 DEX 条目")
	}

	units := make([]*dexUnit, 0, len(entries))
	for _, en := range entries {
		data, err := en.Data()
		if err != nil {
			continue
		}
		f, err := dex.Parse(data)
		if err != nil {
			continue // 伪装文件
		}
		units = append(units, &dexUnit{entry: en, data: data, file: f})
	}
	if len(units) == 0 {
		return fmt.Errorf("没有任何 DEX 条目可被解析")
	}
	// 与 A2/A3 一致：主 DEX 优先，顺序稳定便于复现。
	sort.Slice(units, func(i, j int) bool {
		return dexNameOrder(units[i].entry.NameString()) < dexNameOrder(units[j].entry.NameString())
	})

	n := opts.StrJunkCount
	if n <= 0 {
		n = strJunkDefault
	}
	if n > strJunkMax {
		n = strJunkMax
	}

	rng := newRand(opts.Seed)
	// before 是处理前总字节数，delta 是处理带来的**增量**。
	//
	// 曾经把 delta 直接当成「处理后大小」打印，于是日志出现
	// 「5012264 → 22528 字节（增加 -4989736）」这种看起来把 DEX 毁掉的行，
	// 而实际产物是增大的——统计口径错了会误导排查方向，必须如实计算。
	before, delta := 0, 0
	var requested, added, skipped int
	ok := 0
	for _, u := range units {
		req, add, d, skip, err := strJunkUnit(u, rng, n)
		if err != nil {
			return fmt.Errorf("重建 %s 失败: %w", u.entry.NameString(), err)
		}
		if skip {
			skipped++
			art.Note("A19：%s 的字符串池已达 %d 个（16 位索引上限 65535），"+
				"保守跳过垃圾注入——即便 const-string 已支持自动加宽，超大池的排序平移"+
				"也会让大量指令集体加宽，体积与校验开销不划算", u.entry.NameString(), u.file.NString)
			continue
		}
		before += len(u.data)
		delta += d
		requested += req
		added += add
		ok++
	}
	after := before + delta

	art.Note("A19 字符串池垃圾注入：%d 个 DEX，请求 %d 条、实际新增 %d 条（与既有池去重/生成冲突 %d 条），"+
		"跳过 %d 个 DEX（池接近 16 位上限）；%d → %d 字节（增加 %d）",
		ok, requested, added, requested-added, skipped, before, after, after-before)
	art.Stat("A19.dex", fmt.Sprint(ok))
	art.Stat("A19.requested", fmt.Sprint(requested))
	art.Stat("A19.added", fmt.Sprint(added))
	art.Stat("A19.bytes", fmt.Sprint(delta))
	art.Stat("A19.skipped", fmt.Sprint(skipped))
	return nil
}

// strJunkUnit 处理单个 DEX：注入 n 条垃圾字符串。
//
// 返回 requested（交给 ExtraStrings 的条数）、added（字符串池实际增量）、
// bytes（产物体积增量）；skipped=true 表示因池接近上限而整体跳过。
//
// 独立成函数是为了让「池过大即跳过并记账」这条路径可被单元测试直接命中
// （无需真的构造 6.5 万条字符串的 DEX）。
func strJunkUnit(u *dexUnit, rng *rand.Rand, n int) (requested, added, bytes int, skipped bool, err error) {
	if strJunkPoolTooBig(u.file.NString) {
		return 0, 0, 0, true, nil
	}

	// 收集既有字符串，提前避开它们。ExtraStrings 在 rebuild 内部会用 extra 集合
	// 去重，但那会让「请求条数」与「实际新增」出现无法解释的差额；这里先排除，
	// 使 added 尽量逼近 requested，差额只可能来自随机串之间的碰撞。
	existing := make(map[string]bool, u.file.NString)
	for i := uint32(0); i < u.file.NString; i++ {
		if s, e := u.file.String(i); e == nil {
			existing[s] = true
		}
	}
	strs := genStrJunk(rng, n, existing)

	out, _, err := dex.RebuildWithStats(u.file, dex.RebuildOptions{ExtraStrings: strs})
	if err != nil {
		return 0, 0, 0, false, err
	}
	// 只改字符串池，不动任何引用；仍跑结构自检以防去重/排序环节出错。
	if err := dex.Verify(out); err != nil {
		return 0, 0, 0, false, err
	}
	if err := dex.ValidateDescriptors(out); err != nil {
		return 0, 0, 0, false, err
	}
	if err := u.entry.SetData(out, true); err != nil {
		return 0, 0, 0, false, err
	}
	f1, err := dex.Parse(out)
	if err != nil {
		return 0, 0, 0, false, err
	}
	return len(strs), int(f1.NString) - int(u.file.NString), len(out) - len(u.data), false, nil
}

// genStrJunk 生成 n 条**互不重复**、且不与 existing 冲突的垃圾字符串。
//
// attempts 上限防止「n 很大而可用字符组合有限」时空转；返回条数可能略少于 n，
// 调用方据此如实上报 requested。
func genStrJunk(rng *rand.Rand, n int, existing map[string]bool) []string {
	seen := make(map[string]bool, n)
	out := make([]string, 0, n)
	for attempts := 0; len(out) < n && attempts < n*20; attempts++ {
		s := randJunkString(rng)
		if s == "" || existing[s] || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// ---- 垃圾字符串的形态素材 ----

var (
	strJunkSchemes   = []string{"https", "http", "wss"}
	strJunkHosts     = []string{"api.internal", "cdn-edge", "telemetry-svc", "config-center", "push-gateway", "stats-collector", "auth-provider", "media-cache"}
	strJunkKeyWords  = []string{"app", "auth", "billing", "cache", "config", "device", "gateway", "identity", "license", "media", "network", "profile", "push", "sync", "telemetry", "user", "wallet"}
	strJunkPaths     = []string{"v1", "v2", "v3", "api", "internal", "service", "rpc", "edge"}
	strJunkTLDs      = []string{"com", "net", "io", "cn", "co"}
	strJunkErrCodes  = []string{"INVALID_TOKEN", "SIGNATURE_MISMATCH", "NETWORK_TIMEOUT", "CONFIG_NOT_FOUND", "QUOTA_EXCEEDED", "DEVICE_REJECTED", "SESSION_EXPIRED"}
	strJunkCJK       = []string{"配置项", "缓存目录", "设备标识", "会话密钥", "网络超时", "资源校验", "授权回调", "同步状态", "渠道标记", "埋点事件"}
	strJunkEmoji     = []string{"\U0001F512", "\U0001F4E6", "\U00002699\U0000FE0F", "\U0001F6F0", "\U0001F9E9", "\U00002705", "\U0001F4E1", "\U0001F5DD"}
	strJunkSyllables = []string{"al", "be", "cor", "da", "en", "flux", "grav", "hex", "ion", "ka", "lum", "mo", "net", "op", "py", "qua", "ra", "st", "tor", "us", "vec", "w", "xa", "yr", "ze", "sys", "data", "cloud", "sync", "core", "link", "node", "byte", "forge", "prism", "vault"}
)

// randJunkString 生成一条随机形态的垃圾字符串。
//
// 形态刻意多样：URL/端点、配置键名、形似令牌的 hex/base64、错误码、文件路径、
// 中文/emoji 混排。这样基于「形态正则」的过滤会同时误伤真实常量，从而难以使用。
//
// 令牌只是「形似」：长度与字符集受控，既不生成可用凭据，也不会被误认为本项目
// 自己注入的标记（没有固定前缀）。
func randJunkString(rng *rand.Rand) string {
	switch rng.Intn(8) {
	case 0: // URL / 端点
		return fmt.Sprintf("%s://%s.%s.%s/%s/%s?ver=%d",
			strJunkSchemes[rng.Intn(len(strJunkSchemes))],
			strJunkHosts[rng.Intn(len(strJunkHosts))],
			randJunkWord(rng),
			strJunkTLDs[rng.Intn(len(strJunkTLDs))],
			strJunkPaths[rng.Intn(len(strJunkPaths))],
			randJunkWord(rng),
			1+rng.Intn(99))
	case 1: // 配置键名 *_api_key
		return fmt.Sprintf("%s_%s_api_key",
			randJunkWord(rng), strJunkKeyWords[rng.Intn(len(strJunkKeyWords))])
	case 2: // HTTP 头形 token
		return fmt.Sprintf("X-%s-%s-Token",
			upperFirstASCII(randJunkWord(rng)),
			upperFirstASCII(strJunkKeyWords[rng.Intn(len(strJunkKeyWords))]))
	case 3: // hex 形令牌
		return randHex(rng, []int{16, 32, 40, 64}[rng.Intn(4)])
	case 4: // base64 形令牌
		s := randB64(rng, []int{20, 24, 32, 43, 44}[rng.Intn(5)])
		if rng.Intn(2) == 0 {
			s += "="
		}
		return s
	case 5: // 错误码 / 状态标记
		if rng.Intn(2) == 0 {
			return fmt.Sprintf("ERR_%04X", rng.Intn(0x10000))
		}
		return fmt.Sprintf("E%05d_%s", rng.Intn(100000),
			strJunkErrCodes[rng.Intn(len(strJunkErrCodes))])
	case 6: // 文件路径
		return fmt.Sprintf("/data/data/com.%s.%s/files/%s_%d.cache",
			randJunkWord(rng), randJunkWord(rng), randJunkWord(rng), rng.Intn(10000))
	default: // 中文 / emoji 混排
		if rng.Intn(2) == 0 {
			return fmt.Sprintf("%s_%s_%d",
				strJunkCJK[rng.Intn(len(strJunkCJK))], randJunkWord(rng), rng.Intn(10000))
		}
		return fmt.Sprintf("%s%s%s%d",
			strJunkEmoji[rng.Intn(len(strJunkEmoji))],
			strJunkCJK[rng.Intn(len(strJunkCJK))],
			strJunkEmoji[rng.Intn(len(strJunkEmoji))],
			rng.Intn(10000))
	}
}

// randJunkWord 拼接 1~3 个音节，得到「像业务名」的可读词。
func randJunkWord(rng *rand.Rand) string {
	n := 1 + rng.Intn(3)
	var sb strings.Builder
	for i := 0; i < n; i++ {
		sb.WriteString(strJunkSyllables[rng.Intn(len(strJunkSyllables))])
	}
	return sb.String()
}

func randHex(rng *rand.Rand, n int) string {
	const cs = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = cs[rng.Intn(len(cs))]
	}
	return string(b)
}

func randB64(rng *rand.Rand, n int) string {
	const cs = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	b := make([]byte, n)
	for i := range b {
		b[i] = cs[rng.Intn(len(cs))]
	}
	return string(b)
}

// upperFirstASCII 仅把首字节大写。素材全是 ASCII，无需处理多字节。
func upperFirstASCII(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
