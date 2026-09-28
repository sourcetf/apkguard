package passes

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"

	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/pipeline"
	"apkguard/internal/zipx"
)

// ---- A2 字符串加密 ----

// encryptString 把 DEX 中的 const-string 常量加密为密文，运行时调用解密方法还原。
//
// 多 DEX 场景的处理方式与 A1 类似：解密器类必须**全局唯一**，
// 否则每个 DEX 都会注入一份同名类，导致 MultiDex 加载时出现
// 「类重复定义」或「不同 DEX 引用不同实现」的问题。
// 因此只有主 DEX 注入解密器，其余 DEX 仅生成对该方法的引用。
type encryptString struct{}

func (encryptString) ID() config.FeatureID { return "A2" }
func (encryptString) In() pipeline.Level   { return pipeline.LevelZip }
func (encryptString) Out() pipeline.Level  { return pipeline.LevelZip }

func (e *encryptString) Run(_ context.Context, art *pipeline.Artifact, opts *config.Options) error {
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
	// 主 DEX 即名字排序最靠前的那个（classes.dex < classes2.dex < ...）。
	sort.Slice(units, func(i, j int) bool {
		return dexNameOrder(units[i].entry.NameString()) < dexNameOrder(units[j].entry.NameString())
	})
	host := units[0]

	key := deriveKey(opts.DexKey, opts.Seed)
	cls := fmt.Sprintf("L%s/Dec;", shellPkgOf(opts))
	minLen := opts.ObfStringMin
	if minLen < 0 {
		minLen = 0
	}

	totalBefore, totalAfter, totalEnc := 0, 0, 0
	ok := 0
	for _, u := range units {
		se := &dex.StringEncrypt{
			Class:      cls,
			MethodName: "a",
			Key:        key,
			MinLen:     minLen,
			// 只有主 DEX 落地解密器类，其余 DEX 仅引用它。
			InjectClass: u == host,
		}
		out, stats, err := dex.RebuildWithStats(u.file, dex.RebuildOptions{StringEncrypt: se})
		if err != nil {
			return fmt.Errorf("重建 %s 失败: %w", u.entry.NameString(), err)
		}
		if err := dex.Verify(out); err != nil {
			return fmt.Errorf("%s 重建后校验失败: %w", u.entry.NameString(), err)
		}
		if err := u.entry.SetData(out, true); err != nil {
			return fmt.Errorf("写回 %s 失败: %w", u.entry.NameString(), err)
		}
		totalBefore += len(u.data)
		totalAfter += len(out)
		totalEnc += stats.StringsEncrypted
		ok++
	}

	art.Note("A2 字符串加密：%d 个 DEX，加密 %d 个字符串，解密器 %s->a（密钥 0x%02x，最短长度 %d）；%d → %d 字节（增加 %d）",
		ok, totalEnc, cls, key, minLen, totalBefore, totalAfter, totalAfter-totalBefore)
	art.Stat("A2.dex", fmt.Sprint(ok))
	art.Stat("A2.strings", fmt.Sprint(totalEnc))
	art.Stat("A2.key", fmt.Sprintf("0x%02x", key))
	art.Stat("A2.grow", fmt.Sprint(totalAfter-totalBefore))
	return nil
}

// dexUnit 是一个已解析的 DEX 条目。
type dexUnit struct {
	entry *zipx.Entry
	data  []byte
	file  *dex.File
}

// ---- A3 常量数组化 ----

// constantArray 把 const-string 常量改写为「方法体内构造 byte[] 再还原」。
//
// 与 A2 的分工：
//   - A2 把明文从字符串池中彻底移除（池里只剩密文），因此 strings/grep 提不到；
//   - A3 保留池中明文，只让字节码不再直接引用它，用于绕过「仅扫描字符串池
//     与常量引用」的静态扫描器，同时不改变字符串池，风险更低。
//
// 两者都改写 const-string，因此实现上必须串行执行且互不重复处理同一条常量：
// 重建流程先跑 A2 再跑 A3，A3 通过 isStringDecryptPattern 识别并跳过已加密的常量。
type constantArray struct{}

func (constantArray) ID() config.FeatureID { return "A3" }
func (constantArray) In() pipeline.Level   { return pipeline.LevelZip }
func (constantArray) Out() pipeline.Level  { return pipeline.LevelZip }

func (c *constantArray) Run(_ context.Context, art *pipeline.Artifact, opts *config.Options) error {
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
	sort.Slice(units, func(i, j int) bool {
		return dexNameOrder(units[i].entry.NameString()) < dexNameOrder(units[j].entry.NameString())
	})
	host := units[0]

	cls := fmt.Sprintf("L%s/Arr;", shellPkgOf(opts))
	minLen := opts.ObfStringMin
	if minLen < 0 {
		minLen = 0
	}

	before, after, total := 0, 0, 0
	ok := 0
	for _, u := range units {
		ca := &dex.ConstantArray{
			Class:       cls,
			MethodName:  "b",
			MinLen:      minLen,
			InjectClass: u == host,
		}
		out, st, err := dex.RebuildWithStats(u.file, dex.RebuildOptions{ConstantArray: ca})
		if err != nil {
			return fmt.Errorf("重建 %s 失败: %w", u.entry.NameString(), err)
		}
		if err := dex.Verify(out); err != nil {
			return fmt.Errorf("%s 重建后校验失败: %w", u.entry.NameString(), err)
		}
		if err := u.entry.SetData(out, true); err != nil {
			return fmt.Errorf("写回 %s 失败: %w", u.entry.NameString(), err)
		}
		before += len(u.data)
		after += len(out)
		total += st.StringsArrayized
		ok++
	}

	art.Note("A3 常量数组化：%d 个 DEX，数组化 %d 个字符串，还原方法 %s->b（最短长度 %d）；%d → %d 字节（增加 %d）",
		ok, total, cls, minLen, before, after, after-before)
	art.Stat("A3.dex", fmt.Sprint(ok))
	art.Stat("A3.strings", fmt.Sprint(total))
	art.Stat("A3.grow", fmt.Sprint(after-before))
	return nil
}

// dexNameOrder 返回 DEX 名字的排序键，使 classes.dex 排在最前。
func dexNameOrder(name string) string {
	low := strings.ToLower(name)
	if low == "classes.dex" {
		return "0"
	}
	return "1" + low
}

// shellPkgOf 返回壳类所在包名（形如 "com/foo"），并去掉首尾的点与斜杠。
//
// 留空时回退到与 CLI 默认值相同的包名：注入类（字符串解密器、Loader、
// 壳 Application）都应落在同一个可配置的包下，避免出现「库调用一套、
// 命令行调用另一套」的不一致。
func shellPkgOf(opts *config.Options) string {
	p := strings.Trim(strings.TrimSpace(opts.ShellPkg), "./")
	p = strings.ReplaceAll(p, ".", "/")
	if p == "" {
		return "com/apkguard/shell"
	}
	return p
}

// deriveKey 从用户密钥或随机种子派生一个字节密钥。
//
// 这里只做「确定性派生」：同样的输入必须得到同样的密钥，
// 以便同一 APK 的多次加固结果可复现（便于排查问题）。
// 真正「不以明文存在、按设备派生」的密钥管理由 C1 在阶段4接管。
func deriveKey(dexKey, seed string) byte {
	src := dexKey
	if src == "" {
		src = seed
	}
	if src == "" {
		src = "apkguard"
	}
	sum := sha256.Sum256([]byte("apkguard/strkey/" + src))
	return sum[0]
}
