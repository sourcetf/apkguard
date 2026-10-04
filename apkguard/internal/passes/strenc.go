package passes

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	mathrand "math/rand"
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
// 多 DEX 场景的处理方式对齐参考样本：**每个含密文的 DEX 各自注入一份解密器**
// （类名随 seed 随机、DEX 之间两两不同），密钥全包共用一枚。这样：
//   - 任意一个 DEX 单独取出/分析时都自带解密器，不存在跨 DEX 依赖；
//   - 单个 DEX 内只有自己的类名引用，DEX 之间零交叉引用（样本的强指纹）；
//   - 运行期不会出现「类重复定义」（名字互不相同）或「引用不到实现」。
//
// 旧实现只在主 DEX 落地类体、其余 DEX 引用主 DEX 的固定类名，与样本形态不符，
// 且在「单独搬运某个 DEX」的场景下解密器缺失。
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
	// 仍按名字排序遍历，保证随机类名的分配顺序、统计顺序与产物可复现。
	sort.Slice(units, func(i, j int) bool {
		return dexNameOrder(units[i].entry.NameString()) < dexNameOrder(units[j].entry.NameString())
	})

	key, err := deriveKey(opts.DexKey, opts.Seed)
	if err != nil {
		return err
	}
	minLen := opts.ObfStringMin
	if minLen < 0 {
		minLen = 0
	}

	// 解密器类名由 seed 派生（同一 seed 可复现），形态对齐样本
	// （Lcom/rjurepzl/cf/iimlqh;）：随机包1/随机包2/随机短名，全小写。
	// used 先装入**全部 DEX 的全部字符串**（类型描述符也在池内），再逐 DEX
	// 分配互不相同的名字：既避免与既有类/字符串撞车，也保证 DEX 两两不重名。
	rnd := newRand(opts.Seed + "/strenc")
	used := map[string]bool{}
	for _, u := range units {
		for i := uint32(0); i < u.file.NString; i++ {
			if s, err := u.file.String(i); err == nil {
				used[s] = true
			}
		}
	}
	// 解密方法名同样不用 "a" 这类极短固定名：解密器自身用到的字符串会被排
	// 除出加密集合（否则会「解密前先解密」），而 "a" 恰是混淆应用里常见的
	// 短常量/反射成员名，撞车会让那条应用字符串静默留明文。随机名同时更接近
	// 样本的 u() 形态。名字确定性地由 seed 派生，且不与任何既有字符串撞车。
	methodName, err := randomMethodName(newRand(opts.Seed+"/strencmethod"), used)
	if err != nil {
		return err
	}

	totalBefore, totalAfter, totalEnc, totalCls := 0, 0, 0, 0
	ok := 0
	var names []string
	for _, u := range units {
		cls, err := randomDecryptorClass(rnd, used)
		if err != nil {
			return err
		}
		se := &dex.StringEncrypt{
			Class:      cls,
			MethodName: methodName,
			Key:        key,
			MinLen:     minLen,
			// 每个含密文的 DEX 自带一份解密器类本体。
			InjectClass: true,
			// 形态选项：只加密单引用串（默认 false，维持现有强度）。
			SingleRefOnly: opts.ObfStringSingleRefOnly,
		}
		// A7 登记的反射成员名：无论长度与引用次数，一律纳入本 DEX 的加密集合。
		// 键与写入方见 passes/reflect.go 的 reflectionNameKey。
		if v, ok := art.Get(reflectionNameKey).(map[string]bool); ok && len(v) > 0 {
			se.ForceEncrypt = v
		}
		// 先纯分析出本 DEX 的加密目标数：为 0 时既不该注入解密器，也不该
		// 触发无谓的重建（否则会往池里塞一堆用不到的引用）。
		n, err := dex.StringEncryptTargets(u.file, se)
		if err != nil {
			return fmt.Errorf("统计 %s 可加密字符串失败: %w", u.entry.NameString(), err)
		}
		if n == 0 {
			continue
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
		totalCls++
		names = append(names, cls)
		ok++
	}

	// 只输出密钥的 4 字节指纹，绝不输出完整密钥。
	//
	// 日志与统计会随产物一起交付/存档，完整密钥写进去等于公开——
	// 这也是审计曾发现的问题（A2.key 曾等于空口令回退常量）。
	// 指纹足以核对「两次构建是否用了同一把密钥」，但不泄露密钥本身。
	keyFP := fmt.Sprintf("%x", key[:4])
	art.Note("A2 字符串加密：%d 个含密文 DEX，每个自带解密器类（共 %d 个，形如 %s），加密 %d 个字符串（密钥指纹 %s，最短长度 %d，仅单引用串 %v）；%d → %d 字节（增加 %d）",
		ok, totalCls, decryptorNamesBrief(names), totalEnc, keyFP, minLen, opts.ObfStringSingleRefOnly,
		totalBefore, totalAfter, totalAfter-totalBefore)
	art.Stat("A2.dex", fmt.Sprint(ok))
	art.Stat("A2.strings", fmt.Sprint(totalEnc))
	art.Stat("A2.decryptors", fmt.Sprint(totalCls))
	art.Stat("A2.key.fp", keyFP)
	art.Stat("A2.grow", fmt.Sprint(totalAfter-totalBefore))
	return nil
}

// decryptorNamesBrief 把类名列表压缩成日志用示例（最多 3 个，其余以 +N 概括）。
func decryptorNamesBrief(names []string) string {
	if len(names) == 0 {
		return "无"
	}
	out := strings.Join(names[:min(3, len(names))], "、")
	if len(names) > 3 {
		out += fmt.Sprintf(" 等 +%d", len(names)-3)
	}
	return out
}

// randomDecryptorClass 生成一个尚未被任何字符串/类型占用的解密器类描述符。
//
// 生成的名字会写入 used，因此：同一个 DEX 内的全部调用点确定性地共用同一名字；
// 不同 DEX 的名字两两不同（且不与任何 DEX 的既有字符串撞车——跨 DEX 零引用的
// 前提）。类名全部由小写字母组成，不含任何产品/壳包名信息。
func randomDecryptorClass(rnd *mathrand.Rand, used map[string]bool) (string, error) {
	const alpha = "abcdefghijklmnopqrstuvwxyz"
	seg := func(n int) string {
		out := make([]byte, n)
		for i := range out {
			out[i] = alpha[rnd.Intn(len(alpha))]
		}
		return string(out)
	}
	for try := 0; try < 128; try++ {
		cls := "L" + seg(5+rnd.Intn(5)) + "/" + seg(2+rnd.Intn(5)) + "/" + seg(4+rnd.Intn(7)) + ";"
		if !used[cls] {
			used[cls] = true
			return cls, nil
		}
	}
	return "", fmt.Errorf("A2：连续 128 次未能生成未被占用的解密器类名")
}

// randomMethodName 生成一个不与任何既有字符串撞车的解密方法名。
//
// 只用小写字母（合法 DEX 成员名），长度 5~9；生成后写入 used。
func randomMethodName(rnd *mathrand.Rand, used map[string]bool) (string, error) {
	const alpha = "abcdefghijklmnopqrstuvwxyz"
	for try := 0; try < 128; try++ {
		out := make([]byte, 5+rnd.Intn(5))
		for i := range out {
			out[i] = alpha[rnd.Intn(len(alpha))]
		}
		s := string(out)
		if !used[s] {
			used[s] = true
			return s, nil
		}
	}
	return "", fmt.Errorf("A2：连续 128 次未能生成未被占用的解密方法名")
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
	// A2 解密器自身用到的字符串（"SHA-256"、"UTF-8" 等）必须排除。
	//
	// 这类知识只能在 Pass 层传递：A3 是**独立的第二次重建**，那时
	// RebuildOptions.StringEncrypt 为 nil，dex 层无从知道上一轮注入过什么，
	// 于是会把解密器的常量当成应用常量数组化。
	a2Strings := map[string]bool{}
	for _, s := range dex.DecryptorStrings() {
		a2Strings[s] = true
	}

	before, after, total := 0, 0, 0
	ok := 0
	for _, u := range units {
		ca := &dex.ConstantArray{
			Class:       cls,
			MethodName:  "b",
			MinLen:      minLen,
			InjectClass: u == host,
			// A2 注入的解密器在本轮重建里已是「既有类」，它的字符串常量
			// 属于工具自身而非应用，不能被 A3 再数组化（否则解密器反过来
			// 依赖还原器，且破坏「A2 覆盖全部时 A3 不做任何事」的不变量）。
			Skip: func(s string) bool { return a2Strings[s] },
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

// deriveKey 从用户密钥或随机种子派生 32 字节主密钥。
//
// 这里只做「确定性派生」：同样的输入必须得到同样的密钥，
// 以便同一 APK 的多次加固结果可复现（便于排查问题）。
// 真正「不以明文存在、按设备派生」的密钥管理由 C1 在阶段4接管。
//
// 取 SHA-256 的**全部 32 字节**：旧实现只取 sum[0] 一个字节，配合当时
// 仿射密钥流可被单点已知明文攻破；现在密钥流由 SHA-256 派生，
// 密钥宽度必须足够（32 字节），否则暴力枚举 256 种密钥即可解密全部字符串。
// deriveKey 派生 A2 字符串加密的密钥。
//
// 口令（dexKey 或 seed）都为空时**生成随机密钥**，绝不回退到固定常量：
// 常量密钥意味着任何拿到产物的人都能解开全部字符串密文。
func deriveKey(dexKey, seed string) ([32]byte, error) {
	src := dexKey
	if src == "" {
		src = seed
	}
	if src == "" {
		var k [32]byte
		if _, err := rand.Read(k[:]); err != nil {
			return k, fmt.Errorf("生成随机字符串密钥失败: %w", err)
		}
		return k, nil
	}
	return sha256.Sum256([]byte("apkguard/strkey/" + src)), nil
}
