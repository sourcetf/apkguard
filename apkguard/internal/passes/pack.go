package passes

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"apkguard/internal/config"
	"apkguard/internal/dex"
	"apkguard/internal/native"
	"apkguard/internal/pack"
	"apkguard/internal/pipeline"
	"apkguard/internal/zipx"
)

// ---- B1 DEX 整体加密 ----

// sharedKeyPayloads 是「已加密载荷清单」在 Artifact 中的共享键。
//
// B1 写入，B2/B3 读取：壳 Application 与 ClassLoader 接管代码必须知道
// 载荷条目名与解密密钥，才能在运行时把原始 DEX 还原并加载。
const sharedKeyPayloads = "B1.payloads"

// shellPayloads 是 B1 交给后续 Pass 的载荷清单。
type shellPayloads struct {
	// Key 是 AES-256 密钥。
	Key [pack.KeySize]byte
	// Items 是全部载荷（条目名 + 原始 DEX 名 + 密文）。
	Items []pack.Payload
	// Removed 是被移除的原始 DEX 条目名。
	Removed []string
	// MAC 表示本批载荷尾部带 HMAC-SHA256 标签（对应 -payload-mac）。
	//
	// B3 据此决定壳侧是否生成 MAC 校验指令：关闭时壳产物与旧版逐字节一致。
	MAC bool
}

// encryptDex 把原始 DEX 整体加密后存入 assets/，并移除明文 DEX 条目。
//
// 这是加壳的第一道防线：jadx / JEB / apktool 打开产物只能看到壳 DEX，
// 业务代码全部以密文形式躺在 assets/ 中。
//
// 与其它 Pass 的关键区别：B1 会**删除**原始 DEX 条目。因此它必须与
// B2（Application 替换）、B3（ClassLoader 接管）同时启用，
// 否则产物将无法运行——这一约束已由 config.Validate 强制检查。
type encryptDex struct{}

func (encryptDex) ID() config.FeatureID { return "B1" }
func (encryptDex) In() pipeline.Level   { return pipeline.LevelZip }
func (encryptDex) Out() pipeline.Level  { return pipeline.LevelZip }

func (e *encryptDex) Run(_ context.Context, art *pipeline.Artifact, opts *config.Options) error {
	entries := pipeline.FindAll(art, isDexEntry)
	if len(entries) == 0 {
		return fmt.Errorf("未找到任何 DEX 条目")
	}
	// 按名字排序，保证载荷清单与解密顺序稳定可复现。
	sort.Slice(entries, func(i, j int) bool {
		return dexNameOrder(entries[i].NameString()) < dexNameOrder(entries[j].NameString())
	})

	// 收集全部可解析的 DEX 明文。
	var dexes []pack.Dex
	removed := make([]string, 0, len(entries))
	// skipped 记录「名字像 DEX 但解析失败」的条目。
	//
	// 跳过本身是有意为之（A9 的伪 DEX 正是靠解析失败来迷惑工具的），
	// 但必须记账并上报：若某个**真实** DEX 因故解析失败而被留成明文，
	// 那就是一处使用方看不见的防护缺口。
	var skipped []string
	for _, en := range entries {
		data, err := en.Data()
		if err != nil {
			return fmt.Errorf("读取 %s 失败: %w", en.NameString(), err)
		}
		// 伪装文件（magic 不符）不参与加密：它们本就是干扰项，
		// 加密后反而失去「一眼假」的迷惑效果，且会浪费体积。
		if _, err := dex.Parse(data); err != nil {
			skipped = append(skipped, en.NameString())
			continue
		}
		dexes = append(dexes, pack.Dex{Name: en.NameString(), Data: data})
		removed = append(removed, en.NameString())
	}
	if len(dexes) == 0 {
		return fmt.Errorf("没有任何可解析的 DEX 条目可被加密")
	}

	// 密钥来源取决于 C1：启用后由 native 种子 + 签名摘要派生（同一纯函数
	// 在运行时由 libapkguard.so 复算），否则退回内联口令派生。
	key, err := payloadKey(art, opts)
	if err != nil {
		return err
	}
	// -payload-mac 打开时给每份载荷尾部追加 HMAC-SHA256（encrypt-then-MAC）；
	// 关闭时走 Make，产物格式与旧版逐字节一致（不追加任何尾部字节）。
	// 两者必须原子完成：加密与 MAC 共用同一份密钥与同一批载荷，拆开会产生
	// 「加了 tag 却没接线」或反之的不一致窗口。
	var payloads []pack.Payload
	if opts.PayloadMAC {
		payloads, err = pack.MakeMAC(dexes, key, opts.Seed)
	} else {
		payloads, err = pack.Make(dexes, key, opts.Seed)
	}
	if err != nil {
		return fmt.Errorf("生成加密载荷失败: %w", err)
	}

	// 写入载荷条目：必须 Stored（不压缩）。
	// 密文熵值接近 8，Deflate 几乎无收益却会白白消耗运行时解压开销；
	// 更重要的是，载荷需要在运行时被 mmap/读取，保持原样更可控。
	used := map[string]bool{}
	for _, en := range art.Entries() {
		used[en.NameString()] = true
	}
	for _, p := range payloads {
		if used[p.Asset] {
			return fmt.Errorf("载荷条目名与现有条目冲突: %s", p.Asset)
		}
		used[p.Asset] = true
		pipeline.Add(art, zipx.NewStored(p.Asset, p.Blob))
	}

	// 移除明文 DEX。
	removeSet := map[string]bool{}
	for _, n := range removed {
		removeSet[n] = true
	}
	n := pipeline.Remove(art, func(en *zipx.Entry) bool {
		return removeSet[en.NameString()]
	})
	if n != len(removed) {
		return fmt.Errorf("应移除 %d 个明文 DEX，实际移除 %d 个", len(removed), n)
	}

	art.Put(sharedKeyPayloads, &shellPayloads{Key: key, Items: payloads, Removed: removed, MAC: opts.PayloadMAC})

	plainTotal := pack.TotalPlain(payloads)
	blobTotal := pack.TotalBlob(payloads)
	if opts.PayloadMAC {
		art.Note("B1 DEX 整体加密：%d 个 DEX → %d 份 AES-256-SIV 载荷（%d → %d 字节），明文 DEX 已移除；"+
			"每份载荷尾部附 32 字节 HMAC-SHA256（encrypt-then-MAC，绑定原始 DEX 名），壳解密前先校验；载荷名 %s",
			len(payloads), len(payloads), plainTotal, blobTotal, assetSample(payloads))
		art.Stat("B1.mac", "1")
		art.Stat("B1.mac_bytes", fmt.Sprint(pack.TagSize*len(payloads)))
	} else {
		art.Note("B1 DEX 整体加密：%d 个 DEX → %d 份 AES-256-SIV 载荷（%d → %d 字节），明文 DEX 已移除；载荷名 %s",
			len(payloads), len(payloads), plainTotal, blobTotal, assetSample(payloads))
		art.Stat("B1.mac", "0")
	}
	art.Stat("B1.dex", fmt.Sprint(len(payloads)))
	art.Stat("B1.plain", fmt.Sprint(plainTotal))
	art.Stat("B1.blob", fmt.Sprint(blobTotal))
	art.Stat("B1.grow", fmt.Sprint(blobTotal-plainTotal))
	if len(skipped) > 0 {
		art.Stat("B1.skipped", fmt.Sprint(len(skipped)))
		art.Note("B1 提示：%d 个 .dex 条目解析失败、未参与加密（预期为 A9 的伪 DEX；若其中含真实 DEX，则它仍是明文）：%s",
			len(skipped), sampleNames(skipped, 5))
	}
	return nil
}

// sampleNames 返回最多 n 个名字的摘要，超出部分以省略号表示。
func sampleNames(names []string, n int) string {
	if len(names) <= n {
		return strings.Join(names, "、")
	}
	return strings.Join(names[:n], "、") + "…"
}

// sharedKeyPayloadKey 是「本次运行解析出的载荷密钥」在 Artifact 里的键。
const sharedKeyPayloadKey = "pack.payloadkey"

// payloadKey 返回载荷加密所用的密钥，**整个运行期内只解析一次**。
//
// 为什么要缓存：B1（DEX 载荷）与 C2（原生库载荷）必须用同一把密钥，壳才能
// 用一把密钥解两者（B3 里有显式一致性校验）。DexKey 留空时密钥是随机的，
// 若两处各自生成就会得到两把不同的随机密钥——这正是「C2 的 SO 载荷密钥与
// B1 载荷密钥不一致，无法由同一个壳解密」这条报错的来源。同为空的两次
// 随机调用永远不可能相等，所以必须共享同一个解析结果。
func payloadKey(art *pipeline.Artifact, opts *config.Options) ([pack.KeySize]byte, error) {
	if v := art.Get(sharedKeyPayloadKey); v != nil {
		if k, ok := v.([pack.KeySize]byte); ok {
			return k, nil
		}
	}
	k, err := resolvePayloadKey(opts)
	if err != nil {
		return k, err
	}
	art.Put(sharedKeyPayloadKey, k)
	return k, nil
}

// resolvePayloadKey 真正推导密钥。
//
// C1 启用时密钥来自 native 派生函数的同一实现（Go 侧复算），并把
// 「本 APK 的签名证书摘要」并入输入；运行时由 libapkguard.so 用同一公式
// 复算，因此换签名重打包后两端算出的密钥不同，密文解不开。
func resolvePayloadKey(opts *config.Options) ([pack.KeySize]byte, error) {
	if !opts.IsEnabled("C1") {
		// DexKey 留空时由 pack.Key 生成随机密钥，绝不回退到固定常量
		// ——那会让产物等价于明文。
		return pack.Key(opts.DexKey)
	}
	digest, err := expectedSigDigest(opts)
	if err != nil {
		return [pack.KeySize]byte{}, fmt.Errorf("C1 需要确定签名证书摘要: %w", err)
	}
	return native.DeriveKey(digest[:]), nil
}

// assetSample 返回前若干个载荷名，用于报告展示。
func assetSample(ps []pack.Payload) string {
	var names []string
	for i, p := range ps {
		if i >= 3 {
			names = append(names, "…")
			break
		}
		names = append(names, p.Asset)
	}
	return strings.Join(names, "、")
}

// payloadsOf 读取 B1 写入的载荷清单；B1 未启用时返回 nil。
func payloadsOf(art *pipeline.Artifact) *shellPayloads {
	v := art.Get(sharedKeyPayloads)
	if v == nil {
		return nil
	}
	sp, _ := v.(*shellPayloads)
	return sp
}
