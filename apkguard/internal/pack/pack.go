// Package pack 实现加壳所需的载荷加密与命名。
//
// 加壳的核心是「把原始 DEX 变成不可直接反编译的密文」。本包只负责
// 密码学与命名这两件可独立验证的事，不涉及 Manifest 改写与 ClassLoader 接管
// （那些在 passes 层完成）。
//
// 算法选择说明：载荷加密采用 **AES-256-SIV**（RFC 5297，AES-SIV-CMAC-512），
// 输出为「SIV 标签(16B) ‖ AES-CTR 密文」，密文长度与明文相同（无填充），
// 详见 siv.go。
//
// 为什么是 SIV 而不是 GCM/OCB：（1）本方案承诺「同一 seed + 同一输入产出
// 逐字节相同的产物」且有测试钉住，因此 nonce/IV 必须是确定性派生甚至根本
// 不存在——而 GCM/OCB 在同一密钥下复用 nonce 会灾难性地泄漏认证密钥（GHASH
// 密钥可被恢复），确定性 nonce 对它们是致命伤；（2）SIV 恰好是为「nonce 可
// 预测/可能复用」的场景设计的（nonce-misuse resistant）：即使重复，也只泄漏
// 「相同明文 + 相同 AD」这一事实，完整性不受影响；（3）SIV 自带完整性——
// 解密时重算 S2V 并常量时间比较，篡改密文/标签/AD 一律失败，不再依赖填充
// 校验这种非完整性检查。可选的载荷 MAC（PayloadMAC）继续保留：HMAC-SHA256
// 对「name ‖ SIV‖密文」做 encrypt-then-MAC，作为外层纵深防御并绑定逻辑名。
//
// 密钥：主密钥 32 字节（Key(secret) 派生，C1 生效时来自 native），再域分离
// 成 K1（S2V/CMAC）与 K2（CTR）各 32 字节，见 sivDeriveKeys。
package pack

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// 密码学参数。
const (
	// KeySize 是 AES-256 的密钥长度（SIV 的两把子密钥各自再由它派生）。
	KeySize = 32
	// BlockSize 是 AES 的分组长度，也是 SIV 标签长度。
	BlockSize = 16
	// TagSize 是 HMAC-SHA256 校验标签的长度。
	TagSize = 32
)

// macDomain 是 MAC 密钥的域分离串。
//
// MAC key 不使用加密 key 本身，而是 SHA-256(key ‖ macDomain) 派生：
// 这是密码学最佳实践，确保「加密密钥」与「认证密钥」是两把独立的密钥，
// 将来更换 AES 密钥用途时不会牵连。壳侧 loader.go 用完全相同的公式现算，
// 两处的域串必须逐字节一致（有对拍守卫测试）。
const macDomain = "apkguard/payload-mac"

// Key 从口令派生 AES-256 密钥。
//
// 这里只做确定性派生（SHA-256）：同一口令必须得到同一密钥，
// 以便同一 APK 的多次加固结果可复现。「密钥不以明文存在、按设备派生」
// 由 C1（native 密钥派生）在阶段4接管，届时口令本身也会被消除。
//
// secret 为空时**生成随机密钥**，绝不回退到固定常量：固定常量意味着任何
// 拿到产物的人都能用公开可算的密钥解出载荷，等于明文交付。
func Key(secret string) ([KeySize]byte, error) {
	if secret == "" {
		return RandomKey()
	}
	return sha256.Sum256([]byte("apkguard/packkey/" + secret)), nil
}

// RandomKey 生成一个随机 AES-256 密钥。
func RandomKey() ([KeySize]byte, error) {
	var k [KeySize]byte
	if _, err := rand.Read(k[:]); err != nil {
		return k, fmt.Errorf("pack: 生成随机密钥失败: %w", err)
	}
	return k, nil
}

// RandomIV 生成一个随机 IV（CBC 时代的遗留辅助，载荷加密已不使用）。
//
// 仅保留给仍按「IV 参数」调用 Encrypt 的调用方（该参数已被忽略），
// 以及需要随机字节的其它场景。
func RandomIV() ([BlockSize]byte, error) {
	var iv [BlockSize]byte
	if _, err := rand.Read(iv[:]); err != nil {
		return iv, fmt.Errorf("pack: 生成随机 IV 失败: %w", err)
	}
	return iv, nil
}

// IVFromSeed 由种子确定性地派生 IV。
//
// SIV 不需要 IV，载荷路径已不再使用本函数；保留是因为仍有调用方把它
// 传给 Encrypt 的 iv 参数（该参数现被忽略），避免无谓的跨包改动。
func IVFromSeed(seed string) [BlockSize]byte {
	sum := sha256.Sum256([]byte("apkguard/iv/" + seed))
	var iv [BlockSize]byte
	copy(iv[:], sum[:BlockSize])
	return iv
}

// Encrypt 用 AES-256-SIV 加密，返回「SIV 标签(16B) ‖ AES-CTR 密文」。
//
// 密文长度等于明文长度（不做任何填充）；解密必须校验 SIV（见 Decrypt）。
// iv 参数是 CBC 时代的遗物，为兼容既有调用方而保留并被**忽略**：SIV 不需要
// IV/nonce，同一 key + 同一明文永远得到逐字节相同的密文（确定性的可复现保证）。
//
// 本函数使用**零长度 AD 组件**（等价于 EncryptNamed(name="")），S2V 组件为
// ["", 明文]；需要把载荷与逻辑名绑定时用 EncryptNamed——载荷路径
// （Make/MakeMAC/C2）正是走那条路径。壳侧统一以 ad 字节数组为参数
// （无名字时传空数组）即可与两侧对上。
func Encrypt(plain []byte, key [KeySize]byte, iv [BlockSize]byte) ([]byte, error) {
	_ = iv // 保留参数仅为签名兼容；SIV 不使用 IV
	return EncryptNamed(plain, key, "")
}

// EncryptNamed 与 Encrypt 相同，但把逻辑名 name 作为 S2V 的 AD 组件。
//
// 绑定名字使不同载荷的密文无法互换、也无法在不知道名字的情况下伪造：
// 即使外层 HMAC 被关闭，SIV 校验也会拒绝用错误名字解密。
// name 取「原始逻辑名」——B1/B6 的 Payload.Name（原始 DEX 名）、
// C2 的原始库名，而不是容器化/B8 改名后的 assets 条目名。
func EncryptNamed(plain []byte, key [KeySize]byte, name string) ([]byte, error) {
	k1, k2 := sivDeriveKeys(key)
	return sivSeal(k1[:], k2[:], [][]byte{[]byte(name), plain})
}

// Decrypt 解密 Encrypt 的产物（「SIV 标签(16B) ‖ CTR 密文」）。
//
// 该函数是壳侧解密逻辑的参考实现（壳在 Dalvik/native 层做同样的事）：
// 先用标签作 CTR 计数器初值解出明文，再重算 S2V 并常量时间比较，不一致
// 返回错误——不存在「只解密不校验」的用法。
func Decrypt(blob []byte, key [KeySize]byte) ([]byte, error) {
	return DecryptNamed(blob, key, "")
}

// DecryptNamed 解密 EncryptNamed 的产物（AD = 逻辑名）。
//
// 与 EncryptNamed 配对；DecryptMAC 内部也走这条路径（先验 HMAC 再验 SIV）。
func DecryptNamed(blob []byte, key [KeySize]byte, name string) ([]byte, error) {
	k1, k2 := sivDeriveKeys(key)
	return sivOpen(k1[:], k2[:], [][]byte{[]byte(name)}, blob)
}

// MacKey 从 AES 密钥做域分离派生出 HMAC-SHA256 的密钥。
//
// 公式：SHA-256(key ‖ "apkguard/payload-mac")。
// 壳侧（loader.go 的 v 方法）用 MessageDigest 现算同一公式，因此这里
// 不需要把派生结果内联进字节码，也不新增 JNI 符号。
func MacKey(key [KeySize]byte) [32]byte {
	h := sha256.New()
	h.Write(key[:])
	h.Write([]byte(macDomain))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// MAC 计算载荷的 HMAC-SHA256 标签，输入为 (name ‖ body)。
//
// **必须绑定原始 DEX 名（Payload.Name）而不是资产条目名（Payload.Asset）**：
// B8（载荷容器化）在 B1 之后会重命名 Asset，若用 Asset 做 MAC 输入，
// 容器化后的合法产物在壳侧算出的 MAC 与打包时不一致，会启动即失败。
//
// body 是「SIV 标签 ‖ 密文」，即 Encrypt/EncryptNamed 的完整产物；tag 追加
// 在它之后，形成 encrypt-then-MAC 布局，使壳可以先验 MAC 再解密。SIV 本身
// 已能检测篡改，这层 HMAC 是纵深防御并额外绑定逻辑名。
func MAC(body []byte, key [KeySize]byte, name string) []byte {
	mk := MacKey(key)
	m := hmac.New(sha256.New, mk[:])
	m.Write([]byte(name))
	m.Write(body)
	return m.Sum(nil)
}

// VerifyMAC 常量时间地校验带 tag 的载荷。
//
// 返回 false 的三种情形（长度不足、tag 不匹配、name/key 不符）对外表现一致，
// 不向调用方区分，避免成为 oracle。
func VerifyMAC(blob []byte, key [KeySize]byte, name string) bool {
	if len(blob) < BlockSize+TagSize {
		return false
	}
	body := blob[:len(blob)-TagSize]
	tag := blob[len(blob)-TagSize:]
	return hmac.Equal(tag, MAC(body, key, name))
}

// DecryptMAC 是「先验 MAC 再解密」的参考实现，供测试与跨语言对拍。
//
// 它与壳侧 loader.go 的 v + c 两步严格对应：先校验 (name ‖ SIV‖密文) 的
// HMAC-SHA256，通过后才做 AES-SIV 解密（SIV 自身还会再校验一次标签）。
// name 同时参与 HMAC 与 S2V 的 AD：改 name、改 tag 或改任何密文字节都会失败。
func DecryptMAC(blob []byte, key [KeySize]byte, name string) ([]byte, error) {
	if len(blob) < BlockSize+TagSize {
		return nil, fmt.Errorf("pack: 带 MAC 的载荷过短 (%d 字节)", len(blob))
	}
	if !VerifyMAC(blob, key, name) {
		return nil, fmt.Errorf("pack: 载荷 MAC 校验失败")
	}
	return DecryptNamed(blob[:len(blob)-TagSize], key, name)
}

// Dex 是一份待加密的 DEX。
type Dex struct {
	// Name 是原始 DEX 的条目名（如 "classes.dex"）：用于报告、载荷名派生，
	// 并作为 SIV 的 AD 与（启用 MAC 时）HMAC 的绑定输入。
	Name string
	// Data 是 DEX 明文。
	Data []byte
}

// Payload 是一份加密后的载荷。
type Payload struct {
	// Asset 是它在 APK 中的条目名（形如 "assets/res_3f2a1b8c.bin"）。
	Asset string
	// Name 是原始 DEX 名。
	Name string
	// Blob 是「SIV 标签(16B) ‖ CTR 密文」，启用 MAC 时尾部再追加
	// TagSize 字节的 HMAC。密文与明文等长，无填充。
	Blob []byte
	// Plain 是明文长度，用于报告压缩/膨胀比。
	Plain int
	// Tagged 表示 Blob 尾部是否带 HMAC 标签（与 PayloadMAC 开关一致）。
	//
	// 单独记录而不是靠 len(Blob) 推断：B3 必须把「本批次是否带 tag」明确
	// 传给壳，否则壳会对未带 tag 的载荷做校验而误杀合法产物。
	Tagged bool
}

// assetWords 是载荷文件名的「伪装词」。
//
// 载荷名不应暴露用途，因此从常见资源词里挑一个再拼随机十六进制，
// 使条目名看起来像普通资源文件。
var assetWords = []string{
	"config", "data", "index", "cache", "meta", "base", "res", "assets",
}

// assetExts 是载荷的伪装扩展名。
var assetExts = []string{".bin", ".dat", ".res", ".pack"}

// AssetName 依据种子与 DEX 名派生一个稳定且不重复的载荷条目名。
func AssetName(seed, dexName string) string {
	sum := sha256.Sum256([]byte("apkguard/asset/" + seed + "/" + dexName))
	word := assetWords[int(sum[0])%len(assetWords)]
	ext := assetExts[int(sum[1])%len(assetExts)]
	return "assets/" + word + "_" + hex.EncodeToString(sum[2:6]) + ext
}

// Make 为一批 DEX 生成加密载荷（不含 MAC，格式为「SIV 标签 ‖ CTR 密文」）。
//
// 每个 DEX 生成一份独立载荷（B4 需要「按需加载」的粒度）；载荷名由
// seed 与 DEX 名共同派生，因此同一输入的产物完全可复现。
//
// S2V 的 AD 绑定原始 DEX 名（d.Name），与 DecryptNamed / DecryptMAC 的
// name 参数一致。
func Make(dexes []Dex, key [KeySize]byte, seed string) ([]Payload, error) {
	return makePayloads(dexes, key, seed, false)
}

// MakeMAC 与 Make 相同，但为每份载荷追加 HMAC-SHA256 标签，
// 格式变为「SIV 标签 ‖ CTR 密文 ‖ Tag」（encrypt-then-MAC）。
//
// 每份载荷因此多 32 字节（B3 的 LoaderItem.Size 直接取 len(Blob)，自动含 tag）。
func MakeMAC(dexes []Dex, key [KeySize]byte, seed string) ([]Payload, error) {
	return makePayloads(dexes, key, seed, true)
}

// makePayloads 是 Make/MakeMAC 的公共实现。
func makePayloads(dexes []Dex, key [KeySize]byte, seed string, withMAC bool) ([]Payload, error) {
	out := make([]Payload, 0, len(dexes))
	used := map[string]bool{}
	for _, d := range dexes {
		if len(d.Data) == 0 {
			continue
		}
		name := AssetName(seed, d.Name)
		// 极低概率的哈希碰撞：加后缀直到唯一
		for i := 1; used[name]; i++ {
			name = AssetName(seed+fmt.Sprint(i), d.Name)
		}
		used[name] = true

		blob, err := EncryptNamed(d.Data, key, d.Name)
		if err != nil {
			return nil, err
		}
		if withMAC {
			// encrypt-then-MAC：tag 覆盖 name 与「SIV‖密文」整体。
			//
			// 这段字节序是壳侧 v 的输入（先 name 后 body），改动顺序会
			// 让合法产物在真机上启动即终止，且只有装机才能发现。
			blob = append(blob, MAC(blob, key, d.Name)...)
		}
		out = append(out, Payload{
			Asset:  name,
			Name:   d.Name,
			Blob:   blob,
			Plain:  len(d.Data),
			Tagged: withMAC,
		})
	}
	return out, nil
}

// TotalBlob 返回全部载荷的密文总长度。
func TotalBlob(ps []Payload) int {
	n := 0
	for _, p := range ps {
		n += len(p.Blob)
	}
	return n
}

// TotalPlain 返回全部载荷的明文总长度。
func TotalPlain(ps []Payload) int {
	n := 0
	for _, p := range ps {
		n += p.Plain
	}
	return n
}
