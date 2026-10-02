// Package pack 实现加壳所需的载荷加密与命名。
//
// 加壳的核心是「把原始 DEX 变成不可直接反编译的密文」。本包只负责
// 密码学与命名这两件可独立验证的事，不涉及 Manifest 改写与 ClassLoader 接管
// （那些在 passes 层完成）。
//
// 算法选择说明：采用 AES-256-CBC + PKCS#7，而不是 GCM。原因是壳需要在
// Android 5.0+ 全版本上运行，而 javax.crypto 的 "AES/GCM/NoPadding" 在
// 早期版本上存在兼容问题；CBC 是 Android 全版本都稳定可用的模式。
// 完整性校验默认由外层 APK 签名（E1）保证；可选的载荷 MAC（PayloadMAC）
// 用 HMAC-SHA256 做 encrypt-then-MAC 的纵深防御，见下文 TagSize/MAC。
// 之所以不改成 GCM：本包的 IV 由 IVFromSeed 确定性派生，同一 seed 下
// 每次加固的 IV 完全相同，而 GCM 在同一密钥下复用 IV 会灾难性地泄漏
// 认证密钥（比 CBC 可延展性更糟）；改用 GCM 必须引入随机 IV，会打破
// 「产物可复现」的既有承诺。HMAC-SHA256 自 API 1 起可用，不抬高 minAPI。
package pack

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// 密码学参数。
const (
	// KeySize 是 AES-256 的密钥长度。
	KeySize = 32
	// BlockSize 是 AES 的分组长度，也是 IV 长度。
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
func Key(secret string) [KeySize]byte {
	if secret == "" {
		secret = "apkguard"
	}
	return sha256.Sum256([]byte("apkguard/packkey/" + secret))
}

// RandomIV 生成一个随机 IV（用于需要不可预测性的场景）。
func RandomIV() ([BlockSize]byte, error) {
	var iv [BlockSize]byte
	if _, err := rand.Read(iv[:]); err != nil {
		return iv, fmt.Errorf("pack: 生成随机 IV 失败: %w", err)
	}
	return iv, nil
}

// IVFromSeed 由种子确定性地派生 IV。
//
// 加固产物必须可复现（便于排查问题），因此默认走这条路径；
// IV 不需要保密，可预测性不影响 CBC 的安全性前提。
func IVFromSeed(seed string) [BlockSize]byte {
	sum := sha256.Sum256([]byte("apkguard/iv/" + seed))
	var iv [BlockSize]byte
	copy(iv[:], sum[:BlockSize])
	return iv
}

// pkcs7Pad 按 PKCS#7 填充到分组长度整数倍。
func pkcs7Pad(data []byte, blockSize int) []byte {
	n := blockSize - len(data)%blockSize
	out := make([]byte, len(data)+n)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(n)
	}
	return out
}

// pkcs7Unpad 去除 PKCS#7 填充。
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, fmt.Errorf("pack: 密文长度 %d 不是分组长度 %d 的整数倍", len(data), blockSize)
	}
	n := int(data[len(data)-1])
	if n == 0 || n > blockSize || n > len(data) {
		return nil, fmt.Errorf("pack: 填充字节非法 (%d)", n)
	}
	for _, b := range data[len(data)-n:] {
		if int(b) != n {
			return nil, fmt.Errorf("pack: 填充内容不一致")
		}
	}
	return data[:len(data)-n], nil
}

// Encrypt 用 AES-256-CBC 加密，返回「IV ‖ 密文」。
//
// IV 前置存放，使解密方无需额外传递参数——壳只需要一个 assets 条目即可完成解密。
func Encrypt(plain []byte, key [KeySize]byte, iv [BlockSize]byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("pack: 构造 AES 失败: %w", err)
	}
	padded := pkcs7Pad(plain, BlockSize)
	out := make([]byte, BlockSize+len(padded))
	copy(out, iv[:])
	cipher.NewCBCEncrypter(block, iv[:]).CryptBlocks(out[BlockSize:], padded)
	return out, nil
}

// Decrypt 解密 Encrypt 的产物（「IV ‖ 密文」）。
//
// 该函数是壳侧解密逻辑的参考实现：壳在 Dalvik 层用 javax.crypto 做同样的事，
// 测试通过它来验证「加密结果确实能被正确还原」。
func Decrypt(blob []byte, key [KeySize]byte) ([]byte, error) {
	if len(blob) < BlockSize*2 {
		return nil, fmt.Errorf("pack: 密文过短 (%d 字节)", len(blob))
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("pack: 构造 AES 失败: %w", err)
	}
	iv := blob[:BlockSize]
	body := blob[BlockSize:]
	if len(body)%BlockSize != 0 {
		return nil, fmt.Errorf("pack: 密文长度 %d 非法", len(body))
	}
	out := make([]byte, len(body))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, body)
	return pkcs7Unpad(out, BlockSize)
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
// body 是「IV ‖ 密文」，即 Encrypt 的完整产物；tag 追加在它之后，
// 形成 encrypt-then-MAC 布局，使壳可以先验 MAC 再解密，消除 CBC 填充 oracle。
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
// 它与壳侧 loader.go 的 v + c 两步严格对应：先校验 (name ‖ IV‖密文) 的
// HMAC-SHA256，通过后才做 AES-256-CBC 解密。任何字节被改动（含 IV 与 tag）
// 都会在第一步失败。
func DecryptMAC(blob []byte, key [KeySize]byte, name string) ([]byte, error) {
	if len(blob) < BlockSize+TagSize {
		return nil, fmt.Errorf("pack: 带 MAC 的载荷过短 (%d 字节)", len(blob))
	}
	if !VerifyMAC(blob, key, name) {
		return nil, fmt.Errorf("pack: 载荷 MAC 校验失败")
	}
	return Decrypt(blob[:len(blob)-TagSize], key)
}

// Dex 是一份待加密的 DEX。
type Dex struct {
	// Name 是原始 DEX 的条目名（如 "classes.dex"），仅用于报告与命名派生。
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
	// Blob 是「IV ‖ 密文」，启用 MAC 时尾部再追加 TagSize 字节的 HMAC。
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

// Make 为一批 DEX 生成加密载荷（不含 MAC，格式为「IV ‖ 密文」）。
//
// 每个 DEX 生成一份独立载荷（B4 需要「按需加载」的粒度）；载荷名由
// seed 与 DEX 名共同派生，因此同一输入的产物完全可复现。
//
// PayloadMAC 关闭时必须走这条路径：Blob 与旧版产物逐字节一致，
// 不追加任何尾部字节，壳侧也不会生成 MAC 相关指令。
func Make(dexes []Dex, key [KeySize]byte, seed string) ([]Payload, error) {
	return makePayloads(dexes, key, seed, false)
}

// MakeMAC 与 Make 相同，但为每份载荷追加 HMAC-SHA256 标签，
// 格式变为「IV ‖ 密文 ‖ Tag」（encrypt-then-MAC）。
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

		blob, err := Encrypt(d.Data, key, IVFromSeed(seed+"/"+d.Name))
		if err != nil {
			return nil, err
		}
		if withMAC {
			// encrypt-then-MAC：tag 覆盖 name 与「IV ‖ 密文」整体。
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
