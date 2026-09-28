// Package pack 实现加壳所需的载荷加密与命名。
//
// 加壳的核心是「把原始 DEX 变成不可直接反编译的密文」。本包只负责
// 密码学与命名这两件可独立验证的事，不涉及 Manifest 改写与 ClassLoader 接管
// （那些在 passes 层完成）。
//
// 算法选择说明：采用 AES-256-CBC + PKCS#7，而不是 GCM。原因是壳需要在
// Android 5.0+ 全版本上运行，而 javax.crypto 的 "AES/GCM/NoPadding" 在
// 早期版本上存在兼容问题；CBC 是 Android 全版本都稳定可用的模式。
// 完整性校验由外层 APK 签名（E1）保证，载荷本身不额外做 AEAD。
package pack

import (
	"crypto/aes"
	"crypto/cipher"
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
)

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
	// Blob 是「IV ‖ 密文」。
	Blob []byte
	// Plain 是明文长度，用于报告压缩/膨胀比。
	Plain int
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

// Make 为一批 DEX 生成加密载荷。
//
// 每个 DEX 生成一份独立载荷（B4 需要「按需加载」的粒度）；载荷名由
// seed 与 DEX 名共同派生，因此同一输入的产物完全可复现。
func Make(dexes []Dex, key [KeySize]byte, seed string) ([]Payload, error) {
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
		out = append(out, Payload{
			Asset: name,
			Name:  d.Name,
			Blob:  blob,
			Plain: len(d.Data),
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
