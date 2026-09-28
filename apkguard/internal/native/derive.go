// Package native 承载 C1（密钥 native 派生）所需的原生库与派生算法。
//
// 设计要点：载荷密钥 = SHA-256(种子 ‖ 签名证书摘要)。
//
//   - **种子只存在于 native 库中**。Java/DEX 侧看不到它，加固产物里
//     唯一的密钥来源就是 libapkguard.so。这直接修掉了参考样本「所有密钥
//     硬编码在 Java 层、可一次性完整脱壳」的缺陷。
//   - **签名摘要参与派生**。重打包者必然更换签名证书，于是运行时算出的
//     密钥与加密时不同，密文载荷在密码学层面无法解开——这比「检测到异常
//     就退出」更彻底，不存在跳过检测的绕过路径。
//
// 一致性要求：本文件的 Go 实现与 native/apkguard.c 的 C 实现必须逐字节一致，
// 否则产物会在自己手上解不开载荷。两侧的种子常量与算法由
// TestDeriveMatchesNativeC 交叉验证（用 TCC 直接编译运行 C 代码对拍）。
package native

import (
	"crypto/sha256"
)

// seedObf / seedMask 与 native/apkguard.c 中的 AG_SEED_OBF / AG_SEED_MASK
// 必须完全一致。种子以掩码异或形式存放，避免在二进制里以明文常量出现。
var (
	seedObf = [32]byte{
		0x1f, 0x7c, 0x2e, 0x91, 0x05, 0xb8, 0x4d, 0x33,
		0xa2, 0x6e, 0xc5, 0x10, 0x8b, 0x47, 0xfa, 0x29,
		0x64, 0xd3, 0x0c, 0x95, 0x38, 0xe1, 0x5a, 0xb6,
		0x0d, 0x82, 0xf7, 0x43, 0xce, 0x19, 0xa4, 0x70,
	}
	seedMask = [8]byte{0xa5, 0x3c, 0xd7, 0x62, 0x9b, 0x0e, 0x54, 0xf1}
)

// Seed 还原派生种子。
func Seed() [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = seedObf[i] ^ seedMask[i&7]
	}
	return out
}

// KeySize 是载荷密钥长度（AES-256）。
const KeySize = 32

// DeriveKey 计算载荷密钥：SHA-256(seed ‖ sig)。
//
// sig 为 APK 签名证书的 SHA-256；传 nil 时退化为仅由种子派生
// （与 C 侧 ag_derive(0, 0, out) 等价）。
func DeriveKey(sig []byte) [KeySize]byte {
	seed := Seed()
	h := sha256.New()
	h.Write(seed[:])
	if len(sig) > 0 {
		h.Write(sig)
	}
	var out [KeySize]byte
	copy(out[:], h.Sum(nil))
	return out
}
