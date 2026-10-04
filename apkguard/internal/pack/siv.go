// SIV-AES（RFC 5297）实现：AES-SIV-CMAC-512，无第三方依赖。
//
// 本文件只依赖 crypto/aes、crypto/sha256、crypto/subtle，实现：
//   - CMAC（RFC 4493 / NIST SP 800-38B 的 CBC-MAC + 子密钥方案）；
//   - S2V（RFC 5297 §2.4），支持多组件 AD；
//   - CTR（RFC 5297 §2.5/§2.6），计数器 = SIV 且清掉 31/63 位；
//   - sivSeal / sivOpen：AEAD 封装（解密必须校验 SIV）。
//
// 设计要点（与壳侧 C/DEX 实现必须逐字节一致）：
//   - 加密输出 [SIV 标签 16B][CTR 密文]，密文与明文等长（不做任何填充）；
//   - S2V 组件 = AD（可 0..n 个）+ 明文（最后一个组件），载荷路径只有一个
//     AD 组件（逻辑名），官方向量用多组件；
//   - CTR 初始块 V = SIV，且 V[8] &= 0x7f、V[12] &= 0x7f（RFC 5297 §2.6
//     要求清掉 31 与 63 位，使 32/64 位增量实现与 128 位大端递增一致），
//     逐块大端 +1；
//   - 解密先 CTR 解出明文，再重算 S2V(K1, AD, P) 与收到的标签做常量时间
//     比较，不一致即失败（SIV 的 AEAD 语义，不是「只解密不校验」）。
package pack

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
)

// SIV 密钥派生域分离串。K1 用于 S2V/CMAC，K2 用于 CTR。
//
// 壳侧（dex loader 与 native 实现）用完全相同的公式现算，两处必须逐字节
// 一致，有对拍守卫测试钉住这两个常量。
const (
	sivMacDomain = "apkguard/siv/mac"
	sivCTRDomain = "apkguard/siv/ctr"
)

// sivDeriveKeys 从 32 字节主密钥派生 SIV 的两把 32 字节子密钥。
//
//	K1 = SHA-256(master32 ‖ "apkguard/siv/mac")
//	K2 = SHA-256(master32 ‖ "apkguard/siv/ctr")
//
// master32 就是 Key(secret) 的产物（C1 生效时来自 native 派生，语义不变）。
func sivDeriveKeys(master [KeySize]byte) (k1, k2 [32]byte) {
	h := sha256.New()
	h.Write(master[:])
	h.Write([]byte(sivMacDomain))
	copy(k1[:], h.Sum(nil))

	h.Reset()
	h.Write(master[:])
	h.Write([]byte(sivCTRDomain))
	copy(k2[:], h.Sum(nil))
	return k1, k2
}

// ---- CMAC ----

// cmac 是 CMAC 实例：底层分组密码 + 预计算的子密钥 K1/K2。
type cmac struct {
	b cipher.Block
	// sub1/sub2 是 CMAC 子密钥（RFC 4493 的 K1/K2；不要与 SIV 的 K1/K2 混淆）。
	sub1 [BlockSize]byte
	sub2 [BlockSize]byte
}

// newCMAC 预计算子密钥：L = E(K, 0^128)；K1 = dbl(L)；K2 = dbl(K1)。
func newCMAC(b cipher.Block) *cmac {
	var zero, l [BlockSize]byte
	b.Encrypt(l[:], zero[:])
	c := &cmac{b: b}
	c.sub1 = dbl(l)
	c.sub2 = dbl(c.sub1)
	return c
}

// sum 计算 CMAC(message)。message 任意长度（含空）。
func (c *cmac) sum(msg []byte) [BlockSize]byte {
	var state [BlockSize]byte

	// 完整块数：只有当消息长度为分组整数倍时最后一个完整块才用 K1，
	// 否则最后一个不完整块先 10* 填充再用 K2。
	complete := len(msg) > 0 && len(msg)%BlockSize == 0
	n := len(msg) / BlockSize
	if complete {
		n-- // 最后一个完整块单独处理
	}
	for i := 0; i < n; i++ {
		xorInto(&state, msg[i*BlockSize:(i+1)*BlockSize])
		c.b.Encrypt(state[:], state[:])
	}

	var last [BlockSize]byte
	tail := msg[n*BlockSize:]
	copy(last[:], tail)
	if complete {
		xorInto(&last, c.sub1[:])
	} else {
		last[len(tail)] = 0x80 // pad(X) = X ‖ 0x80 ‖ 0…
		xorInto(&last, c.sub2[:])
	}
	xorInto(&state, last[:])
	c.b.Encrypt(state[:], state[:])
	return state
}

// dbl 是 RFC 5297 §2.3 的 128 位左移一比特：最高位为 1 时结果异或 0x87。
func dbl(in [BlockSize]byte) (out [BlockSize]byte) {
	carry := in[0] >> 7
	for i := 0; i < BlockSize-1; i++ {
		out[i] = in[i]<<1 | in[i+1]>>7
	}
	out[BlockSize-1] = in[BlockSize-1] << 1
	if carry != 0 {
		out[BlockSize-1] ^= 0x87
	}
	return out
}

// xorInto 把 b 异或进 a（长度必须相等）。
func xorInto(a *[BlockSize]byte, b []byte) {
	for i := 0; i < BlockSize; i++ {
		a[i] ^= b[i]
	}
}

// xorBlock 返回 a ^ b。
func xorBlock(a, b [BlockSize]byte) (out [BlockSize]byte) {
	for i := 0; i < BlockSize; i++ {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// xorend 实现 S2V 的 xorend：把 D 异或到 Sn 的最后 16 字节，长度保持 len(Sn)。
func xorend(sn []byte, d [BlockSize]byte) []byte {
	out := make([]byte, len(sn))
	copy(out, sn)
	for i := 0; i < BlockSize; i++ {
		out[len(out)-BlockSize+i] ^= d[i]
	}
	return out
}

// ---- S2V ----

// s2v 实现 RFC 5297 §2.4 的 S2V(K, S1, …, Sn)。
//
// components 是组件向量（至少 1 个；最后一个作为 Sn）。载荷路径传
// [逻辑名, 明文]；官方向量测试传多组件。n=0 的分支按 RFC 返回
// AES-CMAC(K, <one>)，本实现保留以保证与 RFC 完全一致（正常调用不会走到）。
func s2v(b cipher.Block, components ...[]byte) [BlockSize]byte {
	c := newCMAC(b)
	if len(components) == 0 {
		var one [BlockSize]byte
		one[BlockSize-1] = 1
		return c.sum(one[:])
	}

	var zero [BlockSize]byte
	d := c.sum(zero[:])
	for _, s := range components[:len(components)-1] {
		t := c.sum(s)
		d = xorBlock(dbl(d), t)
	}

	sn := components[len(components)-1]
	var t [BlockSize]byte
	if len(sn) >= BlockSize {
		return c.sum(xorend(sn, d))
	}
	// len(Sn) < 128 位：T = dbl(D) xor pad(Sn)，pad = 10*。
	var p [BlockSize]byte
	copy(p[:], sn)
	p[len(sn)] = 0x80
	t = xorBlock(dbl(d), p)
	return c.sum(t[:])
}

// ---- CTR ----

// ctrCrypt 用 CTR 流异或 in（加解密同一操作）。
//
// 计数器块初值 V = ctr（即 SIV），按 RFC 5297 §2.6 清掉 31/63 位后
// 逐块大端 +1。输出长度等于输入长度。
func ctrCrypt(b cipher.Block, ctr [BlockSize]byte, in []byte) []byte {
	v := ctr
	v[8] &= 0x7f  // 清 63 位（右端为第 0 位）
	v[12] &= 0x7f // 清 31 位
	out := make([]byte, len(in))
	var ks [BlockSize]byte
	for off := 0; off < len(in); off += BlockSize {
		b.Encrypt(ks[:], v[:])
		n := len(in) - off
		if n > BlockSize {
			n = BlockSize
		}
		for i := 0; i < n; i++ {
			out[off+i] = in[off+i] ^ ks[i]
		}
		for i := BlockSize - 1; i >= 0; i-- { // 128 位大端 +1
			v[i]++
			if v[i] != 0 {
				break
			}
		}
	}
	return out
}

// ---- AEAD 封装 ----

// sivSeal 做 SIV 加密：返回 [SIV 标签][CTR 密文]。
//
// k1/k2 允许任意合法 AES 长度（测试用 AES-128 跑 RFC 5297 官方向量；
// 生产路径为 32+32 字节）；components 最后一个必须是明文。
func sivSeal(k1, k2 []byte, components [][]byte) ([]byte, error) {
	if len(components) == 0 {
		return nil, fmt.Errorf("pack: SIV 至少需要明文组件")
	}
	b1, err := aes.NewCipher(k1)
	if err != nil {
		return nil, fmt.Errorf("pack: 构造 SIV-MAC 密码失败: %w", err)
	}
	b2, err := aes.NewCipher(k2)
	if err != nil {
		return nil, fmt.Errorf("pack: 构造 SIV-CTR 密码失败: %w", err)
	}
	tag := s2v(b1, components...)
	plain := components[len(components)-1]
	out := make([]byte, BlockSize+len(plain))
	copy(out, tag[:])
	copy(out[BlockSize:], ctrCrypt(b2, tag, plain))
	return out, nil
}

// sivOpen 做 SIV 解密并**校验**标签，失败返回错误。
//
// adComponents 不含明文；明文由 CTR 解出后作为最后一个组件参与 S2V，
// 与收到的标签常量时间比较。任何字节被改动（标签、密文、AD、密钥）都会失败。
func sivOpen(k1, k2 []byte, adComponents [][]byte, blob []byte) ([]byte, error) {
	if len(blob) < BlockSize {
		return nil, fmt.Errorf("pack: SIV 载荷过短 (%d 字节)", len(blob))
	}
	b1, err := aes.NewCipher(k1)
	if err != nil {
		return nil, fmt.Errorf("pack: 构造 SIV-MAC 密码失败: %w", err)
	}
	b2, err := aes.NewCipher(k2)
	if err != nil {
		return nil, fmt.Errorf("pack: 构造 SIV-CTR 密码失败: %w", err)
	}

	var tag [BlockSize]byte
	copy(tag[:], blob[:BlockSize])
	pt := ctrCrypt(b2, tag, blob[BlockSize:])

	components := make([][]byte, 0, len(adComponents)+1)
	components = append(components, adComponents...)
	components = append(components, pt)
	want := s2v(b1, components...)
	if subtle.ConstantTimeCompare(tag[:], want[:]) != 1 {
		return nil, fmt.Errorf("pack: SIV 校验失败（密钥/逻辑名不符或载荷被篡改）")
	}
	return pt, nil
}
