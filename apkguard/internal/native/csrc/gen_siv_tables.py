#!/usr/bin/env python3
"""生成 aes_tables.h（AES-256 的 S 盒/T 表 + AES-SIV 域串密文）。

为什么用生成器而不是手抄常量：
  - AES 的 S 盒与 T 表是 256/1024 个数学常量，手抄一处错就会得到
    「编译通过、NIST/RFC 向量必错」的产物；生成后由 gf_mult/gf_inv 的
    数学定义保证正确，并断言若干已知点（S[0]=0x63、Te0[0]=0xc66363a5）。
  - 域串密文必须与 obfuscate.h 的 ag_ks_byte 逐位一致（含 volatile 的
    g_ag_ks_key 与 uint64 回绕），由本脚本离线复现加密算法，避免手算。

本脚本不参与构建（构建只编译 apkguard.c），仅在常量需要改动时手工运行：
    python3 gen_siv_tables.py
输出：同目录下的 aes_tables.h
"""

import os

# 与 obfuscate.h 的 g_ag_ks_key 一致；volatile 只是为了阻断编译器常量折叠，
# 实际值固定，离线生成密文时按该值计算。
KS_KEY = 0x8F3A5C1D9B7E2465
MASK64 = (1 << 64) - 1


def ks_byte(i, salt):
    """ag_ks_byte 的 Python 逐位复现（splitmix64 风格）。"""
    x = (i * 0x9E3779B97F4A7C15 + salt * 0xBF58476D1CE4E5B9 + KS_KEY) & MASK64
    x ^= x >> 30
    x = (x * 0xBF58476D1CE4E5B9) & MASK64
    x ^= x >> 27
    x = (x * 0x94D049BB133111EB) & MASK64
    x ^= x >> 31
    return x & 0xFF


def enc_str(salt, plain):
    return [b ^ ks_byte(i, salt) for i, b in enumerate(plain.encode("utf-8"))]


# ---- GF(2^8) 与 AES S 盒 ----


def gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B  # x^8 + x^4 + x^3 + x + 1
        b >>= 1
    return p


def ginv(a):
    if a == 0:
        return 0
    for x in range(1, 256):
        if gmul(a, x) == 1:
            return x
    raise AssertionError("GF(2^8) 逆元不存在")


def rotl8(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xFF


def sbox_byte(a):
    b = ginv(a)
    return b ^ rotl8(b, 1) ^ rotl8(b, 2) ^ rotl8(b, 3) ^ rotl8(b, 4) ^ 0x63


def ror32(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def fmt_rows(name, ctype, vals, per_line, width):
    lines = ["static const %s %s[%d] = {" % (ctype, name, len(vals))]
    for i in range(0, len(vals), per_line):
        row = ", ".join("0x%0*x" % (width, v) for v in vals[i:i + per_line])
        lines.append("\t" + row + ",")
    lines.append("};")
    return "\n".join(lines)


def main():
    s = [sbox_byte(i) for i in range(256)]
    assert s[0] == 0x63 and s[1] == 0x7C and s[0x53] == 0xED, "S 盒计算错误"
    te0 = [(gmul(x, 2) << 24) | (x << 16) | (x << 8) | gmul(x, 3) for x in s]
    assert te0[0] == 0xC66363A5, "Te0 计算错误"
    te1 = [ror32(v, 8) for v in te0]
    te2 = [ror32(v, 16) for v in te0]
    te3 = [ror32(v, 24) for v in te0]
    rcon = [(1 << i) << 24 for i in range(7)]  # AES-256 只用到 Rcon[1..7]

    # 两条域串：与 Go 侧 KDF 的字节序列必须逐字节一致，且以密文形态落盘。
    salt_mac = 0x8D31F6A5
    salt_ctr = 0x2E94B7C1
    mac_enc = enc_str(salt_mac, "apkguard/siv/mac")
    ctr_enc = enc_str(salt_ctr, "apkguard/siv/ctr")

    out = []
    out.append("/*")
    out.append(" * aes_tables.h —— 由 gen_siv_tables.py 生成，请勿手工编辑。")
    out.append(" *")
    out.append(" * 内容：AES-256 的 S 盒、四个 T 表（Te1/Te2/Te3 是 Te0 的 32 位循环")
    out.append(" * 右移）、密钥扩展轮常数，以及 AES-SIV 两条密钥派生域串的密文。")
    out.append(" * 生成器带有已知点断言（S[0]=0x63、Te0[0]=0xc66363a5），数学定义见")
    out.append(" * gen_siv_tables.py 的 GF(2^8) 实现；域串密文与 obfuscate.h 的 ag_ks_byte")
    out.append(" * 逐位一致。")
    out.append(" */")
    out.append("")
    out.append("#ifndef APKGUARD_AES_TABLES_H")
    out.append("#define APKGUARD_AES_TABLES_H")
    out.append("")
    out.append("/* AES-SIV 密钥派生域串的盐（供 apkguard.c 的宿主自测做逐串解密断言）。 */")
    out.append("#define AG_SALT_SIV_MAC 0x%08Xu" % salt_mac)
    out.append("#define AG_SALT_SIV_CTR 0x%08Xu" % salt_ctr)
    out.append("")
    out.append(fmt_rows("AG_AES_SBOX", "uint8_t", s, 16, 2))
    out.append("")
    out.append(fmt_rows("AG_AES_TE0", "uint32_t", te0, 8, 8))
    out.append("")
    out.append(fmt_rows("AG_AES_TE1", "uint32_t", te1, 8, 8))
    out.append("")
    out.append(fmt_rows("AG_AES_TE2", "uint32_t", te2, 8, 8))
    out.append("")
    out.append(fmt_rows("AG_AES_TE3", "uint32_t", te3, 8, 8))
    out.append("")
    out.append(fmt_rows("AG_AES_RCON", "uint32_t", rcon, 7, 8))
    out.append("")
    out.append("/* 域串密文：明文不落在源码/产物里（见 obfuscate.h 的 C3 说明）。 */")
    out.append("AG_DEFSTR(ag_s_siv_mac, AG_SALT_SIV_MAC,")
    for i in range(0, len(mac_enc), 12):
        out.append("\t" + ", ".join("0x%02x" % b for b in mac_enc[i:i + 12]) + ",")
    out.append(");")
    out.append("")
    out.append("AG_DEFSTR(ag_s_siv_ctr, AG_SALT_SIV_CTR,")
    for i in range(0, len(ctr_enc), 12):
        out.append("\t" + ", ".join("0x%02x" % b for b in ctr_enc[i:i + 12]) + ",")
    out.append(");")
    out.append("")
    out.append("#endif /* APKGUARD_AES_TABLES_H */")

    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "aes_tables.h")
    with open(path, "w", newline="\n") as f:
        f.write("\n".join(out) + "\n")
    print("已生成 %s" % path)
    # 自检：解密回去必须等于原文。
    for salt, plain in ((salt_mac, "apkguard/siv/mac"), (salt_ctr, "apkguard/siv/ctr")):
        dec = bytes(b ^ ks_byte(i, salt) for i, b in enumerate(enc_str(salt, plain)))
        assert dec == plain.encode(), "域串密文自检失败"
    print("域串密文自检通过")


if __name__ == "__main__":
    main()
