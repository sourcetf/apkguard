/*
 * siv.h —— AES-SIV（RFC 5297）解密实现，只含 AES 加密方向（E_K）。
 *
 * 容器格式（与 Go 侧 internal/pack/siv.go 逐字节一致）：
 *     [SIV 标签 16 字节][AES-CTR 密文，长度 == 明文长度]
 *
 * 组成：
 *   - ag_aes_*   ：AES-128/192/256 的密钥扩展与分组加密（T 表实现，
 *                  T 表/S 盒来自 aes_tables.h，由生成器数学定义保证）；
 *   - ag_cmac_*  ：RFC 4493 CMAC（子密钥 K1/K2 = dbl 链、10* 填充）；
 *   - ag_s2v     ：RFC 5297 §2.4 S2V，支持多组件 AD（官方向量 A.2 是 3 个
 *                  AD 组件 + 明文）；n=0 时按 RFC 返回 CMAC(K, <1>)；
 *   - ag_ctr_xor ：RFC 5297 §2.6 CTR：计数器初值 = SIV 且 V[8]/V[12] 清
 *                  0x7f 位（清掉 63/31 位，使 128 位大端递增与 RFC 的
 *                  32/64 位实现一致），逐块 128 位大端 +1；
 *   - ag_siv_kdf ：K1 = SHA-256(master32 ‖ "apkguard/siv/mac")、
 *                  K2 = SHA-256(master32 ‖ "apkguard/siv/ctr")；域串以密文
 *                  形态存放在 aes_tables.h，运行期解到栈上（C3）；
 *   - ag_siv_decrypt / ag_siv_open_raw：先 CTR 解密，再重算 S2V 并
 *                  **常量时间**比对标签，失败返回 NULL——不存在「只解密
 *                  不校验」的入口。
 *
 * 前置条件：本文件必须在 apkguard.c 的 SHA-256 小节之后包含，且已包含
 * obfuscate.h（AG_DEFSTR/ag_dec）与 aes_tables.h。全部函数 static：不进
 * 动态符号表，-fvisibility=hidden 之外再加一层。
 *
 * 线程安全：无任何全局可变状态；临时缓冲全部是栈或调用方私有堆内存
 * （历史上静态缓冲在并发解密下互相踩踏导致崩溃，这里刻意不重演）。
 */

#ifndef APKGUARD_SIV_H
#define APKGUARD_SIV_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* 擦除辅助                                                            */
/* ------------------------------------------------------------------ */

/* ag_wipe：写零敏感栈/堆缓冲。volatile 指针避免 -O2 把「临死前的写」删掉。 */
static void ag_wipe(void *p, uint32_t n) {
	volatile uint8_t *v = (volatile uint8_t *)p;
	while (n > 0) {
		*v++ = 0;
		n--;
	}
}

/* 常量时间比较：整段异或累积，不因首个不等字节提前返回。 */
static int ag_ct_eq(const uint8_t *a, const uint8_t *b, uint32_t n) {
	uint8_t d = 0;
	uint32_t i;
	for (i = 0; i < n; i++) {
		d = (uint8_t)(d | (a[i] ^ b[i]));
	}
	return d == 0;
}

static void ag_xor16(uint8_t *a, const uint8_t *b) {
	int i;
	for (i = 0; i < 16; i++) {
		a[i] = (uint8_t)(a[i] ^ b[i]);
	}
}

/* ------------------------------------------------------------------ */
/* AES 核心（加密方向 + 密钥扩展，128/192/256）                        */
/* ------------------------------------------------------------------ */

typedef struct {
	/* 4*(Nr+1) 个 32 位轮密钥字，按大端字节序打包（ag_get32be）。 */
	uint32_t rk[60];
	int nr;
	int nk;
} ag_aes;

static uint32_t ag_get32be(const uint8_t *p) {
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void ag_put32be(uint8_t *p, uint32_t v) {
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

/* SubWord：对字的四个字节各做一次 S 盒替换。 */
static uint32_t ag_subword(uint32_t w) {
	return ((uint32_t)AG_AES_SBOX[(w >> 24) & 0xffu] << 24) |
	       ((uint32_t)AG_AES_SBOX[(w >> 16) & 0xffu] << 16) |
	       ((uint32_t)AG_AES_SBOX[(w >> 8) & 0xffu] << 8) |
	       (uint32_t)AG_AES_SBOX[w & 0xffu];
}

/*
 * ag_aes_rcon 返回第 r 个轮常数（r 从 1 起，值形如 0x01000000）。
 * AES-256 只用到 r=1..7，正好覆盖 aes_tables.h 的 AG_AES_RCON 表；
 * AES-128（RFC 4493 测试）需要到 r=10，其后由 xtime 续算。
 */
static uint32_t ag_aes_rcon(unsigned r) {
	uint32_t v = AG_AES_RCON[6];
	unsigned k;
	if (r == 0) {
		return 0;
	}
	if (r <= 7) {
		return AG_AES_RCON[r - 1];
	}
	for (k = 7; k < r; k++) {
		v = (v & 0x80000000u) ? ((v << 1) ^ 0x1B000000u) : (v << 1);
	}
	return v;
}

static int ag_aes_init(ag_aes *a, const uint8_t *key, uint32_t keylen) {
	int nk, nr, i, total;
	if (keylen == 16) {
		nr = 10;
	} else if (keylen == 24) {
		nr = 12;
	} else if (keylen == 32) {
		nr = 14;
	} else {
		return 0;
	}
	nk = (int)keylen / 4;
	a->nr = nr;
	a->nk = nk;
	total = 4 * (nr + 1);
	for (i = 0; i < nk; i++) {
		a->rk[i] = ag_get32be(key + 4 * i);
	}
	for (i = nk; i < total; i++) {
		uint32_t t = a->rk[i - 1];
		if (i % nk == 0) {
			/* RotWord（大端字）再 SubWord，最后异或轮常数。 */
			t = ag_subword((t << 8) | (t >> 24)) ^ ag_aes_rcon((unsigned)(i / nk));
		} else if (nk > 6 && (i % nk) == 4) {
			t = ag_subword(t);
		}
		a->rk[i] = a->rk[i - nk] ^ t;
	}
	return 1;
}

/*
 * ag_aes_encrypt：单块加密。Te1/Te2/Te3 是 Te0 的 32 位循环右移（生成器
 * 保证），配合「状态字按大端打包」得到与 FIPS-197 一致的 ShiftRows 效果；
 * 末轮不乘 MixColumns，只用 S 盒。
 */
static void ag_aes_encrypt(const ag_aes *a, const uint8_t in[16], uint8_t out[16]) {
	const uint32_t *rk = a->rk;
	uint32_t s0 = ag_get32be(in);
	uint32_t s1 = ag_get32be(in + 4);
	uint32_t s2 = ag_get32be(in + 8);
	uint32_t s3 = ag_get32be(in + 12);
	int r;
	s0 ^= rk[0];
	s1 ^= rk[1];
	s2 ^= rk[2];
	s3 ^= rk[3];
	for (r = 1; r < a->nr; r++) {
		uint32_t t0 = AG_AES_TE0[s0 >> 24] ^ AG_AES_TE1[(s1 >> 16) & 0xffu] ^
		              AG_AES_TE2[(s2 >> 8) & 0xffu] ^ AG_AES_TE3[s3 & 0xffu] ^ rk[4 * r];
		uint32_t t1 = AG_AES_TE0[s1 >> 24] ^ AG_AES_TE1[(s2 >> 16) & 0xffu] ^
		              AG_AES_TE2[(s3 >> 8) & 0xffu] ^ AG_AES_TE3[s0 & 0xffu] ^ rk[4 * r + 1];
		uint32_t t2 = AG_AES_TE0[s2 >> 24] ^ AG_AES_TE1[(s3 >> 16) & 0xffu] ^
		              AG_AES_TE2[(s0 >> 8) & 0xffu] ^ AG_AES_TE3[s1 & 0xffu] ^ rk[4 * r + 2];
		uint32_t t3 = AG_AES_TE0[s3 >> 24] ^ AG_AES_TE1[(s0 >> 16) & 0xffu] ^
		              AG_AES_TE2[(s1 >> 8) & 0xffu] ^ AG_AES_TE3[s2 & 0xffu] ^ rk[4 * r + 3];
		s0 = t0;
		s1 = t1;
		s2 = t2;
		s3 = t3;
	}
	{
		uint32_t t0 = ((uint32_t)AG_AES_SBOX[s0 >> 24] << 24) |
		              ((uint32_t)AG_AES_SBOX[(s1 >> 16) & 0xffu] << 16) |
		              ((uint32_t)AG_AES_SBOX[(s2 >> 8) & 0xffu] << 8) |
		              (uint32_t)AG_AES_SBOX[s3 & 0xffu];
		uint32_t t1 = ((uint32_t)AG_AES_SBOX[s1 >> 24] << 24) |
		              ((uint32_t)AG_AES_SBOX[(s2 >> 16) & 0xffu] << 16) |
		              ((uint32_t)AG_AES_SBOX[(s3 >> 8) & 0xffu] << 8) |
		              (uint32_t)AG_AES_SBOX[s0 & 0xffu];
		uint32_t t2 = ((uint32_t)AG_AES_SBOX[s2 >> 24] << 24) |
		              ((uint32_t)AG_AES_SBOX[(s3 >> 16) & 0xffu] << 16) |
		              ((uint32_t)AG_AES_SBOX[(s0 >> 8) & 0xffu] << 8) |
		              (uint32_t)AG_AES_SBOX[s1 & 0xffu];
		uint32_t t3 = ((uint32_t)AG_AES_SBOX[s3 >> 24] << 24) |
		              ((uint32_t)AG_AES_SBOX[(s0 >> 16) & 0xffu] << 16) |
		              ((uint32_t)AG_AES_SBOX[(s1 >> 8) & 0xffu] << 8) |
		              (uint32_t)AG_AES_SBOX[s2 & 0xffu];
		s0 = t0 ^ rk[4 * a->nr];
		s1 = t1 ^ rk[4 * a->nr + 1];
		s2 = t2 ^ rk[4 * a->nr + 2];
		s3 = t3 ^ rk[4 * a->nr + 3];
	}
	ag_put32be(out, s0);
	ag_put32be(out + 4, s1);
	ag_put32be(out + 8, s2);
	ag_put32be(out + 12, s3);
}

/* ------------------------------------------------------------------ */
/* CMAC（RFC 4493）：子密钥 + 10* 填充 + 末块选择                      */
/* ------------------------------------------------------------------ */

typedef struct {
	ag_aes aes;
	uint8_t sub1[16];
	uint8_t sub2[16];
} ag_cmac;

/* dbl(X)：128 位大端左移一位，溢出时异或 0x87（RFC 5297 §2.3）。 */
static void ag_dbl(uint8_t b[16]) {
	uint8_t carry = (uint8_t)(b[0] >> 7);
	int i;
	for (i = 0; i < 15; i++) {
		b[i] = (uint8_t)((b[i] << 1) | (b[i + 1] >> 7));
	}
	b[15] = (uint8_t)(b[15] << 1);
	if (carry) {
		b[15] = (uint8_t)(b[15] ^ 0x87);
	}
}

static int ag_cmac_init(ag_cmac *c, const uint8_t *key, uint32_t keylen) {
	uint8_t l[16];
	if (!ag_aes_init(&c->aes, key, keylen)) {
		return 0;
	}
	memset(l, 0, sizeof(l));
	ag_aes_encrypt(&c->aes, l, l); /* L = E(K, 0^128) */
	memcpy(c->sub1, l, 16);
	ag_dbl(c->sub1);
	memcpy(c->sub2, c->sub1, 16);
	ag_dbl(c->sub2);
	ag_wipe(l, sizeof(l));
	return 1;
}

/*
 * ag_cmac_sum 计算 CMAC(message)。
 *
 * xor16 非 NULL 时实现 S2V 的 xorend：把 xor16 异或到 message 的**最后
 * 16 字节**（长度保持不变，RFC 5297 §2.4）。不复制整段消息即可完成，
 * 4 MB 载荷因此只需一趟 CMAC、不额外分配 4 MB 临时区。
 *
 * 末块规则（RFC 4493）：len>0 且为分组整数倍 → 末完整块异或 sub1；
 * 否则末块补 0x80 后异或 sub2。空消息走 10* 填充 + sub2。
 */
static void ag_cmac_sum(const ag_cmac *c, const uint8_t *m, uint32_t n,
                        const uint8_t *xor16, uint8_t out[16]) {
	uint8_t st[16];
	uint8_t blk[16];
	uint32_t i, full, body, tail_off, tail_len, off;
	int complete = (n > 0 && (n % 16u) == 0u);
	int straddle = (xor16 != 0 && n >= 16 && (n % 16u) != 0u);
	memset(st, 0, sizeof(st));
	full = n / 16u;
	if (complete) {
		/* 最后一个完整块单独处理（异或 sub1，xorend 时整块 16 字节）。 */
		body = full - 1;
		tail_off = (full - 1) * 16u;
		tail_len = 16;
		off = 0;
	} else if (straddle) {
		/*
		 * xorend 的末 16 字节横跨边界：前 off=16-tail_len 字节在最后
		 * 一个完整块尾部，后 tail_len 字节在尾块。A.2 的 47 字节明文
		 * 正是这条路径；漏掉前 off 字节会让 S2V 标签整体错误。
		 */
		body = full - 1;
		tail_off = full * 16u;
		tail_len = n % 16u;
		off = 16u - tail_len;
	} else {
		body = full;
		tail_off = full * 16u;
		tail_len = n - tail_off;
		off = 0;
	}
	for (i = 0; i < body; i++) {
		ag_xor16(st, m + i * 16u);
		ag_aes_encrypt(&c->aes, st, st);
	}
	if (straddle) {
		uint8_t lb[16];
		memcpy(lb, m + (full - 1) * 16u, 16);
		for (i = 0; i < off; i++) {
			lb[16u - off + i] = (uint8_t)(lb[16u - off + i] ^ xor16[i]);
		}
		ag_xor16(st, lb);
		ag_aes_encrypt(&c->aes, st, st);
		ag_wipe(lb, sizeof(lb));
	}
	memset(blk, 0, sizeof(blk));
	if (tail_len > 0) {
		memcpy(blk, m + tail_off, tail_len);
	}
	if (xor16 != 0 && n >= 16) {
		/* 尾块字节 i 对应 xor16 的下标 16-tail_len+i（整块时即 i）。 */
		for (i = 0; i < tail_len; i++) {
			blk[i] = (uint8_t)(blk[i] ^ xor16[16u - tail_len + i]);
		}
	}
	if (complete) {
		ag_xor16(blk, c->sub1);
	} else {
		if (tail_len < 16) {
			blk[tail_len] = 0x80; /* 10* 填充 */
		}
		ag_xor16(blk, c->sub2);
	}
	ag_xor16(st, blk);
	ag_aes_encrypt(&c->aes, st, st);
	memcpy(out, st, 16);
	ag_wipe(st, sizeof(st));
	ag_wipe(blk, sizeof(blk));
}

/* ------------------------------------------------------------------ */
/* S2V（RFC 5297 §2.4）：支持 0..n 个组件的 AD 向量                    */
/* ------------------------------------------------------------------ */

typedef struct {
	const uint8_t *p;
	uint32_t n;
} ag_slice;

static int ag_s2v(const uint8_t *key, uint32_t keylen,
                  const ag_slice *comp, uint32_t ncomp, uint8_t out[16]) {
	ag_cmac c;
	uint8_t d[16], t[16];
	uint32_t i;
	if (ncomp == 0) {
		/* RFC 5297 §2.4：n=0 时返回 AES-CMAC(K, <1>)。 */
		uint8_t one[16];
		memset(one, 0, sizeof(one));
		one[15] = 1;
		if (!ag_cmac_init(&c, key, keylen)) {
			return 0;
		}
		ag_cmac_sum(&c, one, 16, 0, out);
		ag_wipe(&c, (uint32_t)sizeof(c));
		return 1;
	}
	if (!ag_cmac_init(&c, key, keylen)) {
		return 0;
	}
	{
		/* D = CMAC(K, 0^128)：是 16 字节全零消息，不是空消息。 */
		uint8_t zero16[16];
		memset(zero16, 0, sizeof(zero16));
		ag_cmac_sum(&c, zero16, 16, 0, d);
	}
	for (i = 0; i + 1 < ncomp; i++) {
		ag_dbl(d);
		ag_cmac_sum(&c, comp[i].p, comp[i].n, 0, t);
		ag_xor16(d, t);
	}
	{
		const ag_slice *sn = &comp[ncomp - 1];
		if (sn->n >= 16) {
			ag_cmac_sum(&c, sn->p, sn->n, d, out); /* xorend(Sn, D) 后 CMAC */
		} else {
			uint8_t blk[16];
			memset(blk, 0, sizeof(blk));
			if (sn->n > 0) {
				memcpy(blk, sn->p, sn->n);
			}
			blk[sn->n] = 0x80;
			ag_dbl(d);
			ag_xor16(blk, d);
			ag_cmac_sum(&c, blk, 16, 0, out);
		}
	}
	ag_wipe(d, sizeof(d));
	ag_wipe(t, sizeof(t));
	ag_wipe(&c, (uint32_t)sizeof(c));
	return 1;
}

/* ------------------------------------------------------------------ */
/* CTR（RFC 5297 §2.5/§2.6）                                           */
/* ------------------------------------------------------------------ */

/* ag_ctr_xor 用 CTR 流异或 in 到 out（加解密同一操作，允许 in == out）。 */
static int ag_ctr_xor(const uint8_t *key, uint32_t keylen, const uint8_t ctr0[16],
                      const uint8_t *in, uint8_t *out, uint32_t n) {
	ag_aes a;
	uint8_t v[16], ks[16];
	uint32_t off, i, take;
	if (!ag_aes_init(&a, key, keylen)) {
		return 0;
	}
	memcpy(v, ctr0, 16);
	/* 清掉 63 位（v[8] 最高位）与 31 位（v[12] 最高位）。 */
	v[8] = (uint8_t)(v[8] & 0x7f);
	v[12] = (uint8_t)(v[12] & 0x7f);
	for (off = 0; off < n; off += 16u) {
		ag_aes_encrypt(&a, v, ks);
		take = n - off;
		if (take > 16u) {
			take = 16u;
		}
		for (i = 0; i < take; i++) {
			out[off + i] = (uint8_t)(in[off + i] ^ ks[i]);
		}
		/* 128 位大端 +1。 */
		for (i = 16; i > 0; i--) {
			v[i - 1]++;
			if (v[i - 1] != 0) {
				break;
			}
		}
	}
	ag_wipe(ks, sizeof(ks));
	ag_wipe(&a, (uint32_t)sizeof(a));
	return 1;
}

/* ------------------------------------------------------------------ */
/* 密钥派生（与 Go 侧 sivDeriveKeys 逐字节一致）                       */
/* ------------------------------------------------------------------ */

/*
 * K1 = SHA-256(master32 ‖ "apkguard/siv/mac")
 * K2 = SHA-256(master32 ‖ "apkguard/siv/ctr")
 *
 * 域串以密文形态存放在 aes_tables.h（由 gen_siv_tables.py 生成，与
 * obfuscate.h 的 ag_ks_byte 逐位一致），运行期解到本函数的栈缓冲：
 * 明文域串既不进源码也不进 .so 的可见串。
 */
static void ag_siv_kdf(const uint8_t master[32], uint8_t k1[32], uint8_t k2[32]) {
	ag_sha256 s;
	AG_DECL_STR(ag_s_siv_mac, AG_SALT_SIV_MAC);
	AG_DECL_STR(ag_s_siv_ctr, AG_SALT_SIV_CTR);
	ag_sha256_init(&s);
	ag_sha256_update(&s, master, 32);
	ag_sha256_update(&s, (const uint8_t *)ag_s_siv_mac_buf, (uint32_t)ag_s_siv_mac_len);
	ag_sha256_final(&s, k1);
	ag_sha256_init(&s);
	ag_sha256_update(&s, master, 32);
	ag_sha256_update(&s, (const uint8_t *)ag_s_siv_ctr_buf, (uint32_t)ag_s_siv_ctr_len);
	ag_sha256_final(&s, k2);
	ag_wipe(&s, (uint32_t)sizeof(s));
	ag_wipe(ag_s_siv_mac_buf, (uint32_t)ag_s_siv_mac_len);
	ag_wipe(ag_s_siv_ctr_buf, (uint32_t)ag_s_siv_ctr_len);
}

/* S2V 组件上限：官方 A.2 只需 4 个（3 AD + 明文），生产路径 2 个。 */
#define AG_SIV_MAX_COMPONENTS 32

/*
 * ag_siv_open_raw 用给定的 K1/K2（长度任意合法 AES 长度）解开 blob。
 *
 * ad 是 AD 组件数组（不含明文），最后一个 S2V 组件由解密出的明文补上。
 * 成功返回 malloc 的明文（长度写入 *outlen；0 长度明文返回非 NULL 指针），
 * 失败（长度非法、malloc 失败、SIV 校验失败）返回 NULL。
 */
static uint8_t *ag_siv_open_raw(const uint8_t *k1, uint32_t k1len,
                                const uint8_t *k2, uint32_t k2len,
                                const ag_slice *ad, uint32_t nad,
                                const uint8_t *blob, uint32_t blen,
                                uint32_t *outlen) {
	uint8_t tag[16], want[16];
	ag_slice comps[AG_SIV_MAX_COMPONENTS];
	uint8_t *pt;
	uint32_t i, ptlen;
	if (k1 == 0 || k2 == 0 || blob == 0 || outlen == 0) {
		return 0;
	}
	if (blen < 16 || nad + 1 > AG_SIV_MAX_COMPONENTS) {
		return 0;
	}
	if (nad > 0 && ad == 0) {
		return 0;
	}
	*outlen = 0;
	ptlen = blen - 16;
	pt = (uint8_t *)malloc(ptlen > 0 ? ptlen : 1);
	if (pt == 0) {
		return 0;
	}
	memcpy(tag, blob, 16);
	if (!ag_ctr_xor(k2, k2len, tag, blob + 16, pt, ptlen)) {
		free(pt);
		return 0;
	}
	for (i = 0; i < nad; i++) {
		comps[i] = ad[i];
	}
	comps[nad].p = pt;
	comps[nad].n = ptlen;
	if (!ag_s2v(k1, k1len, comps, nad + 1, want)) {
		ag_wipe(pt, ptlen > 0 ? ptlen : 1);
		free(pt);
		return 0;
	}
	if (!ag_ct_eq(tag, want, 16)) {
		/* 标签不符：明文是未认证数据，清零后再释放。 */
		ag_wipe(pt, ptlen > 0 ? ptlen : 1);
		free(pt);
		return 0;
	}
	ag_wipe(tag, sizeof(tag));
	ag_wipe(want, sizeof(want));
	*outlen = ptlen;
	return pt;
}

/*
 * ag_siv_decrypt 是 JNI 与宿主自测共用的生产入口。
 *
 * key32  = 32 字节主密钥；ad = 载荷逻辑名（UTF-8 字节，可为 0 长度但语义上
 * 仍是「一个 AD 组件」）；blob = [SIV 16B][CTR 密文]。任何失败返回 NULL。
 */
static uint8_t *ag_siv_decrypt(const uint8_t *key32, const uint8_t *ad,
                               uint32_t adlen, const uint8_t *blob,
                               uint32_t blen, uint32_t *outlen) {
	uint8_t k1[32], k2[32];
	ag_slice a;
	uint8_t *pt;
	if (key32 == 0) {
		return 0;
	}
	ag_siv_kdf(key32, k1, k2);
	a.p = ad;
	a.n = adlen;
	pt = ag_siv_open_raw(k1, 32, k2, 32, &a, 1, blob, blen, outlen);
	ag_wipe(k1, sizeof(k1));
	ag_wipe(k2, sizeof(k2));
	return pt;
}

/* ------------------------------------------------------------------ */
/* 宿主自测（AG_HOST_TEST）：官方向量 + Go 互操作 + 边界 + 性能        */
/* ------------------------------------------------------------------ */
/*
 * 本段只在宿主构建（gcc -DAG_HOST_TEST）里编译，不进 NDK 产物。
 * 覆盖：
 *   1) FIPS-197 AES-128/256 单块向量（先证明分组密码与密钥扩展）；
 *   2) RFC 4493 CMAC 官方向量 4 条 + 子密钥；
 *   3) RFC 5297 A.1/A.2 官方向量：中间量（CMAC、S2V、CTR 密钥流）
 *      逐字节对拍 + 全量解密 + 篡改必失败；
 *   4) Go 侧 pack.EncryptNamed 生成的 AES-256 互操作向量；
 *   5) 往返/边界（0/1/15/16/17/31/32/63/64/300/4096）、错误密钥、错误 AD；
 *   6) 4 MB 载荷性能计时（生产关注点）。
 */
#ifdef AG_HOST_TEST

#include <stdio.h>
#include <time.h>

static int ag_siv_bad;

static void ag_siv_hex(const uint8_t *b, uint32_t n, char *out) {
	static const char *d = "0123456789abcdef";
	uint32_t i;
	for (i = 0; i < n; i++) {
		out[i * 2] = d[b[i] >> 4];
		out[i * 2 + 1] = d[b[i] & 15];
	}
	out[n * 2] = 0;
}

static int ag_siv_eq(const char *name, const uint8_t *got, const uint8_t *want, uint32_t n) {
	char hg[1024], hw[1024];
	uint32_t m = n;
	if (memcmp(got, want, n) == 0) {
		printf("PASS %s\n", name);
		return 0;
	}
	if (m > 480) {
		m = 480;
	}
	ag_siv_hex(got, m, hg);
	ag_siv_hex(want, m, hw);
	printf("FAIL %s\n  got  %s\n  want %s\n", name, hg, hw);
	return 1;
}

/* ag_siv_unhex 解析去空格的 hex；非法输入返回 0xffffffff。 */
static uint32_t ag_siv_unhex(const char *s, uint8_t *out, uint32_t cap) {
	uint32_t n = 0;
	int hi = -1;
	while (*s != 0) {
		int v;
		char ch = *s++;
		if (ch == ' ') {
			continue;
		}
		if (ch >= '0' && ch <= '9') {
			v = ch - '0';
		} else if (ch >= 'a' && ch <= 'f') {
			v = ch - 'a' + 10;
		} else if (ch >= 'A' && ch <= 'F') {
			v = ch - 'A' + 10;
		} else {
			return 0xffffffffu;
		}
		if (hi < 0) {
			hi = v;
		} else {
			if (n >= cap) {
				return 0xffffffffu;
			}
			out[n++] = (uint8_t)((hi << 4) | v);
			hi = -1;
		}
	}
	if (hi >= 0) {
		return 0xffffffffu;
	}
	return n;
}

static int ag_siv_case(const char *name, int ok) {
	if (ok) {
		printf("PASS %s\n", name);
		return 0;
	}
	printf("FAIL %s\n", name);
	return 1;
}

/* 测试专用封装（只含加密方向 E_K）：[SIV][CTR 密文]。 */
static uint8_t *ag_siv_seal_test(const uint8_t *k1, uint32_t k1len,
                                 const uint8_t *k2, uint32_t k2len,
                                 const ag_slice *ad, uint32_t nad,
                                 const uint8_t *pt, uint32_t ptlen,
                                 uint32_t *bloblen) {
	ag_slice comps[AG_SIV_MAX_COMPONENTS];
	uint8_t tag[16];
	uint8_t *blob;
	uint32_t i;
	if (nad + 1 > AG_SIV_MAX_COMPONENTS || (nad > 0 && ad == 0)) {
		return 0;
	}
	for (i = 0; i < nad; i++) {
		comps[i] = ad[i];
	}
	comps[nad].p = pt;
	comps[nad].n = ptlen;
	if (!ag_s2v(k1, k1len, comps, nad + 1, tag)) {
		return 0;
	}
	blob = (uint8_t *)malloc(ptlen + 16);
	if (blob == 0) {
		return 0;
	}
	memcpy(blob, tag, 16);
	if (!ag_ctr_xor(k2, k2len, tag, pt, blob + 16, ptlen)) {
		ag_wipe(blob, ptlen + 16);
		free(blob);
		return 0;
	}
	*bloblen = ptlen + 16;
	ag_wipe(tag, sizeof(tag));
	return blob;
}

static double ag_siv_now_ms(void) {
	return (double)clock() * 1000.0 / (double)CLOCKS_PER_SEC;
}

/* ---- 4. 与 Go 侧 pack.EncryptNamed 的互操作向量（临时程序生成） ---- */
/*
 * key     = pack.Key("siv-native-interop")
 * name    = "classes.dex"
 * plain[i]= (i*31+7) & 0xff，共 300 字节；blob = EncryptNamed(plain, key, name)
 * 下面是生成时的 key、前 64 字节明文、明文总长与整段 blob 的十六进制。
 */
static const char AG_SIV_INTEROP_KEY[] =
	"47b0c0a519dcee409227531caf9a30dcde6b0fa090a8e35eef3944a620a09c8d";
static const char AG_SIV_INTEROP_NAME[] = "classes.dex";
static const uint32_t AG_SIV_INTEROP_PT_LEN = 300;
static const char AG_SIV_INTEROP_PT64[] =
	"0726456483a2c1e0ff1e3d5c7b9ab9d8f71635547392b1d0ef0e2d4c6b8aa9c8"
	"e70625446382a1c0dffe1d3c5b7a99b8d7f61534537291b0cfee0d2c4b6a89a8";
static const uint32_t AG_SIV_INTEROP_BLOB_LEN = 316;
static const char AG_SIV_INTEROP_BLOB[] =
	"e0aa87515e36757622eea84e608f5f8cb765c8ea0b4556bd834f21a0d9486db5"
	"92b1c023292c5b0c6ef995efe42a1fd2e93a764e87fa58998bc49e6687e43f00"
	"ff73cf0c8dd54dfb000b95b86f9061d3773076534876a4be76c1da0ccfa0e28c"
	"7e71036d6bee3a9b341f089eb78d1f53c47e98314656c96c2e9021d87a086239"
	"38a289f89f20c3a9bbc139bf63cd368dddd3af3da50211f443b39bd1497ab5fb"
	"707b0dcde8c147c585b9271aac73054df7d435cd2249e7a8609d821a130ad262"
	"b191dd0e03fbab39efc07c3cbd3aeccd1af77b901623b213d2e54c5e48e7e1cb"
	"b53589ca0582e3933ce694977dbfce94038b121937af37eea7b258d653c7a746"
	"64f92975677313eb65248d78e2185d0189c3e44cd29d3d2a9a20d2c1b27a9fd1"
	"dd7b3c6d7ff3921fbcc0d21c7223266b4230acc30110fd7b15489729";

static void ag_siv_test_interop(void) {
	uint8_t key[32], blob[AG_SIV_INTEROP_BLOB_LEN];
	uint8_t pt64[64];
	uint8_t *pt;
	uint32_t outlen = 0, i;
	int ok;
	if (ag_siv_unhex(AG_SIV_INTEROP_KEY, key, sizeof(key)) != 32 ||
	    ag_siv_unhex(AG_SIV_INTEROP_BLOB, blob, sizeof(blob)) != sizeof(blob) ||
	    ag_siv_unhex(AG_SIV_INTEROP_PT64, pt64, sizeof(pt64)) != sizeof(pt64)) {
		ag_siv_bad += ag_siv_case("SIV interop 向量常量解析", 0);
		return;
	}
	pt = ag_siv_decrypt(key, (const uint8_t *)AG_SIV_INTEROP_NAME,
	                    (uint32_t)(sizeof(AG_SIV_INTEROP_NAME) - 1),
	                    blob, AG_SIV_INTEROP_BLOB_LEN, &outlen);
	if (pt == 0 || outlen != AG_SIV_INTEROP_PT_LEN) {
		ag_siv_bad += ag_siv_case("SIV interop 长度", 0);
		free(pt);
		return;
	}
	/* 前 64 字节与生成时保存的常量逐字节对拍。 */
	ag_siv_bad += ag_siv_eq("SIV interop 前 64B", pt, pt64, 64);
	/* 其余字节按两侧约定的生成公式 pt[i]=(i*31+7)&0xff 全量复核。 */
	ok = 1;
	for (i = 0; i < outlen; i++) {
		if (pt[i] != (uint8_t)(i * 31u + 7u)) {
			ok = 0;
			break;
		}
	}
	ag_siv_bad += ag_siv_case("SIV interop 全量明文", ok);
	free(pt);
	/* 篡改 1 字节（标签尾）必须失败。 */
	blob[15] ^= 0x01;
	pt = ag_siv_decrypt(key, (const uint8_t *)AG_SIV_INTEROP_NAME,
	                    (uint32_t)(sizeof(AG_SIV_INTEROP_NAME) - 1),
	                    blob, AG_SIV_INTEROP_BLOB_LEN, &outlen);
	ag_siv_bad += ag_siv_case("SIV interop 篡改标签返回 null", pt == 0);
	free(pt);
	blob[15] ^= 0x01;
	blob[AG_SIV_INTEROP_BLOB_LEN - 1] ^= 0x80;
	pt = ag_siv_decrypt(key, (const uint8_t *)AG_SIV_INTEROP_NAME,
	                    (uint32_t)(sizeof(AG_SIV_INTEROP_NAME) - 1),
	                    blob, AG_SIV_INTEROP_BLOB_LEN, &outlen);
	ag_siv_bad += ag_siv_case("SIV interop 篡改密文返回 null", pt == 0);
	free(pt);
	blob[AG_SIV_INTEROP_BLOB_LEN - 1] ^= 0x80;
	/* 错误 AD（逻辑名不符）必须失败。 */
	pt = ag_siv_decrypt(key, (const uint8_t *)"classes2.dex", 12,
	                    blob, AG_SIV_INTEROP_BLOB_LEN, &outlen);
	ag_siv_bad += ag_siv_case("SIV interop 错误 AD 返回 null", pt == 0);
	free(pt);
	/* 截断（< 16 字节）必须失败。 */
	pt = ag_siv_decrypt(key, (const uint8_t *)AG_SIV_INTEROP_NAME,
	                    (uint32_t)(sizeof(AG_SIV_INTEROP_NAME) - 1),
	                    blob, 15, &outlen);
	ag_siv_bad += ag_siv_case("SIV interop 截断返回 null", pt == 0);
	free(pt);
}

/* ---- 入口 ---- */

static int ag_siv_selftest(void) {
	uint8_t key[32], pt[16], ct[16], got[16];
	uint8_t k1[32], k2[32];
	ag_aes a;
	ag_cmac cm;
	uint8_t buf[128];
	uint32_t n;

	ag_siv_bad = 0;

	/* 1. FIPS-197 单块向量：AES-128 与 AES-256。 */
	if (ag_siv_unhex("000102030405060708090a0b0c0d0e0f", key, sizeof(key)) != 16 ||
	    ag_siv_unhex("00112233445566778899aabbccddeeff", pt, sizeof(pt)) != 16 ||
	    ag_siv_unhex("69c4e0d86a7b0430d8cdb78070b4c55a", ct, sizeof(ct)) != 16) {
		ag_siv_bad += ag_siv_case("FIPS-197 AES-128 向量常量", 0);
		return ag_siv_bad;
	}
	ag_aes_init(&a, key, 16);
	ag_aes_encrypt(&a, pt, got);
	ag_siv_bad += ag_siv_eq("FIPS-197 AES-128 单块", got, ct, 16);

	if (ag_siv_unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
	                 key, sizeof(key)) != 32 ||
	    ag_siv_unhex("8ea2b7ca516745bfeafc49904b496089", ct, sizeof(ct)) != 16) {
		ag_siv_bad += ag_siv_case("FIPS-197 AES-256 向量常量", 0);
		return ag_siv_bad;
	}
	ag_aes_init(&a, key, 32);
	ag_aes_encrypt(&a, pt, got);
	ag_siv_bad += ag_siv_eq("FIPS-197 AES-256 单块", got, ct, 16);

	/* 2. RFC 4493 CMAC（AES-128）子密钥与 4 条向量。 */
	if (ag_siv_unhex("2b7e151628aed2a6abf7158809cf4f3c", key, sizeof(key)) != 16) {
		ag_siv_bad += ag_siv_case("RFC 4493 密钥常量", 0);
		return ag_siv_bad;
	}
	ag_cmac_init(&cm, key, 16);
	ag_siv_unhex("7df76b0c1ab899b33e42f047b91b546f", ct, sizeof(ct));
	ag_aes_init(&a, key, 16);
	memset(got, 0, 16);
	ag_aes_encrypt(&a, got, got); /* L = E(K, 0) */
	ag_siv_bad += ag_siv_eq("RFC 4493 L=E(K,0^128)", got, ct, 16);
	ag_siv_unhex("fbeed618357133667c85e08f7236a8de", ct, sizeof(ct));
	ag_siv_bad += ag_siv_eq("RFC 4493 子密钥 K1", cm.sub1, ct, 16);
	ag_siv_unhex("f7ddac306ae266ccf90bc11ee46d513b", ct, sizeof(ct));
	ag_siv_bad += ag_siv_eq("RFC 4493 子密钥 K2", cm.sub2, ct, 16);

	/* D.1 空消息 */
	ag_siv_unhex("bb1d6929e95937287fa37d129b756746", ct, sizeof(ct));
	ag_cmac_sum(&cm, 0, 0, 0, got);
	ag_siv_bad += ag_siv_eq("RFC 4493 D.1 CMAC(空)", got, ct, 16);
	/* D.2 16 字节 */
	n = ag_siv_unhex("6bc1bee22e409f96e93d7e117393172a", buf, sizeof(buf));
	ag_siv_unhex("070a16b46b4d4144f79bdd9dd04a287c", ct, sizeof(ct));
	ag_cmac_sum(&cm, buf, n, 0, got);
	ag_siv_bad += ag_siv_eq("RFC 4493 D.2 CMAC(16B)", got, ct, 16);
	/* D.3 40 字节 */
	n = ag_siv_unhex("6bc1bee22e409f96 e93d7e117393172a ae2d8a571e03ac9c "
	                 "9eb76fac45af8e51 30c81c46a35ce411", buf, sizeof(buf));
	ag_siv_unhex("dfa66747de9ae63030ca32611497c827", ct, sizeof(ct));
	ag_cmac_sum(&cm, buf, n, 0, got);
	ag_siv_bad += ag_siv_eq("RFC 4493 D.3 CMAC(40B)", got, ct, 16);
	/* D.4 64 字节 */
	n = ag_siv_unhex("6bc1bee22e409f96 e93d7e117393172a ae2d8a571e03ac9c "
	                 "9eb76fac45af8e51 30c81c46a35ce411 e5fbc1191a0a52ef "
	                 "f69f2445df4f9b17 ad2b417be66c3710", buf, sizeof(buf));
	ag_siv_unhex("51f0bebf7e3b9d92fc49741779363cfe", ct, sizeof(ct));
	ag_cmac_sum(&cm, buf, n, 0, got);
	ag_siv_bad += ag_siv_eq("RFC 4493 D.4 CMAC(64B)", got, ct, 16);

	/* 3. RFC 5297 A.1（AES-SIV-CMAC-256，单 AD 组件）。 */
	{
		uint8_t ad[32], ptx[32], blob[64];
		ag_slice ads[1];
		uint8_t *out;
		uint32_t outlen = 0;
		if (ag_siv_unhex("fffefdfc fbfaf9f8 f7f6f5f4 f3f2f1f0 "
		                 "f0f1f2f3 f4f5f6f7 f8f9fafb fcfdfeff", key, sizeof(key)) != 32) {
			ag_siv_bad += ag_siv_case("RFC 5297 A.1 密钥常量", 0);
			return ag_siv_bad;
		}
		memcpy(k1, key, 16);
		memcpy(k2, key + 16, 16);
		n = ag_siv_unhex("10111213 14151617 18191a1b 1c1d1e1f 20212223 24252627",
		                 ad, sizeof(ad));
		ads[0].p = ad;
		ads[0].n = n;
		ag_siv_unhex("11223344 55667788 99aabbcc ddee", ptx, sizeof(ptx));
		{
			uint32_t ptn = 14;
			/* 中间量：CMAC(K1, 0^128)、CMAC(K1, AD)。 */
			uint8_t zero16[16];
			ag_cmac_init(&cm, k1, 16);
			ag_siv_unhex("0e04dfafc1efbf040140582859bf073a", ct, sizeof(ct));
			memset(zero16, 0, sizeof(zero16));
			ag_cmac_sum(&cm, zero16, 16, 0, got);
			ag_siv_bad += ag_siv_eq("RFC 5297 A.1 CMAC(K1,0^128)", got, ct, 16);
			ag_siv_unhex("f1f922b7f5193ce64ff80cb47d93f23b", ct, sizeof(ct));
			ag_cmac_sum(&cm, ad, n, 0, got);
			ag_siv_bad += ag_siv_eq("RFC 5297 A.1 CMAC(K1,AD)", got, ct, 16);
			/* S2V 标签。 */
			{
				ag_slice sc[2];
				sc[0] = ads[0];
				sc[1].p = ptx;
				sc[1].n = ptn;
				ag_s2v(k1, 16, sc, 2, got);
			}
			ag_siv_unhex("85632d07 c6e8f37f 950acd32 0a2ecc93", ct, sizeof(ct));
			ag_siv_bad += ag_siv_eq("RFC 5297 A.1 S2V 标签", got, ct, 16);
			/* CTR 首块密钥流（钉住 V[8]/V[12] 清位）。 */
			memset(buf, 0, 16);
			ag_ctr_xor(k2, 16, ct, buf, buf, 16);
			ag_siv_unhex("51e218d2c5a2ab8c4345c4a623b2f08f", got, sizeof(got));
			ag_siv_bad += ag_siv_eq("RFC 5297 A.1 CTR 首块", buf, got, 16);
		}
		/* 官方向量整段解密。 */
		n = ag_siv_unhex("85632d07 c6e8f37f 950acd32 0a2ecc93 "
		                 "40c02b96 90c4dc04 daef7f6a fe5c", blob, sizeof(blob));
		out = ag_siv_open_raw(k1, 16, k2, 16, ads, 1, blob, n, &outlen);
		ag_siv_bad += ag_siv_case("RFC 5297 A.1 解密",
		                          out != 0 && outlen == 14 && memcmp(out, ptx, 14) == 0);
		free(out);
		/* 逐字节篡改必须全部失败。 */
		{
			uint32_t i;
			int allfail = 1;
			for (i = 0; i < n; i++) {
				blob[i] ^= 0x01;
				out = ag_siv_open_raw(k1, 16, k2, 16, ads, 1, blob, n, &outlen);
				if (out != 0) {
					allfail = 0;
				}
				free(out);
				blob[i] ^= 0x01;
			}
			ag_siv_bad += ag_siv_case("RFC 5297 A.1 逐字节篡改全部失败", allfail);
		}
		/* K1/K2 对调必须失败。 */
		out = ag_siv_open_raw(k2, 16, k1, 16, ads, 1, blob, n, &outlen);
		ag_siv_bad += ag_siv_case("RFC 5297 A.1 K1/K2 对调失败", out == 0);
		free(out);
	}

	/* 4. RFC 5297 A.2（3 个 AD 组件 + 47 字节明文，xorend 路径）。 */
	{
		uint8_t ad1[64], ad2[16], nonce[16], ptx[64], blob[80];
		ag_slice ads[3], sc[4];
		uint8_t *out;
		uint32_t outlen = 0, n1, n2, nn, plen;
		const char *msg = "this is some plaintext to encrypt using SIV-AES";
		if (ag_siv_unhex("7f7e7d7c 7b7a7978 77767574 73727170 "
		                 "40414243 44454647 48494a4b 4c4d4e4f", key, sizeof(key)) != 32) {
			ag_siv_bad += ag_siv_case("RFC 5297 A.2 密钥常量", 0);
			return ag_siv_bad;
		}
		memcpy(k1, key, 16);
		memcpy(k2, key + 16, 16);
		n1 = ag_siv_unhex("00112233 44556677 8899aabb ccddeeff deaddada deaddada "
		                  "ffeeddcc bbaa9988 77665544 33221100", ad1, sizeof(ad1));
		n2 = ag_siv_unhex("10203040 50607080 90a0", ad2, sizeof(ad2));
		nn = ag_siv_unhex("09f91102 9d74e35b d84156c5 635688c0", nonce, sizeof(nonce));
		plen = (uint32_t)strlen(msg);
		memcpy(ptx, msg, plen);
		ads[0].p = ad1;
		ads[0].n = n1;
		ads[1].p = ad2;
		ads[1].n = n2;
		ads[2].p = nonce;
		ads[2].n = nn;
		/* 中间量：CMAC(K1, AD1/AD2/Nonce) 与标签。 */
		ag_cmac_init(&cm, k1, 16);
		ag_siv_unhex("3c9b689ab41102e4809547141dd0d15a", ct, sizeof(ct));
		ag_cmac_sum(&cm, ad1, n1, 0, got);
		ag_siv_bad += ag_siv_eq("RFC 5297 A.2 CMAC(AD1)", got, ct, 16);
		ag_siv_unhex("d98c9b0be42cb2d7aa98478ed11eda1b", ct, sizeof(ct));
		ag_cmac_sum(&cm, ad2, n2, 0, got);
		ag_siv_bad += ag_siv_eq("RFC 5297 A.2 CMAC(AD2)", got, ct, 16);
		ag_siv_unhex("128c62a1ce3747a8372c1c05a538b96d", ct, sizeof(ct));
		ag_cmac_sum(&cm, nonce, nn, 0, got);
		ag_siv_bad += ag_siv_eq("RFC 5297 A.2 CMAC(Nonce)", got, ct, 16);
		sc[0] = ads[0];
		sc[1] = ads[1];
		sc[2] = ads[2];
		sc[3].p = ptx;
		sc[3].n = plen;
		ag_s2v(k1, 16, sc, 4, got);
		ag_siv_unhex("7bdb6e3b 432667eb 06f4d14b ff2fbd0f", ct, sizeof(ct));
		ag_siv_bad += ag_siv_eq("RFC 5297 A.2 S2V 标签", got, ct, 16);
		/* 47 字节 CTR 密钥流（3 个计数块，钉住大端递增）。 */
		{
			uint8_t ks[64], want[64];
			memset(ks, 0, sizeof(ks));
			ag_ctr_xor(k2, 16, ct, ks, ks, 47);
			ag_siv_unhex("bff8665c fdd73363 550f7400 e8f9d376 b2c9088e 713b8617 "
			             "d8839226 d9f88159 9e44d827 234949bc 1b12348e bc195ec7",
			             want, sizeof(want));
			ag_siv_bad += ag_siv_eq("RFC 5297 A.2 CTR 密钥流 47B", ks, want, 47);
		}
		/* 整段解密。 */
		n = ag_siv_unhex("7bdb6e3b 432667eb 06f4d14b ff2fbd0f "
		                 "cb900f2f ddbe4043 26601965 c889bf17 dba77ceb 094fa663 "
		                 "b7a3f748 ba8af829 ea64ad54 4a272e9c 485b62a3 fd5c0d",
		                 blob, sizeof(blob));
		out = ag_siv_open_raw(k1, 16, k2, 16, ads, 3, blob, n, &outlen);
		ag_siv_bad += ag_siv_case("RFC 5297 A.2 解密",
		                          out != 0 && outlen == plen &&
		                          memcmp(out, ptx, plen) == 0);
		free(out);
	}

	/* 5. Go 互操作（AES-256 生产路径）。 */
	ag_siv_test_interop();

	/* 6. 往返 / 边界 / 错误密钥 / 空 AD。 */
	{
		static const uint32_t lens[] = {0, 1, 15, 16, 17, 31, 32, 63, 64, 300, 4096};
		uint8_t master[32];
		uint8_t *plain;
		uint32_t i, j;
		int rt_ok = 1;
		for (i = 0; i < 32; i++) {
			master[i] = (uint8_t)(i * 7 + 1);
		}
		/* 与生产一致：加密侧也必须用 KDF 派生的 K1/K2（解密侧由
		 * ag_siv_decrypt 内部派生），否则等于用错密钥，往返必然失败。 */
		ag_siv_kdf(master, k1, k2);
		for (i = 0; i < (uint32_t)(sizeof(lens) / sizeof(lens[0])); i++) {
			uint32_t len = lens[i];
			uint32_t blen = 0, outlen = 0;
			ag_slice ad;
			uint8_t *blob, *out;
			int ok = 1;
			plain = (uint8_t *)malloc(len > 0 ? len : 1);
			if (plain == 0) {
				ag_siv_bad += ag_siv_case("SIV 往返 malloc", 0);
				break;
			}
			for (j = 0; j < len; j++) {
				plain[j] = (uint8_t)(j * 131u + 17u);
			}
			ad.p = (const uint8_t *)"classes.dex";
			ad.n = 11;
			blob = ag_siv_seal_test(k1, 32, k2, 32, &ad, 1, plain, len, &blen);
			if (blob == 0 || blen != len + 16) {
				ok = 0;
			} else {
				out = ag_siv_decrypt(master, ad.p, ad.n, blob, blen, &outlen);
				if (out == 0 || outlen != len || (len > 0 && memcmp(out, plain, len) != 0)) {
					ok = 0;
				}
				free(out);
			}
			free(blob);
			free(plain);
			if (!ok) {
				printf("FAIL SIV 往返 len=%u\n", len);
				rt_ok = 0;
			}
		}
		ag_siv_bad += ag_siv_case("SIV 往返 0/1/15/16/17/31/32/63/64/300/4096", rt_ok);
		/* 错误主密钥必须失败。 */
		{
			uint8_t badkey[32];
			uint8_t *out;
			uint32_t outlen = 0;
			uint32_t blen = 0;
			const uint8_t msg[3] = {1, 2, 3};
			ag_slice ad;
			uint8_t *blob;
			ad.p = (const uint8_t *)"classes.dex";
			ad.n = 11;
			blob = ag_siv_seal_test(k1, 32, k2, 32, &ad, 1, msg, 3, &blen);
			memcpy(badkey, master, 32);
			badkey[0] ^= 0x01;
			out = ag_siv_decrypt(badkey, ad.p, ad.n, blob, blen, &outlen);
			ag_siv_bad += ag_siv_case("SIV 错误主密钥返回 null", out == 0);
			free(out);
			free(blob);
			/* 空 AD（0 字节组件）往返。 */
			ad.p = (const uint8_t *)"";
			ad.n = 0;
			blob = ag_siv_seal_test(k1, 32, k2, 32, &ad, 1, msg, 3, &blen);
			out = ag_siv_decrypt(master, ad.p, 0, blob, blen, &outlen);
			ag_siv_bad += ag_siv_case("SIV 空 AD 往返",
			                          out != 0 && outlen == 3 && memcmp(out, msg, 3) == 0);
			free(out);
			free(blob);
			/* 空明文：blob 恰 16 字节，解密得到 0 字节。 */
			blob = ag_siv_seal_test(k1, 32, k2, 32, &ad, 1, 0, 0, &blen);
			out = ag_siv_decrypt(master, ad.p, 0, blob, blen, &outlen);
			ag_siv_bad += ag_siv_case("SIV 空明文 blob=16B",
			                          blob != 0 && blen == 16 && out != 0 && outlen == 0);
			free(out);
			free(blob);
		}
	}

	/* 7. 4 MB 性能：解密（含 S2V 复算）耗时。 */
	{
		const uint32_t sz = 4u * 1024u * 1024u;
		uint8_t master[32];
		uint8_t *plain = (uint8_t *)malloc(sz);
		uint8_t *blob = 0;
		uint32_t i, blen = 0, outlen = 0;
		double t0, t1, t2;
		int ok = 1;
		for (i = 0; i < 32; i++) {
			master[i] = (uint8_t)(i * 3 + 5);
		}
		ag_siv_kdf(master, k1, k2);
		if (plain == 0) {
			ag_siv_bad += ag_siv_case("SIV 4MB malloc", 0);
		} else {
			for (i = 0; i < sz; i++) {
				plain[i] = (uint8_t)(i * 131u + 17u);
			}
			{
				ag_slice ad;
				ad.p = (const uint8_t *)"classes.dex";
				ad.n = 11;
				t0 = ag_siv_now_ms();
				blob = ag_siv_seal_test(k1, 32, k2, 32, &ad, 1, plain, sz, &blen);
				t1 = ag_siv_now_ms();
				{
					uint8_t *out = ag_siv_decrypt(master, ad.p, ad.n, blob, blen, &outlen);
					t2 = ag_siv_now_ms();
					if (out == 0 || outlen != sz || memcmp(out, plain, sz) != 0) {
						ok = 0;
					}
					free(out);
				}
			}
			printf("SIV_PERF_4MB seal_ms=%.1f open_ms=%.1f\n", t1 - t0, t2 - t1);
			if (!ok) {
				printf("FAIL SIV 4MB 往返\n");
				ag_siv_bad++;
			} else if (t2 - t1 > 300.0) {
				printf("FAIL SIV 4MB 解密超过 300ms\n");
				ag_siv_bad++;
			} else {
				printf("PASS SIV 4MB 解密（%.1f ms，含 S2V 复算）\n", t2 - t1);
			}
		}
		free(blob);
		free(plain);
	}

	return ag_siv_bad;
}

#endif /* AG_HOST_TEST */

#endif /* APKGUARD_SIV_H */
