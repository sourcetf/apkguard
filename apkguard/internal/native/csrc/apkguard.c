/*
 * apkguard 原生防护库。
 *
 * 提供两项能力：
 *   - C1 密钥 native 派生：载荷密钥由**只存在于本文件里的种子**与 APK 的
 *     签名证书摘要共同派生。密钥因此不再以明文出现在 DEX 中；换掉签名证书
 *     重打包后，派生出的密钥不同，密文载荷根本无法解开。
 *   - C4 反调试：检测是否被 ptrace 跟踪（gdb/lldb/IDA 附加的必要条件）。
 *
 * 本文件刻意不依赖任何第三方库，也不依赖 libc 的加密实现：SHA-256 自带一份，
 * 这样既没有外部依赖，行为也完全可预测。
 *
 * 可测性设计：核心逻辑用宏与平台相关部分隔离，
 *   - 定义 AG_HOST_TEST 即可用宿主编译器（TCC/clang）直接编译运行，
 *     以 NIST 测试向量验证 SHA-256；开发期就是这样做过验证的；
 *   - 定义 AG_JNI 才引入 <jni.h> 并导出 JNI 入口（NDK 交叉编译时）。
 */

/* glibc 的 dladdr/Dl_info 需要 _GNU_SOURCE；bionic 默认可见。
 * 只在宿主 Linux 实测（AG_LINUX_TEST）下开启，不影响 NDK 产物。 */
#if defined(AG_LINUX_TEST) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE 1
#endif

#include <stdint.h>
#include <dlfcn.h>

#include "obfuscate.h"

/* ------------------------------------------------------------------ */
/* C3：敏感字符串密文表（加解密原语见 obfuscate.h）                    */
/* ------------------------------------------------------------------ */
/*
 * 这里只出现密文与「用途」注释，明文不落在源码里。-O2 下密钥流必须读
 * volatile 的 g_ag_ks_key，无法被常量折叠回明文，因此构建产物里也扫不到。
 * 离线生成密文的算法与 ag_ks_byte 逐位一致：enc[i] = plain[i] ^ ks(i, salt)。
 */
#define AG_SALT_STATUS         0x5d3a1f27u
#define AG_SALT_MAPS           0x76b4c9e1u
#define AG_SALT_FRIDA          0x1f0c8a53u
#define AG_SALT_XPOSED         0x2ab7d46fu
#define AG_SALT_SUBSTRATE      0x3c58e2a9u
#define AG_SALT_LINJECTOR      0x49d1b753u
#define AG_SALT_LIBHOOK        0x5718af2du
#define AG_SALT_HOOKZZ         0x6e2c40b7u
#define AG_SALT_WHALE          0x7d94e63fu
#define AG_SALT_DDI            0x0b6f3ad1u
#define AG_SALT_EPIC           0x18e75c4bu
#define AG_SALT_MAGISK         0x24c9f06du
#define AG_SALT_TAG            0x31a8d5e3u
#define AG_SALT_TPID           0x43b1c97fu
#define AG_SALT_LOG_NOPATH     0x52d8e4a1u
#define AG_SALT_LOG_OPENFAIL   0x6f13b95du
#define AG_SALT_LOG_NOSEC      0x7a46c8e9u

/* C4 反调试：进程状态文件路径 */
AG_DEFSTR(ag_s_status, AG_SALT_STATUS,
	0x47, 0xbc, 0x28, 0xec, 0xe1, 0x0e, 0xae, 0x3c, 0x72, 0x97, 0x5c, 0x23,
	0xb2, 0x6c, 0x62, 0x48, 0xfc);

/* C5 反注入：内存映射表路径 */
AG_DEFSTR(ag_s_maps, AG_SALT_MAPS,
	0x5e, 0xce, 0x86, 0x37, 0x3d, 0xae, 0x5f, 0xe6, 0xee, 0x32, 0xca, 0x01,
	0x9d, 0x7f, 0x42);

/* C5：注入框架特征名 1 */
AG_DEFSTR(ag_s_frida, AG_SALT_FRIDA,
	0xdb, 0xdd, 0x93, 0x8b, 0x86);

/* C5：注入框架特征名 2 */
AG_DEFSTR(ag_s_xposed, AG_SALT_XPOSED,
	0xfd, 0x14, 0x6f, 0xed, 0xa3, 0x09);

/* C5：注入框架特征名 3 */
AG_DEFSTR(ag_s_substrate, AG_SALT_SUBSTRATE,
	0xa6, 0x05, 0x7e, 0x3c, 0xda, 0x1a, 0x90, 0x48, 0x52);

/* C5：注入框架特征名 4 */
AG_DEFSTR(ag_s_linjector, AG_SALT_LINJECTOR,
	0xfd, 0xcc, 0x58, 0xb1, 0x42, 0xef, 0x10, 0x47, 0x46);

/* C5：注入框架特征名 5 */
AG_DEFSTR(ag_s_libhook, AG_SALT_LIBHOOK,
	0x91, 0x6d, 0x3b, 0xaa, 0x34, 0x5f, 0x24);

/* C5：注入框架特征名 6 */
AG_DEFSTR(ag_s_hookzz, AG_SALT_HOOKZZ,
	0xb8, 0x58, 0x22, 0xbb, 0x84, 0xab);

/* C5：注入框架特征名 7 */
AG_DEFSTR(ag_s_whale, AG_SALT_WHALE,
	0xa0, 0xfa, 0x2c, 0xa2, 0x90);

/* C5：注入框架特征名 8 */
AG_DEFSTR(ag_s_ddi, AG_SALT_DDI,
	0x3e, 0xbe, 0x33);

/* C5：注入框架特征名 9 */
AG_DEFSTR(ag_s_epic, AG_SALT_EPIC,
	0x4e, 0xe7, 0x2f, 0xc1);

/* C5：root 注入框架（Zygisk）特征名 */
AG_DEFSTR(ag_s_magisk, AG_SALT_MAGISK,
	0x8c, 0xde, 0x73, 0x9a, 0x58, 0x04);

/* 日志 tag */
AG_DEFSTR(ag_s_tag, AG_SALT_TAG,
	0xfb, 0x7c, 0x08, 0x6a, 0xc5, 0x82, 0x08, 0x7d);

/* C4：被跟踪字段名（在进程状态文件内容里匹配） */
AG_DEFSTR(ag_s_tpid, AG_SALT_TPID,
	0x96, 0xc9, 0xca, 0xfe, 0x94, 0x2d, 0x85, 0xb1, 0x88, 0x21);

/* C6 降级日志 1（无 printf 参数） */
AG_DEFSTR(ag_s_log_nopath, AG_SALT_LOG_NOPATH,
	0xd8, 0xc0, 0xfa, 0xb2, 0x92, 0x06, 0xe4, 0xbc, 0x0c, 0x97, 0x0f, 0xa3,
	0x90, 0x8e, 0xdd, 0x6c, 0xcd, 0xb7, 0x5b, 0x23, 0x3e, 0xb3, 0x89, 0x8c,
	0x9b, 0x0f, 0x2c, 0x1b, 0x99, 0x07, 0x2e, 0x93, 0xbf, 0xa2, 0x76, 0x16,
	0x4e, 0xf2, 0xfd, 0xb0, 0x09, 0xd3, 0xae, 0xbc, 0xaa, 0x68);

/* C6 降级日志 2（path, g_sec_err） */
AG_DEFSTR(ag_s_log_openfail, AG_SALT_LOG_OPENFAIL,
	0xe4, 0x14, 0x9b, 0x52, 0x34, 0x65, 0x54, 0x53, 0x12, 0xef, 0xf6, 0xde,
	0xae, 0x9f, 0x3c, 0x77, 0x35, 0x68, 0xaa, 0x59, 0x67, 0xb1, 0x5d, 0xda,
	0xea, 0x64, 0x86, 0xd0, 0x78, 0x8c, 0x42, 0xf5, 0x0d, 0xd8, 0x34, 0x73,
	0x13, 0x86, 0xf0, 0xd2, 0x5f, 0xc7, 0x88, 0x23, 0xdc, 0x6c, 0x17, 0x87,
	0xfa, 0xa3, 0xc3, 0xff, 0x2d, 0x2f, 0xf0, 0x72, 0x8f, 0x67, 0x21, 0x5d,
	0x37, 0xfd, 0x0a, 0x43, 0x32, 0x4a);

/* C6 降级日志 3（g_sec_err） */
AG_DEFSTR(ag_s_log_nosec, AG_SALT_LOG_NOSEC,
	0xf8, 0x29, 0xdc, 0x8b, 0xff, 0x6a, 0x9e, 0xc7, 0x1b, 0xee, 0xf4, 0xee,
	0x9f, 0x6b, 0x5e, 0x4b, 0xe6, 0x57, 0xca, 0xe9, 0x29, 0xa7, 0x44, 0xef,
	0xdf, 0x7e, 0x41, 0xa7, 0x98, 0x3e, 0x0a, 0xae, 0x77, 0xcd, 0x0b, 0x81,
	0x03, 0xfa, 0x38, 0xe4, 0x1e, 0x83, 0x4b, 0x78, 0x99, 0x31, 0x5b, 0x34,
	0xce, 0xe3, 0x25, 0x3c, 0x41, 0x1a, 0x61, 0x56, 0xfb, 0xc9, 0x30, 0xa4,
	0xa0, 0xa9, 0x4e, 0x91, 0x4f, 0x96, 0x23, 0x66, 0xee, 0x37, 0x6e, 0xa7,
	0xaf, 0xd0, 0x0e, 0xf2);

/*
 * 可观测的日志：有意不用「悄悄记在内存里」的方式。
 *
 * 存在的理由：C6 的自校验在本机（模拟器 / extractNativeLibs=false 的设备）
 * **无法定位自身文件**——native 库是从 APK 内部直接加载的，/proc/self/maps
 * 里对应的是 base.apk 而不是 .so 自己的路径。旧实现此时「当作完整」返回，
 * 于是完整性校验静默失效（用户以为有防护，实际没有）。现在无论走哪条分支，
 * 都会打一行日志，使这种降级在 logcat 里**可见**，而不是无声无息。
 *
 * C3 之后 tag 与格式串也都以密文存放，ag_logv 先解密到栈上再交给平台日志。
 * 语义不变：只是取字符串的时机从编译期挪到调用时。
 */
#if defined(AG_JNI)
#include <android/log.h>
#include <stdarg.h>
static void ag_logv(const uint8_t *enc, uint32_t n, uint32_t salt, ...) {
	char tag[ag_s_tag_len + 1];
	char fmt[256];
	va_list ap;
	ag_dec((uint8_t *)tag, ag_s_tag_enc, (uint32_t)ag_s_tag_len, AG_SALT_TAG);
	tag[ag_s_tag_len] = 0;
	if (n > sizeof(fmt) - 1) {
		n = sizeof(fmt) - 1;
	}
	ag_dec((uint8_t *)fmt, enc, n, salt);
	fmt[n] = 0;
	va_start(ap, salt);
	__android_log_vprint(4 /*ANDROID_LOG_INFO*/, tag, fmt, ap);
	va_end(ap);
}
#define AG_LOG_ENC(enc, len, salt, ...) ag_logv((enc), (uint32_t)(len), (salt), ##__VA_ARGS__)
#elif defined(AG_HOST_TEST) || defined(AG_LINUX_TEST)
#include <stdio.h>
#include <stdarg.h>
static void ag_logv(const uint8_t *enc, uint32_t n, uint32_t salt, ...) {
	char fmt[256];
	va_list ap;
	if (n > sizeof(fmt) - 1) {
		n = sizeof(fmt) - 1;
	}
	ag_dec((uint8_t *)fmt, enc, n, salt);
	fmt[n] = 0;
	/* 用 fputc(10,..) 而非转义换行：本项目里转义序列多次被多层工具链吃掉 */
	fprintf(stderr, "[AG] ");
	va_start(ap, salt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc(10, stderr);
}
#define AG_LOG_ENC(enc, len, salt, ...) ag_logv((enc), (uint32_t)(len), (salt), ##__VA_ARGS__)
#else
#define AG_LOG_ENC(enc, len, salt, ...) ((void)0)
#endif

/*
 * ag_log_once 只打印一次。
 *
 * 给「能力降级」这类日志用：D4 的看门狗每 3 秒调一次 ag_intact()，若每次都打
 * 同一行日志，logcat 会被刷屏（实测每个进程每 3 秒一行），既淹没有效信息，
 * 又会让「降级可见」这个设计初衷变成噪音而被无视。降级是设备特性、不会自愈，
 * 打一次足够。
 */
static int ag_once_flag = 0;
#define AG_LOG_ONCE_ENC(enc, len, salt, ...) do { \
	if (!ag_once_flag) { ag_once_flag = 1; AG_LOG_ENC((enc), (len), (salt), ##__VA_ARGS__); } \
} while (0)

/* ------------------------------------------------------------------ */
/* SHA-256                                                             */
/* ------------------------------------------------------------------ */

typedef struct {
	uint32_t h[8];
	uint64_t len;
	uint8_t buf[64];
	uint32_t used;
} ag_sha256;

static const uint32_t AG_K[64] = {
	0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
	0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
	0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
	0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
	0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
	0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
	0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
	0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
	0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
	0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
	0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

static uint32_t ag_rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void ag_sha256_block(ag_sha256 *s, const uint8_t *p) {
	uint32_t w[64];
	int i;
	for (i = 0; i < 16; i++) {
		w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
		       ((uint32_t)p[i * 4 + 2] << 8) | (uint32_t)p[i * 4 + 3];
	}
	for (i = 16; i < 64; i++) {
		uint32_t s0 = ag_rotr(w[i - 15], 7) ^ ag_rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
		uint32_t s1 = ag_rotr(w[i - 2], 17) ^ ag_rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}
	uint32_t a = s->h[0], b = s->h[1], c = s->h[2], d = s->h[3];
	uint32_t e = s->h[4], f = s->h[5], g = s->h[6], h = s->h[7];
	for (i = 0; i < 64; i++) {
		uint32_t S1 = ag_rotr(e, 6) ^ ag_rotr(e, 11) ^ ag_rotr(e, 25);
		uint32_t ch = (e & f) ^ ((~e) & g);
		uint32_t t1 = h + S1 + ch + AG_K[i] + w[i];
		uint32_t S0 = ag_rotr(a, 2) ^ ag_rotr(a, 13) ^ ag_rotr(a, 22);
		uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
		uint32_t t2 = S0 + maj;
		h = g; g = f; f = e; e = d + t1;
		d = c; c = b; b = a; a = t1 + t2;
	}
	s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d;
	s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += h;
}

static void ag_sha256_init(ag_sha256 *s) {
	s->h[0] = 0x6a09e667u; s->h[1] = 0xbb67ae85u;
	s->h[2] = 0x3c6ef372u; s->h[3] = 0xa54ff53au;
	s->h[4] = 0x510e527fu; s->h[5] = 0x9b05688cu;
	s->h[6] = 0x1f83d9abu; s->h[7] = 0x5be0cd19u;
	s->len = 0; s->used = 0;
}

static void ag_sha256_update(ag_sha256 *s, const uint8_t *p, uint32_t n) {
	s->len += n;
	while (n > 0) {
		uint32_t take = 64 - s->used;
		if (take > n) {
			take = n;
		}
		{
			uint32_t i;
			for (i = 0; i < take; i++) {
				s->buf[s->used + i] = p[i];
			}
		}
		s->used += take;
		p += take;
		n -= take;
		if (s->used == 64) {
			ag_sha256_block(s, s->buf);
			s->used = 0;
		}
	}
}

static void ag_sha256_final(ag_sha256 *s, uint8_t out[32]) {
	uint64_t bits = s->len * 8;
	uint32_t i;
	s->buf[s->used++] = 0x80;
	if (s->used > 56) {
		while (s->used < 64) {
			s->buf[s->used++] = 0;
		}
		ag_sha256_block(s, s->buf);
		s->used = 0;
	}
	while (s->used < 56) {
		s->buf[s->used++] = 0;
	}
	for (i = 0; i < 8; i++) {
		s->buf[56 + i] = (uint8_t)(bits >> (56 - 8 * i));
	}
	ag_sha256_block(s, s->buf);
	for (i = 0; i < 8; i++) {
		out[i * 4] = (uint8_t)(s->h[i] >> 24);
		out[i * 4 + 1] = (uint8_t)(s->h[i] >> 16);
		out[i * 4 + 2] = (uint8_t)(s->h[i] >> 8);
		out[i * 4 + 3] = (uint8_t)s->h[i];
	}
}

/* ------------------------------------------------------------------ */
/* AES-SIV（RFC 5297）解密                                             */
/* ------------------------------------------------------------------ */
/*
 * 实现在 siv.h：AES-128/256 加密方向（T 表来自 aes_tables.h）、CMAC、
 * S2V（多组件 AD）、CTR、KDF（两条域串以密文形态存放）与生产入口
 * ag_siv_decrypt。只依赖上面的 ag_sha256 与 C3 的串解密原语，不需要
 * AES 逆密码（CMAC/CTR 都只用 E_K）。
 *
 * JNI 入口 Native.sivDecrypt(key32, ad, blob) 见本文件 AG_JNI 小节；
 * 宿主自测（RFC 4493/5297 官方向量 + Go 互操作 + 4 MB 计时）在
 * AG_HOST_TEST 小节调用 ag_siv_selftest()。
 */
#include "aes_tables.h"
#include "siv.h"

/* ------------------------------------------------------------------ */
/* C1：密钥派生                                                        */
/* ------------------------------------------------------------------ */

/*
 * 派生种子以「掩码异或」的形式存放：直接以明文常量躺在 .so 里的话，
 * 一条 `strings` 或者一次熵扫描就能命中；异或之后至少需要读懂这段代码
 * 才能还原。这不是密码学意义上的保护（种子终究在文件里），但与
 * 「明文写在 DEX 里」相比，提取成本从「打开 jadx 就能看到」提高到
 * 「必须反汇编 .so 并理解本函数」。
 */
static const uint8_t AG_SEED_OBF[32] = {
	0x1f, 0x7c, 0x2e, 0x91, 0x05, 0xb8, 0x4d, 0x33,
	0xa2, 0x6e, 0xc5, 0x10, 0x8b, 0x47, 0xfa, 0x29,
	0x64, 0xd3, 0x0c, 0x95, 0x38, 0xe1, 0x5a, 0xb6,
	0x0d, 0x82, 0xf7, 0x43, 0xce, 0x19, 0xa4, 0x70};

static const uint8_t AG_SEED_MASK[8] = {0xa5, 0x3c, 0xd7, 0x62, 0x9b, 0x0e, 0x54, 0xf1};

/*
 * ag_seed 还原派生的种子。
 *
 * C3 控制流平坦化：原「初始化 i → 循环条件 → 循环体 → 返回」四个基本块
 * 映射为状态 0/1/2/3，语义保持论证：
 *   - 状态 1 的条件转移 st=(i<32)?2:3 与原 for 的循环条件逐位一致
 *     （进入循环体 / 退出循环）；状态 2 完成原循环体并 i++ 后回到 1；
 *   - 状态 3 即原函数的 return；状态变量与状态转移都是 volatile，
 *     编译器必须保留间接分派，无法把 switch 还原成 for 结构；
 *   - AG_OPAQUE_GUARD 只插入死分支（volatile 写，无副作用），
 *     其后语句与状态转移不受谓词影响，行为与改造前相同。
 */
static AG_NOINLINE void ag_seed(uint8_t out[32]) {
	AG_FLAT_DECL(st);
	uint32_t i = 0;
	AG_FLAT_LOOP(st) {
		case 0:
			i = 0;
			st = 1;
			break;
		case 1:
			AG_OPAQUE_GUARD(i ^ 0x5au);
			st = (i < 32u) ? 2u : 3u;
			break;
		case 2:
			out[i] = (uint8_t)(AG_SEED_OBF[i] ^ AG_SEED_MASK[i & 7]);
			i++;
			st = 1;
			break;
		case 3:
			return;
		default:
			st = 1; /* 不可达；闭环避免调度器落空 */
			break;
	}
}

/*
 * ag_derive 计算载荷密钥：SHA-256(seed ‖ 签名证书摘要)。
 *
 * 把签名摘要并入派生输入是这套方案的要点：重打包者必然更换签名证书，
 * 于是运行时算出的密钥与加密时所用的不同，密文载荷**在密码学层面**
 * 无法解开——这比「检测到异常就退出」更彻底，因为不存在「跳过检测」
 * 的绕过路径。
 *
 * sig 为 APK 签名证书的 SHA-256（32 字节）；siglen 允许为 0，
 * 此时退化为仅由种子派生。
 */
static AG_NOINLINE void ag_derive(const uint8_t *sig, uint32_t siglen, uint8_t out[32]) {
	uint8_t seed[32];
	ag_sha256 s;
	int have_sig;
	AG_FLAT_DECL(st);
	/*
	 * C3 控制流平坦化：原线性序列「还原种子 → 初始化 → 喂种子 →
	 * （可选）喂签名 → 收尾」映射为状态 0..6。语义保持论证：
	 *   - 状态 3 用原条件 (sig != 0 && siglen > 0) 决定去状态 4 还是跳过
	 *     到 5，与原 if 完全一致；have_sig 的计算无副作用；
	 *   - 状态 0/1/2/4/5 是原语句的一一搬移，状态 6 即 return；
	 *   - AG_OPAQUE_GUARD 不参与状态转移（它不改变 st），只增加死分支。
	 * 派生结果只取决于 seed‖sig 的字节序列，因此该变换逐位保持输出。
	 */
	AG_FLAT_LOOP(st) {
		case 0:
			ag_seed(seed);
			st = 1;
			break;
		case 1:
			ag_sha256_init(&s);
			st = 2;
			break;
		case 2:
			AG_OPAQUE_GUARD(siglen ^ (uint32_t)(uintptr_t)sig);
			ag_sha256_update(&s, seed, 32);
			st = 3;
			break;
		case 3:
			have_sig = (sig != 0 && siglen > 0) ? 1 : 0;
			st = have_sig ? 4u : 5u;
			break;
		case 4:
			ag_sha256_update(&s, sig, siglen);
			st = 5;
			break;
		case 5:
			ag_sha256_final(&s, out);
			st = 6;
			break;
		case 6:
			return;
		default:
			st = 3; /* 不可达；闭环避免调度器落空 */
			break;
	}
}

/* ------------------------------------------------------------------ */
/* C4：反调试                                                          */
/* ------------------------------------------------------------------ */

/*
 * AG_LINUX_TEST：在 WSL/CI 的 Linux 宿主编译（glibc）下也编译这一段，
 * 用于「宿主二进制实测」——正常环境 vs 被 ptrace / 端口监听时的行为对照，
 * 以及 ag_intact 对原文件/篡改文件返回值的对照。NDK 构建不定义它。
 */
#if !defined(AG_HOST_TEST) || defined(AG_LINUX_TEST)

#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

/*
 * 极薄的系统调用包装。
 *
 * 单独包一层是为了让 ag_debugged 不直接依赖 libc 头文件的存在性：
 * 宿主自测（AG_HOST_TEST）时这些函数整体不参与编译。
 */
static int ag_open(const char *path, int flags) { return open(path, flags); }
static int ag_read(int fd, char *buf, int n) { return (int)read(fd, buf, (unsigned)n); }
static int ag_read_byte(int fd, uint8_t *buf, int n) { return (int)read(fd, buf, (unsigned)n); }
static void ag_close(int fd) { close(fd); }
/*
 * ag_seek 返回 0 表示成功、-1 表示失败。
 *
 * 注意**不能**直接 `return lseek(...)`：lseek 成功时返回的是**新的文件偏移**，
 * 只有 seek 0 才恰好返回 0。曾因此留下一个极隐蔽的缺陷——所有
 * `if (ag_seek(fd, off) != 0) return 0;` 的写法，只要 off 非 0 就被判成失败，
 * 于是 ELF 节表定位在第一次非零 seek 处即告失败，C6/D4 在**所有设备上**
 * 静默降级，表现为「自身文件缺少 .text/.rodata 节名」。
 */
static int ag_seek(int fd, int64_t off) {
	return lseek(fd, (off_t)off, SEEK_SET) < 0 ? -1 : 0;
}
/* 取文件大小；失败返回负值。SEEK_END 在没有 <stdio.h> 的环境里不一定可见，
 * 这里按 ABI 语义写死（bionic 与 glibc 都是 2）。 */
static long ag_size(int fd) {
	long cur = lseek(fd, 0, SEEK_CUR);
	long end;
	if (cur < 0) {
		return -1;
	}
	end = lseek(fd, 0, 2 /* SEEK_END */);
	(void)lseek(fd, cur, SEEK_SET);
	return end;
}
static int ag_socket(int d, int t, int p) { return socket(d, t, p); }
static int ag_setsockopt(int fd, int lv, int opt, const void *v, unsigned len) {
	return setsockopt(fd, lv, opt, v, len);
}
static uint16_t ag_htons(uint16_t v) { return htons(v); }
static uint32_t ag_htonl(uint32_t v) { return htonl(v); }

/*
 * ag_debugged 返回 1 表示检测到调试器。
 *
 * 只读 /proc/self/status 的 TracerPid：这是最不具侵入性的判据——它不改变
 * 进程状态，也不会像 ptrace(PTRACE_TRACEME) 那样影响正常的崩溃上报。
 *
 * 判定是「失败开放」的：读不到文件、解析不出数字都按「没有调试器」处理。
 * 宁可漏报，也不能因为 ROM 差异把正常用户挡在门外。
 */
static AG_NOINLINE int ag_debugged(void) {
	char buf[4096];
	char needle[ag_s_tpid_len + 1];
	int fd = -1, n = 0, i = 0;
	AG_FLAT_DECL(st);
	/*
	 * C3 控制流平坦化：原「open → 判 fd → read/close → 判 n → for 扫描
	 * → 匹配后跳过空白并判数字」映射为状态 0..8。语义保持论证：
	 *   - 状态 1/3 的提前 return 0 与原 if 失败分支一致；
	 *   - 状态 4 的循环条件与原 for 的 i+10<n 逐位相同，未命中时状态 5
	 *     自增 i 后回到 4，命中则进 6/7；扫描结束（条件不成立）走状态 8
	 *     返回 0，与原「for 结束返回 0」一致；
	 *   - 状态 5 的逐字节比较等价于原来的 10 个字符常量比较，只是匹配串
	 *     由解密得到；比较所需的 i+9 由 i+10<n 保证在缓冲区内；
	 *   - AG_OPAQUE_GUARD 不触碰 st，不改变任何控制流。
	 */
	AG_FLAT_LOOP(st) {
		case 0: {
			AG_DECL_STR(ag_s_status, AG_SALT_STATUS);
			fd = ag_open(ag_s_status_buf, 0);
			st = 1;
			break;
		}
		case 1:
			if (fd < 0) {
				return 0;
			}
			st = 2;
			break;
		case 2:
			n = ag_read(fd, buf, (int)sizeof(buf) - 1);
			ag_close(fd);
			st = 3;
			break;
		case 3:
			AG_OPAQUE_GUARD((uint32_t)n);
			if (n <= 0) {
				return 0;
			}
			buf[n] = 0;
			/* 匹配字段名，其后第一个非 0 数字即被跟踪。 */
			ag_dec((uint8_t *)needle, ag_s_tpid_enc, (uint32_t)ag_s_tpid_len, AG_SALT_TPID);
			needle[ag_s_tpid_len] = 0;
			i = 0;
			st = 4;
			break;
		case 4:
			AG_OPAQUE_GUARD((uint32_t)i ^ (uint32_t)n);
			st = (i + 10 < n) ? 5u : 8u;
			break;
		case 5: {
			int j, hit = 1;
			for (j = 0; j < 10; j++) {
				if (buf[i + j] != needle[j]) {
					hit = 0;
					break;
				}
			}
			if (!hit) {
				i++;
				st = 4;
				break;
			}
			i += 10;
			st = 6;
			break;
		}
		case 6:
			while (i < n && (buf[i] == ' ' || buf[i] == '\t')) {
				i++;
			}
			st = 7;
			break;
		case 7:
			if (i < n && buf[i] >= '1' && buf[i] <= '9') {
				return 1;
			}
			return 0;
		case 8:
			return 0;
		default:
			st = 4; /* 不可达；闭环避免调度器落空 */
			break;
	}
}

static int ag_frida_port(void);

/*
 * C5 的注入特征串表：表项只存密文指针/长度/salt，运行到匹配前才解密到栈。
 * 新增 magisk 一项用于识别 Zygisk 这类把自身映射进应用进程的 root 框架；
 * 不含 "su"/"gum" 这类过短特征：它们是大量正常路径（package/so 名）的子串，
 * 会引入误报，宁可交由端口与其它特征判定。
 */
typedef struct {
	const uint8_t *enc;
	uint32_t len;
	uint32_t salt;
} ag_enc_t;

static const ag_enc_t AG_HOOK_NEEDLES[] = {
	{ag_s_frida_enc, (uint32_t)ag_s_frida_len, AG_SALT_FRIDA},
	{ag_s_xposed_enc, (uint32_t)ag_s_xposed_len, AG_SALT_XPOSED},
	{ag_s_substrate_enc, (uint32_t)ag_s_substrate_len, AG_SALT_SUBSTRATE},
	{ag_s_linjector_enc, (uint32_t)ag_s_linjector_len, AG_SALT_LINJECTOR},
	{ag_s_libhook_enc, (uint32_t)ag_s_libhook_len, AG_SALT_LIBHOOK},
	{ag_s_hookzz_enc, (uint32_t)ag_s_hookzz_len, AG_SALT_HOOKZZ},
	{ag_s_whale_enc, (uint32_t)ag_s_whale_len, AG_SALT_WHALE},
	{ag_s_ddi_enc, (uint32_t)ag_s_ddi_len, AG_SALT_DDI},
	{ag_s_epic_enc, (uint32_t)ag_s_epic_len, AG_SALT_EPIC},
	{ag_s_magisk_enc, (uint32_t)ag_s_magisk_len, AG_SALT_MAGISK},
};
#define AG_NEEDLE_COUNT ((int)(sizeof(AG_HOOK_NEEDLES) / sizeof(AG_HOOK_NEEDLES[0])))

/*
 * ag_hooked 返回 1 表示检测到注入/Hook 框架。
 *
 * 两类判据：
 *   1) /proc/self/maps 里出现 frida / xposed / substrate 等特征模块名。
 *      这是内存注入最直接的痕迹——注入的模块必然出现在映射表里。
 *   2) Frida 默认端口（27042）在本地可连接。服务端模式下的 frida-server
 *      会监听该端口，能连通就说明设备上跑着 Frida。
 *
 * 同样是失败开放：读不到 maps、socket 建不出来都按「未注入」处理。
 *
 * C3 控制流平坦化：状态 0..8 与原基本块一一对应——
 *   open=0；判 fd=1；read/close=2；判 n 与小写化=3；取第 k 个特征=4；
 *   内层扫描条件=5；内层比较=6；全部未命中/读失败 → 状态 8 端口探测。
 * 语义保持论证：
 *   - 状态 5 的 i+ln<=n 与原内层 for 条件逐位相同，未命中 i++ 后回到 5；
 *   - 状态 6 的逐字节比较与原 while(j<ln && ...) 相同；
 *   - 原来的「maps 打不开 / n<=0 直接 return ag_frida_port()」改走
 *     状态 8，仍是同一个函数调用，返回值语义不变；
 *   - 特征串改由表驱动解密，内容与原字面量一致，仅存放形态不同。
 */
static AG_NOINLINE int ag_hooked(void) {
	char buf[16384];
	char needle[32];
	int fd = -1, n = 0, i = 0, k = 0, ln = 0;
	AG_FLAT_DECL(st);
	AG_FLAT_LOOP(st) {
		case 0: {
			AG_DECL_STR(ag_s_maps, AG_SALT_MAPS);
			fd = ag_open(ag_s_maps_buf, 0);
			st = 1;
			break;
		}
		case 1:
			if (fd < 0) {
				st = 8;
				break;
			}
			n = ag_read(fd, buf, (int)sizeof(buf) - 1);
			ag_close(fd);
			st = 2;
			break;
		case 2:
			AG_OPAQUE_GUARD((uint32_t)n ^ 0x27u);
			if (n <= 0) {
				st = 8;
				break;
			}
			buf[n] = 0;
			i = 0;
			st = 3;
			break;
		case 3:
			/* 逐字节小写化比较，避免依赖 tolower（locale 行为不确定）。 */
			while (i < n) {
				if (buf[i] >= 'A' && buf[i] <= 'Z') {
					buf[i] = (char)(buf[i] + 32);
				}
				i++;
			}
			k = 0;
			st = 4;
			break;
		case 4:
			if (k >= AG_NEEDLE_COUNT) {
				st = 8;
				break;
			}
			ln = (int)AG_HOOK_NEEDLES[k].len;
			ag_dec((uint8_t *)needle, AG_HOOK_NEEDLES[k].enc,
			       AG_HOOK_NEEDLES[k].len, AG_HOOK_NEEDLES[k].salt);
			needle[ln] = 0;
			i = 0;
			st = 5;
			break;
		case 5:
			AG_OPAQUE_GUARD((uint32_t)k ^ (uint32_t)i);
			if (i + ln <= n) {
				st = 6;
			} else {
				k++;
				st = 4;
			}
			break;
		case 6: {
			int j = 0;
			while (j < ln && buf[i + j] == needle[j]) {
				j++;
			}
			if (j == ln) {
				return 1;
			}
			i++;
			st = 5;
			break;
		}
		case 8:
			return ag_frida_port();
		default:
			st = 8; /* 不可达；闭环避免调度器落空 */
			break;
	}
}

/*
 * ag_frida_port 探测 Frida 默认端口是否在本地监听。
 *
 * C3 控制流平坦化：socket 建立、fd 判空、参数填充、connect 结果分支、
 * 两个收尾 return 分别是状态 0..5。语义保持论证：状态转移与原来的
 * if/else 一一对应（connect==0 → 状态 4 返回 1；否则状态 5 返回 0，
 * 且两条路径都先 close(fd)），参数与常量保持不变。
 */
static AG_NOINLINE int ag_frida_port(void) {
	struct sockaddr_in sa;
	int fd = -1;
	int one = 1;
	AG_FLAT_DECL(st);
	AG_FLAT_LOOP(st) {
		case 0:
			fd = ag_socket(AF_INET, SOCK_STREAM, 0);
			st = 1;
			break;
		case 1:
			if (fd < 0) {
				return 0;
			}
			st = 2;
			break;
		case 2:
			AG_OPAQUE_GUARD((uint32_t)fd);
			/* Linux 没有 SO_NOSIGPIPE（那是 BSD/macOS 的选项）；这里保留调用
			 * 只为在某些兼容层下生效，失败无副作用。 */
			ag_setsockopt(fd, SOL_SOCKET, 0, &one, (unsigned)sizeof(one));
			sa.sin_family = AF_INET;
			sa.sin_port = ag_htons(27042);
			sa.sin_addr.s_addr = ag_htonl(0x7f000001u); /* 127.0.0.1 */
			st = 3;
			break;
		case 3:
			st = (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0) ? 4u : 5u;
			break;
		case 4:
			close(fd);
			return 1;
		case 5:
			close(fd);
			return 0;
		default:
			st = 5; /* 不可达；闭环避免调度器落空 */
			break;
	}
}

/*
 * ---- C6 完整性自校验 ----
 *
 * 思路：对自身 .so 的 **.text 与 .rodata 两个节** 做 SHA-256，与编译期
 * 写入 .agexpect 节的期望值比对。
 *
 * 为什么是「.text + .rodata」而不是整个文件：
 *   - 期望值自己就存在文件里，整文件哈希会自指；把它单独放进 .agexpect 节
 *     并只哈希另外两个节，自指问题自然消失，也就不需要在构建期回填任何
 *     文件偏移——偏移由运行时解析 ELF 节表得到。
 *   - 覆盖 .rodata 是必要的：派生种子就住在那里。只校验代码的话，
 *     改掉种子再改掉校验逻辑的代价会低得多。
 *
 * 失败开放：解析不了自己的 ELF、读不到文件，一律返回「完整」。
 * C6 的价值是发现「库被改了」，不是把「读不到」也判成篡改——
 * 后者会在部分 ROM 上造成误杀，代价远高于漏报。
 */

/* AG_EXPECT 存放期望摘要，位于独立的 .agexpect 节，不参与被哈希范围。 */
__attribute__((section(".agexpect"), used))
static const uint8_t AG_EXPECT[32] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

static uint16_t ag_rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t ag_rd32(const uint8_t *p) {
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
	       ((uint32_t)p[3] << 24);
}
static uint64_t ag_rd64(const uint8_t *p) {
	return (uint64_t)ag_rd32(p) | ((uint64_t)ag_rd32(p + 4) << 32);
}

/* g_sec_err 记录 ag_find_section 最近一次失败的原因，供降级日志显示。
 * 只用于诊断，不参与判定。 */
static const char *g_sec_err = "?";

/*
 * ag_find_section 在已打开的 ELF 文件中查找指定名字的节。
 *
 * 返回 1 并写回文件内的偏移与长度；找不到返回 0。
 *
 * 必须同时支持 ELF32 与 ELF64：armeabi-v7a 是 32 位，仍有一批在售设备。
 * 只认 64 位的话，32 位产物上的完整性校峰会静默失效——那是最糟的失败
 * 模式（看起来有防护，实际没有）。
 */
static int ag_find_section(int fd, uint64_t base, const char *want, uint64_t *off, uint64_t *size) {
	uint8_t hdr[64];
	int n;
	int is64;
	uint64_t shoff = 0, stroff = 0, strsize = 0;
	uint16_t shentsize, shnum, shstrndx;
	uint16_t i;
	/*
	 * 必须先把文件偏移复位到 base：本函数会被连续调用两次（先 .text 再 .rodata），
	 * 上一次调用结束时 fd 停在某个节名/节头的位置。若不复位，第二次读到的就
	 * 不是 ELF 头，magic 检查失败 → 返回 0 → 调用方判定「缺少节名」并跳过
	 * 自校验。后果是 C6/D4 **完全失效**，而 logcat 里只有一行容易被忽略的日志
	 * ——正是本项目最忌讳的「看起来有防护，实际没有」。
	 *
	 * base 非 0 的情形：库被直接打包在 APK 内（extractNativeLibs=false），
	 * dladdr 给出的是 "…/base.apk!/lib/<abi>/libxxx.so"。此时 fd 指向 APK，
	 * ELF 从条目数据处开始，base 就是该条目的数据偏移（见 ag_zip_data_offset）。
	 */
	if (ag_seek(fd, (int64_t)base) != 0) {
		g_sec_err = "seek";
		return 0;
	}
	n = ag_read_byte(fd, hdr, 64);
	if (n < 64) {
		g_sec_err = "short-header";
		return 0;
	}
	if (!(hdr[0] == 0x7f && hdr[1] == 'E' && hdr[2] == 'L' && hdr[3] == 'F')) {
		g_sec_err = "bad-magic";
		return 0;
	}
	if (hdr[5] != 1) {
		g_sec_err = "big-endian";
		return 0; /* 大端：Android 上不存在 */
	}
	is64 = (hdr[4] == 2) ? 1 : (hdr[4] == 1 ? 0 : -1);
	if (is64 < 0) {
		g_sec_err = "bad-class";
		return 0;
	}
	if (is64) {
		shoff = ag_rd64(hdr + 0x28);
		shentsize = ag_rd16(hdr + 0x3a);
		shnum = ag_rd16(hdr + 0x3c);
		shstrndx = ag_rd16(hdr + 0x3e);
	} else {
		shoff = ag_rd32(hdr + 0x20);
		shentsize = ag_rd16(hdr + 0x2e);
		shnum = ag_rd16(hdr + 0x30);
		shstrndx = ag_rd16(hdr + 0x32);
	}
	if (shoff == 0 || shnum == 0 || shstrndx >= shnum) {
		g_sec_err = "no-section-table";
		return 0;
	}
	if (shentsize < (is64 ? 64 : 40)) {
		g_sec_err = "bad-shentsize";
		return 0;
	}
	{
		uint8_t sh[64];
		/* 先读节名字表所在节，取得字符串表的位置。 */
		if (ag_seek(fd, (int64_t)(base + shoff + (uint64_t)shstrndx * shentsize)) != 0) {
			g_sec_err = "section-name-table-seek";
			return 0;
		}
		if (ag_read_byte(fd, sh, (int)shentsize) < (int)shentsize) {
			g_sec_err = "section-name-table-read";
			return 0;
		}
		stroff = is64 ? ag_rd64(sh + 0x18) : ag_rd32(sh + 0x10);
		strsize = is64 ? ag_rd64(sh + 0x20) : ag_rd32(sh + 0x14);
		if (stroff == 0 || strsize == 0) {
			g_sec_err = "section-name-table-empty";
			return 0;
		}
	}
	for (i = 0; i < shnum; i++) {
		uint8_t sh[64];
		uint8_t name[64];
		uint32_t name_off;
		int k = 0;
		if (ag_seek(fd, (int64_t)(base + shoff + (uint64_t)i * shentsize)) != 0) {
			g_sec_err = "section-header-seek";
			return 0;
		}
		if (ag_read_byte(fd, sh, (int)shentsize) < (int)shentsize) {
			g_sec_err = "section-header-read";
			return 0;
		}
		name_off = ag_rd32(sh);
		if (name_off >= strsize) {
			continue;
		}
		if (ag_seek(fd, (int64_t)(base + stroff + name_off)) != 0) {
			g_sec_err = "section-name-seek";
			return 0;
		}
		if (ag_read_byte(fd, name, 63) <= 0) {
			continue;
		}
		name[63] = 0;
		while (k < 63 && want[k] && name[k] == (uint8_t)want[k]) {
			k++;
		}
		if (want[k] == 0 && name[k] == 0) {
			/* 返回**文件绝对偏移**：base 是库在 fd 里的起点（APK 情形下为条目数据偏移）。 */
			*off = base + (is64 ? ag_rd64(sh + 0x18) : ag_rd32(sh + 0x10));
			*size = is64 ? ag_rd64(sh + 0x20) : ag_rd32(sh + 0x14);
			return 1;
		}
	}
	g_sec_err = "section-not-found";
	return 0;
}

/* ---- 直接打包在 APK 内的自身文件（extractNativeLibs=false） ---- */

/*
 * 现代 Android（targetSdk>=30）默认 extractNativeLibs=false：native 库不落盘，
 * 由链接器直接从 base.apk 里 mmap。此时 dladdr 给出的是
 *
 *     /data/app/…/base.apk!/lib/x86_64/libguardx.so
 *
 * 这种「APK 路径 + ! + 条目名」的形式（见 Android 链接器 soinfo::set_dt_flags /
 * dli_fname 的构造）。旧实现直接把它当普通路径 open()，必然失败，于是 C6/D4
 * 在**这类设备上（即绝大多数新设备）完全失效**。
 *
 * 这里自己解析 ZIP 把条目数据偏移找出来：因子表只处理 Stored（未压缩）条目——
 * extractNativeLibs=false 要求 native 库不压缩并按页对齐，这是唯一可能出现
 * 的形态；遇到压缩条目（或 ZIP64）返回 0，由调用方走「降级 + 打一次日志」。
 *
 * 为什么不用 zlib/inflate：APK 里这类库一定是 Stored，引入 inflate 只为
 * 一个不可能出现的分支而增加体积与攻击面，不划算。
 */
static const uint8_t AG_PK_EOCD[4] = { 0x50, 0x4b, 0x05, 0x06 };
static const uint8_t AG_PK_CD[4]   = { 0x50, 0x4b, 0x01, 0x02 };
static const uint8_t AG_PK_LFH[4]  = { 0x50, 0x4b, 0x03, 0x04 };

static int ag_same4(const uint8_t *a, const uint8_t *b) {
	return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3];
}

static int ag_zip_data_offset(int fd, const char *want, uint64_t *out) {
	/*
	 * 线程局部：D4 的看门狗线程每 3 秒调一次 ag_intact，Java 侧也可能调用
	 * Native.intact；两者共用同一个 static 缓冲区会互相踩，轻则解析失败降级，
	 * 重则算出错位的偏移 → 摘要不匹配 → 看门狗把**正常的应用**杀掉。
	 */
	static __thread uint8_t buf[66000];
	uint64_t fsz, tail, start, cd_off, cd_size, pos, end;
	uint8_t *p = 0;
	int n, i, want_len = 0;
	/* dladdr 给的条目名带前导 '/'，ZIP 里不带。 */
	while (want[0] == '/') {
		want++;
	}
	while (want[want_len] != 0) {
		want_len++;
	}
	if (want_len == 0 || want_len > 255) {
		return 0;
	}
	fsz = (uint64_t)ag_size(fd);
	if (fsz < 22 || fsz > 0x7fffffffULL) {
		g_sec_err = "zip-size";
		return 0; /* 不支持 zip64 的巨型归档 */
	}
	/* EOCD 只可能出现在文件末尾 64KB 内（注释长度上限 65535）。 */
	tail = fsz < sizeof(buf) ? fsz : sizeof(buf);
	start = fsz - tail;
	if (ag_seek(fd, (int64_t)start) != 0) {
		return 0;
	}
	n = ag_read_byte(fd, buf, (int)tail);
	if (n < 22) {
		g_sec_err = "zip-short";
		return 0;
	}
	for (i = n - 22; i >= 0; i--) {
		if (ag_same4(buf + i, AG_PK_EOCD)) {
			p = buf + i;
			break;
		}
	}
	if (p == 0) {
		g_sec_err = "zip-no-eocd";
		return 0;
	}
	cd_size = ag_rd32(p + 12);
	cd_off = ag_rd32(p + 16);
	if (cd_off == 0xffffffffUL || cd_size == 0xffffffffUL) {
		g_sec_err = "zip64";
		return 0; /* ZIP64：本工具不产出，遇到即降级 */
	}
	if (cd_off > fsz || cd_size > fsz - cd_off) {
		g_sec_err = "zip-cd-range";
		return 0;
	}
	pos = cd_off;
	end = cd_off + cd_size;
	while (pos + 46 <= end) {
		uint8_t h[46];
		uint16_t nlen, elen, clen, method;
		uint32_t lho;
		if (ag_seek(fd, (int64_t)pos) != 0) {
			return 0;
		}
		if (ag_read_byte(fd, h, 46) < 46) {
			return 0;
		}
		if (!ag_same4(h, AG_PK_CD)) {
			return 0;
		}
		method = ag_rd16(h + 10);
		nlen = ag_rd16(h + 28);
		elen = ag_rd16(h + 30);
		clen = ag_rd16(h + 32);
		lho = ag_rd32(h + 42);
		if ((int)nlen == want_len) {
			uint8_t nm[256];
			if (ag_seek(fd, (int64_t)(pos + 46)) == 0 &&
			    ag_read_byte(fd, nm, want_len) == want_len &&
			    memcmp(nm, want, (size_t)want_len) == 0) {
				uint8_t lh[30];
				uint16_t lnlen, lelen;
				if (method != 0) {
					g_sec_err = "zip-deflated";
					return 0; /* 压缩条目：无法在不解压的前提下摘要 */
				}
				if (ag_seek(fd, (int64_t)lho) != 0) {
					return 0;
				}
				if (ag_read_byte(fd, lh, 30) < 30) {
					return 0;
				}
				if (!ag_same4(lh, AG_PK_LFH)) {
					return 0;
				}
				lnlen = ag_rd16(lh + 26);
				lelen = ag_rd16(lh + 28);
				*out = (uint64_t)lho + 30 + lnlen + lelen;
				return 1;
			}
		}
		pos += 46 + nlen + elen + clen;
	}
	g_sec_err = "zip-entry-not-found";
	return 0;
}

/*
 * ag_self_open 打开「自身文件」，并把 ELF 起点偏移写回 base。
 *
 * 两种情形：
 *   1) dladdr 给出真实文件路径（库已落盘）→ 直接 open，base = 0；
 *   2) 路径含 '!'（库在 APK 内）→ 打开 APK，定位条目，base = 条目数据偏移。
 *
 * 成功返回 fd（>=0），失败返回负值。
 */
static int ag_self_open(const char *path, uint64_t *base) {
	int i, bang = -1;
	char zip[512];
	*base = 0;
	for (i = 0; path[i] != 0; i++) {
		if (path[i] == '!') {
			bang = i;
			break;
		}
	}
	if (bang < 0) {
		return ag_open(path, 0);
	}
	if (bang <= 0 || bang >= (int)sizeof(zip)) {
		g_sec_err = "bad-apk-path";
		return -1;
	}
	for (i = 0; i < bang; i++) {
		zip[i] = path[i];
	}
	zip[bang] = 0;
	{
		int fd = ag_open(zip, 0);
		uint64_t off = 0;
		if (fd < 0) {
			return -1;
		}
		if (!ag_zip_data_offset(fd, path + bang + 1, &off)) {
			if (g_sec_err[0] == '?') {
				g_sec_err = "zip-entry";
			}
			ag_close(fd);
			return -1;
		}
		*base = off;
		return fd;
	}
}

/*
 * ag_self_path 从 dladdr 取回本库自己的路径。
 *
 * maps 的每一行形如：
 *   7f8e4c0000-7f8e4c1000 r-xp ... /data/app/.../lib/arm64/libapkguard.so
 * 找到含 "libapkguard.so" 的那一行，取其后半段的路径即可。
 */
static int ag_self_path(char *out, int cap) {
	Dl_info info;
	const char *p;
	int n = 0;
	/*
	 * 用 dladdr 反查本库的加载路径，**而不是在 /proc/self/maps 里匹配字面文件名**。
	 *
	 * 为什么必须这样：C7（原生库伪装）会把 libapkguard.so 改名成类似
	 * libsqlite3x.so 的名字以隐藏加固器身份。按字面名匹配时改名后就找不到自己，
	 * 而下面各处的 "取不到就 return 1（完整）" 会让完整性校验**静默失效**——
	 * 用户以为自己有 C6/D4 防护，实际一个都没有，这正是本项目最忌讳的失败模式。
	 * dladdr 给出的是实际加载路径（dli_fname），改名后依然正确。
	 */
	if (dladdr((const void *)(uintptr_t)&ag_self_path, &info) == 0 || info.dli_fname == NULL) {
		return 0;
	}
	p = info.dli_fname;
	while (p[n] != 0 && n + 1 < cap) {
		out[n] = p[n];
		n++;
	}
	out[n] = 0;
	return n > 0;
}

/* ag_hash_region 把文件 [off, off+size) 区间喂给摘要器。 */
static int ag_hash_region(int fd, ag_sha256 *sh, uint64_t off, uint64_t size) {
	uint8_t chunk[8192];
	uint64_t done = 0;
	if (ag_seek(fd, (int64_t)off) != 0) {
		return 0;
	}
	while (done < size) {
		uint64_t want = size - done;
		int n;
		if (want > sizeof(chunk)) {
			want = sizeof(chunk);
		}
		n = ag_read_byte(fd, chunk, (int)want);
		if (n <= 0) {
			return 0;
		}
		ag_sha256_update(sh, chunk, (uint32_t)n);
		done += (uint64_t)n;
	}
	return 1;
}

/*
 * ag_intact 返回 1 表示自身代码与常量未被篡改。
 */
static AG_NOINLINE int ag_intact(void) {
	char path[512];
	int fd = -1, ok = 1;
	ag_sha256 sh;
	uint8_t got[32];
	uint64_t toff = 0, tsize = 0, roff = 0, rsize = 0;
	uint64_t base = 0;
	int i;
	AG_FLAT_DECL(st);
	/*
	 * 以下分支是**已知的能力边界**，不是应该静默掉的分支：
	 *
	 * 库直接打包在 APK 内（extractNativeLibs=false）时，dladdr 给出的是
	 * "…/base.apk!/lib/<abi>/libxxx.so"——本函数自己解析 ZIP 把条目数据找出来
	 * （见 ag_self_open）。只有「压缩条目 / ZIP64 / 定位失败」等少数情形才会
	 * 走到降级分支：那时返回完整 + 打一次日志，不误杀应用（把它判成篡改会让
	 * 应用直接起不来，而这是设备特性不是攻击），但让缺口在 logcat 里可见。
	 *
	 * 日志用 ONCE 变体：D4 的看门狗每 3 秒调一次本函数，逐次打印会把 logcat
	 * 刷屏（实测每进程每 3 秒一行），反而让这个提示被无视。
	 *
	 * C3 控制流平坦化：状态 0..9 与原基本块一一对应——
	 *   0=取自身路径；1=打开自身文件；2=定位 .text/.rodata；3=初始化摘要器；
	 *   4=哈希 .text；5=哈希 .rodata 并关闭 fd；6=判 ok 与收尾；
	 *   7/8=逐字节比较期望摘要的循环头/体；9=返回完整。
	 * 语义保持论证：
	 *   - 原 `if (!hash(.text) || !hash(.rodata)) ok = 0;` 的短路语义被
	 *     原样保留：状态 4 失败则置 ok=0 并跳到状态 6，不执行状态 5 的
	 *     rodata 哈希（与原 || 短路一致）；
	 *   - 降级分支与对应日志、close(fd) 的位置一一对应，返回值不变；
	 *   - 状态 7/8 的循环与原来的 for (i=0;i<32;i++) 比较完全一致；
	 *   - AG_OPAQUE_GUARD 不写 st，只增加不可达分支，不改变状态转移。
	 */
	AG_FLAT_LOOP(st) {
		case 0:
			if (!ag_self_path(path, (int)sizeof(path))) {
				AG_LOG_ONCE_ENC(ag_s_log_nopath_enc, ag_s_log_nopath_len,
				                AG_SALT_LOG_NOPATH);
				return 1;
			}
			st = 1;
			break;
		case 1:
			AG_OPAQUE_GUARD((uint32_t)path[0]);
			fd = ag_self_open(path, &base);
			if (fd < 0) {
				AG_LOG_ONCE_ENC(ag_s_log_openfail_enc, ag_s_log_openfail_len,
				                AG_SALT_LOG_OPENFAIL, path, g_sec_err);
				return 1;
			}
			st = 2;
			break;
		case 2:
			if (!ag_find_section(fd, base, ".text", &toff, &tsize) ||
			    !ag_find_section(fd, base, ".rodata", &roff, &rsize)) {
				AG_LOG_ONCE_ENC(ag_s_log_nosec_enc, ag_s_log_nosec_len,
				                AG_SALT_LOG_NOSEC, g_sec_err);
				ag_close(fd);
				return 1;
			}
			st = 3;
			break;
		case 3:
			ag_sha256_init(&sh);
			st = 4;
			break;
		case 4:
			if (!ag_hash_region(fd, &sh, toff, tsize)) {
				ok = 0;
				st = 6; /* 与原 || 短路一致：跳过 rodata 哈希 */
				break;
			}
			st = 5;
			break;
		case 5:
			if (!ag_hash_region(fd, &sh, roff, rsize)) {
				ok = 0;
			}
			st = 6;
			break;
		case 6:
			ag_close(fd);
			if (!ok) {
				return 1;
			}
			ag_sha256_final(&sh, got);
			i = 0;
			st = 7;
			break;
		case 7:
			AG_OPAQUE_GUARD((uint32_t)i ^ got[0]);
			st = (i < 32) ? 8u : 9u;
			break;
		case 8:
			if (got[i] != AG_EXPECT[i]) {
				return 0;
			}
			i++;
			st = 7;
			break;
		case 9:
			return 1;
		default:
			st = 6; /* 不可达；闭环避免调度器落空 */
			break;
	}
}

#endif /* !AG_HOST_TEST */

/* ------------------------------------------------------------------ */
/* B6：VMP 私有字节码解释器（核心实现见 agvm.h）                       */
/* ------------------------------------------------------------------ */
/*
 * 私有指令是数据、解释器是固定 C 代码，因此不需要 NDK 之外的任何工具链。
 * agvm.h 在 NDK（AG_JNI）、宿主自测（AG_HOST_TEST）与 Linux 自测下都编译；
 * AG_HOST_TEST 时它还会提供 ag_vm_selftest()，由本文件的宿主自测调用。
 */
#include "agvm.h"

/* ------------------------------------------------------------------ */
/* JNI 入口（仅 NDK 构建）                                             */
/* ------------------------------------------------------------------ */

#ifdef AG_JNI

#include <jni.h>
#include <pthread.h>
#include <time.h>

JNIEXPORT jbyteArray JNICALL
Java_com_apkguard_nativebridge_Native_derive(JNIEnv *env, jclass cls, jbyteArray jSig) {
	uint8_t key[32];
	jbyteArray out;
	jsize n = 0;
	jbyte *sig = 0;
	(void)cls;

	if (jSig != 0) {
		n = (*env)->GetArrayLength(env, jSig);
		if (n < 0) {
			n = 0;
		}
		if (n > 0) {
			sig = (*env)->GetByteArrayElements(env, jSig, 0);
		}
	}
	ag_derive((const uint8_t *)sig, (uint32_t)n, key);
	if (sig != 0) {
		(*env)->ReleaseByteArrayElements(env, jSig, sig, JNI_ABORT);
	}

	out = (*env)->NewByteArray(env, 32);
	if (out == 0) {
		return 0;
	}
	(*env)->SetByteArrayRegion(env, out, 0, 32, (const jbyte *)key);
	return out;
}

/*
 * B3：载荷解密入口。Java 侧签名（与 DEX 字节码逐字一致）：
 *
 *     public static native byte[] sivDecrypt(byte[] key32, byte[] ad, byte[] blob);
 *
 * key32 = 32 字节主密钥；ad = 载荷逻辑名的 UTF-8 字节（允许空数组，语义仍是
 * 「一个 AD 组件」，与 Go 侧 EncryptNamed(name="") 完全对应）；blob =
 * [SIV 16 字节][AES-CTR 密文]。返回明文（len(blob)-16 字节，允许 0）；
 * 任何失败（长度非法、malloc 失败、SIV 校验失败）返回 null——壳按
 * System.exit(1) 硬终止，不做「解密失败照常继续」的降级。
 *
 * 线程安全：全部中间状态在栈/本次 malloc 的堆内存里，没有静态缓冲。
 */
JNIEXPORT jbyteArray JNICALL
Java_com_apkguard_nativebridge_Native_sivDecrypt(JNIEnv *env, jclass cls, jbyteArray jKey, jbyteArray jAd, jbyteArray jBlob) {
	uint8_t key[32];
	jbyte *kb = 0, *ab = 0, *bb = 0;
	jsize klen, alen = 0, blen;
	uint8_t *pt;
	uint32_t ptlen = 0;
	jbyteArray out;
	(void)cls;

	if (jKey == 0 || jBlob == 0) {
		return 0;
	}
	klen = (*env)->GetArrayLength(env, jKey);
	if (klen != 32) {
		return 0;
	}
	blen = (*env)->GetArrayLength(env, jBlob);
	if (blen < 16) {
		return 0;
	}
	kb = (*env)->GetByteArrayElements(env, jKey, 0);
	if (kb == 0) {
		return 0;
	}
	memcpy(key, kb, 32);
	(*env)->ReleaseByteArrayElements(env, jKey, kb, JNI_ABORT);
	if (jAd != 0) {
		alen = (*env)->GetArrayLength(env, jAd);
		if (alen < 0) {
			alen = 0;
		}
	}
	if (alen > 0) {
		ab = (*env)->GetByteArrayElements(env, jAd, 0);
		if (ab == 0) {
			ag_wipe(key, (uint32_t)sizeof(key));
			return 0;
		}
	}
	bb = (*env)->GetByteArrayElements(env, jBlob, 0);
	if (bb == 0) {
		if (ab != 0) {
			(*env)->ReleaseByteArrayElements(env, jAd, ab, JNI_ABORT);
		}
		ag_wipe(key, (uint32_t)sizeof(key));
		return 0;
	}
	pt = ag_siv_decrypt(key, (const uint8_t *)ab, (uint32_t)alen,
	                    (const uint8_t *)bb, (uint32_t)blen, &ptlen);
	(*env)->ReleaseByteArrayElements(env, jBlob, bb, JNI_ABORT);
	if (ab != 0) {
		(*env)->ReleaseByteArrayElements(env, jAd, ab, JNI_ABORT);
	}
	ag_wipe(key, (uint32_t)sizeof(key));
	if (pt == 0) {
		return 0;
	}
	out = (*env)->NewByteArray(env, (jsize)ptlen);
	if (out == 0) {
		ag_wipe(pt, ptlen > 0 ? ptlen : 1);
		free(pt);
		return 0;
	}
	if (ptlen > 0) {
		(*env)->SetByteArrayRegion(env, out, 0, (jsize)ptlen, (const jbyte *)pt);
	}
	ag_wipe(pt, ptlen > 0 ? ptlen : 1);
	free(pt);
	return out;
}

JNIEXPORT jboolean JNICALL
Java_com_apkguard_nativebridge_Native_debugged(JNIEnv *env, jclass cls) {
	(void)env;
	(void)cls;
	return ag_debugged() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_apkguard_nativebridge_Native_hooked(JNIEnv *env, jclass cls) {
	(void)env;
	(void)cls;
	return ag_hooked() ? JNI_TRUE : JNI_FALSE;
}

/* ---- D4：运行期周期性复检 ----
 *
 * C6 的 intact() 是一次性校验，只能证明「启动那一刻没被改」；Frida 之类的
 * 运行期补丁发生在启动之后，因此需要周期复检才能发现。
 *
 * 设计取舍（与其它检测一致的 fail-open 思路）：
 *   - 明确命中（被调试 / 被注入 / 完整性破坏）→ 终止进程，这是反外挂语义；
 *   - 校验本身出错（读不到文件等）→ 各检测函数自身返回「正常」，不误杀。
 *
 * 线程 detach 后自行循环，间隔取 3 秒：足以在一个交互周期内发现补丁，
 * 又不至于让移动端功耗明显上升。
 */
static volatile int g_watch_started = 0;

static void ag_sleep_seconds(unsigned sec) {
    struct timespec ts;
    ts.tv_sec = (time_t)sec;
    ts.tv_nsec = 0;
    nanosleep(&ts, NULL);
}

static void *ag_watch_loop(void *arg) {
    (void)arg;
    for (;;) {
        ag_sleep_seconds(3);
        if (ag_debugged() || ag_hooked() || !ag_intact()) {
            /* 与静态检测同样走 fail-closed：命中即终止，不给补丁留窗口。 */
            _exit(1);
        }
    }
    return NULL;
}

JNIEXPORT jboolean JNICALL
Java_com_apkguard_nativebridge_Native_watch(JNIEnv *env, jclass cls) {
    (void)env;
    (void)cls;
    if (g_watch_started) {
        return JNI_TRUE;
    }
    pthread_t tid;
    if (pthread_create(&tid, NULL, ag_watch_loop, NULL) != 0) {
        return JNI_FALSE;
    }
    pthread_detach(tid);
    g_watch_started = 1;
    return JNI_TRUE;
}

JNIEXPORT jboolean JNICALL
Java_com_apkguard_nativebridge_Native_intact(JNIEnv *env, jclass cls) {
	(void)env;
	(void)cls;
	return ag_intact() ? JNI_TRUE : JNI_FALSE;
}

/*
 * B6：VM 方法注册入口。
 *
 * Java 侧（壳按需注入的桥接类）：
 *   com.apkguard.nativebridge.VM.registerVmMethod(String sig, byte[] code)
 *
 * sig  形如 "Lcom/x/A;->f(I)I"（与 Go 侧 Program.Sig 同格式）；
 * code 是**单方法记录**（Go 侧 vmp.EncodeMethodRecord 的字节），由壳在
 *      B1 载荷解密后逐条取出交给 native。
 *
 * 返回 0 成功；负数错误码（见 agvm.h 的 ag_vm_err）。
 *
 * 边界说明：run/runWide 执行入口需要 JNI 运行时后端（类解析走载荷
 * ClassLoader）与生成的 Dalvik 桥接 stub，属后续切片——本版只交付
 * 「翻译 + 私有字节码 + C 解释器（宿主已对拍）+ 注册表」，
 * 因此不导出半可用的执行入口。
 */
JNIEXPORT jint JNICALL
Java_com_apkguard_nativebridge_VM_registerVmMethod(JNIEnv *env, jclass cls, jstring jSig, jbyteArray jCode) {
	const char *sig;
	jbyte *body;
	jsize n;
	ag_vm_prog *prog;
	int rc = AG_VM_ERR_ARG;
	(void)cls;

	if (!jSig || !jCode) {
		return AG_VM_ERR_ARG;
	}
	sig = (*env)->GetStringUTFChars(env, jSig, 0);
	if (!sig) {
		return AG_VM_ERR_NOMEM;
	}
	n = (*env)->GetArrayLength(env, jCode);
	body = (*env)->GetByteArrayElements(env, jCode, 0);
	if (!body) {
		(*env)->ReleaseStringUTFChars(env, jSig, sig);
		return AG_VM_ERR_NOMEM;
	}
	if (n > 0 && n <= (1 << 20)) {
		prog = ag_vm_parse_record((const uint8_t *)body, (size_t)n, &rc);
	} else {
		prog = 0;
	}
	(*env)->ReleaseByteArrayElements(env, jCode, body, JNI_ABORT);
	if (!prog) {
		(*env)->ReleaseStringUTFChars(env, jSig, sig);
		return rc;
	}
	/* ag_vm_register 内部会校验传入签名与记录身份一致；成功即接管所有权。 */
	rc = ag_vm_register(sig, prog);
	(*env)->ReleaseStringUTFChars(env, jSig, sig);
	if (rc != AG_VM_OK) {
		ag_vm_free_prog(prog);
	}
	return rc;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
	(void)vm;
	(void)reserved;
	return JNI_VERSION_1_6;
}

#endif /* AG_JNI */

/* ------------------------------------------------------------------ */
/* 宿主自测（AG_HOST_TEST）：用 NIST 向量校验 SHA-256 与派生          */
/* ------------------------------------------------------------------ */

#ifdef AG_HOST_TEST

#include <stdio.h>
#include <string.h>

static void tohex(const uint8_t *b, int n, char *out) {
	static const char *d = "0123456789abcdef";
	int i;
	for (i = 0; i < n; i++) {
		out[i * 2] = d[b[i] >> 4];
		out[i * 2 + 1] = d[b[i] & 15];
	}
	out[n * 2] = 0;
}

static int check(const char *name, const uint8_t *got, const char *want) {
	char hex[128];
	tohex(got, 32, hex);
	if (strcmp(hex, want) == 0) {
		printf("PASS %s\n", name);
		return 0;
	}
	printf("FAIL %s\n  got  %s\n  want %s\n", name, hex, want);
	return 1;
}

/*
 * encdec 把一串密文解密到栈上并以 hex 打印。
 *
 * C3 的跨语言断言：Go 测试解析这些行，与自己保存的期望明文（hex）比对——
 * 明文只存在于测试代码里，C 源码与 .so 中都没有。这样既能证明每串密文
 * 解出的是原字符串，也避免把敏感串再写回源码。
 */
static void encdec(const char *name, const uint8_t *enc, int len, uint32_t salt) {
	static const char *d = "0123456789abcdef";
	uint8_t buf[256];
	char hex[520];
	int i;
	if (len > (int)sizeof(buf)) {
		len = (int)sizeof(buf);
	}
	ag_dec(buf, enc, (uint32_t)len, salt);
	for (i = 0; i < len; i++) {
		hex[i * 2] = d[buf[i] >> 4];
		hex[i * 2 + 1] = d[buf[i] & 15];
	}
	hex[len * 2] = 0;
	printf("ENCDEC_%s %s\n", name, hex);
}

int main(void) {
	ag_sha256 s;
	uint8_t out[32];
	int bad = 0;

	ag_sha256_init(&s);
	ag_sha256_update(&s, (const uint8_t *)"", 0);
	ag_sha256_final(&s, out);
	bad += check("sha256(empty)", out,
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

	ag_sha256_init(&s);
	ag_sha256_update(&s, (const uint8_t *)"abc", 3);
	ag_sha256_final(&s, out);
	bad += check("sha256(abc)", out,
		"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

	{
		/* 448 bit 的输入，正好跨越一次分块边界。 */
		const char *m =
			"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
		ag_sha256_init(&s);
		ag_sha256_update(&s, (const uint8_t *)m, (uint32_t)strlen(m));
		ag_sha256_final(&s, out);
		bad += check("sha256(448bit)", out,
			"248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
	}

	{
		/* 896 bit：跨两次分块，用于覆盖 final 里的补块分支。 */
		const char *m =
			"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
			"hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
		ag_sha256_init(&s);
		ag_sha256_update(&s, (const uint8_t *)m, (uint32_t)strlen(m));
		ag_sha256_final(&s, out);
		bad += check("sha256(896bit)", out,
			"cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");
	}

	{
		/* 分片喂入与一次喂入必须得到同一结果。 */
		ag_sha256 a, b;
		uint8_t o1[32], o2[32];
		ag_sha256_init(&a);
		ag_sha256_update(&a, (const uint8_t *)"abcdefgh", 8);
		ag_sha256_update(&a, (const uint8_t *)"ijklmnop", 8);
		ag_sha256_final(&a, o1);
		ag_sha256_init(&b);
		ag_sha256_update(&b, (const uint8_t *)"abcdefghijklmnop", 16);
		ag_sha256_final(&b, o2);
		if (memcmp(o1, o2, 32) == 0) {
			printf("PASS 分片一致性\n");
		} else {
			printf("FAIL 分片一致性\n");
			bad++;
		}
	}

	/* C3：逐串解密并输出 hex，供 Go 侧比对期望明文。 */
	encdec("ag_s_status", ag_s_status_enc, ag_s_status_len, AG_SALT_STATUS);
	encdec("ag_s_maps", ag_s_maps_enc, ag_s_maps_len, AG_SALT_MAPS);
	encdec("ag_s_frida", ag_s_frida_enc, ag_s_frida_len, AG_SALT_FRIDA);
	encdec("ag_s_xposed", ag_s_xposed_enc, ag_s_xposed_len, AG_SALT_XPOSED);
	encdec("ag_s_substrate", ag_s_substrate_enc, ag_s_substrate_len, AG_SALT_SUBSTRATE);
	encdec("ag_s_linjector", ag_s_linjector_enc, ag_s_linjector_len, AG_SALT_LINJECTOR);
	encdec("ag_s_libhook", ag_s_libhook_enc, ag_s_libhook_len, AG_SALT_LIBHOOK);
	encdec("ag_s_hookzz", ag_s_hookzz_enc, ag_s_hookzz_len, AG_SALT_HOOKZZ);
	encdec("ag_s_whale", ag_s_whale_enc, ag_s_whale_len, AG_SALT_WHALE);
	encdec("ag_s_ddi", ag_s_ddi_enc, ag_s_ddi_len, AG_SALT_DDI);
	encdec("ag_s_epic", ag_s_epic_enc, ag_s_epic_len, AG_SALT_EPIC);
	encdec("ag_s_magisk", ag_s_magisk_enc, ag_s_magisk_len, AG_SALT_MAGISK);
	encdec("ag_s_tag", ag_s_tag_enc, ag_s_tag_len, AG_SALT_TAG);
	encdec("ag_s_tpid", ag_s_tpid_enc, ag_s_tpid_len, AG_SALT_TPID);
	encdec("ag_s_log_nopath", ag_s_log_nopath_enc, ag_s_log_nopath_len, AG_SALT_LOG_NOPATH);
	encdec("ag_s_log_openfail", ag_s_log_openfail_enc, ag_s_log_openfail_len, AG_SALT_LOG_OPENFAIL);
	encdec("ag_s_log_nosec", ag_s_log_nosec_enc, ag_s_log_nosec_len, AG_SALT_LOG_NOSEC);
	/* AES-SIV KDF 的两条域串（密文常量在 aes_tables.h，明文只在 Go 测试里）。 */
	encdec("ag_s_siv_mac", ag_s_siv_mac_enc, ag_s_siv_mac_len, AG_SALT_SIV_MAC);
	encdec("ag_s_siv_ctr", ag_s_siv_ctr_enc, ag_s_siv_ctr_len, AG_SALT_SIV_CTR);

	/*
	 * C3：不透明谓词恒定性。边界值 + 100 万组 LCG 输入，任一时刻谓词
	 * 走反方向（或实现有 UB/写错）都会置 opq_bad，RESULT 变 FAIL。
	 */
	{
		uint32_t i, v;
		int opq_bad = 0;
		const uint32_t edge[6] = {
			0u, 1u, 0xffffffffu, 0x80000000u, 0x7fffffffu, 0xdeadbeefu};
		for (i = 0; i < 6; i++) {
			if (!ag_opq_true(edge[i]) || ag_opq_false(edge[i])) {
				opq_bad = 1;
			}
		}
		v = 0x12345678u;
		for (i = 0; i < 1000000u; i++) {
			v = v * 1664525u + 1013904223u;
			if (!ag_opq_true(v) || ag_opq_false(v)) {
				opq_bad = 1;
				break;
			}
		}
		if (opq_bad) {
			printf("FAIL opaque predicate\n");
			bad++;
		} else {
			printf("PASS opaque predicate\n");
		}
	}

	/* 派生：把结果打印出来，供 Go 侧对照，确保两侧实现一致。 */
	{
		uint8_t sig[32];
		char hex[128];
		int i;
		for (i = 0; i < 32; i++) {
			sig[i] = (uint8_t)(i * 7 + 3);
		}
		ag_derive(sig, 32, out);
		tohex(out, 32, hex);
		printf("DERIVE_WITH_SIG %s\n", hex);
		ag_derive(0, 0, out);
		tohex(out, 32, hex);
		printf("DERIVE_NO_SIG %s\n", hex);
	}
	/*
	 * B6：VMP 私有字节码解释器的宿主断言。它不看 JNI，只证明
	 * 「解析 → 结构校验 → dispatch 循环 → 回调运行时」这条链的语义正确。
	 */
	bad += ag_vm_selftest();

	/*
	 * B3：AES-SIV 解密的宿主断言——RFC 4493 CMAC、RFC 5297 A.1/A.2
	 * 官方向量（含中间量与逐字节篡改）、Go 侧 EncryptNamed 的 AES-256
	 * 互操作向量、边界往返与 4 MB 性能计时。
	 */
	bad += ag_siv_selftest();

	printf(bad ? "RESULT FAIL\n" : "RESULT OK\n");
	return bad;
}

#endif /* AG_HOST_TEST */
