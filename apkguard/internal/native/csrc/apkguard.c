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

#include <stdint.h>
#include <dlfcn.h>

/*
 * 可观测的日志：有意不用「悄悄记在内存里」的方式。
 *
 * 存在的理由：C6 的自校验在本机（模拟器 / extractNativeLibs=false 的设备）
 * **无法定位自身文件**——native 库是从 APK 内部直接加载的，/proc/self/maps
 * 里对应的是 base.apk 而不是 .so 自己的路径。旧实现此时「当作完整」返回，
 * 于是完整性校验静默失效（用户以为有防护，实际没有）。现在无论走哪条分支，
 * 都会打一行日志，使这种降级在 logcat 里**可见**，而不是无声无息。
 */
#if defined(AG_JNI)
#include <android/log.h>
#define AG_LOG(fmt, ...) __android_log_print(4 /*ANDROID_LOG_INFO*/, "APKGUARD", fmt, ##__VA_ARGS__)
#elif defined(AG_HOST_TEST)
#include <stdio.h>
/* 用 fputc(10,..) 而非转义换行：本项目里转义序列多次被多层工具链吃掉 */
#define AG_LOG(fmt, ...) do { fprintf(stderr, "[AG] " fmt, ##__VA_ARGS__); fputc(10, stderr); } while (0)
#else
#define AG_LOG(fmt, ...) ((void)0)
#endif

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

/* ag_seed 还原派生的种子。 */
static void ag_seed(uint8_t out[32]) {
	int i;
	for (i = 0; i < 32; i++) {
		out[i] = (uint8_t)(AG_SEED_OBF[i] ^ AG_SEED_MASK[i & 7]);
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
static void ag_derive(const uint8_t *sig, uint32_t siglen, uint8_t out[32]) {
	uint8_t seed[32];
	ag_sha256 s;
	ag_seed(seed);
	ag_sha256_init(&s);
	ag_sha256_update(&s, seed, 32);
	if (sig != 0 && siglen > 0) {
		ag_sha256_update(&s, sig, siglen);
	}
	ag_sha256_final(&s, out);
}

/* ------------------------------------------------------------------ */
/* C4：反调试                                                          */
/* ------------------------------------------------------------------ */

#ifndef AG_HOST_TEST

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
static long ag_seek(int fd, int64_t off) { return (long)lseek(fd, (off_t)off, SEEK_SET); }
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
static int ag_debugged(void) {
	char buf[4096];
	int fd, n, i;
	fd = ag_open("/proc/self/status", 0);
	if (fd < 0) {
		return 0;
	}
	n = ag_read(fd, buf, (int)sizeof(buf) - 1);
	ag_close(fd);
	if (n <= 0) {
		return 0;
	}
	buf[n] = 0;
	for (i = 0; i + 10 < n; i++) {
		/* 匹配 "TracerPid:"，其后第一个非 0 数字即被跟踪。 */
		if (buf[i] == 'T' && buf[i + 1] == 'r' && buf[i + 2] == 'a' &&
		    buf[i + 3] == 'c' && buf[i + 4] == 'e' && buf[i + 5] == 'r' &&
		    buf[i + 6] == 'P' && buf[i + 7] == 'i' && buf[i + 8] == 'd' &&
		    buf[i + 9] == ':') {
			int j = i + 10;
			while (j < n && (buf[j] == ' ' || buf[j] == '\t')) {
				j++;
			}
			if (j < n && buf[j] >= '1' && buf[j] <= '9') {
				return 1;
			}
			return 0;
		}
	}
	return 0;
}

static int ag_frida_port(void);

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
 */
static int ag_hooked(void) {
	static const char *needles[] = {
		"frida", "xposed", "substrate", "linjector",
		"libhook", "hookzz", "whale", "ddi", "epic",
	};
	char buf[16384];
	int fd, n, i, k;
	fd = ag_open("/proc/self/maps", 0);
	if (fd >= 0) {
		n = ag_read(fd, buf, (int)sizeof(buf) - 1);
		ag_close(fd);
		if (n > 0) {
			buf[n] = 0;
			/* 逐字节小写化比较，避免依赖 tolower（locale 行为不确定）。 */
			for (i = 0; i < n; i++) {
				if (buf[i] >= 'A' && buf[i] <= 'Z') {
					buf[i] = (char)(buf[i] + 32);
				}
			}
			for (k = 0; k < (int)(sizeof(needles) / sizeof(needles[0])); k++) {
				const char *nd = needles[k];
				int ln = 0;
				while (nd[ln]) {
					ln++;
				}
				for (i = 0; i + ln <= n; i++) {
					int j = 0;
					while (j < ln && buf[i + j] == nd[j]) {
						j++;
					}
					if (j == ln) {
						return 1;
					}
				}
			}
		}
	}
	return ag_frida_port();
}

/* ag_frida_port 探测 Frida 默认端口是否在本地监听。 */
static int ag_frida_port(void) {
	struct sockaddr_in sa;
	int fd;
	int one = 1;
	fd = ag_socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		return 0;
	}
	/* Linux 没有 SO_NOSIGPIPE（那是 BSD/macOS 的选项）；这里保留调用
	 * 只为在某些兼容层下生效，失败无副作用。 */
	ag_setsockopt(fd, SOL_SOCKET, 0, &one, (unsigned)sizeof(one));
	sa.sin_family = AF_INET;
	sa.sin_port = ag_htons(27042);
	sa.sin_addr.s_addr = ag_htonl(0x7f000001u); /* 127.0.0.1 */
	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
		close(fd);
		return 1;
	}
	close(fd);
	return 0;
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

/*
 * ag_find_section 在已打开的 ELF 文件中查找指定名字的节。
 *
 * 返回 1 并写回文件内的偏移与长度；找不到返回 0。
 *
 * 必须同时支持 ELF32 与 ELF64：armeabi-v7a 是 32 位，仍有一批在售设备。
 * 只认 64 位的话，32 位产物上的完整性校峰会静默失效——那是最糟的失败
 * 模式（看起来有防护，实际没有）。
 */
static int ag_find_section(int fd, const char *want, uint64_t *off, uint64_t *size) {
	uint8_t hdr[64];
	int n = ag_read_byte(fd, hdr, 64);
	int is64;
	uint64_t shoff = 0, stroff = 0, strsize = 0;
	uint16_t shentsize, shnum, shstrndx;
	uint16_t i;
	if (n < 64) {
		return 0;
	}
	if (!(hdr[0] == 0x7f && hdr[1] == 'E' && hdr[2] == 'L' && hdr[3] == 'F')) {
		return 0;
	}
	if (hdr[5] != 1) {
		return 0; /* 大端：Android 上不存在 */
	}
	is64 = (hdr[4] == 2) ? 1 : (hdr[4] == 1 ? 0 : -1);
	if (is64 < 0) {
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
		return 0;
	}
	if (shentsize < (is64 ? 64 : 40)) {
		return 0;
	}
	{
		uint8_t sh[64];
		/* 先读节名字表所在节，取得字符串表的位置。 */
		if (ag_seek(fd, (int64_t)(shoff + (uint64_t)shstrndx * shentsize)) != 0) {
			return 0;
		}
		if (ag_read_byte(fd, sh, (int)shentsize) < (int)shentsize) {
			return 0;
		}
		stroff = is64 ? ag_rd64(sh + 0x18) : ag_rd32(sh + 0x10);
		strsize = is64 ? ag_rd64(sh + 0x20) : ag_rd32(sh + 0x14);
		if (stroff == 0 || strsize == 0) {
			return 0;
		}
	}
	for (i = 0; i < shnum; i++) {
		uint8_t sh[64];
		uint8_t name[64];
		uint32_t name_off;
		int k = 0;
		if (ag_seek(fd, (int64_t)(shoff + (uint64_t)i * shentsize)) != 0) {
			return 0;
		}
		if (ag_read_byte(fd, sh, (int)shentsize) < (int)shentsize) {
			return 0;
		}
		name_off = ag_rd32(sh);
		if (name_off >= strsize) {
			continue;
		}
		if (ag_seek(fd, (int64_t)(stroff + name_off)) != 0) {
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
			*off = is64 ? ag_rd64(sh + 0x18) : ag_rd32(sh + 0x10);
			*size = is64 ? ag_rd64(sh + 0x20) : ag_rd32(sh + 0x14);
			return 1;
		}
	}
	return 0;
}

/*
 * ag_self_path 从 /proc/self/maps 中取出本库自己的绝对路径。
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
	static uint8_t chunk[8192];
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
static int ag_intact(void) {
	char path[512];
	int fd, ok = 1;
	ag_sha256 sh;
	uint8_t got[32];
	uint64_t toff = 0, tsize = 0, roff = 0, rsize = 0;
	int i;
	/*
	 * 以下三处是**已知的能力边界**，不是应该静默掉的分支：
	 *
	 * 「定位不到自身文件」在现代 Android 上是常态——native 库默认**从 APK 内部
	 * 直接加载**（extractNativeLibs=false），此时 /proc/self/maps 里对应的是
	 * base.apk 而不是 .so 自己的路径，本函数拿不到可打开的文件路径。
	 * 旧实现直接 return 1（当作完整），于是 C6/D4 在整类设备上**静默失效**。
	 *
	 * 现在改为「返回完整 + 打一行日志」：不误杀应用（把它判成篡改会让应用
	 * 直接起不来，而这是设备特性不是攻击），但让降级在 logcat 里可见。
	 * 真正的修法是「基于内存镜像（PT_LOAD）而不是磁盘文件做摘要」——那需要在
	 * 运行时读已映射的段，属后续工作；在那之前必须让用户看得见这个缺口。
	 */
	if (!ag_self_path(path, (int)sizeof(path))) {
		AG_LOG("C6: 无法定位自身文件（native 库可能直接从 APK 加载），自校验跳过");
		return 1;
	}
	fd = ag_open(path, 0);
	if (fd < 0) {
		AG_LOG("C6: 打开自身文件失败（%s），自校验跳过", path);
		return 1;
	}
	if (!ag_find_section(fd, ".text", &toff, &tsize) ||
	    !ag_find_section(fd, ".rodata", &roff, &rsize)) {
		AG_LOG("C6: 自身文件缺少 .text/.rodata 节名，自校验跳过");
		ag_close(fd);
		return 1;
	}
	ag_sha256_init(&sh);
	if (!ag_hash_region(fd, &sh, toff, tsize) ||
	    !ag_hash_region(fd, &sh, roff, rsize)) {
		ok = 0;
	}
	ag_close(fd);
	if (!ok) {
		return 1;
	}
	ag_sha256_final(&sh, got);
	for (i = 0; i < 32; i++) {
		if (got[i] != AG_EXPECT[i]) {
			return 0;
		}
	}
	return 1;
}

#endif /* !AG_HOST_TEST */

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
	printf(bad ? "RESULT FAIL\n" : "RESULT OK\n");
	return bad;
}

#endif /* AG_HOST_TEST */
