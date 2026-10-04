/*
 * obfuscate.h —— libapkguard 的 C 源码层混淆原语（C3）。
 *
 * 本项目的 C3 不依赖 OLLVM / LLVM Pass：上游 clang 没有 -mllvm -fla/-bcf/-sub，
 * 而为一套 ~25 KB 的守卫库引入并长期维护匹配版本的 LLVM 工具链，投入产出比
 * 极低（见 docs/方案-C3-OLLVM.md）。因此三项变换全部在 C 源码层用
 * 「宏 + static inline 函数」实现，编译期只用到 NDK clang 的常规优化标志。
 *
 * 三项变换与语义保持论证：
 *
 *   1) 字符串加密（AG_DEFSTR / AG_DECL_STR / ag_dec）
 *      敏感明文以「密文数组 + 运行期解密到栈」的形态存放：
 *          enc[i] = plain[i] ^ ks(i, salt)
 *      ks 的输入包含一个 volatile 的 64-bit 常量 g_ag_ks_key。volatile 读取
 *      必须真实发生，编译器无法把这段异或常量折叠成明文常量，-O2 下密文
 *      仍只是密文（构建后由 strings 扫描断言）。解密函数与加密是同一运算，
 *      离线生成密文时使用与 ag_ks_byte 逐位一致的算法（见该函数注释）。
 *
 *   2) 不透明谓词（ag_opq_true / ag_opq_false / AG_OPAQUE_GUARD）
 *      数学上恒真/恒假：x*(x+1) 在模 2^32 下必为偶数（x 偶则积偶；x 奇则
 *      x+1 偶），无符号回绕是良好定义的行为，不引入 UB。参数含 volatile
 *      读取，且函数 noinline，-O2 不能把它折叠成常量分支。
 *      AG_OPAQUE_GUARD 的写法刻意让谓词**不参与真正的控制流**：它只插入
 *      一个「死分支 + volatile 写」，if 之后照常执行原语句。这样即使谓词
 *      实现被误改，函数行为仍与改造前完全一致——语义保持不依赖谓词的
 *      正确性，只依赖它无副作用。
 *
 *   3) 控制流平坦化（AG_FLAT_* 宏 + 使用方手工状态机）
 *      把函数基本块改写为 `volatile uint32_t st; for(;;) switch(st)` 调度
 *      循环：每个 case 对应原来的一段顺序代码，段的结尾把下一个状态的编号
 *      写入 st。状态变量是 volatile，编译器必须保留对 st 的读写与间接分派，
 *      无法把状态机还原回原始结构化 CFG；反编译视图里只剩「一堆 case」。
 *      语义保持的论证随每个被平坦化的函数注释（状态编号 ↔ 原基本块一一对应，
 *      提前 return 直接 return，循环条件变成条件状态转移）。
 */

#ifndef APKGUARD_OBFUSCATE_H
#define APKGUARD_OBFUSCATE_H

#include <stdint.h>

/* ------------------------------------------------------------------ */
/* 0. 编译器能力宏                                                      */
/* ------------------------------------------------------------------ */

/* TCC（宿主对拍用的最小编译器）不认 noinline；去掉属性不影响正确性，
 * 只是让谓词/平坦化函数可能被内联，宿主的“恒真性/一致性”断言仍然成立。 */
#if defined(__clang__) || defined(__GNUC__)
#define AG_NOINLINE __attribute__((noinline))
#else
#define AG_NOINLINE
#endif

/* ------------------------------------------------------------------ */
/* 1. 字符串加密                                                        */
/* ------------------------------------------------------------------ */

/*
 * g_ag_ks_key 是密钥流的运行期输入：初值即加密密钥，之后从不写入。
 * volatile 是关键——每解一个字节都要真实读一次内存，编译器不能把
 * 「密文 ^ 常量」常量折叠成明文再放进 .rodata。
 */
static volatile uint64_t g_ag_ks_key = 0x8f3a5c1d9b7e2465ull;

/*
 * ag_ks_byte 返回第 i 个密钥流字节：splitmix64 风格的 64 位混合，
 * 输入为 i、每串不同的 salt 与 g_ag_ks_key。
 *
 * 离线生成密文时的算法必须与本函数逐位一致（uint64 回绕、移位与乘法
 * 全部按无符号 64 位语义），把 plain[i] 与返回值异或即得 enc[i]。
 */
static inline uint8_t ag_ks_byte(uint32_t i, uint32_t salt) {
	uint64_t x = (uint64_t)i * 0x9e3779b97f4a7c15ull +
	             (uint64_t)salt * 0xbf58476d1ce4e5b9ull +
	             g_ag_ks_key;
	x ^= x >> 30;
	x *= 0xbf58476d1ce4e5b9ull;
	x ^= x >> 27;
	x *= 0x94d049bb133111ebull;
	x ^= x >> 31;
	return (uint8_t)x;
}

/* ag_dec 把 n 字节密文解密到 dst（调用方提供的栈缓冲区）。 */
static inline void ag_dec(uint8_t *dst, const uint8_t *enc, uint32_t n, uint32_t salt) {
	uint32_t i;
	for (i = 0; i < n; i++) {
		dst[i] = (uint8_t)(enc[i] ^ ag_ks_byte(i, salt));
	}
}

/* AG_DEFSTR 定义一串密文 + 长度；salt 必须与离线生成密文时一致。 */
#define AG_DEFSTR(name, salt, ...) \
	static const uint8_t name##_enc[] = {__VA_ARGS__}; \
	enum { name##_len = (int)(sizeof(name##_enc)) }

/*
 * AG_DECL_STR 在栈上声明 name_len+1 字节的缓冲区并解密，末尾补 NUL。
 * 只能在函数体内使用，且同一作用域内 name 不可重复。
 */
#define AG_DECL_STR(name, salt) \
	char name##_buf[name##_len + 1]; \
	ag_dec((uint8_t *)name##_buf, name##_enc, (uint32_t)name##_len, (salt)); \
	name##_buf[name##_len] = 0

/* 解密到调用方自己的缓冲区（供表驱动场景，如 needle 列表）。 */
#define AG_DECODE_TO(dst, name, salt) \
	ag_dec((uint8_t *)(dst), name##_enc, (uint32_t)name##_len, (salt))

/* ------------------------------------------------------------------ */
/* 2. 不透明谓词                                                        */
/* ------------------------------------------------------------------ */

/* 运行期只读的谓词种子；volatile 同上，用于阻止编译期求值。 */
static volatile uint32_t g_ag_opq_seed = 0x6d5a3c17u;

/*
 * ag_opq_true 恒返回 1：x*(x+1) 的低位必为 0。
 * 证明：x 为偶数 → x 低 bit 为 0 → 积低 bit 0；x 为奇数 → x+1 低 bit 为 0
 * → 积低 bit 0。无符号乘法回绕不改变低位，故在 mod 2^32 下恒成立，无 UB。
 */
AG_NOINLINE static int ag_opq_true(uint32_t v) {
	uint32_t x = g_ag_opq_seed ^ v;
	return (int)((x * (x + 1u)) & 1u) == 0;
}

/* ag_opq_false 恒返回 0（同一恒等式的取反）。 */
AG_NOINLINE static int ag_opq_false(uint32_t v) {
	uint32_t x = g_ag_opq_seed ^ v;
	return (int)((x * (x + 1u)) & 1u) != 0;
}

/* 死分支体：只做 volatile 写，没有副作用，可被优化器保留但不影响结果。 */
#define AG_DEAD_BODY(v) \
	do { volatile uint32_t ag_dead_sink = (uint32_t)(v); (void)ag_dead_sink; } while (0)

/*
 * AG_OPAQUE_GUARD(v)：插入一个永不执行的诱饵分支。
 *
 * 语义保持：谓词恒真，死分支不执行；即便谓词为假，死分支也只做 volatile
 * 写，之后的语句与谓词无关。因此该宏对函数行为零影响。
 */
#define AG_OPAQUE_GUARD(v) \
	do { if (!ag_opq_true((uint32_t)(v))) { AG_DEAD_BODY((uint32_t)(v) ^ 0x9e3779b9u); } } while (0)

/* ------------------------------------------------------------------ */
/* 3. 控制流平坦化辅助                                                  */
/* ------------------------------------------------------------------ */

/*
 * AG_FLAT_DECL / AG_FLAT_LOOP：状态机的声明与调度器骨架，仅供阅读便利，
 * 具体状态编号由使用方手写。展开后就是
 *     volatile uint32_t st = 0;
 *     for (;;) { switch (st) { case ... } }
 */
#define AG_FLAT_DECL(st) volatile uint32_t st = 0
#define AG_FLAT_LOOP(st) for (;;) switch (st)

#endif /* APKGUARD_OBFUSCATE_H */
