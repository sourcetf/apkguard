# 方案 C3：OLLVM 混淆（控制流平坦化 / 虚假控制流 / 指令替换）

> 本文是**设计文档**，不改任何代码。对应功能项 `C3`（`internal/config` 中 Group=Native、Stage=L3、Risk=Safe、默认关闭）。
> 参照实现：`internal/native/csrc/apkguard.c`（守卫 C 源码，唯一由本项目编译的 native 代码）、
> `internal/native/build_native.py`（NDK 交叉编译、`.agexpect` 摘要回填、16 KB 页对齐检查）、
> `internal/passes/shell.go`（C1/C4/C5/C6 注入该库并调用）。

---

## 0. 结论先行（TL;DR）

1. **本项目的 C3 作用对象只能是 `libapkguard.so` 这一个我们自己的守卫库**。设计文档里 C3 的原始表述是「保护 native 层核心逻辑」，但本工具**不编译用户应用的 native 库**（用户应用的 `.so` 随 APK 一起进来，我们只做搬运/注入）。因此 C3 的真实防护对象是我们自己的守卫：派生种子、反调试/反注入/完整性校验逻辑。**必须据此下调它的价值评估。**
2. **完整 OLLVM（LLVM Pass）对本项目性价比极低**：需要引入并长期维护一套与 NDK clang ABI 匹配的 LLVM 工具链（数百 MB），破坏「单二进制、零外部依赖」定位，却只保护一个 ~25 KB 的守卫库。建议**不做 LLVM Pass 版本**。
3. **唯一现实落点是「C 源码层的最小等价变换」**：对 `ag_derive`、`ag_intact`、`ag_hooked`、`ag_debugged` 等少数函数手写/宏化「不透明谓词 + 指令替换 + 轻量平坦化」，无 LLVM 依赖，可确定性复现，并与现有 `build_native.py` 的摘要/对齐检查兼容。
4. 诚实结论：C3 的**实际防护增量是低到中**。守卫库最有效的保护是 **C2（SO 加壳）** 与 **C6（完整性自校验）**；OLLVM 只是让逆向者多花几小时。若目标是保护业务算法，正确路径是 B5/B6/B7 这些 DEX 层方案，不是 C3。

---

## 1. 目标与预期效果

### 1.1 三项变换是什么

| 变换 | 英文 | 做什么 | 对抗什么 |
|---|---|---|---|
| **控制流平坦化** | Control Flow Flattening (CFF) | 把函数的基本块打散，引入一个「状态变量」和 `while(1){ switch(state){...} }` 调度循环；原本的跳转边变成「给 state 赋值」。原本结构化的 if/for 在反编译视图里退化成一堆 case | 结构化反编译（IDA/Ghidra 的 CFG 还原、Hex-Rays 伪代码可读性） |
| **虚假控制流** | Bogus Control Flow (BCF) | 插入恒真/恒假但静态难以判定的**不透明谓词**，制造永远不执行或永远执行的分支与假基本块 | 静态 CFG 分析、符号执行；增加需要人工甄别的路径 |
| **指令替换** | Instruction Substitution (SUB) | 把简单运算替换为等价的复杂形式，如 `a+b` → `a-(-b)`、`a^b` → `(a\|b)-(a&b)`、`a==b` → `(a-b)==0` 变形 | 模式匹配、基于指令特征的检测与自动化还原 |

### 1.2 防住什么、效果如何量化

防护对象 = `libapkguard.so`（C1 的种子与派生、C4/C5/C6/D4 的检测逻辑）。

可量化的指标（都应落到自动化断言，见 §4）：

- **反编译可读性**：用 Ghidra/IDA 反编译 `ag_derive`，平坦化后**伪代码中不再出现可识别的算法结构**（如「两段循环 + 一个异或常量」这类一目了然的 SHA-256/掩码还原）。可量化为「手动分析耗时」的估计，但无法像 DEX 守卫那样自动断言。
- **特征匹配失效**：对 SO 做 `strings`/常量扫描，`AG_SEED_OBF`/`AG_SEED_MASK` 等常量**不以连续、对齐的形式出现**（现在它们已经以掩码异或形式存放，SUB/CFF 会进一步打散索引计算）。
- **不透明谓词恒真性**：对每个插入的谓词，用随机输入验证其分支方向恒定（100% 走同一支），证明它没有改变语义。
- **性能/体积**：守卫库只在启动与每 3 秒的 D4 复检里运行，性能可忽略；体积增量预计 +10%~30%（当前库约 20~25 KB/ABI，即 +3~8 KB/ABI）。

**不能量化的部分要诚实写**：C3 挡不住有经验的逆向者。它提高的是「读懂守卫逻辑」的时间成本，不是「能不能破」。

---

## 2. 技术方案

### 2.1 LLVM IR 层（写 LLVM Pass）还是 C 源码层？

三条可选路线：

| 路线 | 做法 | 依赖 | 评价 |
|---|---|---|---|
| **A. LLVM 官方/自研 Pass** | 用带 OLLVM 变换的 LLVM（如 `obfuscator-llvm` 分支）或自写 out-of-tree Pass 插件，在 LLVM IR 上做 CFF/BCF/SUB | 需要与 NDK clang **ABI 完全匹配**的 LLVM 工具链 | 变换最强，但工程与维护成本最高；对本项目收益最低 |
| **B. 独立 bitcode 混淆器** | `clang -emit-llvm` 生成 `.bc` → 自建 `opt` 跑 OLLVM → `clang` 把 `.bc` 编译成 `.so` | 仍需自建/引入 LLVM（数百 MB） | 比 A 稍灵活，但仍引入 LLVM，且多一跳 bitcode |
| **C. C 源码层变换** | 在 `csrc/apkguard.c` 里用宏/手工写法实现 SUB、BCF，并对少数函数用 `goto` + 状态机做轻量 CFF | 无（只用 NDK clang） | 强度弱于 A/B，但零工具链成本、可确定性复现、与现有构建/摘要流程天然兼容 |

**对本项目而言唯一现实的落点是 C（C 源码层）。** 依据：

1. 我们只编译一个约 25 KB 的守卫库（`build_native.py` 里 `SRC = csrc/apkguard.c`，799 行）。为它引入并维护一套 LLVM 工具链，投入产出比极低。
2. 项目定位是「纯 Go / 单二进制 / 无外部依赖」（`internal/native/embed.go` 包注释、README「构建」节）。LLVM 工具链会像 B7 的 NDK 依赖一样破坏这个定位，而且 C3 是默认关闭的最高强度档，愿意为它装 LLVM 的用户少之又少。
3. C 源码层的 SUB/BCF 可以用宏实现，CFF 可以对手工挑选的少数函数用「状态机 + goto」重写；这些都是编译器无关的、可读可测的。
4. 与现有构建流程兼容：`build_native.py` 在编译后按节表定位 `.text`/`.rodata` 回填 SHA-256（C6）。源码层变换发生在编译前，摘要自然覆盖变换后的代码，无需改动摘要逻辑。

**不推荐 A/B 的理由再展开（诚实说明局限）**：

- LLVM Pass 插件与 clang 的 LLVM 版本必须严格一致，NDK r26 用的是特定 LLVM 大版本；一旦 NDK 升级（r27/r28），插件要么重编要么失效。这是一个**持续维护负担**。
- 即便做了 OLLVM，保护对象仍只是守卫库；用户应用的 native 库**不归我们编译**，C3 对它无能为力。所以「OLLVM 保护 native 核心逻辑」在本项目里是**不成立的**——除非将来支持「把用户 SO 也纳入加固流水线（C2 SO 加壳 + 重编译）」，那时才谈得上。
- 结论：若坚持要做完整 OLLVM，应作为独立项目/独立工具，而不是本加固 exe 的一个 Pass。

### 2.2 C 源码层的三项变换（推荐落点）

在 `internal/native/csrc/apkguard.c` 中实现，且**只作用于挑选过的函数**，避免全局改动影响稳定性。

**(1) 指令替换（SUB）**——用宏，风险最低：

```c
/* 等价替换示例（保持无副作用、可读性可控） */
#define AG_ADD(a,b)  ((a) - (~(b) + 1u))          /* a + b  -> a - (-b) */
#define AG_XOR(a,b)  (((a) | (b)) - ((a) & (b)))  /* a ^ b  -> (a|b)-(a&b) */
#define AG_EQZ(a)    ((uint32_t)((a) | (~(a) + 1u)) >> 31) /* a==0 */
```

- 用在 `ag_derive` 的种子掩码还原、`ag_intact` 的长度/偏移运算等处。
- 关键约束：替换必须**逐位等价**、无副作用（参数只求值一次，用 `static inline` 函数而不是裸宏以避免多次求值）。

**(2) 虚假控制流（BCF）**——不透明谓词：

```c
/* x*x - x 恒为偶数；用它构造恒真谓词，增加假分支 */
static inline uint32_t ag_opaque_true(uint32_t x) {
    uint32_t y = x * (x - 1u);
    return (y & 1u) == 0u;   /* 恒真 */
}
```

- 在关键分支前插入 `if (ag_opaque_true(seed_byte ^ counter)) { /* 真路径 */ } else { /* 永假路径，塞入无效运算 */ }`。
- 必须保证谓词**在编译期无法被优化掉**（用 `volatile` 或来自运行时的 `seed_byte`），否则 `-O2` 会把假分支整个删掉，变换失效。这一点与「可复现」有张力：要在生成与确定性之间取平衡（谓词参数取固定常量 + 一个来自 `volatile` 运行时的值）。

**(3) 控制流平坦化（CFF）**——手工状态机，只对少数函数做：

- 只对 `ag_derive`、`ag_hooked`、`ag_intact` 三个函数做；它们逻辑相对线性、无复杂控制流，改写风险可控。
- 形态：`for(;;){ switch(state){ case 0: ... state=3; continue; ... } }`，`state` 用 `volatile uint32_t` 防止被优化成原控制流。
- **不**对含循环 + 提前返回 + 错误处理的函数做（如 `ag_watch_loop` 的线程循环），否则容易写出死循环或改变语义。

**(4) 附加（低成本高收益）**：

- 编译参数加 `-fno-asynchronous-unwind-tables -fno-unwind-tables`，去掉无用的 `eh_frame`，减少可用信息。
- `-s` 或在版本脚本里只导出 JNI 符号，隐藏内部静态函数名（但 JNI 符号 `Java_com_apkguard_...` 必须保留，否则 `System.loadLibrary` 后找不到方法）。
- 关闭可能泄露结构的调试/注释。

### 2.3 若采用 LLVM Pass：工具链依赖与 CI 怎么处理

（本节写给「万一决定走 A 路线」，并说明代价。）

- **工具链**：需要固定一个与 NDK clang 匹配的 LLVM 版本，构建或下载 OLLVM 版本；作为仓库外的预编译工具链（数百 MB），不能入库（`.gitignore` 已规定不入库 GB 级工具）。CI 需要缓存或每次下载。
- **构建流程改造**：`build_native.py` 增加分支：`clang -emit-llvm -c apkguard.c -o apkguard.bc` → `opt -load OLLVM.so -fla -bcf -sub ... apkguard.bc -o apkguard_obf.bc` → `clang -shared apkguard_obf.bc -o libapkguard.so`。三条命令都要适配 Windows/Linux（现有脚本已处理 `.cmd` 包装，见 `build_native.py:189` 的注释）。
- **CI**：
  - 现有「原生库重建」作业（手动触发或提交信息含 `[native]`）扩展为「用 OLLVM 工具链重建 3 个 ABI」；
  - 缓存工具链（key 用 LLVM 版本 + 目标 ABI）；缓存未命中时下载/构建，超时风险高；
  - 仍然断言 `.agexpect` 摘要一致、`p_align >= 0x4000`、3 个 ABI 都可编译；
  - 增加「确定性」检查：同输入两次构建应产生相同 `.text`（OLLVM 若用随机种子需固定 `-obf-seed`）。
- **回退**：若工具链不可用，CI 用普通 clang 构建并**明确标注该产物不含 C3**（但本地开发路径不能假装有 C3）。

### 2.4 实际防护价值评估（诚实说明局限）

- 保护对象仅 `libapkguard.so`；用户应用的原生库不受 C3 影响（我们不编译它们）。这是最关键的局限。
- 守卫库本身很小（799 行 C / ~25 KB）。逆向者一旦定位到 JNI 入口，OLLVM 通常只能把「读懂的几小时」拉长到「一两天」，挡不住专业团队。
- 真正的防护来自组合：C6 完整性让改库即崩、C2 SO 加壳让静态分析拿不到完整镜像、C4/C5 让动态调试/注入变难。C3 只是叠加的「摩擦」。
- 守卫库里最关键的秘密是**派生种子**（`AG_SEED_OBF`/`AG_SEED_MASK`，见 `internal/native/derive.go`）。SUB/CFF 能增加提取种子的难度，但无法阻止内存 dump：运行时种子必然被还原到内存，Frida hook `ag_derive` 即可拿到。**C3 不能替代 C2 与反注入**。
- 因此 C3 的定位应是「**低成本加固收尾项**」，而不是「核心防护」。设计文档把 C3 的来源标为通用 OLLVM + 厂商，但在本项目里它的性价比结论与厂商（会编译客户 native 代码）完全不同。

---

## 3. 与现有 Pass 的交互与执行顺序

**C3 是构建期（离线）变换，不是 APK 处理 Pass。** 这一点必须说清楚：

- 真正的变换发生在 `python internal/native/build_native.py` 编译 `libapkguard.so` 时（源码层宏或 OLLVM 工具链），产物随后被 `go:embed` 进二进制（`internal/native/embed.go`）。
- 因此 C3 **不在 `pipeline.Registry` 的处理链上改任何 APK 字节**。但为了让 `-enable C3` 能被接受、并与 `implementedIDs ↔ Registry` 的测试一致（`passes.go` 注册 + `config.go` implementedIDs 一一对应，见 `config.go:89` 注释），仍需注册一个**轻量 Pass**，其职责是：
  1. 确认被注入/内嵌的守卫库带有「已混淆」标记；
  2. 记录报告（哪个构建变体、覆盖哪些函数）；
  3. 在未启用时不做任何事。

**注册位置与理由**：

| 相对项 | 顺序 | 理由 |
|---|---|---|
| C1 密钥 native 派生 | C3 在 **C1 之后** | C1 负责把 `libapkguard.so` 注入产物（`shell.go:731` `native.Prebuilt()`），C3 的 Pass 在库存在后断言其已混淆标记最自然。实际上 C3 是内嵌库的属性，与 APK 无强依赖。 |
| C4/C5/C6/D4 | 同层，顺序无关 | 它们共用同一份库；C3 不改变 APK 结构 |
| B1 DEX 加密 | 无关 | B1 只处理 `.dex`，不碰 `.so`；C3 的库与 B1 载荷互不影响 |
| A14 时间戳统一 | C3 在 A14 之前 | C3 只读取，不新增条目；但若未来 C3 注入标记文件/条目，必须排在 A14 之前 |
| E6 兼容性自检 | 在 E6 之前 | E6 会统计各 ABI 的 `.so`；C3 若改变库内容，应在 E6 检查之前完成（构建期已定，顺序仅为报告清晰） |

**标记机制（与 C6 的 `.agexpect` 同构，避免自指问题）**：在 C 源码里放一个独立节，例如

```c
__attribute__((section(".agollvm"), used))
static const char AG_OLLVM_MARK[] = "AGOLLVM1";
```

`build_native.py --check` 既有的 `elf_sections()` 可直接读取该节并断言标记存在；C3 的 Pass 用 `debug/elf` 读取内嵌库的同一节做断言。标记节**不参与** C6 的 `.text`/`.rodata` 摘要范围（摘要只覆盖这两节），因此不会产生自指。

**与 C6 摘要的先后（重点）**：C3 必须在 **C6 摘要计算之前**完成——即 C6 的 SHA-256 覆盖的是**混淆后**的 `.text`/`.rodata`。顺序是「源码变换 → clang 编译 → 计算摘要 → 回填 `.agexpect`」。`build_native.py` 现有流程（编译 → `expected_digest` → `patch`）天然满足，无需改动。若走了 OLLVM 的 bitcode 两跳，也要保证最终 `.so` 生成后再算摘要。

---

## 4. 验收标准（可自动化断言的判据）

1. **存在混淆标记**：内嵌 `libapkguard.so` 的 3 个 ABI 都含 `.agollvm` 节且内容为预期标记。防回归：改了 C 代码却没走混淆构建、或 C3 被静默跳过。
2. **`.agexpect` 摘要与最终 `.text`/`.rodata` 一致**：`python internal/native/build_native.py --check` 全绿。防回归：C3 改了代码但摘要没重算（会导致 C6 运行时误判「被篡改」直接退出）。
3. **16 KB 页对齐**：3 个 ABI 的 `min(PT_LOAD p_align) >= 0x4000`（现有 `load_alignments()` 已实现）。防回归：混淆/额外链接参数改变段布局导致 Android 15+ 装不上。
4. **JNI 符号仍导出**：`Java_com_apkguard_nativebridge_Native_derive/debugged/hooked/intact/watch` 五个符号在 ELF 动态符号表中可见且可被 `System.loadLibrary` 解析。防回归：`-s`/版本脚本隐藏过头，导致 `UnsatisfiedLinkError`。
5. **不透明谓词恒真性**：单元测试用宿主编译（`AG_HOST_TEST`，见 `apkguard.c:695`）随机输入调用谓词宏，断言分支方向 100% 恒定。防回归：谓词写错导致语义改变（这是 C3 最危险的缺陷）。
6. **语义不变**：宿主自测（NIST SHA-256 向量 + `ag_derive` 对拍）全绿；真机上 `derive()` 派生的密钥与 Go 侧 `native.DeriveKey` 一致（现有 `TestDeriveMatchesNativeC` 的扩展）。防回归：SUB/CFF 改变运算结果 → 载荷解不开 → 应用启动即崩。
7. **检测逻辑仍有效**：真机上 `debugged()`/`hooked()`/`intact()`/`watch()` 返回值与混淆前一致（正常环境返回「未命中/完整」）。防回归：CFF 改坏了检测分支。
8. **确定性**：相同源码 + 相同 seed，两次构建的 `.so` 逐字节一致（除构建时间戳，需固定）。防回归：OLLVM 随机种子未固定导致无法复现与摘要对比。
9. **产物仍能正常运行**：三个真实应用（Termux/Dhizuku/RustDesk）在启用 C1+C3+C4/C5/C6 后装机实跑正常，无 `UnsatisfiedLinkError`。防回归：整体回归。
10. **本地器/模拟器**：x86_64 模拟器上进程存活、`libapkguard.so` 正常加载。

---

## 5. 风险与取舍（哪些做法会破坏产物、为什么不能做）

| 做法 | 后果 | 为什么不能做 |
|---|---|---|
| 对 `ag_watch_loop`、含提前返回/循环的函数做 CFF | 死循环、改变线程退出语义、D4 复检失效 | 手写平坦化极易在复杂控制流上出错；只对线性函数做 |
| 不透明谓词被 `-O2` 优化掉 | 变换完全失效却不报错 | 假分支必须依赖运行时值（`volatile`）才不会被删；需用断言/反汇编验证实际保留了分支 |
| 谓词不是恒定的 | 关键分支随机走错，`derive()` 结果错误 → 载荷解不开 → **应用一启动就崩** | 谓词必须数学可证明恒真/恒假，并随机输入验证 |
| 在 C6 摘要之后再做 C3 | 运行时 `intact()` 认为库被篡改，直接 `_exit(1)` | 摘要必须在最终产物上计算，顺序不能反 |
| `-s`/版本脚本把 JNI 符号也隐藏 | `System.loadLibrary` 后调用 native 方法抛 `UnsatisfiedLinkError` | 必须只导出 `Java_com_apkguard_*`，隐藏内部符号 |
| 用 OLLVM 但未固定随机种子 | 每次构建字节不同，无法复现/对比，CI 无法检出「改了 C 没更新 .so」 | 与仓库现有可复现哲学冲突 |
| 为 C3 引入 LLVM 工具链并入库 | 违反 `.gitignore`（不入库 GB 级工具）、破坏单二进制交付 | 工具链应外部化 + CI 缓存，且要评估是否值得 |
| 用宏做 SUB 时参数多次求值 | 副作用执行多次（如自增），语义错误 | 必须用 `static inline` 或确保参数无副作用 |
| 把 C3 宣传成「保护业务 native 代码」 | 用户误判防护范围 | 我们只编译守卫库；用户 SO 不受影响，必须如实说明 |
| 只在本地手工验证「看起来混淆了」 | 无法防回归；一次误改就让全量产物崩 | 必须有 §4 的自动化断言 + 真机回归 |

---

## 6. 最小可落地子集（第一个能独立验证、不破坏现有三个真实应用的切片）

目标：**零 LLVM 依赖、可确定性复现、不改变任何运行时行为**。

1. **只做 SUB + BCF（不做 CFF）**：在 `csrc/apkguard.c` 里加一组 `static inline` 等价替换函数与一个恒真谓词，应用到 `ag_derive` 的种子还原与 `ag_intact` 的长度/偏移计算。
2. **加 `.agollvm` 标记节**（不参与 C6 摘要范围）。
3. **扩展 `build_native.py --check`**：断言 `.agollvm` 标记存在 + `.agexpect` 摘要一致 + `p_align >= 0x4000`（后两项已有，只需加标记断言）。
4. **加一个 C3 Pass**（`LevelZip`，注册在 C1 之后），只读取内嵌库的 `.agollvm` 节并写报告；未启用时什么都不做。
5. **加断言**：
   - 宿主自测里随机输入验证谓词恒真；
   - `TestDeriveMatchesNativeC` 继续通过（证明 SUB 没改语义）；
   - 真机上三个真实应用 + `testapp` 启用 C1/C3/C4/C5/C6 后正常启动、进程存活。
6. **回归保护**：未启用 C3 时，产物与现状逐字节一致；启用 C3 只改变内嵌库内容，不改变 APK 结构（`lib/` 条目数不变）。

**为什么安全**：不动控制流结构（不做 CFF），只做数学等价替换与恒真假分支；语义由现有对拍测试兜底；失败时最坏是库编译不过或摘要不一致，能立刻在 CI 发现。

**第二步（可选）**：对 `ag_derive` 一个函数做手工 CFF，并加「反汇编验证伪代码不再线性」的人工检查；仍不做全库。

---

## 7. 工作量估计（人日，说明依据）

| 工作项 | 人日 | 依据 |
|---|---|---|
| C 源码层 SUB + BCF（含谓词正确性测试） | 3~5 | 改动集中在一个文件，主要成本是证明等价性与防止被优化掉 |
| `.agollvm` 标记 + `build_native.py --check` 扩展 + C3 Pass | 2~3 | 复用现有 `elf_sections()`/节表逻辑，Pass 只读 |
| 宿主对拍 + 真机回归（4 个应用/11 产物） | 3~5 | 参照 README 三应用回归的经验，运行期回归成本高于编码 |
| **最小子集合计** | **8~13 人日** | 约 1.5~2.5 周 |
| 手工 CFF 一个函数（含反汇编验证） | +3~5 | 状态机改写 + 逐路径等价验证 |
| 完整 OLLVM 工具链（路线 A/B）集成 | 15~30 人日，另加**长期维护** | 需要固定并自建 LLVM、改 CI、缓存工具链、跟进 NDK 升级；且只保护守卫库，ROI 极低 |
| **结论** | 最小子集 8~13 人日即可交付；**完整 OLLVM 不建议做** | — |

---

## 附：为什么「先做 B5/A6」比 C3 更重要（给排期者的对照）

- C3 保护的是我们自己 ~25 KB 的守卫库；B5（函数抽取）与 A6（控制流混淆）保护的是**用户的业务代码**，那才是加固产品真正的价值所在。
- C3 与 B5/A6 无依赖关系，可独立推进；若资源有限，应把 C3 排到最后（现有 `剩余功能落地设计.md` 的执行顺序也把 C3 放在最后，本方案的结论与其一致，但理由更具体）。