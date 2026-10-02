# 方案 B7：Dex2C / Java2C（把 Java 方法翻译成 C，编译成 SO，用 RegisterNatives 替换原实现）

> 本文是**设计文档**，不改任何代码。对应功能项 `B7`（`internal/config` 中 Stage=Long、Risk=Dangerous、默认关闭）。
> 参照实现：`internal/dex/nativebridge.go`（桥接类 + 静态初始化 loadLibrary）、`internal/native/csrc/apkguard.c`（JNI 入口）、
> `internal/native/build_native.py`（NDK 交叉编译 + `.agexpect` 回填）、`internal/passes/{shell.go,pack.go}`（native 库与桥接类注入、B1 载荷加密）。

---

## 0. 结论先行（TL;DR）

1. **B7 是一项以「人月」计的工程，短期内不现实**。一个能跑通真实应用（如 RustDesk 5449 类 / Flutter）的生产级 Dex2C，需要完整的 CFG 构建、类型推断、JNI 对象模型、多 ABI 编译与运行时注册框架。本仓库现有基建只覆盖其中的「DEX 解析/重建/汇编」和「native 库注入」两小块。
2. **B7 与项目当前的核心定位直接冲突**：工具现在是「单二进制、零外部依赖、native 库预编译并 `go:embed`」（见 `internal/native/embed.go` 的包注释）。B7 的翻译产物是**每个应用各不相同**的 C 代码，必须在**加固时**用 NDK 编译——这是第一个要求「用户机器上装 NDK」的功能，会破坏「双击即用」的交付形态（README 的用法说明）。详见 §2.5。
3. **B7 不能复用 B5（函数抽取）的 native 回填框架**。两者目标不同、所需能力不同：B5 是「把 code_item 字节写回 DEX 内存映射」，B7 是「DEX 里干脆没有字节码，靠 RegisterNatives 绑定到 C 函数」。重叠的只有「native 库要尽早加载 + 需要解析类」这一层 bootstrap。**正面回答见 §2.7。**
4. 建议路径：**先做 B5，把 B6 的运行时基建抽出来**（DEX→IR 的 CFG、对象模型、JNI 缓存），再决定 B7 是否值得。若一定要在近期交付，只做 §6 的受限子集（静态方法、无 try、无 synchronized、参数/返回值仅限基本类型与 String），且明确标注覆盖率。

---

## 1. 目标与预期效果

### 1.1 防住什么

| 攻击者手段 | B1/B3 一代壳 | +B5 函数抽取 | **+B7 Dex2C** |
|---|---|---|---|
| jadx/JEB/apktool 静态反编译 | 只看到壳 | 只看到壳 + 空方法体 | **方法体根本不在 DEX 里**，反编译得到 `native` 声明 |
| 内存 dump（Frida-DEXDump / BlackDex） | 可 dump 出全部业务字节码 | dump 到空方法体（若回填时机被抢到仍可能 dump 到明文） | **dump 不到任何原始字节码** |
| 静态分析 SO | — | — | 需逆向 C/汇编，配合 C3 才有意义 |
| 字符串/常量提取 | A2/A3 已处理 | 同左 | 翻译后的字符串以 C 字面量进入 `.rodata`，需 C2/C3 兜底 |

B7 的**独有价值**是：原始 Dalvik 字节码在整个生命周期中**从未以明文形式出现在 APK 或内存里**，因此对「静态反编译」和「内存 dump」同时成立。B5 做不到第二点（回填后内存里就是明文字节码，dump 工具只要在回填后取即可）。

### 1.2 量化

在「翻译子集」受限的前提下，可量化的指标应写成**覆盖率**而非「强度」：

- 可翻译方法占比：对受控测试应用 `testapp` 目标 ≥ 30%；对 RustDesk 这类真实应用预计 < 10%（大量 try/catch、synchronized、接口/虚调用、kotlin/Flutter 生成代码）。
- 被翻译方法在产物 DEX 中的 `code_item` 数减少量 = 翻译方法数（可断言）。
- 被翻译方法在 `jadx` 里显示为 `native`，无 `Code` 属性（可自动化断言：重新解析产物 DEX，检查这些 `EncodedMethod.Acc & ACC_NATIVE != 0` 且 `CodeOff == 0`）。
- 运行时：`RegisterNatives` 成功注册的方法数 = 翻译方法数；未注册即抛 `UnsatisfiedLinkError`（可断言）。

> 注意：**不要用「体积增量」当卖点**。翻译成 C 再编译，通常比原 DEX 字节码更大（一份 DEX 字节码约 2~6 字节/指令，等价 C 编译后的机器码在 4~8 字节/指令，再加 JNI 调用开销）。设计文档里写的「体积 +50%+」是准确的。

---

## 2. 技术方案

### 2.1 把哪些 Java 方法翻译成 C（判据）

翻译器的输入是**重建后的明文 DEX**（在 B1 加密之前）。选方法必须**保守**，因为任何一条不满足的语义都可能让整个方法甚至整个类校验失败。

**准入白名单（全部满足才翻译）**：

1. 方法带 `ACC_STATIC`，且不是 `<init>` / `<clinit>`（构造函数不能是 native；类初始化器翻译后无法保证触发时机）。
2. 声明类不是接口（接口方法不能是 native），不是注解，不是 `abstract`。
3. 方法体不含 `try/catch/finally`（异常表为空）。这是最硬的约束，见 §2.4。
4. 方法不带 `ACC_SYNCHRONIZED`（或翻译器能生成正确的 MonitorEnter/Exit，见 §2.4）。
5. 不调用 `invoke-super` / `invoke-direct`（对私有方法与构造函数的非虚调用）——v1 直接拒绝，避免解析「声明类」和 `CallNonvirtualXMethod`。
6. 不引用其他被翻译方法之外的、需要 `FindClass` 的复杂类型（v1 可放宽到「引用的类在注册时可用 `loadClass` 解析」）。
7. 指令数、寄存器数有上限（如 ≤ 200 条指令、≤ 16 个寄存器），避免生成超大 C 函数导致编译时间与栈溢出。
8. 方法被 `A1` 改名后仍在可翻译范围内（B7 排在 A1 之后，见 §3）。

**黑名单（显式排除）**：`onCreate`/`onResume` 等框架回调（可能被系统反射调用，且常含 try）、`equals`/`hashCode`/`toString`（重载多、易冲突）、`native` 已存在的方法、`synchronized` 且 v1 不支持、泛型桥接方法、`@JavascriptInterface` 等反射入口。

**选择策略**：默认不自动全选，而是支持 `-b7-methods <类名#方法名+描述符,...>` 白名单（或 `-b7-classes` 按类）。理由：自动选择在真实应用上很容易挑到不该挑的方法，产生「一装上就崩」的缺陷，而这类缺陷在单元测试里看不见（README 已经记录过多个同类教训）。

### 2.2 翻译器的实现路线（自研 DEX→C，还是先转 IR？）

**结论：必须先转中间表示（IR），不能做「DEX 指令流直接拼 C 文本」。**

原因：Dalvik 寄存器是无类型的、可复用的、宽值占两格、`move-result*` 必须紧邻 invoke、分支是相对偏移、`packed-switch`/`sparse-switch` 带 payload。直接把这种指令序列逐条翻译成 C 语句，会在寄存器复用、宽值、异常边、分支目标上大量出错，且错误只能到 ART 运行时才暴露（本地解释器不校验的部分更多）。

**推荐路线（分三层）**：

```
明文 DEX
  └─(1) CFG 构建：按基本块切分，保留 try 边界与异常处理器（复用 internal/dex/insn.go 的反汇编与分支重定位）
  └─(2) 类型推断 + 寄存器活跃性：给每个寄存器位置定出 int/float/long/double/ref/wide，供 C 声明使用
  └─(3) 自研小型三地址 IR（可选 SSA）：把 DEX 指令降低为 load/store/arith/call/branch/return 的 IR
  └─(4) C 代码生成：IR → C 文本（含 JNI 调用序列、异常检查、字符串字面量）
```

- (1)(2) 与 **A6 控制流混淆、B6 VMP 完全共用**。设计文档已经把 B7 标为「依赖 B6 的运行时基础设施」，本质就是依赖这套 CFG + 类型推断。
- (3) 不必做完整 SSA。对子集来说，一个「基本块 + 三地址指令 + 显式临时变量」的线性 IR 足够；SSA 只在需要做指令替换/优化时才有必要。
- (4) 输出 C 而不是 LLVM IR：理由是调试成本。C 文本可以人工阅读、可以用 `-O2` 交给 clang、出错时能定位到具体源码行；LLVM IR 一旦出错极难排查。若未来要做 C3 的 OLLVM 变换，也可以让 C3 作用在这份 C/IR 上（见 C3 文档），而不是依赖 LLVM Pass。
- **不要**走「DEX→Java 源码→C」这种两跳翻译：Java 源码级 IR 会引入大量本不存在的语义（装箱、泛型、异常），反而更难保证等价。

**翻译器的正确性验证**：必须有一个**解释器对拍**。仓库已有自研 DEX 汇编器，但没有 Dalvik 解释器。建议新增一个最小解释器（或在测试里用 ART 的 `dalvikvm`），对「翻译前的方法」和「翻译后 native 方法的返回值」在固定输入下逐条断言一致。这是 B7 唯一能自动化的语义等价性证明，**没有它就不应该上线**。

### 2.3 JNI 调用约定与 GC 引用

翻译出的 C 函数签名由方法描述符机械映射：

| Java 类型 | JNI 参数类型 | 返回 |
|---|---|---|
| boolean | `jboolean` | `jboolean` |
| byte/short/char/int | `jbyte`/`jshort`/`jchar`/`jint` | 同 |
| long | `jlong` | `jlong` |
| float/double | `jfloat`/`jdouble` | 同 |
| 引用类型 | `jobject`（或具体 `jstring`/`jarray` 等） | `jobject` |
| void | — | `void` |

每个 native 方法实现固定形态：

```c
static jint b7_0x12ab(JNIEnv *env, jclass cls, jint a0, jobject a1) {
    /* ... */
}
```

**GC 引用规则（必须严格遵守，否则是随机崩溃）**：

1. **入参是局部引用**，在本次 native 调用返回前一直有效。返回对象时可以直接 `return obj;`——ART 会把它提升到调用方的引用帧，**不需要** `NewLocalRef`。
2. **只有需要跨调用保存**（缓存 `jclass`/`jmethodID` 的目标对象、缓存字符串）时才用 `NewGlobalRef`。缓存 `jclass` 用全局引用，`jmethodID`/`jfieldID` 本身不是引用、不需要释放，但**方法 id 的解析依赖类未被卸载**，因此对应的 `jclass` 必须持有全局引用。
3. **循环里创建的对象必须 `DeleteLocalRef`**。native 方法的局部引用表默认容量有限（Android 通常 512），循环里 `NewString`/`CallObjectMethod` 返回值不释放会在几十次迭代后溢出，表现为 `JNI ERROR: local reference table overflow`。生成器应在「临时引用离开作用域」处插入 `DeleteLocalRef`，或在循环体内显式释放。
4. **异常检查**：任何可能抛异常的 JNI 调用（`Call*Method`、`Get*Field`、`New*`、`FindClass`、`GetMethodID` 等）之后立即
   `if ((*env)->ExceptionCheck(env)) { /* 见 2.4 的异常映射 */ }`。
   异常挂起期间**只能**调用 JNI 规范允许的少数函数（`ExceptionCheck`/`ExceptionOccurred`/`ExceptionClear`/`DeleteLocalRef`/`MonitorExit` 等），继续调用其它 JNI 函数是未定义行为。
5. `GetByteArrayElements` 后必须配对 `ReleaseByteArrayElements`；返回后不得再使用返回的指针。长生命周期的大数组拷贝建议用 `GetPrimitiveArrayCritical`（注意期间不得阻塞或调用 JNI）。
6. **不要在多线程间共享局部引用**。翻译器若生成静态缓存，必须用 `pthread_once` 或 `__atomic` 保护首次初始化。

### 2.4 Java 语义里 C 没有的部分

| Java 语义 | 处理方案 | v1 取舍 |
|---|---|---|
| **synchronized** | `MonitorEnter(env,obj)` / `MonitorExit`。必须在**所有**退出路径（含异常）配对执行：C 里用 `goto cleanup` + 单一出口，或在进入前保存 `MonitorEnter` 返回值并在每个返回点检查。monitor 对象：实例方法用 `this`，静态方法用 `jclass`。 | **v1 直接拒绝带 `ACC_SYNCHRONIZED` 的方法**（最简单、最不容易错）。后续用单出口模板支持。 |
| **try/catch/finally** | C 无异常。把每个 `try` 区间内的每条可能抛异常的指令之后插入 `ExceptionCheck`，命中则 `goto` 到对应 handler；catch 类型匹配用 `ExceptionOccurred` + `IsInstanceOf`（或用 `ExceptionCatch`）；finally 需在每个出口复制一份。 | **v1 直接拒绝含异常表的方法**。这是覆盖率的最大瓶颈，也是 B7 真正昂贵的部分。 |
| **虚方法调用** | `invoke-virtual`/`invoke-interface` → `Call<Type>Method(env, obj, mid, ...)`，JNI 按 `mid` 做虚分派，语义正确。`invoke-super`/`invoke-direct` → `CallNonvirtual<Type>Method(env, obj, declaringCls, mid, ...)`，需要声明类的 `jclass` 全局引用。 | v1 只允许 `invoke-static`/`invoke-virtual`/`invoke-interface`，拒绝 `invoke-super`/`invoke-direct`。 |
| **字符串常量 `const-string`** | 不能简单 `NewStringUTF`：它接受 modified UTF-8，遇到内嵌 NUL 或 4 字节 UTF-8 会出错，非 ASCII 会与 Java 的 UTF-16 语义不一致。正确做法是把字符串存成 `uint16_t[]`（UTF-16 字面量），运行时 `NewString(env, buf, len)`。 | v1 用 UTF-16 字面量 + `NewString`，每次使用新建（不缓存），正确性优先。 |
| **类初始化 `<clinit>`** | `GetStaticFieldID`/`GetStaticMethodID` **不**触发初始化；`GetStatic<Type>Field`/`CallStatic<Type>Method` **会**触发。因此只要按真实 JNI 调用生成，Java 的惰性初始化语义自动成立。 | 不翻译 `<clinit>`；翻译方法里引用静态成员时按上述规则调用即可。 |
| **`throw`** | `(*env)->ThrowNew(env, excCls, msg)` 后 `return` 默认值；或 `Throw` 一个已有对象。 | v1 若方法体含 `throw` 指令，同样因异常边而拒绝。 |
| **数组 / multianewarray / instanceof / checkcast** | `New<Type>Array`、`Get/Set<Type>ArrayRegion`、`GetArrayLength`；`IsInstanceOf`；checkcast 可省略（类型已由调用方保证），但为语义完整应 `IsInstanceOf`，失败 `ThrowNew(ClassCastException)`。 | 支持基本数组；`multianewarray` 暂拒绝。 |
| **long/double 宽值** | JNI 类型是单值（`jlong`/`jdouble`），但 DEX 寄存器占两格。在 IR 层就要把宽值归一为单个 C 变量，避免 C 侧出现两个寄存器。 | 必须做对，否则所有算术都错。 |

### 2.5 翻译产物怎么编译（NDK 交付约束是否可接受，以及无 NDK 时如何降级）

**编译命令**（每个 ABI 一条，与 `build_native.py` 的守卫库一致）：

```
<ndk>/toolchains/llvm/prebuilt/<host>/bin/<triple><api>-clang \
  -shared -O2 -fPIC -fvisibility=hidden \
  -Wl,-z,max-page-size=16384 -Wl,--gc-sections \
  -Wl,--version-script=b7.exports \
  -o lib<app>_b7.so b7_<app>.c
```

- ABI 集合**必须与 APK 已支持的 ABI 取交集**（与 C1 的 `abisOf` 逻辑一致，见 `internal/passes/shell.go:1169`）：给只有 arm64 库的 APK 补 32 位库会让系统误判支持架构。
- 只链接 `-llog`（可选），不引入 libc++/异常/RTTI；用 C 编译，避免 C++ ABI 与栈展开开销。
- 必须保留 16 KB 页对齐（`p_align >= 0x4000`），否则 Android 15+ 装不上。
- 版本脚本只导出必要的 JNI 符号，隐藏内部函数（同时给 C6 的完整性摘要一个稳定范围）。
- 生成 C 必须**确定性**（相同输入产生逐字节相同的 C），否则无法复现、无法做摘要校验。

**交付约束：加固工具在用户机器上需要 NDK。这可以接受吗？**

诚实回答：**这是对项目定位的一次实质性破坏，只能有条件接受。**

- 现状（`internal/native/embed.go` 包注释）：native 库预编译并 `go:embed`，工具本身单文件、无外部依赖，README 明确写「双击即启动图形界面」。
- B7 的翻译产物**按应用不同**，没有任何办法预编译进二进制。因此 B7 一旦启用，加固机必须能调用 NDK clang。
- 有条件接受的前提：
  1. B7 **默认关闭**、且是显式 opt-in（现状已经是 `Default:false`、`Risk:Dangerous`）；
  2. 启用时若找不到 NDK，**必须 fail-fast 报错**（沿用现有「未实现项被 `-enable` 拒绝而不是静默跳过」的哲学），**绝不静默降级**——否则用户以为拿到了 Dex2C，实际方法还是明文；
  3. GUI/CLI 在启用 B7 前检测 NDK，给出明确安装提示；
  4. 文档把「B7 是唯一需要 NDK 的功能」写清楚。
- 定位冲突的严重性：如果产品目标是「安全人员双击 exe 就能加固」，B7 与这个目标不相容；如果目标是「有构建流水线的团队使用」，可接受。

**没有 NDK 时如何降级**：

- 首选：拒绝启用 B7（fail-fast），并提示「请安装 NDK r26+ 或关闭 B7」。
- 若用户同时启用了 B5：可提示「B7 不可用，已按 B5 处理」（但这是**用户显式选择**的降级，不是工具偷偷做的）。
- **不可以**的降级：把「翻译」退化成「只加密字符串」之类的小改动，却仍然报告 B7 已生效。这与 README 里反复强调的「不静默跳过」原则冲突。
- 另一种真正能在无 NDK 下成立的路线：把方法翻译成**自定义字节码 + 预编译的 VM 解释器**（即 B6）。VM 是固定的、可预编译嵌入，不需要用户 NDK。代价是放弃「编译成机器码」的性能与形态，并且运行时仍要保护 VM。这也是为什么设计文档说「B7 依赖 B6 的运行时基础设施」——如果无法接受 NDK 依赖，B6 是更符合本工具定位的替代。

### 2.6 如何用 RegisterNatives 替换原方法

**DEX 侧改造（新增能力，当前 `dex.RebuildOptions` 不支持）**：

现有 `RebuildOptions` 只有 `CodeReplacements map[uint32][]byte`（按 code_item 偏移替换字节码，见 `rebuild.go:130`），**没有**「把已有方法改成 native」的能力。B7 需要新增：

```
type NativeMethodSpec struct {
    Class string; Name string; Proto ProtoSpec
}
// RebuildOptions 新增：
// NativeMethods []NativeMethodSpec
```

重建时对命中方法：
1. `Acc |= ACC_NATIVE (0x0100)`；
2. `CodeOff = 0`，并从 code_item 布局中剔除其 code_item（`assemble.go` 的 `writeMethods` 已按 `CodeOff != 0` 决定写 0，见 `assemble.go:854`）；
3. 校验：不得是 `<init>`/`<clinit>`/接口方法；不得同时出现在 `CodeReplacements` 里；
4. 更新 `outs_size` 等审计（native 方法没有 code_item，无需 outs）。

同时需要 `accNative` 常量从 `assemble.go:879` 提升为可供 rebuild 使用（当前是包内常量，B7 在 `passes` 包调用需走 `dex` 包 API）。

**注册时机（关键时序）**：

方法变成 native 后，ART 会在**首次解析到该方法**时按 JNI 符号名查找 `Java_<mangled>`，找不到就抛 `UnsatisfiedLinkError`。用 `RegisterNatives` 可以避免符号名映射（尤其 A1 改名后名字很短），但必须在**方法首次被调用之前**完成注册。

流程：

1. B7 生成一份 per-app 的 `lib<b7name>.so`，内含每个被翻译方法的 C 实现，以及一个注册入口（JNI 导出），例如：
   `Java_com_apkguard_nativebridge_Dex2C_reg(JNIEnv*, jclass, jclass target)`。
   该入口内持有「目标类 → JNINativeMethod[] 表」，对传入的 `target` 调 `RegisterNatives`。
2. 注入一个专用桥接类 `com.apkguard.nativebridge.Dex2C`，`<clinit>` 里 `System.loadLibrary("<b7name>")`，声明 `static native void reg(Class c);`（与 `nativebridge.go` 的 `NativeBridgeAddition` 同构，但库名/方法不同，避免与 `libapkguard.so` 的 JNI 符号冲突）。
3. B3 的 Loader 在 `DexClassLoader` 建好、ClassLoader 接管完成之后，对每个被翻译类执行：
   `Class c = cl.loadClass("<类名>"); Dex2C.reg(c);`
   **`ClassLoader.loadClass` 不触发 `<clinit>`**，因此可以在类初始化之前完成注册，语义安全。
4. 若某类在注册前就被解析（例如在 `attachBaseContext` 早期被框架或壳引用），会抛 `UnsatisfiedLinkError`。因此 v1 只翻译「确定在注册之后才被加载」的类（业务类），并把这个约束写进选择判据。

**为什么不用 `JNI_OnLoad` 里直接注册**：`JNI_OnLoad` 在 `System.loadLibrary` 时执行，那时 `DexClassLoader` 还没建立、目标类还不存在（B1 把业务 DEX 加密了），`FindClass` 必然失败。所以注册必须由壳在 ClassLoader 就绪后显式触发。

### 2.7 与 B5 的边界，以及能否复用 B5 的 native 回填框架（必须正面回答）

**边界（两者互斥，不能对同一方法同时启用）**：

| 维度 | B5 函数抽取 | B7 Dex2C |
|---|---|---|
| DEX 里方法的形态 | 仍是普通方法，`code_item` 被清空/移除，运行时**回填明文字节码** | `ACC_NATIVE`，`CodeOff=0`，**永不回填字节码** |
| 运行时由谁执行 | ART 解释器/JIT 执行原始 Dalvik 字节码 | 我们编译的 C 机器码 |
| 需要的能力 | 定位内存中的 DEX 映射、`mprotect` 可写、按偏移写 code_item、回复只读 | DEX 期改方法为 native、JNI 注册、C 运行时与对象模型 |
| 防内存 dump | 部分（回填后内存里有明文，时机抢得好仍能 dump） | 是（内存里从没有原始字节码） |
| 性能 | 基本无损（回填后走 ART） | 每次跨 JNI 有开销；被翻译方法内部是 native 码 |
| 工程复杂度 | 高（时序 + ART 版本差异） | 极高（翻译器 + 对象模型 + 多 ABI 编译） |

**能否复用 B5 的 native 回填框架？——不能直接复用。**

- B5 框架的核心是「`/proc/self/maps` 找 DEX → `mprotect` → 按偏移写 code_item → `mprotect` 回复」，B7 **完全不需要**这条路径，因为 B7 从不回填字节码。
- B7 需要的是另一套东西：JNI 对象模型（方法/字段 id 缓存、引用管理、异常映射）、`RegisterNatives`、以及「在类加载前完成注册」的时序。这些 B5 一个都没有。
- 两者真正共享的只有**最外层 bootstrap**：
  1. native 库尽早加载（B7 是 `Dex2C` 桥接类的 `<clinit>`，B5 可能是壳更早的 native 调用）；
  2. 在 native 侧解析类/方法（B5 找 DEX 映射，B7 找 `jclass`/`jmethodID`）；
  3. 「native 代码必须在 ART 校验/使用某个类之前介入」这一模式。
- 结论：**B7 依赖的是 B6 的运行时基建（CFG/IR/对象模型），不是 B5 的回填框架**。若先做 B5，它为 B7 提供的价值仅限于「证明 native 侧能稳定介入启动早期」这一点经验；B7 仍需从零搭翻译器与 JNI 运行时。
- 若两者共存：需要一个**方法归属登记表**（同一方法只能被 B7 或 B5 之一处理）。建议 B7 优先：B7 先挑走的方法从 B5 的抽取集合中剔除；两者都启用时在 `config.Validate` 里做交叉校验，避免出现「方法既被抽取又被注册」的冲突产物。

---

## 3. 与现有 Pass 的交互与执行顺序

### 3.1 注册位置

B7 横跨两个时机，而 `pipeline.Registry` 是「一个 FeatureID 只能注册一个 Pass」（重复注册会 panic），且所有 Pass 都是 `LevelZip`、执行顺序 = 注册顺序。因此 B7 必须拆成**早期翻译**与**晚期注册**两半，二者共享同一个 FeatureID 门控：

**方案 A（推荐，改动最小）：B7 一个 Pass 放在早期，晚期部分由 B3 消费共享计划。**

- B7 注册在 `renameClass`（A1）之后、`splitDex`（B4）/`encryptDex`（B1）之前。理由：
  - 必须在 A1 之后：`RegisterNatives` 表里的类名/方法名必须是**改名后**的最终名字；且 A1 对 `accNative` 方法不改名（`assemble.go:878` 注释），B7 放在 A1 之后可避免名称错位。
  - 必须在 A2/A3 之前：这样翻译器看到的 `const-string` 还是明文，直接生成 UTF-16 C 字面量；若排在 A2 之后，翻译器必须理解 A2 生成的「解密调用序列」，复杂且脆弱。
  - 必须在 B4 之前：B4 会按类把 DEX 拆成多份，翻译要看到完整类上下文；排在 B4 之后无法跨分片做类型/继承分析。
  - 必须在 B1 之前：B1 会把明文 DEX 加密并移除，之后再也改不了 code_item。
- B7 在早期把 `.so` 与桥接类信息写入 `Artifact.Shared`（键 `"B7.plan"`），并**在早期就注入 `lib/<abi>/lib<b7name>.so`**（zip 层加条目，B1 只处理 `.dex`，不受影响）。
- 晚期由 **B3 的 `classLoader` Pass 消费 `"B7.plan"`**：在生成 Loader 时，于 `DexClassLoader` 建立并接管之后，插入 `Dex2C.reg(cl.loadClass(...))` 调用序列（`LoaderSpec` 需新增 `NativeRegClasses []string` / `NativeRegLib string` 字段）。这需要**修改 B3 的 Loader 生成代码**——属于 B7 落地时的必要改动，需在实现前单独评审。
- 桥接类 `Dex2C` 的注入放在 B7 晚期（B2 之后）还是由 B3 顺带注入？因为 `LoaderSpec` 生成的是壳 DEX 里的类，`Dex2C` 也应注入壳 DEX。最自然的是：B7 早期把 `Dex2C` 的 `dex.Addition` 存进 Shared，B3 在注入 Loader 的同一次 `dex.Rebuild` 里一并加入（`Addition` 可含多个类）。

**方案 B：给 pipeline 增加「同一 FeatureID 多 Pass / 阶段优先级」能力**，让 B7 能注册「早期翻译 Pass + 晚期注册 Pass」两个 Pass。改动 pipeline 框架，影响面比方案 A 大，但更通用（B6/B5 将来也会遇到同类问题）。建议在 B7 立项时二选一，倾向方案 A（不动框架）。

### 3.2 与其它 Pass 的先后关系汇总

| 相对项 | 顺序 | 理由 |
|---|---|---|
| A1 名字混淆 | B7 **后** | 注册表要用最终名字；A1 不重命名 native 方法 |
| A2 字符串加密 / A3 常量数组化 | B7 **前**（即 B7 在它们之前） | 翻译器吃明文 `const-string`；被翻译方法不再有字节码，A2/A3 自然跳过 |
| A4 调试信息清除 | 无所谓 | 被翻译方法无 code_item/debug_info |
| B4 多 DEX 拆分 | B7 **前** | 需要完整类上下文做类型/继承分析 |
| B1 DEX 加密 | B7 **前** | B1 之后 DEX 已是密文，无法改 |
| B2 Application 替换 / B3 ClassLoader 接管 | B7 早期注入 .so；**晚期注册逻辑挂在 B3 内** | 目标类只存在于解密载荷，必须等 ClassLoader 就绪 |
| C1 密钥 native 派生 | 独立、可共存 | C1 注入的是预编译 `libapkguard.so` 与 `Native` 桥接类；B7 注入 per-app `.so` 与 `Dex2C` 桥接类。两者库名/类名/符号名都不同，不冲突。**但** C1 的 `native.Prebuilt()` 与 B7 的 per-app 库都会写 `lib/<abi>/`，需保证 ABI 集合一致，否则会出现「某 ABI 有 C1 库没有 B7 库」→ 该 ABI 上方法未注册而崩。 |
| C4/C5/C6/D4 | 独立 | 守卫库的检测；B7 库可选择性复用同一套检测 |
| E6 兼容性自检 | 需扩展 | E6 现在检查「各 ABI 的 .so 集合是否一致」，B7 的 per-app 库也要纳入该检查 |
| A14 时间戳统一 | B7 之后 | 新加的 `.so`/桥接类条目也要被 A14 覆盖 |

**native 库注入与 B1 载荷加密的先后（重点）**：B7 的 `.so` 是**原生库条目**，不是 DEX；B1 只加密并移除 `.dex` 条目（`pack.go` 的 `isDexEntry`），因此 `.so` 在 B1 之前或之后加入都不受影响。但**翻译（改 code_item）必须在 B1 之前**，因为 B1 之后明文 DEX 已不存在。两者不要混淆：「改 DEX」要早于 B1，「加 .so」随时可做。

---

## 4. 验收标准（可自动化断言的判据）

以下判据应全部进入 `scripts/verify-products.py` 与 Go 单测，每条都对应一类回归：

1. **被翻译方法变成 native 方法**：重新解析产物 DEX，对每个目标方法断言 `Acc & 0x0100 != 0` 且 `CodeOff == 0`。防回归：翻译器漏标/标错，导致方法仍有字节码（防护形同虚设）。
2. **原 code_item 不再存在**：目标方法的 code_item 偏移从布局中消失；产物 DEX 的 `code_item` 总数比输入减少 ≥ 翻译方法数。防回归：只加了 `ACC_NATIVE` 却没清 `CodeOff`（ART 会拒绝或忽略）。
3. **`RegisterNatives` 被调用且成功**：在生成的 C 里插入一次性日志（`-debug-shell` 版），或让 `reg()` 返回注册成功数，Loader 断言其等于目标方法数。防回归：注册表名字/签名与 A1 改名后的名字不一致（`NoSuchMethodError` 或被静默忽略）。
4. **产物 `lib/` 下多出正确的 `.so`**：`lib/<abi>/lib<b7name>.so` 存在，且 ABI 集合与输入 APK 支持的 ABI 一致（只多不少、只少不多）。防回归：给只支持 arm64 的 APK 补 32 位库导致系统误判架构。
5. **ELF 的 `p_align` 满足 16 KB 页要求**：复用 `build_native.py` 的 `load_alignments()`，断言 `min(p_align) >= 0x4000`。防回归：Android 15+ 装不上。
6. **DEX 结构自检仍全绿**：分支目标、异常处理器、`outs_size`、悬空引用等现有守卫（README「自动化守卫」表）对翻译后的产物全部通过。防回归：改 class_data 时破坏了索引/偏移。
7. **ART 能正常执行**：`dex2oat --compiler-filter=verify` 通过（注意 README 已说明它不能替代结构检查），并在模拟器上装机实测：进程存活、无 `UnsatisfiedLinkError`、无 `VerifyError`、无 `FATAL EXCEPTION`，翻译方法的返回值与翻译前一致（解释器/真机对拍）。
8. **语义等价对拍**：对每个被翻译方法，在固定输入下断言 native 实现返回值 == 原字节码实现返回值。防回归：翻译器的类型/宽值/引用处理错误。
9. **确定性**：相同输入 + 相同 seed，生成的 C 与 `.so` 逐字节一致（除编译期时间戳，需 `-frandom-seed` / `SOURCE_DATE_EPOCH` 固定）。防回归：无法复现、无法做摘要校验。
10. **覆盖率统计**：报告被翻译方法数/总方法数、被拒绝的原因分布（try、synchronized、invoke-super…）。防回归：覆盖率悄悄掉到 0 却仍报成功。

---

## 5. 风险与取舍（哪些做法会破坏产物、为什么不能做）

| 做法 | 后果 | 为什么不能做 |
|---|---|---|
| 翻译带 `try/catch` 的方法而不生成异常边 | ART 校验通过但运行时异常不按 Java 语义传播，业务逻辑静默错误 | 异常表是 DEX 校验的一部分，语义必须逐边还原；v1 只能拒绝 |
| `NewStringUTF` 处理非 ASCII / 内嵌 NUL 的 `const-string` | 字符串内容与 Java 不一致（截断、乱码） | modified UTF-8 与 Java UTF-16 不等价；必须 `NewString` |
| 循环里不 `DeleteLocalRef` | 局部引用表溢出，`JNI ERROR` 崩溃 | 引用表容量有限，长循环必崩 |
| 在 `JNI_OnLoad` 里 `FindClass` 注册 | `ClassNotFoundException` | 目标类在解密载荷里，`JNI_OnLoad` 时还不存在 |
| 把 `ACC_NATIVE` 方法也交给 A1 改名 | 注册表与运行时名字失配 | A1 已按 `accNative` 排除（`assemble.go:878`），B7 排在 A1 之后进一步规避 |
| 给 APK 补齐它不支持的 ABI 的 B7 库 | 系统误判支持架构，装上即崩 | 与 C1 的 `abisOf` 同一约束（`shell.go:724` 注释） |
| 翻译构造函数 `<init>` 或 `<clinit>` | ART 直接拒绝或初始化时序错乱 | JNI/ART 不允许；类初始化必须由 ART 自己控制 |
| 翻译接口方法 | DEX 校验失败 | 接口方法不能是 native |
| 直接拼接 DEX→C 文本、无 IR | 寄存器复用/宽值/分支错误，随机崩溃 | 见 §2.2；必须先转 IR |
| 无 NDK 时静默降级但仍报 B7 生效 | 用户误以为有 Dex2C，实际明文 | 与「不静默跳过」原则冲突 |
| 对已翻译方法再跑 B5 抽取 | 方法既是 native 又试图回填 code_item | 必须互斥，需方法归属登记 |
| 生成非确定性 C/.so | 无法复现、无法摘要校验、CI 无法对比 | 与现有 `build_native.py` 的可复现哲学冲突 |
| 用 dex2oat verify 当作唯一正确性证明 | 漏报结构错误 | README 已明确警告；必须叠加运行期对拍 |

---

## 6. 最小可落地子集（第一个能独立验证、不破坏现有三个真实应用的切片）

目标：**不接入 APK、不影响任何现有功能**，先证明翻译器与 JNI 运行时正确。

**Slice 0（纯离线原型，不碰 pipeline）**：

1. 手写一个 C 实现 `static int add(int,int)` 与一个 native 方法描述符，手工用 `RegisterNatives` 在一个最小 Android 测试 Activity 里注册并调用，验证 JNI 模板（引用/异常/字符串）正确。此步不需要翻译器。
2. 实现 `testapp` 中 `Features` 类的一个**静态、无 try、无 synchronized、参数与返回值仅基本类型**的方法的翻译器（如一个纯计算/校验方法），生成 C、用 NDK 编译、注入产物、B3 注册、真机断言返回值一致。
3. 只处理**单一 ABI**（x86_64 模拟器）、单方法、白名单指定。
4. 自动化：`go test` 里对「DEX→C」做金文件比对；`scripts/device-test.sh` 增加「B7 方法返回值 == 原方法」断言。
5. 边界：B7 默认关闭；只有显式 `-enable B7 -b7-methods ...` 且 NDK 可用时才运行；未启用时产物与现在**逐字节一致**（回归保护）。

**为什么这个切片安全**：不改 B1/B2/B3 的现有行为（只在 `LoaderSpec` 增加可选字段，默认为空），不改现有三个真实应用的加固路径；翻译对象由白名单限定；失败时 fail-fast 而不是产出半成品。

**下一步切片**：加入 `long/double` 与引用类型参数、加入 `invoke-virtual`、加入 `synchronized`（单出口模板），再考虑 `try/catch`。每加一类语义，都必须在真机上跑回归。

---

## 7. 工作量估计（人日，说明依据）

假设由熟悉本仓库 DEX 引擎的 1 名工程师全职推进；「人日」为净编码 + 测试时间，不含评审与真机排队。

| 工作项 | 人日 | 依据 |
|---|---|---|
| DEX→CFG + 类型推断 + 寄存器活跃性（与 A6/B6 共用） | 15~25 | 需要处理 try 边界、宽值、payload、move-result 邻接；A6 设计文档估「Go 约 500 行 + 较重测试」 |
| 三地址 IR + C 代码生成（受限子集） | 15~25 | 指令数 × 语义映射；JNI 模板、异常检查、引用管理 |
| JNI 运行时（id 缓存、引用、字符串、类解析） | 10~15 | 见 §2.3/§2.4，每项都要真机验证 |
| DEX 侧「方法改 native」重建能力 + 审计 | 5~8 | 改动 `dex.RebuildOptions`/`assemble.go`，需新增守卫 |
| per-app 多 ABI 编译集成 + `build_native.py` 扩展 + CI | 5~10 | NDK 定位、版本脚本、确定性、p_align、E6/CI 扩展 |
| RegisterNatives 桥接类 + B3 Loader 钩子 | 5~8 | 新增 `Dex2C` 桥接、`LoaderSpec` 扩展、时序验证 |
| 解释器对拍 / 真机回归 / 缺陷修复 | 15~30 | 参照 README 里「三应用全选项修掉 11 个缺陷」的经验，运行期问题通常比预想多 |
| **受限子集合计** | **70~120 人日** | 约 3~5 人月 |
| 完整生产级（try/catch、synchronized、虚调用、多态、真实应用覆盖率） | **6~12 人月** | 业界 Dex2C 产品的公开工程量级；且需持续跟进 ART 版本差异 |

**结论**：受限子集 70~120 人日才刚能验证，完整版以人月计。相对而言 B5（设计文档估「Go 约 300 行 + C 约 250 行」）与 A6（Go 约 500 行）的性价比高得多。**建议：B7 暂不立项，先做 B5/A6，把 CFG/IR 与对象模型作为共享基建沉淀，再评估 B7。**
