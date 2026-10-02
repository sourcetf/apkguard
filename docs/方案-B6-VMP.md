# 方案 B6：VMP 虚拟化（Dalvik 字节码 → 私有指令集，预编译 C 解释器执行）

> 状态：**设计稿（未实现）**。本文只描述落地方案，不改任何代码。
>
> 依据：`APK加固功能设计文档.md` §3 B6、§7.1（B6 防护价值「极高」、实现难度「极高」、P2、长期）；
> `剩余功能落地设计.md` 第三梯队 B6；`APK加固功能设计文档.md` §3 B6 的鉴别提示
> （「伪 VMP 只加密字节码，真 VMP 有独立 VM dispatch 循环」）。
>
> 代码落点（实现时必须遵守）：`apkguard/internal/dex/insn.go`（`InsnList`/`CodeItemFull`，
> 与 A6 共用）、`apkguard/internal/dex/asm.go`（生成桥接 stub）、`apkguard/internal/dex/rebuild.go`
> / `assemble.go`（把方法体替换为 stub）、`apkguard/internal/dex/nativebridge.go`（VM 桥接类）、
> `apkguard/internal/native/csrc/apkguard.c`（C 解释器）、`apkguard/internal/passes/{passes.go,pack.go,shell.go}`、
> `apkguard/internal/pack/pack.go`。
>
> 关联设计：`docs/方案-A6-控制流混淆.md`（CFG/基本块，B6 复用）、
> `docs/方案-B5-函数抽取.md`（边界与共享资产传递链）、
> `docs/方案-B7-Dex2C.md`（B7 §2.5 已指出「无 NDK 时 B6 是更符合本工具定位的替代」）。

---

## 0. 结论先行（TL;DR）

1. **B6 的形态是「翻译为私有指令集 + 生成的 Dalvik 桥接 stub + 预编译 C 解释器」**，
   而不是「把方法改成 `native` 再用 `RegisterNatives` 绑定 per-app 机器码」。后者需要
   在加固时用 NDK 编译每个应用各不相同的代码（即 B7 的交付约束），会破坏
   `internal/native/embed.go`「预编译 + `go:embed`、单二进制、零外部依赖」的定位。
   B6 的私有字节码是**数据**（放 assets，加密），解释器是**固定的 C 代码**（预编译进
   `libapkguard.so`），因此 **B6 不需要 NDK**。见 §2.4。
2. **不需要 `RegisterNatives`，也没有「注册早于类加载」的时序难题**。做法是把原方法体
   替换为一段**我们生成的 Dalvik stub**：它把参数装进 `long[]`/`Object[]`，调用桥接类
   `com.apkguard.nativebridge.VM` 上的**固定签名** native 方法 `run`/`runWide`，再解箱返回。
   `VM` 类在壳 DEX 里（B2/B3 注入、`libapkguard.so` 由 C1 注入），业务类通过父委派即可
   解析它。JNI 符号 `Java_com_apkguard_nativebridge_VM_run` 是**编译期固定**的，全 APK
   共用，天然满足预编译 `.so` 的约束。见 §2.4/§2.5。
3. **B6 与 B5 的本质区别：B6 是「翻译」，不是「加密/搬运」。** B5 保留原始 Dalvik 指令，
   只是把它们搬到 assets、运行时回填进 ART 内存，最终仍由 ART 执行**原始字节码**；B6 把
   原始 Dalvik 指令**翻译成私有指令集**，原始指令在 APK、磁盘、内存中**都不存在**，
   由我们的 C 解释器执行。见 §2.6。
4. **B6 的性价比高于 B7、低于 B5/A6**：无需 NDK、无需多 ABI 编译、无需完整类型推断
   （Dalvik 操作码已自带类型信息），但需要写一个正确、完整的私有 ISA 解释器与 JNI 对象
   交互层，工程量大且正确性风险集中在解释器。建议在 A6/B5 之后、B7 之前排期。见 §7。
5. **依赖必须加强**：B6 需要 B1（加密私有 blob）、B2/B3（壳与 ClassLoader 接管、`VM` 类
   注入）、C1（native 库注入）。当前 `config.Validate` 里 B6 只依赖 B2/B3，需补 B1/C1，
   见 §3.3。

---

## 1. 目标与预期效果

### 1.1 防住什么

| 攻击者手段 | B1/B3 一代壳 | +B5 函数抽取 | **+B6 VMP** |
|---|---|---|---|
| jadx/JEB 反编译 | 只看到壳 | 被抽取方法为空体 | 被虚拟化方法只剩**桥接 stub**，无原始逻辑 |
| 磁盘脱壳（拉解密后的 `d*.dex`） | 完整字节码 | 空方法体 | stub（无原始逻辑） |
| 内存 dump（Frida-DEXDump / BlackDex） | 完整字节码 | 回填后可见明文 | **看不到任何原始 Dalvik 指令**，只有私有指令 + 数据 |
| 静态分析 SO | — | — | 需逆向私有 ISA + 解释器；可再叠加 C2/C3 加固 `.so` |
| 字符串/常量提取 | A2/A3 处理 | 同左 | 字符串以 UTF-16 字面量进私有池（明文），**需 A2/A3 或对池二次加密兜底** |
| Frida hook 运行时 | 可 hook | 可 hook 回填的字节码 | 可 hook `VM.run` 入参/返回值，但拿不到中间逻辑（除非逆向解释器） |

**B6 的独有价值**：被虚拟化方法在整个生命周期中，**原始 Dalvik 指令从不以明文形式出现**
在 APK、磁盘或内存里；内存中只有私有指令流。这是 B5 做不到的（B5 回填后内存里就是原始
字节码），也是 B6 高于二代壳的地方。

**必须诚实说明的边界**：

- 逆向者仍可**逆向解释器本身**（私有 ISA 的语义最终由 C 代码定义），只是成本从「读
  jadx」上升到「逆向 VM + 反汇编私有字节码」。若解释器不做混淆（C3），专业团队仍可还原。
- B6 只保护**被选中的方法**。若方法调用链上的其他方法未虚拟化，攻击者仍能通过它们
  理解上下文。B6 的强度取决于「关键算法是否被完整覆盖」。
- 运行时通过 JNI 调用的对象/字段/方法仍会出现在解释器的调用序列里，Frida 可观察边界
  行为（入参/返回值），但看不到方法内部的运算过程。

### 1.2 量化指标（可自动化断言，见 §4）

- **虚拟化覆盖率**：被虚拟化方法数 / 候选方法数；报告必须给出「候选数、实际数、各拒绝
  原因分布」（含 try、monitor、invoke-super/direct、指令数超限、寄存器超限…），
  禁止「启用 B6 却虚拟化 0 个」仍报成功。
- **原始指令残留 = 0**：每个被虚拟化方法的原始 Dalvik 指令序列（哈希）不得出现在产物
  任何条目、解密后 payload、以及（回填场景下）内存 DEX 中。
- **stub 化率 = 100%**：产物 DEX 中每个目标方法的方法体等于生成的桥接 stub，且其内部
  私有指令流可由 Go 侧反汇编器**无未知操作码**地完整解码。
- **解释器命中率 = 100%**：`VM.init` 载入的 blob 条目数 == 计划虚拟化方法数；`VM.run`
  对每个方法的返回值与翻译前参考实现逐例一致。
- **性能**：被虚拟化方法的单次调用约为原生 Dalvik 的 **50~500 倍**（解释 + 装箱 + JNI），
  因此只用于冷路径；报告应给出被虚拟化方法的「调用频度提示」（无法静态精确，用白名单/
  人工确认代替）。
- **体积**：私有字节码 + 池元数据约为原 Dalvik 字节码的 1.5~3 倍（固定 32 位指令编码
  比 Dalvik 变长编码大），但被替换掉的 Dalvik 字节码本身会缩小，净增量取决于比例；
  解释器固定增加约 20~60 KB（3 个 ABI 合计，见 §7）。

---

## 2. 技术方案

### 2.1 私有指令集设计

**设计原则**：寄存器机、定长 32 位编码、每方法独立、语义贴近 Dalvik 以便机械翻译；
跳转用**绝对私有 PC**；常量池用**运行时可解析的引用表**。

**（1）虚拟寄存器映射**

- VM 寄存器文件 `uint32_t regs[N]`，`N = 原方法 registers_size`（上限如 128，超出拒绝）。
- 宽值（long/double）占连续两格，低编号存低 32 位（与 Dalvik 一致），便于把 Dalvik 的
  `move-wide`/`add-long` 机械映射。
- 参数寄存器布局沿用 Dalvik：参数占最高 `ins` 格，实例方法的 `this` 是第一个参数格。
  桥接 stub 按此把参数取出装箱，VM 侧再把 `regs[]` 还原成同一布局，翻译后的指令可直接
  引用原寄存器编号。

**（2）指令编码（定长 32 位）**

```
位布局：
  [7:0]   opcode
  [15:8]  vA
  [23:16] vB
  [31:24] vC
三种形式：
  RR : op vA, vB, vC          （三寄存器运算）
  RI : op vA, imm16           （小立即数/条件）
  IDX: op vA, idx24           （池引用：类型/方法/字段/字符串）
  JMP: op cc, target24        （绝对私有 PC，单位：32 位字）
  TAB: op vA, tableIdx24      （switch 跳转表在池中的索引）
```

- **定长**是刻意的取舍：解释器 dispatch 只需 `pc += 1`（字），无需按操作码算宽度，
  大幅降低 C 侧与 Go 侧出错面；代价是体积比 Dalvik 变长大。
- **绝对 PC** 而非相对偏移：翻译器在生成时已知最终布局，绝对目标不会因后续插入而漂移
  （私有字节码生成后不再改动，与 DEX 的分支重定位问题无关）。
- `target24` 支持单方法最多 16M 条私有指令，远超实际需要；越界即拒绝该方法的翻译。

**（3）操作码集合（v1 子集）**

| 类别 | 操作码（示意） |
|---|---|
| 数据搬移 | `MOV`、`MOV_WIDE`、`CONST8/16/32`、`CONST_WIDE`（池 literal） |
| 整数运算 | `ADD/SUB/MUL/DIV/REM/NEG`（int 与 long 各一套）、`AND/OR/XOR/SHL/SHR/USHR` |
| 浮点运算 | `FADD/FSUB/FMUL/FDIV`、`DADD/...`（float/double 各一套） |
| 类型转换 | `I2L/I2F/I2D/L2I/L2F/L2D/F2I/F2L/F2D/D2I/D2L/D2F/I2B/I2C/I2S` |
| 比较/分支 | `CMP_L/CMP_G/CMPL_FLOAT/...`（写 -1/0/1）、`TESTZ`、`Jcc cc,target24`（cc=always/eq/ne/lt/le/gt/ge）、`SWITCH`（跳转表） |
| 引用操作 | `NEW_INSTANCE`、`CHECK_CAST`、`INSTANCE_OF`、`MONITOR_ENTER/EXIT`（v1 拒绝） |
| 字段 | `IGET/IPUT/SGET/SPUT`（按值宽窄各一套，引用类型单独一套） |
| 数组 | `ARRAY_LENGTH`、`AGET/APUT`（各类型）、`NEW_ARRAY` |
| 调用 | `INVOKE_STATIC/VIRTUAL/INTERFACE`（v1 不做 super/direct）、`MOVE_RESULT/MOVE_RESULT_WIDE/MOVE_RESULT_OBJECT` |
| 返回 | `RETURN/RETURN_WIDE/RETURN_OBJECT/RETURN_VOID` |
| 异常 | `THROW`（v1 拒绝，见 §2.2） |

**（4）常量池（每方法一张）**

池条目是**运行时可解析**的引用描述，native 在首次执行该方法时解析并缓存：

| 条目 | 内容 | 运行时解析为 |
|---|---|---|
| `TYPE` | 类型描述符 | `jclass`（全局引用） |
| `METHOD` | 所属类 + 名称 + 原型 + 调用种类（static/virtual/interface） | `jclass` + `jmethodID` + 静态标志 |
| `FIELD` | 所属类 + 名称 + 类型 + 静态标志 | `jclass` + `jfieldID` + 静态标志 |
| `STRING` | UTF-16 字面量（`uint16[]`） | `jstring`（全局引用，或每次 `NewString`） |
| `LITERAL64` | 64 位常量 | 直接读取，不解析 |
| `TABLE` | switch 跳转表（`u32 target24[]`） | 直接读取 |

- **类解析必须走载荷 ClassLoader**：native 的 `FindClass` 使用桥接类的类加载器（壳加载器），
  看不到 payload 里的业务类。因此 `VM.init(blob, cl)` 接收 B3 的 `DexClassLoader` 并保存
  其**全局引用**，池里的 `TYPE` 用 `cl.loadClass(name)` 解析（JNI `CallObjectMethod`），
  再 `GetMethodID`/`GetFieldID`。这是本方案能成立的关键一环。
- 池索引在私有指令里是 24 位，单方法池容量 16M，足够。
- 池条目在 blob 里以紧凑二进制存储（见 §2.3），native 解析一次，缓存到 per-method 结构，
  用 `pthread_once`/互斥量保护首次解析（多线程可能并发调用同一方法）。

### 2.2 翻译器放在哪：编译期 Go 侧

**结论：翻译器是 Go 侧、在加固时运行，与 A6 一样做成 `RebuildOptions` 的选项；C 侧只有
解释器，没有编译器。**

流程：

```
明文 DEX（A1/A2/A3/A4 之后，B1 之前）
  └─(1) 选择方法（§2.7 判据）
  └─(2) 解码：复用 InsnList.ParseInsns（已处理 payload/分支/异常表）
  └─(3) CFG：复用 A6 的基本块划分（方案-A6 §2.1），得到块与后继
  └─(4) 降级：逐条 Dalvik 指令 → 一条或多条私有指令；收集池引用
  └─(5) 生成桥接 stub（用 dex.Asm/CodeBlob），并登记 {vmId, classDesc, name, proto}
  └─(6) 序列化私有字节码 + 池元数据 + 跳转表 → blob（明文）
  └─(7) 交给 B1 加密成 assets；B3 的 Loader 在运行时 VM.init(blobPlain, cl)
```

要点：

- **不需要完整类型推断**。Dalvik 操作码自带类型信息（`add-int` vs `add-long`、`iget` vs
  `iget-wide` vs `iget-object`），JNI 调用的返回/参数类型来自方法原型（池里已有）。这与
  B7 必须做类型推断才能生成 C 声明不同，是 B6 的显著简化。
- **`move-result*` 邻接**：翻译时把 `invoke` 与紧随的 `move-result` 合并处理（invoke 的
  目标寄存器 = move-result 的目标），不生成独立的私有指令，避免破坏邻接语义。
- **`packed-switch`/`sparse-switch`**：把 payload 转成私有 `TABLE`，`SWITCH` 指令按
  寄存器值与表做区间/稀疏匹配后跳转。`fill-array-data` 转成私有 `TABLE` + 逐元素写入
  寄存器（或直接在池里放字节数组，`NEW_ARRAY` 时填充）。
- **`<clinit>`/`<init>` 不翻译**（§2.7）。
- **异常**：v1 拒绝含 `try/catch` 与显式 `throw` 的方法。若 JNI 调用抛异常，VM 检测到
  pending exception 后立即停止执行并把异常留给 JNI（桥接 stub 返回后异常在 Java 层继续
  传播）——语义正确，但方法内的 catch 不生效，所以含 try 的方法必须拒绝。
- **`monitor-enter/exit`**：v1 拒绝 `ACC_SYNCHRONIZED` 与含 monitor 指令的方法。

**为什么不做「DEX→私有 IR→再优化」的多层**：B6 的私有 ISA 本身就是目标表示，Dalvik 到
它的映射是机械的；引入中间 IR 只会增加一层出错面。CFG 是为了分支/跳转表生成，不是优化。

### 2.3 私有 blob 格式（明文；由 B1 加密）

```
VmBlob {
    u32 magic/version
    u32 methodCount
    repeat methodCount:
        u32 vmId
        u16 clsLen,   bytes cls        // 类描述符（注册/诊断）
        u16 nameLen,  bytes name       // 方法名（诊断）
        u16 protoLen, bytes proto      // 原型描述（池解析需要参数/返回类型）
        u16 regsSize, u16 insSize
        u32 codeLen,  u32 code[codeLen]        // 私有指令（定长 32 位）
        u32 poolLen
        repeat poolLen: u8 kind + 变长负载（类型/方法/字段/字符串/字面量/跳转表）
    u32 checksum
}
```

- blob 放 **assets、加密**，与 B5 的抽取 blob 完全同一套机制：B6 Pass 只放明文进
  `Artifact`，B1 用载荷密钥 `pack.Encrypt` 加密成 `assets/<word>_<hex>.<ext>`，登记进
  `shellPayloads`（可复用 B5 的 `Extracts` 结构或新增 `Vms`），B8 一并搬迁。**不能放
  native 常量**，理由同 B5 §2.4（`.so` 是共享预编译产物）。
- native 解析后建立 `vmId -> method` 表，池在首次执行时解析缓存。

### 2.4 桥接 stub：为什么不用 `RegisterNatives`，以及 JNI 如何被「注册」

**桥接 stub 的 Java 等价（以 `static int f(int a, String b)` 为例）：**

```java
static int f(int a, String b) {          // 方法体被替换为下面这段 stub
    long[] p = new long[1];
    Object[] o = new Object[1];
    p[0] = a;                            // int 装箱为 long（宽化，不丢位）
    o[0] = b;
    Object r = VM.run(0x12ab, p, o);     // native，固定签名
    return (Integer) r;                  // 或 ((Integer) r).intValue()
}
```

- `VM.run(int id, long[] prims, Object[] objs)` 与 `VM.runWide(int id, long[] prims,
  Object[] objs)`（返回 `long` 原始位，供基本类型返回避免装箱）是**固定签名**的 native
  方法，其 JNI 符号 `Java_com_apkguard_nativebridge_VM_run` 在编译 `.so` 时就确定，
  全 APK 共用。**因此不存在 per-app C 代码、不存在多 ABI 编译、不需要 NDK。**
- 基本类型参数统一以「宽化到 64 位」进入 `long[]`：int-like 直接 `int-to-long`；
  float 用 `Float.floatToRawIntBits` 再 `int-to-long`；double 用
  `Double.doubleToRawLongBits`。VM 侧按原型还原。引用参数（含 `this`）进 `Object[]`。
- 返回值：引用/void 用 `run`（VM 内部装箱或返回 null）；基本类型用 `runWide` 返回原始位，
  stub 用 `long-to-int`/`int-to-float`/`long-to-double` 还原。避免「每次调用都装箱返回」。
- **为什么不用 `RegisterNatives`**：`RegisterNatives` 要求 native 函数指针与 Java 方法
  签名**ABI 一致**。任意签名的函数指针无法用一段通用 C 代码表示（变参 ABI 与定参 ABI 在
  ARM/AArch64 上不同，尤其 float/double 走独立寄存器），所以要么为每种签名预编译一个
  thunk（覆盖有限），要么用 libffi/运行时生成 trampoline（复杂且涉及可执行内存）。
  桥接 stub 方案把「参数搬运」放到我们**能生成的 Dalvik 字节码**里，native 只暴露两个
  固定签名入口，彻底绕开这个问题。这是 B6 区别于 B7 的关键工程决策。
- **时序**：`VM` 类在壳 DEX 里，由壳加载器加载，`<clinit>` 里 `System.loadLibrary`
  （复用 `nativebridge.go` 的既有模式）；业务类经父委派解析 `VM`。**没有「注册早于类
  加载」的约束**——stub 调用 `VM.run` 时 `VM` 必然已可解析（壳先于业务类加载）。
- **备选（不推荐）**：为若干常见签名预编译 native thunk（`(II)I`、`(Ljava/lang/String;)Z`
  等），把方法限定在这些签名内。它省掉 stub 代码生成，但覆盖率被签名集合卡死，且 float/
  double 参数仍需多套 ABI 特化，不如 stub 通用。v1 不采用。

### 2.5 解释器：C 实现，编译进共享 `.so`

- 解释器是 `apkguard.c` 中的固定 C 代码，随 3 个 ABI 预编译、`go:embed` 进主程序。
- 主循环：`for (;;) { op = code[pc]; switch (op) { ... } }`，用 `pc` 为索引（定长编码），
  可选 `goto *dispatch[op]` 的线程化分发提升性能（v1 用 `switch` 即可，先保正确）。
- 对象交互全部走 JNI：`CallStatic*MethodA`/`Call*MethodA`/`NewObjectA`/`Get*Field`/
  `Set*Field`/`New*Array`/`Get*ArrayRegion`/`IsInstanceOf` 等。
- **GC 引用管理（必须严格遵守，否则随机崩溃）**：
  - 每次 `run` 进入时 `PushLocalFrame(env, cap)`（`cap` ≥ 池中对象引用数 + 寄存器数 +
    余量），退出时 `PopLocalFrame`，自动释放方法执行期间产生的局部引用；
  - VM 寄存器里保存的引用来自「入参（局部引用）」「池缓存的全局引用」「JNI 调用返回的
    局部引用」三类，在 `PushLocalFrame` 范围内都合法；
  - 池里缓存的 `jclass`/`jstring` 用 `NewGlobalRef` 长期持有（进程生命周期，不释放）；
    `jmethodID`/`jfieldID` 不是引用，但依赖其 `jclass` 不被卸载，故必须持有全局引用；
  - 循环中创建的对象在覆盖寄存器或退出循环时 `DeleteLocalRef`（或依赖 `PopLocalFrame`）。
- **异常**：每个可能抛异常的 JNI 调用后 `if ((*env)->ExceptionCheck(env)) { /* 停止 VM，把
  pending 异常留给 Java */ }`。异常挂起期间只调用允许的少数 JNI 函数。
- **字符串**：池里的 UTF-16 字面量用 `NewString(env, (jchar*)buf, len)` 构造，**不能**用
  `NewStringUTF`（modified UTF-8 与 Java UTF-16 不等价，非 ASCII/内嵌 NUL 会错）。
- **宽值**：VM 寄存器是 32 位槽，long/double 占两槽；JNI 边界用 `jlong`/`jdouble` 单值，
  需要拼拆高低位，必须与 Dalvik 的「低字在低编号槽」约定一致。

### 2.6 与 B5 的区分（必须显式，防止被做成「伪 VMP」）

| 维度 | B5 函数抽取 | **B6 VMP** |
|---|---|---|
| 原始 Dalvik 指令 | 保留，搬到 assets，运行时**回填** | **翻译掉，永不存在** |
| 被保护方法在 DEX 里 | 普通方法 + 等长 stub | 普通方法 + **生成的桥接 stub**（调用 VM） |
| 运行时执行 | ART 执行原始字节码 | **我们的 C 解释器**执行私有指令 |
| 内存里的形态 | 回填后是原始 Dalvik 明文 | 私有指令流（32 位定长，与 Dalvik 不同构） |
| 是否有独立 dispatch 循环 | 无 | **有**（解释器主循环）——这正是「真 VMP」的鉴别点 |
| 反编译视图 | 空方法体 | stub（含 `VM.run` 调用）+ 私有 blob |
| 防内存 dump | 部分（回填后可见明文） | 是（无原始指令） |
| 性能 | 回填后无损 | 解释执行，慢 50~500 倍 |

**「伪 VMP」的判别**（也是本方案的验收点）：若产物里只是把字节码加密、运行时解密后仍
交给 ART 执行原始 Dalvik，则没有独立的 VM dispatch 循环，不满足 B6。本方案的私有指令
由 `apkguard.c` 的解释器循环消费，满足该判据（判据见 §4）。

### 2.7 哪些方法适合虚拟化（判据）

**硬门槛（全部满足才虚拟化）**

1. 非 `abstract`/`native`；不是 `<init>`/`<clinit>`。
2. `tries_size == 0`（无异常表）；不含显式 `throw`。
3. 不带 `ACC_SYNCHRONIZED`，不含 `monitor-enter/exit`。
4. 不含 `invoke-super`/`invoke-direct`（v1 拒绝，减少声明类解析与 nonvirtual 调用）。
5. 不含 `invoke-polymorphic`/`invoke-custom`（引擎对这两类的引用处理不完整，与 A6 一致）。
6. 指令数 ≤ 上限（如 300 条）、`registers_size` ≤ 上限（如 64），否则拒绝。
7. 参数与返回类型落在支持的集合内：基本类型 + 引用类型（v1 可先限定 int-like + 引用，
   再逐步放开 long/double/float）。
8. 方法体可被 Go 侧完整反汇编与降级（遇到未支持操作码即拒绝，不猜测）。

**收益排序（用白名单/配置，不自动全选）**

1. **冷路径优先**：B6 每次调用都有解释与装箱开销，**热路径绝对不虚拟化**（UI 回调、
   `onDraw`、每帧/每消息调用的方法、`equals/hashCode/toString`）。
2. **算法密集型优先**：加密签名、校验、许可判断、风控规则等「核心算法」是 B6 的目标；
   这些方法通常调用频度低但逻辑价值高。
3. **自包含优先**：尽量少依赖未虚拟化的同类方法，减少攻击者从上下文推断的机会。
4. **默认不自动全选**：提供 `-b6-methods <类#方法+描述符,...>` / `-b6-classes` 白名单
   （与 B7 §2.1 的策略一致）。自动选择在真实应用上极易挑到热路径或框架回调，产生
   「装上就卡/崩」且单测看不见的缺陷。
5. **与 B5/B7 互斥**：同一方法只能被 B5/B6/B7 之一处理。需要一张**方法归属登记表**
   （B7 §2.7 已提出），B6 先挑走的方法从 B5 的抽取集合中剔除。见 §3.1。

---

## 3. 与现有 Pass 的交互与执行顺序

### 3.1 注册位置

`passes.Registry()` 顺序即执行顺序。建议：

```go
r.Register(&renameClass{})     // A1
r.Register(&encryptString{})   // A2
r.Register(&constantArray{})   // A3
r.Register(&dropDebugInfo{})   // A4
r.Register(&controlFlow{})     // A6（若启用）
r.Register(&vmp{})             // B6  ← 新增：必须在 A1~A4/A6 之后、B1 之前
r.Register(&splitDex{})        // B4
r.Register(&extractFunc{})     // B5  ← B5 排除 B6 已拥有的方法
r.Register(&encryptDex{})      // B1
...
```

理由（每条都是硬约束）：

1. **必须在 A1 之后**：池里的类名/方法名/字段名是改名后的最终名字；`VM` 池解析按这些
   名字走 `loadClass`，名字错位会 `ClassNotFoundException`。
2. **必须在 A2/A3 之后**：翻译器面对的是已改写 `const-string` 的稳定指令流；被虚拟化的
   方法不再有 Dalvik 字节码，A2/A3 自然不处理它。
3. **必须在 A4 之后**：被虚拟化方法无 debug_info 需求（A4 已清）。
4. **必须在 B1 之前**：B1 加密并移除明文 DEX；之后无法再改方法体。
5. **与 B5 的先后**：**B6 在 B5 之前**，且 B6 把已虚拟化方法登记进共享的「方法归属表」，
   B5 的 `Select` 跳过它们。若顺序反过来，B5 会先把方法抽走，B6 再替换其 stub，二者冲突。
6. **与 B4 的先后**：B6 的 blob 以「方法身份（类名+方法名+原型）」为键，与 `code_off`
   无关，因此 B4 拆分前后均可；放在 B4 之前可看到完整类上下文（便于诊断），但非硬约束。
   建议 B6 在 B4 之前、A6 之后。
7. **与 B2/B3 的先后**：B3 生成的 Loader 要消费 `"B6.plan"`（`VM` 类注入、`VM.init` 调用）；
   B6 本身只写共享状态与（经 B1）加 assets，不改壳 DEX。
8. **与 B8 的先后**：B8 搬迁 assets 条目名，B6 的 blob 条目必须一并搬迁（同 B5）。

### 3.2 与 A1/A4/B5/B7 的关系

- **A1**：B6 在 A1 之后；A1 不重命名 `native` 方法（B6 的 stub 方法名是 A1 改名后的名字，
  池里记录一致）。`VM` 桥接类在壳 DEX 中，A1 不处理壳（A1 在 B2 之前）。
- **A4**：B6 在 A4 之后；stub 的 `debug_info_off` 为 0，无额外处理。
- **B5**：互斥（见 §3.1）；共享「方法归属表」与 assets 传递链。
- **B7**：互斥且能力互补。B7 需要 NDK、把方法变 native；B6 不需要 NDK、保留 Dalvik stub。
  两者可共存但方法集合必须不相交（同一张归属表）。若同时启用，建议 B7 优先挑走方法，
  B6 处理其余——与 B7 §2.7 的「B7 优先」一致。
- **A6**：两者都在 A4 之后。若同时启用，A6 平坦化的方法与 B6 虚拟化的方法应不相交
  （A6 会打散控制流，B6 需要干净的可翻译体）。建议 B6 在 A6 之后并读取 A6 的归属标记，
  或干脆在文档/配置层要求二者用不同白名单。

### 3.3 依赖校验（`config.Validate` 需要补）

当前：`"B6": {{"B2",...},{"B3",...}}`。落地方案要求补为：

```
"B6": {{"B1","私有 blob 必须随载荷加密，否则明文暴露"},
       {"B2","VM 桥接类注入壳 DEX、壳提供启动时机"},
       {"B3","Loader 触发 VM.init(blob, cl) 并提供载荷 ClassLoader"},
       {"C1","解释器所在的 native 库由 C1 注入"}}
```

同时 `config.Options` 需要新增 B6 的方法白名单字段（如 `B6Methods []string`），并在
CLI/Web UI 暴露；`ExtractRatio` 是 B5 的，不用于 B6。

---

## 4. 验收标准（可自动化断言）

对齐既有守卫风格（`artifact_test.go` 产物级体检、`scripts/verify-products.py` 产物断言）。
B6 新增守卫建议命名 `vmp_test.go`，失败信息写清「ART 会怎么报」。

| # | 判据 | 自动化做法 | 防住的回归 |
|---|---|---|---|
| 1 | **被虚拟化方法体等于桥接 stub** | 解析产物 DEX，对每个目标方法反汇编，断言指令序列等于 Go 侧生成的 stub（含 `VM.run`/`runWide` 调用），且原方法首条指令不再出现 | 替换失败/漏替换 → 防护形同虚设 |
| 2 | **原始 Dalvik 指令残留 = 0** | 对每个目标方法抽取前指令词做哈希，扫描产物所有条目与解密后 payload 的字节流，断言不出现 | 「翻译了但原文还在」 |
| 3 | **私有 blob 可被完整反汇编** | 解密 blob，用 Go 侧私有 ISA 反汇编器逐条解码：无未知 opcode、池索引在界内、跳转目标落在 `[0, codeLen)`、`TABLE` 索引合法 | 翻译器编码错误（本地能过、设备上 `run` 崩溃） |
| 4 | **stub 结构合法** | 复用分支目标/异常处理器/`outs_size`/`move-result` 邻接/`dex.Verify` 守卫；断言 stub 的 `registers_size`/`ins` 与生成器一致 | stub 生成错误 → `VerifyError` |
| 5 | **`VM.init` 命中率 100%** | Loader 调用 `VM.init(blob, cl)` 返回载入方法数，断言 == `B6.methods` 统计；不符即终止 | blob 未解密/未注入/路径错 |
| 6 | **解释器语义正确** | 真机：目标方法返回值与「未虚拟化参考实现」在固定输入下逐例一致；`go test` 里用 Go 侧参考解释器对拍私有字节码 | 解释器算术/宽值/分支/池解析错误 |
| 7 | **ART 能正常执行** | 模拟器装机：进程存活，无 `VerifyError`/`UnsatisfiedLinkError`/`NoSuchMethodError`/`FATAL EXCEPTION`；`adb logcat` 无私有 ISA 相关崩溃 | stub/池引用写坏、`VM` 类解析不到 |
| 8 | **独立 dispatch 循环存在**（真 VMP 判据） | 静态检查 `libapkguard.so` 中存在解释器符号/循环特征；或断言产物中目标方法无原始逻辑且运行时由 native `run` 计数递增 | 「伪 VMP」（只加密字节码仍交给 ART） |
| 9 | **确定性** | 相同输入 + seed，私有 blob 与 stub 逐字节一致 | 无法复现、CI 无法对比 |
| 10 | **B6 不是空操作** | 启用 B6 但实际虚拟化 0 个方法时必须报错/显式警告 | 「声明已实现、退出码 0、实际无效果」 |
| 11 | **E6/ABI 不回归** | 解释器符号在 3 个 ABI 的 `libapkguard.so` 中都存在（复用 `embed_test.go` 风格）；不抬高 `injectedMinAPI`；ABI 集合与 APK 一致 | 某 ABI 缺符号 → 该架构 `UnsatisfiedLinkError` |
| 12 | **B8 联动** | 启用 B8 时私有 blob 条目名被搬迁，壳按容器路径能读到 | 「启用 B8 后 B6 blob 路径失配」 |
| 13 | **方法归属不冲突** | 同一方法不同时出现在 B5/B6/B7 的计划里；冲突时 `config.Validate` 或 Pass 直接报错 | 方法既被抽取又被虚拟化 |

补充：判据 1~4、9、11、12、13 可在 Go 单测（含交付包与 `testdata/`）里跑，**不需要真机**；
判据 5~8、10 需要真机/模拟器（`scripts/device-test.sh`）。

---

## 5. 风险与取舍

### 5.1 明确会破坏产物、不能做的做法

1. **把方法改成 `ACC_NATIVE` + `RegisterNatives` 绑定 per-app C**：需要加固时 NDK 编译，
   破坏单二进制/零依赖定位（B7 的约束），且任意签名需要 per-signature thunk。必须用
   「Dalvik 桥接 stub + 固定签名 native 入口」。
2. **用 `NewStringUTF` 构造池里的字符串**：modified UTF-8 与 Java UTF-16 不等价，
   非 ASCII/内嵌 NUL 会截断/乱码，业务逻辑静默错误。必须 `NewString` + UTF-16。
3. **JNI 局部引用不管理**：循环里创建对象不释放 → `JNI ERROR: local reference table
   overflow`。必须 `PushLocalFrame`/`PopLocalFrame` + 必要的 `DeleteLocalRef`。
4. **在异常挂起期间继续调用普通 JNI 函数**：未定义行为。必须 `ExceptionCheck` 后立即停。
5. **把宽值当单槽处理**：long/double 高低位错乱，所有相关运算错误。必须在寄存器映射层
   统一「占两槽、低字在低编号」。
6. **翻译含 try/catch 的方法却不实现异常边**：异常不按 Java 语义传播，静默错误。v1 必须拒绝。
7. **虚拟化热路径/框架回调**：性能崩塌或时序异常。必须白名单 + 冷路径判据。
8. **把私有 blob 放 native 常量或 per-app 重编 `.so`**：同 B5，破坏预编译定位。
9. **依赖 `dex2oat --compiler-filter=verify` 当唯一验收**：它看不到「stub 调用了错误的 VM id」
   这类语义错误。必须叠加真机返回值对拍。
10. **在 `JNI_OnLoad` 里 `FindClass` 业务类**：业务类在加密载荷里，`JNI_OnLoad` 时不存在
    （B7 §2.6 已论证）。类解析必须走 `VM.init` 保存的载荷 ClassLoader。
11. **不做方法归属登记就同时启用 B5/B6/B7**：同一方法被重复处理，产物冲突。必须有归属表。
12. **解释器不做任何边界检查**：私有 blob 若被篡改（无 MAC 时），`code[pc]` 可能越界执行。
    v1 至少在解析期校验 `codeLen`/池索引/跳转目标；后续可叠加 `方案-载荷完整性.md` 的 MAC。

### 5.2 只在特定 Android 版本可用 / 版本相关风险

- **JNI 与 Dalvik stub**：所有目标版本可用（纯公开 API/字节码）。
- **`DexClassLoader` 与 `VM` 类解析**：`VM` 在壳加载器、业务类经父委派解析，全版本成立。
- **`PushLocalFrame` 容量语义**：各版本最小容量不同，v1 显式请求足够容量并留余量。
- **ART 对 stub 的校验**：与 B5 相同的「具体方法体是否被接受」问题——但 B6 的 stub 是
  正常 Dalvik 方法体（不是等长空洞），结构上更常规，风险低于 B5；仍需真机验证。
- **16 KB 页对齐**：解释器在既有 `libapkguard.so` 内，`build_native.py` 已保证，无需新增
  原生库；`embed_test`/CI 已覆盖。
- **C3/OLLVM**：若要对解释器做控制流混淆，属 C3 范畴，不在 B6 内。

### 5.3 取舍

- **覆盖率 vs 正确性**：v1 拒绝 try/monitor/invoke-super/direct/大方法，覆盖率有限；这是
  保证「不破坏产物」的必要取舍。真实应用（RustDesk/Flutter）大量含 try，预计可虚拟化
  比例 < 10%，因此 B6 应与 B5 组合（B5 覆盖大面、B6 覆盖核心算法）。
- **性能 vs 强度**：解释执行慢 50~500 倍，只用于冷路径；用白名单把代价限制在关键方法。
- **定长编码 vs 体积**：定长 32 位简化解释器与翻译器，代价是体积约 1.5~3 倍。
- **不做类型推断 vs 表达能力**：依赖 Dalvik 操作码自带类型信息，省掉 B7 级的类型推断，
  但要求翻译器对每条操作码都正确映射；遇到不确定的操作码一律拒绝。
- **不做异常/同步**：牺牲覆盖率换取「不引入静默语义错误」，符合本项目「宁可拒绝，不可
  静默降级」的一贯原则。

---

## 6. 最小可落地子集

**目标：独立验证、不破坏现有三个真实应用的运行。**

**M1（第一个可交付切片）**

范围（全部满足才虚拟化）：

- 单个 `testapp` 方法，白名单指定；
- `static`、非 `<init>`/`<clinit>`、无 try、无 monitor、无 `invoke-super/direct`；
- 参数与返回值为 int-like（int/boolean/byte/short/char）或引用类型；
- 方法体含算术、比较、分支、循环（覆盖 CFG 与跳转），指令数 ≤ 64，寄存器数 ≤ 16；
- 只处理 x86_64 模拟器所需路径（解释器本身 3 ABI 都编译，但先只验证 x86_64）。

实现顺序（每一步都可独立验证）：

1. **纯离线原型（不接入 pipeline）**：手写一个私有字节码程序 + 一个最小 C 解释器，
   在宿主上用 TCC/clang 编译运行，验证 ISA 编码、算术、分支、池解析（可参照
   `apkguard.c` 的 `AG_HOST_TEST` 宿主自测模式）。
2. **翻译器**：把上述 testapp 方法的 Dalvik 字节码翻译为私有字节码，Go 侧用参考解释器
   （纯 Go）执行并与 `internal/dex/interp_test.go` 的 Dalvik 解释器结果对拍。
3. **stub 生成**：用 `dex.Asm`/`CodeBlob` 生成桥接 stub，`Rebuild` 替换方法体。
4. **native 解释器**：把宿主原型移植进 `apkguard.c`，加 `VM.init`/`VM.run`/`VM.runWide`
   JNI 入口与 `nativebridge.go` 的 `VM` 类。
5. **接线**：B6 Pass + `"B6.plan"` + B1 加密 blob + B3 Loader 调 `VM.init`。
6. **断言**：`vmp_test.go` 判据 1~4/9/11/13；`device-test.sh` 增加「B6 方法返回值 ==
   参考实现」判据。

交付物：`vmp_test.go` + 一份可复现的 testapp 产物；B6 默认关闭，未启用时产物与现状
**逐字节一致**（回归保护）。

**下一步切片**：逐步放开 long/double/float、引用返回、字段访问、数组、`invoke-virtual`/
`interface`；再考虑 `synchronized`（单出口模板）与 try/catch（异常表进私有 ISA）。每放开
一类语义，都必须在真机上跑回归。

---

## 7. 工作量估计（人日，说明依据）

以 `剩余功能落地设计.md`「B6：最高强度，工作量以周计」与 `方案-B7-Dex2C.md` 的分解为基准
细化。假设由熟悉本仓库 DEX 引擎与 C/JNI 的 1 名工程师全职推进；「人日」为净编码 + 测试。

| 工作项 | 人日 | 依据 |
|---|---|---|
| 私有 ISA 定稿 + 编码/反汇编器（Go） | 3~5 | 定长 32 位、池/跳转表格式；需与 C 解释器逐位对拍 |
| DEX→私有字节码翻译器（复用 A6 的 CFG，受限子集） | 10~18 | 操作码映射、宽值、`move-result` 合并、switch/跳转表；参照 B7 §2.2 的 CFG 估计 |
| 桥接 stub 生成（`dex.Asm` 装箱/解箱/调用/返回） | 4~6 | 参数寄存器布局、宽化与 raw bits、寄存器预算；易错 |
| C 解释器（dispatch + 全部 v1 操作码 + JNI 对象/字段/数组/调用） | 15~25 | 与 JNI/GC 交互是主要成本（引用帧、异常、宽值、字符串） |
| 池解析与缓存（走载荷 ClassLoader、`pthread_once`、全局引用） | 4~6 | `FindClass` 不可用，必须 `cl.loadClass`；多线程首次解析 |
| blob 序列化 + B1 加密 + `shellPayloads`/B8/B3 接线 + `VM` 桥接类 | 4~6 | 复用 B5 的 assets 传递链；`VM` 类注入壳 DEX |
| `vmp_test.go` 守卫（判据 1~4/9/11/13） | 3~4 | 对齐 `artifact_test.go` 产物体检风格 + Go 参考解释器对拍 |
| 真机/模拟器回归与缺陷修复（testapp → Dhizuku → RustDesk） | 10~20 | 解释器/GC/宽值类缺陷平均需多轮真机；README 历史经验 |
| **M1 合计** | **约 55~90 人日** | 约 2.5~4.5 人月 |
| 完整生产级（long/double/float、数组、虚调用、synchronized、try/catch、真实应用覆盖率、解释器混淆） | **6~12 人月** | 业界 VMP 产品的公开工程量级；且需持续跟进 ART 版本 |

**与 B7 的对比**：B7 受限子集 70~120 人日且**需要 NDK**；B6 M1 约 55~90 人日且**不需要
NDK**，因此更符合本项目「单二进制、零外部依赖」的定位。B6 的主要风险不是编译链，而是
**解释器与 JNI/GC 交互的正确性**——这是 M1 里最需要预留真机时间的一项。

**不确定性最大的地方**：① 解释器的 JNI 引用/异常/宽值处理（判据 6/7，建议先在宿主
`AG_HOST_TEST` 模式用纯 C 假 JNI 跑通，再进设备）；② 桥接 stub 的参数搬运是否正确
（判据 4/6）；③ 真实应用里可虚拟化方法的占比（决定 B6 与 B5 的组合价值）。建议把
「离线原型 + Go 参考解释器对拍」作为第一步（约 8~12 人日），在投入 C/JNI 之前先证明
ISA 与翻译器的语义等价性。