# 方案：C2 SO 加壳（Native 库内容保护）

> 状态：设计稿（未实现）。
> 关联代码：`apkguard/internal/dex/loader.go`（Loader 字节码）、
> `apkguard/internal/passes/shell.go`（LoaderSpec / C1 注入 / E6 自检）、
> `apkguard/internal/zipx/write.go`（对齐）、`apkguard/internal/config/config.go`
> （`Options.SOEncrypt` 与功能项注册表）。
> 设计依据：`APK加固功能设计文档.md` §4 C2、§7.1（C2 优先级 P1）、
> `剩余功能落地设计.md`「C2. SO 加壳」。

---

## 1. 目标与预期效果

### 1.1 防住什么

| 攻击手法 | 现状（无 C2） | 加 C2 后 |
|---|---|---|
| `unzip app.apk lib/arm64-v8a/*.so` | 直接拿到明文 ELF，可 `readelf` / IDA / Ghidra 静态分析 | `lib/` 下不再有明文业务 .so，只能拿到高熵密文 |
| `strings libfoo.so` 提密钥/接口/URL | 有效 | 失效（密文无字符串） |
| 基于 ELF 结构的自动化特征扫描 | 有效 | 失效（资产里不是合法 ELF） |
| 对 native 逻辑做静态脱壳（IDA 反编译） | 有效 | 需先复现壳的解密流程并拿到密钥，成本显著抬高 |

**不防住**：动态调试 attach 后的内存 dump（那是 C4/C5/D4 的职责）；
Java 层 `System.loadLibrary` 调用点仍可静态看到库名。C2 只解决
「静态提取并分析 .so 内容」这一层。

### 1.2 效果量化

- `lib/<abi>/` 下业务 .so 数量：**N → 0**（若同时启用 C1，则只剩
  `libapkguard.so` 这 1 个由加固工具自己注入的库）。
- assets 下新增密文载荷数：**= 原 .so 总数**；每个载荷体积 ≈ 原 .so + 16 字节 IV
  （复用 `internal/pack` 的 `IV ‖ AES-256-CBC(PKCS7)` 格式，与 B1 一致）。
- 静态工具判定：`file` 对载荷输出 `data`（非 `ELF`）；`readelf` 报
  `Not an ELF file`。
- 启动开销：每个 .so 多一次「读 assets + AES 解密 + 写私有目录」，
  典型 5~30 ms/库（视体积），且只在首次启动；后续可做「已存在且校验通过则跳过」。
- 体积增量：≈ 0（原 .so 从 `lib/` 移除，密文写入 assets，密文与原文等长；
  AES-CBC 填充最多 +16 字节）。**注意**：若原 .so 是压缩存放，移除后
  assets 密文按 STORED 存，体积可能略微增大。

---

## 2. 技术方案

### 2.1 三种粒度

#### (a) 整文件加密（推荐首期）

**做法**：把 `lib/<abi>/*.so` 从 APK 移除，逐个用 `pack.Encrypt`
（AES-256-CBC，`IV ‖ 密文`）加密后作为 `assets/` 条目存放；壳在
`attachBaseContext` 的最早时机把每个库解密写到应用私有目录
（如 `<dataDir>/app_ag/lib/`），把该目录（可再拼上原 `nativeLibraryDir`）
作为 `DexClassLoader` 的 `librarySearchPath`，随后 B3 照常接管 ClassLoader。

**关键点**：整文件加密**不改动 ELF 一个字节**，因此：

- 16KB 页对齐（`p_align=0x4000`）、`DT_NEEDED`、`DT_RUNPATH`、
  `.init_array`、符号表、重定位表全部原样保留——不存在「重新链接」风险。
- 不需要 `JNI_OnLoad`、不需要解析 ELF、不需要 `mprotect`。运行时只是
  「字节搬运 + AES + 落盘」，与 B1 的 DEX 解密是同一套已验证机制。

**这是唯一能在短时间内做到「不改 ELF 语义」的粒度**，也是本方案的推荐主线。
`internal/config/config.go` 里已预留 `Options.SOEncrypt` 与 CLI
`-so-encrypt`，正是为这条路线铺的。

**可行性前提（必须满足，否则产物直接坏）**：

1. 解密后的 .so 必须在 `dlopen` 前变为**只读**（W^X，见 §2.2.1）。
2. 库搜索路径必须让应用的 `System.loadLibrary` 能找到它（见 §2.2.3）。
3. 同一 ABI 下要么全部加密、要么全部不加密，不能混放——否则
   `DT_NEEDED` 依赖链会一半在私有目录、一半在 `lib/`，解析行为不可控。
4. 应用若用 `System.load(绝对路径)` 或 native `dlopen` 裸名加载，可能失效
   （见 §2.2.4）。

#### (b) 只加密代码段 / 数据段（短期不推荐，`.text` 明确不可行）

**原设计**（`剩余功能落地设计.md`）：解析 ELF、定位 `PT_LOAD`，
在 `JNI_OnLoad` 里 `mprotect` 后解密 `.text`/`.rodata`。

**逐条评估**：

- **`.text` 加密在「由同一个 .so 的 `JNI_OnLoad` 解密」的形态下不可行。**
  动态链接器加载一个库时，必须先完成映射、符号解析与重定位，才能调用该库的
  `JNI_OnLoad`；而执行 `JNI_OnLoad` 的代码本身就在 `.text` 里。密文 `.text`
  在重定位阶段就已经无法执行，`JNI_OnLoad` 永远等不到。要加密 `.text`，必须
  由**另一个**已知明文库（stub）负责 `dlopen` 目标库并在映射后解密，这等价于
  「自建 ELF 加载器 + 手工重定位 + 符号解析」——正是 `剩余功能落地设计.md`
  里评估为「C 约 300 行 + 自建 ELF 加载器、风险高」的那条路。**结论：`.text`
  段加密在首期不可行，需要单独排期。**
- **数据段（`.rodata`/`.data`）加密可行但收益有限。** 可以在 `JNI_OnLoad`
  里对已映射的页 `mprotect(PROT_READ|PROT_WRITE)` → 解密 → 恢复只读。但：
  - 必须保证解密发生在**任何**使用这些数据之前（`JNI_OnLoad` 之前若
    有 `.init_array` 构造函数读到 `.rodata`，就会读到密文）。而 `.init_array`
    在 `JNI_OnLoad` 之前执行，顺序是「`.init_array` → `JNI_OnLoad`」。因此
    只有「不被构造函数、不被重定位使用」的数据才安全，覆盖面被进一步压缩。
  - 并非所有库都有 `JNI_OnLoad`（纯 `dlopen` 的库没有）。要给没有的库加
    一个，就得**改写 ELF**（新增符号、改 `.dynsym`/`.dynamic`、可能改
    `.init_array`）。项目当前**没有 ELF 改写能力**（只有 DEX 引擎），
    这是一块全新的基建。
  - 数据段加密只隐藏字符串/常量，代码逻辑仍可反汇编——防护价值明显低于 (a)。
- **综合**：数据段加密需要「ELF 解析 + 选择性加密 + 注入/复用 `JNI_OnLoad`」，
  且只覆盖部分库，性价比低于 (a)。建议列为 (a) 之后的增强项，且**只做数据段、
  不做代码段**。

#### (c) 组合

先做 (a)（把整个库藏起来），对少数高价值库再做 (b) 的数据段二次加密，
形成「外层整文件密文 + 内层数据段密文」。**首期不做**：两层解密叠加，
排障成本翻倍，且 (b) 的基建尚未具备。若将来做，必须先有 (a) 的稳定验证。

### 2.2 必须正面回答的问题

#### 2.2.1 应用能否写自己私有目录并 `dlopen` 那里的 .so？Android 10+ 有限制吗？

**能，但有 W^X 约束。** 应用私有目录（`/data/user/0/<pkg>/`、`/data/data/<pkg>/`）
所在文件系统是**可执行**的，`dlopen` 私有目录里的 .so 一直是被允许的——
主流加固/热更新方案都靠这一点。限制来自 Android 10（API 29）起的
**W^X 强制**：

- 目标 API ≥ 29 的应用**不能 `dlopen` 一个「可写」文件**。链接器会拒绝，
  典型报错是 `dlopen failed: ... is writable by the app` 或
  `library "... " is not accessible for the namespace`。
- 解决办法：写盘后立刻把文件设为**只读**（`chmod 0400` / `File.setReadOnly()`），
  再 `dlopen`。这与 `loader.go` 里 `loaderWriteCode(MarkReadOnly)` 对 DEX
  做的事完全同构——**C2 必须复用同一套「落地后置只读」逻辑**，并且对
  `targetSdk ≥ 29` 无条件启用（不是像 DEX 那样只在 ≥34 才启用）。
- 另一条约束：**外部存储**（`/sdcard`、`getExternalFilesDir()`）通常
  `noexec` 或不被链接器命名空间接受，**绝不能**把解密后的 .so 放到那里。
  必须落在 `Context.getDir(...)` 返回的内部私有目录（B3 的 `loaderTempDir = "ag"`
  已经踩过这个坑）。

> 结论：**可行**。C2 的解密落地目录应与 B3 的 `loaderTempDir` 同源
> （例如 `<dataDir>/app_ag/lib/`），并复用「写后置只读」。

#### 2.2.2 `extractNativeLibs=true/false` 分别会发生什么？

先明确一个事实：**安装器只处理 `lib/<abi>/` 下的条目**。C2 把业务 .so
移出 `lib/`、放进 `assets/` 之后，**两种取值下系统都不会去碰那些密文**——
assets 不是原生库，安装器不解析、不解包。

| 场景 | `extractNativeLibs="true"` | `extractNativeLibs="false"` |
|---|---|---|
| 安装期行为 | 把 `lib/<abi>/*.so` 解包到 `/data/app/.../lib/<abi>/`，`ApplicationInfo.nativeLibraryDir` 指向该目录 | 不解包；`lib/` 条目必须**未压缩且按页对齐**，链接器直接从 APK mmap |
| C2 移走业务 .so 后 | 该目录里没有业务库（空或只剩 C1 的 `libapkguard.so`） | APK 的 `lib/` 里没有业务库；密文在 assets，与链接器无关 |
| 系统会不会解出「加密的 .so」 | **不会**（因为 lib/ 里已无业务 .so） | **不会**（同上） |
| 对 C2 的要求 | 解密后的库落到私有目录即可 | 同左；额外要求剩下的 `lib/*.so`（如 `libapkguard.so`）保持 STORED + 对齐 |

**危险做法（明确禁止）**：把加密后的 .so **留在 `lib/`** 只是改内容。那样：

- `extractNativeLibs=true`：安装器会把**密文**解包到 `nativeLibraryDir`，
  应用 `System.loadLibrary` 直接读到密文 → `UnsatisfiedLinkError` 或加载非法库崩溃；
- `extractNativeLibs=false`：链接器 mmap 密文页 → 同样失败。

所以 C2 的正确形态是「**从 `lib/` 移除 + 密文进 assets**」，绝不能
「原地加密 `lib/` 条目」。这也是验收判据里必须断言「`lib/` 下无明文 .so」
且「assets 下出现密文」的原因。

另外要注意：**C1 会往 `lib/<abi>/` 注入 `libapkguard.so`**。C2 的扫描必须
**跳过工具自己注入的库**（按文件名 `libapkguard.so` 排除，或按
`internal/native` 的 `LibFileName` 排除），否则会把桥接库也加密，
壳自己就起不来。

#### 2.2.3 运行时如何让应用加载到解密后的 .so？

有两条互补的路径，**两条都要做**：

1. **ClassLoader 库搜索路径**（覆盖绝大多数 `System.loadLibrary`）。
   `System.loadLibrary("foo")` → `Runtime.loadLibrary0` →
   `ClassLoader.findLibrary("foo")` → 在 `nativeLibraryDirectories` 里找
   `libfoo.so`。B3 已经构造了 `DexClassLoader(dexPath, optDir, librarySearchPath, parent)`
   （见 `loader.go` 的 `loaderEntryCode`，当前第三参传的是
   `ApplicationInfo.nativeLibraryDir`）。C2 要把它改成
   `"<解密目录>:<原 nativeLibraryDir>"`——**解密目录在前**，原目录兜底，
   这样未被 C2 处理的库（以及将来 C1 注入的库）仍能解析。多个路径用
   `File.pathSeparator`（`:`）拼接，与现有 `dexPath` 的拼法一致。
2. **反射改写 `ApplicationInfo.nativeLibraryDir`**（覆盖按目录拼路径的代码）。
   不少 SDK 会读 `context.getApplicationInfo().nativeLibraryDir` 再自己拼
   `nativeLibraryDir + "/libfoo.so"` 去 `System.load`。把该字段反射改成
   解密目录（`nativeLibraryDir` 是公开 SDK 字段，反射不受隐藏 API 限制），
   这些代码就能继续工作。**时机**：必须在原 `Application.onCreate()` 之前
   完成（B2 的 `attachBaseContext` 里、委托原 Application 之前），因为
   SDK 通常在 `onCreate` 里初始化。

**注意**：改写 `nativeLibraryDir` **不能**修复 native 层裸名 `dlopen`——
链接器命名空间的搜索路径是进程启动时由系统按 APK 配置的，不读这个 Java 字段
（见 §2.2.4）。

#### 2.2.4 哪些应用形态会不兼容？

按风险从高到低：

| 形态 | 为什么坏 | 能否补救 |
|---|---|---|
| **native 层 `dlopen("libfoo.so")`（裸名）** | 链接器命名空间只包含 APK 的 lib 目录与系统目录，不含我们的私有目录；`librarySearchPath` 是 Java `ClassLoader` 概念，链接器不读 | **不能**（除非自建命名空间/自实现加载器，属 B7 级基建） |
| **`android_dlopen_ext` 从 APK 内按偏移加载**（Flutter / React Native / Unity / TFLite 等常见） | 库直接从 APK 的 `lib/` 里按 zip 偏移 mmap；我们把 .so 移走了，偏移与文件都不存在 | **不能**，且这类框架通常把 APK 路径写死在 native 侧 |
| **`System.load("<绝对路径>")`，路径来自 `nativeLibraryDir`** | 文件已不在 `nativeLibraryDir` | **能**：反射改写 `nativeLibraryDir` 指向解密目录（前提是文件名一致） |
| **`System.loadLibrary` 的名字与文件名不匹配**（如 `loadLibrary("foo")` 但实际是 `libfoo_v2.so`） | 本来就依赖自定义 `findLibrary`；移库后更难命中 | 视应用而定，通常无解 |
| **应用枚举/统计 `lib/` 内容**（自检、体积统计、ABI 判断） | `lib/` 变空 | 视用途，可能误判 |
| **加密的库之间互相 `DT_NEEDED`** | 若同 ABI 全部加密到**同一目录**，链接器会在「请求方所在目录」找依赖，通常能解析；**混放则会失败** | **能**：强制「同 ABI 全加密」 |
| **`.so` 作为数据被读取**（`AssetManager.open("lib/...")` 或读 APK zip） | 条目已改名/移除 | 视应用而定，需审计 |

**Flutter 是重点风险**：RustDesk 1.5.0 是 Flutter 应用。Flutter 引擎加载
`libflutter.so` 通常走 `System.loadLibrary("flutter")`，但随后
`libflutter.so` 会加载 Dart AOT 库 `libapp.so`——现代 Flutter 倾向于用
`android_dlopen_ext` 直接从 APK 读未压缩的 `libapp.so`（配合
`extractNativeLibs=false`）。若是这种形态，整文件加密 `libapp.so` 会让
RustDesk 启动失败，且无法用 `librarySearchPath` 挽救。**这一条必须在
真机上先探针验证，不能靠推测**（见 §6 最小切片）。

#### 2.2.5 16KB 页对齐（`p_align=0x4000`）怎么保持？

- **整文件加密 (a) 天然保持**：加密只改变字节内容，不改变文件长度、
  不改变任何 ELF 偏移与 `p_align`。原库是 0x4000 就是 0x4000。
- **数据段加密 (b) 也保持**：原地加密不改变布局，前提是**绝不允许改动
  文件大小/段偏移**（只做等长异或/流加密）。若用 AES-CBC 这种会填充的算法
  直接原地加密，长度会变，段偏移全废——(b) 若实施，必须用**等长**变换
  （CTR/异或密钥流），这是硬约束。
- **必须警惕的既有缺口**：Android 15（API 35）起，16KB 页设备要求所有
  `PT_LOAD` 的 `p_align ≥ 0x4000`。项目自己的 `libapkguard.so` 已由
  `build_native.py` 用 `-Wl,-z,max-page-size=16384` 保证，但**业务 .so 的
  `p_align` 由原 APK 厂商决定**：老 NDK 构建的库可能是 0x1000，在 16KB
  设备上本来就会加载失败。C2 **不能也不应**去「修正」业务 ELF 的 `p_align`
  （那需要重链接），只能在 E6/审计里**报告**：「该库 `p_align=0x1000`，
  16KB 页设备上会失败」。
- **`extractNativeLibs=false` 时的 ZIP 对齐**：此时剩下的 `lib/*.so`
  （主要是 C1 的 `libapkguard.so`）必须 STORED 且按**页大小**对齐，才能被
  直接 mmap。`zipx.DefaultAlign()` 目前是 `SoAlign: 4096`；在 16KB 页设备上
  应提升到 **16384**（等价 `zipalign -P 16`）。**这是 C2/E2 的一个已知
  交互缺口**：若目标含 targetSdk ≥ 35 或 16KB 页设备，E2 的 `.so` 对齐
  需要可配置为 16384，否则 `extractNativeLibs=false` 的产物在 16KB 设备上
  可能装不上/加载失败。建议在 C2 落地时同步把 `SoAlign` 做成随
  targetSdk/页大小推导。

#### 2.2.6 加固时如何判断某个 .so 是被谁加载的？（决定可行性上限）

**结论先说：无法穷举。** 我们看不到应用源码，也无法在打包期知道运行时的
每一条加载路径。因此 C2 的可行性上限，取决于「能否把待加密的库限定在
**只经 Java `ClassLoader` 解析**的那一类」。

**可做的静态审计（按可靠性排序）**：

1. **DEX 调用点扫描**（可靠）：遍历业务 DEX 的指令流，找
   `System.loadLibrary`、`System.load`、`Runtime.load`、`Runtime.loadLibrary0`
   的调用点，记录：
   - `const-string` 直接给出的库名/路径（最可靠）；
   - 库名来自变量/拼接（A2 字符串加密后更难）→ 标记为「不确定」。
2. **native 依赖图扫描**（可靠，但只覆盖 `DT_NEEDED`）：解析每个业务 .so 的
   `.dynamic`，记录 `DT_NEEDED`、`DT_RUNPATH`/`DT_RPATH`、是否含
   `$ORIGIN`。若 A 依赖 B，则 A、B 必须一起处理（同目录）。
3. **框架特征识别**（启发式，但命中即高危）：检测 APK 是否含
   `libflutter.so`/`libapp.so`、`libhermes.so`、`libunity.so`、
   `libreactnativejni.so`、`libtensorflowlite*.so`、`libmonochrome.so` 等；
   命中则**默认判定为「native 自加载、不可整文件加密」**，除非探针证明可行。
4. **`extractNativeLibs` 与 `nativeLibraryDir` 探针**：装到设备上 dump
   `dumpsys package <pkg>` 与 `ApplicationInfo`，确认 `nativeLibraryDir`
   是否存在、`lib/` 是否被解包。这决定 §2.2.3 的哪条补救路径有效。

**审计输出的裁决**：

- 所有业务 .so 都能在 DEX 里找到明确的 `loadLibrary` 字面名，
  且无 native 自加载特征 → **可整文件加密**。
- 存在 native 裸名 `dlopen` / `android_dlopen_ext` / 无来源的库 →
  **该库不可整文件加密**，只能：跳过、或等 (b) 数据段方案、或标记
  「需人工确认」。
- 审计结果必须写进产物报告与 E6，不能静默通过。

> 这条审计就是 C2 的「可行性上限开关」。没有它，C2 就是一次盲目的赌博：
> 对 Termux 这种「纯 Java 调 `loadLibrary`」的应用大概率成功，
> 对 Flutter/Unity 大概率失败。

### 2.3 推荐数据流（整文件加密 (a)）

```
加固期（新增 C2 Pass，LevelZip，注册在 B4/B1 之前）：
  for each lib/<abi>/<name>.so（排除 libapkguard.so）:
      data = entry.Data()
      blob = pack.Encrypt(data, key, IVFromSeed(seed+"/so/"+abi+"/"+name))
      记录 SOItem{ Abi, Name, Asset, DexName="<abi>/<name>.so", Size=len(blob) }
      pipeline.Add(art, zipx.NewStored(Asset, blob))
      pipeline.Remove(art, lib/<abi>/<name>.so)
  把 SOItems + 原 ABI 集合 存入 Artifact.Shared（键如 "C2.payloads" / "C2.abis"）

运行期（扩展 B3 的 Loader 字节码）：
  libDir = base.getDir("ag/lib", 0); libPath = libDir.getAbsolutePath()
  for each SOItem:
      in  = base.getAssets().open(assetKey(Asset))
      blob = r(in, Size)
      so   = c(blob, key)            // 复用 loaderDecryptCode
      f    = new File(libDir, DexName)  // 注意先 mkdirs
      w(f, so)                        // 复用 loaderWriteCode，且必须置只读
  // librarySearchPath = libPath + ":" + nativeLibraryDir
  // 反射改写 ApplicationInfo.nativeLibraryDir = libPath
  cl = new DexClassLoader(dexPath, optDir, librarySearchPath, parent)
  i(cl)  // 原 B3 接管逻辑
```

**需要的代码改动点（本方案只设计、不实现）**：

- `dex.LoaderSpec` 增加 `LibItems []LoaderLibItem` 与 `LibDir string`
  （或复用 `Items` + 类型标记），`loader.go` 生成对应的解密落地循环，
  并把 `librarySearchPath` 从 `nativeLibraryDir` 改为
  `libPath + ":" + nativeLibraryDir`。
- `passes/classLoader.Run` 读取 C2 写入的共享载荷清单，填充
  `LoaderSpec.LibItems`。
- 新增 C2 Pass 与注册；把 C2 加入 `implementedIDs` 与 `Validate` 依赖表
  （C2 依赖 B2/B3，因为解密与库路径都必须由壳完成）。
- C1 的 ABI 选择（`abisOf`）改为优先使用 C2 记录的原 ABI 集合（见 §3）。
- `-so-encrypt` 与 `-enable C2` 语义统一（当前 `SOEncrypt` 字段存在但
  没有任何 Pass 读取，`-so-encrypt` 单独给等于什么都没做——落地时必须
  让二者等价，否则又是「声明了却没作用」的失败模式）。

---

## 3. 与现有 Pass 的交互与执行顺序

### 3.1 注册位置

`internal/passes/passes.go` 的 `Registry()` 里，**C2 应注册在 B4/B1 之前**，
即 L2 区块的头部（`r.Register(&splitDex{})` 之前），或紧随 A5/A11 之后。

理由：

1. **必须在 B3 之前**：B3 生成 Loader 字节码时要把「SO 载荷清单 +
   解密目录 + librarySearchPath」内联进去；清单必须在 B3 运行时已经存在。
   这与 B8 必须在 B3 之前是同一个道理（B8 先改载荷名，B3 再把名字内联）。
2. **必须在 B2 之前**：B2 决定壳要调用哪些入口；若 C2 要壳调用一个
   资源/库解密入口，清单要先于 B2 存在（或按 §3.2 的替代方案）。
3. **必须在 C1 之前**：C1 会往 `lib/<abi>/` 注入 `libapkguard.so`；
   C2 先跑就不会误加密工具自己的库，且 `abisOf` 看到的是**应用原始 ABI 集合**。
4. **与 B1 无强依赖**：B1 处理 DEX、C2 处理 SO，互不冲突；但两者都往
   assets 加条目，C2 用独立命名空间（如 `assets/<容器>/lib/<abi>/...`）避免
   与 B1/B8 的载荷名冲突。B1/B8 的载荷名派生基于 DEX 名，C2 基于
   ABI+库名，天然不撞。
5. **必须在 A14 之前**：A14 统一全部条目时间戳，C2 新增的密文条目要一并被统一。
6. **与 E2/E1 的关系**：E2/E1 在 `pipeline.DefaultSink.Finish` 里执行，
   在所有 Pass 之后，天然在 C2 之后，顺序正确（对齐/签名不能被 C2 破坏）。
7. **必须在 E6 之前**：E6 要检查最终 `lib/` 的 ABI 覆盖一致性，必须在
   C2 移除业务库之后运行（E6 注册在后面，满足）。

### 3.2 与 B1/B2/B3/B8 的配合

- **B1/B8**：不冲突。建议 C2 早于 B1，这样 C2 只看原始 assets/lib，
  不会把 B1/B8 的加密载荷当成待加密对象。
- **B2**：若 C2 需要在壳 `attachBaseContext` 里增加「解密 SO」的调用，
  B2 需要知道这个入口。两条路线：
  - 路线 1（推荐）：把「解密 SO」并入 **B3 的 Loader**（`Loader.a`），
    B2 无需改动——因为 Loader 本来就在 `attachBaseContext` 里被调用，
    且库搜索路径也是在 Loader 里构造的。这样 C2 只需要 B3 扩展。
  - 路线 2：像 C4/C5/C6 那样，由 B2 在 `checks` 里登记一个 C2 检测/初始化类，
    由 C2 后续 `injectShellClass` 注入类体。这条路要改 B2 的 `checks` 组装
    逻辑（新增 C2 分支）。**不推荐**，因为多一个类、且与 Loader 的
    时序（必须先解密库再构造 ClassLoader）耦合更复杂。
- **B3**：必须扩展（见 §2.3 的代码改动点）。这是 C2 的主要集成面。

### 3.3 与 C1 / E6 的 ABI 冲突（重要，必须处理）

**冲突**：C1 的 ABI 选择逻辑是：

```go
// passes/shell.go
if own := abisOf(art); len(own) > 0 {
    // 只给 APK 已支持的 ABI 注入 libapkguard.so
}
```

`abisOf` 只扫描 `lib/<abi>/*.so`。C2 把业务 .so 移走后，C1 再调用
`abisOf` 会得到**空集合**，于是走「APK 完全没有原生库」分支，给
**全部 3 个 ABI**（arm64-v8a / armeabi-v7a / x86_64）都注入
`libapkguard.so`。后果：一个只支持 arm64 的应用被系统判定为也支持
armeabi-v7a，可能被装到 32 位设备上，而应用的业务 .so 只有 arm64 →
一装就崩。这正是 `shell.go` 注释里警告过的场景。

**解决方案（二选一）**：

1. **C2 记录原 ABI 集合**：C2 在移除前把 `abisOf` 结果存入
   `Artifact.Shared`（键如 `"C2.abis"`）；C1 的 ABI 选择改为
   「优先读 `C2.abis`，否则回退 `abisOf`」。需要改 C1 一处。
2. **C2 在 `lib/` 留下标记**：不可行——任何留在 `lib/` 的东西都会被
   安装器/链接器当原生库处理，且会破坏「无明文 .so」的判据。

推荐方案 1。**若不做这一步，C2+C1 组合必然在 32 位设备上出事故**。

**E6 交互**：

- C2 移除全部业务 .so、C1 注入 `libapkguard.so` 后，每个原 ABI 下都恰好
  有且只有 `libapkguard.so`，E6 的「ABI 覆盖一致」检查通过。
- 若 C1 未启用，`lib/` 为空，E6 的 `libsByAbi` 为空，检查自然通过
  （不报错）——但要注意：此时**没有任何原生库**，E6 无法发现「应用
  本来有 .so 却被 C2 移走」这类问题。所以 C2 自己必须提供审计报告，
  不能依赖 E6 兜底。
- 若 C2 只做了**部分**加密（如按审计跳过某些库），必须保证**每个 ABI 的
  加密/保留决策一致**，否则 E6 会报「ABI A 缺少 libfoo.so（ABI B 有）」——
  这其实是正确的告警，C2 应在 Pass 内就保证对称性。
- **16KB 对齐**：E6 目前不检查 `p_align`。C2 落地时应新增一条审计
  （或扩展 E6）：对每个业务 .so 的原始 `PT_LOAD` 读 `p_align`，< 0x4000
  时报告「16KB 页设备风险」。

### 3.4 与 E2/E1 的顺序

E2/E1 在 Sink 中执行，晚于所有 Pass，顺序天然正确。唯一要改的是
**E2 的 `SoAlign`**（见 §2.2.5）：当存在 `extractNativeLibs=false` 或
targetSdk ≥ 35 时，`.so` 的 ZIP 对齐应为 16384。`zipx.DefaultAlign()` 是
`{Align:4, SoAlign:4096}`，需要参数化。

### 3.5 与 A5/A11 的顺序

A5/A11 只改 `res/` 与 `resources.arsc`；C2 只改 `lib/` 与 `assets/`，
互不重叠。C2 注册在 A5/A11 之后即可（避免 A5/A11 的 `used` 集合与 C2
新增 assets 名互相干扰；实际上 A5/A11 生成的是 `res/...` 名，不会撞
`assets/...`，但保持「资源类 Pass 先跑」更清晰）。

---

## 4. 验收标准（可自动化断言）

| # | 判据 | 断言方式 | 防住的回归 |
|---|---|---|---|
| 1 | 产物 `lib/` 下**不再有明文业务 .so** | 遍历条目：凡以 `lib/` 开头且 `Content[0:4]=="\x7fELF"` 且文件名 != `libapkguard.so`，一律失败 | 「只改内容不移除」的错误实现；C2 静默没生效 |
| 2 | assets 下出现**加密的 .so 载荷**，数量 == 原业务 .so 数 | 对比加固前后 `lib/` 条目集合与 C2 载荷清单；每个载荷不以 ELF magic 开头 | 「移除了但没加密」；载荷丢失 |
| 3 | 载荷可被 `pack.Decrypt` 还原为原 .so（逐字节相等） | 单测：对每个载荷解密后 `bytes.Equal(orig, dec)` | 加密/命名/IV 派生错误 |
| 4 | 16KB 对齐检查通过 | 对 `lib/` 下剩余 .so（`libapkguard.so`）解析 ELF，断言所有 `PT_LOAD.p_align ≥ 0x4000`；对 `extractNativeLibs=false` 产物断言 ZIP 中 .so 的数据偏移 % 16384 == 0 | 破坏 16KB 页设备；E2 对齐不足 |
| 5 | 设备上应用能正常 `loadLibrary` | 装机实测：Termux/RustDesk 启动无 `UnsatisfiedLinkError`；`-debug-shell` 的 Toast/logcat 序列完整（AG1→AG4） | 库搜索路径错、只读未设置、解密落地失败 |
| 6 | 资源 ID 逐条不变 | 沿用 A5/A11 的 `aapt2` 复核（C2 不动 arsc，应天然不变） | C2 误改资源表 |
| 7 | ABI 对称性 | 每个 ABI 的「加密/保留」决策一致；E6 通过 | 混放导致依赖链断裂、E6 报缺库 |
| 8 | C1 组合下 `libapkguard.so` 未被加密 | 产物 `lib/<abi>/libapkguard.so` 存在且是合法 ELF；C1 注入的 ABI 集合 == 原 ABI 集合 | C2 误加密桥接库；ABI 选择错 |
| 9 | 审计报告存在且被 E6/报告输出 | 产物报告含每个库的加载来源判定与风险等级 | 「声明实现了却对高危应用盲目加密」 |
| 10 | `-so-encrypt` 与 `-enable C2` 行为一致 | CLI 冒烟：单独 `-so-encrypt` 必须真的产出加密载荷（当前是 no-op，属已知缺口） | 开关声明与实际行为不符 |

---

## 5. 风险与取舍

### 5.1 会破坏产物的做法（明确禁止）

1. **原地加密 `lib/` 条目**：安装器/链接器会拿到密文（§2.2.2）。
2. **把解密后的 .so 写到外部存储**：`noexec` / 命名空间不接受，`dlopen` 失败。
3. **解密后不置只读**：targetSdk ≥ 29 时 W^X 拒绝 `dlopen`（§2.2.1）。
4. **同 ABI 混放（部分加密、部分留在 lib/）**：`DT_NEEDED` 依赖解析不可控。
5. **用会改变长度的算法做「原地」段加密**：(b) 若实施，必须等长变换，
   否则段偏移与 `p_align` 全废。
6. **加密 `libapkguard.so`**：壳自己的 native 库，加密后 C1/C4/C5/C6/D4 全崩。
7. **C2 之后仍让 C1 用 `abisOf` 选 ABI**：会多加 32 位 ABI（§3.3）。
8. **对 Flutter/RN/Unity 等 native 自加载应用无条件加密**：大概率启动即崩，
   且难以定位（§2.2.4）。

### 5.2 取舍说明

- **为什么整文件而不是段加密**：整文件不碰 ELF 结构，风险从「需自建加载器」
  降到「文件搬运 + AES + 只读」，且能复用 B1 已充分验证的 `pack` 与 Loader
  解密机制。防护上，「整个库是密文」比「只有数据段是密文」也更强。
- **为什么 `.text` 段加密不做**：见 §2.1(b)，与 `JNI_OnLoad` 的执行时序矛盾，
  必须自建加载器；投入产出比极差。
- **为什么保留 `nativeLibraryDir` 兜底**：部分库可能因审计判定而跳过加密，
  原目录仍需可用；且 C1 的 `libapkguard.so` 始终在 `lib/`。
- **为什么必须做加载来源审计**：C2 的兼容性上限由「应用怎么加载 .so」决定，
  无法穷举，只能审计 + 逐个验证。不做审计就是盲目交付。
- **合规取舍**：C2 属于动态代码加载，Google Play 明确禁止；仅适用于
  国内商店、企业内部分发、SDK 保护（与设计文档 §9 的合规提示一致）。

---

## 6. 最小可落地子集

**目标**：第一个能独立验证、且不破坏 Termux / Dhizuku / RustDesk 的切片。

> 修正一个事实：三个验证目标里，**Dhizuku 2.12.0 没有任何原生库**
> （见 `realworld/实测记录-三应用全选项.md`），它是天然的「无 .so」对照组；
> 真正带原生库的是 **Termux（x86_64）** 与 **RustDesk（Flutter，x86_64）**。
> 因此 C2 的正向验证落在 Termux，RustDesk 是高风险对照，Dhizuku 验证 no-op 路径。

**切片定义**：

1. 只实现粒度 **(a) 整文件加密**，仅做 **x86_64**（与验证设备一致），
   且只处理**审计判定为「Java `loadLibrary` 加载」**的库。
2. 新增 C2 Pass + Loader 扩展 + C1 ABI 修正 + 审计器，先不碰 (b)/(c)。
3. **执行顺序**：注册在 B4/B1 之前、A5/A11 之后；C2 记录原 ABI 集合。
4. **验证步骤**：
   - **Termux**：启用 C2 + B1/B2/B3 + C1，装机跑通 `TermuxActivity`，
     无 `UnsatisfiedLinkError`；断言 `lib/x86_64/` 下无明文业务 .so、
     assets 有密文载荷。这是**正向成功**证据。
   - **Dhizuku**：启用 C2（无 .so），验证 Pass 走空路径、产物不变、
     应用正常启动。这是 **no-op 正确性**证据。
   - **RustDesk**：**先跑审计**。审计命中 Flutter 特征（`libflutter.so`/
     `libapp.so`）→ 预期判定「高危、不加密」，产物不含密文载荷、应用
     正常启动。这是**「不破坏」证据**。随后做一次**独立探针实验**：
     手工把 `libapp.so` 加密进 assets、用 `-debug-shell` 观察
     `libflutter.so` 是否能从私有目录加载它，以**证实或证伪**
     §2.2.4 的 Flutter 限制。无论结果如何，都要写进实测记录。
5. **独立可验证性**：单测覆盖「加密→解密逐字节相等」「lib/ 无明文 ELF」
   「载荷非 ELF」「ABI 对称」「C1 不加密 libapkguard.so」；端到端用
   `scripts/e2e.sh` 加一组 `B1,B2,B3,C2,C1,E1,E2,E6` 功能集 + 产物断言。
6. **不包含**：段加密、多 ABI、Flutter 的 native 自加载适配、
   `android_dlopen_ext` 拦截、16KB 页设备实测（只做静态对齐断言）。

这个切片能在**不触碰 RustDesk 高风险路径**的前提下，于 Termux 上给出
C2 生效的完整证据，同时用 Dhizuku 证明空路径安全、用 RustDesk 证明审计
与降级策略有效。

---

## 7. 工作量估计

| 工作项 | 内容 | 人日 |
|---|---|---|
| C2 Pass（扫描 lib/、加密、命名、移除、共享清单） | Go 约 250 行 + 单测 | 1.5 |
| Loader 扩展（`LoaderSpec` 新字段 + 字节码：mkdirs、解密落地、置只读、librarySearchPath 拼接） | Go 约 200 行 + 字节码测试 | 2.5 |
| `ApplicationInfo.nativeLibraryDir` 反射改写 | 字节码生成 + 测试 | 1.0 |
| C1 ABI 修正 + C2/C1 共享 ABI 集合 | 小改 + 回归 | 0.5 |
| 加载来源审计器（DEX 调用点扫描 + ELF DT_NEEDED + 框架特征） | Go 约 250 行 + 单测 | 2.0 |
| E6/16KB 审计扩展 + E2 SoAlign 参数化 | 小改 + 测试 | 1.0 |
| 端到端产物断言 + CLI 冒烟 + `-so-encrypt` 语义统一 | 脚本 + 测试 | 1.0 |
| 三个真实应用装机实测与排障（Termux 正向、Dhizuku no-op、RustDesk 探针） | 设备/模拟器时间 | 2.0~3.0 |
| **小计（粒度 a，x86_64，不含 Flutter 适配）** | | **11.5~13.5** |

**后续增量**：

| 工作项 | 人日 | 备注 |
|---|---|---|
| 多 ABI 覆盖 + 16KB 页设备实测 | 1~2 | 依赖设备矩阵 |
| Flutter / native 自加载适配（若探针证明有解） | 5~10 | 可能无解 |
| 粒度 (b) 数据段加密（ELF 解析 + 等长变换 + 复用/注入 `JNI_OnLoad`） | 12~20 | 需新建 ELF 基建；只覆盖部分库 |
| 粒度 (b) `.text` 加密（自建 ELF 加载器 + 重定位 + 符号解析） | 30+ | **不建议排期** |
| 粒度 (c) 组合 | (a)+(b) 之和 + 2 | 排障成本叠加 |

**估计依据**：整文件方案几乎全部复用既有 `pack`/`zipx`/Loader 基建，
新增量集中在「Loader 字节码扩展」（这是项目里最容易出错、测试最重的部分，
参照 B3 Loader 的历史工作量）与「审计器」（全新逻辑）。风险最大的是
设备实测与 Flutter 探针——历史记录（`realworld/实测记录-RustDesk.md`）
表明，带原生库的 Flutter 应用在 ClassLoader/库路径上曾连续踩坑，
C2 只会更多，因此设备时间按上限估。
