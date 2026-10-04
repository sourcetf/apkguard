# 方案：双 APK 架构（外层壳 + 内层完整 APK）

> 状态：**路线 A（PackageInstaller 二次安装）已实现（可选，默认关闭：`-dual-apk` / `-enable B9`）**，
> 与默认架构的取舍见下；路线 B/C 的结论保持不变。实现位于
> `apkguard/internal/pipeline/dualapk.go`（Sink 收尾阶段，在 E1 签名之后执行）。
> 相关代码/文档：`APK加固功能设计文档.md` §1（参考样本解构）、§3 B1/B3/B8；
> `realworld/实测记录-三应用全选项.md`（B3 内存加载不可行的实测证据）；
> `apkguard/internal/passes/pack.go`（B1）、`container.go`（B8）、`shell.go`（B2/B3）、
> `apkguard/internal/dex/loader.go`（Loader）、`apkguard/internal/pipeline/pipeline.go`。

---

## 1. 目标与预期效果

### 1.1 参考样本的双层结构（实测事实）

`APK加固功能设计文档.md` §1 与 `realworld/实测记录-三应用全选项.md` 记录了参考样本：

- **外层薄壳**（LOADER，14.40 MB，3029 条目中 2418 条为垃圾）只负责启动；
- 内层是**一份完整 APK**（PAYLOAD，13.73 MB，8 个真 DEX、22366 个类、自己的
  Manifest 与 `resources.arsc`），被**单字节 XOR 0x5A**（密钥通篇固定）后塞进
  `assets/*.zip`；
- 运行时把内层 APK 解密、用 `PackageInstaller` **二次安装**，再切入其组件。

也就是说，样本把「加壳」实现成了「**投放器（dropper）**」：用户装的是外层的壳，
真正的应用是壳在运行时替你装上的第二个 APK。

### 1.2 本方案要回答的问题

1. 外层壳 + 内层完整 APK 的打包/加载流程要怎么设计；
2. 内层 APK 的加载路线三选一（`PackageInstaller` / `AssetManager.addAssetPath` +
   自定义 ClassLoader / 直接反射加载内层 DEX）各自的版本限制与用户可见性代价；
3. 与**本项目现有架构**（逐 DEX 加密 + 进程内 ClassLoader 接管）对比：内层 APK
   能保留自己的 Manifest 与资源命名空间，是否真能省掉 A5/A11 的就地资源改写，
   代价是什么；
4. 给出明确的**做 / 不做 / 只做哪一部分**结论。

### 1.3 要防住什么（能力目标）

| 目标 | 双 APK 是否有效 | 现有架构是否有效 |
|---|---|---|
| 静态反编译看不到业务 Manifest/资源 | ✅（整体加密） | ⚠️ 资源仍是明文（A5/A11 只是改名，命名空间仍在） |
| 静态反编译看不到业务 DEX | ✅ | ✅（B1） |
| 防二次打包/植入 | ✅（若内层也校验签名） | ✅（D1+C1） |
| 不引入额外安装/权限/用户交互 | ❌ 与 PackageInstaller 路线冲突 | ✅ |
| 与 A5/A11 就地资源改写解耦 | ✅（前提：能正确加载内层资源） | ❌ 必须就地改写 |

**注意**：1.3 的核心矛盾是——双 APK 唯一的实质收益是「**业务资源/Manifest 整体进密文**」，
而这个收益恰好由**加载内层资源**的技术难点（addAssetPath 隐藏 API、组件无法注册）决定
能否兑现。因此 2.2 的三条路线比较是本文档的关键。

---

## 2. 技术方案

### 2.1 打包与加载总流程

打包（设计）：

```
输入业务 APK  ──(A) 可选：保留其原始签名/用用户密钥库重签
              ──(B) 整体（或分块）加密成容器，放入外层 assets/
外层壳 APK    ── 极简 Manifest：只有壳 Application（+ 需要的代理组件）
              ── 壳 attachBaseContext: 解密容器 → 私有目录（或直接反射加载）
运行          ── 按路线 A/B/C 之一加载内层
```

与本项目现有 B1 的区别：B1 是「**逐 DEX** 加密成多个载荷，业务 Manifest/资源原样留在
外层」；双 APK 是「**整份 APK** 加密成一个（或按块几个）容器」。

### 2.2 内层 APK 的加载路线三选

#### 路线 A：`PackageInstaller` 二次安装（样本做法）

- **机制**：解密出内层 APK 落到应用私有目录 → 创建 `PackageInstaller.Session` →
  写入 → `commit()` → 系统安装第二个包 → 外层通过组件/intent 拉起内层。
- **Android 版本限制 / 用户可见性代价**：
  - 需要 `REQUEST_INSTALL_PACKAGES` 权限（API 26+），Android 8+ 还要用户为该应用开启
    「安装未知应用」；
  - 安装过程**会弹系统安装界面**（除非设备所有者/系统应用，普通应用无法静默安装），
    用户可见、需点击确认；
  - Android 10+ 限制后台启动 Activity，`SESSION` 提交流程对后台应用更严；
  - Android 14 起对 `targetSdk` 过低的内层 APK 直接拒装，且对 session 安装的调用方
    有更严的约束；
  - 内层 APK 必须有**有效签名**才能安装。对「上架包」而言，加固方通常**没有原始签名私钥**，
    只能用自己的密钥库重签内层（E1 场景下用户本来就提供私钥，勉强可行）；这会让内层证书
    与外层证书关系复杂化；
  - **双应用图标、双份卸载、更新耦合**；应用商店政策上这是**投放器行为**，几乎必然被拒。
- **结论**：对「保护自有应用」的定位完全不可接受。**不采用。**

#### 路线 B：`AssetManager.addAssetPath` + 自定义 ClassLoader（进程内）

- **机制**：把内层 APK 解密到私有目录 → 反射拿到 `AssetManager` 并
  `addAssetPath(innerApkPath)` → 用该 `AssetManager` 构造 `Resources` →
  用 `DexClassLoader(innerApkPath, ...)` 加载内层 DEX → 替换 `mClassLoader`，
  并通过包装 `Context`/`Resources` 让应用看到内层资源。
- **Android 版本限制**：
  - `AssetManager.addAssetPath(String)` / `createAssetManager` 属**非 SDK（hidden）接口**，
    Android 9+ 的隐藏 API 限制会拦截反射调用（与 B3 已实测的 `mClassLoader` 被过滤同类问题）；
    不同版本可用性不一致，需逐版本适配；
  - 内层 APK 的**组件（Activity/Service/Provider/Receiver）无法注册到系统**——系统只认
    安装时外层 Manifest 声明的组件。要运行内层界面，必须在外层 Manifest 里**为每个内层
    组件建代理声明**（`activity-alias` 或转发 Activity），等于把「组件清单」工作从 A5/A11
    那侧搬到了另一侧，而且更脆；
  - 内层 `.so` 不会自动进 `DexPathList.nativeLibraryDirectories`（B3 已踩过：缺库搜索路径
    会让 `System.loadLibrary` 报 `UnsatisfiedLinkError`），仍需把库解密落地并把目录传给
    `DexClassLoader`（`loader.go` 现有做法）。
- **用户可见性代价**：无安装界面、无额外权限（这点优于路线 A）。
- **结论**：唯一可能「保留内层资源命名空间」的进程内路线，但**hidden API + 组件注册无解**
  两个硬伤，且与现有 B3 的落盘 `DexClassLoader` 方案高度重叠。**仅作为 spike 评估，不作为
  默认。**

#### 路线 C：直接反射加载内层 DEX（本项目现状的变体）

- **机制**：从内层 APK 中取出 `classes*.dex`，走现有 B1/B3（逐 DEX 加密 + 落盘
  `DexClassLoader` + 替换 `mClassLoader`）；**资源仍用外层 APK 的**。
- 这实际上**退化为现有架构**，只是「内层 APK」变成了一个中间产物：如果资源还是外层的，
  那内层 APK 的 Manifest/资源命名空间并没有被利用，双 APK 的收益（1.3）没兑现。
- **结论**：与现有 B3 无本质区别，不构成独立方案。

### 2.3 与现有架构（逐 DEX 加密 + 进程内 ClassLoader 接管）的对比

| 维度 | 现有架构 B1/B2/B3（+A5/A11） | 双 APK（路线 B，唯一可行候选） |
|---|---|---|
| 业务 DEX | 逐 DEX 加密成多个 assets 载荷 | 内层整包加密，运行时解出 |
| 业务 Manifest | 外层仍是最初的（B2 改 `android:name`、`appComponentFactory`） | 内层 Manifest 无法注册，仍需外层声明全部组件/代理 |
| 业务资源命名空间 | 明文（A5/A11 只改名，`resources.arsc` 仍在） | 内层资源在密文里，**理论上可省 A5/A11** |
| 资源运行时解析 | 系统原生，无额外代码 | 需 `addAssetPath` + 自定义 `Resources`，hidden API |
| 进程内 ClassLoader 接管 | 已有、三应用验证过 | 仍需，且要与资源包装叠加 |
| `.so` 加载 | 已有方案（`nativeLibraryDir`） | 仍需，另需处理内层库 |
| 签名校验（D1） | 校验外层（唯一安装的包） | 内层未安装时 `PackageManager` 查不到其签名，D1 只能覆盖外层 |
| 体积 | 载荷 ≈ 明文 DEX 总量 + IV/padding | 内层整包（含资源）再加密，**明显更大**（资源通常是大头） |
| 首启耗时 | 解密 + 落盘各 DEX | 解密 + 落盘**整份 APK**，更慢 |
| 用户可见性 | 单应用，无变化 | 路线 B 无安装 UI；路线 A 有 |

**「省掉 A5/A11」到底省了什么？**

- A5/A11 的代价是**就地改写资源路径**（`resources.arsc` 全局字符串池 + `res/` 条目名 +
  DEX 里对资源路径的引用），历史上出过「Android 11+ 装不上」的真缺陷（README「已知局限」）。
  双 APK 若能让业务资源整体进密文，确实可以不做这类改写。
- 但代价是：① 运行时必须把资源**解密并加载**（hidden API）；② 组件注册问题没省，反而因为
  「内层清单不可见」而需要在**外层**补齐所有组件声明；③ 体积/首启开销显著上升；
  ④ A5/A11 本来还有「减小体积 5~10%」的收益（资源改名压缩），双 APK 反而丢掉。
- 因此「省掉 A5/A11」是**用隐藏 API 风险 + 组件代理工作 + 体积，换掉一项已有的、已验证的
  就地改写**。**性价比为负。**

### 2.4 与 D1、C1、E1 的交互

- **D1**：只能校验**已安装的那个包**（外层）。若走路线 A，内层是另一个包，需要在内层里
  再注入一套（而内层是用户业务 APK，加固方未必有控制权）；若走路线 B/C，内层未安装，
  `PackageManager.getPackageInfo(innerPkg)` 拿不到内层签名，D1 对业务代码无约束。
- **C1**：密钥绑定外层签名，容器用同一 key 加密即可，机制不变。
- **E1**：外层必须签名；路线 A 还要求内层签名（且内层签名会出现在最终安装的两个包上）。
- **B8**：现有 B8 的诱饵容器与「内层 APK 容器」形态天然接近，可复用其容器/诱饵思路
  （见 2.5）。

### 2.5 结论（明确推荐）

1. **完整双 APK（路线 A，PackageInstaller 二次安装）：已实现（可选，默认关闭），不作为
   默认架构。** 实现与样本同一模型但不依赖任何 Android 构建链：宿主 Manifest/宿主 DEX 全部
   手工合成，原应用在**签名之后**整体以 AES-SIV（RFC 5297，密钥以字节数组内联在
   宿主 DEX）加密进 `assets/<随机名>.zip`，宿主启动后解密落地到
   `getExternalFilesDir()/plugins/`，再用 `PackageInstaller` 会话调起系统安装器；宿主 DEX
   不引用任何 `dalvik/system/*`。代价依旧存在且必须由使用者显式承担：需要
   `REQUEST_INSTALL_PACKAGES`、系统安装界面、双应用图标、内层重签，Android 10+ 的后台安装
   限制与 Android 14 的 targetSdk 限制进一步收紧，商店政策也把这类形态视为投放器。样本这么做
   是因为它是恶意投放器；本工具把它作为**显式的可选产物形态**提供，默认关闭，与「加固自有
   应用」的定位冲突由启用者自行权衡。
2. **路线 B（addAssetPath + 自定义 ClassLoader）：不作为默认，只做可行性 spike。**
   唯一能兑现「业务资源整体进密文」的路线，但受 hidden API 与「内层组件无法注册」两个硬伤
   制约；即便 spike 通过，也要在外层补齐全部组件代理，收益被工作量抵消。
3. **路线 C（直接反射加载内层 DEX）：等价于现状，无需单独实现。**
4. **推荐只做 B8 的增强形态（可选）：把现有「逐 DEX 载荷容器化」保留为默认，另评估
   「把资源也纳入加密容器」的可行性；若 addAssetPath 在目标 API 区间不可用，则结论就是
   连这一子集也不做，维持现状。**
5. **必须同时做的一件事（低风险、高价值）**：`config.Options.SOEncrypt` 与
   `cmd/apkguard/main.go` 的 `-so-encrypt` 已存在但**没有任何 Pass 消费**，当前是静默空操作；
   同样 `-payload-mac` 也是空操作。这些「启用却无效果」的开关应补齐实现或明确报错，
   与项目一贯原则一致（与 `剩余功能落地设计.md` 的收尾要求同源）。

---

## 3. 与现有 Pass 的交互与执行顺序

### 3.1 若只做「B8 增强型内层容器」（路线 B 的受限形态）

- **注册位置**：作为 B8（`payloadContainer`）的一个可选子模式，**不新增顶层 Pass**。
  B8 现注册在 `Registry()` 中 `encryptDex`(B1) 之后、`appReplace`(B2) 之前，顺序正确：
  此时载荷清单已就绪、Loader 尚未生成，条目名可自由改。
- **依赖**：必须 B1 已启用（同现有 B8）。
- **与 B3**：若容器内包含资源，B3 生成 Loader 时不仅要解密 DEX，还要解密资源并调用
  `addAssetPath`——这会**显著扩展 Loader 的职责**，是风险集中点。更稳妥的做法是不在 Loader
  里做资源加载（避免把 hidden API 引入已高度敏感的 Loader），而是把资源加载放到壳 Application
  的另一处、并用 `-debug-shell`/真机 spike 单独验证。
- **与 A5/A11**：若资源进了容器，A5/A11 就**不能**再对同一批资源做就地改名（否则内外两份
  资源命名不一致）。二者**互斥**：启用容器资源模式时，应对 A5/A11 给出明确告警或强制关闭。
- **与 E1/D1**：不改变签名与指纹校验；容器整体被 E1 覆盖。
- **顺序小结**：`B4 → B1 → B8(容器, 可选纳入资源) → B2 → B3 → C1/D* → E1`。
  资源加载逻辑若落地，必须在 B2 壳内、Loader 之后、原 Application 委托之前完成（否则原
  Application 的 `onCreate` 会用到尚未就绪的资源）。

### 3.2 若做完整双层（路线 A）

它不是「现有流水线上的一个普通 Pass」。外层壳本身是一个独立的最小 APK，内层是另一份产物，
需要**新的打包模式**（类似 E5 批量之外的第二种顶层产物形态），与现有 `pipeline.Artifact`
单产物模型不匹配。

**2026-10 更新（已落地）**：B9 按「轻量 Pass（只做启用与前置校验，不参与分层变换）+
`pipeline.DefaultSink` 收尾阶段封装」实现——真正的宿主生成/双次签名发生在 E1 之后的 Sink
里，因此没有把两层生命期塞进 Pass 体系；`opts.DualAPK` 关闭时该路径完全不执行，产物与
改动前逐字节一致。

---

## 4. 验收标准（可自动化断言）

按推荐结论分两类。

### 4.1 推荐路径（不做完整双 APK）的验收

| # | 判据 | 防住的回归 |
|---|---|---|
| 1 | 现有三应用（Termux/Dhizuku/RustDesk 全选项）与 `testapp` 11 产物回归 **100% 通过**，进程存活、无结构性错误 | 误把双 APK 代码路径接进默认流程 |
| 2 | 产出的壳 DEX 中**不出现** `PackageInstaller`、`Session`、`addAssetPath`、`createAssetManager` 等符号（除非显式启用实验开关） | 有人悄悄把投放器/隐藏 API 逻辑接进默认产物 |
| 3 | 产物条目中不出现第二个 `AndroidManifest.xml` / `resources.arsc`（外层只能有一份） | 打包时把内层 APK 原样混入 |
| 4 | 实验开关默认关闭；启用未实现的实验路径必须**报错**而非静默 | 回归到「静默空操作」 |
| 5 | 现有 D1/C1 行为不变：重签名产物仍被 D1 终止、C1 密钥仍绑定外层签名 | 双 APK 改造污染签名/密钥链路 |

### 4.2 若做 addAssetPath 可行性 spike 的验收

| # | 判据 | 防住的回归 |
|---|---|---|
| 6 | 在目标 API 区间（至少 API 21 与 API 36 各一台/模拟器）上，`addAssetPath` 反射调用成功，能按资源 ID 解析出内层资源（返回非 null、字符串/尺寸正确） | hidden API 拦截导致资源丢失（应用启动即 `Resources$NotFoundException`） |
| 7 | 内层 DEX 经现有 `DexClassLoader` 加载后，`mClassLoader` 替换回读校验为「已生效」（复用 B3 的 `i()` 返回码 2） | 自定义 ClassLoader 叠加资源包装后接管失效 |
| 8 | 内层 `.so` 能被 `System.loadLibrary` 找到（复用 B3 的 `nativeLibraryDir` 方案） | 重复踩 `UnsatisfiedLinkError` |
| 9 | 组件代理：外层 Manifest 声明的代理 Activity 能拉起内层真实 Activity；未声明的内层组件不参与 | 内层组件无法启动（路线 B 的已知硬伤） |
| 10 | 首启耗时与私有目录占用有量化报告（解密整包 + 落盘的成本） | 体积/性能回归无感知 |

> 4.2 的判据 9 是**否决性**的：若无法在不重写全部组件清单的前提下拉起内层组件，路线 B
> 即判定不可行，回到 4.1 的「不做」结论。

---

## 5. 风险与取舍

**明确不能做 / 会破坏产物的做法：**

1. **不能把内层 APK 原样（或其 Manifest/`resources.arsc`）直接放进外层**：会出现两份
   `AndroidManifest.xml`/`resources.arsc`，`ZipFile` 取值歧义，安装/运行行为不确定；
   内层必须整体加密成不透明容器（现有 B8 思路）。
2. **不能用 `PackageInstaller` 静默安装内层**：普通应用在多数版本上做不到静默，会弹安装
   界面；`REQUEST_INSTALL_PACKAGES` + Android 10+ 后台限制 + Android 14 targetSdk 限制叠加，
   且商店政策视之为投放器。**产物会变成恶意软件形态。**
3. **不能依赖 `AssetManager.addAssetPath` 作为唯一资源来源**：它是 hidden API，
   Android 9+ 隐藏 API 限制会拦；一旦在某版本失败，应用启动即资源异常。
4. **不能在启用资源容器时还让 A5/A11 就地对同批资源改名**：内外资源命名不一致，必然崩。
5. **不能不做组件代理就期望内层组件可用**：系统只认安装时声明的组件；内层 Activity 不会
   凭空存在。
6. **不能让 D1 去校验一个未安装的内层包**：`PackageManager` 查不到未安装 APK 的签名；
   这会给出「校验通过」的假象。
7. **不能忽略 `.so` 的库搜索路径**：B3 已实测缺 `nativeLibraryPath` 会让带原生库的应用
   `UnsatisfiedLinkError`；双 APK 若照搬内存加载更糟。
8. **不能为双 APK 牺牲现有产物可复现性**：容器加密仍应沿用确定性 IV/seed，否则回归不可比。

**其他取舍：**

- 双 APK 的**唯一实质收益**是「业务资源/Manifest 整体进密文」，但它被 hidden API 与组件
  注册问题抵扣；而现有 A5/A11 已能提供资源改名（虽非加密，但对静态分析已构成门槛）。
- 若目标是「资源也加密」，更务实的替代是：**把资源条目也纳入 B1 容器加密，但运行时不解密成
  完整 APK，只对必要的资源按需解密 + 通过外层已注册的 Context 提供**——仍受 `addAssetPath`
  限制，收益有限。
- 完整双 APK 的工程与合规成本（15~25 人日 + 商店风险）远高于其防护增量。

---

## 6. 最小可落地子集

> 2026-10 更新：路线 A 后来作为**可选开关 B9** 落地（默认关闭，见 2.5 第 1 条与
> `apkguard/internal/pipeline/dualapk.go`）；本节及以下保留为当时的决策记录，不再代表当前状态。

**推荐的最小切片（不破坏现有三个真实应用）：**

1. **决策落文档 + 负向守卫（1 人日）**：
   - 在 `docs/` 固化「不做完整双 APK」的结论（本文档）；
   - 加一条产物断言（可进 `scripts/verify-products.py` 或 Go 侧自检）：默认产物壳 DEX/
     条目中不得出现 `PackageInstaller`/`addAssetPath` 等符号，且只能有一份
     `AndroidManifest.xml`/`resources.arsc`；
   - 修正 `-so-encrypt`、`-payload-mac` 的「静默空操作」：未实现时启用必须报错。
   - 该切片**完全不动现有加载链路**，风险≈0，且立刻消除两个假开关。
2. **可选的隔离 spike（2~3 人日，独立于主流水线）**：
   - 写一个**独立实验命令/测试**（不接入默认 Pass）：给一份 APK，在设备/模拟器上验证
     路线 B 的 `addAssetPath` + `DexClassLoader` + 代理 Activity 三项判据（4.2 的 6/7/8/9）；
   - spike 失败（尤其判据 9）→ 终止，维持结论「不做」；
   - spike 成功 → 再评估是否值得投入「资源容器化」子集（另立设计，8~12 人日的风险投入）。
3. **绝不在最小切片里**：接入 `PackageInstaller`、改动 B1/B3 的默认行为、触碰 A5/A11 与
   签名链路。

选择「独立 spike」而非直接集成，是因为现有架构已用真机验证过三应用，任何触及 Loader/资源
加载的改动都必须先在 `testapp` 隔离验证，避免重复历史上「装上就崩」的缺陷。

---

## 7. 工作量估计

| 方案 | 人日 | 依据 / 结论 |
|---|---|---|
| 决策文档 + 负向守卫 + 修假开关 | **1** | 纯文案 + 少量断言，零加载链路改动 |
| addAssetPath 可行性 spike（隔离，含代理 Activity） | **2~3** | hidden API 反射 + 资源/ClassLoader/`.so` 三项，需真机/模拟器 |
| 「资源也进容器」子集（spike 通过后，含加密、按需解密、addAssetPath、A5/A11 互斥、回归） | **8~12** | 触及 Loader 与资源加载，风险高；未通过 spike 则不做 |
| 完整双 APK（路线 A，PackageInstaller + 内层签名 + 组件代理 + 双包生命周期 + Android 10/14 适配 + 商店合规） | **15~25** | 工程量大且政策/体验不可接受，**不推荐** |

**推荐总投入**：先做 **1 人日的决策+守卫切片**；是否做 **2~3 人日 spike** 由是否需要
「资源入密文」这一目标决定。完整双 APK 不列入排期。

---

## 附：与「载荷完整性」方案的关系

两份方案互相独立：载荷完整性（HMAC-SHA256, encrypt-then-MAC）作用于 B1 的**逐载荷**密文；
本方案讨论的是**打包形态**。若未来真做内层容器，容器内的 DEX 应继续沿用前者的 MAC 与
B1 的密钥/C1 派生链路，而不是另起一套（样本的「单字节 XOR + 固定密钥」正是要规避的反面教材，
见 `APK加固功能设计文档.md` §1.3）。

**最难 / 最不确定的地方**：路线 B 的 `AssetManager.addAssetPath` 在 Android 9+ 隐藏 API
限制下的可用性，以及「内层组件无法注册」是否有低成本的通用代理方案。这两点决定了双 APK
是否有一丝可行性；在拿到 spike 证据前，结论保持「不做完整双 APK」。