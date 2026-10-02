# apkguard —— 纯 Go 实现的 APK 加固工具

一套**自研的 Android APK 加固引擎**：从 DEX 解析/重建、字符串与常量改写、多 DEX 拆分，
到一代壳（DEX 加密 + Application 替换 + ClassLoader 接管）、native 层防护
（密钥派生、反调试、反注入、完整性自校验）与运行时检测，全部用 Go 实现，
**不依赖 dx/d8 等外部工具链**。

设计依据与功能清单见 [`APK加固功能设计文档.md`](APK加固功能设计文档.md)（40 个功能项，6 个阶段）。

---

## 当前进度

**33 / 40 个功能项已实现**（未实现的 7 项均为最高强度档，落地设计见
[`剩余功能落地设计.md`](剩余功能落地设计.md)）。

| 阶段 | 已实现 |
|---|---|
| **A 混淆** | A1 类名混淆(可选包名压缩) · A2 字符串加密 · A3 常量数组化 · A4 去调试信息 · A5 资源混淆 · A8 诱饵类(含组件声明) · A9 伪 DEX · A10 垃圾条目 · A11 资源扁平化 · A12 ZIP 路径攻击 · A13 类膨胀 · A14 时间戳统一 · A15 巨型 Manifest 填充 |
| **B 加壳** | B1 DEX 加密 · B2 Application 替换 · B3 ClassLoader 接管 · B4 多 DEX 拆分 · B8 载荷容器化 |
| **C 原生保护** | C1 密钥由 native 派生 · C4 反调试 · C5 反注入 · C6 完整性自校验 |
| **D 运行时防护** | D1 签名校验 · D2 Root 检测 · D3 模拟器检测 · D4 运行期周期复检 · D5 设备绑定 |
| **E 打包交付** | E1 签名(v1/v2/v3) · E2 对齐 · E3 签名块 · E4 渠道标记 · E5 批量处理 · E6 兼容性自检 |

未实现：A6 控制流混淆 · A7 反射化调用 · B5 函数抽取 · B6 VMP · B7 Dex2C · C2 SO 加壳 · C3 OLLVM

---

## 架构

```
apkguard/
├── cmd/apkguard/            命令行入口 + 内嵌 Web UI（双击即启动图形界面）
└── internal/
    ├── zipx/                ZIP 读写（扩展字段、对齐、UTF-8 标志）
    ├── axml/                二进制 AndroidManifest.xml 解析与改写
    ├── arsc/                resources.arsc 全局字符串池改写（A5/A11）
    ├── dex/                 ★ 自研 DEX 引擎：解析 / 重建 / 汇编 / 反汇编
    │   ├── file.go          头部、索引表、class_data、code_item
    │   ├── rebuild.go       重建流程（索引重排、去重、注入类）
    │   ├── assemble.go      字节码与数据区布局
    │   ├── insn.go          指令流编辑（分支重定位、payload、异常表）
    │   ├── shell.go         壳 Application（B2）
    │   ├── loader.go        Loader：解密 + ClassLoader 接管（B1/B3）
    │   ├── nativebridge.go  JNI 桥接类（C1/C4/C5/C6/D4）
    │   ├── strenc.go        A2 字符串加密
    │   ├── constarr.go      A3 常量数组化
    │   └── envcheck.go      运行时检测类的字节码生成
    ├── native/              C 实现的 native 守卫（SHA-256、反调试、反注入、完整性）
    ├── passes/              各功能项的 Pass 实现与注册
    ├── pipeline/            阶段编排与产物传递
    ├── keystore/            JKS / PKCS12 解析
    ├── sign/                JAR 签名 + APK Signature Scheme v2/v3
    └── config/              功能项注册表、依赖校验
```

**核心设计**：所有改写都走「解析 → 计划 → 重建」而非就地打补丁，
这样索引重排、去重、注入都能在一个统一的布局器里完成，
避免出现「A 改了名而 B 仍引用旧名」的断链。

---

## 用法

```bash
# 加固并签名
apkguard -in app.apk -out app-protected.apk \
         -ks release.jks -ks-pass <口令> \
         -enable A1,A2,A3,A4,B1,B2,B3,B4,E1,E2,E3

# 列表 / 图形界面
apkguard -list
apkguard                     # 双击或直接运行 = 启动图形界面并自动打开浏览器

# 常用选项
-enable / -disable           按功能项 ID 增删
-debug-shell                 排障版：壳每步弹 Toast 并写 logcat（标签 APKGUARD）
-bind-device <android_id>    D5 设备绑定
-channels a,b,c              E4 多渠道批量产出
-seed <值>                   固定随机种子（可复现）
```

`-enable` 只增不减：默认启用的项不会被关掉，要关请用 `-disable`。

---

## 验证情况（重要）

### 已验证可用

**真实应用：RustDesk 1.4.9（x86_64）**
25 MB、5331 个类、4 个原生库、targetSdk 33。加固后（A1~A4+A14 + B1~B4 + E1/E2/E3/E6）：

- 拆成 16 个加密载荷分片，产物 53.4 MB
- 安卓 11 x86_64 模拟器：**一次启动即成功**，`MainActivity` 正常 resume，进程持续存活
- `VerifyError` / `UnsatisfiedLinkError` / `invalid branch target` / `FATAL EXCEPTION` 全部为 0

完整排查过程、9 个缺陷的根因与复现方式见
[`realworld/实测记录-RustDesk.md`](realworld/实测记录-RustDesk.md)。

**三个真实应用 × 全选项 × Android 16（API 36）**：Termux（30 DEX / 8576 类）、
Dhizuku（3292 类）、RustDesk 1.5.0（Flutter / 5449 类）在启用全部 33 个可用功能项
（D2/D3 因设备是已 root 的模拟器而按设计排除）后**全部正常运行**。
本轮据此修掉 11 个缺陷（其中 4 个是「一装上就崩」级别），详见
[`realworld/实测记录-三应用全选项.md`](realworld/实测记录-三应用全选项.md)。

本轮还收口了两项此前挂账的工作：**A8 的诱饵类现在会真的声明成 Manifest
组件**（为此给 `axml` 加了元素插入能力；只声明 receiver/service 且不加
intent-filter，系统永不实例化它们），**B3 的内存加载经实测判定在公开 API 下
不可行**（`InMemoryDexClassLoader` 的库路径构造器是 private、类本身是 final，
缺库路径会让带原生库的应用加载 `.so` 失败），因此保持落盘的 `DexClassLoader`，
证据见设计文档 §B3 与实测记录。

其中 3 个只有「全选项 + 真实 Flutter 应用」才会同时触发、且在单元测试里完全
看不见的缺陷：

- **A1 压包破坏 package-private**：`-package-shrink` 曾把所有类压进默认包，
  而 `$` 内部类被保留在原包，跨包访问导致 `IllegalAccessError`
  （Termux）。改为「每个原包整体映射为一个短包名」，保住包内同包语义。
- **ServiceLoader 两半都引用类名**：`META-INF/services/<接口>` 的**文件名**是
  服务接口类名、**内容**是提供者类名，二者都只存在于资源里。改名后
  `ServiceLoader.load` 找不到实现，报 `Module with the Main dispatcher is
  missing`（RustDesk 1.5.0 的 kotlinx 主调度器）。
- **A10 注入假 MANIFEST.MF 破坏 v1 签名校验**：注入的
  `META-INF//MANIFEST.MF` / `meta-inf/MANIFEST.MF` 会被 `JarVerifier`（大小写
  不敏感）当成真正的主清单，ServiceLoader 经 `JarFile` 读 `META-INF/services`
  时触发 v1 校验，抛 `SecurityException: Invalid signature file digest for
  Manifest main attributes`。现在所有注入条目都经 `manifestCollision` 守卫。

**受控测试应用 × Android 16（API 36）**：`testapp` 的 11 个产物在 x86_64 模拟器上
逐个装机实测，**11/11 通过**（安装成功、运行正常或被按设计拦停、运行时零结构性错误）。
覆盖了此前从未进入端到端链路的 A5/A8/A9/A10/A11/A12/A13 与 E4 多渠道，
并因此查出一个「启用 A5/A11 的包在 Android 11+ 上装不上」的真缺陷（已修）。

**受控测试应用**：`testapp/`（一个 Activity + 一个 ContentProvider + 辅助类 + 一个
代表性业务类 `Features`），用于逐功能隔离验证。

测试固件放在 [`testdata/`](testdata/README.md)（由 `testapp` 构建产物导出，共约 16 KB，
**必须入库**）：此前 `dex`/`axml`/`passes`/`pipeline` 等包的样本加载器只认工作区里的
临时路径，而那些路径都不在仓库里，于是干净检出下 **94 条测试被静默跳过**，
`go test ./...` 却仍然显示 ok——README 里主打的「产物级守卫」在 CI 上一条都没跑。
固件入库后这些测试在干净检出下也会真正执行。

### 端到端矩阵

`scripts/e2e.sh` 用 **9 组功能集**覆盖全部 33 个已实现项（早先只覆盖 22 项，
A5/A8/A9/A10/A11/A12/A13/E4 从未进过端到端链路），并对产物做两类校验：

1. **签名/对齐**：apksigner 校验 + `zipalign -c -p 4`；
2. **产物断言**（`scripts/verify-products.py`）：逐功能项检查产物特征。
   只验签名和对齐看不出「启用了 A9/A10/A12，产物里却什么都没有」这类失败——
   功能项声明为已实现、退出码为 0，实际毫无作用。

装机实测用 [`scripts/device-test.sh`](scripts/device-test.sh)：把产物逐个装到设备上
并检查运行时行为（进程是否存活、有无 `VerifyError`/`ClassNotFoundException`/
`UnsatisfiedLinkError`、壳日志是否出现）。「被检测拦停」与「结构损坏崩溃」在脚本里
是两种不同的判定。

### 自动化守卫

工具会对自己产出的 DEX 做结构自检，这些检查**都曾在真实缺陷上复现过 ART 的报错**：

| 守卫 | 检查内容 | 覆盖量（RustDesk 实测） |
|---|---|---|
| 分支目标 | 分支必须落在指令边界内；goto 超 8 位范围时自动加宽 | 61293 条分支 |
| 异常处理器 | `handler_off` 指向处理器起点、try 区间合法、捕获类型已重映射 | 2567 个 try_item |
| shorty 字符串 | proto 的 shorty 只含 `VZBSCIJFD`/`L`（不被字符串加密破坏） | 164208 个原型 |
| static_values | 与静态字段的类型/数量按新 field_idx 顺序对齐 | 全量 |
| 字段操作码 | 操作码宽度与字段类型匹配（`sput-object` vs `sput-wide` 等） | 全量 |
| outs_size | ≥ 方法内任何 invoke 的参数字数 | 866 个方法体 |
| 类标志 | 不出现 `ACC_STATIC` 等成员标志（真实工具链产出中为 0） | 全量 |
| 悬空引用 | 改名后类型引用与数组描述符均能解析 | 全量 |
| **悬空成员引用** | 方法与字段引用都能在可见继承链里解析（跨 DEX 一致） | 全量 |
| 描述符合法性 | 类型表里不出现 `auo;`、`[[auo;` 这类非法描述符 | 全量 |
| DEX 版本 | 新建用 037，重建时归一化到 ≥037 | 全量 |

`go test ./...` 全绿（含签名、resources.arsc、批量处理等包的单测）。
A5/A11 的**决定性判据**（资源 ID 逐条不变）用 Android 官方 `aapt2` 复核，
只要 `ANDROID_HOME` 可用就会真正执行——此前它因为只认 Windows 路径而一直静默跳过。

> ⚠️ `dex2oat --compiler-filter=verify` **不能**替代上述检查：它对
> `handler_off`、`static_values` 这类结构错误返回 rc=0（漏报）。
> 有效的做法是看 ART 运行时的 logcat 报错，并用未经加固的原始 DEX 反向校验守卫自身。

### 已知局限

- **A4 不裁剪字符串池**：A4 会清空 `class_def` 的 `source_file_idx` 与 code_item 的
  `debug_info_off`（所以反编译视图里不再有 `MainActivity.java`、行号与局部变量名），
  但**不会**把因此失去引用的字符串从池里删掉，`strings` 仍可能捞到 `*.java` 字面量。
  安全地裁剪需要对全部引用做完整扫描，风险大于收益。
  同理，`SourceDebugExtension`（以注解形式存在）目前也未清除。
- **D4 覆盖范围**：实现是周期性地重复 C4/C5/C6 三项检查（调试器/注入/.so 改写），
  默认 3 秒一轮、命中即 `_exit(1)`；**不包含**「单个方法的字节码被改写」。
  原设计见 `剩余功能落地设计.md`，做成它需要先有 B5 的函数抽取基建。
- **原生库为 16 KB 页对齐**（`p_align=0x4000`，Android 15+ 的要求，Google Play 自
  2025-11 起对 targetSdk 35 的提交强制检查）；CI 与 `build_native.py --check`
  都会断言这一点。若自行改了 C 代码，记得用 NDK r26+ 重新构建（脚本已带上
  `-Wl,-z,max-page-size=16384`）。
- **A1 的成员改名偏保守**：真实混淆器（R8/ProGuard）靠**库方法表**判断某个方法是否
  覆写/继承自框架方法，本工具没有这份信息，只能用保守判据替代：① 继承链含框架
  类型的类，其非私有实例方法不改名（可能是框架回调）；② 引用若在可见继承链里
  找不到声明，说明声明来自看不见的父类型，名称保留；③ 多 DEX 应用里跨 DEX 共用的
  成员名一致保留。**类改名不受影响**，但方法/字段改名比例下降（RustDesk 全开时
  仅 15 个方法）。取舍理由见 `realworld/实测记录-三应用全选项.md`。
- **D5 的设备标识必须由应用自报**：Android 8+ 的 `ANDROID_ID` 按应用签名作用域化，
  `adb shell settings get secure android_id` 取到的是**原始值**，与应用内读到的不同
  （实测同一台模拟器：`2ad89c08d44767b6` vs `32a023838d4d9174`）。正确做法是
  `-debug-shell` 出排障版 → 在目标设备跑一次 → `adb logcat -s APKGUARD-D5` 读出
  本机标识 → 作为 `-bind-device` 的值。
- **`android:appComponentFactory` 会被指向框架默认实现**：该系统在壳接管
  ClassLoader **之前**就要实例化它，而原工厂类（通常是
  `androidx.core.app.CoreComponentFactory`）在加密载荷里——不改会让应用启动即
  `ClassNotFoundException`（三个真实应用都声明了它）。改动保留标准组件实例化语义，
  丢失的只有 androidx 的 `CompatWrapped` 包装特性。
- **Android 16 的回归范围**：Android 16（API 36）x86_64 模拟器上，`testapp` 的 11 个
  产物与上述三个真实应用都跑通了；但**没有覆盖更多机型/系统版本矩阵**，
  上生产前仍建议在目标机型上跑完整回归。
- 未实现的 7 项功能（A6/A7/B5/B6/B7/C2/C3）为**最高强度档**，启用会被 `-enable` 拒绝而不是静默跳过。
- 加固会改变代码布局，**与依赖反射/签名的第三方框架可能存在兼容问题**；
  上生产前建议在目标机型上跑一遍完整回归。


---

## 持续集成

工作流见 [`.github/workflows/ci.yml`](.github/workflows/ci.yml)，三个作业：

| 作业 | 内容 | 触发 |
|---|---|---|
| **构建与测试** | gofmt、go vet、内嵌原生库检查 + 摘要与 **16 KB 页对齐**校验、六平台交叉编译（linux/darwin/windows × amd64/arm64）、单元测试、CLI 冒烟测试 | 每次推送 / PR |
| **端到端** | 装 Android SDK 构建工具 → 从源码构建测试 APK → 用 **9 组功能集**加固 → apksigner/zipalign 校验 → **产物断言** → 生成签名摘要 → 跑产物级守卫 → 全量测试 | 每次推送 / PR |
| **原生库重建** | 用 NDK 重新编译 3 个 ABI，校验 `.agexpect` 段与 **16 KB 页对齐**，并对比仓库中的预编译库以检出「改了 C 代码却没更新 .so」 | 手动触发，或提交信息含 `[native]` |

CLI 冒烟测试里有两条**行为断言**，而不只是「能跑起来」：

- 启用未实现的功能项（如 A6）必须**报错**，而不是静默跳过——否则使用者会以为自己拿到了 VMP/控制流混淆等防护，实际完全没有；
- 启用签名（E1）却不给密钥库时必须报错。

产物：六平台二进制、加固后的 APK、3 个 ABI 的原生库（保留 14 天）。

> CI 不跑装机实测（没有设备）。有设备时用
> `bash scripts/device-test.sh`（可加 `ROOTED_DEVICE=1` 表示设备已 root/是模拟器，
> 此时带 D2/D3 的包被拦停属预期）。

### 本地跑同一套检查

GitHub Actions 可能因账号计费无法启动作业（注解会写
`The job was not started because recent account payments have failed…`，
注意 **Actions 对公开仓库免费**）。此时用本地 CI 获得同等门禁：

```bash
export ANDROID_HOME=/path/to/android-sdk     # 跑端到端需要，否则跳过该段
bash scripts/ci-local.sh

bash scripts/device-test.sh                  # 有设备/模拟器时做装机实测
```

### 几个踩过的 CI 坑（供参考）

1. **`.c` 文件不能放在 Go 包目录里**。Go 会把包目录下的 `.c` 当成 cgo 源文件，
   包内没有 `import "C"` 时直接报
   `C source files not allowed when not using cgo or SWIG`。
   更隐蔽的是它取决于 `CGO_ENABLED`（Linux 默认 1、Windows 默认 0），
   于是同一份代码本地能过、CI 失败。现在 C 源码放在 `internal/native/csrc/`。
2. **行尾必须是 LF**。Windows 上 `core.autocrlf=true` 会让检出的 shell 脚本带 CRLF，
   bash 把行尾回车符当成选项的一部分，CI 报
   `set: pipefail: invalid option name`。仓库已加 `.gitattributes` 强制 `eol=lf`；
   同步脚本也从 git 对象库读取内容，避免把工作区的 CRLF 带进仓库。
3. **`build_native.py` 要能同时适配 Windows 与 Linux**：NDK 在 Windows 上提供
   `<target>.cmd` 批处理包装、在 Linux/macOS 上提供同名 shell 脚本；NDK 位置也要
   同时认 `ANDROID_NDK_HOME`/`ANDROID_NDK_ROOT`（CI 的 `setup-ndk` 就是设这两个）
   与 `$ANDROID_HOME/ndk/<版本>`。历史上该脚本只认 Windows 的硬编码路径，
   于是 CI 的「原生库重建」作业从找到的 NDK 里一个 ABI 都编不出来。

---

## 构建

```bash
cd apkguard
go build -o apkguard.exe ./cmd/apkguard      # 需要 Go 1.21+
go test ./...
```

native 库（可选，C1/C4/C5/C6/D4 需要）：

```bash
python internal/native/build_native.py       # 需要 Android NDK；输出 3 个 ABI
```

> 注意：`.so` 通过 `go:embed` 打进二进制，因此**改了 C 代码必须先跑 build_native.py
> 再 go build**，顺序反了会用到旧库。


---

## 同步到 GitHub

本机到 `github.com:443` 的 git 传输不稳定（`Connection was reset` /
`Empty reply from server`），而 `api.github.com` 可用。
因此仓库提供了一个**走 Git Data API 的同步脚本**，效果与 `git push` 等价：

```bash
export GITHUB_TOKEN=<有 repo 权限的 PAT>     # 不要写进文件
python scripts/sync-github.py -m "提交信息"
```

脚本流程：`git add -A` → 必要时本地提交 → 逐个文件上传 blob →
建 tree → 建 commit（父提交取远端 HEAD）→ 移动 `refs/heads/main`。
每个请求都带重试，适配不稳定的网络。

也可在 git 端口可用时直接 `git push`，两者不冲突。

## 仓库内容约定

本目录是一个 7 GB 的研发工作区（含 Android SDK / NDK / Go 工具链、61 个 APK、
大量逆向分析产物），但**只有源码与文档入库**（约 1.1 MB）：

- 入库：`apkguard/`（Go 源码）、`testapp/src/`（测试应用源码）、设计文档、实测记录、同步脚本
- 不入库：`tools/`（工具链，GB 级）、`*.apk` / `*.dex` / `*.so`（二进制产物）、
  密钥库（`*.jks` / `*.pfx`，含私钥）、分析临时产物

过滤规则见 [`.gitignore`](.gitignore)——采用「先全部忽略、再逐个放行」的写法。

> 密钥库不入库：复现签名流程请自行生成，例如
> `keytool -genkeypair -keystore test.jks -alias test -keyalg RSA -keysize 2048 -validity 3650 -storepass 123456`

---

## 法律与用途

本工具用于**自有应用的代码保护**与安全研究。使用者需自行确保对目标 APK 拥有合法授权。