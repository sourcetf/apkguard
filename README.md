# apkguard —— 纯 Go 实现的 APK 加固工具

一套**自研的 Android APK 加固引擎**：从 DEX 解析/重建、字符串与常量改写、多 DEX 拆分，
到一代壳（DEX 加密 + Application 替换 + ClassLoader 接管）、native 层防护
（密钥派生、反调试、反注入、完整性自校验）与运行时检测，全部用 Go 实现，
**不依赖 dx/d8 等外部工具链**。

设计依据与功能清单见 [`APK加固功能设计文档.md`](APK加固功能设计文档.md)（38 个功能项，6 个阶段）。

---

## 当前进度

**31 / 38 个功能项已实现**（未实现的 7 项均为最高强度档，落地设计见
[`剩余功能落地设计.md`](剩余功能落地设计.md)）。

| 阶段 | 已实现 |
|---|---|
| **A 混淆** | A1 类名混淆 · A2 字符串加密 · A3 常量数组化 · A4 去调试信息 · A5 资源混淆 · A8 诱饵类 · A9 伪 DEX · A10 垃圾条目 · A11 资源扁平化 · A12 ZIP 路径攻击 · A13 类膨胀 · A14 时间戳统一 |
| **B 加壳** | B1 DEX 加密 · B2 Application 替换 · B3 ClassLoader 接管 · B4 多 DEX 拆分 |
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

**受控测试应用**：`testapp/`（一个 Activity + 一个 ContentProvider + 辅助类），
用于逐功能隔离验证，覆盖全部 31 个已实现项。

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
| 悬空引用 | 改名后引用与数组描述符均能解析 | 全量 |
| DEX 版本 | 新建用 037，重建时归一化到 ≥037 | 全量 |

`go test ./...` 全绿。

> ⚠️ `dex2oat --compiler-filter=verify` **不能**替代上述检查：它对
> `handler_off`、`static_values` 这类结构错误返回 rc=0（漏报）。
> 有效的做法是看 ART 运行时的 logcat 报错，并用未经加固的原始 DEX 反向校验守卫自身。

### 已知局限

- **安卓 16 未实测**：RustDesk 的验证是在安卓 11 上做的；安卓 16 模拟器（纯软件模拟）启动过慢，尚未跑通回归。
- 未实现的 7 项功能（A6/A7/B5/B6/B7/C2/C3）为**最高强度档**，启用会被 `-enable` 拒绝而不是静默跳过。
- 加固会改变代码布局，**与依赖反射/签名的第三方框架可能存在兼容问题**；
  上生产前建议在目标机型上跑一遍完整回归。


---

## 持续集成

工作流见 [`.github/workflows/ci.yml`](.github/workflows/ci.yml)，三个作业：

| 作业 | 内容 | 触发 |
|---|---|---|
| **构建与测试** | gofmt、go vet、内嵌原生库检查、六平台交叉编译（linux/darwin/windows × amd64/arm64）、单元测试、CLI 冒烟测试 | 每次推送 / PR |
| **端到端** | 装 Android SDK 构建工具 → 从源码构建测试 APK → 用 6 组功能集加固 → apksigner/zipalign 校验 → 生成签名摘要 → 跑产物级守卫 → 全量测试 | 每次推送 / PR |
| **原生库重建** | 用 NDK 重新编译 3 个 ABI，校验 `.agexpect` 段，并对比仓库中的预编译库以检出「改了 C 代码却没更新 .so」 | 手动触发，或提交信息含 `[native]` |

CLI 冒烟测试里有两条**行为断言**，而不只是「能跑起来」：

- 启用未实现的功能项（如 A6）必须**报错**，而不是静默跳过——否则使用者会以为自己拿到了 VMP/控制流混淆等防护，实际完全没有；
- 启用签名（E1）却不给密钥库时必须报错。

产物：六平台二进制、加固后的 APK、3 个 ABI 的原生库（保留 14 天）。

### 本地跑同一套检查

GitHub Actions 可能因账号计费无法启动作业（注解会写
`The job was not started because recent account payments have failed…`，
注意 **Actions 对公开仓库免费**）。此时用本地 CI 获得同等门禁：

```bash
export ANDROID_HOME=/path/to/android-sdk     # 跑端到端需要，否则跳过该段
bash scripts/ci-local.sh
```

### 两个踩过的 CI 坑（供参考）

1. **`.c` 文件不能放在 Go 包目录里**。Go 会把包目录下的 `.c` 当成 cgo 源文件，
   包内没有 `import "C"` 时直接报
   `C source files not allowed when not using cgo or SWIG`。
   更隐蔽的是它取决于 `CGO_ENABLED`（Linux 默认 1、Windows 默认 0），
   于是同一份代码本地能过、CI 失败。现在 C 源码放在 `internal/native/csrc/`。
2. **行尾必须是 LF**。Windows 上 `core.autocrlf=true` 会让检出的 shell 脚本带 CRLF，
   bash 把行尾回车符当成选项的一部分，CI 报
   `set: pipefail: invalid option name`。仓库已加 `.gitattributes` 强制 `eol=lf`；
   同步脚本也从 git 对象库读取内容，避免把工作区的 CRLF 带进仓库。

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