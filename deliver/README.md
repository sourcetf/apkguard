# 交付说明（可直接使用）

## 这是什么

一套**企业级 APK 加固工具**（Go 实现，纯自研 DEX 引擎，不依赖 d8/dx 等外部工具），
按 `APK加固功能设计文档.md` v1.2 的 38 个功能项实现。当前 **31 项已实现**，
全部经过自动化审计 + 装机实测验证。

## 目录里有什么

| 文件 | 用途 |
|---|---|
| `1-shell-only.apk` | **正式包**：加密(B1) + 壳(B2) + ClassLoader 接管(B3) + 多 DEX 分片(B4) + 混淆(A1~A4,A14) |
| `2-full-checks.apk` | **正式包（全功能）**：在 1 的基础上加 C1/C4/C5/C6（native 密钥派生、反调试、反注入、完整性自校验）+ D1/D2/D3（签名、Root、模拟器）+ D4（运行期周期复检） |
| `3-device-bind.apk` | 设备绑定示例（D5），绑定到一个不存在的设备标识，**应当被立即拦停**——用来验证绑定功能确实生效 |
| `D1-debug-shell.apk` | 排障版：每一步都会弹 Toast 并写 logcat（标签 `APKGUARD`），用于定位问题 |
| `D2-debug-full.apk` | 同上，含全部检测 |
| `S0-plain.apk` / `S1-obf.apk` | 基线对照：S0 = 原封不动只重签名；S1 = 只加混淆。用来二分定位问题是否出在加固链路 |

全部包使用同一张证书签名（`../testapp/keystore/real.jks`），可互相覆盖安装。
被测应用是一个**无害的测试应用**（`com.agtest`，一个界面 + 一个 Provider），不是恶意样本。

## 装机实测结果（Android 11 x86_64 模拟器，逐个安装运行）

| 包 | 结果 |
|---|---|
| S0-plain / S1-obf / 1-shell-only / D1-debug-shell | **正常运行**（Provider 接管、Application 委托、跨分片 Activity 三行业务日志齐全） |
| 2-full-checks / D2-debug-full | 被检测拦停 —— **模拟器上属设计行为**（D2 Root / D3 模拟器命中）。D2 会先打出 `AG1 壳已启动` 再退出，证明壳已跑起来 |
| 3-device-bind | 被拦停 —— **设计行为**（设备指纹不符） |
| **全部 7 个包** | **VerifyError = 0**（没有任何类被 ART 拒绝） |

> 手机上导入 `2-full-checks.apk` 应当**正常运行**：D2/D3 只在已 Root 或模拟器环境命中。

## 装机实测结果（Android 16 / API 36 / x86_64 模拟器，已 Root）

用 `scripts/device-test.sh` 逐个安装运行（`ROOTED_DEVICE=1`，该环境已 Root）：

| 包 | 结果 |
|---|---|
| S0-plain / S1-obf / 1-shell-only / D1-debug-shell | **正常运行** |
| **4-obf-full**（A5/A8/A9/A10/A11/A12/A13 一起开） | **正常运行** |
| **5-res-a5-only**（A5 单开） | **正常运行** |
| **6-channels-huawei / 6-channels-xiaomi**（E4 多渠道） | **正常运行** |
| 2-full-checks / D2-debug-full | 被检测拦停 —— 模拟器 + Root 环境下属设计行为 |
| 3-device-bind | 被拦停 —— 设计行为（设备指纹不符） |
| **全部 11 个包** | 安装成功；**VerifyError / ClassNotFoundException / UnsatisfiedLinkError / FATAL EXCEPTION 均为 0** |

排障版在 Android 16 上的完整壳链路日志：

```
I APKGUARD: AG1 壳已启动
I APKGUARD: AG-L1 载荷已解密并落地
I APKGUARD: AG-L2 DexClassLoader 就绪
I APKGUARD: AG-L3 接管成功
I APKGUARD: AG3 载荷解密并接管返回
I APKGUARD: AG4 已委托原 Application
I AGTEST  : HealthProvider.onCreate OK（ClassLoader 接管生效）
I AGTEST  : MyApp.onCreate OK
I AGTEST  : MainActivity.onCreate OK-跨分片
I AGTEST  : Features.classify=-31 parse=42   ← 分支/switch/异常表在真机上跑通
```

> **这轮装机实测查出并修掉的一个真缺陷**：启用 A5/A11 的产物此前**根本装不上**
> （`Failure [-124] ... requires the resources.arsc ... to be stored uncompressed`）——
> 资源 pass 回写 `resources.arsc` 时把它压成了 DEFLATE，而 Android 11+ 要求它未压缩。
> 签名校验与 `zipalign -c` **都发现不了**（zipalign 只检查未压缩条目的对齐），
> 只有装机才会暴露；而此前的交付验证里恰好没有包含 A5/A11 的包。
> 现在收尾阶段会统一把 `resources.arsc` 改为未压缩存放，并在 E3 自检与
> `scripts/verify-products.py` 里各加了一条断言。

## 已实现的功能（31/38）

- **混淆**：A1 改名、A2 字符串加密、A3 常量数组化、A4 去调试信息、A5 资源混淆、A8 诱饵类、A9 伪 DEX、A10 垃圾条目、A11 资源扁平化、A12 ZIP 路径攻击、A13 类膨胀、A14 时间戳统一
- **加壳**：B1 DEX 加密、B2 Application 替换、B3 ClassLoader 接管、B4 多 DEX 分片
- **native 保护**：C1 native 密钥派生、C4 反调试、C5 反注入、C6 完整性自校验
- **运行时防护**：D1 签名校验、D2 Root 检测、D3 模拟器检测、D4 运行期周期复检、D5 设备绑定
- **打包交付**：E1 签名、E2 对齐、E3 签名块、E4 渠道标记、E5 批量处理、E6 兼容性自检

未实现（7 项，均属最高强度档，方案见 `../剩余功能落地设计.md`）：
A6 控制流混淆、A7 反射化调用、B5 函数抽取、B6 VMP、B7 Dex2C、C2 SO 加壳、C3 OLLVM。

## 怎么用

```bash
cd ../apkguard
./apkguard.exe -in 你的.apk -out 加固后.apk     -ks 密钥库.jks -ks-pass 口令     -enable A1,A2,A3,A4,B1,B2,B3,B4,E1,E2,E3
```

常用参数：`-list` 看全部功能项；`-debug-shell` 出排障版；`-bind-device <android_id>` 绑定设备（`adb shell settings get secure android_id` 获取）；`-channels a,b,c` 多渠道批量；`-web` 打开界面。

## 本机验证过的检查（每项都补了自动化守卫）

- **签名与对齐**：apksigner v2+v3 通过、zipalign 4 字节对齐
- **DEX 结构**：AOSP `dexdump` 校验（含解密后的载荷）
- **ART 级验证**：模拟器上 `dex2oat --compiler-filter=verify` 全部通过
- **八项自动化审计**：载荷内容与 Manifest 一致性、悬空引用、类标志合法性、分支目标边界、字段操作码↔类型、`outs_size` 足够性、操作码断言、DEX 版本
- `go test ./...` 全绿

## 一个已知的未验证点（如实说明）

D4 的**"命中即杀"路径**没有被直接观测到：守护线程确实在周期性运行（多次 tick、无误差杀），
但"检测到篡改后 `_exit(1)`"这一步只有代码层面的把握——构造"被篡改但仍可安装"的
测试样本需要一个专门的 native 测试开关，尚未做。其余功能均为实测通过。
