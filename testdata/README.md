# 测试固件（testdata）

这里放的是**测试用的样本**，不是交付产物。

| 文件 | 内容 | 大小 |
|---|---|---|
| `sample.apk` | `testapp` 用 build-tools 构建并签名后的 APK | ~13 KB |
| `sample.dex` | `sample.apk` 里的 `classes.dex`（d8 产物，带调试信息） | ~6 KB |
| `AndroidManifest.xml` | `sample.apk` 里解出的二进制 AXML | ~2 KB |

## 为什么二进制固件要入库

仓库的一般约定是「只入库源码，不入库二进制产物」（见根 `.gitignore`），
这里是一个有意的例外，理由和 native 的预编译 `.so` 相同：**它们是构建/测试的输入，
没有它们构建与测试就跑不起来**。

之前没有固件时，`dex` / `axml` / `passes` / `pipeline` 等包的测试样本加载器
只能去工作区里找临时路径（`iterator.apk.apk`、`dex_tmp/classes2.dex`、
`apk_extracted/AndroidManifest.xml`、`realworld/rd-*.apk`……），而这些都不在仓库里。
后果是**干净检出下 94 条测试被静默跳过**，`go test ./...` 依然显示 ok——
README 里主打的「产物级守卫」在 CI 上其实一条都没跑。

固件入库后，这些测试在干净检出下也会真正执行。加载器仍会**优先**使用
刚构建出来的产物（`testapp/build/dex/classes.dex`、`testapp/testapp-signed.apk`），
所以端到端流程里测的始终是最新构建的结果，固件只在「没有构建产物」时兜底。

## 怎么重新生成

固件来自 `testapp`，改过 `testapp/` 下任何源码后应当重新生成：

```bash
export ANDROID_HOME=/path/to/android-sdk
bash scripts/build-testapp.sh

cp testapp/testapp-signed.apk      testdata/sample.apk
cp testapp/build/dex/classes.dex   testdata/sample.dex
python3 - testdata/sample.apk testdata/AndroidManifest.xml <<'PY'
import sys, zipfile
zf = zipfile.ZipFile(sys.argv[1])
open(sys.argv[2], "wb").write(zf.read("AndroidManifest.xml"))
PY
```

> 固件与 `testapp` 源码不一致时，测试里的断言（类数、指令形态）会失败——
> 这是有意的：它提示你重新生成固件，而不是让你去放宽断言。

## 固件必须覆盖的指令形态

`testapp` 不是随便一个「能跑就行」的空壳，它被刻意写成覆盖下列形态，
否则一批结构类守卫会因为「样本里没有这种指令」而跳过（等于没测）：

| 形态 | 出处 | 依赖它的测试 |
|---|---|---|
| `if` / `switch` / `for` / `while` | `Features.classify` | `TestInsnListRoundTrip`（分支重定位） |
| 数组字面量 | `Features.table` | `TestFillArrayDataNotMistakenForTypeRef` |
| `try/catch/finally` | `Features.parse` | 异常处理器守卫 |
| 静态/实例字段 | `Features` | `TestStringUsage`（字段名集合非空）、字段操作码守卫 |
| 字符串常量 | 各处 | `TestStringUsage`（常量集合非空） |
| 调试信息（`javac -g`） | 全部 | `TestStringUsageCoversDebugInfo`、A4 相关断言 |
| 文件型资源（`res/layout`） | `MainActivity` | A5/A11（`arsc.ResPaths()` 非空） |
| 足够的类数（≥10） | `Features$Inner` / `Features$Inner2` | `TestSplitDexConservesClasses`（B4 拆分） |
