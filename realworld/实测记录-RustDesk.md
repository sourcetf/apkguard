# RustDesk 加固实测记录（已完成：第三轮跑通）

> 结论：加固后的 RustDesk（A1~A4+A14 + B1~B4 + E1/E2/E3/E6）在 Android 11 x86_64
> 模拟器上**一次启动即成功**。本文档按轮次记录了 9 个缺陷的根因与修法，
> 第三轮的完整结论见文末「第三轮」一节。

## 目标

用 apkguard 加固 RustDesk（真实开源应用），在模拟器上跑通。
样本：`realworld/rustdesk-orig.apk`（1.4.9 x86_64，25 MB，5331 个类，单 DEX 4.1 MB，
4 个原生库，minSdk 22 / targetSdk 33，`resources.arsc` 未压缩）。

## 已经正常的部分

| 环节 | 结果 |
|---|---|
| 加固耗时 | 33 秒（A1~A4+A14 + B1~B4 + E1/E2/E3/E6） |
| 产物 | 53.3 MB，签名 v2+v3 通过、4 字节对齐通过 |
| 分片 | 原 DEX 拆成 16 个分片，每个都通过 **ART 的 dex2oat --compiler-filter=verify** |
| 载荷完整性 | 解密后 5331 个类齐全，`Lcom/carriez/flutter_hbb/MainApplication` 在 `d7.dex` 中 |
| 壳链路（排障版） | `AG1 → AG-L1 载荷已解密并落地 → AG-L2 DexClassLoader 就绪 → AG-L3 接管成功 → AG3` 全部打出 |

## 修掉的 bug（本轮）

**只读标记误伤 targetSdk < 34 的应用**（已修 + 双向回归测试）

现象：RustDesk 加固后启动即崩：
```
java.io.FileNotFoundException: /data/user/0/com.carriez.flutter_hbb/app_ag/d0.dex:
  open failed: EACCES (Permission denied)
```
原因：Android 14 起「targetSdk ≥ 34 的应用加载可写 DEX 会被拒绝」这条要求，
我们无条件对所有应用加了 `setReadOnly()`；RustDesk 的 targetSdk 是 33，
标记后 ART 的 DexPathList 打开这些文件被拒。

修复：`LoaderSpec.MarkReadOnly`，由 B3 依 Manifest 的 targetSdk 决定（≥34 才标记）。
测试：`TestLoaderMarksDexReadOnly`（要标记）+ `TestLoaderSkipsReadOnlyWhenNotRequired`（不该标记）。

## 未解决的问题（阻塞 RustDesk）

修完只读标记后，EACCES 消失，但仍崩在同一个地方：

```
java.lang.ClassNotFoundException: com.carriez.flutter_hbb.MainApplication
  at java.lang.Class.forName
  at com.apkguard.shell.App.a(Unknown Source:4)      ← 壳的委托方法
  at com.apkguard.shell.App.attachBaseContext
```

已排除的可能：
- ✗ 类被 A1 改名（关掉 A1 一样崩；改名后的包里该类仍在）
- ✗ 载荷里没有该类（审计确认在 `d7.dex`，5331 个类齐全）
- ✗ dexPath 不完整（16 个分片路径都在）
- ✗ 分片本身非法（16 个分片逐个通过 ART 校验器）
- ✗ 多 DEX 分片机制（关掉 B4 用单载荷，崩在完全相同的位置）
- ✗ 只读标记（已修，EACCES 消失）

对比：同一套机制在自研测试应用（`com.agtest`，2 分片/6 个类/targetSdk 34）上完全正常。
因此是**该应用特有**的某一点。

### 下一步的确定探针（尚未做）

1. 在壳的委托方法里，把 `cl` 的 **每个分片各自可见性** 打出来：
   对每个载荷路径上的 dex，尝试 `cl.loadClass(<该 dex 中某个类>)`，
   看是哪几个分片不可见 —— 这能区分「ART 静默丢弃了部分 dex」和「全部 dex 可见但该类仍找不到」。
2. 检查 `android:appComponentFactory="androidx.core.app.CoreComponentFactory"` 的影响：
   该类的装载发生在壳接管 ClassLoader **之前**，日志里始终有一条
   `Unable to instantiate appComponentFactory`（当前表现为可容忍，但要确认）。
   可能的处理：加固时移除该属性，或把该类复制进壳 DEX。
3. 用 `adb shell dumpsys package com.carriez.flutter_hbb` 确认安装期的 dex 列表与
   `extractNativeLibs` 等属性，排除安装期差异。

## 复现方式

```bash
cd apkguard
./apkguard.exe -in ../realworld/rustdesk-orig.apk -out ../realworld/rd.apk     -ks ../testapp/keystore/real.jks -ks-pass 123456     -enable "A1,A2,A3,A4,A14,B1,B2,B3,B4,E1,E2,E3,E6" [-debug-shell]
adb install -r -t ../realworld/rd.apk && adb shell monkey -p com.carriez.flutter_hbb -c android.intent.category.LAUNCHER 1
adb logcat -s APKGUARD AndroidRuntime
```


---

# 第二轮（用安卓 16 模拟器 + 独立探针）

## 新增的关键手段

用 `d8` 编译了一个独立探针（`Probe.java`，不依赖本项目代码），在设备上直接
`new DexClassLoader(path)` 并逐个 `loadClass`。它一次性给出了决定性信息：

```
loader = dalvik.system.DexClassLoader[DexPathList[[], nativeLibraryDirectories=[/]]]
```

**dexPath 传了，但 ART 把整个 DEX 丢弃了**——所以任何类都找不到。
配合 logcat 拿到 ART 的真实拒收原因，逐个击破。

## 本轮修掉的三个真缺陷

### 1. 异常处理器的 handler_off 未重算（最严重）

```
W dalvikvm: Failure to verify dex file: Bogus handler offset: 19
E System  : Failed to open dex files ... because: Failure to verify dex file
```

`handler_off` 是「相对异常处理器列表起点的**字节**偏移」。改写后处理器目标地址变大，
ULEB128 编码长度可能从 1 字节涨到 3 字节，后续处理器在列表中的位置整体后移；
沿用旧偏移就会指向列表中间甚至越界。

修法：`CodeItemFull.Encode` 现在会**重新编码处理器列表并重算 handler_off**，
同时重算 try 区间长度。

**注意：`dex2oat --compiler-filter=verify` 对这个问题返回 rc=0（不报错）**，
所以之前"16 个分片全部通过 ART 校验"的结论是**不可靠**的——必须用 ART 的结构
校验器规则自己查。已补守卫 `TestArtifactTryHandlers` / `TestRealWorldPayloadTryHandlers`
（在修复前的产物上精确复现了 ART 的报错）。

### 2. 字符串加密破坏了 proto 的 shorty

```
W dalvikvm: Failure to verify dex file: Bad shorty character: '4'
```

shorty（形如 `VL`）**不被任何指令引用**，因此 `StringUsage` 的
「仅被 const-string 引用才可整体替换」判断把它误判为可加密，
变成了十六进制密文（`475f`），而 ART 要求 shorty 只含 `VZBSCIJFD`/`L`。

修法：`StringUsage` 新增 `Shorty` 类别，禁止整体替换。守卫：
`TestArtifactShortyStrings` / `TestRealWorldPayloadShorty`（16.4 万个 shorty 全量检查）。

### 3. 异常处理器的 catch_type_idx 未重映射

```
java.lang.VerifyError: [0x13] unexpected non-exception class Reference: org.xml.sax.helpers.DefaultHandler
```

A1 改名会重排 type_ids，而 `remapCode` 只重映射**指令里**的池引用，
漏了处理器列表里的捕获类型索引 → 处理器去捕获一个无关的类。

修法：`remapCode` 改为按 code_item 整体域处理——重映射捕获类型后整体重编码
（顺带让 handler_off 一并重算）。同时修了两处自身引入的错误：
指令重映射写在 buf 里却用旧副本重编码；以及测试的语义比较需要把捕获类型解析成
名字再比（索引变化属预期）。

### 附：只读标记按 targetSdk 决定（第一轮）

`setReadOnly()` 只对 targetSdk ≥ 34 有意义；对 RustDesk（33）标记反而导致
`EACCES(Permission denied)`。已按 Manifest 的 targetSdk 条件化，双向回归测试。

## 当前状态：仍未启动，但失败点已推进到方法引用层

三个结构缺陷修完后，DEX 结构与类校验全部通过，最新失败变为：

```
java.lang.NoSuchMethodError: No virtual method eh(I)Ljava/lang/String;
  in class Landroid/content/Context;
    at q3.bwe.b
    at androidx.startup.InitializationProvider.onCreate
```

即某个 `invoke-virtual` 的**方法索引被映射到了错误的方法**（应为 `Context.getString(I)`）。
已确认：原始 dex 与我们的载荷里都**不存在** `(Context, eh, (I)String)` 这个 method_ids 条目，
说明是**指令里的方法索引指向了错误条目**，而不是方法表本身有问题。

### 下一步（具体）

1. 反汇编 `q3.bwe.b`（在载荷 d?.dex 中），打印该 `invoke-virtual` 的原始方法索引，
   与 method_ids 表对照，确认它指向了哪个条目；
2. 对照原始 dex 中同一处的索引，看映射是哪一类引用出错（很可能是方法引用的
   映射键或去重逻辑在多 DEX 拆分/改名组合下失配）；
3. 检查是否为「壳 DEX 与载荷 DEX 的 method_ids 索引空间混淆」——
   壳 dex 的引用条目与载荷 dex 的条目是两套独立索引，若某处复用了壳的索引就会如此。


---

# 第三轮：**RustDesk 加固后成功运行** ✅

最终产物：`realworld/rd-v20.apk`（53.4 MB，1 个壳 DEX + 16 个加密载荷分片）
实测（安卓 11 x86_64 模拟器）：**一次启动即成功，MainActivity 正常 resume，
进程持续存活 144 秒以上，全部错误计数为 0**。

```
mResumedActivity: ActivityRecord{... com.carriez.flutter_hbb/.MainActivity}
VerifyError / UnsatisfiedLinkError / invalid branch target / FATAL EXCEPTION: 全部 0
```

## 本轮又修掉的 6 个缺陷（合计 9 个）

| # | ART 报错 | 根因 | 修法 |
|---|---|---|---|
| 4 | `unexpected static field initial value type` / `Bogus encoded_value value_type` | static_values 未按**新的 field_idx 顺序重排**（A1 改名会改变排序）；且补默认值时只写了类型字节（`04`），缺载荷字节（应为 `04 00`） | 按新字段顺序重排 + 完整的默认值编码 + 拼装后整体自校验 |
| 5 | `can't resolve returned type 'Unresolved Reference: z7.c[]'` | **数组描述符是独立类型字符串**（`[Lfoo;`），A1 只改了类名没改数组 → 数组指向已不存在的元素类 | `Plan()` 为每个重命名类派生 1~8 维数组描述符映射 |
| 6 | `invalid switch target` | switch payload 内的 target 规范上**相对 switch 指令**，我们按「相对 payload」处理；插入指令后两者距离变化不同 | 建立 payload→switch 指令归属，按 switch 新地址重算 |
| 7 | `UnsatisfiedLinkError: DexPathList[...]` | 构造 DexClassLoader 时 native 库搜索路径传了 `null` → 应用加载自己的 .so 失败 | 传入 `getApplicationInfo().nativeLibraryDir`（注意是**实例**字段，用 iget-object） |
| 8 | `UnsatisfiedLinkError: No implementation found for void ffi.zl.cc(...)` | **JNI 符号名按类名动态推导**（`Java_<类名>_<方法名>`），含 native 方法的类被改名后符号失配 | 声明了 native 方法的类一律不改名 |
| 9 | `invalid branch target -117 (-> 0x35)` | **goto 是 8 位偏移**（-128..127）；改写拉长跳转距离后超范围，编码被静默截断 | 布局迭代：超范围时把 goto 加宽为 goto/16 或 goto/32 |

## 新增守卫（全部在修复前的产物上复现过 ART 的报错）

- `TestArtifactStaticValues` / `TestRealWorldStaticValues`：static_values 与静态字段的类型/数量对齐
- `TestRealWorldBranchTargets`：**61293 条分支**的目标必须在指令边界内
- `TestOriginalDexStaticValues`：用**未经加固的原始 dex** 校验守卫自身的假设（原始文件必然被 ART 接受，若不通过说明守卫模型有误——这条在本轮起到了关键作用）
- 以及前两轮的 try/handler（2567 个）、shorty（164208 个）

## 方法论上的一个关键教训

**`dex2oat --compiler-filter=verify` 会漏报**（handler_off、static_values 这类结构错误它返回 rc=0）。
第二轮据此得出过"分片全部合法"的错误结论。有效的做法是：
1. 在设备上 `adb logcat` 看 **ART 运行时的**结构校验器报错（最权威）；
2. 用**独立探针**（不依赖本项目代码的 DexClassLoader 测试）暴露"类全部找不到"这类现象；
3. 用**原始 dex 校验守卫自身**，避免守卫模型本身错误导致误报/漏报。
