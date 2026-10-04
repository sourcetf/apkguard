#!/usr/bin/env bash
# 端到端验证：构建测试 APK → 用 apkguard 加固 → 校验产物 → 跑产物级守卫。
#
# 这是 CI 的核心作业，也可以在本地跑（需要 Android SDK + JDK）。
# 环境变量：
#   ANDROID_HOME / ANDROID_SDK_ROOT   SDK 根目录
#   BUILD_TOOLS_DIR                   可选，build-tools 目录（默认 $SDK/build-tools/$BT_VER）
#   BUILD_TOOLS_VERSION               默认 34.0.0
#   PLATFORM_VERSION                  默认 android-34
#   JAVA_HOME                         可选
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP="$ROOT/testapp"
OUT="$ROOT/deliver"
BT_VER="${BUILD_TOOLS_VERSION:-34.0.0}"
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
BT="${BUILD_TOOLS_DIR:-$SDK/build-tools/$BT_VER}"
KS="$APP/build/test.jks"

if [ -z "$SDK" ]; then
  echo "错误：未设置 ANDROID_HOME / ANDROID_SDK_ROOT" >&2
  exit 1
fi
jhome="${JAVA_HOME:-}"
if command -v cygpath >/dev/null 2>&1 && [ -n "$jhome" ]; then
  jhome="$(cygpath -u "$jhome")"
fi
[ -n "$jhome" ] && { PATH="$jhome/bin:$PATH"; export PATH; }

exe() {
  for c in "$1" "$1.exe" "$1.bat"; do
    [ -f "$c" ] && { echo "$c"; return; }
  done
  echo "错误：找不到 $c" >&2
  exit 1
}
APKSIGNER="$(exe "$BT/apksigner")"
ZIPALIGN="$(exe "$BT/zipalign")"
mkdir -p "$OUT"
# 交付目录里可能残留上次运行的产物；第 4 步用 "$OUT"/*.apk 做全局校验时会把这些
# 陈旧文件一并算进去（曾把与本轮无关的旧包报成签名失败）。开跑前清空本次会写
# 的产物与日志，并移除批量模式的临时输入目录。
rm -f "$OUT"/*.apk "$OUT"/*.log
rm -rf "$OUT/inputs"

# 选一个**真正可用**的 python：Windows 上 python3 常指向应用商店的空壳
# （命令存在但执行即失败），因此必须实际跑一次才算数。
PY_BIN=""
for c in python3 python; do
  if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys' >/dev/null 2>&1; then
    PY_BIN="$c"; break
  fi
done
[ -n "$PY_BIN" ] || { echo "错误：找不到可用的 python（产物断言需要 3.x）" >&2; exit 1; }

echo "############ 1) 构建测试 APK ############"
bash "$ROOT/scripts/build-testapp.sh"
IN="$APP/testapp-signed.apk"

echo
echo "############ 2) 构建 apkguard ############"
(cd "$ROOT/apkguard" && go build -o apkguard ./cmd/apkguard)
AG="$ROOT/apkguard/apkguard"

echo
echo "############ 3) 加固（多组功能集）############"
# 覆盖不同代码路径：仅重打包 / 仅混淆 / 壳链路 / 全功能（含 native 与检测）
#
# ENABLE_UNION 收集所有实际下发的 -enable 集合，供第 3.5 步做「已实现项全覆盖」
# 自检：只要有功能项从所有集合里消失，自检就会失败。跟踪放在 harden() 里，
# 直接从命令行参数提取，避免维护一份与命令脱节的副本。
ENABLE_UNION=""
record_enable() {
  local prev=""
  for a in "$@"; do
    if [ "$prev" = "-enable" ]; then ENABLE_UNION="$ENABLE_UNION,$a"; fi
    prev="$a"
  done
}
harden() {
  local name="$1"; shift
  record_enable "$@"
  echo "-- $name"
  "$AG" -in "$IN" -out "$OUT/$name.apk" \
        -ks "$KS" -ks-pass 123456 "$@" >"$OUT/$name.log" 2>&1 || {
    echo "加固失败："; tail -20 "$OUT/$name.log"; exit 1; }
  grep -E '启用功能项|执行了' "$OUT/$name.log" | head -2 || true
}

harden S0-plain      -disable "A1,A2,A3,A4,A5,A6,A7,A8,A9,A10,A11,A12,A13,A14,B1,B2,B3,B4,B5,B6,B7,C1,C2,C3,C4,C5,C6,D1,D2,D3,D4,D5,E4,E5" -enable "E1,E2,E3,E6"
harden S1-obf        -disable "A5,A6,A7,A8,A9,A10,A11,A12,A13,B1,B2,B3,B4,B5,B6,B7,C1,C2,C3,C4,C5,C6,D1,D2,D3,D4,D5,E4,E5" -enable "E1,E2,E3,E6,A1,A2,A3,A4,A14"
harden 1-shell-only  -enable "A1,A2,A3,A4,B1,B2,B3,B4,A14,E1,E2,E3,E6"
harden D1-debug-shell -enable "A1,A2,A3,A4,B1,B2,B3,B4,A14,E1,E2,E3,E6" -debug-shell
harden 2-full-checks -enable "A1,A2,A3,A4,B1,B2,B3,B4,A14,E1,E2,E3,E6,C1,C4,C5,C6,D1,D2,D3,D4"
harden D2-debug-full -enable "A1,A2,A3,A4,B1,B2,B3,B4,A14,E1,E2,E3,E6,C1,C4,C5,C6,D1,D2,D3,D4" -debug-shell
# 此前 e2e 完全没有覆盖的混淆项：A5/A8/A9/A10/A11/A12/A13。
# 它们只被单元测试碰过，而「加固 + 签名 + 对齐之后产物是否仍然合法」没人验过。
harden 4-obf-full    -enable "A1,A2,A3,A4,A5,A7,A8,A9,A10,A11,A12,A13,A14,E1,E2,E3,E6"
# A15 巨型 Manifest 填充 + B8 载荷容器化（两项都需单独验证：
# A15 改 Manifest 字节、B8 改载荷条目名，出问题都是「装不上/起不来」级别）
harden 7-packed -enable "A1,A2,A4,B1,B2,B3,B8,A15,E1,E2,E3,E6" -manifest-pad-mb 16
# 欺骗类手法单列一组：A16 假核心文件 / A17 假内层 APK / A18 假权限元数据 /
# A19 字符串池垃圾 / A20 花指令。它们都不依赖加壳，单独成组便于把产物断言钉死。
harden 8-deception -enable "A1,A4,A16,A17,A18,A19,A20,E1,E2,E3,E6"
# A5 单开（A11 同时启用时 A5 会让位，那样 A5 自身的实现就没人跑了）
harden 5-res-a5-only -enable "A1,A4,A5,A14,E1,E2,E3,E6"
# A6 控制流混淆：单独成组且**不启用 B1**——B1 会把业务 DEX 加密成载荷，
# A6 的指令骨架落在明文 classes.dex 里就看不到了（verify-products.py 在 B1 下
# 对 A6 只能给出提示、无法断言）。受控测试应用上不透明谓词覆盖为 0，真实痕迹
# 是「不可达前向跳转块」，故断言同时认谓词骨架与跳转块两种形态。
harden 9-cff         -enable "A1,A4,A6,A14,E1,E2,E3,E6"
# C7 原生库伪装依赖 C1（它改写的是 C1 注入的 libapkguard.so 的库名），
# B1/B2/B3 提供壳链路；-lib-name 显式指定假库名，便于产物断言。
harden 11-libdisguise -enable "A1,A4,B1,B2,B3,C1,C7,A14,E1,E2,E3,E6" -lib-name libguardx.so

# C2 SO 加壳需要输入里**真的有一个业务 .so**，否则 C2 是空操作、产物断言无从
# 谈起。testapp 没有原生库，这里把仓库里的守卫库复制成 lib/<abi>/libdummy.so
# 注入测试 APK（只验产物结构、不在设备上运行，所以不要求它是可加载的业务库）。
C2_IN="$OUT/inputs/c2-in.apk"
SO_SRC="$ROOT/apkguard/internal/native/prebuilt/x86_64/libapkguard.so"
mkdir -p "$OUT/inputs"
"$PY_BIN" -c 'import shutil,sys,zipfile; src,dst,so=sys.argv[1],sys.argv[2],sys.argv[3]; shutil.copy(src,dst); z=zipfile.ZipFile(dst,"a",zipfile.ZIP_STORED); z.write(so,"lib/x86_64/libdummy.so"); z.close()' "$IN" "$C2_IN" "$SO_SRC"
C2_SIZE="$(stat -c%s "$SO_SRC" 2>/dev/null || wc -c <"$SO_SRC")"
echo "-- 10-soenc（C2，输入注入 %s 字节的 libdummy.so）" "$C2_SIZE"
# -so-encrypt 会自动把 C2 加进启用集合；这里在 -enable 里显式写出 C2，
# 让「实际启用了哪些项」对日志与覆盖率自检都一目了然。
record_enable -enable "A1,A4,B1,B2,B3,C2,A14,E1,E2,E3,E6"
"$AG" -in "$C2_IN" -out "$OUT/10-soenc.apk" -ks "$KS" -ks-pass 123456 \
      -enable "A1,A4,B1,B2,B3,C2,A14,E1,E2,E3,E6" -so-encrypt \
      >"$OUT/10-soenc.log" 2>&1 || {
  echo "加固失败："; tail -20 "$OUT/10-soenc.log"; exit 1; }
grep -E '启用功能项|执行了' "$OUT/10-soenc.log" | head -2 || true

# D5 设备绑定：绑一个不存在的设备标识，运行时应当被立即拦停（用来验证绑定确实生效）
record_enable -enable "B1,B2,B3,D5"
"$AG" -in "$IN" -out "$OUT/3-device-bind.apk"       -ks "$KS" -ks-pass 123456       -enable "B1,B2,B3,D5" -bind-device 0000000000000000       >"$OUT/3-device-bind.log" 2>&1 || {
  echo "加固失败："; tail -20 "$OUT/3-device-bind.log"; exit 1; }
echo "-- 3-device-bind"

# E4 多渠道：每个渠道单独走一遍「写入 → 对齐 → 签名」，产出多个 APK。
# 不能「签一次再改文件」——v2/v3 覆盖整个文件，签完再改会让签名立刻失效。
record_enable -enable "A1,A4,B1,B2,B3,A14,E1,E2,E3,E6,E4"
"$AG" -in "$IN" -out "$OUT/6-channels.apk" -ks "$KS" -ks-pass 123456 \
      -enable "A1,A4,B1,B2,B3,A14,E1,E2,E3,E6,E4" -channels "huawei,xiaomi" \
      >"$OUT/6-channels.log" 2>&1 || {
  echo "加固失败："; tail -20 "$OUT/6-channels.log"; exit 1; }
echo "-- 6-channels（E4：huawei/xiaomi）"

# E5 批量处理：-in 指向目录时逐个子项加固、一次产出多个包。制造两个输入，
# 验证确实产出两个独立产物（E5 的产物证据是「多产物」，verify-products.py
# 只看单个 APK，无法表达，因此这里单独断言数量）。
echo "-- 9-batch（E5：目录批量，2 个输入）"
mkdir -p "$OUT/inputs/e5"
cp "$IN" "$OUT/inputs/e5/e5a.apk"
cp "$IN" "$OUT/inputs/e5/e5b.apk"
record_enable -enable "A1,A4,A14,E1,E2,E3,E6,E5"
"$AG" -in "$OUT/inputs/e5" -out "$OUT" -ks "$KS" -ks-pass 123456 \
      -enable "A1,A4,A14,E1,E2,E3,E6,E5" >"$OUT/9-batch.log" 2>&1 || {
  echo "加固失败："; tail -20 "$OUT/9-batch.log"; exit 1; }
batch_n="$(ls "$OUT"/e5a-protected.apk "$OUT"/e5b-protected.apk 2>/dev/null | wc -l || true)"
[ "$batch_n" -eq 2 ] || { echo "E5 批量未产出 2 个产物（实际 $batch_n）"; exit 1; }

echo
echo "############ 3.5) 功能集覆盖自检（所有已实现项至少出现一次）############"
# 从 -list 自动取「已实现项」清单（未实现的行带 【尚未实现】 标记），
# 再断言它们全部出现在上面收集的 ENABLE_UNION 里。这条自检会真正失败：
# 任何已实现项从所有 -enable 集合里消失（例如新增功能项后忘了加进 e2e），
# 都会在这里报错——避免「功能项已实现、e2e 却从未覆盖」的静默漏洞。
IMPLEMENTED="$("$AG" -list | "$PY_BIN" "$ROOT/scripts/count-features.py" --implemented)"
[ -n "$IMPLEMENTED" ] || { echo "无法从 -list 解析已实现项清单"; exit 1; }
COVERED=",$ENABLE_UNION,"
missing=""
n_impl=0
for f in $IMPLEMENTED; do
  n_impl=$((n_impl + 1))
  case "$COVERED" in
    *",$f,"*) ;;
    *) missing="$missing $f" ;;
  esac
done
if [ -n "$missing" ]; then
  echo "以下已实现功能项未出现在任何一次 -enable 集合中：$missing"
  exit 1
fi
echo "  已实现 $n_impl 项全部被 e2e 功能集覆盖"

echo
echo "############ 4) 签名/对齐校验 ############"
fail=0
for f in "$OUT"/*.apk; do
  name="$(basename "$f")"
  if "$APKSIGNER" verify --min-sdk-version 24 "$f" >/dev/null 2>&1; then s=OK; else s=失败; fail=1; fi
  if "$ZIPALIGN" -c -p 4 "$f" >/dev/null 2>&1; then a=OK; else a=失败; fail=1; fi
  printf "  %-24s 签名=%s 对齐=%s %8d 字节\n" "$name" "$s" "$a" "$(stat -c%s "$f" 2>/dev/null || wc -c <"$f")"
done
[ "$fail" = 0 ] || { echo "校验失败"; exit 1; }

echo
echo "############ 5) 生成签名摘要（C1 载荷测试需要）############"
"$APKSIGNER" verify --print-certs "$OUT/2-full-checks.apk" \
  | grep -i "SHA-256 digest" | head -1 \
  | sed 's/.*digest: //' | tr -d '\r ' > "$OUT/signer-sha256.txt"
echo "  摘要: $(cat "$OUT/signer-sha256.txt")"

echo
echo "############ 6) 产物断言（启用的功能项必须真的生效）############"
# 只验「签名有效 + 对齐正确」是不够的：那看不出「启用了 A9/A10/A12，
# 产物里却什么都没有」这类失败——功能项声明为已实现、exit code 为 0，
# 实际毫无作用。这里按功能项逐个检查产物特征。
verify() {
  local name="$1"; shift
  local feats="$1"; shift
  "$PY_BIN" "$ROOT/scripts/verify-products.py" "$OUT/$name" "$feats" "$@"
}
verify 4-obf-full.apk    "A4,A5,A8,A9,A10,A11,A12,A13"
verify 5-res-a5-only.apk "A4,A5"
verify 1-shell-only.apk  "B1,B2"
verify 2-full-checks.apk "A14,B1,B2"
verify 6-channels-huawei.apk "B1,B2,E4" --channel huawei
verify 6-channels-xiaomi.apk "B1,B2,E4" --channel xiaomi
verify 7-packed.apk      "B1,B2,B8,A15"
verify 8-deception.apk   "A16,A17,A18,A19,A20"
verify 9-cff.apk         "A1,A4,A6,A14"
verify 10-soenc.apk      "B1,B2,C2" --c2-lib libdummy.so --c2-size "$C2_SIZE"
verify 11-libdisguise.apk "B1,B2,C7"
# E5 的两个批量产物也要过产物断言（A14 统一时间戳）。
verify e5a-protected.apk "A14"
verify e5b-protected.apk "A14"

echo
echo "############ 7) 产物级守卫（对刚生成的包做结构自检）############"
# 这些检查都曾在真实缺陷上复现过 ART 的报错，
# 覆盖：分支目标、异常处理器、shorty、static_values、字段操作码、outs_size、
#       类标志、悬空引用与数组描述符、DEX 版本、载荷内容一致性。
(cd "$ROOT/apkguard" && go test ./internal/dex/ -run 'TestArtifact' -v -count=1) \
  | grep -E '^(=== RUN|--- (PASS|FAIL|SKIP)|ok|FAIL)|检查|体检|命中|解密落地|载荷类清单'

echo
echo "############ 8) 全量测试 ############"
(cd "$ROOT/apkguard" && go test ./... -count=1)

echo
echo "端到端验证通过 ✅"