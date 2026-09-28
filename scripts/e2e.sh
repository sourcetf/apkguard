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
harden() {
  local name="$1"; shift
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
# D5 设备绑定：绑一个不存在的设备标识，运行时应当被立即拦停（用来验证绑定确实生效）
"$AG" -in "$IN" -out "$OUT/3-device-bind.apk"       -ks "$KS" -ks-pass 123456       -enable "B1,B2,B3,D5" -bind-device 0000000000000000       >"$OUT/3-device-bind.log" 2>&1 || {
  echo "加固失败："; tail -20 "$OUT/3-device-bind.log"; exit 1; }
echo "-- 3-device-bind"

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
echo "############ 6) 产物级守卫（对刚生成的包做结构自检）############"
# 这些检查都曾在真实缺陷上复现过 ART 的报错，
# 覆盖：分支目标、异常处理器、shorty、static_values、字段操作码、outs_size、
#       类标志、悬空引用与数组描述符、DEX 版本、载荷内容一致性。
(cd "$ROOT/apkguard" && go test ./internal/dex/ -run 'TestArtifact' -v -count=1) \
  | grep -E '^(=== RUN|--- (PASS|FAIL|SKIP)|ok|FAIL)|检查|体检|命中|解密落地|载荷类清单'

echo
echo "############ 7) 全量测试 ############"
(cd "$ROOT/apkguard" && go test ./... -count=1)

echo
echo "端到端验证通过 ✅"