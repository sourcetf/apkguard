#!/usr/bin/env bash
# 用**全部 42 个已实现功能项**加固三个真实应用，并在模拟器上复验。
#
# 产出两个变体：
#   <app>-ALL-emu.apk       全 42 项（含 D2/D3/D5）。在本机（已 root 的模拟器）
#                           D2/D3 会**按设计**命中并终止进程——这是它们生效的证据。
#   <app>-NODETECT-emu.apk  除 D2/D3 外的全部项。用来验证「应用功能本身没被破坏」：
#                           否则 D2/D3 一命中，根本观察不到应用跑起来。
set -uo pipefail

REPO=/mnt/c/Users/admin/Desktop/apkguard
OUT=$REPO/realworld/emu-out
SDK=$HOME/android-sdk
export ANDROID_HOME=$SDK
export ANDROID_SDK_ROOT=$SDK
export JAVA_HOME=$HOME/java
export PATH=$HOME/goroot/bin:$JAVA_HOME/bin:$PATH

mkdir -p "$OUT"
(cd "$REPO/apkguard" && CGO_ENABLED=0 go build -o "$OUT/apkguard-linux" ./cmd/apkguard) || exit 1
AG="$OUT/apkguard-linux"

KS_ARGS="-ks $REPO/realworld/apps/test.p12 -ks-pass apkguard"
EXTRA="-channels emu -package-shrink -manifest-pad-mb 8 -so-encrypt -lib-name libguardx.so -payload-mac"

# 全部 42 个已实现项（B5/B6/B7/C3 未实现，启用会被拒绝）。
ALL="A1,A2,A3,A4,A5,A6,A7,A8,A9,A10,A11,A12,A13,A14,A15,A16,A17,A18,A19,A20,B1,B2,B3,B4,B8,C1,C2,C4,C5,C6,C7,D1,D2,D3,D4,D5,E1,E2,E3,E4,E5,E6"
NODETECT="A1,A2,A3,A4,A5,A6,A7,A8,A9,A10,A11,A12,A13,A14,A15,A16,A17,A18,A19,A20,B1,B2,B3,B4,B8,C1,C2,C4,C5,C6,C7,D1,D4,D5,E1,E2,E3,E4,E5,E6"
# PORTABLE：去掉 D2/D3（检测到 Root/模拟器即终止）与 D5（绑定到采样的那台设备）。
# 这两个变体在**别的设备上会被自己拦住**，所以对外分发要用这一份。
PORTABLE="A1,A2,A3,A4,A5,A6,A7,A8,A9,A10,A11,A12,A13,A14,A15,A16,A17,A18,A19,A20,B1,B2,B3,B4,B8,C1,C2,C4,C5,C6,C7,D1,D4,E1,E2,E3,E4,E5,E6"

# D5 的绑定值：由采集版在目标设备上自报（Android 8+ 的 ANDROID_ID 按签名作用域化，
# adb 取不到应用内看到的值）。三个应用用同一张测试证书签名，故共用同一个值。
BIND="$(cat "$OUT/d5value.txt" 2>/dev/null)"
if [ -z "$BIND" ]; then
  echo "错误：缺少 $OUT/d5value.txt（先跑 wsl-emu-capture-d5.sh 采集）" >&2
  exit 1
fi
echo "D5 绑定值：$BIND"

build() {  # $1=app $2=标签 $3=功能项
  local app=$1 tag=$2 feats=$3
  local src="$REPO/realworld/apps/$app.apk"
  [ -f "$src" ] || { echo "跳过 $app（缺 $src）"; return; }
  echo "=== $app / $tag ==="
  "$AG" -in "$src" -out "$OUT/$app-$tag.apk" $KS_ARGS \
        -enable "$feats" $EXTRA -bind-device "$BIND" -seed "$app" \
        >"$OUT/$app-$tag.log" 2>&1
  local rc=$?
  if [ "${PORTABLE_TAG:-}" = "1" ] && [ "$tag" = "PORTABLE" ]; then
    # E4 会追加渠道后缀；PORTABLE 想留一个不带后缀的干净名字，移动一下。
    [ -f "$OUT/$app-$tag-emu.apk" ] && mv "$OUT/$app-$tag-emu.apk" "$OUT/$app-$tag.apk"
    echo "  rc=$rc  -> $app-$tag.apk"
  else
    echo "  rc=$rc  -> $app-$tag-emu.apk"
  fi
  [ $rc -ne 0 ] && tail -6 "$OUT/$app-$tag.log"
}

for app in dhizuku termux rustdesk; do
  build "$app" ALL "$ALL"
  build "$app" NODETECT "$NODETECT"
  # PORTABLE 不要 -emu 后缀：文件名里的 emu 表示「D5 按模拟器采样绑定」，它没有绑定。
  PORTABLE_TAG=1 build "$app" PORTABLE "$PORTABLE"
done

echo
echo "== 产物 =="
ls -la "$OUT"/*-ALL-emu.apk "$OUT"/*-NODETECT-emu.apk 2>/dev/null | awk '{print $5, $9}'