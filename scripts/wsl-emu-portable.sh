#!/usr/bin/env bash
# 只构建 PORTABLE 变体（全部功能去掉 D2/D3/D5），供对外分发。
#
# 为什么需要它：ALL/NODETECT 都启用了 D5（绑定到采样那台模拟器的 ANDROID_ID），
# 在别的设备上 D5 校验失败会直接终止进程；ALL 还含 D2/D3，在 Root/模拟器环境
# 一律拦停。要给别人用，就得去掉这三项。
set -uo pipefail

REPO=/mnt/c/Users/admin/Desktop/apkguard
OUT=$REPO/realworld/emu-out
SDK=$HOME/android-sdk
export ANDROID_HOME=$SDK ANDROID_SDK_ROOT=$SDK JAVA_HOME=$HOME/java
export PATH=$HOME/goroot/bin:$JAVA_HOME/bin:$PATH

mkdir -p "$OUT"
(cd "$REPO/apkguard" && CGO_ENABLED=0 go build -o "$OUT/apkguard-linux" ./cmd/apkguard) || exit 1
AG=$OUT/apkguard-linux

PORTABLE="A1,A2,A3,A4,A5,A6,A8,A9,A10,A11,A12,A13,A14,A15,A16,A17,A18,A19,A20,B1,B2,B3,B4,B8,C1,C2,C4,C5,C6,C7,D1,D4,E1,E2,E3,E4,E5,E6"

for app in "$@"; do
  src="$REPO/realworld/apps/$app.apk"
  [ -f "$src" ] || { echo "跳过 $app（缺 $src）"; continue; }
  echo "=== $app / PORTABLE ==="
  "$AG" -in "$src" -out "$OUT/$app-PORTABLE.apk" \
        -ks "$REPO/realworld/apps/test.p12" -ks-pass apkguard \
        -enable "$PORTABLE" \
        -channels emu -package-shrink -manifest-pad-mb 8 \
        -so-encrypt -lib-name libguardx.so -payload-mac -seed "$app" \
        >"$OUT/$app-PORTABLE.log" 2>&1
  rc=$?
  if [ $rc -eq 0 ] && [ -f "$OUT/$app-PORTABLE-emu.apk" ]; then
    mv "$OUT/$app-PORTABLE-emu.apk" "$OUT/$app-PORTABLE.apk"
  fi
  echo "  rc=$rc"
  [ $rc -ne 0 ] && tail -6 "$OUT/$app-PORTABLE.log"
done

ls -la "$OUT"/*-PORTABLE.apk 2>/dev/null | awk '{printf "  %10.1f MB  %s\n", $5/1048576, $9}'