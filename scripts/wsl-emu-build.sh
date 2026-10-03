#!/usr/bin/env bash
# 在 WSL 里构建 apkguard 并对三个真实应用做全选项加固，产物落到 Windows 盘。
#
# 用法：wsl.exe -d Ubuntu-26.04 -- bash /mnt/c/.../scripts/wsl-emu-build.sh
set -uo pipefail

REPO=/mnt/c/Users/admin/Desktop/apkguard
OUT=$REPO/realworld/emu-out
SDK=$HOME/android-sdk
export ANDROID_HOME=$SDK
export ANDROID_SDK_ROOT=$SDK
export JAVA_HOME=$HOME/java
export PATH=$HOME/goroot/bin:$JAVA_HOME/bin:$SDK/platform-tools:$PATH

mkdir -p "$OUT"

echo "############ 1) 构建 linux 二进制 ############"
(cd "$REPO/apkguard" && CGO_ENABLED=0 go build -o "$OUT/apkguard-linux" ./cmd/apkguard) || exit 1
AG="$OUT/apkguard-linux"

KS_ARGS="-ks $REPO/realworld/apps/test.p12 -ks-pass apkguard"

# 全选项：41 个已实现项里，去掉 D2（Root 检测）/D3（模拟器检测）——
# 目标模拟器已 root，这两项会**按设计**拦停应用，那是正确行为而非缺陷，
# 会把「应用功能是否完好」这个观测点搅浑。D5 需要真实设备标识，同样排除。
ENABLE="A1,A2,A3,A4,A5,A6,A8,A9,A10,A11,A12,A13,A14,A15,A16,A17,A18,A19,A20,B1,B2,B3,B4,B8,C1,C2,C4,C5,C6,C7,D1,D4,E1,E2,E4,E6"
EXTRA="-channels emu -package-shrink -manifest-pad-mb 8 -so-encrypt -lib-name libguardx.so -payload-mac"

echo
echo "############ 2) 加固三个应用 ############"
for app in dhizuku termux rustdesk; do
  src="$REPO/realworld/apps/$app.apk"
  [ -f "$src" ] || { echo "跳过 $app（缺 $src）"; continue; }
  echo "=== $app ==="
  "$AG" -in "$src" -out "$OUT/$app-full.apk" $KS_ARGS \
        -enable "$ENABLE" $EXTRA -seed "$app" >"$OUT/$app-full.log" 2>&1
  rc=$?
  echo "  rc=$rc  $(grep -c . "$OUT/$app-full.log" 2>/dev/null || echo 0) 行日志"
  [ $rc -ne 0 ] && tail -8 "$OUT/$app-full.log"
done

echo
echo "############ 3) 产物清单 ############"
ls -la "$OUT"/*.apk 2>/dev/null
echo "== done =="