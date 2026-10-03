#!/usr/bin/env bash
# 采集 D5 的绑定值（ANDROID_ID）。
#
# 为什么要单独采：Android 8+ 起 ANDROID_ID 按「应用签名 + 用户 + 设备」作用域化，
# `adb shell settings get secure android_id` 取到的是原始值，与**应用内**读到的
# 不是同一个串，只能让应用自己报出来。
#
# 为什么关掉 D2/D3：壳里的检测顺序是 D1 → D2 → D3 → D5，而 D2/D3 在本机
# （su 路径存在、Build 字段是模拟器特征）必然命中并 System.exit，D5 根本没机会
# 跑到。采集阶段必须先把这两项关掉。
set -uo pipefail

REPO=/mnt/c/Users/admin/Desktop/apkguard
OUT=$REPO/realworld/emu-out
SDK=$HOME/android-sdk
export ANDROID_HOME=$SDK
export ANDROID_SDK_ROOT=$SDK
export JAVA_HOME=$HOME/java
export PATH=$HOME/goroot/bin:$JAVA_HOME/bin:$SDK/platform-tools:$PATH
ADB="adb -s emulator-5554"

mkdir -p "$OUT"
echo "== 构建 linux 二进制 =="
(cd "$REPO/apkguard" && CGO_ENABLED=0 go build -o "$OUT/apkguard-linux" ./cmd/apkguard) || exit 1
AG="$OUT/apkguard-linux"

ENABLE="A1,A2,A3,A4,A5,A6,A8,A9,A10,A11,A12,A13,A14,A15,A16,A17,A18,A19,A20,B1,B2,B3,B4,B8,C1,C2,C4,C5,C6,C7,D1,D4,D5,E1,E2,E4,E6"
# D2/D3 不启用（否则 D5 跑不到）；D5 用占位值，只为让壳把真实标识打出来。
echo
echo "== 构建采集版（D2/D3 关闭，D5 占位 + -debug-shell） =="
"$AG" -in "$REPO/testapp/testapp-signed.apk" -out "$OUT/d5capture.apk" \
  -ks "$REPO/realworld/apps/test.p12" -ks-pass apkguard \
  -enable "$ENABLE" -bind-device PLACEHOLDER_CAPTURE -debug-shell \
  -package-shrink -payload-mac -channels emu >"$OUT/d5capture.log" 2>&1
echo "  rc=$?"

echo
echo "== 安装并启动 =="
$ADB uninstall com.agtest 2>/dev/null >/dev/null
$ADB install -r -t "$OUT/d5capture-emu.apk" 2>&1 | tr -d '\r' | tail -1
$ADB logcat -c
$ADB shell monkey -p com.agtest -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
sleep 12

echo
echo "== D5 日志（标签 APKGUARD-D5） =="
$ADB logcat -d -s APKGUARD-D5 2>/dev/null | tr -d '\r' | tail -5
echo
echo "== 供复制的绑定值 =="
VAL=$($ADB logcat -d -s APKGUARD-D5 2>/dev/null | tr -d '\r' | sed -n 's/.*APKGUARD-D5 *: *//p' | tail -1)
echo "BIND_DEVICE=$VAL"
echo "$VAL" > "$OUT/d5value.txt"
echo
echo "== 壳进度 Toast（AG1/AG2…）与异常 =="
$ADB logcat -d 2>/dev/null | tr -d '\r' | grep -iE "AG-D5|AG[0-9] |apkguard|AndroidRuntime" | tail -8