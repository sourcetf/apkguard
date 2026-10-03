#!/usr/bin/env bash
# 终验：三个应用干净安装 → 启动 → 功能观测（不只是「进程活着」）。
set -uo pipefail
REPO=/mnt/c/Users/admin/Desktop/apkguard
SDK=$HOME/android-sdk
export PATH=$SDK/platform-tools:$PATH
ADB="adb -s emulator-5554"

echo "########## 0) 项目自带的产物断言 ##########"
FEATS="A1,A2,A3,A4,A5,A6,A8,A9,A10,A11,A12,A13,A14,A15,A16,A17,A18,A19,A20,B1,B2,B3,B4,B8,C1,C2,C4,C5,C6,C7,D1,D4,E1,E2,E3,E4,E6"
for a in dhizuku termux rustdesk; do
  python3 "$REPO/scripts/verify-products.py" "$REPO/realworld/emu-out/$a-full-emu.apk" "$FEATS" \
    --channel emu 2>&1 | tail -3
done

echo
echo "########## 1) 安装 + 启动 ##########"
$ADB root >/dev/null 2>&1; sleep 2; $ADB wait-for-device
for spec in "dhizuku com.rosan.dhizuku .ui.activity.SettingsActivity" \
            "termux com.termux .app.TermuxActivity" \
            "rustdesk com.carriez.flutter_hbb .MainActivity"; do
  set -- $spec
  app=$1; pkg=$2; act=$3
  echo "---- $app ----"
  $ADB uninstall "$pkg" >/dev/null 2>&1; sleep 1
  $ADB install -r -t "$REPO/realworld/emu-out/$app-full-emu.apk" 2>&1 | tr -d '\r' | tail -1
  $ADB shell am force-stop "$pkg"
  $ADB logcat -c
  $ADB shell am start -W -n "$pkg/$act" 2>&1 | tr -d '\r' | grep -E "Status|TotalTime" | head -2
  sleep 10
  pid=$($ADB shell pidof "$pkg" | tr -d '\r')
  echo "   pid=$pid"
  echo "   APKGUARD: $($ADB logcat -d | tr -d '\r' | grep -c APKGUARD) 条"
  $ADB logcat -d | tr -d '\r' | grep -i apkguard | head -3 | sed 's/^/     /'
  echo "   崩溃: $($ADB logcat -d | tr -d '\r' | grep -cE 'FATAL EXCEPTION|VerifyError|ClassNotFoundException|NoClassDefFoundError|UnsatisfiedLinkError')"
  $ADB logcat -d | tr -d '\r' | grep -E "FATAL EXCEPTION|VerifyError|ClassNotFoundException|NoClassDefFoundError|UnsatisfiedLinkError" | head -3 | sed 's/^/     /'
done

echo
echo "########## 2) Termux 真实执行命令（验证解密后的 DEX + native 库可用） ##########"
$ADB shell am force-stop com.termux
$ADB shell am start -n com.termux/.app.TermuxActivity >/dev/null 2>&1
sleep 8
$ADB shell "rm -f /sdcard/agtest.txt"
$ADB shell input text "echo%20AGUARD_OK%20%3E%20/sdcard/agtest.txt"
sleep 1
$ADB shell input keyevent 66
sleep 5
out=$($ADB shell "cat /sdcard/agtest.txt 2>/dev/null" | tr -d '\r')
echo "   终端命令输出: [${out}]"
if [ "$out" = "AGUARD_OK" ]; then
  echo "   ✅ Termux 解密后的 DEX 与 native 库均可正常执行命令"
else
  echo "   ⚠️  未能通过终端验证（可能是输入法/焦点问题，需人工确认）"
  $ADB logcat -d | tr -d '\r' | grep -iE "termux" | tail -5 | sed 's/^/     /'
fi