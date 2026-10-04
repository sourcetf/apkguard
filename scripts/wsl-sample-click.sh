#!/usr/bin/env bash
# 点下样本的「Update Now」，观察它是否解密内层真 APK 并落地/安装。
set -uo pipefail
REPO=/mnt/c/Users/admin/Desktop/apkguard
SDK=$HOME/android-sdk
export PATH=$SDK/platform-tools:$PATH
ADB="adb -s emulator-5554"
PKG=nu.pyokn.yyqfzjtrpk.scz
OUT=$REPO/tmpwork/sample-recon/mine

snap() {
  $ADB shell "find /data/user/0/$PKG -type f -newermt '-10 minutes' 2>/dev/null | head -30" | tr -d '\r'
}

echo "== 点击前：私有目录状态 =="
$ADB shell "du -a /data/user/0/$PKG 2>/dev/null | sort -rn | head -10" | tr -d '\r' | sed 's/^/   /'

echo
echo "== 点击 Update Now（屏幕 1080x2400，按钮中心约 (540,1470)） =="
$ADB logcat -c
$ADB logcat -b events -c
$ADB shell input tap 540 1470
sleep 6
$ADB shell input tap 540 1470
sleep 10

echo
echo "== 点击后：新出现的文件 =="
snap | sed 's/^/   /'

echo
echo "== 私有目录大小变化 =="
$ADB shell "du -a /data/user/0/$PKG 2>/dev/null | sort -rn | head -14" | tr -d '\r' | sed 's/^/   /'

echo
echo "== 是否有 .apk/.dex 落地 =="
$ADB shell "find /data/user/0/$PKG /sdcard/Android/data/$PKG -name '*.apk' -o -name '*.dex' -o -name '*.zip' 2>/dev/null | head -20" | tr -d '\r' | sed 's/^/   /'

echo
echo "== 安装/FileProvider 相关事件与日志 =="
$ADB logcat -d -b events 2>/dev/null | tr -d '\r' | grep -iE "install|package|intent" | head -12 | sed 's/^/   /'
$ADB logcat -d 2>/dev/null | tr -d '\r' | grep -iE "FileProvider|application/vnd.android.package|PackageInstaller|REQUEST_INSTALL|startActivity|pyokn" | grep -v ImsResolver | head -12 | sed 's/^/   /'

echo
echo "== 前台界面 =="
$ADB shell dumpsys activity activities 2>/dev/null | grep -m2 -E "ResumedActivity|topResumedActivity" | tr -d '\r' | sed 's/^/   /'

echo
echo "== 截图（点击后） =="
$ADB shell screencap -p /sdcard/sample2.png 2>/dev/null
$ADB pull /sdcard/sample2.png "$OUT/sample-screen-after.png" 2>&1 | tail -1