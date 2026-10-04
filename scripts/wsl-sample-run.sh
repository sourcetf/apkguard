#!/usr/bin/env bash
# 把样本装进模拟器，观察它真实运行时的行为（这是纯静态分析之外最直接的证据）。
set -uo pipefail
REPO=/mnt/c/Users/admin/Desktop/apkguard
SDK=$HOME/android-sdk
export PATH=$SDK/platform-tools:$PATH
ADB="adb -s emulator-5554"
PKG=nu.pyokn.yyqfzjtrpk.scz

$ADB root >/dev/null 2>&1; sleep 2; $ADB wait-for-device

echo "== 安装 =="
$ADB uninstall "$PKG" >/dev/null 2>&1
$ADB install -r "$REPO/sample.apk" 2>&1 | tr -d '\r' | tail -3

echo
echo "== 已安装信息 =="
$ADB shell dumpsys package "$PKG" 2>/dev/null | tr -d '\r' | grep -E "versionName|codePath|primaryCpuAbi|targetSdk|minSdk|signatures|pkgFlags" | head -8

echo
echo "== 启动 =="
$ADB logcat -c
$ADB shell "cmd package resolve-activity --brief $PKG" 2>&1 | tr -d '\r' | tail -2
$ADB shell monkey -p "$PKG" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
sleep 12

echo
echo "== 进程 =="
$ADB shell "ps -A -o PID,NAME | grep -i pyokn" | tr -d '\r'
$ADB shell pidof "$PKG" | tr -d '\r' | sed 's/^/  pid=/'

echo
echo "== 前台 Activity =="
$ADB shell dumpsys activity activities 2>/dev/null | grep -m2 -E "ResumedActivity|topResumedActivity" | tr -d '\r'

echo
echo "== 崩溃/异常 =="
$ADB logcat -d 2>/dev/null | tr -d '\r' | grep -E "FATAL EXCEPTION|AndroidRuntime|ClassNotFound|VerifyError" | head -8

echo
echo "== 应用私有目录（看它是否解密/释放了内层 APK） =="
$ADB shell "ls -la /data/data/$PKG/ 2>/dev/null" | tr -d '\r' | head -14
for d in cache files no_backup app_*; do
  echo "-- $d"
  $ADB shell "ls -la /data/data/$PKG/$d 2>/dev/null | head -10" | tr -d '\r' | sed 's/^/   /'
done

echo
echo "== 与样本相关的日志 =="
$ADB logcat -d 2>/dev/null | tr -d '\r' | grep -iE "pyokn|vault|qelt|update" | head -10