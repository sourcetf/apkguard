#!/usr/bin/env bash
# 深挖样本运行时的加载方式：内层 APK 是否落地、DEX 如何加载、UI 显示什么。
set -uo pipefail
REPO=/mnt/c/Users/admin/Desktop/apkguard
SDK=$HOME/android-sdk
export PATH=$SDK/platform-tools:$PATH
ADB="adb -s emulator-5554"
PKG=nu.pyokn.yyqfzjtrpk.scz
OUT=$REPO/tmpwork/sample-recon/mine
mkdir -p "$OUT"

echo "== cache/ 与 files/ 全量（找解密落地的载荷） =="
$ADB shell "find /data/data/$PKG/cache /data/data/$PKG/files /data/data/$PKG/code_cache -type f 2>/dev/null | head -40" | tr -d '\r' | sed 's/^/   /'

echo
echo "== 各目录大小 =="
$ADB shell "du -a /data/data/$PKG 2>/dev/null | sort -rn | head -20" | tr -d '\r' | sed 's/^/   /'

echo
echo "== 进程 maps 里的 dex/apk/oat（加载方式的关键证据） =="
p=$($ADB shell pidof "$PKG" | tr -d '\r' | awk '{print $1}')
echo "   pid=$p"
$ADB shell "grep -oE '/[^ ]*\.(dex|apk|oat|vdex|jar)' /proc/$p/maps 2>/dev/null | sort -u" | tr -d '\r' | sed 's/^/   /'

echo
echo "== 已打开的文件（fd）里是否有解密出的载荷 =="
$ADB shell "ls -l /proc/$p/fd 2>/dev/null | grep -vE 'socket|pipe|anon_inode|/dev/|/system/|/apex/|/data/dalvik-cache' | head -20" | tr -d '\r' | sed 's/^/   /'

echo
echo "== 应用自身的日志（DEX/oat/加载相关） =="
$ADB logcat -d 2>/dev/null | tr -d '\r' | grep -iE "pyokn|DexClassLoader|InMemoryDex|dex2oat|ClassLoader|loadDex|VJ5" | grep -v ImsResolver | head -15

echo
echo "== 截图 =="
$ADB shell screencap -p /sdcard/sample.png 2>/dev/null
$ADB pull /sdcard/sample.png "$OUT/sample-screen.png" 2>&1 | tail -1
ls -la "$OUT/sample-screen.png" 2>/dev/null

echo
echo "== 顶层 Activity 层级（看 UI 是什么） =="
$ADB shell dumpsys activity top 2>/dev/null | tr -d '\r' | grep -E "ACTIVITY|View Hierarchy|mResumed|Added Fragments|WebView" | head -10