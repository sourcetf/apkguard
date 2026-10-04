#!/usr/bin/env bash
# 点击后：确认插件是否被加载（maps / oat / 插件目录）。
set -uo pipefail
SDK=$HOME/android-sdk
export PATH=$SDK/platform-tools:$PATH
ADB="adb -s emulator-5554"
PKG=nu.pyokn.yyqfzjtrpk.scz

p=$($ADB shell pidof "$PKG" | tr -d '\r' | awk '{print $1}')
echo "== pid=$p 的 maps 里的 apk/dex/oat（排除系统与 WebView） =="
$ADB shell "grep -oE '/[^ ]*\.(apk|dex|oat|vdex)' /proc/$p/maps 2>/dev/null | grep -vE '^/system|^/apex|^/vendor|WebView|Trichrome' | sort -u" | tr -d '\r'

echo
echo "== cache/ 下的文件 =="
$ADB shell "find /data/user/0/$PKG/cache -type f 2>/dev/null" | tr -d '\r'

echo
echo "== 插件目录（外部存储） =="
$ADB shell "ls -la /sdcard/Android/data/$PKG/files/ 2>/dev/null; ls -la /sdcard/Android/data/$PKG/files/plugins/ 2>/dev/null" | tr -d '\r'

echo
echo "== 应用私有 files/ =="
$ADB shell "find /data/user/0/$PKG/files -type f 2>/dev/null" | tr -d '\r'

echo
echo "== logcat 里与加载/反射/插件相关的行 =="
$ADB logcat -d 2>/dev/null | tr -d '\r' | grep -iE "pyokn|dex|oat|classloader|asset" | grep -viE "ImsResolver|PackageUpdated|AppIndexer|Blockstore" | head -12