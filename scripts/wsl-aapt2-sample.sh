#!/usr/bin/env bash
# 用 aapt2 独立验证样本的 arsc/Manifest 是否能被标准工具读取。
set -uo pipefail
REPO=/mnt/c/Users/admin/Desktop/apkguard
SDK=$HOME/android-sdk
export JAVA_HOME=$HOME/java
export PATH=$JAVA_HOME/bin:$PATH
AAPT2=$SDK/build-tools/34.0.0/aapt2
APK="$REPO/sample.apk"

echo "== aapt2 dump packagename =="
"$AAPT2" dump packagename "$APK" 2>&1 | head -5

echo
echo "== aapt2 dump badging（前 25 行）=="
timeout 300 "$AAPT2" dump badging "$APK" 2>&1 | head -25

echo
echo "== aapt2 dump resources（前 25 行）=="
timeout 300 "$AAPT2" dump resources "$APK" 2>&1 | head -25

echo
echo "== aapt2 dump xmltree 的 Manifest 前 20 行 =="
timeout 600 "$AAPT2" dump xmltree --file AndroidManifest.xml "$APK" 2>&1 | head -20