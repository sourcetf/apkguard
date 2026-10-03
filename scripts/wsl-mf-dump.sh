#!/usr/bin/env bash
# 把指定 APK 的 AndroidManifest.xml 用 aapt2 dump 成文本，写到 Windows 盘供分析。
set -uo pipefail
REPO=/mnt/c/Users/admin/Desktop/apkguard
OUT=$REPO/realworld/emu-out
SDK=$HOME/android-sdk
export JAVA_HOME=$HOME/java
export PATH=$JAVA_HOME/bin:$PATH
AAPT2=$SDK/build-tools/34.0.0/aapt2

APK="$1"
DUMP="$OUT/mf-dump.txt"
"$AAPT2" dump xmltree --file AndroidManifest.xml "$APK" > "$DUMP" 2>&1
tr -d '\r' < "$DUMP" > "$DUMP.lf" && mv "$DUMP.lf" "$DUMP"
echo "已写出 $DUMP（$(wc -l < "$DUMP") 行）"