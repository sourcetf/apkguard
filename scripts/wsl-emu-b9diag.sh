#!/usr/bin/env bash
# B9 宿主的装机诊断：装上跑一次，把宿主的日志（含异常栈）与落地目录打出来。
set -uo pipefail

REPO=/mnt/c/Users/admin/Desktop/apkguard
OUT=$REPO/realworld/emu-out
SDK=$HOME/android-sdk
export PATH=$SDK/platform-tools:$PATH
ADB="adb -s emulator-5554"
HOST_PKG=com.vpylfbp.lrkekfwxe

bash "$REPO/scripts/wsl-emu-start.sh" 2>&1 | tail -4
$ADB wait-for-device

echo "== 安装宿主 =="
$ADB uninstall "$HOST_PKG" >/dev/null 2>&1
$ADB install -r -t "$OUT/dhizuku-B9-host.apk" 2>&1 | tr -d '\r' | tail -1

echo "== 启动并抓日志 =="
$ADB logcat -c
$ADB shell am start -W -n "$HOST_PKG/.B" 2>&1 | tr -d '\r' | grep -E "Status|Error|TotalTime" | head -4
sleep 10

$ADB logcat -d > /tmp/b9log.txt 2>&1
echo "日志行数: $(wc -l < /tmp/b9log.txt)"
echo "---- 本应用相关 ----"
grep -aE "$HOST_PKG|AndroidRuntime|FATAL|Caused by" /tmp/b9log.txt | head -30 | sed 's/^/  /'

echo "---- 进程状态 ----"
$ADB shell ps -A 2>/dev/null | tr -d '\r' | grep -c "$HOST_PKG"
echo "---- 落地目录 ----"
$ADB shell ls -la "/sdcard/Android/data/$HOST_PKG/files/" 2>/dev/null | tr -d '\r' | sed 's/^/  /'
$ADB shell ls -la "/sdcard/Android/data/$HOST_PKG/files/plugins/" 2>/dev/null | tr -d '\r' | sed 's/^/  /'
echo "---- 私有目录 ----"
$ADB shell run-as "$HOST_PKG" ls -la files/ 2>/dev/null | tr -d '\r' | sed 's/^/  /'

echo "=== DIAG DONE ==="
for _ in $(seq 1 30); do sleep 20; done
