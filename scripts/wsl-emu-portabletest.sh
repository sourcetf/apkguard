#!/usr/bin/env bash
# 验证 PORTABLE 变体（去掉 D2/D3/D5）在模拟器上能正常运行。
set -uo pipefail
REPO=/mnt/c/Users/admin/Desktop/apkguard
OUT=$REPO/realworld/emu-out
SDK=$HOME/android-sdk
export PATH=$SDK/platform-tools:$PATH
ADB="adb -s emulator-5554"

run() {  # $1=app $2=pkg $3=act
  local app=$1 pkg=$2 act=$3
  echo "---- $app / PORTABLE ----"
  $ADB uninstall "$pkg" >/dev/null 2>&1
  $ADB install -r -t "$OUT/$app-PORTABLE.apk" 2>&1 | tr -d '\r' | tail -1 | sed 's/^/   安装: /'
  $ADB shell am force-stop "$pkg"
  $ADB logcat -c
  $ADB shell am start -n "$pkg/$act" >/dev/null 2>&1
  local n=0
  for _ in $(seq 1 12); do
    sleep 1
    [ -n "$($ADB shell pidof "$pkg" 2>/dev/null | tr -d '\r')" ] && n=$((n + 1))
  done
  echo "   存活 $n/12"
  echo "   崩溃/异常: $($ADB logcat -d 2>/dev/null | tr -d '\r' | grep -cE 'FATAL EXCEPTION|VerifyError|ClassNotFoundException|NoClassDefFoundError|UnsatisfiedLinkError')"
  echo "   壳降级日志: $($ADB logcat -d 2>/dev/null | tr -d '\r' | grep -c 'APKGUARD: C6:')"
}

run dhizuku com.rosan.dhizuku .ui.activity.SettingsActivity
run rustdesk com.carriez.flutter_hbb .MainActivity