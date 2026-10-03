#!/usr/bin/env bash
# 把三个加固产物装进模拟器并做功能观测。
#
# 用法：wsl.exe -d Ubuntu-26.04 -- bash /mnt/c/.../scripts/wsl-emu-test.sh
set -uo pipefail

REPO=/mnt/c/Users/admin/Desktop/apkguard
OUT=$REPO/realworld/emu-out
SDK=$HOME/android-sdk
export PATH=$SDK/platform-tools:$PATH
DEV=emulator-5554
ADB="adb -s $DEV"

echo "== 设备 =="
$ADB devices | tail -2
$ADB shell getprop ro.build.version.sdk
$ADB shell getprop ro.build.version.release

fail=0
ok=0
report() { printf '%-10s %-8s %s\n' "$1" "$2" "$3"; }

for app in dhizuku termux rustdesk; do
  apk="$OUT/$app-full-emu.apk"
  [ -f "$apk" ] || { report "$app" "SKIP" "缺产物"; continue; }

  echo
  echo "================ $app ================"
  echo "-- install"
  inst=$($ADB install -r -t "$apk" 2>&1 | tr -d '\r')
  echo "$inst" | tail -3
  if ! echo "$inst" | grep -qi "Success"; then
    report "$app" "FAIL" "安装失败"
    fail=$((fail+1)); continue
  fi

  # 从安装输出里拿包名
  pkg=$(echo "$inst" | sed -n 's/.*Success.*//p' >/dev/null; true)
  pkg=$($ADB shell pm list packages -3 | tr -d '\r' | sed 's/package://' | grep -i -E "$app" | head -1)
  if [ -z "$pkg" ]; then
    pkg=$($ADB shell pm list packages -3 | tr -d '\r' | sed 's/package://' | grep -i -E "dhizuku|termux|carriez|rustdesk" | head -1)
  fi
  echo "  包名: $pkg"

  # 启动
  $ADB logcat -c || true
  launcher=$($ADB shell "cmd package resolve-activity --brief $pkg" 2>/dev/null | tr -d '\r' | tail -1)
  echo "  launcher: $launcher"
  if [ -n "$launcher" ] && [ "$launcher" != "No activity found" ]; then
    $ADB shell am start -W -n "$launcher" 2>&1 | tr -d '\r' | tail -4
  else
    $ADB shell monkey -p "$pkg" -c android.intent.category.LAUNCHER 1 2>&1 | tr -d '\r' | tail -3
  fi

  sleep 12

  # 进程是否还在
  pid=$($ADB shell pidof "$pkg" 2>/dev/null | tr -d '\r')
  crash=$($ADB logcat -d 2>/dev/null | tr -d '\r' | grep -E "FATAL EXCEPTION|AndroidRuntime.*E |beginning of crash" | head -5)

  if [ -n "$crash" ]; then
    report "$app" "FAIL" "logcat 有崩溃"
    echo "$crash" | head -5
    fail=$((fail+1))
  elif [ -z "$pid" ]; then
    report "$app" "WARN" "进程不在（可能已退出）"
  else
    report "$app" "PASS" "pid=$pid"
    ok=$((ok+1))
  fi

  # 抓当前前台 Activity
  $ADB shell dumpsys activity activities 2>/dev/null | grep -m1 "ResumedActivity" | tr -d '\r' | sed 's/^/  /'
done

echo
echo "== 汇总：通过 $ok，失败 $fail =="
exit $fail