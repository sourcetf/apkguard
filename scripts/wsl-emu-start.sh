#!/usr/bin/env bash
# 在 WSL 里启动 Android 模拟器（后台）并等待其就绪。
set -u

SDK="$HOME/android-sdk"
export ANDROID_HOME="$SDK"
export ANDROID_SDK_ROOT="$SDK"
export PATH="$SDK/platform-tools:$SDK/emulator:$PATH"

echo "== avds =="
"$SDK/emulator/emulator" -list-avds || true

if adb devices 2>/dev/null | grep -q "emulator-5554"; then
  echo "== 模拟器已在运行 =="
  adb -s emulator-5554 shell getprop ro.build.version.sdk
  exit 0
fi

echo "== 启动模拟器 =="
nohup "$SDK/emulator/emulator" -avd anx36 -no-snapshot -no-audio -no-boot-anim \
  >/tmp/emu.log 2>&1 &
echo "pid=$!"

echo "== 等待 adb 设备 =="
for i in $(seq 1 120); do
  if adb devices | grep -q "emulator-5554"; then
    echo "设备出现（第 ${i} 次轮询）"
    break
  fi
  sleep 5
done

adb wait-for-device
echo "== 等待开机完成 =="
for i in $(seq 1 120); do
  b=$(adb -s emulator-5554 shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')
  if [ "$b" = "1" ]; then
    echo "开机完成（第 ${i} 次轮询）"
    break
  fi
  sleep 5
done

adb -s emulator-5554 shell getprop ro.build.version.sdk
adb -s emulator-5554 shell getprop ro.build.version.release
adb -s emulator-5554 shell getprop ro.product.cpu.abi
echo "== done =="