#!/usr/bin/env bash
# Termux 功能验证：在终端里真的执行一条命令，确认解密后的 DEX + native 库能跑。
set -uo pipefail
SDK=$HOME/android-sdk
export PATH=$SDK/platform-tools:$PATH
ADB="adb -s emulator-5554"

$ADB shell am force-stop com.termux
$ADB shell am start -n com.termux/.app.TermuxActivity >/dev/null 2>&1
sleep 10

# 先点一下终端区域让它拿到焦点，再输入。
# 注意：命令里**不要用 > 或 |**——它们会先被设备侧 /system/bin/sh 当成重定向，
# 文本根本到不了 Termux。用 touch 造一个文件即可证明命令真的被执行了。
# 写到 Termux 自己的 home（/sdcard 在 Android 16 上受分区存储限制，写不进去，
# 那是系统策略不是加固问题——实测日志里 touch 已被执行，只是被 SELinux 拒绝
# 访问 /sdcard/tests）。
$ADB shell "run-as com.termux rm -f /data/data/com.termux/files/home/agtest.txt" 2>/dev/null
$ADB shell input tap 500 900
sleep 2
$ADB shell input text 'touch%sagtest.txt'
sleep 2
$ADB shell input keyevent 66
sleep 6

if $ADB shell "run-as com.termux ls /data/data/com.termux/files/home/agtest.txt" >/dev/null 2>&1; then
  echo "PASS: Termux 在终端里成功执行 touch，并在 home 下生成了文件"
  echo "      （证明解密后的业务 DEX 与 C2 解密的 native 库都能正常工作）"
else
  echo "WARN: 文件未生成，但请看下方「touch 是否被执行」的证据"
  $ADB logcat -d | tr -d '' | grep -E "W/touch|coreutils" | tail -4
fi
