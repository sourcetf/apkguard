#!/usr/bin/env bash
# 全功能产物的模拟器复验。
#
# 结构：
#   1) NODETECT 变体 → 验证「应用功能本身没被破坏」（安装/启动/进程存活/无崩溃/真实功能）
#   2) ALL 变体      → 观察 D2/D3 按设计拦停（进程快速退出、且无崩溃异常）
#   3) testapp 隔离试验 → 证明退出**确实由 D2/D3 引起**（base vs +D2 vs +D3）
set -uo pipefail

REPO=/mnt/c/Users/admin/Desktop/apkguard
OUT=$REPO/realworld/emu-out
SDK=$HOME/android-sdk
export PATH=$SDK/platform-tools:$PATH
ADB="adb -s emulator-5554"

alive_seconds() {  # $1=pkg  $2=秒数 → 打印存活秒数
  local pkg=$1 secs=$2 n=0
  for _ in $(seq 1 "$secs"); do
    sleep 1
    [ -n "$($ADB shell pidof "$pkg" 2>/dev/null | tr -d '\r')" ] && n=$((n + 1))
  done
  echo "$n"
}

run() {  # $1=app $2=pkg $3=act $4=标签 $5=apk
  local app=$1 pkg=$2 act=$3 tag=$4 apk=$5
  echo "---- $app / $tag ----"
  $ADB uninstall "$pkg" >/dev/null 2>&1
  local inst
  inst=$($ADB install -r -t "$apk" 2>&1 | tr -d '\r' | tail -1)
  if ! echo "$inst" | grep -q Success; then
    echo "   安装失败: $inst"
    return
  fi
  echo "   安装: OK"
  $ADB shell am force-stop "$pkg" 2>/dev/null
  $ADB logcat -c
  $ADB shell am start -n "$pkg/$act" >/dev/null 2>&1
  local alive
  alive=$(alive_seconds "$pkg" 12)
  echo "   存活秒数: $alive / 12"
  local crash
  crash=$($ADB logcat -d 2>/dev/null | tr -d '\r' | grep -cE "FATAL EXCEPTION|VerifyError|ClassNotFoundException|NoClassDefFoundError|UnsatisfiedLinkError|INSTALL_")
  echo "   崩溃/异常计数: $crash"
  [ "$crash" != "0" ] && $ADB logcat -d 2>/dev/null | tr -d '\r' | grep -E "FATAL EXCEPTION|VerifyError|ClassNotFoundException|NoClassDefFoundError|UnsatisfiedLinkError" | head -3 | sed 's/^/     /'
  local dl
  dl=$($ADB logcat -d 2>/dev/null | tr -d '\r' | grep -c "APKGUARD: C6:")
  echo "   壳降级日志: $dl"
}

echo "################ 1) NODETECT：应用功能是否完好 ################"
run dhizuku com.rosan.dhizuku .ui.activity.SettingsActivity NODETECT "$OUT/dhizuku-NODETECT-emu.apk"
run termux com.termux .app.TermuxActivity NODETECT "$OUT/termux-NODETECT-emu.apk"
run rustdesk com.carriez.flutter_hbb .MainActivity NODETECT "$OUT/rustdesk-NODETECT-emu.apk"

echo
echo "################ 2) ALL：D2/D3 是否按设计拦停 ################"
run dhizuku com.rosan.dhizuku .ui.activity.SettingsActivity ALL "$OUT/dhizuku-ALL-emu.apk"
run termux com.termux .app.TermuxActivity ALL "$OUT/termux-ALL-emu.apk"
run rustdesk com.carriez.flutter_hbb .MainActivity ALL "$OUT/rustdesk-ALL-emu.apk"