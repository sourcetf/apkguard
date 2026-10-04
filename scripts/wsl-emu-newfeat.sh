#!/usr/bin/env bash
# 新增功能项的装机复验：B5（函数抽取的运行时回填）与 B9（双 APK 投放器落地）。
#
# B5 的风险点是「壳加载器在写盘/加载之前把方法体回填进内存 DEX」这条新链路——
# 只有真装上跑起来才算走通；B9 的风险点是宿主能否真的把加密插件解密落地。
set -uo pipefail

REPO=/mnt/c/Users/admin/Desktop/apkguard
OUT=$REPO/realworld/emu-out
SDK=$HOME/android-sdk
export PATH=$SDK/platform-tools:$PATH
ADB="adb -s emulator-5554"
HOST_PKG=com.vpylfbp.lrkekfwxe

echo "################ 1) B5 函数抽取：产物能装、能启动、回填链路在设备上走通 ################"
$ADB uninstall com.rosan.dhizuku >/dev/null 2>&1
echo -n "  安装: "; $ADB install -r -t "$OUT/dhizuku-B5-emu.apk" 2>&1 | tr -d '\r' | tail -1
$ADB shell am force-stop com.rosan.dhizuku >/dev/null 2>&1
$ADB logcat -c
$ADB shell am start -n com.rosan.dhizuku/.ui.activity.SettingsActivity >/dev/null 2>&1
alive=0
for _ in $(seq 1 12); do sleep 1; [ -n "$($ADB shell pidof com.rosan.dhizuku 2>/dev/null | tr -d '\r')" ] && alive=$((alive + 1)); done
echo "  存活秒数: $alive / 12"
crash=$($ADB logcat -d 2>/dev/null | tr -d '\r' | grep -cE "FATAL EXCEPTION|VerifyError|ClassNotFoundException|NoClassDefFoundError|UnsatisfiedLinkError")
echo "  真实异常计数: $crash"
[ "$crash" != "0" ] && $ADB logcat -d 2>/dev/null | tr -d '\r' | grep -E "FATAL EXCEPTION|VerifyError|ClassNotFoundException" | head -3 | sed 's/^/    /'

echo "  -- 私有目录里落盘的 DEX（回填发生在写盘之前）--"
$ADB shell su -c 'ls -la /data/data/com.rosan.dhizuku/files/ 2>/dev/null | head -8' 2>/dev/null | tr -d '\r' | sed 's/^/    /'
$ADB shell su -c 'for f in /data/data/com.rosan.dhizuku/files/*.dex /data/data/com.rosan.dhizuku/files/*/*.dex; do [ -f "$f" ] && echo "$f $(wc -c <"$f") $(head -c 4 "$f" | od -An -tx1 | tr -d " ")"; done' 2>/dev/null | tr -d '\r' | sed 's/^/    /'

echo
echo "################ 2) B9 双 APK 投放器：宿主启动后把插件解密落地 ################"
$ADB uninstall "$HOST_PKG" >/dev/null 2>&1
echo -n "  安装宿主: "; $ADB install -r -t "$OUT/dhizuku-B9-host.apk" 2>&1 | tr -d '\r' | tail -1
$ADB logcat -c
$ADB shell am start -n "$HOST_PKG/.B" >/dev/null 2>&1
sleep 15
alive=0
for _ in $(seq 1 10); do sleep 1; [ -n "$($ADB shell pidof "$HOST_PKG" 2>/dev/null | tr -d '\r')" ] && alive=$((alive + 1)); done
echo "  宿主存活秒数: $alive / 10"
echo "  -- 落地目录 --"
$ADB shell ls -la "/sdcard/Android/data/$HOST_PKG/files/plugins/" 2>/dev/null | tr -d '\r' | sed 's/^/    /'
echo "  -- 落地文件是不是一个真 APK（拉到本地用 aapt2 看包名）--"
DROPPED=$($ADB shell ls "/sdcard/Android/data/$HOST_PKG/files/plugins/" 2>/dev/null | tr -d '\r' | head -1)
if [ -n "$DROPPED" ]; then
  $ADB pull "/sdcard/Android/data/$HOST_PKG/files/plugins/$DROPPED" /tmp/dropped.apk >/dev/null 2>&1
  ls -la /tmp/dropped.apk | awk '{print "    大小:", $5}'
  export PATH=$SDK/build-tools/34.0.0:$PATH
  aapt2 dump badging /tmp/dropped.apk 2>&1 | head -2 | sed 's/^/    /'
else
  echo "    （没找到落地文件）"
fi
echo "  -- 宿主日志（安装器会话相关）--"
$ADB logcat -d 2>/dev/null | tr -d '\r' | grep -iE "PackageInstaller|plugin|install" | head -5 | sed 's/^/    /'

echo
echo "=== DONE ==="
for _ in $(seq 1 40); do sleep 20; done
