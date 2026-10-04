#!/usr/bin/env bash
# SIV 迁移后的装机复验：三个真实应用 + B5 抽取产物 + B9 宿主。
#
# 为什么要单独一轮：载荷解密从 JCA 的 AES/CBC 换成了原生库的 Native.sivDecrypt，
# 这条链路只有真机 ART + 真 .so 才能证明（JNI 签名、库名/ABI、loadLibrary 时机、
# SIV 校验失败时的硬终止行为，本地解释器桩都覆盖不到）。
set -uo pipefail

REPO=/mnt/c/Users/admin/Desktop/apkguard
OUT=$REPO/realworld/emu-out
SDK=$HOME/android-sdk
export PATH=$SDK/platform-tools:$PATH
ADB="adb -s emulator-5554"
HOST_PKG=com.vpylfbp.lrkekfwxe

echo "################ 0) 重建产物（三个应用 + B5 + B9）################"
bash "$REPO/scripts/wsl-emu-all.sh" 2>&1 | tail -10

(cd "$REPO/apkguard" && go build -o "$OUT/apkguard-linux" ./cmd/apkguard)
AG="$OUT/apkguard-linux"
KS="-ks $REPO/realworld/apps/test.p12 -ks-pass apkguard"

echo "-- B5 抽取产物 --"
"$AG" -in "$REPO/realworld/apps/dhizuku.apk" -out "$OUT/dhizuku-B5-emu.apk" $KS \
      -enable "A1,A2,A3,A4,A5,A8,A11,A14,B1,B2,B3,B5,E1,E2,E3,E6" \
      -extract-methods 50 -seed dhizuku-b5 >"$OUT/dhizuku-B5-emu.log" 2>&1
echo "   rc=$? $(grep -a 'B5.extracted' "$OUT/dhizuku-B5-emu.log" | head -1)"

echo "-- B9 宿主 --"
"$AG" -in "$REPO/realworld/apps/dhizuku.apk" -out "$OUT/dhizuku-B9-host.apk" $KS \
      -enable "A1,A4,B1,B2,B3,B9,A14,E1,E2,E3,E6" -dual-apk -seed b9emu \
      >"$OUT/dhizuku-B9-host.log" 2>&1
echo "   rc=$?"

echo "################ 1) 起模拟器 ################"
bash "$REPO/scripts/wsl-emu-start.sh" 2>&1 | tail -4
$ADB wait-for-device

echo "################ 2) 三个真实应用的 NODETECT/ALL 复验 ################"
bash "$REPO/scripts/wsl-emu-alltest.sh" 2>&1 | tail -45

echo "################ 3) B5 与 B9 的专项复验 ################"
$ADB uninstall com.rosan.dhizuku >/dev/null 2>&1
echo -n "  B5 安装: "; $ADB install -r -t "$OUT/dhizuku-B5-emu.apk" 2>&1 | tr -d '\r' | tail -1
$ADB logcat -c
$ADB shell am start -n com.rosan.dhizuku/.ui.activity.SettingsActivity >/dev/null 2>&1
alive=0; for _ in $(seq 1 12); do sleep 1; [ -n "$($ADB shell pidof com.rosan.dhizuku 2>/dev/null | tr -d '\r')" ] && alive=$((alive + 1)); done
echo "  B5 存活: $alive / 12 秒"
echo "  B5 真实异常: $($ADB logcat -d 2>/dev/null | tr -d '\r' | grep -cE 'FATAL EXCEPTION|VerifyError|UnsatisfiedLinkError|ClassNotFoundException|NoClassDefFoundError')"
$ADB logcat -d 2>/dev/null | tr -d '\r' | grep -E "FATAL EXCEPTION|UnsatisfiedLinkError|VerifyError" | head -3 | sed 's/^/    /'

$ADB uninstall "$HOST_PKG" >/dev/null 2>&1
echo -n "  B9 宿主安装: "; $ADB install -r -t "$OUT/dhizuku-B9-host.apk" 2>&1 | tr -d '\r' | tail -1
$ADB logcat -c
$ADB shell am start -n "$HOST_PKG/.B" >/dev/null 2>&1
sleep 15
echo "  宿主 pid: $($ADB shell pidof "$HOST_PKG" | tr -d '\r')"
echo "  B9 真实异常: $($ADB logcat -d 2>/dev/null | tr -d '\r' | grep -cE 'FATAL EXCEPTION|UnsatisfiedLinkError|VerifyError')"
$ADB logcat -d 2>/dev/null | tr -d '\r' | grep -E "FATAL EXCEPTION|UnsatisfiedLinkError|VerifyError" | head -3 | sed 's/^/    /'
echo "  落地目录:"
$ADB shell ls -la "/sdcard/Android/data/$HOST_PKG/files/plugins/" 2>/dev/null | tr -d '\r' | sed 's/^/    /'
DROPPED=$($ADB shell ls "/sdcard/Android/data/$HOST_PKG/files/plugins/" 2>/dev/null | tr -d '\r' | head -1)
if [ -n "$DROPPED" ]; then
  $ADB pull "/sdcard/Android/data/$HOST_PKG/files/plugins/$DROPPED" /tmp/dropped.apk >/dev/null 2>&1
  export PATH=$SDK/build-tools/34.0.0:$PATH
  echo -n "  落地文件包名: "; aapt2 dump badging /tmp/dropped.apk 2>&1 | head -1
fi

echo "=== DONE ==="
for _ in $(seq 1 40); do sleep 20; done
