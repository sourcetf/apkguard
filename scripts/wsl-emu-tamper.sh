#!/usr/bin/env bash
# 反例：篡改已安装 guard 库的 .text 内部字节，验证 D4 看门狗确实会终止进程。
# 判据取自 logcat 事件缓冲区（am_proc_died），而不是「pid 在不在」——
# 前台 Activity 的进程被杀死后 ActivityManager 会立刻重启它，pid 始终存在。
set -uo pipefail
REPO=/mnt/c/Users/admin/Desktop/apkguard
SDK=$HOME/android-sdk
export PATH=$SDK/platform-tools:$PATH
ADB="adb -s emulator-5554"
PKG=com.termux
ACT=.app.TermuxActivity

# .text 在 APK 内那份库里的偏移（设备上装载的就是同一份字节）
read TOFF TSIZE <<<"$(python3 - "$REPO/realworld/emu-out/termux-full-emu.apk" <<'PY'
import sys, zipfile, struct
z = zipfile.ZipFile(sys.argv[1])
name = [n for n in z.namelist() if n.endswith("/libguardx.so") and n.startswith("lib/x86_64")][0]
d = z.read(name)
shoff, = struct.unpack_from("<Q", d, 0x28)
shentsize, shnum, shstrndx = struct.unpack_from("<HHH", d, 0x3a)
so, = struct.unpack_from("<Q", d, shoff + shstrndx * shentsize + 0x18)
for k in range(shnum):
    e = shoff + k * shentsize
    no, = struct.unpack_from("<I", d, e)
    end = d.index(b"\0", so + no)
    if d[so + no:end] == b".text":
        off, size = struct.unpack_from("<QQ", d, e + 0x18)
        print(off, size); break
PY
)"
echo ".text 偏移=$TOFF 长度=$TSIZE"

$ADB root >/dev/null 2>&1; sleep 3; $ADB wait-for-device
$ADB uninstall $PKG >/dev/null 2>&1; sleep 1
$ADB install -r -t "$REPO/realworld/emu-out/termux-full-emu.apk" 2>&1 | tr -d '\r' | tail -1

$ADB shell am force-stop $PKG
$ADB logcat -c; $ADB logcat -b events -c
$ADB shell am start -n "$PKG/$ACT" >/dev/null 2>&1
sleep 10
lib=$($ADB shell "grep -oE '/[^ ]*libguardx.so' /proc/\$(pidof $PKG)/maps | head -1" | tr -d '\r')
echo "== 篡改前：进程死亡事件 =="
$ADB logcat -d -b events | tr -d '\r' | grep -cE "am_proc_died.*$PKG" || true
echo "mapped lib = $lib"

if [ -n "$lib" ]; then
  echo "== 篡改 .text@$TOFF（写 16 个 0xFF） =="
  $ADB shell "dd if=/dev/zero bs=1 count=16 seek=$TOFF conv=notrunc of='$lib' 2>&1 | tail -1" | tr -d '\r'
  $ADB logcat -b events -c
  $ADB shell am force-stop $PKG
  sleep 1
  $ADB logcat -c
  $ADB shell am start -n "$PKG/$ACT" >/dev/null 2>&1
  echo "== 篡改后 12 秒内进程死亡事件 =="
  sleep 12
  $ADB logcat -d -b events 2>/dev/null | tr -d '\r' | grep -E "am_proc_died|am_kill" | grep -iE "$PKG|termux" | head -5
  n=$($ADB logcat -d -b events 2>/dev/null | tr -d '\r' | grep -cE "am_proc_died.*termux")
  echo "am_proc_died 次数 = $n"
fi

echo "== 恢复 =="
$ADB uninstall $PKG >/dev/null 2>&1
$ADB install -r -t "$REPO/realworld/emu-out/termux-full-emu.apk" 2>&1 | tr -d '\r' | tail -1