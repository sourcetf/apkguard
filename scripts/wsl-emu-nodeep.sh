#!/usr/bin/env bash
# 对 NODETECT（除 D2/D3 外全部功能）产物做深度功能验证：
#   A) Termux 终端里真实执行命令 —— 证明解密后的 DEX + C2 解密的 native 库可用
#   B) 篡改已安装守卫库的 .text —— 证明 C6/D4 看门狗真的会终止进程
#   C) 壳工作目录与已加载库 —— 证明 B1/C2 的落地路径正确
set -uo pipefail

REPO=/mnt/c/Users/admin/Desktop/apkguard
OUT=$REPO/realworld/emu-out
SDK=$HOME/android-sdk
export PATH=$SDK/platform-tools:$PATH
ADB="adb -s emulator-5554"
PKG=com.termux
ACT=.app.TermuxActivity
# 默认用 NODETECT 产物；可用 TERMUX_APK 指定别的（例如 PORTABLE）。
APK=${TERMUX_APK:-$OUT/termux-NODETECT-emu.apk}

$ADB root >/dev/null 2>&1; sleep 2; $ADB wait-for-device

echo "################ A) Termux 真实执行命令 ################"
$ADB uninstall $PKG >/dev/null 2>&1
$ADB install -r -t "$APK" 2>&1 | tr -d '\r' | tail -1
$ADB shell am force-stop $PKG
$ADB shell am start -n "$PKG/$ACT" >/dev/null 2>&1
sleep 10
$ADB shell "run-as $PKG rm -f /data/data/$PKG/files/home/agtest.txt" 2>/dev/null
$ADB shell input tap 500 900
sleep 2
$ADB shell input text 'touch%sagtest.txt'
sleep 2
$ADB shell input keyevent 66
sleep 6
if $ADB shell "run-as $PKG ls /data/data/$PKG/files/home/agtest.txt" >/dev/null 2>&1; then
  echo "  PASS: 终端里成功执行 touch，文件已生成（业务 DEX 与 C2 解密库均可用）"
else
  echo "  WARN: 未生成文件"
  $ADB logcat -d | tr -d '\r' | grep -iE "termux|linker|UnsatisfiedLink" | tail -5
fi

echo
echo "################ C) 壳工作目录 / 已加载库 ################"
echo "  app_ag 目录："
$ADB shell "ls /data/data/$PKG/app_ag 2>/dev/null | head -4" | tr -d '\r' | sed 's/^/    /'
$ADB shell "ls /data/data/$PKG/app_ag 2>/dev/null | wc -l" | tr -d '\r' | sed 's/^/    DEX 份数: /'
p=$($ADB shell pidof $PKG | tr -d '\r' | awk '{print $1}')
echo "  pid=$p"
echo "  应用自己的 .so（maps，排除系统）："
[ -n "$p" ] && $ADB shell "grep -oE '/[^ ]*\.so' /proc/$p/maps | grep -vE '^/apex|^/system|^/vendor' | sort -u" | tr -d '\r' | sed 's/^/    /'

echo
echo "################ B) 篡改 .text → C6/D4 是否终止进程 ################"
read -r TOFF TSIZE <<<"$(python3 - "$APK" <<'PY'
import sys, zipfile, struct
z = zipfile.ZipFile(sys.argv[1])
name = [n for n in z.namelist() if n.startswith("lib/x86_64/") and n.endswith(".so")][0]
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
echo "  .text 偏移=$TOFF 长度=$TSIZE"
# C6/D4 只校验**守卫库**（APK 的 lib/<abi>/ 下那一份）。业务库经 C2 解密后
# 落在 app_aglib/ 并被 mmap 进来，如果按「maps 里第一个非系统 .so」去挑，
# 挑到的是业务库，篡改它当然不会触发看门狗——第一版就踩了这个坑。
LIBNAME=$(basename "$(python3 - "$APK" <<'PY'
import sys, zipfile
z = zipfile.ZipFile(sys.argv[1])
print([n for n in z.namelist() if n.startswith("lib/x86_64/") and n.endswith(".so")][0])
PY
)")
$ADB logcat -b events -c
$ADB shell am force-stop $PKG
sleep 1
$ADB logcat -c
$ADB shell am start -n "$PKG/$ACT" >/dev/null 2>&1
sleep 8
# 只挑守卫库（APK 的 lib/<abi>/ 下那一份）：C6/D4 校验的是它。
# 业务库经 C2 解密后落在 app_aglib/ 并被 mmap 进来，篡改它不会触发看门狗。
lib=$($ADB shell "grep -oE '/[^ ]*\.so' /proc/\$(pidof $PKG)/maps 2>/dev/null | grep -F '$LIBNAME' | head -1" | tr -d '
')
echo "  守卫库（$LIBNAME）: $lib"
if [ -n "$lib" ] && [ -n "$TOFF" ]; then
  $ADB logcat -b events -c
  $ADB shell "dd if=/dev/zero bs=1 count=16 seek=$TOFF conv=notrunc of='$lib' 2>&1 | tail -1" | tr -d '\r' | sed 's/^/  /'
  $ADB shell am force-stop $PKG
  sleep 1
  $ADB shell am start -n "$PKG/$ACT" >/dev/null 2>&1
  sleep 12
  n=$($ADB logcat -d -b events 2>/dev/null | tr -d '\r' | grep -cE "am_proc_died.*termux")
  echo "  篡改后 12 秒内 am_proc_died 次数 = $n（>=1 表示看门狗生效）"
else
  echo "  SKIP：拿不到库路径或 .text 偏移"
fi