#!/usr/bin/env bash
# 当模拟器跑在 **Windows 侧**（而不是 WSL 里）时的装机复验。
#
# 为什么需要单独一份：WSL 与 Windows 各自有 adb server，WSL 里的 `adb devices`
# 看不到 Windows 起的 emulator-5554（Windows 的 adb 只监听 127.0.0.1:5037）。
# 这份脚本在 Git Bash 里用 Windows 的 adb.exe 跑，只做装机/启动/存活/落地检查，
# 不依赖 WSL 里的 build-tools 与 Go 工具链。
#
# 用法：bash scripts/win-emu-verify.sh [序列号]        # 默认 emulator-5554
# 注意：机器上可能同时挂着真机，脚本**始终**显式 -s "$SERIAL"，绝不误装到真机。
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$REPO/realworld/emu-out"
ADB_BIN="${ADB_BIN:-/c/Android/platform-tools/adb.exe}"
SERIAL="${1:-emulator-5554}"
ADB="$ADB_BIN -s $SERIAL"
HOST_PKG=com.vpylfbp.lrkekfwxe

say() { printf '%s\n' "$*"; }
alive_seconds() { # $1=pkg $2=秒数
  local pkg=$1 secs=$2 n=0
  for _ in $(seq 1 "$secs"); do
    sleep 1
    [ -n "$($ADB shell pidof "$pkg" 2>/dev/null | tr -d '\r')" ] && n=$((n + 1))
  done
  echo "$n"
}
real_crash() { # 真实异常计数（排除安装器 INSTALL_ 噪声）
  $ADB logcat -d 2>/dev/null | tr -d '\r' \
    | grep -cE "FATAL EXCEPTION|VerifyError|ClassNotFoundException|NoClassDefFoundError|UnsatisfiedLinkError"
}

say "== 设备 =="
$ADB_BIN devices | sed -n '1,5p'
say "  目标序列号: $SERIAL"

run_app() { # $1=app $2=pkg $3=act $4=apk
  local app=$1 pkg=$2 act=$3 apk=$4
  say "---- $app ----"
  [ -f "$apk" ] || { say "  缺少产物: $apk"; return; }
  $ADB uninstall "$pkg" >/dev/null 2>&1
  say -n "  安装: "; $ADB install -r -t "$apk" 2>&1 | tr -d '\r' | tail -1
  $ADB shell am force-stop "$pkg" >/dev/null 2>&1
  $ADB logcat -c
  $ADB shell am start -n "$pkg/$act" >/dev/null 2>&1
  say "  存活秒数: $(alive_seconds "$pkg" 12) / 12"
  say "  真实异常: $(real_crash)"
  $ADB logcat -d 2>/dev/null | tr -d '\r' \
    | grep -E "FATAL EXCEPTION|VerifyError|UnsatisfiedLinkError" | head -3 | sed 's/^/    /'
}

say
say "################ 1) 三个真实应用（NODETECT，走 SIV 链路）################"
run_app dhizuku  com.rosan.dhizuku   .ui.activity.SettingsActivity "$OUT/dhizuku-NODETECT-emu.apk"
run_app termux   com.termux         .app.TermuxActivity         "$OUT/termux-NODETECT-emu.apk"
run_app rustdesk com.carriez.flutter_hbb .MainActivity           "$OUT/rustdesk-NODETECT-emu.apk"

say
say "################ 1b) PORTABLE 变体（不带 D2/D3/D5，可在任意设备运行）################"
run_app dhizuku-PORTABLE  com.rosan.dhizuku      .ui.activity.SettingsActivity "$OUT/dhizuku-PORTABLE.apk"
run_app termux-PORTABLE   com.termux            .app.TermuxActivity           "$OUT/termux-PORTABLE.apk"
run_app rustdesk-PORTABLE com.carriez.flutter_hbb .MainActivity               "$OUT/rustdesk-PORTABLE.apk"

say
say "################ 2) ALL 变体：D2/D3 应拦停（0 秒存活 + 0 崩溃）################"
run_app dhizuku-ALL  com.rosan.dhizuku   .ui.activity.SettingsActivity "$OUT/dhizuku-ALL-emu.apk"
run_app termux-ALL   com.termux         .app.TermuxActivity         "$OUT/termux-ALL-emu.apk"

say
say "################ 3) B5 函数抽取产物（stub + 内存回填 + SIV 载荷）################"
run_app dhizuku-B5 com.rosan.dhizuku .ui.activity.SettingsActivity "$OUT/dhizuku-B5-emu.apk"

say
say "################ 4) B9 双 APK 投放器（宿主经原生 SIV 解密插件）################"
$ADB uninstall "$HOST_PKG" >/dev/null 2>&1
say -n "  宿主安装: "; $ADB install -r -t "$OUT/dhizuku-B9-host.apk" 2>&1 | tr -d '\r' | tail -1
$ADB logcat -c
$ADB shell am start -n "$HOST_PKG/.B" >/dev/null 2>&1
sleep 15
say "  宿主 pid: $($ADB shell pidof "$HOST_PKG" 2>/dev/null | tr -d '\r')"
say "  真实异常: $(real_crash)"
say "  落地目录:"
$ADB shell ls -la "/sdcard/Android/data/$HOST_PKG/files/plugins/" 2>/dev/null | tr -d '\r' | sed 's/^/    /'

say
say "=== DONE ==="
