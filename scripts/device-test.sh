#!/usr/bin/env bash
# 装机实测：把加固产物逐个装到已连接的设备/模拟器上并检查运行时行为。
#
# 为什么需要它：签名、对齐、结构自检都只能证明「包是合法的」，证明不了
# 「装上去能用」。真实崩溃（VerifyError / ClassNotFoundException /
# UnsatisfiedLinkError / 资源找不到）只有跑起来才暴露，而且 ART 的结构校验
# 比 dex2oat --compiler-filter=verify 严格得多。
#
# 用法：
#   bash scripts/device-test.sh [产物目录，默认 deliver]
#
# 环境变量：
#   ADB             adb 可执行文件（默认取 PATH 里的 adb）
#   SERIAL          目标设备序列号（默认 adb 选中的唯一设备）
#   PACKAGE         被测应用包名（默认 com.agtest）
#   WAIT_SECS       启动后等待秒数（默认 6）
#   ROOTED_DEVICE   设备已 root/是模拟器时设为 1：带 D2/D3 的包会被拦停，
#                   这时「被拦停」是**预期行为**而不是缺陷
#
# 前置：先跑 scripts/e2e.sh 或 ci-local.sh 生成产物。
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$ROOT/deliver}"
ADB="${ADB:-adb}"
PKG="${PACKAGE:-com.agtest}"
WAIT="${WAIT_SECS:-6}"
ROOTED="${ROOTED_DEVICE:-0}"

if [ -n "${SERIAL:-}" ]; then ADB="$ADB -s $SERIAL"; fi

if ! $ADB get-state >/dev/null 2>&1; then
  echo "错误：没有可用的设备（adb devices 看不到 device 状态的目标）" >&2
  exit 1
fi

# 期望表：<产物名> <期望: running|blocked> <说明>
# blocked 表示「按设计应被拦截」（Root/模拟器/设备绑定命中），
# 此时进程应当退出，且日志里**不应**出现 VerifyError 之类的结构性错误。
EXPECT() {
  case "$1" in
    S0-plain.apk|S1-obf.apk|1-shell-only.apk|D1-debug-shell.apk|\
    4-obf-full.apk|5-res-a5-only.apk|6-channels-huawei.apk|6-channels-xiaomi.apk)
      echo "running 基线/常规包应当正常运行" ;;
    2-full-checks.apk|D2-debug-full.apk)
      if [ "$ROOTED" = "1" ]; then
        echo "blocked 含 D2/D3，在 root/模拟器上命中属设计行为"
      else
        echo "running 真机上 D2/D3 不应命中"
      fi ;;
    3-device-bind.apk)
      echo "blocked D5 绑定了不存在的设备标识，应被拦停" ;;
    *)
      echo "running 未登记，按应当正常运行处理" ;;
  esac
}

# 结构性错误：出现即视为产物损坏（与被检测拦停是两回事）
FATAL_RE='VerifyError|ClassNotFoundException|NoClassDefFoundError|UnsatisfiedLinkError|FATAL EXCEPTION|invalid branch target|Resources.NotFoundException|Bad shorty|Bogus handler'

pass=0; fail=0; skipped=0
for apk in "$OUT"/*.apk; do
  [ -f "$apk" ] || continue
  name="$(basename "$apk")"
  read -r want reason <<<"$(EXPECT "$name")"
  printf '\n=== %s（期望 %s：%s）===\n' "$name" "$want" "$reason"

  $ADB uninstall "$PKG" >/dev/null 2>&1
  if ! out="$($ADB install -r -t "$apk" 2>&1)"; then
    printf '  安装失败：\n%s\n' "$out"
    fail=$((fail+1)); continue
  fi
  printf '  安装成功\n'

  $ADB logcat -c >/dev/null 2>&1
  $ADB shell monkey -p "$PKG" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
  sleep "$WAIT"

  pid="$($ADB shell pidof "$PKG" 2>/dev/null | tr -d '\r')"
  logs="$($ADB logcat -d -v brief 2>/dev/null)"
  fatal="$(printf '%s' "$logs" | grep -E "$FATAL_RE" | head -3)"
  alive=0; [ -n "$pid" ] && alive=1

  # 壳与业务日志用于区分「壳跑起来了」和「压根没启动」
  shell_log="$(printf '%s' "$logs" | grep -cE 'APKGUARD|AG[0-9] ' || true)"
  app_log="$(printf '%s' "$logs" | grep -c 'AGTEST' || true)"
  printf '  进程存活=%s  壳日志=%s 条  业务日志=%s 条\n' "$alive" "$shell_log" "$app_log"

  ok=1
  case "$want" in
    running)
      [ "$alive" = 1 ] || { echo "  ✗ 进程未存活（期望正常运行）"; ok=0; }
      [ "$app_log" -gt 0 ] || { echo "  ✗ 没有看到业务日志 AGTEST（MainActivity 可能没起来）"; ok=0; }
      ;;
    blocked)
      # 判据是「进程确实退出了」。非排障版的壳不写任何日志，因此不能要求
      # 必须有壳日志——那会把「按设计拦停」误判成失败。
      # 想拿到日志级证据就用 D1-debug-shell / D2-debug-full 这两个排障版。
      [ "$alive" = 0 ] || { echo "  ✗ 进程仍在运行（期望被拦停）"; ok=0; }
      if [ "$shell_log" -eq 0 ] && [ "$alive" = 0 ]; then
        echo "  · 非排障版壳不写日志，仅以「进程已退出」为判据（日志证据见 *-debug-*.apk）"
      fi
      ;;
  esac
  if [ -n "$fatal" ]; then
    echo "  ✗ 出现结构性错误："; printf '%s\n' "$fatal" | sed 's/^/      /'; ok=0
  fi

  if [ "$ok" = 1 ]; then echo "  ✓ 符合预期"; pass=$((pass+1));
  else fail=$((fail+1)); fi
done

printf '\n=========== 装机实测汇总：通过 %d，失败 %d，跳过 %d ===========\n' "$pass" "$fail" "$skipped"
[ "$fail" = 0 ] || exit 1
echo "装机实测通过 ✅"
