#!/usr/bin/env bash
# 本地 CI：把 .github/workflows/ci.yml 的全部检查在本机跑一遍。
#
# 用途：GitHub Actions 因账号计费问题无法启动作业时（注解为
#   "The job was not started because recent account payments have failed…"），
# 仍能在本地获得同等门禁。提交前跑一遍即可。
#
# 环境变量：
#   ANDROID_HOME / ANDROID_SDK_ROOT   跑端到端作业时需要
#   BUILD_TOOLS_DIR                   可选
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP="$ROOT/apkguard"
FAIL=0
step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }
ok()   { printf '    \033[32m✓ %s\033[0m\n' "$1"; }
bad()  { printf '    \033[31m✗ %s\033[0m\n' "$1"; FAIL=1; }
# warn：醒目提示但不置 FAIL —— 用于「环境缺失导致某项检查没跑」这类覆盖缺口。
# 刻意不静默：缺检查项和检查通过必须能区分开。
warn() { printf '    \033[33m! %s\033[0m\n' "$1"; }

# 选一个**真正可用**的 python：Windows 上 python3 常指向应用商店的空壳
# （命令存在但执行即失败），因此必须实际跑一次才算数。功能项计数与原生库
# 摘要检查都要用它；与 e2e.sh / build-testapp.sh 里的探测逻辑保持一致。
PY_BIN=""
for c in python3 python; do
  if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys' >/dev/null 2>&1; then
    PY_BIN="$c"; break
  fi
done
if [ -z "$PY_BIN" ]; then
  bad "找不到可用的 python（功能项计数与原生库检查需要 3.x）"
  exit 1
fi

step "gofmt 检查"
out="$(cd "$APP" && gofmt -l .)"
if [ -z "$out" ]; then ok "全部已格式化"; else bad "未格式化：$out"; fi

step "go vet"
(cd "$APP" && go vet ./...) && ok "vet 通过" || bad "vet 失败"

step "内嵌原生库检查（go:embed 的构建输入）"
for abi in arm64-v8a armeabi-v7a x86_64; do
  f="$APP/internal/native/prebuilt/$abi/libapkguard.so"
  if [ -s "$f" ]; then ok "$abi（$(stat -c%s "$f" 2>/dev/null || wc -c <"$f") 字节）"
  else bad "缺少 $f"; fi
done

# 与 ci.yml 的「校验原生库摘要与 16KB 页对齐」同步：
#  1) .agexpect 里回填的 .text+.rodata 摘要与当前内容一致；
#  2) LOAD 段按 16 KB 对齐（Android 15+ 要求，Google Play 自 2025-11 强制）。
# 以前本地 CI 没有这一步，页对齐出问题只有 GitHub CI 才会发现。
step "原生库摘要与 16KB 页对齐"
if "$PY_BIN" "$APP/internal/native/build_native.py" --check; then
  ok "摘要一致、LOAD 段 16KB 对齐"
else
  bad "原生库摘要不一致或 LOAD 段未按 16KB 对齐"
fi

step "交叉编译"
mkdir -p "$APP/dist"
for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
  os="${target%/*}"; arch="${target#*/}"
  ext=""; [ "$os" = windows ] && ext=".exe"
  if (cd "$APP" && CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
        go build -trimpath -ldflags "-s -w" \
        -o "dist/apkguard-${os}-${arch}${ext}" ./cmd/apkguard); then
    ok "$os/$arch"
  else bad "$os/$arch"; fi
done

step "单元测试"
(cd "$APP" && go test ./... -count=1) && ok "测试全绿" || bad "测试失败"

step "单元测试（竞态检测）"
# E5 批量处理会并发跑流水线，普通 go test 查不出数据竞争。-race 需要 cgo + C 编译器；
# 缺了就**明确跳过并告警**（CI 上一定会跑），不能让它静默消失。
if command -v gcc >/dev/null 2>&1 || command -v cc >/dev/null 2>&1 || command -v clang >/dev/null 2>&1; then
  if (cd "$APP" && CGO_ENABLED=1 go test -race ./... -count=1); then
    ok "无数据竞争"
  else
    bad "竞态检测失败"
  fi
else
  warn "本机没有 C 编译器，-race 未执行（CI 上会跑；这是覆盖缺口，不是通过）"
fi

step "CLI 冒烟测试"
BIN="$APP/dist/apkguard-linux-amd64"
[ -x "$BIN" ] || BIN="$APP/dist/apkguard-windows-amd64.exe"
[ -f "$BIN" ] || { bad "找不到刚构建的二进制"; exit 1; }
# Windows 上跨平台产物不能直接跑，改用本机平台二进制
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) LOCAL_BIN="$APP/dist/apkguard-windows-amd64.exe" ;;
  Darwin) LOCAL_BIN="$APP/dist/apkguard-darwin-$(uname -m | sed 's/x86_64/amd64/;s/arm64/arm64/')" ;;
  *) LOCAL_BIN="$APP/dist/apkguard-linux-amd64" ;;
esac
if "$LOCAL_BIN" -list >/dev/null 2>&1; then ok "-list 可执行"; else bad "-list 失败"; fi
n="$("$LOCAL_BIN" -list | "$PY_BIN" "$ROOT/scripts/count-features.py")"
[ "$n" -eq 47 ] && ok "功能项 47 个" || bad "功能项数量为 $n（应为 47）"

printf 'x' > /tmp/ag-fake.apk
# 注意：本脚本开了 pipefail，而这两条命令**预期会非零退出**（报错即成功）。
# 直接 `cmd | grep -q X` 会因为管道里前半段非零而让整个 if 判假，
# 于是「确实报了错」反而被记成失败。必须先取输出再匹配。
#
# 断言必须匹配**错误文案**而不是功能项 ID：`-enable ZZZ` 的输出里
# 请求行也可能回显 ZZZ，只匹配 ID 会让「根本没校验」也算通过
# （旧版对 A6 就是一条这样的空断言）。本轮之后 47 项全部已实现，
# 「已注册但未实现」的拒绝分支改由 internal/config/config_test.go 的单测
# 覆盖（临时从 implementedIDs 摘掉一项构造场景），这里覆盖未知 ID 分支。
out="$("$LOCAL_BIN" -in /tmp/ag-fake.apk -enable ZZZ 2>&1 || true)"
case "$out" in
  *未知功能项*ZZZ*) ok "未知功能项 ID 被正确拒绝" ;;
  *)                bad "启用未知功能项 ZZZ 没有按要求报错" ;;
esac
out="$("$LOCAL_BIN" -in /tmp/ag-fake.apk -enable E1 2>&1 || true)"
case "$out" in
  *密钥库*) ok "缺密钥库时正确报错" ;;
  *)        bad "缺密钥库未报错" ;;
esac
rm -f /tmp/ag-fake.apk

if [ -n "${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}" ]; then
  step "端到端（构建测试 APK → 加固 → 校验 → 产物级守卫）"
  # 日志目录必须先建：重定向到不存在的目录会让 e2e 直接失败，
  # 而且失败信息只会落在「见 tmpwork/...」这句里，看不出真实原因。
  mkdir -p "$ROOT/tmpwork"
  if bash "$ROOT/scripts/e2e.sh" >"$ROOT/tmpwork/ci-local-e2e.log" 2>&1; then
    ok "端到端通过（日志 tmpwork/ci-local-e2e.log）"
  else
    bad "端到端失败，见 tmpwork/ci-local-e2e.log"
    tail -25 "$ROOT/tmpwork/ci-local-e2e.log"
  fi
else
  step "端到端：跳过（未设置 ANDROID_HOME）"
fi

printf '\n'
if [ "$FAIL" = 0 ]; then
  printf '\033[32m本地 CI 全部通过 ✅\033[0m\n'
else
  printf '\033[31m本地 CI 存在失败项 ❌\033[0m\n'; exit 1
fi
