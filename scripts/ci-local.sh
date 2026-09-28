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
n="$("$LOCAL_BIN" -list | python3 "$ROOT/scripts/count-features.py")"
[ "$n" -eq 38 ] && ok "功能项 38 个" || bad "功能项数量为 $n（应为 38）"

printf 'x' > /tmp/ag-fake.apk
if "$LOCAL_BIN" -in /tmp/ag-fake.apk -enable A6 2>&1 | grep -q "A6"; then
  ok "未实现的功能项被正确拒绝"; else bad "启用未实现的 A6 没有报错"; fi
if "$LOCAL_BIN" -in /tmp/ag-fake.apk -enable E1 2>&1 | grep -q "密钥库"; then
  ok "缺密钥库时正确报错"; else bad "缺密钥库未报错"; fi
rm -f /tmp/ag-fake.apk

if [ -n "${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}" ]; then
  step "端到端（构建测试 APK → 加固 → 校验 → 产物级守卫）"
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
