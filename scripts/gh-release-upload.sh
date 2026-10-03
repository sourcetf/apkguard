#!/usr/bin/env bash
# 用 GitHub Release 发布二进制产物（APK 等）。
#
# 为什么用 Release 而不是 git push：
#   - GitHub 对**单个文件超过 100 MB** 的 push 直接拒绝（rustdesk 加固产物 104 MB），
#     而且大二进制入库会让仓库永久膨胀（本仓库 .gitignore 也刻意排除了 *.apk）。
#   - Release 资产单文件上限 2 GB，且不进入仓库历史。
#
# 凭据：从 git 的凭据助手取（不落盘、不回显、不进 argv）。
# 认证头通过 `curl --config -` 从**标准输入**传入，因此 token 不出现在进程参数里。
#
# 用法：
#   scripts/gh-release-upload.sh --check
#   scripts/gh-release-upload.sh <tag> <标题> <说明文件> <资产>...
set -euo pipefail

REPO_SLUG="${GH_REPO:-sourcetf/apkguard}"
API="https://api.github.com"
TOKEN=""

load_token() {
  local creds
  creds=$(printf 'protocol=https\nhost=github.com\n\n' | git credential fill 2>/dev/null || true)
  TOKEN=$(printf '%s\n' "$creds" | sed -n 's/^password=//p')
  [ -n "$TOKEN" ] || { echo "错误：凭据助手没有返回 github.com 的口令（先 git push 一次）" >&2; exit 1; }
}

# 认证封装：--config - 从 stdin 读认证头，token 不进 argv。
# 这台机器到 api.github.com 的连接偶发超时（实测 21 秒后失败），因此统一加
# 连接级重试；幂等性由调用点保证（创建 Release 撞 tag 会 422、上传前会先删同名资产）。
gh_curl() {
  printf 'header = "Authorization: token %s"\n' "$TOKEN" | curl -sS \
    --retry 4 --retry-connrefused --retry-delay 3 --connect-timeout 30 \
    --config - "$@"
}

# 从 JSON 里取字段（python 是 Windows 原生程序，读不了 Git Bash 的 /tmp，一律走管道）。
jget() { python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
except Exception as e:
    print(''); sys.exit(0)
print($1)
"; }

if [ "${1:-}" = "--check" ]; then
  load_token
  echo "== 仓库 =="
  raw=$(gh_curl -w '\n%{http_code}' "$API/repos/$REPO_SLUG")
  code=$(printf '%s\n' "$raw" | tail -n1)
  body=$(printf '%s\n' "$raw" | sed '$d')
  echo "  HTTP $code"
  printf '%s\n' "$body" | python3 -c '
import json,sys
d=json.load(sys.stdin)
p=d.get("permissions") or {}
print("  %s  可见性=%s  默认分支=%s" % (d.get("full_name"), d.get("visibility"), d.get("default_branch")))
print("  权限: push=%s admin=%s" % (p.get("push"), p.get("admin")))
'
  echo "== 已存在的 Release（最近 5 条） =="
  gh_curl "$API/repos/$REPO_SLUG/releases?per_page=5" | python3 -c '
import json,sys
rs=json.load(sys.stdin)
if not rs: print("  （无）")
for r in rs: print("  %-36s 资产=%d" % (r["tag_name"], len(r.get("assets",[]))))
'
  exit 0
fi

if [ $# -lt 4 ]; then
  sed -n '2,15p' "$0"
  exit 2
fi

TAG="$1"; TITLE="$2"; NOTES="$3"; shift 3
load_token

echo "== 创建 Release：$TAG =="
PAYLOAD=$(python3 - "$TAG" "$TITLE" "$NOTES" <<'PY'
import json, sys
tag, title, notes = sys.argv[1], sys.argv[2], sys.argv[3]
body = open(notes, encoding="utf-8").read()
print(json.dumps({"tag_name": tag, "name": title, "body": body,
                  "draft": False, "prerelease": True}))
PY
)
raw=$(gh_curl -X POST "$API/repos/$REPO_SLUG/releases" \
        -H "Content-Type: application/json" -d "$PAYLOAD" -w '\n%{http_code}')
code=$(printf '%s\n' "$raw" | tail -n1)
body=$(printf '%s\n' "$raw" | sed '$d')
REL=$(printf '%s\n' "$body" | jget 'd.get("id") or ""')

if [ -z "$REL" ]; then
  echo "  创建未成功（HTTP $code）：$(printf '%s\n' "$body" | jget 'd.get("message") or d')"
  echo "  尝试复用同 tag 的既有 Release"
  REL=$(gh_curl "$API/repos/$REPO_SLUG/releases/tags/$TAG" | jget 'd.get("id") or ""')
fi
[ -n "$REL" ] || { echo "错误：拿不到 Release id" >&2; exit 1; }
echo "  release id = $REL"

for f in "$@"; do
  [ -f "$f" ] || { echo "  跳过 $f（不存在）"; continue; }
  name=$(basename "$f")
  mb=$(python3 -c "import os;print('%.1f'%(os.path.getsize('$f')/1048576))")
  printf '  上传 %-36s %7s MB ... ' "$name" "$mb"
  # 已存在同名资产时先删掉再传，避免重试撞 409。
  old=$(gh_curl "$API/repos/$REPO_SLUG/releases/$REL/assets?per_page=100" | python3 -c "
import json,sys
try: rs=json.load(sys.stdin)
except Exception: rs=[]
for a in rs:
    if a['name']=='$name': print(a['id'])
" | head -1)
  if [ -n "$old" ]; then
    gh_curl -X DELETE "$API/repos/$REPO_SLUG/releases/assets/$old" >/dev/null || true
    echo "  (removed existing asset id=$old)"
  fi
  # 大文件必须走 HTTP/1.1 且允许重试：实测 104 MB 的资产在 HTTP/2 下会被
  # "Connection was reset" 打断（GitHub 不支持断点续传，只能整份重传）。
  # --retry-all-errors 让传输层错误也计入重试。
  raw=$(gh_curl --http1.1 --retry 4 --retry-delay 5 --retry-all-errors \
        -X POST -H "Content-Type: application/octet-stream" \
        --data-binary "@$f" -w '\n%{http_code}' \
        "https://uploads.github.com/repos/$REPO_SLUG/releases/$REL/assets?name=$name")
  code=$(printf '%s\n' "$raw" | tail -n1)
  if [ "$code" = "201" ]; then
    echo "OK"
  else
    echo "失败(HTTP $code)：$(printf '%s\n' "$raw" | sed '$d' | jget 'd.get("message") or d')"
  fi
done

echo
echo "== Release =="
gh_curl "$API/repos/$REPO_SLUG/releases/$REL" | python3 -c '
import json,sys
d=json.load(sys.stdin)
print("  " + d["html_url"])
for a in d.get("assets",[]):
    print("    %-36s %7.1f MB" % (a["name"], a["size"]/1048576))
'