#!/usr/bin/env bash
# 检查 WSL 里能否跑 -race（需要 cgo + C 编译器）。
set -uo pipefail
export PATH="$HOME/goroot/bin:$PATH"
echo "== C 编译器 =="
for c in gcc cc clang tcc; do
  if command -v "$c" >/dev/null 2>&1; then echo "  找到 $c: $(command -v $c)"; fi
done
command -v gcc >/dev/null 2>&1 || command -v cc >/dev/null 2>&1 || command -v clang >/dev/null 2>&1 \
  || echo "  （没有可用的 C 编译器，-race 无法在本机运行）"

echo
echo "== go test -race ./... =="
cd /mnt/c/Users/admin/Desktop/apkguard/apkguard
CGO_ENABLED=1 go test -race ./... -count=1 2>&1 | tail -20