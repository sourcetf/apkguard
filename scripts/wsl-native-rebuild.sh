#!/usr/bin/env bash
# 在 WSL 里重编原生库（C 源码改动后必须重编，否则预编译 .so 与源码不一致）。
set -uo pipefail
REPO=/mnt/c/Users/admin/Desktop/apkguard
SDK=$HOME/android-sdk
export ANDROID_HOME=$SDK
export ANDROID_SDK_ROOT=$SDK
export ANDROID_NDK_HOME="$SDK/ndk/26.1.10909125"
export PATH=$HOME/goroot/bin:$PATH

echo "== 重编 =="
python3 "$REPO/apkguard/internal/native/build_native.py" || exit 1

echo
echo "== 校验（--check） =="
python3 "$REPO/apkguard/internal/native/build_native.py" --check || exit 1

echo
echo "== 独立复核 .agexpect（Python 复算 .text||.rodata） =="
echo "（--check 已按节表复算 .text||.rodata 并与 .agexpect 比对，即独立复核）"
