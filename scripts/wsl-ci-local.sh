#!/usr/bin/env bash
# 在 WSL 里跑本地 CI（含原生库摘要、功能项计数、CLI 冒烟）。
set -uo pipefail
export ANDROID_HOME="$HOME/android-sdk"
export ANDROID_SDK_ROOT="$HOME/android-sdk"
export ANDROID_NDK_HOME="$HOME/android-sdk/ndk/26.1.10909125"
export JAVA_HOME="$HOME/java"
export PATH="$HOME/goroot/bin:$JAVA_HOME/bin:$PATH"
bash /mnt/c/Users/admin/Desktop/apkguard/scripts/ci-local.sh