#!/usr/bin/env bash
# 在 WSL 里跑项目的端到端验证（需要 SDK + JDK）。
set -uo pipefail
export ANDROID_HOME="$HOME/android-sdk"
export ANDROID_SDK_ROOT="$HOME/android-sdk"
export JAVA_HOME="$HOME/java"
export PATH="$HOME/goroot/bin:$JAVA_HOME/bin:$PATH"
bash /mnt/c/Users/admin/Desktop/apkguard/scripts/e2e.sh