#!/usr/bin/env bash
# 在「CI 条件」下跑全量测试：CI 上 realworld/apps/ 不存在（原始与加固 APK 都被
# .gitignore 排除），真实产物测试因此回退到 deliver/ 里 e2e 生成的包。
#
# 本机这两个目录都有，因此必须临时把 realworld/apps 挪开，才能复现 CI 的
# 选择路径——否则测试会挑到 realworld/apps 里的旧产物，把问题掩盖掉。
set -uo pipefail

REPO=/mnt/c/Users/admin/Desktop/apkguard
export ANDROID_HOME="$HOME/android-sdk"
export ANDROID_SDK_ROOT="$HOME/android-sdk"
export JAVA_HOME="$HOME/java"
export PATH="$HOME/goroot/bin:$JAVA_HOME/bin:$PATH"

restore() {
  if [ -d "$REPO/realworld/apps.hidden" ]; then
    mv "$REPO/realworld/apps.hidden" "$REPO/realworld/apps"
    echo "== 已还原 realworld/apps =="
  fi
}
trap restore EXIT

if [ -d "$REPO/realworld/apps" ]; then
  mv "$REPO/realworld/apps" "$REPO/realworld/apps.hidden"
  echo "== 已临时隐藏 realworld/apps（模拟 CI）=="
fi

echo "== deliver/ 里可用的产物 =="
ls "$REPO/deliver"/*.apk 2>/dev/null | head -5 || echo "  （无，先跑 e2e）"

echo
echo "== go test ./... =="
cd "$REPO/apkguard" && go test ./... -count=1 2>&1 | tail -25