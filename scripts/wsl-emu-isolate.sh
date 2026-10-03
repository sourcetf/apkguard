#!/usr/bin/env bash
# 隔离试验：证明「ALL 变体启动即退」确实由 D2/D3 引起，而不是别的东西坏了。
#
# 用同一个 testapp、同一套壳（B1/B2/B3），只切换 D2/D3/D5 的开关：
#   base        → 应正常存活
#   +D2         → 应退出（su 路径 /system/xbin/su 与 /data/local/su 存在）
#   +D3         → 应退出（model=sdk_gphone64_x86_64、hardware=ranchu 等）
#   +D5(已绑定) → 应正常存活（绑定值就是本机标识）
set -uo pipefail

REPO=/mnt/c/Users/admin/Desktop/apkguard
OUT=$REPO/realworld/emu-out/bisect
SDK=$HOME/android-sdk
export ANDROID_HOME=$SDK ANDROID_SDK_ROOT=$SDK JAVA_HOME=$HOME/java
export PATH=$HOME/goroot/bin:$JAVA_HOME/bin:$SDK/platform-tools:$PATH
ADB="adb -s emulator-5554"
mkdir -p "$OUT"
(cd "$REPO/apkguard" && CGO_ENABLED=0 go build -o "$OUT/apkguard-linux" ./cmd/apkguard) || exit 1
AG=$OUT/apkguard-linux
BIND="$(cat "$REPO/realworld/emu-out/d5value.txt")"

# 壳基线：B1/B2/B3 让壳真的去解密载荷，E1 供签名与 D1/D5 的摘要来源。
SHELL="B1,B2,B3,E1,E2,E3,E6"

case_run() {  # $1=标签 $2=额外项
  local tag=$1 extra=$2
  local en="$SHELL"
  [ -n "$extra" ] && en="$SHELL,$extra"
  "$AG" -in "$REPO/testapp/testapp-signed.apk" -out "$OUT/iso-$tag.apk" \
        -ks "$REPO/realworld/apps/test.p12" -ks-pass apkguard \
        -enable "$en" -bind-device "$BIND" >"$OUT/iso-$tag.log" 2>&1
  [ $? -ne 0 ] && { echo "  $tag: 构建失败"; tail -2 "$OUT/iso-$tag.log" | sed 's/^/     /'; return; }

  $ADB uninstall com.agtest >/dev/null 2>&1
  $ADB install -r -t "$OUT/iso-$tag.apk" >/dev/null 2>&1 || { echo "  $tag: 安装失败"; return; }
  $ADB shell am force-stop com.agtest 2>/dev/null
  $ADB logcat -c
  $ADB shell am start -n com.agtest/.MainActivity >/dev/null 2>&1
  local n=0
  for _ in $(seq 1 8); do
    sleep 1
    [ -n "$($ADB shell pidof com.agtest 2>/dev/null | tr -d '\r')" ] && n=$((n + 1))
  done
  local crash
  crash=$($ADB logcat -d 2>/dev/null | tr -d '\r' | grep -cE "FATAL EXCEPTION|VerifyError|ClassNotFoundException|NoClassDefFoundError")
  printf '  %-12s 存活 %d/8  崩溃计数 %s\n' "$tag" "$n" "$crash"
}

echo "== 隔离试验（都是同一个 testapp + 同一套壳，只切换 D2/D3/D5） =="
case_run base ""
case_run D2only "D2"
case_run D3only "D3"
case_run D5bound "D5"
case_run D2D3 "D2,D3"