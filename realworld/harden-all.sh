#!/usr/bin/env bash
# 对三个真实应用做「全选项」加固（41 项已实现功能项，与 scripts/wsl-emu-all.sh 的 ALL 一致）。
#
# 用法（在 Linux/WSL 里跑；Windows 侧没有 JDK，签名用 Go 生成的 PKCS12）：
#   bash realworld/harden-all.sh              # 默认：41 项全开（含 D2/D3/D5）
#   PORTABLE=1 bash realworld/harden-all.sh   # 对外分发：去掉 D2/D3/D5
#
# 产物可用范围（重要，别拿默认产物去分发）：
#   - D2（Root 检测）/ D3（模拟器检测）会让产物在 root 设备或模拟器上**按设计**
#     终止进程——在本机复验时这是它们生效的证据，但在别人的环境里就是打不开；
#   - D5（设备绑定）把产物绑定到 -bind-device 指定的那一台设备。
#   因此默认清单的产物只适合在「指定设备 + 非 root 真机」内验证。
#   **对外分发必须用去掉这三项的 PORTABLE 清单**，即 PORTABLE=1 运行本脚本。
#
# 前置：
#   1) 把三个原始 APK 放到 realworld/apps/ 下（见下方 URL），文件名固定为
#        dhizuku.apk / termux.apk / rustdesk.apk
#   2) 生成一张测试密钥库（本机无 JDK keytool 时用纯 Go 生成）：
#        go run ./apkguard/cmd/genkey realworld/apps/test.p12 apkguard
#      （genkey 是开发辅助命令：产物签名/对齐不依赖 JDK，只有生成测试密钥库这一步在无 JDK 时才需要它）
#   3) 默认清单含 D5，需要目标设备标识。Android 8+ 的 ANDROID_ID 按「应用签名 + 用户 +
#      设备」作用域化，`adb shell settings get secure android_id` 取到的不是应用内看到的值。
#      采集方式：先用 -debug-shell 出一个排障版，在目标设备上运行一次，从
#        adb logcat -s APKGUARD-D5
#      读出标识，写入 realworld/apps/d5value.txt，或用 BIND_DEVICE=<值> 传入。
#      PORTABLE=1 时不需要绑定值。
#
# 产物：realworld/apps/<app>-full-official.apk（PORTABLE=1 时为
#       <app>-portable-official.apk；「-official」是 E4 的渠道后缀，来自 -channels official）。
#       另生成 realworld/apps/signer-sha256.txt（apksigner --print-certs 输出的证书
#       SHA-256，供 C1 载荷密钥相关验证使用）；找不到 apksigner 时跳过并给出提示。
#
# 原始 APK 来源（实测使用的版本）：
#   Dhizuku 2.12.0   https://github.com/iamr0s/Dhizuku/releases/download/v2.12.0/Dhizuku_v2.12.0.apk
#   Termux 0.118.3   https://github.com/termux/termux-app/releases/download/v0.118.3/termux-app_v0.118.3+github-debug_x86_64.apk
#   RustDesk 1.5.0   https://github.com/rustdesk/rustdesk/releases/download/1.5.0/rustdesk-1.5.0-universal-signed.apk
set -euo pipefail
cd "$(dirname "$0")"

AG=./apkguard-linux
if [ ! -x "$AG" ]; then
  echo "构建 $AG（交叉编译，供 WSL 使用）"
  (cd apkguard && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o ../realworld/apkguard-linux ./cmd/apkguard)
fi

[ -f apps/test.p12 ] || { echo "错误：缺少 apps/test.p12（见脚本头部说明）" >&2; exit 1; }

KS_ARGS="-ks apps/test.p12 -ks-pass apkguard"

# 全部 41 个已实现项（A7/B5/B6/B7/C3 未实现，启用会被 Validate 拒绝）。
ALL="A1,A2,A3,A4,A5,A6,A8,A9,A10,A11,A12,A13,A14,A15,A16,A17,A18,A19,A20,B1,B2,B3,B4,B8,C1,C2,C4,C5,C6,C7,D1,D2,D3,D4,D5,E1,E2,E3,E4,E5,E6"
# PORTABLE：去掉 D2/D3（检测到 Root/模拟器即终止）与 D5（绑定到采样的那台设备）。
# 这三项会让产物在别的环境/设备上被自己拦住，对外分发必须用这一份。
PORTABLE="A1,A2,A3,A4,A5,A6,A8,A9,A10,A11,A12,A13,A14,A15,A16,A17,A18,A19,A20,B1,B2,B3,B4,B8,C1,C2,C4,C5,C6,C7,D1,D4,E1,E2,E3,E4,E5,E6"

if [ "${PORTABLE:-0}" = "1" ]; then
  ENABLE="$PORTABLE"; TAG=portable
else
  ENABLE="$ALL"; TAG=full
fi

# D5 的绑定值：默认清单必需；PORTABLE 不需要。
BIND_ARGS=()
if [ "${PORTABLE:-0}" != "1" ]; then
  BIND="${BIND_DEVICE:-}"
  if [ -z "$BIND" ] && [ -f apps/d5value.txt ]; then
    BIND="$(tr -d '\r\n' < apps/d5value.txt)"
  fi
  if [ -z "$BIND" ]; then
    echo "错误：默认清单含 D5（设备绑定），但未提供目标设备标识。" >&2
    echo "      把采集到的值写入 apps/d5value.txt，或用 BIND_DEVICE=<值> 运行；" >&2
    echo "      只想产出可对外分发的包，请用：PORTABLE=1 bash realworld/harden-all.sh" >&2
    exit 1
  fi
  BIND_ARGS=(-bind-device "$BIND")
  echo "D5 绑定标识：$BIND"
fi

# 与 scripts/wsl-emu-all.sh 的参数对齐，并显式给出 A15 填充量与 C7 假库名。
EXTRA="-channels official -package-shrink -manifest-pad-mb 16 -payload-mac -so-encrypt -lib-name libguardx.so"

for app in dhizuku termux rustdesk; do
  [ -f "apps/$app.apk" ] || { echo "跳过 $app（缺 apps/$app.apk）"; continue; }
  echo "=== 加固 $app（$TAG）==="
  log="apps/$app-$TAG.log"
  if ! $AG -in "apps/$app.apk" -out "apps/$app-$TAG.apk" $KS_ARGS \
      -enable "$ENABLE" $EXTRA "${BIND_ARGS[@]}" -seed "$app" >"$log" 2>&1; then
    echo "加固失败，日志尾部（$log）：" >&2
    tail -8 "$log" >&2
    exit 1
  fi
  tail -2 "$log"
done

first_apk=""
for f in apps/*-"$TAG"-official.apk; do
  if [ -f "$f" ]; then first_apk="$f"; break; fi
done
if [ -z "$first_apk" ]; then
  echo "没有产出任何 $TAG 产物，跳过 signer-sha256.txt"
  exit 0
fi

# 三个应用用同一张 test.p12 签名，任取一个产物的证书摘要即可代表本批。
# 生成方式对齐 scripts/e2e.sh 第 5 步：apksigner verify --print-certs。
APKSIGNER="${APKSIGNER:-}"
if [ -z "$APKSIGNER" ]; then
  SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
  BT="${BUILD_TOOLS_DIR:-$SDK/build-tools/${BUILD_TOOLS_VERSION:-34.0.0}}"
  for c in "$BT/apksigner" "$BT/apksigner.bat"; do
    [ -f "$c" ] && { APKSIGNER="$c"; break; }
  done
fi
if [ -n "$APKSIGNER" ] && [ -f "$APKSIGNER" ]; then
  "$APKSIGNER" verify --print-certs "$first_apk" \
    | grep -i "SHA-256 digest" | head -1 \
    | sed 's/.*digest: //' | tr -d '\r ' > apps/signer-sha256.txt
  echo "签名证书 SHA-256（$first_apk）: $(cat apps/signer-sha256.txt)"
else
  echo "提示：未找到 apksigner（可用 ANDROID_HOME / BUILD_TOOLS_DIR / APKSIGNER 指定），"
  echo "      跳过 apps/signer-sha256.txt；可手动生成："
  echo "      apksigner verify --print-certs $first_apk | grep 'SHA-256 digest'"
fi

ls -la apps/*-"$TAG"-official.apk 2>/dev/null || true
