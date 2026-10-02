#!/usr/bin/env bash
# 对三个真实应用做「全选项」加固（D2/D3 除外，它们在 root 模拟器上命中属设计行为）。
#
# 用法（在 Linux/WSL 里跑；Windows 侧没有 JDK，签名用 Go 生成的 PKCS12）：
#   bash realworld/harden-all.sh
#
# 前置：
#   1) 把三个原始 APK 放到 realworld/apps/ 下（见下方 URL），文件名固定为
#        dhizuku.apk / termux.apk / rustdesk.apk
#   2) 生成一张测试密钥库（本机无 JDK keytool 时用纯 Go 生成）：
#        go run ./apkguard/cmd/genkey realworld/apps/test.p12 apkguard
#      （genkey 是开发辅助命令：产物签名/对齐不依赖 JDK，只有生成测试密钥库这一步在无 JDK 时才需要它）
#
# 产物：realworld/apps/<app>-full-official.apk
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
# 全部 33 个已实现项，除 D2/D3（root 模拟器上会按设计拦停）。
ENABLE="A1,A2,A3,A4,A5,A8,A9,A10,A11,A12,A13,A14,A15,B1,B2,B3,B4,B8,C1,C4,C5,C6,D1,D4,E1,E2,E3,E4,E5,E6"
EXTRA="-channels official -package-shrink -manifest-pad-mb 16"

for app in dhizuku termux rustdesk; do
  [ -f "apps/$app.apk" ] || { echo "跳过 $app（缺 apps/$app.apk）"; continue; }
  echo "=== 加固 $app ==="
  $AG -in "apps/$app.apk" -out "apps/$app-full.apk" $KS_ARGS \
    -enable "$ENABLE" $EXTRA -seed "$app" 2>&1 | tail -2
done
ls -la apps/*-full-official.apk 2>/dev/null || true