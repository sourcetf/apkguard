#!/usr/bin/env bash
# 构建测试应用（testapp）并签名，用于端到端验证加固流程。
#
# 输出：testapp/testapp-signed.apk（以及 testapp/testapp-unsigned.apk）
#
# 依赖 Android SDK：platforms/android-34 + build-tools；JDK 需可用（javac/keytool）。
# 环境变量：
#   ANDROID_HOME / ANDROID_SDK_ROOT  SDK 根目录（二者任一）
#   BUILD_TOOLS_VERSION              默认 34.0.0
#   PLATFORM_VERSION                 默认 android-34
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP="$ROOT/testapp"
BT_VER="${BUILD_TOOLS_VERSION:-34.0.0}"
PLAT_VER="${PLATFORM_VERSION:-android-34}"

SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
if [ -z "$SDK" ]; then
  echo "错误：未设置 ANDROID_HOME / ANDROID_SDK_ROOT" >&2
  exit 1
fi

# BUILD_TOOLS_DIR 可覆盖（有些环境的 build-tools 与 SDK 分开存放）
BT="${BUILD_TOOLS_DIR:-$SDK/build-tools/$BT_VER}"
PLATFORM="${PLATFORM_JAR:-$SDK/platforms/$PLAT_VER/android.jar}"

# Windows 上工具是 .exe / .bat，逐个探测
exe() {
  for c in "$1" "$1.exe" "$1.bat"; do
    [ -f "$c" ] && { echo "$c"; return; }
  done
  echo "错误：找不到可执行文件 $1" >&2
  exit 1
}
# JDK 工具（javac / keytool）可能不在 PATH 上，用 JAVA_HOME 补齐。
#
# 注意：Windows 上 JAVA_HOME 形如 "C:/Program Files/.../jbr"，其中的冒号会被
# bash 当成 PATH 分隔符，直接拼进 PATH 会把 "C:" 截断成一项 "C"。
# 因此在 MSYS/Cygwin 下先用 cygpath 转成 POSIX 形式（/c/Program Files/...）。
jhome="$JAVA_HOME"
if command -v cygpath >/dev/null 2>&1; then
  jhome="$(cygpath -u "$JAVA_HOME")"
fi
if [ -n "${jhome:-}" ] && [ -d "$jhome/bin" ]; then
  PATH="$jhome/bin:$PATH"
  export PATH
fi
for t in javac keytool java; do
  command -v "$t" >/dev/null 2>&1 || {
    echo "错误：找不到 $t（请设置 JAVA_HOME 或把它加入 PATH）" >&2; exit 1; }
done

# 选一个**真正可用**的 python：Windows 上 python3 常指向应用商店的空壳
# （命令存在但执行即失败），因此必须实际跑一次才算数。
PY_BIN=""
for c in python3 python; do
  if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys' >/dev/null 2>&1; then
    PY_BIN="$c"; break
  fi
done
if [ -z "$PY_BIN" ]; then
  echo "错误：找不到可用的 python（需要 3.x）" >&2
  exit 1
fi

for f in "$PLATFORM"; do
  [ -e "$f" ] || { echo "错误：缺少 $f" >&2; exit 1; }
done
AAPT2="$(exe "$BT/aapt2")"
D8="$(exe "$BT/d8")"
ZIPALIGN="$(exe "$BT/zipalign")"
APKSIGNER="$(exe "$BT/apksigner")"

WORK="$APP/build"
rm -rf "$WORK"
mkdir -p "$WORK/classes" "$WORK/dex"

echo "== 1/6 编译 Java 源码 =="
# 找出全部源文件
mapfile -t SRCS < <(find "$APP/src" -name '*.java')
echo "   源文件 ${#SRCS[@]} 个"
javac -nowarn -source 8 -target 8 \
  -bootclasspath "$PLATFORM" -classpath "$PLATFORM" \
  -d "$WORK/classes" "${SRCS[@]}"

echo "== 2/6 生成 DEX =="
mapfile -t CLASSES < <(find "$WORK/classes" -name '*.class')
"$D8" --min-api 24 --output "$WORK/dex" "${CLASSES[@]}"
ls -la "$WORK/dex/classes.dex"

echo "== 3/6 链接资源与 Manifest =="
"$AAPT2" link \
  -o "$WORK/unsigned-base.apk" \
  --manifest "$APP/AndroidManifest.xml" \
  -I "$PLATFORM" \
  --min-sdk-version 24 --target-sdk-version 34

echo "== 4/6 放入 classes.dex =="
rm -f "$APP/testapp-unsigned.apk"
"$PY_BIN" - "$WORK/unsigned-base.apk" "$WORK/dex/classes.dex" "$APP/testapp-unsigned.apk" <<'PY'
import shutil, sys, zipfile
src, dex, dst = sys.argv[1], sys.argv[2], sys.argv[3]
shutil.copy(src, dst)
# 用追加方式写入，保持原有条目的压缩方式（resources.arsc 必须是 STORED，
# 否则 Android 11+ 会拒绝安装）。
with zipfile.ZipFile(dst, "a", zipfile.ZIP_DEFLATED) as z:
    z.write(dex, "classes.dex")
print("   已写入 classes.dex")
PY

echo "== 5/6 对齐 =="
rm -f "$APP/testapp-aligned.apk"
"$ZIPALIGN" -f -p 4 "$APP/testapp-unsigned.apk" "$APP/testapp-aligned.apk"

echo "== 6/6 签名 =="
KS="$WORK/test.jks"
keytool -genkeypair -keystore "$KS" -alias test -keyalg RSA -keysize 2048 \
  -validity 3650 -storepass 123456 -keypass 123456 \
  -dname "CN=apkguard test, OU=ci, O=apkguard, L=-, ST=-, C=CN" >/dev/null 2>&1
rm -f "$APP/testapp-signed.apk"
"$APKSIGNER" sign \
  --ks "$KS" --ks-pass pass:123456 --key-pass pass:123456 \
  --min-sdk-version 24 \
  --out "$APP/testapp-signed.apk" "$APP/testapp-aligned.apk"

"$APKSIGNER" verify --min-sdk-version 24 "$APP/testapp-signed.apk"
echo "完成：$APP/testapp-signed.apk（$(stat -c%s "$APP/testapp-signed.apk" 2>/dev/null || wc -c <"$APP/testapp-signed.apk") 字节）"