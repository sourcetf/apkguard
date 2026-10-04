#!/usr/bin/env bash
# 核对样本运行时落地的插件 APK 是否就是内层真 APK。
set -uo pipefail
SDK=$HOME/android-sdk
export PATH=$SDK/platform-tools:$PATH
ADB="adb -s emulator-5554"
D=/mnt/c/Users/admin/Desktop/apkguard/tmpwork/sample-recon/mine
REMOTE=/sdcard/Android/data/nu.pyokn.yyqfzjtrpk.scz/files/plugins/nupyoknyyqfzjtrpkscz.apk

echo "== 落地目录 =="
$ADB shell "ls -la /sdcard/Android/data/nu.pyokn.yyqfzjtrpk.scz/files/plugins/" | tr -d '\r'

echo
echo "== 拉取 =="
$ADB pull "$REMOTE" "$D/plugin-dropped.apk" 2>&1 | tail -1

echo
echo "== 与我自己解密的 inner-realapk.apk 比对 =="
ls -la "$D/inner-realapk.apk" "$D/plugin-dropped.apk"
sha256sum "$D/inner-realapk.apk" "$D/plugin-dropped.apk"

echo
echo "== 插件 APK 的清单（确认它是完整可安装 APK）=="
python3 - "$D/plugin-dropped.apk" <<'PY'
import sys, zipfile, re
p = sys.argv[1]
z = zipfile.ZipFile(p)
n = z.namelist()
print("  条目数:", len(n))
print("  AndroidManifest.xml:", "AndroidManifest.xml" in n)
print("  resources.arsc:", "resources.arsc" in n)
dex = [x for x in n if re.match(r"classes\d*\.dex$", x)]
print("  DEX:", dex)
print("  META-INF 条目:", len([x for x in n if x.startswith("META-INF/")]), [x for x in n if x.startswith("META-INF/")][:4])
PY