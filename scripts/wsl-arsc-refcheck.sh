#!/usr/bin/env bash
# 用 aapt2 导出资源表引用的文件路径，并与 APK 实际条目比对。
# 目的：判断 resources.arsc 是「真资源表」还是「指向不存在文件的诱饵」。
set -uo pipefail
REPO=/mnt/c/Users/admin/Desktop/apkguard
SDK=$HOME/android-sdk
export JAVA_HOME=$HOME/java
export PATH=$JAVA_HOME/bin:$PATH
AAPT2=$SDK/build-tools/34.0.0/aapt2
SCRATCH="$REPO/tmpwork/sample-recon/mine"
mkdir -p "$SCRATCH"

APK="$1"
TAG="$2"
echo "== $TAG：aapt2 dump resources -> $SCRATCH/$TAG-res.txt =="
timeout 600 "$AAPT2" dump resources "$APK" > "$SCRATCH/$TAG-res.txt" 2>&1 || echo "  (aapt2 返回非零)"
echo "  行数: $(wc -l < "$SCRATCH/$TAG-res.txt")"

python3 - "$APK" "$SCRATCH/$TAG-res.txt" "$TAG" <<'PY'
import re, sys, zipfile
apk, txt, tag = sys.argv[1], sys.argv[2], sys.argv[3]
body = open(txt, encoding="utf-8", errors="replace").read()
refs = set(re.findall(r"\(file\)\s+(\S+)\s", body))
names = set(zipfile.ZipFile(apk).namelist())
missing = sorted(r for r in refs if r not in names)
print("  资源表引用的文件数: %d" % len(refs))
print("  其中在 APK 里不存在的: %d" % len(missing))
for m in missing[:12]:
    print("     缺:", m)
present = len(refs) - len(missing)
print("  存在比例: %d/%d" % (present, len(refs)))
# 也看看 APK 里有但资源表没引用的 res/ 文件
unref = sorted(n for n in names if n.startswith("res/") and n not in refs)
print("  APK 里未被引用的 res/ 条目: %d（前 8）: %s" % (len(unref), unref[:8]))
PY