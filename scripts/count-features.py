#!/usr/bin/env python3
"""统计 `apkguard -list` 输出的功能项数量。

从标准输入读取 -list 的输出，打印功能项个数（用于 CI 冒烟测试）。

用法：
    apkguard -list | count-features.py               # 打印功能项总数（46）
    apkguard -list | count-features.py --implemented # 打印已实现项 ID（空格分隔）

「已实现」= 名称行不带 `【尚未实现】` 标记；e2e 的覆盖率自检用它动态取得清单，
避免在脚本里硬编码一份会随功能项增删而过期的副本。

为什么单独写脚本而不是在 CI 里内联 grep：
  - 「默认启用」的标记是 `√`（UTF-8 三字节），grep 的 . 是否按字符匹配
    取决于 locale，CI 上不可靠；
  - -list 每个功能项占两行（名称行 + 描述行），按行数统计会翻倍；
  - 描述文本里也会出现功能项 ID，必须锚定行首格式才能数准。
"""
import re
import sys

pat = re.compile(r'^\s+\S?\s*([A-E][0-9]+)\s')

if "--implemented" in sys.argv[1:]:
    ids = []
    for line in sys.stdin:
        m = pat.match(line)
        if m and "尚未实现" not in line:
            ids.append(m.group(1))
    print(" ".join(sorted(set(ids))))
    sys.exit(0)

ids = set()
for line in sys.stdin:
    m = pat.match(line)
    if m:
        ids.add(m.group(1))
print(len(ids))
