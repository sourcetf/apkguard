#!/usr/bin/env python3
"""统计 `apkguard -list` 输出的功能项数量。

从标准输入读取 -list 的输出，打印功能项个数（用于 CI 冒烟测试）。

为什么单独写脚本而不是在 CI 里内联 grep：
  - 「默认启用」的标记是 `√`（UTF-8 三字节），grep 的 . 是否按字符匹配
    取决于 locale，CI 上不可靠；
  - -list 每个功能项占两行（名称行 + 描述行），按行数统计会翻倍；
  - 描述文本里也会出现功能项 ID，必须锚定行首格式才能数准。
"""
import re
import sys

pat = re.compile(r'^\s+\S?\s*([A-E][0-9]+)\s')
ids = set()
for line in sys.stdin:
    m = pat.match(line)
    if m:
        ids.add(m.group(1))
print(len(ids))
