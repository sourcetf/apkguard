#!/usr/bin/env python3
"""解析 AXML 的字符串池与 RES_XML_RESOURCE_MAP，检查「属性名 → 资源 ID」映射是否完整。

为什么关键：Android 框架解析属性名时用的是**资源 ID**（如 android:value = 0x01010024），
不是字符串。resource map 是一张按「字符串索引」对齐的数组：字符串池里第 i 个串
（仅前 N 个）对应 resource_map[i]。若字符串池被重建过而 resource map 没跟着对齐，
框架就认不出 android:value，于是报
  <meta-data> requires an android:value or android:resource attribute
——而 aapt2 按字符串显示，看起来一切正常。
"""
import struct
import sys
import zipfile


def chunks(data):
    """遍历 AXML 的子 chunk。

    注意：最外层是 ResXMLTree_header（type 0x0003），它的 size 是**整个文件**，
    直接按它前进就再也走不到子 chunk 了（第一次实现就踩了这个坑，导致
    「未找到字符串池」）。因此先跳过 8 字节的头，再从 8 开始逐个子 chunk 走。
    """
    top_type, _, top_size = struct.unpack_from("<HHI", data, 0)
    if top_type != 0x0003:
        return
    off = 8
    end = min(top_size, len(data))
    while off + 8 <= end:
        t, hdr, size = struct.unpack_from("<HHI", data, off)
        if size < 8 or off + size > end:
            break
        yield off, t, hdr, size
        off += size


def parse_pool(data, off, size):
    hdr = struct.unpack_from("<HHI", data, off)[1]
    cnt, stycnt, flags, strstart, stylestart = struct.unpack_from("<IIIII", data, off + 8)
    utf8 = bool(flags & (1 << 8))
    offs = struct.unpack_from("<%dI" % cnt, data, off + hdr)
    out = []
    for o in offs:
        p = off + strstart + o
        if utf8:
            n = data[p]
            if n & 0x80:
                n = ((n & 0x7F) << 8) | data[p + 1]
                p += 2
            else:
                p += 1
            out.append(data[p:p + n].decode("utf-8", "replace"))
        else:
            n = struct.unpack_from("<H", data, p)[0]
            p += 2
            if n & 0x8000:
                n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", data, p)[0]
                p += 2
            out.append(data[p:p + n * 2].decode("utf-16-le", "replace"))
    return out


def analyze(path, tag):
    z = zipfile.ZipFile(path)
    data = z.read("AndroidManifest.xml")
    pool, rmap = None, None
    for off, t, hdr, size in chunks(data):
        if t == 0x0001 and pool is None:
            pool = parse_pool(data, off, size)
        elif t == 0x0180:
            n = (size - 8) // 4
            rmap = list(struct.unpack_from("<%dI" % n, data, off + 8))
    print("=== %s ===" % tag)
    if pool is None:
        print("  未找到字符串池")
        return
    print("  字符串数=%d  resource_map 条目数=%s" % (len(pool), len(rmap) if rmap else None))
    for want in ("value", "resource", "name"):
        if want in pool:
            i = pool.index(want)
            rid = rmap[i] if (rmap and i < len(rmap)) else None
            print("  属性名 %-9s 字符串索引=%d  resource_map[%d]=%s"
                  % (repr(want), i, i, hex(rid) if rid else "缺失"))
        else:
            print("  属性名 %-9s 不在字符串池里" % repr(want))
    # 列出 resource_map 覆盖到的字符串
    if rmap:
        covered = [(i, pool[i], hex(rmap[i])) for i in range(min(len(rmap), len(pool)))]
        print("  resource_map 覆盖的字符串（前 20 条）:")
        for i, s, r in covered[:20]:
            print("     [%2d] %-28s -> %s" % (i, s[:28], r))


if __name__ == "__main__":
    analyze(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else sys.argv[1])

def walk_elements(path):
    """列出每个 start element 及其属性（名字 + 解析出的资源 ID）。"""
    z = zipfile.ZipFile(path)
    data = z.read("AndroidManifest.xml")
    pool, rmap = None, []
    for off, t, hdr, size in chunks(data):
        if t == 0x0001 and pool is None:
            pool = parse_pool(data, off, size)
        elif t == 0x0180:
            n = (size - 8) // 4
            rmap = list(struct.unpack_from("<%dI" % n, data, off + 8))
    if pool is None:
        print("  无字符串池")
        return
    for off, t, hdr, size in chunks(data):
        if t != 0x0102:  # RES_XML_START_ELEMENT
            continue
        a = off + hdr                      # ResXMLTree_attrExt
        ns_i, name_i, attr_start, attr_size, cnt = struct.unpack_from("<IIHHH", data, a)
        name = pool[name_i] if name_i < len(pool) else "?"
        parts = []
        for k in range(cnt):
            p = a + attr_start + k * attr_size
            ans, anm, raw, dsize, res0, dtype, dval = struct.unpack_from("<IIIHBBI", data, p)
            an = pool[anm] if anm < len(pool) else "?"
            rid = rmap[anm] if anm < len(rmap) else 0
            parts.append("%s(id=%s idx=%d type=0x%02x)" % (an, hex(rid) if rid else "无", anm, dtype))
        print("  <%s> %s" % (name, ", ".join(parts)))


if len(sys.argv) > 3 and sys.argv[3] == "elements":
    walk_elements(sys.argv[1])
