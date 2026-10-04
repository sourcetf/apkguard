#!/usr/bin/env python3
"""对加固产物做「产物级」断言：确认启用的功能项在产物里真的留下了痕迹。

为什么需要它：端到端脚本此前只验证「签名有效 + 对齐正确」，于是
「启用了 A9/A10/A12，但产物里什么都没有」这种失败模式完全看不出来——
功能项在功能表里声明为已实现、命令 exit code 为 0，实际却毫无作用。
这个脚本按功能项逐个检查产物特征，把那类「静默不生效」变成构建失败。

用法：
    verify-products.py <加固后的.apk> <启用的功能项,逗号分隔> [--channel 名字]
                       [--c2-lib 原始.so名] [--c2-size 原始.so字节数]

退出码：0 = 全部通过；1 = 有断言失败（会逐条打印原因）。
"""

import io
import re
import struct
import sys
import unicodedata
import zipfile

# 与 internal/passes/shell.go 的 ChannelAssetName 保持一致。
CHANNEL_ASSET = "assets/apkguard_channel.txt"

# A8 的诱饵类名已改为由 seed 派生（主题包 + 三个名族），不再有固定类名清单；
# 这里保留的是族内名词词表（与 internal/passes/passes.go 的 decoyNouns 对齐），
# 用于「类名是否像诱饵」的结构化判定：简单名 = 名族前缀 + 词表名词（如 CoreAtlas）。
DECOY_NOUNS = [
    "Atlas", "Forge", "Hatch", "Orbit", "Ridge", "Spire",
    "Beacon", "Courier", "Drift", "Echo", "Flux", "Gauge",
    "Annex", "Basin", "Creek", "Dune", "Field", "Lattice",
]

# 与 internal/dex/shell.go 的壳类名保持一致。
SHELL_CLASS = "com.apkguard.shell.App"

DEX_HEADER_CLASS_DEFS_SIZE = 0x60  # class_defs_size 在 DEX 头部偏移 0x60
DEX_HEADER_CLASS_DEFS_OFF = 0x64   # class_defs_off 在 DEX 头部偏移 0x64
CLASS_DEF_SIZE = 32
CLASS_DEF_SOURCE_FILE_IDX = 16
NO_INDEX = 0xFFFFFFFF

FAKE_DEX_RE = re.compile(r"^(CLASSES\.DEX|Classes\.Dex|classes\.DEX)(\.\d+)?$")

# B8 的容器目录：assets/<词>/<8 位十六进制>/...。
# 诱饵容器已改为「与真实载荷同构」：不再是顶层 `assets/<词>_<hex8>.zip`（带 PK 头，
# 一眼可辨），而是落在**同一目录树**下的 `<12 位十六进制>.json`（写假包名）。
CONTAINER_DIR_RE = re.compile(r"^assets/[a-z]+/[0-9a-f]{8}/")
DECOY_CFG_RE = re.compile(r"^assets/[a-z]+/[0-9a-f]{8}/[0-9a-f]{12}[.]json$")

# B1 的加密载荷条目名：assets/<伪装词>_<8 位十六进制>.<伪装扩展名>。
# 扩展名从 .bin/.dat/.res/.pack 里按哈希挑一个（见 internal/pack/pack.go 的
# assetExts），所以不能只认 .bin。
#
# 注意：C2（SO 加壳）的载荷条目名用的是**同一套命名规范**（见
# internal/passes/soenc.go 的 soAssetName），因此 PAYLOAD_RE 同时匹配两者的
# 载荷——不能靠名字区分 B1 与 C2 的产物。
PAYLOAD_RE = re.compile(r"^assets/[A-Za-z]+_[0-9a-f]{8}\.(bin|dat|res|pack)$")

# A6 控制流混淆在 DEX 里留下的**不透明谓词指令骨架**。
#
# internal/dex/cff.go 的 predicateInsns 依次生成 8 条指令，每条都是 4 字节编码：
#   const/16 vP,c | const/16 vT,c | mul-int vP,vP,vP | sub-int vP,vP,vT |
#   const/16 vT,1 | and-int vP,vP,vT | if-eqz vP,off | goto/16 off
# 寄存器 P/T 与常量 c 随方法变化，但 opcode 与「同一寄存器重复出现」的结构固定，
# 因此用带反向引用的字节模式匹配：\1=vP、\2=常量 c（两字节）、\3=vT。
#
# 这是产物自身的证据，比 DEX 体积或加固日志里的统计更硬：实测在未加固的
# classes.dex 上命中 0 次、在启用 A6 的产物上命中数与注入组数一致。
A6_PREDICATE_RE = re.compile(
    rb"\x13(.)(..)\x13(.)\2"  # const/16 vP,c ; const/16 vT,c
    rb"\x92\1\1\1"            # mul-int vP,vP,vP
    rb"\x91\1\1\3"            # sub-int vP,vP,vT
    rb"\x13\3\x01\x00"        # const/16 vT,#1
    rb"\x95\1\1\3"            # and-int vP,vP,vT
    rb"\x38\1"                # if-eqz vP,off
)

# A6 的「不可达前向跳转块」骨架：方法入口处两条 goto/16（opcode 0x29），
# 分别前向偏移 4 与 2 个码元，都指向紧随其后的真实入口。当前实现（cffRegs
# 修好宽值寄存器占用后）在受控测试应用上不透明谓词覆盖为 0，真实痕迹落在这
# 对 goto 上，因此 A6 的产物断言必须同时认这一形态。
#
# 注意：A20 无害花指令用的是同一对 goto 形态（只是前面多几个 nop），在产物
# 字节上二者不可区分；因此本断言只能证明「A6 或 A20 生效」，两者同时启用时
# 无法把功劳单独记给 A6。
A6_FAKEJUMP_RE = re.compile(rb"\x29\x00\x04\x00\x29\x00\x02\x00")


def read_bytes(zf, name):
    with zf.open(name) as fh:
        return fh.read()


def dex_strings(data):
    """粗粒度地把 DEX 里可读的 MUTF-8 字符串片段取出来。

    不做完整 DEX 解析：类名/字符串常量在池里以 NUL 结尾的 MUTF-8 存放，
    对「某名字是否还在产物里」这类判定，逐段解码足够且不引入新解析风险。
    """
    out = set()
    for chunk in data.split(b"\x00"):
        if not chunk:
            continue
        try:
            out.add(chunk.decode("utf-8"))
        except UnicodeDecodeError:
            continue
    return out


def class_count(data):
    if len(data) < DEX_HEADER_CLASS_DEFS_SIZE + 4:
        return 0
    return int.from_bytes(data[DEX_HEADER_CLASS_DEFS_SIZE:DEX_HEADER_CLASS_DEFS_SIZE + 4], "little")


def source_file_indexes(data):
    """返回每个 class_def 的 source_file_idx；解析不了时返回 None。

    class_def_item 的布局（DEX 规范）：
        class_idx(0) access_flags(4) superclass_idx(8) interfaces_off(12)
        source_file_idx(16) annotations_off(20) class_data_off(24) static_values_off(28)
    A4 要做的是把这个字段置为 NO_INDEX，这样 jadx 之类的工具就读不到源文件名。
    """
    if len(data) < DEX_HEADER_CLASS_DEFS_OFF + 4:
        return None
    n = class_count(data)
    off = int.from_bytes(data[DEX_HEADER_CLASS_DEFS_OFF:DEX_HEADER_CLASS_DEFS_OFF + 4], "little")
    if n == 0 or off == 0 or off + n * CLASS_DEF_SIZE > len(data):
        return None
    out = []
    for i in range(n):
        base = off + i * CLASS_DEF_SIZE + CLASS_DEF_SOURCE_FILE_IDX
        out.append(int.from_bytes(data[base:base + 4], "little"))
    return out


# android 框架属性名 -> 资源 ID。Android 解析属性名用的是**资源 ID**，
# 不是字符串，所以下面这张表用来核对 resource map 是否覆盖到注入的属性。
ANDROID_ATTR_IDS = {
    "name": 0x01010003, "label": 0x01010001, "enabled": 0x0101000E,
    "exported": 0x01010010, "authorities": 0x01010018, "permission": 0x01010006,
    "process": 0x01010011, "value": 0x01010024, "resource": 0x01010025,
    "required": 0x0101028E, "targetActivity": 0x01010202,
    "appComponentFactory": 0x0101057A,
}


def _axml_chunks(data):
    """遍历 AXML 的子 chunk（跳过 8 字节的 ResXMLTree_header）。"""
    if len(data) < 8:
        return
    top_type, _, top_size = struct.unpack_from("<HHI", data, 0)
    if top_type != 0x0003:
        return
    off = 8
    end = min(top_size, len(data))
    while off + 8 <= end:
        t, _hdr, size = struct.unpack_from("<HHI", data, off)
        if size < 8 or off + size > end:
            return
        yield off, t, size
        off += size


def _axml_strings(data, off, size):
    hdr = struct.unpack_from("<HHI", data, off)[1]
    cnt, _sty, flags, strstart, _stystart = struct.unpack_from("<IIIII", data, off + 8)
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


def axml_attr_resid_problems(raw):
    """检查 Manifest 里 android 命名空间的框架属性名是否都能解析出资源 ID。

    返回问题描述列表。这是**安装期硬要求**：resource map 是按字符串索引对齐的
    数组，索引超出长度的属性会被框架当成「未知属性」。曾因此产出装不上的包：

        INSTALL_PARSE_FAILED_MANIFEST_MALFORMED:
          <meta-data> requires an android:value or android:resource attribute

    诱因是 A18 注入 <meta-data android:value="…"> 时，`value` 是池里的新字符串，
    落在 resource map 覆盖范围之外。真实应用恰好自己用过 value/required，
    所以只有 Manifest 属性少的小应用才暴露——产物断言必须独立守住这条。
    """
    pool = rmap = None
    for off, t, size in _axml_chunks(raw):
        if t == 0x0001 and pool is None:
            pool = _axml_strings(raw, off, size)
        elif t == 0x0180:
            n = (size - 8) // 4
            rmap = list(struct.unpack_from("<%dI" % n, raw, off + 8))
    if pool is None:
        return ["Manifest 里找不到字符串池"]
    if rmap is None:
        return ["Manifest 里没有 RES_XML_RESOURCE_MAP（框架无法按资源 ID 解析任何属性）"]
    problems = []
    for off, t, size in _axml_chunks(raw):
        if t != 0x0102:  # RES_XML_START_ELEMENT
            continue
        hdr = struct.unpack_from("<HHI", raw, off)[1]
        a = off + hdr
        name_i, attr_start, attr_size, cnt = struct.unpack_from("<IHHH", raw, a + 4)
        elem = pool[name_i] if name_i < len(pool) else "?"
        for k in range(cnt):
            p = a + attr_start + k * attr_size
            _ns, anm = struct.unpack_from("<II", raw, p)
            if anm >= len(pool):
                continue
            an = pool[anm]
            if an not in ANDROID_ATTR_IDS:
                continue
            if anm >= len(rmap):
                problems.append("<%s> 的属性 %s（字符串索引 %d）超出 resource map 长度 %d："
                                "框架会把它当成未知属性" % (elem, an, anm, len(rmap)))
            elif rmap[anm] != ANDROID_ATTR_IDS[an]:
                problems.append("<%s> 的属性 %s 资源 ID 错误：resource_map[%d]=0x%08x，期望 0x%08x"
                                % (elem, an, anm, rmap[anm], ANDROID_ATTR_IDS[an]))
    return problems


def manifest_contains(raw, needle):
    """在 AndroidManifest.xml 的原始字节里找 needle（UTF-8 或 UTF-16LE 都试）。

    参数是 **Manifest 的原始字节**而不是 ZipFile：调用方在 with 块里一次性读出，
    之后再拿 ZipFile 去 open 会因为归档已关闭而报错。
    """
    if needle.encode("utf-8") in raw:
        return True
    return needle.encode("utf-16-le") in raw


def manifest_component_of(raw, needle):
    """返回「引用 needle 的那个元素的元素名」（如 receiver/service/provider）。

    AXML 的块列表是线性的，没有父子指针。这里顺序遍历全部块，记录最近一个
    start element 的元素名与它携带的属性字符串；当某个属性字符串等于 needle 时，
    当前元素名就是答案。

    只解到「元素名 + 属性原始文本」这一层，不解析 Res_value 的数值语义——
    对「这个名字被声明成哪种组件」的判定已经足够。
    """

    def pool_strings():
        """读字符串池，返回 [文本]（按池索引）。"""
        if len(raw) < 12:
            return []
        off = 8  # 跳过根块头
        while off + 8 <= len(raw):
            typ = int.from_bytes(raw[off:off + 2], "little")
            size = int.from_bytes(raw[off + 4:off + 8], "little")
            if size < 8 or off + size > len(raw):
                return []
            if typ == 0x0001:  # RES_STRING_POOL_TYPE
                count = int.from_bytes(raw[off + 8:off + 12], "little")
                flags = int.from_bytes(raw[off + 16:off + 20], "little")
                sstart = int.from_bytes(raw[off + 20:off + 24], "little")
                utf8 = bool(flags & 0x100)
                base = off + sstart
                out, p = [], base
                for _ in range(count):
                    if utf8:
                        # UTF-8 池：字符数（变长） + 字节数（变长） + 数据 + NUL
                        def _u8len(q):
                            b = raw[q]
                            if b & 0x80:
                                return ((b & 0x7F) << 8) | raw[q + 1], q + 2
                            return b, q + 1
                        _, p2 = _u8len(p)
                        blen, p3 = _u8len(p2)
                        out.append(raw[p3:p3 + blen].decode("utf-8", "replace"))
                        p = p3 + blen + 1
                    else:
                        # UTF-16 池：码元数（变长） + 数据 + NUL
                        n = int.from_bytes(raw[p:p + 2], "little")
                        if n & 0x8000:
                            n = int.from_bytes(raw[p + 2:p + 4], "little")
                            p += 4
                        else:
                            p += 2
                        out.append(raw[p:p + n * 2].decode("utf-16-le", "replace"))
                        p += n * 2 + 2
                return out
            off += size
        return []

    pool = pool_strings()
    if not pool:
        return None
    off = 8
    current = None
    while off + 8 <= len(raw):
        typ = int.from_bytes(raw[off:off + 2], "little")
        size = int.from_bytes(raw[off + 4:off + 8], "little")
        if size < 8 or off + size > len(raw):
            break
        if typ == 0x0102 and off + 36 <= len(raw):  # RES_XML_START_ELEMENT_TYPE
            name_idx = int.from_bytes(raw[off + 20:off + 24], "little")
            attr_start = int.from_bytes(raw[off + 24:off + 26], "little")
            attr_size = int.from_bytes(raw[off + 26:off + 28], "little")
            attr_count = int.from_bytes(raw[off + 28:off + 30], "little")
            current = pool[name_idx] if name_idx < len(pool) else None
            p = off + 16 + attr_start
            for _ in range(attr_count):
                if p + attr_size > off + size:
                    break
                raw_idx = int.from_bytes(raw[p + 8:p + 12], "little")
                data_idx = int.from_bytes(raw[p + 16:p + 20], "little")
                dtype = raw[p + 15]
                for idx in (raw_idx, data_idx):
                    if idx == NO_INDEX or idx >= len(pool):
                        continue
                    if dtype == 0x03 and pool[idx] == needle:
                        return current
                p += attr_size
        off += size
    return None


def _axml_pool_strings(raw):
    """读 AXML 字符串池，返回 [文本]（按池索引）。

    与 manifest_component_of 内的 pool_strings 同实现；A8 的类名由 seed 派生、
    无法预先枚举，按结构识别组件时需要自己枚举 start element 与属性名。
    """
    if len(raw) < 12:
        return []
    off = 8  # 跳过根块头
    while off + 8 <= len(raw):
        typ = int.from_bytes(raw[off:off + 2], "little")
        size = int.from_bytes(raw[off + 4:off + 8], "little")
        if size < 8 or off + size > len(raw):
            return []
        if typ == 0x0001:  # RES_STRING_POOL_TYPE
            count = int.from_bytes(raw[off + 8:off + 12], "little")
            flags = int.from_bytes(raw[off + 16:off + 20], "little")
            sstart = int.from_bytes(raw[off + 20:off + 24], "little")
            utf8 = bool(flags & 0x100)
            base = off + sstart
            out, p = [], base
            for _ in range(count):
                if utf8:
                    # UTF-8 池：字符数（变长） + 字节数（变长） + 数据 + NUL
                    def _u8len(q):
                        b = raw[q]
                        if b & 0x80:
                            return ((b & 0x7F) << 8) | raw[q + 1], q + 2
                        return b, q + 1
                    _, p2 = _u8len(p)
                    blen, p3 = _u8len(p2)
                    out.append(raw[p3:p3 + blen].decode("utf-8", "replace"))
                    p = p3 + blen + 1
                else:
                    # UTF-16 池：码元数（变长） + 数据 + NUL
                    n = int.from_bytes(raw[p:p + 2], "little")
                    if n & 0x8000:
                        n = int.from_bytes(raw[p + 2:p + 4], "little")
                        p += 4
                    else:
                        p += 2
                    out.append(raw[p:p + n * 2].decode("utf-16-le", "replace"))
                    p += n * 2 + 2
            return out
        off += size
    return []


def _manifest_components(raw):
    """返回 Manifest 里全部 (元素名, android:name 文本) 对（仅字符串型属性）。"""
    pool = _axml_pool_strings(raw)
    if not pool:
        return []
    out = []
    off = 8
    while off + 8 <= len(raw):
        typ = int.from_bytes(raw[off:off + 2], "little")
        size = int.from_bytes(raw[off + 4:off + 8], "little")
        if size < 8 or off + size > len(raw):
            break
        if typ == 0x0102 and off + 36 <= len(raw):  # RES_XML_START_ELEMENT_TYPE
            name_idx = int.from_bytes(raw[off + 20:off + 24], "little")
            attr_start = int.from_bytes(raw[off + 24:off + 26], "little")
            attr_size = int.from_bytes(raw[off + 26:off + 28], "little")
            attr_count = int.from_bytes(raw[off + 28:off + 30], "little")
            elem = pool[name_idx] if name_idx < len(pool) else None
            p = off + 16 + attr_start
            for _ in range(attr_count):
                if p + attr_size > off + size:
                    break
                attr_name_idx = int.from_bytes(raw[p + 4:p + 8], "little")
                data_idx = int.from_bytes(raw[p + 16:p + 20], "little")
                dtype = raw[p + 15]
                if (dtype == 0x03 and attr_name_idx < len(pool) and pool[attr_name_idx] == "name"
                        and data_idx < len(pool)):
                    out.append((elem, pool[data_idx]))
                p += attr_size
        off += size
    return out


def _decoy_like_class(cls):
    """A8 诱饵类的简单名 = 名族前缀 + 词表名词（如 CoreAtlas / SignalBeacon）。"""
    if "." not in cls:
        return False
    simple = cls.rsplit(".", 1)[-1]
    return any(simple.endswith(n) and simple != n for n in DECOY_NOUNS)


def _decoy_components(raw):
    """返回 Manifest 里所有「像 A8 诱饵」的 (元素名, 类名) 对。"""
    return [(kind, cls) for kind, cls in _manifest_components(raw) if _decoy_like_class(cls)]


def _decoy_is_provider(raw):
    """是否有诱饵类被声明成 <provider>（会在应用启动时被实例化）。"""
    return any(kind == "provider" for kind, _ in _decoy_components(raw))


class Checker:
    def __init__(self, apk, features, channel=None, c2_lib=None, c2_size=None):
        self.apk = apk
        self.features = {f.strip().upper() for f in features if f.strip()}
        self.channel = channel
        # C2 断言用的原始业务库名与字节数（由 e2e 传入，可选）。
        self.c2_lib = c2_lib
        self.c2_size = c2_size
        self.fails = []
        self.notes = []
        with zipfile.ZipFile(apk) as zf:
            self.names = zf.namelist()
            self.manifest = read_bytes(zf, "AndroidManifest.xml") if "AndroidManifest.xml" in self.names else b""
            dex = [n for n in self.names if n == "classes.dex"]
            self.shell_dex = read_bytes(zf, "classes.dex") if dex else b""
            self.dex_strs = dex_strings(self.shell_dex) if dex else set()
            self.payloads = [n for n in self.names if PAYLOAD_RE.match(n)]

    def want(self, feat):
        return feat in self.features

    def check(self, cond, feat, msg):
        if not cond:
            self.fails.append("[%s] %s" % (feat, msg))

    def run(self):
        zv = zipfile.ZipFile(self.apk)
        try:
            self._run(zv)
        finally:
            zv.close()
        return self.fails

    def _run(self, zf):
        # ---- 无条件检查：resources.arsc 必须未压缩存放 ----
        #
        # Android 11+（targetSdk ≥ 30）的安装期硬要求；违反时安装直接被拒：
        #   Failure [-124] ... requires the resources.arsc of installed APKs
        #   to be stored uncompressed and aligned on a 4-byte boundary
        # apksigner 与 zipalign -c 都不会报错，所以这条必须单独断言——
        # 否则「产物装不上」只有装机才能发现。
        if "resources.arsc" in self.names:
            info = zf.getinfo("resources.arsc")
            self.check(info.compress_type == 0, "ALL",
                       "resources.arsc 是压缩存放（compress_type=%d）——Android 11+ 会拒绝安装该 APK"
                       % info.compress_type)

        # ---- A14 元数据统一化：产物最多允许三组时间戳 ----
        #
        # 签名阶段会新增 MANIFEST.MF / CERT.SF / CERT.RSA 三个条目，它们晚于
        # A14。若它们退回 ZIP 的 1980 默认值，产物里就出现「唯独签名文件是
        # 1980」这一枚独有的重打包指纹——恰好与 A14 消除痕迹的目的相反。
        # 这条断言曾经抓到一次真实回归（3 个签名条目全是 1980）。
        #
        # A14 现在按注入阶段派生三组时间戳：基准 / +32s / +44s（对齐参考样本的
        # 22:01:08 / 22:01:40 / 22:01:52）。启用 A10/A12 等注入类功能时最多出现
        # 3 个；只有原始条目时退化为 1 个（全部条目同一秒本身就是重打包指纹）。
        if self.want("A14"):
            stamps = {}
            for info in zf.infolist():
                stamps.setdefault(info.date_time, []).append(info.filename)
            self.check(len(stamps) <= 3, "A14",
                       "产物出现 %d 个不同时间戳（A14 最多派生 3 个：基准/+32s/+44s）：%s"
                       % (len(stamps), {k: v[:4] for k, v in stamps.items()}))

            def _dos_secs(t):
                return ((((t[0] * 12 + t[1] - 1) * 31 + t[2] - 1) * 24 + t[3]) * 3600
                        + t[4] * 60 + t[5])

            keys = sorted(stamps)
            if keys:
                base = _dos_secs(keys[0])
                for k in keys[1:]:
                    delta = (_dos_secs(k) - base) % 86400
                    self.check(delta in (32, 44), "A14",
                               "时间戳 %s 与最早时间戳 %s 相差 %d 秒，不在 A14 的 +32s/+44s 派生内"
                               % (k, keys[0], delta))
            for k, names in stamps.items():
                if k[0] == 1980:
                    self.check(False, "A14",
                               "以下条目残留 1980 默认时间戳（签名阶段新增的条目未沿用统一时间）：%s"
                               % names[:6])

        # ---- 无条件：Manifest 的属性必须都能按资源 ID 解析（安装期硬要求）----
        #
        # 这一条与具体功能项无关：任何往 Manifest 注入元素的 Pass（A8/A16/A18…）
        # 都可能因为新属性名没有资源 ID 而产出**装不上**的包，而 apksigner 与
        # zipalign 都不会报错（它们不解析 Manifest）。所以必须在这里守住。
        for prob in axml_attr_resid_problems(self.manifest):
            self.check(False, "ALL", "Manifest 属性资源 ID 异常：" + prob)

        # ---- B1 DEX 整体加密：明文业务类不在 classes.dex 里，载荷在 assets/ ----
        #
        # 注意：启用 B8 后载荷被移进容器目录（assets/<词>/<hex>/...），
        # 不再匹配顶层载荷命名，因此两种位置都算数。
        if self.want("B1"):
            in_container = [n for n in self.names if CONTAINER_DIR_RE.match(n)]
            found = self.payloads or in_container
            if self.want("B8"):
                self.check(bool(in_container), "B1",
                           "启用 B8 后应在容器目录里找到载荷（assets/<词>/<hex>/）")
            else:
                self.check(bool(found), "B1",
                           "assets/ 下找不到加密载荷（*.bin/*.dat/*.res/*.pack）")
            self.check("Lcom/agtest/MainActivity;" not in self.dex_strs, "B1",
                       "classes.dex 里仍能看到业务类 MainActivity（未被加密载荷替换）")

        # ---- B2 Application 替换：Manifest 指向壳类 ----
        if self.want("B2"):
            self.check(manifest_contains(self.manifest, SHELL_CLASS), "B2",
                       "Manifest 里找不到壳类 %s（android:name 未被改写）" % SHELL_CLASS)

        # ---- B9 双 APK 投放器：产物是宿主，原应用是加密插件 ----
        #
        # 判据取自「宿主形态」而不是原应用：宿主必须声明安装权限，且 assets 下
        # 必须有一个高熵、非 ZIP 的载荷（插件本体）。原应用的资源/类名在这里
        # 不该出现——那正是双 APK 形态的意义。
        if self.want("B9"):
            self.check(manifest_contains(self.manifest, "REQUEST_INSTALL_PACKAGES"), "B9",
                       "宿主 Manifest 未声明 REQUEST_INSTALL_PACKAGES（无法调起安装器）")
            import math
            plugs = []
            for n in self.names:
                if not n.startswith("assets/"):
                    continue
                data = zf.read(n)
                if len(data) < 4096:
                    continue
                if data[:4] == b"PK":
                    continue
                # 香农熵：加密载荷应接近 8 bit/byte
                cnt = [0] * 256
                for b in data:
                    cnt[b] += 1
                ent = -sum((c / len(data)) * math.log2(c / len(data)) for c in cnt if c)
                if ent > 7.5:
                    plugs.append((n, len(data), ent))
            self.check(bool(plugs), "B9",
                       "宿主 assets 下找不到高熵加密插件载荷")
            self.check("Lcom/agtest/MainActivity;" not in self.dex_strs, "B9",
                       "宿主 classes.dex 里出现了原应用业务类（宿主不应包含业务代码）")

        # ---- A4 调试信息清除 ----
        #
        # 判据是「class_def.source_file_idx 全部置空」——这正是 jadx 读取源文件名的
        # 入口。注意本 Pass **不会**把已失去引用的字符串从池里删掉（那需要完整
        # 引用扫描，风险高），所以 strings 仍可能捞到 *.java 字面量：这是已知局限，
        # 记入提示而不是失败，避免断言超出实现真正保证的范围。
        if self.want("A4"):
            idx = source_file_indexes(self.shell_dex)
            if idx is None:
                self.fails.append("[A4] 无法解析 classes.dex 的 class_defs")
            else:
                bad = [i for i, v in enumerate(idx) if v != NO_INDEX]
                self.check(not bad, "A4",
                           "%d/%d 个 class_def 仍带有 source_file_idx（源文件名未被清除）"
                           % (len(bad), len(idx)))
            leaked = sorted(s for s in self.dex_strs if s.endswith(".java"))
            if leaked:
                self.notes.append(
                    "[A4] 提示：字符串池仍保留 %d 个 *.java 字面量（如 %s）——"
                    "是 A4 的已知局限（不裁剪字符串池），不影响反编译视图。"
                    % (len(leaked), leaked[0]))

        # ---- A5 / A11 资源改名与扁平化 ----
        res_entries = [n for n in self.names if n.startswith("res/")]
        if self.want("A5") or self.want("A11"):
            self.check("res/layout/main.xml" not in self.names, "A5",
                       "res/layout/main.xml 未被改名（资源混淆没生效）")
            self.check(bool(res_entries), "A5", "res/ 条目全部消失了")
        if self.want("A11"):
            # A10 的「真资源路径变体」垃圾族（对齐样本）故意用 aapt2 源文件名当
            # 目录前缀（res/values/integers.xml//\///.xml 这类畸形路径）；它们是
            # 注入的诱饵、不是真实资源，判据必须先排除含 \ 或 // 的畸形名，
            # 否则 A10 与 A11 会互相误报。
            def _clean_res(n):
                return "\\" not in n and "//" not in n
            semantic = [n for n in res_entries
                        if _clean_res(n) and len(n.split("/")) >= 3
                        and len(n.split("/")[1]) != 1]
            self.check(not semantic, "A11",
                       "res/ 下仍存在语义目录名：%s" % semantic[:5])

        # ---- A8 诱饵类注入 ----
        if self.want("A8"):
            # 诱饵类名必须真的声明成 Manifest 组件：否则静态分析者扫一遍组件表
            # 就能看出「没有任何安全相关组件」，立刻判定这些类是填充物。
            #
            # 命名已由 seed 派生（主题包 + Core*/Signal*/Quiet* 三名族），无法用
            # 固定类名断言；改为按结构识别：简单名 = 名族前缀 + 词表名词。
            # 判据用 Manifest 而不是 DEX：启用 B1 时业务 DEX 已被加密成载荷，
            # 诱饵类名不会出现在任何明文 DEX 里，靠 DEX 字符串判断会误报失败。
            decoys = _decoy_components(self.manifest)
            decoy_kinds = {kind for kind, _ in decoys}
            self.check(len(decoys) >= 3, "A8",
                       "Manifest 里没有诱饵组件声明（只注入类是不够的）")
            self.check({"activity", "receiver", "service"} <= decoy_kinds, "A8",
                       "诱饵组件缺少 activity/receiver/service 三类形态之一：%s" % sorted(decoy_kinds))
            if not self.want("B1"):
                hit = any(n in s for s in self.dex_strs for n in DECOY_NOUNS)
                self.check(hit, "A8", "DEX 里找不到任何诱饵类名词（如 CoreAtlas/SignalBeacon）")
            # ContentProvider 会在应用启动时被主动实例化，诱饵绝不能声明成 provider。
            if decoys:
                self.check(not _decoy_is_provider(self.manifest),
                           "A8", "诱饵被声明成了 <provider>（会在启动时被实例化）")

        # ---- A16 诱饵核心文件：大小写/同形变体，且绝不撞真名 ----
        if self.want("A16"):
            # 判据：存在与真核心文件同名（忽略大小写）但大小写不同的变体条目。
            # 排除三个精确名即可——resources.arsc 本身全小写，所以它的变体必然是
            # 混合大小写（如 Resources.Arsc）；Manifest/dex 的变体同理。
            variants = [n for n in self.names if "/" not in n
                        and n.lower() in ("androidmanifest.xml", "resources.arsc", "classes.dex")
                        and n not in ("AndroidManifest.xml", "resources.arsc", "classes.dex")]
            self.check(bool(variants), "A16",
                       "找不到大小写/同形变体的假核心文件（如 ANDROIDMANIFEST.XML）")
            # 真核心文件必须恰好各一条，否则系统会读到假的、应用直接死。
            for real in ("AndroidManifest.xml", "resources.arsc", "classes.dex"):
                self.check(self.names.count(real) == 1, "A16",
                           "真核心文件 %s 的条目数不是 1（系统可能读到假的那份）" % real)

        # ---- A17 假内层 APK：assets 下存在一个能被打开的完整 APK ----
        if self.want("A17"):
            nested = []
            # 直接用 _run 传进来的 zf（它在整个 _run 期间都是打开的）。
            #
            # 曾经这里写成 `with zipfile.ZipFile(self.apk) as zf:`——那会**遮蔽**
            # 同名参数，with 结束时把参数指向的归档关掉；后续任何用 zf 的断言
            # （如 E4 渠道）就会抛 "Attempt to use ZIP archive that was already
            # closed"。参数本身就是打开的那个，直接用即可。
            blobs = {n: read_bytes(zf, n) for n in self.names if n.startswith("assets/")}
            for n, blob in blobs.items():
                if not blob.startswith(b"PK"):
                    continue
                try:
                    iz = zipfile.ZipFile(io.BytesIO(blob))
                except Exception:
                    continue
                inner = iz.namelist()
                if ("AndroidManifest.xml" in inner and "resources.arsc" in inner
                        and any(x.startswith("classes") and x.endswith(".dex") for x in inner)):
                    nested.append(n)
            self.check(bool(nested), "A17",
                       "assets 下找不到「自带 Manifest/arsc/dex 的完整假 APK」")

        # ---- A18 Manifest 诱饵元数据：自定义权限 + required=false 特性 ----
        #
        # 必须用 manifest_contains（UTF-8 与 UTF-16LE 都试）：二进制 AXML 的字符串
        # 池通常是 UTF-16，裸字节搜 ASCII 一定搜不到（这一点踩过一次）。
        if self.want("A18"):
            self.check(manifest_contains(self.manifest, ".permission."), "A18",
                       "Manifest 里找不到自定义权限声明（诱饵权限没生效）")
            # 不能断言「Manifest 里没有 android.permission.*」：真实应用自己就会
            # 声明 INTERNET/CAMERA 之类的系统权限，这条会无条件误报。
            # A18 的约束是「它**新增**的诱饵权限用自定义名」（系统不认识 → 不影响
            # 安装与授权），而合并后的 Manifest 无法区分哪些是原有、哪些是新增。
            # 因此只保留正向断言：诱饵权限确实以自定义名写入了。
            if manifest_contains(self.manifest, "android.permission."):
                self.notes.append("A18：Manifest 含系统权限名，可能来自应用自身声明（无法区分新增/原有），不做失败判定")
            self.check(manifest_contains(self.manifest, "uses-feature"), "A18",
                       "Manifest 里找不到 uses-feature（诱饵特性没生效）")
            self.check(manifest_contains(self.manifest, "queries"), "A18",
                       "Manifest 里找不到 queries 包可见性声明（诱饵没生效）")

        # ---- C2 SO 加壳：业务 .so 从 lib/ 移走，变成 assets 下的加密载荷 ----
        #
        # 与 B1 的载荷同规范命名，无法靠名字区分，因此判据是：
        #   1) 原始业务库名（--c2-lib）必须已从 lib/ 消失；
        #   2) assets 下存在**密文**载荷（首字节不是 ELF magic）；
        #   3) 若给出原始字节数（--c2-size），必须能找到一条长度≈明文+IV+填充
        #      （16~64 字节增量）的载荷——把「某条载荷」与「被移走的那个 .so」
        #      正向绑定，避免只靠「少了个文件」的弱断言。
        #
        # 局限：若同时启用 B1，assets 下会同时存在 B1 的 DEX 载荷；本断言靠
        # 大小匹配与「非 ELF」仍成立，但 C2 与 B1 载荷的彻底区分需要解密。
        if self.want("C2"):
            if self.c2_lib:
                left = [n for n in self.names if n.startswith("lib/")
                        and n.rsplit("/", 1)[-1] == self.c2_lib]
                self.check(not left, "C2",
                           "lib/ 下仍存在未加密的业务库：%s" % left)
            # 注意：启用 B8 后 C2 的库载荷也会被移进容器目录
            # （assets/<词>/<hex8>/<hex12>.<ext>），不再匹配顶层载荷命名。
            # 只认顶层会把「已加壳但被容器化」误判成「没加壳」。
            cand = list(self.payloads) + [n for n in self.names if CONTAINER_DIR_RE.match(n)]
            if not cand:
                self.fails.append("[C2] assets/ 下找不到任何加密载荷（业务 .so 未被加壳）")
            else:
                matched = False
                for n in cand:
                    blob = read_bytes(zf, n)
                    if blob[:4] == b"\x7fELF":
                        self.check(False, "C2", "载荷 %s 仍是明文 ELF（没有被加密）" % n)
                    if self.c2_size is not None:
                        delta = zf.getinfo(n).file_size - self.c2_size
                        if 16 <= delta <= 64:
                            matched = True
                    else:
                        matched = True
                if self.c2_size is not None:
                    self.check(matched, "C2",
                               "找不到与原始 .so（%d 字节）大小匹配的加密载荷" % self.c2_size)

        # ---- C7 原生库伪装：lib/ 下不再有 libapkguard.so，而是假名 ----
        if self.want("C7"):
            libs = [n for n in self.names if n.startswith("lib/") and n.endswith(".so")]
            guard = [n for n in libs if "apkguard" in n.lower()]
            self.check(not guard, "C7",
                       "lib/ 下仍存在暴露身份的守卫库名：%s" % guard)
            self.check(bool(libs), "C7",
                       "lib/ 下没有任何 .so（守卫库被搬走了？C7 应与 C2 协调）")

        # ---- A19 字符串池垃圾：DEX 里出现形似业务常量的注入串 ----
        #
        # 启用 B1 时 classes.dex 是**壳** DEX，业务 DEX 已加密进 assets；
        # 注入的垃圾串只在业务 DEX 里，壳里查不到。此时该断言不适用
        # （要验就得先解密载荷，超出本脚本的能力边界）。
        if self.want("A19"):
            if self.want("B1"):
                self.notes.append("A19 断言跳过：已启用 B1，业务 DEX 不在 classes.dex（壳里查不到注入串）")
            else:
                marks = [s for s in self.dex_strs
                         if "_api_key" in s or "api.internal." in s or "X-" in s and "Token" in s]
                self.check(bool(marks), "A19",
                           "classes.dex 的字符串池里找不到注入的垃圾串特征")

        # ---- A20 花指令：连续 nop（编译产物里不会连续出现）----
        if self.want("A20"):
            self.check(bytes([0, 0, 0, 0, 0, 0]) in self.shell_dex, "A20",
                       "classes.dex 里找不到连续 nop 填充（A20 未生效）")

        # ---- A6 控制流混淆：不透明谓词的固定指令骨架 ----
        #
        # 判据是产物自身的不透明谓词字节序列（见 A6_PREDICATE_RE）。这条比
        # 「DEX 变大」或「加固日志里的统计」更硬：体积可能被其它项改变，
        # 统计来自流程而非产物。仅适用于未启用 B1 的产物——B1 之后业务 DEX
        # 已被加密成载荷，明文 classes.dex 是壳，A6 痕迹不在其中。
        if self.want("A6"):
            if self.want("B1"):
                self.notes.append(
                    "[A6] 提示：已启用 B1，明文 classes.dex 是壳，A6 痕迹在加密载荷内，"
                    "本断言不适用（e2e 的 A6 功能集刻意不启用 B1）。")
            else:
                pred = len(A6_PREDICATE_RE.findall(self.shell_dex))
                fake = len(A6_FAKEJUMP_RE.findall(self.shell_dex))
                self.check(pred + fake > 0, "A6",
                           "classes.dex 里既无不透明谓词骨架、也无不可达跳转块（A6 未生效或未注入）")

        # ---- A9 伪 DEX 块 ----
        if self.want("A9"):
            fakes = [n for n in self.names if FAKE_DEX_RE.match(n)]
            self.check(bool(fakes), "A9", "找不到伪 DEX 填充块（CLASSES.DEX 之类）")

        # ---- A10 垃圾条目：非 ASCII 顶层名 或 畸形 META-INF ----
        if self.want("A10"):
            nonascii = [n for n in self.names
                        if "/" not in n and any(ord(c) > 127 for c in n)]
            malformed = [n for n in self.names
                         if n.startswith("META-INF/") and ("//" in n or "/./" in n or n.endswith("/"))]
            self.check(bool(nonascii) or bool(malformed), "A10",
                       "既没有非 ASCII 顶层文件，也没有畸形 META-INF 条目")

        # ---- A12 ZIP 路径攻击：绝对路径条目 + 归一化近重名组 ----
        if self.want("A12"):
            absents = [n for n in self.names if n.startswith("/")]
            self.check(bool(absents), "A12", "找不到绝对路径攻击条目")

            # 归一化近重名：把 `\` 当分隔符、折叠连续 `/` 后落进同一路径的条目组。
            # 样本实测 33+ 组（最大一组 13 条，如 /resources.arsc//.xml 一族），
            # 组内中央目录精确名互不相同，所以能通过签名与安装；任何「先归一化
            # 路径再处理」的工具都会在这类组上撞车。A12 至少注入 8 组（基础路径
            # 覆盖 AndroidManifest.xml/、classes*.dex/、resources.arsc/、META-INF/、
            # res/values/、kotlin/），这里按 ≥8 组断言。
            #
            # 必须用 orig_filename 而不是 ZipInfo.filename：Windows 上 Python 的
            # zipfile 会把 `\` 归一化成 `/`（os.sep 替换），于是同一个 `//` 变体
            # 会被当成精确重名（假阳性），而中央目录里的名字其实是唯一的。
            raw_names = [getattr(i, "orig_filename", i.filename) for i in zf.infolist()]

            def _norm(n):
                out = []
                prev_slash = False
                for ch in n.replace("\\", "/"):
                    if ch == "/":
                        if prev_slash:
                            continue
                        prev_slash = True
                    else:
                        prev_slash = False
                    out.append(ch)
                return "".join(out)

            groups = {}
            for n in raw_names:
                groups.setdefault(_norm(n), []).append(n)
            near = [g for g in groups.values() if len(g) >= 2]
            self.check(len(near) >= 8, "A12",
                       "归一化后同路径的条目组只有 %d 组（要求 ≥8）" % len(near))
            # 与精确重名的关键差别：这些组在中央目录里名字必须互不相同
            # （apksigner 只拒绝精确重名，否则整个归档无法签名/安装）。
            self.check(len(raw_names) == len(set(raw_names)), "A12",
                       "中央目录存在精确重名条目（apksigner 会以 Duplicate entry 拒绝归档）")
            if near:
                biggest = max(near, key=len)
                self.notes.append("[A12] 归一化近重名 %d 组，最大一组 %d 条（样例 %s）"
                                  % (len(near), len(biggest), biggest[0]))

        # ---- A13 类膨胀 ----
        if self.want("A13"):
            # 同 A19：启用 B1 时 classes.dex 是壳（就几个类），膨胀的类在
            # 加密载荷里，无从直接计数。
            if self.want("B1"):
                self.notes.append("A13 断言跳过：已启用 B1，膨胀类在加密载荷里，classes.dex 只是壳")
            else:
                n = class_count(self.shell_dex)
                self.check(n >= 50, "A13",
                           "壳 DEX 只有 %d 个类，远低于膨胀后的预期（>=50）" % n)

        # ---- A15 巨型 Manifest 填充 ----
        #
        # 判据：Manifest 确实被撑大了，且**仍能被解析**（后者决定装不装得上）。
        # 只查体积是不够的：填充把真实内容挤没了同样「体积达标」，但应用会装不上。
        if self.want("A15"):
            info = zf.getinfo("AndroidManifest.xml")
            self.check(info.file_size >= 8 << 20, "A15",
                       "AndroidManifest.xml 只有 %d 字节，未达到填充效果" % info.file_size)
            # 顶层 XML chunk 的 size 必须等于整个文件长度（填充靠它串起真实内容）
            head = read_bytes(zf, "AndroidManifest.xml")[:8]
            if len(head) >= 8:
                sz = int.from_bytes(head[4:8], "little")
                self.check(sz == info.file_size, "A15",
                           "顶层 XML chunk size=%d 应等于文件长度 %d（否则真实内容读不到，应用装不上）"
                           % (sz, info.file_size))
            # 真实内容必须还在：字符串池里应能找到 AndroidManifest 必然包含的串。
            # AXML 的字符串池可能是 UTF-8 也可能是 UTF-16LE（aapt1 时代的产物），
            # 因此两种编码都要试——只查 UTF-8 会把正常的产物误判成「内容丢失」。
            raw = read_bytes(zf, "AndroidManifest.xml")
            needle = b"application"
            u16 = "application".encode("utf-16-le")
            self.check(needle in raw or u16 in raw, "A15",
                       "填充后 Manifest 里找不到真实内容（application 字样，UTF-8/UTF-16 均无）")
            # 再确认按 chunk 链能找到字符串池 chunk（type=0x0001）——
            # 这是「真实内容被完整保留」的结构性证据。
            # 注意新布局把真池放在假 chunk #1 之后（池声明 size 已把巨串算进去），
            # 池不再位于文件末尾，因此不能只看尾部，要沿 chunk 头遍历前几个 chunk。
            pos = 8
            pool_found = False
            for _ in range(4):
                if pos + 8 > len(raw):
                    break
                ctype = int.from_bytes(raw[pos:pos + 2], "little")
                csize = int.from_bytes(raw[pos + 4:pos + 8], "little")
                if ctype == 0x0001:
                    pool_found = True
                    break
                if csize < 8:
                    break
                pos += csize
            self.check(pool_found, "A15",
                       "填充后按 chunk 链找不到字符串池 chunk（真实内容可能被挤掉）")

        # ---- B8 载荷容器化 ----
        if self.want("B8"):
            moved = [n for n in self.names if CONTAINER_DIR_RE.match(n)]
            self.check(bool(moved), "B8", "载荷未移入容器目录（assets/<词>/<hex8>/）")
            # 诱饵容器已改为「与真实载荷同构」：不再是以 PK 开头的顶层 zip，
            # 而是落在同一目录树下的配置 JSON（写假包名、路径形态与真载荷一致）。
            decoys = [n for n in self.names if DECOY_CFG_RE.match(n)]
            self.check(bool(decoys), "B8",
                       "找不到诱饵容器配置（assets/<词>/<hex8>/<hex12>.json）")
            # 顶层不应再直接暴露载荷（B1 的载荷名形如 assets/<词>_<hex>.<ext>）
            top = [n for n in self.names if PAYLOAD_RE.match(n)]
            self.check(not top, "B8",
                       "顶层 assets 仍直接暴露载荷：%s" % top[:3])
            # 正向同构断言：容器目录下**不允许**出现以 PK 开头的文件。
            # 真载荷是密文（前置 IV）、诱饵是高熵随机字节，二者都不带 zip magic；
            # 一旦容器里出现 PK 头，脱壳脚本「找 PK 头 / 找 zip」的排除法就能把
            # 真载荷与诱饵区分开，同构性（B8 的核心价值）即告失效。
            #
            # 例外：A17（嵌套 APK 诱饵）**故意**在同一目录树里放一个合法 zip
            # （假内层 APK，PK 头是它的本质）。那不是可被排除法利用的破绽，而是
            # 更深的诱饵——脚本按 PK 抓到的正是它，解包后得到一个看起来正常的
            # 假应用。因此 A17 启用时这条断言不适用。
            if self.want("A17"):
                self.notes.append("B8 同构断言：已启用 A17，容器内的 PK 文件是 A17 的假内层 APK，跳过 PK 检查")
            else:
                pk = [n for n in moved if read_bytes(zf, n)[:2] == b"PK"]
                self.check(not pk, "B8",
                           "容器目录下存在 PK 开头的文件（真假载荷可被 zip 启发式区分）：%s"
                           % pk[:3])
            if decoys:
                blob = read_bytes(zf, decoys[0])
                self.check(b"packageName" in blob, "B8",
                           "诱饵配置 JSON 里找不到假包名（packageName）")

        # ---- E4 渠道标记 ----
        if self.want("E4"):
            self.check(CHANNEL_ASSET in self.names, "E4",
                       "找不到渠道文件 %s" % CHANNEL_ASSET)
            if CHANNEL_ASSET in self.names:
                got = read_bytes(zf, CHANNEL_ASSET).decode("utf-8", "replace").strip()
                if self.channel:
                    self.check(got == self.channel, "E4",
                               "渠道文件内容为 %r，期望 %r" % (got, self.channel))
                self.check(got != "", "E4", "渠道文件内容为空")
        return self.fails


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 2
    apk, feats = argv[1], argv[2]
    channel = None
    if "--channel" in argv:
        channel = argv[argv.index("--channel") + 1]
    c2_lib = None
    if "--c2-lib" in argv:
        c2_lib = argv[argv.index("--c2-lib") + 1]
    c2_size = None
    if "--c2-size" in argv:
        try:
            c2_size = int(argv[argv.index("--c2-size") + 1])
        except ValueError:
            print("--c2-size 需要一个整数（原始 .so 的字节数）")
            return 2

    checker = Checker(apk, feats.split(","), channel, c2_lib, c2_size)
    fails = checker.run()
    for n in checker.notes:
        print("  · %s" % n)
    if fails:
        print("产物断言失败：%s" % apk)
        for f in fails:
            print("  ✗ %s" % f)
        return 1
    print("产物断言通过：%s（启用 %s）" % (apk, ",".join(sorted(checker.features)) or "无"))
    if channel:
        print("  渠道标记 = %s" % channel)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
