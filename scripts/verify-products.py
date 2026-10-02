#!/usr/bin/env python3
"""对加固产物做「产物级」断言：确认启用的功能项在产物里真的留下了痕迹。

为什么需要它：端到端脚本此前只验证「签名有效 + 对齐正确」，于是
「启用了 A9/A10/A12，但产物里什么都没有」这种失败模式完全看不出来——
功能项在功能表里声明为已实现、命令 exit code 为 0，实际却毫无作用。
这个脚本按功能项逐个检查产物特征，把那类「静默不生效」变成构建失败。

用法：
    verify-products.py <加固后的.apk> <启用的功能项,逗号分隔> [--channel 名字]

退出码：0 = 全部通过；1 = 有断言失败（会逐条打印原因）。
"""

import re
import sys
import unicodedata
import zipfile

# 与 internal/passes/shell.go 的 ChannelAssetName 保持一致。
CHANNEL_ASSET = "assets/apkguard_channel.txt"

# 与 internal/dex/decoy.go 的 DecoyClassNames 保持一致（取前若干个即可判定）。
DECOY_NAMES = [
    "SecurityMonitor", "IntegrityChecker", "ThreatDetector", "RootGuard",
    "EnvironmentProbe", "LicenseValidator", "NativeBridge", "CryptoProvider",
    "SignatureVerifier", "DebugWatcher",
]

# 与 internal/dex/shell.go 的壳类名保持一致。
SHELL_CLASS = "com.apkguard.shell.App"

DEX_HEADER_CLASS_DEFS_SIZE = 0x60  # class_defs_size 在 DEX 头部偏移 0x60
DEX_HEADER_CLASS_DEFS_OFF = 0x64   # class_defs_off 在 DEX 头部偏移 0x64
CLASS_DEF_SIZE = 32
CLASS_DEF_SOURCE_FILE_IDX = 16
NO_INDEX = 0xFFFFFFFF

FAKE_DEX_RE = re.compile(r"^(CLASSES\.DEX|Classes\.Dex|classes\.DEX)(\.\d+)?$")

# B8 的容器目录：assets/<词>/<8 位十六进制>/... ；诱饵容器为 assets/<词>_<8 位十六进制>.zip
CONTAINER_DIR_RE = re.compile(r"^assets/[a-z]+/[0-9a-f]{8}/")
DECOY_ZIP_RE = re.compile(r"^assets/[a-z]+_[0-9a-f]{8}[.]zip$")

# B1 的加密载荷条目名：assets/<伪装词>_<8 位十六进制>.<伪装扩展名>。
# 扩展名从 .bin/.dat/.res/.pack 里按哈希挑一个（见 internal/pack/pack.go 的
# assetExts），所以不能只认 .bin。
PAYLOAD_RE = re.compile(r"^assets/[A-Za-z]+_[0-9a-f]{8}\.(bin|dat|res|pack)$")


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


def manifest_contains(zf, needle):
    """在 AndroidManifest.xml 的字符串池里找 needle（UTF-8 或 UTF-16LE 都试）。"""
    raw = read_bytes(zf, "AndroidManifest.xml")
    if needle.encode("utf-8") in raw:
        return True
    return needle.encode("utf-16-le") in raw


class Checker:
    def __init__(self, apk, features, channel=None):
        self.apk = apk
        self.features = {f.strip().upper() for f in features if f.strip()}
        self.channel = channel
        self.fails = []
        self.notes = []
        with zipfile.ZipFile(apk) as zf:
            self.names = zf.namelist()
            self.zw = zf
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
            self.check(manifest_contains(zf, SHELL_CLASS), "B2",
                       "Manifest 里找不到壳类 %s（android:name 未被改写）" % SHELL_CLASS)

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
            semantic = [n for n in res_entries
                        if len(n.split("/")) >= 3 and len(n.split("/")[1]) != 1]
            self.check(not semantic, "A11",
                       "res/ 下仍存在语义目录名：%s" % semantic[:5])

        # ---- A8 诱饵类注入 ----
        if self.want("A8"):
            hit = [n for n in DECOY_NAMES if any(n in s for s in self.dex_strs)]
            self.check(bool(hit), "A8", "DEX 里找不到任何诱饵类名（如 SecurityMonitor）")

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

        # ---- A12 ZIP 路径攻击：绝对路径条目 ----
        if self.want("A12"):
            absents = [n for n in self.names if n.startswith("/")]
            self.check(bool(absents), "A12", "找不到绝对路径攻击条目")

        # ---- A13 类膨胀 ----
        if self.want("A13"):
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
            # 再确认末尾真实内容区存在字符串池 chunk（type=0x0001）——
            # 这是「真实内容被完整保留」的结构性证据。
            tail = raw[-65536:]
            self.check(bytes([1, 0]) in tail, "A15",
                       "填充后 Manifest 末尾找不到字符串池 chunk（真实内容可能被挤掉）")

        # ---- B8 载荷容器化 ----
        if self.want("B8"):
            moved = [n for n in self.names if CONTAINER_DIR_RE.match(n)]
            self.check(bool(moved), "B8", "载荷未移入容器目录（assets/<词>/<hex>/）")
            decoys = [n for n in self.names if DECOY_ZIP_RE.match(n)]
            self.check(bool(decoys), "B8", "找不到诱饵容器（assets/<词>_<hex>.zip）")
            # 顶层不应再直接暴露载荷（B1 的载荷名形如 assets/<词>_<hex>.<ext>）
            top = [n for n in self.names if PAYLOAD_RE.match(n)]
            self.check(not top, "B8",
                       "顶层 assets 仍直接暴露载荷：%s" % top[:3])
            if decoys:
                blob = read_bytes(zf, decoys[0])
                self.check(blob[:2] == b"PK", "B8", "诱饵容器不是 zip（缺 PK 头）")
                self.check(b"dummy.installed.check" in blob or b"packageName" in blob, "B8",
                           "诱饵容器里找不到诱饵配置（packageName）")

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

    checker = Checker(apk, feats.split(","), channel)
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
