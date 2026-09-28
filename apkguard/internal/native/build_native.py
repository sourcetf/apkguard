#!/usr/bin/env python3
"""编译 apkguard 原生库，并回填 C6 的期望摘要。

C6（完整性自校验）要求库里存有「自身 .text + .rodata 的 SHA-256」。
期望值放在独立的 .agexpect 节，因此它不参与被哈希的范围，不存在自指问题；
本脚本负责在编译完成后按节表定位 .agexpect 并把摘要写进去。

用法：
    python build_native.py [--check]

不带参数即重新编译全部 ABI 并回填；带 --check 只校验现有产物中回填的
摘要与重新计算结果是否一致（用于 CI/回归，不重新编译）。
"""

import hashlib
import os
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PREBUILT = os.path.join(HERE, "prebuilt")
# 源码放在 csrc/ 子目录而不是包根目录。
#
# Go 工具链会把包目录下的 .c 文件当成 cgo 源文件：当包内没有 import "C" 时，
# `go build`/`go vet` 会直接报错——
#   "C source files not allowed when not using cgo or SWIG: apkguard.c"
# 该行为还与 CGO_ENABLED 有关（Linux 上默认 1、Windows 上默认 0），
# 因此同一份代码在本地能过、在 CI 上失败。放到子目录后 Go 不再扫描它，
# 而本脚本仍按显式路径编译。
SRC = os.path.join(HERE, "csrc", "apkguard.c")
LIB = "libapkguard.so"

# ABI -> NDK clang 目标三元组。API 24 与签名默认 minSdk 一致。
TARGETS = {
    "arm64-v8a": "aarch64-linux-android24-clang",
    "armeabi-v7a": "armv7a-linux-androideabi24-clang",
    "x86_64": "x86_64-linux-android24-clang",
}


def find_ndk_bin():
    """定位 NDK 的 clang 目录。"""
    root = os.path.normpath(os.path.join(HERE, "..", "..", "..", "tools", "android-sdk", "ndk"))
    if not os.path.isdir(root):
        return None
    for name in sorted(os.listdir(root)):
        b = os.path.join(root, name, "toolchains", "llvm", "prebuilt", "windows-x86_64", "bin")
        if os.path.isdir(b):
            return b
    return None


def elf_sections(data):
    """解析 ELF32/ELF64 小端的节表，返回 {名字: (文件偏移, 长度)}。

    必须同时支持 32 位：armeabi-v7a 是 ELF32，只认 64 位会让该 ABI 的
    完整性校峰静默失效。
    """
    if data[:4] != b"ELF" or data[5] != 1:
        raise ValueError("只支持小端 ELF")
    is64 = data[4] == 2
    if not is64 and data[4] != 1:
        raise ValueError("ELF class 非法: %d" % data[4])
    if is64:
        shoff, = struct.unpack_from("<Q", data, 0x28)
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
        hdr_min = 64
    else:
        shoff, = struct.unpack_from("<I", data, 0x20)
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x2E)
        hdr_min = 40
    if shoff == 0 or shentsize < hdr_min or shnum == 0 or shstrndx >= shnum:
        raise ValueError("节表信息非法")

    def shdr(i):
        o = shoff + i * shentsize
        if is64:
            name, typ, flags, addr, off, size = struct.unpack_from("<IIQQQQ", data, o)
        else:
            name, typ, flags, addr, off, size = struct.unpack_from("<IIIIII", data, o)
        return name, off, size

    _, stroff, strsize = shdr(shstrndx)
    strtab = data[stroff:stroff + strsize]
    out = {}
    for i in range(shnum):
        name_off, off, size = shdr(i)
        end = strtab.find(b"\0", name_off)
        name = strtab[name_off:end].decode("ascii", "replace")
        out[name] = (off, size)
    return out


def expected_digest(data):
    """按与运行时一致的顺序（先是 .text，再是 .rodata）计算期望摘要。"""
    sec = elf_sections(data)
    h = hashlib.sha256()
    for name in (".text", ".rodata"):
        if name not in sec:
            raise ValueError("缺少节 %s" % name)
        off, size = sec[name]
        h.update(data[off:off + size])
    return h.digest(), sec


def patch(path, digest, sec):
    """把摘要写入 .agexpect 节。"""
    if ".agexpect" not in sec:
        raise ValueError("缺少 .agexpect 节（期望值没有独立存放，会产生自指）")
    off, size = sec[".agexpect"]
    if size < 32:
        raise ValueError(".agexpect 节只有 %d 字节，放不下 32 字节摘要" % size)
    with open(path, "r+b") as f:
        f.seek(off)
        f.write(digest)


def verify(path):
    """校验回填摘要与重新计算的结果一致。"""
    with open(path, "rb") as f:
        data = f.read()
    want, sec = expected_digest(data)
    off, _ = sec[".agexpect"]
    got = data[off:off + 32]
    return want == got, want.hex(), got.hex()


def build(ndk_bin):
    ok = True
    for abi, target in TARGETS.items():
        cc = os.path.join(ndk_bin, target + ".cmd")
        if not os.path.exists(cc):
            print("  跳过 %s：找不到 %s" % (abi, cc))
            ok = False
            continue
        outdir = os.path.join(PREBUILT, abi)
        os.makedirs(outdir, exist_ok=True)
        out = os.path.join(outdir, LIB)
        r = subprocess.run([cc, "-shared", "-O2", "-fPIC", "-DAG_JNI", "-o", out, SRC],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print("  编译 %s 失败：\n%s" % (abi, r.stderr))
            ok = False
            continue
        with open(out, "rb") as f:
            data = f.read()
        digest, sec = expected_digest(data)
        patch(out, digest, sec)
        good, want, got = verify(out)
        print("  %-12s %6d 字节  .agexpect@0x%x  摘要=%s  %s"
              % (abi, len(data), sec[".agexpect"][0], digest.hex()[:16],
                 "回填一致" if good else "回填不一致！"))
        ok = ok and good
    return ok


def main():
    if "--check" in sys.argv:
        ok = True
        for abi in TARGETS:
            p = os.path.join(PREBUILT, abi, LIB)
            if not os.path.exists(p):
                print("  缺少 %s" % p)
                ok = False
                continue
            good, want, got = verify(p)
            print("  %-12s %s" % (abi, "一致" if good else "不一致 want=%s got=%s" % (want, got)))
            ok = ok and good
        return 0 if ok else 1

    ndk_bin = find_ndk_bin()
    if ndk_bin is None:
        print("找不到 NDK（期望位于 tools/android-sdk/ndk/<版本>/toolchains/llvm/prebuilt/...）")
        return 2
    print("使用 NDK clang：%s" % ndk_bin)
    return 0 if build(ndk_bin) else 1


if __name__ == "__main__":
    sys.exit(main())
