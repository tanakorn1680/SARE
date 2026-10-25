#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""refbytes.py - ทุกที่อยู่ข้อมูล (DAT_/LAB_/UNK_/s_) ที่โค้ดเมนูอ้างถึง -> ไบต์จริงจากไฟล์ .so
ใช้: refbytes.py <lib.so> <decompiled.c> <out.tsv>
ผลลัพธ์ out.tsv: offset<TAB>segment(rx/ro/rw/นอกไฟล์)<TAB>bytes96(hex)<TAB>cstring
 -> ไม่ต้องไล่หาใน rx.hex เอง ; ครอบทุกค่าคงที่/โครงสคริปต์ที่เมนูใช้ครบในไฟล์เดียว
offset = address - imageBase (0x100000)
"""
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elfdump import Elf, PF_X  # noqa: E402

BASE = 0x100000
PAT = re.compile(r"\b(?:DAT|LAB|UNK|s_[A-Za-z0-9_]*?)_?([0-9a-f]{8})\b")
PAT2 = re.compile(r"\b(?:DAT|LAB|UNK)_([0-9a-f]{8})\b")


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        return 2
    so, dec, out = sys.argv[1:4]
    elf = Elf(so)
    txt = open(dec, errors="replace").read()
    addrs = set(int(m, 16) for m in PAT2.findall(txt))
    n = 0
    with open(out, "w") as w:
        w.write("offset\tseg\tbytes96\tcstring\n")
        for a in sorted(addrs):
            off = a - BASE
            seg = "?"
            for va, fo, fsz, msz, fl in elf.loads:
                if va <= off < va + msz:
                    seg = "rx" if fl & PF_X else ("rw" if fl & 2 else "ro")
                    break
            b = elf.read(off, 96)
            cs = elf.cstr(off) if b else ""
            w.write("0x%x\t%s\t%s\t%s\n" % (off, seg, b.hex() if b else "(bss/นอกไฟล์)", cs))
            n += 1
    print("[refbytes] %d addresses" % n, file=sys.stderr)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as ex:
        print("[refbytes] ล้มเหลว:", repr(ex), file=sys.stderr)
        sys.exit(0)
