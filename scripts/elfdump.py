#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""elfdump.py - ดึง "ข้อมูลดิบ" ที่ Ghidra export ไม่ได้ให้ จากไฟล์ .so (ELF64 little-endian) โดยตรง
ไม่ต้องใช้ Ghidra / pyelftools (Python ล้วน) ; offset ทุกตัว = vaddr = address - imageBase เหมือน functions.tsv

ใช้:  elfdump.py <lib.so> <outdir> --mode menu|game [--offsets offsets.txt] [--window 0x20000]

mode menu (libCheatMenu64):
  segments.tsv   ตาราง PT_LOAD
  rodata.hex / data.hex   hexdump ของ segment ที่ไม่ใช่โค้ด (บรรทัดศูนย์ล้วนถูกตัดทิ้ง)  -> ไบต์ของ struct คำสั่งสคริปต์ (DAT_001477ec ฯลฯ), ตารางค่าคงที่
  ptrs.tsv       ทุกช่องพอยน์เตอร์ใน segment ข้อมูลที่ถูก relocate : slot, ชนิด, เป้าหมาย(offset หรือชื่อ symbol), สตริงที่เป้าหมายชี้ถึง
                 -> ตาราง {ชื่อ, พอยน์เตอร์} ของหน้า Visual/Timecyc, ตารางสตริงต่าง ๆ
mode game (libGTASA):
  got_targets.tsv  ช่อง GOT [PLTGOT, PLTGOT+window) -> เป้าหมายจริง (ใช้แปลงที่อยู่ base+0x84xxxx ที่เมนูใช้ ให้เป็นชื่อตัวแปร/ฟังก์ชันของเกม)
  game_values.tsv  (ถ้ามี --offsets) ไบต์เริ่มต้น 64 ไบต์ ณ แต่ละ offset ที่เมนูอ้างถึง + ค่าที่ relocate แล้วถ้าเป็นช่องพอยน์เตอร์
"""
import os
import struct
import sys

PT_LOAD, PT_DYNAMIC = 1, 2
PF_X = 1
MACH_AARCH64, MACH_X86_64 = 183, 62
RELNAME = {
    MACH_AARCH64: {257: "ABS64", 1025: "GLOB_DAT", 1026: "JUMP_SLOT", 1027: "RELATIVE", 1032: "IRELATIVE"},
    MACH_X86_64: {1: "ABS64", 6: "GLOB_DAT", 7: "JUMP_SLOT", 8: "RELATIVE", 37: "IRELATIVE"},
}


def log(*a):
    print("[elfdump]", *a, file=sys.stderr)


class Elf:
    def __init__(self, path):
        with open(path, "rb") as f:
            self.d = f.read()
        d = self.d
        if d[:4] != b"\x7fELF" or d[4] != 2 or d[5] != 1:
            raise SystemExit("ไม่ใช่ ELF64 little-endian: " + path)
        self.mach = struct.unpack_from("<H", d, 0x12)[0]
        phoff = struct.unpack_from("<Q", d, 0x20)[0]
        phentsize, phnum = struct.unpack_from("<HH", d, 0x36)
        self.loads, self.dyn = [], None
        for i in range(phnum):
            o = phoff + i * phentsize
            ptype, flags, off, vaddr, paddr, filesz, memsz, align = struct.unpack_from("<IIQQQQQQ", d, o)
            if ptype == PT_LOAD:
                self.loads.append((vaddr, off, filesz, memsz, flags))
            elif ptype == PT_DYNAMIC:
                self.dyn = (vaddr, off, filesz)
        self.dt = {}
        if self.dyn:
            _, off, sz = self.dyn
            for i in range(0, sz, 16):
                tag, val = struct.unpack_from("<qQ", d, off + i)
                if tag == 0:
                    break
                self.dt.setdefault(tag, val)
        self.relnames = RELNAME.get(self.mach, {})

    def v2f(self, vaddr):
        for va, off, fsz, msz, fl in self.loads:
            if va <= vaddr < va + fsz:
                return off + (vaddr - va)
        return None

    def read(self, vaddr, n):
        o = self.v2f(vaddr)
        if o is None:
            return None
        return self.d[o:o + n]

    def cstr(self, vaddr, maxlen=120):
        b = self.read(vaddr, maxlen)
        if not b:
            return ""
        b = b.split(b"\0", 1)[0]
        if len(b) < 3:
            return ""
        try:
            s = b.decode("ascii")
        except UnicodeDecodeError:
            return ""
        if all(32 <= ord(c) < 127 for c in s):
            return s
        return ""

    def sym(self, idx):
        symtab, strtab = self.dt.get(6), self.dt.get(5)
        if not symtab or not strtab or idx == 0:
            return ""
        b = self.read(symtab + idx * 24, 24)
        if not b or len(b) < 24:
            return ""
        name_off = struct.unpack_from("<I", b, 0)[0]
        n = self.read(strtab + name_off, 200)
        if not n:
            return ""
        return n.split(b"\0", 1)[0].decode("ascii", "replace")

    def relocs(self):
        out = {}
        for tab, szt in ((7, 8), (23, 2)):  # DT_RELA/DT_RELASZ , DT_JMPREL/DT_PLTRELSZ
            addr, size = self.dt.get(tab), self.dt.get(szt)
            if not addr or not size:
                continue
            raw = self.read(addr, size)
            if not raw:
                continue
            for i in range(0, len(raw) - 23, 24):
                r_off, r_info, r_add = struct.unpack_from("<QQq", raw, i)
                out[r_off] = (r_info & 0xFFFFFFFF, r_info >> 32, r_add)
        return out

    def target(self, rel):
        rtype, symi, add = rel
        name = self.relnames.get(rtype, str(rtype))
        if name == "RELATIVE":
            return name, add, ""
        s = self.sym(symi)
        return name, add, s


def hexdump(elf, fname, segs):
    with open(fname, "w") as w:
        w.write("# vaddr(=offset): bytes   (บรรทัดศูนย์ล้วนถูกตัดออก ; ช่องพอยน์เตอร์ที่ถูก relocate จะเป็น 0 ในไฟล์ ดูค่าจริงใน ptrs.tsv)\n")
        for va, off, fsz, msz, fl in segs:
            w.write("# segment vaddr=0x%x filesz=0x%x\n" % (va, fsz))
            data = elf.d[off:off + fsz]
            for i in range(0, len(data), 32):
                ch = data[i:i + 32]
                if ch.count(0) == len(ch):
                    continue
                w.write("0x%x: %s\n" % (va + i, ch.hex()))


def mode_menu(elf, out):
    with open(os.path.join(out, "segments.tsv"), "w") as w:
        w.write("vaddr\tfilesz\tmemsz\tflags\n")
        for va, off, fsz, msz, fl in elf.loads:
            w.write("0x%x\t0x%x\t0x%x\t%s\n" % (va, fsz, msz, "".join(c if fl & m else "-" for c, m in (("r", 4), ("w", 2), ("x", 1)))))
    ro = [s for s in elf.loads if not s[4] & PF_X and not s[4] & 2]
    rw = [s for s in elf.loads if not s[4] & PF_X and s[4] & 2]
    hexdump(elf, os.path.join(out, "rodata.hex"), ro)
    hexdump(elf, os.path.join(out, "data.hex"), rw)
    rels = elf.relocs()
    n = 0
    with open(os.path.join(out, "ptrs.tsv"), "w") as w:
        w.write("slot\ttype\ttarget\tsymbol\ttarget_string\n")
        for slot in sorted(rels):
            seg = [s for s in elf.loads if s[0] <= slot < s[0] + s[3] and not s[4] & PF_X]
            if not seg:
                continue
            name, add, sym = elf.target(rels[slot])
            tstr = elf.cstr(add) if name == "RELATIVE" else ""
            w.write("0x%x\t%s\t0x%x\t%s\t%s\n" % (slot, name, add & 0xFFFFFFFFFFFFFFFF, sym, tstr))
            n += 1
    log("menu: relocs=%d ptr-slots=%d" % (len(rels), n))


def mode_game(elf, out, window, offsets):
    rels = elf.relocs()
    got = elf.dt.get(3)
    cnt = 0
    with open(os.path.join(out, "got_targets.tsv"), "w") as w:
        w.write("slot\ttype\ttarget\tsymbol\n")
        if got:
            for slot in sorted(rels):
                if got <= slot < got + window:
                    name, add, sym = elf.target(rels[slot])
                    w.write("0x%x\t%s\t0x%x\t%s\n" % (slot, name, add & 0xFFFFFFFFFFFFFFFF, sym))
                    cnt += 1
    log("game: relocs=%d got_slots=%d (PLTGOT=%s)" % (len(rels), cnt, hex(got) if got else None))
    if offsets:
        with open(os.path.join(out, "game_values.tsv"), "w") as w:
            w.write("offset\treloc_target\tbytes64\n")
            for o in offsets:
                b = elf.read(o, 64)
                rt = ""
                if o in rels:
                    name, add, sym = elf.target(rels[o])
                    rt = "%s:0x%x:%s" % (name, add & 0xFFFFFFFFFFFFFFFF, sym)
                w.write("0x%x\t%s\t%s\n" % (o, rt, b.hex() if b else "(bss/นอกไฟล์)"))
        log("game_values: %d offsets" % len(offsets))


def main():
    a = sys.argv[1:]
    if len(a) < 3 or "--mode" not in a:
        print(__doc__)
        return 2
    so, out = a[0], a[1]
    mode = a[a.index("--mode") + 1]
    window = int(a[a.index("--window") + 1], 0) if "--window" in a else 0x20000
    offsets = []
    if "--offsets" in a:
        p = a[a.index("--offsets") + 1]
        if os.path.exists(p):
            for line in open(p):
                line = line.split("#")[0].strip()
                if line:
                    try:
                        offsets.append(int(line, 0))
                    except ValueError:
                        pass
    os.makedirs(out, exist_ok=True)
    elf = Elf(so)
    if mode == "menu":
        mode_menu(elf, out)
    elif mode == "game":
        mode_game(elf, out, window, offsets)
    else:
        print("mode ต้องเป็น menu หรือ game")
        return 2
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as ex:  # ห้ามทำให้ workflow ล้ม
        log("ล้มเหลว:", repr(ex))
        sys.exit(0)
