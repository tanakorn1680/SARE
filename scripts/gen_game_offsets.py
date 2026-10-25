#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gen_game_offsets.py <decompiled.c ของ libCheatMenu64> <ไฟล์ออก keywords> <ไฟล์ออก offsets>
เก็บทุก "base + 0xNNN" (base = ตัวแปรที่เก็บ base ของ libGTASA ในเมนู) ที่โค้ดเมนู (รวมหน้าที่เพิ่งกู้ได้) อ้างถึง
 -> keywords: บรรทัด @0x.. ให้ ExportInfo ถอดฟังก์ชันเกมที่เมนู hook/เรียกด้วยที่อยู่ดิบ (ถ้า offset ไม่ใช่ฟังก์ชันจะถูกข้ามเอง)
 -> offsets : ใช้กับ elfdump.py --mode game --offsets เพื่ออ่านค่าเริ่มต้น/เป้าหมาย GOT
"""
import re
import sys

src = open(sys.argv[1], errors="ignore").read()
base = sys.argv[4] if len(sys.argv) > 4 else None
if not base:
    # หา base var: ตัวแปร DAT_xxxxxxxx ที่ถูกบวกด้วย 0x... บ่อยที่สุด
    cnt = {}
    for m in re.finditer(r"\b(DAT_[0-9a-f]{8}) \+ 0x[0-9a-f]+", src):
        cnt[m.group(1)] = cnt.get(m.group(1), 0) + 1
    base = max(cnt, key=cnt.get) if cnt else "DAT_002bb0e8"
offs = sorted(set(int(x, 16) for x in re.findall(re.escape(base) + r" \+ (0x[0-9a-f]+)", src)))
with open(sys.argv[2], "w") as w:
    w.write("# สร้างอัตโนมัติจาก %s (base=%s) : %d offset\n" % (sys.argv[1], base, len(offs)))
    for o in offs:
        w.write("@0x%x\n" % o)
with open(sys.argv[3], "w") as w:
    for o in offs:
        w.write("0x%x\n" % o)
print("gen_game_offsets: base=%s offsets=%d" % (base, len(offs)))
