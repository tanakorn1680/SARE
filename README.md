# SARE — GTA SA target

Ghidra decompile pipeline (GitHub Actions) สำหรับถอดโค้ด libGTASA.so / libCheatMenu64.so (GTA San Andreas Android 2.10) ใช้สนับสนุน ProMenu
(tanakorn1680/Menusan-Mod.so) อ่าน `HANDOFF.txt` ก่อนเริ่มงาน

รัน: Actions > Ghidra analyze > Run workflow (ใส่ .so ใน `input/` เป็น zip ก่อน) -> โหลด artifact `ghidra-out` -> ส่งกลับ
ตั้งค่าสิ่งที่จะถอดใน `keywords.txt` (รูปแบบอยู่ที่หัวไฟล์ `scripts/ExportInfo.java`)
