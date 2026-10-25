// DefineCode.java - กู้ "ฟังก์ชันที่ Ghidra มองไม่เห็น" ก่อน ExportInfo จะถอดโค้ด
// ที่มา: หน้า Player / Weapon / Visual / Teleport ของเมนู ARM ไม่มีฟังก์ชันไหนอ้างสตริงของมันเลยใน dump (byfunc.tsv)
//       และตัวแปรเกม ~750 ตัวที่ _INIT ผูกไว้ไม่ถูกใช้ในโค้ดที่ถอดได้ = โค้ดส่วนนั้นเป็นไบต์ "undefined" ที่ไม่มีฟังก์ชันครอบ
// ทำอะไร: ไล่ช่วง offset ที่ระบุด้วยบรรทัด  @define 0xA-0xB  ใน keywords.txt (ใต้ @lib ที่ตรงกับโปรแกรม)
//         ถ้าเจอไบต์ที่ยังไม่มีทั้งฟังก์ชัน/คำสั่ง/ข้อมูล -> disassemble + createFunction แล้วข้ามไปท้ายฟังก์ชัน
//         (ไม่ลบ/ไม่แก้ฟังก์ชันที่มีอยู่แล้ว ทำซ้ำได้ ปลอดภัย) ผลเขียนใน define_report.txt (OUT_DIR)
//@category Export

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;

public class DefineCode extends GhidraScript {

    private static final int MAX_CREATE = 6000;

    private boolean prologueLike(Instruction in) {
        if (in == null) {
            return false;
        }
        String m = in.getMnemonicString().toLowerCase();
        return m.equals("stp") || m.equals("sub") || m.equals("str") || m.equals("paciasp") || m.equals("pacibsp")
                || m.equals("bti") || m.equals("sturdh");
    }

    @Override
    public void run() throws Exception {
        long base = currentProgram.getImageBase().getOffset();
        String progName = currentProgram.getName().toLowerCase();
        List<long[]> ranges = new ArrayList<long[]>();
        String kf = System.getenv("KEYWORDS_FILE");
        if (kf != null && new File(kf).exists()) {
            boolean active = true;
            try (BufferedReader r = new BufferedReader(new FileReader(kf))) {
                String line;
                while ((line = r.readLine()) != null) {
                    line = line.trim();
                    if (line.isEmpty() || line.startsWith("#")) {
                        continue;
                    }
                    if (line.startsWith("@lib")) {
                        String v = line.substring(4).trim().toLowerCase();
                        active = v.equals("*") || v.isEmpty() || progName.contains(v);
                        continue;
                    }
                    if (!active || !line.startsWith("@define")) {
                        continue;
                    }
                    int h = line.indexOf('#');
                    if (h > 0) {
                        line = line.substring(0, h).trim();
                    }
                    try {
                        String[] pr = line.substring(7).trim().split("-");
                        ranges.add(new long[] { Long.decode(pr[0].trim()).longValue(), Long.decode(pr[1].trim()).longValue() });
                    } catch (RuntimeException ex) {
                        println("DefineCode: อ่านบรรทัดไม่ได้: " + line);
                    }
                }
            }
        }
        String outEnv = System.getenv("OUT_DIR");
        File out = new File(outEnv != null ? outEnv : "out");
        out.mkdirs();
        if (ranges.isEmpty()) {
            println("DefineCode: ไม่มี @define สำหรับ " + progName + " -> ข้าม");
            return;
        }

        Listing listing = currentProgram.getListing();
        Memory mem = currentProgram.getMemory();
        int created = 0;
        int failed = 0;
        int skippedData = 0;
        try (PrintWriter rep = new PrintWriter(new File(out, "define_report.txt"))) {
            rep.println("# ฟังก์ชันที่ DefineCode สร้างเพิ่ม : offset<TAB>size<TAB>ชื่อ");
            for (long[] rg : ranges) {
                Address cur = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(base + rg[0]);
                long endOff = base + rg[1];
                boolean afterFail = false;
                int rangeCreated = 0;
                while (cur != null && cur.getOffset() < endOff && created < MAX_CREATE) {
                    monitor.checkCancelled();
                    try {
                        Function f = listing.getFunctionContaining(cur);
                        if (f != null) {
                            cur = f.getBody().getMaxAddress().add(1);
                            afterFail = false;
                            continue;
                        }
                        Instruction in = listing.getInstructionContaining(cur);
                        if (in != null) {
                            // มีคำสั่งแต่ไม่มีฟังก์ชันครอบ (เช่นถูก disassemble ตามการไหลของโค้ด) -> สร้างฟังก์ชันที่จุดนี้
                            Function nf = createFunction(in.getMinAddress(), null);
                            if (nf != null) {
                                created++;
                                rangeCreated++;
                                rep.println("0x" + Long.toHexString(nf.getEntryPoint().getOffset() - base) + "\t"
                                        + nf.getBody().getNumAddresses() + "\t" + nf.getName());
                                cur = nf.getBody().getMaxAddress().add(1);
                            } else {
                                cur = in.getMaxAddress().add(1);
                            }
                            continue;
                        }
                        Data d = listing.getDefinedDataContaining(cur);
                        if (d != null) {
                            skippedData++;
                            cur = d.getMaxAddress().add(1);
                            afterFail = false;
                            continue;
                        }
                        MemoryBlock blk = mem.getBlock(cur);
                        if (blk == null || !blk.isExecute() || !blk.isInitialized()) {
                            cur = (blk == null) ? cur.add(4) : blk.getEnd().add(1);
                            continue;
                        }
                        long o = cur.getOffset();
                        if ((o & 3L) != 0) {
                            cur = cur.add(4 - (o & 3L));
                            continue;
                        }
                        int w = mem.getInt(cur);
                        if (w == 0) {
                            cur = cur.add(4); // padding
                            continue;
                        }
                        boolean ok = disassemble(cur);
                        Instruction first = ok ? listing.getInstructionAt(cur) : null;
                        // จุดเริ่มของช่องว่าง (ต่อจากฟังก์ชันก่อนหน้าพอดี) ต้องเป็นต้นฟังก์ชันเสมอ ; ถ้าเพิ่งพลาดมา ต้องหน้าตาเหมือน prologue
                        if (ok && first != null && (!afterFail || prologueLike(first))) {
                            Function nf = createFunction(cur, null);
                            if (nf != null) {
                                created++;
                                rangeCreated++;
                                rep.println("0x" + Long.toHexString(nf.getEntryPoint().getOffset() - base) + "\t"
                                        + nf.getBody().getNumAddresses() + "\t" + nf.getName());
                                cur = nf.getBody().getMaxAddress().add(1);
                                afterFail = false;
                                continue;
                            }
                        }
                        failed++;
                        afterFail = true;
                        cur = cur.add(4);
                    } catch (RuntimeException | MemoryAccessException ex) {
                        // ชนขอบ address space / อ่านหน่วยความจำไม่ได้ -> จบช่วงนี้
                        break;
                    }
                }
                rep.println("# range 0x" + Long.toHexString(rg[0]) + "-0x" + Long.toHexString(rg[1]) + " created=" + rangeCreated);
            }
            rep.println("# total created=" + created + " failed-steps=" + failed + " skipped-data-blocks=" + skippedData);
        }
        println("DefineCode: created=" + created + " failed=" + failed + " skippedData=" + skippedData);
    }
}
