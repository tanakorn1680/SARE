// ส่งออก: functions.tsv, symbols.tsv, strings.tsv (พร้อมฟังก์ชันที่อ้างถึง), decompiled.c (ตาม keywords.txt)
// รูปแบบ keywords.txt (เพิ่มใน v2):
//   @lib <ชื่อ>        = บรรทัดต่อจากนี้ใช้กับไลบรารีที่ชื่อโปรแกรมมีคำนี้ (เช่น libgtasa, libcheatmenu64) ; @lib * = ทุกไลบรารี
//   @range 0xA-0xB     = ถอดโค้ดทุกฟังก์ชันที่ offset อยู่ในช่วงนี้ (ข้าม toml:: std:: __ndk1 และฟังก์ชันเล็กกว่า 8 ไบต์)
//   @0xOFFSET          = ถอดโค้ดฟังก์ชันที่ offset นี้ (ต่อท้ายด้วย  # คอมเมนต์ ได้)
//   @nocallers         = ไม่ถอด callers ของไลบรารีนี้ (ลดเวลา เมื่อมีเป้าหมายเป็นพันตัว)
//   @callees N         = ถอด N ฟังก์ชันที่เป้าหมายเรียกบ่อยที่สุด (ที่ไม่ใช่เป้าหมายเอง) -> callees.tsv + decompiled_callees.c (ใช้หา ImGui / ตัวช่วยที่ไม่มีชื่อ)
//   fn:<คำ>            = ถอดโค้ดทุกฟังก์ชันที่ชื่อ (ตามที่ Ghidra แสดง) มีคำนี้
//   อื่น ๆ              = คำค้นในสตริง (เหมือนเดิม)
// offset ทุกตัว = address - imageBase  (ตรงกับ "start ของโมดูล + offset" ใน GameGuardian ถ้า segment แรกเริ่มที่ 0)
//@category Export

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

public class ExportInfo extends GhidraScript {

    private long base;

    private String off(long addr) {
        return "0x" + Long.toHexString(addr - base);
    }

    private PrintWriter open(File dir, String name) throws IOException {
        return new PrintWriter(new BufferedWriter(new FileWriter(new File(dir, name))));
    }

    @Override
    public void run() throws Exception {
        String outEnv = System.getenv("OUT_DIR");
        File out = new File(outEnv != null ? outEnv : "out");
        out.mkdirs();
        base = currentProgram.getImageBase().getOffset();

        int maxDecomp = 100;
        String md = System.getenv("MAX_DECOMP");
        if (md != null) {
            try {
                maxDecomp = Integer.parseInt(md.trim());
            } catch (NumberFormatException ex) {
                // ใช้ค่าเริ่มต้น
            }
        }

        List<String> kws = new ArrayList<String>();
        List<String> fnKws = new ArrayList<String>();
        List<long[]> ranges = new ArrayList<long[]>();
        List<Long> manual = new ArrayList<Long>();
        boolean noCallers = false;
        int calleeTop = 0;
        boolean libActive = true;
        String progName = currentProgram.getName().toLowerCase();
        String kf = System.getenv("KEYWORDS_FILE");
        if (kf != null) {
            File f = new File(kf);
            if (f.exists()) {
                try (BufferedReader r = new BufferedReader(new FileReader(f))) {
                    String line;
                    while ((line = r.readLine()) != null) {
                        line = line.trim();
                        if (line.isEmpty() || line.startsWith("#")) {
                            continue;
                        }
                        if (line.startsWith("@lib")) {
                            String v = line.substring(4).trim().toLowerCase();
                            libActive = v.equals("*") || v.isEmpty() || progName.contains(v);
                            continue;
                        }
                        if (!libActive) {
                            continue;
                        }
                        int hashAt = line.indexOf('#');
                        if (line.startsWith("@") && hashAt > 0) {
                            line = line.substring(0, hashAt).trim();
                        }
                        if (line.startsWith("@nocallers")) {
                            noCallers = true;
                            continue;
                        }
                        if (line.startsWith("@callees")) {
                            try {
                                calleeTop = Integer.parseInt(line.substring(8).trim());
                            } catch (NumberFormatException ex) {
                                calleeTop = 0;
                            }
                            continue;
                        }
                        if (line.startsWith("@range")) {
                            try {
                                String[] pr = line.substring(6).trim().split("-");
                                ranges.add(new long[] { Long.decode(pr[0].trim()).longValue(), Long.decode(pr[1].trim()).longValue() });
                            } catch (RuntimeException ex) {
                                // ข้ามบรรทัดที่อ่านไม่ได้
                            }
                            continue;
                        }
                        if (line.startsWith("@")) {
                            // @0xOFFSET = ถอดโค้ดฟังก์ชันที่ offset นี้ตรงๆ (offset = address - imageBase)
                            try {
                                manual.add(Long.decode(line.substring(1).trim()));
                            } catch (NumberFormatException ex) {
                                // ข้ามบรรทัดที่อ่านไม่ได้
                            }
                            continue;
                        }
                        if (line.startsWith("fn:")) {
                            String fk = line.substring(3).trim().toLowerCase();
                            if (!fk.isEmpty()) {
                                fnKws.add(fk);
                            }
                            continue;
                        }
                        kws.add(line.toLowerCase());
                    }
                }
            }
        }

        // ---- functions ----
        int nFunc = 0;
        try (PrintWriter w = open(out, "functions.tsv")) {
            w.println("offset\tsize\tthunk\tname");
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            while (it.hasNext()) {
                monitor.checkCancelled();
                Function f = it.next();
                w.println(off(f.getEntryPoint().getOffset()) + "\t" + f.getBody().getNumAddresses()
                        + "\t" + f.isThunk() + "\t" + f.getName(true));
                nFunc++;
            }
        }

        // ---- symbols (เฉพาะที่มีชื่อจริง ไม่ใช่ FUN_/DAT_ อัตโนมัติ) ----
        int nSym = 0;
        try (PrintWriter w = open(out, "symbols.tsv")) {
            w.println("offset\ttype\tname");
            SymbolIterator si = currentProgram.getSymbolTable().getAllSymbols(false);
            while (si.hasNext()) {
                monitor.checkCancelled();
                Symbol s = si.next();
                if (s.getSource() == SourceType.DEFAULT) {
                    continue;
                }
                if (!s.getAddress().isMemoryAddress()) {
                    continue;
                }
                w.println(off(s.getAddress().getOffset()) + "\t" + s.getSymbolType() + "\t" + s.getName(true));
                nSym++;
            }
        }

        // ---- strings + xrefs ----
        Map<Function, String> targets = new LinkedHashMap<Function, String>();
        int nStr = 0;
        try (PrintWriter w = open(out, "strings.tsv")) {
            w.println("offset\txref_functions\tstring");
            for (Data d : currentProgram.getListing().getDefinedData(true)) {
                monitor.checkCancelled();
                Object val = d.getValue();
                if (!(val instanceof String)) {
                    continue;
                }
                String v = (String) val;
                if (v.length() < 4) {
                    continue; // สั้นกว่า 4 ตัวอักษรข้าม
                }
                String clean = v.replace("\t", " ").replace("\r", " ").replace("\n", " ");

                LinkedHashSet<Function> fns = new LinkedHashSet<Function>();
                Reference[] refs = getReferencesTo(d.getAddress());
                for (Reference ref : refs) {
                    Function fn = getFunctionContaining(ref.getFromAddress());
                    if (fn != null) {
                        fns.add(fn);
                    }
                }
                StringBuilder sb = new StringBuilder();
                int c = 0;
                for (Function fn : fns) {
                    if (c >= 8) {
                        sb.append(",...");
                        break;
                    }
                    if (sb.length() > 0) {
                        sb.append(",");
                    }
                    sb.append(off(fn.getEntryPoint().getOffset()));
                    c++;
                }

                if (!kws.isEmpty() && !fns.isEmpty()) {
                    String lv = clean.toLowerCase();
                    for (String k : kws) {
                        if (lv.contains(k)) {
                            for (Function fn : fns) {
                                if (!targets.containsKey(fn)) {
                                    targets.put(fn, clean);
                                }
                            }
                            break;
                        }
                    }
                }
                w.println(off(d.getAddress().getOffset()) + "\t" + sb + "\t" + clean);
                nStr++;
            }
        }

        for (Long mo : manual) {
            Address ma = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(base + mo.longValue());
            Function mf = getFunctionAt(ma);
            if (mf == null) {
                mf = getFunctionContaining(ma);
            }
            if (mf != null && !targets.containsKey(mf)) {
                targets.put(mf, "manual @" + off(ma.getOffset()));
            }
        }

        // ---- เป้าหมายตามชื่อฟังก์ชัน (fn:) และช่วง offset (@range) ----
        if (!fnKws.isEmpty() || !ranges.isEmpty()) {
            FunctionIterator fi = currentProgram.getFunctionManager().getFunctions(true);
            while (fi.hasNext()) {
                monitor.checkCancelled();
                Function f = fi.next();
                if (targets.containsKey(f)) {
                    continue;
                }
                String nm = f.getName(true);
                String nl = nm.toLowerCase();
                long fo = f.getEntryPoint().getOffset() - base;
                boolean hit = false;
                for (String k : fnKws) {
                    if (nl.contains(k)) {
                        targets.put(f, "fn: " + nm);
                        hit = true;
                        break;
                    }
                }
                if (hit) {
                    continue;
                }
                if (nl.contains("toml::") || nl.contains("std::") || nl.contains("__ndk1") || nl.startsWith("<external>")
                        || f.getBody().getNumAddresses() < 8) {
                    continue;
                }
                for (long[] rg : ranges) {
                    if (fo >= rg[0] && fo < rg[1]) {
                        targets.put(f, "range " + off(f.getEntryPoint().getOffset()));
                        break;
                    }
                }
            }
        }

        // ---- decompile ฟังก์ชันที่อ้างถึงสตริงตาม keywords ----
        int nDec = 0;
        if (!targets.isEmpty()) {
            DecompInterface di = new DecompInterface();
            di.openProgram(currentProgram);
            try (PrintWriter w = open(out, "decompiled.c")) {
                for (Map.Entry<Function, String> e : targets.entrySet()) {
                    if (nDec >= maxDecomp) {
                        break;
                    }
                    monitor.checkCancelled();
                    Function f = e.getKey();
                    DecompileResults r = di.decompileFunction(f, 40, monitor);
                    if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null) {
                        w.println("// ===== " + off(f.getEntryPoint().getOffset()) + "  "
                                + f.getName(true) + "  via string: " + e.getValue());
                        w.println(r.getDecompiledFunction().getC());
                        nDec++;
                    }
                }
            } finally {
                di.dispose();
            }
        }

        // ---- callees: ฟังก์ชันที่เป้าหมายเรียกบ่อยที่สุด (ImGui static / ตัวช่วยที่ไม่มีชื่อ) ----
        int nCalleeDec = 0;
        if (calleeTop > 0 && !targets.isEmpty()) {
            try {
                final Map<Function, Integer> cnt = new HashMap<Function, Integer>();
                for (Function t : targets.keySet()) {
                    monitor.checkCancelled();
                    try {
                        for (Function c : t.getCalledFunctions(monitor)) {
                            if (targets.containsKey(c)) {
                                continue;
                            }
                            Integer old = cnt.get(c);
                            cnt.put(c, Integer.valueOf(old == null ? 1 : old.intValue() + 1));
                        }
                    } catch (RuntimeException ex) {
                        // ข้ามฟังก์ชันที่อ่านไม่ได้
                    }
                }
                List<Function> order = new ArrayList<Function>(cnt.keySet());
                Collections.sort(order, new Comparator<Function>() {
                    public int compare(Function a, Function b) {
                        return cnt.get(b).intValue() - cnt.get(a).intValue();
                    }
                });
                DecompInterface dc = new DecompInterface();
                dc.openProgram(currentProgram);
                try (PrintWriter cw = open(out, "callees.tsv"); PrintWriter dw = open(out, "decompiled_callees.c")) {
                    cw.println("offset\tcalled_by_n_targets\tsize\tname");
                    for (Function c : order) {
                        if (nCalleeDec >= calleeTop) {
                            break;
                        }
                        monitor.checkCancelled();
                        String cn = c.getName(true);
                        String cl = cn.toLowerCase();
                        long csz = c.getBody().getNumAddresses();
                        if (cl.startsWith("<external>") || cl.contains("toml::") || cl.contains("std::") || cl.contains("__ndk1")
                                || csz < 8 || csz > 6000) {
                            continue;
                        }
                        cw.println(off(c.getEntryPoint().getOffset()) + "\t" + cnt.get(c) + "\t" + csz + "\t" + cn);
                        DecompileResults rc = dc.decompileFunction(c, 40, monitor);
                        if (rc != null && rc.decompileCompleted() && rc.getDecompiledFunction() != null) {
                            dw.println("// ===== " + off(c.getEntryPoint().getOffset()) + "  " + cn + "  called by " + cnt.get(c) + " targets");
                            dw.println(rc.getDecompiledFunction().getC());
                            nCalleeDec++;
                        }
                    }
                } finally {
                    dc.dispose();
                }
            } catch (RuntimeException ex) {
                println("callees step failed: " + ex);
            }
        }

        // ---- callers ของฟังก์ชันที่ตรง keyword (callers.tsv + decompiled_callers.c) ----
        int maxCallers = 40;
        String mc = System.getenv("MAX_CALLERS");
        if (mc != null) {
            try {
                maxCallers = Integer.parseInt(mc.trim());
            } catch (NumberFormatException ex) {
                // ใช้ค่าเริ่มต้น
            }
        }
        int nCallers = 0;
        int nCallerDec = 0;
        if (!targets.isEmpty() && !noCallers) {
            Map<Function, String> callerMap = new LinkedHashMap<Function, String>();
            try (PrintWriter cw = open(out, "callers.tsv")) {
                cw.println("callee\tcaller\tcallsite");
                for (Function callee : targets.keySet()) {
                    monitor.checkCancelled();
                    int perCallee = 0;
                    LinkedHashSet<Function> seen = new LinkedHashSet<Function>();
                    Reference[] crefs = getReferencesTo(callee.getEntryPoint());
                    for (Reference ref : crefs) {
                        if (!ref.getReferenceType().isCall()) {
                            continue;
                        }
                        Function caller = getFunctionContaining(ref.getFromAddress());
                        if (caller == null) {
                            continue;
                        }
                        cw.println(off(callee.getEntryPoint().getOffset()) + "\t"
                                + off(caller.getEntryPoint().getOffset()) + "\t"
                                + off(ref.getFromAddress().getOffset()));
                        nCallers++;
                        if (seen.add(caller) && perCallee < 3 && !targets.containsKey(caller)
                                && !callerMap.containsKey(caller)) {
                            callerMap.put(caller, "calls " + off(callee.getEntryPoint().getOffset()));
                            perCallee++;
                        }
                    }
                }
            }
            if (!callerMap.isEmpty()) {
                DecompInterface di2 = new DecompInterface();
                di2.openProgram(currentProgram);
                try (PrintWriter dw = open(out, "decompiled_callers.c")) {
                    for (Map.Entry<Function, String> e2 : callerMap.entrySet()) {
                        if (nCallerDec >= maxCallers) {
                            break;
                        }
                        monitor.checkCancelled();
                        Function cf = e2.getKey();
                        DecompileResults r2 = di2.decompileFunction(cf, 40, monitor);
                        if (r2 != null && r2.decompileCompleted() && r2.getDecompiledFunction() != null) {
                            dw.println("// ===== " + off(cf.getEntryPoint().getOffset()) + "  "
                                    + cf.getName(true) + "  " + e2.getValue());
                            dw.println(r2.getDecompiledFunction().getC());
                            nCallerDec++;
                        }
                    }
                } finally {
                    di2.dispose();
                }
            }
        }

        // ---- summary ----
        try (PrintWriter w = open(out, "summary.txt")) {
            w.println("program: " + currentProgram.getName());
            w.println("imageBase: 0x" + Long.toHexString(base));
            w.println("functions: " + nFunc);
            w.println("named symbols: " + nSym);
            w.println("strings: " + nStr);
            w.println("keywords: " + kws.size() + "  matched functions: " + targets.size()
                    + "  decompiled: " + nDec + " (max " + maxDecomp + ")");
            w.println("callees decompiled: " + nCalleeDec + " (max " + calleeTop + ")");
            w.println("callers (call sites): " + nCallers + "  decompiled callers: " + nCallerDec + " (max " + maxCallers + ")");
            w.println("offset = address - imageBase");
        }
        println("ExportInfo done: functions=" + nFunc + " symbols=" + nSym + " strings=" + nStr + " decompiled=" + nDec);
    }
}
