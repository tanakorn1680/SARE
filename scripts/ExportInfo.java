// ส่งออก: functions.tsv, symbols.tsv, strings.tsv (พร้อมฟังก์ชันที่อ้างถึง), decompiled.c (ตาม keywords.txt)
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
        List<Long> manual = new ArrayList<Long>();
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
                        if (line.startsWith("@")) {
                            // @0xOFFSET = ถอดโค้ดฟังก์ชันที่ offset นี้ตรงๆ (offset = address - imageBase)
                            try {
                                manual.add(Long.decode(line.substring(1).trim()));
                            } catch (NumberFormatException ex) {
                                // ข้ามบรรทัดที่อ่านไม่ได้
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
        if (!targets.isEmpty()) {
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
            w.println("callers (call sites): " + nCallers + "  decompiled callers: " + nCallerDec + " (max " + maxCallers + ")");
            w.println("offset = address - imageBase");
        }
        println("ExportInfo done: functions=" + nFunc + " symbols=" + nSym + " strings=" + nStr + " decompiled=" + nDec);
    }
}
