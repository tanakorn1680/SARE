#!/usr/bin/env python3
"""postprocess.py <out_dir>  -  ทำให้ผล Ghidra อ่านออก (ไม่ใช้ Ghidra / รันได้ซ้ำ)

ต่อไลบรารี (โฟลเดอร์ย่อยของ out/ ที่มี decompiled.c) สร้าง:
  imports.tsv            ชื่อสัญลักษณ์เกมที่ไลบรารีนำเข้า : FUN_ (stub) / DAT_ (ตัวแปร) -> mangled -> demangled
  decompiled.named.c     decompiled.c ที่แทน FUN_xxxx / DAT_xxxx ด้วยชื่อสัญลักษณ์จริง
  decompiled_callers.named.c  เช่นเดียวกัน
  byfunc.tsv             ฟังก์ชัน -> สตริงที่ฟังก์ชันนั้นอ้างถึง (ไว้ดูว่าฟังก์ชันไหนคือหน้าไหน)
ไลบรารีนี้เรียกสัญลักษณ์เกมผ่าน dlsym-wrapper:
  stub:  void FUN_001a2ba4(..){ f = FUN_0019d6c0("_ZN11CWaterLevel..."); (*f)(..); }
  data:  DAT_002bc8d8 = FUN_0019d6c0("_ZN11CWeaponInfo15ms_aWeaponNamesE");
  base:  DAT_002bc8e8 = DAT_002bb0e8 + 0x84fdc8;      (ที่อยู่ในเกมแบบ base + offset ตรง ๆ ไม่มีชื่อ symbol)
"""
import os, re, subprocess, sys


def read_tsv(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding='utf-8', errors='replace') as f:
        lines = f.read().split('\n')
    return [l.split('\t') for l in lines[1:] if l]


def image_base(lib_dir):
    p = os.path.join(lib_dir, 'summary.txt')
    if os.path.exists(p):
        for l in open(p, encoding='utf-8', errors='replace'):
            m = re.match(r'imageBase:\s*0x([0-9a-fA-F]+)', l)
            if m:
                return int(m.group(1), 16)
    return 0x100000


def demangle(names):
    uniq = sorted(set(n for n in names if n.startswith('_Z')))
    res = {}
    if not uniq:
        return res
    try:
        p = subprocess.run(['c++filt'], input='\n'.join(uniq) + '\n', capture_output=True, text=True, timeout=120)
        out = p.stdout.split('\n')
        for a, b in zip(uniq, out):
            res[a] = b.strip() or a
    except Exception:
        pass
    return res


def ident(demangled, mangled):
    s = demangled if demangled and demangled != mangled else mangled
    cut = s.find('(')
    if cut > 0:
        s = s[:cut]
    s = re.sub(r'[^0-9A-Za-z_]+', '_', s).strip('_')
    return s or mangled


def process(lib_dir):
    dec = os.path.join(lib_dir, 'decompiled.c')
    dec2 = os.path.join(lib_dir, 'decompiled_callers.c')
    dec3 = os.path.join(lib_dir, 'decompiled_callees.c')
    base = image_base(lib_dir)
    funcs = {}                                   # offset -> (size, name)
    for r in read_tsv(os.path.join(lib_dir, 'functions.tsv')):
        if len(r) >= 4:
            funcs[int(r[0], 16)] = (int(r[1]), r[3])
    strings = read_tsv(os.path.join(lib_dir, 'strings.tsv'))

    stub = {}                                    # FUN_xxxxxxxx -> mangled
    for r in strings:
        if len(r) < 3 or not r[2].startswith('_Z') or not r[1]:
            continue
        xs = [x for x in r[1].split(',') if x.startswith('0x')]
        if len(xs) != 1:
            continue
        o = int(xs[0], 16)
        sz = funcs.get(o, (0, ''))[0]
        if 0 < sz <= 0x90:                       # a stub is a handful of instructions
            stub['FUN_%08x' % (o + base)] = r[2]

    data = {}                                    # DAT_xxxxxxxx -> mangled
    baseoff = {}                                 # DAT_xxxxxxxx -> (DAT_base, offset)
    text = ''
    for p in (dec, dec2, dec3):
        if os.path.exists(p):
            text += open(p, encoding='utf-8', errors='replace').read() + '\n'
    for m in re.finditer(r'(DAT_[0-9a-f]+)\s*=\s*(?:\([^)]*\)\s*)?FUN_[0-9a-f]+\(\s*"([^"]+)"\s*\)', text):
        data.setdefault(m.group(1), m.group(2))
    for m in re.finditer(r'(DAT_[0-9a-f]+)\s*=\s*(DAT_[0-9a-f]+)\s*\+\s*(0x[0-9a-f]+)\s*;', text):
        baseoff.setdefault(m.group(1), (m.group(2), m.group(3)))
    # stub bodies decompiled in this run also say which symbol they call
    for m in re.finditer(r'// ===== 0x[0-9a-f]+\s+(FUN_[0-9a-f]+)[^\n]*\n(?:(?!// =====).)*?FUN_[0-9a-f]+\(\s*"(_Z[^"]+)"\s*\)', text, re.S):
        stub.setdefault(m.group(1), m.group(2))

    dm = demangle(list(stub.values()) + list(data.values()))
    used = {}
    names = {}                                   # old identifier -> new identifier

    def unique(n):
        k = used.get(n, 0)
        used[n] = k + 1
        return n if k == 0 else '%s_%d' % (n, k + 1)

    rows = []
    for old, mg in sorted(stub.items()):
        d = dm.get(mg, '')
        isfn = '(' in d or not d                  # no "(" in the demangled name = a variable: the stub only hands back its address
        nn = unique(ident(d, mg) if isfn else 'get_' + ident(d, mg))
        names[old] = nn
        rows.append((old, 'function' if isfn else 'data-getter', mg, d, nn))
    for old, mg in sorted(data.items()):
        nn = unique('g_' + ident(dm.get(mg), mg))
        names[old] = nn
        rows.append((old, 'data', mg, dm.get(mg, ''), nn))
    for old, (b, off) in sorted(baseoff.items()):
        nn = unique('g_%s_plus_%s' % (b, off))
        names.setdefault(old, nn)
        rows.append((old, 'base+offset', b + ' + ' + off, '', names[old]))

    with open(os.path.join(lib_dir, 'imports.tsv'), 'w', encoding='utf-8') as f:
        f.write('ghidra_name\tkind\tmangled\tdemangled\tnamed_as\n')
        for r in rows:
            f.write('\t'.join(r) + '\n')

    if names:
        rx = re.compile(r'\b(' + '|'.join(re.escape(k) for k in sorted(names, key=len, reverse=True)) + r')\b')
        for p in (dec, dec2, dec3):
            if os.path.exists(p):
                src = open(p, encoding='utf-8', errors='replace').read()
                outp = p[:-2] + '.named.c'
                with open(outp, 'w', encoding='utf-8') as f:
                    f.write(rx.sub(lambda m: names[m.group(1)], src))

    byf = {}                                     # function offset -> strings
    for r in strings:
        if len(r) < 3 or not r[1] or r[2].startswith('_Z'):
            continue
        for x in r[1].split(','):
            if x.startswith('0x'):
                byf.setdefault(int(x, 16), []).append(r[2])
    with open(os.path.join(lib_dir, 'byfunc.tsv'), 'w', encoding='utf-8') as f:
        f.write('offset\tsize\tname\tn_strings\tstrings\n')
        for o in sorted(byf, key=lambda k: -len(byf[k])):
            sz, nm = funcs.get(o, (0, ''))
            f.write('0x%x\t%d\t%s\t%d\t%s\n' % (o, sz, nm, len(byf[o]), ' | '.join(byf[o][:60])))
    return len(stub), len(data), len(baseoff)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else 'out'
    for d in sorted(os.listdir(out)):
        p = os.path.join(out, d)
        if os.path.isdir(p) and os.path.exists(os.path.join(p, 'functions.tsv')):
            try:
                s, dt, b = process(p)
                print('postprocess %s: %d function stubs, %d data symbols, %d base+offset' % (d, s, dt, b))
            except Exception as ex:                      # never fail the workflow because of this step
                print('postprocess %s FAILED: %r' % (d, ex))


if __name__ == '__main__':
    main()
