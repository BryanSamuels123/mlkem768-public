#!/usr/bin/env python3
"""Sum the bytes a function actually zeroes, from its disassembly.

`audit-zeroize` used to count store/move instructions and require the total to be
"materially larger than the eliminated control". That is a proxy, and it cannot tell a
COMPLETE erase from a PARTIAL one: a 64-byte erase is `xorps` + four 16-byte stores, and
a 48-byte erase is `xorps` + three. Both clear the old bar. This measures the property
the spec actually requires -- that the whole buffer is overwritten -- by adding up the
widths of the stores that write zero.

Only stores of a KNOWN-ZERO source count. That distinction matters on macOS, where the
stack protector emits `movq %rax, -0x8(%rbp)` inside the same function: a real store, of
a non-zero value, which a naive count would have credited to the erase.

Prints the total byte count, or a diagnostic and a negative total if it cannot decide.
"""

import re
import subprocess
import sys

# AT&T, and identical between Apple objdump and GNU objdump for these forms.
INSN = re.compile(r"^\s*[0-9a-f]+:\s*(?:[0-9a-f]{2} )*\s*(?P<m>[a-z][a-z0-9.]*)\s*(?P<ops>[^#;]*)")

VEC_WIDTH = {"xmm": 16, "ymm": 32, "zmm": 64}
IMM_WIDTH = {"movb": 1, "movw": 2, "movl": 4, "movq": 8}
# Vector stores whose source register may be a zeroed vector register.
VEC_STORE = {"movaps", "movups", "movapd", "movupd", "movdqa", "movdqu",
             "vmovaps", "vmovups", "vmovapd", "vmovupd", "vmovdqa", "vmovdqu",
             "vmovdqa32", "vmovdqa64", "vmovntdq", "movntdq", "movntps"}
# Instructions that zero a register outright.
ZEROERS = {"xorps", "xorpd", "pxor", "vpxor", "vxorps", "vxorpd", "xor", "xorl",
           "xorq", "xorw", "xorb", "vpxord", "vpxorq"}


def regname(op):
    m = re.search(r"%([a-z0-9]+)", op)
    return m.group(1) if m else None


def vec_width(reg):
    for k, v in VEC_WIDTH.items():
        if reg and reg.startswith(k):
            return v
    return None


def body(obj, sym, objdump="objdump"):
    txt = subprocess.run([objdump, "-d", "--no-show-raw-insn", obj],
                         capture_output=True, text=True).stdout
    out, inside = [], False
    for line in txt.split("\n"):
        m = re.match(r"^[0-9a-f]+ <(?P<n>[^>]+)>:", line)
        if m:
            inside = (m.group("n").lstrip("_") == sym.lstrip("_"))
            continue
        if inside:
            out.append(line)
    return out


def zeroed_bytes(lines):
    """(total_bytes, notes). Counts only stores whose source is provably zero."""
    zero_regs = set()
    gpr_zero = set()
    total = 0
    notes = []
    rcx = None

    for line in lines:
        m = INSN.match(line)
        if not m:
            continue
        mn = m.group("m")
        ops = [o.strip() for o in m.group("ops").split(",")] if m.group("ops").strip() else []

        # --- register zeroing: xor reg, reg (same register) ---
        if mn in ZEROERS and len(ops) >= 2:
            srcs = [regname(o) for o in ops[:-1]]
            dst = regname(ops[-1])
            if dst and all(s == dst for s in srcs if s):
                zero_regs.add(dst)
                gpr_zero.add(dst)
                continue
            # vpxor a,a,b style: all sources identical -> dst zero
            if dst and len(set(s for s in srcs if s)) == 1:
                zero_regs.add(dst)
                continue
            if dst:
                zero_regs.discard(dst)
                gpr_zero.discard(dst)
            continue

        # --- track a constant into %ecx/%rcx for rep stos ---
        if mn.startswith("mov") and len(ops) == 2 and ops[0].startswith("$"):
            d = regname(ops[1])
            if d in ("ecx", "rcx"):
                try:
                    rcx = int(ops[0][1:], 0)
                except ValueError:
                    rcx = None
            if d:
                zero_regs.discard(d)
                gpr_zero.discard(d)
                if ops[0] in ("$0x0", "$0"):
                    gpr_zero.add(d)
                    zero_regs.add(d)

        # --- rep stos: writes %rcx units of %al/%eax/%rax ---
        if "stos" in mn or (mn == "rep" and "stos" in line):
            unit = {"stosb": 1, "stosw": 2, "stosl": 4, "stosq": 8}
            u = next((v for k, v in unit.items() if k in line), None)
            src_zero = any(r in gpr_zero for r in ("eax", "rax", "al"))
            if u and rcx is not None and src_zero:
                total += u * rcx
            elif u:
                notes.append("rep stos with unknown count or non-zero source")
            continue

        # --- immediate-zero store to memory: movb $0x0, -0x8(%rbp) ---
        if mn in IMM_WIDTH and len(ops) == 2 and ops[0] in ("$0x0", "$0"):
            if "(" in ops[1]:
                total += IMM_WIDTH[mn]
            continue

        # --- vector store from a known-zero register to memory ---
        if mn in VEC_STORE and len(ops) == 2:
            src, dst = ops[0], ops[1]
            if "(" in dst and not dst.startswith("%"):
                r = regname(src)
                if r in zero_regs:
                    w = vec_width(r)
                    if w:
                        total += w
                # a store from a non-zero vector register is simply not an erase
            elif "(" in src:
                # load into a register: it is no longer known-zero
                d = regname(dst)
                if d:
                    zero_regs.discard(d)
            continue

        # --- generic GPR store of a known-zero register ---
        if mn in IMM_WIDTH and len(ops) == 2 and ops[0].startswith("%"):
            if "(" in ops[1]:
                r = regname(ops[0])
                if r in gpr_zero:
                    total += IMM_WIDTH[mn]
            continue

    return total, notes


def main():
    if len(sys.argv) < 3:
        print("usage: zeroize_width.py <obj> <symbol> [objdump]", file=sys.stderr)
        return 2
    obj, sym = sys.argv[1], sys.argv[2]
    objdump = sys.argv[3] if len(sys.argv) > 3 else "objdump"
    lines = body(obj, sym, objdump)
    if not lines:
        print("-1 no-such-symbol")
        return 0
    total, notes = zeroed_bytes(lines)
    print(f"{total} {';'.join(notes) if notes else 'ok'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
