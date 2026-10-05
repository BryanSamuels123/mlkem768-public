#!/usr/bin/env python3
"""Per-site Zeroizing<T> destructor-elision check (spec 8.3, FIPS 203 3.3).

`gmake audit-zeroize` proves that `secure_zero` itself survives -O3 IN ISOLATION.
It does not prove that the `Zeroizing<T>` destructor actually runs at each wrap
site: an inlined destructor on a large PolyVec is a plausible place for the
optimizer to be cleverer than expected, and nothing checked it until now.

METHOD
------
Ground truth comes from SOURCE: every `Zeroizing<T> a, b;` declaration is parsed
out of the .cpp files and attributed to its enclosing function by brace depth.
Observed erase events come from the OBJECT's DWARF, built at the real build
flags. The two are derived independently on purpose -- deriving both from DWARF
would make the check circular.

Why DWARF inline DIEs and not disassembly line markers: a single erase can be
split across several basic blocks. Measured on this host, the 32-byte erase in
`decaps_internal` compiles to a peeled first byte store plus a 4x-unrolled loop,
which is TWO `zeroize.hpp:<loop>` line markers for ONE site -- so counting
markers over-counts (it reported 8 events for 7 wraps). A DW_TAG_inlined_subroutine
is emitted once per inlined instance regardless of how the loop was shaped, so
counting those is exact.

Each site's erase appears as an inlined `Zeroizing<T>::~Zeroizing` DIE. That holds
in both codegen shapes seen here:
  - destructor fully inlined       -> D1 DIE containing an inlined D2 DIE
  - D1 inlined, D2 left out-of-line -> D1 DIE containing a `call` to the D2 symbol
Counting the OUTERMOST Zeroizing-destructor DIE of each chain therefore counts
sites either way. For the second shape the erase lives in the out-of-line
destructor body, so each such body present in the object is separately checked to
contain real zeroing stores.

A function can be both emitted out-of-line AND inlined into a caller (clang does
this for `encaps_internal`), which duplicates its erase events. The DWARF inline
tree says how many instances exist, so expected counts are scaled by that rather
than the duplicates being waved away.

LIMITS
------
Valid only for the build flags it runs under. It compiles single translation
units; enabling LTO would let the optimizer see across TU boundaries and every
result here would have to be re-established. See ADR-034.
"""

import os
import re
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Translation units holding Zeroizing wraps, and the functions we require coverage
# for. The function list is a floor, not the whole story: any function found to
# declare a wrap is checked, so a new wrap in a new function cannot slip through
# by not being listed here.
TUS = ["src/kpke.cpp", "src/kem.cpp"]

def _which(*names):
    """First tool on PATH out of `names`, or None.

    macOS ships it as `dwarfdump`; Debian's llvm-16 package installs only the
    versioned `llvm-dwarfdump-16`, so the gate has to look for both or it would
    be silently unavailable on the very platform ADR-011 runs the CT gates on.
    """
    import shutil
    for n in names:
        if n and shutil.which(n):
            return n
    return None


CXX = os.environ.get("CXX", "clang++")
DWARFDUMP = (os.environ.get("DWARFDUMP")
             or _which("dwarfdump", "llvm-dwarfdump", "llvm-dwarfdump-16",
                       "llvm-dwarfdump-17", "llvm-dwarfdump-18"))
OBJDUMP = os.environ.get("OBJDUMP", "objdump")
CXXFLAGS = os.environ.get("CXXFLAGS", "").split()
CPPFLAGS = os.environ.get("CPPFLAGS", "").split()

# ---------------------------------------------------------------- ground truth

DECL = re.compile(r"^\s*Zeroizing<(?P<type>.+?)>\s+(?P<names>[A-Za-z_][^;=]*);")
KEYWORD_BRACE = {"if", "for", "while", "switch", "do", "else", "catch",
                 "namespace", "struct", "class", "enum", "union", "extern"}
IDENT_TAIL = re.compile(r"(?P<name>[A-Za-z_~][A-Za-z0-9_]*)\s*$")


def strip_code(text):
    """Remove comments and string/char literals, preserving newlines and offsets."""
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        two = text[i:i + 2]
        if two == "//":
            while i < n and text[i] != "\n":
                i += 1
        elif two == "/*":
            i += 2
            while i < n and text[i:i + 2] != "*/":
                out.append("\n" if text[i] == "\n" else " ")
                i += 1
            i += 2
        elif c in "\"'":
            q = c
            out.append(" ")
            i += 1
            while i < n and text[i] != q:
                if text[i] == "\\":
                    i += 1
                i += 1
            i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def enclosing_functions(path):
    """Map line number -> innermost enclosing function name.

    Walks the file as a character stream rather than line by line, so a
    signature spread over several lines (which all five target functions have)
    is handled without special cases.
    """
    src = strip_code(open(path, encoding="utf-8").read())
    out = {}
    stack = []      # function names, innermost last (None for non-function scopes)
    buf = []        # text seen since the last statement boundary
    line = 1
    for ch in src:
        if ch == "\n":
            cur = next((nm for nm in reversed(stack) if nm), None)
            out[line] = cur
            line += 1
            buf.append(" ")
            continue
        if ch == "{":
            seg = "".join(buf)
            name = None
            if "(" in seg:
                head = seg.rsplit("(", 1)[0] if seg.count("(") == 1 else None
                # take text before the FIRST '(' of this declarator
                head = seg.split("(")[0]
                m = IDENT_TAIL.search(head.rstrip())
                if m and m.group("name") not in KEYWORD_BRACE:
                    toks = re.findall(r"[A-Za-z_~][A-Za-z0-9_]*", head)
                    if not (toks and toks[0] in KEYWORD_BRACE):
                        name = m.group("name")
            stack.append(name)
            buf = []
            continue
        if ch == "}":
            if stack:
                stack.pop()
            buf = []
            continue
        if ch == ";":
            buf = []
            continue
        buf.append(ch)
    out.setdefault(line, next((nm for nm in reversed(stack) if nm), None))
    return out


def ground_truth():
    """(file, func, var, decl_line, type_text) for every declared Zeroizing object."""
    sites = []
    for tu in TUS:
        path = os.path.join(REPO, tu)
        scope = enclosing_functions(path)
        for i, raw in enumerate(open(path, encoding="utf-8").read().split("\n"), 1):
            line = raw.split("//")[0]
            m = DECL.match(line)
            if not m:
                continue
            names = [n.strip() for n in m.group("names").split(",") if n.strip()]
            for n in names:
                sites.append((tu, scope.get(i), n, i, m.group("type").strip()))
    return sites


# ----------------------------------------------------------------------- DWARF

TAG = re.compile(r"^(?P<pad>\s*)(?P<off>0x[0-9a-f]+):(?P<ind>\s+)(?P<tag>DW_TAG_\w+)")
# Deliberately NOT anchored on the closing paren: DW_AT_ranges spans several lines
# (`(indexed (0x6) rangelist = 0x98` then one line per range). Anchoring on `)$`
# silently dropped it, which made an inlined instance look like it had no code and
# under-counted the instances of every function clang both emitted and inlined.
ATTR = re.compile(r"^\s+(?P<at>DW_AT_\w+)\s*\((?P<val>.*)$")
# Continuation lines of a DW_AT_ranges list: `[0x0000000000000070, 0x00000000000001cf)`
RANGE_LINE = re.compile(r"^\s*\[0x(?P<lo>[0-9a-f]+),\s*0x(?P<hi>[0-9a-f]+)\)")

ZERO_DTOR = re.compile(r"^_ZN8mlkem7689ZeroizingI(?P<t>.*)ED[0-9]Ev$")


def demangle(names):
    if not names:
        return {}
    p = subprocess.run(["c++filt"], input="\n".join(names), capture_output=True, text=True)
    return dict(zip(names, p.stdout.strip().split("\n")))


def parse_dwarf(obj):
    """Return (events, instances, dtor_bodies).

    events    : list of (func_identity, mangled_dtor, size_or_None)
    instances : func_identity -> how many copies of it exist in the object
    dtor_bodies: mangled names of out-of-line ~Zeroizing definitions in this object
    """
    txt = subprocess.run([DWARFDUMP, "--debug-info", obj],
                         capture_output=True, text=True).stdout

    # depth = (tag column - 13) / 2, calibrated from dwarfdump's own indentation
    stack = []   # (depth, tag, attrs, ranges)
    events = []
    instances = {}
    dtor_bodies = set()
    scopes = []  # (lo, hi, depth, name) for every code-bearing non-dtor scope
    counted = []  # ranges of dtor DIEs already counted as an erase event

    def ident(attrs, tag):
        for key in ("DW_AT_abstract_origin", "DW_AT_linkage_name", "DW_AT_name"):
            m = re.search(r'"(?P<n>[^"]+)"', attrs.get(key, ""))
            if m:
                return m.group("n")
        return None

    def flush(die):
        depth, tag, attrs, rngs = die
        name = ident(attrs, tag)
        if not name:
            return
        if tag in ("DW_TAG_subprogram", "DW_TAG_inlined_subroutine"):
            # only count things that actually occupy code
            if not rngs:
                return
            instances[name] = instances.get(name, 0) + 1
            zm = ZERO_DTOR.match(name)
            if not zm:
                for lo, hi in rngs:
                    scopes.append((lo, hi, depth, name))
                return
            if tag == "DW_TAG_subprogram":
                dtor_bodies.add(name)
            else:
                # outermost dtor DIE of the chain only
                outer = any(ZERO_DTOR.match(ident(a, t) or "")
                            for (_, t, a, _r) in stack
                            if t == "DW_TAG_inlined_subroutine")
                if not outer:
                    owner = None
                    for (_, t, a, _r) in reversed(stack):
                        if t in ("DW_TAG_subprogram", "DW_TAG_inlined_subroutine"):
                            n2 = ident(a, t)
                            if n2 and not ZERO_DTOR.match(n2):
                                owner = n2
                                break
                    events.append((owner, name))
                    # This site is now counted. If clang inlined D1 but left D2 out
                    # of line, the call to D2 sits inside this range -- record it so
                    # the call loop below does not count the same site twice.
                    counted.extend(rngs)

    # Collect every DIE with its attributes first; a DIE cannot be judged until
    # all of its attribute lines have been read.
    dies = []
    cur = None
    in_ranges = False
    for raw in txt.split("\n"):
        m = TAG.match(raw)
        if m:
            col = raw.index(m.group("tag"))
            depth = (col - 13) // 2
            cur = (depth, m.group("tag"), {}, [])
            dies.append(cur)
            in_ranges = False
            continue
        if in_ranges and cur is not None:
            r = RANGE_LINE.match(raw)
            if r:
                cur[3].append((int(r.group("lo"), 16), int(r.group("hi"), 16)))
                continue
            in_ranges = False
        m = ATTR.match(raw)
        if m and cur is not None:
            cur[2][m.group("at")] = m.group("val")
            in_ranges = (m.group("at") == "DW_AT_ranges")

    # Resolve each code-bearing DIE to concrete address ranges, so an out-of-line
    # destructor CALL can be attributed to the scope it sits in.
    for die in dies:
        attrs, rngs = die[2], die[3]
        if rngs:
            continue
        lo = attrs.get("DW_AT_low_pc")
        hi = attrs.get("DW_AT_high_pc")
        if lo is None:
            continue
        try:
            lo_v = int(lo.split()[0].rstrip(")"), 16)
        except ValueError:
            continue
        hi_v = lo_v + 1
        if hi is not None:
            try:
                h = int(hi.split()[0].rstrip(")"), 16)
                hi_v = h if h > lo_v else lo_v + h
            except ValueError:
                pass
        rngs.append((lo_v, hi_v))

    for die in dies:
        depth = die[0]
        while stack and stack[-1][0] >= depth:
            stack.pop()
        flush(die)
        stack.append(die)

    # A site whose destructor was left entirely out of line produces a plain `call`
    # and NO inlined DIE. That is what clang does on Linux/libstdc++ for the 64-byte
    # wraps, where macOS/libc++ instead inlines a D1 that calls D2 -- so counting only
    # inlined DIEs reported five real erases as missing. Attribute those calls to the
    # innermost enclosing scope by address.
    for addr, sym in dtor_call_sites(obj):
        if any(lo <= addr < hi for lo, hi in counted):
            continue
        best = None
        for lo, hi, depth, name in scopes:
            if lo <= addr < hi and (best is None or depth > best[0]):
                best = (depth, name)
        events.append((best[1] if best else None, sym))

    return events, instances, dtor_bodies


RELOC = re.compile(
    r"^\s*0*(?P<addr>[0-9a-f]+):\s+(?:X86_64_RELOC_\w+|R_X86_64_\w+)\s+(?P<sym>\S+)")


def dtor_call_sites(obj):
    """(address, symbol) for each relocated call to an out-of-line ~Zeroizing."""
    txt = subprocess.run([OBJDUMP, "-dr", "--no-show-raw-insn", obj],
                         capture_output=True, text=True).stdout
    out = []
    for line in txt.split("\n"):
        m = RELOC.match(line)
        if not m:
            continue
        sym = m.group("sym").split("-")[0].split("@")[0].lstrip("_")
        if ZERO_DTOR.match("_" + sym):
            out.append((int(m.group("addr"), 16), "_" + sym))
    return out


ARR_SRC = re.compile(r"\barray<.*,\s*(?P<n>[^,<>]+)>\s*$")
# libc++ mangles std::array as NSt3__15arrayI...; libstdc++ as St5arrayI... . Match the
# array-of-uchar-length part only, so the gate reads the same on macOS and in the
# Linux container rather than silently failing to fingerprint types on one of them.
ARR_MANGLED = re.compile(r"arrayIhLm(?P<n>\d+)E")
NAMED_MANGLED = re.compile(r"ZeroizingINS_\d+(?P<w>[A-Za-z_][A-Za-z0-9_]*)EED[0-9]Ev$")


def type_key_src(type_text):
    """Fingerprint a source-level Zeroizing<T> type, or None if not resolvable.

    `std::array<std::uint8_t, 33>` resolves; `std::array<std::uint8_t, 32 + CT_BYTES>`
    does not, because the size is an expression this script will not evaluate.
    Unresolved types are paired up by elimination instead of being guessed at.
    """
    t = type_text.strip()
    m = ARR_SRC.search(t)
    if m:
        n = m.group("n").strip()
        return ("array", int(n)) if n.isdigit() else None
    return ("name", t.split("::")[-1].strip())


def type_key_mangled(mangled):
    m = ARR_MANGLED.search(mangled)
    if m:
        return ("array", int(m.group("n")))
    m = NAMED_MANGLED.search(mangled)
    if m:
        return ("name", m.group("w"))
    return None


def name_missing_sites(vars_, observed_types):
    """Return the declared wraps that have no erase event, by type fingerprint."""
    from collections import Counter
    obs = Counter()
    for mangled, count in observed_types.items():
        k = type_key_mangled(mangled)
        obs[k] += count

    resolved, unresolved = [], []
    for var, line, typ in vars_:
        k = type_key_src(typ)
        (resolved if k else unresolved).append((var, line, typ, k))

    missing = []
    for var, line, typ, k in resolved:
        if obs.get(k, 0) > 0:
            obs[k] -= 1
        else:
            missing.append((var, line, typ))

    # Whatever erase events are still unclaimed must belong to the wraps whose
    # sizes were not resolvable; pair them off by elimination.
    leftover = sum(v for v in obs.values() if v > 0)
    for i, (var, line, typ, _) in enumerate(unresolved):
        if i < leftover:
            continue
        missing.append((var, line, typ))
    return missing


def dtor_body_zeroes(obj, mangled):
    """Confirm an out-of-line ~Zeroizing definition really contains zero stores."""
    txt = subprocess.run([OBJDUMP, "-d", "--no-show-raw-insn", obj],
                         capture_output=True, text=True).stdout
    # Mach-O labels carry an extra leading underscore that ELF ones do not, so
    # compare with leading underscores stripped from both sides.
    want = mangled.lstrip("_")
    body, inside = [], False
    for line in txt.split("\n"):
        m = re.match(r"^[0-9a-f]+ <(?P<n>[^>]+)>:", line)
        if m:
            inside = (m.group("n").lstrip("_") == want)
            continue
        if inside:
            body.append(line)
    blob = "\n".join(body)
    # a zeroing store: immediate 0 moved to memory, or rep stos
    return bool(re.search(r"mov[bwlq]?\s+\$0x0,\s*[-0-9(]", blob)
                or "stos" in blob)


# ------------------------------------------------------------------------ main

def main():
    only = sys.argv[1] if len(sys.argv) > 1 else None

    if not DWARFDUMP:
        print("FAIL: no dwarfdump / llvm-dwarfdump on PATH. This gate reads DWARF")
        print("      inline records; without them it cannot see per-site erases.")
        print("      Install llvm (Debian: the llvm-16 package) or set DWARFDUMP.")
        return 1

    sites = ground_truth()
    if not sites:
        print("FAIL: parsed zero Zeroizing declarations -- the source parser is broken.")
        return 1

    # expected: (tu, func) -> count
    expected = {}
    for tu, func, var, line, typ in sites:
        expected.setdefault((tu, func), []).append((var, line, typ))

    print("=== per-site Zeroizing destructor check (spec 8.3) ===")
    print(f"  CXX      = {CXX}")
    print(f"  flags    = {' '.join(CXXFLAGS)}")
    print("  method   = DWARF inlined-subroutine instances, real build flags")
    print()

    status = 0
    grand_exp = grand_obs = 0

    with tempfile.TemporaryDirectory() as td:
        for tu in TUS:
            obj = os.path.join(td, os.path.basename(tu) + ".o")
            objg = os.path.join(td, os.path.basename(tu) + ".g.o")
            base = [CXX] + CXXFLAGS + CPPFLAGS + ["-c", os.path.join(REPO, tu)]
            r = subprocess.run(base + ["-o", obj], capture_output=True, text=True)
            if r.returncode:
                print(f"FAIL: could not build {tu}\n{r.stderr}")
                return 1
            r = subprocess.run(base + ["-g", "-o", objg], capture_output=True, text=True)
            if r.returncode:
                print(f"FAIL: could not build {tu} with -g\n{r.stderr}")
                return 1

            # -g must not change codegen, or the thing measured is not the thing shipped.
            t1 = subprocess.run([OBJDUMP, "-d", "--no-show-raw-insn", obj],
                                capture_output=True, text=True).stdout
            t2 = subprocess.run([OBJDUMP, "-d", "--no-show-raw-insn", objg],
                                capture_output=True, text=True).stdout
            strip = lambda s: re.sub(r"^.*file format.*$", "", s, flags=re.M).strip()
            if strip(t1) != strip(t2):
                print(f"FAIL: adding -g changed codegen for {tu}.")
                print("      The DWARF-based site check would then describe a different")
                print("      binary than the one shipped. Investigate before trusting it.")
                status = 1

            events, instances, dtor_bodies = parse_dwarf(objg)

            # every out-of-line destructor body must actually zero
            for mangled in sorted(dtor_bodies):
                if not dtor_body_zeroes(objg, mangled):
                    d = demangle([mangled]).get(mangled, mangled)
                    print(f"FAIL [{tu}]: out-of-line {d} contains no zeroing store.")
                    status = 1

            obs = {}
            for owner, dtor in events:
                obs[owner] = obs.get(owner, 0) + 1

            print(f"--- {tu} ---")
            print(f"  {'function':<26} {'inst':>4} {'wraps':>6} {'erase':>6} {'per-inst':>9}  verdict")
            for (etu, func), vars_ in sorted(expected.items(), key=lambda k: str(k[0])):
                if etu != tu:
                    continue
                if func is None:
                    print(f"  FAIL: wraps at {[v[1] for v in vars_]} have no enclosing function")
                    status = 1
                    continue
                # match DWARF identity by mangled-name substring on the function name
                cands = [n for n in instances
                         if re.search(r"\d+" + re.escape(func) + r"[EI]", n)
                         or n == func]
                ninst = max((instances[n] for n in cands), default=0)
                nexp = len(vars_)
                cand_ev = 0
                for owner, dtor in events:
                    if owner and (re.search(r"\d+" + re.escape(func) + r"[EI]", owner)
                                  or owner == func):
                        cand_ev += 1
                grand_exp += nexp
                grand_obs += cand_ev
                if ninst == 0:
                    print(f"  {func:<26} {'-':>4} {nexp:>6} {cand_ev:>6} {'-':>9}  "
                          f"FAIL: function not emitted")
                    status = 1
                    continue
                per = cand_ev / ninst
                ok = abs(per - nexp) < 1e-9
                verdict = "ok" if ok else "FAIL"
                if not ok:
                    status = 1
                print(f"  {func:<26} {ninst:>4} {nexp:>6} {cand_ev:>6} {per:>9.2f}  {verdict}")
                if not ok:
                    deficit = nexp - per
                    print(f"      -> {deficit:.2f} erase events MISSING per instance "
                          f"({nexp} wraps declared, {per:.2f} erased).")
                    byt = {}
                    for owner, dtor in events:
                        if owner and re.search(r"\d+" + re.escape(func) + r"[EI]", owner):
                            byt[dtor] = byt.get(dtor, 0) + 1
                    per_inst = {k: v / ninst for k, v in byt.items()}
                    missing = name_missing_sites(vars_, per_inst)
                    if missing:
                        print(f"      -> wrap(s) with NO destructor erase in the emitted code:")
                        for var, line, typ in missing:
                            print(f"           {tu}:{line}  {var:<10} Zeroizing<{typ}>")
                    else:
                        print(f"      -> could not pin the missing wrap to a single "
                              f"declaration; all wraps in {func}:")
                        for var, line, typ in vars_:
                            print(f"           {tu}:{line}  {var:<10} Zeroizing<{typ}>")
                    dm = demangle(list(byt))
                    print(f"      -> erase events found, by type:")
                    for k, v in sorted(byt.items()):
                        print(f"           {v / ninst:g} x {dm.get(k, k)}")
            print()

    print(f"  total declared wraps        : {grand_exp}")
    print(f"  total erase events observed : {grand_obs}  "
          f"(includes duplicated inline copies)")
    print()
    if status == 0:
        print("audit-zeroize-sites: PASS -- every declared Zeroizing wrap has a")
        print("                     destructor erase in the emitted code.")
    else:
        print("audit-zeroize-sites: FAIL")
    return status


if __name__ == "__main__":
    sys.exit(main())
