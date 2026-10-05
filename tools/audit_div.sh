#!/bin/sh
# Machine-level audit: no div/idiv instruction may appear in the shipped library.
#
# WHY THIS IS A GATE AND NOT A CODE REVIEW. Per ADR-016, ctgrind is PROVABLY BLIND to
# secret-dependent div/mod: valgrind models values, not timing. `docs/reference/invariants.md` bans the
# instruction and nothing else enforces it.
#
# Source-level enumeration is NOT sufficient. Phase 4 found a `divl` inside ntt() that
# appears nowhere in the source -- the compiler strength-reduced an inner-loop counter
# into `k += 255/(2*len)`. Only objdump saw it. Any audit that greps C++ will miss that
# entire class.
#
# POSITIVE CONTROL. The script first compiles a function that definitely divides and
# requires the detector to find it. Phase 4's first attempt used a \b pattern that BSD
# grep does not honour and silently reported 0 for everything, control included. A
# detector that cannot detect is worse than none.
#
# Known allowances are listed explicitly with a justification. An unlisted hit fails.

set -e

BUILD="${BUILD:-build}"
OBJDUMP="${OBJDUMP:-objdump}"
CC_PROBE="${CC:-clang}"

# Matches div/idiv with optional operand-size suffix, not preceded by a letter (so
# "divss", "vdivpd" and identifiers containing "div" do not match).
PATTERN='(^|[^a-z])i?div[lqwb]?[[:space:]]'

count_div() {
    "$OBJDUMP" -d "$1" 2>/dev/null | grep -cE "$PATTERN" || true
}

echo "=== div/idiv audit (ADR-016: no tool enforces the div ban; this one does) ==="

# --- positive control ------------------------------------------------------
tmp_c="$(mktemp -t auditdiv.XXXXXX).c"
tmp_o="${tmp_c%.c}.o"
printf 'int probe_div(int a, int b){ return a / b; }\n' > "$tmp_c"
"$CC_PROBE" -O3 -c "$tmp_c" -o "$tmp_o"
control="$(count_div "$tmp_o")"
rm -f "$tmp_c" "$tmp_o"

if [ "$control" -lt 1 ]; then
    echo "FAIL: the detector found 0 divisions in a function that is literally a/b."
    echo "      The audit is blind; every result below would be meaningless."
    echo "      (Phase 4 hit exactly this: a \\b pattern BSD grep ignores.)"
    exit 1
fi
echo "  positive control: detector found $control division(s) in a/b  [OK]"
echo ""

# --- the audit -------------------------------------------------------------
# NO ALLOWANCES. Every library object must contain zero div/idiv.
#
# Phase 4 through 8a carried one: clang emitted a `divl` in ntt.o computing the trip
# count 255/(2*len) for the layer loop, because `len` was a runtime variable. The
# divisor was the public layer width, so it was never a leak -- but an allowance is a
# standing invitation for a SECOND division to hide behind it, and checking that a
# given divisor is public requires tracing the disassembly by hand every time.
#
# Phase 8b made every layer width a template parameter, so the trip counts are
# compile-time constants and the division is gone. The allowance is removed rather
# than set to 0, so that ntt.o now falls through to the UNEXPECTED branch like every
# other object and any regression fails loudly instead of fitting inside a budget.

status=0
found_any=0
# Only this BUILD's library objects. Do NOT recurse: $BUILD/asan, $BUILD/ubsan etc.
# are separate sanitizer builds of the same sources and would be counted again.
OBJS="$(find "$BUILD/src" "$BUILD/third_party" -name '*.o' 2>/dev/null | sort || true)"

for obj in $OBJS; do
    n="$(count_div "$obj")"
    [ "$n" -eq 0 ] && continue
    found_any=1
    base="$(basename "$obj")"
    case "$base" in
        *)
            echo "  $base: $n  *** UNEXPECTED DIVISION ***"
            "$OBJDUMP" -d "$obj" | grep -E "$PATTERN" | sed 's/^/           /'
            echo "         If this divisor is provably public, add an explicit allowance"
            echo "         here AND a justification row in docs/bounds.md. Do not raise"
            echo "         the allowance without tracing the divisor in the disassembly."
            status=1
            ;;
    esac
done

[ "$found_any" -eq 0 ] && echo "  no div/idiv in any library object"

echo ""
if [ "$status" -eq 0 ]; then
    echo "audit-div: PASS"
else
    echo "audit-div: FAIL"
fi
exit "$status"
