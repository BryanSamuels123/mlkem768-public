#!/bin/sh
# Spec §8.3: verify secure_zero is not elided BY DISASSEMBLY, not by inspection.
#
# This measures BYTE COVERAGE, not an instruction count. Counting instructions was a
# proxy and it could not tell a COMPLETE erase from a PARTIAL one: at -O3 a 64-byte
# erase is `xorps` plus four 16-byte stores, and a 48-byte erase is `xorps` plus three
# -- both clear any "materially more than the eliminated control" bar, but only one of
# them satisfies FIPS 203 §3.3. The gate now requires the widths of the zero stores to
# sum to the WHOLE buffer. tools/zeroize_width.py does the summing, and counts only
# stores whose source is provably zero -- on macOS the stack protector emits a real
# `movq %rax, -0x8(%rbp)` into this same function, which a naive count credited to the
# erase.
#
# std::memset on a buffer never read again is dead-store-elimination bait. Measured on
# this host at -O3: the memset body compiles to a bare `ret` -- the erase is COMPLETELY
# GONE. secure_zero emits the stores. That contrast is the whole point, so the memset
# case is kept as a NEGATIVE CONTROL: if it ever stops being eliminated, this gate is no
# longer demonstrating anything and says so.
#
# Per `docs/reference/invariants.md` (testing philosophy): a planted control that the compiler removed proves nothing, so
# both directions are checked at the build's real optimization level.

set -e

CXX_="${CXX:-clang++}"
OBJDUMP="${OBJDUMP:-objdump}"
SRC="$(mktemp -t zeroaudit.XXXXXX).cpp"
OBJ="${SRC%.cpp}.o"

cat > "$SRC" <<'EOF'
#include "zeroize.hpp"
#include <array>
#include <cstdint>
#include <cstring>
extern "C" void audit_secure_zero() {
  std::array<std::uint8_t, 64> k{};
  k.fill(0xAB);
  mlkem768::secure_zero(k.data(), k.size());
}
extern "C" void audit_plain_memset() {
  std::array<std::uint8_t, 64> k{};
  k.fill(0xAB);
  std::memset(k.data(), 0, k.size());
}
EOF

"$CXX_" -std=c++20 -O3 -Isrc -c "$SRC" -o "$OBJ"

# BUFBYTES must match the array size in the probe above.
BUFBYTES=64
HERE="$(dirname "$0")"

width_of() {
    python3 "$HERE/zeroize_width.py" "$OBJ" "$1" "$OBJDUMP" | awk '{print $1}'
}
notes_of() {
    python3 "$HERE/zeroize_width.py" "$OBJ" "$1" "$OBJDUMP" | cut -d' ' -f2-
}

secure="$(width_of audit_secure_zero)"
secure_notes="$(notes_of audit_secure_zero)"
memset_="$(width_of audit_plain_memset)"
rm -f "$SRC" "$OBJ"

echo "=== zeroize audit (spec §8.3: verify by disassembly) ==="
echo "  buffer under test -> $BUFBYTES bytes"
echo "  secure_zero      -> $secure bytes actually zeroed  ($secure_notes)"
echo "  plain memset     -> $memset_ bytes actually zeroed  (negative control)"
echo ""

status=0

# EXACT COVERAGE, not a threshold. The erase must cover the whole buffer: a partial
# erase leaves secret bytes live and is exactly what an instruction count cannot see.
if [ "$secure" -lt 0 ]; then
    echo "FAIL: could not locate audit_secure_zero in the object."
    status=1
elif [ "$secure" -eq 0 ]; then
    echo "FAIL: secure_zero zeroed 0 of $BUFBYTES bytes -- the erase was eliminated"
    echo "      entirely at -O3. FIPS 203 §3.3 requires that intermediate secret data"
    echo "      is actually destroyed. secure_zero's survival rests on the asm barrier,"
    echo "      not on volatile -- check the barrier is present and clobbers \"memory\"."
    status=1
elif [ "$secure" -ne "$BUFBYTES" ]; then
    echo "FAIL: secure_zero zeroed $secure of $BUFBYTES bytes -- the erase is PARTIAL."
    echo "      Some of the buffer keeps its secret contents. This is the failure an"
    echo "      instruction count could not see: fewer, or narrower, stores still look"
    echo "      like 'more than the eliminated control'."
    status=1
fi

# The negative control is now sharper too: with byte coverage, "eliminated" means
# exactly zero bytes zeroed, not merely "fewer instructions than secure_zero".
if [ "$memset_" -ne 0 ]; then
    echo "NOTE: the plain-memset negative control was NOT eliminated on this"
    echo "      toolchain ($memset_ bytes still zeroed). The gate still passes, but it"
    echo "      is no longer demonstrating the contrast it exists to demonstrate --"
    echo "      re-check that secure_zero's survival is due to its construction."
fi

[ "$status" -eq 0 ] && echo "audit-zeroize: PASS" || echo "audit-zeroize: FAIL"
exit "$status"
