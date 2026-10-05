#!/bin/sh
# Every ADR-nnn referenced anywhere must resolve to a "### ADR-nnn" header in
# DECISIONS.md.
#
# WHY THIS IS A GATE. ADR-015 and ADR-016 were cited by the project documentation, source
# comments and two commit messages for TWO PHASES before they existed: a scripted edit
# targeted a placeholder that was not there, replace() matched nothing, and it printed
# success. Nothing noticed, because nothing was looking.
#
# WHAT THIS DOES NOT CATCH. Only DANGLING references -- a citation with no ADR behind
# it. It cannot tell whether an ADR that DOES exist still says what the citing text
# claims. Stale-but-resolving prose is held by the rewrite-don't-append rule in
# `docs/reference/invariants.md` (testing philosophy), not by this tool. Do not mistake a green audit-refs for "the
# documentation is accurate".
#
# POSITIVE CONTROL: --selftest plants a dangling reference in a scratch tree and
# requires the detector to find it (`docs/reference/invariants.md` (testing philosophy)).

set -e

ROOT="${ROOT:-.}"
DECISIONS="$ROOT/DECISIONS.md"

# Files that may cite an ADR. Deliberately excludes build output and vendored code.
scan_files() {
    find "$1" \
        \( -path '*/.git' -o -path '*/build' -o -path '*/third_party' \
           -o -path '*/tests/kat/vectors' -o -name '*.pdf' \) -prune -o \
        -type f \( -name '*.md' -o -name '*.cpp' -o -name '*.hpp' -o -name '*.h' \
                   -o -name '*.sh' -o -name '*.py' -o -name 'Makefile' \) -print
}

collect_refs() {
    scan_files "$1" | xargs grep -ho 'ADR-[0-9][0-9][0-9]' 2>/dev/null | sort -u
}

if [ "$1" = "--selftest" ]; then
    tmp="$(mktemp -d)"
    mkdir -p "$tmp"
    printf '### ADR-001: real\n' > "$tmp/DECISIONS.md"
    # Built from parts: if the literal appeared in this file, the real audit below
    # would scan this script and flag its own test fixture.
    printf 'This cites ADR-001 and also %s-%s which does not exist.\n' "ADR" "997" \
        > "$tmp/note.md"
    dangling=0
    for ref in $(collect_refs "$tmp"); do
        grep -q "^### $ref" "$tmp/DECISIONS.md" || dangling=$((dangling + 1))
    done
    rm -rf "$tmp"
    if [ "$dangling" -lt 1 ]; then
        echo "FAIL: the detector found 0 dangling references in a tree that contains"
        echo "      a deliberate one. The audit is blind."
        exit 1
    fi
    echo "  positive control: detector found $dangling dangling reference(s)  [OK]"
    exit 0
fi

echo "=== ADR reference audit (ADR-019) ==="

# Run the control first: a detector that cannot detect is worse than none.
sh "$0" --selftest || exit 1
echo ""

[ -f "$DECISIONS" ] || { echo "FAIL: $DECISIONS not found"; exit 1; }

status=0
total=0
for ref in $(collect_refs "$ROOT"); do
    total=$((total + 1))
    if ! grep -q "^### $ref" "$DECISIONS"; then
        echo "  $ref  *** DANGLING -- referenced but no '### $ref' in DECISIONS.md ***"
        echo "        cited by:"
        scan_files "$ROOT" | xargs grep -ln "$ref" 2>/dev/null | sed 's/^/          /'
        status=1
    fi
done

echo "  $total distinct ADR references checked"

# Also flag ADRs that exist but are cited nowhere -- not a failure, just noise worth
# seeing, since an uncited ADR is often one that was superseded without being marked.
uncited=""
for hdr in $(grep -o '^### ADR-[0-9][0-9][0-9]' "$DECISIONS" | sed 's/^### //' | sort -u); do
    n="$(collect_refs "$ROOT" | grep -c "^$hdr$" || true)"
    [ "$n" -eq 0 ] && uncited="$uncited $hdr"
done
[ -n "$uncited" ] && echo "  note: defined but never cited outside DECISIONS.md:$uncited"

echo ""
if [ "$status" -eq 0 ]; then
    echo "audit-refs: PASS  (dangling references only -- stale prose is NOT checked;"
    echo "                   see the rewrite-don't-append rule in docs/reference/invariants.md (testing philosophy))"
else
    echo "audit-refs: FAIL"
fi
exit "$status"
