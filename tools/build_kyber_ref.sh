#!/bin/sh
# Rebuild the pq-crystals/kyber AVX2 comparison library, OUTSIDE this repository.
#
# BENCHMARK-ONLY USE. Nothing from pq-crystals is vendored or copied into this tree by
# this script (ADR-003, ADR-022); only the already-vendored FIPS 202 files under
# third_party/fips202/ come from that project, recorded in ADR-015. The clone and every
# object produced here live under /tmp and are never committed.
#
# WHY IT IS SCRIPTED. The head-to-head number in ADR-030 is only meaningful if the
# comparison build is reproducible: same pinned commit, same compiler, same flags, same
# machine. A number produced by a build nobody can recreate is an anecdote.
#
# Usage:  sh tools/build_kyber_ref.sh          -> /tmp/libkyber768.a
set -e

PIN=3edd5af5991927164edd4aacebfcbee00b8064e7      # identical to ADR-015's vendoring pin
SRC=${KYBER_SRC:-/tmp/kyber-ref}
OUT=${KYBER_LIB:-/tmp/libkyber768.a}

echo "  pin    : $PIN"
echo "  source : $SRC   (outside the repo, never committed)"
echo "  output : $OUT"

rm -rf "$SRC"; mkdir -p "$SRC"; cd "$SRC"
git init -q .
git remote add origin https://github.com/pq-crystals/kyber.git
git fetch -q --depth 1 origin "$PIN"
git checkout -q FETCH_HEAD
[ "$(git rev-parse HEAD)" = "$PIN" ] || { echo "  PIN MISMATCH"; exit 1; }

cd "$SRC/avx2"
# KYBER_K=3 is ML-KEM-768. -march=native matches how this project benchmarks itself.
CF="-O3 -fomit-frame-pointer -mavx2 -mbmi2 -mpopcnt -maes -march=native -mtune=native -DKYBER_K=3 -I. -Ikeccak4x"
rm -f "$SRC"/obj_*.o
for f in kem.c indcpa.c polyvec.c poly.c fq.S shuffle.S ntt.S invntt.S basemul.S \
         consts.c rejsample.c cbd.c verify.c symmetric-shake.c fips202.c fips202x4.c \
         keccak4x/KeccakP-1600-times4-SIMD256.c randombytes.c; do
    [ -f "$f" ] || { echo "  MISSING $f -- upstream layout changed at this pin?"; exit 1; }
    o="$SRC/obj_$(echo "$f" | tr '/.' '__').o"
    clang $CF -c "$f" -o "$o"
done
rm -f "$OUT"
ar rcs "$OUT" "$SRC"/obj_*.o
echo "  built $(ls -l "$OUT" | awk '{print $5}') bytes"
echo "  symbols: $(nm "$OUT" | grep -c 'T _pqcrystals_kyber768_avx2')"
