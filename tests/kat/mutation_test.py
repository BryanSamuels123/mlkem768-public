#!/usr/bin/env python3
"""Mutation-test the ACVP KAT harness.

A gate that cannot fail is not a gate. This deliberately breaks the golden model in
seven specific, spec-relevant ways and asserts that `make kat-model` notices each one.

Any mutation that still reports PASS 80/80 means the harness is filtering rather than
comparing, or is not reaching that code path at all -- which is a more urgent finding
than anything downstream.

Each mutation is applied, measured, then reverted with `git checkout --`. The script
refuses to run against a dirty tree and verifies the tree is clean again at the end,
so it cannot silently leave a mutation behind.

Re-run this at Phase 7 against the real implementation by pointing SUT at the kat target.

Usage:  python3 tests/kat/mutation_test.py [--target kat-model]
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MAKE = "gmake"
KPKE = "tests/model/model_kpke.cpp"
POLY = "tests/model/model_poly.cpp"
MLKEM = "tests/model/model_mlkem.cpp"

# Each mutation: (id, title, spec reference, file, old, new)
# Source files, per tree. `gmake kat-model` links tests/model/; `gmake kat` links
# src/ via backend_impl.cpp and never touches the model. Mutating the wrong tree makes
# every mutation "survive" -- not because the gate is weak, but because the harness is
# aimed at code the binary does not contain.
IMPL_KPKE = "src/kpke.cpp"
IMPL_NTT = "src/ntt.cpp"
IMPL_POLY = "src/poly.cpp"
IMPL_KEM = "src/kem.cpp"

MUTATIONS = [
    (
        "M1", "Drop the domain separator in G(d || k)", "Alg. 13 line 1 / failure mode #1",
        KPKE,
        "  G(gout, gin, 33);",
        "  G(gout, gin, 32);   // MUTANT: omit the trailing k byte, as round-3 Kyber does",
    ),
    (
        "M2", "Swap i and j in the SampleNTT seed", "Alg. 13 line 5 / failure mode #3",
        KPKE,
        "      seed[32] = static_cast<std::uint8_t>(j);   // j FIRST\n"
        "      seed[33] = static_cast<std::uint8_t>(i);",
        "      seed[32] = static_cast<std::uint8_t>(i);   // MUTANT: transposed\n"
        "      seed[33] = static_cast<std::uint8_t>(j);",
    ),
    (
        "M3", "invntt final scale 3303 -> 3302", "Alg. 10 line 14 / failure mode #6",
        POLY,
        "  for (auto& c : f) c = static_cast<std::int32_t>((3303LL * c) % Q);",
        "  for (auto& c : f) c = static_cast<std::int32_t>((3302LL * c) % Q);  // MUTANT",
    ),
    (
        "M4", "Remove the transpose in u = NTT^-1(A^T o y_hat)", "Alg. 14 line 19 / failure mode #4",
        KPKE,
        "      acc = poly_add(acc, multiply_ntts(A[static_cast<std::size_t>(j)][static_cast<std::size_t>(i)],\n"
        "                                        y_hat[static_cast<std::size_t>(j)]));",
        "      acc = poly_add(acc, multiply_ntts(A[static_cast<std::size_t>(i)][static_cast<std::size_t>(j)],\n"
        "                                        y_hat[static_cast<std::size_t>(j)]));  // MUTANT: no transpose",
    ),
    (
        "M5", "Swap the N counter order in Encrypt (e1 sampled before y)", "Alg. 14 lines 9-16 / failure mode #5",
        KPKE,
        "  for (int i = 0; i < K; ++i) {                     // lines 9-12: y, with ETA1\n"
        "    y[static_cast<std::size_t>(i)] =\n"
        "        sample_poly_cbd(ETA1, PRF(ETA1, r, static_cast<std::uint8_t>(Ncount)));\n"
        "    ++Ncount;\n"
        "  }\n"
        "  for (int i = 0; i < K; ++i) {                     // lines 13-16: e1, with ETA2\n"
        "    e1[static_cast<std::size_t>(i)] =\n"
        "        sample_poly_cbd(ETA2, PRF(ETA2, r, static_cast<std::uint8_t>(Ncount)));\n"
        "    ++Ncount;\n"
        "  }",
        "  for (int i = 0; i < K; ++i) {                     // MUTANT: e1 first, N = 0,1,2\n"
        "    e1[static_cast<std::size_t>(i)] =\n"
        "        sample_poly_cbd(ETA2, PRF(ETA2, r, static_cast<std::uint8_t>(Ncount)));\n"
        "    ++Ncount;\n"
        "  }\n"
        "  for (int i = 0; i < K; ++i) {                     // MUTANT: y second, N = 3,4,5\n"
        "    y[static_cast<std::size_t>(i)] =\n"
        "        sample_poly_cbd(ETA1, PRF(ETA1, r, static_cast<std::uint8_t>(Ncount)));\n"
        "    ++Ncount;\n"
        "  }",
    ),
    (
        "M6", "Skip the implicit-rejection select; always return K'", "Alg. 18 lines 9-11 / failure mode #10",
        MLKEM,
        "  if (!equal) std::memcpy(K_prime, K_bar, 32);",
        "  (void)equal;  // MUTANT: never substitute K_bar; always return K'",
    ),
    (
        "M7", "Off-by-one in Compress_du rounding (+q/2 -> +q/2 - 1)", "(4.7) / failure mode #9",
        POLY,
        "  const std::int64_t num = (static_cast<std::int64_t>(x) << (d + 1)) + Q;",
        "  // MUTANT: du only. Doubled numerator, so +Q == +q/2; +Q-2 == +q/2 - 1.\n"
        "  const std::int64_t num = (static_cast<std::int64_t>(x) << (d + 1)) + ((d == 10) ? Q - 2 : Q);",
    ),
    # M1-M7 are the spec-directed set. None of them touches the §7.2/§7.3 input checks,
    # so both KeyCheck groups pass throughout -- which proves those groups RUN, not that
    # they BITE. M8 and M9 close that gap: without them, a harness that accepted every
    # key would look identical to a correct one.
    (
        "M8", "Encapsulation key check always passes (skip the modulus check)", "§7.2 (7.1)",
        MLKEM,
        "    if (std::memcmp(reencoded.data(), chunk, 384) != 0) return false;",
        "    (void)reencoded;  // MUTANT: never reject an out-of-range 12-bit field",
    ),
    (
        "M9", "Decapsulation key check always passes (skip the hash check)", "§7.3 (7.2)",
        MLKEM,
        "  return std::memcmp(test, dk + DK_PKE_BYTES + EK_BYTES, 32) == 0;",
        "  (void)test; return true;  // MUTANT: never reject a corrupted H(ek)",
    ),
]


# The same nine spec-relevant breaks, aimed at the REAL implementation. Kept parallel to
# MUTATIONS above so a divergence in detection between model and implementation is
# meaningful rather than an artefact of testing different things.
IMPL_MUTATIONS = [
    (
        "M1", "Drop the domain separator in G(d || k)", "Alg. 13 line 1 / failure mode #1",
        IMPL_KPKE,
        "  G(gout.value.data(), gin.value);",
        "  G(gout.value.data(), std::span<const std::uint8_t>(gin.value.data(), 32));  // MUTANT",
    ),
    (
        "M2", "Swap i and j in the SampleNTT seed", "Alg. 13 line 5 / failure mode #3",
        IMPL_KPKE,
        "      sd[32] = static_cast<std::uint8_t>(j);        // j FIRST\n"
        "      sd[33] = static_cast<std::uint8_t>(i);",
        "      sd[32] = static_cast<std::uint8_t>(i);        // MUTANT\n"
        "      sd[33] = static_cast<std::uint8_t>(j);",
    ),
    (
        "M3", "invntt final scale 3303 -> 3302", "Alg. 10 line 14 / failure mode #6",
        IMPL_NTT,
        "c = barrett_reduce(mont_mul(c, kInvNttScale));",
        "c = barrett_reduce(mont_mul(c, static_cast<std::int16_t>(kInvNttScale - 1)));  // MUTANT",
    ),
    (
        "M4", "Remove the transpose in u = NTT^-1(A^T o y_hat)", "Alg. 14 line 19 / #4",
        IMPL_KPKE,
        "      poly_basemul_acc(acc, a[static_cast<std::size_t>(j)].v[static_cast<std::size_t>(i)],",
        "      poly_basemul_acc(acc, a[static_cast<std::size_t>(i)].v[static_cast<std::size_t>(j)],  // MUTANT",
    ),
    (
        "M5", "Swap the N counter order in Encrypt", "Alg. 14 lines 9-16 / #5",
        IMPL_KPKE,
        "                         r, 0, 1, 2, 7);",
        "                         r, 3, 4, 5, 7);  // MUTANT",
    ),
    (
        "M6", "Skip the implicit-rejection select", "Alg. 18 lines 9-11 / #10",
        IMPL_KEM,
        "  ct_cmov(std::span<std::uint8_t>(k_prime.value), std::span<const std::uint8_t>(k_bar.value),\n"
        "          mask);",
        "  (void)k_bar;  // MUTANT: never substitute K_bar",
    ),
    (
        "M7", "Off-by-one in Compress_du rounding", "(4.7) / failure mode #9",
        IMPL_POLY,
        "  const std::uint64_t n = (static_cast<std::uint64_t>(x) << (D + 1)) + params::Q;",
        "  const std::uint64_t n = (static_cast<std::uint64_t>(x) << (D + 1))\n"
        "                          + ((D == 10) ? params::Q - 2 : params::Q);  // MUTANT",
    ),
    (
        "M8", "Encapsulation key check always passes", "§7.2 (7.1)",
        IMPL_KEM,
        "    if (std::memcmp(re.data(), chunk, params::POLY_BYTES) != 0) return false;",
        "    (void)re;  // MUTANT: never reject an out-of-range field",
    ),
    (
        "M9", "Decapsulation key check always passes", "§7.3 (7.2)",
        IMPL_KEM,
        "  return std::memcmp(test.data(), dk + kHOff, 32) == 0;",
        "  (void)test; return true;  // MUTANT",
    ),
]


def mutations_for(target):
    """kat-model mutates the model; kat mutates the implementation."""
    return IMPL_MUTATIONS if target == "kat" else MUTATIONS


def sh(cmd, **kw):
    return subprocess.run(cmd, shell=True, cwd=ROOT, capture_output=True, text=True, **kw)


def tree_clean():
    return sh("git status --porcelain tests/model src").stdout.strip() == ""


def parse(output):
    """Extract per-group results and the verdict from harness output."""
    groups = {}
    for m in re.finditer(
        r"^\s+(\d+)\s+(AFT|VAL)\s+(\w+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$", output, re.M
    ):
        tg, tt, fn, cases, passed, failed = m.groups()
        groups[fn] = dict(tgId=int(tg), testType=tt, cases=int(cases),
                          passed=int(passed), failed=int(failed))
    verdict = "PASS" if re.search(r"^PASS \d+/\d+$", output, re.M) else "FAIL"
    total_pass = 0
    tm = re.search(r"TOTAL\s+(\d+)\s+(\d+)\s+(\d+)", output)
    if tm:
        total_pass = int(tm.group(2))
    build_failed = "error:" in output or "Error 1" in output and not groups
    return groups, verdict, total_pass, build_failed


def run_target(target):
    # DELETE the model objects and the harness binary before every build.
    #
    # Do NOT rely on mtimes here. GNU Make 3.81 (which macOS ships) compares
    # timestamps at 1-SECOND granularity. This script reverts one mutation and writes
    # the next into the same file within the same second, so make saw the object as
    # up to date and silently reused it -- mutation N ran mutation N-1's binary and
    # reported N-1's signature. Observed, not theorised: it made M2 look like a
    # keyGen-only failure when it actually breaks three groups.
    #
    # A missing prerequisite always forces a rebuild, so deletion is unconditional and
    # cannot be defeated by clock granularity. kat_main.o is left alone: it pulls in
    # nlohmann/json and is slow, and no model mutation can affect it.
    sh("rm -f build/tests/model/*.o build/tests/model/*.d "
       "build/tests/kat/backend_model.o build/kat_model")
    # gmake, not make: this host's `make` is 3.81 and the Makefile hard-errors under it,
    # which the script previously reported as "baseline does not pass".
    r = sh(f"{MAKE} {target} 2>&1")
    return r.stdout + r.stderr


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="kat-model")
    args = ap.parse_args()

    if not tree_clean():
        print("REFUSING TO RUN: the source tree is dirty. Commit or stash first.")
        return 2

    print(f"baseline: make {args.target}")
    base_groups, base_verdict, base_pass, _ = parse(run_target(args.target))
    if base_verdict != "PASS":
        print("REFUSING TO RUN: baseline does not pass. Fix that first.")
        return 2
    print(f"  baseline {base_verdict} {base_pass}/80\n")

    order = ["keyGen", "encapsulation", "decapsulation",
             "encapsulationKeyCheck", "decapsulationKeyCheck"]
    results = []

    for mid, title, ref, path, old, new in mutations_for(args.target):
        src = (ROOT / path).read_text()
        if old not in src:
            print(f"{mid}: ANCHOR NOT FOUND in {path} -- skipping")
            results.append((mid, title, ref, path, None, None, None, "ANCHOR NOT FOUND"))
            continue
        assert src.count(old) == 1, f"{mid}: anchor is not unique in {path}"
        (ROOT / path).write_text(src.replace(old, new))

        out = run_target(args.target)
        groups, verdict, total_pass, build_failed = parse(out)

        # The mutated TU must appear on a compile line, or we measured a stale binary.
        if f"-c {path}" not in out and not build_failed:
            print(f"{mid}: ERROR -- {path} was not recompiled; result would be stale")
            sh(f"git checkout -- {path}")
            return 2

        sh(f"git checkout -- {path}")
        assert tree_clean(), f"{mid}: failed to revert {path}"

        if build_failed and not groups:
            note = "BUILD FAILED"
        elif verdict == "PASS":
            note = "*** SURVIVED -- HARNESS DEFECT ***"
        else:
            note = "detected"

        per = {g: (groups.get(g, {}).get("failed", 0)) for g in order}
        results.append((mid, title, ref, path, verdict, total_pass, per, note))

        fails = ", ".join(f"{g}:{per[g]}" for g in order if per[g])
        print(f"{mid} {verdict:4s} {total_pass}/80  [{note}]  {fails or 'no group failed'}")

    if not tree_clean():
        print("\nERROR: tree is dirty after the run -- a mutation may have been left in.")
        return 2

    print("\nfinal tree clean; all mutations reverted")
    survivors = [r for r in results if r[7].startswith("***")]
    import json
    (ROOT / "tests/kat/.mutation_results.json").write_text(json.dumps(
        [dict(id=r[0], title=r[1], ref=r[2], file=r[3], verdict=r[4],
              total_pass=r[5], per_group=r[6], note=r[7]) for r in results], indent=2))
    return 1 if survivors else 0


if __name__ == "__main__":
    sys.exit(main())
