# Invariants — the things you must not get wrong

**Read this before changing anything in `src/`.** It is the condensed set of properties the
implementation depends on, the ones where a plausible-looking change silently breaks
correctness or security without failing an obvious test.

Rationale for each decision is in `DECISIONS.md`, by ADR number. Per-phase measurements are
in `docs/notes/`. A plain-language tour of the whole project is `docs/SUMMARY.md`.

---

## The normative reference

**FIPS 203 is the authority.** Where anything else disagrees, FIPS 203 wins, and the
discrepancy is recorded in `DECISIONS.md` → *Spec corrections*.

**Round-3 CRYSTALS-Kyber is NOT ML-KEM.** Most material published before mid-2024 —
including the designers' own code and papers of that era — describes Kyber. Three
differences silently break the official test vectors while leaving an implementation
perfectly self-consistent:

1. ML-KEM appends the byte `k` to the seed: `(ρ, σ) ← G(d ‖ k)`, with **`k = 3`** for
   ML-KEM-768. Kyber does not.
2. ML-KEM does **not** hash the message first. There is no `m ← H(m)`.
3. ML-KEM does **not** apply a final key-derivation step. `K` comes straight out of
   `G(m ‖ H(ek))`.

Check any reference against these three before trusting it.

The algorithms themselves were extracted once into `docs/algorithms/`, one file per
algorithm, with the pseudocode verbatim. **Read those rather than re-deriving from the
standard**; if a note is wrong, fix the note and log the correction in `DECISIONS.md`.

---

## Parameters (ML-KEM-768)

```
n = 256   q = 3329   ζ = 17   k = 3   η1 = η2 = 2   du = 10   dv = 4
ek = 1184   dk = 2400   ct = 1088   ss = 32   seed(d‖z) = 64
dk_PKE = 1152   ek_PKE = 1184
decapsulation failure rate = 2^-164.8
```

**No `#define`.** These live in the `constexpr` namespace in `src/params.hpp`, which
re-derives them from `n`, `q` and `k` and `static_assert`s the results, so a wrong edit is a
compile error rather than a runtime surprise.

---

## Montgomery domain convention — full table in `docs/reference/montgomery.md`

`R = 2^16`; `ntt` is normal→normal; `poly_basemul` emits `×R⁻¹`; `invntt` emits `×R`.

So **`invntt(poly_basemul(ntt a, ntt b)) == a·b` exactly**, and
**`invntt(ntt(f)) == f·R`, not `f`** — which looks like a bug and is not.

**Derive every constant with `consteval` + `static_assert`. Transcribe nothing.** Getting
the direction of the scaling factor backwards produces results wrong by a constant factor
that round-trip correctly and pass a great many tests. This is the single most dangerous
thing in the project to get wrong, and it has been mis-documented before.

---

## Coefficient bounds

`docs/bounds.md` is the authoritative invariant table. **Lazy reduction is only legal where
that table proves no `int16_t` overflow.** Any lazy-reduction change updates the table in
the same commit.

**Overflow in the NTT is silent and produces wrong-but-plausible output.** It is not
undefined behaviour, so no sanitizer catches it: `-fsanitize=implicit-integer-truncation`
sees *implicit* narrowing but is blind to the explicit `static_cast<int16_t>` the NTT
actually uses. The bounds table is the only thing protecting this.

---

## The decrypt path has no test-vector coverage — function-level exactness IS the gate

**Small errors anywhere on the decryption path are invisible to every known-answer test**,
by design. Along `decompress_du` → `ntt(u')` → `basemul` → `invntt` → `Compress_1`, the
final rounding to the nearer of 0 and q/2 absorbs small perturbations, the re-encryption
then reproduces a matching ciphertext, and the shared secret comes out correct. `gmake kat`
passes. Measured: a one-bit error planted in `decompress` left all 80 vectors green.

**Absorbed is not harmless.** Every such error spends part of decryption's noise margin, and
that margin is what holds the failure rate at 2^-164.8. Decapsulation failures are
themselves a known attack surface against this family of schemes, so silently eating margin
is a security regression that no functional test reports.

**Therefore, for every function on the decrypt path, exhaustive or differential verification
against the golden model is the ONLY correctness gate — not a supplement to `gmake kat`.** A
change there that is "KAT-clean" has not been tested at all. Only 5 of the 80 vectors
exercise a successful decapsulation.

---

## Constant-time rules

**Secret:** `d`, `z`, `σ`, `s`, `ŝ`, `e`, `e1`, `e2`, `y`, `m`, `m'`, `r`, `r'`, `K`, `K̄`,
all of `dk`, the seed, and the implicit-reject flag.

Forbidden on any of the above:

- Branches — `if`, a branching `?:`, short-circuit `&&`/`||`, secret-dependent loop bounds
- Memory addresses derived from secrets — table lookups, array indices
- Variable-latency instructions: integer `div` / `mod`
- `memcmp`, `std::equal`, `operator==` on arrays — use `ct_neq` / `ct_cmov`
- **Any floating-point operation** (forbidden outright by FIPS 203 §3.3)

Variable time is fine for anything depending only on public data: `ρ`, `ek`, `Â`, `c`.
`sample_ntt` is deliberately variable-time.

**`ρ` may be declassified in constant-time test builds only** (ADR-020). It is `G(d‖k)[0:32]`
and so inherits taint from the secret `d`, but FIPS 203 publishes it verbatim inside `ek`.
Declassifying it is correct, not a leak — but **`σ` is never declassified**, and any change
to the declassification boundary must be re-verified narrowly by ADR-020's method: plant a
real leak in the non-declassified path and confirm it is still caught.

**After adding any declassification, re-check every positive control that could have
depended on that value being tainted.** One such control did not fail when `ρ` was
declassified — it became *vacuous*, still passing while testing nothing, which is worse. It
was caught only because the control demanded a specific exit code rather than merely
"nonzero".

In `decaps`: compute `K̄ = J(z ‖ c)` **unconditionally**, select branchlessly, and destroy
the reject flag before returning. **Never return a distinguishable error for a well-sized
but invalid ciphertext** — see `docs/SUMMARY.md` §8 for why that would hand an attacker a
decryption oracle.

Compilers reintroduce branches at `-O3`. `ct_neq` needs a compiler barrier. `secure_zero`
must not be elidable — **verify by disassembly, not by inspection** (`gmake audit-zeroize`).

### What the tools can and cannot enforce — matrix in `docs/reference/ct-tooling.md`

**Three tools, three different blind spots; none is sufficient alone.** The
branch-and-address checker cannot see `div`/`mod`; `audit-div` sees every division at
machine level but not whether a divisor is secret; the statistical timing test needs
statistical power and has a measured floor of roughly 100 ticks per operation.

---

## Testing philosophy — the rule the code comments refer to

**Every check needs a positive control. Prove a gate can FAIL before trusting that it
passes.** Introduce the exact bug the check exists to catch, confirm it is caught, then
remove it. This is the highest-value habit in the project; four separate checks here were
discovered to be incapable of failing, every one of them found this way rather than by
inspection. `docs/SUMMARY.md` §4 tells those four stories.

Controls must check the **specific** failure signal — exit code *and* expected output —
never merely "nonzero".

**A planted control can pass its own check and still prove nothing** if the compiler removed
what was planted, if the plant is too *small* for the gate to resolve, or if the measuring
tool was never watching the code in question. All three have happened here. After planting,
confirm the artifact survives at the build's real optimization level, and ask what size of
fault the gate can actually detect.

**From the first commit that passed the official vectors onward, those vectors must pass at
the end of every change.** A change that breaks one is reverted, not debugged forward.

**Benchmarks, experiments and planted controls use `git worktree`** — never `git stash`,
never `git checkout` onto the working tree. A stash does not cover untracked files, so a
"clean" restore can silently keep new ones.

---

## Copying policy

**Read reference implementations for technique. Do not copy their source.** The hand-written
AVX2 code here is the deliverable.

The only third-party source in this repository is vendored FIPS 202 / Keccak and two
single-header test-only dependencies. Every vendored file has a row in `DECISIONS.md` →
*Third-party provenance*: upstream repo, commit hash, licence, local path, and local
modifications (which should always read "none"). **Never reformat a vendored file** — its
value is being byte-identical to an audited upstream. Licences are reproduced in full in
`THIRD_PARTY_NOTICES.txt`.

---

## Build environment

Use **`gmake`, not `make`.** macOS ships GNU Make 3.81, whose 1-second timestamp granularity
silently reuses stale object files — it produced a wrong-but-plausible result twice here. The
Makefile hard-errors under it. `brew install make`.

The environment this was developed and measured on:

| Tool | Version |
|---|---|
| c++ / clang++ | Apple clang 16.0.0 — C++20 verified by compile probe, not by version string |
| make | gmake 4.4.1 required; container has 4.3 |
| python3 | 3.14.3 |
| valgrind | **absent on macOS** — the constant-time checks run in the Linux container |

**CPU:** Intel Core i7-9750H @ 2.60 GHz (Coffee Lake-H), 6 physical / 12 logical cores,
32 GB RAM, 64-byte cache line, 32 KB L1d, 256 KB L2.
**SIMD:** AVX2, BMI2, FMA, AES — **no AVX-512** (consumer Coffee Lake has none), verified by
compiling *and running* a probe using `_mm256_mulhi_epi16` and `_pext_u64`.

This is an **x86-64** Mac, not Apple Silicon, so the AVX2 work is buildable here. Treat
`src/arch/avx512/` as untested-by-construction until it runs somewhere with AVX-512BW.

**The timestamp counter on this host is a constant-rate reference clock, not a
retired-instruction counter, and it does not track turbo.** Treat every timing figure as a
ratio on one machine, never as a portable cycle count. Benchmarks report medians and spread,
never best-of.

**Several checks cannot run on macOS and run in the Linux container instead** — the
constant-time checker, AddressSanitizer, MemorySanitizer and fuzzing. The host-side targets
fail loudly saying so rather than quietly doing nothing (ADR-008, ADR-011). The statistical
timing test is the reverse: **host only**, because a container here is a virtual machine and
would add a timing layer to the thing being measured (ADR-035).

---

## When a known-answer test fails

`docs/reference/kat-failure-checklist.md` lists ten causes in likelihood order. The top three
are the missing `‖k` domain separator in `G(d ‖ k)`, Kyber's transform instead of ML-KEM's,
and a transposed `Â`.

**But first ask whether a known-answer test can see your bug at all** — see the decrypt-path
section above. A change on the decryption path that leaves `gmake kat` green has not been
tested.
