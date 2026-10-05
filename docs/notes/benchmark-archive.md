# Benchmark archive — superseded records

*Moved out of the rolling state file in the Phase 9 close-out prune (2026-09-29). These are the
historical figures, kept because a later session may need to see how the ladder moved, not
because they describe the current code.*

**The CURRENT figures are the release measurements in `docs/SUMMARY.md` (performance), with
the head-to-head against pq-crystals in `DECISIONS.md` ADR-030.** If anything here disagrees
with those, those win.

Contents: the post-8e record and its head-to-head, component breakdown and interop; the
pre-8e ladder, head-to-head and interop; and the Phase 8a "does hashing actually dominate?"
analysis that set the optimization order.

**Host caveat that applies to every figure here:** `rdtsc` on this machine is a
constant-rate reference clock, not a retired-instruction counter, and it does not track
turbo. Treat all numbers as ratios on one machine, never as portable cycle counts.

---

### POST-8e RECORD (2026-09-28) — superseded by the post-9a and release figures

**Ladder extended with an 8e stage**, 24 rounds per stage, all six in one run:

| stage | KeyGen | Encaps | Decaps |
|---|---|---|---|
| kat-clean `76b6c13` | 110 100 | 120 386 | 147 062 |
| end 8a | 77 701 | 86 840 | 112 744 |
| end 8b | 58 995 | 65 684 | 78 704 |
| end 8c | 53 931 | 60 554 | 71 170 |
| end 8d | 46 314 | 50 353 | 58 739 |
| **end 8e `6395fef`** | **39 557** | **41 262** | **47 701** |

| per-stage | KeyGen | Encaps | Decaps |
|---|---|---|---|
| 8a 4-way Keccak | 1.417x | 1.386x | 1.304x |
| 8b AVX2 NTT | 1.317x | 1.322x | 1.433x |
| 8c lazy reduction | 1.094x | 1.085x | 1.106x |
| 8d SIMD sampling/compress | 1.164x | 1.203x | 1.212x |
| 8e basemul + decompress | 1.171x | 1.220x | 1.231x |
| **cumulative kat-clean -> 8e** | **2.783x** | **2.918x** | **3.083x** |

**RUN-TO-RUN VARIANCE IS REAL — do not quote three digits.** Stages shared with the
pre-8e run moved: 8d read 1.090/1.042/1.100 there and 1.164/1.203/1.212 here, from the
**same static binaries**. Cumulative kat-clean -> 8d was 2.186x then and 2.377x now, ~9%
apart. The `H()` sanity control — byte-identical code in every stage — read 0.955x in the
pre-8e run and 0.992x here. **Treat per-stage figures as ±5–9% and the cumulative as
"roughly 2.8–3.1x".**

### POST-8e — head-to-head vs pq-crystals AVX2

| operation | ours | pq-crystals | ratio | pre-8e | criterion |
|---|---|---|---|---|---|
| KeyGen | 40 445 | 26 273 | **1.53x** | 1.81x | <=1.5x — miss, but close |
| Encaps | 42 891 | 26 990 | **1.60x** | 1.92x | miss |
| Decaps | 48 782 | 30 828 | **1.60x** | 2.03x | miss |

**Still does not meet spec §1 criterion 4 (ADR-030)**; 8e closed roughly half the gap.

### POST-8e — component breakdown

| component | ours | kyber | ratio | pre-8e ratio |
|---|---|---|---|---|
| **basemul 1 poly** | 202.7 | 55.1 | **3.68x** | 16.48x |
| **matvec k=3** | 495.5 | 190.7 | **2.60x** | 14.66x |
| **decompress du** | 337.3 | 98.4 | **3.43x** | 13.59x |
| compress du | 1345.3 | 272.9 | 4.93x | 4.79x |
| polyvec_tobytes | 537.6 | 130.4 | 4.12x | 3.73x |
| invntt | 315.3 | 178.9 | 1.76x | 2.12x |
| CBD eta=2 | 53.3 | 30.5 | 1.75x | 1.75x |
| ntt | 213.7 | 161.8 | 1.32x | 1.29x |
| gen_matrix (9) | 14 970 | 11 562 | 1.29x | 1.23x |

**The three 8e targets moved from 13–16x down to 2.6–3.7x.** Largest remaining absolute
deltas: `gen_matrix` (+3408), `compress_du` (+1072), `polyvec_tobytes` (+407) — plus
`secure_zero` at ~3012 ticks per KeyGen, which is **deliberate** FIPS 203 §3.3 compliance
that pq-crystals does not do at all.

### POST-8e — interop unchanged

10 000/10 000 both directions, plus bit-identical keypairs and ciphertexts from identical
seeds. `gmake interop`.

---

### PRE-8e RECORD — directly measured ladder, kat-clean → HEAD (2026-09-28)

**This replaces every composed per-step ratio.** Five worktrees built at the stage
boundaries and measured in ONE interleaved run, 28 rounds per stage, alternating order
both ways. `35c9fb0` is HEAD at the time of measurement.

| stage | commit | KeyGen | Encaps | Decaps |
|---|---|---|---|---|
| kat-clean | `76b6c13` | 108 641 | 123 971 | 147 366 |
| end 8a — 4-way Keccak | `0a598e4` | 76 946 | 87 337 | 112 492 |
| end 8b — AVX2 NTT | `8fe4c94` | 58 944 | 65 409 | 78 034 |
| end 8c — lazy reduction | `6fadc70` | 54 195 | 59 662 | 70 252 |
| HEAD 8d — SIMD sampling/compress | `35c9fb0` | 49 705 | 57 253 | 63 852 |

| per-stage speedup | KeyGen | Encaps | Decaps |
|---|---|---|---|
| 8a 4-way Keccak | 1.412× | 1.419× | 1.310× |
| 8b AVX2 NTT | 1.305× | 1.335× | 1.442× |
| 8c lazy reduction | 1.088× | 1.096× | 1.111× |
| 8d SIMD sampling/compress | 1.090× | 1.042× | 1.100× |
| **cumulative kat-clean → HEAD** | **2.186×** | **2.165×** | **2.308×** |

**SANITY CONTROL, and it moved.** Scalar `H()` is byte-identical code in all five stages
and read **0.955×** cumulative — later binaries measure ~4.5 % slower on identical code,
most likely code layout / I-cache as the library grew. So read the cumulative figures as
**~2.2× with ±4.5 % systematic uncertainty**; if the drift is uniform the true values are
slightly *higher*, not lower. Do not quote three significant figures.

### PRE-8e RECORD — head-to-head vs pq-crystals AVX2 (2026-09-28)

Spec §1 success criterion 4, measured for the first time. Their code built **outside this
repo** at ADR-015's pin `3edd5af5`, same compiler, same flags, same machine; **both
implementations linked into ONE process** and measured interleaved (comparing two
projects' own speed-test binaries would compare harnesses, not implementations);
deterministic entry points on both sides (`*_derand` / `*_internal`), so OS RNG cost skews
neither. 16 rounds.

| operation | ours | pq-crystals | ratio | criterion |
|---|---|---|---|---|
| KeyGen | 46 278 | 25 643 | **1.81×** | ≤ 1.5× — **MISS** |
| Encaps | 50 840 | 26 438 | **1.92×** | ≤ 1.5× — **MISS** |
| Decaps | 60 210 | 29 453 | **2.03×** | ≤ 1.5× — **MISS** |

**We do not meet spec §1 criterion 4.** Logged as **ADR-030**; the criterion is not
revised to fit the result.

### PRE-8e RECORD — cross-implementation interop (spec §10.5, 2026-09-28)

Never done in Phase 7. 10⁴ iterations each direction, both implementations in one process.

| check | result |
|---|---|
| ours encaps → pq-crystals decaps | **10 000 / 10 000** shared secrets match |
| pq-crystals enc → ours decaps | **10 000 / 10 000** |
| *bonus:* identical keypair from identical seeds | **10 000 / 10 000** |
| *bonus:* identical ciphertext from identical `m` | **10 000 / 10 000** |

Bit-identical to an independent implementation, not merely interoperable. This is the one
test that catches a serialization bug two self-consistent implementations could share, or
one the ACVP vectors happen not to exercise.

---


Whole-operation TSC ticks. **A = Phase 7 baseline (`76b6c13`, built in a `git worktree`),
B = Phase 8a forced portable, C = Phase 8a on AVX2 — median of 21 INTERLEAVED triples.**

| Operation | A baseline | B portable | C AVX2 | speedup (A/C) | Date |
|---|---|---|---|---|---|
| keygen | 110 869 | 110 800 | **83 124** | 1.41× | 2026-09-22 |
| encaps | 130 573 | 117 840 | **90 856** | 1.38× | 2026-09-22 |
| decaps | 159 763 | 144 510 | **115 193** | 1.32× | 2026-09-22 |

**Measurement rule for this host.** Per-run ratios between the same two binaries spanned
**1.04×–1.71×**; a "before" from an earlier session compared against a later "after" is
*misleading*, not merely noisy. Build the old revision in a worktree, alternate the
binaries, median the per-pair ratios over ≥20 pairs, and include a sanity control timing
identical code in both trees. Full method: ADR-023, and `docs/notes/08a-batched-keccak.md` §5.

Component measurements below (`gmake bench`) are the PRE-8a scalar figures that drove
ADR-017; they have not been re-taken.

### Does hashing actually dominate? (spec §9.2) — all three operations

§9.2 asserts batched Keccak outranks NTT tuning. Measured rather than assumed.
**TSC ticks, not core cycles** (see the caveat above); the ratios are scale-free and are
the result. `gmake bench`.

| Primitive | median (ticks) |
|---|---|
| Keccak-f[1600] permutation | ~1 270 |
| `ntt()` | ~4 570 |
| `invntt()` | ~4 180 |
| `poly_basemul()` | ~1 094 |
| `PRF<2>` (33 → 128 B) | ~1 620 |
| XOF absorb + 504 B squeeze | ~5 140 |

One Keccak permutation ≈ **0.28 `ntt()`**.

Operation counts taken from `docs/algorithms/`, not guessed. Amdahl columns compare a
perfect 4× batched Keccak against a 3× faster NTT. Stable across five runs:

| Operation | hash % | hash/arith | 4× Keccak | 3× NTT | winner |
|---|---|---|---|---|---|
| KeyGen | 58–62 % | 1.34–1.66× | **1.75–1.88×** | 1.33–1.40× | Keccak |
| Encaps, `Â` re-expanded | 53–64 % | 1.13–1.77× | **1.66–1.92×** | ~1.32× | Keccak |
| **Encaps, `Â` CACHED** | **33–37 %** | **0.49–0.58×** | 1.33–1.38× | **~1.81×** | **NTT** |
| Decaps | 50–54 % | 1.01–1.18× | **1.60–1.69×** | 1.44–1.50× | Keccak *(marginal)* |

**Finding: one-shot and batch want DIFFERENT optimization orders.**

- For KeyGen, one-shot Encaps, and Decaps, **§9.2's ordering holds** — batched Keccak is
  the larger win. This is now evidence, not assertion.
- **Caching `Â` inverts it.** Removing the 9 SampleNTT streams drops hashing from ~60 % to
  ~34 %, and the NTT becomes the thing worth optimizing by a clear margin (1.81× vs
  1.33×). `batch::encaps` against a *single* `ek` (spec §9.3, §9.2 item 6) is exactly this
  case, and FIPS 203 §3.3 explicitly permits the caching.
- **Decaps is marginal**: 1.61× vs 1.49×. Do not treat it as strong support either way.

Two qualifiers, pulling opposite directions, both of which must be stated:

1. The Phase 2 NTT is **deliberately unoptimized** — a `barrett_reduce` after every
   butterfly, no lazy reduction. That inflates the arithmetic side, so the "NTT first"
   verdict for the cached case is partly self-fulfilling: a slow component has more
   headroom. It is still the correct *operational* conclusion today.
2. Conversely the vendored Keccak is already the tuned scalar reference, so it has less
   headroom left than the NTT does — which pushes the other way.

**Action for Phase 8:** keep §9.2's order (batched Keccak first) as the default, because
it wins for three of the four cases. But **re-measure after the NTT is optimized**, and if
the batch API is a priority, evaluate the cached-`Â` path on its own terms rather than
inheriting the one-shot ordering.

**Batch threading crossover:** *(not measured — Phase 10)*

---
