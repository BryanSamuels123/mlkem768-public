# Phase 8: what the optimization work actually achieved

*Plain language, for someone studying this codebase later. The per-phase notes
(`08a`–`08e`) cover how each piece works; this one covers what it was worth.*

---

## 1. The headline

ML-KEM-768 got **roughly 2.8–3.1× faster** than the correctness-locked baseline, measured
directly rather than by multiplying together per-phase claims.

| stage | KeyGen | Encaps | Decaps |
|---|---|---|---|
| `kat-clean` (scalar, correctness locked) | 110 100 | 120 386 | 147 062 |
| 8a — 4-way batched Keccak | 77 701 | 86 840 | 112 744 |
| 8b — AVX2 NTT | 58 995 | 65 684 | 78 704 |
| 8c — lazy reduction | 53 931 | 60 554 | 71 170 |
| 8d — SIMD sampling / compression | 46 314 | 50 353 | 58 739 |
| 8e — AVX2 basemul + decompress | **39 557** | **41 262** | **47 701** |
| **cumulative** | **2.78×** | **2.92×** | **3.08×** |

TSC ticks on one Intel i7-9750H. **Do not quote three digits.** Re-running the same static
binaries moved the shared stages by ~9 %, and a sanity control that times *byte-identical
code in every stage* read 0.955× in one run and 0.992× in another. Treat per-stage figures
as ±5–9 %.

### Why this ladder exists at all

Every earlier figure in the project was a per-step ratio from a different session, and
ADR-023 had already shown those don't compose — its additive cross-check fell 19 % short
of in-situ measurement. So the ladder was re-measured from scratch: five (later six) git
worktrees at the stage boundaries, all built, all run interleaved in a single session with
the order alternated both ways. That is the number to trust.

---

## 2. Against a real reference implementation

Spec §1 criterion 4 asks for "within ~1.5× of a reference AVX2 implementation". Until the
Phase 8 close-out, **this had never been measured** — every figure was self-relative, this
repo against an earlier commit of itself, which cannot tell you whether the result is
competitive.

Measured against `pq-crystals/kyber` AVX2, built outside this repo at the same pinned
commit, same compiler, same flags, **both linked into one process** and interleaved:

| | pre-8e | post-8e | criterion |
|---|---|---|---|
| KeyGen | 1.81× | **1.53×** | ≤1.5× — **miss**, marginal |
| Encaps | 1.92× | **1.60×** | miss |
| Decaps | 2.03× | **1.60×** | miss |

**We do not meet criterion 4.** ADR-030 records that without revising the criterion to fit
the result. Phase 8e closed roughly half the original gap.

*(Comparing the two projects' own speed-test binaries would have compared harnesses, not
implementations — hence one process. Deterministic entry points on both sides keep OS RNG
cost out of it. A cross-project comparison cannot use this project's usual byte-identity
sanity control, because no code is identical to both sides; that limit is stated with the
number.)*

### Where the remaining gap is

| component | ours | kyber | ratio pre-8e | ratio post-8e |
|---|---|---|---|---|
| basemul, 1 poly | 202.7 | 55.1 | 16.48× | **3.68×** |
| matvec k=3 | 495.5 | 190.7 | 14.66× | **2.60×** |
| decompress du | 337.3 | 98.4 | 13.59× | **3.43×** |
| compress du | 1345.3 | 272.9 | 4.79× | 4.93× |
| polyvec_tobytes | 537.6 | 130.4 | 3.73× | 4.12× |
| invntt | 315.3 | 178.9 | 2.12× | 1.76× |
| CBD η=2 | 53.3 | 30.5 | 1.75× | 1.75× |
| ntt | 213.7 | 161.8 | 1.29× | 1.32× |
| gen_matrix (9 streams) | 14 970 | 11 562 | 1.23× | 1.29× |

Three things worth knowing about that table.

**Zeroization is a deliberate cost, not a gap.** `secure_zero` runs ~3000 ticks per KeyGen
— about 8 % of the operation — wiping every stack secret per FIPS 203 §3.3.
**pq-crystals does no zeroization whatsoever.** This must never be "optimized away" to
close a benchmark. Its *speed*, however, is accidental: it is a byte-at-a-time `volatile`
loop at 1.50 B/tick against memset's ~40 B/tick. Making it fast **while keeping it
non-elidable** is a Phase 9 task, and the estimate is that it alone would bring all three
operations inside criterion 4 (~1.41/1.46/1.43×).

> **Outcome (Phase 9a, 2026-09-29).** Done, and the estimate held: `secure_zero` is now a
> wide `memset` plus a compiler barrier, and the head-to-head came in at
> **1.413/1.416/1.403× — criterion 4 met on all three.** The zeroization was **not**
> weakened to get there; all 27 wrap sites are still verified erasing, per site, by
> `gmake audit-zeroize-sites`. See ADR-030 (post-9a update) and ADR-034.

**`gen_matrix` is still +3408 ticks behind, and nobody knows why.** Both sides run the
*identical* vendored 4-way Keccak, so the difference is entirely in the surrounding
non-hash code. Recorded as a known remaining gap; cause not measured.

**Our whole pipeline keeps the portable coefficient order.** pq-crystals' NTT leaves a
permuted internal order that its basemul consumes with no deinterleave; ours is
bit-identical to the scalar implementation, so our basemul must shuffle. That is a
deliberate exclusion (**ADR-031**) worth ~3–4 points, not an oversight — four gates depend
on our output order.

---

## 3. What earned its keep, and what didn't

| change | function-level | end-to-end | verdict |
|---|---|---|---|
| 4-way Keccak (8a) | XOF 4.30× | 1.30–1.42× | **kept** — the biggest single win |
| AVX2 NTT (8b) | `ntt` 8.7× cumulative | 1.32–1.43× | **kept** |
| lazy reduction: `basemul_acc`, `ntt`, `invntt` (8c) | `ntt` 2.39× | 1.09–1.11× | **kept** |
| lazy reduction: 3 further sites (8c) | — | — | **rejected** — see below |
| SIMD `rej_uniform` (8d) | `gen_matrix` 1.44× | 1.11–1.14× | **kept** |
| SIMD CBD (8d) | 3.90× | **flat** | **kept as an exception** (ADR-029) |
| SIMD compress/decompress (8d/8e) | 2.2–3.2× | 1.00–1.07× | **kept** |
| AVX2 basemul (8e) | matvec 5.4× | **1.16–1.22×** | **kept** — second-biggest win |
| packed NTT layout | ~3–4 points | — | **excluded** (ADR-031) |

**The rejections matter as much as the wins.** Three lazy-reduction sites were dropped:
one (`basemul` internals) was *proven unsafe* — removing it overflows `int16_t` in
`invntt`'s first layer, 39 948 against a 32 767 limit — and two were measured at 0.97×,
i.e. worth nothing. Deleting work that doesn't pay is part of the result.

**SIMD CBD is the interesting case.** The function got 3.9× faster and the operation did
not notice, because the noise draws are only ~9 % of a KeyGen. It was kept anyway, as a
*weighed exception* (ADR-029): exhaustively verified, constant-time-proven with its own
controls, and its share grows as everything around it shrinks. The cost — more
constant-time surface on secret data — is stated. The contrast is the two rejected
reduction sites, which had no function-level win and no mechanism: nothing to bank.

---

## 4. How a whole optimization went missing

Spec §9.2 lists seven optimization opportunities. Phase 8 was planned as four workstreams.
Nobody noticed the difference for five sub-phases.

ADR-017 chose the *ordering* of the work and ended with a consequence line —
"batched Keccak → AVX2 NTT → lazy reduction → SIMD compress/CBD" — that silently condensed
seven items into four. ADR-022 then wrote "Scope: all four Phase 8 workstreams… ADR-017
sequences them, it does not drop any," which is true of the four it names and inherited
the omission of the rest. Every later scope statement copied it.

**AVX2 basemul with accumulation (item 4) was never considered** — not rejected, not
deferred, just absent. Its only traces anywhere were two parentheticals. It turned out to
be the second-largest win in the entire phase, worth 1.16–1.22×.

The audit that found it was mechanical: walk §9.2's seven items one at a time and mark each
**done / deliberately excluded (which ADR) / never considered**. Item 6 (caching `Â`) came
back "considered and deferred" — ADR-017 measured it. Item 7 came back "never considered"
and, on inspection, **not actionable as written** (ADR-032): decrypt and re-encrypt share
no intermediate, so there is nothing to reuse.

**The lesson is about summarizing.** A consequence line that condenses a list is a place
where items disappear without anyone deciding to drop them. Audit the source list, not the
summary.

---

## 5. A correctness finding that outlives the phase

Phase 8e planted a one-bit error in `decompress` to prove the dispatch was live.
**`gmake kat` stayed at 80/80.**

Not a broken control — ML-KEM *absorbed* it. `Compress_1` rounds to the nearest of 0 and
q/2, so a ±1 perturbation in `u'` never flips a message bit; the re-encryption then
reproduces a matching ciphertext and the shared secret is correct. At `XOR 0x400` it
failed 5 of 80.

**This is a property of the whole decrypt path**, not of one function: `decompress_du` →
`ntt(u')` → `basemul` → `invntt` → `Compress_1`. A small error anywhere along it is
invisible to every KAT, and only 5 of the 80 ACVP cases exercise valid decapsulation at
all.

**Absorbed is not harmless.** Each such error spends part of decryption's noise margin,
and that margin is what holds the failure rate at FIPS 203's 2^-164.8. Decryption failures
are a known attack surface against ML-KEM, so quietly eating margin is a security
regression no functional test reports.

So for every function on the decrypt path, **exhaustive or differential verification is the
only correctness gate — not a supplement to `gmake kat`**. A decrypt-path change that is
"KAT-clean" has not been tested. This is now a rule in `docs/reference/invariants.md`, alongside a sharpened
version of the positive-control rule: **a planted fault must exceed the system's own error
tolerance to be observable.**

---

## 6. What Phase 8 did not do

- **Spec §1 criterion 4 is unmet** at 1.53/1.60/1.60×. Recorded, not rationalised.
- **`gen_matrix`'s +3408-tick gap** is unexplained, with identical Keccak on both sides.
- **The packed NTT layout** is excluded by decision (ADR-031), revisitable only as its own
  sub-phase with all four dependent gates updated together.
- **Caching `Â`** (item 6) waits for the batch API in Phase 10.
- **Energy per operation** was built and deferred to after Phase 9, so it is measured once
  on final code.
