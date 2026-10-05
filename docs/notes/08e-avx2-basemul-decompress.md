# AVX2 basemul, and fixing decompress (Phase 8e)

*Written for someone reading this codebase later.*

Two commits. Together they took KeyGen **1.17×**, Encaps **1.22×**, Decaps **1.23×**, and
moved the head-to-head against pq-crystals from 1.81/1.92/2.03× to **1.53/1.60/1.60×**.

The phase exists because of an audit finding, not a plan: **spec §9.2 item 4 (AVX2
basemul with accumulation) had never been considered.** ADR-017's consequence line
condensed §9.2's seven items into four workstreams without recording that it was dropping
anything, and every later scope statement — including ADR-022's "Scope: all four" —
inherited that silently. The omission was found only by auditing §9.2 against the record
item by item.

---

## 1. Basemul — the arithmetic, and the layout it has to live with

`poly_basemul_acc` computes 128 products of degree-1 polynomials mod `X² − γ`:

```
c0 = a0·b0 + a1·b1·γ
c1 = a0·b1 + a1·b0
```

Pair *m* lives at coefficients `(2m, 2m+1)` — **interleaved**. SIMD wants the `a0`s
contiguous and the `a1`s contiguous, so each step deinterleaves with `vpshufb` +
`vpermq`, multiplies, and re-interleaves with `vpunpcklwd`/`vpunpckhwd`.

**pq-crystals does not pay that.** Their `ntt_avx` leaves coefficients in a *permuted
internal order* in which the halves are already separated: `basemul.S` loads `a0` at `+0`,
`b0` at `+16`, `a1` at `+32`, `b1` at `+48`, straight into the multiply. `poly_nttunpack`
is applied **only to matrix polynomials** — which arrive from `rej_uniform_avx` in yet
another order — and **never after `polyvec_ntt`**, which confirms the packed order is the
NTT's native output.

Adopting it is **excluded, deliberately (ADR-031)**, and that matters because this phase
exists to fix an *accidental* omission. Measured worth: ~3–4 points on top of basemul. The
cost: our NTT output order is assumed by four things — the portable backend (the
differential reference), the model differentials, serialization, and the ctgrind taint
probes that name specific coefficient indices. Changing an invariant four gates depend on,
in the same phase as a basemul rewrite, is not a trade worth making. Revisitable only as
its own sub-phase.

### The reductions that had to survive the rewrite

Phase 8c site #4 proposed deleting basemul's two internal `barrett_reduce` calls and
**proved it unsafe**: with the accumulator already unreduced (8c removal #1), `|t|` rises
1664 → 2q = 6658, the accumulator to 19 974, and `invntt`'s layer-1 sum to **39 948** —
past `int16_t`'s 32 767.

A SIMD rewrite is exactly where such a reduction vanishes quietly, so both are explicit in
the code with the bound restated in the file banner. The k=3 accumulator bound of **4992
is attained exactly, with no slack** — verified at the extremes (all +1664; −1664 × +1664)
as well as over 200 000 random pairs. Any change to accumulation order has to re-check it.

### Prediction vs measurement — and this time it means something

| | predicted | measured |
|---|---|---|
| KeyGen | 1.15–1.17× | **1.160×** |
| Encaps | 1.19–1.22× | **1.204×** |
| Decaps | 1.20–1.23× | **1.218×** |

All three inside their brackets, sanity control at 0.995×. Unlike 8d part 3 — where the
predicted effect was 4.7 %/7.6 % against a ±3–4 % floor and so could not confirm anything
— these are **16–22 % effects, several times the floor**. The agreement is informative.

---

## 2. Decompress — why the 8d version was slow, and the honest result

8d vectorized decompress's *arithmetic* and left the 10-bit field extraction as a scalar
`memcpy`-and-shift loop. Measurement put that glue at **34 %** of the function — but the
bigger problem was structural: it chopped the work into 8-coefficient chunks with scalar
code between them, so nothing pipelined. The "vectorized" remainder alone was still **9×
pq-crystals' entire function**.

### The unpack

Each 10-bit field spans at most two bytes, so one `vpshufb` gathers the right byte pair
into every 16-bit lane. The per-lane shift then differs — 0, 2, 4, 6 bits — and AVX2 has
no per-lane 16-bit variable shift. So instead **multiply by 2^(6−s) and shift everything
right by 6**; `mullo` keeps only the low 16 bits, discarding exactly what a mask would
have removed:

```
s=0: t·64 >>6 = t & 0x3FF          s=4: t·4 >>6 = (t>>4) & 0x3FF
s=2: t·16 >>6 = (t>>2) & 0x3FF     s=6: t·1 >>6 = (t>>6) & 0x3FF
```

No mask instruction at all. Result: **3.18×** on the function.

### The prediction said it would not show, and it did not

Stated before writing code: decompress runs **only in Decaps** and is 2.30 % of it, so
even at pq-crystals' full 13.6× the end-to-end gain would be 1.022× — **inside the ±3–4 %
floor** — and exactly 0 % for KeyGen and Encaps.

Measured: KeyGen 0.996×, Encaps 1.002×, Decaps 1.004×. Flat, as predicted.

Done anyway, and the justification is *not* ADR-029's. ADR-029 governs keeping
constant-time surface **on secret data** for no measurable gain. Decompress reads the
**public ciphertext**, so it adds no secret-data CT surface at all and that bar does not
apply. The technique is worth having and the function is now 3.4× rather than 13.6× off
the reference.

### Two bugs the guards caught

**Over-read.** 16 coefficients consume 20 bytes, but the high 128-bit half is loaded from
`in + 20i + 10` and reads 16 — so the guard is `20i + 26 ≤ 320`, **not** `20i + 20 ≤ 320`.
Guarding on bytes *consumed* rather than bytes *loaded* is precisely the Phase 8d part 1
bug. `docker-asan` was run on this commit specifically: clean.

**A control that did not fire.** The first planted corruption flipped one bit of one
coefficient and `kat` stayed at **80/80**. Not a broken control — ML-KEM *absorbs* it:
`Compress_1` rounds to the nearest of 0 and q/2, so a ±1 perturbation in `u'` is far
inside the decryption error margin and never flips a message bit. Re-planted as `XOR
0x400`, it fails 5 of 80.

**This goes further than "kat is weak for decompress."** The absorption is a property of
the *whole decrypt path*, not of one function. `decompress_du` → `ntt(u')` → `basemul` →
`invntt` → `Compress_1`: a small error anywhere along it is rounded away by `Compress_1`,
the re-encryption then reproduces a matching ciphertext, and the shared secret is correct.
**No KAT can see it**, and only 5 of the 80 ACVP cases exercise valid decapsulation at all.

And absorbed is **not** harmless. Each such error spends part of decryption's noise margin,
and that margin is exactly what holds the failure rate at FIPS 203's 2^-164.8. Decryption
failures are a known attack surface against ML-KEM, so quietly eating margin is a security
regression that no functional test reports.

So for every function on the decrypt path, **exhaustive or differential verification is
the only correctness gate — not a supplement to `gmake kat`.** A decrypt-path change that
is "KAT-clean" has not been tested. This is now a rule in `docs/reference/invariants.md`.

The second lesson is about controls: `docs/reference/invariants.md`'s rule that *a planted control can pass its
own check and still prove nothing* applies to **magnitude**, not only to optimizer
elimination. A fault must exceed the system's own error tolerance to be observable.

---

## 3. Where the remaining gap is

| component | ours | kyber | ratio | was |
|---|---|---|---|---|
| basemul 1 poly | 202.7 | 55.1 | 3.68× | 16.48× |
| matvec k=3 | 495.5 | 190.7 | 2.60× | 14.66× |
| decompress du | 337.3 | 98.4 | 3.43× | 13.59× |
| compress du | 1345.3 | 272.9 | 4.93× | 4.79× |
| polyvec_tobytes | 537.6 | 130.4 | 4.12× | 3.73× |
| gen_matrix (9) | 14 970 | 11 562 | 1.29× | 1.23× |

The three 8e targets fell from 13–16× to 2.6–3.7×. What remains, by absolute delta, is
`gen_matrix` (+3408), `compress_du` (+1072) and `polyvec_tobytes` (+407).

**And one item that is not a gap at all.** `secure_zero` costs ~3012 ticks per KeyGen —
6.5 % of our runtime — because every stack secret is wiped (FIPS 203 §3.3). pq-crystals
does **no zeroization whatsoever**. That is a cost paid on purpose and should never be
"optimized away" to close a benchmark.

Spec §1 criterion 4 (~1.5×) is still **not met** at 1.53/1.60/1.60× — ADR-030 records that
without revising the criterion.

---

## 4. If you are about to continue

* **Do not delete basemul's internal reductions.** 8c site #4 proved it overflows
  `int16_t` in `invntt` layer 1 while the accumulator stays unreduced. The bound 4992 is
  attained exactly — there is no slack to spend.
* **ADR-031 is a decision, not an omission.** If you want the packed NTT order, it lands
  as its own sub-phase with all four dependent gates updated in the same commit.
* **Predict before implementing, and say when the prediction cannot confirm anything.**
  Basemul's 16–22 % effect makes its agreement meaningful; decompress's 2.3 % share meant
  the result was known to be unmeasurable before a line was written. Both were worth
  stating in advance.
* **Check a planted control's magnitude, not just its presence.** A ±1 error in `u'` is
  invisible to `kat` by design.
