# Lazy reduction (Phase 8c)

*Written for someone reading this codebase later. Assumes you have read
`docs/bounds.md`, or are about to.*

**Status: three removals landed, four deferred with reasons, one site reclassified.** The site
register in `docs/bounds.md` is the authoritative list; this note explains the reasoning.

---

## 1. Why this phase is different in kind from 8a and 8b

8a made the hashing arrive faster. 8b made the transform arrive faster. Neither changed
*what was in the array* at any point — the AVX2 NTT is bit-identical to the portable one,
and that identity is exactly what let `gmake kat` gate it.

Lazy reduction changes **which `int16_t` representative of a coefficient exists at
intermediate steps.** The value mod q is untouched; the number in the array is not. That
has two consequences that shape everything below:

1. **A partial state is not "incomplete", it is wrong.** If one call site stops reducing
   and a consumer's input assumption is not updated with it, an `int16_t` overflows
   silently and produces wrong-but-plausible output. There is no partially-correct
   version of this change, so each removal lands as **one commit** spanning the code,
   both backends where shared, and the `docs/bounds.md` row it depends on.
2. **The bounds table stops being documentation and becomes the precondition.** No
   reduction is removed unless the table *already* proves the removal safe. Where a bound
   was missing, it was derived and verified as its own step first.

---

## 2. What "equivalent" means now, and what it rests on

Before any value was allowed to drift, the equivalence contract was written down and
checked (`docs/bounds.md`, "Equivalence under lazy reduction"):

1. Intermediate coefficients may hold **any** `int16_t` representative of the right
   residue class. Not canonical, not centered. What is required is that it **fits**.
2. **The two backends stay bit-identical to each other.** A lazy change lands in both in
   the same commit, so `tests/unit/test_avx2.cpp` keeps its `memcmp`. This gate does not
   weaken.
3. At every serialization boundary the value is canonical `[0, q)` and the bytes match
   the model. `gmake kat` and the byte-for-byte differentials do not weaken either.

Point 3 rests entirely on `poly_canonicalize` = `to_canonical(barrett_reduce(c))` being
**total over `int16_t`** — correct for an arbitrary representative, not merely for inputs
that happen to be small. If that were false for one value, lazy reduction would corrupt
ciphertexts at the boundary while every intermediate check still passed.

Phase 2's finding is the precedent: `montgomery_reduce`'s contract was off by one at
exactly one input out of 218 169 345, and only exhaustive evaluation found it. So this was
proven exhaustively, not sampled, and the checks are permanent test cases:

| Property | Domain | Result |
|---|---|---|
| `barrett_reduce(a) ≡ a (mod q)` | all 65 536 `int16_t` | holds |
| `\|barrett_reduce(a)\| ≤ 1664` | all 65 536 `int16_t` | holds, tight |
| `poly_canonicalize` → `[0,q)`, right residue | every `int16_t` value | holds |

**A useful null result from that audit:** almost nothing needed changing.
`test_arith.cpp`'s `to_model()` already reduces mod q, so the model differentials were
*already* congruence-based and survive lazy intermediates untouched; and the
backend-vs-backend `memcmp` is correct as-is under rule 2. No existing assertion had to be
weakened — which is the outcome worth having, because weakening a gate to accommodate a
change is how gates stop being evidence.

---

## 3. Removal #1 — `poly_basemul_acc`

**What was removed:** both `barrett_reduce` calls in the accumulate loop. The accumulator
now absorbs all *k* terms of a matrix-vector row and the caller reduces once.

**The bound that justified it**, derived and checked *before* the edit:

```
|t| ≤ 1664                          barrett_reduce is total over int16_t (exhaustive)
|r| ≤ k · 1664 = 4992               after the k = 3 calls of one row
transient ≤ 4992 + 1664 = 6656      inside the last add;  int16_t holds 32767   (5× margin)
```

**The binding consumer is `invntt`**, whose input bound therefore widened **1664 → 4992**.
Only its *first* layer sees the larger value — that layer emits `barrett_reduce`'d output,
so layers 2–7 are unchanged. Two quantities had to be re-proven for the wider input:

```
|t + f[j+len]| ≤ 9984                      int16_t holds 32767
|zeta · d|     ≤ 1664 · 9984 = 16,613,376  vs montgomery_reduce's STRICT q·2^15 = 109,084,672
```

— 15 % of the strict limit. (Strict: Phase 2 found `|a| = q·2^15` exactly is the single
violating input, so the contract is `<`, not `≤`.)

The other consumer, KeyGen's `poly_to_mont`, takes `|c| ≤ 4992` into `mont_mul` against
`R²`: `1664 · 4992 = 8,306,688`, 7.6 % of the limit.

**Derived vs observed** (`gmake bounds`, real call shape — not a synthetic harness, which
is how Phase 5 and 6a both found bounds that assumption had got wrong):

| Site | Derived | Observed | int16 headroom |
|---|---|---|---|
| `acc \|r + t\|` | 4992 | **4992 — attained exactly** | 15.2 % |
| `invntt \|t + f[j+len]\|` | 9984 | 8778 | 26.8 % |
| `invntt \|zeta·diff\|` | 16 613 376 | 13 684 968 | 12.6 % |

The accumulator bound being **tight** is the good outcome: the derivation has no hidden
slack, so a later change cannot quietly spend margin that was never really there.

**Measured effect, this removal alone** (24 alternating pairs, ADR-023 method):

| | KeyGen | Encaps | Decaps | `ntt()` | `invntt()` |
|---|---|---|---|---|---|
| pairwise | **1.053×** | **1.070×** | **1.070×** | 1.003× | 1.001× |

`ntt`/`invntt` are untouched by this removal and read ~1.00 — a sanity control built into
the same measurement, in the style ADR-023 requires.

**Gates:** `kat` 80/80 on both backends; `test-deep` 109 cases / 2 097 959 827 assertions;
all ctgrind controls still firing, re-run *after* this change specifically to catch a
control that had silently stopped applying.

---

## 3b. Removals #2 and #3 — the butterflies

The growth bound was derived and committed **before** either removal, as its own step.

### The derivation, and the thing it corrected

**Forward `ntt`.** `mont_mul` returns `|t| < q` *regardless of how large its input was*,
so a lazy layer **adds a constant rather than scaling**:

```
B₀ = 3328   (ntt's input bound; Decrypt feeds canonical [0,q))
Bᵢ = Bᵢ₋₁ + 3328
B₇ = 26624                      81.3 % of int16_t  ->  ~19 % HEADROOM REMAINS
mont input ≤ 1664 · 23296 = 38,764,544   vs strict q·2¹⁵ = 109,084,672   (35.5 %)
```

So both per-butterfly reductions can go — **provided one `poly_reduce` runs at the end.**
That is the trap in this site: `basemul` multiplies two NTT outputs together, and
**Read the headroom as ~19 %, not ~63 %.** The measured 12 132 (37 % of `int16_t`) is
only what random traffic reached; the **derived 26 624 is what binds**, because
`docs/bounds.md`'s rule is that an argued bound is normative and a measurement merely
corroborates it. Phase 8d fuses work into the NTT output path, and it spends that 19 %.

`26624² ≈ 7.1 × 10⁸` is six times past `montgomery_reduce`'s strict contract. Fully lazy
with no final reduce doesn't lose precision, it produces wrong-but-plausible output.

**Inverse `invntt` — the site register was wrong.** Gentleman–Sande is asymmetric:

```
f[j]     = barrett(t + f[j+len])        SUM side  — grows
f[j+len] = barrett(mont_mul(zeta, d))   MONT side — already |·| < q
```

Only the MONT-side reduction is removable; it was pure canonicalization. **The SUM-side
one must stay** — without it that half doubles every layer, `2⁷ = 128×`, and overflows
immediately. The register had listed the two as a single removable unit. Removing "both"
is not a bound question, it is simply wrong, and the derivation is what surfaced it.

### A harness bug, and why it is in this note

The first growth simulation reported an inverse layer-1 sum of **29 934** against a
derived 9984 — a factor of three, which looked like the derivation was broken. It wasn't.
The harness generated `(int)rnd() % 9985 - 4992`, and `%` on a negative `int` is negative
in C++, so "input ≤ 4992" was really `[−14976, 4992]`.

This is the third time the project has hit it: **a synthetic harness confirming the bound
it was built with rather than the real one** (Phase 5's basemul, Phase 6a's `ntt` input).
The rule that came out of it: when simulation and derivation disagree, suspect the harness
first, and fix it before trusting either number.

### Derived vs observed, after both removals

| Quantity | Derived | Simulated | `gmake bounds` (real call shape) |
|---|---|---|---|
| forward `\|c\|` after 7 lazy layers | **26 624 — normative** | 13 505 | 12 132 |
| forward mont input | 38 764 544 | 19 971 546 | 18 860 730 (17.3 %) |
| inverse layer-1 `\|sum\|` | 9984 | **9983** | 8778 |
| inverse mont input | 16 613 376 | **16 548 525** | 13 684 968 |

### An output property worth stating

`[-1664, 1664]` is a **complete residue system** mod q — exactly 3329 values — and
`barrett_reduce` is total over `int16_t` and residue-preserving (both proven exhaustively,
§2). So the single final pass yields *precisely* the representative the old per-butterfly
reductions did: **`ntt()`'s output is bit-identical to the pre-8c version**, not merely
congruent. Verified directly over 20 000 polynomials across both input shapes, plus the
`|c| ≤ 1664` output bound.

---

## 3c. Measured effect, per removal and cumulative

Each row is 20–24 alternating pairs (ADR-023 method), with a **built-in sanity control**:
the function *not* touched by that removal, which must read ~1.00.

| Removal | `ntt()` | `invntt()` | KeyGen | Encaps | Decaps |
|---|---|---|---|---|---|
| #1 `poly_basemul_acc` | *1.003* | *1.001* | 1.053× | 1.070× | 1.070× |
| #2 `invntt` MONT side | *0.997* | **1.403×** | 1.034× | 1.039× | 1.033× |
| #3 forward `ntt` butterfly | **2.393×** | *1.029* | 1.053× | 1.036× | 1.040× |
| **Phase 8c cumulative** | **2.351×** | **1.409×** | **1.119×** | **1.140×** | **1.136×** |

*Italic* entries are the sanity controls. They read 0.997–1.029 throughout, which is the
measurement floor on this host and is what makes the non-italic figures believable.

**Which mattered:** #3 is by far the largest single win on the transform itself (1792
reductions → 256), but end-to-end the three are comparable — 1.03–1.07× each — because
each one only removes work from a different slice of the same operation. Worth knowing
before 8d: no single remaining reduction is likely to be worth much on its own.

---

## 4. What was deferred, and why that is a decision rather than an omission

The full register is in `docs/bounds.md`. The two that matter:

**Site #6 — `barrett_reduce(mont_mul(...))` in the `invntt` final scale and
`poly_to_mont`.** `mont_mul` already returns `|r| < q`, so this `barrett_reduce` is
canonicalization to `≤ 1664`, **not overflow protection**. Removing it cannot overflow;
it only changes which representative reaches `poly_tobytes`, and `poly_canonicalize` is
now proven total. So it is very likely safe — but "very likely" is not this file's
standard, and it should be *measured* before the verification effort is spent, because a
single `barrett_reduce` per coefficient on one pass may be worth nothing at all.

---

## 5. If you are about to continue this phase

* **Derive the bound first, in `docs/bounds.md`, as its own step.** Then the removal.
  Not the other way around, and not in the same breath.
* **One removal per commit**, spanning code + both backends + the bounds row. Never
  sequence a single logical removal across commits.
* **`gmake kat` and `gmake test-deep` after *each* removal, not batched.** If either
  breaks, revert that one removal and report — do not debug forward. `test-deep` matters
  more than `kat` here: 80 vectors are a weak gate against a rare-trigger overflow, which
  is exactly the bug class lazy reduction risks (`docs/bounds.md`, "Statistical power").
* **Re-run the CT controls after each removal**, not just at the end. A changed
  representative can make a control stop applying to the path it was written for while
  still passing.
* **Check `gmake bounds` observed-vs-derived after each removal.** A derived bound that
  the real call shape never approaches is a sign the derivation modelled the wrong thing;
  Phase 5 and Phase 6a both found bounds that way.
