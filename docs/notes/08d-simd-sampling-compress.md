# SIMD sampling and compression (Phase 8d)

*Written for someone reading this codebase later.*

Three independent pieces, landed as three commits. They close the residue ADR-023
attributed to scalar byte-wise code sitting inside the batched Keccak blocks.

| Part | Function | In situ | End to end |
|---|---|---|---|
| 1 `rej_uniform` | — | `gen_matrix` **1.441×** | KeyGen 1.137×, Encaps 1.128×, Decaps 1.105× |
| 2 CBD η=2 | **3.901×** | noise block 1.380× | **flat** — 1.004× / 0.992× / 1.012× |
| 3 compress/decompress d=10 | — | — | 1.011× / **1.050×** / **1.074×** |

---

## 1. The three constant-time regimes, because they are not the same

This phase touches three functions with **three different** requirements. Getting them
confused is the easiest way to introduce a real leak here, so they are stated together:

| | input | requirement | why |
|---|---|---|---|
| `rej_uniform` | ρ ‖ j ‖ i | **variable-time is FINE** | ρ is published verbatim in `ek` |
| `sample_poly_cbd` | `PRF(σ, N)` | **must be constant-time** | its output *is* the secret key |
| `decompress_du` | the ciphertext | variable-time would be fine | `c` is public |
| `compress_du` | `u`, from noise `y`,`e1` | **must be constant-time** | secret-derived |
| `Compress_1` in `poly_tomsg` | `v` in decaps | **must be constant-time** | output is `m'`, the decrypted message |

The last row is the most sensitive value in the scheme and gets its **own** ctgrind
control (`ct_kpke --tomsg-leak` / `--tomsg-map`) rather than coverage inherited from the
general compress test — so the project can say it checked *that* path, not a path near it.

---

## 2. Part 1 — the rejection sampler, and the one data-indexed table

12 bytes → 8 candidates. One `pshufb` spreads the packed 12-bit fields into 16-bit lanes
(lane 2k takes bytes 3k,3k+1; lane 2k+1 takes 3k+1,3k+2); mask-and-blend separates the low
field from the high; a signed compare against q gives the accept mask (candidates ≤ 4095,
so signed is exact); `packs_epi16` + `movemask` turns that into 8 bits; a table lookup
compacts accepted lanes to the front; `popcount` advances the count.

**The table is indexed by the accept mask — the only data-indexed table in the library.**
It is permitted only because the index derives from ρ: it leaks exactly what the rejection
loop's iteration count already leaks, to someone who can recompute both from `ek`.
**ADR-027** carries the argument, and the permission attaches to *this path* — not to the
technique, and not to CBD.

Generated `consteval`; all 256 entries verified at runtime against what `_mm_shuffle_epi8`
*actually does* (accepted lanes at the front, order preserved, count = `popcount`, tail
zeroed).

**A bug worth remembering.** `_mm_loadu_si128` reads 16 bytes while the step *consumes* 12,
so the loop guard has to cover the **load** width, not the consumed width. At `pos+12` it
over-reads up to 4 bytes past the buffer. The arithmetic is unaffected, so no equivalence
test would fail — only ASan or valgrind, later. The guard is `pos+16`.

**And a control that had quietly stopped proving anything.** `ct_sample --ntt-secret` fires
correctly either way, so it would have passed while exercising the *scalar* path the
library no longer dispatches. The gate now additionally requires the run to print
`backend: AVX2 (SIMD rej_uniform)`.

---

## 3. Part 2 — CBD, and a `vpshufb` that is not a table lookup

At η=2 each coefficient takes 4 bits and **those bits always lie inside one byte**:

```
coefficient 2b   = low  nibble of byte b
coefficient 2b+1 = high nibble of byte b
nibble n         -> popcount(n & 3) - popcount((n >> 2) & 3)      in [-2, 2]
```

So Algorithm 8 at η=2 collapses to a 16-entry nibble permutation plus a sign-extend. That
byte-locality is also what makes exhaustive verification possible — 256 byte values × 128
positions is the *complete* input→output map — and **the locality claim the exhaustiveness
rests on is itself checked**, because otherwise "exhaustive" would be unfounded.

### The distinction that matters (ADR-028)

The permutation uses `vpshufb` with the **secret nibble as the selector**. This reads like
a CT violation and is not:

| | forbidden | this |
|---|---|---|
| table lives in | memory | a register |
| index does | computes an address | selects a lane |
| leak channel | which cache line is touched | none — no memory accessed |
| timing | depends on cache state | fixed, value-independent |

**ADR-028 is deliberately separate from ADR-027**, not a citation of it. ADR-027 rests
entirely on ρ being public, which says nothing about CBD. If someone later routes a secret
into `rej_uniform`, 027 dies and 028 is untouched; if someone moves this LUT to memory,
028 dies and 027 is untouched.

### The control that mattered

8a's `--x4-taint` covered `vpshufb` only with a **constant** selector. A permute whose
*index* is undefined could plausibly be modelled as producing defined output — which would
have made the clean run vacuous. `--cbd-map` measures it: all 256 coefficients come back
tainted. Then `--cbd-taint` fires, and only then does `--cbd` count.

### η=3 stays scalar, and is now exhaustively verified

Its 6-bit fields cross byte boundaries, so none of the above applies; ML-KEM-768 never
calls it. It is 3-byte-local, so **all 2²⁴ three-byte groups** are checked against
Algorithm 8 directly — the path no shipped parameter set exercises is the one that rots
silently (ADR-009).

### Kept despite a flat end-to-end result — ADR-029

The function is 3.901× and the operation did not notice, because the noise draws are only
~9% of a KeyGen. It is kept as a **weighed exception**: exhaustively verified, CT-proven
with its own controls, share grows as everything else gets faster, and learning value.
Cost: new CT surface on secret data.

The contrast that decides such cases is 8c's sites #5/#6, which were **reverted** on a
similar-looking 0.97×: those had no function-level win and no mechanism, so there was
nothing to bank. ADR-029 is citable for a *verified* optimization inside the noise floor —
never for a merely unmeasured one.

---

## 4. Part 3 — compress/decompress, predicted before it was written

### The prediction, and why predicting first mattered

ADR-023's Phase 8a prediction did **not** match measurement, so this time the estimate was
stated up front and checked against, rather than explained afterwards. Measured in-situ
share first, then applied the same Amdahl form:

| | share of the operation | predicted @3× | **measured** |
|---|---|---|---|
| KeyGen | **0.0%** — no compress at all | 1.000× | **1.011×** |
| Encaps | 6.8% | 1.047× | **1.050×** |
| Decaps | 10.7% | 1.076× | **1.074×** |

**The measurements are CONSISTENT WITH the prediction — they cannot strongly confirm it,
and the agreement is partly coincidental.** Three reasons to state it that way:

1. **The predicted gains are barely above the noise floor.** 4.7 % and 7.6 % against a
   ±3–4 % floor. A result that size cannot distinguish a good model from a lucky one.
2. **KeyGen bounds the noise directly.** It has *zero* compress share by construction, so
   its true value is exactly 1.000×. It measured **1.011×** — so roughly 1 % of every
   figure in that table is noise.
3. **The prediction assumed 3× on the compress functions; the real numbers are 2.16×
   (`compress_du`) and 2.48× (`decompress_du`).** Re-running the model with those gives
   **1.033× / 1.056×**, and measurement came in at 1.050× / 1.074× — about 1.8 points
   *above* the corrected model. So there were two errors in opposite directions, roughly
   cancelling: the assumed function speedup was too high, and the measurement ran high.

| | Encaps | Decaps |
|---|---|---|
| predicted, assuming 3× | 1.047× | 1.077× |
| **corrected**, using measured 2.16× / 2.48× | 1.033× | 1.056× |
| measured | 1.050× | 1.074× |

**The ADR-023 contrast is a HYPOTHESIS, not a demonstrated cause.** It is plausible that
measuring the share *in situ* rather than composing hot-cache micro-benchmarks is why this
estimate landed closer than 8a's — but a single agreement at this effect size does not
establish it. Two data points, one of which is inside its own noise, is not evidence of a
methodology. Treat it as a reason to keep measuring shares in situ, not as a proven
technique.

`compress_du` is 2956 of Encaps's 3365 compress ticks and `decompress_du` 2726 of
Decaps's, so **d = 10 is the whole target**. `dv = 4` (260 ticks) and `d = 1` (243/149) are
each below the measurement floor alone, and ADR-029 forbids adding CT surface on secret
data for nothing measurable — so they stay scalar.

### Why the two directions use different constants

A `consteval` search for an exact 32-bit-lane multiply-shift found one for **d = 1 and
d = 4** but **not for d = 10**. The reason is precision: exactness needs the multiplier
within about 4.5 × 10⁻⁸ of 1024/q, which forces S ≥ 24 and pushes `x·M` past 2³¹.

```
d= 1:  M=315  S=19  A=262144      exact over [0,q)
d= 4:  M=315  S=16  A= 32768      exact over [0,q)
d=10:  none exists with x*M + A < 2^31
```

So `compress_du` keeps the 64-bit multiply already proven exhaustively at compile time in
`poly.cpp`, applied four products at a time with `vpmuludq`; `decompress_du`'s product is
only 22 bits (q·y ≤ 3,405,567) and stays in 32-bit lanes with `vpmulld`. The exactness
`static_assert` is re-stated in the AVX2 file so the two derivations cannot drift.

### Canonicalization is deliberately NOT fused in

`kpke_encrypt` calls `polyvec_canonicalize(u)` before compress, so the domain reaching it
is `[0,q)` — which is what the exhaustive test covers. Fusing canonicalization would widen
the domain to the post-8c range and **spend the ~19% `int16_t` headroom** removal #3 left
(the normative bound is 26 624, not the 12 132 that was merely observed), for a gain
already predicted at ~1.05×. Not worth it.

### ADR-025 for the new classes

`compress_avx2.o` emits classes no earlier control covered: `vpmuldq` (64-bit multiply),
`vpmulld`, `vpmovzxwd`, **`vpackusdw`** — a *saturating* pack, a plausible candidate for
being modelled as producing defined output — plus `vpinsrw`/`vpextrw` and the 32-bit
arithmetic. `ct_kpke --taint-map` asserts the ciphertext comes back 1088/1088 tainted with
`m`, `r` secret, and the ciphertext **is** the SIMD compress output, so that assertion
doubles as the taint-survival proof. It was re-run after this change, not assumed.

---

## 5. How much of ADR-023's residue is closed

ADR-023 attributed about two-thirds of its shortfall to two effects, one of which was
scalar work inside the batched blocks:

- **Matrix half: closed.** `gen_matrix` was 2.95× against a 3.98× primitive; part 1 makes
  it 2.95 × 1.441 = **4.25×**, now *above* the primitive. `rej_uniform` is no longer the
  limiter there.
- **Noise half: closed at the function, invisible in situ.** CBD itself went 3.901×, but
  the noise draws are too small a share for it to show. What remains in that block is the
  Keccak, not CBD.
- **Compression** was never part of ADR-023's residue; part 3 is a separate ~5–7% on
  Encaps and Decaps, and 0% on KeyGen by construction.

**Do not compose these ratios across sessions to claim a cumulative figure.** ADR-023's
additive cross-check fell 19% short of in-situ measurement; a direct `kat-clean → final`
interleaved run is logged as a Phase 8 close-out item for exactly this reason.

---

## 6. If you are about to change something here

* **Know which of the three CT regimes you are in** (§1). `rej_uniform` may be
  variable-time and may use a memory table; CBD and compress may be neither.
* **ADR-027 does not generalize.** It permits one memory table on one public path. ADR-028
  permits register-resident `vpshufb` with a secret selector. A new SIMD backend needs
  whichever argument actually applies, or its own.
* **New instruction classes need a taint control that FIRES before a clean run counts**
  (ADR-025). Disassemble the object and compare against what existing controls cover;
  don't assume.
* **Exhaustive means over the domain that actually reaches the function.** For compress
  that is `[0,q)` *because* canonicalization runs first — if you fuse it in, the domain
  becomes the widened post-8c range and every exhaustive claim here needs redoing.
* **Predict before implementing** — but read the result honestly. Part 3's measurement
  was *consistent with* its prediction; it did not confirm it, because the predicted
  effect (4.7 %/7.6 %) is barely above the ±3–4 % floor and the assumed 3× function
  speedup was really 2.16×/2.48×. Predicting first is still worth doing: it fixes scope
  (it is why d=1 and d=4 stayed scalar) and it stops a result being explained after the
  fact. It does not make a small measurement trustworthy.
