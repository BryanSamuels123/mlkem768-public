# Coefficient bound invariants

This table is the specification for lazy reduction. Skipping a `barrett_reduce` is legal
**only** if this table proves no `int16_t` overflow along every path that reaches it.

`int16_t` range is `[-32768, 32767]`. `q = 3329`, so the headroom is roughly `9.8q`.
Overflow is silent and produces wrong-but-plausible output that can still pass roundtrip
tests — it typically surfaces as a KAT failure many phases later.

**Any change to reduction placement updates this table in the same commit.**

---

## Status: Phase 8c — lazy reduction IN PROGRESS (site register below)

Every butterfly output is `barrett_reduce`d. The invariant is uniform and deliberately
crude:

> **Every coefficient satisfies `|c| <= 1664` at every layer boundary.**

Nothing here is lazy. That is the point: Phase 2 is about being obviously correct, and
every place a reduction could provably be skipped is marked `LAZY-OPPORTUNITY` in
`src/ntt.cpp` with a row below. **Do not act on them before Phase 8**, and not then
without this table proving it.

---

## Primitives

| Function | Input bound | Output bound | Verified |
|---|---|---|---|
| `montgomery_reduce(a)` | `\|a\| < q·2^15` (**strict**) | `\|out\| < q`, i.e. `<= 3328` | [x] **exhaustive** |
| `mont_mul(a,b)` | `\|a·b\| < q·2^15` | `\|out\| <= 3328` | [x] via the above |
| `barrett_reduce(a)` | any `int16_t` | `\|out\| <= (q−1)/2 = 1664` | [x] **exhaustive** (65536) |
| `csubq(a)` | `[0, 2q)` | `[0, q)` | [x] **exhaustive** (6658) |
| `to_canonical(a)` | `\|a\| < q` | `[0, q)` | [x] **exhaustive** |

`montgomery_reduce` and `barrett_reduce` are verified by exhaustive sweep, not sampling.
The montgomery sweep covers all 218,169,343 legal inputs in ~0.3 s.

**Both bounds are tight**: `barrett_reduce` attains exactly 1664, and `montgomery_reduce`
attains exactly 3328. Margin of 1 in each case — they are achieved, never exceeded.

### The strict input bound on `montgomery_reduce` — a spec correction

Spec §5.2 states the contract as `|a| <= q·2^15` with output `|t| < q`. **That is off by
one.** Exhaustive evaluation finds exactly one violation in the whole range:

| `a` | `montgomery_reduce(a)` |
|---|---|
| `+q·2^15 = 109084672` | **3329 = q** — not `< q` |
| `−q·2^15` | 0 — fine |
| everything else in range | `<= 3328` |

The contract in `src/reduce.hpp` is therefore the **strict** inequality. Every call site
satisfies it with an enormous margin (worst observed: 5.05% of the limit). Logged in
`DECISIONS.md` → Spec corrections.

---

## Composite operations

Claimed bounds are **argued from the algorithm**, not read off the measurements.
Observed values come from `make bounds` (20 000 random inputs plus five adversarial
corners: all-`+1664`, all-`−1664`, mixed, and two alternating-extreme patterns).

| Site | Observed max | Argued bound | Hard limit | Headroom vs hard limit |
|---|---|---|---|---|
| `ntt` `\|zeta·c\|` → `montgomery_reduce` | 2 760 576 | `1664 · 1664 = 2 770 496` | `q·2^15 − 1` | **2.53 %** |
| `ntt` `\|c\|` on **entry** | 3 328 | `3328` — canonical `[0, q)` is accepted | 32 767 | 10.2 % |
| `ntt` `\|f[j] ± t\|` → `barrett_reduce` | 5 010 | `3328 + 3328 = 6656` (first layer) | 32 767 | **20.3 %** |
| `invntt` `\|t + f[j+len]\|` → `barrett` | 3 328 | `1664 + 1664 = 3328` ← **tight** | 32 767 | 10.2 % |
| `invntt` `\|f[j+len] − t\|` → `mont_mul` | 3 328 | `1664 + 1664 = 3328` ← **tight** | 32 767 | 10.2 % |
| `invntt` `\|zeta·diff\|` → `montgomery_reduce` | 5 512 857 | `1664 · 3328 = 5 537 792` | `q·2^15 − 1` | **5.08 %** |
| `invntt` `\|c·R²/128\|` → `montgomery_reduce` | 2 397 824 | `1664 · 1441 = 2 397 824` ← **tight** | `q·2^15 − 1` | 2.20 % |
| `basemul` `\|a·b\|` → `montgomery_reduce` | 11 075 584 | `3328 · 3328 = 11 075 584` ← **tight** | `q·2^15 − 1` | **10.15 %** |
| `basemul` `\|c0\|,\|c1\|` → `barrett_reduce` | 3 370 | `3328 + 3328 = 6656` | 32 767 | **20.3 %** |
| `acc` `\|r + t\|` → `barrett_reduce` | 3 328 | `1664 + 1664 = 3328` ← **tight** | 32 767 | 10.2 % |
| `poly_basemul_acc` over **k = 3**, real path | 3 328 | `3328`, independent of k — see below | 32 767 | **10.2 %** |
| `to_mont` `\|c·R²\|` → `montgomery_reduce` | 2 251 392 | `1664 · 1353 = 2 251 392` ← **tight** | `q·2^15 − 1` | 2.06 % |

### The arguments

Each claimed bound follows from two facts: `barrett_reduce` outputs `|c| <= 1664`, and
`montgomery_reduce` outputs `|c| <= 3328`.

- **`ntt` input is 3328, NOT 1664 — corrected in Phase 6a.** `K-PKE.Decrypt` (Alg. 15
  line 6) applies `NTT` to `u'` straight out of `Decompress_du`, which produces
  **canonical `[0, q)`**. That is FIPS 203's own call shape, so the contract accommodates
  it rather than forcing a centering pass.
- **`ntt` butterfly.** On the **first** layer `f[j]` may be up to 3328 (the input bound
  above) and `t = mont_mul(zeta, f[j+len])` is a montgomery output so `<= 3328`, giving
  `|f[j] ± t| <= 6656`. After the first layer every coefficient is post-barrett
  (`<= 1664`) so later layers are bounded by `1664 + 3328 = 4992`. The observed 5 010
  sits between the two, which is exactly what that structure predicts.

  **This was the SECOND bound the real call shape corrected.** The synthetic harness
  measured 4 928 and appeared to confirm 4992; only driving the actual `kpke_decrypt`
  exposed 5 010. Phase 5 corrected `basemul`'s input bound the same way. Two for two:
  **a synthetic harness confirms the bound you assumed, not the bound that holds.**
- **`invntt` butterfly.** Both operands are post-barrett, so every sum and difference is
  `<= 3328`. Three of these are tight, and the measurement confirms it.
- **`basemul` — the input bound is 3328, NOT 1664.** Phase 5 corrected this.
  `sample_ntt` produces `Â` in **canonical `[0, q)`**, i.e. up to 3328, and `Â` goes
  **straight into `basemul` with no intervening `ntt()`** because it is already in the
  NTT domain (Alg. 13 line 5). So one operand routinely exceeds the `±1664` the barrett
  invariant provides. The multiply bound is therefore `3328 · 3328 = 11 075 584`, which
  is 10.15 % of `montgomery_reduce`'s limit — comfortable, but it is double what the
  Phase 2 table claimed. The real Phase 6 shape is milder still (`3328 · 1664`, canonical
  `Â` against a reduced `ŝ`); the table records the pathological both-canonical case.
- **`basemul` outputs.** `mont_mul` outputs `<= 3328`; `c0` and `c1` each add two of
  them, so `<= 6656`. The observed 3 370 is far below because random inputs almost never
  drive both products to their extremes simultaneously — **this is the clearest case in
  the table of measurement understating the true worst case.**
- **`poly_basemul_acc` accumulating `k = 3` terms — the row Phase 6a was asked to fill.**
  Measured on the **real** path: `Â ∘ ŝ` in KeyGen, `Âᵀ ∘ ŷ` in Encrypt, and
  `ŝᵀ ∘ NTT(u')` in Decrypt, with `Â` canonical from `sample_ntt`.

  **Argued: `3328`, and it does NOT grow with `k`.** Each `basemul` output is
  barrett-reduced to `<= 1664` before being added, and the accumulator is itself
  barrett-reduced after every add. So the pre-reduction sum is `1664 + 1664 = 3328` on
  every iteration regardless of how many terms are accumulated. **Observed: 3 328** —
  tight, and identical for `k = 1` and `k = 3`, confirming the argument rather than
  merely being consistent with it.

  This is exactly what the Phase 8 `LAZY-OPPORTUNITY` would change: absorbing all three
  terms before a single reduction gives `3 · 3328 = 9984`, still only 30 % of `int16_t`.
- **`invntt` scale and `to_mont`.** One post-barrett operand times a fixed constant
  (`1441` and `1353` respectively), so the bound is exact and is attained.

> **Random testing establishes a lower bound on the worst case, not the worst case.**
> Four rows above are tight — observed equals argued — which is evidence the corners are
> being reached. The `basemul` rows are *not* tight, so for those the **argument is the
> only real guarantee** and the measurement is merely a sanity check. Treat the argued
> column as normative and the observed column as corroboration.

Even the argued worst case (`6656`) uses only 20 % of `int16_t`. Phase 2 has roughly a
**5× safety factor** everywhere.

---

## Phase 4: serialization and compression

All byte-writing functions require **canonical `[0, q)`** input. The arithmetic layer
produces centered values carrying Montgomery factors, so `poly_canonicalize` /
`polyvec_canonicalize` must run first — that is ADR-004's consequence made concrete, and
`test_serialize.cpp` pins it with a test that shows a post-`ntt` polynomial really does
contain negative coefficients.

| Function | Input | Output | Verified |
|---|---|---|---|
| `compress_coeff<D>` | canonical `[0, q)` | `[0, 2^D)` | [x] **exhaustive**, all `D ∈ {1,4,5,10,11}` |
| `decompress_coeff<D>` | `[0, 2^D)` | `[0, q)` | [x] **exhaustive** |
| `poly_canonicalize` | any `int16_t` | `[0, q)` | [x] **exhaustive** (65536) |
| `poly_tobytes` | canonical `[0, q)` | 384 B | [x] differential vs model |
| `poly_frombytes` | 384 B | `[0, q)` | [x] incl. non-injectivity |
| `poly_compress_dv` | canonical `[0, q)` | 128 B | [x] differential |
| `polyvec_compress_du` | canonical `[0, q)` | 960 B | [x] differential + ASan bound check |
| `poly_frommsg` | 32 B | `{0, 1665}` | [x] endianness pinned |
| `poly_tomsg` | canonical `[0, q)` | 32 B | [x] exhaustive over all `x` |

**Rounding.** `⌈x⌋` is round-to-nearest, ties **up** (FIPS 203 §2.3). Two facts worth
recording because neither is obvious:

- **`Compress_d` can never tie.** A tie needs `2·(2^d·x mod q) == q`, and `q = 3329` is
  **odd**, so an even number can never equal it. The tie-break rule is *vacuous* for
  Compress, at every `d`. Proven exhaustively.
- **`Decompress_d` ties exactly once per `d`**, at `y = 2^(d-1)`, because `q` is odd and
  therefore invertible mod `2^d`. For `d = 1` that single tie **is** the message
  constant: `Decompress_1(1) = ⌈q/2⌋ = 1665`.

  Rounding half-*down* there yields 1664, and the failure mode is worth stating
  precisely because the obvious guess is wrong. **Decryption would still work**: 1664 is
  nowhere near the `q/4` and `3q/4` decision boundaries that `Compress_1` uses to recover
  the bit, so every message bit would still be read back correctly. What breaks is
  **byte-exactness**. `μ` shifts by 1 in every set-bit coefficient, so `v = t̂ᵀŷ + e2 + μ`
  shifts too, and for a fraction of inputs that is enough to change a `Compress_dv`
  output and therefore the ciphertext bytes. The result is a **self-consistent
  implementation that fails KATs** — the signature failure of this project, and exactly
  why the standard specifies the rounding direction.

---

## Division audit — the hazard no tool can see

Per **ADR-016**, ctgrind is **provably blind** to secret-dependent `div`/`mod`: valgrind
models values, not timing. `docs/reference/invariants.md` bans it; nothing enforces that ban automatically. So
every division is enumerated here and justified, and the audit is done **at the machine
level**, not by reading source.

### Source-level

| Location | Expression | Justification |
|---|---|---|
| `poly.cpp` `derive_compress_mul` | `/ divisor` | **consteval** — compile time only |
| `poly.cpp` `compress_mulshift_is_exact` | `n / 2q` | **consteval** — the compile-time exactness proof |
| `poly.cpp` `HALF_Q_UP` | `(Q+1)/2` | `constexpr` initializer |
| `poly.cpp` ×4 loop bounds | `params::N / 2` | both operands `constexpr`; constant-folded |
| `polyvec.cpp` `kDuGroups` | `params::N / 4` | `constexpr` |

`Compress_d` itself performs **no division**: it uses a derived multiply-shift, with `M`
computed from `S` and the substitution **proven exhaustively at compile time** for every
`d` the scheme uses. `Decompress_d`'s divisor is `2^(d+1)`, a power of two, so it is a
shift.

### Machine-level (`objdump`, verified with a positive control)

| Object | `div`/`idiv` instructions |
|---|---|
| every library object, including the AVX2 and vendored ones | **0** |

**`gmake audit-div` now carries NO allowance.** It did, from Phase 4 through 8a: clang
strength-reduced the NTT's inner-loop `k++` into `k += 255/(2·len)` and emitted one
`divl` per call, because `len` was a runtime loop variable. Traced in the disassembly at
the time, the divisor was the **layer width**, derived solely from the induction variable
and never touching `f.c[]` — public, data-independent, not a timing leak, but ~20–40
cycles × 7 layers of waste in the hottest loop.

**Phase 8b removed it** by making every layer width a template parameter
(`ntt_layer<Len>` / `invntt_layer<Len>`), which turns each trip count into a compile-time
constant. The allowance was then deleted outright rather than set to 0, so `ntt.o` falls
through to the UNEXPECTED branch like every other object.

That distinction matters: an allowance of 0 and no allowance behave identically today,
but an allowance is a named place for a *second* division to hide, and confirming that
some future divisor is public means tracing the disassembly by hand every time. Re-proven
able to fail in Phase 8b by planting a `volatile` division in `ntt()` — the gate reported
`ntt.o: 1 *** UNEXPECTED DIVISION ***` with the `idivl` line and exited non-zero.

**Raising this above 0 again requires tracing the divisor in the disassembly and adding a
justification row here, per ADR-018. Do not do it casually.**

---

## Phase 5: sampling — and the CT asymmetry that must not be "cleaned up"

`src/sample.cpp` contains two functions with **opposite** constant-time requirements.
This is deliberate and correct; the shape invites a later session to make them uniform,
and both directions of that are wrong.

| Function | Timing | Input | Output |
|---|---|---|---|
| `sample_ntt` | **VARIABLE-TIME BY DESIGN** | `ρ ‖ j ‖ i` — **public** | canonical `[0, q)`, already in the NTT domain |
| `sample_poly_cbd<Eta>` | **MUST BE CONSTANT-TIME** | `PRF(σ, N)` / `PRF(r, N)` — **secret** | centered `[-η, η]` |

- **Making `sample_ntt` constant-time would require bounding the rejection loop**, which
  FIPS 203 Appendix B explicitly tells implementations not to do ("an incorrect limit
  will cause interoperability errors"). If a bound is ever mandated it shall be ≥ 280.
  There is nothing to protect: `ρ` is derivable from the public `ek` by anyone.
- **Making CBD variable-time would leak the secret key.** It is constant-time *by
  construction* — bit-slicing and popcounts, no rejection, no table, no branch, no
  division. That is the structural reason ML-KEM samples from a centered binomial rather
  than a discrete Gaussian: a Gaussian needs rejection, and rejection on secret data
  leaks.

`tests/ct/ct_sample.cpp` asserts **both** directions under valgrind, and the negative one
is what makes the positive one meaningful:

| Check | Requirement | Result |
|---|---|---|
| CBD, `σ` marked secret, η=2 and η=3 | **zero findings** | ✅ 0 errors |
| `sample_ntt`, `ρ` marked secret | **findings REQUIRED** | ✅ detected |
| `sample_ntt`, `ρ` public | **zero findings** | ✅ 0 errors |

The middle row is a **positive control**. `sample_ntt`'s rejection loop has a
data-dependent trip count, which ADR-016 measured ctgrind as able to detect. If it came
back clean, the harness could not see secret-dependent control flow — which is exactly
the class CBD must avoid — and the CBD result above would prove nothing. `ctgrind-run`
fails if it does not fire.

### Declassification — rho in K-PKE.KeyGen (ADR-020)

`kpke_keygen` declassifies **32 bytes, rho only, never sigma** for ctgrind. `rho` is
`G(d||k)[0:32]`, so memcheck inherits `d`'s marking, but `rho` is published verbatim in
`ek` and spec §8.1 permits variable time on it. Verified narrow: a planted CBD leak is
still caught by `--keygen-secret-d` (exit 99 with, 0 without), and `--encrypt-secret-ek`
still fires. **Declassification silences a real leak if misapplied — never add one to
make a test pass.**

### Sampling bounds

| Function | Input | Output | Verified |
|---|---|---|---|
| `sample_ntt` | 34-byte public seed | canonical `[0, q)` | [x] every coefficient range-checked; χ² uniformity |
| `sample_poly_cbd<2>` | 128 B secret | `[-2, 2]` | [x] range + `{1,4,6,4,1}/16` over 10⁶ |
| `sample_poly_cbd<3>` | 192 B secret | `[-3, 3]` | [x] range + `{1,6,15,20,15,6,1}/64` over 10⁶ |

---

## `static_cast<int16_t>` sites — where this table is the ONLY defence

Per **ADR-012**, `int16_t` overflow is *not* undefined behaviour (operands promote to
`int`, and narrowing back is well-defined wrapping in C++20), so
`-fsanitize=signed-integer-overflow` cannot see it. `-fsanitize=implicit-integer-truncation`
catches *implicit* narrowing — but **it is blind to an explicit `static_cast`**.

Every explicit narrowing in the arithmetic path is listed here. At each of these, this
table is the only thing standing between the code and failure mode #8:

| File | Site | Value narrowed | Why it is safe |
|---|---|---|---|
| `ntt.cpp` | `ntt` butterfly, `f[jl]` | `f[j0] − t` | `<= 4992` by the argument above |
| `ntt.cpp` | `ntt` butterfly, `f[j0]` | `f[j0] + t` | `<= 4992` |
| `ntt.cpp` | `invntt` sum | `t + f[jl]` | `<= 3328` |
| `ntt.cpp` | `invntt` diff | `f[jl] − t` | `<= 3328` |
| `ntt.cpp` | `basemul` `c0` | `t + mont_mul(a0,b0)` | `<= 6656` |
| `ntt.cpp` | `basemul` `c1` | sum of two `mont_mul` | `<= 6656` |
| `ntt.cpp` | `poly_basemul_acc` ×2 | `r + t` | `<= 3328` |
| `reduce.hpp` | `montgomery_reduce` result | `t >> 16` | `\|.\| <= q` by construction |
| `reduce.hpp` | `montgomery_reduce` `m` | `uint16_t` → `int16_t` | **intentional reinterpretation** of the low 16 bits; the wrap is the algorithm |
| `reduce.hpp` | `barrett_reduce` result | `a − t·q` | `<= 1664`, value-preserving |
| `reduce.hpp` | `csubq`, `to_canonical` | result | `[0, q)`, value-preserving |
| `poly.cpp` | `poly_frombytes` ×2 | 12-bit field → `int16_t` | `<= 4095`, value-preserving; then `csubq` folds it into `[0,q)` |
| `poly.cpp` | `poly_decompress_dv` ×2 | `decompress_coeff<4>` result | `< q = 3329`, value-preserving |
| `poly.cpp` | `poly_frommsg` | `mask & 1665` | `<= 1665`, value-preserving |
| `polyvec.cpp` | `polyvec_decompress_du` | `decompress_coeff<10>` result | `< q`, value-preserving |

`barrett_reduce` deliberately does its subtraction in `int32` and narrows **once**, at a
point where the result provably fits. The reference lineage instead relies on a
deliberate `int16_t` wrap mid-computation; that would be invisible to the sanitizer and
is avoided here on purpose.

---

## Statistical power — why the differential, not `make kat`, is the real gate

Recorded here because it governs how the lazy-reduction log below must be validated.

Mutation M7 (`tests/kat/MUTATION.md`) shifted the `Compress_du` rounding addend by one.
It was caught by only **7 of 25** encaps vectors — about 21 % each, consistent with ~768
compressed coefficients each tripping with probability ~`1/3329`. Scale that bug down 10×
and the chance **all 25 encaps vectors miss it is ~56 %**.

The property tests cannot rescue this either: `decaps` re-encrypts, so a *symmetric*
compress bug reproduces identically on both sides and the roundtrip still succeeds.

**Therefore the model differential is the gate with real statistical power, not the 80
ACVP KATs.** The model is KAT-clean (ADR-002), so every differential comparison is
equivalent to a KAT test but can be run millions of times instead of 80.

```
make test           # 10^5 iterations, the default
make test-deep      # 10^7 iterations (MLKEM_DIFF_ITERS)
make bounds         # re-measure the observed column above
```

Heavy tests (anything invoking the model's `O(n²)` schoolbook) scale at `base/100`, since
each iteration costs ~100×. At the deep setting that still yields `10^5` schoolbook pairs,
which is what spec §5.3 asks for.

**This harness stays wired through Phase 8.** Every lazy reduction and every SIMD change
re-runs it at high count. A lazy-reduction change that passes `make kat` but has not been
through `make test-deep` is not validated.

---

## Verification method

```
make bounds                      # observed maxima, claimed bounds, margins
make bounds BOUNDS_ITERS=200000  # more random inputs
```

`-DMLKEM_TRACK_BOUNDS` compiles in `src/bounds_track.hpp`, which records a running
maximum at each instrumented site. It is header-only and emits nothing at all when the
macro is undefined, so the shipped library is unaffected.

The tool measures; it does not prove. See the argument section above.

---

## Equivalence under lazy reduction (Phase 8c precondition)

**Written and checked BEFORE the first reduction was removed.** Lazy reduction does not
change which answer the scheme computes; it changes **which int16_t representative of
that answer exists at intermediate steps**. So "is the output still correct?" needs a
definition sharper than "the bytes match", and the gates that enforce it have to be
checking the right thing before any value is allowed to drift.

The contract, in three parts:

1. **Intermediate coefficients may hold ANY `int16_t` representative of the correct
   residue class mod q.** They are not required to be canonical `[0, q)`, nor centered
   `|c| ≤ 1664`. What is required is that the representative FITS — every bound below is
   a proof that no `int16_t` overflows before the next reduction.
2. **The two backends stay BIT-IDENTICAL to each other.** A lazy change lands in the
   portable and AVX2 paths in the *same commit*, so this gate does not weaken; it is
   `tests/unit/test_avx2.cpp` and it still uses `memcmp`. If the two ever need to differ,
   that is a bug, not a consequence of laziness.
3. **At every serialization boundary the value is canonical `[0, q)` and the bytes are
   identical to the model's.** This gate does not weaken either — it is `gmake kat` and
   the byte-for-byte differentials in `test_kpke.cpp` / `test_kem.cpp`.

### What part (3) actually rests on, proven exhaustively

`poly_canonicalize` is `to_canonical(barrett_reduce(c))`. The whole phase depends on that
composition being **total over `int16_t`** — correct for an arbitrary representative, not
merely for inputs that happen to already be small. If it were wrong for even one value,
lazy reduction would corrupt ciphertexts at the boundary while every intermediate check
still passed.

Phase 2's finding is the precedent: `montgomery_reduce`'s contract was off by one at
exactly one input out of 218 169 345, and **only exhaustive evaluation found it**. The
domain here is `int16_t`, so exhaustive costs nothing.

| Property | Domain | Result |
|---|---|---|
| `barrett_reduce(a) ≡ a (mod q)` | **all 65 536 `int16_t`** | holds |
| `\|barrett_reduce(a)\| ≤ 1664` | **all 65 536 `int16_t`** | holds, and is tight (1664 attained) |
| `poly_canonicalize` → `[0, q)` with correct residue | every `int16_t` value, across 256 offsets | holds |

Checked in `tests/unit/test_arith.cpp`, "Phase 8c precondition" cases. **These run on
every `gmake test`; they are not a one-off.**

### Consequence for reading the rest of this file

Rows below that state a bound like `|c| ≤ 1664` at a layer boundary describe the
*current* reduction placement. When a reduction is removed, its row is **rewritten in the
same commit**, never appended to — a stale bound here is worse than no bound, because the
next lazy change will be justified against it.

---

## Lazy reduction log

Each entry: what reduction was removed, what bound now covers the path, and the
before/after cycle count. An entry with no measured speedup should be reverted — the
complexity is not free.

**Every entry must also record a `make test-deep` run at 10^7**, for the reason given
under Statistical power. `make kat` passing is necessary and not sufficient.

| Date | Reduction removed | Covering bound | Measured (pairwise, 24 alt. pairs) | test-deep | Notes |
|---|---|---|---|---|---|
| 2026-09-22 | **#1 `poly_basemul_acc`** — both `barrett_reduce` calls | `\|t\| ≤ 1664` exhaustively ⇒ `\|r\| ≤ k·1664 = 4992`; transient 6656; **binding consumer** `invntt`, input bound widened 1664 → 4992 | KeyGen **1.053×**, Encaps **1.070×**, Decaps **1.070×** | 109 cases, 2 097 959 827 assertions, 0 fail | `ntt`/`invntt` unchanged by this removal and measured **1.003×/1.001×** — the built-in sanity control |
| 2026-09-22 | **#2 `invntt` MONT side** — `barrett_reduce(mont_mul(..))` → `mont_mul(..)`; SUM side kept | `mont_mul` already gives `\|·\| < q`, so the barrett was canonicalization only. MONT half relaxes 1664 → 3328 ⇒ layer-1 `\|sum\| ≤ 9984`, `\|zeta·d\| ≤ 16 613 376` (15.2 % of strict) | `invntt()` **1.403×**; KeyGen 1.034×, Encaps 1.039×, Decaps 1.033× | 109 cases, 2 097 959 827 assertions, 0 fail | **both backends, one commit.** `ntt()` 0.997× = sanity control |
| 2026-09-22 | **#3 forward `ntt` butterfly** — both `barrett_reduce`, replaced by ONE `poly_reduce` at the end | `\|t\| < q` ⇒ a layer ADDS 3328: `B₇ = 3328 + 7·3328 = 26624` (81.3 % int16); mont input `≤ 1664·23296 = 38 764 544` (35.5 % strict). Final reduce **mandatory** — `basemul` would otherwise see `26624² ≫ q·2^15` | `ntt()` **2.393×**; KeyGen 1.053×, Encaps 1.036×, Decaps 1.040× | 109 cases, 2 097 959 827 assertions, 0 fail | **both backends, one commit.** `invntt()` 1.029× = sanity control. 1792 barretts → 256 |

**Observed vs derived after removal #1** (`gmake bounds`, real call shape):

| Site | Derived bound | **Observed** | int16 headroom |
|---|---|---|---|
| `acc \|r + t\|` | 4992 | **4992** — tight, not merely satisfied | 15.2 % |
| `invntt \|t + f[j+len]\|` | 9984 | 8778 | 26.8 % |
| `invntt \|f[j+len] − t\|` | 9984 | 8864 | 27.1 % |
| `invntt \|zeta·diff\|` → `montgomery_reduce` | 16 613 376 | 13 684 968 | 12.6 % of the **strict** `q·2^15` limit |

The accumulator bound is **attained exactly**, which is the outcome to want: the
derivation is not loose, so a future change that pushes it further has no hidden slack to
spend.

### Per-layer growth bound for the butterflies (sites #2 and #3)

**Derived and checked BEFORE any butterfly reduction was removed**, per the phase rule.

#### Forward `ntt` — fully lazy is safe, with ONE reduction at the end

Each butterfly writes `f[j] ± t` where `t = mont_mul(zeta, f[j+len])`, and `mont_mul`'s
contract gives `|t| < q`, i.e. `|t| ≤ 3328` **regardless of how large its input was**.
So a layer adds a constant, it does not scale:

```
B₀ = 3328                       (ntt's documented input bound — Decrypt feeds canonical [0,q))
Bᵢ = Bᵢ₋₁ + 3328
B₇ = 3328 + 7·3328 = 26624      81.3 % of int16_t's 32767  — ONLY ~19 % HEADROOM LEFT
```

The other constraint is `montgomery_reduce`'s **strict** `|a| < q·2^15`. Worst case is the
last layer, whose input is `B₆ = 23296`:

```
|zeta · f[j+len]| ≤ 1664 · 23296 = 38,764,544    vs 109,084,672    35.5 %
```

Both hold, so **both per-butterfly `barrett_reduce` calls can go**, provided a single
`poly_reduce` runs at the end of `ntt()` to restore `|c| ≤ 1664` for consumers — in
particular `basemul`, which multiplies two NTT outputs together and would otherwise see
**THE HEADROOM AFTER #3 IS ~19 %, NOT ~63 %.** The `gmake bounds` observation of 12 132
(37 % of `int16_t`) is what random traffic happened to reach; **the derived 26 624 is the
number that binds**, per this file's own rule that an argued bound is normative and a
measurement only corroborates it. Anything fused into the NTT output path in Phase 8d
spends that 19 %, and it is nowhere near as much slack as the observed figure suggests.

`26624² ≫ q·2^15`. That final reduction is not optional: **fully lazy with no final
reduce breaks `basemul`'s Montgomery contract**, which is the trap in this site.

Net: 1792 `barrett_reduce` calls (2 × 128 × 7) become 256.

#### Inverse `invntt` — only the MONT-side reduction is removable

The Gentleman–Sande butterfly is **asymmetric**, and this is the part the site register
originally got wrong by listing "2 × `barrett_reduce`" as one removable unit:

```
f[j]      = barrett(t + f[j+len])        <- SUM side: grows
f[j+len]  = barrett(mont_mul(zeta, d))   <- MONT side: already |·| < q before the barrett
```

The MONT side's `barrett_reduce` is pure canonicalization — `mont_mul` has already
bounded it — so removing it only relaxes `|f[j+len]|` from 1664 to 3328. **The SUM side's
`barrett_reduce` must stay.** Without it the sum side doubles every layer, `2⁷ = 128×`,
which overflows immediately. Removing "both" is not a bound question, it is simply wrong.

With the MONT-side reduction removed and `invntt`'s input bound at **4992** (widened by
removal #1):

```
layer 1:  |t + f[j+len]| ≤ 2·4992 = 9984        |zeta·d| ≤ 1664·9984 = 16,613,376  (15.2 %)
layer ≥2: sum side ≤ 1664, mont side ≤ 3328 ⇒ |sum| ≤ 4992, |d| ≤ 4992
```

#### Derived vs simulated

Simulation tracks the true per-layer maximum on in-range random input (`/tmp/growth.cpp`
method; the permanent check lands with the code change).

| Quantity | Derived | Simulated max | Status |
|---|---|---|---|
| forward `\|c\|` after 7 lazy layers | **26 624 (normative, 19 % headroom)** | 13 505 | holds; the simulation does not reach the worst case and must not be read as headroom |
| forward mont input | 38 764 544 | 19 971 546 | holds |
| inverse layer-1 `\|sum\|` | 9984 | **9983** | holds, effectively tight |
| inverse mont input | 16 613 376 | **16 548 525** | holds, tight to 0.4 % |
| inverse steady `\|c\|` | 3328 | 1908 | holds |

**A harness bug found while doing this, worth recording.** The first simulation reported
an inverse layer-1 sum of 29 934 against a derived 9984 — a factor of three. The
derivation was right; the harness was generating `(int)rnd() % 9985 - 4992`, and `%` on a
negative `int` is negative in C++, so the "input ≤ 4992" was really `[−14976, 4992]`. This
is the same failure the project hit in Phase 5 and 6a: **a synthetic harness confirming
the bound it was built with rather than the real one.** The rule stands — when simulation
and derivation disagree, suspect the harness first, and fix it before trusting either.

---

### Phase 8c site register — all candidates, with disposition

Enumerated up front so scope was fixed before work started, not discovered mid-phase.
**Nothing below is left silently unresolved**; each is either done or deferred with a
reason.

| # | Site | Backends | Status |
|---|---|---|---|
| 1 | `poly_basemul_acc` — 2 × `barrett_reduce` | portable only (no AVX2 basemul yet) | **DONE**, logged above |
| 2 | `ntt` butterfly — both `barrett_reduce`, **plus a final `poly_reduce`** | **both** (`ntt.cpp` + `ntt_avx2.cpp`) | **DONE** — logged above |
| 3 | `invntt` butterfly — **MONT-side `barrett_reduce` only**; the SUM-side one must stay | **both** | **DONE** — logged above |
| 4 | `basemul` internals — `barrett_reduce(c0)`, `(c1)` | portable only | **BLOCKED — UNSAFE while #1 stands.** Raises `\|t\|` to 2q ⇒ accumulator 19974 (fits) ⇒ **`invntt` layer-1 sum 39948, overflows int16**. See below |
| 5 | `poly_add_into` / `poly_sub_into` (`kpke.cpp`) | portable only | **WON'T DO — measured worthless.** Safe (`kat` 80/80 with it removed), 0.97× end-to-end. See below |
| 6 | `invntt` final scale, `poly_to_mont` — `barrett_reduce(mont_mul(..))` | **both** | **WON'T DO — measured worthless.** Canonicalization, not overflow protection; `invntt()` +7.8 % alone, 0.97× end-to-end. See below |
| 7 | `zetas_basemul` table halving (`gamma[2m+1] = −gamma[2m]`) | portable only | **NOT A REDUCTION** — table-size change; belongs with SIMD basemul in 8d |

**Why the remaining three are not done — each now settled by evidence, not judgement.**

**#4 `basemul` internals is UNSAFE, not merely deferred.** An earlier version of this row
said the bound "still fits". That was true of the accumulator and **false of its
consumer** — the exact failure this phase was built to avoid. Given site #1 already
removed the accumulator's reduction:

```
basemul output      |t| : 1664  ->  2q = 6658      (two mont_mul terms, each < q)
accumulator  |r| <= k*t : 4992  ->  19974          fits int16 (32767)
invntt layer-1 |t+f|    : 9984  ->  39948          *** OVERFLOWS int16_t ***
```

The accumulator IS `invntt`'s input — Encrypt and Decrypt feed it straight in. Removing
#4 would need a compensating reduction before `invntt`, which is precisely the reduction
#1 removed, cancelling that gain. **Do not attempt #4 without re-deriving #1 in the same
commit.**

**#5 and #6 were MEASURED, and are worth nothing.** Both were deferred on the reasoning
"safe for overflow but probably not worth the verification effort — measure first". That
measurement has now been done: both removed together, both backends, 20 alternating pairs.

| | KeyGen | Encaps | Decaps | `ntt()` | `invntt()` |
|---|---|---|---|---|---|
| #5 + #6 removed | **0.974x** | **0.970x** | **0.976x** | *1.003* | 1.078x |

`invntt()` alone does get ~7.8% faster, and it does not survive to the whole operation:
all three end-to-end figures sit just below 1.00 with the `ntt()` sanity control at 1.003.
At this host's +-3-4% floor that reads as "no gain", not "a loss" — but it is certainly
not a win, and neither site is worth the bound-verification effort or the extra unreduced
representative reaching `poly_tobytes`. `gmake kat` passes 80/80 on both backends with
them removed, so this is a value judgement, not a correctness one.

**#7 is not a reduction at all** — halving `zetas_basemul` via `gamma[2m+1] = -gamma[2m]`
is a table-size change that happened to share the list. It belongs with SIMD basemul in 8d.

**So of six actual reduction sites: three done, one unsafe while #1 stands, two measured
worthless.** That is the complete set — there is no fourth win waiting here.
