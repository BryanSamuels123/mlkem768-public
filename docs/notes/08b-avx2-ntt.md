# The AVX2 NTT (Phase 8b)

*Written for someone reading this codebase for the first time. Assumes you know what the
NTT is for; assumes nothing about SIMD.*

`ntt()` got **5.05×** faster and `invntt()` **4.99×** faster than the Phase 8a code — and
**8.74× / 8.19×** against the original Phase 7 scalar implementation. End to end that is
KeyGen **1.84×**, Encaps **1.84×**, Decaps **1.87×** cumulative since Phase 7.

Output is **bit-identical** to the portable transform. That is the whole basis on which
`gmake kat` gates this code, and it is why the file contains no new mathematics — only a
re-expression of `src/ntt.cpp` sixteen lanes wide.

---

## 1. What is actually being parallelised

The NTT is seven layers of butterflies. A layer of width `len` pairs coefficient `j` with
coefficient `j + len`, and the two outputs are

```
t      = ζ · f[j+len] · R⁻¹      (Montgomery multiply)
f[j+len] = barrett(f[j] − t)
f[j]     = barrett(f[j] + t)
```

Every butterfly in a layer is independent of every other. Nothing is read after it is
written within a layer, there are no data-dependent branches, and the multiplier ζ is
constant across a whole group. That is the ideal shape for SIMD: sixteen `int16_t` fit in
one 256-bit register, so one instruction does sixteen butterflies' worth of an operation.

The work is therefore *not* in the arithmetic. It is in **getting partners into the same
lane position**, which is §3.

---

## 2. Doing modular arithmetic without leaving 16 bits

Both reduction primitives had to return exactly what `src/reduce.hpp` returns, lane for
lane. Both are proven so **exhaustively**, not by sampling — `barrett_reduce_vec` over all
65 536 `int16_t`, `mont_mul_vec` over all 8 388 608 (a, ζ) pairs — in
`tests/unit/test_avx2.cpp`.

### Montgomery multiply — 3 multiplies, no widening

Scalar: `p = a·z`, `m = (int16)(lo16(p)·QINV)`, result `= (p − m·q) >> 16`.

The trick is that `p − m·q` is divisible by 2¹⁶ **by construction** — `m ≡ p·QINV (mod 2¹⁶)`
and `q·QINV ≡ 1 (mod 2¹⁶)`, so the low halves are equal and cancel with no borrow.
Therefore the shifted result is just the difference of the high halves:

```c
m  = _mm256_mullo_epi16(a, zqinv);   // = lo16(a·z)·QINV
hi = _mm256_mulhi_epi16(a, z);       // hi16(a·z), signed
t  = _mm256_mulhi_epi16(m, q);       // hi16(m·q), signed
r  = _mm256_sub_epi16(hi, t);
```

No 32-bit widening anywhere. **`zqinv` is `z·QINV mod 2¹⁶`, precomputed** — multiplication
mod 2¹⁶ is associative, so `mullo(a, z·QINV) == mullo(mullo(a,z), QINV)`, which saves one
`vpmullw` per butterfly. That is why the zeta tables are stored in pairs (ζ and ζ·QINV);
it is the single cheapest win in the file and it is invisible unless you know to look for
it. (Learned from pq-crystals — §7.)

### Barrett — the rounding term becomes a constant add

Scalar: `t = (V·a + 2²⁵) >> 26; r = a − t·q`, with `V = 20159`.

`mulhi(a,V)` is `floor(V·a / 2¹⁶)`. Writing `V·a = hi·2¹⁶ + lo` with `0 ≤ lo < 2¹⁶`:

```
(V·a + 2²⁵) >> 26  ==  floor((hi + 512 + lo/2¹⁶) / 1024)  ==  floor((hi + 512) / 1024)
```

because for an integer `X` and `0 ≤ f < 1`, `floor((X+f)/1024) == floor(X/1024)` — `X+f`
cannot reach the next multiple of 1024 unless `X` already is one. So the rounding constant
`2²⁵` collapses into a `+512` before an arithmetic shift by 10, and again nothing widens.

---

## 3. The layers, and where the difficulty actually is

256 coefficients = 16 vectors. Vector `v` holds coefficients `16v … 16v+15`.

**Layers `len = 128, 64, 32, 16` are easy.** Partners live in *different* vectors —
`v ↔ v+8`, `v+4`, `v+2`, `v+1` — so the butterfly is a plain vector operation on two
registers, with one broadcast ζ per group. No data movement at all.

**Layers `len = 8, 4, 2` are the problem.** Partners live *inside* one vector, so the
vector must be split first. Taking vectors in pairs `(V₂ᵤ, V₂ᵤ₊₁)` and producing an `A`
half and a `B` half keeps everything 256 bits wide:

| len | granularity | split | recombine |
|---|---|---|---|
| 8 | 128-bit | `permute2x128(V0,V1,0x20)` / `(…,0x31)` | `permute2x128(A,B,0x20)` / `(…,0x31)` |
| 4 | 64-bit | `unpacklo_epi64` / `unpackhi_epi64` | `unpacklo_epi64(A,B)` / `unpackhi_epi64(A,B)` |
| 2 | 32-bit | `shuffle_epi32(·,0xD8)` on each, then as len = 4 | as len = 4, then `shuffle_epi32(·,0xD8)` again |

`shuffle_epi32(v, 0xD8)` reorders the four 32-bit elements of each 128-bit lane as
`[0,2,1,3]`. It is an **involution**, so the same instruction undoes it — convenient, and
worth knowing before you go looking for an inverse shuffle that does not exist.

---

## 4. The genuinely dangerous part: which ζ goes in which lane

After a split, the sixteen lanes of `A` **no longer hold sixteen consecutive
coefficients.** They hold an interleaving determined by the exact intrinsic used. For
`len = 2` the ζ layout works out to

```
[ z(8u+0) z(8u+1) z(8u+4) z(8u+5) z(8u+2) z(8u+3) z(8u+6) z(8u+7) ]     two lanes each
```

Nobody should write that by hand. One wrong lane produces a transform that is entirely
self-consistent and fails every KAT — the same failure class as a transposed `Â`
(docs/reference/kat-failure-checklist.md #3), and just as hard to find by staring at it.

So `src/arch/avx2/zetas_avx2.hpp` **generates** the tables: `consteval` helpers mimic each
shuffle on an array of coefficient *indices*, and the ζ for a lane is then looked up from
whichever coefficient landed there. There is only one description of the permutation, so
the table and the code cannot silently disagree.

A mimic is still hand-written code describing a hardware permutation, so
`tests/unit/test_avx2.cpp` closes the loop the other way: it applies the **real
intrinsic** to an index array at runtime, reads off where each index actually landed, and
independently recomputes which ζ the **scalar** algorithm assigns to that coefficient by
replaying Algorithm 9/10's own counter. Three independent descriptions must agree.

---

## 5. The error in the recorded design

The Phase 8b design was written out in `docs/reference/invariants.md` at the end of the previous session
and the instruction was to execute it, not re-derive it. One thing in it was **wrong**,
and it surfaced immediately on implementation:

> The design gave a single uniform ζ-index formula, `k = k_base + i/(2·len)`, and assumed
> the inverse transform could reuse the forward lane tables.

**It cannot.** Algorithm 9 counts `k` **up** from 1; Algorithm 10 counts it **down** from
127. A layer has exactly `k_base` groups, so the inverse's group `s` uses

```
k = (2·k_base − 1) − s
```

i.e. each layer's ζ sequence is the forward layer's **reversed** — `len=2` runs
`127…64` where the forward ran `64…127`, and so on. Sharing the tables would have produced
a self-consistent inverse transform that failed every KAT.

The forward half of the design — the layer/vector mapping, the split/recombine shuffles,
the SIMD forms of both reduction primitives, the `len = 2` ζ layout — was correct as
recorded, and the generated table reproduced the predicted layout exactly.

Separate inverse tables (`kLane8Inv`, `kLane4Inv`, `kLane2Inv`) are generated from the
same shuffle mimics with `zeta_index_inv`, and a `static_assert` requires them to differ
from the forward ones, so a future edit cannot quietly collapse the two again.

---

## 6. Constant-time status, and why a clean ctgrind run needed a new control first

The NTT runs on `ŝ`, `ê`, `ŷ` and the decrypt path — secret material. It must be
constant-time, and it is by construction: no branches on coefficients, no table lookups
indexed by data, no division, fixed shuffle patterns.

**The clean ctgrind result could not simply be believed, and ADR-025 forbids citing the
Phase 8a proof here.** That proof (`--x4-taint`) showed definedness survives the 4-way
Keccak's instruction set — gathers, xors, 64-bit shifts, `pshufb`, `perm2f128`. But
**Keccak-f contains no multiply at all**, so it says nothing about `vpmullw`, `vpmulhw`,
`vpsraw`, or about `vpshufd` / `vpunpck*qdq` / `vperm2i128`. Those are precisely what this
file is built from. If memcheck modelled any of them as producing *defined* output from
undefined input, a clean run would be clean for the wrong reason.

So `tests/ct/ct_ntt.cpp --ntt-taint` marks a polynomial secret, runs `ntt()` and
`invntt()`, and branches on outputs while still secret. **valgrind must report, and
does.** Only then is `--secret`'s zero-findings result evidence, and the Makefile runs
them in that order deliberately.

**Which coefficients to probe was measured, not reasoned about** — and the first attempt
got it wrong. The original comment claimed coefficients 0, 255 and 7 "span both 128-bit
lanes"; coefficient 7 is lane 7 of vector 0, the *same* half as coefficient 0, so the span
rested entirely on 255. Rather than restate the claim more carefully, `--taint-map` now
measures it: `VALGRIND_GET_VBITS` reads memcheck's definedness shadow directly, without
emitting an error, and asserts that **all 256 output coefficients are tainted in both
directions**. They are, today — so any single probe point would suffice. The multi-point
probe is kept anyway, spanning both halves of the first and last vectors, because
complete propagation is a property of the current code and not a law; `--taint-map` is
what will notice the day a removed reduction or a different shuffle changes it.

---

## 7. What I took from pq-crystals, in my own words

Per ADR-022 the policy is study-then-write, and the honest accounting is:

**I did not open `avx2/ntt.S` during this implementation session.** The design executed
here was derived in the previous session and recorded in `docs/reference/invariants.md`; this session
implemented that record. One technique in it is theirs and I want it attributed properly
rather than absorbed silently:

1. **Store ζ·QINV alongside ζ, and do it like this.**

   The Montgomery reduction needs `m = lo16(a·z)·QINV`. Written literally that is two
   packed multiplies, and the whole reduction is four:

   ```c
   lo = _mm256_mullo_epi16(a, z);        // lo16(a·z)
   m  = _mm256_mullo_epi16(lo, qinv);    // ·QINV          <-- second multiply
   hi = _mm256_mulhi_epi16(a, z);
   t  = _mm256_mulhi_epi16(m, q);
   r  = _mm256_sub_epi16(hi, t);
   ```

   Multiplication mod 2¹⁶ is associative and `mullo` *is* multiplication mod 2¹⁶, so

   ```
   lo16( lo16(a·z) · QINV )  ==  lo16( a · lo16(z·QINV) )
   ```

   `z` is a compile-time constant here, so `z·QINV mod 2¹⁶` can be precomputed and the
   first two multiplies collapse into one:

   ```c
   // table holds, for each zeta: z  and  zq = (uint16)(z * QINV)
   m  = _mm256_mullo_epi16(a, zq);       // one multiply, same m as above
   hi = _mm256_mulhi_epi16(a, z);
   t  = _mm256_mulhi_epi16(m, q);
   r  = _mm256_sub_epi16(hi, t);
   ```

   Four multiplies become three, in the innermost loop of the hottest function in the
   scheme. Compute `zq` in `uint32` and truncate — a `uint16 × uint16` product promotes
   to `int` and overflows it, which `consteval` rejects outright (that is `qinv_of` in
   `zetas_avx2.hpp`, and the error is how I found out).

   I would have written the four-multiply version and not noticed. Seeing their paired
   tables is what prompted the question "why is this table twice as wide as it needs to
   be?".

2. **Split the last layers pairwise rather than working on one vector.** The instinct is
   to handle a vector's internal butterflies with a self-shuffle. Processing *two* vectors
   into an `A`/`B` pair keeps both operands full-width, and the recombine is the same
   instruction as the split. That symmetry is what makes the three intra-vector layers
   read almost identically.

The rest — the layer mapping, the ζ-index formula and its inverse correction, the
generated lane tables and their three-way verification — is written here.

---

## 8. If you are about to change something here

* **Bit-identity is the contract.** Any change must keep the AVX2 output equal to
  `generic::ntt`/`generic::invntt`, lane for lane. `gmake test` checks it over 3000 random
  polynomials at three bound shapes; `gmake kat` checks it end to end.
* **Do not fold lazy reduction in here.** That is Phase 8c and it *changes the values*, so
  it breaks the bit-identity gate. It has to land in both backends at once, with
  `docs/bounds.md` updated in the same commit.
* **Verify the dispatch actually dispatches.** Perturbing one vector in the AVX2 `ntt()`
  must make the default `kat` run fail while `MLKEM_FORCE_ARCH=portable` still passes.
* **`-DMLKEM_TRACK_BOUNDS` forces the portable path on purpose** (`src/ntt.cpp`). The AVX2
  path has no `MLKEM_TRACK` instrumentation, so dispatching to it under a bounds build
  would report zero observations and `docs/bounds.md` would be measuring nothing.
* **If you add another SIMD backend, it needs its own taint control** before its clean
  ctgrind run means anything. ADR-025: do not generalize a taint proof across instruction
  classes.
