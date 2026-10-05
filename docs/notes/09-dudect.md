# Phase 9b — dudect: statistical timing verification

*2026-09-29. Decisions in `DECISIONS.md` ADR-035. Run with `gmake dudect`.*

---

## 1. What dudect measures, and why ctgrind is not enough

`gmake docker-ctgrind` proves the absence of secret-dependent **branches** and
**secret-derived memory addresses**. It does that by marking secrets as uninitialized and
letting valgrind object when control flow or an address depends on them.

It is structurally blind to code that leaks **without** either. A variable-latency
instruction on secret data has no branch and no secret index — `div` is the canonical
case, and it is the one that broke the pq-crystals reference in 2023 (KyberSlash). ADR-016
has the measured blind-spot matrix; the short version is:

| tool | catches | blind to |
|---|---|---|
| ctgrind | secret branches, secret indices, early-exit compares | `div`/`mod` timing; a flattened `if (secret & 1)` at `-O3` |
| `audit-div` | every `div`/`idiv` in the library, at machine level | whether a given divisor is secret; anything not a division |
| **dudect** | **microarchitectural timing variation** | **needs statistical power; noisy** |

dudect feeds two input classes — one fixed secret, one random — and applies Welch's t-test
to the timing distributions. A large |t| says the two distributions differ, i.e. runtime
depends on the secret.

**Gate: |t| < 10** (spec §8.4). **10 is the lenient bar** — dudect's own "moderate"
threshold. The stricter leakage-assessment convention is **4.5**, so anything between the
two is named in the output rather than passed silently.

**|t| answers "is the difference real?", never "is it big?"** At 285 000 measurements
|t| = 10 corresponds to a mean gap of roughly 0.05 ticks. The harness therefore reports a
`dmean` column in ticks alongside every |t|. This matters more than it sounds — see §4.

---

## 2. Calibration — and the two harness bugs it caught

The t-test here is hand-written (ADR-035 explains why dudect.h was not vendored despite
being MIT). **A t-test that cannot report a leak is a gate that cannot fail**, so
calibration runs first and `gmake dudect` fails if a planted leak is missed.

### KyberSlash-shaped plant

A secret-dependent division, the exact 2023 bug class, planted in the test TU only:
detected at **|t| ≈ 2900**.

The plant forces a real `div` with a `volatile` divisor purely to prove the harness can
see the leak class. It never enters the library, so `audit-div` stays clean.

**Why this library is not vulnerable — stated correctly.** The reason is *not* that `q` is
a compile-time constant. The pq-crystals divisor was a constant too; whether it became a
`div` instruction depended on the compiler and flags, which is why KyberSlash affected some
builds and not others. The two real reasons are:

1. **The source never divides secret data.** Phase 4 derived a multiply-shift with
   `consteval` and proved it exhaustively over every input, so there is no division in the
   source for any compiler to make a decision about.
2. **`gmake audit-div` proves no `div`/`idiv` survives in `libmlkem768.a`**, at the machine
   level, including instructions the compiler inserts that appear nowhere in the source.

Reason 1 alone is a source-level argument that a different toolchain could invalidate.
Reason 2 is what makes it a checked property of the binary that actually ships.

### The delay ladder was wrong, and the ladder exposed it

First version: `if (secret_bit) { loop N times; }`. It reported |t| ≈ 140 for N = 1000 and
for N = 1 **alike** — completely flat.

It was not measuring a delay of N cycles. The signal was the **presence of the branch**,
whose misprediction cost is roughly constant whatever the body does. A ladder that does
not vary what it claims to vary produces the illusion of a sensitivity, not a sensitivity.

Rewritten so the loop always runs with a fixed baseline and the secret adds `delta`
iterations, it scales as it should:

| planted delta | max \|t\| |
|---|---|
| 1000 cycles | 124 |
| 100 | 129 |
| 10 | 118 |
| 3 | 67 |
| 1 | **22.8** |
| **0 (null control)** | **1.41 — clean** |

### The null control then failed, and it was a real bug

At delta = 0 nothing leaks, so the harness must report clean. It reported **|t| = 10.5**.

The cause was in `prepare()`: it did *different work per class*. Class 1 ran hundreds of
RNG steps that class 0 did not, immediately before the timed region, leaving different
cache and branch-predictor state — perfectly correlated with the class label. **Every
target had this.** Fixed by always generating the random input and then selecting
branchlessly, so both classes execute identical instructions and only the resulting bytes
differ.

> **Sensitivity of the calibration loop: a 1-cycle secret-dependent delay is detected at
> |t| ≈ 22.8 with 40 000 measurements, against a null control of 1.41.**

**That figure does not transfer, and saying it did was wrong.** It is measured on a
~200-cycle loop with low variance. `decaps` is ~40 000 ticks with variance orders of
magnitude larger, so a 1-cycle leak inside `decaps` is invisible. A sensitivity is a
property of the *target*, not of the harness.

### 2b. In-context calibration — what "top-level clean" actually means

The same ladder was planted **inside `decaps`'s secret-dependent path**: a branchless
delay gated on `m_prime[0] & 1`, where `m_prime` is secret. Library source is never
modified in the repo — the plant lives in a `git worktree`, the same method the zeroization
controls use.

Confirmed to survive `-O3` by disassembly before trusting any result — it is a real loop
with a back edge, gated on the secret:

```
movzbl -0x50(%rbp), %eax     ; m_prime[0]
andl   $0x1, %eax            ; the secret bit
negl   %eax                  ; mask
andl   (%rip), %eax          ; & plant_delta
1f0:  addq $0x1, %rcx        ; <-- the delay loop
      decl %eax
      jne  0x1f0
```

Ladder on `decaps fixed-vs-random dk`, both fixed-class values:

| planted delta | 38 000 samples | 250 000 samples |
|---|---|---|
| 400 cycles | 22.6 / 59.4 — LEAK | 86.7 / 64.5 — LEAK |
| 200 | 22.5 / 30.1 — LEAK | 44.7 / 70.2 — LEAK |
| **100** | **20.3 / 31.1 — LEAK** | **13.6 / 26.1 — LEAK** |
| 50 | 1.5 / 3.4 — **missed** | 7.3 / 2.0 — **missed** |
| 20 | 7.8 / 6.7 — marginal | 20.3 / 18.0 — erratic |
| 10 | 1.9 / 4.7 — missed | 10.7 / 1.3 — erratic |
| **0 (null)** | 2.5 / 1.3 — clean | 2.0 / 3.1 — clean |

> **The top-level floor is ~100 cycles.** Detection is reliable at 100 and above, fails at
> 50, and is erratic below that. More samples do not help much — the variance is decaps's
> own, not the counter's. So **"top-level clean" means clean to roughly ±100 cycles of
> secret-dependent timing**, about 0.22 % of a ~45 000-tick operation. It does **not** mean
> clean to one cycle.

---

## 3. Class design — ADR-020's lesson, applied to timing

**Any value FIPS 203 makes public is held constant across both classes.** This is not
fastidiousness. Varying a KeyGen seed varies ρ, which varies `sample_ntt`'s rejection-loop
trip count — and `sample_ntt` is *deliberately* variable-time (spec §8.1). A test that let
ρ vary would correctly report a timing difference that is not a leak, and "correctly
reports a non-leak" is how a gate becomes noise.

| target | fixed | varies |
|---|---|---|
| `ntt` | nothing public in scope | secret polynomial coefficients |
| `invntt` | nothing public in scope | secret polynomial coefficients |
| `basemul` | `b`, the public Â operand | `a`, the secret ŝ operand |
| `sample_poly_cbd<2>` | nothing public in scope | the secret `PRF(σ,N)` buffer |
| `polyvec_compress_du` | nothing public in scope | `u`, derived from the secret `r` |
| `poly_tomsg` (Compress_1) | nothing public in scope | `w`, the secret decrypted poly |
| `decaps` valid-vs-invalid | **dk, ek, ρ byte-identical** | ciphertext validity — public, **and that is the point** |
| `decaps` fixed-vs-random dk | **ek and H(ek)**, so ρ and Â identical | `dk_PKE` (secret `s`); both classes reject |
| `encaps` fixed-vs-random m | **ek**, so ρ and the matrix expansion | `m`, the secret message |

Two deliberate choices worth stating:

- **valid-vs-invalid ciphertext varies a PUBLIC value on purpose.** Spec §10.3 requires
  decaps runtime to be independent of ciphertext validity, so the public variation *is*
  the property under test. It is attributed explicitly rather than called a leak.
- **fixed-vs-random dk makes BOTH classes implicitly reject.** A fixed *valid* dk against
  a random invalid one would confound "does timing depend on the key bits" with
  "does timing depend on accept-vs-reject", which is the previous test's job.

**Two fixed-class values per test**, as required: all-zero and a fixed random value. An
all-zero secret can hit special cases a random one never does, and vice versa. They do
differ in practice — `sample_poly_cbd` read 1.97 (zero) against 17.51 (random) on one run
— which is exactly why reporting only one would have been misleading.

---

## 4. Results

`gmake dudect`, macOS host, native. Component targets 285 000 measurements each,
top-level 38 000. Every row carries its own **attributability control**: the same target
with *both* classes held to a constant (different) value, where nothing secret-dependent
can appear.

### Top-level — these are the gate

Clean across three seeds and both fixed-class values.

| target | fixed | max \|t\| | meas | control | verdict |
|---|---|---|---|---|---|
| `decaps` valid-vs-invalid ct | zero | 2.30 | 38 000 | 2.48 | clean |
| `decaps` valid-vs-invalid ct | random | 1.31 | 38 000 | 2.74 | clean |
| `decaps` fixed-vs-random dk | zero | 2.19 | 38 000 | 2.25 | clean |
| `decaps` fixed-vs-random dk | random | 1.85 | 38 000 | 2.09 | clean |
| `encaps` fixed-vs-random m | zero | 2.56 | 38 000 | 1.63 | clean |
| `encaps` fixed-vs-random m | random | 1.56 | 38 000 | 3.37 | clean |

Worst top-level |t| observed over three seeds: **6.99** (`decaps` fixed-vs-random dk,
random), above the 4.5 convention and below the spec's 10 — named, not waved through.

**Spec §10.3 is satisfied: decaps runtime does not depend on ciphertext validity**, and
implicit rejection is not distinguishable by timing at this resolution.

### Component level — batched, discriminated, and decided per row

Three things changed since the first attempt, each because the earlier reasoning did not
hold up.

**(a) Batched timing, K = 32 repetitions per rdtsc pair.** One `rdtsc` pair costs tens of
ticks and quantizes to 1, which for a 300-tick function is a large fraction of the
measurement. Batching amortizes both.

*It was wrong to discount |t| = 40 as "below rdtsc resolution".* Averaging resolves mean
gaps well under one tick, and the t-statistic already accounts for noise. The right move
was to fix the instrument and re-measure — which changed the numbers dramatically:

| target (fixed-vs-fixed control) | before batching | with K = 32 |
|---|---|---|
| `ntt` | 42.2 | 2.1 |
| `invntt` | 54.3 | 1.9 |
| `polyvec_compress_du` | 55.5 | 3.9 |
| `poly_tomsg` | 15.5 | 2.0 |

So most of the original signal *was* instrument overhead — but established by
intervention, not by an argument about resolution.

**(b) The value-vs-placement discrimination.** The earlier claim that the attributability
control was "evidence against a leak" was wrong: two constant inputs with different mean
timing means timing depends on something differing between the classes — the values
(which for secret inputs *is* a leak) or where they sit in memory.

Placement is already controlled by construction here: every target writes both classes'
input into the **same** working buffer before the timed region, so address, alignment and
cache set are identical. The remaining test is the swap — exchange which value each class
uses, keep the class label. If the difference follows the value, `dmean` flips sign.

**(c) Per-row decisions**, at 1.9 M samples, K = 32:

| target | fixed-vs-random | fixed-vs-fixed | swap | decision |
|---|---|---|---|---|
| `invntt` | 2.7 / 3.2 | 6.1 / 4.8 | — | **clean under batching — gated** |
| `polyvec_compress_du` | 5.6 / 4.4 | 3.2 / 4.0 | — | **clean under batching — gated** |
| `basemul` | 11.9 / 2.9 | 3.1 / 2.3 | no consistent flip | not value-dependent; erratic across seeds — advisory |
| `sample_poly_cbd<2>` | 10.3 / 8.3 | 5.4 / 9.2 | inconsistent | not value-dependent; `dmean` sign wanders at <0.2 ticks — advisory |
| `poly_tomsg` | **31.5 / 19.9** | **1.8 / 4.9 — clean** | n/a | **construction artifact, explained below** |
| `ntt` | 6.2 / 11.1 | **13.9 / 9.7** | **flips in both** | **value-following, unexplained — advisory, see below** |

**`poly_tomsg` is decided: not a value leak.** It has the largest and most consistent
fixed-vs-random signal in the suite — |t| = 31.5 at 1.9 M, `dmean` positive in all eight
runs (+2.3 to +4.8 ticks per 32 calls) — which looked like the one real finding. But with
**both** classes held constant at *different* values it is **clean (1.8 / 4.9 at 1.9 M)**.
Timing therefore does not depend on the input's value; it depends on whether the input
**changes between measurements**, which is a property of the fixed-vs-random class
construction and not of the secret. An attacker chooses the inputs and already knows
whether they repeated.

**`ntt` is not decided, and I am not calling it clean.** Under fixed-vs-fixed it reaches
|t| = 13.9 / 9.7 at 1.9 M and `dmean` **flips sign under the swap** for both fixed values
(−2.18 → +3.37 and −7.27 → +5.15). By the discrimination criterion that is
value-following. Against that:

- The magnitude is **~0.07 ticks per call** (2–7 ticks per 32 calls) — two to three orders
  of magnitude below the ~100-cycle floor at which anything is detectable at the API.
- There is **no architectural mechanism**. The AVX2 NTT is branchless SIMD; `vpmullw`,
  `vpmulhw`, `vpaddw`, `vpsubw` have operand-independent latency on every current x86, and
  `audit-div` proves no division anywhere in the library.
- The swap test **cannot separate algorithmic value-dependence from data-dependent
  switching power**, and the latter also follows the value. It is strongest with the
  all-zero fixed class, where switching contrast is maximal — which is what a power
  effect predicts and which no constant-time *software* can remove.
- Across seeds it is erratic (2.1, 6.3, 13.9, 3.5), so it is not reproducibly over the gate.

Deciding this needs a different instrument than dudect — a power/frequency-aware
measurement, or a core with a fixed clock. **Recorded as advisory with that reason, not
waved through.**

### Deciding `ntt` — differential controls, not argument

`ntt` was the one row the swap test marked value-following. The switching-power explanation
never fitted the design: frequency scaling reacts over tens of microseconds, one K=32
measurement is ~2 µs, and the class is randomized per measurement, so a frequency excursion
should smear across both classes rather than align with one.

So it was decided the way interop decided serialization — by differential control. Three
implementations, **identical harness**: same K, sample count, fixed values, fixed-vs-fixed
and swap controls. `gmake dudect-ntt-diff`.

| implementation | value-follows | max \|dmean\| | max \|t\| (fixed-vs-fixed) |
|---|---|---|---|
| A: **our AVX2 ntt** | 2/2, 2/2, 1/2 | 1.1 – 2.9 | **2.4 – 10.0** |
| B: our portable **scalar** ntt | 2/2, 0/2, 0/2 | 12.8 – 42.1 | **1.7 – 4.8 — not significant** |
| C: **pq-crystals** AVX2 ntt | 1/2, 2/2, 1/2 | 3.2 – 4.4 | **7.3 – 22.7** |

Read the **|t|** column, not `|dmean|`: `|dmean|` is a raw gap in ticks and scales with how
long the function runs, while |t| is the gap measured against its own noise. The scalar NTT
is ~30× slower than the AVX2 one, so its larger `|dmean|` at an insignificant |t| says
nothing.

Three seeds. **The conclusion rests on row C, the pq-crystals comparison** — read the rows
precisely, because two of them say less than they appear to:

- **C is the decisive row.** pq-crystals' AVX2 NTT — an independent implementation, same
  machine, same harness — shows the effect at |t| = 7.3–22.7, *above* our 2.4–10.0. Both
  AVX2 implementations show it, and theirs more strongly.
- **B is INCONCLUSIVE, not a stronger showing.** Its `|dmean|` is larger (12.8–42.1), but its
  fixed-vs-fixed **|t| is only 1.7–4.8 — not significant**. The scalar NTT is roughly 30×
  slower than the AVX2 one, so a larger raw gap sitting inside proportionally larger noise is
  evidence in neither direction. Its flip counts are noise for the same reason. B neither
  supports nor undermines the conclusion; it is reported because it was measured.
- **A has the smallest `|dmean|` of the three**, which is not what a defect in it would look
  like — but on its own that is a weak signal, and the argument does not lean on it.

> **`ntt` is decided: both AVX2 implementations show a tiny value-dependent effect, which
> points to this CPU running this class of code rather than to anything this implementation
> introduced.** Not a red gate.
>
> **Bounded at ≤ ~0.2 ticks per call — not zero.** The claim is that the effect is not ours
> and is far below the ~100-cycle floor at which anything is observable at the API, not that
> no effect exists.

This also reframes the other advisory rows: the same ~0.02–0.2 ticks-per-call effect turns
up on whatever code is put through this harness, which is why per-row verdicts below that
magnitude were never going to be stable.

### `poly_tomsg` — the similarity test, and what it did NOT settle

"Follows novelty, not value" assumed the effect keys on *exact* repetition. If it graded
with partial similarity between successive inputs it would carry information about how much
the secret-derived `w` changed, which an attacker does not choose. `gmake dudect-tomsg-sim`
tests three regimes: class 0 constant throughout, against class 1 as (i) a fresh random `w`,
(ii) the same base `w` with **one coefficient** changed each measurement, (iii) a second
constant `w`.

At 1.9 M samples, K = 32:

| regime | max \|t\| | dmean per call (ticks) |
|---|---|---|
| NOVEL (fixed vs random) | 12.2 – 16.7 | −0.03 … +0.17 |
| NEAR-REPEAT (1 coeff differs) | 13.5 – 19.0 | −0.02 … +0.21 |
| REPEAT (both constant) | 7.2 – 12.2 | +0.01 … +0.15 |

> **INCONCLUSIVE, and the harness says so rather than picking a side.** The REPEAT
> baseline — where nothing varies between the classes except one constant value — reads as
> high as NOVEL. This standalone harness's own floor is therefore as large as the difference
> under test, so near-repeat cannot be placed against either baseline. The earlier
> "novelty, not value" reading is **not confirmed**; it is also not contradicted.

What *is* established, and it is the part that matters:

- **Every per-call gap is ≤ ~0.2 ticks**, against a **~100-cycle** top-level detection
  floor — a factor of several hundred. Nothing at this magnitude is observable at the API.
- The same small value-following effect appears in **pq-crystals' independent code** (the
  `ntt` differential above), so it is not a property of `poly_tomsg` or of this project.

Deciding novelty-versus-similarity would need an instrument with a lower floor than this
one: a fixed-clock core, or performance counters rather than `rdtsc`. Recorded as open, with
the magnitude bound stated, rather than resolved by assertion.

**What supports the clean top-level result independently**

- `docker-ctgrind` is green on the same code, covering branch and index leak classes.
- `gmake audit-div` reports **zero** `div`/`idiv` in the library — the instruction class
  dudect exists to catch and the one behind KyberSlash.
- Any component effect large enough to matter would have to surface in `decaps`, which
  calls these routines on secret data many times over; decaps is clean and stable, and its
  measured floor is ~100 cycles against component effects of ~0.1 cycle per call.

## 5. Where it runs

**Host, natively.** Docker on this Mac is a VM: it interposes a virtualization layer on
exactly the quantity being measured, and timing behaviour is a property of the silicon,
not the OS image. `gmake docker-dudect` exists for comparison only.

`gmake dudect` is deliberately **out of `docker-all`**, for that reason plus runtime.

```
gmake dudect                          default budget, ~4 min (each row + its control)
gmake dudect DUDECT_ARGS=--quick      smoke test
gmake dudect DUDECT_ARGS=--deep       2M/250k measurements
gmake dudect DUDECT_ARGS=--calibrate  calibration and sensitivity only
gmake dudect DUDECT_ARGS=--null-check every target with both classes random
gmake dudect DUDECT_ARGS=--fixed-vs-fixed   both classes constant
```

---

## 6. Open items

- [ ] **Batched component timing** (time K repetitions per sample). Until then the
      component rows stay advisory. This is the one thing standing between Phase 9b and a
      component-level verdict.
- [ ] Re-run after any change to the SIMD code paths; Phase 8's AVX2 NTT, SIMD CBD, SIMD
      basemul and SIMD compress are the surfaces ADR-029 flagged as never timing-tested,
      and they remain only top-level-covered.
