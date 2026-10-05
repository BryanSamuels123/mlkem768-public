# 4-way batched Keccak (Phase 8a)

*Written for someone reading this codebase for the first time, not for a resuming
session. It assumes you know what ML-KEM is and roughly what a sponge is, and nothing
about SIMD.*

Phase 8a made `KeyGen` **1.41×**, `Encaps` **1.38×** and `Decaps` **1.32×** faster on
this machine by changing *how the hashing is driven*, not by changing a single byte of
what gets hashed. The output is bit-identical to the scalar path, which is the whole
reason this optimization can be trusted: `gmake kat` gates it.

---

## 1. The idea in one paragraph

ML-KEM spends most of its time in SHAKE. Almost all of that time is in one function —
the Keccak-f[1600] permutation — and almost all of *those* calls are part of streams
that have nothing to do with each other. Expanding the matrix `Â` needs nine
independent SHAKE-128 streams; drawing the noise needs six or seven independent
SHAKE-256 streams. Run one at a time, each stream leaves most of a 256-bit vector
register empty. Run four at a time, stacked one per lane, and a single instruction does
four sponges' worth of work. That is the entire trick. Everything below is detail about
why it's sound and where it applies.

---

## 2. Why Keccak vectorizes so cleanly

The Keccak-f[1600] state is a 5×5 array of 64-bit **lanes** — 25 lanes, 1600 bits.
The permutation is 24 rounds of five steps (θ, ρ, π, χ, ι), and every one of them is
built from exactly three kinds of operation:

* bitwise XOR / AND / NOT between whole lanes,
* rotation of a lane by a fixed, compile-time-constant amount,
* permuting *which* lane goes where, also by a fixed pattern.

Notice what is **not** in that list: no addition with carries, no table lookups, no
comparisons, no data-dependent branches, no multiplication. Every round does the same
work on every input. That is why Keccak is constant-time to begin with, and — the point
here — it is also why it vectorizes without any of the usual friction.

### The layout

The scalar state is `uint64_t s[25]`. The 4-way state is:

```c
typedef struct { __m256i s[25]; } keccakx4_state;   // third_party/fips202/fips202x4.h
```

Same 25 entries, but each is now 256 bits wide, holding **lane *i* of four separate
sponges side by side**:

```
   s[i]  =  [ sponge3.lane_i | sponge2.lane_i | sponge1.lane_i | sponge0.lane_i ]
              63..0 bits each, four of them in one 256-bit register
```

This is a *transpose*. Four sponges that would each occupy 25 scalar registers now
occupy 25 vector registers between them.

Now re-read the operation list. A lane-wise XOR of two Keccak lanes becomes one
`vpxor` on two 256-bit registers — and because the four sponges sit in disjoint 64-bit
elements, that single instruction has just XORed lane *i* for all four sponges at once.
A fixed rotation of a lane becomes `_mm256_slli_epi64` + `_mm256_srli_epi64` + `or`,
which shift *within each 64-bit element independently* — exactly the per-sponge rotate
you want, with no bits crossing a sponge boundary. The π step, which permutes which
lane is which, is free: it's just a renaming of which register you read next.

So the four sponges never interact. Nothing in the permutation mixes element 0 with
element 1 of a register. The vector unit is being used as four independent 64-bit ALUs
that happen to be driven by one instruction stream.

**One detail worth knowing**, because it looks like a magic number if you meet it cold:
rotations by 8 and 56 bits are special-cased to a single `_mm256_shuffle_epi8` with a
constant byte pattern (`rho8` / `rho56` in
`third_party/fips202/keccak4x/KeccakP-1600-times4-SIMD256.c`). A rotate by a multiple of
8 is a byte permutation, and `pshufb` does a byte permutation in one instruction instead
of shift-shift-or. It is a small win repeated 24 rounds deep.

### Getting data in and out

The awkward part is the boundary, because the *inputs* are four ordinary byte arrays,
not a transposed structure. Absorbing has to gather one 64-bit word from each of four
separate pointers into one register. AVX2 has an instruction for exactly that:

```c
idx = _mm256_set_epi64x(in3, in2, in1, in0);          /* four base addresses */
t   = _mm256_i64gather_epi64((long long *)pos, idx, 1);  /* one word from each */
s[i] = _mm256_xor_si256(s[i], t);
```

`vpgatherqq` takes a vector of addresses and returns a vector of the values at them.
Here the "index" vector holds the four input pointers and the scalar base is the offset
`pos`, so one gather performs the transpose on the fly.

Squeezing is the reverse scatter: each 256-bit register has to be split back into four
64-bit writes to four different output buffers. The vendored code does this with
`_mm_storel_pd` / `_mm_storeh_pd` — the "store low / high half of a 128-bit register"
instructions. Those are spelled with `pd` (packed double) because x86 only provides
`movlps`/`movhps` in the floating-point encoding; **no floating-point arithmetic
happens**. See §6 — this matters for our constant-time rules and was verified at the
machine level rather than assumed.

### What this costs you

The permutation is ~4× more throughput for the same instruction count. The catch is the
precondition: **you must have four independent streams available at the same moment.**
If your algorithm produces one stream, then waits for its output, then produces the
next, batching is worth nothing — three lanes sit idle. Finding the places where four
streams genuinely are independent is the real work, and it happens at the *call sites*,
not in the Keccak code. That is §3.

---

## 3. Where this applies in ML-KEM-768, and why those streams are independent

Three call sites, all in `src/kpke.cpp`.

### `gen_matrix` — 9 streams, batched 4 + 4 + 1

FIPS 203 Alg. 13 lines 3–7 / Alg. 14 lines 4–8 build a *k*×*k* = 3×3 matrix:

```
Â[i][j] ← SampleNTT(ρ ‖ j ‖ i)
```

Each entry absorbs its own 34-byte seed — the same ρ, but a distinct `(j, i)` pair in
the last two bytes — and squeezes its own stream. **No entry reads any other entry's
sponge state or output.** They are nine wholly separate SHAKE-128 instances that merely
happen to share a prefix. That is the strongest form of independence you can ask for,
and it is why the matrix expansion is the single best batching target in the algorithm:
it is the largest block of hashing in both KeyGen and Encaps.

9 doesn't divide by 4. The ninth stream runs through the scalar `sample_ntt`. Padding it
out to a third batch of four would run an entire extra permutation chain to discard
three lanes — strictly worse than one scalar stream.

There is a wrinkle specific to `SampleNTT`: it is **rejection sampling**. It reads
3-byte groups, forms two 12-bit candidates, and keeps each only if it is `< q = 3329`
(acceptance probability 3329/4096 ≈ 0.813). So the four lanes do *not* finish at the
same time — one may need an extra squeeze the others don't. `sample_ntt_x4` handles this
by squeezing a bulk of three blocks four-wide, then looping four-wide until the
**slowest** lane has its 256 coefficients, letting finished lanes drop their bytes on
the floor. Again, discarded lanes are free: a 4-way permutation costs about what one
scalar permutation costs.

Three blocks is not arbitrary. 3 × 168 = 504 bytes = 168 three-byte groups = 336
candidates, and 336 × 0.813 ≈ 273 expected acceptances against the 256 needed. So the
common case is one bulk squeeze with no top-up. Sizing the bulk at one block would make
the top-up loop the normal path and hand back most of the win.

`sample_ntt` is **deliberately variable-time** and stays that way — see the banner in
`src/sample.hpp`. Its inputs (ρ and two index bytes) are public, derivable from `ek` by
anyone, so there is nothing to leak; FIPS 203 Appendix B explicitly tells you not to
bound the loop. Batching does not change that argument either way.

### `kpke_keygen` — 6 noise streams, batched 4 + 4

Alg. 13 lines 8–15 draw `s₀,s₁,s₂` with nonces 0,1,2 and `e₀,e₁,e₂` with nonces 3,4,5,
all from `PRF_η1(σ, N)`. Six independent SHAKE-256 streams off a shared key and
distinct nonce bytes — independent for the same reason as above.

Batched as `(s₀,s₁,s₂,e₀)` and `(e₁,e₂,·,·)`: the second batch runs two lanes whose
output is thrown away, using nonces 6 and 7 that Alg. 13 never assigns (so they cannot
collide with a real draw). Two discarded lanes cost nothing, whereas two scalar streams
would cost two full scalar permutation chains.

### `kpke_encrypt` — 7 noise streams, batched 4 + 4, **split by η**

Alg. 14 lines 9–17: `y` (nonces 0,1,2, at η₁), `e₁` (nonces 3,4,5, at η₂), `e₂`
(nonce 6, at η₂).

The obvious split is 4 + 3. This codebase deliberately does **not** do that. `PRF<η>`
squeezes 64·η bytes, and a lane cannot squeeze a different number of bytes from its
neighbours — all four lanes advance through the permutation together. **A mixed-η batch
is not expressible.** At ML-KEM-768 η₁ = η₂ = 2 so 4+3 would happen to work, but it
would be silently depending on that equality; ADR-009 keeps the η₁ ≠ η₂ path alive for a
future ML-KEM-512 port. Splitting on η instead — `(y₀,y₁,y₂,·)` at η₁ and
`(e₁₀,e₁₁,e₁₂,e₂)` at η₂ — is correct for any parameter set and costs the same eight
lanes.

### What cannot be batched — and this is the performance ceiling

`G(d ‖ k)`, `H(ek)`, `J(z ‖ c)` are single streams with nothing to pair them with. On
this machine they are ~9.4% of KeyGen, and 4-way Keccak does nothing for them. Any
prediction of the form "hashing is 60% of the runtime, so 4× the hashing gives 1.86×"
silently assumes all of that 60% is batchable. It isn't. See §5.

---

## 4. How it's wired

```
src/symmetric.hpp           PRF_x4<η>, xof_x4_absorb_squeeze, xof_x4_squeezeblocks
src/symmetric.cpp           dispatch front-end: picks a backend per call
src/arch/dispatch.{hpp,cpp} runtime AVX2 detection (cpuid + XCR0), MLKEM_FORCE_ARCH
src/arch/avx2/              AVX2 backend, compiled with -mavx2 (separate TU)
src/arch/generic/           portable backend: four sequential scalar sponges
third_party/fips202/        vendored fips202x4 + keccak4x (same pin as the scalar path)
```

**The portable path is the default in the sense that matters: the library runs
correctly with no AVX2 at all.** The AVX2 translation units are compiled with
`-mavx2 -mbmi2 -mfma` and are only *entered* after `has_avx2()` returns true;
everything else, including the dispatcher itself, is compiled at baseline ISA. The
dispatcher reads XCR0 through inline `xgetbv` rather than the `_xgetbv` intrinsic,
because that intrinsic requires the `xsave` target feature the baseline TU deliberately
does not have.

`MLKEM_FORCE_ARCH=portable` forces the scalar backend at runtime. That is not a debug
convenience — it's how the portable path is *tested*:

```sh
MLKEM_FORCE_ARCH=portable build/kat_impl tests/kat/vectors    # 80/80
```

**The generic backend's output is bit-identical to the AVX2 backend's.** Both produce
exactly what four separate scalar SHAKE calls produce. This is the property that lets a
correctness gate written before any of this existed still gate it.

---

## 5. Measured results, and why they are below the Phase 4 prediction

### How to measure anything on this host

Read this before the numbers, because the first version of this section got them wrong.

rdtsc here is a constant-rate reference clock, not a retired-instruction counter, and it
does not track turbo. **Per-run ratios between the same two binaries ranged 1.04× to
1.71×.** A single run means nothing. Worse, a "before" number recorded in one session and
compared against an "after" number taken later is actively misleading — this machine
drifted about 18% between two such measurements, which is larger than the entire effect
being measured.

What works:

* Build the old revision in a `git worktree` so both binaries exist at once.
* **Alternate them** — `A B A B …` — so drift lands inside each pair instead of between
  the groups, and take the median of the per-pair ratios over at least 20 pairs.
* **Include a sanity control**: time a code path that is byte-identical in both trees.
  Its ratio must come out ~1.00. Ours came out 0.96 — that is the measurement floor, and
  it also caught that Phase 8a's `sample_ntt` refactor made the *scalar* path ~4% slower.

### The numbers

Median of 21 interleaved triples. A = Phase 7 baseline (`76b6c13`), B = Phase 8a with
`MLKEM_FORCE_ARCH=portable`, C = Phase 8a on AVX2.

| Operation | A baseline | B portable | C AVX2 | **A/C total** | A/B restructuring | B/C SIMD |
|---|---|---|---|---|---|---|
| KeyGen | 110 869 | 110 800 | 83 124 | **1.41×** | 1.02× | 1.38× |
| Encaps | 130 573 | 117 840 | 90 856 | **1.38×** | 1.04× | 1.35× |
| Decaps | 159 763 | 144 510 | 115 193 | **1.32×** | 1.04× | 1.27× |

ADR-017 predicted 1.75–1.88× / 1.66–1.92× / 1.60–1.69×.

### Why it is lower — and what is still unaccounted for

The primitive is not the problem. Measured directly, the 4-way XOF is **3.98×** four
scalar XOF streams and the 4-way PRF **3.87×**. Two effects pull the whole-operation
number down:

| | KeyGen prediction |
|---|---|
| 0. ADR-017's model: **all** hashing (~68%) at 4× | 2.03× |
| 1. only the **batchable** hashing (~58%) at 3.98× | 1.77× |
| 2. batchable at its measured **block** rate 2.79×, not the primitive rate | 1.60× |
| 3. **measured in situ** | **1.41×** |

**Effect 1 — not all hashing is batchable.** `G(d ‖ k)` and `H(ek)` are single streams
with nothing to pair them with (§3). Worth about 0.26×.

**Effect 2 — the batched blocks contain unbatched work.** `gen_matrix` as a whole
improves 2.95× and the noise draws 2.14×, well short of 3.98×, because `rej_uniform` and
`sample_poly_cbd` are still scalar byte-wise code on both paths. Batching the XOF does
not touch them. Worth about 0.18×.

**Together they account for roughly two-thirds of the gap and leave about 0.19× (12%)
unexplained.** That residual is stated, not hidden. An additive cross-check built from
the same component timings comes out **19% short** of the measured in-situ KeyGen, which
is the direct evidence that the component numbers are biased: a microbenchmark runs
`gen_matrix` in a tight loop with everything in L1, and that is not what it costs inside
a full KeyGen. So the ladder above is the right *shape* and the right *direction*, but it
is not an exact budget and should not be quoted as one.

Effect 2 is a pointer rather than a dead end: **SIMD compress/CBD is itself a Phase 8
workstream**, and the unbatched CBD and rejection work this measurement exposes is
exactly what it targets, while the AVX2 NTT (Phase 8b) attacks the arithmetic. The honest
reading is that ADR-017's ordering decision was still right — Keccak was the biggest
single win — but its magnitude estimate should have been ~1.6×, not ~1.85×, and even
~1.6× is optimistic against the 1.41× actually delivered. Logged as ADR-023.

## 6. Constant-time status

Keccak-f has no secret-dependent branches, no table lookups, and no variable-latency
instructions, and the 4-way version is the same algorithm on wider registers — so the
constant-time argument from Phase 3 carries over unchanged. `gmake ctgrind` re-runs the
Phase 6 scenarios against the batched path with σ, `r` and `dk` marked secret.

One thing that did need checking rather than assuming. `docs/reference/invariants.md` forbids **any
floating-point operation** on secret data (FIPS 203 §3.3 forbids it outright), and the
vendored 4-way code is full of `pd`/`ps`-typed intrinsics — `_mm_storel_pd`,
`_mm256_broadcast_sd`, `_mm256_permute2f128_ps`. Those are *encodings*, not arithmetic:
x86 spells several pure data-movement instructions in the floating-point domain, and
they move bits without rounding, without denormals, and at fixed latency. Verified at
the machine level, not by reading the source — disassembling all three AVX2 objects
finds **zero** FP-arithmetic mnemonics (no `add/sub/mul/div/sqrt/cvt/round/max/min/cmp`
in `ss/sd/ps/pd` form) and only `vmovaps` / `vmovups` / `vbroadcastsd` moves. Logged as
ADR-024.

---

## 7. What I took from pq-crystals, in my own words

Per ADR-022 the policy for Phase 8 is study-then-write: read `pq-crystals/kyber`'s
`avx2/` for technique, write the implementation from that understanding, and be able to
explain anything borrowed. The 4-way Keccak core itself is *vendored*, not rewritten —
FIPS 202 is the standing pre-approved exception (ADR-015), and `fips202x4.c` plus
`keccak4x/` come from the same pinned commit as the scalar `fips202.c` so there is one
provenance record, not two. Everything above it — the dispatch layer, the batched
wrappers, `sample_ntt_x4`, and the call-site restructuring — is written here.

Four things I understood only after reading their code:

1. **Discarded lanes are the right answer to a count that isn't a multiple of four.**
   My instinct was to batch what divides evenly and run the remainder scalar. For the
   *noise* draws that is backwards: a 4-way permutation costs about one scalar
   permutation, so a batch of four with two lanes thrown away beats two scalar streams
   outright. The remainder-goes-scalar instinct is only right when the leftover is a
   single stream and the alternative is a whole extra batch — which is why
   `gen_matrix` is 4+4+**1** but `kpke_keygen` is 4+**4**.
2. **Size the bulk squeeze from the rejection rate.** Their `REJ_UNIFORM_AVX_NBLOCKS`
   is derived, not tuned: enough blocks that the expected acceptances clear 256, so the
   top-up loop is the rare path. I had been thinking of the squeeze size as a tuning
   knob; it's a probability calculation.
3. **The gather is the transpose.** I expected a batched API to need an explicit
   pack/unpack step. `_mm256_i64gather_epi64` with the four input *pointers* in the
   index vector does the transpose as part of the absorb, at no separate cost.
4. **Rotate-by-8 is a byte shuffle.** Obvious in hindsight, invisible until seen.

Where I departed: the η-split in `kpke_encrypt` (§3) is not their shape — Kyber-768 has
η₁ = η₂ so they batch 4+4 across the boundary. That is correct for their parameter set
and would be a latent bug in a codebase that keeps η₁ ≠ η₂ reachable.

---

## 8. If you are about to change something here

* **The gate is byte-identity, not plausibility.** Any change to a backend must keep
  `PRF_x4` / `xof_x4_*` producing exactly what four scalar calls produce. Both backends
  are checked against the scalar path directly, and `gmake kat` checks end to end.
* **Verify the dispatch actually dispatches.** Planting a one-byte corruption in the
  AVX2 `prf_x4` must make the default `kat` run fail *and* leave
  `MLKEM_FORCE_ARCH=portable` passing. If both still pass, the AVX2 path isn't being
  taken and any speedup you measured came from somewhere else.
* **Nonce order is normative** (failure mode #5). Batching turned a running `N++`
  counter into literal nonce arguments, which makes the order easier to get wrong and
  easier to review. The literals *are* the counter.
* **Don't "tidy" `sample_ntt` into constant time.** See the banner in `src/sample.hpp`.
