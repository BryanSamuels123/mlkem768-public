# ML-KEM-768 (FIPS 203) — Implementation Specification

**Target:** A high-performance, constant-time, CPU-only implementation of ML-KEM-768 in modern C++.
**Audience:** Autonomous coding agents (Claude Code) building this repository.
**Normative reference:** NIST FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism Standard*, published 2024-08-13.

---

## 0. How to use this document

This spec is the contract. FIPS 203 is the normative authority — where this document and FIPS 203 disagree, **FIPS 203 wins**, and the discrepancy must be recorded in `DECISIONS.md`.

Read §1 (goals), §2 (repo layout), §11 (workflow and context management) before writing any code. Then work phase by phase through §12.

### Reference material caution

**The reference PDFs are not redistributed with this repository** — three of the four are
third-party publications whose copyright is not ours to re-publish. They are cited here so
they can be obtained from the publisher; only the first is normative.

| Document | Status | Use |
|---|---|---|
| **FIPS 203**, *Module-Lattice-Based Key-Encapsulation Mechanism Standard*, NIST, August 2024. [doi:10.6028/NIST.FIPS.203](https://doi.org/10.6028/NIST.FIPS.203) | **Normative** | The specification. All algorithm numbers cited below refer to this. Freely available from NIST. |
| *Rapid Prototyping of CRYSTALS-Kyber Primitives on FPGA using Python-only HW-SW Flow*, 2024 28th International Symposium on VLSI Design and Test (VDAT) | Informative | Useful for NTT/Keccak *architecture* intuition. Describes **round-3 Kyber**, not ML-KEM. |
| Post-quantum algorithm survey paper | Background only | Contains no implementable detail. Do not use for parameters. |
| Post-quantum hardware evaluation study | Informative | Hardware evaluation context only. |

The algorithms themselves were extracted once into `docs/algorithms/`, one file per
algorithm with the pseudocode verbatim; **those notes are what the implementation was built
against**, so none of the PDFs is needed to build, test or audit this code.

**Round-3 CRYSTALS-Kyber is not ML-KEM.** The differences (FIPS 203 Appendix C) are small and will silently break KAT matching:

1. ML-KEM appends the byte `k` to the seed in K-PKE.KeyGen: `(ρ,σ) ← G(d ‖ k)`. Kyber does not. **`k = 3` for ML-KEM-768.**
2. ML-KEM does **not** hash the message first (`m ← H(m)` is removed).
3. ML-KEM does **not** apply a final KDF over the ciphertext hash. `K` comes directly out of `G(m ‖ H(ek))`.
4. ML-KEM specifies mandatory input validation.

Any code, blog post, or reference implementation predating mid-2024 is likely Kyber, not ML-KEM. Verify before copying.

---

## 1. Goals and constraints

### Hard requirements

- **Correctness first.** Must pass NIST ACVP known-answer tests for ML-KEM-768 before any optimization work begins.
- **No GPU, no CUDA, no OpenCL.** CPU only.
- **C++20** minimum (C++23 acceptable if the toolchain supports it; `std::span`, `std::bit_cast`, `consteval` are all wanted).
- **Makefile-driven build.** No CMake required for the core build. A `Makefile` at repo root must build, test, benchmark, and package.
- **No floating-point arithmetic anywhere in the cryptographic core.** FIPS 203 §3.3 forbids it explicitly; rounding errors produce wrong results.
- **Constant-time** with respect to all secret data. See §8.
- **Reuse optimized code where it exists**, rather than reimplementing. See §7.
- **Thread-level parallelism is permitted and encouraged at the batch API level.** See §9.3.

### Non-goals

- Other parameter sets (512, 1024) are *out of scope for v1* but the code must be structured so adding them is a parameter change, not a rewrite. Use a `constexpr` parameter struct, not `#define`.
- ML-DSA / FIPS 204, hybrid KEX constructions, TLS integration.
- Formal verification. (Worth reading formally verified implementations; not producing one.)

### Success criteria

1. `make kat` passes all NIST ACVP ML-KEM-768 vectors (keyGen + encapDecaps, both AFT and VAL).
2. `make test` passes all unit, property, and differential tests.
3. `make ctgrind` reports zero secret-dependent branches or memory accesses.
4. `make bench` reports cycle counts within ~1.5× of `pq-crystals/kyber` AVX2 on the same machine.
5. `make package` produces a static library, a header, and a `.tar.gz`.

---

## 2. Repository layout

```
mlkem768/
├── Makefile                  # primary build
├── DECISIONS.md              # ADR log; see §11.4
├── README.md
├── docs/
│   ├── algorithms/           # extracted FIPS 203 pseudocode, one .md per algorithm
│   ├── bounds.md             # coefficient range invariants; see §5.4
│   ├── reference/            # invariants.md, plus material consulted when needed
│   └── spec/                 # this file (the reference PDFs are not redistributed)
├── include/
│   └── mlkem/
│       ├── mlkem768.hpp      # THE public API. Stable. See §3.
│       └── mlkem768.h        # optional C ABI shim
├── src/
│   ├── params.hpp            # constexpr parameter set
│   ├── reduce.hpp            # Montgomery / Barrett (header-only, inline)
│   ├── ntt.hpp / ntt.cpp     # forward/inverse NTT, basemul, zeta tables
│   ├── poly.hpp / poly.cpp   # single-polynomial ops
│   ├── polyvec.hpp/.cpp      # k-vector ops
│   ├── symmetric.hpp/.cpp    # H, G, J, PRF, XOF wrappers over FIPS 202
│   ├── kpke.hpp / kpke.cpp   # Algorithms 13, 14, 15
│   ├── kem.hpp / kem.cpp     # Algorithms 16–21
│   ├── verify.hpp            # constant-time compare + conditional move
│   ├── zeroize.hpp/.cpp      # non-elidable secure erase
│   ├── rng.hpp / rng.cpp     # RBG interface + default OS-backed impl
│   └── arch/
│       ├── dispatch.hpp/.cpp # runtime CPU feature detection
│       ├── generic/          # portable C++ implementations
│       ├── avx2/             # AVX2 NTT, basemul, compress, cbd
│       └── avx512/           # optional; AVX-512BW path
├── third_party/
│   └── fips202/              # vendored Keccak; see §7.1
├── tests/
│   ├── model/                # slow, obviously-correct golden model; see §10.2
│   ├── unit/                 # per-function tests
│   ├── kat/                  # ACVP harness + vector files
│   └── ct/                   # constant-time test drivers
├── bench/
└── tools/                    # vector fetcher, zeta table generator, etc.
```

**File size discipline:** no source file over ~400 lines. This is a context-window constraint as much as a style one (see §11).

---

## 3. Public API

This is the only surface external consumers see. Keep it stable from Phase 6 onward.

```cpp
// include/mlkem/mlkem768.hpp
#pragma once
#include <array>
#include <cstdint>
#include <span>

namespace mlkem768 {

inline constexpr std::size_t EK_BYTES        = 1184;  // 384k + 32,  k=3
inline constexpr std::size_t DK_BYTES        = 2400;  // 768k + 96
inline constexpr std::size_t CT_BYTES        = 1088;  // 32(du*k + dv) = 32*34
inline constexpr std::size_t SS_BYTES        = 32;
inline constexpr std::size_t SEED_BYTES      = 64;    // (d ‖ z)

using EncapsKey    = std::array<std::uint8_t, EK_BYTES>;
using DecapsKey    = std::array<std::uint8_t, DK_BYTES>;   // SECRET
using Ciphertext   = std::array<std::uint8_t, CT_BYTES>;
using SharedSecret = std::array<std::uint8_t, SS_BYTES>;   // SECRET
using Seed         = std::array<std::uint8_t, SEED_BYTES>; // SECRET

enum class Status { Ok, RngFailure, InvalidEncapsKey, InvalidDecapsKey, InvalidCiphertext };

// --- Randomized API (FIPS 203 §7) ---------------------------------------

// Algorithm 19. Draws d, z from the configured RBG.
[[nodiscard]] Status keygen(EncapsKey& ek, DecapsKey& dk) noexcept;

// Algorithm 20. Performs the encapsulation key check (§7.2) before use.
[[nodiscard]] Status encaps(const EncapsKey& ek,
                            Ciphertext& ct,
                            SharedSecret& ss) noexcept;

// Algorithm 21. Performs the decapsulation input checks (§7.3).
// NEVER returns a distinguishable error for a malformed-but-well-sized
// ciphertext: implicit rejection is silent by design.
[[nodiscard]] Status decaps(const DecapsKey& dk,
                            const Ciphertext& ct,
                            SharedSecret& ss) noexcept;

// --- Seed-expanded keys (FIPS 203 §3.3 exception 1) ---------------------
// The 64-byte seed (d ‖ z) may be stored instead of the 2400-byte dk.
// Treat the seed with the same protections as dk.
[[nodiscard]] Status keygen_from_seed(const Seed& seed,
                                      EncapsKey& ek, DecapsKey& dk) noexcept;
[[nodiscard]] Status keygen_seeded(Seed& seed,
                                   EncapsKey& ek, DecapsKey& dk) noexcept;

// --- Validation helpers (callable independently; see §6.4) --------------
[[nodiscard]] bool check_encaps_key(std::span<const std::uint8_t> ek) noexcept;
[[nodiscard]] bool check_decaps_key(std::span<const std::uint8_t> dk) noexcept;

// --- RBG injection -------------------------------------------------------
// Must be thread-safe if the batch API is used. Returns false on failure.
using RngFn = bool (*)(std::span<std::uint8_t> out, void* ctx) noexcept;
void set_rng(RngFn fn, void* ctx) noexcept;

// --- Batch API (see §9.3) -----------------------------------------------
namespace batch {
[[nodiscard]] Status encaps(std::span<const EncapsKey> eks,
                            std::span<Ciphertext> cts,
                            std::span<SharedSecret> sss,
                            unsigned threads = 0) noexcept;  // 0 = hw concurrency
[[nodiscard]] Status decaps(std::span<const DecapsKey> dks,
                            std::span<const Ciphertext> cts,
                            std::span<SharedSecret> sss,
                            unsigned threads = 0) noexcept;
} // namespace batch

} // namespace mlkem768
```

### 3.1 Internal (deterministic) API — testing only

FIPS 203 §3.3 says these "should not be made available to applications other than for testing purposes." Gate them behind a build flag so they cannot be linked accidentally.

```cpp
#ifdef MLKEM_ENABLE_INTERNAL_API
namespace mlkem768::internal {
  // Algorithm 16
  void keygen_internal(std::span<const std::uint8_t, 32> d,
                       std::span<const std::uint8_t, 32> z,
                       EncapsKey& ek, DecapsKey& dk) noexcept;
  // Algorithm 17
  void encaps_internal(const EncapsKey& ek,
                       std::span<const std::uint8_t, 32> m,
                       Ciphertext& ct, SharedSecret& ss) noexcept;
  // Algorithm 18
  void decaps_internal(const DecapsKey& dk, const Ciphertext& ct,
                       SharedSecret& ss) noexcept;
}
#endif
```

`make kat` must build with `MLKEM_ENABLE_INTERNAL_API=1`. The default `make` must not.

---

## 4. Parameters

```cpp
// src/params.hpp
namespace mlkem768::params {
inline constexpr int      N   = 256;
inline constexpr int16_t  Q   = 3329;      // = 2^8 * 13 + 1
inline constexpr int16_t  ZETA = 17;       // primitive 256th root of unity mod Q
inline constexpr int      K   = 3;
inline constexpr int      ETA1 = 2;
inline constexpr int      ETA2 = 2;
inline constexpr int      DU  = 10;
inline constexpr int      DV  = 4;

inline constexpr int POLY_BYTES        = 384;             // 12 bits * 256 / 8
inline constexpr int POLYVEC_BYTES     = K * POLY_BYTES;  // 1152
inline constexpr int POLY_COMPRESSED_DV_BYTES  = 32 * DV; // 128
inline constexpr int POLYVEC_COMPRESSED_DU_BYTES = K * 32 * DU; // 960
inline constexpr int EK_PKE_BYTES = POLYVEC_BYTES + 32;   // 1184
inline constexpr int DK_PKE_BYTES = POLYVEC_BYTES;        // 1152
inline constexpr int CT_BYTES     = POLYVEC_COMPRESSED_DU_BYTES
                                  + POLY_COMPRESSED_DV_BYTES; // 1088
}
```

Do **not** use preprocessor macros for these. Other parameter sets are added later by templating or by a second `constexpr` namespace, not by redefining macros.

**Decapsulation failure rate for ML-KEM-768: 2⁻¹⁶⁴·⁸.** Nonzero, which is precisely why implicit rejection exists.

---

## 5. Core arithmetic layer

### 5.1 Representation

Coefficients are stored as `int16_t` in **signed** representation. A polynomial is:

```cpp
struct Poly { alignas(32) std::array<int16_t, 256> c; };
struct PolyVec { std::array<Poly, params::K> v; };
```

`alignas(32)` (or 64 for AVX-512) matters — unaligned loads cost real cycles in the NTT inner loop.

**Montgomery convention:** the implementation must pick one and document it in `DECISIONS.md`. Recommended (matches the well-tested reference lineage):
- `R = 2^16`, `R mod q = 2285`, `R² mod q = 1353`.
- `q⁻¹ mod 2^16` such that `q * qinv ≡ 1`. Compute it in a `consteval` function rather than hardcoding a magic number, then `static_assert` the result.
- `zetas[]` are stored **pre-multiplied into the Montgomery domain**.
- `invntt` folds the final `n⁻¹ = 3303` scaling together with a Montgomery factor so the output lands in a known domain. Document precisely which.

Getting the domain bookkeeping wrong produces output that is off by a constant factor and passes roundtrip tests while failing KATs. Write the domain of every function's input and output as a comment on its declaration.

### 5.2 Reduction primitives (`src/reduce.hpp`)

```cpp
// Montgomery reduction.
// Input:  a with |a| <= Q * 2^15
// Output: t ≡ a * R^-1 (mod Q), with |t| < Q
[[gnu::always_inline]] inline int16_t montgomery_reduce(int32_t a) noexcept;

// Barrett reduction.
// Input:  any int16_t
// Output: t ≡ a (mod Q), with |t| <= (Q-1)/2 = 1664
[[gnu::always_inline]] inline int16_t barrett_reduce(int16_t a) noexcept;

// Conditional subtraction of Q. Input in [0, 2Q); output in [0, Q).
[[gnu::always_inline]] inline int16_t csubq(int16_t a) noexcept;
```

**Derive the Barrett constant, do not copy it.** `v = floor(((1 << 26) + Q/2) / Q)` computed in a `consteval` function, `static_assert`ed.

**Tests:**
- `barrett_reduce`: **exhaustive** over all 65536 `int16_t` inputs. Assert `t ≡ a (mod Q)` and `|t| <= 1664`. This test runs in microseconds — there is no excuse for not doing it.
- `csubq`: exhaustive over `[0, 2Q)`.
- `montgomery_reduce`: random-sample 10⁷ values across the full legal range, plus all boundary values `±Q*2^15`, `0`, `±1`, `±Q`. Compare against a `__int128` or Python-computed reference. Also verify the tight bound `|t| < Q` holds for every sample.

### 5.3 NTT (`src/ntt.hpp`, `src/ntt.cpp`)

`q - 1 = 3328 = 2^8 · 13`. There is a primitive 256th root of unity (ζ = 17) but **no** 512th root. Therefore `X^256 + 1` factors into **128 quadratics**, not 256 linears, and the transform has **7 layers, not 8**. The NTT image `T_q` is 128 degree-1 polynomials, each modulo `X² − ζ^(2·BitRev7(i)+1)`.

This is why pointwise multiplication is *not* a scalar multiply.

```cpp
// Forward NTT, in place. FIPS 203 Algorithm 9.
// Input:  coefficients of f ∈ R_q, |c| < Q
// Output: NTT representation, bounds documented in docs/bounds.md
void ntt(Poly& f) noexcept;

// Inverse NTT, in place, including the 128^-1 = 3303 scaling.
// FIPS 203 Algorithm 10. Output domain documented in DECISIONS.md.
void invntt(Poly& f) noexcept;

// Base-case multiply. FIPS 203 Algorithm 12.
//   c0 = a0*b0 + a1*b1*gamma
//   c1 = a0*b1 + a1*b0
void basemul(int16_t r[2], const int16_t a[2], const int16_t b[2],
             int16_t gamma) noexcept;

// FIPS 203 Algorithm 11: 128 base-case multiplies with the correct gammas.
void poly_basemul(Poly& r, const Poly& a, const Poly& b) noexcept;

// Accumulating variant — essential for matrix-vector products.
// r += a ∘ b, without an intermediate buffer.
void poly_basemul_acc(Poly& r, const Poly& a, const Poly& b) noexcept;
```

**Zeta tables.** Two are needed:
- `zetas[128]`: `ζ^BitRev7(i) mod q` (FIPS 203 Appendix A, first table) — used by `ntt` and `invntt`.
- `zetas_basemul[128]`: `±ζ^(2·BitRev7(i)+1) mod q` (Appendix A, second table) — used by `poly_basemul`.

Generate these with `tools/gen_zetas.cpp` (or a `consteval` function) and **assert at build time or in a unit test that they match Appendix A byte for byte**, after undoing the Montgomery factor. Do not hand-transcribe 128 numbers.

**Loop structure:** use Cooley-Tukey (decimation-in-time) for forward and Gentleman-Sande (decimation-in-frequency) for inverse. This pairing cancels the bit-reversal permutation on both ends — no explicit reorder step is ever needed. The Kyber VDAT paper (§II.C) describes the same property.

**Tests:**
1. **Roundtrip:** `invntt(ntt(f)) == f` for 10⁶ random `f`. Must be exact, coefficient for coefficient, after canonical reduction.
2. **Differential against schoolbook (the critical test):** implement naive negacyclic multiplication in `tests/model/` —
   ```
   for i in 0..255: for j in 0..255:
       k = i + j
       if k < 256: r[k] += a[i]*b[j]
       else:       r[k-256] -= a[i]*b[j]      // because X^256 = -1
   ```
   Then assert `invntt(poly_basemul(ntt(a), ntt(b))) == schoolbook(a, b) mod q` for 10⁵ random pairs. **This single test catches nearly every NTT bug**: wrong zetas, wrong layer count, wrong bit-reversal, wrong Montgomery domain, wrong gamma signs in basemul.
3. **Linearity:** `ntt(a + b) == ntt(a) + ntt(b)`.
4. **Known vector:** `ntt` of `f = 1` (constant polynomial) and of `f = X` — compute expected values independently in Python, hardcode as a regression test.
5. **Bounds:** instrument a debug build to track max `|coefficient|` at every layer and assert it never exceeds the documented invariant. Overflow of `int16_t` in the NTT is silent and produces wrong-but-plausible output.

### 5.4 Coefficient bound invariants

Create `docs/bounds.md`. For every function that touches polynomial coefficients, record the required input range and guaranteed output range. Example:

| Function | Input bound | Output bound |
|---|---|---|
| `ntt` | `|c| < Q` | `|c| < 7Q` (verify empirically and prove) |
| `invntt` | `|c| < 7Q` | `|c| < Q` |
| `poly_basemul` | `|c| < 7Q` for both | `|c| < Q` |
| `poly_add` | `|a|,|b| < 3Q` | `|c| < 6Q` |
| `poly_tomsg` | canonical `[0, Q)` | n/a |

This table is the specification for **lazy reduction** — the main scalar optimization. Skipping a `barrett_reduce` is only safe if the bounds table proves no overflow. Every lazy-reduction change must update this table in the same commit.

---

## 6. Algorithm layer

### 6.1 Serialization (`src/poly.cpp`)

```cpp
// FIPS 203 Algorithm 5 with d=12. Input coefficients must be canonical [0,Q).
void poly_tobytes(std::uint8_t out[384], const Poly& a) noexcept;

// FIPS 203 Algorithm 6 with d=12. NOTE: reduces mod Q, so the map is not
// injective. Out-of-range 12-bit values are silently folded — this is why
// the encapsulation-key modulus check in §6.4 exists.
void poly_frombytes(Poly& r, const std::uint8_t in[384]) noexcept;

// Compress_dv + ByteEncode_dv, dv = 4.  256 coeffs -> 128 bytes.  MUST be CT.
void poly_compress_dv(std::uint8_t out[128], const Poly& a) noexcept;
void poly_decompress_dv(Poly& r, const std::uint8_t in[128]) noexcept;

// Compress_du + ByteEncode_du, du = 10.  256 coeffs -> 320 bytes per poly.
void polyvec_compress_du(std::uint8_t out[960], const PolyVec& a) noexcept;
void polyvec_decompress_du(PolyVec& r, const std::uint8_t in[960]) noexcept;

// Decompress_1(ByteDecode_1(m)): each message bit -> 0 or ceil(Q/2) = 1665.
void poly_frommsg(Poly& r, const std::uint8_t msg[32]) noexcept;

// ByteEncode_1(Compress_1(w)): round each coeff to nearest of {0, ceil(Q/2)}.
void poly_tomsg(std::uint8_t msg[32], const Poly& a) noexcept;
```

**Integer-only rounding.** FIPS 203 defines `⌈x⌋` as round-half-**up**. For non-negative integers:

```
Compress_d(x)   = floor( (2^(d+1) * x + Q) / (2Q) )  mod 2^d
Decompress_d(y) = floor( (2^(d+1) ... )  -->  ( (uint32_t)y * Q + (1 << (d-1)) ) >> d
```

Integer division by `Q` is slow. Replace it with a multiply-and-shift (`(x * M) >> S` for suitable `M`, `S`). **Do not copy a magic constant from anywhere.** Derive `M` and `S`, then verify:

> **Exhaustive test.** For every `x` in `[0, 3329)` and every `d` in `{1, 4, 10}`, assert the optimized `Compress_d(x)` equals the exact rational formula computed in 64-bit integers. 3329 × 3 cases. Likewise `Decompress_d(y)` for every `y` in `[0, 2^d)`.

This makes an entire class of subtle off-by-one bugs impossible.

**Other tests:**
- `Compress_d(Decompress_d(y)) == y` for all `y ∈ [0, 2^d)` — FIPS 203 §4.2.1 guarantees this; it is a free correctness oracle.
- `poly_frombytes(poly_tobytes(f)) == f` for random canonical `f`.
- `poly_tomsg(poly_frommsg(m)) == m` for 10⁵ random 32-byte messages.
- Byte-level golden vectors: generate 20 random polynomials, serialize with a Python model, commit the hex, compare.
- Bit-packing endianness: FIPS 203 uses **little-endian** bit order (Algorithm 3/4). Test with a message of `0x01 0x00 0x00 ...` and verify the *first* coefficient is set, not the eighth.

### 6.2 Sampling (`src/poly.cpp`)

```cpp
// FIPS 203 Algorithm 7. Rejection sampling from SHAKE128.
// Input is the 34-byte seed (rho ‖ j ‖ i). Output is already in T_q —
// it is NOT transformed by ntt().
// VARIABLE-TIME IS ACCEPTABLE AND EXPECTED: the input is public.
void sample_ntt(Poly& a, const std::uint8_t seed[34]) noexcept;

// FIPS 203 Algorithm 8, PARAMETERIZED ON ETA. Input is exactly 64*eta bytes
// from PRF<eta>. MUST be constant-time: the output is secret.
//   eta = 2 -> 128 bytes  (ML-KEM-768 and -1024; also eta2 for every set)
//   eta = 3 -> 192 bytes  (ML-KEM-512 eta1 only)
// Eta is a template parameter, not a runtime argument: the bit-slicing shape
// differs between 2 and 3, and a runtime branch on it would be both slower and
// harder to keep constant-time.
template <int Eta>
void sample_poly_cbd(Poly& f, std::span<const std::uint8_t, 64 * Eta> buf) noexcept;
```

**Do not declare an `eta2`-only entry point.** Naming the function after the value
`eta = 2` hardcodes `eta1 == eta2`, which is true for ML-KEM-768 and **false for
ML-KEM-512** (`eta1 = 3`, needing 192 PRF bytes). That contradicts §1's requirement that
other parameter sets be a parameter change and not a rewrite. Call sites select by
**role**, not by value:

| Call site | Parameter |
|---|---|
| K-PKE.KeyGen: `s`, `e` | `params::ETA1` (**both** — FIPS 203 Alg. 13 lines 9 and 13) |
| K-PKE.Encrypt: `y` | `params::ETA1` |
| K-PKE.Encrypt: `e1`, `e2` | `params::ETA2` |

See `DECISIONS.md` ADR-009.

**`sample_ntt` loop bound.** FIPS 203 Appendix B: do not bound the `while` loop if avoidable. If you must, the minimum permitted limit is **280 iterations** (probability of exceeding: 2⁻²⁶¹). If the limit is hit, destroy all intermediates and return an identical result for every such execution. Default: **no bound**, with a comment citing Appendix B.

**CBD is constant-time by construction** — it is bit-slicing and popcounts, no tables, no rejection. That is exactly why Kyber/ML-KEM uses a centered binomial rather than a discrete Gaussian. Implement it branchlessly: load 4 bytes, mask with `0x55555555`, add shifted halves, extract nibbles. For η=2 the whole polynomial is 128 bytes → 32 `uint32_t` loads.

**Tests:**
- `sample_ntt`: all 256 output coefficients in `[0, Q)`. Chi-squared uniformity test over 10⁴ samples (loose threshold — this catches a broken rejection condition, not subtle bias).
- `sample_ntt` golden vector: fixed `ρ`, fixed `(i,j)`, compare full 256-coefficient output against a Python model. **Critically: verify index order.** FIPS 203 Algorithm 13 line 5 is `Â[i,j] ← SampleNTT(ρ ‖ j ‖ i)` — `j` is byte 33, `i` is byte 34. This was swapped in the FIPS 203 initial public draft and corrected in the final; getting it wrong transposes the matrix and produces a self-consistent implementation that fails every KAT.
- `sample_poly_cbd<2>`: all coefficients in `{-2,-1,0,1,2}` (mod Q: `{0,1,2,3327,3328}`). Distribution over 10⁶ samples should approximate `{1,4,6,4,1}/16`. Test `sample_poly_cbd<3>` too — range `{-3..3}`, distribution `{1,6,15,20,15,6,1}/64` — even though ML-KEM-768 never calls it, so the eta1≠eta2 path is not first exercised by a future ML-KEM-512 port.
- CBD golden vector against Python model, 20 cases.

### 6.3 Symmetric primitives (`src/symmetric.cpp`)

Thin wrappers. No logic beyond length bookkeeping.

```cpp
void H(std::uint8_t out[32], std::span<const std::uint8_t> in) noexcept;  // SHA3-256
void G(std::uint8_t out[64], std::span<const std::uint8_t> in) noexcept;  // SHA3-512
void J(std::uint8_t out[32], std::span<const std::uint8_t> in) noexcept;  // SHAKE256(·,32)

// PRF_eta(s, b) = SHAKE256(s ‖ b, 64*eta bytes), PARAMETERIZED ON ETA.
//   eta = 2 -> 128 bytes out;  eta = 3 -> 192 bytes out.
// NOTE: eta selects the OUTPUT LENGTH ONLY. FIPS 203 §4.1 is explicit that
// "eta is only used to specify the desired output length and not to perform
// domain separation" - so PRF<2>(s,b) is a 128-byte PREFIX of PRF<3>(s,b).
// Do not add a domain-separation byte for eta; it would break every KAT.
template <int Eta>
void PRF(std::span<std::uint8_t, 64 * Eta> out,
         const std::uint8_t s[32], std::uint8_t b) noexcept;

// Incremental SHAKE128 for sample_ntt (absorb 34 bytes, squeeze 3 at a time).
struct Xof { /* opaque Keccak state */ };
void xof_init_absorb(Xof&, const std::uint8_t seed[34]) noexcept;
void xof_squeeze(Xof&, std::uint8_t* out, std::size_t len) noexcept;
```

**Tests:** FIPS 202 KATs for SHA3-256, SHA3-512, SHAKE128, SHAKE256 (NIST CAVP byte-oriented vectors). Test `xof_squeeze` in mismatched chunk sizes (3 bytes at a time vs one bulk squeeze) and assert identical output — this catches state-management bugs at rate boundaries. FIPS 203 Algorithm 2 documents exactly this equivalence requirement.

### 6.4 K-PKE and ML-KEM

```cpp
// --- K-PKE (FIPS 203 §5). NOT approved standalone. Internal linkage only. ---

// Algorithm 13
void kpke_keygen(std::uint8_t ek[1184], std::uint8_t dk[1152],
                 const std::uint8_t d[32]) noexcept;

// Algorithm 14
void kpke_encrypt(std::uint8_t ct[1088], const std::uint8_t ek[1184],
                  const std::uint8_t m[32], const std::uint8_t r[32]) noexcept;

// Algorithm 15
void kpke_decrypt(std::uint8_t m[32], const std::uint8_t dk[1152],
                  const std::uint8_t ct[1088]) noexcept;
```

Implementation notes, in the order the steps occur:

**KeyGen (Alg. 13)**
1. `(ρ, σ) ← G(d ‖ k)` where the appended byte is `k = 3`. **Do not omit.**
2. Generate `Â[i][j] ← SampleNTT(ρ ‖ j ‖ i)` — 9 calls for k=3.
3. Sample `s[0..2]` with `N = 0,1,2`, then `e[0..2]` with `N = 3,4,5`. The counter order is normative.
4. `ŝ ← NTT(s)`, `ê ← NTT(e)`.
5. `t̂ ← Â ∘ ŝ + ê`.
6. `ek_PKE ← ByteEncode₁₂(t̂) ‖ ρ`; `dk_PKE ← ByteEncode₁₂(ŝ)`.

`t̂`, `ŝ`, and `Â` all live **permanently in the NTT domain**. They are never transformed again. `SampleNTT` produces NTT-domain output directly.

**Encrypt (Alg. 14)**
- Sample `y` with `N = 0,1,2` (η1), `e1` with `N = 3,4,5` (η2), `e2` with `N = 6` (η2).
- `u ← NTT⁻¹(Âᵀ ∘ ŷ) + e1` — note the **transpose**.
- `μ ← Decompress₁(ByteDecode₁(m))`.
- `v ← NTT⁻¹(t̂ᵀ ∘ ŷ) + e2 + μ`.
- `c ← ByteEncode_du(Compress_du(u)) ‖ ByteEncode_dv(Compress_dv(v))` → 960 + 128.

`u` is compressed to 10 bits, `v` to 4. `v` carries the message with an enormous per-coefficient margin, so it tolerates aggressive rounding; `u` is `k×` larger, so trimming even 2 bits saves 3× more bytes.

**Why decryption works:** `w = v' − ŝᵀu' = μ + (eᵀy − sᵀe1 + e2) + (compression noise)`. Everything after `μ` is small. As long as the total stays below `q/4`, `Compress₁` recovers the bit. Failure probability 2⁻¹⁶⁴·⁸.

```cpp
// --- ML-KEM (FIPS 203 §6, §7) -------------------------------------------
// Algorithm 16: dk ← (dk_PKE ‖ ek ‖ H(ek) ‖ z)
// Algorithm 17: (K, r) ← G(m ‖ H(ek)); c ← kpke_encrypt(ek, m, r)
// Algorithm 18: see below
```

**Decaps_internal (Alg. 18) — the part that must be exactly right:**

```
1. parse dk_PKE = dk[0:1152], ek_PKE = dk[1152:2336],
         h = dk[2336:2368], z = dk[2368:2400]
2. m'  ← kpke_decrypt(dk_PKE, c)
3. (K', r') ← G(m' ‖ h)
4. K̄  ← J(z ‖ c)                       // computed UNCONDITIONALLY
5. c'  ← kpke_encrypt(ek_PKE, m', r')   // re-encrypt
6. K'  ← cmov(K', K̄, ct_neq(c, c'))     // branchless select
7. return K'
```

Requirements on steps 4–6, all of which are security-critical:
- `K̄` is computed **every time**, not inside an `if`.
- The comparison is `ct_memcmp`, never `std::memcmp` or `==` on arrays.
- The selection is a branchless conditional move using a full-width mask.
- The "implicit reject" flag is secret intermediate data and **shall be destroyed** before returning (FIPS 203 §6.3). It must never be returned, logged, or inferable from timing.
- `decaps` must not return a distinguishable status for a well-sized but invalid ciphertext. Length/type failures are public and *may* return an error; cryptographic failures must not.

**Input validation (FIPS 203 §7.2, §7.3) — mandatory:**

| Check | Where | How |
|---|---|---|
| ek type check | `encaps` | length == 1184 |
| ek **modulus check** | `encaps` | `ByteEncode₁₂(ByteDecode₁₂(ek[0:1152])) == ek[0:1152]` |
| ct type check | `decaps` | length == 1088. **Every call.** |
| dk type check | `decaps` | length == 2400 |
| dk **hash check** | `decaps` | `H(dk[1152:2336]) == dk[2336:2368]` |

The modulus check exists because `ByteDecode₁₂` reduces mod `q` and is therefore not injective — a 12-bit field can hold `[3329, 4095]`, which no honest encoder produces. Encode-then-compare is the cheapest way to detect it.

FIPS 203 permits the ek check and dk check to be done once out-of-band rather than on every call; the **ciphertext length check must happen on every `decaps`**.

---

## 7. External code: what to pull in, what to write

### 7.1 Keccak / FIPS 202 — **pull in, do not write**

SHAKE128/256 and SHA3-256/512 will be the **majority of the cycle count** in a well-optimized ML-KEM. A hand-rolled Keccak will not be competitive. Options, in recommended order:

| Option | License | Pros | Cons |
|---|---|---|---|
| **`pq-crystals/kyber` `fips202.c` + `fips202x4.c`** | CC0 / public domain | Purpose-built for exactly this use; includes **4-way batched SHAKE** over AVX2; tiny, vendorable, no build system | Only x86-64 AVX2 for the ×4 path |
| **XKCP (eXtended Keccak Code Package)** | CC0 / public domain | Official; `KeccakP1600times4_SIMD256` (AVX2) and `times8` (AVX-512); ARM NEON paths | Build system is convoluted — vendor specific files rather than integrating their makefiles |
| **OpenSSL / AWS-LC `EVP` SHA3+SHAKE** | Apache-2.0 | Well-optimized, already installed | Per-call EVP overhead is significant at these message sizes; **no 4-way batching**, which is the single biggest win; heavy dependency |
| **`tiny_sha3`** | MIT | Trivially portable, ~200 lines | Slow. Use only as the portable fallback path. |

**Recommendation:** vendor the pq-crystals `fips202` pair into `third_party/fips202/` for the AVX2 path, with `tiny_sha3` or a clean C++ Keccak-f1600 as the portable fallback. Both are public domain, so vendoring is unencumbered. Record the exact upstream commit hash in `DECISIONS.md`.

**Why 4-way batching matters so much:** ML-KEM-768 generates a 3×3 matrix — **9 independent `SampleNTT` calls**, each an independent SHAKE128 stream. Plus 6 independent `PRF` calls in KeyGen and 7 in Encrypt. These are perfectly parallel across SIMD lanes. `KeccakF1600_StatePermute_x4` processes four independent 1600-bit states in AVX2 registers, giving close to 4× on the dominant cost. On AVX-512, `times8` gives 8 lanes. **This is the highest-leverage optimization in the entire project** — do it before hand-tuning the NTT.

### 7.2 NTT / modular arithmetic — **write it yourself**

There is no general-purpose library that will beat a purpose-built Kyber NTT:
- **GMP, NTL, FLINT, MPFR** — bignum-oriented. Wrong abstraction entirely; the coefficients are 12 bits.
- **FFTW, PocketFFT** — floating-point. Forbidden by FIPS 203 §3.3.
- **Eigen, xtensor** — no modular arithmetic, no 16-bit lane awareness.

Write `int16_t` SIMD intrinsics directly. The core AVX2 instructions are `vpmullw`, `vpmulhw`, `vpaddw`, `vpsubw`, `vpermq`, `vpshufb`, plus BMI2 for bit-packing in compress. 16 coefficients per `__m256i` means one NTT layer is 8 register operations.

**Optional:** Google **Highway** (`libhwy`, Apache-2.0) for portable SIMD if ARM NEON support is wanted later. Hand intrinsics will still win for the NTT inner loop; Highway is reasonable for compress/decompress and CBD. Decide in Phase 8, not now.

### 7.3 Implementations worth reading (not copying wholesale)

- **`pq-crystals/kyber`** (CC0) — the canonical reference and AVX2 implementation. Check the branch: master has been updated for ML-KEM, but older tags are round-3 Kyber.
- **`pq-crystals/mlkem-native`** (Apache-2.0) — the C implementation adopted into AWS-LC; extensively verified, excellent AVX2 and NEON backends. **This is the right benchmark target.**
- **PQClean** (`ml-kem-768`) — clean, portable, heavily audited. Good cross-check oracle.
- **`open-quantum-safe/liboqs`** — useful for its test harness design.
- **BoringSSL / AWS-LC** `ml_kem` — production-grade constant-time patterns.

Licensing is permissive across all of these (CC0 / Apache-2.0 / MIT), but **record provenance for anything copied** in `DECISIONS.md`, including file, upstream commit, and license.

#### Copying policy — read this before Phase 8

The licenses permit copying. The project goal does not. The default is:

> **Read these implementations for technique. Do not copy their source into this repository.** Understanding *why* the AVX2 NTT fuses the first three layers, then writing that yourself, is the deliverable. Pasting `ntt.S` is not.

Two explicit exceptions, both pre-approved:

1. **FIPS 202 / Keccak** (§7.1). Vendored wholesale. This is a solved, separable problem and rewriting it adds nothing.
2. **Single-header test/tooling dependencies** (doctest, nlohmann/json). Test-only; never linked into the shipped library.

Anything else requires the human's approval before it lands. If an agent believes copying a specific file is the right call, it should stop and ask, with a one-paragraph justification — not copy and record it afterward.

Every vendored file, approved or pre-approved, gets a `DECISIONS.md` entry with: upstream repo, commit hash, license, local path, and any local modifications.

### 7.4 Tooling dependencies

| Need | Pick | Notes |
|---|---|---|
| Unit test framework | **doctest** (single header, MIT) | Or Catch2. Avoid GoogleTest — build weight not worth it here. |
| JSON parsing for ACVP vectors | **nlohmann/json** (single header, MIT) or **simdjson** | Test-only dependency; never links into the library. |
| Benchmarking | **Hand-rolled `rdtsc`/`rdpmc` cycle counter** | Cycles-per-operation is the standard crypto metric; wall-clock hides too much. Google Benchmark is acceptable as a secondary harness. |
| Constant-time checking | **valgrind + ctgrind-style annotations**, and/or **dudect** | See §8.2. |

**Rule: zero runtime dependencies for the shipped library.** `libmlkem768.a` must link against nothing but libc. All of the above are test/bench-only.

---

## 8. Constant-time requirements

### 8.1 Rules

Secret data: `d`, `z`, `σ`, `s`, `ŝ`, `e`, `e1`, `e2`, `y`, `m`, `m'`, `r`, `r'`, `K`, `K̄`, `dk` in full, the seed, and the implicit-reject flag.

Forbidden on any of the above:
- Conditional branches (`if`, `? :` that compiles to a branch, `&&`/`||` short-circuit, loop bounds)
- Memory addresses derived from secrets (table lookups, array indices)
- Variable-latency instructions: integer `div`/`mod`, and on some microarchitectures `popcnt` edge cases
- `memcmp`, `strcmp`, `std::equal`, `operator==` on arrays
- Any floating-point operation (also forbidden outright by §3.3)

Permitted variable-time: anything depending only on `ρ`, `ek`, `Â`, or `c` — `sample_ntt` is the main case.

### 8.2 Primitives (`src/verify.hpp`)

```cpp
// Returns 0 if equal, 0xFF..FF mask if different. No branches, no early exit.
[[nodiscard]] std::uint8_t ct_neq(std::span<const std::uint8_t> a,
                                  std::span<const std::uint8_t> b) noexcept;

// r = mask ? x : r, byte-wise. mask must be all-zeros or all-ones.
void ct_cmov(std::span<std::uint8_t> r, std::span<const std::uint8_t> x,
             std::uint8_t mask) noexcept;
```

Implement `ct_neq` as an OR-accumulator over XORed bytes, then fold to a mask. Add a compiler barrier (`asm volatile("" ::: "memory")` or a `volatile` read) around the accumulator so the optimizer cannot reintroduce a branch — compilers **do** turn accumulator loops into early exits at `-O3`.

### 8.3 Zeroization (`src/zeroize.hpp`)

FIPS 203 §3.3: "implementers **shall** ensure that intermediate data is destroyed as soon as it is no longer needed... only the designated output can be retained in memory after the algorithm terminates."

```cpp
void secure_zero(void* p, std::size_t n) noexcept;

template <typename T> struct Zeroizing {   // RAII wrapper
  T value;
  ~Zeroizing() { secure_zero(&value, sizeof(T)); }
  // non-copyable, non-movable
};
```

`std::memset` is legally elidable by the optimizer. Use `explicit_bzero` (BSD/glibc ≥2.25), `SecureZeroMemory` (Windows), `memset_s` (C11 Annex K), or a `volatile` function-pointer-to-memset trick. Verify elimination didn't happen by **inspecting the disassembly in a unit test** or checking with a `-O3 -flto` build.

Wrap every stack-resident secret (`Poly` holding `s`, the `σ` buffer, `m'`, the reject flag) in `Zeroizing`.

The two explicit exceptions (§3.3): the `(d,z)` seed may be retained, and `Â` may be cached since it is derivable from public data.

### 8.4 Verification

**`make ctgrind`:** build with `-DMLKEM_CT_TESTING`, mark all secret inputs as uninitialized using valgrind client requests (`VALGRIND_MAKE_MEM_UNDEFINED`), run under `valgrind --tool=memcheck --track-origins=yes`. Any branch or memory index on "uninitialized" data produces a valgrind error. This is the cheapest high-confidence check available and it should be wired into CI. Zero errors is the gate.

**`make dudect`:** statistical timing test — feed two input classes (fixed vs random secret) and run Welch's t-test on timing distributions. A `|t| > 10` indicates a leak. Slower and noisier than ctgrind, but catches microarchitectural leaks ctgrind misses.

---

## 9. Performance

### 9.1 Rough targets (x86-64, AVX2, modern core)

Order-of-magnitude, for calibration only — measure against `mlkem-native` or `pq-crystals/kyber` on **your** machine and record the actual baseline in `docs/reference/invariants.md`:

| Operation | Portable C++ | AVX2 target |
|---|---|---|
| KeyGen | ~100k cycles | ~25–35k cycles |
| Encaps | ~120k cycles | ~35–45k cycles |
| Decaps | ~140k cycles | ~35–50k cycles |

Decaps is slowest because it does a full re-encryption. Do not chase a number; chase the gap against a known-good implementation on identical hardware.

### 9.2 Optimization order (highest leverage first)

1. **4-way (or 8-way) batched Keccak.** Hashing dominates. The 9 matrix-expansion streams and the noise-sampling streams batch perfectly. Biggest single win.
2. **AVX2 NTT.** 16 `int16_t` per register. Fuse layers to keep data in registers across passes; the first 2–3 layers can be merged before a spill is needed.
3. **Lazy reduction.** Use the `docs/bounds.md` table to eliminate provably unnecessary `barrett_reduce` calls.
4. **AVX2 basemul with accumulation.** `poly_basemul_acc` avoids `k` temporary polynomials in the matrix-vector product.
5. **SIMD compress/decompress and CBD.** `vpmulhw` + `vpshufb` for bit packing; BMI2 `pext`/`pdep` for the 10-bit packing.
6. **Cache the expanded matrix `Â`** when the same `ek` is used repeatedly (explicitly permitted by §3.3). Enormous win for batch encapsulation against one key.
7. **Avoid redundant NTTs.** In `decaps`, the re-encryption recomputes `Â` and `NTT(y)`; some intermediates can be shared with the decryption step.

### 9.3 Threading

**Be realistic about this.** A single ML-KEM-768 operation is on the order of 10–20 microseconds. Thread spawn/join and synchronization overhead is comparable to the whole operation. Fine-grained intra-operation threading (e.g. one thread per row of `Â`) will usually be a **net loss**.

Where threading genuinely pays:

- **Batch operations.** `batch::encaps` over N keys: partition the work across a thread pool, one full operation per task, chunked so each task does ≥64 operations. Near-linear scaling.
- **Server-side connection handling.** Naturally parallel at the connection level; the library just needs to be thread-safe and reentrant.

Requirements:
- The library must be **reentrant and free of mutable global state**. Dispatch tables initialized once via `std::call_once` are fine.
- The injected RNG **must be thread-safe** or per-thread. Document this in the `set_rng` contract. A non-thread-safe RNG shared across threads is a catastrophic, silent security bug.
- Pad per-thread output buffers to avoid false sharing (`alignas(std::hardware_destructive_interference_size)`).
- Use a simple work-stealing or static-chunk thread pool. Do not pull in TBB or a large framework.

**Benchmark the threaded path against the serial path and record the crossover point (batch size N) in `docs/reference/invariants.md`.** If threading doesn't win below N=1000, say so plainly and leave the serial path as the default.

### 9.4 Build and dispatch

Compile the portable, AVX2, and (optional) AVX-512 backends as **separate translation units** with different `-m` flags, and select at **runtime** via `cpuid`:

```
src/arch/generic/ntt_generic.cpp   →  (baseline flags)
src/arch/avx2/ntt_avx2.cpp         →  -mavx2 -mbmi2 -mfma
src/arch/avx512/ntt_avx512.cpp     →  -mavx512f -mavx512bw -mavx512vl
```

Do **not** build the whole library with `-march=native` by default — it produces binaries that SIGILL on other machines. Offer it as `make CPU=native` for local benchmarking only.

Detect once at first use with `std::call_once` and store function pointers. Note that AVX-512 downclocking on some server parts can make the AVX-512 path *slower*; benchmark before enabling it by default, and provide `MLKEM_FORCE_ARCH` env override for testing.

---

## 10. Testing

### 10.1 NIST ACVP known-answer tests — the primary gate

The authoritative vectors live in the **`usnistgov/ACVP-Server`** GitHub repository under the generated JSON files for `ML-KEM-keyGen-FIPS203` and `ML-KEM-encapDecaps-FIPS203`. NIST also publishes intermediate-value examples on the CSRC "Cryptographic Standards and Guidelines — Example Values" page.

**Agents have web access. Fetch the current URLs and verify what you download** — paths and file layouts change. Do not trust a URL from memory. Record the exact source URL, file, and a SHA-256 of each downloaded vector file in `tests/kat/PROVENANCE.md`.

**Acquire the vectors in Phase 0, not Phase 7.** They are the exit criterion for Phase 1 (see §12), and discovering a network restriction or a moved path at Phase 7 wastes everything built on an unverified foundation.

> **Context warning.** ACVP vector files are large — hundreds of KB to several MB of JSON. **Never read them into context.** Download with `curl`, inspect structure with `python3 -c` or `jq` and print only what you need (key names, group counts, one truncated example). A single `view` of a vector file can consume a large fraction of the window.

Vector structure:
- **keyGen**: inputs `d`, `z`; expected outputs `ek`, `dk`. Tests `keygen_internal` (Alg. 16).
- **encapDecaps / AFT**: inputs `ek`, `m`; expected `c`, `K`. Tests `encaps_internal` (Alg. 17).
- **encapDecaps / VAL**: inputs `dk`, `c`; expected `K`. Tests `decaps_internal` (Alg. 18), **including the implicit-rejection cases** — some vectors deliberately supply invalid ciphertexts and expect the `J(z‖c)` output.

`make kat` must:
1. Load the JSON.
2. Run every test group.
3. Compare byte-for-byte.
4. Print `PASS n/n` or the first mismatch with a hex diff, **and exit nonzero on any failure**.

The harness must be able to run against **either** the golden model or the real implementation, selected by a flag:

```
make kat              # runs the C++ implementation
make kat-model        # runs the golden model (tools/model.py or tests/model/)
```

`kat-model` is the Phase 1 exit criterion. `kat` is the Phase 7 gate. Build the harness once, in Phase 1, and reuse it.

**No optimization work begins until `make kat` passes.** Tag that commit `kat-clean` so Phase 8 regressions can be bisected and reverted with one command.

### 10.2 Golden model — the key testing strategy

Write a deliberately slow, obviously-correct implementation in `tests/model/`, transcribed **literally** from the FIPS 203 pseudocode:
- Polynomials as `std::array<int32_t, 256>` or Python lists, no Montgomery, no lazy reduction.
- Multiplication via **schoolbook negacyclic convolution**, not NTT.
- `Compress`/`Decompress` via exact 64-bit rational arithmetic.
- Straight-line translation of Algorithms 3–21, no cleverness.

Then differential-test the optimized implementation against it on random inputs at every level: `ntt`, `basemul`, `compress`, `sample_*`, `kpke_*`, `keygen_internal`, `encaps_internal`, `decaps_internal`.

A Python model (`tools/model.py`) is also acceptable and often faster to write correctly; generate vectors offline and commit them. **Build the model before the optimized code, not after.** It is the oracle that makes every subsequent phase debuggable.

**The model must pass the ACVP KATs before Phase 2 begins.** A model that is merely self-consistent is worth very little — it can share a misreading with the implementation it is supposed to check, and the two will agree all the way to a failing Phase 7. A KAT-clean model, by contrast, makes every subsequent differential test *equivalent to a KAT test*: when `poly_basemul` disagrees with the model, you have localized a real spec violation to one function instead of discovering a wall of mismatched hex twenty hours later.

This is the highest-value two hours in the project. Do not skip it, and do not let the model's KAT failures be deferred to "fix later" — if the model can't reproduce NIST's vectors, the notes in `docs/algorithms/` are wrong, and every phase built on them will inherit the error.

### 10.3 Property tests

| Property | Iterations |
|---|---|
| `decaps(dk, encaps(ek).ct) == encaps(ek).ss` | 10⁵ |
| Flipping any single bit of `ct` → `decaps` returns a *different* but *deterministic* value | 10⁴ |
| `decaps` with the wrong `dk` → deterministic garbage, never a crash or a match | 10⁴ |
| `keygen_from_seed(s)` is deterministic — same seed, same `(ek, dk)` | 10³ |
| `invntt(ntt(f)) == f` | 10⁶ |
| `Compress_d(Decompress_d(y)) == y` for all `y` | exhaustive |
| `poly_tomsg(poly_frommsg(m)) == m` | 10⁵ |
| `decaps` runtime is independent of whether the ciphertext is valid | dudect |

### 10.4 Negative / robustness tests

- `ek` of wrong length → `InvalidEncapsKey`, no read past the buffer.
- `ek` with a 12-bit field ≥ 3329 → **modulus check must reject**. Construct this vector by hand.
- `dk` with a corrupted `H(ek)` field → `InvalidDecapsKey`.
- `ct` of wrong length → `InvalidCiphertext`.
- All-zero `ek`, all-0xFF `ek`, all-zero `ct` → no crash, no UB.
- Run the entire test suite under **ASan, UBSan, and MSan** (`make asan`, `make ubsan`, `make msan`). Zero findings is the gate.
- Fuzz `decaps` with libFuzzer or AFL++ over random 1088-byte ciphertexts and random 2400-byte dks. Target: 10⁸ executions, zero crashes.

### 10.5 Cross-implementation interop

Once KATs pass, cross-test against an independent implementation (PQClean or `mlkem-native`, linked into the test binary):
- Our `encaps` against their `decaps` → same shared secret.
- Their `encaps` against our `decaps` → same shared secret.
- 10⁴ iterations in each direction.

This catches serialization endianness bugs that self-consistent testing cannot.

---

## 11. Workflow and context-window management

This project is too large for a single agent session. The following is **mandatory process**, not advice.

### 11.1 Never load the PDFs into context repeatedly

FIPS 203 is ~50 pages. Reading it into context costs a large fraction of the window and it will be evicted.

**In Phase 0, do this once:** extract each algorithm you need into a short markdown file under `docs/algorithms/`, one per algorithm:

```
docs/algorithms/alg07-sample-ntt.md
docs/algorithms/alg09-ntt.md
docs/algorithms/alg13-kpke-keygen.md
docs/algorithms/alg18-decaps-internal.md
...
```

Each file: the pseudocode verbatim, the input/output types, and any footnote from the standard that applies. 20–40 lines each. **Thereafter, read the extracted note, never the PDF.** If a note turns out to be wrong or incomplete, fix the note and record the correction in `DECISIONS.md` — do not re-read the whole PDF.

Do the same for Appendix A: generate `docs/algorithms/appendixA-zetas.md` once and have the zeta-table test compare against it.

### 11.2 The invariants file — re-read at the start of every session

Keep it under 150 lines. Contents:
- Build commands: `make`, `make test`, `make kat`, `make bench`, `make ctgrind`.
- The Montgomery domain convention (one paragraph).
- The coefficient bounds invariant (link to `docs/bounds.md`).
- The constant-time rules (§8.1 condensed to a bullet list).
- "FIPS 203 is normative. Round-3 Kyber is not ML-KEM. Check for the `‖k` domain separator, the absence of `m ← H(m)`, and the absence of a final KDF."
- File-size limit: 400 lines.
- "Run `make test` before ending any session. Do not end a session red."

### 11.3 The rolling state file

Update at the **end of every phase and every session**, before compacting. Structure:

```markdown
## Current state (updated YYYY-MM-DD, session N)

### Done and verified
- [x] Phase 1: reduce + NTT. All unit tests green. Schoolbook differential passes 10^5 cases.
- [x] Phase 2: Keccak vendored from <repo>@<commit>. FIPS 202 KATs pass.

### In progress
- [ ] Phase 3: serialization. poly_tobytes/frombytes done. Compress_du NOT started.

### Next action
Implement `polyvec_compress_du` in src/poly.cpp. Exhaustive test over [0,3329) required.

### Key decisions made this session
- Chose R = 2^16 Montgomery. invntt outputs in Montgomery domain. See DECISIONS.md #4.

### Gotchas discovered
- SampleNTT index order is (rho ‖ j ‖ i), NOT (rho ‖ i ‖ j). Cost 2 hours.
- Compiler turned ct_neq into an early-exit at -O3; added asm barrier.

### Benchmarks (machine: <cpu model>)
keygen: 98k cycles (portable). Baseline mlkem-native AVX2 on same box: 27k.
```

A new session should be able to resume productively from `docs/reference/invariants.md` plus the rolling state file alone, without reading any source.

### 11.4 `DECISIONS.md` — append-only ADR log

One short entry per decision that a future session might otherwise second-guess and reverse:

```markdown
### ADR-004: Montgomery convention
Date: ...
Decision: R = 2^16. zetas stored pre-multiplied by R. invntt folds n^-1 * R^2.
Rationale: matches the well-tested reference lineage; keeps basemul to 4 mults.
Consequences: poly_tobytes must convert out of Montgomery domain first.
```

Also log every vendored third-party file: source repo, commit hash, license, local path.

### 11.5 Session and compaction discipline

1. **One phase per session where possible.** Phases are sized (§12) to fit.
2. **Compact at phase boundaries, never mid-task.** Update the rolling state file *first*, then compact. The state file is what survives; context is not.
3. **Commit at every green checkpoint.** `git commit` after every passing test suite. The commit message is part of the state record: `"Phase 3: compress/decompress, exhaustive tests pass (3329*3 cases)"`.
4. **Use subagents for isolated, exploratory work.** Fetching and parsing ACVP vectors, researching a library's API, investigating a benchmark regression — these generate a lot of throwaway context. Delegate them so the exploration doesn't land in the main window. The subagent returns a summary; the summary goes in the rolling state file.
5. **Read targeted files, not directories.** `src/ntt.cpp` is 300 lines; that's cheap. Recursively reading `src/` is not.
6. **If context exceeds ~70%:** stop starting new work. Finish the current function, make tests green, update the rolling state file, commit, compact.
7. **If a phase is running long,** split it and record the split in `docs/reference/invariants.md` rather than pushing through on a degraded context.

### 11.6 Web access

Agents have web access and should use it for:
- Fetching current ACVP test vector URLs from `usnistgov/ACVP-Server` (do not guess paths).
- Checking the current API and commit hash of any vendored dependency.
- Verifying which branch of `pq-crystals/kyber` is ML-KEM vs round-3 Kyber.
- Looking up intrinsics semantics (Intel Intrinsics Guide) rather than guessing.
- Checking published benchmark figures to calibrate the performance target.

Agents should **not** use the web as a substitute for FIPS 203 on any normative question. Blog posts and StackOverflow answers about "Kyber" are frequently about the round-3 version and will introduce exactly the bugs listed in §0.

Record every URL that materially influenced an implementation decision in `DECISIONS.md`.

---

## 12. Phase plan

Each phase ends with a green test suite, a rolling state file update, and a commit.

| Phase | Deliverable | Exit criterion |
|---|---|---|
| **0. Scaffold** | `git init` + initial commit; toolchain + `lscpu` audit recorded; **ACVP vectors downloaded and checksummed**; repo layout; Makefile skeleton; doctest wired; `docs/reference/invariants.md` / `DECISIONS.md`; `docs/algorithms/*.md` extracted from FIPS 203 | `make test` passes one trivial test; vectors present with `PROVENANCE.md`; PDF not read again after this point |
| **1. Golden model** | Literal transcription of Algorithms 3–21: schoolbook negacyclic multiply, exact integer compress, no Montgomery, no lazy reduction. Plus the reusable KAT harness (`make kat-model`) | **`make kat-model` passes all ML-KEM-768 ACVP vectors.** Hard gate — see §10.2. |
| **2. Arithmetic** | `reduce.hpp`, `ntt.cpp`, zeta tables, `basemul` | Exhaustive Barrett test; NTT roundtrip 10⁶; **schoolbook differential 10⁵** against the KAT-clean model |
| **3. Symmetric** | Keccak vendored, `symmetric.cpp` wrappers | FIPS 202 KATs pass; chunked-squeeze equivalence test passes |
| **4. Serialization** | `poly_tobytes/frombytes`, compress/decompress all `d`, `tomsg/frommsg` | **Exhaustive** compress/decompress over `[0,3329)`; roundtrips; golden vectors |
| **5. Sampling** | `sample_ntt`, `sample_poly_cbd<Eta>` | Range checks, distribution checks, golden vectors incl. **index-order test** |
| **6. K-PKE + ML-KEM** | Algorithms 13–21, input validation, `ct_neq`/`ct_cmov`, zeroization | Differential vs golden model; self-consistency `decaps(encaps())` |
| **7. KAT gate** | ACVP vector fetcher, JSON parser, `make kat` | **All ML-KEM-768 ACVP vectors pass.** Hard gate. |
| **8. Optimize** | 4-way Keccak → AVX2 NTT → lazy reduction → SIMD compress/CBD → runtime dispatch | KATs still pass after every single change; benchmark improvement recorded per step |
| **9. Constant-time** | ctgrind harness, dudect harness, zeroization audit incl. disassembly check | `make ctgrind` zero findings; dudect `|t| < 10` |
| **10. Batch + package** | Thread pool, `batch::` API, static lib, header install, `make package`, README | Batch speedup measured and crossover point documented; ASan/UBSan/MSan clean |

**Rule: KATs must pass at the end of every phase from 7 onward.** An optimization that breaks a KAT is reverted, not debugged forward.

### 12.1 Phase 0 environment audit

Record all of the following in `docs/reference/invariants.md` before writing code. Flag anything missing rather than working around it silently:

- `git --version`, and confirm `git init` + initial commit succeeded
- `c++ --version` / `clang++ --version` — **C++20 support is required**
- `make --version`, `python3 --version`, `curl --version`
- `valgrind --version` (needed for §8.4; note as missing if absent — do not silently drop the ctgrind target)
- `clang-format --version` (optional)
- Full `lscpu` output — needed for the benchmark baseline and to know whether AVX2 / AVX-512BW are available. `grep -o 'avx2\|avx512bw\|bmi2' /proc/cpuinfo | sort -u` is a useful summary.
- Confirm network reach to `github.com` and `raw.githubusercontent.com`. **If vectors cannot be downloaded, stop and report.** Do not proceed to Phase 1 without them.

### 12.2 Human review checkpoints

Stop and report, rather than continuing, at:

- **End of Phase 1** — the oracle is correct or it isn't; everything downstream depends on it.
- **End of Phase 2** — the NTT differential passing is the first real signal the arithmetic layer is sound.
- **End of Phase 7** — correctness is locked; tag `kat-clean` before any optimization.
- **Any point where the spec appears wrong**, a dependency not listed in §7 seems necessary, or copying third-party source seems warranted (§7.3).

Phases 3–6 can run without interruption once a KAT-clean model exists.

---

## 13. Makefile requirements

Required targets:

```
make                 # build libmlkem768.a (portable + runtime dispatch), -O3
make debug           # -O0 -g, assertions on, bounds instrumentation
make test            # unit + property + differential tests
make kat             # ACVP KATs against the implementation (MLKEM_ENABLE_INTERNAL_API=1)
make kat-model       # ACVP KATs against the golden model — Phase 1 gate
make bench           # cycle-count benchmarks
make ctgrind         # constant-time check under valgrind
make dudect          # statistical timing test
make asan / ubsan / msan
make fuzz            # libFuzzer targets
make fetch-vectors   # download + checksum ACVP vectors into tests/kat/
make package         # tarball: lib + headers + README + LICENSE
make install PREFIX= # headers + static lib
make clean / distclean
make format          # clang-format
```

Required variables: `CXX`, `CXXFLAGS`, `PREFIX`, `CPU={portable,avx2,avx512,native}`, `DEBUG={0,1}`.

Baseline flags for the **library**: `-std=c++20 -O3 -Wall -Wextra -Wpedantic -Werror -fno-exceptions -fno-rtti -fvisibility=hidden`.

**Two flag exceptions — set these up in Phase 0 so they don't cost a debugging cycle later:**

1. **Test and bench targets need exceptions enabled.** doctest (and Catch2) use exceptions for assertion reporting and will not compile under `-fno-exceptions`. Give test TUs their own flag variable: `TEST_CXXFLAGS = $(filter-out -fno-exceptions -fno-rtti,$(CXXFLAGS))`. The library itself stays exception-free; only the test harness links with them.

2. **Third-party code gets relaxed warnings.** Vendored Keccak will not survive `-Werror -Wpedantic` — it is C, written to different conventions. Use a separate `THIRDPARTY_CFLAGS = -O3 -Wall` with no `-Werror` and no `-Wpedantic`, and never reformat or "fix" vendored files. Their value is that they are byte-identical to an audited upstream; local edits destroy that and must be recorded in `DECISIONS.md` if genuinely unavoidable.

Per-TU flags for arch backends (see §9.4). Use automatic dependency generation (`-MMD -MP`). Out-of-tree object files in `build/`. Parallel-safe (`make -j`).

**Do not** put `-march=native` in the default `CXXFLAGS`.

---

## 14. Documentation deliverables

- `README.md` — what it is, how to build, how to use, API examples, benchmark table, security notes, FIPS 203 conformance statement, and an explicit list of what is *not* claimed (no CMVP validation, no formal verification).
- `docs/bounds.md` — coefficient invariants (§5.4). Living document.
- `DECISIONS.md` — ADRs and third-party provenance.
- `tests/kat/PROVENANCE.md` — source URL, download date, SHA-256 of every vector file.
- Doxygen-style comments on the public header only. Internal headers get the input/output/domain/bounds contract as a comment on each declaration.

---

## 15. Common failure modes (check these first when a KAT fails)

1. **Missing `‖k` domain separator** in `G(d ‖ k)`. The single most common cause of a self-consistent implementation failing FIPS 203 KATs.
2. **Kyber's FO transform instead of ML-KEM's** — the extra `m ← H(m)`, or a final `KDF(K̄ ‖ H(c))`.
3. **Transposed matrix `Â`** — `SampleNTT(ρ ‖ j ‖ i)`, with `j` at byte 33.
4. **Missing transpose** in `Âᵀ ∘ ŷ` in Encrypt.
5. **Wrong `N` counter order** in noise sampling.
6. **Montgomery domain mismatch** — output off by a constant factor; roundtrip tests pass, KATs fail.
7. **Bit-packing endianness** — FIPS 203 is little-endian at the bit level (Algorithms 3/4).
8. **`int16_t` overflow** in the NTT from over-aggressive lazy reduction.
9. **Compress rounding** — round-half-up, and the exact formula matters at the boundary.
10. **`memcmp` in decaps** instead of `ct_neq` — passes all functional tests, fails every security review.
