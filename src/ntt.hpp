#pragma once
// Number-Theoretic Transform. FIPS 203 §4.3, Algorithms 9-12.
//
// q - 1 = 3328 = 2^8 * 13, so there is a primitive 256th root of unity (zeta = 17) but
// NO 512th root. X^256 + 1 therefore factors into 128 QUADRATICS, not 256 linears, and
// the transform has SEVEN layers, not eight. That is why multiplication in the NTT
// domain is BaseCaseMultiply and not a scalar product.
//
// DOMAIN CONVENTION (DECISIONS.md ADR-004, mirrored in `docs/reference/invariants.md`). R = 2^16.
//   ntt          normal -> normal              (zetas are stored *R, so mont_mul is
//                                               domain-preserving)
//   poly_basemul normal x normal -> *R^-1      (mont_mul introduces one R^-1)
//   invntt       x -> true_inverse(x) * R      (folds 128^-1 with R^2)
//
// The R^-1 from basemul and the R from invntt CANCEL, so
//   invntt(poly_basemul(ntt(a), ntt(b))) == a * b   exactly, with no correction.
// That is the composition the whole scheme is built on. A caller that needs the
// basemul result WITHOUT an inverse transform (K-PKE.KeyGen computes t_hat in the NTT
// domain) must apply poly_to_mont to undo the R^-1.
//
// Consequence worth stating explicitly, because it looks like a bug otherwise:
//   invntt(ntt(f)) == f * R   (mod q),  NOT f.
//
// PHASE 2 BOUNDS INVARIANT: every coefficient is |c| <= 1664 at every layer boundary.
// A barrett_reduce follows every butterfly output. This is deliberately NOT lazy --
// see docs/bounds.md for the per-function table and the Phase 8 opportunities.

#include "params.hpp"
#include "poly.hpp"

#include <cstdint>

namespace mlkem768 {

// Forward NTT, in place. FIPS 203 Algorithm 9.
//   Input  domain: normal      bound: |c| <= 3328   (canonical [0, q) IS accepted)
//   Output domain: normal      bound: |c| <= 1664
//
// NOTE THE ASYMMETRIC INPUT BOUND. It is 3328, not 1664, because K-PKE.Decrypt
// (Alg. 15 line 6) applies NTT to u' straight out of Decompress_du, which produces
// canonical [0, q). That is the standard's own call shape, so the bound accommodates
// it rather than forcing a centering pass. Consequence: the first layer's butterfly
// sum reaches 3328 + 3328 = 6656 rather than 4992. Still 20% of int16_t.
// docs/bounds.md carries the argument and the measurement.
void ntt(Poly& f) noexcept;

// Inverse NTT, in place, including the 128^-1 scaling. FIPS 203 Algorithm 10.
//   Input  domain: normal      bound: |c| <= 4992
//   Output domain: normal * R  bound: |c| <= 1664
//
// THE INPUT BOUND IS 4992, NOT 1664, since Phase 8c removed poly_basemul_acc's
// reduction -- Encrypt and Decrypt feed an unreduced accumulator straight in. Only the
// FIRST layer sees the widened value; it emits barrett_reduce'd output, so layers 2-7
// are unchanged. The two quantities that had to be re-proven for the wider input:
// |t + f[j+len]| <= 9984 (int16_t holds 32767) and the Montgomery input
// |zeta * d| <= 1664 * 9984 = 16,613,376, against montgomery_reduce's STRICT limit of
// q * 2^15 = 109,084,672 -- 15% of it. docs/bounds.md carries the derivation.
void invntt(Poly& f) noexcept;

// The portable implementations, exposed so tests can run them against the AVX2 backend
// directly rather than through the dispatcher. `ntt`/`invntt` above pick one of these at
// runtime; both produce IDENTICAL output, which is what lets `gmake kat` gate the AVX2
// path (tests/unit/test_avx2.cpp).
namespace generic {
void ntt(Poly& f) noexcept;
void invntt(Poly& f) noexcept;
}  // namespace generic

// Base-case multiply. FIPS 203 Algorithm 12: the product of two degree-1 polynomials
// modulo X^2 - gamma.
//   c0 = a0*b0 + a1*b1*gamma
//   c1 = a0*b1 + a1*b0
//   Input  bound: |a|,|b| <= 1664; gamma is a Montgomery-domain constant
//   Output domain: *R^-1 relative to the inputs   bound: |c| <= 1664
void basemul(std::int16_t r[2], const std::int16_t a[2], const std::int16_t b[2],
             std::int16_t gamma) noexcept;

// FIPS 203 Algorithm 11: 128 base-case multiplies with the correct gammas.
//   Input  domain: normal x normal   bound: |c| <= 1664
//   Output domain: *R^-1             bound: |c| <= 1664
void poly_basemul(Poly& r, const Poly& a, const Poly& b) noexcept;

// Accumulating variant: r += a o b. Essential for matrix-vector products, which would
// otherwise need k temporary polynomials (spec §5.3).
//
// LAZY (Phase 8c): this does NOT reduce. Each call adds at most 1664 per coefficient,
// so after the k = 3 calls of a matrix-vector row |r| <= 4992 -- NOT canonical, NOT
// centered. The caller must reduce, and every current caller does: KeyGen via
// poly_to_mont, Encrypt and Decrypt via invntt, both of which absorb the wider input.
//   Input  bound: |a|,|b| <= 1664, |r| unbounded up to 32767 - 1664
//   Output bound: |r| grows by <= 1664 per call  (<= 4992 after k = 3)
void poly_basemul_acc(Poly& r, const Poly& a, const Poly& b) noexcept;


// Multiply every coefficient by R: normal domain -> Montgomery domain. This is how a
// caller undoes the R^-1 that poly_basemul introduces (K-PKE.KeyGen line 18).
//   Input bound: |c| <= 1664   Output domain: *R   bound: |c| <= 1664
void poly_to_mont(Poly& r) noexcept;

// The zeta tables, exposed so the unit test can check them against FIPS 203 Appendix A.
// Stored PRE-MULTIPLIED into the Montgomery domain and centered to [-(q-1)/2, (q-1)/2].
namespace tables {
const std::int16_t* zetas() noexcept;          // 128 entries: zeta^BitRev7(i) * R
const std::int16_t* zetas_basemul() noexcept;  // 128 entries: zeta^(2*BitRev7(i)+1) * R
}  // namespace tables

}  // namespace mlkem768
