#pragma once
// AVX2 reduction primitives. 16 int16_t lanes per __m256i.
//
// THESE MUST RETURN BIT-IDENTICAL RESULTS TO src/reduce.hpp, lane for lane.
// That is not a style preference: `gmake kat` gates the AVX2 NTT only because its
// output equals the portable NTT's, and the portable NTT's output is determined by
// exactly which representative montgomery_reduce and barrett_reduce return. Both are
// proven equal EXHAUSTIVELY over all 65 536 int16_t inputs in tests/unit/test_avx2.cpp
// -- sampled agreement would not be evidence (docs/bounds.md, "Statistical power").
//
// THIS HEADER IS AVX2-ONLY. Include it only from a TU compiled with -mavx2.

#include "params.hpp"
#include "reduce.hpp"

#include <immintrin.h>
#include <cstdint>

namespace mlkem768::avx2 {

// Montgomery multiply by a CONSTANT zeta, four lanes' worth of arithmetic per
// instruction. Returns a*z*R^-1 mod q with |r| < q, matching mont_mul(a, z).
//
//   scalar:  p = a*z;  m = (int16)(lo16(p) * QINV);  r = (p - m*q) >> 16
//
// In SIMD, lo16(p) is mullo(a,z) and the high half is mulhi(a,z). The subtraction's
// low halves cancel EXACTLY -- p - m*q is divisible by 2^16 by construction, since
// m == p*QINV (mod 2^16) and q*QINV == 1 (mod 2^16) -- so there is no borrow and the
// shifted result is simply mulhi(a,z) - mulhi(m,q). No 32-bit widening needed.
//
// `zqinv` MUST be z*QINV mod 2^16, precomputed. Multiplication mod 2^16 is
// associative, so mullo(a, zqinv) == mullo(mullo(a,z), QINV) -- the same m, one
// vpmullw cheaper. That one saved multiply per butterfly is why the zeta tables are
// stored in pairs. (Technique learned from pq-crystals' avx2/ntt.S; see
// docs/notes/08b-avx2-ntt.md.)
[[gnu::always_inline]] inline __m256i mont_mul_vec(__m256i a, __m256i z,
                                                   __m256i zqinv) noexcept {
  const __m256i qv = _mm256_set1_epi16(static_cast<short>(params::Q));
  const __m256i m  = _mm256_mullo_epi16(a, zqinv);        // m = lo16(a*z)*QINV
  const __m256i hi = _mm256_mulhi_epi16(a, z);            // hi16(a*z), signed
  const __m256i t  = _mm256_mulhi_epi16(m, qv);           // hi16(m*q),  signed
  return _mm256_sub_epi16(hi, t);
}

// Barrett reduce every lane. Matches barrett_reduce(a): output |r| <= 1664.
//
//   scalar:  t = (V*a + 2^25) >> 26;  r = a - t*q      with V = BARRETT_V = 20159
//
// Rewritten for 16-bit lanes: mulhi(a,V) is floor(V*a / 2^16), so writing V*a as
// hi*2^16 + lo with 0 <= lo < 2^16,
//
//   (V*a + 2^25) >> 26 == floor((hi + 512 + lo/2^16) / 1024) == floor((hi + 512)/1024)
//
// because for an integer X and 0 <= f < 1, floor((X+f)/1024) == floor(X/1024): X+f
// cannot reach the next multiple of 1024 unless X already is one. So the +2^25
// rounding term becomes a +512 before an arithmetic shift by 10, with no 32-bit
// intermediate anywhere.
[[gnu::always_inline]] inline __m256i barrett_reduce_vec(__m256i a) noexcept {
  const __m256i vv = _mm256_set1_epi16(static_cast<short>(BARRETT_V));
  const __m256i qv = _mm256_set1_epi16(static_cast<short>(params::Q));
  __m256i t = _mm256_mulhi_epi16(a, vv);                  // floor(V*a / 2^16)
  t = _mm256_add_epi16(t, _mm256_set1_epi16(512));        // the 2^25 rounding term
  t = _mm256_srai_epi16(t, 10);                           // arithmetic, not logical
  return _mm256_sub_epi16(a, _mm256_mullo_epi16(t, qv));
}

// Montgomery multiply where BOTH operands vary, so no z*QINV can be precomputed.
// Four multiplies instead of three -- the saving in mont_mul_vec depends on one operand
// being a compile-time-known constant, which is false for basemul's a*b products.
[[gnu::always_inline]] inline __m256i mont_mul_vec_v(__m256i a, __m256i b) noexcept {
  const __m256i qv   = _mm256_set1_epi16(static_cast<short>(params::Q));
  const __m256i qinv = _mm256_set1_epi16(static_cast<short>(QINV));
  const __m256i lo = _mm256_mullo_epi16(a, b);
  const __m256i m  = _mm256_mullo_epi16(lo, qinv);
  const __m256i hi = _mm256_mulhi_epi16(a, b);
  return _mm256_sub_epi16(hi, _mm256_mulhi_epi16(m, qv));
}

}  // namespace mlkem768::avx2
