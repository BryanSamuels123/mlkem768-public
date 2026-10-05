// AVX2 base-case multiply with accumulation. FIPS 203 Algorithms 11/12.
// Spec §9.2 item 4 — the one §9.2 item that was never considered until the Phase 8e
// audit found it had been dropped silently by ADR-017's consequence line.
//
// CONSTANT-TIME, on SECRET data: the operands are ŝ, ŷ and t̂. No branch, no table, no
// division. It does use `vpshufb`, and only ever with a CONSTANT selector, so neither
// ADR-027 (memory table, public ρ) nor ADR-028 (register table, secret selector) is
// being claimed here — a constant-selector permute is not a lookup at all.
//
// ############################################################################
// # THE INTERNAL barrett_reduce CALLS STAY. THEY ARE NOT DEAD WEIGHT.        #
// ############################################################################
// Phase 8c site #4 proposed removing them and PROVED IT UNSAFE: with the accumulator
// already unreduced (site #1), |t| would rise 1664 -> 2q = 6658, the accumulator to
// k*6658 = 19974, and `invntt`'s layer-1 sum to 39 948 -- past int16_t's 32 767. A SIMD
// rewrite is exactly where such a reduction disappears quietly, so both are explicit
// below and the bound is restated. docs/bounds.md carries the derivation.
//
// LAYOUT. Ours is the PORTABLE order: pair m occupies coefficients (2m, 2m+1),
// interleaved. pq-crystals' NTT instead leaves a permuted order in which the halves are
// already separated, so their basemul needs no deinterleave; adopting that order is
// EXCLUDED by ADR-031, deliberately. We therefore deinterleave into even/odd halves,
// multiply, and re-interleave -- the accepted price of keeping an output order that the
// portable backend, the model differentials, serialization and the ctgrind probes all
// depend on.
//
// DIVISION AUDIT: no runtime `/` or `%`.

#include "params.hpp"
#include "poly.hpp"
#include "reduce.hpp"
#include "reduce_avx2.hpp"

#include <immintrin.h>
#include <array>
#include <cstdint>

namespace mlkem768::avx2 {
namespace {

using detail::bitrev7;
using detail::pow_mod;
using detail::to_mont;

// GENERATED, never transcribed -- the same consteval derivation as src/ntt.cpp's
// make_zetas_basemul, so the two cannot disagree. tests/unit/test_avx2.cpp asserts this
// equals tables::zetas_basemul(), which test_arith.cpp already checks against FIPS 203
// Appendix A table 2.
consteval std::array<std::int16_t, 128> gen_gamma() {
  std::array<std::int16_t, 128> z{};
  for (int i = 0; i < 128; ++i)
    z[static_cast<std::size_t>(i)] = to_mont(pow_mod(params::ZETA, 2 * bitrev7(i) + 1));
  return z;
}
inline constexpr auto kGamma = gen_gamma();

consteval std::int16_t qinv_of(std::int16_t z) {
  const std::uint32_t p = static_cast<std::uint32_t>(static_cast<std::uint16_t>(z)) *
                          static_cast<std::uint32_t>(QINV);
  return static_cast<std::int16_t>(static_cast<std::uint16_t>(p));
}
consteval std::array<std::int16_t, 128> gen_gamma_qinv() {
  std::array<std::int16_t, 128> z{};
  for (int i = 0; i < 128; ++i) z[static_cast<std::size_t>(i)] = qinv_of(kGamma[static_cast<std::size_t>(i)]);
  return z;
}
inline constexpr auto kGammaQ = gen_gamma_qinv();

static_assert(kGamma[0] == to_mont(params::ZETA), "gamma[0] derivation wrong");

// Deinterleave 16 int16 pairs held in two vectors into (evens, odds).
// _mm256_shuffle_epi8 with a CONSTANT selector, then a 64-bit lane fix-up: pshufb works
// inside 128-bit lanes, so permute4x64 restores the across-lane order afterwards.
[[gnu::always_inline]] inline void split(__m256i x, __m256i y, __m256i& ev, __m256i& od) {
  const __m256i sh = _mm256_setr_epi8(0,1,4,5,8,9,12,13, 2,3,6,7,10,11,14,15,
                                      0,1,4,5,8,9,12,13, 2,3,6,7,10,11,14,15);
  const __m256i a = _mm256_permute4x64_epi64(_mm256_shuffle_epi8(x, sh), 0xD8);
  const __m256i b = _mm256_permute4x64_epi64(_mm256_shuffle_epi8(y, sh), 0xD8);
  ev = _mm256_permute2x128_si256(a, b, 0x20);
  od = _mm256_permute2x128_si256(a, b, 0x31);
}

// Inverse of split().
[[gnu::always_inline]] inline void join(__m256i ev, __m256i od, __m256i& x, __m256i& y) {
  const __m256i lo = _mm256_unpacklo_epi16(ev, od);
  const __m256i hi = _mm256_unpackhi_epi16(ev, od);
  x = _mm256_permute2x128_si256(lo, hi, 0x20);
  y = _mm256_permute2x128_si256(lo, hi, 0x31);
}

}  // namespace

// Exposed so tests can tie the generated table to the Appendix-A-checked one.
const std::int16_t* gamma_table() noexcept { return kGamma.data(); }

// r += a o b  (accumulating). Output domain x R^-1 (ADR-004).
// Bit-identical to poly_basemul_acc: same mont_mul, same TWO barrett_reduce per pair.
void basemul_acc(Poly& r, const Poly& a, const Poly& b) noexcept {
  const __m256i qv = _mm256_set1_epi16(static_cast<short>(params::Q));
  for (int g = 0; g < 8; ++g) {                 // 8 groups x 16 pairs = 128 pairs
    const auto* ap = reinterpret_cast<const __m256i*>(a.c.data() + 32 * g);
    const auto* bp = reinterpret_cast<const __m256i*>(b.c.data() + 32 * g);
    auto* rp = reinterpret_cast<__m256i*>(r.c.data() + 32 * g);

    __m256i a0, a1, b0, b1;
    split(_mm256_loadu_si256(ap), _mm256_loadu_si256(ap + 1), a0, a1);
    split(_mm256_loadu_si256(bp), _mm256_loadu_si256(bp + 1), b0, b1);

    const __m256i gm = _mm256_loadu_si256(
        reinterpret_cast<const __m256i*>(kGamma.data() + 16 * g));
    const __m256i gq = _mm256_loadu_si256(
        reinterpret_cast<const __m256i*>(kGammaQ.data() + 16 * g));

    // c0 = a0*b0 + (a1*b1)*gamma ; c1 = a0*b1 + a1*b0   -- Algorithm 12, verbatim.
    __m256i t = mont_mul_vec_v(a1, b1);
    t = mont_mul_vec(t, gm, gq);
    const __m256i c0 = _mm256_add_epi16(t, mont_mul_vec_v(a0, b0));
    const __m256i c1 = _mm256_add_epi16(mont_mul_vec_v(a0, b1), mont_mul_vec_v(a1, b0));

    // BOTH reductions kept -- see the banner. |c0|,|c1| < 2q before, <= 1664 after.
    const __m256i r0 = barrett_reduce_vec(c0);
    const __m256i r1 = barrett_reduce_vec(c1);

    __m256i o0, o1;
    join(r0, r1, o0, o1);
    // Accumulate WITHOUT reducing: Phase 8c removal #1. |r| <= k*1664 = 4992 after the
    // k = 3 calls of one matrix-vector row, attained EXACTLY, with no slack.
    _mm256_storeu_si256(rp,     _mm256_add_epi16(_mm256_loadu_si256(rp), o0));
    _mm256_storeu_si256(rp + 1, _mm256_add_epi16(_mm256_loadu_si256(rp + 1), o1));
    (void)qv;
  }
}

// Non-accumulating variant: r = a o b.
void basemul(Poly& r, const Poly& a, const Poly& b) noexcept {
  for (auto& c : r.c) c = 0;
  basemul_acc(r, a, b);
}

}  // namespace mlkem768::avx2
