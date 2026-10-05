// AVX2 forward and inverse NTT. FIPS 203 Algorithms 9 and 10, 16 coefficients at a time.
//
// OUTPUT IS BIT-IDENTICAL TO src/ntt.cpp. That is the entire basis on which `gmake kat`
// gates this file: same butterflies, same order, same reduction in the same places,
// just sixteen lanes wide. Deliberately NOT lazy -- coefficients stay |c| <= 1664 at
// every layer boundary exactly as docs/bounds.md states. Lazy reduction is Phase 8c and
// it CHANGES the values, so it cannot be smuggled in here.
//
// DIVISION AUDIT: no runtime `/` or `%`. All index arithmetic is compile-time.
//
// Layout: 256 int16_t = 16 __m256i. Vector v holds coefficients 16v .. 16v+15.
// Layers len = 128, 64, 32, 16 pair DIFFERENT vectors. Layers len = 8, 4, 2 pair lanes
// INSIDE a vector and need a shuffle first -- see zetas_avx2.hpp for why the zeta lane
// tables for those three are generated rather than written.

#include "poly.hpp"
#include "params.hpp"
#include "reduce.hpp"

#include "reduce_avx2.hpp"
#include "zetas_avx2.hpp"

#include <immintrin.h>
#include <cstdint>

namespace mlkem768::avx2 {
namespace {

inline __m256i ld(const std::int16_t* p) { return _mm256_loadu_si256(reinterpret_cast<const __m256i*>(p)); }
inline void    st(std::int16_t* p, __m256i v) { _mm256_storeu_si256(reinterpret_cast<__m256i*>(p), v); }

// Cooley-Tukey butterfly, matching src/ntt.cpp exactly:
//   t = mont_mul(zeta, hi);  hi = barrett(lo - t);  lo = barrett(lo + t)
[[gnu::always_inline]] inline void ct_bfly(__m256i& lo, __m256i& hi, __m256i z, __m256i zq) noexcept {
  const __m256i t = mont_mul_vec(hi, z, zq);
  // LAZY (Phase 8c, removal #3), matching src/ntt.cpp: no reduction here. |t| < q, so
  // a layer adds 3328 and B_7 = 26624 < 32767. avx2::ntt reduces once at the end.
  const __m256i u = lo;
  hi = _mm256_sub_epi16(u, t);
  lo = _mm256_add_epi16(u, t);
}

// Gentleman-Sande butterfly, matching src/ntt.cpp's invntt:
//   t = lo(OLD);  lo = barrett(t + hi);  hi = barrett(mont_mul(zeta, hi - t))
// The subtraction uses the SAVED old lo -- this is not the CT butterfly reversed.
[[gnu::always_inline]] inline void gs_bfly(__m256i& lo, __m256i& hi, __m256i z, __m256i zq) noexcept {
  const __m256i t = lo;
  lo = barrett_reduce_vec(_mm256_add_epi16(t, hi));
  const __m256i d = _mm256_sub_epi16(hi, t);
  // LAZY (Phase 8c, removal #2), matching src/ntt.cpp exactly: mont_mul already
  // returns |.| < q, so the barrett here was canonicalization only. The SUM-side
  // barrett above stays -- that half grows and must be reduced every layer.
  hi = mont_mul_vec(d, z, zq);
}

inline __m256i bcast(std::int16_t v) { return _mm256_set1_epi16(v); }

inline const std::int16_t* lane_z (const LaneTable& t, int u) { return t.z[static_cast<std::size_t>(u)].data(); }
inline const std::int16_t* lane_zq(const LaneTable& t, int u) { return t.zq[static_cast<std::size_t>(u)].data(); }

}  // namespace

void ntt(Poly& f) noexcept {
  __m256i v[16];
  for (int i = 0; i < 16; ++i) v[i] = ld(f.c.data() + 16 * i);

  // --- len = 128: v <-> v+8, one zeta for the whole layer (kZ[1]) ---
  {
    const __m256i z = bcast(kZ[1]), zq = bcast(qinv_of(kZ[1]));
    for (int i = 0; i < 8; ++i) ct_bfly(v[i], v[i + 8], z, zq);
  }
  // --- len = 64: two groups of 8 vectors, v <-> v+4 ---
  for (int g = 0; g < 2; ++g) {
    const std::int16_t zz = kZ[static_cast<std::size_t>(2 + g)];
    const __m256i z = bcast(zz), zq = bcast(qinv_of(zz));
    for (int i = 0; i < 4; ++i) ct_bfly(v[8 * g + i], v[8 * g + i + 4], z, zq);
  }
  // --- len = 32: four groups of 4 vectors, v <-> v+2 ---
  for (int g = 0; g < 4; ++g) {
    const std::int16_t zz = kZ[static_cast<std::size_t>(4 + g)];
    const __m256i z = bcast(zz), zq = bcast(qinv_of(zz));
    for (int i = 0; i < 2; ++i) ct_bfly(v[4 * g + i], v[4 * g + i + 2], z, zq);
  }
  // --- len = 16: eight groups of 2 vectors, v <-> v+1 ---
  for (int g = 0; g < 8; ++g) {
    const std::int16_t zz = kZ[static_cast<std::size_t>(8 + g)];
    const __m256i z = bcast(zz), zq = bcast(qinv_of(zz));
    ct_bfly(v[2 * g], v[2 * g + 1], z, zq);
  }

  // --- len = 8: partners are the two 128-bit halves. Split two vectors at a time so
  //     both halves of the work stay 256 bits wide. ---
  for (int u = 0; u < 8; ++u) {
    __m256i& V0 = v[2 * u];
    __m256i& V1 = v[2 * u + 1];
    __m256i A = _mm256_permute2x128_si256(V0, V1, 0x20);
    __m256i B = _mm256_permute2x128_si256(V0, V1, 0x31);
    ct_bfly(A, B, ld(lane_z(kLane8, u)), ld(lane_zq(kLane8, u)));
    V0 = _mm256_permute2x128_si256(A, B, 0x20);
    V1 = _mm256_permute2x128_si256(A, B, 0x31);
  }
  // --- len = 4: 64-bit granularity ---
  for (int u = 0; u < 8; ++u) {
    __m256i& V0 = v[2 * u];
    __m256i& V1 = v[2 * u + 1];
    __m256i A = _mm256_unpacklo_epi64(V0, V1);
    __m256i B = _mm256_unpackhi_epi64(V0, V1);
    ct_bfly(A, B, ld(lane_z(kLane4, u)), ld(lane_zq(kLane4, u)));
    V0 = _mm256_unpacklo_epi64(A, B);
    V1 = _mm256_unpackhi_epi64(A, B);
  }
  // --- len = 2: 32-bit granularity. shuffle_epi32(0xD8) de-interleaves the 32-bit
  //     blocks so unpack*_epi64 then separates partners; it is an involution, so the
  //     same shuffle undoes it. ---
  for (int u = 0; u < 8; ++u) {
    __m256i V0 = _mm256_shuffle_epi32(v[2 * u], 0xD8);
    __m256i V1 = _mm256_shuffle_epi32(v[2 * u + 1], 0xD8);
    __m256i A = _mm256_unpacklo_epi64(V0, V1);
    __m256i B = _mm256_unpackhi_epi64(V0, V1);
    ct_bfly(A, B, ld(lane_z(kLane2, u)), ld(lane_zq(kLane2, u)));
    V0 = _mm256_unpacklo_epi64(A, B);
    V1 = _mm256_unpackhi_epi64(A, B);
    v[2 * u]     = _mm256_shuffle_epi32(V0, 0xD8);
    v[2 * u + 1] = _mm256_shuffle_epi32(V1, 0xD8);
  }

  // The single final reduction the lazy butterflies require. Same argument as
  // src/ntt.cpp's: NOT optional -- basemul would otherwise break montgomery_reduce's
  // strict contract -- and it reproduces the old per-butterfly representative exactly,
  // so this output stays bit-identical to the portable path AND to the pre-8c version.
  for (int i = 0; i < 16; ++i) v[i] = barrett_reduce_vec(v[i]);

  for (int i = 0; i < 16; ++i) st(f.c.data() + 16 * i, v[i]);
}

void invntt(Poly& f) noexcept {
  __m256i v[16];
  for (int i = 0; i < 16; ++i) v[i] = ld(f.c.data() + 16 * i);

  // Inverse order: the same seven layers, widths ascending, zetas descending. The
  // intra-vector layers come FIRST here, and each uses the same lane table as the
  // forward pass -- the shuffle is identical, only the butterfly differs.
  for (int u = 0; u < 8; ++u) {
    __m256i V0 = _mm256_shuffle_epi32(v[2 * u], 0xD8);
    __m256i V1 = _mm256_shuffle_epi32(v[2 * u + 1], 0xD8);
    __m256i A = _mm256_unpacklo_epi64(V0, V1);
    __m256i B = _mm256_unpackhi_epi64(V0, V1);
    gs_bfly(A, B, ld(lane_z(kLane2Inv, u)), ld(lane_zq(kLane2Inv, u)));
    V0 = _mm256_unpacklo_epi64(A, B);
    V1 = _mm256_unpackhi_epi64(A, B);
    v[2 * u]     = _mm256_shuffle_epi32(V0, 0xD8);
    v[2 * u + 1] = _mm256_shuffle_epi32(V1, 0xD8);
  }
  for (int u = 0; u < 8; ++u) {
    __m256i& V0 = v[2 * u];
    __m256i& V1 = v[2 * u + 1];
    __m256i A = _mm256_unpacklo_epi64(V0, V1);
    __m256i B = _mm256_unpackhi_epi64(V0, V1);
    gs_bfly(A, B, ld(lane_z(kLane4Inv, u)), ld(lane_zq(kLane4Inv, u)));
    V0 = _mm256_unpacklo_epi64(A, B);
    V1 = _mm256_unpackhi_epi64(A, B);
  }
  for (int u = 0; u < 8; ++u) {
    __m256i& V0 = v[2 * u];
    __m256i& V1 = v[2 * u + 1];
    __m256i A = _mm256_permute2x128_si256(V0, V1, 0x20);
    __m256i B = _mm256_permute2x128_si256(V0, V1, 0x31);
    gs_bfly(A, B, ld(lane_z(kLane8Inv, u)), ld(lane_zq(kLane8Inv, u)));
    V0 = _mm256_permute2x128_si256(A, B, 0x20);
    V1 = _mm256_permute2x128_si256(A, B, 0x31);
  }
  for (int g = 7; g >= 0; --g) {                       // len=16: k = 15-g, not 8+g
    const std::int16_t zz = kZ[static_cast<std::size_t>(15 - g)];
    const __m256i z = bcast(zz), zq = bcast(qinv_of(zz));
    gs_bfly(v[2 * g], v[2 * g + 1], z, zq);
  }
  for (int g = 3; g >= 0; --g) {                       // len=32: k = 7-g
    const std::int16_t zz = kZ[static_cast<std::size_t>(7 - g)];
    const __m256i z = bcast(zz), zq = bcast(qinv_of(zz));
    for (int i = 1; i >= 0; --i) gs_bfly(v[4 * g + i], v[4 * g + i + 2], z, zq);
  }
  for (int g = 1; g >= 0; --g) {                       // len=64: k = 3-g
    const std::int16_t zz = kZ[static_cast<std::size_t>(3 - g)];
    const __m256i z = bcast(zz), zq = bcast(qinv_of(zz));
    for (int i = 3; i >= 0; --i) gs_bfly(v[8 * g + i], v[8 * g + i + 4], z, zq);
  }
  {
    const __m256i z = bcast(kZ[1]), zq = bcast(qinv_of(kZ[1]));
    for (int i = 7; i >= 0; --i) gs_bfly(v[i], v[i + 8], z, zq);
  }

  // Fold 128^-1 with R^2 as the single constant 1441 (ADR-004). SEVEN layers, so the
  // raw transform's factor is 128, not 256.
  constexpr std::int16_t kScale = detail::center(static_cast<std::int32_t>(
      (static_cast<std::int64_t>(R2_MOD_Q) * INV_128) % params::Q));
  static_assert(kScale == 1441, "R^2 * 128^-1 mod q -- must match src/ntt.cpp");
  const __m256i z = bcast(kScale), zq = bcast(qinv_of(kScale));
  for (int i = 0; i < 16; ++i) v[i] = barrett_reduce_vec(mont_mul_vec(v[i], z, zq));

  for (int i = 0; i < 16; ++i) st(f.c.data() + 16 * i, v[i]);
}

}  // namespace mlkem768::avx2
