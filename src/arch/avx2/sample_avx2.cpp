// SIMD rejection sampler. FIPS 203 Algorithm 7, lines 5-15.
//
// VARIABLE-TIME BY DESIGN, on PUBLIC input. See src/sample.hpp's banner and
// rej_table_avx2.hpp's header before changing anything here -- this file deliberately
// contains the one data-indexed table in the library, and it is correct (ADR-027).
//
// Output is BIT-IDENTICAL to the scalar rej_uniform: same acceptance rule, same order,
// same coefficients. That equivalence is what lets `gmake kat` gate it.
//
// DIVISION AUDIT: no runtime `/` or `%`. The "C[1]/16" and "C[1] mod 16" of Algorithm 7
// lines 6-7 are a shift and a mask, exactly as in the scalar path.

#include "params.hpp"
#include "rej_table_avx2.hpp"

#include <immintrin.h>
#include <cstdint>
#include <cstddef>

namespace mlkem768::avx2 {

// Process `buflen` bytes, appending accepted coefficients to r[ctr..]. Returns the new
// count. Mirrors the scalar signature so the dispatcher is a straight swap.
int rej_uniform(std::int16_t* r, int ctr, const std::uint8_t* buf, std::size_t buflen) noexcept {
  // 12 bytes -> 8 candidates per step. Stop the vector path with a full 8-lane store's
  // worth of slack so a store can never run past r[255]; the caller's scalar tail
  // finishes the last few. (Writing 8 lanes when 2 slots remain would corrupt whatever
  // follows the Poly -- the reason this bound is 248 and not 256.)
  constexpr int kVecLimit = params::N - 8;

  const __m128i qv    = _mm_set1_epi16(static_cast<short>(params::Q));
  const __m128i mask12 = _mm_set1_epi16(0x0FFF);
  // Byte pattern turning 12 packed bytes into 8 16-bit lanes: lane 2k takes bytes
  // (3k, 3k+1), lane 2k+1 takes (3k+1, 3k+2) -- the two 12-bit fields of each 3-byte
  // group, still unaligned at this point.
  const __m128i spread = _mm_set_epi8(11, 10, 10, 9, 8, 7, 7, 6, 5, 4, 4, 3, 2, 1, 1, 0);

  std::size_t pos = 0;
  // NOTE pos + 16, not pos + 12: the load reads a full 16 bytes while the step only
  // CONSUMES 12, so the guard must cover the load width or it over-reads the buffer by
  // up to 4 bytes. ASan and valgrind would both flag it; the arithmetic would not.
  while (ctr <= kVecLimit && pos + 16 <= buflen) {
    const __m128i raw = _mm_loadu_si128(reinterpret_cast<const __m128i*>(buf + pos));
    pos += 12;

    const __m128i t  = _mm_shuffle_epi8(raw, spread);
    // Even lanes are the low field (mask off the top nibble); odd lanes are the high
    // field (shift it down). blend picks lanes 1,3,5,7 from the shifted copy.
    const __m128i lo = _mm_and_si128(t, mask12);
    const __m128i hi = _mm_srli_epi16(t, 4);
    const __m128i v  = _mm_blend_epi16(lo, hi, 0xAA);

    // Accept where v < q. v <= 4095 so a signed compare is exact.
    const __m128i acc = _mm_cmpgt_epi16(qv, v);
    // packs_epi16 collapses each 16-bit lane to one byte, so movemask gives 8 bits.
    const int m = _mm_movemask_epi8(_mm_packs_epi16(acc, acc)) & 0xFF;

    // THE DATA-INDEXED LOOKUP. Index derives from rho, which is public (ADR-027).
    const __m128i sh = _mm_loadu_si128(
        reinterpret_cast<const __m128i*>(kRejShuffle.e[static_cast<std::size_t>(m)].data()));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(r + ctr), _mm_shuffle_epi8(v, sh));
    ctr += __builtin_popcount(static_cast<unsigned>(m));
  }

  // Scalar tail: the leftover bytes, and everything once ctr passes kVecLimit.
  while (ctr < params::N && pos + 3 <= buflen) {
    const std::uint32_t c0 = buf[pos + 0];
    const std::uint32_t c1 = buf[pos + 1];
    const std::uint32_t c2 = buf[pos + 2];
    pos += 3;
    const std::uint32_t d1 = c0 | ((c1 & 0x0Fu) << 8);
    const std::uint32_t d2 = (c1 >> 4) | (c2 << 4);
    if (d1 < static_cast<std::uint32_t>(params::Q)) { r[ctr] = static_cast<std::int16_t>(d1); ++ctr; }
    if (d2 < static_cast<std::uint32_t>(params::Q) && ctr < params::N) {
      r[ctr] = static_cast<std::int16_t>(d2); ++ctr;
    }
  }
  return ctr;
}

}  // namespace mlkem768::avx2
