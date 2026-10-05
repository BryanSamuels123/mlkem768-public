// SIMD centered binomial distribution. FIPS 203 Algorithm 8, eta = 2.
//
// ############################################################################
// # CONSTANT-TIME, ON SECRET sigma. The OPPOSITE requirement to the sampler   #
// # in sample_avx2.cpp, which sits one directory over and is variable-time.   #
// ############################################################################
//
// ADR-027 PERMITS A DATA-INDEXED TABLE IN rej_uniform. THAT PERMISSION DOES NOT
// REACH THIS FILE. rej_uniform's index derives from rho, which FIPS 203 publishes;
// this function's input is PRF(sigma, N) and its output IS the secret key.
//
// BUT THERE IS A DISTINCTION WORTH STATING, BECAUSE IT IS SUBTLE AND A FUTURE SESSION
// COULD "FIX" IT INTO A REAL BUG:
//
//   * A MEMORY-RESIDENT table indexed by secret data is forbidden. The address depends
//     on the secret, so which cache line is touched depends on the secret, and cache
//     timing recovers it. That is what the no-table-lookups rule in `docs/reference/invariants.md` is about.
//
//   * `vpshufb` with a secret selector is NOT that. Both the table and the index live
//     in REGISTERS. No address is computed, no memory is read, nothing enters a cache.
//     vpshufb has fixed latency and throughput on every microarchitecture that has it,
//     independent of operand values. It is a permutation instruction, not a load.
//
// This file uses the second kind: a 16-entry nibble->coefficient map held in one xmm
// register for the lifetime of the call. It is as constant-time as an XOR, and
// replacing it with arithmetic would be slower for no security gain. See ADR-028.
//
// THE STRUCTURE THAT MAKES THIS WORK. Algorithm 8 at eta = 2 gives each coefficient
// 2*eta = 4 bits, and those 4 bits always lie inside ONE byte:
//
//     coefficient 2b = low  nibble of byte b
//     coefficient 2b+1 = high nibble of byte b
//     nibble n  ->  popcount(n & 3) - popcount((n >> 2) & 3)   in [-2, 2]
//
// CBD is therefore byte-local, which is also why it can be verified EXHAUSTIVELY: the
// entire input-to-output map is 256 byte values x 128 positions, not 2^1024 buffers.
//
// eta = 3 stays scalar. Its fields are 6 bits and cross byte boundaries, so none of the
// above applies; ML-KEM-768 never calls it (eta1 = eta2 = 2) and ADR-009 keeps it alive
// for a future ML-KEM-512 port, where correctness matters and speed does not yet.
//
// DIVISION AUDIT: no runtime `/` or `%`.

#include "params.hpp"
#include "poly.hpp"

#include <immintrin.h>
#include <array>
#include <cstdint>

namespace mlkem768::avx2 {
namespace {

// DERIVED, never transcribed: popcount(n & 3) - popcount((n >> 2) & 3).
consteval std::array<std::int8_t, 16> make_cbd2_lut() {
  std::array<std::int8_t, 16> t{};
  for (int n = 0; n < 16; ++n) {
    int x = ((n >> 0) & 1) + ((n >> 1) & 1);
    int y = ((n >> 2) & 1) + ((n >> 3) & 1);
    t[static_cast<std::size_t>(n)] = static_cast<std::int8_t>(x - y);
  }
  return t;
}
inline constexpr auto kCbd2 = make_cbd2_lut();
static_assert(kCbd2[0] == 0 && kCbd2[3] == 2 && kCbd2[12] == -2 && kCbd2[15] == 0,
              "nibble map derivation is wrong");

}  // namespace

// eta = 2: 128 input bytes -> 256 coefficients, centered in [-2, 2].
// Bit-identical to sample_poly_cbd<2>.
void cbd2(Poly& f, const std::uint8_t* buf) noexcept {
  const __m128i lut  = _mm_loadu_si128(reinterpret_cast<const __m128i*>(kCbd2.data()));
  const __m128i m0f  = _mm_set1_epi8(0x0F);

  // 16 input bytes -> 32 coefficients per step. 128-bit ops deliberately: AVX2's
  // 256-bit unpack/shuffle work per 128-bit lane, and the resulting lane bookkeeping
  // is the single most likely place to introduce a silent ordering bug. The win here
  // is the nibble LUT, not the register width.
  for (int i = 0; i < 8; ++i) {
    const __m128i v = _mm_loadu_si128(reinterpret_cast<const __m128i*>(buf + 16 * i));

    const __m128i lo = _mm_and_si128(v, m0f);
    const __m128i hi = _mm_and_si128(_mm_srli_epi16(v, 4), m0f);

    // REGISTER-RESIDENT permutation, not a memory lookup. See the header.
    const __m128i clo = _mm_shuffle_epi8(lut, lo);      // coefficients 2b
    const __m128i chi = _mm_shuffle_epi8(lut, hi);      // coefficients 2b+1

    // Interleave to the emission order 2b, 2b+1, 2b+2, ...
    const __m128i p0 = _mm_unpacklo_epi8(clo, chi);     // bytes 0..7  -> coeffs 0..15
    const __m128i p1 = _mm_unpackhi_epi8(clo, chi);     // bytes 8..15 -> coeffs 16..31

    std::int16_t* out = f.c.data() + 32 * i;
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 0),
                     _mm_cvtepi8_epi16(p0));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 8),
                     _mm_cvtepi8_epi16(_mm_srli_si128(p0, 8)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 16),
                     _mm_cvtepi8_epi16(p1));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 24),
                     _mm_cvtepi8_epi16(_mm_srli_si128(p1, 8)));
  }
}

}  // namespace mlkem768::avx2
