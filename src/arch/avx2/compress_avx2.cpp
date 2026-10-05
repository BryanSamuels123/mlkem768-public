// SIMD Compress/Decompress for du = 10. FIPS 203 Algorithms 4/5 with d = 10.
//
// CONSTANT-TIME SCOPE DIFFERS BY DIRECTION -- state it before reading the code:
//
//   decompress_du  reads the CIPHERTEXT, which is PUBLIC. Timing here leaks nothing.
//   compress_du    reads u, derived from the secret noise y and e1. MUST be CT.
//
// Both are CT anyway (multiply-shift, no branch, no division, no table), so the
// distinction costs nothing -- but it decides which ctgrind controls are required, and
// a future reader should not have to reconstruct it. Compress_1 inside poly_tomsg is a
// third case and the most sensitive of all: its output IS the decrypted message m'.
// It stays scalar here and has its own control (ct_kpke --tomsg-taint).
//
// WHY ONLY d = 10. Measured in-situ share before writing any code: compress_du is 2956
// of Encaps's 3365 compress ticks and decompress_du 2726 of Decaps's. dv = 4 (260) and
// d = 1 (243 / 149) are each below this host's measurement floor on their own; SIMD for
// them would add constant-time surface on secret data for nothing measurable, which
// ADR-029 permits only when there is a real function-level win to bank.
//
// WHY THE CONSTANTS DIFFER BETWEEN THE TWO DIRECTIONS. A consteval search (recorded in
// the note) shows d = 1 and d = 4 admit an exact 32-bit-lane multiply-shift but **d = 10
// does not**: a 10-bit output needs the multiplier within ~4.5e-8 of 1024/q, which forces
// S >= 24 and pushes x*M past 2^31. So compress_du keeps the 64-bit multiply already
// proven exhaustively at compile time in poly.cpp and applies it four products at a time
// with vpmuludq; decompress_du's product is only 22 bits and stays in 32-bit lanes.
//
// CANONICALIZATION IS NOT FUSED IN. kpke_encrypt calls polyvec_canonicalize(u) before
// compress, so the domain reaching this file is [0, q) -- which is what the exhaustive
// test covers. Fusing it would widen the domain to the post-8c range and spend the ~19 %
// int16 headroom removal #3 left, for a gain already predicted at ~1.05x.
//
// DIVISION AUDIT: no runtime `/` or `%`.

#include "params.hpp"
#include "poly.hpp"
#include "polyvec.hpp"

#include <immintrin.h>
#include <cstdint>
#include <cstring>

namespace mlkem768::avx2 {
namespace {

// Re-derived here rather than shared out of poly.cpp's detail namespace: same consteval
// derivation, so they cannot disagree, and test_avx2.cpp asserts the SIMD output equals
// the scalar one exhaustively anyway.
consteval std::uint64_t compress_mul() {
  constexpr std::uint64_t divisor = 2ULL * static_cast<std::uint64_t>(params::Q);
  return ((1ULL << 40) + divisor - 1) / divisor;
}
inline constexpr std::uint64_t kCMul = compress_mul();
static_assert(kCMul < (1ULL << 32), "must fit a 32-bit lane for vpmuludq");

// Exhaustive compile-time proof for d = 10, the same check poly.cpp makes.
consteval bool exact10() {
  for (std::uint32_t x = 0; x < static_cast<std::uint32_t>(params::Q); ++x) {
    const std::uint64_t n = (static_cast<std::uint64_t>(x) << 11) + params::Q;
    if (n / (2ULL * params::Q) != ((n * kCMul) >> 40)) return false;
  }
  return true;
}
static_assert(exact10(), "d=10 multiply-shift is not exact");

}  // namespace

// 256 coefficients in [0,q) -> 320 bytes. Bit-identical to the scalar packer.
void compress_du_poly(std::uint8_t* out, const Poly& a) noexcept {
  const __m256i mulv = _mm256_set1_epi64x(static_cast<long long>(kCMul));
  const __m256i qv   = _mm256_set1_epi32(params::Q);

  for (int g = 0; g < params::N / 8; ++g) {
    const __m128i x16 = _mm_loadu_si128(
        reinterpret_cast<const __m128i*>(a.c.data() + 8 * g));
    // n = (x << 11) + q, in 32-bit lanes. Max 6,819,073 -- fits comfortably.
    const __m256i n = _mm256_add_epi32(_mm256_slli_epi32(_mm256_cvtepu16_epi32(x16), 11), qv);

    // vpmuludq multiplies the EVEN 32-bit lanes and yields 4 64-bit products. Doing it
    // twice -- once as-is, once with the odd lanes shifted into even position -- covers
    // all eight coefficients while keeping the full 64-bit product the d=10 precision
    // requires.
    const __m256i pe = _mm256_srli_epi64(_mm256_mul_epu32(n, mulv), 40);
    const __m256i po = _mm256_srli_epi64(_mm256_mul_epu32(_mm256_srli_epi64(n, 32), mulv), 40);

    // Results sit in the low 16 bits of each 64-bit lane: pe holds coefficients
    // 0,2,4,6 and po holds 1,3,5,7. Interleave via a 32-bit shuffle, then mask to 10
    // bits. (po shifted left 32 aligns its values with pe's odd 32-bit slots.)
    const __m256i merged = _mm256_or_si256(pe, _mm256_slli_epi64(po, 32));
    alignas(32) std::uint32_t t32[8];
    _mm256_storeu_si256(reinterpret_cast<__m256i*>(t32), merged);

    std::uint16_t t[8];
    for (int k = 0; k < 8; ++k) t[k] = static_cast<std::uint16_t>(t32[k] & 0x3FFu);

    // Two 5-byte groups of four 10-bit fields, little-endian at the bit level.
    for (int h = 0; h < 2; ++h) {
      const std::uint64_t w = static_cast<std::uint64_t>(t[4 * h + 0]) |
                              (static_cast<std::uint64_t>(t[4 * h + 1]) << 10) |
                              (static_cast<std::uint64_t>(t[4 * h + 2]) << 20) |
                              (static_cast<std::uint64_t>(t[4 * h + 3]) << 30);
      std::memcpy(out + 5 * (2 * g + h), &w, 5);
    }
  }
}

// 320 bytes -> 256 coefficients in [0,q). Input is the PUBLIC ciphertext.
// Decompress_10(y) = round(q*y / 2^10) = (q*y*2 + 2^10) >> 11. The product q*y is at
// most 3329*1023 = 3,405,567, so 32-bit lanes are exact with no 64-bit step.
void decompress_du_poly(Poly& r, const std::uint8_t* in) noexcept {
  // FULL-WIDTH SIMD UNPACK. The Phase 8d version extracted the 10-bit fields with a
  // scalar memcpy-and-shift loop and vectorized only the arithmetic; measurement put
  // that scalar glue at 34 % of the function and, worse, it broke up the arithmetic so
  // nothing pipelined -- the "vectorized" part alone was still 9x pq-crystals' entire
  // function. The fix is to unpack in registers too.
  //
  // THE UNPACK TRICK. Each 10-bit field spans at most two bytes, so one pshufb gathers
  // the right byte pair into every 16-bit lane. The per-lane shift that follows differs
  // (0, 2, 4, 6 bits) and AVX2 has no per-lane 16-bit variable shift -- so instead
  // multiply by 2^(6-s) and shift everything right by 6. `mullo` keeps only the low 16
  // bits, which discards exactly the high bits a mask would have removed:
  //     s=0: t*64 >>6 = t & 0x3FF      s=4: t*4 >>6 = (t>>4) & 0x3FF
  //     s=2: t*16 >>6 = (t>>2) & 0x3FF s=6: t*1 >>6 = (t>>6) & 0x3FF
  // So no mask instruction is needed at all.
  //
  // INPUT IS THE PUBLIC CIPHERTEXT -- see this file's header for why the CT scope
  // differs between the two directions.
  const __m256i qv  = _mm256_set1_epi32(2 * params::Q);
  const __m256i rnd = _mm256_set1_epi32(1 << 10);
  // lane j takes bytes (idx, idx+1) with idx = 0,1,2,3, 5,6,7,8 -- the byte pair holding
  // field j. Identical pattern in both 128-bit lanes; the second lane is fed from
  // in+10, which is where the next eight fields begin.
  const __m256i sh = _mm256_setr_epi8(0,1, 1,2, 2,3, 3,4, 5,6, 6,7, 7,8, 8,9,
                                      0,1, 1,2, 2,3, 3,4, 5,6, 6,7, 7,8, 8,9);
  const __m256i mul = _mm256_setr_epi16(64,16,4,1, 64,16,4,1, 64,16,4,1, 64,16,4,1);

  // 16 coefficients per step = 20 input bytes. The HIGH 128-bit half is loaded from
  // in+20i+10 and reads 16 bytes, so the guard must cover 20i+26 <= 320 -- i <= 14.
  // Guarding on bytes CONSUMED (20) instead of bytes LOADED is the Phase 8d part 1
  // over-read bug; it is guarded on the load width here.
  int c = 0;
  int i = 0;
  for (; 20 * i + 26 <= 320 && c + 16 <= params::N; ++i, c += 16) {
    const __m128i lo = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 20 * i));
    const __m128i hi = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 20 * i + 10));
    const __m256i t  = _mm256_inserti128_si256(_mm256_castsi128_si256(lo), hi, 1);
    const __m256i y  = _mm256_srli_epi16(_mm256_mullo_epi16(_mm256_shuffle_epi8(t, sh), mul), 6);

    // y holds 16 values in [0,1024). Decompress_10(v) = (2q*v + 2^10) >> 11; 2q*v is at
    // most 6,810,  so 32-bit lanes are exact.
    const __m256i v0 = _mm256_srli_epi32(_mm256_add_epi32(
        _mm256_mullo_epi32(_mm256_cvtepu16_epi32(_mm256_castsi256_si128(y)), qv), rnd), 11);
    const __m256i v1 = _mm256_srli_epi32(_mm256_add_epi32(
        _mm256_mullo_epi32(_mm256_cvtepu16_epi32(_mm256_extracti128_si256(y, 1)), qv), rnd), 11);
    const __m256i p  = _mm256_permute4x64_epi64(_mm256_packus_epi32(v0, v1), 0xD8);
    _mm256_storeu_si256(reinterpret_cast<__m256i*>(r.c.data() + c), p);
  }
  // Scalar tail: the last coefficients, where a wide load would run past the buffer.
  for (int g = c / 4; g < params::N / 4; ++g) {
    std::uint64_t w = 0;
    std::memcpy(&w, in + 5 * g, 5);
    for (int k = 0; k < 4; ++k) {
      const std::uint32_t y = static_cast<std::uint32_t>((w >> (10 * k)) & 0x3FFu);
      r.c[static_cast<std::size_t>(4 * g + k)] =
          static_cast<std::int16_t>((y * 2u * params::Q + (1u << 10)) >> 11);
    }
  }
}

}  // namespace mlkem768::avx2
