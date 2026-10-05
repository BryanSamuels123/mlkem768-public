// k-vector serialization. See polyvec.hpp for the contract.
//
// DIVISION AUDIT: no runtime `/` or `%` in this file at all. Every buffer offset is
// computed by multiplication from a loop counter.

#include "polyvec.hpp"

#include "arch/dispatch.hpp"
#include "reduce.hpp"

#include <cstdint>

namespace mlkem768 {

void polyvec_canonicalize(PolyVec& r) noexcept {
  for (auto& p : r.v) poly_canonicalize(p);
}

void polyvec_tobytes(std::uint8_t out[params::POLYVEC_BYTES], const PolyVec& a) noexcept {
  for (int i = 0; i < params::K; ++i)
    poly_tobytes(out + static_cast<std::size_t>(i) * params::POLY_BYTES,
                 a.v[static_cast<std::size_t>(i)]);
}

void polyvec_frombytes(PolyVec& r, const std::uint8_t in[params::POLYVEC_BYTES]) noexcept {
  for (int i = 0; i < params::K; ++i)
    poly_frombytes(r.v[static_cast<std::size_t>(i)],
                   in + static_cast<std::size_t>(i) * params::POLY_BYTES);
}

// ---------------------------------------------------------------------------
// Compress_du + ByteEncode_du, du = 10.
//
// Four 10-bit values pack into five bytes, LSB first:
//   b0 =  t0[7:0]
//   b1 =  t0[9:8] | t1[5:0] << 2
//   b2 =  t1[9:6] | t2[3:0] << 4
//   b3 =  t2[9:4] | t3[1:0] << 6
//   b4 =  t3[9:2]
//
// 256 coefficients -> 64 groups of 4 -> 320 bytes per polynomial. The group count and
// the byte stride are asserted below: a 10-bit packer writing into a 320-byte buffer is
// the canonical shape for a one-byte overrun, so the arithmetic is pinned at compile
// time and ASan is run against this phase specifically.
// ---------------------------------------------------------------------------

namespace {
constexpr int kDuGroups = params::N / 4;                 // 64 groups of four coefficients
constexpr int kDuBytesPerPoly = 32 * params::DU;         // 320
static_assert(kDuGroups * 5 == kDuBytesPerPoly, "du=10 packs 4 coefficients into 5 bytes");
static_assert(kDuBytesPerPoly * params::K == params::POLYVEC_COMPRESSED_DU_BYTES);
}  // namespace

namespace avx2 {
void compress_du_poly(std::uint8_t* out, const Poly& a) noexcept;
void decompress_du_poly(Poly& r, const std::uint8_t* in) noexcept;
}

void polyvec_compress_du(std::uint8_t out[params::POLYVEC_COMPRESSED_DU_BYTES],
                         const PolyVec& a) noexcept {
  std::size_t o = 0;
  for (int i = 0; i < params::K; ++i) {
    const Poly& p = a.v[static_cast<std::size_t>(i)];
    // CONSTANT-TIME: u is derived from the secret noise y and e1. Both paths are
    // multiply-shift with no branch, table or division; the SIMD one is bit-identical
    // (exhaustively verified over [0,q) x every position). See compress_avx2.cpp.
    if (arch::has_avx2()) { avx2::compress_du_poly(out + o, p); o += 320; continue; }
    for (int g = 0; g < kDuGroups; ++g) {
      std::uint16_t t[4];
      for (int k = 0; k < 4; ++k)
        t[k] = compress_coeff<params::DU>(
            static_cast<std::uint16_t>(p.c[static_cast<std::size_t>(4 * g + k)]));

      out[o + 0] = static_cast<std::uint8_t>(t[0]);
      out[o + 1] = static_cast<std::uint8_t>((t[0] >> 8) | static_cast<std::uint16_t>(t[1] << 2));
      out[o + 2] = static_cast<std::uint8_t>((t[1] >> 6) | static_cast<std::uint16_t>(t[2] << 4));
      out[o + 3] = static_cast<std::uint8_t>((t[2] >> 4) | static_cast<std::uint16_t>(t[3] << 6));
      out[o + 4] = static_cast<std::uint8_t>(t[3] >> 2);
      o += 5;
    }
  }
}

void polyvec_decompress_du(PolyVec& r,
                           const std::uint8_t in[params::POLYVEC_COMPRESSED_DU_BYTES]) noexcept {
  std::size_t o = 0;
  for (int i = 0; i < params::K; ++i) {
    Poly& p = r.v[static_cast<std::size_t>(i)];
    // The input here is the CIPHERTEXT, which is public -- see compress_avx2.cpp for why
    // the CT scope differs between the two directions.
    if (arch::has_avx2()) { avx2::decompress_du_poly(p, in + o); o += 320; continue; }
    for (int g = 0; g < kDuGroups; ++g) {
      const auto b0 = static_cast<std::uint32_t>(in[o + 0]);
      const auto b1 = static_cast<std::uint32_t>(in[o + 1]);
      const auto b2 = static_cast<std::uint32_t>(in[o + 2]);
      const auto b3 = static_cast<std::uint32_t>(in[o + 3]);
      const auto b4 = static_cast<std::uint32_t>(in[o + 4]);

      const std::uint16_t t[4] = {
          static_cast<std::uint16_t>((b0 | (b1 << 8)) & 0x3FF),
          static_cast<std::uint16_t>(((b1 >> 2) | (b2 << 6)) & 0x3FF),
          static_cast<std::uint16_t>(((b2 >> 4) | (b3 << 4)) & 0x3FF),
          static_cast<std::uint16_t>(((b3 >> 6) | (b4 << 2)) & 0x3FF),
      };
      for (int k = 0; k < 4; ++k)
        p.c[static_cast<std::size_t>(4 * g + k)] =
            static_cast<std::int16_t>(decompress_coeff<params::DU>(t[k]));
      o += 5;
    }
  }
}

}  // namespace mlkem768
