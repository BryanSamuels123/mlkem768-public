// 4-way batched Keccak, AVX2 backend. Phase 8a.
//
// Compiled with -mavx2 and reached only when arch::has_avx2() is true. See
// docs/notes/08a-batched-keccak.md for why four independent sponges vectorize.
//
// This file is OUR code; it wraps the vendored 4-way primitives (ADR-015, extended).
// The vendored files are byte-identical to upstream and are never reformatted.

#include "symmetric.hpp"

#include <cstring>
#include <immintrin.h>

extern "C" {
#include "fips202.h"
#include "fips202x4.h"
}

namespace mlkem768::avx2 {
namespace {

// The vendored state is __m256i s[25]: word i of all four sponges in one register.
static_assert(sizeof(keccakx4_state) <= XOF4_STATE_BYTES,
              "XOF4_STATE_BYTES too small for keccakx4_state");

keccakx4_state* as_state(void* p) noexcept {
  return reinterpret_cast<keccakx4_state*>(p);
}

}  // namespace

// PRF_eta(s, b) = SHAKE256(s || b, 64*eta), four counters at once.
// Each stream gets its own 33-byte input; only the final byte differs.
void prf_x4(std::uint8_t* out0, std::uint8_t* out1, std::uint8_t* out2, std::uint8_t* out3,
            std::size_t outlen, const std::uint8_t s[32],
            std::uint8_t b0, std::uint8_t b1, std::uint8_t b2, std::uint8_t b3) noexcept {
  alignas(32) std::uint8_t in0[33], in1[33], in2[33], in3[33];
  std::memcpy(in0, s, 32); in0[32] = b0;
  std::memcpy(in1, s, 32); in1[32] = b1;
  std::memcpy(in2, s, 32); in2[32] = b2;
  std::memcpy(in3, s, 32); in3[32] = b3;
  shake256x4(out0, out1, out2, out3, outlen, in0, in1, in2, in3, 33);
}

void xof4_absorb_squeeze(const std::uint8_t seed0[34], const std::uint8_t seed1[34],
                         const std::uint8_t seed2[34], const std::uint8_t seed3[34],
                         std::uint8_t* out0, std::uint8_t* out1,
                         std::uint8_t* out2, std::uint8_t* out3,
                         std::size_t nblocks, void* storage) noexcept {
  keccakx4_state* st = as_state(storage);
  shake128x4_absorb_once(st, seed0, seed1, seed2, seed3, 34);
  shake128x4_squeezeblocks(out0, out1, out2, out3, nblocks, st);
}

void xof4_squeezeblocks(std::uint8_t* out0, std::uint8_t* out1,
                        std::uint8_t* out2, std::uint8_t* out3,
                        std::size_t nblocks, void* storage) noexcept {
  shake128x4_squeezeblocks(out0, out1, out2, out3, nblocks, as_state(storage));
}

}  // namespace mlkem768::avx2
