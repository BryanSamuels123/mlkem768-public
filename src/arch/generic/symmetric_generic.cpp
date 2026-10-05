// 4-way batched Keccak, PORTABLE fallback. Phase 8a.
//
// Four sequential scalar calls. Output is BIT-IDENTICAL to the AVX2 backend: batching
// changes only how the work is scheduled across vector lanes, never the result. That
// equivalence is what lets `gmake kat` gate the optimization -- it must pass with either
// backend, and MLKEM_FORCE_ARCH=portable is how that is verified on AVX2 hardware.
//
// This path is the DEFAULT on any CPU without AVX2.

#include "symmetric.hpp"

#include <cstring>

extern "C" {
#include "fips202.h"
}

namespace mlkem768::generic {
namespace {

// Four independent scalar SHAKE128 sponges, laid out so the caller's opaque storage
// works for either backend.
struct Xof4State {
  keccak_state s[4];
};
static_assert(sizeof(Xof4State) <= XOF4_STATE_BYTES, "storage too small");

Xof4State* as_state(void* p) noexcept { return reinterpret_cast<Xof4State*>(p); }

}  // namespace

void prf_x4(std::uint8_t* out0, std::uint8_t* out1, std::uint8_t* out2, std::uint8_t* out3,
            std::size_t outlen, const std::uint8_t s[32],
            std::uint8_t b0, std::uint8_t b1, std::uint8_t b2, std::uint8_t b3) noexcept {
  std::uint8_t in[33];
  std::memcpy(in, s, 32);
  std::uint8_t* outs[4] = {out0, out1, out2, out3};
  const std::uint8_t bs[4] = {b0, b1, b2, b3};
  for (int i = 0; i < 4; ++i) {
    in[32] = bs[i];
    shake256(outs[i], outlen, in, 33);
  }
}

void xof4_absorb_squeeze(const std::uint8_t seed0[34], const std::uint8_t seed1[34],
                         const std::uint8_t seed2[34], const std::uint8_t seed3[34],
                         std::uint8_t* out0, std::uint8_t* out1,
                         std::uint8_t* out2, std::uint8_t* out3,
                         std::size_t nblocks, void* storage) noexcept {
  Xof4State* st = as_state(storage);
  const std::uint8_t* seeds[4] = {seed0, seed1, seed2, seed3};
  std::uint8_t* outs[4] = {out0, out1, out2, out3};
  for (int i = 0; i < 4; ++i) {
    shake128_absorb_once(&st->s[i], seeds[i], 34);
    shake128_squeezeblocks(outs[i], nblocks, &st->s[i]);
  }
}

void xof4_squeezeblocks(std::uint8_t* out0, std::uint8_t* out1,
                        std::uint8_t* out2, std::uint8_t* out3,
                        std::size_t nblocks, void* storage) noexcept {
  Xof4State* st = as_state(storage);
  std::uint8_t* outs[4] = {out0, out1, out2, out3};
  for (int i = 0; i < 4; ++i) shake128_squeezeblocks(outs[i], nblocks, &st->s[i]);
}

}  // namespace mlkem768::generic
