// FIPS 202 wrappers. Length bookkeeping only — all cryptography is in the vendored
// third_party/fips202/, which is never modified (ADR-015).

#include "symmetric.hpp"

#include "arch/dispatch.hpp"

extern "C" {
#include "fips202.h"
}

#include <cstring>
#include <type_traits>

namespace mlkem768 {
namespace {

// The opaque Xof storage must be able to hold the vendored state exactly.
static_assert(sizeof(Xof) >= sizeof(keccak_state), "Xof too small for keccak_state");
static_assert(alignof(Xof) >= alignof(keccak_state), "Xof underaligned for keccak_state");

keccak_state* as_state(Xof& x) noexcept {
  return reinterpret_cast<keccak_state*>(x.opaque);
}

}  // namespace

void H(std::uint8_t out[32], std::span<const std::uint8_t> in) noexcept {
  sha3_256(out, in.data(), in.size());              // (4.4)
}

void G(std::uint8_t out[64], std::span<const std::uint8_t> in) noexcept {
  sha3_512(out, in.data(), in.size());              // (4.5)
}

void J(std::uint8_t out[32], std::span<const std::uint8_t> in) noexcept {
  shake256(out, 32, in.data(), in.size());          // (4.4): SHAKE256(s, 8*32)
}

template <int Eta>
void PRF(std::span<std::uint8_t, 64 * Eta> out, const std::uint8_t s[32],
         std::uint8_t b) noexcept {
  static_assert(Eta == 2 || Eta == 3, "FIPS 203 defines PRF only for eta in {2,3}");
  // SHAKE256(s || b, 8*64*eta).  (4.3)
  std::uint8_t in[33];
  std::memcpy(in, s, 32);
  in[32] = b;
  shake256(out.data(), out.size(), in, sizeof in);
  // `in` holds a copy of the secret seed. Phase 6 wraps callers in Zeroizing and
  // src/zeroize.hpp lands there; a plain memset here would be legally elidable, so
  // this is deliberately left to the dedicated non-elidable primitive rather than
  // pretending to solve it now.
}

template void PRF<2>(std::span<std::uint8_t, 128>, const std::uint8_t[32],
                     std::uint8_t) noexcept;
template void PRF<3>(std::span<std::uint8_t, 192>, const std::uint8_t[32],
                     std::uint8_t) noexcept;

void xof_init_absorb(Xof& x, const std::uint8_t seed[34]) noexcept {
  keccak_state* st = as_state(x);
  // absorb_once == init + absorb + finalize for a single contiguous input, which is
  // exactly SampleNTT's pattern (XOF.Init, one XOF.Absorb, then only squeezes).
  shake128_absorb_once(st, seed, 34);
}

void xof_squeeze(Xof& x, std::uint8_t* out, std::size_t len) noexcept {
  shake128_squeeze(out, len, as_state(x));
}

// ---------------------------------------------------------------------------
// 4-way dispatch. Both backends produce BIT-IDENTICAL output; the choice is purely
// about how the work is scheduled. Declared here rather than in a header because the
// backends are separate TUs with different -m flags.
// ---------------------------------------------------------------------------
namespace avx2 {
void prf_x4(std::uint8_t*, std::uint8_t*, std::uint8_t*, std::uint8_t*, std::size_t,
            const std::uint8_t[32], std::uint8_t, std::uint8_t, std::uint8_t,
            std::uint8_t) noexcept;
void xof4_absorb_squeeze(const std::uint8_t[34], const std::uint8_t[34],
                         const std::uint8_t[34], const std::uint8_t[34], std::uint8_t*,
                         std::uint8_t*, std::uint8_t*, std::uint8_t*, std::size_t,
                         void*) noexcept;
void xof4_squeezeblocks(std::uint8_t*, std::uint8_t*, std::uint8_t*, std::uint8_t*,
                        std::size_t, void*) noexcept;
}  // namespace avx2
namespace generic {
void prf_x4(std::uint8_t*, std::uint8_t*, std::uint8_t*, std::uint8_t*, std::size_t,
            const std::uint8_t[32], std::uint8_t, std::uint8_t, std::uint8_t,
            std::uint8_t) noexcept;
void xof4_absorb_squeeze(const std::uint8_t[34], const std::uint8_t[34],
                         const std::uint8_t[34], const std::uint8_t[34], std::uint8_t*,
                         std::uint8_t*, std::uint8_t*, std::uint8_t*, std::size_t,
                         void*) noexcept;
void xof4_squeezeblocks(std::uint8_t*, std::uint8_t*, std::uint8_t*, std::uint8_t*,
                        std::size_t, void*) noexcept;
}  // namespace generic

template <int Eta>
void PRF_x4(std::span<std::uint8_t, 64 * Eta> o0, std::span<std::uint8_t, 64 * Eta> o1,
            std::span<std::uint8_t, 64 * Eta> o2, std::span<std::uint8_t, 64 * Eta> o3,
            const std::uint8_t s[32], std::uint8_t b0, std::uint8_t b1, std::uint8_t b2,
            std::uint8_t b3) noexcept {
  static_assert(Eta == 2 || Eta == 3);
  if (arch::has_avx2())
    avx2::prf_x4(o0.data(), o1.data(), o2.data(), o3.data(), o0.size(), s, b0, b1, b2, b3);
  else
    generic::prf_x4(o0.data(), o1.data(), o2.data(), o3.data(), o0.size(), s, b0, b1, b2, b3);
}

template void PRF_x4<2>(std::span<std::uint8_t, 128>, std::span<std::uint8_t, 128>,
                        std::span<std::uint8_t, 128>, std::span<std::uint8_t, 128>,
                        const std::uint8_t[32], std::uint8_t, std::uint8_t, std::uint8_t,
                        std::uint8_t) noexcept;
template void PRF_x4<3>(std::span<std::uint8_t, 192>, std::span<std::uint8_t, 192>,
                        std::span<std::uint8_t, 192>, std::span<std::uint8_t, 192>,
                        const std::uint8_t[32], std::uint8_t, std::uint8_t, std::uint8_t,
                        std::uint8_t) noexcept;

void xof_x4_absorb_squeeze(const std::uint8_t seed0[34], const std::uint8_t seed1[34],
                           const std::uint8_t seed2[34], const std::uint8_t seed3[34],
                           std::uint8_t* out0, std::uint8_t* out1, std::uint8_t* out2,
                           std::uint8_t* out3, std::size_t nblocks,
                           void* storage) noexcept {
  if (arch::has_avx2())
    avx2::xof4_absorb_squeeze(seed0, seed1, seed2, seed3, out0, out1, out2, out3,
                              nblocks, storage);
  else
    generic::xof4_absorb_squeeze(seed0, seed1, seed2, seed3, out0, out1, out2, out3,
                                 nblocks, storage);
}

void xof_x4_squeezeblocks(std::uint8_t* out0, std::uint8_t* out1, std::uint8_t* out2,
                          std::uint8_t* out3, std::size_t nblocks,
                          void* storage) noexcept {
  if (arch::has_avx2())
    avx2::xof4_squeezeblocks(out0, out1, out2, out3, nblocks, storage);
  else
    generic::xof4_squeezeblocks(out0, out1, out2, out3, nblocks, storage);
}

}  // namespace mlkem768
