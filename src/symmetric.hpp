#pragma once
// Symmetric primitives. Thin wrappers over vendored FIPS 202 — no logic beyond length
// bookkeeping (spec §6.3).
//
// FIPS 203 §4.1, equations (4.2)-(4.5):
//   H(s)        := SHA3-256(s)
//   J(s)        := SHAKE256(s, 8*32)
//   G(c)        := SHA3-512(c)              two 32-byte outputs, K first then r
//   PRF_eta(s,b):= SHAKE256(s || b, 8*64*eta)
//
// SECRECY. This is the first layer where SECRET data flows through third-party code:
//   PRF        sigma / r are SECRET (K-PKE.KeyGen line 9/13, K-PKE.Encrypt line 10/14/17)
//   G          d is SECRET in K-PKE.KeyGen; m is SECRET in Encaps_internal
//   J          z is SECRET (the implicit-reject value)
//   H          ek is public
//   XOF        rho and the two index bytes are PUBLIC; sample_ntt is deliberately
//              variable-time (spec §8.1)
//
// The vendored Keccak is inherently constant-time: no lookup tables, chi is pure
// bitwise, every array index is a literal or a position counter, and every branch tests
// a length rather than content. Verified by inspection AND by ctgrind in Phase 3 with
// sigma/r/z/d marked secret — see tests/ct/ct_keccak.cpp and ADR-015.

#include <cstddef>
#include <cstdint>
#include <span>

namespace mlkem768 {

// SHA3-256. Input may be secret (G's caller) or public (H(ek)).
void H(std::uint8_t out[32], std::span<const std::uint8_t> in) noexcept;

// SHA3-512 -> 64 bytes. The caller splits it: first 32 bytes, then the second 32.
void G(std::uint8_t out[64], std::span<const std::uint8_t> in) noexcept;

// SHAKE256(in, 32). A DIFFERENT function from H despite the same output size --
// swapping them is silent and fatal.
void J(std::uint8_t out[32], std::span<const std::uint8_t> in) noexcept;

// PRF_eta(s, b) = SHAKE256(s || b, 64*eta bytes).
//
// Eta selects OUTPUT LENGTH ONLY. FIPS 203 §4.1: "eta is only used to specify the
// desired output length and not to perform domain separation." So PRF<2>(s,b) is a
// 128-byte PREFIX of PRF<3>(s,b). Adding a domain-separation byte for eta would break
// every KAT (ADR-009).
//
//   eta = 2 -> 128 bytes  (ML-KEM-768 and -1024; eta2 for every parameter set)
//   eta = 3 -> 192 bytes  (ML-KEM-512 eta1 only)
//
// s is SECRET.
template <int Eta>
void PRF(std::span<std::uint8_t, 64 * Eta> out, const std::uint8_t s[32],
         std::uint8_t b) noexcept;

extern template void PRF<2>(std::span<std::uint8_t, 128>, const std::uint8_t[32],
                            std::uint8_t) noexcept;
extern template void PRF<3>(std::span<std::uint8_t, 192>, const std::uint8_t[32],
                            std::uint8_t) noexcept;

// Incremental XOF = SHAKE128, for SampleNTT (FIPS 203 §4.1 wrapper definition).
// XOF.Squeeze takes its length in BYTES; the SHAKE128 primitive takes bits. Mixing
// those up is an 8x length bug.
//
// Input is PUBLIC (rho || j || i), so variable-time squeezing is fine and expected.
struct Xof {
  alignas(8) std::uint64_t opaque[26];   // keccak_state: 25 lanes + pos
};

void xof_init_absorb(Xof& x, const std::uint8_t seed[34]) noexcept;
void xof_squeeze(Xof& x, std::uint8_t* out, std::size_t len) noexcept;

// ---------------------------------------------------------------------------
// 4-WAY BATCHED PRIMITIVES (Phase 8a). docs/notes/08a-batched-keccak.md
//
// Keccak-f is a fixed sequence of bitwise ops and lane rotations on 25 64-bit words --
// no data-dependent branches, no table lookups, no value-dependent addressing. So four
// INDEPENDENT sponges can be interleaved across the four 64-bit lanes of an AVX2
// register and advanced by one instruction stream: word i of all four states lives in
// one __m256i. The streams never interact, which is exactly why it vectorizes.
//
// These entry points dispatch at runtime (spec §9.4). On a CPU without AVX2 they fall
// back to four sequential scalar calls and produce BIT-IDENTICAL output -- the batching
// is a performance decision with no effect on results, which is what lets `gmake kat`
// gate it.

// Four independent PRF streams from ONE seed with four different counters -- exactly
// the shape of K-PKE.KeyGen's noise sampling (N = 0..5) and K-PKE.Encrypt's (N = 0..6).
template <int Eta>
void PRF_x4(std::span<std::uint8_t, 64 * Eta> out0,
            std::span<std::uint8_t, 64 * Eta> out1,
            std::span<std::uint8_t, 64 * Eta> out2,
            std::span<std::uint8_t, 64 * Eta> out3,
            const std::uint8_t s[32],
            std::uint8_t b0, std::uint8_t b1, std::uint8_t b2, std::uint8_t b3) noexcept;

extern template void PRF_x4<2>(std::span<std::uint8_t, 128>, std::span<std::uint8_t, 128>,
                               std::span<std::uint8_t, 128>, std::span<std::uint8_t, 128>,
                               const std::uint8_t[32], std::uint8_t, std::uint8_t,
                               std::uint8_t, std::uint8_t) noexcept;
extern template void PRF_x4<3>(std::span<std::uint8_t, 192>, std::span<std::uint8_t, 192>,
                               std::span<std::uint8_t, 192>, std::span<std::uint8_t, 192>,
                               const std::uint8_t[32], std::uint8_t, std::uint8_t,
                               std::uint8_t, std::uint8_t) noexcept;

// Four independent XOF streams, one per (rho || j || i) seed. Used to expand four
// entries of A_hat at once. Squeezes `nblocks` SHAKE128 blocks into each output.
struct Xof4;                                  // opaque; defined per backend

// Absorb four 34-byte seeds and squeeze `nblocks` blocks into each of four buffers.
// The caller drives further squeezes through xof_x4_squeezeblocks.
void xof_x4_absorb_squeeze(const std::uint8_t seed0[34], const std::uint8_t seed1[34],
                           const std::uint8_t seed2[34], const std::uint8_t seed3[34],
                           std::uint8_t* out0, std::uint8_t* out1,
                           std::uint8_t* out2, std::uint8_t* out3,
                           std::size_t nblocks, void* state_storage) noexcept;

// Continue squeezing from a state previously initialized by xof_x4_absorb_squeeze.
void xof_x4_squeezeblocks(std::uint8_t* out0, std::uint8_t* out1,
                          std::uint8_t* out2, std::uint8_t* out3,
                          std::size_t nblocks, void* state_storage) noexcept;

// Storage the caller must provide for a 4-way state. Sized for __m256i s[25] plus
// slack; the AVX2 backend requires 32-byte alignment.
inline constexpr std::size_t XOF4_STATE_BYTES = 25 * 32 + 64;

// The SHAKE128 rate, exposed because SampleNTT wants to squeeze whole blocks.
// 168 is divisible by 3, so a block boundary never splits a 3-byte group -- an
// accident worth relying on deliberately rather than by luck (Phase 5).
inline constexpr std::size_t XOF_RATE = 168;
static_assert(XOF_RATE % 3 == 0, "SampleNTT relies on the rate being a multiple of 3");

}  // namespace mlkem768
