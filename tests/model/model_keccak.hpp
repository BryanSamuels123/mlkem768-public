#pragma once
// Keccak / FIPS 202 for the GOLDEN MODEL ONLY.
//
// Deliberately independent of the optimized FIPS 202 that Phase 3 vendors into
// third_party/fips202/. That independence is the point: when Phase 3 lands, the vendored
// Keccak gets differentially tested against this one, and a shared misreading cannot hide.
//
// Slow and literal. No unrolling, no lane-complementing, no bit-interleaving.

#include <cstddef>
#include <cstdint>
#include <array>
#include <vector>

namespace mlkem768::model {

// Keccak-f[1600] permutation on a 25-lane state. FIPS 202 §3.3.
void keccak_f1600(std::uint64_t state[25]) noexcept;

// A Keccak sponge with an explicit incremental API, matching the SHAKE128.Init /
// Absorb / Squeeze interface FIPS 203 §4.1 is written against.
//
// FIPS 203 (4.6) requires that a sequence of absorbs followed by a sequence of squeezes
// equal one monolithic call, "whether or not |str_i| and b_j are multiples of the
// SHAKE128 block length". This implementation satisfies that by construction: it tracks
// a byte offset into the rate block across calls.
class Sponge {
 public:
  // rate_bytes: 168 for SHAKE128, 136 for SHA3-256/SHAKE256, 72 for SHA3-512.
  // pad: 0x06 for SHA3-*, 0x1F for SHAKE*.
  Sponge(std::size_t rate_bytes, std::uint8_t pad) noexcept;

  void absorb(const std::uint8_t* in, std::size_t len) noexcept;
  void squeeze(std::uint8_t* out, std::size_t len) noexcept;   // finalizes on first call

 private:
  void permute_and_reset() noexcept;
  void finalize() noexcept;

  std::array<std::uint64_t, 25> s_{};
  std::size_t rate_;
  std::uint8_t pad_;
  std::size_t pos_ = 0;        // byte offset within the current rate block
  bool squeezing_ = false;
};

// One-shot wrappers. FIPS 203 §4.1 (4.2)-(4.5).
void sha3_256(std::uint8_t out[32], const std::uint8_t* in, std::size_t len) noexcept;
void sha3_512(std::uint8_t out[64], const std::uint8_t* in, std::size_t len) noexcept;
void shake128(std::uint8_t* out, std::size_t outlen,
              const std::uint8_t* in, std::size_t inlen) noexcept;
void shake256(std::uint8_t* out, std::size_t outlen,
              const std::uint8_t* in, std::size_t inlen) noexcept;

}  // namespace mlkem768::model
