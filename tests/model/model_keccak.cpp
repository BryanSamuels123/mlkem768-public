#include "model_keccak.hpp"

#include <cstring>

namespace mlkem768::model {
namespace {

constexpr std::uint64_t kRoundConstants[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
};

// rho rotation offsets, in the order the rho/pi lane-chase visits them.
constexpr int kRho[24] = {1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
                          27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44};

// pi lane permutation, same visiting order.
constexpr int kPi[24] = {10, 7,  11, 17, 18, 3,  5,  16, 8,  21, 24, 4,
                         15, 23, 19, 13, 12, 2,  20, 14, 22, 9,  6,  1};

constexpr std::uint64_t rol(std::uint64_t x, int n) noexcept {
  return (x << n) | (x >> (64 - n));
}

std::uint64_t load64(const std::uint8_t* p) noexcept {
  std::uint64_t r = 0;
  for (int i = 0; i < 8; ++i) r |= static_cast<std::uint64_t>(p[i]) << (8 * i);
  return r;  // little-endian, FIPS 202 §B.1
}

void store64(std::uint8_t* p, std::uint64_t v) noexcept {
  for (int i = 0; i < 8; ++i) p[i] = static_cast<std::uint8_t>(v >> (8 * i));
}

}  // namespace

void keccak_f1600(std::uint64_t a[25]) noexcept {
  for (int round = 0; round < 24; ++round) {
    std::uint64_t c[5], d;

    // theta
    for (int x = 0; x < 5; ++x) c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
    for (int x = 0; x < 5; ++x) {
      d = c[(x + 4) % 5] ^ rol(c[(x + 1) % 5], 1);
      for (int y = 0; y < 25; y += 5) a[y + x] ^= d;
    }

    // rho + pi, as a single lane chase starting at A[1]
    std::uint64_t t = a[1];
    for (int i = 0; i < 24; ++i) {
      const int j = kPi[i];
      const std::uint64_t tmp = a[j];
      a[j] = rol(t, kRho[i]);
      t = tmp;
    }

    // chi
    for (int y = 0; y < 25; y += 5) {
      for (int x = 0; x < 5; ++x) c[x] = a[y + x];
      for (int x = 0; x < 5; ++x) a[y + x] = c[x] ^ ((~c[(x + 1) % 5]) & c[(x + 2) % 5]);
    }

    // iota
    a[0] ^= kRoundConstants[round];
  }
}

Sponge::Sponge(std::size_t rate_bytes, std::uint8_t pad) noexcept
    : rate_(rate_bytes), pad_(pad) {
  s_.fill(0);
}

void Sponge::permute_and_reset() noexcept {
  keccak_f1600(s_.data());
  pos_ = 0;
}

void Sponge::absorb(const std::uint8_t* in, std::size_t len) noexcept {
  // Absorbing after squeezing has begun is not a defined operation here; ML-KEM never
  // does it (FIPS 203 §4.1 absorbs fully, then squeezes).
  for (std::size_t i = 0; i < len; ++i) {
    // XOR one byte into the correct lane at the correct byte offset.
    const std::size_t lane = pos_ / 8;
    const std::size_t byte = pos_ % 8;
    s_[lane] ^= static_cast<std::uint64_t>(in[i]) << (8 * byte);
    if (++pos_ == rate_) permute_and_reset();
  }
}

void Sponge::finalize() noexcept {
  // Multi-rate padding: pad byte at the current position, 0x80 at the end of the block.
  const std::size_t lane = pos_ / 8;
  const std::size_t byte = pos_ % 8;
  s_[lane] ^= static_cast<std::uint64_t>(pad_) << (8 * byte);

  const std::size_t last = rate_ - 1;
  s_[last / 8] ^= 0x80ULL << (8 * (last % 8));

  permute_and_reset();
  squeezing_ = true;
}

void Sponge::squeeze(std::uint8_t* out, std::size_t len) noexcept {
  if (!squeezing_) finalize();

  for (std::size_t i = 0; i < len; ++i) {
    if (pos_ == rate_) permute_and_reset();
    const std::size_t lane = pos_ / 8;
    const std::size_t byte = pos_ % 8;
    out[i] = static_cast<std::uint8_t>(s_[lane] >> (8 * byte));
    ++pos_;
  }
}

void sha3_256(std::uint8_t out[32], const std::uint8_t* in, std::size_t len) noexcept {
  Sponge sp(136, 0x06);
  sp.absorb(in, len);
  sp.squeeze(out, 32);
}

void sha3_512(std::uint8_t out[64], const std::uint8_t* in, std::size_t len) noexcept {
  Sponge sp(72, 0x06);
  sp.absorb(in, len);
  sp.squeeze(out, 64);
}

void shake128(std::uint8_t* out, std::size_t outlen,
              const std::uint8_t* in, std::size_t inlen) noexcept {
  Sponge sp(168, 0x1F);
  sp.absorb(in, inlen);
  sp.squeeze(out, outlen);
}

void shake256(std::uint8_t* out, std::size_t outlen,
              const std::uint8_t* in, std::size_t inlen) noexcept {
  Sponge sp(136, 0x1F);
  sp.absorb(in, inlen);
  sp.squeeze(out, outlen);
}

// Unused-parameter guard: store64/load64 are kept for readability of the lane layout
// even though the byte-wise absorb/squeeze above does not call them.
[[maybe_unused]] void keccak_lane_helpers_are_used() noexcept {
  std::uint8_t buf[8] = {};
  store64(buf, load64(buf));
}

}  // namespace mlkem768::model
