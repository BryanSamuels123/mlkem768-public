// Serialization and compression. FIPS 203 §4.2.1.
//
// See docs/algorithms/alg05-byte-encode.md, alg06-byte-decode.md and
// compress-decompress.md. Bit order is LITTLE-ENDIAN at the bit level (Algorithms 3/4):
// coefficient i occupies bits [i*d, (i+1)*d), LSB first within the coefficient.
//
// DIVISION AUDIT (ADR-016: ctgrind cannot see this hazard). The only `/` and `%` in this
// file are inside consteval functions, evaluated entirely at compile time. There is no
// runtime division or modulo anywhere, on secret data or otherwise. The bit-packing
// loops index by multiplication, never by i/8 or i%8.

#include "poly.hpp"
#include "reduce.hpp"

#include <cstdint>

namespace mlkem768 {
namespace detail {

// --- derived multiply-shift for Compress -----------------------------------
//
// Compress_d(x) = round(2^d * x / q) mod 2^d, ties up. For non-negative integers,
// round(a/b) = floor((2a + b) / 2b), so with N = 2^(d+1)*x + q:
//
//     Compress_d(x) = floor(N / 2q) mod 2^d
//
// The divisor 2q is not a power of two, so a naive implementation divides -- forbidden
// on secret data. Replace it with floor(N * M >> S) for derived M and S.
//
// NOTHING HERE IS TRANSCRIBED. M is computed from S, and the exactness of the
// substitution is PROVEN EXHAUSTIVELY AT COMPILE TIME for every d the scheme uses.

inline constexpr int COMPRESS_SHIFT = 40;

consteval std::uint64_t derive_compress_mul() {
  constexpr std::uint64_t divisor = 2ULL * static_cast<std::uint64_t>(params::Q);
  // ceil(2^S / 2q)
  return ((1ULL << COMPRESS_SHIFT) + divisor - 1) / divisor;
}

inline constexpr std::uint64_t COMPRESS_MUL = derive_compress_mul();

// Exhaustive compile-time proof that the multiply-shift equals the exact rational
// formula for every legal input. This is what validates the derivation -- the runtime
// tests then re-prove it independently.
consteval bool compress_mulshift_is_exact(int d) {
  for (std::uint32_t x = 0; x < static_cast<std::uint32_t>(params::Q); ++x) {
    const std::uint64_t n = (static_cast<std::uint64_t>(x) << (d + 1)) + params::Q;
    const std::uint64_t exact = n / (2ULL * params::Q);
    const std::uint64_t fast = (n * COMPRESS_MUL) >> COMPRESS_SHIFT;
    if (exact != fast) return false;
  }
  return true;
}

static_assert(compress_mulshift_is_exact(1),  "Compress_1 multiply-shift is not exact");
static_assert(compress_mulshift_is_exact(4),  "Compress_4 multiply-shift is not exact");
static_assert(compress_mulshift_is_exact(10), "Compress_10 multiply-shift is not exact");
static_assert(compress_mulshift_is_exact(11), "Compress_11 multiply-shift is not exact");
static_assert(compress_mulshift_is_exact(5),  "Compress_5 multiply-shift is not exact");

// No overflow: the largest N is for d = 11, N = (q-1)*2^12 + q = 13,634,817, and
// N * COMPRESS_MUL is ~2.3e15, far inside uint64_t.
static_assert((((static_cast<std::uint64_t>(params::Q - 1) << 12) + params::Q) *
               COMPRESS_MUL) < (1ULL << 62));

// ceil(q/2) = 1665, the value a set message bit decompresses to.
inline constexpr std::uint16_t HALF_Q_UP = (params::Q + 1) / 2;
static_assert(HALF_Q_UP == 1665);

}  // namespace detail

// ---------------------------------------------------------------------------
// Compress / Decompress
// ---------------------------------------------------------------------------

template <int D>
std::uint16_t compress_coeff(std::uint16_t x) noexcept {
  static_assert(D >= 1 && D < 12, "Compress_d is defined for d < 12");
  const std::uint64_t n = (static_cast<std::uint64_t>(x) << (D + 1)) + params::Q;
  const std::uint64_t q = (n * detail::COMPRESS_MUL) >> detail::COMPRESS_SHIFT;
  return static_cast<std::uint16_t>(q & ((1U << D) - 1));      // mod 2^d
}

template <int D>
std::uint16_t decompress_coeff(std::uint16_t y) noexcept {
  static_assert(D >= 1 && D < 12, "Decompress_d is defined for d < 12");
  // round(q*y / 2^d) = floor((2*q*y + 2^d) / 2^(d+1)). The divisor is a power of two,
  // so this is a shift -- no division, nothing to audit.
  const std::uint32_t n = 2u * static_cast<std::uint32_t>(params::Q) * y + (1u << D);
  return static_cast<std::uint16_t>(n >> (D + 1));
}

template std::uint16_t compress_coeff<1>(std::uint16_t) noexcept;
template std::uint16_t compress_coeff<4>(std::uint16_t) noexcept;
template std::uint16_t compress_coeff<5>(std::uint16_t) noexcept;
template std::uint16_t compress_coeff<10>(std::uint16_t) noexcept;
template std::uint16_t compress_coeff<11>(std::uint16_t) noexcept;
template std::uint16_t decompress_coeff<1>(std::uint16_t) noexcept;
template std::uint16_t decompress_coeff<4>(std::uint16_t) noexcept;
template std::uint16_t decompress_coeff<5>(std::uint16_t) noexcept;
template std::uint16_t decompress_coeff<10>(std::uint16_t) noexcept;
template std::uint16_t decompress_coeff<11>(std::uint16_t) noexcept;

// ---------------------------------------------------------------------------
// Canonicalization — where ADR-004's consequence lands
// ---------------------------------------------------------------------------
void poly_canonicalize(Poly& r) noexcept {
  for (auto& c : r.c) c = to_canonical(barrett_reduce(c));
}

// ---------------------------------------------------------------------------
// Algorithm 5 / 6 with d = 12
// ---------------------------------------------------------------------------
void poly_tobytes(std::uint8_t out[384], const Poly& a) noexcept {
  // Two 12-bit coefficients pack into three bytes, LSB first.
  for (int i = 0; i < params::N / 2; ++i) {
    const auto t0 = static_cast<std::uint16_t>(a.c[static_cast<std::size_t>(2 * i)]);
    const auto t1 = static_cast<std::uint16_t>(a.c[static_cast<std::size_t>(2 * i + 1)]);
    const auto o = static_cast<std::size_t>(3 * i);
    out[o + 0] = static_cast<std::uint8_t>(t0);
    out[o + 1] = static_cast<std::uint8_t>((t0 >> 8) | static_cast<std::uint16_t>(t1 << 4));
    out[o + 2] = static_cast<std::uint8_t>(t1 >> 4);
  }
}

void poly_frombytes(Poly& r, const std::uint8_t in[384]) noexcept {
  for (int i = 0; i < params::N / 2; ++i) {
    const auto o = static_cast<std::size_t>(3 * i);
    const auto b0 = static_cast<std::uint16_t>(in[o + 0]);
    const auto b1 = static_cast<std::uint16_t>(in[o + 1]);
    const auto b2 = static_cast<std::uint16_t>(in[o + 2]);

    const auto t0 = static_cast<std::uint16_t>((b0 | static_cast<std::uint16_t>(b1 << 8)) & 0x0FFF);
    const auto t1 = static_cast<std::uint16_t>(((b1 >> 4) | static_cast<std::uint16_t>(b2 << 4)) & 0x0FFF);

    // ByteDecode_12 reduces mod q. A 12-bit field holds [0, 4095] and 4095 < 2q = 6658,
    // so ONE conditional subtraction suffices -- branchless, no division.
    //
    // This is deliberately NOT injective: [3329, 4095] folds into [0, 766]. An honest
    // encoder never produces such a field, which is precisely what the §7.2 modulus
    // check detects (docs/algorithms/alg06-byte-decode.md). Do not "fix" it.
    r.c[static_cast<std::size_t>(2 * i)]     = csubq(static_cast<std::int16_t>(t0));
    r.c[static_cast<std::size_t>(2 * i + 1)] = csubq(static_cast<std::int16_t>(t1));
  }
}

// ---------------------------------------------------------------------------
// Compress_dv + ByteEncode_dv, dv = 4.  Two coefficients per byte.
// ---------------------------------------------------------------------------
void poly_compress_dv(std::uint8_t out[128], const Poly& a) noexcept {
  for (int i = 0; i < params::N / 2; ++i) {
    const auto c0 = compress_coeff<params::DV>(
        static_cast<std::uint16_t>(a.c[static_cast<std::size_t>(2 * i)]));
    const auto c1 = compress_coeff<params::DV>(
        static_cast<std::uint16_t>(a.c[static_cast<std::size_t>(2 * i + 1)]));
    out[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(c0 | (c1 << 4));
  }
}

void poly_decompress_dv(Poly& r, const std::uint8_t in[128]) noexcept {
  for (int i = 0; i < params::N / 2; ++i) {
    const auto byte = in[static_cast<std::size_t>(i)];
    r.c[static_cast<std::size_t>(2 * i)] =
        static_cast<std::int16_t>(decompress_coeff<params::DV>(static_cast<std::uint16_t>(byte & 0x0F)));
    r.c[static_cast<std::size_t>(2 * i + 1)] =
        static_cast<std::int16_t>(decompress_coeff<params::DV>(static_cast<std::uint16_t>(byte >> 4)));
  }
}

// ---------------------------------------------------------------------------
// Message encoding: Decompress_1 / Compress_1
// ---------------------------------------------------------------------------
void poly_frommsg(Poly& r, const std::uint8_t msg[32]) noexcept {
  // Each message BIT becomes a coefficient: 0 -> 0, 1 -> ceil(q/2) = 1665.
  // Branchless: build a full-width mask from the bit and AND it with 1665.
  // m is SECRET, so no branch and no secret-dependent index.
  for (int i = 0; i < 32; ++i) {
    const auto byte = static_cast<std::uint16_t>(msg[static_cast<std::size_t>(i)]);
    for (int j = 0; j < 8; ++j) {
      // Bit j of byte i is coefficient 8i + j -- LITTLE-ENDIAN at the bit level, so
      // msg[0] bit 0 sets coefficient 0, NOT coefficient 7 (failure mode #7).
      const auto bit = static_cast<std::uint16_t>((byte >> j) & 1u);
      const auto mask = static_cast<std::uint16_t>(0u - bit);          // 0x0000 or 0xFFFF
      r.c[static_cast<std::size_t>(8 * i + j)] =
          static_cast<std::int16_t>(mask & detail::HALF_Q_UP);
    }
  }
}

void poly_tomsg(std::uint8_t msg[32], const Poly& a) noexcept {
  // Compress_1 rounds each coefficient to the nearer of {0, ceil(q/2)} and yields the
  // bit. Uses the same derived multiply-shift, so no division on secret data.
  for (int i = 0; i < 32; ++i) {
    std::uint8_t byte = 0;
    for (int j = 0; j < 8; ++j) {
      const auto bit = compress_coeff<1>(
          static_cast<std::uint16_t>(a.c[static_cast<std::size_t>(8 * i + j)]));
      byte = static_cast<std::uint8_t>(byte | (bit << j));
    }
    msg[static_cast<std::size_t>(i)] = byte;
  }
}

}  // namespace mlkem768
