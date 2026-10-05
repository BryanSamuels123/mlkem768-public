#pragma once
// Modular reduction primitives. Header-only and inline: these are the innermost
// operations in the NTT.
//
// EVERY CONSTANT HERE IS DERIVED AT COMPILE TIME AND static_assert-ed.
// Nothing is transcribed from a reference implementation, a paper, or a person.
//
// Montgomery convention — see DECISIONS.md ADR-004, mirrored in `docs/reference/invariants.md`:
//   R = 2^16.  mont_mul(a, b) computes a*b*R^-1 mod q.
//   A value x is "normal domain" if it represents x, and "Montgomery domain" if it
//   represents x*R. mont_mul of two normal-domain values yields x*y*R^-1, which is why
//   zetas are STORED pre-multiplied by R: mont_mul(zeta_mont, x) = zeta*x, domain-preserving.

#include "params.hpp"

#include <cstdint>

namespace mlkem768 {

// ---------------------------------------------------------------------------
// Compile-time derivation of the magic numbers
// ---------------------------------------------------------------------------
namespace detail {

// q^-1 mod 2^16 by Newton iteration. MUST be unsigned: the iteration overflows, and
// signed overflow is UB and is rejected outright in a constant expression (a real
// compiler error hit while probing C++20 support in Phase 0).
consteval std::uint16_t derive_qinv() {
  std::uint32_t inv = 1;
  for (int i = 0; i < 5; ++i) {                  // doubles the correct bits each step
    inv *= 2u - static_cast<std::uint32_t>(params::Q) * inv;
  }
  return static_cast<std::uint16_t>(inv);
}

// Barrett constant v = floor((2^26 + q/2) / q). Derived, per spec §5.2.
consteval std::int32_t derive_barrett_v() {
  return ((1 << 26) + params::Q / 2) / params::Q;
}

// (base^exp) mod q, in 64-bit so nothing overflows.
consteval std::int32_t pow_mod(std::int32_t base, int exp) {
  std::int64_t result = 1;
  std::int64_t b = base % params::Q;
  for (int e = exp; e > 0; e >>= 1) {
    if (e & 1) result = (result * b) % params::Q;
    b = (b * b) % params::Q;
  }
  return static_cast<std::int32_t>(result);
}

// Bit reversal of a 7-bit integer (FIPS 203 §2.3 BitRev7).
consteval int bitrev7(int r) {
  int out = 0;
  for (int i = 0; i < 7; ++i) out |= ((r >> i) & 1) << (6 - i);
  return out;
}

// Map [0, q) to the centered representative in [-(q-1)/2, (q-1)/2], which is what fits
// an int16_t with the most headroom.
consteval std::int16_t center(std::int32_t v) {
  std::int32_t m = v % params::Q;
  if (m < 0) m += params::Q;
  if (m > params::Q / 2) m -= params::Q;
  return static_cast<std::int16_t>(m);
}

// x -> x*R mod q, centered. "Into the Montgomery domain."
consteval std::int16_t to_mont(std::int32_t x) {
  return center(static_cast<std::int32_t>((static_cast<std::int64_t>(x) * 65536) % params::Q));
}

}  // namespace detail

// q^-1 mod 2^16. Used only as a 16-bit wrapping multiplier inside montgomery_reduce.
inline constexpr std::uint16_t QINV = detail::derive_qinv();
static_assert(static_cast<std::uint16_t>(QINV * static_cast<std::uint16_t>(params::Q)) == 1u,
              "QINV must satisfy q * q^-1 == 1 (mod 2^16)");

inline constexpr std::int32_t BARRETT_V = detail::derive_barrett_v();
static_assert(BARRETT_V > 0);

// R mod q and R^2 mod q. Derived, then cross-checked against the values `docs/reference/invariants.md` pins.
inline constexpr std::int32_t R_MOD_Q  = 65536 % params::Q;
inline constexpr std::int32_t R2_MOD_Q = static_cast<std::int32_t>((65536LL * 65536LL) % params::Q);
static_assert(R_MOD_Q == 2285, "R mod q disagrees with the documented convention");
static_assert(R2_MOD_Q == 1353, "R^2 mod q disagrees with the documented convention");

// 128^-1 mod q. SEVEN NTT layers, so the inverse transform accumulates 2^7 = 128,
// NOT 256. Using 256^-1 leaves every output scaled by 2 (a classic off-by-one-layer bug).
inline constexpr std::int32_t INV_128 = detail::pow_mod(128, params::Q - 2);  // Fermat
static_assert(static_cast<std::int64_t>(INV_128) * 128 % params::Q == 1,
              "INV_128 must satisfy 128 * 128^-1 == 1 (mod q)");
static_assert(INV_128 == 3303);

// ---------------------------------------------------------------------------
// Reduction primitives
// ---------------------------------------------------------------------------

// Montgomery reduction.
//   Input:  |a| <  q * 2^15 = 109,084,672   (STRICT -- see below)
//   Output: t == a * R^-1 (mod q), with |t| < q
//
// NOTE THE STRICT INPUT BOUND. Spec §5.2 states the input contract as |a| <= q*2^15
// with output |t| < q. That is off by one: exhaustive evaluation over all 218,169,345
// inputs in [-q*2^15, +q*2^15] finds EXACTLY ONE violation -- a = +q*2^15 yields
// t = 3329 = q exactly, not < q. (a = -q*2^15 is fine; it yields 0.) Every other input
// in the range satisfies |t| <= q-1. Logged as a spec correction in DECISIONS.md.
//
// The contract here is therefore the strict inequality, which every caller satisfies
// with an enormous margin: the worst case in the NTT is |zeta| * |c| <= 1664 * 1664 =
// 2,770,496, which is 2.5% of the bound. docs/bounds.md carries the per-call-site
// figures. test_arith.cpp proves the bound exhaustively rather than by sampling.
//
// The wrapping 16-bit multiply is done in UNSIGNED arithmetic so the wrap is explicit
// and well-defined rather than relying on signed conversion behaviour (ADR-012).
[[nodiscard, gnu::always_inline]] inline std::int16_t montgomery_reduce(std::int32_t a) noexcept {
  // m = a * q^-1 mod 2^16, taken as a signed 16-bit value.
  const std::uint16_t m_u = static_cast<std::uint16_t>(static_cast<std::uint32_t>(a) * QINV);
  const std::int16_t  m   = static_cast<std::int16_t>(m_u);

  // a - m*q is divisible by 2^16 by construction, so the shift is exact.
  // |a| <= q*2^15 and |m*q| <= 2^15*q, so the difference fits int32 with room to spare.
  const std::int32_t t = a - static_cast<std::int32_t>(m) * params::Q;
  return static_cast<std::int16_t>(t >> 16);
}

// a * b * R^-1 mod q. The workhorse: multiplying by a Montgomery-domain constant with
// this is domain-preserving on the other operand.
//   Input:  any int16_t a, b  (|a*b| <= 32768*32767 < q*2^15 is NOT automatic --
//           callers must respect montgomery_reduce's bound; see docs/bounds.md)
//   Output: |r| < q
[[nodiscard, gnu::always_inline]] inline std::int16_t mont_mul(std::int16_t a,
                                                               std::int16_t b) noexcept {
  return montgomery_reduce(static_cast<std::int32_t>(a) * static_cast<std::int32_t>(b));
}

// Barrett reduction.
//   Input:  any int16_t
//   Output: t == a (mod q), with |t| <= (q-1)/2 = 1664
//
// The subtraction is carried out in int32 and narrowed exactly once, at a point where
// the result provably fits. That avoids the deliberate-int16-wrap trick the reference
// lineage uses, which -fsanitize=implicit-integer-truncation would flag (ADR-012).
[[nodiscard, gnu::always_inline]] inline std::int16_t barrett_reduce(std::int16_t a) noexcept {
  const std::int32_t t = (BARRETT_V * static_cast<std::int32_t>(a) + (1 << 25)) >> 26;
  const std::int32_t r = static_cast<std::int32_t>(a) - t * params::Q;
  // |r| <= 1664 here, so this narrowing is value-preserving, not a wrap.
  return static_cast<std::int16_t>(r);
}

// Conditional subtraction of q.
//   Input:  [0, 2q)
//   Output: [0, q)
[[nodiscard, gnu::always_inline]] inline std::int16_t csubq(std::int16_t a) noexcept {
  const std::int32_t d = static_cast<std::int32_t>(a) - params::Q;   // [-q, q)
  // Arithmetic shift yields 0 or -1; & q adds q back exactly when d went negative.
  // Branchless: this runs on secret data.
  const std::int32_t r = d + ((d >> 31) & params::Q);
  return static_cast<std::int16_t>(r);
}

// Map a signed representative to canonical [0, q). Input |a| < q.
[[nodiscard, gnu::always_inline]] inline std::int16_t to_canonical(std::int16_t a) noexcept {
  const std::int32_t r = static_cast<std::int32_t>(a) + ((static_cast<std::int32_t>(a) >> 31) & params::Q);
  return static_cast<std::int16_t>(r);
}

}  // namespace mlkem768
