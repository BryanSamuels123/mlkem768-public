#pragma once
// Polynomial containers. Phase 4 adds the serialization operations (spec §6.1); this
// header carries only the types the arithmetic layer needs.

#include "params.hpp"

#include <array>
#include <cstdint>

namespace mlkem768 {

// Coefficients are int16_t in SIGNED representation throughout the arithmetic layer
// (spec §5.1). The exact range at each point is the contract in docs/bounds.md.
//
// alignas(32) matters: unaligned loads cost real cycles in the AVX2 NTT inner loop
// (Phase 8). It is set now so the layout never has to change later.
struct Poly {
  alignas(32) std::array<std::int16_t, params::N> c;
};

struct PolyVec {
  std::array<Poly, params::K> v;
};

static_assert(sizeof(Poly) == params::N * sizeof(std::int16_t));
static_assert(alignof(Poly) >= 32);

// ---------------------------------------------------------------------------
// Serialization. FIPS 203 §4.2.1 (Algorithms 5, 6) and the Compress/Decompress
// definitions (4.7)/(4.8).
//
// EVERY function below that WRITES bytes requires CANONICAL [0, q) input. The
// arithmetic layer produces centered values carrying Montgomery factors, so callers
// must run poly_canonicalize() first -- that is where ADR-004's consequence lands.
// Debug builds assert it; release builds trust the contract.
//
// NO INTEGER div OR mod ON SECRET DATA. Compress is a division by q if written
// naively. It is implemented as a derived multiply-shift instead. Per ADR-016 ctgrind
// is PROVABLY BLIND to this hazard, so it is held by review: every `/` and `%` in this
// phase is enumerated in docs/bounds.md with a justification.
// ---------------------------------------------------------------------------

// Compress_d(x) = round((2^d / q) * x) mod 2^d, ties UP.
//   Input:  CANONICAL x in [0, q)      Output: [0, 2^d)
//   Constant-time: yes. Multiply-shift, no division, no branch.
template <int D>
[[nodiscard]] std::uint16_t compress_coeff(std::uint16_t x) noexcept;

// Decompress_d(y) = round((q / 2^d) * y), ties UP.
//   Input:  y in [0, 2^d)              Output: [0, q)
//   Constant-time: yes. The divisor is a power of two, so it is a shift.
template <int D>
[[nodiscard]] std::uint16_t decompress_coeff(std::uint16_t y) noexcept;

// Map every coefficient to canonical [0, q). Run this before ANY of the byte-writing
// functions below. Branchless.
//   Input: any int16_t   Output: [0, q)
void poly_canonicalize(Poly& r) noexcept;

// FIPS 203 Algorithm 5 with d = 12.  256 coeffs -> 384 bytes.
//   Input: CANONICAL [0, q)
void poly_tobytes(std::uint8_t out[384], const Poly& a) noexcept;

// FIPS 203 Algorithm 6 with d = 12.  384 bytes -> 256 coeffs in [0, q).
//   NOT INJECTIVE: a 12-bit field can hold [3329, 4095], which is folded mod q. That
//   is deliberate and is exactly what the §7.2 modulus check detects. Do not "fix" it.
void poly_frombytes(Poly& r, const std::uint8_t in[384]) noexcept;

// Compress_dv + ByteEncode_dv, dv = 4.  256 coeffs -> 128 bytes.
//   Input: CANONICAL [0, q).  MUST be constant-time: v is secret.
void poly_compress_dv(std::uint8_t out[128], const Poly& a) noexcept;
void poly_decompress_dv(Poly& r, const std::uint8_t in[128]) noexcept;

// Decompress_1(ByteDecode_1(m)): each message BIT -> 0 or ceil(q/2) = 1665.
//   m is SECRET. Branchless.
void poly_frommsg(Poly& r, const std::uint8_t msg[32]) noexcept;

// ByteEncode_1(Compress_1(w)): round each coeff to the nearer of {0, ceil(q/2)}.
//   Input: CANONICAL [0, q). w is SECRET. Branchless.
void poly_tomsg(std::uint8_t msg[32], const Poly& a) noexcept;

}  // namespace mlkem768
