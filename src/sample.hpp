#pragma once
// Sampling. FIPS 203 §4.2.2, Algorithms 7 and 8.
//
// ############################################################################
// # THESE TWO FUNCTIONS HAVE OPPOSITE CONSTANT-TIME REQUIREMENTS.            #
// # THAT ASYMMETRY IS CORRECT AND DELIBERATE. DO NOT "CLEAN IT UP".          #
// ############################################################################
//
//   sample_ntt        VARIABLE-TIME BY DESIGN. Rejection sampling, unbounded loop.
//                     Input is rho and two index bytes -- all PUBLIC, all derivable
//                     from ek by anyone. There is nothing to leak. Making it
//                     constant-time would mean bounding the rejection loop, which
//                     FIPS 203 Appendix B explicitly tells implementations not to do.
//
//   sample_poly_cbd   MUST BE CONSTANT-TIME. Its input is PRF(sigma, N) or PRF(r, N)
//                     and its output IS the secret s / e / y / e1 / e2. No branches,
//                     no data-dependent indices, no division. Constant-time by
//                     construction: bit-slicing and popcounts, no rejection at all.
//                     That is precisely why ML-KEM uses a centered binomial rather
//                     than a discrete Gaussian.
//
// A future session looking at this file will see one function that branches on its
// data and one that refuses to, and may try to make them uniform. Both directions are
// wrong: bounding sample_ntt's loop breaks interoperability (Appendix B), and making
// CBD variable-time leaks the secret key. docs/bounds.md carries the same note, and
// tests/ct/ct_sample.cpp asserts BOTH properties -- including that ctgrind actually
// *fires* on sample_ntt when rho is marked secret, which is what proves the harness
// can see the class of leak CBD must avoid.

#include "params.hpp"
#include "poly.hpp"

#include <cstdint>
#include <span>

namespace mlkem768 {

// FIPS 203 Algorithm 7 — SampleNTT.
//
// Input:  the 34-byte seed (rho || j || i).  PUBLIC.
//         j is byte 32 and i is byte 33 -- j FIRST (failure mode #3).
// Output: canonical [0, q), ALREADY IN THE NTT DOMAIN. It is NOT passed through ntt().
//
// VARIABLE-TIME. See the banner above.
void sample_ntt(Poly& a, const std::uint8_t seed[34]) noexcept;

// FIPS 203 Algorithm 7, four independent invocations driven together.
//
// Output is BYTE-IDENTICAL to four separate sample_ntt calls -- that equivalence is
// what lets `gmake kat` gate the batched path. Batching changes only how the XOF bytes
// are produced, never which bytes they are.
//
// The four seeds differ only in the two index bytes, so the four Keccak sponges are
// fully independent: no lane reads another lane's state. See docs/notes/08a-batched-
// keccak.md for why that independence is exactly what SIMD lanes want.
//
// STILL VARIABLE-TIME, and still correctly so -- all four seeds are public. The lanes
// reject at different rates, so the loop runs until the SLOWEST lane has 256
// coefficients; finished lanes simply discard their share of the later squeezes.
void sample_ntt_x4(Poly& a0, Poly& a1, Poly& a2, Poly& a3,
                   const std::uint8_t seed0[34], const std::uint8_t seed1[34],
                   const std::uint8_t seed2[34], const std::uint8_t seed3[34]) noexcept;

// FIPS 203 Algorithm 8 — SamplePolyCBD_eta.
//
// Input:  exactly 64*eta bytes from PRF<Eta>.  SECRET.
// Output: CENTERED [-eta, eta]. The arithmetic layer works in signed centered
//         representation (spec §5.1), so no reduction is needed or wanted here.
//
// MUST BE CONSTANT-TIME. Branchless, no table lookups, no division.
template <int Eta>
void sample_poly_cbd(Poly& f, std::span<const std::uint8_t, 64 * Eta> buf) noexcept;

// Fully specialized per eta: the bit-slicing shape genuinely differs between 2 and 3,
// and a runtime branch on eta would be both slower and harder to keep constant-time
// (ADR-009). Declared here so callers see the specializations, defined in sample.cpp.
template <>
void sample_poly_cbd<2>(Poly& f, std::span<const std::uint8_t, 128> buf) noexcept;
template <>
void sample_poly_cbd<3>(Poly& f, std::span<const std::uint8_t, 192> buf) noexcept;

}  // namespace mlkem768
