// Sampling. FIPS 203 Algorithms 7 and 8.
//
// See sample.hpp for the constant-time banner: these two functions deliberately have
// OPPOSITE timing requirements and that asymmetry must not be smoothed away.
//
// DIVISION AUDIT: no runtime `/` or `%` in this file. Algorithm 7 line 7 is written
// "C[1]/16" and line 6 "C[1] mod 16"; both are powers of two and are implemented as a
// shift and a mask. `gmake audit-div` verifies at the machine level.

#include "sample.hpp"
#include "symmetric.hpp"

#include "arch/dispatch.hpp"

#include <array>
#include <cstdint>

namespace mlkem768 {

// ---------------------------------------------------------------------------
// Algorithm 7 — SampleNTT
//
// VARIABLE-TIME BY DESIGN. Everything here depends only on rho and two public index
// bytes. The number of loop iterations, and hence the running time, depends on the XOF
// output -- which an attacker can compute themselves from the public ek.
// ---------------------------------------------------------------------------
namespace {

// The rejection core of Algorithm 7, lines 5-15, lifted out so the scalar and the
// 4-way driver share ONE copy. Two copies of a rejection rule is two chances to get
// the acceptance boundary wrong, and a divergence would show up only as a KAT failure
// in whichever path happened to be dispatched.
//
// `buf` holds `buflen` bytes of XOF output, buflen a multiple of 3 (XOF_RATE = 168 is,
// so any whole number of blocks is). Returns the new accepted-coefficient count.
int rej_uniform_generic(std::int16_t* r, int ctr, const std::uint8_t* buf,
                        std::size_t buflen) noexcept {
  std::size_t pos = 0;
  while (ctr < params::N && pos + 3 <= buflen) {
    const std::uint32_t c0 = buf[pos + 0];          // line 5: a fresh 3-byte group
    const std::uint32_t c1 = buf[pos + 1];
    const std::uint32_t c2 = buf[pos + 2];
    pos += 3;

    // Line 6: d1 = C[0] + 256*(C[1] mod 16).  "mod 16" is a mask, not a division.
    const std::uint32_t d1 = c0 | ((c1 & 0x0Fu) << 8);
    // Line 7: d2 = floor(C[1]/16) + 16*C[2].  "/16" is a shift.
    const std::uint32_t d2 = (c1 >> 4) | (c2 << 4);

    // Lines 8-15. These branches are on XOF output derived from PUBLIC input.
    if (d1 < static_cast<std::uint32_t>(params::Q)) {
      r[ctr] = static_cast<std::int16_t>(d1);
      ++ctr;
    }
    if (d2 < static_cast<std::uint32_t>(params::Q) && ctr < params::N) {
      r[ctr] = static_cast<std::int16_t>(d2);
      ++ctr;
    }
  }
  return ctr;
}

}  // namespace

// Runtime dispatch (spec 9.4), same shape as the 8a/8b backends. The SIMD sampler is
// bit-identical to the scalar one (tests/unit/test_avx2.cpp), which is what lets
// `gmake kat` gate it.
//
// It is VARIABLE-TIME on PUBLIC rho, and it contains the library's only data-indexed
// table. Both are correct here and neither is correct anywhere secret flows -- ADR-027
// and src/arch/avx2/rej_table_avx2.hpp carry the argument.
namespace avx2 {
int rej_uniform(std::int16_t* r, int ctr, const std::uint8_t* buf, std::size_t buflen) noexcept;
}

namespace {
int rej_uniform(std::int16_t* r, int ctr, const std::uint8_t* buf, std::size_t buflen) noexcept {
  if (arch::has_avx2()) return avx2::rej_uniform(r, ctr, buf, buflen);
  return rej_uniform_generic(r, ctr, buf, buflen);
}
}  // namespace

void sample_ntt(Poly& a, const std::uint8_t seed[34]) noexcept {
  Xof xof;
  xof_init_absorb(xof, seed);                       // lines 1-2

  // Squeeze a whole Keccak block at a time rather than 3 bytes at a time. FIPS 203
  // (4.6) makes these identical, and symmetric.hpp static_asserts XOF_RATE % 3 == 0
  // (168 = 56*3), so a block boundary NEVER splits a 3-byte group. Relied on
  // deliberately, not by luck -- and the chunked-squeeze equivalence test in Phase 3
  // is what licenses it.
  std::array<std::uint8_t, XOF_RATE> block{};

  int j = 0;                                        // line 3
  // NO LOOP BOUND. FIPS 203 Appendix B: "Implementations should not bound this loop,
  // if at all possible. An incorrect limit will cause interoperability errors, and the
  // chances for SampleNTT to iterate longer become exponentially rare."
  //
  // If a bound is ever required (e.g. for a certification profile) it SHALL NOT be
  // lower than 280 iterations (probability of exceeding: 2^-261), and on exceeding it
  // the algorithm SHALL destroy all intermediates and return an identical result for
  // every such execution. Do not add one casually.
  // docs/algorithms/appendixB-sample-ntt-bounds.md
  while (j < params::N) {                           // line 4
    xof_squeeze(xof, block.data(), block.size());
    j = rej_uniform(a.c.data(), j, block.data(), block.size());
  }
}

// ---------------------------------------------------------------------------
// Algorithm 7, four lanes at a time.
//
// Same rejection rule, same byte stream per lane, same output -- only the XOF is
// driven four-wide. See sample.hpp for why that is safe and sample_ntt above for the
// per-lane semantics.
// ---------------------------------------------------------------------------
void sample_ntt_x4(Poly& a0, Poly& a1, Poly& a2, Poly& a3,
                   const std::uint8_t seed0[34], const std::uint8_t seed1[34],
                   const std::uint8_t seed2[34], const std::uint8_t seed3[34]) noexcept {
  // 3 blocks = 504 bytes = 168 three-byte groups = 336 candidates. Acceptance is
  // q/2^12 = 3329/4096, so the expectation is ~273 accepted -- comfortably over the
  // 256 needed, which is why the common case is one bulk squeeze and no top-up.
  // Sizing this at 1 block would make the top-up loop the normal path and give back
  // most of the batching win.
  constexpr std::size_t NBLOCKS = 3;

  alignas(32) std::array<std::uint8_t, NBLOCKS * XOF_RATE> b0{}, b1{}, b2{}, b3{};
  alignas(64) std::uint8_t state[XOF4_STATE_BYTES];

  xof_x4_absorb_squeeze(seed0, seed1, seed2, seed3,
                        b0.data(), b1.data(), b2.data(), b3.data(), NBLOCKS, state);

  int c0 = rej_uniform(a0.c.data(), 0, b0.data(), b0.size());
  int c1 = rej_uniform(a1.c.data(), 0, b1.data(), b1.size());
  int c2 = rej_uniform(a2.c.data(), 0, b2.data(), b2.size());
  int c3 = rej_uniform(a3.c.data(), 0, b3.data(), b3.size());

  // Top-up. The lanes reject independently, so they finish at different times; keep
  // squeezing four-wide until the slowest is done and let finished lanes drop their
  // bytes on the floor. Squeezing one lane scalar-style here would cost more than the
  // wasted lanes do -- a 4-way permutation costs about what one scalar permutation
  // costs, so three discarded lanes are free. (No loop bound: Appendix B, as above.)
  while (c0 < params::N || c1 < params::N || c2 < params::N || c3 < params::N) {
    xof_x4_squeezeblocks(b0.data(), b1.data(), b2.data(), b3.data(), 1, state);
    c0 = rej_uniform(a0.c.data(), c0, b0.data(), XOF_RATE);
    c1 = rej_uniform(a1.c.data(), c1, b1.data(), XOF_RATE);
    c2 = rej_uniform(a2.c.data(), c2, b2.data(), XOF_RATE);
    c3 = rej_uniform(a3.c.data(), c3, b3.data(), XOF_RATE);
  }
}

// ---------------------------------------------------------------------------
// Algorithm 8 — SamplePolyCBD_eta
//
// MUST BE CONSTANT-TIME: the output is the secret s / e / y / e1 / e2.
//
// Constant-time BY CONSTRUCTION -- bit-slicing and popcounts, no rejection, no table,
// no branch, no division. Every coefficient costs exactly the same work regardless of
// value. This is the structural reason ML-KEM samples from a centered binomial instead
// of a discrete Gaussian: the Gaussian would need rejection, and rejection on secret
// data leaks.
// ---------------------------------------------------------------------------
namespace {

std::uint32_t load32_le(const std::uint8_t* p) noexcept {
  return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
         (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
}

std::uint32_t load24_le(const std::uint8_t* p) noexcept {
  return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
         (static_cast<std::uint32_t>(p[2]) << 16);
}

}  // namespace

namespace avx2 {
void cbd2(Poly& f, const std::uint8_t* buf) noexcept;
}

namespace {
// The scalar eta = 2 path, kept as the portable backend and as the differential
// reference the SIMD one is checked against (exhaustively -- tests/unit/test_avx2.cpp).
void cbd2_generic(Poly& f, std::span<const std::uint8_t, 128> buf) noexcept {
  // eta = 2: each coefficient consumes 2*eta = 4 bits, so 4 bytes -> 8 coefficients.
  // 0x55555555 selects the even bit of each pair; adding the shifted odd bits gives a
  // 2-bit popcount in every 2-bit field.
  for (int i = 0; i < params::N / 8; ++i) {
    const std::uint32_t t = load32_le(buf.data() + static_cast<std::size_t>(4 * i));
    std::uint32_t d = t & 0x55555555u;
    d += (t >> 1) & 0x55555555u;                    // d[2k+1:2k] = popcount of bit pair k

    for (int k = 0; k < 8; ++k) {
      // x and y are the two 2-bit halves of each 4-bit field.
      const auto x = static_cast<std::int16_t>((d >> (4 * k + 0)) & 0x3u);
      const auto y = static_cast<std::int16_t>((d >> (4 * k + 2)) & 0x3u);
      // Line 5: f[i] = x - y. CENTERED, in [-2, 2] -- no reduction, no branch.
      f.c[static_cast<std::size_t>(8 * i + k)] = static_cast<std::int16_t>(x - y);
    }
  }
}

}  // namespace

// Dispatch. CONSTANT-TIME on both paths -- this is the secret-carrying sampler, the
// opposite requirement to sample_ntt above. The SIMD backend uses a register-resident
// vpshufb permutation, NOT a memory table; ADR-027's data-indexed-table permission does
// not reach here and is not being claimed. See ADR-028 and src/arch/avx2/cbd_avx2.cpp.
template <>
void sample_poly_cbd<2>(Poly& f, std::span<const std::uint8_t, 128> buf) noexcept {
  if (arch::has_avx2()) avx2::cbd2(f, buf.data());
  else cbd2_generic(f, buf);
}

template <>
void sample_poly_cbd<3>(Poly& f, std::span<const std::uint8_t, 192> buf) noexcept {
  // eta = 3: each coefficient consumes 6 bits, so 3 bytes -> 4 coefficients.
  // 0x00249249 selects every third bit; three masked adds give a 3-bit popcount in
  // every 3-bit field.
  //
  // ML-KEM-768 NEVER CALLS THIS -- eta1 = eta2 = 2. It exists because ADR-009 put the
  // eta1 != eta2 path in scope now rather than letting it first run in a future
  // ML-KEM-512 port, and it is tested and ctgrind-checked alongside eta = 2.
  for (int i = 0; i < params::N / 4; ++i) {
    const std::uint32_t t = load24_le(buf.data() + static_cast<std::size_t>(3 * i));
    std::uint32_t d = t & 0x00249249u;
    d += (t >> 1) & 0x00249249u;
    d += (t >> 2) & 0x00249249u;                    // d[3k+2:3k] = popcount of triple k

    for (int k = 0; k < 4; ++k) {
      const auto x = static_cast<std::int16_t>((d >> (6 * k + 0)) & 0x7u);
      const auto y = static_cast<std::int16_t>((d >> (6 * k + 3)) & 0x7u);
      f.c[static_cast<std::size_t>(4 * i + k)] = static_cast<std::int16_t>(x - y);
    }
  }
}

}  // namespace mlkem768
