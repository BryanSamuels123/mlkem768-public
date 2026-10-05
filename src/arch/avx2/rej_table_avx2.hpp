#pragma once
// Compaction shuffle table for the SIMD rejection sampler.
//
// ############################################################################
// # THIS IS THE ONLY DATA-INDEXED TABLE IN THE LIBRARY.                      #
// # IT IS PERMITTED HERE AND WOULD BE A VIOLATION ALMOST ANYWHERE ELSE.      #
// ############################################################################
//
// A future session WILL read `kRejShuffle[mask]` as a constant-time violation, because
// by the rules in `docs/reference/invariants.md` it looks exactly like one: a memory address derived from
// data. Read this before "fixing" it.
//
// WHY IT IS CORRECT HERE. The index is a bitmask of which 12-bit candidates from the
// XOF stream were < q. Those candidates come from SHAKE-128 seeded with rho || j || i.
// **rho is PUBLIC** -- FIPS 203 publishes it verbatim as the tail of ek, and an attacker
// derives the entire matrix from it. `docs/reference/invariants.md` lists rho among the values variable time
// is fine for, and `sample_ntt`'s whole rejection loop is already variable-time by
// design (spec Appendix B forbids bounding it). The table index leaks exactly what the
// loop's iteration count already leaks, to an attacker who can compute both themselves.
//
// WHAT WOULD MAKE IT A REAL LEAK. Routing any secret through this path -- sigma, r, or a
// CBD input. `sample_poly_cbd` must NEVER use this table; it has the opposite
// requirement and is branchless by construction. See ADR-027 and src/sample.hpp's banner.
//
// GENERATED, NEVER TRANSCRIBED. All 256 entries are derived below and every one is
// verified at runtime against what `_mm_shuffle_epi8` actually does
// (tests/unit/test_avx2.cpp) -- the same three-way check the NTT's zeta lane tables get.

#include <array>
#include <cstdint>

namespace mlkem768::avx2 {

// Entry m is a byte-shuffle control for `_mm_shuffle_epi8` that moves the 16-bit lanes
// selected by mask m down to the front, preserving order. Lane i occupies bytes 2i and
// 2i+1; unselected output bytes get 0x80, which makes pshufb write a zero there.
struct RejShuffleTable {
  std::array<std::array<std::uint8_t, 16>, 256> e{};
};

consteval RejShuffleTable make_rej_shuffle() {
  RejShuffleTable t{};
  for (int m = 0; m < 256; ++m) {
    auto& row = t.e[static_cast<std::size_t>(m)];
    for (auto& b : row) b = 0x80;                  // pshufb: high bit set -> write zero
    int out = 0;
    for (int lane = 0; lane < 8; ++lane) {
      if ((m >> lane) & 1) {
        row[static_cast<std::size_t>(2 * out)]     = static_cast<std::uint8_t>(2 * lane);
        row[static_cast<std::size_t>(2 * out + 1)] = static_cast<std::uint8_t>(2 * lane + 1);
        ++out;
      }
    }
  }
  return t;
}

inline constexpr RejShuffleTable kRejShuffle = make_rej_shuffle();

// Structural checks on the derivation itself, not on transcribed values.
static_assert(kRejShuffle.e[0][0] == 0x80, "mask 0 must select nothing");
static_assert(kRejShuffle.e[0xFF][0] == 0 && kRejShuffle.e[0xFF][15] == 15,
              "mask 0xFF must be the identity shuffle");
static_assert(kRejShuffle.e[0x02][0] == 2 && kRejShuffle.e[0x02][1] == 3,
              "mask with only lane 1 set must bring lane 1 to the front");

}  // namespace mlkem768::avx2
