#pragma once
// Zeta lane tables for the AVX2 NTT's three INTRA-VECTOR layers.
//
// ############################################################################
// # NOTHING IN THIS FILE IS TRANSCRIBED. Every lane is DERIVED by simulating  #
// # the exact shuffle the intrinsic performs, on an array of coefficient      #
// # indices, and then looking up which zeta that coefficient's group uses.    #
// ############################################################################
//
// WHY THIS MATTERS MORE HERE THAN ANYWHERE ELSE IN THE PROJECT.
//
// For the four wide layers (len = 128, 64, 32, 16) the butterfly partners live in
// DIFFERENT vectors, one zeta applies to a whole vector, and getting it wrong is
// obvious. For len = 8, 4 and 2 the partners live INSIDE a vector, so the vector must
// be split with a shuffle first -- and after that shuffle the sixteen lanes no longer
// hold sixteen consecutive coefficients. They hold an interleaving that depends on the
// exact intrinsic used. The len = 2 layout, for instance, is
//
//     [z(8u+0) z(8u+1) z(8u+4) z(8u+5) z(8u+2) z(8u+3) z(8u+6) z(8u+7)]   (two lanes each)
//
// which is not a pattern anyone should be trusted to write out by hand, and a single
// wrong lane produces a self-consistent NTT that fails every KAT -- the same failure
// class as a transposed A-hat (docs/reference/kat-failure-checklist.md #3).
//
// So the tables are generated from the SAME permutation the code applies. If the
// shuffle in ntt_avx2.cpp changes, change the mimic here and the table follows. They
// cannot silently disagree, because there is only one description of the permutation.
//
// The generated tables are checked against FIPS 203 Appendix A in tests/unit/test_avx2.cpp
// by undoing the Montgomery factor -- the same exhaustive treatment every other
// generated table in this project gets (see make_zetas in src/ntt.cpp).

#include "params.hpp"
#include "reduce.hpp"

#include <array>
#include <cstdint>

namespace mlkem768::avx2 {

// The zeta table itself, regenerated here rather than shared out of ntt.cpp's anonymous
// namespace -- same consteval derivation, so a divergence is impossible by construction,
// and test_avx2.cpp asserts equality against tables::zetas() anyway.
consteval std::array<std::int16_t, 128> gen_zetas() {
  std::array<std::int16_t, 128> z{};
  for (int i = 0; i < 128; ++i)
    z[static_cast<std::size_t>(i)] =
        detail::to_mont(detail::pow_mod(params::ZETA, detail::bitrev7(i)));
  return z;
}
inline constexpr auto kZ = gen_zetas();

// --- the shuffle mimics -----------------------------------------------------
//
// A pair of vectors is modelled as 32 coefficient indices: [0..15] = V0's lanes,
// [16..31] = V1's lanes. Each function below returns the 16 indices that end up in
// the A half (the "lower" operand of each butterfly) after the corresponding
// intrinsic. B is the matching upper half; we only need A, because the zeta for a
// butterfly is fixed by the group containing its lower coefficient.

using Pair = std::array<int, 32>;
using Half = std::array<int, 16>;

// _mm256_permute2x128_si256(V0, V1, 0x20) -> {V0.lo128, V1.lo128}
consteval Half a_perm2x128(const Pair& p) {
  Half a{};
  for (int i = 0; i < 8; ++i) a[static_cast<std::size_t>(i)] = p[static_cast<std::size_t>(i)];
  for (int i = 0; i < 8; ++i) a[static_cast<std::size_t>(8 + i)] = p[static_cast<std::size_t>(16 + i)];
  return a;
}

// _mm256_unpacklo_epi64(V0, V1): per 128-bit lane, the low 64 bits (4 int16) of each.
consteval Half a_unpacklo64(const Pair& p) {
  Half a{};
  for (int i = 0; i < 4; ++i) a[static_cast<std::size_t>(i)]      = p[static_cast<std::size_t>(i)];        // V0 lane0 low
  for (int i = 0; i < 4; ++i) a[static_cast<std::size_t>(4 + i)]  = p[static_cast<std::size_t>(16 + i)];   // V1 lane0 low
  for (int i = 0; i < 4; ++i) a[static_cast<std::size_t>(8 + i)]  = p[static_cast<std::size_t>(8 + i)];    // V0 lane1 low
  for (int i = 0; i < 4; ++i) a[static_cast<std::size_t>(12 + i)] = p[static_cast<std::size_t>(24 + i)];   // V1 lane1 low
  return a;
}

// _mm256_shuffle_epi32(v, 0xD8): within each 128-bit lane the four 32-bit elements are
// reordered [0,2,1,3], i.e. int16 lanes [0,1, 4,5, 2,3, 6,7]. An involution.
consteval Pair shuffle32_d8(const Pair& p) {
  constexpr int m[8] = {0, 1, 4, 5, 2, 3, 6, 7};
  Pair r{};
  for (int half = 0; half < 2; ++half) {              // V0 then V1
    for (int lane128 = 0; lane128 < 2; ++lane128) {
      const int base = half * 16 + lane128 * 8;
      for (int i = 0; i < 8; ++i)
        r[static_cast<std::size_t>(base + i)] = p[static_cast<std::size_t>(base + m[i])];
    }
  }
  return r;
}

// --- the tables -------------------------------------------------------------
//
// Zeta index for coefficient i at a layer of width len is uniformly
//     k = k_base + i / (2*len)
// because the scalar loop advances k once per `start` group and start = (i/(2len))*2len.
// k_base = 1, 2, 4, 8, 16, 32, 64 for len = 128, 64, 32, 16, 8, 4, 2.
consteval int zeta_index(int coeff, int len, int k_base) { return k_base + coeff / (2 * len); }

// THE INVERSE TRANSFORM DOES NOT REUSE THE FORWARD INDEX. Algorithm 10 counts k DOWN
// from 127, so within a layer the zetas are the forward layer's REVERSED:
//
//   len=2 : 64 groups, k = 127..64      len=16 : 8 groups, k = 15..8
//   len=4 : 32 groups, k =  63..32      len=32 : 4 groups, k =  7..4
//   len=8 : 16 groups, k =  31..16      len=64 : 2 groups, k =  3..2,  len=128: k=1
//
// A layer has exactly k_base groups, so group s uses k = (2*k_base - 1) - s. This was
// NOT in the recorded design -- the design gave only the forward formula and assumed the
// inverse could share the tables. It cannot, and sharing them silently produces a
// self-consistent transform that fails every KAT.
consteval int zeta_index_inv(int coeff, int len, int k_base) {
  return (2 * k_base - 1) - coeff / (2 * len);
}

consteval Pair pair_indices(int u) {                   // vectors V_{2u}, V_{2u+1}
  Pair p{};
  for (int i = 0; i < 32; ++i) p[static_cast<std::size_t>(i)] = 32 * u + i;
  return p;
}

// One __m256i worth of zetas (and of zeta*QINV) per vector-pair, per intra-vector layer.
struct LaneTable {
  std::array<std::array<std::int16_t, 16>, 8> z{};      // 8 pairs
  std::array<std::array<std::int16_t, 16>, 8> zq{};
};

// z * QINV mod 2^16. The multiply is done in uint32 exactly as montgomery_reduce does
// (ADR-012: wrapping is explicit and unsigned, never left to signed conversion) -- a
// uint16*uint16 product promotes to int and overflows it, which consteval rejects.
// constexpr, not consteval: the four WIDE layers need it at runtime (their zeta is a
// broadcast, not a lane table) and tests call it. ONE definition, so the tables and the
// wide layers cannot drift apart.
constexpr std::int16_t qinv_of(std::int16_t z) {
  const std::uint32_t p = static_cast<std::uint32_t>(static_cast<std::uint16_t>(z)) *
                          static_cast<std::uint32_t>(QINV);
  return static_cast<std::int16_t>(static_cast<std::uint16_t>(p));
}

template <int Len, int KBase, int Which, bool Inverse>   // Which: 0 = perm2x128, 1 = unpacklo64, 2 = shuffle+unpacklo64
consteval LaneTable make_lane_table() {
  LaneTable t{};
  for (int u = 0; u < 8; ++u) {
    Pair p = pair_indices(u);
    if constexpr (Which == 2) p = shuffle32_d8(p);
    const Half a = (Which == 0) ? a_perm2x128(p) : a_unpacklo64(p);
    for (int l = 0; l < 16; ++l) {
      const int ci = a[static_cast<std::size_t>(l)];
      const std::int16_t z = kZ[static_cast<std::size_t>(
          Inverse ? zeta_index_inv(ci, Len, KBase) : zeta_index(ci, Len, KBase))];
      t.z[static_cast<std::size_t>(u)][static_cast<std::size_t>(l)]  = z;
      t.zq[static_cast<std::size_t>(u)][static_cast<std::size_t>(l)] = qinv_of(z);
    }
  }
  return t;
}

inline constexpr LaneTable kLane8 = make_lane_table<8, 16, 0, false>();   // len=8  -> perm2x128
inline constexpr LaneTable kLane4 = make_lane_table<4, 32, 1, false>();   // len=4  -> unpacklo64
inline constexpr LaneTable kLane2 = make_lane_table<2, 64, 2, false>();   // len=2  -> shuffle+unpacklo64

// Same shuffles, reversed zeta assignment. See zeta_index_inv.
inline constexpr LaneTable kLane8Inv = make_lane_table<8, 16, 0, true>();
inline constexpr LaneTable kLane4Inv = make_lane_table<4, 32, 1, true>();
inline constexpr LaneTable kLane2Inv = make_lane_table<2, 64, 2, true>();

// The inverse tables must be a permutation of the forward ones, never equal to them:
// same zeta multiset per layer, different lane assignment.
static_assert(kLane2Inv.z[0][0] != kLane2.z[0][0], "inverse len=2 table wrongly equals forward");
static_assert(kLane8Inv.z[0][0] != kLane8.z[0][0], "inverse len=8 table wrongly equals forward");

// Sanity that the derivation did what the comment claims: at len = 8 all sixteen lanes
// of pair u must carry exactly two distinct zetas (one per source vector), and at len = 2
// the first two lanes must share one. These are structural, not transcribed values.
static_assert(kLane8.z[0][0] == kLane8.z[0][7] && kLane8.z[0][8] == kLane8.z[0][15] &&
              kLane8.z[0][0] != kLane8.z[0][8], "len=8 lane table is not 8+8");
static_assert(kLane2.z[0][0] == kLane2.z[0][1], "len=2 lane table is not 2-lane grouped");

}  // namespace mlkem768::avx2
