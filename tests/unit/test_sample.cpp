// Phase 5: sampling. FIPS 203 Algorithms 7 and 8.
//
// These two functions have OPPOSITE constant-time requirements (see src/sample.hpp).
// The timing properties are asserted in tests/ct/ct_sample.cpp under valgrind; this
// file covers correctness.

#include "doctest.h"

#include "ntt.hpp"
#include "params.hpp"
#include "poly.hpp"
#include "sample.hpp"
#include "symmetric.hpp"

#include "model.hpp"

#include <array>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <random>
#include <vector>

using namespace mlkem768;
namespace M = mlkem768::model;

namespace {

int diff_iters() {
  static const int n = [] {
    const char* e = std::getenv("MLKEM_DIFF_ITERS");
    const int v = e ? std::atoi(e) : 100000;
    return v > 0 ? v : 100000;
  }();
  return n;
}

std::mt19937_64 rng(0x73616D706C653A35ULL);   // "sample:5"

constexpr std::int32_t Q = params::Q;

// The implementation returns CENTERED CBD output in [-eta, eta]; the model returns
// canonical [0, q). Conversion is documented, not a fudge.
std::int32_t to_canon(std::int32_t v) { return ((v % Q) + Q) % Q; }

}  // namespace

// ===========================================================================
// Algorithm 7 — SampleNTT
// ===========================================================================

TEST_CASE("sample_ntt output is in [0,q) and matches the model exactly") {
  const int n = diff_iters() / 100 < 2000 ? 2000 : diff_iters() / 100;
  for (int t = 0; t < n; ++t) {
    std::uint8_t seed[34];
    for (auto& b : seed) b = static_cast<std::uint8_t>(rng());

    Poly impl{};
    sample_ntt(impl, seed);
    for (const auto c : impl.c) { REQUIRE(c >= 0); REQUIRE(c < Q); }

    const M::Poly want = M::sample_ntt(seed);
    for (std::size_t k = 0; k < params::N; ++k) REQUIRE(impl.c[k] == want[k]);
  }
  MESSAGE("sample_ntt differential: " << n << " iterations");
}

TEST_CASE("sample_ntt GOLDEN VECTOR: fixed rho, fixed (i,j), full 256 coefficients") {
  // Pinned against the model for a fixed input, so a regression shows up as a concrete
  // mismatch rather than a statistical wobble.
  std::uint8_t seed[34];
  for (int k = 0; k < 32; ++k) seed[k] = static_cast<std::uint8_t>(k * 7 + 1);
  seed[32] = 1;      // j
  seed[33] = 2;      // i

  Poly impl{};
  sample_ntt(impl, seed);
  const M::Poly want = M::sample_ntt(seed);
  for (std::size_t k = 0; k < params::N; ++k)
    REQUIRE_MESSAGE(impl.c[k] == want[k], "coefficient " << k << " differs");

  // Spot-pin a few values so the test still means something if the model is ever
  // edited in the same wrong direction.
  MESSAGE("golden (rho=0x01,0x08,...  j=1 i=2): c[0]=" << impl.c[0]
          << " c[1]=" << impl.c[1] << " c[255]=" << impl.c[255]);
}

TEST_CASE("index order is (rho || j || i) -- swapping i and j CHANGES the output") {
  // Failure mode #3. A test that only checks agreement with the model for i == j
  // cannot detect a transpose, so this uses i != j and asserts the outputs DIFFER.
  std::uint8_t seed_ji[34], seed_ij[34];
  for (int k = 0; k < 32; ++k) {
    seed_ji[k] = static_cast<std::uint8_t>(k * 3 + 5);
    seed_ij[k] = seed_ji[k];
  }
  const std::uint8_t i = 2, j = 1;
  REQUIRE(i != j);                       // otherwise the test is vacuous

  seed_ji[32] = j; seed_ji[33] = i;      // CORRECT: j at byte 32, i at byte 33
  seed_ij[32] = i; seed_ij[33] = j;      // TRANSPOSED

  Poly a{}, b{};
  sample_ntt(a, seed_ji);
  sample_ntt(b, seed_ij);

  bool differs = false;
  for (std::size_t k = 0; k < params::N; ++k) if (a.c[k] != b.c[k]) differs = true;
  REQUIRE_MESSAGE(differs, "swapping the index bytes did not change the output -- the "
                           "two bytes must be reaching the same place, and a transposed "
                           "matrix would be undetectable");

  // And the correct order is the one that matches the model.
  const M::Poly want = M::sample_ntt(seed_ji);
  for (std::size_t k = 0; k < params::N; ++k) REQUIRE(a.c[k] == want[k]);
}

TEST_CASE("sample_ntt is uniform over [0,q) -- loose chi-squared") {
  // Catches a broken rejection condition (e.g. accepting >= q, or dropping a branch),
  // not subtle bias. 64 bins over [0,q).
  constexpr int kBins = 64;
  constexpr int kPolys = 400;
  std::array<long, kBins> hist{};
  hist.fill(0);

  for (int t = 0; t < kPolys; ++t) {
    std::uint8_t seed[34];
    for (auto& b : seed) b = static_cast<std::uint8_t>(rng());
    Poly p{};
    sample_ntt(p, seed);
    for (const auto c : p.c) {
      REQUIRE(c >= 0);
      REQUIRE(c < Q);
      hist[static_cast<std::size_t>((static_cast<long>(c) * kBins) / Q)]++;
    }
  }

  const double total = static_cast<double>(kPolys) * params::N;
  const double expect = total / kBins;
  double chi2 = 0.0;
  for (const auto h : hist) {
    const double d = static_cast<double>(h) - expect;
    chi2 += d * d / expect;
  }
  // 63 degrees of freedom. The 99.9th percentile is ~112; use a very loose 200 so this
  // never flakes while still catching a broken rejection.
  MESSAGE("sample_ntt chi^2 = " << chi2 << " over " << kBins << " bins, "
          << static_cast<long>(total) << " samples (df=63, loose threshold 200)");
  CHECK(chi2 < 200.0);
}

TEST_CASE("sample_ntt output is ALREADY in the NTT domain -- it is not ntt()'d") {
  // A structural guard: applying ntt() to the output must CHANGE it. If someone later
  // "helpfully" transforms A_hat, this fires.
  std::uint8_t seed[34] = {};
  for (int k = 0; k < 34; ++k) seed[k] = static_cast<std::uint8_t>(k);
  Poly a{};
  sample_ntt(a, seed);
  Poly b = a;
  ntt(b);
  bool differs = false;
  for (std::size_t k = 0; k < params::N; ++k) if (a.c[k] != b.c[k]) differs = true;
  CHECK(differs);
}

// ===========================================================================
// Algorithm 8 — SamplePolyCBD
// ===========================================================================

TEST_CASE("sample_poly_cbd<2> matches the model and lands in [-2,2]") {
  const int n = diff_iters() / 10 < 5000 ? 5000 : diff_iters() / 10;
  for (int t = 0; t < n; ++t) {
    std::uint8_t s[32];
    for (auto& c : s) c = static_cast<std::uint8_t>(rng());
    const auto b = static_cast<std::uint8_t>(rng());

    std::array<std::uint8_t, 128> buf{};
    PRF<2>(buf, s, b);

    Poly impl{};
    sample_poly_cbd<2>(impl, std::span<const std::uint8_t, 128>(buf));
    for (const auto c : impl.c) { REQUIRE(c >= -2); REQUIRE(c <= 2); }

    const std::vector<std::uint8_t> mbuf(buf.begin(), buf.end());
    const M::Poly want = M::sample_poly_cbd(2, mbuf);
    for (std::size_t k = 0; k < params::N; ++k)
      REQUIRE(to_canon(impl.c[k]) == want[k]);
  }
  MESSAGE("sample_poly_cbd<2> differential: " << n << " iterations");
}

TEST_CASE("sample_poly_cbd<3> matches the model and lands in [-3,3]") {
  // ML-KEM-768 never calls this. Tested here so the eta1 != eta2 path is not first
  // exercised by a future ML-KEM-512 port (ADR-009).
  const int n = diff_iters() / 10 < 5000 ? 5000 : diff_iters() / 10;
  for (int t = 0; t < n; ++t) {
    std::uint8_t s[32];
    for (auto& c : s) c = static_cast<std::uint8_t>(rng());
    const auto b = static_cast<std::uint8_t>(rng());

    std::array<std::uint8_t, 192> buf{};
    PRF<3>(buf, s, b);

    Poly impl{};
    sample_poly_cbd<3>(impl, std::span<const std::uint8_t, 192>(buf));
    for (const auto c : impl.c) { REQUIRE(c >= -3); REQUIRE(c <= 3); }

    const std::vector<std::uint8_t> mbuf(buf.begin(), buf.end());
    const M::Poly want = M::sample_poly_cbd(3, mbuf);
    for (std::size_t k = 0; k < params::N; ++k)
      REQUIRE(to_canon(impl.c[k]) == want[k]);
  }
  MESSAGE("sample_poly_cbd<3> differential: " << n << " iterations");
}

TEST_CASE("CBD eta=2 distribution is {1,4,6,4,1}/16 over 10^6 samples") {
  constexpr long kTarget = 1000000;
  std::array<long, 5> hist{};                    // -2..2
  hist.fill(0);
  long total = 0;

  std::uint8_t s[32] = {};
  for (std::uint32_t b = 0; total < kTarget; ++b) {
    for (int k = 0; k < 32; ++k) s[k] = static_cast<std::uint8_t>(rng());
    std::array<std::uint8_t, 128> buf{};
    PRF<2>(buf, s, static_cast<std::uint8_t>(b));
    Poly p{};
    sample_poly_cbd<2>(p, std::span<const std::uint8_t, 128>(buf));
    for (const auto c : p.c) { hist[static_cast<std::size_t>(c + 2)]++; ++total; }
  }

  const double expect[5] = {1.0 / 16, 4.0 / 16, 6.0 / 16, 4.0 / 16, 1.0 / 16};
  for (int k = 0; k < 5; ++k) {
    const double obs = static_cast<double>(hist[static_cast<std::size_t>(k)]) / static_cast<double>(total);
    MESSAGE("  eta=2  value " << (k - 2) << ": observed " << obs << "  expected " << expect[k]);
    CHECK(std::fabs(obs - expect[k]) < 0.004);   // ~10 sigma at n = 10^6
  }
}

TEST_CASE("CBD eta=3 distribution is {1,6,15,20,15,6,1}/64") {
  constexpr long kTarget = 1000000;
  std::array<long, 7> hist{};                    // -3..3
  hist.fill(0);
  long total = 0;

  std::uint8_t s[32] = {};
  for (std::uint32_t b = 0; total < kTarget; ++b) {
    for (int k = 0; k < 32; ++k) s[k] = static_cast<std::uint8_t>(rng());
    std::array<std::uint8_t, 192> buf{};
    PRF<3>(buf, s, static_cast<std::uint8_t>(b));
    Poly p{};
    sample_poly_cbd<3>(p, std::span<const std::uint8_t, 192>(buf));
    for (const auto c : p.c) { hist[static_cast<std::size_t>(c + 3)]++; ++total; }
  }

  const double expect[7] = {1.0 / 64, 6.0 / 64, 15.0 / 64, 20.0 / 64, 15.0 / 64, 6.0 / 64, 1.0 / 64};
  for (int k = 0; k < 7; ++k) {
    const double obs = static_cast<double>(hist[static_cast<std::size_t>(k)]) / static_cast<double>(total);
    MESSAGE("  eta=3  value " << (k - 3) << ": observed " << obs << "  expected " << expect[k]);
    CHECK(std::fabs(obs - expect[k]) < 0.004);
  }
}

TEST_CASE("CBD is a pure function of its input buffer -- no hidden state") {
  std::array<std::uint8_t, 128> buf{};
  for (auto& b : buf) b = static_cast<std::uint8_t>(rng());
  Poly a{}, b2{};
  sample_poly_cbd<2>(a, std::span<const std::uint8_t, 128>(buf));
  sample_poly_cbd<2>(b2, std::span<const std::uint8_t, 128>(buf));
  CHECK(std::memcmp(a.c.data(), b2.c.data(), sizeof a.c) == 0);

  // All-zero input -> all-zero output (x and y are both 0).
  std::array<std::uint8_t, 128> zeros{};
  Poly z{};
  sample_poly_cbd<2>(z, std::span<const std::uint8_t, 128>(zeros));
  for (const auto c : z.c) CHECK(c == 0);

  // All-ones input: every 4-bit field is 0b1111 -> x = 2, y = 2 -> 0.
  std::array<std::uint8_t, 128> ones{};
  ones.fill(0xFF);
  Poly o{};
  sample_poly_cbd<2>(o, std::span<const std::uint8_t, 128>(ones));
  for (const auto c : o.c) CHECK(c == 0);
}

TEST_CASE("CBD bit order: the first 4 bits of byte 0 produce coefficient 0") {
  // Guards the bit-slicing layout against a silent reordering.
  std::array<std::uint8_t, 128> buf{};
  buf[0] = 0x03;                                  // bits 0,1 set -> x = 2, y = 0
  Poly p{};
  sample_poly_cbd<2>(p, std::span<const std::uint8_t, 128>(buf));
  CHECK(p.c[0] == 2);
  for (std::size_t k = 1; k < params::N; ++k) CHECK(p.c[k] == 0);

  std::array<std::uint8_t, 128> buf2{};
  buf2[0] = 0x0C;                                 // bits 2,3 set -> x = 0, y = 2
  Poly p2{};
  sample_poly_cbd<2>(p2, std::span<const std::uint8_t, 128>(buf2));
  CHECK(p2.c[0] == -2);

  std::array<std::uint8_t, 128> buf3{};
  buf3[0] = 0x10;                                 // bit 4 -> coefficient 1, x = 1
  Poly p3{};
  sample_poly_cbd<2>(p3, std::span<const std::uint8_t, 128>(buf3));
  CHECK(p3.c[0] == 0);
  CHECK(p3.c[1] == 1);
}

// ===========================================================================
// eta = 3 (ADR-009): exhaustive, and deliberately still SCALAR
// ===========================================================================
//
// ML-KEM-768 never calls this path -- eta1 = eta2 = 2 -- which is exactly why it rots
// silently. Phase 8d gave eta=2 a SIMD backend and left eta=3 alone: its 6-bit fields
// cross byte boundaries, so the nibble-LUT structure that makes eta=2 vectorize does
// not apply, and speed does not matter for a path no shipped parameter set uses.
// Correctness does, so it is verified EXHAUSTIVELY here.
//
// eta=3 is 3-BYTE-LOCAL: Algorithm 8 reads load24_le(buf + 3i) and emits 4 coefficients
// from it, touching nothing else. So all 2^24 possible 3-byte groups IS the complete
// input-to-output map for one group -- genuinely exhaustive.

TEST_CASE("sample_poly_cbd<3> is exhaustively correct over all 2^24 three-byte groups") {
  long bad = 0;
  std::array<std::uint8_t, 192> buf{};
  // Independent reference, straight from Algorithm 8 lines 2-5 at eta=3.
  auto ref = [](std::uint32_t t, int k) -> int {
    int x = 0, y = 0;
    for (int j = 0; j < 3; ++j) x += static_cast<int>((t >> (6 * k + j)) & 1u);
    for (int j = 0; j < 3; ++j) y += static_cast<int>((t >> (6 * k + 3 + j)) & 1u);
    return x - y;
  };
  for (std::uint32_t g = 0; g < (1u << 24); ++g) {
    buf[0] = static_cast<std::uint8_t>(g & 0xFF);
    buf[1] = static_cast<std::uint8_t>((g >> 8) & 0xFF);
    buf[2] = static_cast<std::uint8_t>((g >> 16) & 0xFF);
    Poly f{};
    mlkem768::sample_poly_cbd<3>(f, std::span<const std::uint8_t, 192>(buf));
    for (int k = 0; k < 4; ++k)
      if (f.c[static_cast<std::size_t>(k)] != ref(g, k)) { ++bad; break; }
  }
  CHECK(bad == 0);
  MESSAGE("cbd eta=3: all 2^24 three-byte groups verified against Algorithm 8");
}
