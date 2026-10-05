// Phase 3: FIPS 202 wrappers over the vendored Keccak.
//
// The differential against tests/model/model_keccak.cpp is the point of ADR-013: the
// model wrote its own independent Keccak precisely so the vendored one could be checked
// against something that cannot share a misreading with it.

#include "doctest.h"

#include "symmetric.hpp"

#include "model.hpp"
#include "model_keccak.hpp"

#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <random>
#include <string>
#include <vector>

using namespace mlkem768;

namespace {

int diff_iters() {
  static const int n = [] {
    const char* e = std::getenv("MLKEM_DIFF_ITERS");
    const int v = e ? std::atoi(e) : 100000;
    return v > 0 ? v : 100000;
  }();
  return n;
}

std::mt19937_64 rng(0x6B656363616B3A33ULL);   // "keccak:3"

std::string hex(const std::uint8_t* p, std::size_t n) {
  static const char* d = "0123456789abcdef";
  std::string s;
  for (std::size_t i = 0; i < n; ++i) { s += d[p[i] >> 4]; s += d[p[i] & 15]; }
  return s;
}

std::vector<std::uint8_t> random_bytes(std::size_t n) {
  std::vector<std::uint8_t> v(n);
  for (auto& b : v) b = static_cast<std::uint8_t>(rng());
  return v;
}

}  // namespace

// ===========================================================================
// FIPS 202 known-answer tests (NIST CAVP byte-oriented values)
// ===========================================================================

TEST_CASE("SHA3-256 / SHA3-512 known answers") {
  std::uint8_t out[64];
  const std::uint8_t* empty = reinterpret_cast<const std::uint8_t*>("");

  H(out, {empty, 0});
  CHECK(hex(out, 32) == "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
  G(out, {empty, 0});
  CHECK(hex(out, 64) == "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
                        "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");

  const std::uint8_t abc[3] = {'a', 'b', 'c'};
  H(out, {abc, 3});
  CHECK(hex(out, 32) == "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
  G(out, {abc, 3});
  CHECK(hex(out, 64) == "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
                        "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0");

  // 448-bit message: crosses no rate boundary for SHA3-256 (rate 136) but does for
  // SHA3-512 (rate 72).
  const char* m = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  const auto* mp = reinterpret_cast<const std::uint8_t*>(m);
  H(out, {mp, 56});
  CHECK(hex(out, 32) == "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376");
  G(out, {mp, 56});
  CHECK(hex(out, 64) == "04a371e84ecfb5b8b77cb48610fca8182dd457ce6f326a0fd3d7ec2f1e91636d"
                        "ee691fbe0c985302ba1b0d8dc78c086346b533b49c030d99a27daf1139d6e75e");
}

TEST_CASE("J = SHAKE256(., 32) known answers, and J is NOT H") {
  std::uint8_t out[32];
  const std::uint8_t* empty = reinterpret_cast<const std::uint8_t*>("");
  J(out, {empty, 0});
  CHECK(hex(out, 32) == "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f");

  // Same input, same output length, different function. Swapping them is silent
  // and fatal (docs/algorithms/params-and-conventions.md).
  std::uint8_t h_out[32];
  H(h_out, {empty, 0});
  CHECK(std::memcmp(out, h_out, 32) != 0);
}

TEST_CASE("XOF = SHAKE128 known answer") {
  std::uint8_t seed[34] = {};
  Xof x;
  // SHAKE128("") for the empty input is the documented vector; absorb the empty string
  // via the model since the wrapper's XOF is fixed at 34 bytes.
  std::array<std::uint8_t, 32> got{};
  model::shake128(got.data(), got.size(), seed, 0);
  CHECK(hex(got.data(), 32) == "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");

  // And the 34-byte path the implementation actually uses, against the model.
  for (int i = 0; i < 34; ++i) seed[i] = static_cast<std::uint8_t>(i);
  xof_init_absorb(x, seed);
  std::array<std::uint8_t, 168> impl{}, want{};
  xof_squeeze(x, impl.data(), impl.size());
  model::shake128(want.data(), want.size(), seed, 34);
  CHECK(impl == want);
}

// ===========================================================================
// Differential against the model's INDEPENDENT Keccak (ADR-013)
// ===========================================================================

TEST_CASE("H/G/J agree with the model across all lengths around every rate boundary") {
  // Rates: SHA3-256 and SHAKE256 = 136, SHA3-512 = 72. Sweep every length up to 300 so
  // each boundary, and the multi-block path, is crossed exactly.
  for (std::size_t len = 0; len <= 300; ++len) {
    const auto in = random_bytes(len);

    std::uint8_t a32[32], b32[32];
    H(a32, {in.data(), in.size()});
    model::sha3_256(b32, in.data(), in.size());
    REQUIRE(std::memcmp(a32, b32, 32) == 0);

    std::uint8_t a64[64], b64[64];
    G(a64, {in.data(), in.size()});
    model::sha3_512(b64, in.data(), in.size());
    REQUIRE(std::memcmp(a64, b64, 64) == 0);

    J(a32, {in.data(), in.size()});
    model::shake256(b32, 32, in.data(), in.size());
    REQUIRE(std::memcmp(a32, b32, 32) == 0);
  }
}

TEST_CASE("H/G/J differential against the model, randomized") {
  const int n = diff_iters() / 10 < 1000 ? 1000 : diff_iters() / 10;
  for (int i = 0; i < n; ++i) {
    const auto in = random_bytes(rng() % 400);
    std::uint8_t a[64], b[64];

    H(a, {in.data(), in.size()});
    model::sha3_256(b, in.data(), in.size());
    REQUIRE(std::memcmp(a, b, 32) == 0);

    G(a, {in.data(), in.size()});
    model::sha3_512(b, in.data(), in.size());
    REQUIRE(std::memcmp(a, b, 64) == 0);

    J(a, {in.data(), in.size()});
    model::shake256(b, 32, in.data(), in.size());
    REQUIRE(std::memcmp(a, b, 32) == 0);
  }
  MESSAGE("H/G/J differential: " << n << " iterations");
}

TEST_CASE("PRF<2> and PRF<3> agree with the model") {
  const int n = diff_iters() / 10 < 1000 ? 1000 : diff_iters() / 10;
  for (int i = 0; i < n; ++i) {
    std::uint8_t s[32];
    for (auto& c : s) c = static_cast<std::uint8_t>(rng());
    const auto b = static_cast<std::uint8_t>(rng());

    std::array<std::uint8_t, 128> p2{};
    PRF<2>(p2, s, b);
    const auto m2 = model::PRF(2, s, b);
    REQUIRE(m2.size() == 128);
    REQUIRE(std::memcmp(p2.data(), m2.data(), 128) == 0);

    std::array<std::uint8_t, 192> p3{};
    PRF<3>(p3, s, b);
    const auto m3 = model::PRF(3, s, b);
    REQUIRE(m3.size() == 192);
    REQUIRE(std::memcmp(p3.data(), m3.data(), 192) == 0);

    // ADR-009: eta selects output LENGTH only, no domain separation. PRF<2> must be a
    // strict prefix of PRF<3>. If someone "improves" this by adding an eta byte, every
    // KAT breaks -- so pin it here.
    REQUIRE(std::memcmp(p2.data(), p3.data(), 128) == 0);
  }
  MESSAGE("PRF differential: " << n << " iterations");
}

TEST_CASE("XOF differential against the model over many seeds and lengths") {
  const int n = diff_iters() / 10 < 1000 ? 1000 : diff_iters() / 10;
  for (int i = 0; i < n; ++i) {
    std::uint8_t seed[34];
    for (auto& c : seed) c = static_cast<std::uint8_t>(rng());
    const std::size_t len = 1 + rng() % 600;      // spans several 168-byte blocks

    std::vector<std::uint8_t> impl(len), want(len);
    Xof x;
    xof_init_absorb(x, seed);
    xof_squeeze(x, impl.data(), len);
    model::shake128(want.data(), len, seed, 34);
    REQUIRE(impl == want);
  }
  MESSAGE("XOF differential: " << n << " iterations");
}

// ===========================================================================
// Chunked-squeeze equivalence — FIPS 203 (4.6) / spec §6.3
// ===========================================================================

TEST_CASE("chunked squeeze equals bulk squeeze -- 3 bytes at a time, as SampleNTT does") {
  // This is the test that catches state-management bugs at the 168-byte rate boundary,
  // which is exactly what sample_ntt will hammer in Phase 5. FIPS 203 (4.6) requires the
  // equivalence to hold "whether or not |str_i| and b_j are multiples of the block
  // length", so the chunk size is deliberately coprime-ish to the rate: 168/3 = 56
  // groups per block, and the boundary lands mid-stream repeatedly.
  for (int trial = 0; trial < 64; ++trial) {
    std::uint8_t seed[34];
    for (auto& c : seed) c = static_cast<std::uint8_t>(rng());

    constexpr std::size_t kTotal = 168 * 5;      // five full blocks
    std::vector<std::uint8_t> bulk(kTotal), chunked(kTotal);

    Xof a;
    xof_init_absorb(a, seed);
    xof_squeeze(a, bulk.data(), kTotal);

    Xof b;
    xof_init_absorb(b, seed);
    for (std::size_t off = 0; off < kTotal; off += 3)
      xof_squeeze(b, chunked.data() + off, 3);

    REQUIRE(bulk == chunked);
  }
}

TEST_CASE("chunked squeeze at every chunk size from 1 to 200") {
  // Sweeps chunk sizes that divide the rate, that don't, and that exceed it.
  std::uint8_t seed[34];
  for (auto& c : seed) c = static_cast<std::uint8_t>(rng());

  constexpr std::size_t kTotal = 1000;
  std::vector<std::uint8_t> bulk(kTotal);
  Xof a;
  xof_init_absorb(a, seed);
  xof_squeeze(a, bulk.data(), kTotal);

  for (std::size_t chunk = 1; chunk <= 200; ++chunk) {
    std::vector<std::uint8_t> got(kTotal);
    Xof b;
    xof_init_absorb(b, seed);
    for (std::size_t off = 0; off < kTotal; off += chunk) {
      const std::size_t n = (off + chunk <= kTotal) ? chunk : kTotal - off;
      xof_squeeze(b, got.data() + off, n);
    }
    REQUIRE_MESSAGE(got == bulk, "chunk size " << chunk << " disagreed with bulk squeeze");
  }
}

TEST_CASE("XOF rate is a multiple of 3, so a block boundary never splits a 3-byte group") {
  // Relied on deliberately by SampleNTT in Phase 5 rather than by luck.
  CHECK(XOF_RATE == 168);
  CHECK(XOF_RATE % 3 == 0);
}
