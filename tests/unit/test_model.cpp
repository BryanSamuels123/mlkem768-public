// Self-tests for the golden model (spec §10.2, §10.3).
//
// The ACVP KATs prove the model reproduces NIST's answers end to end. These tests prove
// the INTERNALS are right for the right reasons, and localize a failure to one algorithm
// instead of a wall of mismatched hex. They are also the tests that will be reused as
// differential oracles for the real implementation from Phase 2 onward.

#include "doctest.h"

#include "model.hpp"
#include "model_keccak.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <random>
#include <string>
#include <vector>

using namespace mlkem768::model;

namespace {

std::string hex(const std::uint8_t* p, std::size_t n) {
  static const char* d = "0123456789abcdef";
  std::string s;
  for (std::size_t i = 0; i < n; ++i) { s += d[p[i] >> 4]; s += d[p[i] & 15]; }
  return s;
}

std::mt19937_64 rng(0x6D6C6B656D373638ULL);

Poly random_poly() {
  Poly p{};
  for (auto& c : p) c = static_cast<std::int32_t>(rng() % Q);
  return p;
}

// Independent round-half-up reference, deliberately formulated differently from the
// model's own (2a+b)/2b so the test is not just restating the implementation.
std::int32_t ref_compress(int d, std::int32_t x) {
  const std::int64_t v = static_cast<std::int64_t>(x) << d;   // 2^d * x
  std::int64_t r = v / Q;
  const std::int64_t rem = v % Q;
  if (2 * rem >= Q) ++r;                                      // ties round UP
  return static_cast<std::int32_t>(r & ((1LL << d) - 1));
}
std::int32_t ref_decompress(int d, std::int32_t y) {
  const std::int64_t v = static_cast<std::int64_t>(Q) * y;
  const std::int64_t den = 1LL << d;
  std::int64_t r = v / den;
  const std::int64_t rem = v % den;
  if (2 * rem >= den) ++r;
  return static_cast<std::int32_t>(r);
}

}  // namespace

// ---------------------------------------------------------------------------
TEST_CASE("model Keccak matches FIPS 202 known answers") {
  std::uint8_t o[64];
  const auto* empty = reinterpret_cast<const std::uint8_t*>("");

  sha3_256(o, empty, 0);
  CHECK(hex(o, 32) == "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
  sha3_512(o, empty, 0);
  CHECK(hex(o, 64) == "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
                      "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
  shake128(o, 32, empty, 0);
  CHECK(hex(o, 32) == "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
  shake256(o, 32, empty, 0);
  CHECK(hex(o, 32) == "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f");

  const std::uint8_t abc[3] = {'a', 'b', 'c'};
  sha3_256(o, abc, 3);
  CHECK(hex(o, 32) == "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
}

TEST_CASE("XOF chunked squeeze equals bulk squeeze (FIPS 203 eq. 4.6)") {
  // The property SampleNTT relies on to squeeze a whole Keccak block instead of 3 bytes.
  std::uint8_t seed[34];
  for (int i = 0; i < 34; ++i) seed[i] = static_cast<std::uint8_t>(i);

  std::array<std::uint8_t, 504> bulk{}, chunked{};
  shake128(bulk.data(), bulk.size(), seed, 34);

  Sponge sp(168, 0x1F);
  sp.absorb(seed, 34);
  for (int i = 0; i < 168; ++i) sp.squeeze(chunked.data() + 3 * i, 3);

  CHECK(chunked == bulk);
}

TEST_CASE("split absorb equals bulk absorb across a rate boundary") {
  std::array<std::uint8_t, 400> in{};
  for (std::size_t i = 0; i < in.size(); ++i) in[i] = static_cast<std::uint8_t>(i * 7);

  std::array<std::uint8_t, 64> a{}, b{};
  shake128(a.data(), a.size(), in.data(), in.size());

  Sponge sp(168, 0x1F);
  sp.absorb(in.data(), 100);
  sp.absorb(in.data() + 100, 68);    // crosses the 168-byte rate boundary
  sp.absorb(in.data() + 168, 232);
  sp.squeeze(b.data(), b.size());

  CHECK(a == b);
}

// ---------------------------------------------------------------------------
TEST_CASE("zeta table matches FIPS 203 Appendix A table 1") {
  // Transcribed from docs/algorithms/appendixA-zetas.md. The model computes its zetas
  // from zeta=17 and BitRev7; this pins that computation to the published table.
  static const std::int32_t kAppendixA[128] = {
         1, 1729, 2580, 3289, 2642,  630, 1897,  848,
      1062, 1919,  193,  797, 2786, 3260,  569, 1746,
       296, 2447, 1339, 1476, 3046,   56, 2240, 1333,
      1426, 2094,  535, 2882, 2393, 2879, 1974,  821,
       289,  331, 3253, 1756, 1197, 2304, 2277, 2055,
       650, 1977, 2513,  632, 2865,   33, 1320, 1915,
      2319, 1435,  807,  452, 1438, 2868, 1534, 2402,
      2647, 2617, 1481,  648, 2474, 3110, 1227,  910,
        17, 2761,  583, 2649, 1637,  723, 2288, 1100,
      1409, 2662, 3281,  233,  756, 2156, 3015, 3050,
      1703, 1651, 2789, 1789, 1847,  952, 1461, 2687,
       939, 2308, 2437, 2388,  733, 2337,  268,  641,
      1584, 2298, 2037, 3220,  375, 2549, 2090, 1645,
      1063,  319, 2773,  757, 2099,  561, 2466, 2594,
      2804, 1092,  403, 1026, 1143, 2150, 2775,  886,
      1722, 1212, 1874, 1029, 2110, 2935,  885, 2154,
  };
  // Recover the model's table by transforming a unit impulse: NTT of the polynomial
  // f = X^k is not a direct read, so instead verify via the documented identity that
  // zetas[i] = 17^BitRev7(i) mod q, recomputed independently here.
  auto bitrev7 = [](int r) { int o = 0; for (int i = 0; i < 7; ++i) o |= ((r >> i) & 1) << (6 - i); return o; };
  auto powmod = [](std::int64_t b, int e, std::int64_t m) {
    std::int64_t r = 1; b %= m;
    for (; e > 0; e >>= 1) { if (e & 1) r = r * b % m; b = b * b % m; }
    return static_cast<std::int32_t>(r);
  };
  for (int i = 0; i < 128; ++i) CHECK(powmod(ZETA, bitrev7(i), Q) == kAppendixA[i]);

  // Table 2's pair structure: gamma[2m+1] == -gamma[2m] (mod q).
  for (int i = 1; i < 128; i += 2) {
    const std::int32_t even = powmod(ZETA, 2 * bitrev7(i - 1) + 1, Q);
    const std::int32_t odd  = powmod(ZETA, 2 * bitrev7(i) + 1, Q);
    CHECK(odd == (Q - even) % Q);
  }
  CHECK(powmod(ZETA, 1, Q) == 17);
  CHECK((3303LL * 128) % Q == 1);   // 128^-1 = 3303, NOT 256^-1: seven layers
}

TEST_CASE("NTT roundtrip is exact") {
  for (int t = 0; t < 200; ++t) {
    const Poly f = random_poly();
    CHECK(inv_ntt(ntt(f)) == f);
  }
}

TEST_CASE("NTT is linear") {
  for (int t = 0; t < 50; ++t) {
    const Poly a = random_poly(), b = random_poly();
    Poly sum{};
    for (std::size_t i = 0; i < N; ++i) sum[i] = (a[i] + b[i]) % Q;
    const Poly lhs = ntt(sum);
    const Poly na = ntt(a), nb = ntt(b);
    Poly rhs{};
    for (std::size_t i = 0; i < N; ++i) rhs[i] = (na[i] + nb[i]) % Q;
    CHECK(lhs == rhs);
  }
}

TEST_CASE("schoolbook differential — THE critical NTT test (spec §5.3 test 2)") {
  // invntt(basemul(ntt(a), ntt(b))) == schoolbook_negacyclic(a, b).
  // Catches wrong zetas, wrong layer count, wrong bit-reversal, and wrong gamma signs
  // in one shot. The model's NTT path and its schoolbook path are independent code.
  for (int t = 0; t < 100; ++t) {
    const Poly a = random_poly(), b = random_poly();
    const Poly via_ntt = inv_ntt(multiply_ntts(ntt(a), ntt(b)));
    const Poly via_schoolbook = schoolbook_negacyclic(a, b);
    REQUIRE(via_ntt == via_schoolbook);
  }
}

// ---------------------------------------------------------------------------
TEST_CASE("Compress_d is exact for every input (spec §6.1 exhaustive)") {
  for (int d : {1, 4, 10, 11, 5}) {
    for (std::int32_t x = 0; x < Q; ++x) {
      REQUIRE(compress(d, x) == ref_compress(d, x));
    }
  }
}

TEST_CASE("Decompress_d is exact, and Compress(Decompress(y)) == y") {
  // FIPS 203 §4.2.1 guarantees the roundtrip for all y and all d < 12. A free oracle.
  for (int d : {1, 4, 10, 11, 5}) {
    for (std::int32_t y = 0; y < (1 << d); ++y) {
      REQUIRE(decompress(d, y) == ref_decompress(d, y));
      REQUIRE(decompress(d, y) < Q);
      REQUIRE(compress(d, decompress(d, y)) == y);
    }
  }
}

TEST_CASE("ByteEncode/ByteDecode roundtrip for every d") {
  for (int d = 1; d <= 12; ++d) {
    const std::int32_t m = (d < 12) ? (1 << d) : Q;
    Poly f{};
    for (auto& c : f) c = static_cast<std::int32_t>(rng() % static_cast<std::uint64_t>(m));
    const auto bytes = byte_encode(d, f);
    CHECK(bytes.size() == static_cast<std::size_t>(32 * d));
    CHECK(byte_decode(d, bytes.data()) == f);
  }
}

TEST_CASE("bit packing is little-endian at the bit level (failure mode #7)") {
  // A message of 0x01 0x00 ... must set the FIRST coefficient, not the eighth.
  std::uint8_t msg[32] = {};
  msg[0] = 0x01;
  const Poly bits = byte_decode(1, msg);
  CHECK(bits[0] == 1);
  for (std::size_t i = 1; i < N; ++i) CHECK(bits[i] == 0);

  // And bit 7 of byte 0 must land in coefficient 7.
  std::uint8_t msg2[32] = {};
  msg2[0] = 0x80;
  const Poly bits2 = byte_decode(1, msg2);
  CHECK(bits2[7] == 1);
  CHECK(bits2[0] == 0);

  // Decompress_1(1) = ceil(q/2) = 1665.
  CHECK(decompress(1, 1) == 1665);
  CHECK(decompress(1, 0) == 0);
}

TEST_CASE("BitsToBytes matches the standard's own worked example") {
  // FIPS 203 p.20: the 8-bit string 11010001 is 2^0+2^1+2^3+2^7 = 139.
  const std::vector<std::uint8_t> b = {1, 1, 0, 1, 0, 0, 0, 1};
  const auto B = bits_to_bytes(b);
  REQUIRE(B.size() == 1);
  CHECK(B[0] == 139);
  CHECK(bytes_to_bits(B) == b);
}

// ---------------------------------------------------------------------------
TEST_CASE("SampleNTT output is in range and index order is (rho || j || i)") {
  std::uint8_t seed[34] = {};
  for (int i = 0; i < 32; ++i) seed[i] = static_cast<std::uint8_t>(i);

  seed[32] = 1; seed[33] = 2;            // j=1, i=2
  const Poly a = sample_ntt(seed);
  for (const auto c : a) { CHECK(c >= 0); CHECK(c < Q); }

  seed[32] = 2; seed[33] = 1;            // j=2, i=1 — the transposed index
  const Poly b = sample_ntt(seed);

  // Swapping the two index bytes must change the output. If it does not, the two bytes
  // are being written to the same place and the matrix would be silently transposable.
  CHECK(a != b);
}

TEST_CASE("CBD output has the right support and distribution") {
  std::uint8_t s[32] = {};
  for (int i = 0; i < 32; ++i) s[i] = static_cast<std::uint8_t>(i * 3);

  int counts[5] = {0, 0, 0, 0, 0};   // -2,-1,0,1,2
  for (int b = 0; b < 64; ++b) {
    const Poly f = sample_poly_cbd(2, PRF(2, s, static_cast<std::uint8_t>(b)));
    for (const auto c : f) {
      const int signed_c = (c > Q / 2) ? c - Q : c;
      REQUIRE(signed_c >= -2);
      REQUIRE(signed_c <= 2);
      counts[signed_c + 2]++;
    }
  }
  // Expect {1,4,6,4,1}/16. Loose bounds — this catches a broken bit-slice, not bias.
  const double total = 64 * 256;
  CHECK(counts[2] / total > 0.30);   // 0 is the mode, ~0.375
  CHECK(counts[2] / total < 0.45);
  CHECK(counts[0] / total > 0.03);   // -2, ~0.0625
  CHECK(counts[0] / total < 0.10);
}

TEST_CASE("eta=3 CBD works — the ML-KEM-512 path (ADR-009)") {
  // ML-KEM-768 never calls this. Tested anyway so the eta1 != eta2 path is not first
  // exercised by a future ML-KEM-512 port.
  std::uint8_t s[32] = {};
  const auto buf = PRF(3, s, 0);
  CHECK(buf.size() == 192);          // 64*3, not 128
  const Poly f = sample_poly_cbd(3, buf);
  for (const auto c : f) {
    const int signed_c = (c > Q / 2) ? c - Q : c;
    CHECK(signed_c >= -3);
    CHECK(signed_c <= 3);
  }
}

// ---------------------------------------------------------------------------
TEST_CASE("ML-KEM self-consistency: decaps(encaps()) recovers the shared secret") {
  for (int t = 0; t < 8; ++t) {
    std::uint8_t d[32], z[32], m[32];
    for (int i = 0; i < 32; ++i) {
      d[i] = static_cast<std::uint8_t>(rng());
      z[i] = static_cast<std::uint8_t>(rng());
      m[i] = static_cast<std::uint8_t>(rng());
    }
    std::vector<std::uint8_t> ek(EK_BYTES), dk(DK_BYTES), ct(CT_BYTES), ss1(32), ss2(32);
    keygen_internal(d, z, ek.data(), dk.data());
    encaps_internal(ek.data(), m, ct.data(), ss1.data());
    decaps_internal(dk.data(), ct.data(), ss2.data());
    REQUIRE(ss1 == ss2);

    // A generated key must pass both input checks.
    CHECK(check_encaps_key(ek.data(), ek.size()));
    CHECK(check_decaps_key(dk.data(), dk.size()));
  }
}

TEST_CASE("keygen_from_seed is deterministic") {
  std::uint8_t d[32], z[32];
  for (int i = 0; i < 32; ++i) { d[i] = static_cast<std::uint8_t>(i); z[i] = static_cast<std::uint8_t>(255 - i); }
  std::vector<std::uint8_t> ek1(EK_BYTES), dk1(DK_BYTES), ek2(EK_BYTES), dk2(DK_BYTES);
  keygen_internal(d, z, ek1.data(), dk1.data());
  keygen_internal(d, z, ek2.data(), dk2.data());
  CHECK(ek1 == ek2);
  CHECK(dk1 == dk2);

  // z is stored verbatim in the last 32 bytes of dk.
  CHECK(std::memcmp(dk1.data() + 2368, z, 32) == 0);
  // ek is embedded at dk[1152:2336].
  CHECK(std::memcmp(dk1.data() + 1152, ek1.data(), EK_BYTES) == 0);
}

TEST_CASE("implicit rejection: a flipped ciphertext bit gives a different, deterministic secret") {
  std::uint8_t d[32] = {}, z[32] = {}, m[32] = {};
  for (int i = 0; i < 32; ++i) { d[i] = static_cast<std::uint8_t>(i); z[i] = static_cast<std::uint8_t>(i * 5); m[i] = static_cast<std::uint8_t>(i * 9); }
  std::vector<std::uint8_t> ek(EK_BYTES), dk(DK_BYTES), ct(CT_BYTES), ss(32);
  keygen_internal(d, z, ek.data(), dk.data());
  encaps_internal(ek.data(), m, ct.data(), ss.data());

  for (std::size_t bit : {std::size_t(0), std::size_t(500), std::size_t(CT_BYTES * 8 - 1)}) {
    auto bad = ct;
    bad[bit / 8] ^= static_cast<std::uint8_t>(1u << (bit % 8));

    std::vector<std::uint8_t> ss_bad(32), ss_bad2(32);
    decaps_internal(dk.data(), bad.data(), ss_bad.data());
    decaps_internal(dk.data(), bad.data(), ss_bad2.data());

    CHECK(ss_bad != ss);        // different from the honest secret
    CHECK(ss_bad == ss_bad2);   // but deterministic

    // And it must equal J(z || c) exactly — the implicit-reject secret.
    std::vector<std::uint8_t> jin(32 + CT_BYTES);
    std::memcpy(jin.data(), z, 32);
    std::memcpy(jin.data() + 32, bad.data(), CT_BYTES);
    std::uint8_t expect[32];
    J(expect, jin.data(), jin.size());
    CHECK(std::memcmp(ss_bad.data(), expect, 32) == 0);
  }
}

TEST_CASE("input checks reject malformed keys (spec §10.4)") {
  std::uint8_t d[32] = {}, z[32] = {};
  std::vector<std::uint8_t> ek(EK_BYTES), dk(DK_BYTES);
  keygen_internal(d, z, ek.data(), dk.data());

  CHECK_FALSE(check_encaps_key(ek.data(), EK_BYTES - 1));   // wrong length
  CHECK_FALSE(check_decaps_key(dk.data(), DK_BYTES + 1));

  // A 12-bit field >= q must fail the modulus check. 0xFF 0xFF packs two fields of
  // 0xFFF = 4095 > 3328.
  auto bad_ek = ek;
  bad_ek[0] = 0xFF; bad_ek[1] = 0xFF; bad_ek[2] = 0xFF;
  CHECK_FALSE(check_encaps_key(bad_ek.data(), EK_BYTES));

  // A corrupted H(ek) must fail the hash check.
  auto bad_dk = dk;
  bad_dk[2336] ^= 0x01;
  CHECK_FALSE(check_decaps_key(bad_dk.data(), DK_BYTES));

  // All-zero and all-0xFF inputs must not crash.
  std::vector<std::uint8_t> zeros(EK_BYTES, 0x00), ones(EK_BYTES, 0xFF);
  (void)check_encaps_key(zeros.data(), EK_BYTES);
  (void)check_encaps_key(ones.data(), EK_BYTES);
  CHECK_FALSE(check_encaps_key(ones.data(), EK_BYTES));     // 0xFFF fields are out of range
}
