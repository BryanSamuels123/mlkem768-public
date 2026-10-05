// Phase 6a: K-PKE. FIPS 203 Algorithms 13, 14, 15.
//
// The model is KAT-clean (ADR-002), so each differential comparison here is equivalent
// to a KAT test but localized to one algorithm rather than a wall of mismatched hex.

#include "doctest.h"

#include "kpke.hpp"
#include "params.hpp"

#include "model.hpp"

#include <array>
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

// K-PKE is expensive (9 SampleNTT streams per call). Scale well below the base count;
// at the deep setting this still gives thousands of full key generations.
int kpke_iters() {
  const int n = diff_iters() / 500;
  return n < 40 ? 40 : n;
}

std::mt19937_64 rng(0x6B706B653A3661ULL);   // "kpke:6a"

std::array<std::uint8_t, 32> random32() {
  std::array<std::uint8_t, 32> v{};
  for (auto& b : v) b = static_cast<std::uint8_t>(rng());
  return v;
}

}  // namespace

TEST_CASE("kpke_keygen agrees with the model byte for byte") {
  const int n = kpke_iters();
  for (int t = 0; t < n; ++t) {
    const auto d = random32();

    std::array<std::uint8_t, params::EK_PKE_BYTES> ek{};
    std::array<std::uint8_t, params::DK_PKE_BYTES> dk{};
    kpke_keygen(ek.data(), dk.data(), d.data());

    std::array<std::uint8_t, params::EK_PKE_BYTES> mek{};
    std::array<std::uint8_t, params::DK_PKE_BYTES> mdk{};
    M::kpke_keygen(mek.data(), mdk.data(), d.data());

    REQUIRE(ek == mek);
    REQUIRE(dk == mdk);
  }
  MESSAGE("kpke_keygen differential: " << n << " iterations");
}

TEST_CASE("kpke_encrypt agrees with the model byte for byte") {
  const int n = kpke_iters();
  for (int t = 0; t < n; ++t) {
    const auto d = random32(), m = random32(), r = random32();

    std::array<std::uint8_t, params::EK_PKE_BYTES> ek{};
    std::array<std::uint8_t, params::DK_PKE_BYTES> dk{};
    M::kpke_keygen(ek.data(), dk.data(), d.data());     // model key, so encrypt is isolated

    std::array<std::uint8_t, params::CT_BYTES> c{}, mc{};
    kpke_encrypt(c.data(), ek.data(), m.data(), r.data());
    M::kpke_encrypt(mc.data(), ek.data(), m.data(), r.data());

    REQUIRE(c == mc);
  }
  MESSAGE("kpke_encrypt differential: " << n << " iterations");
}

TEST_CASE("kpke_decrypt agrees with the model") {
  const int n = kpke_iters();
  for (int t = 0; t < n; ++t) {
    const auto d = random32(), m = random32(), r = random32();

    std::array<std::uint8_t, params::EK_PKE_BYTES> ek{};
    std::array<std::uint8_t, params::DK_PKE_BYTES> dk{};
    M::kpke_keygen(ek.data(), dk.data(), d.data());
    std::array<std::uint8_t, params::CT_BYTES> c{};
    M::kpke_encrypt(c.data(), ek.data(), m.data(), r.data());

    std::array<std::uint8_t, 32> got{}, want{};
    kpke_decrypt(got.data(), dk.data(), c.data());
    M::kpke_decrypt(want.data(), dk.data(), c.data());

    REQUIRE(got == want);
    REQUIRE(got == m);                                  // and it recovers the plaintext
  }
  MESSAGE("kpke_decrypt differential: " << n << " iterations");
}

TEST_CASE("K-PKE roundtrip: decrypt(encrypt(m)) == m, fully self-hosted") {
  const int n = kpke_iters();
  for (int t = 0; t < n; ++t) {
    const auto d = random32(), m = random32(), r = random32();

    std::array<std::uint8_t, params::EK_PKE_BYTES> ek{};
    std::array<std::uint8_t, params::DK_PKE_BYTES> dk{};
    kpke_keygen(ek.data(), dk.data(), d.data());

    std::array<std::uint8_t, params::CT_BYTES> c{};
    kpke_encrypt(c.data(), ek.data(), m.data(), r.data());

    std::array<std::uint8_t, 32> back{};
    kpke_decrypt(back.data(), dk.data(), c.data());
    REQUIRE(back == m);
  }
  MESSAGE("K-PKE roundtrip: " << n << " iterations");
}

TEST_CASE("kpke_keygen is deterministic in d") {
  const auto d = random32();
  std::array<std::uint8_t, params::EK_PKE_BYTES> ek1{}, ek2{};
  std::array<std::uint8_t, params::DK_PKE_BYTES> dk1{}, dk2{};
  kpke_keygen(ek1.data(), dk1.data(), d.data());
  kpke_keygen(ek2.data(), dk2.data(), d.data());
  CHECK(ek1 == ek2);
  CHECK(dk1 == dk2);

  // A one-bit change in d changes both outputs.
  auto d2 = d;
  d2[0] ^= 0x01;
  std::array<std::uint8_t, params::EK_PKE_BYTES> ek3{};
  std::array<std::uint8_t, params::DK_PKE_BYTES> dk3{};
  kpke_keygen(ek3.data(), dk3.data(), d2.data());
  CHECK(ek1 != ek3);
  CHECK(dk1 != dk3);
}

TEST_CASE("ek_PKE carries rho verbatim in its last 32 bytes") {
  // rho is public and is the seed the decryptor re-expands A_hat from. If it were
  // transformed, encrypt would build a different matrix than keygen did.
  const auto d = random32();
  std::array<std::uint8_t, params::EK_PKE_BYTES> ek{};
  std::array<std::uint8_t, params::DK_PKE_BYTES> dk{};
  kpke_keygen(ek.data(), dk.data(), d.data());

  // Recompute rho independently: (rho, sigma) = G(d || k), k = 3.
  std::array<std::uint8_t, 33> gin{};
  std::memcpy(gin.data(), d.data(), 32);
  gin[32] = static_cast<std::uint8_t>(params::K);
  std::array<std::uint8_t, 64> gout{};
  M::G(gout.data(), gin.data(), gin.size());

  CHECK(std::memcmp(ek.data() + params::POLYVEC_BYTES, gout.data(), 32) == 0);
}

TEST_CASE("the ||k domain separator is present -- G(d||3), not G(d)") {
  // Failure mode #1. If the separator were dropped, keygen would equal a keygen driven
  // by G(d) alone. Construct that alternative explicitly and require it to DIFFER.
  const auto d = random32();
  std::array<std::uint8_t, params::EK_PKE_BYTES> ek{};
  std::array<std::uint8_t, params::DK_PKE_BYTES> dk{};
  kpke_keygen(ek.data(), dk.data(), d.data());

  std::array<std::uint8_t, 64> with_k{}, without_k{};
  std::array<std::uint8_t, 33> gin{};
  std::memcpy(gin.data(), d.data(), 32);
  gin[32] = static_cast<std::uint8_t>(params::K);
  M::G(with_k.data(), gin.data(), 33);
  M::G(without_k.data(), d.data(), 32);
  REQUIRE(std::memcmp(with_k.data(), without_k.data(), 64) != 0);

  // ek's rho matches the WITH-k expansion.
  CHECK(std::memcmp(ek.data() + params::POLYVEC_BYTES, with_k.data(), 32) == 0);
  CHECK(std::memcmp(ek.data() + params::POLYVEC_BYTES, without_k.data(), 32) != 0);
}

TEST_CASE("decryption tolerates the compression noise it is designed for") {
  // Not a failure-rate measurement (2^-164.8 is unobservable). This confirms the
  // margin is real across many random messages rather than lucky on one.
  const int n = kpke_iters();
  int ok = 0;
  for (int t = 0; t < n; ++t) {
    const auto d = random32(), m = random32(), r = random32();
    std::array<std::uint8_t, params::EK_PKE_BYTES> ek{};
    std::array<std::uint8_t, params::DK_PKE_BYTES> dk{};
    kpke_keygen(ek.data(), dk.data(), d.data());
    std::array<std::uint8_t, params::CT_BYTES> c{};
    kpke_encrypt(c.data(), ek.data(), m.data(), r.data());
    std::array<std::uint8_t, 32> back{};
    kpke_decrypt(back.data(), dk.data(), c.data());
    if (back == m) ++ok;
  }
  CHECK(ok == n);
  MESSAGE("decryption succeeded " << ok << "/" << n);
}
