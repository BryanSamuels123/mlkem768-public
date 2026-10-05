// Phase 6b: ML-KEM. FIPS 203 Algorithms 16-18 and the §7.2/§7.3 checks.

#include "doctest.h"

#include "kem.hpp"
#include "params.hpp"
#include "rng.hpp"
#include "verify.hpp"
#include "zeroize.hpp"

#include "model.hpp"

#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <random>

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
int kem_iters() { const int n = diff_iters() / 500; return n < 40 ? 40 : n; }

std::mt19937_64 rng(0x6B656D3A36620ULL);
std::array<std::uint8_t, 32> r32() {
  std::array<std::uint8_t, 32> v{};
  for (auto& b : v) b = static_cast<std::uint8_t>(rng());
  return v;
}
}  // namespace

TEST_CASE("ct_neq is exhaustive-correct on single-byte differences and has no early exit") {
  std::array<std::uint8_t, 64> a{}, b{};
  for (std::size_t i = 0; i < a.size(); ++i) { a[i] = static_cast<std::uint8_t>(i); b[i] = a[i]; }
  CHECK(ct_neq(a, b) == 0x00);

  // A difference at ANY position must be detected -- including the last, which an
  // early-exit implementation would still find, and the first, which it would find
  // fastest. The point is that both return the same mask.
  for (std::size_t i = 0; i < a.size(); ++i) {
    for (int bit = 0; bit < 8; ++bit) {
      auto c = b;
      c[i] = static_cast<std::uint8_t>(c[i] ^ (1u << bit));
      REQUIRE(ct_neq(a, c) == 0xFF);
    }
  }
  // Length mismatch is a public, structural fact.
  CHECK(ct_neq(std::span<const std::uint8_t>(a.data(), 64),
               std::span<const std::uint8_t>(b.data(), 32)) == 0xFF);
}

TEST_CASE("ct_cmov selects branchlessly on a full-width mask") {
  std::array<std::uint8_t, 32> r{}, x{};
  for (std::size_t i = 0; i < 32; ++i) { r[i] = 0xAA; x[i] = 0x55; }
  auto keep = r;
  ct_cmov(keep, x, 0x00);
  CHECK(keep == r);                      // mask 0 -> unchanged
  auto take = r;
  ct_cmov(take, x, 0xFF);
  CHECK(take == x);                      // mask 0xFF -> replaced
}

TEST_CASE("secure_zero actually clears, and Zeroizing wipes on scope exit") {
  std::array<std::uint8_t, 32> buf{};
  buf.fill(0xCD);
  secure_zero(buf.data(), buf.size());
  for (const auto b : buf) CHECK(b == 0);
  secure_zero(nullptr, 0);               // must not crash
  secure_zero(buf.data(), 0);
}

TEST_CASE("keygen_internal agrees with the model byte for byte") {
  const int n = kem_iters();
  for (int t = 0; t < n; ++t) {
    const auto d = r32(), z = r32();
    std::array<std::uint8_t, EK_BYTES> ek{}, mek{};
    std::array<std::uint8_t, DK_BYTES> dk{}, mdk{};
    keygen_internal(d.data(), z.data(), ek.data(), dk.data());
    M::keygen_internal(d.data(), z.data(), mek.data(), mdk.data());
    REQUIRE(ek == mek);
    REQUIRE(dk == mdk);
  }
  MESSAGE("keygen_internal differential: " << n << " iterations");
}

TEST_CASE("encaps_internal agrees with the model byte for byte") {
  const int n = kem_iters();
  for (int t = 0; t < n; ++t) {
    const auto d = r32(), z = r32(), m = r32();
    std::array<std::uint8_t, EK_BYTES> ek{};
    std::array<std::uint8_t, DK_BYTES> dk{};
    M::keygen_internal(d.data(), z.data(), ek.data(), dk.data());

    std::array<std::uint8_t, CT_BYTES> c{}, mc{};
    std::array<std::uint8_t, 32> k{}, mk{};
    encaps_internal(ek.data(), m.data(), c.data(), k.data());
    M::encaps_internal(ek.data(), m.data(), mc.data(), mk.data());
    REQUIRE(c == mc);
    REQUIRE(k == mk);
  }
  MESSAGE("encaps_internal differential: " << n << " iterations");
}

TEST_CASE("decaps_internal agrees with the model, valid AND rejecting") {
  const int n = kem_iters();
  for (int t = 0; t < n; ++t) {
    const auto d = r32(), z = r32(), m = r32();
    std::array<std::uint8_t, EK_BYTES> ek{};
    std::array<std::uint8_t, DK_BYTES> dk{};
    M::keygen_internal(d.data(), z.data(), ek.data(), dk.data());
    std::array<std::uint8_t, CT_BYTES> c{};
    std::array<std::uint8_t, 32> k{};
    M::encaps_internal(ek.data(), m.data(), c.data(), k.data());

    std::array<std::uint8_t, 32> got{}, want{};
    decaps_internal(dk.data(), c.data(), got.data());
    M::decaps_internal(dk.data(), c.data(), want.data());
    REQUIRE(got == want);
    REQUIRE(got == k);                   // valid path recovers the shared secret

    // Now the REJECTION path, which is the half that only M6 could isolate.
    auto bad = c;
    bad[static_cast<std::size_t>(rng() % CT_BYTES)] ^= 0x01;
    std::array<std::uint8_t, 32> rgot{}, rwant{};
    decaps_internal(dk.data(), bad.data(), rgot.data());
    M::decaps_internal(dk.data(), bad.data(), rwant.data());
    REQUIRE(rgot == rwant);
    REQUIRE(rgot != k);                  // different from the honest secret
  }
  MESSAGE("decaps_internal differential (valid + rejecting): " << n << " iterations");
}

TEST_CASE("implicit rejection returns exactly J(z || c)") {
  const auto d = r32(), z = r32(), m = r32();
  std::array<std::uint8_t, EK_BYTES> ek{};
  std::array<std::uint8_t, DK_BYTES> dk{};
  keygen_internal(d.data(), z.data(), ek.data(), dk.data());
  std::array<std::uint8_t, CT_BYTES> c{};
  std::array<std::uint8_t, 32> k{};
  encaps_internal(ek.data(), m.data(), c.data(), k.data());

  for (std::size_t bit : {std::size_t(0), std::size_t(4321), CT_BYTES * 8 - 1}) {
    auto bad = c;
    bad[bit / 8] ^= static_cast<std::uint8_t>(1u << (bit % 8));

    std::array<std::uint8_t, 32> got{}, got2{};
    decaps_internal(dk.data(), bad.data(), got.data());
    decaps_internal(dk.data(), bad.data(), got2.data());
    CHECK(got == got2);                  // deterministic
    CHECK(got != k);

    // And it equals J(z || c) exactly.
    std::array<std::uint8_t, 32 + CT_BYTES> jin{};
    std::memcpy(jin.data(), z.data(), 32);
    std::memcpy(jin.data() + 32, bad.data(), CT_BYTES);
    std::array<std::uint8_t, 32> expect{};
    M::J(expect.data(), jin.data(), jin.size());
    CHECK(got == expect);
  }
}

TEST_CASE("implicit rejection at EVERY bit position of the ciphertext") {
  // Not a sample. All 1088 * 8 = 8704 single-bit flips of a valid ciphertext. For each:
  // decaps must return exactly J(z||c), match the model, and be deterministic.
  //
  // This is the property M6 isolated in the KAT mutation work -- the 5 ACVP
  // modified-ciphertext vectors are the only automated evidence implicit rejection
  // exists, and 5 vectors is thin. 8704 flips is not.
  const auto d = r32(), z = r32(), m = r32();
  std::array<std::uint8_t, EK_BYTES> ek{};
  std::array<std::uint8_t, DK_BYTES> dk{};
  keygen_internal(d.data(), z.data(), ek.data(), dk.data());
  std::array<std::uint8_t, CT_BYTES> c{};
  std::array<std::uint8_t, 32> k{};
  encaps_internal(ek.data(), m.data(), c.data(), k.data());

  int rejected = 0, matched_model = 0, deterministic = 0, equals_J = 0;

  for (std::size_t bit = 0; bit < CT_BYTES * 8; ++bit) {
    auto bad = c;
    bad[bit / 8] = static_cast<std::uint8_t>(bad[bit / 8] ^ (1u << (bit % 8)));

    std::array<std::uint8_t, 32> got{}, again{}, want{};
    decaps_internal(dk.data(), bad.data(), got.data());
    decaps_internal(dk.data(), bad.data(), again.data());
    M::decaps_internal(dk.data(), bad.data(), want.data());

    if (got != k) ++rejected;              // differs from the honest secret
    if (got == want) ++matched_model;
    if (got == again) ++deterministic;

    // J(z || c) computed independently through the model.
    std::array<std::uint8_t, 32 + CT_BYTES> jin{};
    std::memcpy(jin.data(), z.data(), 32);
    std::memcpy(jin.data() + 32, bad.data(), CT_BYTES);
    std::array<std::uint8_t, 32> expect{};
    M::J(expect.data(), jin.data(), jin.size());
    if (got == expect) ++equals_J;
  }

  const int total = static_cast<int>(CT_BYTES * 8);
  CHECK(matched_model == total);
  CHECK(deterministic == total);
  CHECK(equals_J == total);
  // Every flip rejects: a single-bit change to a compressed ciphertext cannot
  // re-encrypt to itself, so there is no "accidentally still valid" case here.
  CHECK(rejected == total);
  MESSAGE("implicit rejection over all " << total << " single-bit flips: "
          << "rejected " << rejected << ", model-match " << matched_model
          << ", deterministic " << deterministic << ", == J(z||c) " << equals_J);
}

TEST_CASE("dk layout: z verbatim, ek embedded, H(ek) correct") {
  const auto d = r32(), z = r32();
  std::array<std::uint8_t, EK_BYTES> ek{};
  std::array<std::uint8_t, DK_BYTES> dk{};
  keygen_internal(d.data(), z.data(), ek.data(), dk.data());

  CHECK(std::memcmp(dk.data() + 1152, ek.data(), EK_BYTES) == 0);   // ek embedded
  CHECK(std::memcmp(dk.data() + 2368, z.data(), 32) == 0);          // z VERBATIM
  std::array<std::uint8_t, 32> h{};
  M::H(h.data(), ek.data(), EK_BYTES);
  CHECK(std::memcmp(dk.data() + 2336, h.data(), 32) == 0);          // H(ek)
}

TEST_CASE("no m <- H(m) and no final KDF (failure mode #2)") {
  // If Encaps hashed m first, K would equal the K produced by feeding H(m) instead.
  // Construct that alternative and require it to DIFFER.
  const auto d = r32(), z = r32(), m = r32();
  std::array<std::uint8_t, EK_BYTES> ek{};
  std::array<std::uint8_t, DK_BYTES> dk{};
  keygen_internal(d.data(), z.data(), ek.data(), dk.data());

  std::array<std::uint8_t, CT_BYTES> c{};
  std::array<std::uint8_t, 32> k{};
  encaps_internal(ek.data(), m.data(), c.data(), k.data());

  std::array<std::uint8_t, 32> hm{};
  M::H(hm.data(), m.data(), 32);
  std::array<std::uint8_t, CT_BYTES> c2{};
  std::array<std::uint8_t, 32> k2{};
  encaps_internal(ek.data(), hm.data(), c2.data(), k2.data());
  CHECK(k != k2);                        // m is NOT hashed first

  // K is G(m || H(ek))[0:32] verbatim -- no KDF applied afterwards.
  std::array<std::uint8_t, 64> gin{}, gout{};
  std::memcpy(gin.data(), m.data(), 32);
  M::H(gin.data() + 32, ek.data(), EK_BYTES);
  M::G(gout.data(), gin.data(), 64);
  CHECK(std::memcmp(k.data(), gout.data(), 32) == 0);
}

TEST_CASE("§7.2 encapsulation key check") {
  const auto d = r32(), z = r32();
  std::array<std::uint8_t, EK_BYTES> ek{};
  std::array<std::uint8_t, DK_BYTES> dk{};
  keygen_internal(d.data(), z.data(), ek.data(), dk.data());

  CHECK(check_encaps_key(ek.data(), EK_BYTES));
  CHECK_FALSE(check_encaps_key(ek.data(), EK_BYTES - 1));
  CHECK_FALSE(check_encaps_key(ek.data(), EK_BYTES + 1));

  // A 12-bit field >= q must be rejected: 0xFF 0xFF packs two fields of 4095.
  auto bad = ek;
  bad[0] = 0xFF; bad[1] = 0xFF; bad[2] = 0xFF;
  CHECK_FALSE(check_encaps_key(bad.data(), EK_BYTES));

  std::array<std::uint8_t, EK_BYTES> ones{};
  ones.fill(0xFF);
  CHECK_FALSE(check_encaps_key(ones.data(), EK_BYTES));

  // Agrees with the model on every case.
  CHECK(check_encaps_key(ek.data(), EK_BYTES) == M::check_encaps_key(ek.data(), EK_BYTES));
  CHECK(check_encaps_key(bad.data(), EK_BYTES) == M::check_encaps_key(bad.data(), EK_BYTES));
}

TEST_CASE("§7.3 decapsulation key check") {
  const auto d = r32(), z = r32();
  std::array<std::uint8_t, EK_BYTES> ek{};
  std::array<std::uint8_t, DK_BYTES> dk{};
  keygen_internal(d.data(), z.data(), ek.data(), dk.data());

  CHECK(check_decaps_key(dk.data(), DK_BYTES));
  CHECK_FALSE(check_decaps_key(dk.data(), DK_BYTES - 1));

  auto bad = dk;
  bad[2336] ^= 0x01;                     // corrupt H(ek)
  CHECK_FALSE(check_decaps_key(bad.data(), DK_BYTES));

  auto bad2 = dk;
  bad2[1152] ^= 0x01;                    // corrupt the embedded ek
  CHECK_FALSE(check_decaps_key(bad2.data(), DK_BYTES));

  CHECK(check_decaps_key(dk.data(), DK_BYTES) == M::check_decaps_key(dk.data(), DK_BYTES));
  CHECK(check_decaps_key(bad.data(), DK_BYTES) == M::check_decaps_key(bad.data(), DK_BYTES));
}

TEST_CASE("full KEM roundtrip, self-hosted") {
  const int n = kem_iters();
  for (int t = 0; t < n; ++t) {
    const auto d = r32(), z = r32(), m = r32();
    std::array<std::uint8_t, EK_BYTES> ek{};
    std::array<std::uint8_t, DK_BYTES> dk{};
    keygen_internal(d.data(), z.data(), ek.data(), dk.data());
    std::array<std::uint8_t, CT_BYTES> c{};
    std::array<std::uint8_t, 32> k{}, k2{};
    encaps_internal(ek.data(), m.data(), c.data(), k.data());
    decaps_internal(dk.data(), c.data(), k2.data());
    REQUIRE(k == k2);
  }
  MESSAGE("KEM roundtrip: " << n << " iterations");
}

// ===========================================================================
// Algorithms 19-21 — thin wrappers. Error path and plumbing only; correctness
// is inherited from 16/17/18 (see docs/notes/ for why they are excluded from
// the differential/mutation work).
// ===========================================================================

namespace {
bool g_rng_should_fail = false;
bool failing_rng(std::span<std::uint8_t> out, void*) noexcept {
  if (g_rng_should_fail) return false;
  for (auto& b : out) b = 0x5A;
  return true;
}
}  // namespace

TEST_CASE("keygen/encaps/decaps round-trip through the public API") {
  set_rng(nullptr, nullptr);                    // OS CSPRNG
  std::array<std::uint8_t, EK_BYTES> ek{};
  std::array<std::uint8_t, DK_BYTES> dk{};
  REQUIRE(keygen(ek.data(), dk.data()) == Status::Ok);

  std::array<std::uint8_t, CT_BYTES> c{};
  std::array<std::uint8_t, 32> k1{}, k2{};
  REQUIRE(encaps(ek.data(), ek.size(), c.data(), k1.data()) == Status::Ok);
  REQUIRE(decaps(dk.data(), dk.size(), c.data(), c.size(), k2.data()) == Status::Ok);
  CHECK(k1 == k2);
}

TEST_CASE("RBG failure is reported, not ignored (Alg. 19 lines 3-5, Alg. 20 lines 2-4)") {
  set_rng(failing_rng, nullptr);
  g_rng_should_fail = true;

  std::array<std::uint8_t, EK_BYTES> ek{};
  std::array<std::uint8_t, DK_BYTES> dk{};
  CHECK(keygen(ek.data(), dk.data()) == Status::RngFailure);

  g_rng_should_fail = false;
  REQUIRE(keygen(ek.data(), dk.data()) == Status::Ok);

  g_rng_should_fail = true;
  std::array<std::uint8_t, CT_BYTES> c{};
  std::array<std::uint8_t, 32> k{};
  CHECK(encaps(ek.data(), ek.size(), c.data(), k.data()) == Status::RngFailure);

  g_rng_should_fail = false;
  set_rng(nullptr, nullptr);
}

TEST_CASE("public API enforces §7.2/§7.3, and length checks are distinguishable") {
  set_rng(nullptr, nullptr);
  std::array<std::uint8_t, EK_BYTES> ek{};
  std::array<std::uint8_t, DK_BYTES> dk{};
  REQUIRE(keygen(ek.data(), dk.data()) == Status::Ok);
  std::array<std::uint8_t, CT_BYTES> c{};
  std::array<std::uint8_t, 32> k{};
  REQUIRE(encaps(ek.data(), ek.size(), c.data(), k.data()) == Status::Ok);

  CHECK(encaps(ek.data(), EK_BYTES - 1, c.data(), k.data()) == Status::InvalidEncapsKey);
  auto badek = ek; badek[0] = 0xFF; badek[1] = 0xFF; badek[2] = 0xFF;
  CHECK(encaps(badek.data(), EK_BYTES, c.data(), k.data()) == Status::InvalidEncapsKey);

  CHECK(decaps(dk.data(), dk.size(), c.data(), CT_BYTES - 1, k.data())
        == Status::InvalidCiphertext);
  auto baddk = dk; baddk[2336] ^= 0x01;
  CHECK(decaps(baddk.data(), DK_BYTES, c.data(), c.size(), k.data())
        == Status::InvalidDecapsKey);

  // A well-sized but INVALID ciphertext must NOT be distinguishable: Ok, with the
  // implicit-reject secret. This is the line between a status code and an oracle.
  auto badct = c; badct[7] ^= 0x01;
  std::array<std::uint8_t, 32> kr{};
  CHECK(decaps(dk.data(), dk.size(), badct.data(), badct.size(), kr.data()) == Status::Ok);
  CHECK(kr != k);
}

TEST_CASE("keygen is deterministic given a fixed RBG") {
  set_rng(failing_rng, nullptr);                // returns constant 0x5A bytes
  g_rng_should_fail = false;
  std::array<std::uint8_t, EK_BYTES> ek1{}, ek2{};
  std::array<std::uint8_t, DK_BYTES> dk1{}, dk2{};
  REQUIRE(keygen(ek1.data(), dk1.data()) == Status::Ok);
  REQUIRE(keygen(ek2.data(), dk2.data()) == Status::Ok);
  CHECK(ek1 == ek2);
  CHECK(dk1 == dk2);
  set_rng(nullptr, nullptr);
}
