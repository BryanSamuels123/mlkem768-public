#pragma once
// Phase 9b dudect targets. See docs/notes/09-dudect.md for the class design.
//
// CLASS DESIGN RULE (the ADR-020 lesson, applied to timing). Any value FIPS 203 makes
// public -- rho, ek, A_hat, c -- is held CONSTANT across both classes. If a public value
// varies, dudect will correctly report a timing difference that is not a leak: varying a
// KeyGen seed varies rho, which varies the rejection sampler's trip count, and
// `sample_ntt` is deliberately variable-time. Every target below states what is fixed,
// what varies, and why.
//
// The one deliberate exception is DecapsValidity, where a PUBLIC value (the ciphertext)
// varies on purpose: spec §10.3 requires decaps runtime to be independent of ciphertext
// validity, so there the public variation IS the property under test.

#include "kem.hpp"
#include "ntt.hpp"
#include "poly.hpp"
#include "polyvec.hpp"
#include "sample.hpp"
#include "params.hpp"

#include <array>
#include <cstdint>
#include <cstring>

namespace ctb {

using namespace mlkem768;

// splitmix64: small, fast, and never on a measured path.
struct Rng {
  std::uint64_t s;
  explicit Rng(std::uint64_t seed) : s(seed) {}
  std::uint64_t next() {
    std::uint64_t z = (s += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
  }
  void fill(std::uint8_t* p, std::size_t n) {
    for (std::size_t i = 0; i < n; ++i) p[i] = std::uint8_t(next());
  }
  int bit() { return int(next() & 1); }
};


// EVERY prepare() MUST DO IDENTICAL WORK FOR BOTH CLASSES.
//
// The first version of this harness wrote `if (cls == 0) work = fixed; else <fill with
// rng>`, which made class 1 run hundreds of RNG steps that class 0 did not, immediately
// before the timed region. That is a difference in cache and branch-predictor state
// entering the measurement, correlated perfectly with the class label -- a systematic
// bias that looks exactly like a leak. It showed up as the delta = 0 NULL CONTROL
// reporting |t| = 10.5 when nothing whatsoever was leaking.
//
// The fix is to always generate the random input and then select branchlessly. Both
// classes now execute the same instructions in prepare(); only the resulting BYTES
// differ, which is the thing under test.
inline void sel_bytes(void* dst, const void* fixed_v, const void* rand_v,
                      std::size_t n, int cls) {
  auto* d = static_cast<std::uint8_t*>(dst);
  auto* f = static_cast<const std::uint8_t*>(fixed_v);
  auto* r = static_cast<const std::uint8_t*>(rand_v);
  const std::uint8_t m = std::uint8_t(-(std::uint8_t)(cls & 1));   // 0x00 or 0xFF
  for (std::size_t i = 0; i < n; ++i)
    d[i] = std::uint8_t((f[i] & std::uint8_t(~m)) | (r[i] & m));
}

// Keeps the optimizer from deleting a measured computation whose result is unused.
extern volatile std::uint8_t g_sink;

enum class Fixed { Zero, Random };

struct Bench {
  const char* name;
  const char* fixed_desc;
  const char* varies_desc;
  virtual ~Bench() = default;
  virtual void setup(Fixed kind, Rng& rng) = 0;   // once, before measuring
  virtual void prepare(int cls, Rng& rng) = 0;    // per measurement, NOT timed
  virtual void run() = 0;                         // the timed region
  // BATCHED TIMING: K repetitions inside one rdtsc pair. For a function that runs a few
  // hundred ticks, one rdtsc pair spends a large fraction of the measurement on its own
  // overhead and quantizes to 1 tick; batching amortizes both and raises signal per
  // sample. The default is fine for every target whose run() does not destroy its input.
  virtual void run_n(int k) { for (int i = 0; i < k; ++i) run(); }
};

// ---------------------------------------------------------------- component targets
//
// For every component target the measured input IS the secret, and nothing public
// varies at all: there is no rho, no ek and no ciphertext in scope. These are the
// cleanest class designs in the suite.

struct NttBench : Bench {
  Poly fixedp{}, work{};
  NttBench() { name = "ntt"; fixed_desc = "nothing public in scope";
               varies_desc = "secret polynomial coefficients"; }
  void setup(Fixed kind, Rng& rng) override {
    for (auto& c : fixedp.c)
      c = (kind == Fixed::Zero) ? 0 : std::int16_t(rng.next() % params::Q);
  }
  Poly rnd{}, staged{};
  void prepare(int cls, Rng& rng) override {
    for (auto& c : rnd.c) c = std::int16_t(rng.next() % params::Q);
    sel_bytes(&staged, &fixedp, &rnd, sizeof(Poly), cls);
  }
  // ntt is IN-PLACE, so a batch has to re-stage the input each repetition or the second
  // iteration would transform already-transformed data (and leave the bounds table).
  // The copy is inside the timed region and identical for both classes.
  void run() override { work = staged; ntt(work); g_sink = std::uint8_t(work.c[0]); }
};

struct InvnttBench : Bench {
  Poly fixedp{}, work{};
  InvnttBench() { name = "invntt"; fixed_desc = "nothing public in scope";
                  varies_desc = "secret polynomial coefficients"; }
  void setup(Fixed kind, Rng& rng) override {
    for (auto& c : fixedp.c)
      c = (kind == Fixed::Zero) ? 0 : std::int16_t(rng.next() % params::Q);
  }
  Poly rnd{}, staged{};
  void prepare(int cls, Rng& rng) override {
    for (auto& c : rnd.c) c = std::int16_t(rng.next() % params::Q);
    sel_bytes(&staged, &fixedp, &rnd, sizeof(Poly), cls);
  }
  // invntt is IN-PLACE, so a batch has to re-stage the input each repetition or the second
  // iteration would transform already-transformed data (and leave the bounds table).
  // The copy is inside the timed region and identical for both classes.
  void run() override { work = staged; invntt(work); g_sink = std::uint8_t(work.c[0]); }
};

struct BasemulBench : Bench {
  Poly fixed_a{}, a{}, b{}, r{};
  BasemulBench() { name = "basemul"; fixed_desc = "b (the public A_hat operand)";
                   varies_desc = "a (the secret s_hat operand)"; }
  void setup(Fixed kind, Rng& rng) override {
    for (auto& c : b.c) c = std::int16_t(rng.next() % params::Q);   // fixed for both
    for (auto& c : fixed_a.c)
      c = (kind == Fixed::Zero) ? 0 : std::int16_t(rng.next() % params::Q);
  }
  Poly rnd{};
  void prepare(int cls, Rng& rng) override {
    for (auto& c : rnd.c) c = std::int16_t(rng.next() % params::Q);
    sel_bytes(&a, &fixed_a, &rnd, sizeof(Poly), cls);
  }
  void run() override { poly_basemul(r, a, b); g_sink = std::uint8_t(r.c[0]); }
};

struct CbdBench : Bench {
  std::array<std::uint8_t, 128> fixed_buf{}, buf{};
  Poly f{};
  CbdBench() { name = "sample_poly_cbd<2>"; fixed_desc = "nothing public in scope";
               varies_desc = "the secret PRF(sigma,N) output buffer"; }
  void setup(Fixed kind, Rng& rng) override {
    if (kind == Fixed::Zero) fixed_buf.fill(0); else rng.fill(fixed_buf.data(), 128);
  }
  std::array<std::uint8_t, 128> rnd{};
  void prepare(int cls, Rng& rng) override {
    rng.fill(rnd.data(), 128);
    sel_bytes(buf.data(), fixed_buf.data(), rnd.data(), 128, cls);
  }
  void run() override {
    sample_poly_cbd<2>(f, std::span<const std::uint8_t, 128>(buf));
    g_sink = std::uint8_t(f.c[0]);
  }
};

struct CompressDuBench : Bench {
  PolyVec fixed_pv{}, pv{};
  std::array<std::uint8_t, params::POLYVEC_COMPRESSED_DU_BYTES> out{};
  CompressDuBench() { name = "polyvec_compress_du"; fixed_desc = "nothing public in scope";
                      varies_desc = "u, which is derived from the secret r"; }
  void setup(Fixed kind, Rng& rng) override {
    for (auto& p : fixed_pv.v)
      for (auto& c : p.c)
        c = (kind == Fixed::Zero) ? 0 : std::int16_t(rng.next() % params::Q);
  }
  PolyVec rnd{};
  void prepare(int cls, Rng& rng) override {
    for (auto& p : rnd.v) for (auto& c : p.c) c = std::int16_t(rng.next() % params::Q);
    sel_bytes(&pv, &fixed_pv, &rnd, sizeof(PolyVec), cls);
  }
  void run() override { polyvec_compress_du(out.data(), pv); g_sink = out[0]; }
};

// THE KyberSlash SITE. Compress_1 is where the 2023 division-timing bug lived in the
// pq-crystals reference: `(((t << 1) + Q/2) / Q) & 1` with a secret dividend.
//
// This implementation has no division here at all: Phase 4 derived a multiply-shift with
// consteval and proved it exhaustively, and `gmake audit-div` checks at machine level that
// no div/idiv survives in the library. Note it is NOT the constant-ness of q that saves
// us -- the reference's divisor was constant too, and whether it compiled to a div
// depended on the toolchain.
struct TomsgBench : Bench {
  Poly fixed_w{}, w{};
  std::array<std::uint8_t, 32> msg{};
  TomsgBench() { name = "poly_tomsg (Compress_1)"; fixed_desc = "nothing public in scope";
                 varies_desc = "w, the secret decrypted polynomial"; }
  void setup(Fixed kind, Rng& rng) override {
    for (auto& c : fixed_w.c)
      c = (kind == Fixed::Zero) ? 0 : std::int16_t(rng.next() % params::Q);
  }
  Poly rnd{};
  void prepare(int cls, Rng& rng) override {
    for (auto& c : rnd.c) c = std::int16_t(rng.next() % params::Q);
    sel_bytes(&w, &fixed_w, &rnd, sizeof(Poly), cls);
  }
  void run() override { poly_tomsg(msg.data(), w); g_sink = msg[0]; }
};

// ---------------------------------------------------------------- top-level targets

// Spec §10.3: decaps runtime must not depend on whether the ciphertext is valid.
// Here a PUBLIC value (the ciphertext) varies deliberately -- that is the property.
// dk and ek, and therefore rho, are identical in both classes.
struct DecapsValidity : Bench {
  std::array<std::uint8_t, EK_BYTES> ek{};
  std::array<std::uint8_t, DK_BYTES> dk{};
  std::array<std::uint8_t, CT_BYTES> good{}, ct{};
  std::array<std::uint8_t, SS_BYTES> ss{};
  DecapsValidity() { name = "decaps valid-vs-invalid ct";
                     fixed_desc = "dk, ek, rho -- byte-identical in both classes";
                     varies_desc = "ciphertext validity (public, and that IS the property)"; }
  void setup(Fixed, Rng& rng) override {
    std::array<std::uint8_t, 32> d{}, z{}, m{};
    rng.fill(d.data(), 32); rng.fill(z.data(), 32); rng.fill(m.data(), 32);
    keygen_internal(d.data(), z.data(), ek.data(), dk.data());
    encaps_internal(ek.data(), m.data(), good.data(), ss.data());
  }
  std::array<std::uint8_t, CT_BYTES> bad{};
  void prepare(int cls, Rng& rng) override {
    bad = good;
    bad[rng.next() % CT_BYTES] ^= std::uint8_t(1u << (rng.next() & 7));
    sel_bytes(ct.data(), good.data(), bad.data(), CT_BYTES, cls);
  }
  void run() override { decaps_internal(dk.data(), ct.data(), ss.data()); g_sink = ss[0]; }
};

// Does decaps timing depend on the SECRET KEY BITS? ek (and so rho, and so the matrix
// expansion) is byte-identical across both classes: only dk_PKE's s and z vary.
// BOTH classes implicitly reject, deliberately -- accept-vs-reject is DecapsValidity's
// job, and mixing the two would confound this test with that one.
struct DecapsSecretKey : Bench {
  std::array<std::uint8_t, EK_BYTES> ek{};
  std::array<std::uint8_t, DK_BYTES> base{}, fixed_dk{}, dk{};
  std::array<std::uint8_t, CT_BYTES> ct{};
  std::array<std::uint8_t, SS_BYTES> ss{};
  static constexpr std::size_t kSecretLen = params::DK_PKE_BYTES;  // the s half
  DecapsSecretKey() { name = "decaps fixed-vs-random dk";
                      fixed_desc = "ek and H(ek) -- so rho and A_hat are identical";
                      varies_desc = "dk_PKE (the secret s); both classes reject"; }
  void setup(Fixed kind, Rng& rng) override {
    std::array<std::uint8_t, 32> d{}, z{}, m{}, ss2{};
    rng.fill(d.data(), 32); rng.fill(z.data(), 32); rng.fill(m.data(), 32);
    keygen_internal(d.data(), z.data(), ek.data(), base.data());
    encaps_internal(ek.data(), m.data(), ct.data(), ss2.data());
    fixed_dk = base;
    // Scramble s so class 0 also rejects, matching class 1's path.
    if (kind == Fixed::Zero) std::memset(fixed_dk.data(), 0, kSecretLen);
    else rng.fill(fixed_dk.data(), kSecretLen);
  }
  std::array<std::uint8_t, DK_BYTES> rnd{};
  void prepare(int cls, Rng& rng) override {
    rnd = base;
    rng.fill(rnd.data(), kSecretLen);
    dk = base;
    sel_bytes(dk.data(), fixed_dk.data(), rnd.data(), kSecretLen, cls);
  }
  void run() override { decaps_internal(dk.data(), ct.data(), ss.data()); g_sink = ss[0]; }
};

// m is secret; ek is fixed, so rho is fixed and gen_matrix's rejection sampling --
// legitimately variable-time -- is identical across classes.
struct EncapsMessage : Bench {
  std::array<std::uint8_t, EK_BYTES> ek{};
  std::array<std::uint8_t, DK_BYTES> dk{};
  std::array<std::uint8_t, 32> fixed_m{}, m{};
  std::array<std::uint8_t, CT_BYTES> ct{};
  std::array<std::uint8_t, SS_BYTES> ss{};
  EncapsMessage() { name = "encaps fixed-vs-random m";
                    fixed_desc = "ek, and therefore rho and the matrix expansion";
                    varies_desc = "m, the secret message"; }
  void setup(Fixed kind, Rng& rng) override {
    std::array<std::uint8_t, 32> d{}, z{};
    rng.fill(d.data(), 32); rng.fill(z.data(), 32);
    keygen_internal(d.data(), z.data(), ek.data(), dk.data());
    if (kind == Fixed::Zero) fixed_m.fill(0); else rng.fill(fixed_m.data(), 32);
  }
  std::array<std::uint8_t, 32> rnd{};
  void prepare(int cls, Rng& rng) override {
    rng.fill(rnd.data(), 32);
    sel_bytes(m.data(), fixed_m.data(), rnd.data(), 32, cls);
  }
  void run() override {
    encaps_internal(ek.data(), m.data(), ct.data(), ss.data());
    g_sink = ct[0];
  }
};

}  // namespace ctb
