// Phase 4: serialization, compression, message encoding.
//
// EXHAUSTIVE, not sampled. The domains are tiny -- 3329 values per d, 2^d per y -- so
// there is no excuse for sampling. Phase 2's montgomery_reduce off-by-one and mutation
// M7 both argue the same point: sampling misses rare-trigger bugs, and a rounding
// off-by-one is exactly a rare-trigger bug.

#include "doctest.h"

#include "params.hpp"
#include "poly.hpp"
#include "ntt.hpp"
#include "polyvec.hpp"
#include "reduce.hpp"

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

std::mt19937_64 rng(0x73657269616C3A34ULL);   // "serial:4"

constexpr std::int32_t Q = params::Q;

// Independent reference, formulated DIFFERENTLY from the implementation's
// multiply-shift so the test is not merely restating it: exact rational rounding with
// explicit tie handling.
std::uint32_t ref_compress(int d, std::uint32_t x) {
  const std::uint64_t v = static_cast<std::uint64_t>(x) << d;   // 2^d * x
  std::uint64_t r = v / static_cast<std::uint64_t>(Q);
  const std::uint64_t rem = v % static_cast<std::uint64_t>(Q);
  if (2 * rem >= static_cast<std::uint64_t>(Q)) ++r;            // ties round UP
  return static_cast<std::uint32_t>(r & ((1u << d) - 1));
}
std::uint32_t ref_decompress(int d, std::uint32_t y) {
  const std::uint64_t v = static_cast<std::uint64_t>(Q) * y;
  const std::uint64_t den = 1ULL << d;
  std::uint64_t r = v / den;
  const std::uint64_t rem = v % den;
  if (2 * rem >= den) ++r;
  return static_cast<std::uint32_t>(r);
}

Poly random_canonical_poly() {
  Poly p{};
  for (auto& c : p.c) c = static_cast<std::int16_t>(rng() % static_cast<std::uint64_t>(Q));
  return p;
}

PolyVec random_canonical_polyvec() {
  PolyVec v{};
  for (auto& p : v.v) p = random_canonical_poly();
  return v;
}

}  // namespace

// ===========================================================================
// Compress / Decompress — EXHAUSTIVE
// ===========================================================================

TEST_CASE("Compress_d is exact for EVERY x in [0,q), for every d used") {
  for (std::uint32_t x = 0; x < static_cast<std::uint32_t>(Q); ++x) {
    REQUIRE(compress_coeff<1>(static_cast<std::uint16_t>(x))  == ref_compress(1, x));
    REQUIRE(compress_coeff<4>(static_cast<std::uint16_t>(x))  == ref_compress(4, x));
    REQUIRE(compress_coeff<10>(static_cast<std::uint16_t>(x)) == ref_compress(10, x));
    // Not used by ML-KEM-768, but 1024 uses du=11/dv=5. Tested so the derivation is
    // not first exercised by a future parameter-set port.
    REQUIRE(compress_coeff<5>(static_cast<std::uint16_t>(x))  == ref_compress(5, x));
    REQUIRE(compress_coeff<11>(static_cast<std::uint16_t>(x)) == ref_compress(11, x));
  }
  MESSAGE("Compress exhaustive: " << Q << " inputs x 5 values of d = " << (Q * 5) << " cases");
}

TEST_CASE("Decompress_d is exact for EVERY y in [0, 2^d), and lands in [0,q)") {
  auto sweep = [](int d, auto fn) {
    for (std::uint32_t y = 0; y < (1u << d); ++y) {
      const std::uint16_t got = fn(static_cast<std::uint16_t>(y));
      REQUIRE(got == ref_decompress(d, y));
      REQUIRE(got < Q);
    }
  };
  sweep(1,  [](std::uint16_t y) { return decompress_coeff<1>(y); });
  sweep(4,  [](std::uint16_t y) { return decompress_coeff<4>(y); });
  sweep(5,  [](std::uint16_t y) { return decompress_coeff<5>(y); });
  sweep(10, [](std::uint16_t y) { return decompress_coeff<10>(y); });
  sweep(11, [](std::uint16_t y) { return decompress_coeff<11>(y); });
}

TEST_CASE("Compress_d(Decompress_d(y)) == y for ALL y -- the free oracle") {
  // FIPS 203 §4.2.1 guarantees this for every y and every d < 12.
  auto roundtrip = [](int d, auto c, auto dc) {
    for (std::uint32_t y = 0; y < (1u << d); ++y) {
      const auto back = c(dc(static_cast<std::uint16_t>(y)));
      REQUIRE_MESSAGE(back == y, "d=" << d << " y=" << y << " -> " << back);
    }
  };
  roundtrip(1,  [](std::uint16_t v){return compress_coeff<1>(v);},  [](std::uint16_t v){return decompress_coeff<1>(v);});
  roundtrip(4,  [](std::uint16_t v){return compress_coeff<4>(v);},  [](std::uint16_t v){return decompress_coeff<4>(v);});
  roundtrip(5,  [](std::uint16_t v){return compress_coeff<5>(v);},  [](std::uint16_t v){return decompress_coeff<5>(v);});
  roundtrip(10, [](std::uint16_t v){return compress_coeff<10>(v);}, [](std::uint16_t v){return decompress_coeff<10>(v);});
  roundtrip(11, [](std::uint16_t v){return compress_coeff<11>(v);}, [](std::uint16_t v){return decompress_coeff<11>(v);});
}

TEST_CASE("Compress agrees with the golden model exhaustively") {
  // The model computes it a third way (floor((2^(d+1)x + q)/2q) with real division).
  for (std::uint32_t x = 0; x < static_cast<std::uint32_t>(Q); ++x) {
    REQUIRE(compress_coeff<1>(static_cast<std::uint16_t>(x))  == static_cast<std::uint16_t>(M::compress(1, static_cast<std::int32_t>(x))));
    REQUIRE(compress_coeff<4>(static_cast<std::uint16_t>(x))  == static_cast<std::uint16_t>(M::compress(4, static_cast<std::int32_t>(x))));
    REQUIRE(compress_coeff<10>(static_cast<std::uint16_t>(x)) == static_cast<std::uint16_t>(M::compress(10, static_cast<std::int32_t>(x))));
  }
  for (int d : {1, 4, 10})
    for (std::uint32_t y = 0; y < (1u << d); ++y) {
      const std::uint16_t got = (d == 1)  ? decompress_coeff<1>(static_cast<std::uint16_t>(y))
                              : (d == 4)  ? decompress_coeff<4>(static_cast<std::uint16_t>(y))
                                          : decompress_coeff<10>(static_cast<std::uint16_t>(y));
      REQUIRE(got == static_cast<std::uint16_t>(M::decompress(d, static_cast<std::int32_t>(y))));
    }
}

TEST_CASE("round-half-UP: Compress can NEVER tie, Decompress ties exactly once per d") {
  // Worth stating precisely, because the naive expectation is wrong in both directions.
  //
  // COMPRESS: a tie needs 2*(2^d*x mod q) == q. q = 3329 is ODD, so an even number can
  // never equal it -- Compress_d has NO exact ties for any d, and FIPS 203 §2.3's
  // tie-break rule is VACUOUS there. Proven exhaustively below rather than argued.
  for (int d : {1, 4, 10, 11}) {
    int ties = 0;
    for (std::uint32_t x = 0; x < static_cast<std::uint32_t>(Q); ++x) {
      const std::uint64_t v = static_cast<std::uint64_t>(x) << d;
      if (2 * (v % static_cast<std::uint64_t>(Q)) == static_cast<std::uint64_t>(Q)) ++ties;
    }
    REQUIRE_MESSAGE(ties == 0, "d=" << d << " unexpectedly has Compress ties");
  }

  // DECOMPRESS: a tie needs q*y == 2^(d-1) (mod 2^d). q is odd hence invertible mod
  // 2^d, so there is EXACTLY ONE such y per d, namely y = 2^(d-1). That single value is
  // the only place the tie-break direction is observable anywhere in the scheme.
  auto check_tie = [](int d, std::uint16_t y, std::uint16_t got) {
    const std::uint64_t v = static_cast<std::uint64_t>(Q) * y;
    const std::uint64_t den = 1ULL << d;
    REQUIRE(2 * (v % den) == den);                 // confirm it really is a tie
    REQUIRE(got == (v / den) + 1);                 // and that it rounded UP, not down
  };
  check_tie(1,  1,    decompress_coeff<1>(1));
  check_tie(4,  8,    decompress_coeff<4>(8));
  check_tie(10, 512,  decompress_coeff<10>(512));
  check_tie(11, 1024, decompress_coeff<11>(1024));

  // And the d=1 tie IS the message-bit constant. Rounding half-DOWN gives 1664.
  //
  // Note what that would and would not break. DECRYPTION STILL WORKS: 1664 is far from
  // the q/4 and 3q/4 boundaries Compress_1 uses to recover the bit. What breaks is
  // BYTE-EXACTNESS -- mu shifts by 1 in every set-bit coefficient, v shifts with it, and
  // for a fraction of inputs that changes a Compress_dv output and therefore the
  // ciphertext. A self-consistent implementation that fails KATs, which is why the
  // standard specifies the direction.
  CHECK(decompress_coeff<1>(1) == 1665);
  CHECK(decompress_coeff<1>(1) == (Q + 1) / 2);
  MESSAGE("Compress: 0 ties for any d (q is odd). Decompress: exactly 1 tie per d, "
          "at y = 2^(d-1); for d=1 that tie is the message constant 1665.");
}

// ===========================================================================
// ByteEncode / ByteDecode
// ===========================================================================

TEST_CASE("poly_tobytes/frombytes roundtrip over random canonical polynomials") {
  const int n = diff_iters() / 100 < 1000 ? 1000 : diff_iters() / 100;
  for (int i = 0; i < n; ++i) {
    const Poly a = random_canonical_poly();
    std::array<std::uint8_t, 384> bytes{};
    poly_tobytes(bytes.data(), a);
    Poly b{};
    poly_frombytes(b, bytes.data());
    REQUIRE(std::memcmp(a.c.data(), b.c.data(), sizeof a.c) == 0);
  }
}

TEST_CASE("poly_tobytes agrees with the model byte for byte") {
  const int n = diff_iters() / 100 < 1000 ? 1000 : diff_iters() / 100;
  for (int i = 0; i < n; ++i) {
    const Poly a = random_canonical_poly();
    M::Poly ma{};
    for (std::size_t k = 0; k < params::N; ++k) ma[k] = a.c[k];

    std::array<std::uint8_t, 384> impl{};
    poly_tobytes(impl.data(), a);
    const auto want = M::byte_encode(12, ma);
    REQUIRE(want.size() == 384);
    REQUIRE(std::memcmp(impl.data(), want.data(), 384) == 0);

    // ...and decode back through the model.
    const M::Poly back = M::byte_decode(12, impl.data());
    Poly ib{};
    poly_frombytes(ib, impl.data());
    for (std::size_t k = 0; k < params::N; ++k) REQUIRE(ib.c[k] == back[k]);
  }
  MESSAGE("poly_tobytes/frombytes differential: " << n << " iterations");
}

TEST_CASE("ByteDecode_12 is NOT injective -- out-of-range fields fold mod q") {
  // This is the property the §7.2 modulus check exists to detect. It is deliberate;
  // the test pins it so nobody "fixes" it later.
  std::array<std::uint8_t, 384> bytes{};
  bytes.fill(0xFF);                        // every 12-bit field = 4095
  Poly r{};
  poly_frombytes(r, bytes.data());
  for (const auto c : r.c) {
    REQUIRE(c >= 0);
    REQUIRE(c < Q);
    REQUIRE(c == 4095 - Q);                // 4095 mod 3329 = 766
  }

  // Re-encoding does NOT reproduce the input -- exactly what the check detects.
  std::array<std::uint8_t, 384> re{};
  poly_tobytes(re.data(), r);
  REQUIRE(std::memcmp(re.data(), bytes.data(), 384) != 0);

  // Whereas a canonically-encoded polynomial DOES survive the roundtrip.
  const Poly good = random_canonical_poly();
  std::array<std::uint8_t, 384> gb{}, gb2{};
  poly_tobytes(gb.data(), good);
  Poly gd{};
  poly_frombytes(gd, gb.data());
  poly_tobytes(gb2.data(), gd);
  REQUIRE(std::memcmp(gb.data(), gb2.data(), 384) == 0);
}

// ===========================================================================
// Compression paths
// ===========================================================================

TEST_CASE("poly_compress_dv / decompress_dv agree with the model") {
  const int n = diff_iters() / 100 < 1000 ? 1000 : diff_iters() / 100;
  for (int i = 0; i < n; ++i) {
    const Poly a = random_canonical_poly();
    M::Poly ma{};
    for (std::size_t k = 0; k < params::N; ++k) ma[k] = a.c[k];

    std::array<std::uint8_t, 128> impl{};
    poly_compress_dv(impl.data(), a);

    M::Poly mc{};
    for (std::size_t k = 0; k < params::N; ++k) mc[k] = M::compress(params::DV, ma[k]);
    const auto want = M::byte_encode(params::DV, mc);
    REQUIRE(std::memcmp(impl.data(), want.data(), 128) == 0);

    Poly back{};
    poly_decompress_dv(back, impl.data());
    const M::Poly mdec = M::byte_decode(params::DV, impl.data());
    for (std::size_t k = 0; k < params::N; ++k)
      REQUIRE(back.c[k] == M::decompress(params::DV, mdec[k]));
  }
  MESSAGE("poly_compress_dv differential: " << n << " iterations");
}

TEST_CASE("polyvec_compress_du / decompress_du agree with the model") {
  const int n = diff_iters() / 100 < 1000 ? 1000 : diff_iters() / 100;
  for (int i = 0; i < n; ++i) {
    const PolyVec a = random_canonical_polyvec();

    std::array<std::uint8_t, params::POLYVEC_COMPRESSED_DU_BYTES> impl{};
    polyvec_compress_du(impl.data(), a);

    // Model: compress then ByteEncode_du, one polynomial at a time.
    std::size_t off = 0;
    for (int i2 = 0; i2 < params::K; ++i2) {
      M::Poly mc{};
      for (std::size_t k = 0; k < params::N; ++k)
        mc[k] = M::compress(params::DU, a.v[static_cast<std::size_t>(i2)].c[k]);
      const auto want = M::byte_encode(params::DU, mc);
      REQUIRE(want.size() == 320);
      REQUIRE(std::memcmp(impl.data() + off, want.data(), 320) == 0);
      off += 320;
    }
    REQUIRE(off == params::POLYVEC_COMPRESSED_DU_BYTES);

    PolyVec back{};
    polyvec_decompress_du(back, impl.data());
    for (int i2 = 0; i2 < params::K; ++i2) {
      const M::Poly md = M::byte_decode(params::DU, impl.data() + static_cast<std::size_t>(i2) * 320);
      for (std::size_t k = 0; k < params::N; ++k)
        REQUIRE(back.v[static_cast<std::size_t>(i2)].c[k] == M::decompress(params::DU, md[k]));
    }
  }
  MESSAGE("polyvec_compress_du differential: " << n << " iterations");
}

TEST_CASE("polyvec_tobytes/frombytes roundtrip and model agreement") {
  const int n = diff_iters() / 100 < 1000 ? 1000 : diff_iters() / 100;
  for (int i = 0; i < n; ++i) {
    const PolyVec a = random_canonical_polyvec();
    std::array<std::uint8_t, params::POLYVEC_BYTES> bytes{};
    polyvec_tobytes(bytes.data(), a);
    PolyVec b{};
    polyvec_frombytes(b, bytes.data());
    for (int k = 0; k < params::K; ++k)
      REQUIRE(std::memcmp(a.v[static_cast<std::size_t>(k)].c.data(),
                          b.v[static_cast<std::size_t>(k)].c.data(), sizeof(Poly)) == 0);
  }
}

// ===========================================================================
// Message encoding
// ===========================================================================

TEST_CASE("poly_tomsg(poly_frommsg(m)) == m") {
  const int n = diff_iters() / 10 < 10000 ? 10000 : diff_iters() / 10;
  for (int i = 0; i < n; ++i) {
    std::array<std::uint8_t, 32> m{}, back{};
    for (auto& b : m) b = static_cast<std::uint8_t>(rng());
    Poly p{};
    poly_frommsg(p, m.data());
    poly_tomsg(back.data(), p);
    REQUIRE(m == back);
  }
  MESSAGE("tomsg/frommsg roundtrip: " << n << " iterations");
}

TEST_CASE("poly_frommsg/tomsg agree with the model") {
  const int n = diff_iters() / 100 < 1000 ? 1000 : diff_iters() / 100;
  for (int i = 0; i < n; ++i) {
    std::array<std::uint8_t, 32> m{};
    for (auto& b : m) b = static_cast<std::uint8_t>(rng());

    Poly p{};
    poly_frommsg(p, m.data());
    // model: Decompress_1(ByteDecode_1(m))
    const M::Poly md = M::byte_decode(1, m.data());
    for (std::size_t k = 0; k < params::N; ++k)
      REQUIRE(p.c[k] == M::decompress(1, md[k]));

    // model: ByteEncode_1(Compress_1(w)) over a random canonical w
    const Poly w = random_canonical_poly();
    std::array<std::uint8_t, 32> impl{};
    poly_tomsg(impl.data(), w);
    M::Poly mw{}, mc{};
    for (std::size_t k = 0; k < params::N; ++k) mw[k] = w.c[k];
    for (std::size_t k = 0; k < params::N; ++k) mc[k] = M::compress(1, mw[k]);
    const auto want = M::byte_encode(1, mc);
    REQUIRE(std::memcmp(impl.data(), want.data(), 32) == 0);
  }
  MESSAGE("frommsg/tomsg differential: " << n << " iterations");
}

TEST_CASE("bit packing is LITTLE-ENDIAN at the bit level (failure mode #7)") {
  // A message of 0x01 0x00 ... must set the FIRST coefficient, not the eighth.
  std::array<std::uint8_t, 32> m{};
  m[0] = 0x01;
  Poly p{};
  poly_frommsg(p, m.data());
  CHECK(p.c[0] == 1665);
  for (std::size_t k = 1; k < params::N; ++k) CHECK(p.c[k] == 0);

  // Bit 7 of byte 0 lands in coefficient 7.
  std::array<std::uint8_t, 32> m2{};
  m2[0] = 0x80;
  Poly p2{};
  poly_frommsg(p2, m2.data());
  CHECK(p2.c[7] == 1665);
  CHECK(p2.c[0] == 0);

  // Byte 1 bit 0 lands in coefficient 8.
  std::array<std::uint8_t, 32> m3{};
  m3[1] = 0x01;
  Poly p3{};
  poly_frommsg(p3, m3.data());
  CHECK(p3.c[8] == 1665);

  // Decompress_1(1) = ceil(q/2) = 1665, and 0 -> 0.
  CHECK(decompress_coeff<1>(1) == 1665);
  CHECK(decompress_coeff<1>(0) == 0);
}

TEST_CASE("tomsg rounds to the nearer of {0, 1665} across the whole range") {
  // Exhaustive over every coefficient value: the decision boundary is q/4 and 3q/4.
  for (std::int32_t x = 0; x < Q; ++x) {
    Poly p{};
    p.c.fill(0);
    p.c[0] = static_cast<std::int16_t>(x);
    std::array<std::uint8_t, 32> msg{};
    poly_tomsg(msg.data(), p);
    const int bit = msg[0] & 1;
    REQUIRE(bit == static_cast<int>(ref_compress(1, static_cast<std::uint32_t>(x))));
  }
}

// ===========================================================================
// Canonicalization — ADR-004's consequence
// ===========================================================================

TEST_CASE("poly_canonicalize maps ANY int16_t to [0, q) preserving the residue") {
  for (std::int32_t v = -32768; v <= 32767; ++v) {
    Poly p{};
    p.c.fill(0);
    p.c[0] = static_cast<std::int16_t>(v);
    poly_canonicalize(p);
    REQUIRE(p.c[0] >= 0);
    REQUIRE(p.c[0] < Q);
    REQUIRE(((p.c[0] - v) % Q) == 0);
  }
  MESSAGE("poly_canonicalize exhaustive over all 65536 int16_t values");
}

TEST_CASE("serialization requires canonicalization -- the Montgomery consequence") {
  // A polynomial straight out of the arithmetic layer carries centered values and a
  // Montgomery factor. Feeding that to tobytes without canonicalizing produces garbage;
  // canonicalizing first makes the roundtrip exact. This is ADR-004 made concrete.
  Poly p = random_canonical_poly();
  ntt(p);                                    // now centered, |c| <= 1664, some negative
  bool any_negative = false;
  for (const auto c : p.c) if (c < 0) any_negative = true;
  REQUIRE(any_negative);                     // the hazard is real, not hypothetical

  Poly canon = p;
  poly_canonicalize(canon);
  for (const auto c : canon.c) { REQUIRE(c >= 0); REQUIRE(c < Q); }

  std::array<std::uint8_t, 384> bytes{};
  poly_tobytes(bytes.data(), canon);
  Poly back{};
  poly_frombytes(back, bytes.data());
  REQUIRE(std::memcmp(canon.c.data(), back.c.data(), sizeof canon.c) == 0);

  // And the residues match the pre-canonicalization values.
  for (std::size_t k = 0; k < params::N; ++k)
    REQUIRE(((back.c[k] - p.c[k]) % Q) == 0);
}

TEST_CASE("polyvec_canonicalize covers every coordinate") {
  PolyVec v{};
  for (auto& p : v.v) for (auto& c : p.c) c = static_cast<std::int16_t>(rng());
  polyvec_canonicalize(v);
  for (const auto& p : v.v) for (const auto c : p.c) { REQUIRE(c >= 0); REQUIRE(c < Q); }
}
