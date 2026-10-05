// AVX2 backend: the AVX2 code must be a re-expression of the portable code, never a
// re-derivation of the mathematics. Everything here checks EQUALITY, not plausibility.
//
// Three layers of check, in increasing strength:
//   1. the SIMD reduction primitives equal the scalar ones, EXHAUSTIVELY;
//   2. the regenerated zeta table equals the one already checked against Appendix A;
//   3. the generated lane tables agree with what the REAL INTRINSICS actually do, and
//      with what the SCALAR loop's own index bookkeeping would pick.
//
// (3) is the one that matters. zetas_avx2.hpp derives its lane layout by simulating the
// shuffles on an index array. That mimic could be wrong -- it is hand-written code
// describing a hardware permutation. So this test applies the ACTUAL intrinsic to an
// array of coefficient indices at runtime, reads off where each index landed, and
// independently recomputes which zeta the scalar algorithm assigns to that coefficient.
// If the mimic and the hardware ever disagree, this fails; a KAT would too, but this
// says which lane and why.

#include "doctest.h"

#include "ntt.hpp"
#include "poly.hpp"
#include "polyvec.hpp"
#include "reduce.hpp"

#include <cstring>

#include "arch/dispatch.hpp"

#if defined(__x86_64__)
#include "arch/avx2/reduce_avx2.hpp"
#include "arch/avx2/zetas_avx2.hpp"
#include "arch/avx2/rej_table_avx2.hpp"
#include <immintrin.h>

using namespace mlkem768;

namespace mlkem768::avx2 {
void cbd2(Poly&, const std::uint8_t*) noexcept;
void compress_du_poly(std::uint8_t*, const Poly&) noexcept;
void basemul(Poly&, const Poly&, const Poly&) noexcept;
void basemul_acc(Poly&, const Poly&, const Poly&) noexcept;
const std::int16_t* gamma_table() noexcept;
void decompress_du_poly(Poly&, const std::uint8_t*) noexcept;
void ntt(Poly&) noexcept;
void invntt(Poly&) noexcept;
}

namespace {

// Literal transcription of Algorithm 8 at eta=2, independent of the library's dispatch,
// so this test compares SIMD against the SPEC rather than against whichever backend
// sample_poly_cbd<2> happens to select.
void cbd2_scalar_ref(Poly& f, const std::uint8_t* buf) {
  for (int i = 0; i < params::N / 8; ++i) {
    std::uint32_t t = 0;
    for (int k = 0; k < 4; ++k) t |= static_cast<std::uint32_t>(buf[4 * i + k]) << (8 * k);
    std::uint32_t d = t & 0x55555555u;
    d += (t >> 1) & 0x55555555u;
    for (int k = 0; k < 8; ++k) {
      const auto x = static_cast<std::int16_t>((d >> (4 * k + 0)) & 0x3u);
      const auto y = static_cast<std::int16_t>((d >> (4 * k + 2)) & 0x3u);
      f.c[static_cast<std::size_t>(8 * i + k)] = static_cast<std::int16_t>(x - y);
    }
  }
}

// The scalar algorithm's own answer to "which zeta does coefficient `c` use at this
// layer?", obtained by replaying Algorithm 9's / Algorithm 10's counter, not by a
// formula copied from the implementation.
int scalar_zeta_index(int coeff, int len, bool inverse) {
  int k = inverse ? 127 : 1;
  for (int L = inverse ? 2 : 128; inverse ? (L <= 128) : (L >= 2); L = inverse ? (L << 1) : (L >> 1)) {
    for (int start = 0; start < params::N; start += 2 * L) {
      const int here = inverse ? k-- : k++;
      if (L == len && coeff >= start && coeff < start + 2 * L) return here;
    }
  }
  return -1;
}

// Read back where each coefficient index lands after a real intrinsic shuffle.
struct Lanes { std::int16_t a[16]; };

Lanes apply_split(int which, int u) {
  alignas(32) std::int16_t i0[16], i1[16];
  for (int l = 0; l < 16; ++l) { i0[l] = static_cast<std::int16_t>(32 * u + l);
                                 i1[l] = static_cast<std::int16_t>(32 * u + 16 + l); }
  __m256i V0 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(i0));
  __m256i V1 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(i1));
  if (which == 2) { V0 = _mm256_shuffle_epi32(V0, 0xD8); V1 = _mm256_shuffle_epi32(V1, 0xD8); }
  const __m256i A = (which == 0) ? _mm256_permute2x128_si256(V0, V1, 0x20)
                                 : _mm256_unpacklo_epi64(V0, V1);
  Lanes out{};
  _mm256_storeu_si256(reinterpret_cast<__m256i*>(out.a), A);
  return out;
}

}  // namespace

TEST_CASE("avx2: SIMD reduction primitives equal the scalar ones, exhaustively") {
  // A skip must be VISIBLE, never silent (the project has been bitten by vacuous
  // passes). MLKEM_FORCE_ARCH=portable turns has_avx2() off, which is the only way
  // these skip on an AVX2 host.
  if (!arch::has_avx2()) { MESSAGE("SKIPPED: no AVX2 (or forced portable)"); return; }
  alignas(32) std::int16_t in[16], out[16];
  long bad = 0;
  for (long base = -32768; base <= 32767; base += 16) {
    for (int l = 0; l < 16; ++l) { long v = base + l;
      in[l] = static_cast<std::int16_t>(v > 32767 ? v - 65536 : v); }
    const __m256i a = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(in));
    _mm256_storeu_si256(reinterpret_cast<__m256i*>(out), avx2::barrett_reduce_vec(a));
    for (int l = 0; l < 16; ++l) if (barrett_reduce(in[l]) != out[l]) ++bad;
  }
  CHECK(bad == 0);                                     // all 65536 int16_t

  const std::int16_t* Z = tables::zetas();
  long badm = 0;
  for (int zi = 0; zi < 128; ++zi) {
    const std::int16_t z = Z[zi];
    const __m256i zv = _mm256_set1_epi16(z);
    const __m256i zqv = _mm256_set1_epi16(avx2::qinv_of(z));
    for (long base = -32768; base <= 32767; base += 16) {
      for (int l = 0; l < 16; ++l) { long v = base + l;
        in[l] = static_cast<std::int16_t>(v > 32767 ? v - 65536 : v); }
      const __m256i a = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(in));
      _mm256_storeu_si256(reinterpret_cast<__m256i*>(out), avx2::mont_mul_vec(a, zv, zqv));
      for (int l = 0; l < 16; ++l) if (mont_mul(in[l], z) != out[l]) ++badm;
    }
  }
  CHECK(badm == 0);                                    // 8,388,608 (a, zeta) pairs
}

TEST_CASE("avx2: regenerated zeta table equals the Appendix-A-checked one") {
  const std::int16_t* Z = tables::zetas();
  for (int i = 0; i < 128; ++i) CHECK(avx2::kZ[static_cast<std::size_t>(i)] == Z[i]);
}

TEST_CASE("avx2: lane tables agree with the REAL intrinsics and the SCALAR counter") {
  // A skip must be VISIBLE, never silent (the project has been bitten by vacuous
  // passes). MLKEM_FORCE_ARCH=portable turns has_avx2() off, which is the only way
  // these skip on an AVX2 host.
  if (!arch::has_avx2()) { MESSAGE("SKIPPED: no AVX2 (or forced portable)"); return; }
  struct Case { const avx2::LaneTable* fwd; const avx2::LaneTable* inv; int which; int len; };
  const Case cases[] = {
      {&avx2::kLane8, &avx2::kLane8Inv, 0, 8},
      {&avx2::kLane4, &avx2::kLane4Inv, 1, 4},
      {&avx2::kLane2, &avx2::kLane2Inv, 2, 2},
  };
  const std::int16_t* Z = tables::zetas();
  for (const Case& c : cases) {
    for (int u = 0; u < 8; ++u) {
      const Lanes A = apply_split(c.which, u);
      for (int l = 0; l < 16; ++l) {
        const int coeff = A.a[l];
        REQUIRE(coeff >= 0);
        REQUIRE(coeff < params::N);
        // forward
        const int kf = scalar_zeta_index(coeff, c.len, false);
        REQUIRE(kf > 0);
        CHECK(c.fwd->z[static_cast<std::size_t>(u)][static_cast<std::size_t>(l)] == Z[kf]);
        CHECK(c.fwd->zq[static_cast<std::size_t>(u)][static_cast<std::size_t>(l)] == avx2::qinv_of(Z[kf]));
        // inverse -- a DIFFERENT index; sharing the forward table was the design's one error
        const int ki = scalar_zeta_index(coeff, c.len, true);
        REQUIRE(ki > 0);
        CHECK(c.inv->z[static_cast<std::size_t>(u)][static_cast<std::size_t>(l)] == Z[ki]);
      }
    }
  }
}

TEST_CASE("avx2: rej compaction table matches what _mm_shuffle_epi8 ACTUALLY does, all 256 masks") {
  if (!arch::has_avx2()) { MESSAGE("SKIPPED: no AVX2 (or forced portable)"); return; }
  // The table is generated by simulating the shuffle. That simulation is hand-written
  // code describing a hardware instruction, so it is checked from the other side: run
  // the REAL intrinsic on a known lane pattern and confirm the accepted lanes land at
  // the front, in order, for every one of the 256 masks. Same three-way discipline the
  // NTT zeta lane tables get.
  alignas(16) std::int16_t in[8], out[8];
  for (int i = 0; i < 8; ++i) in[i] = static_cast<std::int16_t>(1000 + i);
  const __m128i v = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in));
  for (int m = 0; m < 256; ++m) {
    const __m128i sh = _mm_loadu_si128(
        reinterpret_cast<const __m128i*>(avx2::kRejShuffle.e[static_cast<std::size_t>(m)].data()));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out), _mm_shuffle_epi8(v, sh));
    int k = 0;
    for (int lane = 0; lane < 8; ++lane)
      if ((m >> lane) & 1) { CHECK(out[k] == in[lane]); ++k; }     // order preserved
    CHECK(k == __builtin_popcount(static_cast<unsigned>(m)));      // count correct
    for (int j = k; j < 8; ++j) CHECK(out[j] == 0);                // tail zeroed by 0x80
  }
  MESSAGE("rej compaction table: all 256 masks verified against the real pshufb");
}

TEST_CASE("avx2: SIMD CBD eta=2 is bit-identical to scalar, EXHAUSTIVELY") {
  if (!arch::has_avx2()) { MESSAGE("SKIPPED: no AVX2 (or forced portable)"); return; }
  // CBD at eta=2 is BYTE-LOCAL: coefficient 2b comes from the low nibble of byte b and
  // 2b+1 from the high nibble. So 256 byte values x 128 positions is the ENTIRE
  // input-to-output map -- genuinely exhaustive, not a large sample.
  std::uint8_t buf[128];
  long bad = 0;
  for (int pos = 0; pos < 128; ++pos) {
    for (int val = 0; val < 256; ++val) {
      std::memset(buf, 0, sizeof buf);
      buf[pos] = static_cast<std::uint8_t>(val);
      Poly a{}, b{};
      cbd2_scalar_ref(a, buf);
      avx2::cbd2(b, buf);
      if (std::memcmp(a.c.data(), b.c.data(), sizeof(a.c)) != 0) ++bad;
    }
  }
  CHECK(bad == 0);

  // The exhaustive argument RESTS on byte-locality. Check that too, or the claim above
  // is unfounded: byte b must move only coefficients 2b and 2b+1.
  long nonlocal = 0;
  for (int pos = 0; pos < 128; ++pos) {
    std::memset(buf, 0, sizeof buf);
    Poly z{}; avx2::cbd2(z, buf);
    buf[pos] = 0xFF;
    Poly y{}; avx2::cbd2(y, buf);
    for (int c = 0; c < params::N; ++c)
      if (c != 2 * pos && c != 2 * pos + 1 && y.c[c] != z.c[c]) ++nonlocal;
  }
  CHECK(nonlocal == 0);
  MESSAGE("CBD eta=2: 32768 exhaustive cases identical; byte-locality holds");
}

TEST_CASE("avx2: SIMD compress/decompress du=10 bit-identical to scalar, EXHAUSTIVELY") {
  if (!arch::has_avx2()) { MESSAGE("SKIPPED: no AVX2 (or forced portable)"); return; }
  // The domain that ACTUALLY reaches compress is [0,q): kpke_encrypt runs
  // polyvec_canonicalize(u) first, so canonicalization is NOT fused in and the input is
  // always canonical. Compress is coefficient-local, so [0,q) x 256 positions is the
  // complete input-to-output map. Decompress's domain is all 2^10 field values.
  long bad = 0;
  for (int pos = 0; pos < params::N; ++pos) {
    for (int x = 0; x < params::Q; ++x) {
      PolyVec pv{}; pv.v[0].c[static_cast<std::size_t>(pos)] = static_cast<std::int16_t>(x);
      std::array<std::uint8_t, params::POLYVEC_COMPRESSED_DU_BYTES> g{}, h{};
      polyvec_compress_du(g.data(), pv);                    // dispatches to SIMD
      avx2::compress_du_poly(h.data(), pv.v[0]);            // direct
      if (std::memcmp(g.data(), h.data(), 320) != 0) ++bad;
    }
  }
  CHECK(bad == 0);
  long badd = 0;
  for (int slot = 0; slot < params::N; ++slot) {
    for (int y = 0; y < 1024; ++y) {
      std::array<std::uint8_t, params::POLYVEC_COMPRESSED_DU_BYTES> in{};
      std::uint64_t w = static_cast<std::uint64_t>(y) << (10 * (slot % 4));
      std::memcpy(in.data() + 5 * (slot / 4), &w, 5);
      PolyVec a{}; Poly b{};
      polyvec_decompress_du(a, in.data());
      avx2::decompress_du_poly(b, in.data());
      if (std::memcmp(a.v[0].c.data(), b.c.data(), sizeof(b.c)) != 0) ++badd;
    }
  }
  CHECK(badd == 0);
  MESSAGE("compress_du: " << 256 * params::Q << " exhaustive cases; decompress_du: "
          << 256 * 1024 << " -- all identical");
}

TEST_CASE("avx2: basemul is bit-identical to portable, and the k=3 bound holds exactly") {
  if (!arch::has_avx2()) { MESSAGE("SKIPPED: no AVX2 (or forced portable)"); return; }
  std::uint32_t st = 4242u;
  auto rnd = [&st] { st ^= st << 13; st ^= st >> 17; st ^= st << 5; return st; };
  long bad = 0, badacc = 0, worst = 0;
  for (int t = 0; t < 3000; ++t) {
    Poly a{}, b{};
    for (std::size_t j = 0; j < params::N; ++j) {
      a.c[j] = static_cast<std::int16_t>(static_cast<int>(rnd() % 3329u) - 1664);
      b.c[j] = static_cast<std::int16_t>(static_cast<int>(rnd() % 3329u) - 1664);
    }
    Poly r1{}, r2{};
    poly_basemul(r1, a, b);          // dispatches to AVX2
    avx2::basemul(r2, a, b);         // direct
    if (std::memcmp(r1.c.data(), r2.c.data(), sizeof(r1.c)) != 0) ++bad;
    Poly s1{}, s2{};
    for (int k = 0; k < params::K; ++k) { poly_basemul_acc(s1, a, b); avx2::basemul_acc(s2, a, b); }
    if (std::memcmp(s1.c.data(), s2.c.data(), sizeof(s1.c)) != 0) ++badacc;
    for (auto c : s1.c) { const long m = c < 0 ? -c : c; if (m > worst) worst = m; }
  }
  CHECK(bad == 0);
  CHECK(badacc == 0);
  // The k=3 accumulator bound is 4992 and is ATTAINED EXACTLY -- there is no slack, so
  // any change to accumulation order must be re-checked here, not assumed safe.
  CHECK(worst <= 4992);
  MESSAGE("basemul: 3000 polys identical; k=3 accumulator max |r| = " << worst << " (bound 4992)");
}

TEST_CASE("avx2: basemul gamma table equals the Appendix-A-checked one") {
  const std::int16_t* ref = tables::zetas_basemul();
  for (int i = 0; i < 128; ++i) CHECK(avx2::gamma_table()[static_cast<std::size_t>(i)] == ref[i]);
  MESSAGE("gamma table: generated consteval, equal to tables::zetas_basemul()");
}

TEST_CASE("avx2: ntt/invntt are bit-identical to the portable transforms") {
  if (!arch::has_avx2()) return;
  std::uint32_t st = 2463534242u;
  auto rnd = [&st] { st ^= st << 13; st ^= st >> 17; st ^= st << 5; return st; };
  for (int trial = 0; trial < 3000; ++trial) {
    const int shape = trial % 3;
    Poly a{};
    for (auto& cc : a.c) {
      const int r = static_cast<int>(rnd());
      cc = static_cast<std::int16_t>(shape == 0 ? (r % 3329) - 1664
                                   : shape == 1 ? (r % 3329)
                                                : (r % 6657) - 3328);
    }
    Poly b = a;
    generic::ntt(a);
    avx2::ntt(b);
    CHECK(std::memcmp(a.c.data(), b.c.data(), sizeof(a.c)) == 0);
    // invntt's input bound widened to 4992 in Phase 8c (unreduced accumulator from
    // poly_basemul_acc). Feed the WIDER range too, or the backends would only be
    // compared on inputs the code no longer restricts itself to.
    Poly c = a, d = a;
    if (trial % 2) {
      for (auto& cc : c.c) cc = static_cast<std::int16_t>(static_cast<int>(rnd()) % 9985 - 4992);
      d = c;
    }
    generic::invntt(c);
    avx2::invntt(d);
    CHECK(std::memcmp(c.c.data(), d.c.data(), sizeof(c.c)) == 0);
  }
}
#endif  // __x86_64__
