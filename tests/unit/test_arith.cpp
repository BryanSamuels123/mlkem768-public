// Phase 2 arithmetic tests: reduction primitives, zeta tables, NTT, basemul.
//
// The differential tests against tests/model/ are the ones with real power. The model is
// KAT-clean (ADR-002), so a disagreement here is equivalent to a KAT failure but
// localized to a single function.
//
// ITERATION COUNTS are configurable (see diff_iters below) because 80 ACVP vectors are a
// weak gate against rare-trigger bugs -- the M7 mutation was caught by only 7 of 25
// encaps vectors. See docs/bounds.md "Statistical power".

#include "doctest.h"

#include "ntt.hpp"
#include "params.hpp"
#include "poly.hpp"
#include "reduce.hpp"

#include "model.hpp"

#include <array>
#include <cstdint>
#include <cstdlib>
#include <random>
#include <vector>

using namespace mlkem768;
namespace M = mlkem768::model;

namespace {

// ---------------------------------------------------------------------------
// Configurable iteration counts.
//   make test        -> default 10^5
//   make test-deep   -> MLKEM_DIFF_ITERS=10000000
//
// Heavy tests (anything invoking the model's O(n^2) schoolbook) scale at base/100,
// because each iteration is ~100x the cost. At the deep setting that still yields 10^5
// schoolbook pairs, which is what spec §5.3 asks for.
// ---------------------------------------------------------------------------
int diff_iters() {
  static const int n = [] {
    const char* e = std::getenv("MLKEM_DIFF_ITERS");
    const int v = e ? std::atoi(e) : 100000;
    return v > 0 ? v : 100000;
  }();
  return n;
}
int diff_iters_heavy() {
  const int n = diff_iters() / 100;
  return n < 100 ? 100 : n;
}

std::mt19937_64 rng(0x6D6C6B656D323A32ULL);   // "mlkem2:2"

constexpr std::int32_t Q = params::Q;

// --- domain conversion at the test boundary -------------------------------
// The model is canonical [0, q). The implementation is centered [-(q-1)/2, (q-1)/2]
// and, depending on the function, carries a factor of R. These conversions come
// straight from ADR-004. THEY ARE NOT FUDGE FACTORS: if a differential test needed an
// unexplained constant to pass, the convention would be wrong.

Poly from_model(const M::Poly& m) {
  Poly p{};
  for (std::size_t i = 0; i < params::N; ++i) {
    std::int32_t v = m[i] % Q;
    if (v > Q / 2) v -= Q;                 // center, so |c| <= 1664 as ntt() requires
    p.c[i] = static_cast<std::int16_t>(v);
  }
  return p;
}

M::Poly to_model(const Poly& p) {
  M::Poly m{};
  for (std::size_t i = 0; i < params::N; ++i) {
    std::int32_t v = p.c[i] % Q;
    if (v < 0) v += Q;
    m[i] = v;
  }
  return m;
}

// Multiply a canonical model polynomial by R mod q. Used to move a model value into the
// domain the implementation produces (invntt) or to move an implementation value back
// (basemul). Only R mod q is ever needed -- never R^-1 -- so there is one constant.
M::Poly scale_by_R(const M::Poly& m) {
  M::Poly r{};
  for (std::size_t i = 0; i < params::N; ++i)
    r[i] = static_cast<std::int32_t>((static_cast<std::int64_t>(m[i]) * R_MOD_Q) % Q);
  return r;
}

M::Poly random_model_poly() {
  M::Poly p{};
  for (auto& c : p) c = static_cast<std::int32_t>(rng() % static_cast<std::uint64_t>(Q));
  return p;
}

}  // namespace

// ===========================================================================
// Reduction primitives
// ===========================================================================

TEST_CASE("barrett_reduce is exhaustively correct over all 65536 int16_t inputs") {
  // Spec §5.2: "This test runs in microseconds -- there is no excuse for not doing it."
  int worst = 0;
  for (std::int32_t a = -32768; a <= 32767; ++a) {
    const std::int16_t t = barrett_reduce(static_cast<std::int16_t>(a));
    REQUIRE(((t - a) % Q) == 0);                       // congruent mod q
    REQUIRE(t >= -1664);
    REQUIRE(t <= 1664);
    const int m = t < 0 ? -t : t;
    if (m > worst) worst = m;
  }
  MESSAGE("barrett_reduce observed max |t| = " << worst << " (claimed bound 1664)");
  CHECK(worst == 1664);     // the bound is tight, not merely satisfied
}

TEST_CASE("csubq is exhaustively correct over [0, 2q)") {
  for (std::int32_t a = 0; a < 2 * Q; ++a) {
    const std::int16_t t = csubq(static_cast<std::int16_t>(a));
    REQUIRE(t >= 0);
    REQUIRE(t < Q);
    REQUIRE(((t - a) % Q) == 0);
  }
}

TEST_CASE("to_canonical maps a centered representative into [0, q)") {
  for (std::int32_t a = -(Q - 1); a < Q; ++a) {
    const std::int16_t t = to_canonical(static_cast<std::int16_t>(a));
    REQUIRE(t >= 0);
    REQUIRE(t < Q);
    REQUIRE(((t - a) % Q) == 0);
  }
}

TEST_CASE("montgomery_reduce is EXHAUSTIVELY correct over its entire legal range") {
  // Not sampled. The whole input range is only 2*q*2^15+1 = 218,169,345 values and
  // sweeps in well under a second, so this is a proof rather than evidence.
  //
  // Spec §5.2 asks for "random-sample 10^7 values". Exhaustive is strictly better and
  // is what found the off-by-one in the spec's own stated bound (see reduce.hpp).
  constexpr std::int64_t kLimit = static_cast<std::int64_t>(Q) * 32768;   // q * 2^15

  int worst = 0;
  std::int64_t worst_at = 0;
  for (std::int64_t a = -kLimit + 1; a <= kLimit - 1; ++a) {   // STRICT bound
    const std::int16_t t = montgomery_reduce(static_cast<std::int32_t>(a));
    // t == a*R^-1 (mod q)  <=>  t*R == a (mod q). No need for R^-1.
    if (((static_cast<std::int64_t>(t) * 65536 - a) % Q) != 0) {
      REQUIRE_MESSAGE(false, "congruence failed at a = " << a);
    }
    const int m = t < 0 ? -t : t;
    if (m > worst) { worst = m; worst_at = a; }
  }
  MESSAGE("montgomery_reduce exhaustive over " << (2 * kLimit - 1)
          << " inputs: max |t| = " << worst << " at a = " << worst_at
          << " (claimed bound < " << Q << ", margin " << (Q - worst) << ")");
  CHECK(worst == Q - 1);      // tight: the bound is achieved but never exceeded
}

TEST_CASE("montgomery_reduce: the one input OUTSIDE the contract, documented") {
  // a = +q*2^15 is excluded by the strict input bound precisely because it yields
  // exactly q. Pinned here so the exclusion is a recorded fact, not folklore, and so
  // that a future change to the reduction is forced to confront it.
  constexpr std::int32_t kOut = static_cast<std::int32_t>(Q) * 32768;
  CHECK(montgomery_reduce(kOut) == Q);          // == q, NOT < q
  CHECK(montgomery_reduce(-kOut) == 0);         // the negative extreme is fine
}

// ===========================================================================
// Zeta tables vs FIPS 203 Appendix A
// ===========================================================================

TEST_CASE("zeta tables match FIPS 203 Appendix A") {
  // Phase 0 verified both tables computationally, once. This wires that check in so it
  // re-runs on every build rather than living only in a commit message.
  //
  // The published values are plain Z_q. The implementation stores them pre-multiplied
  // by R and centered, so the Montgomery factor is undone before comparing.
  static const std::int32_t kAppendixA_table1[128] = {
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

  // R^-1 mod q, derived here by Fermat so the test does not depend on a constant the
  // implementation also derives (an independent path to the same conversion).
  std::int64_t r_inv = 1, base = R_MOD_Q;
  for (std::int32_t e = Q - 2; e > 0; e >>= 1) {
    if (e & 1) r_inv = r_inv * base % Q;
    base = base * base % Q;
  }
  REQUIRE((r_inv * R_MOD_Q) % Q == 1);

  const std::int16_t* z = tables::zetas();
  for (int i = 0; i < 128; ++i) {
    std::int64_t v = z[i] % Q;
    if (v < 0) v += Q;
    const std::int64_t plain = (v * r_inv) % Q;        // undo the Montgomery factor
    REQUIRE(plain == kAppendixA_table1[i]);
  }

  // Table 2 is a DIFFERENT table: zeta^(2*BitRev7(i)+1). Its defining property is
  // checked against table 1 rather than transcribing 128 more numbers: entry i must be
  // zeta * (table1 entry)^2, since 2*BitRev7(i)+1 = 2*BitRev7(i) + 1.
  const std::int16_t* g = tables::zetas_basemul();
  for (int i = 0; i < 128; ++i) {
    std::int64_t v = g[i] % Q;
    if (v < 0) v += Q;
    const std::int64_t plain = (v * r_inv) % Q;
    const std::int64_t t1 = kAppendixA_table1[i];
    const std::int64_t expect = (t1 * t1 % Q) * params::ZETA % Q;
    REQUIRE(plain == expect);
  }

  // Sign alternation in pairs, the property Phase 8 will exploit to halve the table.
  for (int i = 1; i < 128; i += 2)
    REQUIRE(((g[i - 1] + g[i]) % Q) == 0);
}

TEST_CASE("derived constants satisfy their defining identities") {
  CHECK(static_cast<std::uint16_t>(QINV * static_cast<std::uint16_t>(params::Q)) == 1u);
  CHECK(R_MOD_Q == 65536 % Q);
  CHECK(R2_MOD_Q == static_cast<std::int32_t>((65536LL * 65536LL) % Q));
  CHECK((static_cast<std::int64_t>(INV_128) * 128) % Q == 1);
}

// ===========================================================================
// NTT — differential against the KAT-clean model
// ===========================================================================

TEST_CASE("ntt agrees with the model coefficient for coefficient") {
  const int n = diff_iters();
  for (int i = 0; i < n; ++i) {
    const M::Poly f = random_model_poly();
    Poly impl = from_model(f);
    ntt(impl);
    REQUIRE(to_model(impl) == M::ntt(f));      // both normal domain: no conversion
  }
  MESSAGE("ntt differential: " << n << " iterations");
}

TEST_CASE("invntt agrees with the model, up to the documented factor of R") {
  // ADR-004: invntt(x) == true_inverse(x) * R. The factor is the convention, derived
  // from R_MOD_Q, not a constant found by trial and error.
  const int n = diff_iters();
  for (int i = 0; i < n; ++i) {
    const M::Poly f = random_model_poly();
    Poly impl = from_model(f);
    invntt(impl);
    REQUIRE(to_model(impl) == scale_by_R(M::inv_ntt(f)));
  }
  MESSAGE("invntt differential: " << n << " iterations");
}

TEST_CASE("poly_basemul agrees with the model, up to the documented factor of R^-1") {
  const int n = diff_iters();
  for (int i = 0; i < n; ++i) {
    const M::Poly a = random_model_poly();
    const M::Poly b = random_model_poly();
    Poly r{};
    poly_basemul(r, from_model(a), from_model(b));
    // impl == a*b*R^-1, so impl*R == a*b == model.
    REQUIRE(scale_by_R(to_model(r)) == M::multiply_ntts(a, b));
  }
  MESSAGE("poly_basemul differential: " << n << " iterations");
}

TEST_CASE("basemul single coordinate agrees with the model") {
  const int n = diff_iters();
  const std::int16_t* g = tables::zetas_basemul();
  for (int i = 0; i < n; ++i) {
    const M::Poly a = random_model_poly();
    const M::Poly b = random_model_poly();
    const Poly ia = from_model(a), ib = from_model(b);
    const M::Poly want = M::multiply_ntts(a, b);
    const auto idx = static_cast<std::size_t>(rng() % 128);   // one random coordinate
    std::int16_t r[2];
    basemul(r, &ia.c[2 * idx], &ib.c[2 * idx], g[idx]);
    for (int j = 0; j < 2; ++j) {
      std::int32_t got = r[j] % Q;
      if (got < 0) got += Q;
      const std::int64_t got_scaled = (static_cast<std::int64_t>(got) * R_MOD_Q) % Q;
      REQUIRE(got_scaled == want[2 * idx + static_cast<std::size_t>(j)]);
    }
  }
  MESSAGE("basemul differential: " << n << " iterations");
}

TEST_CASE("poly_basemul_acc accumulates correctly over k terms") {
  const int n = diff_iters() / 10 < 100 ? 100 : diff_iters() / 10;
  for (int i = 0; i < n; ++i) {
    std::array<M::Poly, params::K> a{}, b{};
    for (int j = 0; j < params::K; ++j) { a[static_cast<std::size_t>(j)] = random_model_poly();
                                          b[static_cast<std::size_t>(j)] = random_model_poly(); }
    Poly acc{};
    acc.c.fill(0);
    for (int j = 0; j < params::K; ++j)
      poly_basemul_acc(acc, from_model(a[static_cast<std::size_t>(j)]),
                            from_model(b[static_cast<std::size_t>(j)]));

    M::Poly want{};
    for (int j = 0; j < params::K; ++j) {
      const M::Poly t = M::multiply_ntts(a[static_cast<std::size_t>(j)], b[static_cast<std::size_t>(j)]);
      for (std::size_t c = 0; c < params::N; ++c) want[c] = (want[c] + t[c]) % Q;
    }
    REQUIRE(scale_by_R(to_model(acc)) == want);
  }
  MESSAGE("poly_basemul_acc differential: " << n << " iterations");
}

// ===========================================================================
// The composition tests
// ===========================================================================

TEST_CASE("roundtrip: invntt(ntt(f)) == f * R") {
  // NOT f. The factor of R is what makes basemul's R^-1 cancel in the composition
  // below, and it is the single most important line of ADR-004 to internalize.
  const int n = diff_iters();
  for (int i = 0; i < n; ++i) {
    const M::Poly f = random_model_poly();
    Poly p = from_model(f);
    ntt(p);
    invntt(p);
    REQUIRE(to_model(p) == scale_by_R(f));
  }
  MESSAGE("ntt/invntt roundtrip: " << n << " iterations");
}

TEST_CASE("schoolbook differential -- the critical NTT test (spec §5.3 test 2)") {
  // invntt(poly_basemul(ntt(a), ntt(b))) == schoolbook_negacyclic(a, b), with NO
  // scaling: basemul's R^-1 and invntt's R cancel exactly. If this needed a correction
  // factor, the Montgomery convention would be wrong.
  //
  // Catches wrong zetas, wrong layer count, wrong bit-reversal, wrong Montgomery
  // domain, and wrong gamma signs in one shot.
  const int n = diff_iters_heavy();
  for (int i = 0; i < n; ++i) {
    const M::Poly a = random_model_poly();
    const M::Poly b = random_model_poly();

    Poly ia = from_model(a), ib = from_model(b);
    ntt(ia);
    ntt(ib);
    Poly r{};
    poly_basemul(r, ia, ib);
    invntt(r);

    REQUIRE(to_model(r) == M::schoolbook_negacyclic(a, b));
  }
  MESSAGE("schoolbook differential: " << n << " iterations (heavy: base/100)");
}

TEST_CASE("ntt is linear") {
  const int n = diff_iters() / 10 < 100 ? 100 : diff_iters() / 10;
  for (int i = 0; i < n; ++i) {
    const M::Poly a = random_model_poly(), b = random_model_poly();
    M::Poly sum{};
    for (std::size_t c = 0; c < params::N; ++c) sum[c] = (a[c] + b[c]) % Q;

    Poly ia = from_model(a), ib = from_model(b), is = from_model(sum);
    ntt(ia); ntt(ib); ntt(is);

    const M::Poly ma = to_model(ia), mb = to_model(ib), ms = to_model(is);
    for (std::size_t c = 0; c < params::N; ++c) REQUIRE(ms[c] == (ma[c] + mb[c]) % Q);
  }
}

TEST_CASE("poly_to_mont undoes the R^-1 that poly_basemul introduces") {
  // This is the composition K-PKE.KeyGen needs: t_hat = A o s_hat + e_hat, computed
  // entirely in the NTT domain with no inverse transform.
  const int n = diff_iters() / 10 < 100 ? 100 : diff_iters() / 10;
  for (int i = 0; i < n; ++i) {
    const M::Poly a = random_model_poly(), b = random_model_poly();
    Poly r{};
    poly_basemul(r, from_model(a), from_model(b));
    poly_to_mont(r);
    REQUIRE(to_model(r) == M::multiply_ntts(a, b));   // exact, no scaling
  }
}

TEST_CASE("poly_canonicalize produces [0, q)") {
  for (int i = 0; i < 1000; ++i) {
    Poly p{};
    for (auto& c : p.c) c = static_cast<std::int16_t>(rng());
    poly_canonicalize(p);
    for (const auto c : p.c) { REQUIRE(c >= 0); REQUIRE(c < Q); }
  }
}

// ===========================================================================
// Phase 8c precondition: what "equivalent" means once reductions go lazy
// ===========================================================================
//
// Lazy reduction changes WHICH REPRESENTATIVE of a coefficient exists at intermediate
// steps -- the value mod q is unchanged, the int16_t holding it is not. Before any
// reduction is removed, the project needs a written and CHECKED answer to "equivalent
// to what?". The contract (docs/bounds.md, "Equivalence under lazy reduction") is:
//
//   1. Intermediate coefficients may take ANY int16_t representative of the correct
//      residue class mod q. They are NOT required to be canonical or centered.
//   2. The two backends must remain BIT-IDENTICAL to each other, because a lazy change
//      lands in both in the same commit. That gate does not weaken.
//   3. At every serialization boundary the value must be canonical [0, q) and the bytes
//      must be identical to the model's. That gate does not weaken either.
//
// (3) rests entirely on one property: poly_canonicalize must map ANY int16_t to the
// correct canonical residue -- not merely inputs already within some bound. If that is
// false for even one value, lazy reduction corrupts ciphertexts at the boundary while
// every intermediate check still passes.
//
// Phase 2's lesson applies directly: montgomery_reduce's contract was off by one at
// exactly one input out of 218 million, and only exhaustive evaluation found it. The
// input domain here is int16_t, so exhaustive is cheap. There is no excuse for sampling.

TEST_CASE("Phase 8c precondition: barrett_reduce is total and correct over ALL int16_t") {
  // Correct residue for every possible input, not just in-bound ones.
  int worst = 0;
  for (std::int32_t v = -32768; v <= 32767; ++v) {
    const auto a = static_cast<std::int16_t>(v);
    const std::int16_t t = barrett_reduce(a);
    // same residue class
    REQUIRE(((static_cast<std::int32_t>(t) - v) % Q) == 0);
    // and within the claimed bound
    REQUIRE(t >= -1664);
    REQUIRE(t <= 1664);
    const int m = t < 0 ? -t : t;
    if (m > worst) worst = m;
  }
  CHECK(worst == 1664);
  MESSAGE("barrett_reduce: exhaustive over all 65536 int16_t, residue-correct, max |t| = " << worst);
}

TEST_CASE("Phase 8c precondition: poly_canonicalize maps ANY int16_t into [0, q) correctly") {
  // This is the property the whole phase rests on: the serialization boundary must be
  // safe for an ARBITRARY representative, because that is what a lazy intermediate is.
  for (std::int32_t base = -32768; base <= 32767; base += 256) {
    Poly p{};
    for (std::size_t i = 0; i < params::N; ++i) {
      const std::int32_t v = base + static_cast<std::int32_t>(i);
      p.c[i] = static_cast<std::int16_t>(v > 32767 ? v - 65536 : v);
    }
    Poly q = p;
    poly_canonicalize(q);
    for (std::size_t i = 0; i < params::N; ++i) {
      REQUIRE(q.c[i] >= 0);
      REQUIRE(q.c[i] < Q);
      REQUIRE(((static_cast<std::int32_t>(q.c[i]) - p.c[i]) % Q) == 0);
    }
  }
  MESSAGE("poly_canonicalize: every int16_t value covered, all map into [0,q) with the right residue");
}
