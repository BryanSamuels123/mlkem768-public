// Produces the "observed maximum" column of docs/bounds.md.
//
// Build with -DMLKEM_TRACK_BOUNDS (make bounds). Drives every arithmetic entry point
// over random inputs AND over adversarially extreme inputs, then reports the running
// maximum at each instrumented site alongside the claimed bound and the margin.
//
// This MEASURES; it does not PROVE. Random testing establishes a lower bound on the
// worst case, never the worst case. Where the margin is thin, docs/bounds.md must carry
// an argument from the algorithm as well.

#include "bounds_track.hpp"
#include "kpke.hpp"
#include "ntt.hpp"
#include "params.hpp"
#include "poly.hpp"
#include "reduce.hpp"

#include <cstdio>
#include <cstdlib>
#include <random>

using namespace mlkem768;

namespace {

std::mt19937_64 rng(0xB0ADDECAFULL);

// Keeps the optimizer from deleting the calls under measurement.
volatile std::int16_t g_sink = 0;
void sink(const Poly& p) {
  std::int16_t a = 0;
  for (const auto c : p.c) a = static_cast<std::int16_t>(a ^ c);
  g_sink = static_cast<std::int16_t>(g_sink ^ a);
}

Poly random_poly() {
  Poly p{};
  for (auto& c : p.c) {
    std::int32_t v = static_cast<std::int32_t>(rng() % static_cast<std::uint64_t>(params::Q));
    if (v > params::Q / 2) v -= params::Q;
    p.c[static_cast<std::size_t>(&c - p.c.data())] = static_cast<std::int16_t>(v);
  }
  return p;
}

// Every coefficient pinned to +-1664, the extreme the Phase 2 invariant permits.
Poly extreme_poly(bool positive) {
  Poly p{};
  const auto v = static_cast<std::int16_t>(positive ? 1664 : -1664);
  p.c.fill(v);
  return p;
}

// The path Phase 6 actually takes for the matrix-vector product: A_hat comes straight
// out of sample_ntt in CANONICAL [0, q) and goes into basemul WITHOUT an ntt() -- it is
// already in the NTT domain. So basemul must tolerate one operand up to q-1 = 3328,
// not the +-1664 the barrett invariant provides. Measured directly here.
void exercise_matrix_path(const Poly& a_hat_canonical, const Poly& s_hat_reduced) {
  Poly r{};
  poly_basemul(r, a_hat_canonical, s_hat_reduced);
  Poly acc{};
  acc.c.fill(0);
  for (int k = 0; k < params::K; ++k) poly_basemul_acc(acc, a_hat_canonical, s_hat_reduced);
  sink(acc);
  sink(r);
}

// A polynomial in the CANONICAL range [0, q), which is what sample_ntt produces for
// A_hat. Up to 3328 -- double the +-1664 the barrett-reduced invariant gives -- so the
// basemul bounds must cover it. Phase 5 added this case.
Poly canonical_extreme_poly() {
  Poly p{};
  for (std::size_t i = 0; i < params::N; ++i)
    p.c[i] = static_cast<std::int16_t>((i % 2) ? params::Q - 1 : 0);
  return p;
}

// Alternating extremes, which maximizes |f[j] - t| style differences.
Poly alternating_poly() {
  Poly p{};
  for (std::size_t i = 0; i < params::N; ++i)
    p.c[i] = static_cast<std::int16_t>((i % 2) ? 1664 : -1664);
  return p;
}

void exercise(Poly a, Poly b) {
  Poly x = a;
  ntt(x);
  Poly y = b;
  ntt(y);

  Poly r{};
  poly_basemul(r, x, y);

  Poly acc{};
  acc.c.fill(0);
  for (int k = 0; k < params::K; ++k) poly_basemul_acc(acc, x, y);

  Poly m = r;
  poly_to_mont(m);

  Poly inv = r;
  invntt(inv);
}

}  // namespace

// THE REAL CALL SHAPES. Everything above is a synthetic approximation; this drives the
// actual K-PKE algorithms, which is the only way to measure poly_basemul_acc
// accumulating k = 3 terms with A_hat canonical from sample_ntt.
//
// This exists because basemul's input bound was WRONG FOR THREE PHASES: the synthetic
// harness ran ntt() on its inputs first, barrett-reducing them to +-1664 before basemul
// ever saw a canonical A_hat. A measurement harness that does not reproduce the real
// call shape measures the wrong thing.
void exercise_kpke_real_path(std::uint64_t seed) {
  std::uint8_t d[32], m[32], r[32];
  for (int i = 0; i < 32; ++i) {
    d[i] = static_cast<std::uint8_t>(seed >> (i % 8 * 8)) ^ static_cast<std::uint8_t>(i);
    m[i] = static_cast<std::uint8_t>(seed >> ((i + 3) % 8 * 8)) ^ static_cast<std::uint8_t>(i * 7);
    r[i] = static_cast<std::uint8_t>(seed >> ((i + 5) % 8 * 8)) ^ static_cast<std::uint8_t>(i * 13);
  }

  std::array<std::uint8_t, params::EK_PKE_BYTES> ek{};
  std::array<std::uint8_t, params::DK_PKE_BYTES> dk{};
  kpke_keygen(ek.data(), dk.data(), d);          // A_hat o s_hat, k=3 accumulation

  std::array<std::uint8_t, params::CT_BYTES> c{};
  kpke_encrypt(c.data(), ek.data(), m, r);       // A_hat^T o y_hat, k=3 accumulation

  std::uint8_t out[32];
  kpke_decrypt(out, dk.data(), c.data());        // s_hat^T o NTT(u'), k=3 accumulation

  std::uint8_t acc = 0;
  for (int i = 0; i < 32; ++i) acc = static_cast<std::uint8_t>(acc ^ out[i]);
  g_sink = static_cast<std::int16_t>(g_sink ^ acc);
}

int main(int argc, char** argv) {
  const long iters = (argc > 1) ? std::atol(argv[1]) : 20000;

#ifndef MLKEM_TRACK_BOUNDS
  std::printf("ERROR: built without -DMLKEM_TRACK_BOUNDS; nothing to measure.\n"
              "       Use: make bounds\n");
  return 2;
#else
  bounds::reset();

  // Adversarial corners first, so they are never lost in the noise.
  exercise(extreme_poly(true), extreme_poly(true));
  exercise(extreme_poly(false), extreme_poly(false));
  exercise(extreme_poly(true), extreme_poly(false));
  exercise(alternating_poly(), alternating_poly());
  exercise(alternating_poly(), extreme_poly(true));
  // A_hat from sample_ntt is canonical [0, q), NOT centered. basemul must tolerate it.
  exercise(canonical_extreme_poly(), canonical_extreme_poly());
  exercise(canonical_extreme_poly(), extreme_poly(true));

  // The real Phase 6 shape: canonical A_hat x barrett-reduced s_hat, straight into
  // basemul with no intervening ntt().
  {
    Poly s = extreme_poly(true);
    ntt(s);                                     // s_hat: |c| <= 1664
    exercise_matrix_path(canonical_extreme_poly(), s);
    Poly s2 = alternating_poly();
    ntt(s2);
    exercise_matrix_path(canonical_extreme_poly(), s2);
    // Worst case: both operands canonical-extreme (not a real shape, but an upper bound)
    exercise_matrix_path(canonical_extreme_poly(), canonical_extreme_poly());
  }

  for (long i = 0; i < iters; ++i) exercise(random_poly(), random_poly());

  // The real K-PKE path. Fewer iterations -- each is a full keygen+encrypt+decrypt with
  // 18 SampleNTT streams -- but these are the only measurements that reflect the
  // accumulation shape the algorithms actually use.
  const long kpke_iters = (iters / 100) < 20 ? 20 : (iters / 100);
  for (long i = 0; i < kpke_iters; ++i)
    exercise_kpke_real_path(static_cast<std::uint64_t>(i) * 0x9E3779B97F4A7C15ULL + 1);
  std::printf("real K-PKE path: %ld full keygen+encrypt+decrypt cycles\n", kpke_iters);

  std::printf("bounds measurement: %ld random iterations + 5 adversarial corners\n", iters);
  std::printf("(Phase 2 invariant: every coefficient |c| <= 1664 at every layer boundary)\n\n");
  std::printf("%-42s %12s %14s %10s\n", "site", "observed", "claimed", "margin");
  std::printf("%-42s %12s %14s %10s\n", "------------------------------------------",
              "------------", "--------------", "----------");

  int over = 0;
  for (int s = 0; s < bounds::kSiteCount; ++s) {
    const auto site = static_cast<bounds::Site>(s);
    const long long obs = bounds::observed[static_cast<std::size_t>(s)];
    const long long lim = bounds::limit(site);
    const double pct = lim ? (100.0 * static_cast<double>(obs) / static_cast<double>(lim)) : 0.0;
    std::printf("%-42s %12lld %14lld %9.2f%%\n", bounds::name(site), obs, lim, pct);
    if (obs > lim) ++over;
  }
  std::printf("\n%s\n", over ? "*** BOUND EXCEEDED ***" : "all sites within their claimed bounds");
  return over ? 1 : 0;
#endif
}
