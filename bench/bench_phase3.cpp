// Phase 3 measurement: does hashing actually dominate the NTT?
//
// Spec §9.2 asserts that batched Keccak outranks NTT tuning because hashing dominates
// the cycle count, and therefore that it should be optimized FIRST in Phase 8. That
// ordering has so far been an assertion. This measures it.
//
// TSC CAVEAT (see `docs/reference/invariants.md`, Build environment). This host has an invariant TSC pinned to the 2.592 GHz base
// clock while cores boost to ~4.5 GHz, so __rdtsc() deltas are wall-time at a fixed rate,
// NOT core cycles. Absolute figures here are therefore NOT comparable to published
// cycle counts. The RATIO is scale-invariant and is what §9.2 is actually about, so the
// ratio is the result; the absolute numbers are context only.

#include "ntt.hpp"
#include "poly.hpp"
#include "symmetric.hpp"

extern "C" {
#include "fips202.h"
}

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <vector>

#if defined(__x86_64__)
#include <x86intrin.h>
static inline std::uint64_t ticks() { return __rdtsc(); }
#else
#include <chrono>
static inline std::uint64_t ticks() {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now().time_since_epoch()).count());
}
#endif

using namespace mlkem768;

namespace {

volatile std::uint8_t g_sink = 0;
void sink(const std::uint8_t* p, std::size_t n) {
  std::uint8_t a = 0;
  for (std::size_t i = 0; i < n; ++i) a = static_cast<std::uint8_t>(a ^ p[i]);
  g_sink = static_cast<std::uint8_t>(g_sink ^ a);
}

// Median of repeated runs. `docs/reference/invariants.md` requires medians AND spread, never best-of:
// thermal drift makes a lone number meaningless on this machine.
struct Stat { double median, p10, p90; };

template <typename F>
Stat measure(F&& f, int reps, int inner) {
  std::vector<double> samples;
  samples.reserve(static_cast<std::size_t>(reps));
  for (int r = 0; r < reps; ++r) {
    const std::uint64_t t0 = ticks();
    for (int i = 0; i < inner; ++i) f();
    const std::uint64_t t1 = ticks();
    samples.push_back(static_cast<double>(t1 - t0) / inner);
  }
  std::sort(samples.begin(), samples.end());
  return Stat{samples[samples.size() / 2],
              samples[samples.size() / 10],
              samples[(samples.size() * 9) / 10]};
}

void row(const char* name, const Stat& s) {
  std::printf("  %-44s %10.1f   %8.1f %8.1f\n", name, s.median, s.p10, s.p90);
}

}  // namespace

int main() {
  constexpr int kReps = 51;

  std::printf("Phase 3 measurement: hashing vs NTT (spec §9.2)\n");
  std::printf("TSC runs at a fixed 2.592 GHz here while cores boost to ~4.5 GHz, so these\n");
  std::printf("are TSC ticks, NOT core cycles. The RATIO is what matters and is scale-free.\n\n");
  std::printf("  %-44s %10s   %8s %8s\n", "operation", "median", "p10", "p90");
  std::printf("  %-44s %10s   %8s %8s\n",
              "--------------------------------------------", "----------", "--------", "--------");

  // --- primitives ---------------------------------------------------------
  keccak_state st{};
  std::array<std::uint8_t, 168 * 8> blocks{};
  shake128_absorb_once(&st, blocks.data(), 34);
  const Stat perm = measure([&] {
    // squeezeblocks performs exactly one Keccak-f[1600] permutation per block.
    shake128_squeezeblocks(blocks.data(), 8, &st);
    sink(blocks.data(), 8);
  }, kReps, 2000);
  const Stat perm1{perm.median / 8, perm.p10 / 8, perm.p90 / 8};
  row("Keccak-f[1600] permutation (1x)", perm1);

  Poly p{};
  for (std::size_t i = 0; i < params::N; ++i) p.c[i] = static_cast<std::int16_t>((i * 37) % 1665);
  const Stat ntt_s = measure([&] { Poly q = p; ntt(q); sink(reinterpret_cast<std::uint8_t*>(q.c.data()), 8); },
                             kReps, 2000);
  row("ntt()  (256-point, 7 layers)", ntt_s);

  const Stat inv_s = measure([&] { Poly q = p; invntt(q); sink(reinterpret_cast<std::uint8_t*>(q.c.data()), 8); },
                             kReps, 2000);
  row("invntt()", inv_s);

  Poly a = p, b = p, r{};
  const Stat bm_s = measure([&] { poly_basemul(r, a, b); sink(reinterpret_cast<std::uint8_t*>(r.c.data()), 8); },
                            kReps, 2000);
  row("poly_basemul()", bm_s);

  std::uint8_t seed32[32] = {};
  const Stat prf_s = measure([&] {
    std::array<std::uint8_t, 128> o{};
    PRF<2>(o, seed32, 0);
    sink(o.data(), 8);
  }, kReps, 2000);
  row("PRF<2>  (SHAKE256, 33 -> 128 bytes)", prf_s);

  std::uint8_t seed34[34] = {};
  const Stat xof_s = measure([&] {
    Xof x;
    xof_init_absorb(x, seed34);
    std::array<std::uint8_t, 504> o{};
    xof_squeeze(x, o.data(), o.size());
    sink(o.data(), 8);
  }, kReps, 500);
  row("XOF absorb+squeeze 504B (SampleNTT's draw)", xof_s);

  // --- aggregates: the work each ML-KEM-768 operation actually does -------
  //
  // Operation counts are taken from docs/algorithms/, not guessed:
  //
  //   KeyGen   hash  G(d||k) + 9 SampleNTT + 6 PRF
  //            arith 6 ntt + 9 basemul_acc + 3 to_mont   (NO invntt -- t_hat stays
  //                  in the NTT domain, Alg. 13 line 18)
  //   Encaps   hash  H(ek) + G(m||H(ek)) + 9 SampleNTT + 7 PRF
  //            arith 3 ntt + 12 basemul_acc + 4 invntt   (u is k polys, v is one)
  //   Decaps   hash  G(m'||h) + J(z||c) + 9 SampleNTT + 7 PRF   (re-encryption)
  //            arith decrypt (3 ntt + 3 acc + 1 invntt) + a full encrypt

  auto xof_draw = [&](int n) {
    for (int i = 0; i < n; ++i) {
      Xof x;
      xof_init_absorb(x, seed34);
      std::array<std::uint8_t, 504> o{};
      xof_squeeze(x, o.data(), o.size());
      sink(o.data(), 4);
    }
  };
  auto prf_draw = [&](int n) {
    for (int i = 0; i < n; ++i) {
      std::array<std::uint8_t, 128> o{};
      PRF<2>(o, seed32, static_cast<std::uint8_t>(i));
      sink(o.data(), 4);
    }
  };
  auto ntt_work = [&](int n) {
    for (int i = 0; i < n; ++i) { Poly q = p; ntt(q); sink(reinterpret_cast<std::uint8_t*>(q.c.data()), 4); }
  };
  auto invntt_work = [&](int n) {
    for (int i = 0; i < n; ++i) { Poly q = p; invntt(q); sink(reinterpret_cast<std::uint8_t*>(q.c.data()), 4); }
  };
  auto acc_work = [&](int n) {
    Poly acc{}; acc.c.fill(0);
    for (int i = 0; i < n; ++i) poly_basemul_acc(acc, a, b);
    sink(reinterpret_cast<std::uint8_t*>(acc.c.data()), 4);
  };

  std::array<std::uint8_t, 1184> ek{};
  std::array<std::uint8_t, 32 + 1088> zc{};

  const Stat keygen_hash = measure([&] {
    std::uint8_t gin[33] = {}, gout[64];
    G(gout, gin);
    xof_draw(9);
    prf_draw(6);
  }, kReps, 200);
  const Stat keygen_arith = measure([&] {
    ntt_work(6); acc_work(9);
    for (int i = 0; i < 3; ++i) { Poly q = p; poly_to_mont(q); sink(reinterpret_cast<std::uint8_t*>(q.c.data()), 4); }
  }, kReps, 200);

  const Stat encaps_hash = measure([&] {
    std::uint8_t h[32], gout[64];
    H(h, ek);
    std::array<std::uint8_t, 64> gin{};
    G(gout, gin);
    xof_draw(9);
    prf_draw(7);
  }, kReps, 200);
  // Same, but with A_hat CACHED (spec §9.2 item 6 -- explicitly permitted by FIPS 203
  // §3.3 since A is derived from the public ek). Removes all 9 SampleNTT streams.
  const Stat encaps_hash_cached = measure([&] {
    std::uint8_t h[32], gout[64];
    H(h, ek);
    std::array<std::uint8_t, 64> gin{};
    G(gout, gin);
    prf_draw(7);
  }, kReps, 200);
  const Stat encaps_arith = measure([&] {
    ntt_work(3); acc_work(12); invntt_work(4);
  }, kReps, 200);

  const Stat decaps_hash = measure([&] {
    std::uint8_t gout[64];
    std::array<std::uint8_t, 64> gin{};
    G(gout, gin);
    std::uint8_t k[32];
    J(k, zc);
    xof_draw(9);
    prf_draw(7);
  }, kReps, 200);
  const Stat decaps_arith = measure([&] {
    ntt_work(3); acc_work(3); invntt_work(1);     // decrypt
    ntt_work(3); acc_work(12); invntt_work(4);    // re-encrypt
  }, kReps, 200);

  std::printf("\n");
  row("KeyGen  hashing", keygen_hash);
  row("KeyGen  arithmetic", keygen_arith);
  row("Encaps  hashing (A re-expanded)", encaps_hash);
  row("Encaps  hashing (A CACHED)", encaps_hash_cached);
  row("Encaps  arithmetic", encaps_arith);
  row("Decaps  hashing", decaps_hash);
  row("Decaps  arithmetic", decaps_arith);

  // --- the verdict --------------------------------------------------------
  struct Case { const char* name; double hash, arith; };
  const Case cases[] = {
      {"KeyGen",                 keygen_hash.median,        keygen_arith.median},
      {"Encaps (A re-expanded)", encaps_hash.median,        encaps_arith.median},
      {"Encaps (A cached)",      encaps_hash_cached.median, encaps_arith.median},
      {"Decaps",                 decaps_hash.median,        decaps_arith.median},
  };

  std::printf("\n  %-24s %8s %8s %10s  %s\n", "operation", "hash%", "ratio",
              "4x-Keccak", "vs 3x-NTT");
  std::printf("  %-24s %8s %8s %10s  %s\n", "------------------------",
              "--------", "--------", "----------", "----------");
  for (const auto& c : cases) {
    const double total = c.hash + c.arith;
    const double frac = c.hash / total;
    // Amdahl: overall speedup from making the hashing 4x faster, vs the NTT 3x faster.
    const double keccak4 = 1.0 / ((1.0 - frac) + frac / 4.0);
    const double ntt3 = 1.0 / (frac + (1.0 - frac) / 3.0);
    std::printf("  %-24s %7.1f%% %7.2fx %9.2fx  %8.2fx  %s\n", c.name, 100 * frac,
                c.hash / c.arith, keccak4, ntt3,
                keccak4 > ntt3 ? "Keccak first" : "NTT first");
  }
  std::printf("\n  one Keccak permutation = %.2f ntt()\n", perm1.median / ntt_s.median);

  return 0;
}
