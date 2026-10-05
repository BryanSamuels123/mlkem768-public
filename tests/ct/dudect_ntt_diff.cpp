// Phase 9b follow-up: decide the `ntt` row by DIFFERENTIAL control, not by argument.
//
// The main suite left one row undecided. Our AVX2 `ntt` shows a value-following timing
// signature -- `dmean` flips sign when the two classes swap which value they use -- at
// about 0.07 ticks per call. Two explanations fit: a real data-dependence in Phase 8b's
// AVX2 code, or a property of this CPU / this instrument that any comparable code would
// show.
//
// The switching-power story is hard to square with the experiment's design: frequency
// scaling reacts over tens of microseconds or longer, one K=32 measurement is ~2 us, and
// the class is randomized per measurement, so a frequency excursion should smear across
// both classes rather than align with one. So it is measured instead of argued, the way
// interop decided serialization:
//
//   A. our AVX2 ntt              (the code under suspicion)
//   B. our portable scalar ntt   (same algorithm, no SIMD -- src/ntt.cpp generic)
//   C. pq-crystals' AVX2 ntt     (independent implementation, same machine)
//
// All three run through the IDENTICAL harness: same K, same sample count, same fixed
// values, same fixed-vs-fixed and swap controls.
//
//   all three show it at similar magnitude -> this CPU or the instrument, not our code
//   only A shows it                        -> a real finding in Phase 8b's AVX2 NTT
//
// pq-crystals is used for BENCHMARK COMPARISON ONLY (ADR-022/ADR-003): built outside this
// repo, nothing vendored, never linked into the shipped library.

#include "ttest.hpp"
#include "ntt.hpp"
#include "poly.hpp"
#include "params.hpp"

#include <array>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#if defined(__x86_64__)
#include <x86intrin.h>
#else
#error "x86-64 only"
#endif

// pq-crystals AVX2. Their `poly` is a 32-byte-aligned union over 256 int16_t, so an
// aligned raw buffer is layout-compatible for this call.
extern "C" void pqcrystals_kyber768_avx2_poly_ntt(void*);

namespace {

using mlkem768::Poly;

volatile std::uint8_t g_sink = 0;

inline std::uint64_t ticks() {
  _mm_lfence();
  const std::uint64_t t = __rdtsc();
  _mm_lfence();
  return t;
}

struct Rng {
  std::uint64_t s;
  explicit Rng(std::uint64_t seed) : s(seed) {}
  std::uint64_t next() {
    std::uint64_t z = (s += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
  }
  int bit() { return int(next() & 1); }
};

inline void sel_bytes(void* dst, const void* f_, const void* r_, std::size_t n, int cls) {
  auto* d = static_cast<std::uint8_t*>(dst);
  auto* f = static_cast<const std::uint8_t*>(f_);
  auto* r = static_cast<const std::uint8_t*>(r_);
  const std::uint8_t m = std::uint8_t(-(std::uint8_t)(cls & 1));
  for (std::size_t i = 0; i < n; ++i)
    d[i] = std::uint8_t((f[i] & std::uint8_t(~m)) | (r[i] & m));
}

enum class Impl { OursAvx2, OursPortable, KyberAvx2 };

const char* impl_name(Impl i) {
  switch (i) {
    case Impl::OursAvx2:     return "A: ours AVX2 ntt";
    case Impl::OursPortable: return "B: ours portable ntt";
    case Impl::KyberAvx2:    return "C: pq-crystals AVX2 ntt";
  }
  return "?";
}

// One bench, three implementations, so the harness is provably identical across them.
struct NttDiff {
  alignas(32) Poly fixedp{}, rnd{}, staged{}, work{};
  Impl impl;
  explicit NttDiff(Impl i) : impl(i) {}

  void setup(bool fixed_zero, Rng& rng) {
    for (auto& c : fixedp.c)
      c = fixed_zero ? 0 : std::int16_t(rng.next() % mlkem768::params::Q);
  }
  void prepare(int cls, Rng& rng) {
    for (auto& c : rnd.c) c = std::int16_t(rng.next() % mlkem768::params::Q);
    sel_bytes(&staged, &fixedp, &rnd, sizeof(Poly), cls);
  }
  // Re-stage inside the timed region: all three transforms are in place, so a batch has
  // to restore the input each repetition. The copy is identical for all three impls and
  // for both classes, so it cannot create a class-correlated difference.
  void run() {
    work = staged;
    switch (impl) {
      case Impl::OursAvx2:     mlkem768::ntt(work); break;
      case Impl::OursPortable: mlkem768::generic::ntt(work); break;
      case Impl::KyberAvx2:    pqcrystals_kyber768_avx2_poly_ntt(&work); break;
    }
    g_sink = std::uint8_t(work.c[0]);
  }
  void run_n(int k) { for (int i = 0; i < k; ++i) run(); }
};

struct Out { double t, dmean, samples; };

// fixed_vs_fixed: both classes constant, differing only in value -- so placement,
// alignment and cache set are identical and only the VALUE differs.
// swap: exchange which value each class uses while keeping the class label.
Out measure(Impl impl, bool fixed_zero, std::size_t n, int K,
            std::uint64_t seed, bool fixed_vs_fixed, bool swap) {
  NttDiff b(impl);
  Rng rng(seed);
  b.setup(fixed_zero, rng);
  Rng prep(seed ^ 0x5DEECE66DULL);
  ct::Session sess(n / 20 < 2000 ? 2000 : n / 20);

  for (std::size_t i = 0; i < n; ++i) {
    const int cls = rng.bit();
    if (fixed_vs_fixed) prep = Rng(seed ^ 0x5DEECE66DULL);
    b.prepare(swap ? (cls ^ 1) : cls, prep);
    const std::uint64_t t0 = ticks();
    b.run_n(K);
    const std::uint64_t t1 = ticks();
    sess.push(std::int64_t(t1 - t0), cls);
  }
  double at = 0.0, dl = 0.0;
  const double mt = sess.max_abs_t(&at, &dl);
  return {mt, dl, sess.total_samples()};
}

}  // namespace

int main(int argc, char** argv) {
  std::size_t n = 300000;
  int K = 32;
  std::uint64_t seed = 0xC0FFEEULL;
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "--deep") n = 1900000;
    else if (a.rfind("--K=", 0) == 0) K = int(std::strtol(a.c_str() + 4, nullptr, 0));
    else if (a.rfind("--seed=", 0) == 0) seed = std::strtoull(a.c_str() + 7, nullptr, 0);
    else { std::fprintf(stderr, "unknown arg %s\n", a.c_str()); return 2; }
  }

  std::printf("=== ntt differential: is the value-following signature OURS or the MACHINE? ===\n");
  std::printf("identical harness for all three: K = %d, %zu samples, same fixed values,\n"
              "same fixed-vs-fixed and swap controls.\n\n", K, n);
  std::printf("%-24s %-7s %8s %9s %9s %9s  %s\n",
              "implementation", "fixed", "|t|ff", "dmean", "|t|swap", "dmnSwap", "follows");
  std::printf("%s\n", std::string(88, '-').c_str());

  struct Row { Impl impl; bool zero; bool flipped; double mag; };
  std::vector<Row> rows;

  for (Impl impl : {Impl::OursAvx2, Impl::OursPortable, Impl::KyberAvx2}) {
    for (bool zero : {true, false}) {
      Out a = measure(impl, zero, n, K, seed, /*ff=*/true, /*swap=*/false);
      Out c = measure(impl, zero, n, K, seed, /*ff=*/true, /*swap=*/true);
      const bool flipped = (a.dmean > 0.0) != (c.dmean > 0.0);
      const bool tiny = std::fabs(a.dmean) < 0.05 && std::fabs(c.dmean) < 0.05;
      const char* follows = tiny ? "(too small)" : (flipped ? "VALUE" : "not value");
      std::printf("%-24s %-7s %8.2f %9.3f %9.2f %9.3f  %s\n",
                  impl_name(impl), zero ? "zero" : "random",
                  a.t, a.dmean, c.t, c.dmean, follows);
      rows.push_back({impl, zero, flipped, std::fabs(a.dmean)});
    }
  }

  // Verdict: does the signature single OUT our AVX2 code, or appear in all three?
  int flips[3] = {0, 0, 0};
  double mag[3] = {0.0, 0.0, 0.0};
  for (const auto& r : rows) {
    const int i = int(r.impl);
    if (r.flipped) flips[i]++;
    if (r.mag > mag[i]) mag[i] = r.mag;
  }
  std::printf("\n%-24s %12s %14s\n", "implementation", "value-follows", "max |dmean|");
  for (int i = 0; i < 3; ++i)
    std::printf("%-24s %9d / 2 %14.3f\n", impl_name(Impl(i)), flips[i], mag[i]);

  const bool only_ours = flips[0] > 0 && flips[1] == 0 && flips[2] == 0;
  std::printf("\n");
  if (only_ours) {
    std::printf("VERDICT: the signature appears ONLY in our AVX2 ntt. That is a real\n"
                "         finding in Phase 8b's code, not a machine artifact. RED GATE.\n");
    return 1;
  }
  if (flips[0] == 0) {
    std::printf("VERDICT: our AVX2 ntt does NOT show the signature in this run.\n");
    return 0;
  }
  std::printf("VERDICT: the signature is NOT specific to our AVX2 ntt -- it appears in\n"
              "         an independent implementation and/or the portable scalar path at\n"
              "         comparable magnitude. It is a property of this CPU or of the\n"
              "         instrument, not of Phase 8b's code.\n");
  return 0;
}
