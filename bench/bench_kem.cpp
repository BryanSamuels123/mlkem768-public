// End-to-end ML-KEM-768 benchmark: KeyGen / Encaps / Decaps, whole operations.
//
// bench_phase3.cpp measures COMPONENTS (one permutation, one ntt) to decide what to
// optimize. This one measures the thing the user actually calls, which is what a
// speedup claim has to be made against.
//
// Uses the *_internal entry points so the RNG is out of the measurement -- otherwise a
// getentropy() syscall dominates KeyGen and swamps the arithmetic.
//
// HOST CAVEAT (see `docs/reference/invariants.md`, Build environment): rdtsc on this machine is a constant-rate reference clock,
// not a retired-instruction counter, and it does not track turbo. Treat these numbers
// as ratios on one machine, never as portable cycle counts.

#include "kem.hpp"
#include "arch/dispatch.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
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

struct Stat { double median, p10, p90; };

template <typename F>
Stat measure(F&& f, int reps, int inner) {
  std::vector<double> s;
  s.reserve(static_cast<std::size_t>(reps));
  for (int r = 0; r < reps; ++r) {
    const std::uint64_t t0 = ticks();
    for (int i = 0; i < inner; ++i) f();
    const std::uint64_t t1 = ticks();
    s.push_back(static_cast<double>(t1 - t0) / inner);
  }
  std::sort(s.begin(), s.end());
  return Stat{s[s.size() / 2], s[s.size() / 10], s[(s.size() * 9) / 10]};
}

}  // namespace

int main() {
  const int REPS = 51, INNER = 200;

  std::uint8_t d[32], z[32], m[32];
  for (int i = 0; i < 32; ++i) { d[i] = static_cast<std::uint8_t>(i);
                                 z[i] = static_cast<std::uint8_t>(i + 64);
                                 m[i] = static_cast<std::uint8_t>(i * 3 + 1); }

  std::vector<std::uint8_t> ek(EK_BYTES), dk(DK_BYTES), ct(CT_BYTES), ss(SS_BYTES);
  keygen_internal(d, z, ek.data(), dk.data());
  encaps_internal(ek.data(), m, ct.data(), ss.data());

  const Stat kg = measure([&] {
    std::uint8_t e[EK_BYTES], k[DK_BYTES];
    keygen_internal(d, z, e, k); sink(e, 32);
  }, REPS, INNER);

  const Stat en = measure([&] {
    std::uint8_t c[CT_BYTES], s[SS_BYTES];
    encaps_internal(ek.data(), m, c, s); sink(s, SS_BYTES);
  }, REPS, INNER);

  const Stat de = measure([&] {
    std::uint8_t s[SS_BYTES];
    decaps_internal(dk.data(), ct.data(), s); sink(s, SS_BYTES);
  }, REPS, INNER);

  std::printf("backend: %s   (reps=%d, inner=%d, TSC ticks/op)\n",
              arch::has_avx2() ? "AVX2" : "portable", REPS, INNER);
  std::printf("  %-10s %12s %12s %12s\n", "op", "median", "p10", "p90");
  std::printf("  %-10s %12.1f %12.1f %12.1f\n", "KeyGen", kg.median, kg.p10, kg.p90);
  std::printf("  %-10s %12.1f %12.1f %12.1f\n", "Encaps", en.median, en.p10, en.p90);
  std::printf("  %-10s %12.1f %12.1f %12.1f\n", "Decaps", de.median, de.p10, de.p90);
  std::printf("MACHINE %.1f %.1f %.1f\n", kg.median, en.median, de.median);
  return 0;
}
