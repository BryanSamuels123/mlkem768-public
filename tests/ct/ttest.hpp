#pragma once
// Welch's t-test with dudect's percentile-cropping method (spec §7.4, §8.4).
//
// WHY THIS IS NOT VENDORED dudect.h. dudect is MIT (checked, recorded in DECISIONS.md
// ADR-035) so vendoring was permitted. It was not a licensing decision but an API one:
//
//   - dudect drives everything through two `extern` globals, `do_one_computation` and
//     `prepare_inputs`. That is one measured target per binary. Phase 9b has nine.
//   - `max_t` is computed inside dudect's static `report()` and only PRINTED. The gate
//     here has to report the actual max |t| per target, so the number would have had to
//     be scraped back out of stdout.
//
// The statistics are dudect's method, reimplemented: class-randomized measurement,
// Welch's t on the raw timings, and the same test repeated over a ladder of percentile
// crops to suppress the long right tail that OS noise puts on every sample.
//
// THE RISK IN WRITING YOUR OWN STATISTICS is a t-test that cannot report a leak -- a
// gate that cannot fail. That is why the calibration in dudect_mlkem.cpp runs FIRST and
// is not optional: a planted leak must be detected.
//
// SENSITIVITY IS PER-TARGET. A floor measured on the calibration loop does not carry over
// to a target with different variance -- see the in-context measurement in
// docs/notes/09-dudect.md section 2b, which is what the top-level rows are calibrated
// against.

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <vector>

namespace ct {

// Welford running mean/variance, one per class.
struct TTest {
  double mean[2]{0.0, 0.0};
  double m2[2]{0.0, 0.0};
  double n[2]{0.0, 0.0};

  void push(double x, int cls) noexcept {
    n[cls] += 1.0;
    const double d = x - mean[cls];
    mean[cls] += d / n[cls];
    m2[cls] += d * (x - mean[cls]);
  }

  // Welch's t. Returns 0 when either class lacks the samples to have a variance.
  double t() const noexcept {
    if (n[0] < 2.0 || n[1] < 2.0) return 0.0;
    const double v0 = m2[0] / (n[0] - 1.0);
    const double v1 = m2[1] / (n[1] - 1.0);
    const double denom = std::sqrt(v0 / n[0] + v1 / n[1]);
    if (!(denom > 0.0)) return 0.0;
    return (mean[0] - mean[1]) / denom;
  }

  double samples() const noexcept { return n[0] + n[1]; }
};

// dudect's crop ladder: the same t-test repeated over measurements below each of a set
// of percentile thresholds. The tail of a timing distribution is dominated by
// interrupts and migrations, which are not the signal; cropping it raises sensitivity
// to a small constant offset that would otherwise be buried.
inline constexpr int kNumPercentiles = 100;
// One extra slot for the uncropped test.
inline constexpr int kNumTests = kNumPercentiles + 1;

struct Session {
  TTest tests[kNumTests];
  std::vector<std::int64_t> warmup;   // timings collected before thresholds exist
  std::int64_t thresholds[kNumPercentiles]{};
  bool have_thresholds = false;
  std::size_t warmup_target;

  explicit Session(std::size_t warmup_n = 10000) : warmup_target(warmup_n) {
    warmup.reserve(warmup_n);
  }

  void set_thresholds() {
    std::vector<std::int64_t> s = warmup;
    std::sort(s.begin(), s.end());
    for (int i = 0; i < kNumPercentiles; ++i) {
      // dudect's spacing: dense near the top, so most crops keep most of the data.
      const double p = 1.0 - std::pow(0.5, 10.0 * double(i + 1) / kNumPercentiles);
      std::size_t idx = static_cast<std::size_t>(p * double(s.size() - 1));
      if (idx >= s.size()) idx = s.size() - 1;
      thresholds[i] = s[idx];
    }
    have_thresholds = true;
  }

  void push(std::int64_t cycles, int cls) {
    if (cycles <= 0) return;                 // discard counter wrap / descheduled
    if (!have_thresholds) {
      warmup.push_back(cycles);
      if (warmup.size() >= warmup_target) set_thresholds();
      return;
    }
    tests[0].push(double(cycles), cls);
    for (int i = 0; i < kNumPercentiles; ++i) {
      if (cycles < thresholds[i]) tests[i + 1].push(double(cycles), cls);
    }
  }

  // Largest |t| over every crop that retained enough data to be meaningful.
  double max_abs_t(double* at_samples = nullptr, double* at_delta = nullptr) const {
    double best = 0.0, best_n = 0.0, best_d = 0.0;
    for (const auto& tt : tests) {
      if (tt.n[0] < 100.0 || tt.n[1] < 100.0) continue;
      const double a = std::fabs(tt.t());
      if (a > best) {
        best = a; best_n = tt.samples();
        best_d = tt.mean[1] - tt.mean[0];   // cycles, class1 - class0
      }
    }
    if (at_samples) *at_samples = best_n;
    // |t| answers "is the difference real?", never "is it big?". With a quarter of a
    // million measurements a difference far below one cycle clears |t| = 10 easily.
    // The mean gap is what says whether anything is actually exploitable.
    if (at_delta) *at_delta = best_d;
    return best;
  }

  double total_samples() const { return tests[0].samples(); }
};

// Spec §8.4 gate. 4.5 is the stricter leakage-assessment convention; anything between
// the two is named rather than waved through -- see docs/notes/09-dudect.md.
inline constexpr double kGateSpec = 10.0;
inline constexpr double kGateStrict = 4.5;

inline const char* verdict(double max_t) {
  if (max_t >= kGateSpec) return "LEAK";
  if (max_t >= kGateStrict) return "MARGINAL";
  return "clean";
}

}  // namespace ct
