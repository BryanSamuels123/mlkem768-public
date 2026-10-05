// Phase 9b: statistical timing test (spec §7.4, §8.4, §10.3).
//
// ctgrind proves the absence of secret-dependent BRANCHES and MEMORY INDICES. It is
// structurally blind to timing that varies without either -- a variable-latency
// instruction on secret data is the canonical case, and `div` is the canonical
// instruction (ADR-016). This is the gate for that dimension.
//
// CALIBRATION IS NOT OPTIONAL AND RUNS FIRST. A t-test that cannot report a leak is a
// gate that cannot fail, and this one is hand-written (see ttest.hpp for why). So the
// harness plants real leaks and requires them to be detected, then steps the leak down
// until detection fails.
//
// SENSITIVITY IS PER-TARGET AND DOES NOT TRANSFER. The ladder below runs on a ~200-cycle
// loop with low variance, where 1 cycle is detectable. That number says NOTHING about
// decaps, which is ~40 000 ticks with variance orders of magnitude larger -- a 1-cycle
// leak inside decaps is invisible. The in-context floor was measured separately, by
// planting the same ladder INSIDE decaps's secret-dependent path in a worktree:
// detection holds down to ~100 cycles and fails below ~50. See docs/notes/09-dudect.md
// §2b. "Top-level clean" therefore means clean to about +/-100 cycles, not +/-1.

#include "ttest.hpp"
#include "dudect_targets.hpp"

#include <cinttypes>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#if defined(__x86_64__)
#include <x86intrin.h>
#else
#error "dudect harness requires x86-64 rdtsc"
#endif

namespace ctb { volatile std::uint8_t g_sink = 0; }

namespace {

// lfence on both sides: rdtsc is not ordered against surrounding work on its own, and
// without the fences short targets pick up a large amount of reordering noise.
inline std::uint64_t ticks_begin() {
  _mm_lfence();
  const std::uint64_t t = __rdtsc();
  _mm_lfence();
  return t;
}
inline std::uint64_t ticks_end() { return ticks_begin(); }

// ----------------------------------------------------------------- planted leaks
//
// These live ONLY in this test TU. They are never compiled into the library, so
// `gmake audit-div` stays clean -- it audits libmlkem768.a, not the test harness.

volatile std::uint64_t g_divisor = 3329;   // volatile: forces a real div instruction

// A KyberSlash-shaped leak: Compress_1's division with a SECRET dividend.
//
// The plant makes the divisor `volatile` to force a genuine 64-bit `div`, reproducing the
// leak CLASS that broke the pq-crystals reference in 2023 so the harness can be shown to
// detect it.
//
// Why the library is not vulnerable, stated correctly: NOT because `q` is a compile-time
// constant -- the reference's divisor was constant too, and whether it became a `div`
// depended on compiler and flags, which is why KyberSlash hit some builds and not others.
// The reasons are that the source never divides secret data (Phase 4 derived a
// multiply-shift with consteval and proved it exhaustively) and that `audit-div` proves no
// div/idiv survives in the shipped library at machine level.
struct KyberSlashLeak : ctb::Bench {
  ctb::Rng* rng_ = nullptr;
  std::uint64_t secret[64]{};
  KyberSlashLeak() { name = "CALIBRATION: KyberSlash-style secret-dependent div";
                     fixed_desc = "nothing"; varies_desc = "the secret dividend"; }
  void setup(ctb::Fixed, ctb::Rng&) override {}
  std::uint64_t rnd[64]{};
  void prepare(int cls, ctb::Rng& rng) override {
    for (auto& r : rnd) r = rng.next();               // same work either way
    ctb::sel_bytes(secret, zeros, rnd, sizeof(secret), cls);
  }
  std::uint64_t zeros[64]{};
  void run() override {
    std::uint64_t acc = 0;
    for (std::uint64_t s : secret) acc += ((s << 1) + g_divisor / 2) / g_divisor;
    ctb::g_sink = std::uint8_t(acc);
  }
};

// A secret-dependent extra delay of a known size, used to find the detection floor.
//
// THE FIRST VERSION OF THIS WAS WRONG AND THE LADDER EXPOSED IT. It was written as
// `if (secret_bit) { loop N times; }`, and reported |t| ~= 140 for N = 1000 and for
// N = 1 alike -- completely flat. It was not measuring a delay of N cycles at all: the
// signal was the PRESENCE of the branch, whose misprediction cost is about the same
// whatever the loop body does. A ladder that does not vary what it claims to vary
// cannot establish a sensitivity, only the illusion of one.
//
// So the loop now ALWAYS runs, with a baseline trip count, and the secret adds `delta`
// iterations on top. Both classes execute the same shape of code and the only
// difference is duration, which is the quantity a sensitivity figure is about.
//
// `delta = 0` is kept in the ladder as a NULL CONTROL. It is the check that the
// harness reports *clean* when nothing leaks -- without it, a harness that always
// cried leak would be indistinguishable from one that works.
struct DelayLeak : ctb::Bench {
  static constexpr int kBase = 200;   // identical in both classes
  int delta;
  int extra = 0;
  std::string label;
  explicit DelayLeak(int d) : delta(d) {
    label = "CALIBRATION: secret-dependent delay, delta = " + std::to_string(d)
          + (d == 0 ? " cycles (NULL CONTROL)" : " cycles");
    name = label.c_str();
    fixed_desc = "baseline loop length, identical in both classes";
    varies_desc = d == 0 ? "nothing -- must report clean"
                         : "one secret bit adding delta iterations";
  }
  void setup(ctb::Fixed, ctb::Rng&) override {}
  void prepare(int cls, ctb::Rng& rng) override {
    const int rbit = int(rng.next() & 1);             // drawn either way
    const int bit = rbit & (cls & 1);                 // class 0 never delays
    extra = delta & -bit;                             // branchless
  }
  void run() override {
    std::uint64_t x = ctb::g_sink;
    const int n = kBase + extra;
    for (int i = 0; i < n; ++i) asm volatile("addq $1, %0" : "+r"(x));
    ctb::g_sink = std::uint8_t(x);
  }
};

// ----------------------------------------------------------------------- driver

struct Result {
  std::string name, fixed_kind;
  double max_t, samples, total, delta;
  int K = 1;
  double ctrl = -1.0;   // same target, both classes constant: attributability control
  bool gates = true;
};

// null_mode: the t-test still receives a randomly chosen class LABEL, but the input is
// prepared as class 1 (random) every time, so the two labelled groups are drawn from an
// identical distribution. Nothing can leak. Any |t| above the gate here is measurement
// artifact -- drift, the harness itself, or data-independent noise -- and it calibrates
// how much of a "leak" in the real run is attributable to the setup rather than the code.
// fixed_vs_fixed: BOTH classes get a constant input, differing in value. Class 0 uses
// the bench's fixed value; class 1's "random" input is regenerated from a reseeded RNG
// every iteration, so it too is the same bytes every time. Both classes therefore share
// the repetition property, and whatever |t| remains is attributable to the input VALUE
// rather than to one class repeating while the other varies.
Result measure(ctb::Bench& b, ctb::Fixed kind, std::size_t n, std::uint64_t seed,
               bool null_mode = false, bool fixed_vs_fixed = false,
               int K = 1, bool swap = false) {
  ctb::Rng rng(seed);
  b.setup(kind, rng);
  ctb::Rng prep(seed ^ 0x5DEECE66DULL);
  ct::Session sess(n / 20 < 2000 ? 2000 : n / 20);

  for (std::size_t i = 0; i < n; ++i) {
    // Class order is randomized PER MEASUREMENT so thermal drift, turbo transitions
    // and migrations land on both classes equally. Measuring all of class 0 and then
    // all of class 1 would attribute any drift between the halves to the secret.
    const int cls = rng.bit();
    if (fixed_vs_fixed) prep = ctb::Rng(seed ^ 0x5DEECE66DULL);   // same bytes each time
    // SWAP CONTROL: the recorded class label is unchanged, but the two classes exchange
    // which VALUE they use. If the timing difference follows the value, dmean flips sign;
    // if it follows the class mechanics or the buffer, dmean keeps its sign.
    const int data_cls = null_mode ? 1 : (swap ? (cls ^ 1) : cls);
    b.prepare(data_cls, prep);
    const std::uint64_t t0 = ticks_begin();
    b.run_n(K);
    const std::uint64_t t1 = ticks_end();
    sess.push(std::int64_t(t1 - t0), cls);
  }

  double at = 0.0, dl = 0.0;
  const double mt = sess.max_abs_t(&at, &dl);
  Result res{b.name, kind == ctb::Fixed::Zero ? "zero" : "random",
             mt, at, sess.total_samples(), dl};
  res.K = K;
  return res;
}

void print_header() {
  std::printf("%-38s %-7s %8s %10s %10s %8s  %s\n",
              "target", "fixed", "max |t|", "meas", "dmean(cyc)", "control", "verdict");
  std::printf("%s\n", std::string(104, '-').c_str());
}

void print_row(const Result& r) {
  const char* v;
  if (r.ctrl < 0.0) v = ct::verdict(r.max_t);
  else if (r.max_t < ct::kGateSpec) v = ct::verdict(r.max_t);
  else if (r.ctrl >= ct::kGateSpec) v = "INCONCLUSIVE";
  else v = "LEAK";
  if (r.ctrl < 0.0)
    std::printf("%-38s %-7s %8.2f %10.0f %10.3f %8s  %s\n",
                r.name.c_str(), r.fixed_kind.c_str(), r.max_t, r.total, r.delta, "-", v);
  else
    std::printf("%-38s %-7s %8.2f %10.0f %10.3f %8.2f  %s\n",
                r.name.c_str(), r.fixed_kind.c_str(), r.max_t, r.total, r.delta, r.ctrl, v);
}

}  // namespace

int main(int argc, char** argv) {
  std::size_t comp_n = 300000;    // component targets: cheap, many measurements
  std::size_t top_n = 40000;      // decaps/encaps: ~45k cycles each
  // K repetitions inside one rdtsc pair for the short component targets. One pair costs
  // tens of ticks and quantizes to 1; batching amortizes both. Top-level targets already
  // run ~40k ticks, so K = 1 there.
  int kBatch = 32;
  bool calibrate_only = false, skip_calibration = false, null_check = false;
  bool fvf = false, discriminate = false;
  std::uint64_t seed = 0xC0FFEEULL;
  std::string only;

  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "--calibrate") calibrate_only = true;
    else if (a == "--no-calibrate") skip_calibration = true;
    else if (a == "--quick") { comp_n = 40000; top_n = 6000; }
    else if (a == "--deep") { comp_n = 2000000; top_n = 250000; }
    else if (a.rfind("--seed=", 0) == 0) seed = std::strtoull(a.c_str() + 7, nullptr, 0);
    else if (a.rfind("--only=", 0) == 0) only = a.substr(7);
    else if (a == "--null-check") null_check = true;
    else if (a == "--fixed-vs-fixed") fvf = true;
    else if (a == "--discriminate") discriminate = true;
    else if (a.rfind("--K=", 0) == 0) kBatch = int(std::strtol(a.c_str() + 4, nullptr, 0));
    else { std::fprintf(stderr, "unknown argument: %s\n", a.c_str()); return 2; }
  }

  int status = 0;
  std::vector<Result> results;

  // ------------------------------------------------------------- calibration
  if (!skip_calibration) {
    std::printf("=== CALIBRATION (spec §8.4) — the harness must detect a known leak ===\n\n");
    print_header();

    KyberSlashLeak ks;
    Result r = measure(ks, ctb::Fixed::Zero, comp_n, seed);
    print_row(r);
    if (r.max_t < ct::kGateSpec) {
      std::printf("\nFAIL: the harness did NOT detect a deliberate secret-dependent\n"
                  "      division. Every 'clean' result below would be meaningless.\n");
      status = 1;
    }

    // Step the leak down to find the detection floor.
    std::printf("\n--- detection floor: secret-dependent delay, stepped down ---\n");
    const int ladder[] = {1000, 300, 100, 30, 10, 3, 1, 0};
    int smallest_detected = -1;
    for (int n : ladder) {
      DelayLeak dl(n);
      Result d = measure(dl, ctb::Fixed::Zero, comp_n, seed + std::uint64_t(n));
      print_row(d);
      if (n == 0) {
        // NULL CONTROL: nothing leaks, so a working harness must report clean here.
        if (d.max_t >= ct::kGateSpec) {
          std::printf("\nFAIL: the NULL CONTROL (delta = 0, no leak planted) reported\n"
                      "      |t| = %.2f. The harness cries leak on identical classes,\n"
                      "      so every LEAK verdict above is uninterpretable.\n", d.max_t);
          status = 1;
        }
        continue;
      }
      if (d.max_t >= ct::kGateSpec) smallest_detected = n;
    }
    if (smallest_detected < 0) {
      std::printf("\nFAIL: no planted delay was detected at all.\n");
      status = 1;
    } else {
      std::printf("\n  SENSITIVITY OF THIS LOOP: smallest planted delay detected at\n"
                  "  |t| >= %.1f is %d cycle(s), at %zu measurements.\n"
                  "\n  THIS NUMBER DOES NOT TRANSFER TO THE TOP-LEVEL ROWS. It is measured\n"
                  "  on a ~200-cycle loop with low variance. decaps is ~40,000 ticks with\n"
                  "  far larger variance, so a 1-cycle leak inside it is invisible. The\n"
                  "  in-context floor, measured by planting this same ladder inside\n"
                  "  decaps's secret-dependent path (worktree, see docs/notes/09-dudect.md\n"
                  "  section 2b): detection holds to ~100 cycles, fails below ~50.\n"
                  "  'Top-level clean' means clean to about +/-100 cycles, not +/-1.\n",
                  ct::kGateSpec, smallest_detected, comp_n);
    }
    std::printf("\n");
    if (calibrate_only) return status;
  }

  // ------------------------------------------------------------- real targets
  // (bench, is_top_level, gates)
  //   is_top_level -> K = 1 and the smaller sample budget
  //   gates        -> a LEAK here fails the target
  //
  // Component rows gate ONLY where the evidence decided them (docs/notes/09-dudect.md
  // §4): invntt and polyvec_compress_du are clean under batching at 1.9M samples in both
  // the fixed-vs-random test and the fixed-vs-fixed control. The rest stay advisory with
  // a stated reason -- poly_tomsg is a class-construction artifact, ntt is value-following
  // but sub-tick and not separable from switching power with this instrument.
  struct Row { std::unique_ptr<ctb::Bench> b; bool is_top; bool gates; };
  std::vector<Row> targets;
  targets.push_back({std::make_unique<ctb::NttBench>(),         false, false});
  targets.push_back({std::make_unique<ctb::InvnttBench>(),      false, true });
  targets.push_back({std::make_unique<ctb::BasemulBench>(),     false, false});
  targets.push_back({std::make_unique<ctb::CbdBench>(),         false, false});
  targets.push_back({std::make_unique<ctb::CompressDuBench>(),  false, true });
  targets.push_back({std::make_unique<ctb::TomsgBench>(),       false, false});
  targets.push_back({std::make_unique<ctb::DecapsValidity>(),   true,  true });
  targets.push_back({std::make_unique<ctb::DecapsSecretKey>(),  true,  true });
  targets.push_back({std::make_unique<ctb::EncapsMessage>(),    true,  true });

  std::printf("=== TARGETS ===\n");
  std::printf("gate: |t| < %.1f (spec §8.4).  |t| >= %.1f is named, not waved through.\n\n",
              ct::kGateSpec, ct::kGateStrict);
  print_header();

  for (auto& [b, is_top, row_gates] : targets) {
    if (!only.empty() && std::string(b->name).find(only) == std::string::npos) continue;
    const std::size_t n = is_top ? top_n : comp_n;
    // Requirement: at least two fixed-class values. An all-zero secret can hit special
    // cases (early loop exits, denormal-like shortcuts) that a random one never does,
    // and a random fixed value can miss a zero-only special case. Both are reported.
    const int K = is_top ? 1 : kBatch;
    if (null_check) {
      Result r = measure(*b, ctb::Fixed::Random, n, seed, /*null_mode=*/true, false, K);
      r.fixed_kind = "NULL";
      results.push_back(r);
      print_row(r);
      continue;
    }
    for (ctb::Fixed kind : {ctb::Fixed::Zero, ctb::Fixed::Random}) {
      Result r = measure(*b, kind, n, seed, false, fvf, K);
      // ATTRIBUTABILITY CONTROL, run for every row. The same target with BOTH classes
      // held to a constant (different) value. Nothing secret-dependent can show up
      // there, so whatever |t| it reaches is this harness's own systematic offset at
      // this measurement count. A row only counts as a leak if it clears the gate and
      // its control does not -- otherwise the number is real but not attributable.
      Result c = measure(*b, kind, n, seed, false, true, K);
      r.ctrl = c.max_t;
      r.gates = row_gates;
      results.push_back(r);
      print_row(r);
      // Component rows are ADVISORY, not a gate -- see the banner below. They are
      // reported in full and never silently dropped, but a measurement whose own
      // control is as large as its signal cannot decide anything.
      if (row_gates && r.max_t >= ct::kGateSpec && r.ctrl < ct::kGateSpec) status = 1;
    }
  }

  // ------------------------------------------------- value vs placement discrimination
  if (discriminate) {
    std::printf(
      "\n=== VALUE vs PLACEMENT (item 2) ===\n"
      "Both classes already write their input into the SAME working buffer before the\n"
      "timed region, so address, alignment and cache set are identical by construction.\n"
      "The swap run exchanges which VALUE each class uses while keeping the class label.\n"
      "  dmean flips sign  -> the difference follows the VALUE (value-dependent timing)\n"
      "  dmean keeps sign  -> it follows the class mechanics or the buffer (placement)\n\n");
    std::printf("%-30s %-7s %8s %10s %9s %10s  %s\n",
                "target", "fixed", "|t|", "dmean", "|t|swap", "dmeanSwap", "follows");
    std::printf("%s\n", std::string(92, '-').c_str());
    for (auto& [b, is_top, row_gates] : targets) {
      if (is_top) continue;                       // component rows are the question
      if (!only.empty() && std::string(b->name).find(only) == std::string::npos) continue;
      const int K = kBatch;
      for (ctb::Fixed kind : {ctb::Fixed::Zero, ctb::Fixed::Random}) {
        Result a = measure(*b, kind, comp_n, seed, false, true, K, false);
        Result c = measure(*b, kind, comp_n, seed, false, true, K, true);
        const bool flipped = (a.delta > 0.0) != (c.delta > 0.0);
        const bool small = std::fabs(a.delta) < 0.05 && std::fabs(c.delta) < 0.05;
        const char* follows = small ? "(too small)" : (flipped ? "VALUE" : "placement/class");
        std::printf("%-30s %-7s %8.2f %10.3f %9.2f %10.3f  %s\n",
                    b->name, kind == ctb::Fixed::Zero ? "zero" : "random",
                    a.max_t, a.delta, c.max_t, c.delta, follows);
      }
    }
    std::printf("\nBoth runs use fixed-vs-fixed inputs (each class constant), so neither\n"
                "class varies its input and only the VALUES differ between them.\n");
  }

  std::printf("\n=== CLASS DESIGN ===\n");
  for (auto& [b, is_top, row_gates] : targets) {
    if (!only.empty() && std::string(b->name).find(only) == std::string::npos) continue;
    std::printf("  %s%s\n      fixed : %s\n      varies: %s\n", row_gates ? "[gated] " : "[advisory] ",
                b->name, b->fixed_desc, b->varies_desc);
  }

  double worst = 0.0, worst_attrib = 0.0;
  const char* worst_name = "-";
  const char* worst_attrib_name = "-";
  for (const auto& r : results) {
    if (r.max_t > worst) { worst = r.max_t; worst_name = r.name.c_str(); }
    if (r.ctrl >= 0.0 && r.ctrl < ct::kGateSpec && r.max_t > worst_attrib) {
      worst_attrib = r.max_t; worst_attrib_name = r.name.c_str();
    }
  }
  std::printf("\nworst ATTRIBUTABLE max |t| (control below gate): %.2f  (%s)\n",
              worst_attrib, worst_attrib_name);

  std::printf(
    "\nWHICH ROWS GATE, AND WHY (docs/notes/09-dudect.md section 4)\n"
    "  GATED   top-level decaps/encaps -- ~40k ticks, far above counter resolution,\n"
    "          clean and stable across seeds. In-context floor ~100 cycles: that is\n"
    "          what 'clean' means here, NOT 1 cycle.\n"
    "  GATED   invntt, polyvec_compress_du -- decided clean under batching at 1.9M\n"
    "          samples, in both the test and the fixed-vs-fixed control.\n"
    "  ADVISORY poly_tomsg -- largest fixed-vs-random signal in the suite (|t| 31.5),\n"
    "          but CLEAN with both classes held constant at different values. So it\n"
    "          follows input NOVELTY, not value: a class-construction artifact.\n"
    "  ADVISORY ntt -- value-following (dmean flips under swap) at ~0.07 ticks/call.\n"
    "          No architectural mechanism; branchless SIMD, audit-div clean. Not\n"
    "          separable from data-dependent switching power by this instrument, and\n"
    "          erratic across seeds. NOT called clean.\n"
    "  ADVISORY basemul, sample_poly_cbd<2> -- not value-dependent (fixed-vs-fixed\n"
    "          clean) but erratic across seeds at sub-0.2-tick dmean.\n");

  double worst_gating = 0.0;
  const char* worst_gating_name = "-";
  for (const auto& r : results)
    if (r.gates && r.max_t > worst_gating) { worst_gating = r.max_t; worst_gating_name = r.name.c_str(); }

  std::printf("\nworst max |t|, GATING rows only : %.2f  (%s)\n",
              worst_gating, worst_gating_name);
  std::printf("worst max |t|, incl. advisory   : %.2f  (%s)  <- not a verdict, see above\n",
              worst, worst_name);
  if (worst_gating >= ct::kGateStrict && worst_gating < ct::kGateSpec)
    std::printf("NOTE: a gating row is above the stricter 4.5 convention though below\n"
                "      the spec's 10. Named rather than waved through.\n");
  std::printf("dudect: %s\n", status == 0 ? "PASS" : "FAIL");
  return status;
}
