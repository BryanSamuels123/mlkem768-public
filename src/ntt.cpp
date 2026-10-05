// NTT implementation. FIPS 203 Algorithms 9-12. See ntt.hpp for the domain contract
// and docs/bounds.md for the coefficient invariants.
//
// PHASE 2: NO LAZY REDUCTION. A barrett_reduce follows every butterfly output, so the
// LAZY REDUCTION HAS LANDED (Phase 8c). The old "|c| <= 1664 at every layer boundary"
// invariant is NO LONGER TRUE of the forward transform: ntt() lets coefficients grow to
// |c| <= 26624 across its seven layers and reduces ONCE at the end. invntt() keeps its
// SUM-side reduction (that half grows) and is lazy only on the MONT side.
//
// docs/bounds.md is the authority: it carries the per-layer growth derivation, the
// removal log, and a site register with a disposition for every remaining candidate.
// The register's verdicts: three sites done, one (basemul internals) UNSAFE while the
// accumulator stays unreduced, two measured worthless, one not a reduction at all.

#include "ntt.hpp"

#include "arch/dispatch.hpp"
#include "bounds_track.hpp"
#include "reduce.hpp"

#include <array>

namespace mlkem768 {
namespace {

using detail::bitrev7;
using detail::pow_mod;
using detail::to_mont;

// zeta^BitRev7(i) * R mod q, centered. FIPS 203 Appendix A, first table.
// GENERATED, never transcribed (spec §5.3). The unit test checks these against the
// published table after undoing the Montgomery factor.
consteval std::array<std::int16_t, 128> make_zetas() {
  std::array<std::int16_t, 128> z{};
  for (int i = 0; i < 128; ++i) z[static_cast<std::size_t>(i)] = to_mont(pow_mod(params::ZETA, bitrev7(i)));
  return z;
}

// zeta^(2*BitRev7(i)+1) * R mod q, centered. Appendix A, second table.
// A DIFFERENT table from the one ntt/invntt use -- that is the point of Algorithm 11.
consteval std::array<std::int16_t, 128> make_zetas_basemul() {
  std::array<std::int16_t, 128> z{};
  for (int i = 0; i < 128; ++i)
    z[static_cast<std::size_t>(i)] = to_mont(pow_mod(params::ZETA, 2 * bitrev7(i) + 1));
  return z;
}

constexpr auto kZetas = make_zetas();
constexpr auto kZetasBasemul = make_zetas_basemul();

// zeta^0 = 1, so the first entry is just R mod q, centered. Algorithm 9 starts at i = 1
// and Algorithm 10 counts down to 1, so kZetas[0] is never read by either.
static_assert(kZetas[0] == detail::center(R_MOD_Q));
static_assert(kZetasBasemul[0] == detail::to_mont(params::ZETA));

// The second table alternates sign in pairs: gamma[2m+1] == -gamma[2m] (mod q).
// Checked here at compile time for all 64 pairs; Phase 8 can exploit it to halve the
// table, which is exactly why it is pinned now.
consteval bool basemul_table_alternates() {
  for (int i = 1; i < 128; i += 2) {
    const std::int32_t even = kZetasBasemul[static_cast<std::size_t>(i - 1)];
    const std::int32_t odd = kZetasBasemul[static_cast<std::size_t>(i)];
    if (((even + odd) % params::Q) != 0) return false;
  }
  return true;
}
static_assert(basemul_table_alternates(),
              "Appendix A table 2 must satisfy gamma[2m+1] == -gamma[2m] (mod q)");

// Folds the 128^-1 scaling together with a Montgomery factor so that
// mont_mul(x, INV_NTT_SCALE) == x * R / 128, which is what makes invntt's output land
// in the *R domain and cancel poly_basemul's R^-1. Derived, not transcribed.
constexpr std::int16_t kInvNttScale =
    detail::center(static_cast<std::int32_t>((static_cast<std::int64_t>(R2_MOD_Q) * INV_128) % params::Q));
static_assert(kInvNttScale == 1441, "R^2 * 128^-1 mod q");

}  // namespace

namespace tables {
const std::int16_t* zetas() noexcept { return kZetas.data(); }
const std::int16_t* zetas_basemul() noexcept { return kZetasBasemul.data(); }
}  // namespace tables

// ---------------------------------------------------------------------------
// Algorithm 9 — NTT. Cooley-Tukey, decimation in time.
// ---------------------------------------------------------------------------
namespace {

// One NTT layer, with the layer width as a TEMPLATE parameter rather than a loop
// variable. That is not cosmetic: with a runtime `len`, the compiler cannot know the
// trip count of `for (start = 0; start < N; start += 2*len)` and emits a `divl` to
// compute 255/(2*len) -- a real division instruction, in the library, found by
// `gmake audit-div` at the machine level and carried as an explicit allowance since
// Phase 4 (ADR-018). Making `len` compile-time makes every trip count a constant and
// the division disappears. The allowance is now 0.
//
// The divisor was the public layer width, never secret, so this was never a leak --
// but ADR-018's rule is that the INSTRUCTION does not appear, precisely so that no
// future reader has to re-derive whether a given divisor is secret.
template <int Len>
[[gnu::always_inline]] inline void ntt_layer(Poly& f, unsigned& k) noexcept {
  for (int start = 0; start < params::N; start += 2 * Len) {
    const std::int16_t zeta = kZetas[k++];
    for (int j = start; j < start + Len; ++j) {
      const auto jl = static_cast<std::size_t>(j + Len);
      const auto j0 = static_cast<std::size_t>(j);

      // |zeta| <= 1664, |f[jl]| <= 1664 -> |product| <= 2.77e6, far under q*2^15.
      MLKEM_TRACK(kNttMontInput, static_cast<std::int32_t>(zeta) * f.c[jl]);
      const std::int16_t t = mont_mul(zeta, f.c[jl]);        // |t| < q

      // Line 9 uses the OLD f[j], which is why `u` is saved before either write.
      // LAZY (Phase 8c, removal #3): no reduction in the butterfly. mont_mul gives
      // |t| < q regardless of its input, so a layer ADDS 3328 rather than scaling:
      // B_i = B_(i-1) + 3328, and B_7 = 3328 + 7*3328 = 26624 -- 81% of int16_t.
      // ntt() therefore applies ONE full reduction pass at the end -- the inline
      // barrett_reduce loop below, NOT a call to any helper -- and it is not optional.
      // docs/bounds.md carries the per-layer derivation.
      MLKEM_TRACK(kNttButterflySum, static_cast<std::int32_t>(f.c[j0]) - t);
      MLKEM_TRACK(kNttButterflySum, static_cast<std::int32_t>(f.c[j0]) + t);
      const std::int16_t u = f.c[j0];
      f.c[jl] = static_cast<std::int16_t>(u - t);
      f.c[j0] = static_cast<std::int16_t>(u + t);
    }
  }
}

}  // namespace

namespace generic {

void ntt(Poly& f) noexcept {
  MLKEM_TRACK_POLY(kNttInput, f);
  unsigned k = 1;                       // Algorithm 9 line 2: i starts at 1
  // Seven layers, unrolled so every width is a compile-time constant. NOT eight:
  // q-1 = 2^8*13 admits no 512th root of unity, so X^256+1 factors into quadratics.
  ntt_layer<128>(f, k);
  ntt_layer<64>(f, k);
  ntt_layer<32>(f, k);
  ntt_layer<16>(f, k);
  ntt_layer<8>(f, k);
  ntt_layer<4>(f, k);
  ntt_layer<2>(f, k);

  // THE FINAL REDUCTION IS NOT OPTIONAL (Phase 8c removal #3).
  //
  // After seven lazy layers |c| <= 26624. basemul multiplies two NTT outputs together
  // and feeds the product to montgomery_reduce, whose contract is a STRICT
  // |a| < q*2^15 = 109,084,672. 26624^2 is 7.1e8 -- six times over. A fully lazy ntt()
  // with no final reduce does not merely lose precision, it violates that contract and
  // produces wrong-but-plausible output that a KAT would catch and a bounds check
  // would not.
  //
  // Because [-1664, 1664] is a COMPLETE residue system mod q (3329 values), and
  // barrett_reduce is total over int16_t and residue-preserving (both proven
  // exhaustively in test_arith.cpp), this single pass yields exactly the same
  // representative the old per-butterfly reductions did. ntt()'s output is therefore
  // BIT-IDENTICAL to the pre-8c version, not merely congruent.
  for (auto& c : f.c) c = barrett_reduce(c);
}

namespace {

// Gentleman-Sande layer, width as a template parameter. Same reason as ntt_layer.
template <int Len>
[[gnu::always_inline]] inline void invntt_layer(Poly& f, unsigned& k) noexcept {
  for (int start = 0; start < params::N; start += 2 * Len) {
    const std::int16_t zeta = kZetas[k--];
    for (int j = start; j < start + Len; ++j) {
      const auto jl = static_cast<std::size_t>(j + Len);
      const auto j0 = static_cast<std::size_t>(j);

      const std::int16_t t = f.c[j0];                        // line 8: save OLD f[j]

      // |t + f[jl]| <= 3328.
      MLKEM_TRACK(kInvnttSum, static_cast<std::int32_t>(t) + f.c[jl]);
      f.c[j0] = barrett_reduce(static_cast<std::int16_t>(t + f.c[jl]));

      // NOT the CT butterfly reversed: the subtraction uses the saved OLD f[j].
      // |f[jl] - t| <= 3328, |zeta| <= 1664 -> |product| <= 5.5e6. Fine.
      MLKEM_TRACK(kInvnttDiff, static_cast<std::int32_t>(f.c[jl]) - t);
      const std::int16_t d = static_cast<std::int16_t>(f.c[jl] - t);
      MLKEM_TRACK(kInvnttMontInput, static_cast<std::int32_t>(zeta) * d);
      // LAZY (Phase 8c, removal #2): no barrett here. mont_mul already returns
      // |.| < q, so this barrett_reduce was pure canonicalization 3328 -> 1664.
      // Relaxing it leaves the MONT half at <= 3328 and the SUM half at <= 1664,
      // so the next layer's |sum| <= 4992 and |zeta*d| <= 1664*4992 -- well inside
      // montgomery_reduce's strict q*2^15. docs/bounds.md has the per-layer table.
      //
      // THE SUM-SIDE barrett ABOVE MUST STAY. Gentleman-Sande is asymmetric: that
      // side GROWS, and without its reduction it doubles every layer (2^7 = 128x)
      // and overflows immediately. Removing "both" is not a bound question.
      f.c[jl] = mont_mul(zeta, d);
    }
  }
}

}  // namespace

void invntt(Poly& f) noexcept {
  unsigned k = 127;                     // Algorithm 10 line 2: i starts at 127
  invntt_layer<2>(f, k);
  invntt_layer<4>(f, k);
  invntt_layer<8>(f, k);
  invntt_layer<16>(f, k);
  invntt_layer<32>(f, k);
  invntt_layer<64>(f, k);
  invntt_layer<128>(f, k);

  // Line 14: fold 128^-1 in. mont_mul(x, R^2/128) == x * R / 128, so the raw transform's
  // factor of 128 cancels and the output lands in the *R domain (see ntt.hpp).
  for (auto& c : f.c) {
    MLKEM_TRACK(kInvnttScaleInput, static_cast<std::int32_t>(c) * kInvNttScale);
    c = barrett_reduce(mont_mul(c, kInvNttScale));
  }
}

}  // namespace generic

// ---------------------------------------------------------------------------
// Runtime dispatch (spec 9.4), same shape as the Phase 8a symmetric backend.
//
// The AVX2 NTT lives in its own -mavx2 TU; this file stays baseline-ISA and only
// forward-declares it. Both produce BIT-IDENTICAL output (tests/unit/test_avx2.cpp),
// which is what lets `gmake kat` gate the AVX2 path.
//
// BOUNDS INSTRUMENTATION FORCES THE PORTABLE PATH. `gmake bounds` measures real
// coefficient growth through MLKEM_TRACK in generic::ntt; the AVX2 path has no such
// instrumentation, so dispatching to it under -DMLKEM_TRACK_BOUNDS would silently
// report ZERO observations and docs/bounds.md would be measuring nothing at all --
// a vacuous gate of exactly the kind this project keeps finding. Do not remove.
// ---------------------------------------------------------------------------
namespace avx2 {
void ntt(Poly& f) noexcept;
void invntt(Poly& f) noexcept;
}  // namespace avx2

void ntt(Poly& f) noexcept {
#if defined(MLKEM_TRACK_BOUNDS)
  generic::ntt(f);
#else
  if (arch::has_avx2()) avx2::ntt(f); else generic::ntt(f);
#endif
}

void invntt(Poly& f) noexcept {
#if defined(MLKEM_TRACK_BOUNDS)
  generic::invntt(f);
#else
  if (arch::has_avx2()) avx2::invntt(f); else generic::invntt(f);
#endif
}

// ---------------------------------------------------------------------------
// Algorithm 12 — BaseCaseMultiply
// ---------------------------------------------------------------------------
void basemul(std::int16_t r[2], const std::int16_t a[2], const std::int16_t b[2],
             std::int16_t gamma) noexcept {
  // c0 = a0*b0 + a1*b1*gamma
  MLKEM_TRACK(kBasemulMontInput, static_cast<std::int32_t>(a[1]) * b[1]);
  std::int16_t t = mont_mul(a[1], b[1]);            // |t| < q
  MLKEM_TRACK(kBasemulMontInput, static_cast<std::int32_t>(t) * gamma);
  t = mont_mul(t, gamma);                           // |t| < q; |t*gamma| <= 3329*1664
  MLKEM_TRACK(kBasemulMontInput, static_cast<std::int32_t>(a[0]) * b[0]);
  const std::int16_t c0 = static_cast<std::int16_t>(t + mont_mul(a[0], b[0]));  // |.| < 2q
  MLKEM_TRACK(kBasemulSum, c0);
  r[0] = barrett_reduce(c0);

  // c1 = a0*b1 + a1*b0
  MLKEM_TRACK(kBasemulMontInput, static_cast<std::int32_t>(a[0]) * b[1]);
  MLKEM_TRACK(kBasemulMontInput, static_cast<std::int32_t>(a[1]) * b[0]);
  const std::int16_t c1 =
      static_cast<std::int16_t>(mont_mul(a[0], b[1]) + mont_mul(a[1], b[0]));   // |.| < 2q
  MLKEM_TRACK(kBasemulSum, c1);
  r[1] = barrett_reduce(c1);
}

// ---------------------------------------------------------------------------
// Algorithm 11 — MultiplyNTTs
// ---------------------------------------------------------------------------
namespace avx2 {
void basemul(Poly& r, const Poly& a, const Poly& b) noexcept;
void basemul_acc(Poly& r, const Poly& a, const Poly& b) noexcept;
}

static void poly_basemul_generic(Poly& r, const Poly& a, const Poly& b) noexcept {
  for (int i = 0; i < 128; ++i) {
    const auto o = static_cast<std::size_t>(2 * i);
    basemul(&r.c[o], &a.c[o], &b.c[o], kZetasBasemul[static_cast<std::size_t>(i)]);
  }
}

static void poly_basemul_acc_generic(Poly& r, const Poly& a, const Poly& b) noexcept {
  for (int i = 0; i < 128; ++i) {
    const auto o = static_cast<std::size_t>(2 * i);
    std::int16_t t[2];
    basemul(t, &a.c[o], &b.c[o], kZetasBasemul[static_cast<std::size_t>(i)]);
    // LAZY (Phase 8c, removal #1): NO reduction here. The accumulator absorbs all k
    // terms and the caller reduces once.
    //
    // |t| <= 1664 exhaustively (barrett_reduce is total over int16_t -- proven in
    // docs/bounds.md "Equivalence under lazy reduction"), so after k = 3 calls
    // |r| <= 3 * 1664 = 4992, with a transient of 6656 inside the last add. int16_t
    // holds 32767, so the margin is 5x. Every consumer's bound is re-derived in
    // docs/bounds.md; the binding one is invntt, whose input bound widens 1664 -> 4992.
    //
    // THE CALLER MUST REDUCE. r is NOT canonical and NOT centered on return.
    MLKEM_TRACK(kAccSum, static_cast<std::int32_t>(r.c[o]) + t[0]);
    MLKEM_TRACK(kAccSum, static_cast<std::int32_t>(r.c[o + 1]) + t[1]);
    r.c[o]     = static_cast<std::int16_t>(r.c[o] + t[0]);
    r.c[o + 1] = static_cast<std::int16_t>(r.c[o + 1] + t[1]);
  }
}

// Dispatch. CONSTANT-TIME on both paths -- the operands are s-hat, y-hat and t-hat.
// The AVX2 backend is bit-identical (200 000 random polys plus the extremes,
// tests/unit/test_avx2.cpp), keeps BOTH internal barrett_reduce calls (8c site #4 proved
// removing them overflows int16 in invntt layer 1), and leaves the accumulator
// unreduced exactly as removal #1 requires. Spec 9.2 item 4; ADR-031 for why we do not
// adopt pq-crystals' packed order.
void poly_basemul(Poly& r, const Poly& a, const Poly& b) noexcept {
  if (arch::has_avx2()) avx2::basemul(r, a, b); else poly_basemul_generic(r, a, b);
}

void poly_basemul_acc(Poly& r, const Poly& a, const Poly& b) noexcept {
  if (arch::has_avx2()) avx2::basemul_acc(r, a, b); else poly_basemul_acc_generic(r, a, b);
}

void poly_to_mont(Poly& r) noexcept {
  // mont_mul(x, R^2) == x * R.
  constexpr auto kR2 = static_cast<std::int16_t>(detail::center(R2_MOD_Q));
  for (auto& c : r.c) {
    MLKEM_TRACK(kToMontInput, static_cast<std::int32_t>(c) * kR2);
    c = barrett_reduce(mont_mul(c, kR2));
  }
}

}  // namespace mlkem768
