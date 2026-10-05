#pragma once
// Coefficient-bound instrumentation. Compiled out entirely unless MLKEM_TRACK_BOUNDS is
// defined, so the shipped library pays nothing.
//
// docs/bounds.md is the authoritative invariant table and this is how its "observed
// maximum" column is produced. Random testing establishes a LOWER bound on the worst
// case, never the worst case -- so where the margin is thin, bounds.md must also carry
// an argument from the algorithm. This tool measures; it does not prove.

#include <cstdint>

#ifdef MLKEM_TRACK_BOUNDS

#include <array>

namespace mlkem768::bounds {

enum Site : int {
  kNttInput,          // |c| entering ntt() -- NOT always <= 1664
  kNttMontInput,      // |zeta * c| entering montgomery_reduce
  kNttButterflySum,   // |f[j] +- t| before barrett_reduce
  kInvnttSum,         // |t + f[j+len]| before barrett_reduce
  kInvnttDiff,        // |f[j+len] - t| before mont_mul
  kInvnttMontInput,   // |zeta * diff| entering montgomery_reduce
  kInvnttScaleInput,  // |c * kInvNttScale| entering montgomery_reduce
  kBasemulMontInput,  // |a*b| entering montgomery_reduce
  kBasemulSum,        // |c0|, |c1| before barrett_reduce
  kAccSum,            // |r + t| before barrett_reduce
  kToMontInput,       // |c * R^2| entering montgomery_reduce
  kSiteCount,
};

// Header-only (C++17 inline variables), so there is no translation unit to link and
// nothing at all is emitted when tracking is off.
inline std::array<long long, kSiteCount> observed{};

inline void record(Site s, long long v) noexcept {
  const long long m = v < 0 ? -v : v;
  if (m > observed[static_cast<std::size_t>(s)]) observed[static_cast<std::size_t>(s)] = m;
}

inline void reset() noexcept { observed.fill(0); }

inline const char* name(Site s) noexcept {
  switch (s) {
    case kNttInput:         return "ntt      |c| on ENTRY   (input bound)";
    case kNttMontInput:     return "ntt      |zeta*c|      -> montgomery_reduce";
    case kNttButterflySum:  return "ntt      |f[j] +- t|   -> barrett_reduce";
    case kInvnttSum:        return "invntt   |t + f[j+l]|  -> barrett_reduce";
    case kInvnttDiff:       return "invntt   |f[j+l] - t|  -> mont_mul";
    case kInvnttMontInput:  return "invntt   |zeta*diff|   -> montgomery_reduce";
    case kInvnttScaleInput: return "invntt   |c*R^2/128|   -> montgomery_reduce";
    case kBasemulMontInput: return "basemul  |a*b|         -> montgomery_reduce";
    case kBasemulSum:       return "basemul  |c0|,|c1|     -> barrett_reduce";
    case kAccSum:           return "acc      |r + t|       -> barrett_reduce";
    case kToMontInput:      return "to_mont  |c*R^2|       -> montgomery_reduce";
    default:                return "?";
  }
}

// The claimed bound for each site: montgomery_reduce's strict input limit q*2^15, or
// int16_t's range for anything that must survive being stored in a coefficient.
inline long long limit(Site s) noexcept {
  constexpr long long kMontLimit = 3329LL * 32768 - 1;   // strict, see reduce.hpp
  constexpr long long kInt16 = 32767;
  switch (s) {
    case kNttInput:
      return kInt16;
    case kNttMontInput:
    case kInvnttMontInput:
    case kInvnttScaleInput:
    case kBasemulMontInput:
    case kToMontInput:
      return kMontLimit;
    default:
      return kInt16;
  }
}

}  // namespace mlkem768::bounds

#define MLKEM_TRACK(site, v) \
  ::mlkem768::bounds::record(::mlkem768::bounds::site, static_cast<long long>(v))

// Whole-polynomial variant. Must compile to NOTHING when tracking is off -- a
// `for (auto c : p.c) ((void)0);` leaves an unused loop variable and fails -Werror.
#define MLKEM_TRACK_POLY(site, poly)                     \
  do {                                                   \
    for (const auto mlkem_track_c_ : (poly).c)           \
      MLKEM_TRACK(site, mlkem_track_c_);                 \
  } while (0)

#else   // !MLKEM_TRACK_BOUNDS

#define MLKEM_TRACK(site, v) ((void)0)
#define MLKEM_TRACK_POLY(site, poly) ((void)0)

#endif
