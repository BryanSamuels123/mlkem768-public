#pragma once
// ML-KEM-768 parameter set. FIPS 203 §8 Table 2.
// docs/algorithms/params-and-conventions.md carries the full table for all three sets.
//
// No preprocessor macros (spec §4). Other parameter sets are added later by templating
// or a second constexpr namespace, never by redefining these.

#include <cstddef>
#include <cstdint>

namespace mlkem768::params {

inline constexpr int          N    = 256;
inline constexpr std::int16_t Q    = 3329;      // = 2^8 * 13 + 1
inline constexpr std::int16_t ZETA = 17;        // primitive 256th root of unity mod Q
inline constexpr int          K    = 3;
inline constexpr int          ETA1 = 2;
inline constexpr int          ETA2 = 2;
inline constexpr int          DU   = 10;
inline constexpr int          DV   = 4;

inline constexpr int POLY_BYTES                  = 384;             // 12 bits * 256 / 8
inline constexpr int POLYVEC_BYTES               = K * POLY_BYTES;  // 1152
inline constexpr int POLY_COMPRESSED_DV_BYTES    = 32 * DV;         // 128
inline constexpr int POLYVEC_COMPRESSED_DU_BYTES = K * 32 * DU;     // 960
inline constexpr int EK_PKE_BYTES = POLYVEC_BYTES + 32;             // 1184
inline constexpr int DK_PKE_BYTES = POLYVEC_BYTES;                  // 1152
inline constexpr int CT_BYTES = POLYVEC_COMPRESSED_DU_BYTES + POLY_COMPRESSED_DV_BYTES;  // 1088

// Derived-size self-checks: these are the numbers `docs/reference/invariants.md` pins, re-derived here so a
// parameter edit cannot silently desynchronize them.
static_assert(EK_PKE_BYTES == 1184);
static_assert(DK_PKE_BYTES == 1152);
static_assert(CT_BYTES == 1088);
static_assert(Q == 3329);
static_assert((Q - 1) == 3328);          // = 2^8 * 13: a 256th root exists, a 512th does not
static_assert((Q - 1) % 256 == 0);
static_assert((Q - 1) % 512 != 0);       // hence 128 quadratics, 7 NTT layers

}  // namespace mlkem768::params
