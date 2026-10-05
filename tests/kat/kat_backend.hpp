#pragma once
// The seam that lets ONE harness drive either the golden model or the real
// implementation (spec §10.1):
//
//   make kat-model  ->  tests/kat/backend_model.cpp   (Phase 1 exit criterion)
//   make kat        ->  tests/kat/backend_impl.cpp    (Phase 7 gate)
//
// Built once, in Phase 1, and reused. Adding the Phase 7 backend must not require
// touching kat_main.cpp.

#include <cstddef>
#include <cstdint>

namespace mlkem768::kat {

inline constexpr std::size_t EK_BYTES = 1184;
inline constexpr std::size_t DK_BYTES = 2400;
inline constexpr std::size_t CT_BYTES = 1088;
inline constexpr std::size_t SS_BYTES = 32;

struct Backend {
  const char* name;

  // FIPS 203 Algorithm 16
  void (*keygen_internal)(const std::uint8_t d[32], const std::uint8_t z[32],
                          std::uint8_t* ek, std::uint8_t* dk);
  // Algorithm 17
  void (*encaps_internal)(const std::uint8_t* ek, const std::uint8_t m[32],
                          std::uint8_t* ct, std::uint8_t* ss);
  // Algorithm 18
  void (*decaps_internal)(const std::uint8_t* dk, const std::uint8_t* ct,
                          std::uint8_t* ss);
  // §7.2 / §7.3 input checks. Return true when the input PASSES.
  bool (*check_encaps_key)(const std::uint8_t* ek, std::size_t len);
  bool (*check_decaps_key)(const std::uint8_t* dk, std::size_t len);
};

// Defined by exactly one backend translation unit, chosen at link time.
const Backend& backend();

}  // namespace mlkem768::kat
