#pragma once
// ML-KEM. FIPS 203 §6 (Algorithms 16-18) and §7 (the input checks).
//
// Algorithms 19-21 are the randomized wrappers; they add only RBG sampling and are
// Phase 10 work (spec §3). ACVP exercises the deterministic _internal interfaces, which
// is what this header exposes.

#include "params.hpp"

#include <cstddef>
#include <cstdint>

namespace mlkem768 {

inline constexpr std::size_t EK_BYTES = 384 * params::K + 32;   // 1184
inline constexpr std::size_t DK_BYTES = 768 * params::K + 96;   // 2400
inline constexpr std::size_t CT_BYTES = params::CT_BYTES;       // 1088
inline constexpr std::size_t SS_BYTES = 32;

static_assert(EK_BYTES == 1184);
static_assert(DK_BYTES == 2400);
static_assert(CT_BYTES == 1088);

// ---------------------------------------------------------------------------
// THE DETERMINISTIC _internal INTERFACES — GATED (spec §3.1).
//
// FIPS 203 §6: "the interfaces specified in this section should not be made available
// to applications other than for testing purposes". Spec §3.1 turns that into a build
// requirement: gate them so they cannot be linked accidentally, and `make kat` builds
// with MLKEM_ENABLE_INTERNAL_API=1 while the default `make` does not.
//
// The DECLARATIONS are gated, not the definitions -- Algorithms 19-21 in kem.cpp call
// them, so the code must exist. What an application cannot do is obtain a declaration
// by including this header.
// ---------------------------------------------------------------------------
#ifdef MLKEM_ENABLE_INTERNAL_API

// Algorithm 16 — ML-KEM.KeyGen_internal(d, z).  d and z are SECRET.
//   dk = dk_PKE || ek || H(ek) || z       z stored VERBATIM
void keygen_internal(const std::uint8_t d[32], const std::uint8_t z[32],
                     std::uint8_t ek[EK_BYTES], std::uint8_t dk[DK_BYTES]) noexcept;

// Algorithm 17 — ML-KEM.Encaps_internal(ek, m).  m is SECRET.
//   (K, r) = G(m || H(ek));  c = K-PKE.Encrypt(ek, m, r)
//   NO m <- H(m), NO final KDF (failure mode #2). K is returned straight out of G.
void encaps_internal(const std::uint8_t ek[EK_BYTES], const std::uint8_t m[32],
                     std::uint8_t ct[CT_BYTES], std::uint8_t ss[SS_BYTES]) noexcept;

// Algorithm 18 — ML-KEM.Decaps_internal(dk, c).  THE security-critical one.
//   K_bar = J(z || c) computed UNCONDITIONALLY, branchless select, flag destroyed.
void decaps_internal(const std::uint8_t dk[DK_BYTES], const std::uint8_t ct[CT_BYTES],
                     std::uint8_t ss[SS_BYTES]) noexcept;

#endif  // MLKEM_ENABLE_INTERNAL_API

// ---------------------------------------------------------------------------
// Algorithms 19-21 — the randomized wrappers (FIPS 203 §7).
//
// THIN BY DESIGN. They add only RBG sampling and a normative error path around
// 16/17/18; correctness is inherited. ACVP tests the _internal interfaces, so these
// carry no KAT coverage -- they exist for the public API and for `make package`.
//
// The RBG failure check is NOT optional: Alg. 19 lines 3-5 and Alg. 20 lines 2-4
// specify "return an error indication if random bit generation failed".
// ---------------------------------------------------------------------------

enum class Status { Ok, RngFailure, InvalidEncapsKey, InvalidDecapsKey, InvalidCiphertext };

// Algorithm 19 — ML-KEM.KeyGen(). Draws d and z from the configured RBG.
[[nodiscard]] Status keygen(std::uint8_t ek[EK_BYTES], std::uint8_t dk[DK_BYTES]) noexcept;

// Algorithm 20 — ML-KEM.Encaps(ek). Performs the §7.2 check, then draws m.
[[nodiscard]] Status encaps(const std::uint8_t* ek, std::size_t ek_len,
                            std::uint8_t ct[CT_BYTES], std::uint8_t ss[SS_BYTES]) noexcept;

// Algorithm 21 — ML-KEM.Decaps(dk, c). Performs the §7.3 checks.
//
// The CIPHERTEXT LENGTH CHECK RUNS ON EVERY CALL (§7.3: "Ciphertext checking shall be
// performed with every execution"). Length and type failures are PUBLIC and may return a
// distinguishable status; a well-sized but cryptographically invalid ciphertext must NOT
// -- it goes through implicit rejection and returns Ok with the reject secret.
[[nodiscard]] Status decaps(const std::uint8_t* dk, std::size_t dk_len,
                            const std::uint8_t* ct, std::size_t ct_len,
                            std::uint8_t ss[SS_BYTES]) noexcept;

// §7.2 encapsulation key check: length, then the modulus check
// ByteEncode_12(ByteDecode_12(ek[0:384k])) == ek[0:384k].
// Operates on PUBLIC data only, so it may be variable-time.
[[nodiscard]] bool check_encaps_key(const std::uint8_t* ek, std::size_t len) noexcept;

// §7.3 decapsulation key check: length, then H(dk[384k:768k+32]) == dk[768k+32:768k+64].
[[nodiscard]] bool check_decaps_key(const std::uint8_t* dk, std::size_t len) noexcept;

}  // namespace mlkem768
