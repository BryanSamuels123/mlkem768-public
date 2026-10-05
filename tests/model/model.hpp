#pragma once
// GOLDEN MODEL for ML-KEM-768 (FIPS 203).
//
// Deliberately slow and obviously correct. Spec §10.2:
//   - coefficients as int32_t, canonical [0, q); no Montgomery, no lazy reduction
//   - exact integer Compress/Decompress; no floating point (FIPS 203 §3.3 forbids it)
//   - straight-line transcription of the pseudocode in docs/algorithms/
//
// Its only job is to be right. Every optimization instinct is resisted on purpose: this
// is the oracle every later phase is differentially tested against, so a clever-but-wrong
// model would silently corrupt the whole project.
//
// NOTE ON THE NTT. Spec §10.2 says "multiplication via schoolbook negacyclic convolution,
// not NTT". That applies to multiplication in R_q. It cannot apply to the model as a
// whole, because FIPS 203 SERIALIZES the NTT representation: ek_PKE is
// ByteEncode_12(t_hat) and dk_PKE is ByteEncode_12(s_hat). Producing byte-identical keys
// therefore requires implementing Algorithms 9-12. They are transcribed literally here,
// with plain `% q` arithmetic. `schoolbook_negacyclic` is provided alongside as the
// INDEPENDENT cross-check (spec §5.3 test 2) and is verified against the NTT path in the
// model's own self-test.

#include <array>
#include <cstdint>
#include <cstddef>
#include <vector>

namespace mlkem768::model {

// ---------------------------------------------------------------------------
// Parameters (FIPS 203 §8 Table 2, ML-KEM-768). docs/algorithms/params-and-conventions.md
// ---------------------------------------------------------------------------
inline constexpr int N    = 256;
inline constexpr int Q    = 3329;
inline constexpr int ZETA = 17;
inline constexpr int K    = 3;
inline constexpr int ETA1 = 2;
inline constexpr int ETA2 = 2;
inline constexpr int DU   = 10;
inline constexpr int DV   = 4;

inline constexpr std::size_t EK_BYTES = 384 * K + 32;   // 1184
inline constexpr std::size_t DK_BYTES = 768 * K + 96;   // 2400
inline constexpr std::size_t CT_BYTES = 32 * (DU * K + DV);  // 1088
inline constexpr std::size_t SS_BYTES = 32;
inline constexpr std::size_t EK_PKE_BYTES = 384 * K + 32;    // 1184
inline constexpr std::size_t DK_PKE_BYTES = 384 * K;         // 1152

// Coefficients are kept canonical in [0, Q) at all times. int32_t, not int16_t: the
// model must never rely on a bound argument, and int16_t overflow is exactly the silent
// failure mode (docs/reference/kat-failure-checklist.md #8) this oracle exists to detect in the real implementation.
using Poly    = std::array<std::int32_t, N>;
using PolyVec = std::array<Poly, K>;
using Matrix  = std::array<PolyVec, K>;   // A[i][j]

// ---------------------------------------------------------------------------
// Symmetric primitives — FIPS 203 §4.1 (4.2)-(4.5)
// ---------------------------------------------------------------------------
void H(std::uint8_t out[32], const std::uint8_t* in, std::size_t len) noexcept;
void G(std::uint8_t out[64], const std::uint8_t* in, std::size_t len) noexcept;
void J(std::uint8_t out[32], const std::uint8_t* in, std::size_t len) noexcept;

// PRF_eta(s, b) = SHAKE256(s || b, 64*eta). eta selects OUTPUT LENGTH ONLY — FIPS 203
// §4.1 is explicit that it performs no domain separation (ADR-009).
std::vector<std::uint8_t> PRF(int eta, const std::uint8_t s[32], std::uint8_t b);

// ---------------------------------------------------------------------------
// Conversion and compression — FIPS 203 §4.2.1
// ---------------------------------------------------------------------------
std::vector<std::uint8_t> bits_to_bytes(const std::vector<std::uint8_t>& b);   // Alg 3
std::vector<std::uint8_t> bytes_to_bits(const std::vector<std::uint8_t>& B);   // Alg 4

std::vector<std::uint8_t> byte_encode(int d, const Poly& F);                   // Alg 5
Poly byte_decode(int d, const std::uint8_t* B);                                // Alg 6

std::int32_t compress(int d, std::int32_t x) noexcept;    // (4.7)
std::int32_t decompress(int d, std::int32_t y) noexcept;  // (4.8)

// ---------------------------------------------------------------------------
// Sampling — FIPS 203 §4.2.2
// ---------------------------------------------------------------------------
Poly sample_ntt(const std::uint8_t B[34]);                    // Alg 7
Poly sample_poly_cbd(int eta, const std::vector<std::uint8_t>& B);  // Alg 8

// ---------------------------------------------------------------------------
// NTT — FIPS 203 §4.3
// ---------------------------------------------------------------------------
Poly ntt(const Poly& f);                                      // Alg 9
Poly inv_ntt(const Poly& f_hat);                              // Alg 10
Poly multiply_ntts(const Poly& f_hat, const Poly& g_hat);     // Alg 11

// Independent cross-check: negacyclic convolution in R_q, X^256 = -1. Not part of
// FIPS 203; used to validate the NTT path (spec §5.3 test 2).
Poly schoolbook_negacyclic(const Poly& a, const Poly& b);

// ---------------------------------------------------------------------------
// K-PKE — FIPS 203 §5. NOT approved standalone.
// ---------------------------------------------------------------------------
void kpke_keygen(std::uint8_t ek[EK_PKE_BYTES], std::uint8_t dk[DK_PKE_BYTES],
                 const std::uint8_t d[32]);                   // Alg 13
void kpke_encrypt(std::uint8_t c[CT_BYTES], const std::uint8_t ek[EK_PKE_BYTES],
                  const std::uint8_t m[32], const std::uint8_t r[32]);  // Alg 14
void kpke_decrypt(std::uint8_t m[32], const std::uint8_t dk[DK_PKE_BYTES],
                  const std::uint8_t c[CT_BYTES]);            // Alg 15

// ---------------------------------------------------------------------------
// ML-KEM — FIPS 203 §6, §7
// ---------------------------------------------------------------------------
void keygen_internal(const std::uint8_t d[32], const std::uint8_t z[32],
                     std::uint8_t ek[EK_BYTES], std::uint8_t dk[DK_BYTES]);   // Alg 16
void encaps_internal(const std::uint8_t ek[EK_BYTES], const std::uint8_t m[32],
                     std::uint8_t ct[CT_BYTES], std::uint8_t ss[SS_BYTES]);   // Alg 17
void decaps_internal(const std::uint8_t dk[DK_BYTES], const std::uint8_t ct[CT_BYTES],
                     std::uint8_t ss[SS_BYTES]);                              // Alg 18

// Input checks. FIPS 203 §7.2 / §7.3. Return true when the input PASSES.
bool check_encaps_key(const std::uint8_t* ek, std::size_t len);   // type + modulus check
bool check_decaps_key(const std::uint8_t* dk, std::size_t len);   // type + hash check

}  // namespace mlkem768::model
