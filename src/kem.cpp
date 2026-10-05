// ML-KEM. FIPS 203 Algorithms 16-18 and the §7.2/§7.3 input checks.
// Transcribed from docs/algorithms/alg16..alg21.

// This TU defines the _internal algorithms and Algorithms 19-21 call them, so it opts
// in to its own gated declarations. Applications including kem.hpp do not.
#define MLKEM_ENABLE_INTERNAL_API 1
#include "kem.hpp"

#include "kpke.hpp"
#include "rng.hpp"
#include "poly.hpp"
#include "polyvec.hpp"
#include "symmetric.hpp"
#include "verify.hpp"
#include "zeroize.hpp"

#include <array>
#include <cstring>
#include <span>

namespace mlkem768 {
namespace {

// dk layout for k = 3 (Alg. 18 lines 1-4).
constexpr std::size_t kDkPkeOff = 0;                                  // [0, 1152)
constexpr std::size_t kEkOff    = params::DK_PKE_BYTES;               // [1152, 2336)
constexpr std::size_t kHOff     = kEkOff + EK_BYTES;                  // [2336, 2368)
constexpr std::size_t kZOff     = kHOff + 32;                         // [2368, 2400)
static_assert(kZOff + 32 == DK_BYTES);

}  // namespace

// ---------------------------------------------------------------------------
// Algorithm 16 — KeyGen_internal
// ---------------------------------------------------------------------------
void keygen_internal(const std::uint8_t d[32], const std::uint8_t z[32],
                     std::uint8_t ek[EK_BYTES], std::uint8_t dk[DK_BYTES]) noexcept {
  kpke_keygen(ek, dk + kDkPkeOff, d);                    // line 1: ek = ek_PKE
  std::memcpy(dk + kEkOff, ek, EK_BYTES);                // line 3
  H(dk + kHOff, std::span<const std::uint8_t>(ek, EK_BYTES));
  // z is stored VERBATIM -- never transformed. A KAT failure confined to the last 32
  // bytes of dk means this line did something.
  std::memcpy(dk + kZOff, z, 32);
}

// ---------------------------------------------------------------------------
// Algorithm 17 — Encaps_internal
// ---------------------------------------------------------------------------
void encaps_internal(const std::uint8_t ek[EK_BYTES], const std::uint8_t m[32],
                     std::uint8_t ct[CT_BYTES], std::uint8_t ss[SS_BYTES]) noexcept {
  // Line 1: (K, r) <- G(m || H(ek)).
  //
  // THE TWO KYBER DIFFERENCES LIVE HERE (failure mode #2):
  //   - there is NO m <- H(m). m is used exactly as supplied.
  //   - there is NO final KDF. K is G(...)[0:32], returned directly.
  Zeroizing<std::array<std::uint8_t, 64>> gin;
  std::memcpy(gin.value.data(), m, 32);
  H(gin.value.data() + 32, std::span<const std::uint8_t>(ek, EK_BYTES));

  Zeroizing<std::array<std::uint8_t, 64>> gout;
  G(gout.value.data(), gin.value);

  kpke_encrypt(ct, ek, m, gout.value.data() + 32);       // line 2: r = G(...)[32:64]
  std::memcpy(ss, gout.value.data(), 32);                // line 3: K = G(...)[0:32]
}

// ---------------------------------------------------------------------------
// Algorithm 18 — Decaps_internal.  THE security-critical algorithm.
// ---------------------------------------------------------------------------
void decaps_internal(const std::uint8_t dk[DK_BYTES], const std::uint8_t ct[CT_BYTES],
                     std::uint8_t ss[SS_BYTES]) noexcept {
  const std::uint8_t* dk_pke = dk + kDkPkeOff;           // line 1
  const std::uint8_t* ek_pke = dk + kEkOff;              // line 2
  const std::uint8_t* h      = dk + kHOff;               // line 3
  const std::uint8_t* z      = dk + kZOff;               // line 4

  Zeroizing<std::array<std::uint8_t, 32>> m_prime;
  kpke_decrypt(m_prime.value.data(), dk_pke, ct);        // line 5

  // Line 6: (K', r') <- G(m' || h).  h comes from dk; H(ek) is NOT recomputed.
  Zeroizing<std::array<std::uint8_t, 64>> gin;
  std::memcpy(gin.value.data(), m_prime.value.data(), 32);
  std::memcpy(gin.value.data() + 32, h, 32);
  Zeroizing<std::array<std::uint8_t, 64>> gout;
  G(gout.value.data(), gin.value);

  Zeroizing<std::array<std::uint8_t, 32>> k_prime;
  std::memcpy(k_prime.value.data(), gout.value.data(), 32);

  // Line 7: K_bar <- J(z || c).
  //
  // COMPUTED UNCONDITIONALLY, BEFORE THE COMPARISON. This is the order FIPS 203 itself
  // uses -- it is NOT inside the `if`. Hoisting it into a failure branch would make the
  // rejection path measurably slower than the success path.
  Zeroizing<std::array<std::uint8_t, 32 + CT_BYTES>> jin;
  std::memcpy(jin.value.data(), z, 32);
  std::memcpy(jin.value.data() + 32, ct, CT_BYTES);
  Zeroizing<std::array<std::uint8_t, 32>> k_bar;
  J(k_bar.value.data(), jin.value);

  // Line 8: c' <- K-PKE.Encrypt(ek_PKE, m', r')
  Zeroizing<std::array<std::uint8_t, CT_BYTES>> c_prime;
  kpke_encrypt(c_prime.value.data(), ek_pke, m_prime.value.data(),
               gout.value.data() + 32);

  // Lines 9-11. The `if` in the standard is PSEUDOCODE, not an instruction.
  //
  // NO memcmp -- that is failure mode #10, and ADR-016 measured that ctgrind detects
  // the early-exit compare shape, so the mistake is catchable. ct_neq scans the whole
  // buffer with a compiler barrier; ct_cmov selects branchlessly on a full-width mask.
  std::uint8_t mask = ct_neq(std::span<const std::uint8_t>(ct, CT_BYTES),
                             std::span<const std::uint8_t>(c_prime.value));
  ct_cmov(std::span<std::uint8_t>(k_prime.value), std::span<const std::uint8_t>(k_bar.value),
          mask);

  std::memcpy(ss, k_prime.value.data(), 32);             // line 12

  // FIPS 203 §6.3: the implicit-reject flag "shall be destroyed prior to
  // ML-KEM.Decaps_internal terminating... returning the value of the flag as an output
  // in any form is not permitted." Every other intermediate is a Zeroizing and is
  // erased by its destructor; the mask is a scalar, so it is erased explicitly.
  secure_zero(&mask, sizeof mask);
}

// ---------------------------------------------------------------------------
// Algorithms 19-21 — randomized wrappers
// ---------------------------------------------------------------------------

Status keygen(std::uint8_t ek[EK_BYTES], std::uint8_t dk[DK_BYTES]) noexcept {
  Zeroizing<std::array<std::uint8_t, 64>> seed;          // (d || z)
  if (!randombytes(seed.value)) return Status::RngFailure;   // lines 3-5: normative
  keygen_internal(seed.value.data(), seed.value.data() + 32, ek, dk);
  return Status::Ok;
}

Status encaps(const std::uint8_t* ek, std::size_t ek_len,
              std::uint8_t ct[CT_BYTES], std::uint8_t ss[SS_BYTES]) noexcept {
  // §7.2. FIPS 203 permits hoisting this out of the hot path, but doing it here is the
  // safe default: "ML-KEM.Encaps shall not be run with an encapsulation key that has
  // not been checked."
  if (!check_encaps_key(ek, ek_len)) return Status::InvalidEncapsKey;

  Zeroizing<std::array<std::uint8_t, 32>> m;
  if (!randombytes(m.value)) return Status::RngFailure;      // lines 2-4: normative
  encaps_internal(ek, m.value.data(), ct, ss);
  return Status::Ok;
}

Status decaps(const std::uint8_t* dk, std::size_t dk_len,
              const std::uint8_t* ct, std::size_t ct_len,
              std::uint8_t ss[SS_BYTES]) noexcept {
  // §7.3 check 1, EVERY call. A length mismatch is a public, structural fact.
  if (ct_len != CT_BYTES) return Status::InvalidCiphertext;
  // §7.3 checks 2 and 3.
  if (!check_decaps_key(dk, dk_len)) return Status::InvalidDecapsKey;

  // A well-sized ciphertext that is cryptographically invalid returns Ok here and the
  // implicit-reject secret in ss -- indistinguishable from success, by design.
  decaps_internal(dk, ct, ss);
  return Status::Ok;
}

// ---------------------------------------------------------------------------
// §7.2 / §7.3 input checks.  PUBLIC data only -- variable time is fine.
// ---------------------------------------------------------------------------
bool check_encaps_key(const std::uint8_t* ek, std::size_t len) noexcept {
  if (len != EK_BYTES) return false;                     // type check

  // Modulus check (7.1): ByteEncode_12(ByteDecode_12(ek[0:384k])) == ek[0:384k].
  // ByteDecode_12 reduces mod q and is NOT injective -- a 12-bit field can hold
  // [3329, 4095], which no honest encoder produces. Encode-then-compare detects it.
  for (int i = 0; i < params::K; ++i) {
    const std::uint8_t* chunk = ek + static_cast<std::size_t>(i) * params::POLY_BYTES;
    Poly decoded{};
    poly_frombytes(decoded, chunk);
    std::array<std::uint8_t, params::POLY_BYTES> re{};
    poly_tobytes(re.data(), decoded);
    if (std::memcmp(re.data(), chunk, params::POLY_BYTES) != 0) return false;
  }
  return true;
}

bool check_decaps_key(const std::uint8_t* dk, std::size_t len) noexcept {
  if (len != DK_BYTES) return false;                     // type check
  // Hash check (7.2): H(dk[384k : 768k+32]) == dk[768k+32 : 768k+64].
  std::array<std::uint8_t, 32> test{};
  H(test.data(), std::span<const std::uint8_t>(dk + kEkOff, EK_BYTES));
  return std::memcmp(test.data(), dk + kHOff, 32) == 0;
}

}  // namespace mlkem768
