// Golden model: FIPS 203 Algorithms 16-18 and the §7.2 / §7.3 input checks.
// Literal transcriptions from docs/algorithms/alg16..alg21.
//
// Algorithms 19-21 (the randomized wrappers) are not modelled: they add only RBG
// sampling around the _internal algorithms, and the ACVP vectors exercise the
// deterministic interfaces. The input CHECKS from §7.2/§7.3 are modelled, because the
// vectors test them directly (encapsulationKeyCheck / decapsulationKeyCheck groups).

#include "model.hpp"

#include <cstring>

namespace mlkem768::model {

// ---------------------------------------------------------------------------
// Algorithm 16 — ML-KEM.KeyGen_internal(d, z)
// ---------------------------------------------------------------------------
void keygen_internal(const std::uint8_t d[32], const std::uint8_t z[32],
                     std::uint8_t ek[EK_BYTES], std::uint8_t dk[DK_BYTES]) {
  std::uint8_t ek_pke[EK_PKE_BYTES];
  std::uint8_t dk_pke[DK_PKE_BYTES];
  kpke_keygen(ek_pke, dk_pke, d);                       // line 1

  std::memcpy(ek, ek_pke, EK_BYTES);                    // line 2: ek = ek_PKE

  // line 3: dk <- (dk_PKE || ek || H(ek) || z)
  std::memcpy(dk, dk_pke, DK_PKE_BYTES);                            // [0, 1152)
  std::memcpy(dk + DK_PKE_BYTES, ek, EK_BYTES);                     // [1152, 2336)
  H(dk + DK_PKE_BYTES + EK_BYTES, ek, EK_BYTES);                    // [2336, 2368)
  std::memcpy(dk + DK_PKE_BYTES + EK_BYTES + 32, z, 32);            // [2368, 2400)
  // z is stored VERBATIM — never transformed. A KAT failure confined to the last 32
  // bytes of dk means this line did something.
}

// ---------------------------------------------------------------------------
// Algorithm 17 — ML-KEM.Encaps_internal(ek, m)
// ---------------------------------------------------------------------------
void encaps_internal(const std::uint8_t ek[EK_BYTES], const std::uint8_t m[32],
                     std::uint8_t ct[CT_BYTES], std::uint8_t ss[SS_BYTES]) {
  // line 1: (K, r) <- G(m || H(ek))
  //
  // NOTE the two Kyber differences that live here (failure mode #2):
  //   - there is NO m <- H(m); m is used exactly as supplied
  //   - there is NO final KDF; K is returned straight out of G
  std::uint8_t gin[64];
  std::memcpy(gin, m, 32);
  H(gin + 32, ek, EK_BYTES);

  std::uint8_t gout[64];
  G(gout, gin, 64);
  const std::uint8_t* Kbytes = gout;          // K = G(...)[0:32]
  const std::uint8_t* r      = gout + 32;     // r = G(...)[32:64]

  kpke_encrypt(ct, ek, m, r);                 // line 2
  std::memcpy(ss, Kbytes, 32);                // line 3
}

// ---------------------------------------------------------------------------
// Algorithm 18 — ML-KEM.Decaps_internal(dk, c)
// ---------------------------------------------------------------------------
void decaps_internal(const std::uint8_t dk[DK_BYTES], const std::uint8_t ct[CT_BYTES],
                     std::uint8_t ss[SS_BYTES]) {
  const std::uint8_t* dk_pke = dk;                                   // line 1 [0,1152)
  const std::uint8_t* ek_pke = dk + DK_PKE_BYTES;                    // line 2 [1152,2336)
  const std::uint8_t* h      = dk + DK_PKE_BYTES + EK_BYTES;         // line 3 [2336,2368)
  const std::uint8_t* z      = dk + DK_PKE_BYTES + EK_BYTES + 32;    // line 4 [2368,2400)

  std::uint8_t m_prime[32];
  kpke_decrypt(m_prime, dk_pke, ct);                                 // line 5

  // line 6: (K', r') <- G(m' || h).  h comes from dk; H(ek) is NOT recomputed.
  std::uint8_t gin[64];
  std::memcpy(gin, m_prime, 32);
  std::memcpy(gin + 32, h, 32);
  std::uint8_t gout[64];
  G(gout, gin, 64);
  std::uint8_t K_prime[32];
  std::memcpy(K_prime, gout, 32);
  const std::uint8_t* r_prime = gout + 32;

  // line 7: K_bar <- J(z || c).  Computed UNCONDITIONALLY, before the comparison —
  // this is the order FIPS 203 itself uses, and it is not inside the `if`.
  std::uint8_t jin[32 + CT_BYTES];
  std::memcpy(jin, z, 32);
  std::memcpy(jin + 32, ct, CT_BYTES);
  std::uint8_t K_bar[32];
  J(K_bar, jin, sizeof jin);

  // line 8: c' <- K-PKE.Encrypt(ek_PKE, m', r')
  std::uint8_t c_prime[CT_BYTES];
  kpke_encrypt(c_prime, ek_pke, m_prime, r_prime);

  // lines 9-11: if c != c' then K' <- K_bar.
  //
  // THE MODEL IS NOT THE CONSTANT-TIME ARTEFACT. It is transcribed literally, branch and
  // all, because its job is to be obviously correct. The real implementation must use
  // ct_neq + ct_cmov with a compiler barrier and must destroy the flag (FIPS 203 §6.3,
  // spec §8.2, failure mode #10). Phase 9 verifies that; this file deliberately does not
  // model it, and must never be used as evidence that the branchless path is correct.
  bool equal = true;
  for (std::size_t i = 0; i < CT_BYTES; ++i)
    if (ct[i] != c_prime[i]) equal = false;

  if (!equal) std::memcpy(K_prime, K_bar, 32);

  std::memcpy(ss, K_prime, 32);                                      // line 12
}

// ---------------------------------------------------------------------------
// §7.2 encapsulation key check
// ---------------------------------------------------------------------------
bool check_encaps_key(const std::uint8_t* ek, std::size_t len) {
  // 1. Type check: length must be 384k + 32.
  if (len != EK_BYTES) return false;

  // 2. Modulus check: ByteEncode_12(ByteDecode_12(ek[0:384k])) == ek[0:384k].
  //    ByteDecode_12 reduces mod q and is not injective, so a 12-bit field holding
  //    [3329, 4095] — which no honest encoder produces — is detected by re-encoding.
  for (int i = 0; i < K; ++i) {
    const std::uint8_t* chunk = ek + static_cast<std::size_t>(i) * 384;
    const Poly decoded = byte_decode(12, chunk);
    const auto reencoded = byte_encode(12, decoded);
    if (std::memcmp(reencoded.data(), chunk, 384) != 0) return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// §7.3 decapsulation key check (the dk part; the ciphertext length check is the
// caller's, and must run on EVERY decaps)
// ---------------------------------------------------------------------------
bool check_decaps_key(const std::uint8_t* dk, std::size_t len) {
  // 2. Type check: length must be 768k + 96.
  if (len != DK_BYTES) return false;

  // 3. Hash check: H(dk[384k : 768k+32]) == dk[768k+32 : 768k+64].
  std::uint8_t test[32];
  H(test, dk + DK_PKE_BYTES, EK_BYTES);
  return std::memcmp(test, dk + DK_PKE_BYTES + EK_BYTES, 32) == 0;
}

}  // namespace mlkem768::model
