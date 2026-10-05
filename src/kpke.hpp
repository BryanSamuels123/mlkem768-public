#pragma once
// K-PKE. FIPS 203 §5, Algorithms 13, 14, 15.
//
// NOT APPROVED STANDALONE (FIPS 203 §5). K-PKE exists only as a collection of
// subroutines for ML-KEM, and it performs NO INPUT CHECKING -- the §7.2/§7.3 checks live
// in the ML-KEM layer (Phase 6b), which is the only caller. Nothing here is exported
// from the public header.
//
// Domains, per ADR-004 (mirrored in `docs/reference/invariants.md`):
//   A_hat comes from sample_ntt in CANONICAL [0, q) and is ALREADY in the NTT domain --
//   it goes straight into basemul with NO ntt(). docs/bounds.md covers the resulting
//   3328 input bound.
//   poly_basemul emits x R^-1, so t_hat = A_hat o s_hat + e_hat needs poly_to_mont to
//   get back to the normal domain. KeyGen calls NO inverse NTT.
//   Everything is canonicalized before serialization.
//
// LAZY REDUCTION IS PARTIALLY APPLIED (Phase 8c). poly_basemul_acc no longer reduces,
// so an accumulator arriving here can be |c| <= 4992; ntt() and invntt() are lazy
// internally. Everything is still canonicalized before serialization, which is what
// keeps the byte-level contract intact -- poly_canonicalize is proven total over
// int16_t. docs/bounds.md carries the site register and every remaining disposition.

#include "params.hpp"

#include <cstdint>

namespace mlkem768 {

// Algorithm 13 — K-PKE.KeyGen(d).
//   d is SECRET (32 bytes).
//   ek_PKE = ByteEncode_12(t_hat) || rho      (1184 bytes, public)
//   dk_PKE = ByteEncode_12(s_hat)             (1152 bytes, SECRET)
void kpke_keygen(std::uint8_t ek[params::EK_PKE_BYTES],
                 std::uint8_t dk[params::DK_PKE_BYTES],
                 const std::uint8_t d[32]) noexcept;

// Algorithm 14 — K-PKE.Encrypt(ek_PKE, m, r).
//   ek is PUBLIC; m and r are SECRET.
//   c = ByteEncode_du(Compress_du(u)) || ByteEncode_dv(Compress_dv(v))   (1088 bytes)
void kpke_encrypt(std::uint8_t c[params::CT_BYTES],
                  const std::uint8_t ek[params::EK_PKE_BYTES],
                  const std::uint8_t m[32],
                  const std::uint8_t r[32]) noexcept;

// Algorithm 15 — K-PKE.Decrypt(dk_PKE, c).
//   dk is SECRET; c is PUBLIC; the recovered m is SECRET.
void kpke_decrypt(std::uint8_t m[32],
                  const std::uint8_t dk[params::DK_PKE_BYTES],
                  const std::uint8_t c[params::CT_BYTES]) noexcept;

}  // namespace mlkem768
