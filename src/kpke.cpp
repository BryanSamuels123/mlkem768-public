// K-PKE. FIPS 203 Algorithms 13, 14, 15.
// Transcribed from docs/algorithms/alg13-kpke-keygen.md, alg14-kpke-encrypt.md,
// alg15-kpke-decrypt.md. See kpke.hpp for the domain contract.
//
// DIVISION AUDIT: no runtime `/` or `%` in this file. `gmake audit-div` verifies at the
// machine level.

#include "kpke.hpp"

#include "ct_declassify.hpp"
#include "zeroize.hpp"

#include "ntt.hpp"
#include "poly.hpp"
#include "polyvec.hpp"
#include "reduce.hpp"
#include "sample.hpp"
#include "symmetric.hpp"

#include <array>
#include <cstring>
#include <span>

namespace mlkem768 {
namespace {

using Matrix = std::array<PolyVec, params::K>;   // A[i][j]

// Regenerate A_hat. Identical in Alg. 13 lines 3-7 and Alg. 14 lines 4-8.
//
//   A_hat[i][j] <- SampleNTT(rho || j || i)     -- j at byte 32, i at byte 33
//
// j FIRST. This is failure mode #3: getting it backwards transposes the matrix and
// produces a fully self-consistent implementation that fails every KAT.
//
// The output is CANONICAL [0, q) and ALREADY in the NTT domain -- it is NOT ntt()'d.
// rho is public, so sample_ntt's variable timing is correct here (ADR-016 / sample.hpp).
Matrix gen_matrix(const std::uint8_t rho[32]) noexcept {
  Matrix a{};

  // The K*K = 9 SampleNTT streams are mutually independent -- each absorbs its own
  // 34-byte seed and never reads another's sponge state -- so they can be driven four
  // at a time through the 4-way Keccak (docs/notes/08a-batched-keccak.md).
  //
  // 9 = 4 + 4 + 1. The odd stream falls back to the scalar path; padding it out to a
  // fourth batch would run a whole extra 4-way permutation chain to throw three lanes
  // away, which is strictly worse than one scalar stream.
  //
  // Seeds are built for all 9 up front so the batching is a plain regrouping of the
  // same loop, not a change to WHICH seed goes where. j at byte 32, i at byte 33 --
  // j FIRST (failure mode #3).
  std::uint8_t seeds[params::K * params::K][34];
  for (int i = 0; i < params::K; ++i) {
    for (int j = 0; j < params::K; ++j) {
      std::uint8_t* sd = seeds[i * params::K + j];
      std::memcpy(sd, rho, 32);
      sd[32] = static_cast<std::uint8_t>(j);        // j FIRST
      sd[33] = static_cast<std::uint8_t>(i);
    }
  }

  // Flattened view: idx = i*K + j, matching the seed table above.
  Poly* out[params::K * params::K];
  for (int i = 0; i < params::K; ++i)
    for (int j = 0; j < params::K; ++j)
      out[i * params::K + j] = &a[static_cast<std::size_t>(i)].v[static_cast<std::size_t>(j)];

  constexpr int NB = (params::K * params::K) / 4;   // whole groups of four
  for (int b = 0; b < NB; ++b) {
    const int k = 4 * b;
    sample_ntt_x4(*out[k], *out[k + 1], *out[k + 2], *out[k + 3],
                  seeds[k], seeds[k + 1], seeds[k + 2], seeds[k + 3]);
  }
  for (int k = 4 * NB; k < params::K * params::K; ++k)
    sample_ntt(*out[k], seeds[k]);

  return a;
}

// Four noise polynomials in one 4-way PRF. FIPS 203 Alg. 13 lines 8-15 and Alg. 14
// lines 9-17 draw their noise from independent PRF streams that differ only in the
// nonce byte, so the four sponges share nothing and batch cleanly
// (docs/notes/08a-batched-keccak.md).
//
// SECRET THROUGHOUT: `key` is sigma or r, and the outputs ARE s / e / y / e1 / e2.
// The four PRF buffers are Zeroizing -- batching quadruples the amount of secret
// keystream live at once, so forgetting that here would be a real regression.
// sample_poly_cbd stays the constant-time Algorithm 8; only the XOF driving it changed.
template <int Eta>
void noise_x4(Poly& f0, Poly& f1, Poly& f2, Poly& f3,
              const std::uint8_t key[32],
              std::uint8_t n0, std::uint8_t n1, std::uint8_t n2, std::uint8_t n3) noexcept {
  Zeroizing<std::array<std::uint8_t, 64 * Eta>> b0, b1, b2, b3;
  PRF_x4<Eta>(b0.value, b1.value, b2.value, b3.value, key, n0, n1, n2, n3);
  sample_poly_cbd<Eta>(f0, std::span<const std::uint8_t, 64 * Eta>(b0.value));
  sample_poly_cbd<Eta>(f1, std::span<const std::uint8_t, 64 * Eta>(b1.value));
  sample_poly_cbd<Eta>(f2, std::span<const std::uint8_t, 64 * Eta>(b2.value));
  sample_poly_cbd<Eta>(f3, std::span<const std::uint8_t, 64 * Eta>(b3.value));
}

void poly_add_into(Poly& r, const Poly& b) noexcept {
  // |r|,|b| <= 1664 after barrett, so the sum is <= 3328 and fits int16_t.
  // NOT LAZY, DELIBERATELY (Phase 8c site #5: WON'T DO -- measured, not assumed).
  // Removing these two barrett_reduce calls is SAFE -- each caller does at most two adds
  // before a canonicalize that is proven total over int16_t, and `gmake kat` passes
  // 80/80 on both backends with them gone. It is simply worth nothing: measured together
  // with site #6 it came out 0.97x end-to-end, against a sanity control at 1.003.
  // Not a bound problem; a value judgement. docs/bounds.md site register has the table.
  for (std::size_t i = 0; i < params::N; ++i)
    r.c[i] = barrett_reduce(static_cast<std::int16_t>(r.c[i] + b.c[i]));
}

void poly_sub_into(Poly& r, const Poly& b) noexcept {
  for (std::size_t i = 0; i < params::N; ++i)
    r.c[i] = barrett_reduce(static_cast<std::int16_t>(r.c[i] - b.c[i]));
}

}  // namespace

// ---------------------------------------------------------------------------
// Algorithm 13 — K-PKE.KeyGen(d)
// ---------------------------------------------------------------------------
void kpke_keygen(std::uint8_t ek[params::EK_PKE_BYTES],
                 std::uint8_t dk[params::DK_PKE_BYTES],
                 const std::uint8_t d[32]) noexcept {
  // Line 1: (rho, sigma) <- G(d || k).  The trailing k byte is the ML-KEM domain
  // separator that round-3 Kyber does not have -- failure mode #1, the single most
  // common cause of a self-consistent implementation failing every KAT. k = 3.
  // gin holds a copy of the secret d; gout holds sigma. Both erased on scope exit
  // (FIPS 203 §3.3: only the designated output may be retained).
  Zeroizing<std::array<std::uint8_t, 33>> gin;
  std::memcpy(gin.value.data(), d, 32);
  gin.value[32] = static_cast<std::uint8_t>(params::K);

  Zeroizing<std::array<std::uint8_t, 64>> gout;
  G(gout.value.data(), gin.value);
  const std::uint8_t* rho = gout.value.data();
  const std::uint8_t* sigma = gout.value.data() + 32;

  // DECLASSIFY RHO -- exactly 32 bytes, and never sigma. See ct_declassify.hpp and
  // DECISIONS.md ADR-020.
  //
  // rho is derived from the secret d, so under ctgrind it inherits d's marking and
  // sample_ntt's rejection loop then looks like a secret-dependent branch. It is not:
  // rho is copied VERBATIM into ek below and published, and FIPS 203 / spec §8.1
  // explicitly permit variable time on rho ("Variable time is fine for anything
  // depending only on public data: rho, ek, A_hat, c"). An attacker reads rho out of ek
  // regardless; sample_ntt's timing tells them nothing further.
  //
  // SIGMA IS NOT DECLASSIFIED. It feeds PRF -> sample_poly_cbd, whose output IS the
  // secret key, and that path must remain constant-time. The 32-byte length here is
  // load-bearing: declassifying all 64 would silence a real leak in the CBD path.
  MLKEM_CT_DECLASSIFY(rho, 32);

  // Alg. 13 line 2 initializes a running counter N. Batching consumes four nonces
  // per call, so N appears below as literal arguments (0..5) instead of a variable.
  // The literals ARE the counter -- see the nonce-order note at the batch site.

  const Matrix a = gen_matrix(rho);                   // lines 3-7

  // Lines 8-15. N counter order is normative (failure mode #5): s = 0,1,2 then
  // e = 3,4,5. BOTH use ETA1 -- Alg. 13 lines 9 and 13 both say eta1. Invisible at
  // ML-KEM-768 where eta1 == eta2, wrong at ML-KEM-512 (ADR-009).
  // s and e ARE the secret key material.
  Zeroizing<PolyVec> s, e;
  Zeroizing<Poly> scratch0, scratch1;   // discarded lanes; secret, so still zeroized

  // NONCE ORDER IS NORMATIVE (failure mode #5): s = 0,1,2 then e = 3,4,5, and BOTH use
  // ETA1 -- Alg. 13 lines 9 and 13 both say eta1. Invisible at ML-KEM-768 where
  // eta1 == eta2, wrong at ML-KEM-512 (ADR-009).
  //
  // 6 streams do not divide by 4, so the second batch runs two lanes whose output is
  // thrown away. That is NOT waste: a 4-way permutation costs roughly what ONE scalar
  // permutation costs, so 4+4 with two discards beats 4 batched + 2 scalar. The
  // discarded lanes use nonces 6 and 7, which Alg. 13 never assigns, so they cannot
  // collide with a real draw.
  static_assert(params::K == 3, "the 4+4 noise batching below is written for k = 3");
  noise_x4<params::ETA1>(s.value.v[0], s.value.v[1], s.value.v[2], e.value.v[0],
                         sigma, 0, 1, 2, 3);
  noise_x4<params::ETA1>(e.value.v[1], e.value.v[2], scratch0.value, scratch1.value,
                         sigma, 4, 5, 6, 7);
  // Lines 16-17
  for (int i = 0; i < params::K; ++i) {
    ntt(s.value.v[static_cast<std::size_t>(i)]);
    ntt(e.value.v[static_cast<std::size_t>(i)]);
  }

  // Line 18: t_hat <- A_hat o s_hat + e_hat, entirely in the NTT domain.
  //
  // A_hat is canonical [0, q) straight from sample_ntt -- no ntt() on it.
  // poly_basemul_acc emits x R^-1, so poly_to_mont restores the normal domain
  // BEFORE adding e_hat, which is already normal (ADR-004). KeyGen calls no invntt.
  PolyVec t{};
  for (int i = 0; i < params::K; ++i) {
    Poly acc{};
    acc.c.fill(0);
    for (int j = 0; j < params::K; ++j)
      poly_basemul_acc(acc, a[static_cast<std::size_t>(i)].v[static_cast<std::size_t>(j)],
                       s.value.v[static_cast<std::size_t>(j)]);
    poly_to_mont(acc);                                // undo basemul's R^-1
    poly_add_into(acc, e.value.v[static_cast<std::size_t>(i)]);
    t.v[static_cast<std::size_t>(i)] = acc;
  }

  // Lines 19-20. Serialization demands canonical [0, q) -- ADR-004's consequence.
  polyvec_canonicalize(t);
  polyvec_canonicalize(s.value);
  polyvec_tobytes(ek, t);
  std::memcpy(ek + params::POLYVEC_BYTES, rho, 32);
  polyvec_tobytes(dk, s.value);
}

// ---------------------------------------------------------------------------
// Algorithm 14 — K-PKE.Encrypt(ek_PKE, m, r)
// ---------------------------------------------------------------------------
void kpke_encrypt(std::uint8_t c[params::CT_BYTES],
                  const std::uint8_t ek[params::EK_PKE_BYTES],
                  const std::uint8_t m[32],
                  const std::uint8_t r[32]) noexcept {
  // Alg. 14 line 1's running counter N, likewise expressed as literal nonces (0..6)
  // at the batch sites below.

  PolyVec t{};                                        // line 2
  polyvec_frombytes(t, ek);
  const std::uint8_t* rho = ek + params::POLYVEC_BYTES;   // line 3

  // DECLASSIFY RHO -- 32 bytes, the tail of ek. A WIDER boundary than ADR-020's, and
  // justified separately in ADR-021; do not read this as covered by ADR-020.
  //
  // ADR-020 declassified rho where KeyGen DERIVES it from secret d. This is a different
  // call path: Decaps_internal re-encrypts, so ek_PKE here is a pointer INTO dk, and dk
  // is secret in its entirety. rho therefore arrives tainted through a second route.
  //
  // It is still public: ek is the encapsulation key, published at keygen, and `docs/reference/invariants.md`
  // lists ek among the values variable time is fine for. An attacker holds ek already;
  // sample_ntt's timing on rho adds nothing. What is NOT declassified is the other
  // 1152 bytes of ek (t_hat) or any part of dk_PKE -- only the 32-byte rho window.
  MLKEM_CT_DECLASSIFY(rho, 32);

  const Matrix a = gen_matrix(rho);                   // lines 4-8

  // Lines 9-17. y = 0,1,2 with ETA1; e1 = 3,4,5 with ETA2; e2 = 6 with ETA2.
  // y, e1, e2 are secret noise; mu carries the secret message.
  Zeroizing<PolyVec> y, e1;
  Zeroizing<Poly> e2;
  Zeroizing<Poly> scratch;              // discarded lane; secret, so still zeroized

  // NONCE ORDER IS NORMATIVE (failure mode #5): y = 0,1,2 at ETA1; e1 = 3,4,5 at ETA2;
  // e2 = 6 at ETA2.
  //
  // The batches are split BY ETA, not 4+3. ML-KEM-768 has eta1 == eta2 so a 4+3 split
  // would also work here, but PRF<Eta> squeezes 64*eta bytes and a lane cannot squeeze
  // a different length from its neighbours -- a mixed-eta batch is not expressible.
  // Splitting on eta keeps this correct for a parameter set where eta1 != eta2
  // (ADR-009) instead of silently depending on their being equal.
  //
  // That puts y's three ETA1 streams in one batch with a discarded fourth (nonce 7,
  // which Alg. 14 never assigns), and e1[0..2] + e2 exactly fill the ETA2 batch.
  static_assert(params::K == 3, "the noise batching below is written for k = 3");
  noise_x4<params::ETA1>(y.value.v[0], y.value.v[1], y.value.v[2], scratch.value,
                         r, 0, 1, 2, 7);
  noise_x4<params::ETA2>(e1.value.v[0], e1.value.v[1], e1.value.v[2], e2.value,
                         r, 3, 4, 5, 6);
  for (int i = 0; i < params::K; ++i) ntt(y.value.v[static_cast<std::size_t>(i)]);  // line 18

  // Line 19: u <- NTT^-1(A_hat^T o y_hat) + e1.
  //
  // NOTE THE TRANSPOSE (failure mode #4). KeyGen uses A_hat[i][j]; Encrypt uses
  // A_hat^T, so row i sums over A[j][i]. There are two independent chances to
  // transpose -- here and in the seed byte order -- and they can cancel, producing
  // something self-consistent that fails every KAT.
  //
  // invntt emits x R, cancelling basemul's x R^-1 exactly (ADR-004), so no correction.
  PolyVec u{};
  for (int i = 0; i < params::K; ++i) {
    Poly acc{};
    acc.c.fill(0);
    for (int j = 0; j < params::K; ++j)
      poly_basemul_acc(acc, a[static_cast<std::size_t>(j)].v[static_cast<std::size_t>(i)],
                       y.value.v[static_cast<std::size_t>(j)]);
    invntt(acc);
    poly_add_into(acc, e1.value.v[static_cast<std::size_t>(i)]);
    u.v[static_cast<std::size_t>(i)] = acc;
  }

  Zeroizing<Poly> mu;                                 // line 20
  poly_frommsg(mu.value, m);

  // Line 21: v <- NTT^-1(t_hat^T o y_hat) + e2 + mu
  Poly v{};
  v.c.fill(0);
  for (int i = 0; i < params::K; ++i)
    poly_basemul_acc(v, t.v[static_cast<std::size_t>(i)],
                     y.value.v[static_cast<std::size_t>(i)]);
  invntt(v);
  poly_add_into(v, e2.value);
  poly_add_into(v, mu.value);

  // Lines 22-24. Compression demands canonical [0, q).
  polyvec_canonicalize(u);
  poly_canonicalize(v);
  polyvec_compress_du(c, u);
  poly_compress_dv(c + params::POLYVEC_COMPRESSED_DU_BYTES, v);
}

// ---------------------------------------------------------------------------
// Algorithm 15 — K-PKE.Decrypt(dk_PKE, c)
// ---------------------------------------------------------------------------
void kpke_decrypt(std::uint8_t m[32],
                  const std::uint8_t dk[params::DK_PKE_BYTES],
                  const std::uint8_t c[params::CT_BYTES]) noexcept {
  PolyVec u{};                                        // lines 1, 3
  polyvec_decompress_du(u, c);

  Poly v{};                                           // lines 2, 4
  poly_decompress_dv(v, c + params::POLYVEC_COMPRESSED_DU_BYTES);

  Zeroizing<PolyVec> s;                               // line 5 -- s_hat IS the key
  polyvec_frombytes(s.value, dk);

  // Line 6: w <- v' - NTT^-1(s_hat^T o NTT(u')).
  //
  // s_hat comes out of dk already in the NTT domain; u' is decompressed in the NORMAL
  // domain, so it is transformed here. One invntt, after the inner product.
  Poly acc{};
  acc.c.fill(0);
  for (int i = 0; i < params::K; ++i) {
    ntt(u.v[static_cast<std::size_t>(i)]);
    poly_basemul_acc(acc, s.value.v[static_cast<std::size_t>(i)],
                     u.v[static_cast<std::size_t>(i)]);
  }
  invntt(acc);
  poly_sub_into(v, acc);

  // Line 7: m <- ByteEncode_1(Compress_1(w)). Canonical input required.
  poly_canonicalize(v);
  poly_tomsg(m, v);
}

}  // namespace mlkem768
