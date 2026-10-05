// Golden model: FIPS 203 Algorithms 13-15 (K-PKE).
// Literal transcriptions from docs/algorithms/alg13..alg15.
//
// K-PKE is NOT approved standalone (FIPS 203 §5) and performs no input checking —
// it is only ever invoked as a subroutine of ML-KEM, which does the checking.

#include "model.hpp"

#include <cassert>
#include <cstring>

namespace mlkem768::model {
namespace {

// Apply Compress_d / Decompress_d coefficient-wise.
Poly poly_compress(int d, const Poly& a) {
  Poly r{};
  for (std::size_t i = 0; i < N; ++i) r[i] = compress(d, a[i]);
  return r;
}
Poly poly_decompress(int d, const Poly& a) {
  Poly r{};
  for (std::size_t i = 0; i < N; ++i) r[i] = decompress(d, a[i]);
  return r;
}

Poly poly_add(const Poly& a, const Poly& b) {
  Poly r{};
  for (std::size_t i = 0; i < N; ++i) r[i] = (a[i] + b[i]) % Q;
  return r;
}
Poly poly_sub(const Poly& a, const Poly& b) {
  Poly r{};
  for (std::size_t i = 0; i < N; ++i) r[i] = ((a[i] - b[i]) % Q + Q) % Q;
  return r;
}

// Regenerate A_hat exactly as Algorithms 13 and 14 both specify.
//   A_hat[i][j] <- SampleNTT(rho || j || i)     with j at byte 32, i at byte 33
// The j-then-i order is failure mode #3; see docs/algorithms/alg07-sample-ntt.md.
Matrix gen_matrix(const std::uint8_t rho[32]) {
  Matrix A{};
  for (int i = 0; i < K; ++i) {
    for (int j = 0; j < K; ++j) {
      std::uint8_t seed[34];
      std::memcpy(seed, rho, 32);
      seed[32] = static_cast<std::uint8_t>(j);   // j FIRST
      seed[33] = static_cast<std::uint8_t>(i);
      A[static_cast<std::size_t>(i)][static_cast<std::size_t>(j)] = sample_ntt(seed);
    }
  }
  return A;
}

}  // namespace

// ---------------------------------------------------------------------------
// Algorithm 13 — K-PKE.KeyGen(d)
// ---------------------------------------------------------------------------
void kpke_keygen(std::uint8_t ek[EK_PKE_BYTES], std::uint8_t dk[DK_PKE_BYTES],
                 const std::uint8_t d[32]) {
  // line 1: (rho, sigma) <- G(d || k).  The trailing k byte is the ML-KEM domain
  // separator absent from round-3 Kyber — failure mode #1. k = 3 for ML-KEM-768.
  std::uint8_t gin[33];
  std::memcpy(gin, d, 32);
  gin[32] = static_cast<std::uint8_t>(K);
  std::uint8_t gout[64];
  G(gout, gin, 33);
  const std::uint8_t* rho   = gout;
  const std::uint8_t* sigma = gout + 32;

  int Ncount = 0;                                   // line 2

  const Matrix A = gen_matrix(rho);                 // lines 3-7

  PolyVec s{}, e{};
  for (int i = 0; i < K; ++i) {                     // lines 8-11: s, with ETA1
    s[static_cast<std::size_t>(i)] =
        sample_poly_cbd(ETA1, PRF(ETA1, sigma, static_cast<std::uint8_t>(Ncount)));
    ++Ncount;
  }
  for (int i = 0; i < K; ++i) {                     // lines 12-15: e, ALSO with ETA1
    e[static_cast<std::size_t>(i)] =
        sample_poly_cbd(ETA1, PRF(ETA1, sigma, static_cast<std::uint8_t>(Ncount)));
    ++Ncount;
  }

  PolyVec s_hat{}, e_hat{};
  for (int i = 0; i < K; ++i) {                     // lines 16-17
    s_hat[static_cast<std::size_t>(i)] = ntt(s[static_cast<std::size_t>(i)]);
    e_hat[static_cast<std::size_t>(i)] = ntt(e[static_cast<std::size_t>(i)]);
  }

  // line 18: t_hat <- A_hat o s_hat + e_hat  (matrix-vector product in T_q)
  PolyVec t_hat{};
  for (int i = 0; i < K; ++i) {
    Poly acc{};
    for (int j = 0; j < K; ++j) {
      acc = poly_add(acc, multiply_ntts(A[static_cast<std::size_t>(i)][static_cast<std::size_t>(j)],
                                        s_hat[static_cast<std::size_t>(j)]));
    }
    t_hat[static_cast<std::size_t>(i)] = poly_add(acc, e_hat[static_cast<std::size_t>(i)]);
  }

  // line 19: ek_PKE <- ByteEncode_12(t_hat) || rho
  for (int i = 0; i < K; ++i) {
    const auto enc = byte_encode(12, t_hat[static_cast<std::size_t>(i)]);
    std::memcpy(ek + static_cast<std::size_t>(i) * 384, enc.data(), 384);
  }
  std::memcpy(ek + 384 * K, rho, 32);

  // line 20: dk_PKE <- ByteEncode_12(s_hat)
  for (int i = 0; i < K; ++i) {
    const auto enc = byte_encode(12, s_hat[static_cast<std::size_t>(i)]);
    std::memcpy(dk + static_cast<std::size_t>(i) * 384, enc.data(), 384);
  }
}

// ---------------------------------------------------------------------------
// Algorithm 14 — K-PKE.Encrypt(ek_PKE, m, r)
// ---------------------------------------------------------------------------
void kpke_encrypt(std::uint8_t c[CT_BYTES], const std::uint8_t ek[EK_PKE_BYTES],
                  const std::uint8_t m[32], const std::uint8_t r[32]) {
  int Ncount = 0;                                   // line 1

  PolyVec t_hat{};                                  // line 2
  for (int i = 0; i < K; ++i)
    t_hat[static_cast<std::size_t>(i)] = byte_decode(12, ek + static_cast<std::size_t>(i) * 384);

  const std::uint8_t* rho = ek + 384 * K;           // line 3

  const Matrix A = gen_matrix(rho);                 // lines 4-8

  PolyVec y{}, e1{};
  for (int i = 0; i < K; ++i) {                     // lines 9-12: y, with ETA1
    y[static_cast<std::size_t>(i)] =
        sample_poly_cbd(ETA1, PRF(ETA1, r, static_cast<std::uint8_t>(Ncount)));
    ++Ncount;
  }
  for (int i = 0; i < K; ++i) {                     // lines 13-16: e1, with ETA2
    e1[static_cast<std::size_t>(i)] =
        sample_poly_cbd(ETA2, PRF(ETA2, r, static_cast<std::uint8_t>(Ncount)));
    ++Ncount;
  }
  // line 17: e2, with ETA2, N = 6
  const Poly e2 = sample_poly_cbd(ETA2, PRF(ETA2, r, static_cast<std::uint8_t>(Ncount)));

  PolyVec y_hat{};                                  // line 18
  for (int i = 0; i < K; ++i) y_hat[static_cast<std::size_t>(i)] = ntt(y[static_cast<std::size_t>(i)]);

  // line 19: u <- NTT^-1(A_hat^T o y_hat) + e1.  NOTE THE TRANSPOSE (failure mode #4):
  // KeyGen uses A_hat, Encrypt uses A_hat^T, so here row i sums over A[j][i], not A[i][j].
  PolyVec u{};
  for (int i = 0; i < K; ++i) {
    Poly acc{};
    for (int j = 0; j < K; ++j) {
      acc = poly_add(acc, multiply_ntts(A[static_cast<std::size_t>(j)][static_cast<std::size_t>(i)],
                                        y_hat[static_cast<std::size_t>(j)]));
    }
    u[static_cast<std::size_t>(i)] = poly_add(inv_ntt(acc), e1[static_cast<std::size_t>(i)]);
  }

  // line 20: mu <- Decompress_1(ByteDecode_1(m))
  const Poly mu = poly_decompress(1, byte_decode(1, m));

  // line 21: v <- NTT^-1(t_hat^T o y_hat) + e2 + mu
  Poly vacc{};
  for (int i = 0; i < K; ++i)
    vacc = poly_add(vacc, multiply_ntts(t_hat[static_cast<std::size_t>(i)],
                                        y_hat[static_cast<std::size_t>(i)]));
  const Poly v = poly_add(poly_add(inv_ntt(vacc), e2), mu);

  // lines 22-24: c <- ByteEncode_du(Compress_du(u)) || ByteEncode_dv(Compress_dv(v))
  std::size_t off = 0;
  for (int i = 0; i < K; ++i) {
    const auto enc = byte_encode(DU, poly_compress(DU, u[static_cast<std::size_t>(i)]));
    std::memcpy(c + off, enc.data(), enc.size());
    off += enc.size();                                     // 32*DU = 320 each
  }
  const auto encv = byte_encode(DV, poly_compress(DV, v));
  std::memcpy(c + off, encv.data(), encv.size());          // 32*DV = 128
  off += encv.size();
  assert(off == CT_BYTES);
}

// ---------------------------------------------------------------------------
// Algorithm 15 — K-PKE.Decrypt(dk_PKE, c)
// ---------------------------------------------------------------------------
void kpke_decrypt(std::uint8_t m[32], const std::uint8_t dk[DK_PKE_BYTES],
                  const std::uint8_t c[CT_BYTES]) {
  const std::size_t c1_len = 32 * static_cast<std::size_t>(DU) * K;   // 960
  const std::uint8_t* c1 = c;                                        // line 1
  const std::uint8_t* c2 = c + c1_len;                               // line 2

  PolyVec u_prime{};                                                 // line 3
  for (int i = 0; i < K; ++i) {
    const Poly dec = byte_decode(DU, c1 + static_cast<std::size_t>(i) * 32 * DU);
    u_prime[static_cast<std::size_t>(i)] = poly_decompress(DU, dec);
  }

  const Poly v_prime = poly_decompress(DV, byte_decode(DV, c2));     // line 4

  PolyVec s_hat{};                                                   // line 5
  for (int i = 0; i < K; ++i)
    s_hat[static_cast<std::size_t>(i)] = byte_decode(12, dk + static_cast<std::size_t>(i) * 384);

  // line 6: w <- v' - NTT^-1(s_hat^T o NTT(u')).  s_hat is already in the NTT domain;
  // u' is not, so it is transformed here. One inverse NTT, after the inner product.
  Poly acc{};
  for (int i = 0; i < K; ++i)
    acc = poly_add(acc, multiply_ntts(s_hat[static_cast<std::size_t>(i)],
                                      ntt(u_prime[static_cast<std::size_t>(i)])));
  const Poly w = poly_sub(v_prime, inv_ntt(acc));

  // line 7: m <- ByteEncode_1(Compress_1(w))
  const auto enc = byte_encode(1, poly_compress(1, w));
  std::memcpy(m, enc.data(), 32);
}

}  // namespace mlkem768::model
