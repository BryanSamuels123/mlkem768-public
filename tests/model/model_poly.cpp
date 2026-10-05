// Golden model: FIPS 203 Algorithms 3-12 and the compression definitions.
// Literal transcriptions from docs/algorithms/. See model.hpp for the contract.

#include "model.hpp"
#include "model_keccak.hpp"

#include <cassert>
#include <cstring>

namespace mlkem768::model {

// ---------------------------------------------------------------------------
// Symmetric primitives — FIPS 203 §4.1
// ---------------------------------------------------------------------------

void H(std::uint8_t out[32], const std::uint8_t* in, std::size_t len) noexcept {
  sha3_256(out, in, len);                       // (4.4)
}
void G(std::uint8_t out[64], const std::uint8_t* in, std::size_t len) noexcept {
  sha3_512(out, in, len);                       // (4.5)
}
void J(std::uint8_t out[32], const std::uint8_t* in, std::size_t len) noexcept {
  shake256(out, 32, in, len);                   // (4.4)  J(s) = SHAKE256(s, 8*32)
}

std::vector<std::uint8_t> PRF(int eta, const std::uint8_t s[32], std::uint8_t b) {
  // PRF_eta(s, b) = SHAKE256(s || b, 8*64*eta).  (4.3)
  std::uint8_t in[33];
  std::memcpy(in, s, 32);
  in[32] = b;
  std::vector<std::uint8_t> out(static_cast<std::size_t>(64 * eta));
  shake256(out.data(), out.size(), in, 33);
  return out;
}

// ---------------------------------------------------------------------------
// Algorithm 3 — BitsToBytes(b)
// ---------------------------------------------------------------------------
std::vector<std::uint8_t> bits_to_bytes(const std::vector<std::uint8_t>& b) {
  assert(b.size() % 8 == 0);
  const std::size_t l = b.size() / 8;
  std::vector<std::uint8_t> B(l, 0);
  for (std::size_t i = 0; i < b.size(); ++i) {
    // B[i/8] += b[i] * 2^(i mod 8)   — little-endian at the bit level
    B[i / 8] = static_cast<std::uint8_t>(B[i / 8] + (b[i] << (i % 8)));
  }
  return B;
}

// ---------------------------------------------------------------------------
// Algorithm 4 — BytesToBits(B)
// ---------------------------------------------------------------------------
std::vector<std::uint8_t> bytes_to_bits(const std::vector<std::uint8_t>& B) {
  std::vector<std::uint8_t> b(B.size() * 8, 0);
  std::vector<std::uint8_t> C = B;                 // line 1: copy
  for (std::size_t i = 0; i < B.size(); ++i) {
    for (int j = 0; j < 8; ++j) {
      b[8 * i + static_cast<std::size_t>(j)] = static_cast<std::uint8_t>(C[i] % 2);
      C[i] = static_cast<std::uint8_t>(C[i] / 2);
    }
  }
  return b;
}

// ---------------------------------------------------------------------------
// Algorithm 5 — ByteEncode_d(F)
// ---------------------------------------------------------------------------
std::vector<std::uint8_t> byte_encode(int d, const Poly& F) {
  assert(d >= 1 && d <= 12);
  std::vector<std::uint8_t> b(static_cast<std::size_t>(256 * d), 0);
  for (int i = 0; i < 256; ++i) {
    std::int32_t a = F[static_cast<std::size_t>(i)];    // a in Z_m
    for (int j = 0; j < d; ++j) {
      const std::uint8_t bit = static_cast<std::uint8_t>(a % 2);
      b[static_cast<std::size_t>(i * d + j)] = bit;
      a = (a - bit) / 2;                                // always even
    }
  }
  return bits_to_bytes(b);
}

// ---------------------------------------------------------------------------
// Algorithm 6 — ByteDecode_d(B)
// ---------------------------------------------------------------------------
Poly byte_decode(int d, const std::uint8_t* B) {
  assert(d >= 1 && d <= 12);
  // m = 2^d for d < 12, m = q for d = 12.  For d = 12 this is NOT injective:
  // a 12-bit field in [3329, 4095] folds mod q. That is why the §7.2 modulus check
  // exists. docs/algorithms/alg06-byte-decode.md
  const std::int32_t m = (d < 12) ? (1 << d) : Q;
  const std::vector<std::uint8_t> Bv(B, B + 32 * d);
  const std::vector<std::uint8_t> b = bytes_to_bits(Bv);
  Poly F{};
  for (int i = 0; i < 256; ++i) {
    std::int32_t acc = 0;
    for (int j = 0; j < d; ++j) {
      acc += static_cast<std::int32_t>(b[static_cast<std::size_t>(i * d + j)]) << j;
    }
    F[static_cast<std::size_t>(i)] = acc % m;
  }
  return F;
}

// ---------------------------------------------------------------------------
// Compress_d / Decompress_d — (4.7), (4.8)
// ---------------------------------------------------------------------------
// Rounding is round-to-nearest, TIES UP: FIPS 203 §2.3 defines ceil(y + 1/2) = y + 1.
// For non-negative integers, round(a/b) = floor((2a + b) / 2b). Exact 64-bit integer
// arithmetic; no floating point anywhere (FIPS 203 §3.3).

std::int32_t compress(int d, std::int32_t x) noexcept {
  // Compress_d(x) = round((2^d / q) * x) mod 2^d
  const std::int64_t num = (static_cast<std::int64_t>(x) << (d + 1)) + Q;
  const std::int64_t val = num / (2LL * Q);
  return static_cast<std::int32_t>(val & ((1LL << d) - 1));   // mod 2^d
}

std::int32_t decompress(int d, std::int32_t y) noexcept {
  // Decompress_d(y) = round((q / 2^d) * y)
  const std::int64_t num = 2LL * Q * static_cast<std::int64_t>(y) + (1LL << d);
  return static_cast<std::int32_t>(num / (1LL << (d + 1)));
}

// ---------------------------------------------------------------------------
// Algorithm 7 — SampleNTT(B).  Output is ALREADY in the NTT domain.
// Variable-time by design: the input is public (rho and two indices).
// ---------------------------------------------------------------------------
Poly sample_ntt(const std::uint8_t B[34]) {
  Sponge xof(168, 0x1F);            // XOF = SHAKE128
  xof.absorb(B, 34);

  Poly a{};
  int j = 0;
  // No loop bound, per FIPS 203 Appendix B ("implementations should not bound this
  // loop, if at all possible"). docs/algorithms/appendixB-sample-ntt-bounds.md
  while (j < 256) {
    std::uint8_t C[3];
    xof.squeeze(C, 3);
    const std::int32_t d1 = C[0] + 256 * (C[1] % 16);
    const std::int32_t d2 = (C[1] / 16) + 16 * C[2];
    if (d1 < Q) {
      a[static_cast<std::size_t>(j)] = d1;
      ++j;
    }
    if (d2 < Q && j < 256) {
      a[static_cast<std::size_t>(j)] = d2;
      ++j;
    }
  }
  return a;
}

// ---------------------------------------------------------------------------
// Algorithm 8 — SamplePolyCBD_eta(B)
// ---------------------------------------------------------------------------
Poly sample_poly_cbd(int eta, const std::vector<std::uint8_t>& B) {
  assert(B.size() == static_cast<std::size_t>(64 * eta));
  const std::vector<std::uint8_t> b = bytes_to_bits(B);
  Poly f{};
  for (int i = 0; i < 256; ++i) {
    std::int32_t x = 0, y = 0;
    for (int jj = 0; jj < eta; ++jj)
      x += b[static_cast<std::size_t>(2 * i * eta + jj)];
    for (int jj = 0; jj < eta; ++jj)
      y += b[static_cast<std::size_t>(2 * i * eta + eta + jj)];
    // f[i] = (x - y) mod q, with the FIPS 203 convention that mod yields [0, q)
    f[static_cast<std::size_t>(i)] = ((x - y) % Q + Q) % Q;
  }
  return f;
}

// ---------------------------------------------------------------------------
// Zeta tables — computed, never transcribed (spec §5.3). Verified against
// docs/algorithms/appendixA-zetas.md by the model self-test.
// ---------------------------------------------------------------------------
namespace {

int bitrev7(int r) noexcept {
  int out = 0;
  for (int i = 0; i < 7; ++i) out |= ((r >> i) & 1) << (6 - i);
  return out;
}

std::int32_t powmod(std::int32_t base, int exp, std::int32_t mod) noexcept {
  std::int64_t result = 1, b = base % mod;
  for (int e = exp; e > 0; e >>= 1) {
    if (e & 1) result = (result * b) % mod;
    b = (b * b) % mod;
  }
  return static_cast<std::int32_t>(result);
}

// zeta^BitRev7(i) mod q, i in [0,128). Appendix A table 1.
const std::array<std::int32_t, 128>& zetas() {
  static const std::array<std::int32_t, 128> t = [] {
    std::array<std::int32_t, 128> v{};
    for (int i = 0; i < 128; ++i) v[static_cast<std::size_t>(i)] = powmod(ZETA, bitrev7(i), Q);
    return v;
  }();
  return t;
}

// zeta^(2*BitRev7(i)+1) mod q, i in [0,128). Appendix A table 2.
const std::array<std::int32_t, 128>& gammas() {
  static const std::array<std::int32_t, 128> t = [] {
    std::array<std::int32_t, 128> v{};
    for (int i = 0; i < 128; ++i)
      v[static_cast<std::size_t>(i)] = powmod(ZETA, 2 * bitrev7(i) + 1, Q);
    return v;
  }();
  return t;
}

}  // namespace

// ---------------------------------------------------------------------------
// Algorithm 9 — NTT(f).  7 layers (len = 128..2), i ascending from 1.
// ---------------------------------------------------------------------------
Poly ntt(const Poly& f) {
  Poly fh = f;                                    // line 1: work on a copy
  int i = 1;
  for (int len = 128; len >= 2; len /= 2) {
    for (int start = 0; start < 256; start += 2 * len) {
      const std::int64_t zeta = zetas()[static_cast<std::size_t>(i)];
      ++i;
      for (int j = start; j < start + len; ++j) {
        const std::size_t jl = static_cast<std::size_t>(j + len);
        const std::size_t j0 = static_cast<std::size_t>(j);
        const std::int32_t t = static_cast<std::int32_t>((zeta * fh[jl]) % Q);
        fh[jl] = ((fh[j0] - t) % Q + Q) % Q;      // uses the OLD fh[j]
        fh[j0] = (fh[j0] + t) % Q;
      }
    }
  }
  return fh;
}

// ---------------------------------------------------------------------------
// Algorithm 10 — NTT^-1(f_hat).  i descending from 127, then scale by 3303 = 128^-1.
// ---------------------------------------------------------------------------
Poly inv_ntt(const Poly& f_hat) {
  Poly f = f_hat;                                 // line 1
  int i = 127;
  for (int len = 2; len <= 128; len *= 2) {
    for (int start = 0; start < 256; start += 2 * len) {
      const std::int64_t zeta = zetas()[static_cast<std::size_t>(i)];
      --i;
      for (int j = start; j < start + len; ++j) {
        const std::size_t jl = static_cast<std::size_t>(j + len);
        const std::size_t j0 = static_cast<std::size_t>(j);
        const std::int32_t t = f[j0];             // line 8: save the OLD f[j]
        f[j0] = (t + f[jl]) % Q;
        f[jl] = static_cast<std::int32_t>((zeta * (((f[jl] - t) % Q + Q) % Q)) % Q);
      }
    }
  }
  // line 14: multiply every entry by 3303 = 128^-1 mod q (NOT 256^-1 — 7 layers).
  for (auto& c : f) c = static_cast<std::int32_t>((3303LL * c) % Q);
  return f;
}

// ---------------------------------------------------------------------------
// Algorithms 11 and 12 — MultiplyNTTs / BaseCaseMultiply
// ---------------------------------------------------------------------------
Poly multiply_ntts(const Poly& f_hat, const Poly& g_hat) {
  Poly h{};
  for (int i = 0; i < 128; ++i) {
    const std::int64_t a0 = f_hat[static_cast<std::size_t>(2 * i)];
    const std::int64_t a1 = f_hat[static_cast<std::size_t>(2 * i + 1)];
    const std::int64_t b0 = g_hat[static_cast<std::size_t>(2 * i)];
    const std::int64_t b1 = g_hat[static_cast<std::size_t>(2 * i + 1)];
    const std::int64_t gamma = gammas()[static_cast<std::size_t>(i)];
    // Alg 12: c0 = a0*b0 + a1*b1*gamma;  c1 = a0*b1 + a1*b0
    h[static_cast<std::size_t>(2 * i)] =
        static_cast<std::int32_t>((a0 * b0 + (a1 * b1 % Q) * gamma) % Q);
    h[static_cast<std::size_t>(2 * i + 1)] =
        static_cast<std::int32_t>((a0 * b1 + a1 * b0) % Q);
  }
  return h;
}

// ---------------------------------------------------------------------------
// Independent cross-check: negacyclic convolution in R_q = Z_q[X]/(X^256 + 1).
// Not a FIPS 203 algorithm. Spec §5.3 test 2.
// ---------------------------------------------------------------------------
Poly schoolbook_negacyclic(const Poly& a, const Poly& b) {
  std::array<std::int64_t, 256> acc{};
  for (int i = 0; i < 256; ++i) {
    for (int j = 0; j < 256; ++j) {
      const std::int64_t prod =
          static_cast<std::int64_t>(a[static_cast<std::size_t>(i)]) *
          static_cast<std::int64_t>(b[static_cast<std::size_t>(j)]);
      const int k = i + j;
      if (k < 256) acc[static_cast<std::size_t>(k)] += prod;
      else         acc[static_cast<std::size_t>(k - 256)] -= prod;   // X^256 = -1
    }
  }
  Poly r{};
  for (int i = 0; i < 256; ++i)
    r[static_cast<std::size_t>(i)] =
        static_cast<std::int32_t>((acc[static_cast<std::size_t>(i)] % Q + Q) % Q);
  return r;
}

}  // namespace mlkem768::model
