#pragma once
// k-vector serialization. FIPS 203 §4.2.1 applied coordinate-wise.
//
// Sizes for ML-KEM-768 (k = 3):
//   polyvec_tobytes        3 * 384 = 1152   (dk_PKE, and t_hat inside ek_PKE)
//   polyvec_compress_du    3 * 320 =  960   (c1, the u part of the ciphertext)
//
// All byte-writing functions require CANONICAL [0, q) input -- poly_canonicalize each
// coordinate first (ADR-004).

#include "params.hpp"
#include "poly.hpp"

#include <cstdint>

namespace mlkem768 {

// Canonicalize every coordinate.
void polyvec_canonicalize(PolyVec& r) noexcept;

// ByteEncode_12 / ByteDecode_12 applied k times.
//   Input to tobytes: CANONICAL [0, q)
void polyvec_tobytes(std::uint8_t out[params::POLYVEC_BYTES], const PolyVec& a) noexcept;
void polyvec_frombytes(PolyVec& r, const std::uint8_t in[params::POLYVEC_BYTES]) noexcept;

// Compress_du + ByteEncode_du, du = 10.  Four coefficients pack into five bytes.
//   Input: CANONICAL [0, q).  MUST be constant-time: u is secret.
void polyvec_compress_du(std::uint8_t out[params::POLYVEC_COMPRESSED_DU_BYTES],
                         const PolyVec& a) noexcept;
void polyvec_decompress_du(PolyVec& r,
                           const std::uint8_t in[params::POLYVEC_COMPRESSED_DU_BYTES]) noexcept;

}  // namespace mlkem768
