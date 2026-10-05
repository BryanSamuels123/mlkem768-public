// Spec §10.4: fuzz the two input-validation checks, FIPS 203 §7.2 and §7.3.
//
// §7.2 encapsulation-key check: `ek` must be exactly 1184 bytes AND every 12-bit field must
// decode to a value below q = 3329. The modulus half is the interesting one -- it is the
// check that rejects a key whose ByteDecode would otherwise produce out-of-range
// coefficients, and a hand-built vector is the only way the unit tests reach it.
//
// §7.3 decapsulation-key check: `dk` must be exactly 2400 bytes and the embedded H(ek) must
// match a recomputed hash of the embedded ek.
//
// REACHABILITY. A uniformly random 1184-byte buffer essentially always fails the modulus
// check (each 12-bit field independently exceeds q with probability ~1/5, so a random key
// passes with probability ~(3329/4096)^1536 -- zero in practice). Fuzzing only that would
// test the rejection path and never the acceptance path. So the input carries a mode byte:
// one mode builds a VALID key from a seed and then perturbs it, which lands inputs near the
// q boundary where the check actually has to decide; the other passes fuzzer bytes through
// raw, which covers the wild-input path including wrong lengths.
//
// DIFFERENTIAL ORACLE. Our check and the model's must agree on every input, and where the
// key is accepted, encapsulation must agree byte for byte too. A check that is merely
// "not crashing" is not verified -- one that silently accepts a bad key would pass a
// crash-only fuzzer forever.

#include "kem.hpp"
#include "../model/model.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace {

using namespace mlkem768;

constexpr std::size_t kMinInput = 65;    // mode + 32 d + 32 z

[[noreturn]] void oracle_fail(const char* what, const std::uint8_t* data, std::size_t size) {
  std::fprintf(stderr, "\n=== FUZZ ORACLE MISMATCH: %s ===\ninput (%zu bytes):\n", what, size);
  for (std::size_t i = 0; i < size; ++i)
    std::fprintf(stderr, "%02x%s", data[i], ((i + 1) % 32 == 0) ? "\n" : "");
  std::fprintf(stderr, "\n");
  std::fflush(stderr);
  __builtin_trap();
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size < kMinInput) return -1;

  const std::uint8_t mode = data[0];
  std::uint8_t d[32], z[32];
  std::memcpy(d, data + 1, 32);
  std::memcpy(z, data + 33, 32);

  static std::array<std::uint8_t, EK_BYTES> ek;
  static std::array<std::uint8_t, DK_BYTES> dk;
  keygen_internal(d, z, ek.data(), dk.data());

  const std::uint8_t* tail = data + kMinInput;
  const std::size_t tail_len = size - kMinInput;

  // ---- §7.2: encapsulation key ----
  if ((mode & 1) == 0) {
    // Perturb a VALID key: this is what lands fields near the q boundary, where the
    // modulus check has to make a real decision rather than an obvious rejection.
    for (std::size_t i = 0; i + 1 < tail_len; i += 3) {
      const std::size_t off = (std::size_t(tail[i]) | (std::size_t(tail[i + 1]) << 8)) % EK_BYTES;
      ek[off] ^= (i + 2 < tail_len) ? tail[i + 2] : tail[i];
    }
  } else if (tail_len >= EK_BYTES) {
    std::memcpy(ek.data(), tail, EK_BYTES);       // wild input, raw fuzzer bytes
  }

  const bool ours_ek = check_encaps_key(ek.data(), ek.size());
  const bool model_ek = model::check_encaps_key(ek.data(), ek.size());
  if (ours_ek != model_ek) oracle_fail("check_encaps_key disagrees with the model", data, size);

  // Wrong lengths must be rejected by both, without reading past the buffer (ASan watches).
  const std::size_t short_len = tail_len ? (std::size_t(tail[0]) % EK_BYTES) : 0;
  if (check_encaps_key(ek.data(), short_len) != model::check_encaps_key(ek.data(), short_len))
    oracle_fail("check_encaps_key disagrees on a wrong length", data, size);

  // If the key is accepted, encapsulation must match the model byte for byte.
  if (ours_ek) {
    std::uint8_t m[32];
    std::memcpy(m, data + 1, 32);               // reuse d as the message; it is secret input
    std::array<std::uint8_t, CT_BYTES> ct_a{}, ct_b{};
    std::array<std::uint8_t, SS_BYTES> ss_a{}, ss_b{};
    encaps_internal(ek.data(), m, ct_a.data(), ss_a.data());
    model::encaps_internal(ek.data(), m, ct_b.data(), ss_b.data());
    if (ct_a != ct_b) oracle_fail("encaps ciphertext differs from the model", data, size);
    if (ss_a != ss_b) oracle_fail("encaps shared secret differs from the model", data, size);
  }

  // ---- §7.3: decapsulation key ----
  if ((mode & 2) != 0) {
    for (std::size_t i = 0; i + 1 < tail_len; i += 3) {
      const std::size_t off = (std::size_t(tail[i]) | (std::size_t(tail[i + 1]) << 8)) % DK_BYTES;
      dk[off] ^= (i + 2 < tail_len) ? tail[i + 2] : tail[i];
    }
  }
  const bool ours_dk = check_decaps_key(dk.data(), dk.size());
  const bool model_dk = model::check_decaps_key(dk.data(), dk.size());
  if (ours_dk != model_dk) oracle_fail("check_decaps_key disagrees with the model", data, size);

  const std::size_t short_dk = tail_len ? (std::size_t(tail[0]) % DK_BYTES) : 0;
  if (check_decaps_key(dk.data(), short_dk) != model::check_decaps_key(dk.data(), short_dk))
    oracle_fail("check_decaps_key disagrees on a wrong length", data, size);

  return 0;
}
