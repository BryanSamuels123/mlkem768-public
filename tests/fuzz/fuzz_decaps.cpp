// Spec §10.4: fuzz decapsulation. libFuzzer entry point.
//
// TWO THINGS THIS DOES THAT A NAIVE FUZZER WOULD NOT.
//
// 1. REACHABILITY. Feeding 1088 random bytes to `decaps` as a ciphertext tests almost
//    nothing: without a matching decapsulation key the input dies at the length or key
//    check, so the fuzzer spends its whole budget on the first few lines. A fuzzer whose
//    inputs mostly fail the first check only tests the first check.
//
//    So a VALID key pair is DERIVED from the fuzzer's own bytes -- 32 bytes of `d` and 32
//    of `z` through `keygen_internal` -- and a VALID ciphertext is produced by
//    encapsulating against it. Every input therefore reaches ByteDecode, decompression,
//    the NTT, the inner product, Compress_1, the full re-encryption, the ciphertext
//    comparison, and implicit rejection.
//
//    TWO MUTATION MODES, and the first version had only the second, which cost it a
//    control. Mode OVERLAY copies the fuzzer's bytes DIRECTLY over the ciphertext; mode
//    PATCH applies sparse XORs at fuzzer-chosen offsets. Only OVERLAY gives the fuzzer
//    direct control of specific ciphertext byte VALUES, which is what lets libFuzzer's
//    comparison tracing drive a byte-pattern-triggered branch. With PATCH alone, hitting
//    a chosen value at a chosen offset is a blind ~1-in-278,000 search per mutation pair,
//    and a planted out-of-bounds read guarded by a 2-byte pattern SURVIVED 400,000 runs
//    undetected. Both modes are kept: PATCH explores near-valid ciphertexts, which is
//    where decryption's noise margin lives, and OVERLAY explores the byte-value space.
//
//    Reachability does not depend on the ciphertext being valid: `decaps` has no validity
//    precheck beyond length, so ANY 1088-byte ciphertext runs the whole path. Validity
//    only decides accept versus implicit-reject, and the seeded corpus covers accept.
//
// 2. A DIFFERENTIAL ORACLE, not just crash-finding. Every input is also run through the
//    golden model, and the two 32-byte shared secrets must match EXACTLY. This matters
//    more here than anywhere else in the project: `docs/reference/invariants.md` records that the decrypt path
//    has no KAT coverage, because Compress_1's rounding absorbs small errors and the
//    re-encryption then reproduces a matching ciphertext. Almost every fuzzed ciphertext
//    implicitly rejects, and the result must equal the model's J(z || c) byte for byte --
//    which turns the fuzzer into a correctness check on exactly the path KATs cannot see.
//
// A crash is a finding. An oracle mismatch is equally a finding, and is reported with the
// input that produced it rather than swallowed.

#include "kem.hpp"
#include "../model/model.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <array>

namespace {

using namespace mlkem768;

// Layout of the fuzzer's bytes. Anything shorter than kMinInput is rejected so the fuzzer
// learns the useful shape quickly.
//   [0,32)    d      -> keygen
//   [32,64)   z      -> keygen
//   [64,96)   m      -> encaps, giving a valid ciphertext
//   [96]      mode   -> bit 0 selects OVERLAY (direct bytes) vs PATCH (sparse XOR)
//   [97, ...) mutation payload
constexpr std::size_t kMinInput = 97;

[[noreturn]] void oracle_fail(const char* what,
                             const std::uint8_t* data, std::size_t size,
                             const std::uint8_t* ours, const std::uint8_t* model) {
  std::fprintf(stderr, "\n=== FUZZ ORACLE MISMATCH: %s ===\n", what);
  std::fprintf(stderr, "input (%zu bytes):\n", size);
  for (std::size_t i = 0; i < size; ++i)
    std::fprintf(stderr, "%02x%s", data[i], ((i + 1) % 32 == 0) ? "\n" : "");
  std::fprintf(stderr, "\nours : ");
  for (int i = 0; i < 32; ++i) std::fprintf(stderr, "%02x", ours[i]);
  std::fprintf(stderr, "\nmodel: ");
  for (int i = 0; i < 32; ++i) std::fprintf(stderr, "%02x", model[i]);
  std::fprintf(stderr, "\n");
  std::fflush(stderr);
  __builtin_trap();          // libFuzzer records the crashing input
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size < kMinInput) return -1;          // -1: do not add to the corpus

  std::uint8_t d[32], z[32], m[32];
  std::memcpy(d, data, 32);
  std::memcpy(z, data + 32, 32);
  std::memcpy(m, data + 64, 32);

  // A real key pair and a real ciphertext, both derived from fuzzer bytes.
  static std::array<std::uint8_t, EK_BYTES> ek;
  static std::array<std::uint8_t, DK_BYTES> dk;
  static std::array<std::uint8_t, CT_BYTES> ct;
  std::array<std::uint8_t, SS_BYTES> ss_enc{};
  keygen_internal(d, z, ek.data(), dk.data());
  encaps_internal(ek.data(), m, ct.data(), ss_enc.data());

  // Perturb the ciphertext. Kept well-sized on purpose: a wrong LENGTH is covered by the
  // unit tests and would only re-test the length check here.
  const std::uint8_t mode = data[96];
  const std::uint8_t* tail = data + kMinInput;
  const std::size_t tail_len = size - kMinInput;

  if ((mode & 1) != 0) {
    // OVERLAY: the fuzzer writes ciphertext bytes directly, so comparison tracing can
    // drive a value-guarded branch instead of searching blindly.
    const std::size_t n = (tail_len < CT_BYTES) ? tail_len : CT_BYTES;
    std::memcpy(ct.data(), tail, n);
  } else {
    // PATCH: sparse XORs, which keeps the ciphertext near-valid.
    for (std::size_t i = 0; i + 1 < tail_len; i += 3) {
      const std::size_t off =
          (std::size_t(tail[i]) | (std::size_t(tail[i + 1]) << 8)) % CT_BYTES;
      ct[off] ^= (i + 2 < tail_len) ? tail[i + 2] : tail[i];
    }
  }

  std::array<std::uint8_t, SS_BYTES> ours{}, theirs{};
  decaps_internal(dk.data(), ct.data(), ours.data());
  model::decaps_internal(dk.data(), ct.data(), theirs.data());

  if (std::memcmp(ours.data(), theirs.data(), SS_BYTES) != 0)
    oracle_fail("decaps shared secret differs from the golden model",
                data, size, ours.data(), theirs.data());

  // Also exercise the public entry point, which adds the length and key checks.
  std::array<std::uint8_t, SS_BYTES> pub{};
  const Status st = decaps(dk.data(), dk.size(), ct.data(), ct.size(), pub.data());
  if (st == Status::Ok && std::memcmp(pub.data(), ours.data(), SS_BYTES) != 0)
    oracle_fail("public decaps disagrees with decaps_internal",
                data, size, pub.data(), ours.data());

  return 0;
}
