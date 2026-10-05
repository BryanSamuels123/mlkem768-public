// Constant-time verification of ML-KEM, under valgrind/memcheck.
//
//   --keygen-secret-dz    d and z SECRET.              clean expected
//   --encaps-secret-m     m SECRET, ek public.         clean expected
//   --decaps-secret-dk    dk SECRET, c public.         clean expected
//   --decaps-memcmp       a memcmp-based decaps.       FINDINGS EXPECTED
//
// The last mode is the POSITIVE CONTROL and the whole point of the phase. It replays
// Decaps_internal with std::memcmp in place of ct_neq -- failure mode #10, the mistake
// that passes every functional test and fails every security review. ADR-016 measured
// the early-exit compare as a shape ctgrind detects, so this MUST produce findings.
// If it does not, the three clean results prove nothing.
//
// Per `docs/reference/invariants.md` (testing philosophy), the control is checked for SURVIVAL: `gmake ctgrind-run`
// disassembles it first and requires a real byte-compare loop, because a memcmp the
// compiler turned into a constant would be a control that proves nothing.

#include "kem.hpp"
#include "kpke.hpp"
#include "params.hpp"
#include "symmetric.hpp"

#include "ct_mode.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <span>

#if __has_include(<valgrind/memcheck.h>)
#include <valgrind/memcheck.h>
#define HAVE_VALGRIND 1
#else
#define HAVE_VALGRIND 0
#define VALGRIND_MAKE_MEM_UNDEFINED(p, n) ((void)(p), (void)(n))
#define VALGRIND_MAKE_MEM_DEFINED(p, n) ((void)(p), (void)(n))
#endif

using namespace mlkem768;

namespace {

volatile std::uint8_t g_sink = 0;

template <typename T>
void mark_secret(T* p, std::size_t n) { VALGRIND_MAKE_MEM_UNDEFINED(p, n); }

void consume(const std::uint8_t* p, std::size_t n) {
  VALGRIND_MAKE_MEM_DEFINED(const_cast<std::uint8_t*>(p), n);
  std::uint8_t a = 0;
  for (std::size_t i = 0; i < n; ++i) a = static_cast<std::uint8_t>(a ^ p[i]);
  g_sink = static_cast<std::uint8_t>(g_sink ^ a);
}

void fill(std::uint8_t* p, std::size_t n, std::uint8_t s) {
  for (std::size_t i = 0; i < n; ++i) p[i] = static_cast<std::uint8_t>(s + i * 31u);
}

struct Keypair {
  std::array<std::uint8_t, EK_BYTES> ek{};
  std::array<std::uint8_t, DK_BYTES> dk{};
};

Keypair make_keys(std::uint8_t s) {
  Keypair kp;
  std::uint8_t d[32], z[32];
  fill(d, sizeof d, s);
  fill(z, sizeof z, static_cast<std::uint8_t>(s + 7));
  keygen_internal(d, z, kp.ek.data(), kp.dk.data());
  return kp;
}

int keygen_secret_dz() {
  std::uint8_t d[32], z[32];
  fill(d, sizeof d, 0x11);
  fill(z, sizeof z, 0x22);
  mark_secret(d, sizeof d);
  mark_secret(z, sizeof z);
  std::array<std::uint8_t, EK_BYTES> ek{};
  std::array<std::uint8_t, DK_BYTES> dk{};
  keygen_internal(d, z, ek.data(), dk.data());
  consume(ek.data(), ek.size());
  consume(dk.data(), dk.size());
  std::printf("  keygen_internal with d and z SECRET. REQUIREMENT: zero findings.\n");
  return 0;
}

int encaps_secret_m() {
  const Keypair kp = make_keys(0x33);
  std::uint8_t m[32];
  fill(m, sizeof m, 0x44);
  mark_secret(m, sizeof m);
  std::array<std::uint8_t, CT_BYTES> c{};
  std::array<std::uint8_t, 32> k{};
  encaps_internal(kp.ek.data(), m, c.data(), k.data());
  consume(c.data(), c.size());
  consume(k.data(), k.size());
  std::printf("  encaps_internal with m SECRET, ek public. REQUIREMENT: zero findings.\n");
  return 0;
}

// dk SECRET, both the valid and the rejecting path.
int decaps_secret_dk() {
  Keypair kp = make_keys(0x55);
  std::uint8_t m[32];
  fill(m, sizeof m, 0x66);
  std::array<std::uint8_t, CT_BYTES> c{};
  std::array<std::uint8_t, 32> k{};
  encaps_internal(kp.ek.data(), m, c.data(), k.data());

  mark_secret(kp.dk.data(), kp.dk.size());

  std::array<std::uint8_t, 32> out{};
  decaps_internal(kp.dk.data(), c.data(), out.data());   // valid
  consume(out.data(), out.size());

  auto bad = c;
  bad[123] ^= 0x01;
  decaps_internal(kp.dk.data(), bad.data(), out.data()); // rejecting
  consume(out.data(), out.size());

  std::printf("  decaps_internal with dk SECRET, valid AND rejecting paths.\n"
              "  REQUIREMENT: zero findings.\n");
  return 0;
}

// ---------------------------------------------------------------------------
// POSITIVE CONTROL: the memcmp mistake (failure mode #10).
//
// Marked noinline so it survives as its own symbol for the survival check.
// ---------------------------------------------------------------------------
[[gnu::noinline]] int decaps_via_memcmp(const std::uint8_t* dk, const std::uint8_t* ct,
                                        std::uint8_t* ss) {
  const std::uint8_t* dk_pke = dk;
  const std::uint8_t* ek_pke = dk + params::DK_PKE_BYTES;
  const std::uint8_t* h = dk + params::DK_PKE_BYTES + EK_BYTES;
  const std::uint8_t* z = h + 32;

  std::array<std::uint8_t, 32> m_prime{};
  kpke_decrypt(m_prime.data(), dk_pke, ct);

  std::array<std::uint8_t, 64> gin{}, gout{};
  std::memcpy(gin.data(), m_prime.data(), 32);
  std::memcpy(gin.data() + 32, h, 32);
  G(gout.data(), gin);

  std::array<std::uint8_t, 32 + CT_BYTES> jin{};
  std::memcpy(jin.data(), z, 32);
  std::memcpy(jin.data() + 32, ct, CT_BYTES);
  std::array<std::uint8_t, 32> k_bar{};
  J(k_bar.data(), jin);

  std::array<std::uint8_t, CT_BYTES> c_prime{};
  kpke_encrypt(c_prime.data(), ek_pke, m_prime.data(), gout.data() + 32);

  // THE PLANTED MISTAKE. std::memcmp short-circuits on the first differing byte, so the
  // running time depends on WHERE the ciphertexts diverge -- and that position is a
  // function of secret data. This is exactly what ct_neq exists to prevent.
  if (std::memcmp(ct, c_prime.data(), CT_BYTES) != 0)
    std::memcpy(gout.data(), k_bar.data(), 32);

  std::memcpy(ss, gout.data(), 32);
  return 0;
}

int decaps_memcmp_control() {
  Keypair kp = make_keys(0x77);
  std::uint8_t m[32];
  fill(m, sizeof m, 0x88);
  std::array<std::uint8_t, CT_BYTES> c{};
  std::array<std::uint8_t, 32> k{};
  encaps_internal(kp.ek.data(), m, c.data(), k.data());

  mark_secret(kp.dk.data(), kp.dk.size());

  std::array<std::uint8_t, 32> out{};
  decaps_via_memcmp(kp.dk.data(), c.data(), out.data());
  consume(out.data(), out.size());

  std::printf("  decaps via std::memcmp with dk SECRET (failure mode #10).\n"
              "  REQUIREMENT: findings EXPECTED. A clean result means ctgrind is not\n"
              "  watching the comparison and the three clean modes prove nothing.\n");
  return 0;
}

constexpr ctmode::Mode kModes[] = {
    {"--keygen-secret-dz", keygen_secret_dz,       "clean expected"},
    {"--encaps-secret-m",  encaps_secret_m,        "clean expected"},
    {"--decaps-secret-dk", decaps_secret_dk,       "clean expected"},
    {"--decaps-memcmp",    decaps_memcmp_control,  "findings EXPECTED (positive control)"},
};

}  // namespace

int main(int argc, char** argv) {
#if !HAVE_VALGRIND
  (void)argc; (void)argv;
  std::printf("ERROR: built without <valgrind/memcheck.h>; use gmake docker-ctgrind\n");
  return 2;
#else
  return ctmode::dispatch(argc, argv, kModes,
                          sizeof(kModes) / sizeof(kModes[0]), "ct_kem");
#endif
}
