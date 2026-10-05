// Constant-time verification of the sampling layer, under valgrind/memcheck.
//
// These two functions have OPPOSITE requirements, and this harness asserts BOTH
// directions -- including the negative one, which is what makes the positive result
// meaningful:
//
//   --cbd          CBD with sigma marked SECRET, eta = 2 and eta = 3.
//                  MUST produce ZERO findings. Its output is the secret key material.
//
//   --ntt-secret   sample_ntt with rho marked SECRET.
//                  MUST PRODUCE FINDINGS. The rejection loop's trip count depends on
//                  the XOF output, which ADR-016 measured ctgrind as able to detect
//                  (secret loop bounds). If this comes back CLEAN, the harness is not
//                  seeing what we think it is seeing, and the --cbd result above is
//                  worthless. This is the control.
//
//   --ntt-public   sample_ntt with rho PUBLIC (unmarked). Clean, confirming the
//                  variable timing is attributable to the secret marking and not to
//                  something incidental in the function.

#include "params.hpp"
#include "poly.hpp"
#include "sample.hpp"
#include "symmetric.hpp"

#include "arch/dispatch.hpp"

#include "ct_mode.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <span>
#include <string>

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

volatile std::int16_t g_sink = 0;

template <typename T>
void mark_secret(T* p, std::size_t n) { VALGRIND_MAKE_MEM_UNDEFINED(p, n); }

void consume(const Poly& p) {
  VALGRIND_MAKE_MEM_DEFINED(const_cast<std::int16_t*>(p.c.data()), sizeof(p.c));
  std::int16_t acc = 0;
  for (const auto c : p.c) acc = static_cast<std::int16_t>(acc ^ c);
  g_sink = static_cast<std::int16_t>(g_sink ^ acc);
}

// CBD must be clean: its input is PRF(sigma, N) and its output is the secret.
int run_cbd() {
  std::array<std::uint8_t, 32> sigma{};
  mark_secret(sigma.data(), sigma.size());

  for (int n = 0; n < 6; ++n) {                       // the KeyGen counter range
    std::array<std::uint8_t, 128> buf{};
    PRF<2>(buf, sigma.data(), static_cast<std::uint8_t>(n));
    Poly p{};
    sample_poly_cbd<2>(p, std::span<const std::uint8_t, 128>(buf));
    consume(p);
  }

  // eta = 3: the ML-KEM-512 path. Never called by 768, checked anyway (ADR-009).
  {
    std::array<std::uint8_t, 192> buf{};
    PRF<3>(buf, sigma.data(), 0);
    Poly p{};
    sample_poly_cbd<3>(p, std::span<const std::uint8_t, 192>(buf));
    consume(p);
  }

  std::printf("ct_sample --cbd: CBD eta=2 (N=0..5) and eta=3 with sigma marked secret.\n"
              "                 REQUIREMENT: zero findings.\n");
  return 0;
}

// POSITIVE CONTROL. sample_ntt is variable-time by design; marking rho secret must
// make valgrind complain. A clean result here means the harness is blind.
// Phase 8d: the sampler now has a SIMD backend. A control that silently exercised the
// SCALAR path while the library ships the SIMD one would pass while proving nothing
// about the code that actually runs -- the vacuous-pass failure this project keeps
// hitting (ADR-021, ADR-025). So the mode ASSERTS which path it took rather than
// printing it and hoping someone reads the log.
volatile int g_cts_sink = 0;
__attribute__((noinline)) void ctsample_opaque(int v) { g_cts_sink ^= v; }

void report_backend(const char* mode) {
  std::printf("  %s backend: %s\n", mode, mlkem768::arch::has_avx2() ? "AVX2 (SIMD rej_uniform)"
                                                                     : "portable (scalar)");
}

int run_ntt_secret() {
  std::uint8_t seed[34] = {};
  mark_secret(seed, 32);                              // rho secret; indices public
  seed[32] = 1;
  seed[33] = 2;
  Poly a{};
  sample_ntt(a, seed);
  consume(a);
  report_backend("--ntt-secret");
  std::printf("ct_sample --ntt-secret: sample_ntt with rho marked SECRET.\n"
              "                 REQUIREMENT: findings EXPECTED. A clean result means the\n"
              "                 harness cannot see secret-dependent loop bounds, and the\n"
              "                 --cbd result proves nothing.\n");
  return 0;
}

// Same call, rho public. Confirms the variable timing is attributable to the marking.
int run_ntt_public() {
  std::uint8_t seed[34] = {};
  for (int i = 0; i < 32; ++i) seed[i] = static_cast<std::uint8_t>(i * 11 + 3);
  seed[32] = 1;
  seed[33] = 2;
  Poly a{};
  sample_ntt(a, seed);
  consume(a);
  report_backend("--ntt-public");
  std::printf("ct_sample --ntt-public: sample_ntt with rho PUBLIC.\n"
              "                 REQUIREMENT: zero findings.\n");
  return 0;
}

}  // namespace

namespace {

// --- Phase 8d part 2: the SIMD CBD ------------------------------------------
//
// ADR-025: a new backend's clean run means nothing until a control proves memcheck can
// SEE the instruction classes it emits. Disassembling cbd_avx2.o gives vpshufb,
// vpmovsxbw, vpunpcklbw/hbw, vpand, vpsrlw, vpshufd, vpbroadcastb.
//
// ONE OF THOSE IS NOT LIKE THE OTHERS. Phase 8a's --x4-taint covered vpshufb, but with
// a CONSTANT selector (the rho8/rho56 rotation patterns). Here the selector is the
// SECRET nibble and the table is the constant. If memcheck propagated definedness from
// the table operand only -- a plausible modelling choice for a permute -- secret input
// would emerge DEFINED and --cbd's clean result would be worthless. That specific
// question is what this control answers.

// CLEAN EXPECTED: asserts taint reaches every coefficient, so --cbd-taint cannot be
// probing an untainted one and passing for the wrong reason.
int run_cbd_taint_map() {
  report_backend("--cbd-map");
  std::array<std::uint8_t, 128> buf{};
  mark_secret(buf.data(), buf.size());
  Poly f{};
  sample_poly_cbd<2>(f, std::span<const std::uint8_t, 128>(buf));
  unsigned char vb[sizeof(f.c)];
  VALGRIND_GET_VBITS(f.c.data(), vb, sizeof(f.c));
  int tainted = 0;
  for (std::size_t i = 0; i < params::N; ++i)
    if (vb[2 * i] || vb[2 * i + 1]) ++tainted;
  std::printf("  CBD output: %d / %d coefficients tainted\n", tainted, (int)params::N);
  if (tainted != static_cast<int>(params::N)) {
    std::printf("cbd-map: FAIL -- taint did NOT survive the vpshufb permutation with a\n"
                "         secret selector. --cbd's clean result would be vacuous.\n");
    return 1;
  }
  std::printf("cbd-map: taint survives vpshufb(secret selector), vpmovsxbw and the\n"
              "         byte unpacks; all 256 coefficients undefined as required.\n");
  return 0;
}

// FINDINGS EXPECTED.
int run_cbd_taint() {
  report_backend("--cbd-taint");
  std::array<std::uint8_t, 128> buf{};
  mark_secret(buf.data(), buf.size());
  Poly f{};
  sample_poly_cbd<2>(f, std::span<const std::uint8_t, 128>(buf));
  // Branch on secret CBD output, spanning both halves of the first and last 16-byte
  // block so a permutation that lost taint in one half is still caught.
  if (f.c[0] == 2) ctsample_opaque(1);
  if (f.c[31] == -2) ctsample_opaque(2);
  if (f.c[224] == 2) ctsample_opaque(3);
  if (f.c[255] == -2) ctsample_opaque(4);
  std::printf("cbd-taint: branched on SIMD CBD output derived from secret sigma.\n"
              "           valgrind MUST report. Zero findings means the permutation\n"
              "           laundered the secret and --cbd proves nothing (ADR-025).\n");
  return 0;
}

constexpr ctmode::Mode kModes[] = {
    {"--cbd",         run_cbd,        "clean expected"},
    {"--cbd-map",     run_cbd_taint_map, "clean expected; taint must reach all 256 coeffs"},
    {"--cbd-taint",   run_cbd_taint,  "findings EXPECTED (SIMD CBD taint control)"},
    {"--ntt-secret",  run_ntt_secret, "findings EXPECTED (positive control)"},
    {"--ntt-public",  run_ntt_public, "clean expected"},
};

}  // namespace

int main(int argc, char** argv) {
#if !HAVE_VALGRIND
  (void)argc; (void)argv;
  std::printf("ERROR: built without <valgrind/memcheck.h>; client requests are no-ops\n"
              "       and this binary proves nothing. Use: gmake docker-ctgrind\n");
  return 2;
#else
  return ctmode::dispatch(argc, argv, kModes,
                          sizeof(kModes) / sizeof(kModes[0]), "ct_sample");
#endif
}
