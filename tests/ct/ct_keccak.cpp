// Constant-time verification of the symmetric layer, under valgrind/memcheck.
//
// WHY THIS RUNS IN PHASE 3 AND NOT PHASE 9. This is the first layer where SECRET data
// flows through third-party code. PRF_eta(sigma, N) and PRF_eta(r, N) take secret seeds;
// G(d || k) and J(z || c) take secret d and z. Everything before now was either our own
// code or operated on public data. If the vendored Keccak had a data-dependent branch or
// table lookup, six phases would be built on it before Phase 9 noticed.
//
// METHOD (ctgrind, spec §8.4). Secret buffers are marked UNDEFINED with a valgrind
// client request. Memcheck then reports any conditional jump or memory address that
// depends on them. Zero errors is the gate.
//
// The harness verifies ITSELF: `--selftest` deliberately branches on a secret and must
// make valgrind report. A CT harness that cannot detect a leak is worse than none,
// because it looks like evidence.

#include "symmetric.hpp"

#include "ct_mode.hpp"

#include <array>
#include <cstdio>
#include <cstring>
#include <cstdint>
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

// Mark a buffer as secret: any branch or address derived from it is an error.
template <typename T>
void mark_secret(T* p, std::size_t n) {
  VALGRIND_MAKE_MEM_UNDEFINED(p, n);
}

// Declassify: the value is allowed to be observed from here on. Used only on OUTPUTS
// that the harness must consume to stop the optimizer deleting the call -- never to
// silence a finding inside the code under test.
template <typename T>
void declassify(T* p, std::size_t n) {
  VALGRIND_MAKE_MEM_DEFINED(p, n);
}

volatile std::uint8_t g_sink = 0;

void consume(const std::uint8_t* p, std::size_t n) {
  declassify(const_cast<std::uint8_t*>(p), n);
  std::uint8_t acc = 0;
  for (std::size_t i = 0; i < n; ++i) acc = static_cast<std::uint8_t>(acc ^ p[i]);
  g_sink = static_cast<std::uint8_t>(g_sink ^ acc);
}

// --- the actual checks ----------------------------------------------------

// PRF_eta(sigma, N). sigma is SECRET: K-PKE.KeyGen lines 9 and 13.
void check_prf_eta2() {
  std::array<std::uint8_t, 32> sigma{};
  mark_secret(sigma.data(), sigma.size());
  for (int n = 0; n < 6; ++n) {                    // N = 0..5, the KeyGen counter range
    std::array<std::uint8_t, 128> out{};
    PRF<2>(out, sigma.data(), static_cast<std::uint8_t>(n));
    consume(out.data(), out.size());
  }
}

// The ML-KEM-512 eta1 path. Exercised even though 768 never calls it (ADR-009).
void check_prf_eta3() {
  std::array<std::uint8_t, 32> sigma{};
  mark_secret(sigma.data(), sigma.size());
  std::array<std::uint8_t, 192> out{};
  PRF<3>(out, sigma.data(), 0);
  consume(out.data(), out.size());
}

// PRF_eta(r, N). r is SECRET: K-PKE.Encrypt lines 10, 14, 17.
void check_prf_encrypt_coins() {
  std::array<std::uint8_t, 32> r{};
  mark_secret(r.data(), r.size());
  for (int n = 0; n < 7; ++n) {                    // N = 0..6, the Encrypt counter range
    std::array<std::uint8_t, 128> out{};
    PRF<2>(out, r.data(), static_cast<std::uint8_t>(n));
    consume(out.data(), out.size());
  }
}

// G(d || k). d is SECRET (K-PKE.KeyGen line 1).
void check_g_keygen_seed() {
  std::array<std::uint8_t, 33> in{};
  mark_secret(in.data(), 32);                      // d secret; the k byte is public
  in[32] = 3;
  std::array<std::uint8_t, 64> out{};
  G(out.data(), in);
  consume(out.data(), out.size());
}

// G(m || H(ek)). m is SECRET (Encaps_internal line 1).
void check_g_encaps() {
  std::array<std::uint8_t, 64> in{};
  mark_secret(in.data(), 32);                      // m secret; H(ek) public
  std::array<std::uint8_t, 64> out{};
  G(out.data(), in);
  consume(out.data(), out.size());
}

// J(z || c). z is SECRET (Decaps_internal line 7). c is public.
void check_j_implicit_reject() {
  std::array<std::uint8_t, 32 + 1088> in{};
  mark_secret(in.data(), 32);                      // z secret; ciphertext public
  std::array<std::uint8_t, 32> out{};
  J(out.data(), in);
  consume(out.data(), out.size());
}

// Control: H(ek) is entirely public. Included so a failure here would indicate the
// harness itself is broken rather than a real leak.
void check_h_public() {
  std::array<std::uint8_t, 1184> ek{};
  std::array<std::uint8_t, 32> out{};
  H(out.data(), ek);
  consume(out.data(), out.size());
}

// Control: the XOF input is PUBLIC (rho || j || i) and sample_ntt is deliberately
// variable-time (spec §8.1). Exercised to confirm the wrapper does not accidentally
// touch secret state.
void check_xof_public() {
  std::uint8_t seed[34] = {};
  Xof x;
  xof_init_absorb(x, seed);
  std::array<std::uint8_t, 504> out{};
  xof_squeeze(x, out.data(), out.size());
  consume(out.data(), out.size());
}

// --- self-test: prove the harness can actually SEE a leak ------------------
//
// WHAT CTGRIND CAN AND CANNOT SEE. Measured in the container at -O3, not assumed:
//
//   DETECTED  secret-dependent memory index (table[secret])         <- the classic leak
//   DETECTED  secret-dependent loop bound  (for i < secret)
//   DETECTED  early-exit loop on secret    (the memcmp pattern)     <- Phase 6 ct_neq
//   NOT SEEN  a simple `if (secret & 1)` -- clang flattens it to a branchless select
//             at -O3, so there is no conditional jump left to observe. (It is then
//             genuinely constant-time, but do not rely on the optimizer for that.)
//   NOT SEEN  secret-dependent `div`/`mod` -- valgrind models values, not TIMING, so
//             variable-latency instructions are invisible to it entirely.
//
// The last line is the important one: `docs/reference/invariants.md`'s ban on integer div/mod over secrets
// CANNOT be enforced by this tool and must be held by review, and by dudect in Phase 9.
// ctgrind and dudect are complementary, not redundant.
//
// The self-test therefore plants one leak of each DETECTABLE class. All three must fire.

__attribute__((noinline)) void opaque(int v) {
  g_sink = static_cast<std::uint8_t>(g_sink ^ v);
}

int selftest() {
  std::array<std::uint8_t, 32> secret{};
  mark_secret(secret.data(), secret.size());

  // 1. Secret-dependent memory index.
  static const std::uint8_t table[256] = {};
  g_sink = static_cast<std::uint8_t>(g_sink ^ table[secret[0]]);

  // 2. Secret-dependent loop bound.
  for (int i = 0; i < (secret[1] & 7); ++i) opaque(i);

  // 3. Early exit on a secret comparison -- exactly the memcmp shape that
  //    Phase 6's ct_neq must avoid in Decaps_internal.
  for (int i = 0; i < 32; ++i) {
    if (secret[i] == 0x5A) { opaque(i); break; }
  }

  std::printf("selftest: planted 3 leaks (secret memory index, secret loop bound,\n"
              "          early-exit compare). valgrind MUST report all of them.\n"
              "          Zero errors means the CT harness is blind and every other\n"
              "          result from it is worthless.\n");
  return 0;
}

}  // namespace

namespace {

// --- Phase 8a: the 4-WAY batched path -------------------------------------
//
// PRF_x4 and xof_x4 route secret material through AVX2 code that the scalar checks
// above never touch: a `vpgatherqq` transpose on absorb, 24 rounds on __m256i lanes,
// and a movlps/movhps scatter on squeeze. Those are different instructions, so the
// Phase 3 result does not transfer by argument -- it has to be re-run here.
//
// Dispatch is runtime, so WHICHEVER backend this container selects is the one tested.
// Under valgrind that is the AVX2 one (checked: valgrind's emulated CPUID reports AVX2).

// PRF_x4(sigma, N) -- the batched form of K-PKE.KeyGen lines 9 and 13.
void check_prf_x4_secret() {
  std::array<std::uint8_t, 32> sigma{};
  mark_secret(sigma.data(), sigma.size());
  std::array<std::uint8_t, 128> a{}, b{}, c{}, d{};
  PRF_x4<2>(a, b, c, d, sigma.data(), 0, 1, 2, 3);
  consume(a.data(), a.size()); consume(b.data(), b.size());
  consume(c.data(), c.size()); consume(d.data(), d.size());

  std::array<std::uint8_t, 192> e{}, f{}, g{}, h{};
  PRF_x4<3>(e, f, g, h, sigma.data(), 0, 1, 2, 3);   // ADR-009's eta1 != eta2 path
  consume(e.data(), e.size()); consume(f.data(), f.size());
  consume(g.data(), g.size()); consume(h.data(), h.size());
}

// xof_x4 on PUBLIC seeds -- the gen_matrix shape. Public, so clean is expected for the
// same reason sample_ntt's rejection loop is allowed to branch (ADR-016 / sample.hpp).
void check_xof_x4_public() {
  std::uint8_t sd[4][34]{};
  for (int k = 0; k < 4; ++k) { sd[k][32] = static_cast<std::uint8_t>(k); sd[k][33] = 0; }
  alignas(64) std::uint8_t st[XOF4_STATE_BYTES];
  std::array<std::uint8_t, XOF_RATE> o0{}, o1{}, o2{}, o3{};
  xof_x4_absorb_squeeze(sd[0], sd[1], sd[2], sd[3],
                        o0.data(), o1.data(), o2.data(), o3.data(), 1, st);
  consume(o0.data(), o0.size()); consume(o1.data(), o1.size());
  consume(o2.data(), o2.size()); consume(o3.data(), o3.size());
}

// POSITIVE CONTROL FOR THE 4-WAY PATH, and it checks something specific:
// that undefinedness SURVIVES the AVX2 gather/permute/scatter chain.
//
// This is not paranoia. memcheck tracks definedness per bit through emulated
// instructions; if it modelled `vpgatherqq` or the 256-bit lane permutes as producing
// defined output, then secret input would emerge DEFINED on the far side and
// check_prf_x4_secret() above would report zero findings for the wrong reason --
// a vacuous pass, which this project has been bitten by before (ADR-021).
//
// So: mark sigma secret, run it through the batched path, and then branch on the
// output while it is still secret. valgrind MUST report. If it does not, taint was
// lost inside the 4-way code and every clean result from that path is worthless.
//
// NARROWNESS (ADR-025): this proves taint survives only the instruction classes the
// vendored 4-way code emits -- gather, xor/andn/or, 64-bit shifts, pshufb, perm2f128,
// punpcklqdq, and the movsd/movq scatter. Keccak-f has NO multiply, so vpmullw/vpmulhw/
// vpsraw are OUTSIDE this evidence. A future SIMD backend built on those (the AVX2 NTT
// is) needs its OWN control; it may not cite this one.
int x4_taint_control() {
  std::array<std::uint8_t, 32> sigma{};
  mark_secret(sigma.data(), sigma.size());
  std::array<std::uint8_t, 128> a{}, b{}, c{}, d{};
  PRF_x4<2>(a, b, c, d, sigma.data(), 0, 1, 2, 3);

  // Deliberate secret-dependent branch on 4-way OUTPUT. Not declassified first.
  for (int i = 0; i < 128; ++i) {
    if (a[static_cast<std::size_t>(i)] == 0x5A) { opaque(i); break; }
  }
  // Same on the last lane, so a backend that only taints lane 0 is also caught.
  for (int i = 0; i < 128; ++i) {
    if (d[static_cast<std::size_t>(i)] == 0xA5) { opaque(i); break; }
  }

  std::printf("x4-taint: branched on PRF_x4 output derived from secret sigma, on\n"
              "          lanes 0 and 3. valgrind MUST report both. Zero findings\n"
              "          means memcheck lost definedness through the AVX2 gather/\n"
              "          permute/scatter chain, and every clean result on the 4-way\n"
              "          path is vacuous rather than reassuring.\n");
  return 0;
}

// The clean-expected mode: all the secret-marked wrappers in one run.
int run_secrets() {
  check_prf_eta2();
  check_prf_eta3();
  check_prf_encrypt_coins();
  check_g_keygen_seed();
  check_g_encaps();
  check_j_implicit_reject();
  check_h_public();
  check_xof_public();
  check_prf_x4_secret();      // Phase 8a: the batched path, same secret marking
  check_xof_x4_public();
  std::printf("  exercised PRF<2>, PRF<3>, G, J with secret inputs, plus\n"
              "  public-input controls H and XOF, plus the Phase 8a 4-WAY path\n"
              "  (PRF_x4<2>, PRF_x4<3> secret; xof_x4 public).\n"
              "  REQUIREMENT: zero findings.\n");
  return 0;
}

// Phase 8c audit: the --x4-taint control probes lanes 0 and 3, chosen by reasoning that
// "a backend that taints only lane 0 is also caught". That was never measured. This does
// measure it: all four lanes must come back fully tainted. If a future backend change
// made propagation lane-dependent, --x4-taint could probe a clean lane and still pass.
int x4_taint_map() {
  std::array<std::uint8_t, 32> sigma{};
  mark_secret(sigma.data(), sigma.size());
  std::array<std::uint8_t, 128> a{}, b{}, c{}, d{};
  PRF_x4<2>(a, b, c, d, sigma.data(), 0, 1, 2, 3);
  const std::array<std::uint8_t, 128>* lanes[4] = {&a, &b, &c, &d};
  int bad = 0;
  for (int l = 0; l < 4; ++l) {
    unsigned char vb[128];
    VALGRIND_GET_VBITS(lanes[l]->data(), vb, 128);
    int t = 0; for (int i = 0; i < 128; ++i) if (vb[i]) ++t;
    std::printf("  PRF_x4 lane %d  %3d / 128 tainted\n", l, t);
    if (t != 128) ++bad;
  }
  if (bad) {
    std::printf("x4-taint-map: FAIL -- propagation is lane-dependent; --x4-taint may be\n"
                "              probing a clean lane and passing for the wrong reason.\n");
    return 1;
  }
  std::printf("x4-taint-map: all four lanes fully tainted.\n");
  return 0;
}

constexpr ctmode::Mode kModes[] = {
    {"--secrets",   run_secrets,       "clean expected"},
    {"--selftest",  selftest,          "findings EXPECTED (positive control)"},
    {"--x4-taint",  x4_taint_control,  "findings EXPECTED (4-way taint-survival control)"},
    {"--x4-map",    x4_taint_map,      "clean expected; asserts all 4 lanes fully tainted"},
};

}  // namespace

int main(int argc, char** argv) {
#if !HAVE_VALGRIND
  (void)argc; (void)argv;
  std::printf("ERROR: built without <valgrind/memcheck.h>; the client requests are\n"
              "       no-ops and this binary proves nothing. Run it in the Linux\n"
              "       container: gmake docker-ctgrind\n");
  return 2;
#else
  return ctmode::dispatch(argc, argv, kModes,
                          sizeof(kModes) / sizeof(kModes[0]), "ct_keccak");
#endif
}
