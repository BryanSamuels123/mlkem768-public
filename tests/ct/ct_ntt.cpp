// Constant-time verification of the NTT, and -- separately and first -- verification
// that ctgrind can SEE the instruction classes the AVX2 NTT is built from.
//
// WHY THIS FILE EXISTS SEPARATELY FROM ct_sample.cpp. ct_sample's --ntt-secret concerns
// SampleNTT, the rejection sampler, which is variable-time by design. This file concerns
// the NTT transform itself, which operates on s, e, y, and dk and MUST be constant-time.
// Different function, opposite requirement.
//
// WHY THE TAINT CONTROL IS NOT OPTIONAL (ADR-025). The Phase 8a --x4-taint control
// proved definedness survives the 4-way Keccak's instruction set -- gathers, xors,
// 64-bit shifts, pshufb, perm2f128. Keccak-f contains NO MULTIPLY, so that proof says
// nothing about vpmullw / vpmulhw / vpsraw, and nothing about vpshufd / vpunpck*qdq /
// vperm2i128. Those are exactly what the AVX2 NTT is made of: Montgomery multiply is
// mulhi+mullo, Barrett is mulhi+srai, and the three intra-vector layers are shuffles.
//
// If memcheck modelled any of those as producing DEFINED output from undefined input,
// the clean run below would be clean for the wrong reason. ADR-025 therefore forbids
// citing the 8a control here and requires this one.

#include "ntt.hpp"
#include "poly.hpp"
#include "arch/dispatch.hpp"

#include "ct_mode.hpp"

#include <cstdio>
#include <cstdint>

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

volatile int g_sink = 0;
__attribute__((noinline)) void opaque(int v) { g_sink ^= v; }

void mark_secret(void* p, std::size_t n) { VALGRIND_MAKE_MEM_UNDEFINED(p, n); }

void consume(Poly& f) {
  VALGRIND_MAKE_MEM_DEFINED(f.c.data(), sizeof(f.c));
  int a = 0;
  for (auto c : f.c) a ^= c;
  g_sink ^= a;
}

Poly secret_poly() {
  Poly f{};
  for (std::size_t i = 0; i < f.c.size(); ++i) f.c[i] = static_cast<std::int16_t>((i % 7) - 3);
  mark_secret(f.c.data(), sizeof(f.c));
  return f;
}

// CLEAN EXPECTED: the transform on secret coefficients. s-hat, e-hat, y-hat and the
// decrypt path all run this on key material.
int run_secret() {
  std::printf("  backend: %s\n", arch::has_avx2() ? "AVX2" : "portable");
  Poly a = secret_poly();
  ntt(a);
  consume(a);
  Poly b = secret_poly();
  invntt(b);
  consume(b);
  Poly c = secret_poly();
  ntt(c);
  invntt(c);
  consume(c);
  std::printf("  ran ntt/invntt with SECRET coefficients. REQUIREMENT: zero findings.\n");
  return 0;
}

// POSITIVE CONTROL -- taint survival through multiply and shuffle.
//
// Mark a polynomial secret, transform it, then branch on outputs while still secret.
//
// WHICH COEFFICIENTS TO PROBE WAS MEASURED, NOT ASSUMED. An earlier version of this
// comment claimed coefficients 0, 255 and 7 "span both 128-bit lanes". That was wrong:
// coefficient 7 is lane 7 of vector 0, the SAME 128-bit half as coefficient 0, so the
// span rested entirely on 255. Reading memcheck's shadow directly with VALGRIND_GET_VBITS
// (see --taint-map below) shows the question is moot TODAY -- all 256 outputs of both
// transforms are tainted, so any single probe point would do.
//
// The probe points below are still chosen to span the layout, because "all 256 are
// tainted" is a property of the current implementation, not a law: a future change could
// make propagation incomplete. 0 and 8 are the two halves of vector 0; 248 and 255 are
// the two halves of vector 15. --taint-map is what keeps the assumption honest.
// valgrind MUST report.
int taint_control() {
  std::printf("  backend: %s\n", arch::has_avx2() ? "AVX2" : "portable");
  Poly a = secret_poly();
  ntt(a);                                   // vpmullw/vpmulhw/vpsraw + all three shuffles
  if (a.c[0]   == 1234)  opaque(1);         // vector 0,  low  128-bit half
  if (a.c[8]   == -1234) opaque(2);         // vector 0,  high 128-bit half
  if (a.c[248] == 555)   opaque(3);         // vector 15, low  half
  if (a.c[255] == -555)  opaque(4);         // vector 15, high half

  Poly b = secret_poly();
  invntt(b);                                // the Gentleman-Sande direction as well
  if (b.c[0]   == 99)  opaque(5);
  if (b.c[8]   == -99) opaque(6);
  if (b.c[255] == 77)  opaque(7);

  std::printf("ntt-taint: branched on ntt() and invntt() output derived from a SECRET\n"
              "           polynomial, at coefficients spanning both 128-bit halves of\n"
              "           the first and last vectors, in BOTH directions. MUST report.\n"
              "           Zero findings means memcheck lost definedness through the\n"
              "           packed multiplies or the lane shuffles, and the clean result\n"
              "           from --secret is vacuous rather than reassuring (ADR-025).\n");
  return 0;
}

// Reads memcheck's definedness shadow directly (no error emitted) and REQUIRES every
// one of the 256 output coefficients to be tainted, in both directions.
//
// This exists because the control above used to rest on an unverified claim about which
// coefficients land in which lane. Rather than restate the claim more carefully, this
// measures the thing the claim was about. If a future change makes taint propagation
// incomplete -- a removed reduction, a different shuffle -- this fails and says how many
// coefficients and which vectors, instead of the control quietly probing a clean lane.
int taint_map() {
  std::printf("  backend: %s\n", arch::has_avx2() ? "AVX2" : "portable");
  int worst = 256;
  for (int dir = 0; dir < 2; ++dir) {
    Poly f = secret_poly();
    if (dir == 0) ntt(f); else invntt(f);
    unsigned char vb[2 * 256];
    VALGRIND_GET_VBITS(f.c.data(), vb, sizeof(f.c));
    int tainted = 0, vecs[16] = {0};
    for (int i = 0; i < 256; ++i)
      if (vb[2 * i] != 0 || vb[2 * i + 1] != 0) { ++tainted; vecs[i / 16]++; }
    int vhit = 0; for (int v = 0; v < 16; ++v) if (vecs[v]) ++vhit;
    std::printf("  %-7s tainted %3d/256, vectors hit %2d/16\n",
                dir == 0 ? "ntt" : "invntt", tainted, vhit);
    if (tainted < worst) worst = tainted;
  }
  if (worst != 256) {
    std::printf("taint-map: FAIL -- propagation is INCOMPLETE. The --ntt-taint control\n"
                "           may be probing coefficients that are no longer tainted, in\n"
                "           which case a clean --secret run proves nothing (ADR-025).\n");
    return 1;
  }
  std::printf("taint-map: all 256 coefficients tainted in both directions.\n");
  return 0;
}

// --- Phase 8e: AVX2 basemul ------------------------------------------------
//
// ADR-025. basemul_avx2.o emits two classes no earlier control covered:
// vpunpcklwd / vpunpckhwd -- 16-BIT unpacks, where Phase 8d's --cbd-map covered only the
// BYTE variants vpunpcklbw/hbw -- and vpermq (permute4x64). Both are used to deinterleave
// the degree-1 pair halves and put them back, on SECRET s-hat and y-hat.
//
// A cross-lane permute is a plausible candidate for being modelled as producing defined
// output, which would make a clean run on basemul vacuous. Measured rather than assumed.

int basemul_taint_map() {
  std::printf("  backend: %s\n", arch::has_avx2() ? "AVX2" : "portable");
  Poly a = secret_poly(), b = secret_poly(), r{};
  poly_basemul(r, a, b);
  unsigned char vb[sizeof(r.c)];
  VALGRIND_GET_VBITS(r.c.data(), vb, sizeof(r.c));
  int t = 0;
  for (int i = 0; i < params::N; ++i) if (vb[2 * i] || vb[2 * i + 1]) ++t;
  std::printf("  basemul output: %d / %d coefficients tainted\n", t, (int)params::N);
  if (t != params::N) {
    std::printf("basemul-map: FAIL -- taint did not survive the deinterleave permutes\n"
                "             (vpunpcklwd/vpunpckhwd/vpermq). A clean basemul run would\n"
                "             be vacuous.\n");
    return 1;
  }
  std::printf("basemul-map: taint survives the 16-bit unpacks and the cross-lane permute.\n");
  return 0;
}

int basemul_taint_control() {
  std::printf("  backend: %s\n", arch::has_avx2() ? "AVX2" : "portable");
  Poly a = secret_poly(), b = secret_poly(), r{};
  poly_basemul(r, a, b);
  // Probe both halves of the first and last group, and both parities -- a permute that
  // lost taint on only the even or only the odd lanes must still be caught.
  if (r.c[0]   == 111) opaque(1);
  if (r.c[1]   == 222) opaque(2);
  if (r.c[254] == 333) opaque(3);
  if (r.c[255] == 444) opaque(4);
  Poly acc{};
  poly_basemul_acc(acc, a, b);
  if (acc.c[128] == 555) opaque(5);
  std::printf("basemul-taint: branched on basemul and basemul_acc output derived from\n"
              "               secret polynomials, both parities, both ends. MUST report.\n");
  return 0;
}

constexpr ctmode::Mode kModes[] = {
    {"--secret",     run_secret,     "clean expected"},
    {"--ntt-taint",  taint_control,  "findings EXPECTED (multiply/shuffle taint control)"},
    {"--taint-map",  taint_map,      "clean expected; asserts 256/256 coefficients tainted"},
    {"--basemul-map",   basemul_taint_map,     "clean expected; basemul output fully tainted"},
    {"--basemul-taint", basemul_taint_control, "findings EXPECTED (basemul permute control)"},
};

}  // namespace

int main(int argc, char** argv) {
#if !HAVE_VALGRIND
  (void)argc; (void)argv;
  std::printf("ERROR: built without <valgrind/memcheck.h>. Run: gmake docker-ctgrind\n");
  return 2;
#else
  return ctmode::dispatch(argc, argv, kModes, sizeof(kModes) / sizeof(kModes[0]), "ct_ntt");
#endif
}
