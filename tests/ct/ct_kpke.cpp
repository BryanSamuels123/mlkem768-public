// Constant-time verification of K-PKE, under valgrind/memcheck.
//
// Four modes. The last is a POSITIVE CONTROL on the real path, and without it the three
// clean results prove nothing (`docs/reference/invariants.md` (testing philosophy)).
//
//   --keygen-secret-d      d SECRET.                     clean expected
//   --encrypt-secret-mr    m and r SECRET, ek public.    clean expected
//   --decrypt-secret-dk    dk SECRET, c public.          clean expected
//   --encrypt-secret-ek    ek SECRET.                    FINDINGS EXPECTED
//
// The control works because kpke_encrypt re-expands A_hat from rho, and rho lives in the
// last 32 bytes of ek. sample_ntt's rejection loop then has a trip count that depends on
// secret-marked data -- the leak class ADR-016 measured ctgrind as able to detect. If
// that comes back clean, ctgrind is not watching this code path and the three clean
// results above are worthless.
//
// ek is PUBLIC in real use (spec §8.1), so the control is a deliberate lie about
// classification, not a claim that the implementation is wrong.

#include "kpke.hpp"
#include "params.hpp"

#include "ct_mode.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>

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

void fill(std::uint8_t* p, std::size_t n, std::uint8_t seed) {
  for (std::size_t i = 0; i < n; ++i)
    p[i] = static_cast<std::uint8_t>(seed + i * 31u);
}

// Alg. 13. d is SECRET. rho is derived from it but becomes public in ek; sample_ntt's
// variable timing on rho is therefore correct and must NOT show up here -- which it
// does not, because the marking is on d and rho is a G() output that memcheck tracks
// as derived-but-defined once written into ek.
int keygen_secret_d() {
  std::uint8_t d[32];
  fill(d, sizeof d, 0x11);
  mark_secret(d, sizeof d);

  std::array<std::uint8_t, params::EK_PKE_BYTES> ek{};
  std::array<std::uint8_t, params::DK_PKE_BYTES> dk{};
  kpke_keygen(ek.data(), dk.data(), d);
  consume(ek.data(), ek.size());
  consume(dk.data(), dk.size());
  std::printf("  kpke_keygen with d SECRET. REQUIREMENT: zero findings.\n");
  return 0;
}

// Alg. 14. m and r are SECRET; ek is PUBLIC.
int encrypt_secret_mr() {
  std::uint8_t d[32], m[32], r[32];
  fill(d, sizeof d, 0x22);
  fill(m, sizeof m, 0x33);
  fill(r, sizeof r, 0x44);

  std::array<std::uint8_t, params::EK_PKE_BYTES> ek{};
  std::array<std::uint8_t, params::DK_PKE_BYTES> dk{};
  kpke_keygen(ek.data(), dk.data(), d);          // d NOT marked: ek must stay public

  mark_secret(m, sizeof m);
  mark_secret(r, sizeof r);

  std::array<std::uint8_t, params::CT_BYTES> c{};
  kpke_encrypt(c.data(), ek.data(), m, r);
  consume(c.data(), c.size());
  std::printf("  kpke_encrypt with m and r SECRET, ek public. "
              "REQUIREMENT: zero findings.\n");
  return 0;
}

// Alg. 15. dk is SECRET; c is PUBLIC; the recovered m is SECRET.
int decrypt_secret_dk() {
  std::uint8_t d[32], m[32], r[32];
  fill(d, sizeof d, 0x55);
  fill(m, sizeof m, 0x66);
  fill(r, sizeof r, 0x77);

  std::array<std::uint8_t, params::EK_PKE_BYTES> ek{};
  std::array<std::uint8_t, params::DK_PKE_BYTES> dk{};
  kpke_keygen(ek.data(), dk.data(), d);
  std::array<std::uint8_t, params::CT_BYTES> c{};
  kpke_encrypt(c.data(), ek.data(), m, r);

  mark_secret(dk.data(), dk.size());

  std::uint8_t out[32];
  kpke_decrypt(out, dk.data(), c.data());
  consume(out, sizeof out);
  std::printf("  kpke_decrypt with dk SECRET, c public. "
              "REQUIREMENT: zero findings.\n");
  return 0;
}

// WAS a positive control in Phase 6a; is now CLEAN BY CONSTRUCTION. Kept, repurposed,
// and documented rather than deleted, because the reason it changed is the point.
//
// Phase 6b's ADR-021 added MLKEM_CT_DECLASSIFY(rho, 32) on entry to kpke_encrypt, to fix
// decaps_internal's re-encrypt path. That declassification also silences THIS control:
// marking ek secret no longer taints rho, so sample_ntt no longer fires. The control did
// not break -- it became vacuous, which is worse, because a vacuous control still prints
// OK if you only check for "clean".
//
// A DECLASSIFICATION CAN SILENCE A POSITIVE CONTROL. That is the hazard ADR-020 and
// ADR-021 warn about, arriving on this project's own gate. It was caught only because
// ct_expect_findings requires exit 99 specifically -- a "nonzero" check would have
// reported OK forever.
//
// sample_ntt's watchability is still PROVEN, by ct_sample --ntt-secret, which marks rho
// directly and never passes through kpke_encrypt. That control is unaffected and still
// returns 99.
int encrypt_secret_ek() {
  std::uint8_t d[32], m[32], r[32];
  fill(d, sizeof d, 0x88);
  fill(m, sizeof m, 0x99);
  fill(r, sizeof r, 0xAA);

  std::array<std::uint8_t, params::EK_PKE_BYTES> ek{};
  std::array<std::uint8_t, params::DK_PKE_BYTES> dk{};
  kpke_keygen(ek.data(), dk.data(), d);

  mark_secret(ek.data(), ek.size());             // the deliberate misclassification

  std::array<std::uint8_t, params::CT_BYTES> c{};
  kpke_encrypt(c.data(), ek.data(), m, r);
  consume(c.data(), c.size());
  std::printf("  kpke_encrypt with ek SECRET. rho is DECLASSIFIED here (ADR-021), so\n"
              "  this is now CLEAN BY CONSTRUCTION and is no longer a control.\n"
              "  sample_ntt's watchability is proven by ct_sample --ntt-secret instead.\n"
              "  REQUIREMENT: zero findings.\n");
  return 0;
}

// ---------------------------------------------------------------------------
// AUDIT ADDITIONS (Phase 8c). Two gaps found by auditing the Phase 6 controls for
// unverified assumptions -- the same class of defect that --ntt-taint had.
//
// GAP 1: THIS FILE HAD NO POSITIVE CONTROL AT ALL. The ctgrind-run header said
// "three clean modes + a control on the real path", but all four K-PKE modes were
// clean-expected. The control it referred to was --encrypt-secret-ek, which ADR-021's
// rho declassification converted from findings-expected into clean-expected. `docs/reference/invariants.md`
// records that it "did not fail, it became vacuous" -- and the repair at the time
// preserved the mode but left K-PKE with nothing that proves ctgrind can SEE a leak on
// this path. Four clean results and no demonstration the tool can fail is not evidence.
//
// GAP 2: the clean results assumed, and never checked, that secret marking actually
// REACHES the K-PKE computation. If taint were lost on the way in, all four would pass
// for the wrong reason.
//
// Both are now measured rather than argued.
// ---------------------------------------------------------------------------

volatile int g_leak_sink = 0;
__attribute__((noinline)) void opaque(int v) { g_leak_sink ^= v; }

int tainted_bytes(const void* p, std::size_t n) {
  unsigned char vb[params::EK_PKE_BYTES > params::CT_BYTES ? params::EK_PKE_BYTES
                                                           : params::CT_BYTES];
  VALGRIND_GET_VBITS(p, vb, n);
  int t = 0;
  for (std::size_t i = 0; i < n; ++i) if (vb[i]) ++t;
  return t;
}

// CLEAN EXPECTED. Asserts that secret input actually propagates to every K-PKE output,
// and -- the sharper half -- that the declassified region is EXACTLY the 32-byte rho
// window and not one byte more.
//
// ADR-020 and ADR-021 both hinge on "exactly 32 bytes, and never sigma". Until now that
// was prose. VALGRIND_GET_VBITS makes it machine-checked: ek must come back tainted
// everywhere except offsets [POLYVEC_BYTES, EK_PKE_BYTES), which is rho. If a future
// change widened the declassification by even one byte, this fails and names the range.
int kpke_taint_map() {
  int bad = 0;

  std::uint8_t d[32];
  fill(d, sizeof d, 0x11);
  mark_secret(d, sizeof d);
  std::array<std::uint8_t, params::EK_PKE_BYTES> ek{};
  std::array<std::uint8_t, params::DK_PKE_BYTES> dk{};
  kpke_keygen(ek.data(), dk.data(), d);

  const int tdk = tainted_bytes(dk.data(), dk.size());
  std::printf("  dk_PKE              %5d / %5zu tainted\n", tdk, dk.size());
  if (tdk != static_cast<int>(dk.size())) { std::printf("    *** dk not fully tainted\n"); ++bad; }

  // Locate the declassified window rather than just counting it.
  unsigned char vb[params::EK_PKE_BYTES];
  VALGRIND_GET_VBITS(ek.data(), vb, ek.size());
  int first = -1, last = -1, ndef = 0;
  for (std::size_t i = 0; i < ek.size(); ++i)
    if (!vb[i]) { if (first < 0) first = static_cast<int>(i); last = static_cast<int>(i); ++ndef; }
  std::printf("  ek_PKE declassified %5d bytes at [%d .. %d]  (rho window is [%d .. %d])\n",
              ndef, first, last, static_cast<int>(params::POLYVEC_BYTES),
              static_cast<int>(params::EK_PKE_BYTES) - 1);
  if (ndef != 32 || first != static_cast<int>(params::POLYVEC_BYTES) ||
      last != static_cast<int>(params::EK_PKE_BYTES) - 1) {
    std::printf("    *** declassified region is NOT exactly the rho window (ADR-020/021)\n");
    ++bad;
  }

  std::uint8_t m[32], r[32];
  fill(m, sizeof m, 0x33); fill(r, sizeof r, 0x44);
  mark_secret(m, sizeof m); mark_secret(r, sizeof r);
  std::array<std::uint8_t, params::CT_BYTES> c{};
  kpke_encrypt(c.data(), ek.data(), m, r);
  const int tc = tainted_bytes(c.data(), c.size());
  std::printf("  ciphertext          %5d / %5zu tainted\n", tc, c.size());
  if (tc != static_cast<int>(c.size())) { std::printf("    *** ciphertext not fully tainted\n"); ++bad; }

  if (bad) {
    std::printf("kpke-taint-map: FAIL -- a clean result from the other modes would be\n"
                "                vacuous, not reassuring (the ADR-021 failure mode).\n");
    return 1;
  }
  std::printf("kpke-taint-map: secret input reaches every output; declassification is\n"
              "                exactly the 32-byte rho window.\n");
  return 0;
}

// FINDINGS EXPECTED -- the positive control this file was missing.
//
// Runs the REAL kpke_keygen with d secret, then branches on the resulting dk_PKE while
// it is still secret. valgrind must report. This is what licenses reading the four clean
// modes as evidence: it demonstrates the tool fails on this specific code path, with
// this specific secret marking, rather than on a synthetic one elsewhere.
int keygen_leak_control() {
  std::uint8_t d[32];
  fill(d, sizeof d, 0x11);
  mark_secret(d, sizeof d);
  std::array<std::uint8_t, params::EK_PKE_BYTES> ek{};
  std::array<std::uint8_t, params::DK_PKE_BYTES> dk{};
  kpke_keygen(ek.data(), dk.data(), d);

  // Deliberate secret-dependent branches, spread across dk so a partial-taint
  // regression is caught too. Not declassified first -- that is the point.
  for (std::size_t i = 0; i < dk.size(); i += 257)
    if (dk[i] == 0x5A) { opaque(static_cast<int>(i)); break; }

  std::printf("kpke-leak: branched on dk_PKE derived from secret d, on the REAL\n"
              "           kpke_keygen path. valgrind MUST report. Zero findings means\n"
              "           K-PKE's four clean modes prove nothing -- this file had no\n"
              "           positive control at all until Phase 8c's audit.\n");
  return 0;
}

// --- Phase 8d part 3: SIMD compress, and Compress_1 specifically ------------
//
// ADR-025. compress_avx2.o emits classes no earlier control covered: vpmuldq (64-bit
// multiply), vpmulld, vpmovzxwd, vpackusdw (a SATURATING pack -- a plausible candidate
// for being modelled as producing defined output), vpinsrw/vpextrw, vpaddd/vpslld/vpsrld.
// The existing --taint-map already asserts the ciphertext comes back 1088/1088 tainted
// with m and r secret, and the ciphertext IS the SIMD compress output, so that assertion
// now doubles as the taint-survival proof for those classes. It is re-run after this
// change rather than assumed to still hold.
//
// COMPRESS_1 GETS ITS OWN CONTROL. It sits inside poly_tomsg and its output is m', the
// DECRYPTED MESSAGE -- the most sensitive value in decaps, and the one an attacker most
// wants. Inheriting coverage from the general compress test would leave the project
// unable to say it had checked that specific path. It stays scalar (d=1 is 243 ticks,
// below the measurement floor; ADR-029 forbids adding CT surface on secret data for
// nothing), but the control is required regardless of which backend runs it.

// CLEAN EXPECTED: taint must reach every byte of the decrypted message.
int tomsg_taint_map() {
  std::uint8_t d[32];
  fill(d, sizeof d, 0x5A);
  std::array<std::uint8_t, params::EK_PKE_BYTES> ek{};
  std::array<std::uint8_t, params::DK_PKE_BYTES> dk{};
  kpke_keygen(ek.data(), dk.data(), d);
  std::uint8_t m0[32];
  fill(m0, sizeof m0, 0x3C);
  std::array<std::uint8_t, params::CT_BYTES> c{};
  kpke_encrypt(c.data(), ek.data(), m0, m0);

  mark_secret(dk.data(), dk.size());
  std::uint8_t out[32];
  kpke_decrypt(out, dk.data(), c.data());

  const int t = tainted_bytes(out, sizeof out);
  std::printf("  m' out of poly_tomsg (Compress_1): %d / 32 bytes tainted\n", t);
  if (t != 32) {
    std::printf("tomsg-map: FAIL -- the DECRYPTED MESSAGE is not fully tainted, so any\n"
                "           clean run on this path is vacuous. m' is the most sensitive\n"
                "           value in decaps.\n");
    return 1;
  }
  std::printf("tomsg-map: all 32 bytes of m' tainted.\n");
  return 0;
}

// FINDINGS EXPECTED -- the dedicated Compress_1 control.
int tomsg_leak_control() {
  std::uint8_t d[32];
  fill(d, sizeof d, 0x5A);
  std::array<std::uint8_t, params::EK_PKE_BYTES> ek{};
  std::array<std::uint8_t, params::DK_PKE_BYTES> dk{};
  kpke_keygen(ek.data(), dk.data(), d);
  std::uint8_t m0[32];
  fill(m0, sizeof m0, 0x3C);
  std::array<std::uint8_t, params::CT_BYTES> c{};
  kpke_encrypt(c.data(), ek.data(), m0, m0);

  mark_secret(dk.data(), dk.size());
  std::uint8_t out[32];
  kpke_decrypt(out, dk.data(), c.data());

  // Branch on the decrypted message while still secret, across all four 8-byte words.
  for (int i = 0; i < 32; i += 8)
    if (out[i] == 0x5A) { opaque(i); break; }

  std::printf("tomsg-leak: branched on m', the decrypted message, straight out of\n"
              "            Compress_1 on the real kpke_decrypt path. valgrind MUST\n"
              "            report. Zero findings means the most sensitive value in the\n"
              "            scheme is invisible to the CT gate.\n");
  return 0;
}

constexpr ctmode::Mode kModes[] = {
    {"--taint-map",   kpke_taint_map,      "clean expected; asserts taint reaches outputs + rho window exact"},
    {"--tomsg-map",   tomsg_taint_map,     "clean expected; m' fully tainted out of Compress_1"},
    {"--tomsg-leak",  tomsg_leak_control,  "findings EXPECTED (Compress_1 / m' control)"},
    {"--keygen-leak", keygen_leak_control, "findings EXPECTED (the K-PKE positive control)"},
    {"--keygen-secret-d",   keygen_secret_d,   "clean expected"},
    {"--encrypt-secret-mr", encrypt_secret_mr, "clean expected"},
    {"--decrypt-secret-dk", decrypt_secret_dk, "clean expected"},
    {"--encrypt-secret-ek", encrypt_secret_ek, "clean expected (rho declassified, ADR-021)"},
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
                          sizeof(kModes) / sizeof(kModes[0]), "ct_kpke");
#endif
}
