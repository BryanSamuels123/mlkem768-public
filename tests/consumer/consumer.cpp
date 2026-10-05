// The consumer test: what an actual user of the installed library can do.
//
// THIS IS DELIBERATELY BUILT AGAINST THE INSTALLED TREE, NOT THE SOURCE TREE. It is
// compiled with only -I<prefix>/include and linked against <prefix>/lib/libmlkem768.a,
// with nothing from src/ on the include path. That restriction is the whole point: every
// other test in this project includes headers straight out of src/, so none of them can
// tell whether `make install` actually ships a usable API.
//
// It did not. When this test was first written, `include/mlkem/` contained only
// version.hpp and the declarations lived in src/kem.hpp, which is not installed -- so an
// installed library exposed no API at all and every existing test passed anyway. This file
// exists so that gap cannot reappear silently.
//
// It uses ONLY the public header. If it ever needs something from src/, that is a finding
// about the public API, not a reason to widen the include path.

#include <mlkem/mlkem768.hpp>

#include <cstdio>
#include <cstring>

namespace {

int failures = 0;

void check(bool ok, const char* what) {
  std::printf("  %-52s %s\n", what, ok ? "ok" : "FAIL");
  if (!ok) ++failures;
}

}  // namespace

int main() {
  std::printf("=== consumer test: installed tree only ===\n");
  std::printf("  header  : <mlkem/mlkem768.hpp>\n");
  std::printf("  library : libmlkem768.a\n\n");

  // The sizes a caller needs in order to allocate anything must come from the header.
  check(mlkem768::EK_BYTES == 1184, "EK_BYTES == 1184");
  check(mlkem768::DK_BYTES == 2400, "DK_BYTES == 2400");
  check(mlkem768::CT_BYTES == 1088, "CT_BYTES == 1088");
  check(mlkem768::SS_BYTES == 32, "SS_BYTES == 32");

  mlkem768::EncapsKey ek{};
  mlkem768::DecapsKey dk{};
  mlkem768::Ciphertext ct{};
  mlkem768::SharedSecret ss_a{}, ss_b{};

  // --- the round trip, which is the thing a user cares about ---
  check(mlkem768::keygen(ek, dk) == mlkem768::Status::Ok, "keygen returns Ok");
  check(mlkem768::encaps(ek, ct, ss_a) == mlkem768::Status::Ok, "encaps returns Ok");
  check(mlkem768::decaps(dk, ct, ss_b) == mlkem768::Status::Ok, "decaps returns Ok");
  check(ss_a == ss_b, "the two shared secrets match");

  // A shared secret of all zeros would compare equal above while meaning nothing happened.
  bool nonzero = false;
  for (auto b : ss_a) nonzero = nonzero || (b != 0);
  check(nonzero, "the shared secret is not all zeros");

  // --- validation helpers are part of the public surface ---
  check(mlkem768::check_encaps_key(ek), "check_encaps_key accepts a real key");
  check(mlkem768::check_decaps_key(dk), "check_decaps_key accepts a real key");

  // --- a corrupted ciphertext must decapsulate to something ELSE, not error ---
  // Implicit rejection is silent by design: a well-sized but invalid ciphertext returns Ok
  // with a different shared secret. A user relying on an error code here would be wrong,
  // so the public behaviour is pinned down.
  mlkem768::Ciphertext bad = ct;
  bad[0] ^= 0x01;
  mlkem768::SharedSecret ss_bad{};
  check(mlkem768::decaps(dk, bad, ss_bad) == mlkem768::Status::Ok,
        "decaps(corrupt ct) still returns Ok (implicit rejection)");
  check(!(ss_bad == ss_a), "corrupt ciphertext yields a different shared secret");

  // --- two independent keys must not interoperate ---
  mlkem768::EncapsKey ek2{};
  mlkem768::DecapsKey dk2{};
  check(mlkem768::keygen(ek2, dk2) == mlkem768::Status::Ok, "second keygen returns Ok");
  check(!(ek == ek2), "two keygens produce different keys");
  mlkem768::SharedSecret ss_wrong{};
  // Decapsulating with an unrelated key is not an error either -- same implicit-rejection
  // rule -- so the status is Ok and only the secret differs.
  check(mlkem768::decaps(dk2, ct, ss_wrong) == mlkem768::Status::Ok,
        "decaps with an unrelated key returns Ok");
  check(!(ss_wrong == ss_a), "the wrong key yields a different shared secret");

  std::printf("\n");
  if (failures == 0) {
    std::printf("consumer test: PASS -- the installed tree is usable on its own.\n");
    return 0;
  }
  std::printf("consumer test: FAIL (%d check(s))\n", failures);
  return 1;
}
