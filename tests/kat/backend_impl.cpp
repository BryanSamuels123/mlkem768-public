// KAT backend: the REAL implementation. Drives `gmake kat` (Phase 7 correctness gate).
//
// Mirrors backend_model.cpp exactly. kat_main.cpp is NOT forked -- the harness has been
// backend-agnostic since Phase 1 and this is the two-line rule that pays that design off.
//
// The harness calls the _internal entry points, so Algorithms 19-21 are not on the KAT
// path. check_encaps_key / check_decaps_key ARE, via the encapsulationKeyCheck and
// decapsulationKeyCheck groups.
//
// Built only with MLKEM_ENABLE_INTERNAL_API=1 (spec §3.1): FIPS 203 §3.3 says the
// _internal interfaces "should not be made available to applications other than for
// testing purposes", so the default `gmake` build must not expose them.

#include "kat_backend.hpp"

#include "kem.hpp"

#ifndef MLKEM_ENABLE_INTERNAL_API
#error "backend_impl.cpp requires MLKEM_ENABLE_INTERNAL_API=1 (spec §3.1)"
#endif

namespace mlkem768::kat {
namespace {

void keygen(const std::uint8_t d[32], const std::uint8_t z[32],
            std::uint8_t* ek, std::uint8_t* dk) {
  mlkem768::keygen_internal(d, z, ek, dk);
}
void encaps(const std::uint8_t* ek, const std::uint8_t m[32],
            std::uint8_t* ct, std::uint8_t* ss) {
  mlkem768::encaps_internal(ek, m, ct, ss);
}
void decaps(const std::uint8_t* dk, const std::uint8_t* ct, std::uint8_t* ss) {
  mlkem768::decaps_internal(dk, ct, ss);
}
bool check_ek(const std::uint8_t* ek, std::size_t len) {
  return mlkem768::check_encaps_key(ek, len);
}
bool check_dk(const std::uint8_t* dk, std::size_t len) {
  return mlkem768::check_decaps_key(dk, len);
}

// The name is load-bearing: kat_main.cpp prints it, and the Makefile ASSERTS on it so a
// build that silently linked backend_model.o cannot pass `gmake kat` while testing
// nothing about the real library. See the ct-style banner check in the kat target.
constexpr Backend kImplBackend{
    "real implementation", keygen, encaps, decaps, check_ek, check_dk,
};

}  // namespace

const Backend& backend() { return kImplBackend; }

}  // namespace mlkem768::kat
