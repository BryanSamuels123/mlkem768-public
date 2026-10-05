// KAT backend: the golden model. Drives `make kat-model` (Phase 1 exit criterion).
#include "kat_backend.hpp"
#include "model.hpp"

namespace mlkem768::kat {
namespace {

void keygen(const std::uint8_t d[32], const std::uint8_t z[32],
            std::uint8_t* ek, std::uint8_t* dk) {
  model::keygen_internal(d, z, ek, dk);
}
void encaps(const std::uint8_t* ek, const std::uint8_t m[32],
            std::uint8_t* ct, std::uint8_t* ss) {
  model::encaps_internal(ek, m, ct, ss);
}
void decaps(const std::uint8_t* dk, const std::uint8_t* ct, std::uint8_t* ss) {
  model::decaps_internal(dk, ct, ss);
}
bool check_ek(const std::uint8_t* ek, std::size_t len) {
  return model::check_encaps_key(ek, len);
}
bool check_dk(const std::uint8_t* dk, std::size_t len) {
  return model::check_decaps_key(dk, len);
}

constexpr Backend kModelBackend{
    "golden model", keygen, encaps, decaps, check_ek, check_dk,
};

}  // namespace

const Backend& backend() { return kModelBackend; }

}  // namespace mlkem768::kat
