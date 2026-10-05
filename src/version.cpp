#include "mlkem/version.hpp"

namespace mlkem768 {

namespace {
constexpr const char kVersion[] = "0.1.0";
}

const char* version() noexcept { return kVersion; }

}  // namespace mlkem768
