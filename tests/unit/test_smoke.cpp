// Phase 0 smoke test. Its job is to prove the build and test wiring work end to end:
// the library compiles under the strict flag set, the test TU compiles under the
// relaxed one (doctest needs exceptions), and the two link together.
//
// Real tests arrive from Phase 2 onward.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "mlkem/version.hpp"

#include <cstdint>
#include <string_view>

TEST_CASE("library links and reports a version") {
    const std::string_view v = mlkem768::version();
    CHECK(!v.empty());

    // Deliberately NOT pinned to a literal. It was ("0.0.0-phase0"), and the Phase 10b
    // bump to 0.1.0 then failed a 2-billion-assertion test-deep run for a reason that had
    // nothing to do with correctness -- which is noise in the one gate whose failures must
    // always be taken seriously. What is worth asserting is the SHAPE: a version the
    // packaging step can put in a tarball name, i.e. major.minor.patch with an optional
    // pre-release suffix. `gmake package` reads the same string out of src/version.cpp, so
    // a malformed version breaks the package name, and this catches it first.
    CHECK(v.find('.') != std::string_view::npos);
    std::size_t dots = 0;
    for (const char c : v) {
        const bool ok = (c >= '0' && c <= '9') || c == '.' || c == '-' ||
                        (c >= 'a' && c <= 'z');
        CHECK(ok);
        if (c == '.') ++dots;
    }
    CHECK(dots >= 2);                       // major.minor.patch
    CHECK(v[0] >= '0');
    CHECK(v[0] <= '9');                     // must start with a digit
}

TEST_CASE("parameter set is ML-KEM-768") {
    CHECK(mlkem768::PARAMETER_SET_K == 3);
}

TEST_CASE("toolchain has the integer properties the implementation assumes") {
    // The NTT stores coefficients as int16_t and relies on wrapping two's-complement
    // semantics and a 16-bit width. Assert rather than discover this at Phase 2.
    CHECK(sizeof(std::int16_t) == 2);
    CHECK(static_cast<std::int16_t>(-1) == ~static_cast<std::int16_t>(0));

    // q^-1 mod 2^16, derived by Newton iteration in unsigned arithmetic.
    // Signed overflow here is UB and is rejected in a constant expression.
    constexpr std::uint32_t kQ = 3329;
    std::uint32_t qinv = 1;
    for (int i = 0; i < 5; ++i) qinv *= 2u - kQ * qinv;
    CHECK((qinv * kQ) % 65536u == 1u);
    CHECK(static_cast<std::uint16_t>(qinv) == 62209u);
}
