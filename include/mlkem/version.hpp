#pragma once

// Phase 0 placeholder. The real public API (mlkem768.hpp) lands in Phase 6 — see
// docs/spec/MLKEM768_SPEC.md §3. This header exists so that the library build rules,
// the strict library flag set, and `make package` are exercised from Phase 0 onward
// rather than being debugged for the first time at Phase 10.

namespace mlkem768 {

// Returns "major.minor.patch". Never null.
[[nodiscard]] const char* version() noexcept;

// Compile-time parameter-set identity, so a linked binary can assert which set it got.
inline constexpr int PARAMETER_SET_K = 3;  // ML-KEM-768

}  // namespace mlkem768
