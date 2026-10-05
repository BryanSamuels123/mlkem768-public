#pragma once
// Runtime CPU feature detection. Spec §9.4.
//
// The portable scalar path is the DEFAULT and must work on hardware without AVX2.
// AVX2 code lives in separate translation units compiled with -mavx2, and is reached
// only after cpuid says the CPU supports it. Nothing is built with -march=native:
// that produces binaries which SIGILL on other machines.
//
// Detection happens once, via std::call_once (spec §9.3 requires the library be
// reentrant and free of mutable global state; a once-initialized cache is fine).

namespace mlkem768::arch {

// True if the CPU supports AVX2 (and the OS has enabled YMM state saving).
[[nodiscard]] bool has_avx2() noexcept;

// Force a backend for testing. MLKEM_FORCE_ARCH=portable disables every SIMD path;
// =avx2 requires it. Read once, at first detection. Spec §9.4 asks for this override.
enum class Backend { Auto, Portable, Avx2 };
[[nodiscard]] Backend forced_backend() noexcept;

}  // namespace mlkem768::arch
