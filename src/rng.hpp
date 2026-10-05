#pragma once
// Random bit generation. FIPS 203 §3.3 requires an approved RBG with at least
// 192-bit security strength for ML-KEM-768, and requires the seeds be generated
// BY THE CRYPTOGRAPHIC MODULE.
//
// NOT AN SP 800-90 VALIDATED RBG. This defaults to the operating system CSPRNG, which
// is a sound engineering choice and is NOT a validated DRBG construction. See README.
// A caller needing validation injects their own via set_rng().
//
// THREAD SAFETY (spec §9.3): the default is thread-safe -- getentropy/arc4random_buf
// and getrandom are all safe to call concurrently. An INJECTED rng must be thread-safe
// or per-thread; a non-thread-safe RBG shared across threads is a catastrophic, silent
// security bug, so the contract is stated here and in the public header.

#include <cstddef>
#include <cstdint>
#include <span>

namespace mlkem768 {

// Returns false on failure. FIPS 203 Alg. 19/20 require an explicit error path when
// random generation fails -- it is not optional.
using RngFn = bool (*)(std::span<std::uint8_t> out, void* ctx) noexcept;

// Install a custom RBG. Passing nullptr restores the OS default.
//
// THE INJECTED RBG MUST BE THREAD-SAFE OR PER-THREAD. This requirement does NOT depend on
// the batch API, which is excluded (ADR-036): callers are free to use this library from
// several threads themselves, and the library is reentrant with no mutable global state
// apart from this hook. A non-thread-safe RBG shared across threads is a catastrophic,
// SILENT security bug -- it can repeat randomness without any visible failure, and
// repeated randomness in KeyGen or Encaps breaks the scheme outright.
//
// `set_rng` itself is not synchronised: install the hook once, before any threads that
// use the library exist.
void set_rng(RngFn fn, void* ctx) noexcept;

// Fill out with random bytes using the installed RBG. Returns false on failure.
[[nodiscard]] bool randombytes(std::span<std::uint8_t> out) noexcept;

}  // namespace mlkem768
