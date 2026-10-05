#pragma once
// Non-elidable secure erase. Spec §8.3, FIPS 203 §3.3.
//
// FIPS 203 §3.3: "implementers shall ensure that intermediate data is destroyed as soon
// as it is no longer needed... only the designated output can be retained in memory
// after the algorithm terminates."
//
// std::memset on a buffer that is never read again is DEAD STORE ELIMINATION bait --
// the compiler is entitled to delete it entirely, and at -O3 it does. Every mechanism
// below defeats that; which one is available is a platform question, not a style one.
//
// Spec §8.3 requires verifying the erase was not elided by DISASSEMBLY, not inspection.
// tests/unit/test_verify.cpp does that at build time via `gmake audit-zeroize`.

#include <cstddef>
#include <cstring>

namespace mlkem768 {

// Overwrite n bytes at p with zero, in a way the optimizer may not remove.
//
// ONE MECHANISM, NOT A PLATFORM LADDER. Probed on this project's two targets:
//
//   macOS 26 / Apple clang 16 : explicit_bzero NOT available.
//                               memset_s only with __STDC_WANT_LIB_EXT1__ defined
//                               before <string.h> -- fragile in a header, since any
//                               earlier include of <string.h> silently disables it.
//   Debian bookworm / glibc   : explicit_bzero available.
//
// A #if ladder would take a different path on each target, so the erase most likely to
// be elided would be the one least exercised. One mechanism on both, therefore.
//
// THE MECHANISM: a plain wide memset, followed by an empty asm barrier that takes the
// pointer as an input operand and clobbers "memory".
//
//   - memset ALONE is dead-store-elimination bait and at -O3 is deleted outright. That
//     is not a hypothetical: it is this file's negative control, and it compiles to a
//     bare `ret`.
//   - The barrier is what makes it survive. `"memory"` tells the compiler the asm may
//     read or write any memory, so the zero stores are observable and cannot be proven
//     dead; passing `p` as an `"r"` input additionally stops it reasoning that the
//     buffer never escaped. The asm emits no instructions, so it costs nothing.
//
// Measured 2026-09-29, both platforms, all six real wrap sizes, interleaved in one
// process: this runs at essentially plain-memset throughput -- up to 31x the
// byte-at-a-time volatile loop it replaces, and at or above explicit_bzero on glibc.
//
// WHAT WAS REPLACED, AND WHY NOT THE OBVIOUS SMALLER FIX. The previous implementation
// was a byte-at-a-time `volatile` write loop. Writing it as a pointer TO volatile
// instead of a volatile POINTER removes a per-byte reload, but measured only ~1.5
// vs ~1.3 B/tick: the cost is the volatile semantics themselves, which forbid merging
// the byte stores into wide ones, not the reload. Only dropping volatile entirely --
// and holding the line with the barrier instead -- gets memset speed.
//
// Spec §8.3 requires verifying non-elision by DISASSEMBLY, not inspection, and that is
// doubly true now that the survival argument rests on the barrier rather than on
// volatile. `gmake audit-zeroize` checks this function with a plain memset as the
// negative control; `gmake audit-zeroize-sites` (ADR-034) checks that the erase is
// actually emitted at all 27 Zeroizing<T> wrap sites. Both must stay green.
inline void secure_zero(void* p, std::size_t n) noexcept {
  if (p == nullptr || n == 0) return;
  std::memset(p, 0, n);
  asm volatile("" : : "r"(p) : "memory");
}

// RAII wrapper for a stack-resident secret. Non-copyable and non-movable: a copy would
// leave a second, un-erased instance behind, which defeats the purpose.
template <typename T>
struct Zeroizing {
  T value{};

  Zeroizing() = default;
  explicit Zeroizing(const T& v) : value(v) {}
  ~Zeroizing() { secure_zero(&value, sizeof(T)); }

  Zeroizing(const Zeroizing&) = delete;
  Zeroizing& operator=(const Zeroizing&) = delete;
  Zeroizing(Zeroizing&&) = delete;
  Zeroizing& operator=(Zeroizing&&) = delete;

  T* operator->() noexcept { return &value; }
  T& operator*() noexcept { return value; }
  const T& operator*() const noexcept { return value; }
};

}  // namespace mlkem768
