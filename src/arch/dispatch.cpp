#include "dispatch.hpp"

#include <cstdlib>
#include <cstring>
#include <mutex>

#if defined(__x86_64__) || defined(_M_X64)
#include <cpuid.h>
#endif

namespace mlkem768::arch {
namespace {

bool detect_avx2() noexcept {
#if defined(__x86_64__) || defined(_M_X64)
  unsigned eax, ebx, ecx, edx;

  // AVX2 is CPUID leaf 7, sub-leaf 0, EBX bit 5.
  if (__get_cpuid_max(0, nullptr) < 7) return false;
  if (!__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) return false;
  const bool cpu_avx2 = (ebx & (1u << 5)) != 0;
  if (!cpu_avx2) return false;

  // CPU support is not enough: the OS must also have enabled XSAVE of the YMM state,
  // or the registers are not preserved across context switches and using them faults.
  // Leaf 1 ECX bit 27 = OSXSAVE, bit 28 = AVX.
  if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx)) return false;
  const bool osxsave = (ecx & (1u << 27)) != 0;
  const bool avx = (ecx & (1u << 28)) != 0;
  if (!osxsave || !avx) return false;

  // XCR0 bits 1 (SSE) and 2 (YMM) must both be set.
  //
  // Inline asm rather than the _xgetbv intrinsic: this TU is compiled at BASELINE
  // (no -mavx2, no -mxsave) precisely because it must run on a CPU that may lack
  // those features. The intrinsic requires the xsave target feature at compile time,
  // which would defeat the point of a runtime check.
  unsigned int xcr_lo, xcr_hi;
  __asm__ volatile("xgetbv" : "=a"(xcr_lo), "=d"(xcr_hi) : "c"(0));
  const unsigned long long xcr0 = (static_cast<unsigned long long>(xcr_hi) << 32) | xcr_lo;
  return (xcr0 & 0x6ull) == 0x6ull;
#else
  return false;
#endif
}

Backend read_forced() noexcept {
  const char* e = std::getenv("MLKEM_FORCE_ARCH");
  if (e == nullptr) return Backend::Auto;
  if (std::strcmp(e, "portable") == 0) return Backend::Portable;
  if (std::strcmp(e, "avx2") == 0) return Backend::Avx2;
  return Backend::Auto;
}

std::once_flag g_once;
bool g_has_avx2 = false;
Backend g_forced = Backend::Auto;

void init() noexcept {
  g_forced = read_forced();
  const bool detected = detect_avx2();
  switch (g_forced) {
    case Backend::Portable: g_has_avx2 = false; break;
    case Backend::Avx2:     g_has_avx2 = detected; break;   // never claim what the CPU lacks
    case Backend::Auto:     g_has_avx2 = detected; break;
  }
}

}  // namespace

bool has_avx2() noexcept {
  std::call_once(g_once, init);
  return g_has_avx2;
}

Backend forced_backend() noexcept {
  std::call_once(g_once, init);
  return g_forced;
}

}  // namespace mlkem768::arch
