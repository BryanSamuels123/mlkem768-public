#pragma once
// Constant-time comparison and conditional move. Spec §8.2.
//
// These exist because `memcmp` in Decaps_internal is failure mode #10: it passes every
// functional test and fails every security review. ADR-016 measured that ctgrind DOES
// detect the early-exit compare shape, so a mistake here is catchable -- and Phase 6b
// plants exactly that mistake as a positive control.
//
// THE COMPILER IS THE ADVERSARY HERE. At -O3 clang will happily turn an OR-accumulator
// loop into an early exit, which reintroduces the timing leak the loop exists to avoid.
// Every function below carries an explicit barrier; none of them may be rewritten into
// something "cleaner" without re-running the ctgrind control.

#include <cstddef>
#include <cstdint>
#include <span>

namespace mlkem768 {

// Opaque barrier: forces the value to exist in a register and prevents the optimizer
// from reasoning about it across this point. Cheaper and more portable than a full
// memory clobber, and enough to stop the accumulator-to-early-exit rewrite.
[[gnu::always_inline]] inline std::uint32_t ct_opaque(std::uint32_t v) noexcept {
  asm volatile("" : "+r"(v) : : );
  return v;
}

// Returns 0x00 if the ranges are equal, 0xFF if they differ anywhere.
// NO early exit, NO branch on content. Both spans must be the same length; the length
// itself is public (it is a protocol constant).
[[nodiscard]] inline std::uint8_t ct_neq(std::span<const std::uint8_t> a,
                                         std::span<const std::uint8_t> b) noexcept {
  // A length mismatch is a PUBLIC, structural fact -- the caller checks lengths before
  // reaching here (§7.3 ciphertext type check). Returning "different" is safe.
  if (a.size() != b.size()) return 0xFF;

  std::uint32_t acc = 0;
  for (std::size_t i = 0; i < a.size(); ++i)
    acc |= static_cast<std::uint32_t>(a[i] ^ b[i]);

  // THE BARRIER. Without it, -O3 may hoist a `break` out of the loop above once acc
  // becomes nonzero, turning a constant-time scan into an early-exit compare.
  acc = ct_opaque(acc);

  // Fold any nonzero bit down to a full-width 0x00 / 0xFF mask, branchlessly.
  // (acc | -acc) has its top bit set iff acc != 0.
  const std::uint32_t nz = (acc | (0u - acc)) >> 31;     // 0 or 1
  return static_cast<std::uint8_t>(0u - nz);             // 0x00 or 0xFF
}

// r = mask ? x : r, byte-wise. mask MUST be 0x00 or 0xFF -- anything else silently
// produces a blend of the two inputs rather than a select.
inline void ct_cmov(std::span<std::uint8_t> r, std::span<const std::uint8_t> x,
                    std::uint8_t mask) noexcept {
  const std::uint32_t m = ct_opaque(mask);
  const auto m8 = static_cast<std::uint8_t>(m);
  for (std::size_t i = 0; i < r.size() && i < x.size(); ++i)
    r[i] = static_cast<std::uint8_t>(r[i] ^ (m8 & (r[i] ^ x[i])));
}

}  // namespace mlkem768
