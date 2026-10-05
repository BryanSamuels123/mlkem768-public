# Gotchas discovered

*Moved out of `docs/reference/invariants.md` in the Phase 9 close-out prune (2026-09-29), the same treatment
`docs/reference/ct-tooling.md` got in the Phase 8 prune. Most of these are resolved history:
worth having when something looks familiar, not worth carrying in context every session.*

**The few that are still live invariants stayed in `docs/reference/invariants.md`** under "Gotchas that are
still live" — chiefly that `int16_t` overflow is not UB and no sanitizer fully covers it,
and that Make does not rebuild when only flags change. If this file and `docs/reference/invariants.md`
disagree, `docs/reference/invariants.md` wins.

---

- **The ACVP directory is `ML-KEM-encapDecap-FIPS203` — singular "Decap".** This project's
  own spec (§10.1) writes "encapDecaps"; that path 404s. Logged in DECISIONS.md → Spec
  corrections.
- **ACVP groups need TWO discriminators.** `testType` alone is insufficient: three
  different `function` values (`decapsulation`, `decapsulationKeyCheck`,
  `encapsulationKeyCheck`) all carry `testType: "VAL"`. **Key off `function`.**
- **The shared-secret field is lowercase `k`** — the same letter as the module dimension
  `k = 3`. Easy to confuse in a parser.
- **`expectedResults.json` has no `parameterSet` field**, only `tgId`. Another reason to
  use `internalProjection.json`.
- **`consteval` for `q⁻¹ mod 2^16` must use unsigned arithmetic.** The Newton iteration
  overflows `int`, and signed overflow is UB — the compiler rejects it outright in a
  constant expression. Caught this while probing C++20 support, before it could cost time
  in Phase 2. `q⁻¹ = 62209` (signed: −3327); derive it, don't hardcode it.
- **K-PKE.KeyGen samples both `s` and `e` with η1**, not η2 (Alg. 13 lines 9 and 13).
  Invisible for ML-KEM-768 where η1 = η2 = 2; wrong for ML-KEM-512.
- **GNU Make 3.81 is refused outright** — see the Environment table. Historical note:
  pattern-specific overrides and `-j` work under it, but its mtime granularity does not.
  Install a newer
  `make` via Homebrew if this ever bites.
- **`int16_t` overflow is NOT undefined behaviour — UBSan will not catch it.** This is the
  opposite of the natural assumption and was verified, not reasoned about. `int16_t *
  int16_t` promotes to `int`, so `300 * 200 = 60000` is valid; narrowing back is
  well-defined wrapping in C++20. With `-fsanitize=signed-integer-overflow
  -fno-sanitize-recover=all` the program printed `-5536` and **exited 0**.
  **`-fsanitize=implicit-integer-truncation` does catch it** (clang-only, now probed for in
  `UBSAN_FLAGS`) — but only for *implicit* conversions; an explicit `static_cast<int16_t>`
  is invisible to it. **`docs/bounds.md` therefore remains the primary defence for failure
  mode #8; no sanitizer replaces the bounds table.** ADR-012.
- **The container's `c++` is g++, not clang.** Debian's alternatives resolved it that way,
  which silently dropped the clang-only sanitizer above. Docker targets now pin
  `CXX=clang++`. Worth remembering for Phase 8: benchmark numbers from the container are
  not comparable across compilers unless CXX is pinned.
- **`basemul`'s input bound was wrong from Phase 2 until Phase 5.** It claimed `|c| <=
  1664`, but `sample_ntt` produces `Â` in canonical `[0, q)` (up to 3328) and `Â` goes
  straight into `basemul` with no `ntt()`. The true bound is `3328·3328`, still only
  10.15 % of the limit — so no overflow, but the table was understating by 2×. Caught by
  adding a canonical-range case to `make bounds`; the previous measurement missed it
  because the harness ran `ntt()` first, which barrett-reduces the input before
  `basemul` ever sees it. **A measurement harness that does not reproduce the real call
  shape measures the wrong thing.**
- **ADR-015 and ADR-016 were referenced for two phases before they existed.** A Phase 3
  script targeted a placeholder that was not there, `replace()` matched nothing, and it
  printed success. The project documentation, source comments and two commit messages
  all cited ADRs that were absent from `DECISIONS.md`. Recovered in Phase 5 at the
  numbers already cited. **Every scripted edit to a state file must assert its anchor** —
  the same silent-no-op class as the stale-build and empty-tie-set bugs below.
- **`Compress_d` can never tie; `Decompress_d` ties exactly once per `d`.** `q = 3329` is
  odd, so `2·(x mod q) == q` is impossible and the round-half-up rule is *vacuous* for
  Compress. Decompress ties at exactly `y = 2^(d-1)`, and for `d = 1` that single value
  **is** the message constant 1665. Round half-down there and decryption still works
  (1664 is far from the q/4 boundary) — what breaks is byte-exactness: `μ` shifts by 1
  per set bit, `v` with it, and the ciphertext changes for a fraction of inputs. A
  self-consistent implementation that fails KATs. A first attempt at a tie test found zero ties and was silently asserting
  nothing; the corrected test proves both halves.
- **The compiler emitted a `divl` inside `ntt()`** by strength-reducing `k++` into
  `k += 255/(2·len)`. Traced in the disassembly: the divisor is the layer counter, never
  data, so it is not a leak — but it is ~5 % of an `ntt()` wasted. Phase 8 should unroll
  the layer loop. Found by auditing at the MACHINE level, not by reading source; the
  first grep pattern used `\b`, which BSD grep does not honour, and silently reported 0
  for everything including a positive control.
- **`audit-zeroize` proves `secure_zero` survives `-O3` STANDALONE — it does NOT prove
  the `Zeroizing<T>` destructor is emitted at each call site.** There are 13 wraps in
  `kpke.cpp` and 11 in `kem.cpp`; an inlined destructor on a large `PolyVec` is a
  plausible place for the optimizer to be cleverer than expected. The Phase 6b audit
  confirmed the wraps are on the *right variables* (nothing live is zeroed, verified by
  disassembly-independent runtime probe + KAT 80/80) but **not** that each erase is
  actually emitted. **Logged as an explicit Phase 9 task below.**
- **ctgrind cannot see secret-dependent `div`/`mod`, and at `-O3` cannot see a simple
  `if (secret)` either** (clang flattens it to a select). It *does* catch secret memory
  indices, secret loop bounds, and early-exit compares — so a `memcmp` in Decaps would be
  caught at Phase 6. ADR-016 has the measured table. The div/mod ban is enforced by
  review and by dudect, not by the tool.
- **`int16_t` overflow is NOT UB and no sanitizer fully covers it.** ADR-012 established
  that `-fsanitize=implicit-integer-truncation` catches *implicit* narrowing; Phase 2
  confirmed it is **blind to an explicit `static_cast<int16_t>`**, which is what the NTT
  butterflies use. `docs/bounds.md` now lists every such site and is the only defence.
- **Spec §5.2's `montgomery_reduce` contract is off by one.** Exhaustive sweep of all
  218,169,345 inputs found exactly one violation: `a = +q*2^15` returns `q`, not `< q`.
  The input bound is now strict. Found by making the test exhaustive instead of sampled —
  the spec only asked for 10^7 random samples, which would very likely have missed it.
- **GNU Make 3.81 is now a hard error.** `brew install make`; use `gmake`. The build
  refuses to run under 3.81 rather than silently producing a stale binary.
- **Make 3.81 compares mtimes at 1-SECOND granularity — a same-second edit is invisible.**
  Bit during KAT mutation testing: the driver reverted one mutation and wrote the next
  into the same file inside one second, make judged the `.o` up to date, and mutation N
  silently ran mutation N-1's binary. The result looked plausible, not broken. **Do not
  fix this with `sleep`** — delete the object file, since a missing prerequisite always
  forces a rebuild. Relevant to Phase 2, where the edit-test loop is fast.
- **Make does not rebuild when flags change.** Running two sanitizer targets into the same
  BUILD directory silently reuses objects compiled with the wrong flags — this produced a
  confusing "MSan still sees libstdc++" result that looked like a toolchain problem and was
  actually a stale `.o`. Each target now uses a distinct subdirectory; `rm -rf build/linux`
  when a sanitizer result looks impossible.
- **`std::hardware_destructive_interference_size` is absent from libc++.** Verified:
  `__cpp_lib_hardware_interference_size` is not defined by Apple clang 16's libc++, so the
  `alignas(std::hardware_destructive_interference_size)` that spec §9.3 prescribes for
  batch output padding **will not compile here**. Hardcode 64 (the measured
  `hw.cachelinesize` on this CPU, and correct for every x86-64 part this project targets)
  behind an `#ifdef __cpp_lib_hardware_interference_size`, preferring the library value
  where it exists. **Phase 10 problem — logged now so it is not discovered then.**
- ASan's failure mode here is a bare `Illegal instruction: 4` with **no output at all**,
  which reads like a project bug rather than a toolchain one. `make asan` now runs a
  preflight probe and explains it.

---
