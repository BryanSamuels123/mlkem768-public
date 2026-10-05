# ML-KEM-768

A constant-time, CPU-only implementation of **ML-KEM-768** (NIST FIPS 203) in C++20.

> **Status: v0.1.0 — COMPLETE.** All ten phases done; released and tagged.
>
> The KEM works and passes all 80 NIST ACVP known-answer vectors. AVX2 optimization is done, and it lands within ~1.41× of
> `pq-crystals/kyber`'s AVX2 code on the same machine while additionally erasing every
> secret it puts on the stack, which that implementation does not do. Constant-time
> validation is complete: no secret-dependent branches or memory addresses under valgrind,
> no division instructions anywhere in the library, and no timing dependence on secret
> inputs detectable at the API **down to a measured resolution of about 100 processor time
> ticks per operation** — that floor was measured by planting a known delay, not assumed.
> Fuzzing is done, with a differential oracle against an independent model. Packaged, with
> licence and third-party notices, and the tarball verified by building a consumer program
> against it. **`docs/SUMMARY.md` is the plain-language write-up; start there.**
>
> **Still not for production use** — see *Not claimed*, below.

## Build

```sh
gmake           # build build/libmlkem768.a
gmake test      # unit + differential tests
gmake test-deep # differential tests at 10^7 iterations
gmake bounds    # coefficient-bound measurement
gmake env       # show the resolved toolchain and flags
```

Requires a C++20 compiler and **GNU Make >= 4.0**. macOS ships Make 3.81, which compares
mtimes at 1-second granularity and will silently reuse stale objects; the build hard-errors
under it. `brew install make` provides `gmake`.

Verified on Apple clang 16 / macOS x86-64 and Debian clang 16 / Linux x86-64.

## Using it

Install the library and header, then compile against that — nothing from `src/` is needed
or supported:

```sh
gmake
gmake install PREFIX=/usr/local        # or any prefix you like
c++ -std=c++20 myapp.cpp -I/usr/local/include \
    /usr/local/lib/libmlkem768.a -o myapp
```

The whole interface is one header. Two parties end up holding the same 32-byte secret
without it ever crossing the wire: the receiver publishes a key, the sender uses it to make
a ciphertext plus a secret, and the receiver turns that ciphertext back into the same secret.

```cpp
#include <mlkem/mlkem768.hpp>

mlkem768::EncapsKey ek;          // public   -- send this out
mlkem768::DecapsKey dk;          // SECRET   -- keep it
mlkem768::keygen(ek, dk);

mlkem768::Ciphertext ct;         // public   -- send this back
mlkem768::SharedSecret ss_send;  // SECRET
mlkem768::encaps(ek, ct, ss_send);

mlkem768::SharedSecret ss_recv;  // SECRET
mlkem768::decaps(dk, ct, ss_recv);
// ss_send == ss_recv
```

**One thing to get right.** A corrupted or forged ciphertext does **not** return an error.
It returns `Ok` and a *different* secret — deliberately, because reporting "invalid
ciphertext" would hand an attacker a decryption oracle. So never treat `Ok` as proof the
exchange worked: use the secret inside an authenticated protocol, where a mismatch simply
makes authentication fail. Every function returns a status and none of them throw; the
header documents each one, and which values are secret.

## Targets

| Target | Purpose | Available from |
|---|---|---|
| `gmake` | build the static library | Phase 0 |
| `gmake test` | unit + property + differential tests | Phase 0 |
| `gmake test-deep` | differentials at 10^7 iterations | Phase 2 |
| `gmake bounds` | coefficient-bound measurement | Phase 2 |
| `gmake kat-model` | ACVP KATs against the golden model | Phase 1 |
| `gmake kat` | ACVP KATs against the implementation | Phase 7 |
| `gmake bench` / `bench-kem` | cycle-count benchmarks | Phase 8 |
| `gmake docker-ctgrind` | constant-time check under valgrind | Phase 9 |
| `gmake dudect` | statistical timing test (host-only) | Phase 9b |
| `gmake audit-div` | no `div`/`idiv` in the library, at machine level | Phase 4 |
| `gmake audit-zeroize` | `secure_zero` survives `-O3`, by disassembly | Phase 6 |
| `gmake audit-zeroize-sites` | every `Zeroizing<T>` wrap really erases | Phase 9a |
| `gmake ubsan` | UndefinedBehaviorSanitizer (works on this host) | Phase 0 |
| `gmake docker-asan` / `docker-msan` | Address/Memory sanitizers | Phase 0 |
| `gmake docker-fuzz` | libFuzzer + sanitizers + differential oracle | Phase 10a |
| `gmake verify-vectors` | re-check ACVP vector checksums | Phase 0 |
| `gmake consumer-test` | build a user program against the INSTALLED tree | Phase 10b |
| `gmake package` / `package-test` | build the tarball; test the unpacked tarball | Phase 10b |
| `gmake docker-all` | every gate that needs Linux, in one run | Phase 1 |

Every target listed above is implemented. Targets that cannot run on a given host say so
and fail, rather than silently succeeding.

**On this development host, `gmake docker-ctgrind`, `docker-asan`, `docker-msan` and
`docker-fuzz` do the work in a Linux container**, because the macOS toolchain cannot:
valgrind does not support this configuration, AddressSanitizer is non-functional for C++
here, MemorySanitizer needs an instrumented standard library, and Apple's compiler ships no
libFuzzer. The host-side names fail with that explanation instead of doing nothing quietly.
`gmake ubsan` works natively. **`gmake dudect` is the reverse — host only**, because a
container here is a virtual machine and would add a timing layer to the very thing it
measures. See `docs/reference/invariants.md` → Build environment.

## Layout

```
docs/algorithms/   FIPS 203 pseudocode, extracted once. Read these, not the standard.
docs/spec/         the project contract (reference PDFs are not redistributed)
docs/bounds.md     coefficient range invariants (Phase 2)
src/               implementation
tests/kat/         ACVP vectors + provenance
tests/model/       golden model (Phase 1)
tests/ct/          constant-time + timing harnesses (Phases 6, 9)
docs/notes/        one note per phase: what was done, measured, and learned
docs/reference/    material consulted when needed, not every session
third_party/       vendored code, 12 files, three upstream licences:
                     fips202/          pq-crystals FIPS 202 (CC0) -- IN the library
                     fips202/keccak4x/ Keccak Teams AVX2 permutation (CC0), plus
                                       KeccakP-brg_endian.h (Brian Gladman, BSD-style
                                       WITH conditions) -- IN the library
                     doctest/          unit test framework (MIT) -- test-only
                     nlohmann/         JSON, reads the NIST vectors (MIT) -- test-only
                   See THIRD_PARTY_NOTICES.txt; required to accompany binaries.
```

## Documentation

**New here? Read `docs/SUMMARY.md` first.** It explains what this is, how it works and what
was measured, in plain language, assuming no cryptography background.

| File | What it is |
|---|---|
| `docs/SUMMARY.md` | **start here** — the whole project in plain words, no background assumed |
| `LICENSE` | MIT, this project's own code only |
| `THIRD_PARTY_NOTICES.txt` | vendored code's licences; **required to accompany binaries** |
| `docs/reference/invariants.md` | **read before changing `src/`** — the properties a plausible change silently breaks |
| `DECISIONS.md` | every decision with its reasoning, plus third-party provenance |
| `docs/bounds.md` | coefficient range invariants; lazy reduction is only legal where this proves it |
| `docs/spec/MLKEM768_SPEC.md` | the project contract |
| `docs/algorithms/README.md` | index of the 25 extracted algorithm notes |
| `tests/kat/PROVENANCE.md` | vector sources, checksums, and the full JSON field map |
| `docs/notes/` | per-phase notes — what was measured and what it meant |

## Conformance

**Normative reference: NIST FIPS 203**, published 2024-08-13. Round-3 CRYSTALS-Kyber is
*not* ML-KEM; see `docs/algorithms/appendixC-kyber-differences.md`.

**Randomness.** The default RBG is the operating system CSPRNG — `getentropy` on macOS,
`getrandom` on Linux — which is thread-safe and suitable for general use. **It is not an
SP 800-90 validated RBG**, and FIPS 203 §3.3 requires an approved RBG of at least 192-bit
security strength for ML-KEM-768. Callers needing validated randomness inject their own
with `set_rng()`; an injected RBG **must** be thread-safe or per-thread, because a
non-thread-safe RBG shared across threads is a catastrophic, silent security bug.

**Zeroization, and what it does not cover.** FIPS 203 §3.3 requires intermediate secret
data to be destroyed once it is no longer needed. Every stack-resident secret is wrapped
in `Zeroizing<T>`, whose destructor calls a non-elidable `secure_zero`. Two gates check
this rather than assuming it: `gmake audit-zeroize` proves by disassembly that
`secure_zero` survives `-O3` (with a plain `memset`, which the compiler deletes entirely,
as the negative control), and `gmake audit-zeroize-sites` proves that **all 27** wrap
sites actually emit their erase, at the real build flags, on both supported toolchains.

**What that does not mean.** `secure_zero` erases **the named object only**. It does not
reach copies the compiler made of that value — register copies, stack spill slots, or
temporaries — and no destructor in C++ can reach them. The language provides no way to
enumerate or erase them, so this is a **known, unclosed limitation**, not an oversight
this project can fix. Auditing the wrap sites more thoroughly does not change it. Treat
the guarantee as "each named secret object is overwritten before its scope ends", **not**
as "this secret no longer exists anywhere in memory". Both gates are also valid only for
the flags they run under: enabling LTO would let the optimizer reason across translation
units, and every result would have to be re-established. See `DECISIONS.md` ADR-034.

**The internal deterministic functions are undeclared, not unreachable.** FIPS 203 §3.3 says
the deterministic interfaces should not be exposed, and the public header does not declare
them — but they remain present as symbols in the static archive, so a caller who writes the
prototype themselves can link to them. They are undocumented and cannot be reached by
accident; they are not hidden. Stated because `nm` on the shipped archive would show it in
one command.

**Not claimed:** no CMVP validation, no CAVP certificate, **no SP 800-90 validated RBG**,
no formal verification, no independent security audit, **no claim that secret values are
absent from compiler-generated copies**, and **no claim that the internal entry points are
inaccessible** — only that they are undeclared. Do not use this in production.

## License

**This project's own code is MIT licensed** — Copyright (c) 2026 Bryan Samuels. See
**`LICENSE`**, which covers this project's code and nothing else.

**Vendored third-party components keep their own licences**, which are *not* all the same and
are *not* covered by the above. They are reproduced in full in **`THIRD_PARTY_NOTICES.txt`**,
built by walking the repository and reading all twelve vendored files rather than from any
summary list. One of them — a byte-order header by Brian Gladman — is BSD-style with
conditions rather than public domain, and **its notice is required to accompany any binary
distribution of this library**, so that file ships inside the package. Per-file provenance,
with commit hashes, is in `DECISIONS.md`.
