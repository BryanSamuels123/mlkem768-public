# DECISIONS.md

**Append-only.** Never edit or delete an entry. If a decision is reversed, add a new entry
that supersedes it and mark the old one `SUPERSEDED BY ADR-nnn`.

Purpose: stop a future session from second-guessing and silently reversing a decision that
was made for a good reason it no longer has in context.

---

## Format

```
### ADR-nnn: <short title>
Date: YYYY-MM-DD | Phase: n | Status: Accepted | Superseded by ADR-mmm

Decision:    What was decided, in one or two sentences.
Rationale:   Why. Include what was rejected and why.
Consequences: What this forces elsewhere in the codebase.
```

---

## Architecture decisions

### ADR-001: FIPS 203 is normative; round-3 Kyber is not
Date: 2026-09-19 | Phase: 0 | Status: Accepted

**Decision:** FIPS 203 (NIST, August 2024) is the sole normative reference. The three other
project PDFs are informative. Round-3 CRYSTALS-Kyber material is treated as a known
hazard, not a reference.

**Rationale:** Kyber and ML-KEM differ in the `‖k` domain separator, the removed `m ← H(m)`,
and the removed final KDF. Each difference produces a self-consistent implementation that
fails every NIST KAT. Most material online predates mid-2024.

**Consequences:** Any reference consulted must be checked against those three differences
before use. Logged here if it influenced an implementation choice.

---

### ADR-002: Golden model must be KAT-clean before Phase 2
Date: 2026-09-19 | Phase: 0 | Status: Accepted

**Decision:** Phase 1 does not end when the model is self-consistent. It ends when
`make kat-model` passes all ML-KEM-768 ACVP vectors.

**Rationale:** A merely self-consistent model can share a misreading with the
implementation it is meant to check; both agree all the way to a failing Phase 7. A
KAT-clean model makes every downstream differential test equivalent to a KAT test,
localizing spec violations to the function that owns them.

**Consequences:** ACVP vectors must be acquired in Phase 0, not Phase 7. The KAT harness is
built once in Phase 1 and reused, with `make kat` / `make kat-model` selecting the target.

---

### ADR-003: Read reference implementations, do not copy them
Date: 2026-09-19 | Phase: 0 | Status: Accepted

**Decision:** No source from pq-crystals, mlkem-native, PQClean, liboqs, BoringSSL, or
AWS-LC enters this repository without explicit human approval. Pre-approved exceptions:
vendored FIPS 202 / Keccak, and single-header test-only dependencies.

**Rationale:** The licenses permit copying; the project goal does not. Writing the AVX2 NTT
is the deliverable. Keccak is a solved, separable problem where rewriting adds nothing.

**Consequences:** Phase 8 is slower than pasting `ntt.S`. Every vendored file needs a
provenance entry below.

---

### ADR-004: Montgomery domain convention
Date: 2026-09-20 | Phase: 2 | Status: Accepted

**Decision:** `R = 2^16`. `mont_mul(a, b)` computes `a·b·R^-1 mod q`. Zetas are stored
**pre-multiplied by R** and centered to `[-(q-1)/2, (q-1)/2]`. The resulting domains are:

| Function | Input domain | Output domain |
|---|---|---|
| `ntt` | normal | **normal** |
| `poly_basemul` / `basemul` / `poly_basemul_acc` | normal × normal | **× R^-1** |
| `invntt` | any | **× R** (folds `128^-1` together with `R^2`) |
| `poly_to_mont` | normal | **× R** |

Two consequences follow, and both must be internalized:

1. **`invntt(poly_basemul(ntt(a), ntt(b))) == a · b` exactly, with no correction.**
   The `R^-1` from basemul and the `R` from invntt cancel. This is the composition the
   whole scheme rests on, and it is asserted directly by the schoolbook differential test.
2. **`invntt(ntt(f)) == f · R`, NOT `f`.** This looks like a bug and is not. A caller
   needing a basemul result *without* an inverse transform — K-PKE.KeyGen computes
   `t_hat` entirely in the NTT domain — applies `poly_to_mont` to undo the `R^-1`.

`invntt` folds the scaling as `mont_mul(c, R^2 · 128^-1 mod q)`, since
`mont_mul(x, R^2/128) = x·R/128` and the raw Gentleman–Sande transform carries a spare
factor of 128. The constant works out to 1441. **Seven layers, so `128^-1 = 3303`, not
`256^-1`** — using 256 leaves every output scaled by 2.

**Rationale:** Matches the well-tested reference lineage, which spec §5.1 recommends, and
keeps `basemul` to four multiplies. The alternative of making `basemul` return the normal
domain would cost an extra Montgomery multiply per coefficient pair in the hottest loop
in the library, and would make the critical composition above require a correction step
instead of being exact.

**Consequences:**
- Every constant is derived by `consteval` and `static_assert`ed — `QINV = 62209`,
  `R mod q = 2285`, `R² mod q = 1353`, `128^-1 = 3303`, `R²·128^-1 = 1441`, both zeta
  tables. **Nothing is transcribed**, including from the spec or from a human.
- Serialization (Phase 4) must convert out of the Montgomery domain first:
  `poly_tobytes`, `poly_tomsg`, and both compress paths all demand canonical `[0, q)`.
  `poly_canonicalize` exists for exactly this.
- Differential tests against the golden model convert explicitly at the boundary, using
  only `R mod q` (never `R^-1`). Those conversions are *derived from this ADR*. If a
  differential test ever needs an unexplained constant to pass, this convention is wrong
  and the test is right.
- `docs/bounds.md` holds the coefficient invariants that make the domains safe.

> This ADR is load-bearing. A domain mismatch passes every roundtrip test and fails every
> KAT, with output off by a constant factor. The wording above is mirrored into
> `docs/reference/invariants.md`.

---

### ADR-005: Vendor doctest v2.5.3 as the unit-test framework
Date: 2026-09-19 | Phase: 0 | Status: Accepted

**Decision:** Vendor the doctest single header at `third_party/doctest/doctest.h`, pinned
to commit `2d0a9359a60c51affe2a9bebb1be1dca47868151` (tag `v2.5.3`), MIT licensed. Test-only; never linked into
`libmlkem768.a`.

**Rationale:** Pre-approved by spec §7.3 exception 2 and §7.4. Single header, no build
system, and far lighter than GoogleTest. Pinned to a commit rather than a tag so the
download is reproducible even if the tag moves.

**Consequences:** doctest uses exceptions for assertion reporting and will not compile
under `-fno-exceptions`, which is why flag exception 1 (§13) exists:
`TEST_CXXFLAGS = $(filter-out -fno-exceptions -fno-rtti,$(CXXFLAGS))`. The library itself
stays exception-free and RTTI-free.

---

### ADR-006: Commit the ACVP vector JSON to the repository
Date: 2026-09-19 | Phase: 0 | Status: Accepted

**Decision:** The six ACVP JSON files (~3.4 MB total) are committed to git, not
gitignored and re-fetched. `make fetch-vectors` verifies an existing copy against
`SHA256SUMS` and refuses to overwrite it; it only instructs a re-download when the files
are absent. `make distclean` deliberately does not delete them.

**Rationale:** The vectors are the Phase 1 and Phase 7 gates. Upstream ACVP-Server paths
demonstrably move — the directory is `ML-KEM-encapDecap-FIPS203`, singular "Decap",
which already differs from the name used in this project's own spec. A correctness gate
that depends on a live URL can break for reasons unrelated to the code, at the worst
possible moment. The repository already carries 4.5 MB of reference PDFs, so the size
precedent is set. URLs are pinned to commit
`975de31eb83d87039ec88934fdc47d8c312b892d` regardless, for reproducibility.

**Consequences:** Repository grows by ~3.4 MB. Updating vectors is an explicit, reviewable
commit rather than a silent re-fetch. `tests/kat/PROVENANCE.md` records the pinned URLs
so a fresh download is always possible.

---

### ADR-007: Parse `internalProjection.json`, not the prompt/expectedResults pair
Date: 2026-09-19 | Phase: 0 | Status: Accepted

**Decision:** The KAT harness parses `*-internalProjection.json` as its single source.
The `prompt.json` / `expectedResults.json` pair is committed but used only as an
independent cross-check.

**Rationale:** `internalProjection` is prompt ∪ expectedResults in one file, avoiding a
`tgId`/`tcId` join (`expectedResults` does not even carry `parameterSet`). Critically, it
is the **only** file carrying the `reason` field that identifies the implicit-rejection
cases. It was verified to agree with `expectedResults` on every `c`, `k`, and
`testPassed` across all 165 encapDecap cases.

**Consequences:** The harness must filter on `parameterSet == "ML-KEM-768"` **and** on
`function`, since `testType` alone does not separate the three `VAL` group kinds. See
`tests/kat/PROVENANCE.md` for the full field map.

---

### ADR-008: The constant-time and ASan/MSan gates cannot run on this machine
Date: 2026-09-19 | Phase: 0 | Status: Accepted

**Decision:** `make ctgrind`, `make asan`, and `make msan` are kept wired in the Makefile
and each fails loudly with a specific diagnosis and a pointer to Linux CI. None of them is
removed, weakened, or allowed to report success. Phase 9 sign-off requires a Linux host.

**Rationale:** Verified in the Phase 0 environment audit on macOS 26.6.2 / Apple clang 16:

- **valgrind** is not installed and has no working port for current macOS on x86-64, so
  the ctgrind approach of spec §8.4 cannot run here at all.
- **ASan is non-functional for C++**: a minimal `std::string` program built with
  `-fsanitize=address` terminates with SIGILL. Both the LeakSanitizer exit path and the
  ASan error-*reporting* path crash; no `ASAN_OPTIONS` combination (`detect_leaks=0`,
  `symbolize=0`, `halt_on_error=0`, `print_module_map=0`) recovers them. A gate that
  crashes identically on correct and incorrect code carries no signal.
- **MSan** requires an MSan-instrumented libc++, which Apple clang does not ship.

Dropping these targets would silently delete the security gates the project is built
around — precisely the failure this ADR exists to prevent.

**Consequences:** UBSan is the only fully functional sanitizer on this host (verified to
catch real signed-overflow UB) and is the one to run locally. `make asan` runs a preflight
probe and explains the situation rather than emitting a bare "Illegal instruction: 4".
Phases 9 and 10 need Linux CI or a VM; this is a known, recorded gap, not a surprise to
discover at Phase 9.

---

### ADR-009: Parameterize CBD sampling and PRF on η; never name them `eta2`
Date: 2026-09-19 | Phase: 1 (pre-flight) | Status: Accepted

**Decision:** `sample_poly_cbd<Eta>` and `PRF<Eta>` are templated on η. The
`sample_poly_cbd_eta2` / `PRF_eta2` declarations originally in spec §6.2/§6.3 are removed.
Call sites select by **role** — `params::ETA1` or `params::ETA2` — never by literal value.
Applies to the golden model and to the optimized implementation alike.

**Rationale:** The original declarations fixed a 128-byte PRF output and an η=2 CBD shape.
That silently hardcodes `η1 == η2`, which holds for ML-KEM-768 and ML-KEM-1024 but **not
for ML-KEM-512**, where `η1 = 3` and the PRF must emit 192 bytes. Spec §1 requires that
adding a parameter set be a parameter change and not a rewrite, so the §6.2/§6.3
declarations contradicted §1. Caught in Phase 0 while extracting FIPS 203 Alg. 13, which
samples **both `s` and `e` with η1** — the asymmetry is invisible at 768 and load-bearing
at 512.

η is a **template** parameter rather than a runtime argument because the bit-slicing shape
genuinely differs between η=2 and η=3; a runtime branch would be slower and harder to keep
constant-time.

**Consequences:**
- `PRF<Eta>`'s η selects **output length only**. FIPS 203 §4.1: "η is only used to specify
  the desired output length and not to perform domain separation." So `PRF<2>(s,b)` is a
  128-byte prefix of `PRF<3>(s,b)`. **Adding a domain-separation byte for η breaks every
  KAT.** Recorded here because it is a tempting "improvement".
- Phase 5 must test `sample_poly_cbd<3>` as well as `<2>`, even though ML-KEM-768 never
  calls it, so the η1≠η2 path is not first exercised by a future ML-KEM-512 port.
- `docs/bounds.md`, spec §6.2, §6.3, §10.3, §12, and
  `docs/algorithms/alg08-sample-poly-cbd.md` were all updated in the same commit.

---

### ADR-010: Vendor nlohmann/json v3.12.0 for the ACVP KAT harness
Date: 2026-09-20 | Phase: 1 | Status: Accepted

**Decision:** Vendor the nlohmann/json single header at `third_party/nlohmann/json.hpp`,
pinned to commit `55f93686c01528224f448c19128836e7df245f72` (tag `v3.12.0`), MIT licensed. Test-only; never linked
into `libmlkem768.a`.

**Rationale:** Pre-approved by spec §7.4. The ACVP vectors are JSON and the harness is the
Phase 1 exit criterion. Single header, no build system.

**Consequences:** Adds ~950 KB to `third_party/`. Like doctest it needs exceptions, so it
is compiled only into test TUs under `TEST_CXXFLAGS` (flag exception 1, §13).

---

### ADR-011: Linux CI container built at Phase 1, not Phase 9
Date: 2026-09-20 | Phase: 1 (pre-flight) | Status: Accepted

**Decision:** A Debian bookworm x86-64 container (`ci/Dockerfile`) carries clang 16,
valgrind, and the compiler-rt sanitizer runtimes. A second image (`ci/Dockerfile.msan`)
adds an **MSan-instrumented libc++**. Targets: `docker-build`, `docker-msan-build`,
`docker-probe`, `docker-test`, `docker-asan`, `docker-ubsan`, `docker-msan`,
`docker-ctgrind`, `docker-kat-model`, `docker-shell`, `docker-all`.

**Rationale:** Same reasoning that put the ACVP fetch in Phase 0 (ADR-006): discovering at
the gate that the environment cannot run the gate invalidates everything built on top of
it. ADR-008 established that ctgrind, ASan and MSan cannot run on the macOS host. Building
the escape hatch at Phase 9 would mean eight phases of work resting on an unverified
assumption that a container could run them.

`ci/probe.sh` does not merely check that things compile — it **compiles and executes**
AVX2/BMI2/FMA (the Phase 8 instruction mix: `vpmulhw`, `vpmullw`, `vpshufb`, `pext`,
`pdep`) and requires each sanitizer to produce a real report against a deliberately buggy
program. A container that compiles AVX2 but cannot execute it — qemu emulation, a
restricted runner — is exactly the failure this catches.

**Verified 2026-09-20, all green:** x86-64 confirmed; AVX2/BMI2/FMA present and executing;
no AVX-512 (matches the host CPU, so `src/arch/avx512/` stays untested-by-construction);
ASan reports heap-buffer-overflow; UBSan reports signed integer overflow; valgrind detects
an uninitialised-value branch (the ctgrind mechanism); MSan reports
use-of-uninitialized-value.

**Consequences:**
- **MSan requires the instrumented libc++.** Against stock libstdc++ it reports
  use-of-uninitialized-value inside `std::_Rb_tree` the moment doctest registers a test
  case — observed, not theorised. The `msan` target refuses to run without `MSAN_LIBCXX`
  set rather than emitting noise. Building libc++ with `-DLLVM_USE_SANITIZER=MemoryWithOrigins`
  adds ~40 s to the one-time image build.
- Container builds use `BUILD=build/linux` so Linux objects never collide with macOS ones.
- **Make does not rebuild on flag changes.** Running two sanitizer targets into one BUILD
  directory silently reuses objects compiled with the wrong flags. Each target uses a
  distinct subdirectory; `rm -rf build/linux` when in doubt.
- `docker-ctgrind` is currently memcheck over the test suite — a real check, but the
  secret-marking client requests that make it the CT gate arrive in Phase 9.

---

### ADR-012: int16_t overflow is NOT undefined behaviour — UBSan alone will not catch it
Date: 2026-09-20 | Phase: 1 | Status: Accepted

**Decision:** `-fsanitize=implicit-integer-truncation` is added to `UBSAN_FLAGS` and is the
designated guard for docs/reference/kat-failure-checklist.md #8. It is probed for, not assumed, because it
is clang-only.

**Rationale:** The natural assumption — "signed overflow is UB, so UBSan catches the
int16_t overflow that ASan wouldn't" — **is false**, and this was verified rather than
reasoned about:

- `int16_t * int16_t` undergoes integer promotion: both operands become `int`, and
  `300 * 200 = 60000` is a perfectly valid `int`. Narrowing the result back to `int16_t`
  is **implementation-defined and, since C++20, well-defined modular wrapping** — not UB.
- Measured: with `-fsanitize=signed-integer-overflow -fno-sanitize-recover=all`, the
  program printed `-5536` and **exited 0**. No diagnostic.
- `-fsanitize=signed-integer-overflow` does fire correctly on genuine `int`-width
  overflow (`2000000000 + 2000000000`), so the flag works — it simply does not apply.
- `-fsanitize=implicit-integer-truncation` **does** catch it, with a precise message, and
  correctly stays silent on an in-range narrowing (`100 * 30 = 3000`).

**Consequences:**
- **Use the SIGNED variant.** `-fsanitize=implicit-integer-truncation` also covers
  *unsigned* truncation, which is not UB and is the whole point of byte extraction — the
  vendored Keccak's `store64` (`x[i] = u >> 8*i`) trips it on every hash. Phase 3 narrowed
  the flag to `-fsanitize=implicit-signed-integer-truncation`, which still catches the
  `int16_t` hazard and no longer fires on vendored code. Verified both ways rather than
  suppressed, and with no modification to the vendored file.
- **It only sees IMPLICIT conversions.** An explicit `static_cast<int16_t>` is invisible to
  it — verified. Phase 2/8 reduction helpers that deliberately wrap must therefore either
  keep the narrowing implicit, or rely on the `-DMLKEM_TRACK_BOUNDS` instrumented build in
  `docs/bounds.md`. **`docs/bounds.md` remains the primary defence; no sanitizer replaces
  the bounds table.**
- GCC rejects the flag outright, so `make ubsan` probes for it and prints a warning
  naming exactly what is lost when it is absent.
- The Docker targets pin `CXX=clang++`: the container ships both, and Debian's `c++`
  resolved to g++, silently dropping this check.

---

### ADR-013: Golden model writes its own Keccak and implements the NTT
Date: 2026-09-20 | Phase: 1 | Status: Accepted

**Decision:** `tests/model/model_keccak.cpp` is an independent, literal Keccak-f[1600] and
sponge written for the model. The model also implements FIPS 203 Algorithms 9-12 (NTT,
NTT^-1, MultiplyNTTs, BaseCaseMultiply) literally, with plain `% q` arithmetic, alongside
an independent `schoolbook_negacyclic`.

**Rationale, Keccak:** Phase 3 vendors an optimized FIPS 202 into `third_party/fips202/`.
If the model shared it, a bug in the vendored code would be invisible to every
differential test. Writing a separate slow one makes Phase 3 a real cross-check. It is
validated against FIPS 202 known answers (SHA3-256/512, SHAKE128/256, empty and "abc")
and against the FIPS 203 (4.6) chunked-squeeze equivalence.

**Rationale, NTT:** spec §10.2 says "multiplication via schoolbook negacyclic convolution,
not NTT". That cannot apply to the model as a whole: FIPS 203 **serializes the NTT
representation** — `ek_PKE = ByteEncode_12(t_hat)`, `dk_PKE = ByteEncode_12(s_hat)` — so
byte-identical keys are impossible without Algorithms 9-12. The spec's intent is honoured
by keeping the arithmetic naive (`int32_t`, canonical `[0, q)`, no Montgomery, no lazy
reduction) and by providing schoolbook as the **independent** oracle. The model's own test
suite asserts `invntt(multiply_ntts(ntt(a), ntt(b))) == schoolbook(a, b)` over 100 random
pairs, which is spec §5.3 test 2 applied to the model itself.

**Consequences:** The model is slow by construction and that is correct. From Phase 2 on,
`tests/unit/test_model.cpp` doubles as the differential oracle for the real
implementation. The model's `decaps_internal` uses a plain `if` for the implicit-reject
branch and is explicitly commented as **not** the constant-time artefact — it must never
be cited as evidence that the branchless path is right.

---

### ADR-014: *(number intentionally unused)*
Date: 2026-09-20 | Status: N/A

Never allocated. Phase 3's ADR text was written against a placeholder that did not exist
and silently no-oped, so ADR-015 and ADR-016 were referenced by `docs/reference/invariants.md`,
`docs/reference/invariants.md`, source comments and two commit messages before they existed in this file.
Recovered in Phase 5 by writing them at the numbers already cited rather than renumbering
live cross-references. This entry exists so the gap is not read as a lost decision.

**Process consequence:** every scripted edit to a state file must assert its anchor. A
`replace()` that matches nothing prints success and changes nothing — the same
silent-no-op failure mode as the stale-build and empty-tie-set bugs already in
`docs/reference/invariants.md`.

---

### ADR-015: Vendor pq-crystals/kyber scalar FIPS 202; ctgrind it in Phase 3
Date: 2026-09-20 | Phase: 3 | Status: Accepted

**Decision:** Vendor `ref/fips202.c` and `ref/fips202.h` from `pq-crystals/kyber` at
commit `3edd5af5991927164edd4aacebfcbee00b8064e7` into `third_party/fips202/`, unmodified.
`src/symmetric.cpp` wraps it with length bookkeeping and no logic.

**Phase 3 vendored the scalar path only; Phase 8a extended this record to the 4-way
batched path from the SAME pin.** The full file list, provenance and licences are in the
table at the end of this ADR. Read that table, not this paragraph, for what is vendored.

**Rationale:** Pre-approved by the copying policy (ADR-003) and recommended by spec §7.1:
Keccak will be the majority of the cycle count and a hand-rolled one will not be
competitive. CC0 / public domain. Upstream `main` was confirmed to be **ML-KEM, not
round-3 Kyber**, by checking for the `buf[KYBER_SYMBYTES] = KYBER_K` domain separator in
`indcpa.c` — irrelevant to FIPS 202 itself, but the provenance record should say what was
inspected.

**Constant-time status — VERIFIED, not assumed.** This is the first phase where secret
data (`σ`, `r`, `d`, `z`) flows through third-party code, so the CT check ran here rather
than at Phase 9.

*By inspection:* no lookup tables anywhere; `chi` is pure bitwise
`BCa ^ ((~BCe) & BCi)`; every array subscript is a literal, a loop counter, or `i/8`/`i%8`
on a position — **no index derives from message data**, and in absorb the data is the
XORed value, never an address; `KeccakF_RoundConstants[round]` is indexed by the public
round counter; every branch tests a length.

*By ctgrind* (`tests/ct/ct_keccak.cpp`, `gmake docker-ctgrind`): `PRF<2>`, `PRF<3>`,
`G(d‖k)`, `G(m‖H(ek))` and `J(z‖c)` run with secret inputs marked
`VALGRIND_MAKE_MEM_UNDEFINED`. **Zero errors**, with `H(ek)` and the XOF as public-input
controls.

**Consequences:** built with `THIRDPARTY_CFLAGS` (no `-Werror`/`-Wpedantic`), excluded
from `gmake format`, never reformatted, local modifications **none** (re-verified
byte-identical against upstream). `fips202x4` was wired in Phase 8a behind the same
`symmetric.hpp` interface, as planned. Differentially tested against the model's independent Keccak
(ADR-013) — the reason that implementation exists.


---

### ADR-015 (extended, Phase 8a): the complete vendored FIPS 202 file list

`docs/reference/invariants.md` requires **every vendored file** to carry repo, commit, licence, local path and
local modifications. Phase 8a added nine files; this table is the single record for all
eleven. **One vendoring decision, one entry** — `fips202x4` is not a separate ADR.

All files are taken from **`pq-crystals/kyber` @ `3edd5af5991927164edd4aacebfcbee00b8064e7`**
and are **byte-identical to upstream — local modifications: NONE**, re-verified by direct
comparison against the pinned raw URLs on 2026-09-22 (all 11 `IDENTICAL`).

| Local path | Upstream path | Phase | Copyright / licence |
|---|---|---|---|
| `third_party/fips202/fips202.c` | `ref/fips202.c` | 3 | pq-crystals — CC0 / public domain |
| `third_party/fips202/fips202.h` | `ref/fips202.h` | 3 | pq-crystals — CC0 / public domain |
| `third_party/fips202/fips202x4.c` | `avx2/fips202x4.c` | **8a** | pq-crystals — CC0 / public domain |
| `third_party/fips202/fips202x4.h` | `avx2/fips202x4.h` | **8a** | pq-crystals — CC0 / public domain |
| `keccak4x/KeccakP-1600-times4-SIMD256.c` | `avx2/keccak4x/…` | **8a** | **Keccak/Keyak/Ketje Teams** (Bertoni, Daemen, Peeters, Van Assche, Van Keer) — CC0 waiver |
| `keccak4x/KeccakP-1600-times4-SnP.h` | `avx2/keccak4x/…` | **8a** | Keccak Teams — CC0 waiver |
| `keccak4x/KeccakP-1600-unrolling.macros` | `avx2/keccak4x/…` | **8a** | Keccak Teams — CC0 waiver |
| `keccak4x/KeccakP-SIMD256-config.h` | `avx2/keccak4x/…` | **8a** | Keccak Teams — CC0 waiver |
| `keccak4x/KeccakP-align.h` | `avx2/keccak4x/…` | **8a** | Keccak Teams — CC0 waiver |
| `keccak4x/KeccakP-brg_endian.h` | `avx2/keccak4x/…` | **8a** | **Brian Gladman** (1998–2008) — **BSD-style, WITH CONDITIONS** |

**THE LICENCE SET IS NOT UNIFORM, and the body of this ADR above says "CC0 / public
domain" because in Phase 3 it was.** Three distinct situations now:

1. **pq-crystals files** — CC0 / public domain, as before.
2. **`keccak4x/` (most)** — a *different upstream author*, the Keccak/Keyak/Ketje Teams,
   vendored via pq-crystals. CC0 waiver, but the attribution header names the
   implementers and points at `keccak.noekeon.org`. Not pq-crystals' work.
3. **`keccak4x/KeccakP-brg_endian.h`** — **Brian Gladman, and NOT public domain.** It is a
   BSD-style licence with explicit conditions: source distributions must retain the
   copyright notice and licence terms, binary distributions must reproduce them, and the
   copyright holder's name may not be used to endorse products derived from it.

**Consequence — an obligation, not a note.** Condition 1 is satisfied today only because
the files are unmodified and the headers are intact, which is exactly what the
never-reformat rule already enforces. **Condition 2 is not yet satisfied by anything in
this repo: a binary distribution would need to reproduce the Gladman notice.** Nothing is
distributed today, so nothing is wrong today — but Phase 10 packaging MUST carry a
third-party licence file reproducing all three notices. Logged as a Phase 10 task in
`docs/reference/invariants.md`.

**`avx2/align.h` was fetched in Phase 8a and is NOT vendored.** Nothing includes it and
the build succeeds without it (verified by deleting it and rebuilding). It was removed
rather than left in place: an unused vendored file carries licence and provenance
obligations while providing nothing, and a future reader would reasonably assume it is
load-bearing.

**How this record was produced.** Not from memory — by listing `third_party/fips202`,
reading the licence header of every file, and `cmp`-ing each against its pinned raw URL.
It exists because a session crash mid-Phase-8a left ADR-022 asserting that "ADR-015's
record" had been "extended" when no such extension had been written, and the nine new
files had no provenance entry at all for a day. **When an ADR claims another ADR was
updated, check the other ADR.**

---

### ADR-016: What ctgrind can and cannot detect
Date: 2026-09-20 | Phase: 3 | Status: Accepted

**Decision:** Record the measured sensitivity of the ctgrind harness and keep dudect
(Phase 9) as a complement rather than treating ctgrind as sufficient.
`tests/ct/ct_keccak.cpp --selftest` plants one leak of each detectable class, and
`ctgrind-run` fails if valgrind does not report them.

**Rationale:** A CT harness that cannot see a leak is worse than none, because it looks
like evidence. Measured in the container at `-O3`:

| Leak class | Detected? |
|---|---|
| Secret-dependent memory index (`table[secret]`) | **yes** |
| Secret-dependent loop bound | **yes** |
| Early-exit loop on a secret (the `memcmp` shape) | **yes** — 32 findings |
| Simple `if (secret & 1)` | **NO** — clang flattens it to a branchless select at `-O3` |
| Secret-dependent `div` / `mod` | **NO** — valgrind models values, not timing |

**Consequences:**
- **Use the SIGNED truncation variant.** `-fsanitize=implicit-integer-truncation` also
  covers *unsigned* truncation, which is not UB and is the whole point of byte
  extraction — the vendored `store64` trips it on every hash. Narrowed to
  `-fsanitize=implicit-signed-integer-truncation`.
- **The `div`/`mod` ban cannot be enforced by ctgrind.** ADR-018's `audit-div` gate
  covers it at the machine level; dudect covers the timing dimension. Three tools, three
  different blind spots.
- The `if (secret)` result is benign *here* but must not be relied upon: a different
  optimization level may emit the branch. Write branchless code.
- Early-exit detection is the encouraging one: a `std::memcmp` in `Decaps_internal`
  **would** be caught at Phase 6 — failure mode #10.

---

### ADR-017: Phase 8 optimizes for the ONE-SHOT workload; batched Keccak goes first
Date: 2026-09-20 | Phase: 4 | Status: Accepted

**Decision:** **One-shot is the primary workload.** Phase 8 follows spec §9.2's ordering —
4-way batched Keccak first, AVX2 NTT second — even though a cached-`Â` batch workload
would prefer the reverse.

**Rationale:** Measured for all three operations (`gmake bench`, stable over five runs;
TSC ratios, so scale-free):

| Operation | hash % | 4× Keccak | 3× NTT | prefers |
|---|---|---|---|---|
| KeyGen | 58–62 % | **1.75–1.88×** | 1.33–1.40× | Keccak |
| Encaps, `Â` re-expanded | 53–64 % | **1.66–1.92×** | ~1.32× | Keccak |
| **Encaps, `Â` cached** | **33–37 %** | 1.33–1.38× | **~1.81×** | **NTT** |
| Decaps | 50–54 % | **1.60–1.69×** | 1.44–1.50× | Keccak *(marginal)* |

Caching `Â` removes the 9 `SampleNTT` streams — most of the hashing — and inverts the
ordering. That case is real (`batch::encaps` against one `ek`, permitted by FIPS 203
§3.3), but it is one specific batch shape, and three of four measured cases favour
Keccak.

**Consequences:**
- Phase 8 order: batched Keccak → AVX2 NTT → lazy reduction → SIMD compress/CBD.
- **Re-measure after the NTT is optimized.** Today's arithmetic is inflated by a
  deliberately unoptimized NTT, so the cached-`Â` verdict is partly self-fulfilling.
- If the batch API becomes a priority, evaluate the cached-`Â` path on its own terms.
- Decaps is marginal and should not be cited as support either way.

---

### ADR-018: `audit-div` is a permanent machine-level gate
Date: 2026-09-20 | Phase: 4 | Status: Accepted

**Decision:** `gmake audit-div` disassembles every library object and fails on any
`div`/`idiv` not covered by an explicitly justified allowance. It runs as part of
`docker-all` and carries a **positive control**: it compiles `a / b` first and fails
loudly if the detector cannot find that division.

**Rationale:** ADR-016 established that ctgrind is provably blind to secret-dependent
`div`/`mod`. `docs/reference/invariants.md` bans the instruction; nothing else enforced it.

**Source-level enumeration is demonstrably insufficient.** Phase 4 found a `divl` inside
`ntt()` that appears **nowhere in the source** — the compiler strength-reduced the
inner-loop counter into `k += 255/(2·len)`. Any audit that greps C++ misses that class
entirely.

The positive control exists because Phase 4's first detector used a `\b` pattern BSD grep
does not honour and silently reported zero for everything, **including a deliberate
control**. Verified in both directions: passes clean, and a division planted in
`symmetric.cpp` makes it fail with the offending instruction printed.

**Consequences:**
- Allowance: `ntt.o` ≤ 1, the compiler-inserted layer-counter division, traced in the
  disassembly to the `$0x80` seed and therefore public. Phase 8 drops it to 0.
- Raising an allowance requires tracing the divisor in the disassembly and adding a
  justification row to `docs/bounds.md`.

---

### ADR-019: `audit-refs` — every cited ADR must resolve
Date: 2026-09-20 | Phase: 5 (housekeeping) | Status: Accepted

**Decision:** `gmake audit-refs` scans every `.md`, `.cpp`, `.hpp`, `.sh`, `.py` and the
`Makefile` for `ADR-nnn` citations and fails if any does not resolve to a `### ADR-nnn`
header in `DECISIONS.md`. It runs as part of `docker-all` and carries a **positive
control**: it plants a dangling reference in a scratch tree and fails loudly if the
detector cannot find it.

**Rationale:** ADR-015 and ADR-016 were cited by the project's own documentation, source
comments and two commit messages **for two phases before they existed**. A scripted edit
targeted a placeholder that was not present, `replace()` matched nothing, and it printed
success. Nothing noticed, because nothing was looking.

**WHAT IT DOES NOT CATCH — read this before trusting a green result.** It detects
**dangling** references only: a citation with no ADR behind it. It **cannot** tell
whether an ADR that *does* exist still says what the citing text claims. The same
housekeeping pass that added this gate also found `docs/reference/invariants.md` asserting that ADR-004
was "still Proposed and deliberately unfilled — do not guess it", three phases after
Phase 2 filled it and mirrored it into `docs/reference/invariants.md`. That reference **resolved**; it was
simply false, and directly contradicted `docs/reference/invariants.md` about the most dangerous convention
in the project.

Stale-but-resolving prose is therefore held by the **rewrite-don't-append rule** in
the project's process rules — at every phase end, rewrite the rolling state file's
"Current state" and "Key decisions this session" rather than appending. **A green `audit-refs` means the
citations point somewhere, not that the documentation is accurate.**

**Consequences:**
- The tool excludes `build/`, `third_party/` and the ACVP vectors. Its own selftest
  fixture is built from string parts so the literal never appears in the file — the
  first version flagged itself, which is the gate working correctly on the wrong input.
- It also reports ADRs defined but never cited outside `DECISIONS.md`. Not a failure,
  but an uncited ADR is often one superseded without being marked.
- Verified in both directions: passes clean, and a dangling reference planted in
  `docs/reference/invariants.md` makes it fail and names the citing file.

---

### ADR-020: Declassify rho in K-PKE.KeyGen for constant-time testing
Date: 2026-09-21 | Phase: 6a | Status: Accepted

**Decision:** `kpke_keygen` declassifies **exactly 32 bytes — rho, never sigma** — right
after `(rho, sigma) = G(d || k)`, via `MLKEM_CT_DECLASSIFY` in `src/ct_declassify.hpp`.
The macro compiles to nothing unless `MLKEM_CT_TESTING` is defined, which only the
ctgrind binaries' separate library build sets. The shipped `libmlkem768.a` contains no
trace of it.

**Rationale:** ctgrind reported `sample_ntt`'s rejection loop as a secret-dependent
branch inside `kpke_keygen` when `d` was marked secret. Traced in the valgrind output:
`sample_ntt <- gen_matrix <- kpke_keygen`.

**It is not a leak.** `rho` is `G(d || k)[0:32]`, so memcheck propagates `d`'s marking to
it — but `rho` is copied **verbatim into ek and published** (pinned by a unit test).
FIPS 203 and spec §8.1 permit variable time on it explicitly: *"Variable time is fine for
anything depending only on public data: rho, ek, A_hat, c."* An attacker reads `rho` out
of `ek` regardless; `sample_ntt`'s timing tells them nothing further. memcheck simply
cannot know that a value derived from a secret is later published.

**DECLASSIFICATION IS DANGEROUS and this one is deliberately narrow.** Each use asserts
"this is public output", and a wrong assertion silences a real leak while making ctgrind
agree with you. Two properties were therefore verified rather than assumed:

1. **`sample_ntt` is still watched.** `ct_kpke --encrypt-secret-ek` marks `ek` secret and
   still produces findings — the declassification did not blanket-silence the function.
2. **The sigma -> CBD path is still watched.** A non-elidable secret-indexed table load
   was planted in `sample_poly_cbd<2>`; `--keygen-secret-d` returned **99 (caught)** with
   it and **0 (clean)** without. Declassifying `rho` did not silence the secret path.

**Two earlier control attempts were defeated by the optimizer**, which is itself the
ADR-016 lesson arriving in practice: `if (x > y) {A} else {A}` was flattened to `A`, and
`+t[x] - t[x]` had both loads cancelled. Only a `volatile` table survived `-O3`.
**A planted control must be checked for survival, not just planted.**

**Consequences:**
- The 32-byte length is load-bearing. Declassifying all 64 would expose `sigma`, whose
  PRF output *is* the secret key, and property 2 above would no longer hold.
- CT binaries link `$(CT_BUILD)/libmlkem768.a`, built with `MLKEM_CT_TESTING`. Keeping
  that separate from the shipped archive is what makes "no trace in the library" true
  rather than aspirational.
- Any future declassification needs the same treatment: a justification comment, an ADR
  entry, and a verified control proving the surrounding path is still watched.

---

### ADR-021: Declassify rho at the K-PKE.Encrypt boundary (the decaps re-encrypt path)
Date: 2026-09-21 | Phase: 6b | Status: Accepted | Extends: ADR-020

**Decision:** `kpke_encrypt` declassifies the 32-byte `rho` window at
`ek + POLYVEC_BYTES`. This is a **second, wider** declassification boundary than
ADR-020's and is justified here separately. **ADR-020's narrowness proof does not
transfer**, because it covers a different call path.

**The diagnosis, from the trace and not from guessing.** `ct_kem --decaps-secret-dk`
returned 99. All **27 contexts** were `sample_ntt <- gen_matrix <- kpke_encrypt <-
decaps_internal`, and **zero** mentioned `ct_neq`, `ct_cmov` or `ct_opaque`. So the
constant-time comparison this phase exists to get right was clean; the findings were
entirely the rejection loop.

**Why it differs from ADR-020.** ADR-020 declassifies `rho` where **KeyGen derives** it
from secret `d`. Here `Decaps_internal` re-encrypts, so `ek_PKE` is a pointer **into
`dk`** — and `dk` is secret in its entirety (`docs/reference/invariants.md` lists "all of `dk`"). `rho`
therefore arrives tainted by a **second, independent route**, through a function ADR-020
never touched.

**Why it is still correct.** `rho` is the tail of `ek`, the encapsulation key, published
at keygen. `docs/reference/invariants.md` already lists `ek` among the values variable time is fine for. An
attacker holds `ek`; `sample_ntt`'s timing on `rho` adds nothing. What is **not**
declassified: the other 1152 bytes of `ek` (`t_hat`), any part of `dk_PKE`, `z`, or
`h` — only the 32-byte `rho` window.

**Fresh narrowness proof for THIS path** (ADR-020's method, re-run rather than assumed):
a `volatile` secret-indexed table load was planted in `poly_tomsg`, which derives `m'`
inside `kpke_decrypt` and is squarely on the secret path through `decaps_internal`.

| | `ct_kem --decaps-secret-dk` |
|---|---|
| leak planted on the secret path | **exit 99 — still caught** |
| leak removed | **exit 0 — clean** |

Declassifying `rho`-via-`dk` did not silence the secret path.

**CONSEQUENCE THAT BIT IMMEDIATELY: this declassification SILENCED A POSITIVE CONTROL.**
Phase 6a's `ct_kpke --encrypt-secret-ek` marked `ek` secret and required findings, since
`rho` fed `sample_ntt`. Declassifying `rho` on entry to `kpke_encrypt` makes that control
**clean by construction** — it did not break, it became **vacuous**, which is worse: a
vacuous control still prints OK.

It was caught only because `ct_expect_findings` requires **exit 99 specifically**. A
"nonzero" check — the form this project used until Phase 5 — would have reported OK
forever. That is the concrete payoff of hardening the controls.

Resolution: the mode is repurposed to clean-expected and documented in place rather than
deleted, because the reason it changed is the lesson. `sample_ntt`'s watchability is
still proven by `ct_sample --ntt-secret`, which marks `rho` directly, never passes
through `kpke_encrypt`, and still returns 99.

**Standing rule this establishes: after adding any declassification, re-check every
positive control that could have depended on the value being tainted.**

**Consequences:**
- There are now **two** declassification sites, both 32 bytes, both `rho`, neither ever
  `sigma`. Any third one needs its own ADR and its own proof — the count is small
  deliberately, and a growing list is a signal that something is being silenced rather
  than understood.
- `--decaps-memcmp` still returns 99 after the fix, so the positive control that makes
  the clean results meaningful is unaffected.

---

### ADR-022: Phase 8 copying policy — STUDY-THEN-WRITE, and explain the technique
Date: 2026-09-21 | Phase: 8 | Status: Accepted | Decided by: the human, not the agent

**Decision:** For Phase 8, read `pq-crystals/kyber`'s `avx2/` code **for technique and
understanding**. Write the implementation from that understanding. **Do not copy source.**
Whenever a technique learned from their code is used, **explain it in the commit message
and in `docs/notes/`, in the author's own words, as if teaching someone who has not seen
it.**

**Rationale (the human's, recorded verbatim in substance):** the point of this project is
to understand how real optimized cryptography is built, not merely to possess working
optimized cryptography. **If you cannot explain why a technique works, you have not
understood it well enough to have written it yourself.** The explanation is therefore not
documentation overhead — it is the acceptance test for the copying policy.

This sharpens ADR-003 rather than replacing it. ADR-003 said "read for technique, do not
copy". ADR-022 adds the verification: an explanation, in your own words, of *why* the
technique works.

**Scope:** all four Phase 8 workstreams — 4-way Keccak, AVX2 NTT, lazy reduction, SIMD
compress/CBD. **All four are in scope; ADR-017 sequences them, it does not drop any.**

**Interaction with the pre-approved FIPS 202 exception.** ADR-003 and `docs/reference/invariants.md`
pre-approve vendoring Keccak wholesale, and `fips202x4` is vendored under that exception
(ADR-015's record, extended — one coherent vendoring decision, not a second provenance
entry). ADR-022 still applies to the *surrounding* work: the dispatch layer, the batched
wrappers, and the call-site restructuring are written here, and the technique — why four
independent sponges fit in one AVX2 register file, and why these particular streams are
independent — is explained in `docs/notes/08a-batched-keccak.md`.

**Consequences:**
- Every Phase 8 sub-phase produces a `docs/notes/0N-*.md` aimed at a human reading the
  codebase later, not at a resuming session. `docs/reference/invariants.md` carries a one-line pointer
  only, the pattern already used for `MUTATION.md` and `docs/bounds.md`.
- A technique that cannot be explained does not ship. That is a stopping condition, not
  a documentation debt.

---

### ADR-023: ADR-017's Keccak estimate was optimistic; the gap is only PARTLY explained
Date: 2026-09-21 (revised 2026-09-22) | Phase: 8a | Status: Accepted

**Decision:** Record the measured Phase 8a result, correct ADR-017's magnitude estimate,
and record honestly that the decomposition **does not fully close**. ADR-017's *ordering*
decision stands unchanged.

**Measured** (TSC ticks; median of **21 interleaved A/B/C triples**, see Method below):

| Operation | A: baseline `76b6c13` | B: 8a portable | C: 8a AVX2 | A/C total | B/C SIMD alone |
|---|---|---|---|---|---|
| KeyGen | 110 869 | 110 800 | 83 124 | **1.41x** | 1.38x |
| Encaps | 130 573 | 117 840 | 90 856 | **1.38x** | 1.35x |
| Decaps | 159 763 | 144 510 | 115 193 | **1.32x** | 1.27x |

ADR-017 predicted 1.75-1.88x / 1.66-1.92x / 1.60-1.69x.

**How much of the gap is explained.** KeyGen ladder, each step substituting one corrected
term:

| | prediction |
|---|---|
| 0. ADR-017's model: ALL hashing (~68%) at 4x | 2.03x |
| 1. only the **batchable** hashing (~58%) at the measured primitive 3.98x | 1.77x |
| 2. batchable at its measured **block** rate 2.79x, not the primitive rate | 1.60x |
| 3. **measured in situ** | **1.41x** |

- **Effect 1 — not all hashing is batchable.** `G(d||k)` and `H(ek)` are single streams
  with nothing to pair them with. Worth ~0.26x.
- **Effect 2 — the batched blocks carry unbatched work.** `gen_matrix` improves 2.95x
  and the noise draws 2.14x, short of the primitive's 3.98x, because `rej_uniform` and
  `sample_poly_cbd` stay scalar byte-wise code in both paths. Worth ~0.18x.

**The two effects together account for roughly two-thirds of the gap and leave ~0.19x
(12%) unexplained.** This is stated as an open residual, not as a closed budget. An
additive cross-check of the same components falls **19% short** of the measured in-situ
KeyGen, which is the direct evidence that the component numbers are biased: the
microbenchmarks run hot-cache in tight loops and understate what the same code costs
inside a full KeyGen. Do not quote the component figures as an exact budget.

> **Superseded claim, kept deliberately.** The first version of this ADR asserted the
> budget "reconciles to 1.6%". That came from a single dataset in which the baseline and
> the component measurements were taken at different times, and this host drifted ~18%
> between them. It did not survive re-measurement. The lesson is in Method below.

**Method (this host cannot be measured casually).** rdtsc here is a constant-rate
reference clock, not a retired-instruction counter, and does not track turbo.

- **Per-triple A/C ratios ranged 1.04x to 1.71x.** A single run, or a "before" run
  compared against an "after" run taken minutes later, is worthless.
- Only **medians over >=20 interleaved runs** are meaningful, and the before/after
  binaries must alternate so drift falls inside each pair rather than between the groups.
- The Phase 7 baseline is measured by building `76b6c13` in a `git worktree` and
  alternating the two binaries -- not by trusting a number recorded in an earlier session.
- **Sanity control:** the A/B probe also times a code path that is *identical* in both
  trees. Its ratio must come out ~1.00; it came out 0.96, which is the measurement floor
  and also caught that the Phase 8a `sample_ntt` refactor made the scalar path ~4%
  slower.

**FOLLOW-UP (Phase 8d part 3, 2026-09-28).** Part 3 stated its Amdahl prediction before
implementing and came out consistent with it (predicted 1.047x/1.077x, measured
1.050x/1.074x). **That is not a demonstration that the method is fixed.** The predicted
effect was 4.7%/7.6% against a +-3-4% floor; KeyGen, whose true value is exactly 1.000x
by construction, measured 1.011x, so ~1% of each figure is noise; and the prediction
assumed a 3x function speedup where the real numbers were **2.16x** (`compress_du`) and
**2.48x** (`decompress_du`), putting the corrected model at 1.033x/1.056x -- about 1.8
points *below* what was measured. Two errors in opposite directions roughly cancelled.

The hypothesis that measuring the share **in situ**, rather than composing hot-cache
micro-benchmarks as here, is what closed the gap remains **plausible and unproven** on two
data points. Keep measuring shares in situ; do not cite it as an established method.

**Consequences:**
- The corrected rule of thumb: apply the 4x only to the *batchable* hash fraction, then
  expect the enclosing block to fall short of the primitive by whatever scalar
  post-processing it carries -- and expect a residual on top of that.
- Effect 2 is a pointer, not a dead end: it is what the SIMD compress/CBD workstream
  targets, and the arithmetic is what 8b targets.
- **Re-measure the one-shot ordering after 8b**, as ADR-017 already required.
- Full derivation and method: `docs/notes/08a-batched-keccak.md` §5.

---

### ADR-024: FP-typed *move* intrinsics in vendored 4-way Keccak are not FP operations
Date: 2026-09-21 | Phase: 8a | Status: Accepted

**Decision:** The `pd`/`ps`-typed intrinsics in `third_party/fips202/fips202x4.c` and
`keccak4x/` do **not** violate `docs/reference/invariants.md`'s "no floating-point operation" rule, and the
rule is not amended. The basis is a machine-level check, not source inspection.

**Context:** `docs/reference/invariants.md` forbids any floating-point operation on secret data, and FIPS 203
§3.3 forbids it outright. The vendored 4-way code uses `_mm_storel_pd`, `_mm_storeh_pd`,
`_mm256_broadcast_sd` and `_mm256_permute2f128_ps` -- which reads, on inspection, like a
direct violation on a path that carries sigma and r.

**Rationale:** Those are *encodings*, not arithmetic. x86 spells several pure
data-movement instructions in the floating-point domain (`movlps`/`movhps` have no
integer-domain equivalent), and they move bits without rounding, without denormal
handling, and at fixed latency. The rule exists because FP arithmetic has
value-dependent timing; bit-preserving moves have none of that.

**Evidence** -- disassembly of all three AVX2 objects (`fips202x4.avx2.o`,
`KeccakP-1600-times4-SIMD256.avx2.o`, `symmetric_avx2.o`):

- FP-**arithmetic** mnemonics (`add/sub/mul/div/sqrt/cvt/round/max/min/cmp` in
  `ss|sd|ps|pd` form): **zero, in all three objects.**
- FP-**typed move** mnemonics only: `vmovaps` (385), `vmovups` (147),
  `vbroadcastsd` (34).

**Consequences:**
- Recheck with the same disassembly filter whenever the vendored files are re-pinned or
  a new AVX2 backend TU is added; source review cannot settle this question.
- Do not "fix" the vendored intrinsics to integer-domain equivalents. Never reformat
  vendored files (copying policy), and the FP spelling is deliberate and correct.
- `docs/notes/08a-batched-keccak.md` §6 carries the reader-facing version.

---

### ADR-025: the `--x4-taint` control, and exactly how narrow its proof is
Date: 2026-09-22 | Phase: 8a (retrospective) | Status: Accepted

**Decision:** `ct_keccak --x4-taint` is a permanent gate. Its proof is recorded here
**with its boundary**, in the style ADR-020/021 use for declassification, because a
taint-survival proof is only valid for the instruction classes it actually exercised.

**What it proves.** ctgrind's clean result on the 4-way path could be clean for the wrong
reason: memcheck tracks definedness per bit *through emulated instructions*, so if it
modelled `vpgatherqq` or the 256-bit lane permutes as producing DEFINED output, secret
input would emerge defined on the far side and `--secrets` would report zero findings on
a path it could not actually see. That is the ADR-021 failure mode — a control that does
not fail, but has become vacuous.

`--x4-taint` marks σ secret, runs `PRF_x4<2>`, and branches on lanes 0 **and 3** of the
output while still secret (two lanes, so a backend that taints only lane 0 is also
caught). valgrind **must** report. It does. Therefore definedness genuinely survives the
absorb-gather → permutation → squeeze-scatter chain, and the clean `--secrets` result on
the 4-way path is real evidence rather than an artifact.

**THE BOUNDARY — this is the load-bearing part.** The proof covers only the instruction
classes the vendored 4-way code actually emits, measured by disassembly:

> `vpgatherqq`, `vpxor`, `vpandn`, `vpor`, `vpsllq`/`vpsrlq`, `vpaddq`, `vpshufb`,
> `vperm2f128`, `vpunpcklqdq`, `vpbroadcastq`, `vinserti128`, and the
> `vmovsd`/`vmovq` scatter.

**It does NOT cover packed multiplies. Keccak-f has no multiply at all** — it is pure
bitwise and rotation — so `vpmullw`, `vpmulhw`, `vpsraw`, `vpaddw`/`vpsubw`, `vpshufd`,
`vpunpckhqdq` and `vperm2i128` appear nowhere in the 4-way objects and are therefore
entirely outside this control's evidence.

**AMENDMENT (Phase 8c audit, 2026-09-22) — the list above is slightly OVER-CLAIMED.**
It was produced by disassembling the whole `fips202x4` and `keccak4x` objects, which is
*what code exists*, not *what the control executes*. `--x4-taint` runs `PRF_x4<2>` only,
i.e. the **SHAKE-256** path: `shake256x4_absorb_once` → permutation → `squeezeblocks`.
It does not run `xof_x4` (SHAKE-128), and per-instruction execution coverage was not
measured. So the honest statement is: **the proof covers the code path exercised by
`PRF_x4<2>`, which contains those classes** — not every instruction in those objects.

This does not weaken the security argument, because `xof_x4` is only ever driven by `rho`
in `gen_matrix`, which is **public** (ADR-020/021); there is no secret to lose taint on
that path, so it needs no taint proof. It does mean a future change routing secret
material through `xof_x4` would need its own control rather than citing this one.

Also added by that audit: **`ct_keccak --x4-map`**, which measures what `--x4-taint`
previously assumed — that all four lanes are tainted, not just the probed 0 and 3.

**Consequences:**
- **The AVX2 NTT (Phase 8b) is built precisely on the uncovered classes**: Montgomery
  multiplication is `vpmullw`/`vpmulhw`, Barrett is `vpmulhw` + `vpsraw`, and the
  intra-vector layers are `vperm2i128`/`vpunpck*qdq`/`vpshufd`. **A clean ctgrind run on
  the AVX2 NTT may NOT cite ADR-025.** It requires its own taint-survival control
  exercising the multiply and shuffle classes before a clean result means anything.
- Same rule for any future SIMD backend (compress/CBD, AVX-512): **extend the control to
  the new instruction classes first, then trust the clean run.** Do not generalize a
  taint proof across instruction classes; memcheck's shadow propagation is per-operation.
- Re-check this boundary whenever the vendored files are re-pinned — a new upstream
  revision could change the emitted set.

---

### ADR-026: the inverse NTT does not share the forward zeta lane tables
Date: 2026-09-22 | Phase: 8b | Status: Accepted

**Decision:** The AVX2 inverse NTT uses its OWN generated lane tables. The recorded 8b
design said it could reuse the forward ones; that was wrong and is corrected here so the
error is on the record rather than only in a commit message.

**What was wrong.** The design gave one uniform zeta-index formula,
`k = k_base + i/(2*len)`, derived from Algorithm 9. Algorithm 9 counts `k` **up** from 1;
**Algorithm 10 counts it DOWN from 127.** A layer has exactly `k_base` groups, so the
inverse's group `s` uses `k = (2*k_base - 1) - s` -- each layer's zeta sequence is the
forward layer's **reversed** (`len=2` runs 127..64 where forward ran 64..127).

**Why it mattered.** Reusing the forward tables would have produced a fully
self-consistent inverse transform that failed every KAT with no obvious cause -- the same
failure class as a transposed `A_hat` (docs/reference/kat-failure-checklist.md #3). It was caught on the
first differential run against the portable `invntt`, before anything was wired.

**Guard:** `kLane8Inv` / `kLane4Inv` / `kLane2Inv` are generated from the same shuffle
mimics via `zeta_index_inv`, and a `static_assert` requires each to differ from its
forward counterpart, so a later edit cannot quietly collapse them back together.

**The rest of the recorded design was correct** -- layer/vector mapping, the
split/recombine shuffles for all three intra-vector layers, both SIMD reduction forms,
and the predicted `len=2` zeta lane layout, which the generated table reproduced exactly.

**Consequence / lesson:** a design derived from the forward algorithm does not
automatically describe its inverse. When a recorded design is handed forward for
execution, the executing session must still differential-test each half independently
rather than assuming symmetry -- which is what "execute, but flag anything that turns out
wrong" is for.

---

### ADR-027: the SIMD rejection sampler's data-indexed table is permitted; nothing else's is
Date: 2026-09-26 | Phase: 8d | Status: Accepted

**Decision:** `src/arch/avx2/rej_table_avx2.hpp` may index a 256-entry compaction shuffle
table by a mask derived from XOF output. **This is the only data-indexed table in the
library and the only place one is permitted.**

**Why it looks like a violation.** `docs/reference/invariants.md`'s constant-time rules forbid "memory
addresses derived from secrets (table lookups, array indices)". `kRejShuffle[mask]` is
literally a table lookup on a data-derived index, and a future session reading this file
cold will flag it. This ADR exists so that reader stops and checks the argument instead
of "fixing" it — and so that the argument is written down where it can be checked.

**Why it is nonetheless correct.** The index is a bitmask of which 12-bit candidates were
`< q`. Those candidates come from SHAKE-128 seeded with `rho ‖ j ‖ i`, and **`rho` is
public**: FIPS 203 publishes it verbatim as the tail of `ek`, `docs/reference/invariants.md` lists it among
the values variable time is fine for, and `sample_ntt`'s rejection loop is *already*
variable-time by design — spec Appendix B forbids bounding it. The table index leaks
exactly what the loop's iteration count already leaks, to an attacker who can recompute
both from `ek`. It adds no new observable.

**The boundary, stated so it can be enforced.** The permission attaches to *this path*,
not to the technique:

- **`sample_poly_cbd` must never use this or any data-indexed table.** Its input is
  `PRF(sigma, N)` and its output *is* the secret key; it is branchless and table-free by
  construction, and that asymmetry with `sample_ntt` — opposite requirements in one file
  — is documented in `src/sample.hpp`'s banner.
- Routing any secret (`sigma`, `r`, a CBD input, `dk`) through `rej_uniform` would make
  this a real leak. Nothing does today.
- A second data-indexed table anywhere else needs its own ADR, not a citation of this one.

**Verification, not assertion.**
- The table is **generated** `consteval`, never transcribed, and all 256 entries are
  checked at runtime against what `_mm_shuffle_epi8` *actually does* — accepted lanes at
  the front, order preserved, count equal to `popcount`, tail zeroed
  (`tests/unit/test_avx2.cpp`). Same three-way discipline as the NTT zeta lane tables.
- `ct_sample --ntt-secret` still **fires**, and the ctgrind gate now additionally
  requires the run to report `backend: AVX2 (SIMD rej_uniform)` — a control that
  exercised the scalar fallback while the library dispatches SIMD would have proved
  nothing about the shipped code, which is the vacuous-pass failure of ADR-021/025.

**Consequences:** `audit-div` is unaffected (no division). If a future parameter set or
API routes secret material into `sample_ntt`, this ADR is void and the table must go.

---

### ADR-028: a register-resident `vpshufb` with a secret selector is NOT a table lookup
Date: 2026-09-26 | Phase: 8d | Status: Accepted

**Decision:** The SIMD CBD may use a 16-entry nibble→coefficient map applied with
`vpshufb`, with the **secret** nibble as the selector. This does not violate `docs/reference/invariants.md`'s
ban on table lookups indexed by secret data, and it does **not** rely on ADR-027.

**The distinction, which is subtle enough to be worth writing down.**

| | forbidden | this |
|---|---|---|
| where the table lives | memory | a register (`xmm`) |
| what the index does | computes an address | selects a lane |
| leak channel | which cache line is touched | none — no memory is accessed |
| timing | depends on cache state | `vpshufb` is fixed-latency, value-independent |

`docs/reference/invariants.md`'s rule exists because a memory-resident table indexed by a secret makes the
*address* secret-dependent, and cache timing recovers it. `vpshufb` computes no address:
both operands are registers, nothing enters a cache, and the instruction's latency and
throughput are constant on every microarchitecture implementing it. It is a permutation,
not a load. Replacing it with arithmetic would be slower and no safer.

**Why this is a separate ADR from ADR-027 rather than a citation of it.** ADR-027 permits
a genuinely memory-resident, data-indexed table in `rej_uniform`, and its justification
is entirely that **ρ is public**. That argument does not transfer to CBD, whose input is
`PRF(σ, N)` and whose output *is* the secret key. The two permissions rest on unrelated
grounds and must not be merged: if someone later routes a secret into `rej_uniform`,
ADR-027 dies and ADR-028 is unaffected; if someone moves this LUT to memory, ADR-028 dies
and ADR-027 is unaffected.

**Verified, not asserted (ADR-025).** Disassembling `cbd_avx2.o` gives `vpshufb`,
`vpmovsxbw`, `vpunpcklbw`/`vpunpckhbw`, `vpand`, `vpsrlw`, `vpshufd`, `vpbroadcastb`.
Phase 8a's `--x4-taint` covered `vpshufb` only with a **constant** selector; here the
selector is the secret, which is a materially different question — a permute whose *index*
is undefined could plausibly have been modelled as producing defined output, which would
have made the clean run vacuous. `ct_sample --cbd-map` measures it: **all 256 output
coefficients come back tainted**, so definedness does survive. `--cbd-taint` then fires as
required, and only then does `--cbd` count. The Makefile runs them in that order.

**Consequences:** any future SIMD backend using a secret selector may cite this ADR; one
using a *memory* table on secret data may not, and needs its own argument or a redesign.

---

### ADR-029: SIMD CBD is KEPT despite a flat end-to-end result — a weighed exception
Date: 2026-09-27 | Phase: 8d | Status: Accepted | Decided with the human

**Decision:** Phase 8d part 2 (SIMD CBD, η=2) stays in the tree even though it produced
**no measurable end-to-end gain**: `sample_poly_cbd<2>` is 3.901× and the noise block
1.380×, but KeyGen/Encaps/Decaps came out 1.004× / 0.992× / 1.012× — inside this host's
±3–4 % floor.

**This is the first optimization in the project to add SIMD code on SECRET data for no
measurable end-to-end gain.** It is recorded as an exception so the precedent is *"this
was weighed"*, not *"function-level wins are kept automatically"*.

**Why kept:**
- **Exhaustively verified, not sampled.** CBD at η=2 is byte-local, so 256 byte values ×
  128 positions is the complete input→output map — and the byte-locality claim the
  exhaustiveness rests on is itself checked.
- **Constant-time proven with its own controls**, not inherited: `--cbd-map` measures
  that taint survives a `vpshufb` whose *selector* is the secret (a case 8a's control did
  not cover), `--cbd-taint` fires, and only then does `--cbd` count.
- **Its share grows as everything around it shrinks.** The noise draws are ~9 % of a
  KeyGen today; every future win elsewhere raises that fraction, and this work is then
  already banked and verified.
- **Learning value**, which spec §1 lists as a project goal alongside performance.

**The cost, stated plainly:** new constant-time surface on secret data. More SIMD acting
on `σ`-derived material means more code where a future edit can introduce a real leak, and
more that Phase 9's validation must cover.

**Contrast with what was REJECTED** — 8c sites #5/#6, reverted on a similar-looking
measurement. Those were 0.97× end-to-end with **no function-level win and no mechanism**:
nothing to bank, so the added surface bought nothing. The distinction that decides these
cases is whether there is a real, mechanistic, verified win at the function level waiting
for its share to grow — not whether the end-to-end number is flat.

**Consequences:** cite this ADR when keeping a verified optimization whose end-to-end
effect is inside the noise floor. **Do not cite it for one that is merely unmeasured** —
the measurement is what makes this a decision rather than a hope. If Phase 9 finds the
extra CT surface costly to validate, revisiting this is legitimate.

---

### ADR-030: spec §1 criterion 4 — missed at 1.8–2.0×, now MET at ~1.41× after Phase 9a
Date: 2026-09-28 | Phase: 8 close-out | Status: Accepted
*Updated 2026-09-29 (Phase 9a): criterion now met on all three operations — see the
POST-9a update below. The original miss is left on the record, unedited.*

**Decision:** Record the miss. **The criterion is not revised to fit the result.**

**Measured** (first time; §1 criterion 4 had never been tested — every prior figure in
this project is self-relative, this repo against an earlier commit of itself):

| operation | ours | pq-crystals AVX2 | ratio |
|---|---|---|---|
| KeyGen | 46 278 | 25 643 | **1.81×** |
| Encaps | 50 840 | 26 438 | **1.92×** |
| Decaps | 60 210 | 29 453 | **2.03×** |

**Method, because a cross-project number is easy to get wrong.** Their code built outside
this repo at ADR-015's pin `3edd5af5`; same compiler, flags and machine; **both linked
into one process** and measured interleaved — comparing the two projects' own speed-test
binaries would compare harnesses, not implementations; deterministic entry points on both
sides so OS RNG cost skews neither. A cross-project comparison **cannot** use this
project's usual byte-identity sanity control, since there is no code identical to both
sides; that limitation is stated with the number rather than papered over.

**What is NOT concluded.** The gap is plausibly their hand-written assembly NTT/basemul
(`ntt.S`, `invntt.S`, `basemul.S`, `shuffle.S`) plus a SIMD basemul this project never
wrote — but that is a hypothesis until measured per component. Both sides use the same
4-way Keccak, so the entire difference is in non-hash code.

**POST-8e UPDATE (2026-09-28).** Phase 8e (AVX2 basemul + the decompress fix) closed
roughly half the gap:

| operation | pre-8e | **post-8e** | criterion |
|---|---|---|---|
| KeyGen | 1.81x | **1.53x** | <=1.5x — miss, marginal |
| Encaps | 1.92x | **1.60x** | miss |
| Decaps | 2.03x | **1.60x** | miss |

**Still unmet. The criterion is still not revised.**

**A measured lead on closing it, for Phase 9.** `secure_zero` is a byte-at-a-time
volatile store loop running at **1.50 B/tick against memset's ~40 B/tick — 27x slower**.
KeyGen zeroizes ~5217 bytes, costing ~3000-3500 ticks, about 8% of the operation;
pq-crystals zeroizes nothing at all. If Phase 9 can make it memset-speed **without making
it elidable**, the estimated head-to-head becomes **1.41x / 1.46x / 1.43x — inside the
criterion on all three.**

That is an *estimate*, not a result: the byte counts are derived from the `Zeroizing`
wrap list rather than instrumented, and "memset-speed while still non-elidable" is the
hard part, which is precisely why it belongs to Phase 9 alongside the per-site
destructor-elision check that uses the same disassembly tooling. **Zeroization itself is
never the thing to remove** — it is FIPS 203 §3.3 compliance, and the cost is paid on
purpose.

**POST-9a UPDATE (2026-09-29) — the criterion is now MET on all three operations.**

Phase 9a step 2 replaced `secure_zero`'s byte-at-a-time volatile loop with a wide
`memset` held in place by a compiler barrier. Measured head-to-head, median of 9 runs,
same one-process interleaved method as above:

| operation | pre-8e | post-8e | **post-9a** | criterion |
|---|---|---|---|---|
| KeyGen | 1.81x | 1.53x | **1.413x** | <=~1.5x — **MET** |
| Encaps | 1.92x | 1.60x | **1.416x** | **MET** |
| Decaps | 2.03x | 1.60x | **1.403x** | **MET** |

End-to-end effect of the change alone, baseline worktree at `e3667ed`, 20 alternating
pairs: **KeyGen 1.086x, Encaps 1.101x, Decaps 1.151x**. Decaps gains most because it
zeroizes the most (~7200 B).

**The estimate above held up.** It predicted 1.41 / 1.46 / 1.43 and the measurement came
in at 1.413 / 1.416 / 1.403 — recorded because this project's estimates have not always
survived contact (ADR-023's prediction was only *consistent with* its result, not
confirmed by it). This one was derived from wrap-list byte counts and is now instrumented.

**We meet the criterion while doing strictly MORE work than the reference.**
pq-crystals/kyber does not zeroize at all. This implementation erases all 27 wrapped
stack secrets on every operation, verified per site by `audit-zeroize-sites`, and is
still inside ~1.5x. That is the honest framing: the comparison is not like-for-like and
it is unfavourable to us, not to them.

**What did NOT change:** the mechanism is faster, never weaker. `audit-zeroize` still
passes with a plain memset as its negative control, and removing the barrier was checked
to collapse `secure_zero` to a bare `ret` and fail both gates — so the erase is still
provably present. See ADR-034.

**Also recorded as a known remaining gap, cause not yet measured:** `gen_matrix` is still
+3408 ticks behind despite both sides running the *identical* vendored 4-way Keccak. Not
investigated. **This is now the largest known remaining gap** — with zeroization closed,
it is the obvious next lead if criterion 4 ever needs more headroom.

**Consequences:**
- The result stands in `docs/reference/invariants.md` as a measured fact, not as a target to be edited.
- A per-component breakdown is the next step; scope for any Phase 8e follows from it,
  not from this ADR.
- Spec §1's other criteria are unaffected: correctness (80/80 ACVP, plus bit-identical
  interop with an independent implementation) and constant-time discipline are met.
- **If a later session cannot close the gap, the honest outcome is to record that §1
  criterion 4 is unmet and why** — not to restate the criterion.

---

### ADR-031: the packed NTT output order is EXCLUDED from Phase 8e — deliberately
Date: 2026-09-28 | Phase: 8e | Status: Accepted | Decided with the human

**Decision:** Phase 8e writes an AVX2 basemul **on our current, portable-order layout**.
Adopting pq-crystals' permuted internal NTT order is **excluded**, and this is a decision
on the record — not another inherited omission like §9.2 item 4 (ADR-030 / the §9.2 audit).

**What they actually do, confirmed from their source, not assumed:**
- `basemul.S`'s schoolbook macro loads `a0` at `+0`, `b0` at `+16`, `a1` at `+32`,
  `b1` at `+48` — the two halves of each degree-1 pair sit in **separate contiguous
  16-element blocks**, so the multiply needs **no deinterleave at all**.
- `poly_nttunpack` is applied **only to matrix polynomials** (which arrive from
  `rej_uniform_avx` in a different order) and **never after `polyvec_ntt`** — so the
  packed order is `ntt_avx`'s native output, and everything downstream consumes it.

**Measured worth:** with basemul at their speed (matvec 14.7× rather than the 4–7× our
layout can reach) the end-to-end gain would be 1.19× / 1.24× / 1.26× instead of
1.15–1.17× / 1.19–1.22× / 1.20–1.23× — **about 3–4 points on top of basemul**.

**Why excluded anyway.** The NTT output order is not an internal detail here; four things
assume it, and all four would have to change together:
1. the **portable backend**, which is the differential reference and must stay
   bit-identical (`tests/unit/test_avx2.cpp`);
2. the **model differentials**, which compare coefficient-for-coefficient against the
   KAT-clean golden model (`test_arith.cpp`);
3. **serialization** — `polyvec_tobytes` and the compressors read coefficients in order;
4. the **ctgrind taint probes**, which name specific coefficient indices
   (`ct_ntt --taint-map` asserts all 256, `--ntt-taint` probes 0/8/248/255 chosen for
   their lane positions).

A 3–4 point gain does not justify changing an invariant that four gates depend on, in the
same phase as a basemul rewrite. **Revisitable only as its own sub-phase**, where the
order change lands first, alone, with every dependent gate updated in the same commit.

**Consequences:** the AVX2 basemul must deinterleave and re-interleave, and will not reach
their matvec speed. That is the accepted price, and the prediction already reflects it.

---

### ADR-032: spec §9.2 item 7 (avoid redundant NTTs in decaps) — dispositioned
Date: 2026-09-28 | Phase: 8e | Status: Accepted

**Decision:** Item 7 is **not actionable as written**, and this is its written disposition
so it never reads "never considered" again (the §9.2 audit found zero mentions of it
anywhere in the project record).

**What the spec suggests:** "In `decaps`, the re-encryption recomputes `Â` and `NTT(y)`;
some intermediates can be shared with the decryption step."

**What the code actually does.** `decaps_internal` runs `kpke_decrypt` then `kpke_encrypt`:
- **decrypt** computes `NTT(u')` from the decompressed *ciphertext*, and uses `ŝ` from
  `dk`. It never touches `Â`.
- **re-encrypt** computes `Â` from `ρ`, and `NTT(y)` where `y` is drawn from `r'`, which
  derives from the just-recovered `m'`.

So the two do **not** share intermediates: `NTT(u')` and `NTT(y)` are transforms of
different values, and `Â` is used by exactly one of the two steps. There is nothing to
reuse between them without changing what is computed.

**The real opportunity is item 6, not item 7.** `Â` depends only on `ρ`, so it could be
cached **across calls** that share a key — which is exactly ADR-017's cached-`Â` analysis,
already deferred to the batch API in Phase 10. Item 7 as phrased appears to conflate
"recomputed within one decaps" with "recomputed across decaps calls"; only the latter is
avoidable.

**Consequences:** item 7 is closed as not-actionable. If a future reader disagrees, the
burden is to name the specific intermediate that both steps compute — this ADR asserts
there is none, and that claim is checkable against `src/kpke.cpp`.

---

### ADR-033: `audit-state` — mechanising the part of the rewrite rule that can be
Date: 2026-09-28 | Phase: 8 close-out | Status: Accepted

> **STATUS IN THIS DISTRIBUTION: REMOVED.** `audit-state` and `audit-markers` both checked
> the freshness of a rolling state file that is not part of this release, so both gates and
> the state file were dropped together. The ADR is kept because its *conclusion* generalizes
> and is cited elsewhere: a mechanical check on a document's date cannot catch stale prose
> under a fresh date, and the answer to that is not another gate.

**Decision:** `gmake audit-state` was a permanent gate in `docker-all`. It fails if
the rolling state file's Current state is demonstrably older than the code it describes.

**Why.** The rewrite-don't-append rule has now failed **six times**. Five were in deferred
lists, Makefile comments or source comments. **The sixth was in "Current state" — the
section a fresh session reads first.** After Phase 8 shipped, it still said Phase 8e was
expected, Next action still listed a close-out that was already done, and Key decisions
was headed Phase 7. A fresh session following it would have redone finished work.
`audit-markers` cannot reach this: it checks that source markers point at live rows, not
whether the narrative is current.

**What it checks** — deliberately only what is mechanical:
1. the `*Updated: YYYY-MM-DD` stamp is not older than HEAD's commit date;
2. the highest phase ticked in "Done and verified" is named in "In progress" (or its
   successor, so "Phase 8e done → Phase 9 next" passes).

**WHAT IT CANNOT CATCH, and this is the point of writing it down.** **Stale content under
a fresh stamp.** Bumping the date satisfies check 1 without rewriting a word, and check 2
catches only the one shape where a phase completed and "In progress" never heard. Prose
that is confidently wrong while well-formed is exactly what this gate is blind to, and
that remains **the rewrite rule's job**. A green `audit-state` means "not obviously
stale", never "accurate" — the same distinction `audit-refs` draws between a resolving
reference and a true one.

**Positive control:** `--selftest` backdates the stamp in a scratch copy and requires the
detector to flag it. Runs before the real check.

**Consequences:** three gates now cover three different staleness shapes — `audit-refs`
(dangling ADR citations), `audit-markers` (deferral markers pointing at dead rows),
`audit-state` (a state file older than its code). None of them checks whether the prose is
*true*. If the rule fails a seventh time inside a fresh stamp, the answer is not a fourth
gate; it is that the phase-end rewrite is not actually being done.

---

### ADR-034: `audit-zeroize-sites` — proving the erase happens at every wrap, not
just that `secure_zero` survives
Date: 2026-09-29 | Phase: 9a | Status: Accepted

**Decision:** `gmake audit-zeroize-sites` is a permanent gate in `docker-all`. It checks
that **every** declared `Zeroizing<T>` wrap produces a destructor erase in the emitted
code, at the real build flags. It complements `audit-zeroize`, which it does not replace.

**Why.** `audit-zeroize` compiles one synthetic function and proves `secure_zero` is not
elided **in isolation**. It has never said anything about the 27 real wrap sites. An
inlined destructor on a 1536-byte `PolyVec` is exactly where the optimizer could decide
the stores are dead, and nothing would have noticed: no KAT can see a missed erase, and
ctgrind does not model it either. FIPS 203 §3.3 makes the erase mandatory, so an
unverified erase is an unverified `shall`.

**The wrap count was wrong in the state file.** It said 24 wraps (13 in
`kpke.cpp`, 11 in `kem.cpp`). The measured figure is **27** — 16 in `kpke.cpp`, 11 in
`kem.cpp`. The undercount was in `kpke.cpp`, whose declarations bind several objects per
line (`Zeroizing<PolyVec> s, e;` is two wraps, and `noise_x4`'s `b0, b1, b2, b3` is four).
Counting declaration *lines* rather than objects loses three. The gate derives the number
itself now, so it cannot drift again.

**Method, and why not the obvious one.**
- Ground truth is parsed from the **`.cpp` sources**; observed erases come from the
  **object's DWARF**. Deriving both from DWARF would have been circular.
- The first implementation counted `zeroize.hpp:<loop>` line markers in the disassembly.
  **That over-counts.** The 32-byte erase in `decaps_internal` compiles to a peeled first
  byte store plus a 4×-unrolled loop — two markers, one site — and it reported 8 events
  for 7 wraps. `DW_TAG_inlined_subroutine` is emitted once per inlined instance whatever
  shape the loop took, so the gate counts those instead.
- A function can be **both emitted out-of-line and inlined into a caller** (clang does
  this to `encaps_internal`), which duplicates its erase events. Expected counts are
  scaled by the instance count read from the DWARF rather than the duplicates being
  explained away.

**A cross-platform blind spot, found by running it in the container.** Where macOS/libc++
inlines the complete-object destructor `D1` (which then calls an out-of-line `D2`),
Linux/libstdc++ emits a **bare call** to `D2` with no inlined DIE at all. Counting only
inlined DIEs therefore reported all five 64-byte wraps as unerased **on Linux only** —
a false positive, not a regression: `objdump -dr` showed seven real relocated calls to
the destructor. The gate now counts inlined dtor DIEs **plus** relocated calls to
out-of-line destructors, attributed to the innermost enclosing scope by address, and
de-duplicates calls that sit inside an already-counted DIE. **Both platforms now report
27 wraps / 29 events identically.** This is the second time a check written against one
toolchain proved to mean something different on the other.

**Positive control.** The control cannot simply delete a wrap: that removes the
declaration too, so expected and observed both drop and the gate still passes — a
vacuous control of exactly the shape the Process rule warns about. Instead the control
lives in a **worktree** (never the working tree) and patches `~Zeroizing` to skip the
erase for one `sizeof(T)`, leaving all declarations intact so ground truth is unchanged.
Run at sizes 33, 64 and 1536, on **both** platforms: each fails and names the exact
missing sites by file, line and variable. Size 64 is the one that matters most — it is
the out-of-line-destructor path that the blind spot above hid.

**The plant was confirmed to be real, not optimized away.** Because this control *removes*
code, "survival" means confirming the erase truly left the machine code: `kpke_decrypt`
drops from 6 zero-byte stores and 117 instructions to **0 and 100**. The gate is detecting
absent stores, not an absent DWARF record.

**LIMITS — these are real and are not closed by this gate.**
1. **It is valid only for the build flags it runs under.** It compiles single translation
   units. **If LTO is ever enabled, every result here must be re-established**, because
   the optimizer would then see across TU boundaries and could eliminate stores this
   per-TU check proved present.
2. **`secure_zero` erases the named object — not copies the compiler made of it.** Values
   spilled to stack slots, held in registers, or copied into temporaries are not reached
   by any `Zeroizing<T>` destructor, and no amount of disassembly auditing of the wrap
   sites changes that. This is a **known, unclosed limitation of zeroization in C++**, not
   something this project can fix; claiming the secrets are fully erased from memory would
   overstate what is true. See README's zeroization note.

**RE-RUN AFTER THE STEP-2 CHANGE (2026-09-29).** `secure_zero` became a wide `memset`
plus a barrier. Both gates re-run on the new implementation: **27/27 sites still erasing,
identically on macOS and Linux**, and `audit-zeroize` still passes with the memset
negative control still eliminated. Note the emitted shape changed — `noise_x4` is now
inlined four times instead of emitted once (41 raw erase events instead of 29), which the
instance-scaling handles; a check that had hard-coded the event total would have broken
here.

**The negative control got stronger, and the threshold had to change to stay honest.**
`audit-zeroize`'s floor was 8 instructions, calibrated against the old byte loop (~140
instructions for 64 bytes). A wide erase of the same 64 bytes is ~11 on macOS and **5 on
Linux** — four `movaps` of a zeroed register plus the `xorps`, verified by disassembly to
cover the whole buffer. **The old floor of 8 would have failed the correct new
implementation on Linux.** The criterion is now the property rather than the number: the
erase must be materially larger than the eliminated control, not a bare `ret`.

**New positive control, and it is a better one than the old mechanism allowed.** Because
survival now rests entirely on the barrier rather than on `volatile`, the barrier itself
is the thing to attack: removing it (in a worktree) collapses `secure_zero` to a **single
instruction — a bare `ret`** — and **both** gates fail, `audit-zeroize` on the count and
`audit-zeroize-sites` reporting 0 erases at all 27 sites. That is a direct demonstration
of the exact failure mode the gates exist to catch, which the volatile-loop mechanism
could never produce on demand.

**A measured claim that turned out to be wrong, recorded so it is not repeated.** The
first reading of the disassembly blamed the 27x on the old loop reloading its pointer
before every byte (`auto* volatile q` is a volatile *pointer*, not a pointer to volatile).
Measured across all six wrap sizes on both platforms, fixing only that reaches ~1.5 B/tick
against the original ~1.3 — a marginal gain. The cost was the volatile semantics
themselves, which forbid merging byte stores into wide ones. Dropping `volatile` entirely
and holding the line with the barrier is what reaches memset speed.

**WHAT `audit-zeroize-sites` CHECKS, PRECISELY: PRESENCE PER SITE, NOT BYTE COVERAGE.**
It answers "does a destructor erase exist at each of the 27 wraps?" — it counts erase
events, and it does **not** verify that any given erase covers the whole object. A wrap
whose erase covered only half its bytes would still count as one event and the gate would
still read 27/27. The two gates divide the work and neither subsumes the other:

| gate | question | scope |
|---|---|---|
| `audit-zeroize` | does the erase cover **every byte**? | one synthetic 64-byte buffer |
| `audit-zeroize-sites` | does an erase **exist at every site**? | all 27 real wraps |

So byte coverage is verified for the *mechanism* on a known size, and presence is
verified at *every site*. Full byte coverage at all 27 sites is checked by neither
directly; it follows only from the mechanism being size-generic (`memset(&value,
sizeof(T))`), which is an argument, not a measurement. Recorded as the honest limit.

*(Byte coverage was added to `audit-zeroize` on 2026-09-29, replacing an instruction
count. The count could not distinguish a complete erase from a partial one — a 64-byte
erase is `xorps` + four 16-byte stores and a 48-byte erase is `xorps` + three, and the
old rule passed both. Verified by control: shortening the erase by one store is now
caught as "48 of 64 bytes -- PARTIAL", and the old rule passed exactly that case.)*

**Consequences:** the gate is a floor, not a ceiling — it proves each declared wrap erases
its own object at the current flags. It does not prove the secret exists nowhere else in
memory, and it will need re-running, not trusting, after any toolchain or flag change.

---

### ADR-035: `gmake dudect` — own t-test, host-only, and component rows are advisory
Date: 2026-09-29 | Phase: 9b | Status: Accepted

**Decision:** `gmake dudect` is a host-only gate. It gates on the TOP-LEVEL targets
(decaps, encaps) and reports the component targets as **advisory**, for a measured
reason given below. It is deliberately **not** in `docker-all`.

**dudect's licence, as instructed.** `oreparaz/dudect`, `src/dudect.h`, **MIT**,
copyright Oscar Reparaz 2016–today, SHA-256 of the file fetched 2026-09-29
`3fb3b2bd7f9e17ae34b7c92518c1311c67342c56facc80da925d85f121b649da`. Permissive, so
vendoring was permitted. **It was not vendored**, and not for licence reasons:

- dudect drives everything through two `extern` globals, `do_one_computation` and
  `prepare_inputs` — one measured target per binary. Phase 9b has nine.
- `max_t` is computed inside dudect's static `report()` and only *printed*. Reporting
  actual max |t| per target would have meant scraping it back out of stdout.

So the statistics are dudect's **method**, reimplemented in `tests/ct/ttest.hpp`:
class-randomized measurement, Welch's t, and the same test over a ladder of percentile
crops. Nothing is vendored, so no provenance row is needed; the URL is recorded above
because it materially influenced the design.

**Host, not Docker.** Docker on this Mac is a VM, which interposes a virtualization
layer on precisely the quantity being measured, and timing behaviour is a property of
this silicon rather than of the OS image. `docker-dudect` exists for comparison only.
It is out of `docker-all` for the same reason plus runtime.

**CALIBRATION FIRST, AND IT FOUND TWO BUGS IN THE HARNESS.** Writing your own t-test
risks a gate that cannot fail, so the harness plants leaks and must detect them.

1. A **KyberSlash-shaped** plant — Compress_1's division with a secret dividend, the
   2023 pq-crystals bug — is detected at |t| ≈ 2900. The plant makes the divisor
   `volatile` to force a real `div`, reproducing the leak CLASS. It lives only in the
   test TU, so `audit-div` stays clean.

   **Why this library is not vulnerable to it — corrected wording.** Not "because `q` is
   a compile-time constant": the reference's divisor was *also* a constant, and whether it
   became a `div` instruction depended on the compiler and the flags, which is exactly why
   KyberSlash hit some builds and not others. The two actual reasons are
   **(a)** the source never divides secret data at all — Phase 4 derived a multiply-shift
   with `consteval` and proved it exhaustively, so there is no division in the source to
   compile, and **(b)** `gmake audit-div` proves, at the machine level, that no `div`/`idiv`
   survives anywhere in `libmlkem768.a`, including any the compiler might have inserted.
   (a) alone would be a source-level argument that a different compiler could invalidate;
   (b) is what makes it a checked property of the shipped binary.
2. **The delay ladder was wrong the first time, and the ladder itself exposed it.**
   Written as `if (secret_bit) { loop N times; }` it reported |t| ≈ 140 for N = 1000 and
   for N = 1 alike — perfectly flat. It was measuring the *presence of the branch*, whose
   misprediction cost is about the same whatever the body does, not a delay of N cycles.
   Rewritten so the loop always runs and the secret adds `delta` iterations, it scales
   properly: delta 1000 → 124, 3 → 67, 1 → 22.8.
3. **The NULL CONTROL (delta = 0) then failed at |t| = 10.5**, and that was a real bug in
   the harness: `prepare()` did different work per class — class 1 ran hundreds of RNG
   steps that class 0 did not, immediately before the timed region, leaving different
   cache and predictor state perfectly correlated with the class label. Every target had
   it. Fixed by always generating the random input and selecting branchlessly, so both
   classes execute identical instructions and only the resulting bytes differ. The null
   control then reads 1.41.

**SENSITIVITY IS PER-TARGET AND THE FIRST VERSION OF THIS ADR GOT IT WRONG.** It claimed
a 1-cycle floor and that "every clean result is clean only to that resolution". The 1-cycle
figure was measured on the ~200-cycle calibration loop, which has low variance. `decaps` is
~40 000 ticks with variance orders of magnitude larger, so a 1-cycle leak inside `decaps` is
invisible and the figure does not transfer.

**Measured in context instead.** The same ladder was planted inside `decaps`'s
secret-dependent path — a branchless delay gated on `m_prime[0] & 1` — in a **worktree**,
so the library source is never modified in the repo. Confirmed to survive `-O3` by
disassembly (a real loop with a back edge, gated on the secret) before any result was
trusted. Detection holds at **100 cycles** (|t| 13.6–31.1) at both 38 k and 250 k samples,
**fails at 50**, and is erratic below. More samples barely help: the variance is decaps's
own, not the counter's.

> **The top-level floor is ~100 cycles — about 0.22 % of a 45 000-tick operation. That is
> what "top-level clean" means.**

**BATCHED TIMING (K = 32) CHANGED THE COMPONENT PICTURE, AND THE EARLIER REASONING WAS
WRONG TWICE.**

- It was wrong to discount |t| = 40 as "below rdtsc resolution". Averaging resolves mean
  gaps well under one tick and the t-statistic already accounts for noise. The correct move
  was to fix the instrument, not argue about it. Batching K repetitions inside one `rdtsc`
  pair amortizes its overhead and quantization, and the fixed-vs-fixed control then fell
  from 42.2 → 2.1 (`ntt`), 54.3 → 1.9 (`invntt`), 55.5 → 3.9 (`compress_du`). So most of
  the original signal *was* instrument overhead — but shown by intervention, not asserted.
- It was also wrong to read the attributability control as *evidence against* a leak. Two
  constant inputs with different mean timing means timing depends on something that differs
  between the classes: the values (which for secret input is a leak) or their placement.
  Placement is already controlled here — every target writes both classes' input into the
  **same** working buffer, so address, alignment and cache set are identical — so the
  discriminating test is the **swap**: exchange which value each class uses, keep the label.
  `dmean` flipping sign means the difference follows the value.

**PER-ROW DECISIONS (1.9 M samples, K = 32).** Component rows now gate where the evidence
decided them and stay advisory, with a reason, where it did not:

| target | decision | basis |
|---|---|---|
| `invntt`, `polyvec_compress_du` | **clean under batching — GATED** | test and fixed-vs-fixed control both < 7 at 1.9 M |
| `poly_tomsg` | advisory; magnitude bounded ≤ ~0.2 ticks/call | novelty-vs-similarity INCONCLUSIVE — the REPEAT baseline reads as high as NOVEL |
| `ntt` | **DECIDED: machine/instrument, not our code** | differential — pq-crystals shows it at |t| 22.7 vs our 10.0; our scalar path at 10–40× our AVX2's dmean |
| `basemul`, `sample_poly_cbd<2>` | not value-dependent, erratic — advisory | fixed-vs-fixed clean; `dmean` sign wanders at < 0.2 ticks |

**`ntt` IS NOW DECIDED, by differential control rather than by argument** (`gmake
dudect-ntt-diff`). The switching-power story never fitted the design — frequency scaling
reacts over tens of microseconds, one K=32 measurement is ~2 µs, and the class is randomized
per measurement, so a frequency excursion should smear across both classes rather than align
with one. So three implementations were run through an **identical** harness — same K,
sample count, fixed values, fixed-vs-fixed and swap controls — across three seeds:

| implementation | max \|dmean\| | max \|t\| (fixed-vs-fixed) |
|---|---|---|
| our AVX2 `ntt` | **1.1 – 2.9** | 2.4 – 10.0 |
| our portable **scalar** `ntt` (no SIMD) | 12.8 – 42.1 | **1.7 – 4.8 — not significant** |
| **pq-crystals** AVX2 `ntt` (independent) | 3.2 – 4.4 | **7.3 – 22.7** |

**The conclusion rests on the pq-crystals row, and the rows must be read by |t| rather than
by `|dmean|`** — `|dmean|` is a raw tick gap that scales with how long the function runs,
while |t| measures that gap against its own noise.

- pq-crystals' AVX2 NTT, an independent implementation on the same machine through the same
  harness, shows the effect at **|t| 7.3–22.7, above our 2.4–10.0**. Both AVX2
  implementations show it; theirs more strongly. **This is the decisive comparison.**
- **The scalar row is INCONCLUSIVE, not a stronger showing.** Its `|dmean|` is larger, but
  its fixed-vs-fixed **|t| is 1.7–4.8, not significant**: the scalar NTT is ~30× slower, so
  a larger raw gap inside proportionally larger noise is evidence in neither direction. An
  earlier version of this ADR read it as corroboration; it is not.
- Our AVX2 having the smallest `|dmean|` is not what a defect would look like, but on its own
  that is weak and the argument does not lean on it.

> **Decision: both AVX2 implementations show a tiny value-dependent effect, which points to
> this CPU running this class of code rather than to anything this implementation introduced.
> NOT a red gate.**
>
> **Bounded at ≤ ~0.2 ticks per call — not zero.** The claim is that the effect is not ours,
> and is far below the ~100-cycle floor at which anything is observable at the API.

This also reframes the other advisory rows: the same ~0.02–0.2 ticks-per-call effect appears
on whatever code goes through this harness, which is why per-row verdicts below that
magnitude were never going to be stable.

**`poly_tomsg`: "novelty, not value" is NOT CONFIRMED, and the test says so.** That reading
assumed the effect keys on *exact* repetition; if it graded with partial similarity between
successive inputs it would carry information about how much the secret-derived `w` changed.
`gmake dudect-tomsg-sim` compares class 1 as a fresh random `w`, as the base `w` with **one
coefficient** changed, and as a second constant. At 1.9 M samples the three regimes land at
|t| 12.2–16.7, 13.5–19.0 and 7.2–12.2 — **the REPEAT baseline reads as high as NOVEL**, so
the harness's own floor is as large as the difference under test and near-repeat cannot be
placed against either baseline. The harness prints INCONCLUSIVE rather than picking a side.

What is established instead, and it is the part that matters: **every per-call gap is ≤ ~0.2
ticks against a ~100-cycle top-level floor** — a factor of several hundred — and the same
effect appears in pq-crystals' independent code, so it is not a property of `poly_tomsg`.
Settling novelty-versus-similarity needs a lower-floor instrument (fixed-clock core, or
performance counters instead of `rdtsc`). Recorded open **with the magnitude bound stated**,
not resolved by assertion.

**What IS established.** The top-level targets run ~40 000 ticks, far above the counter's
resolution, and are stable: **clean across three seeds and both fixed-class values, worst
|t| = 6.99, controls below 3.5.** That covers spec §10.3's requirement that decaps runtime
not depend on ciphertext validity, and the two secret-input tests.

**Class design follows ADR-020's lesson, applied to timing.** Every public value — ρ, ek,
Â, c — is held constant across both classes, because varying a KeyGen seed varies ρ and
therefore `sample_ntt`'s trip count, which is *permitted* variable time and would be
reported as a leak it is not. The one deliberate exception is the valid-vs-invalid
ciphertext test, where a public value varies on purpose because that variation IS the
property under test. Per-target statements are in `docs/notes/09-dudect.md`.

**Two fixed-class values per test, as required:** all-zero and a fixed random value. They
do differ — `sample_poly_cbd` read 1.97 (zero) against 17.51 (random) on one run — which
is exactly why one of them alone would not have been enough.

**Consequences:**
- Spec §12's Phase 9 exit ("dudect |t| < 10") is met **for the top-level API**, with the
  component-level caveat recorded rather than buried.
- Batched component timing is a named follow-up, not a silent omission.
- If a later change makes a component row attributable and reproducible, ADR-030's
  criterion-4 margin is only ~0.09×, so any fix must re-measure the head-to-head.

---

### ADR-036: Phase 10 scope — batch API and cached Â are EXCLUDED; what Phase 10 is
Date: 2026-09-29 | Phase: 9 close-out | Status: Accepted | Decided with the human

**Decision:** Phase 10 is **fuzzing, then packaging, then the wrap-up summary**. Two items
the spec lists are **excluded by decision, not by omission** — the distinction ADR-031
established and ADR-030 was written to preserve.

**EXCLUDED: the batch API** (spec §3 `batch::`, §9.3).

The comparison target is a **single real-time stream**, where cross-core parallelism adds
nothing: one ML-KEM-768 operation is ~10–20 µs, comparable to thread spawn and
synchronization, and spec §9.3 says as much itself. Batching only pays when many independent
operations are queued, which this workload does not produce. **Revisitable** — it is a
scope decision about the target workload, not a judgement that the code would not work.

Consequences that must not be lost:
- **Phase 10's FIRST task is to remove or clearly mark the `batch::` declarations in the
  public header.** A header that declares an unimplemented API advertises something the
  library does not do, which is worse than not offering it.
- The deferred item *"zeroization audit of the wider surface once Phase 10 adds the batch
  API"* **closes with this reason**: there is no batch surface to audit.

**EXCLUDED: cached Â** (spec §9.2 item 6).

FIPS 203 §3.3 explicitly permits caching Â since it derives from public data, and §9.2 calls
it an enormous win — but only for the workload it describes: one encapsulation key reused
across many exchanges. **The target workload uses a fresh key per exchange**, so the cache
would never be hit and the memory would be spent for nothing. **Revisitable** if the target
workload ever changes.

With this, all seven spec §9.2 items are accounted for: done (1–5), excluded by decision
(6, and the packed NTT layout under ADR-031), or dispositioned not-actionable (7, ADR-032).

**Packaging requirement — the licence inventory is built FROM THE REPOSITORY.** Not from any
list in `DECISIONS.md`, `docs/reference/invariants.md` or this ADR. The procedure is: walk the tree for
vendored files, **read the licence header in each file**, then cross-check what was found
against `DECISIONS.md`'s provenance table and **flag every mismatch in either direction** —
a file with no table row, and a table row with no file. The vendored code has **multiple
authors and multiple licences**, so a single notice naming one of them would be wrong.

It must also cover **whatever the package actually contains**, which is decided by
inspecting the built artifact rather than assumed: in particular whether test-only
dependencies (doctest, nlohmann/json) ship inside a source tarball, because if they do they
need notices even though they never link into the library.

**Wrap-up requirement — `docs/SUMMARY.md`.** Written for a capable C++ engineer with **no
background in cryptography and none in this project's history**, who should never have to
look anything up. Rules, because they are what makes it usable:
- every technical term explained in plain words on first use, or not used at all;
- **why before how**;
- numbers stated with their meaning, never bare;
- **no ADR numbers, file paths or tool names in the main text** — those belong in one short
  "where to look" section at the end;
- layered: a one-page overview that stands alone, then deeper sections;
- **include what did not work and what is still unknown.**

**And it gets tested, not just written.** A fresh session is given **only** `SUMMARY.md`,
acts as that reader, and lists every term it did not understand and every claim it could not
follow. Fix and repeat until the list is short. A summary whose readability was never tested
is an assertion about readability.

**Energy runs once, after Phase 9 closes and BEFORE Phase 10**, on final code. If Phase 10's
fuzzing forces a library fix, **the energy run is repeated** — and ADR-030's criterion-4
head-to-head is re-measured too, since it is met by only ~0.09×.

**Consequences:**
- Two spec items are now on the record as deliberate exclusions with a stated workload
  assumption, so a later session finding them missing reads a decision rather than a gap.
- Phase 10 has three deliverables and a first task, not an open-ended list.
- The licence inventory and the summary both have a defined verification step, which is what
  separates them from work that merely looks done.

---

### ADR-037: packaging — contents, the licence inventory, and three findings
Date: 2026-09-30 | Phase: 10b | Status: Accepted

**Decision:** `gmake package` produces `mlkem768-<version>.tar.gz` containing a **compiled
binary distribution and no sources**: `lib/libmlkem768.a`, `include/mlkem/*.hpp`, `LICENSE`,
`THIRD_PARTY_NOTICES.txt`, `README.md`, `MANIFEST.txt`. The version is read out of
`src/version.cpp` by the Makefile so the tarball name and the string the library reports
cannot drift. Version bumped `0.0.0-phase0` → **0.1.0**.

**Why contents are a decision and not a convenience:** they determine which third-party
notices are legally required. Verified by inspecting the built artifact rather than assumed —
`ar t` shows `fips202.o`, `fips202x4.avx2.o` and `KeccakP-1600-times4-SIMD256.avx2.o` in the
archive, so the pq-crystals, Keccak Teams **and Brian Gladman** notices all apply, and
Gladman's **condition 2 requires its notice to accompany a binary distribution**. `nm` on
the same archive reports **zero** doctest or nlohmann symbols, so those two test-only
dependencies are not shipped and their notices are not required *here* — a source tarball
would change that, which is why the contents are pinned rather than left open.

**THE CONSUMER TEST WAS BUILT FIRST AND PROVEN ABLE TO FAIL.** `gmake consumer-test`
installs to a temporary prefix and compiles a program with only `-I<prefix>/include`, nothing
from `src/`. Against the pre-existing install it failed with
`fatal error: 'mlkem/mlkem768.hpp' file not found`. That is the point: **every other test in
this project includes headers straight out of `src/`, so none of them could detect that
`make install` shipped no usable API at all.** `gmake package-test` runs the same program
against the *unpacked tarball*, so what is verified is what ships.

---

**FINDING 1 — the public header never existed, and nothing noticed for four phases.**
Deviation #3 recorded that "the real `mlkem768.hpp` lands in Phase 6". It did not.
`include/mlkem/` held only `version.hpp`, `make install` copies `include/mlkem/*.hpp`, and
the declarations lived in `src/kem.hpp`, which is not installed. Now written, per spec §3
minus the batch API (ADR-036).

*Deviation from spec §3, recorded:* the header omits `keygen_from_seed` / `keygen_seeded`.
Those were never implemented, and providing them at packaging time would mean either a new
library symbol or exposing the internal API through the public header. **Omitted and
recorded rather than improvised.** Also, the shipped ABI takes pointers and lengths rather
than the `std::array`/`std::span` signatures spec §3 sketches; the typed forms are provided
as inline forwarders over it, so callers get the spec's ergonomics without new symbols.

**FINDING 2 — the internal API is NOT hidden, only undeclared.** Spec §3.1 intends the
`*_internal` entry points to be unavailable without `MLKEM_ENABLE_INTERNAL_API`. Verified by
`nm` on the **default-built** archive, and they are all present:

```
mlkem768::keygen_internal   mlkem768::encaps_internal   mlkem768::decaps_internal
mlkem768::kpke_keygen       mlkem768::kpke_encrypt      mlkem768::kpke_decrypt
```

The macro gates the **declarations** in the header, as `src/kem.hpp` itself says; it does not
affect the symbols. A caller who writes the prototype themselves can link straight to them.
`-fvisibility=hidden` does not help: it governs dynamic symbol tables, and this is a static
archive. **Recorded, not silently fixed** — the honest statement is "these are undeclared,
not inaccessible". Closing it properly means localizing the symbols at packaging time
(`objcopy --localize-symbol` or an LTO internalize pass), which is a real change with its own
risks and belongs to a decision, not a packaging afterthought.

**FINDING 3 — the provenance table claims completeness and is incomplete.**
`DECISIONS.md`'s `## Third-party provenance` table opens "Every file not written in this
repository. No exceptions" and lists **4 files**. Walking the repository finds **12** vendored
code files. The missing 8 *are* documented — in ADR-015's own extended table, added in
Phase 8a — so nothing is unrecorded, but the table that advertises itself as the complete
register is not, and it is the one carrying commit hashes and local-modification status.
**Reported rather than resolved silently**, per the packaging instruction; the notices file
was built from the repository walk, so it does not depend on either table being right.

Two smaller observations from actually reading the headers:
- `keccak4x/KeccakP-SIMD256-config.h` carries **no licence header at all** — its content is
  three `#define`s. ADR-015 lists it as "Keccak Teams — CC0 waiver", which is an inference
  from its siblings, not a statement in the file. Three configuration macros are very
  unlikely to attract copyright and the enclosing package is CC0, so nothing is in doubt —
  but the notices file states it as an inference.
- `fips202.h`, `fips202x4.c` and `fips202x4.h` also carry no licence header; their provenance
  is the pq-crystals commit. `fips202.c`'s header names the public-domain originals' authors
  (Van Keer, Van Assche, Bernstein, Schwabe), which ADR-015 does not; the notices file does.

**FINDING 4 — `poly_reduce` was dead code, and its comment pointed at it.** Fuzzing coverage
flagged it as reached on no path; it has **no callers anywhere**. Removed. The comment in
`ntt.cpp` claiming "ntt() applies ONE poly_reduce at the end; it is not optional" was
misleading rather than wrong: the reduction happens, as an inline `barrett_reduce` loop, not
via that helper. Comment corrected to name the real mechanism. `kat` 80/80 and `test-deep`
green after removal.

**A gate failure worth recording, because it was noise in the wrong place.** Bumping the
version failed `test-deep` — 1 assertion out of 2,097,962,267 — on
`tests/unit/test_smoke.cpp` asserting the literal `"0.0.0-phase0"`. Harmless, but it put a
red result in the one gate whose failures must always be taken seriously, for a reason with
nothing to do with correctness. The test now asserts the version's **shape** (digits, dots,
at least major.minor.patch, starts with a digit) rather than a literal, which is what
`gmake package` actually depends on since it parses that string into the tarball name.

**Consequences:**
- Two verification steps exist that did not: a consumer build against the installed tree, and
  one against the unpacked tarball. Both were proven able to fail before being trusted.
- Findings 2 and 3 are open items with stated reasons, not fixed-in-passing.
- The notices file is derived from the repository, so it stays correct even if the
  DECISIONS.md tables drift again.

---

### ADR-038: `keygen_from_seed` / `keygen_seeded` are omitted from the public API
Date: 2026-09-30 | Phase: 10b close-out | Status: Accepted | Decided with the human

**Decision:** The seed-expanded key interface sketched in spec §3 is **not provided**.
`include/mlkem/mlkem768.hpp` exposes only the randomized API. **Revisitable.**

**What it would have been.** FIPS 203 §3.3 permits storing the 64-byte seed `(d ‖ z)`
instead of the 2400-byte decapsulation key and re-deriving the key when needed — a 37×
storage saving for anything holding many keys at rest.

**Why it is omitted.** It is not needed for the target workload, which uses a fresh key per
exchange and never stores one. And it was never implemented: providing it at packaging time
would have meant either adding a new library symbol on the last day of the project, or
exposing `keygen_internal` through the public header, which would defeat §3.1's intent (see
ADR-039). Neither is a good trade against an unused convenience.

**Consequences:** callers who want it store the seed themselves and keep their own wrapper,
or the function gets added deliberately in a future version with its own tests. Recorded as a
**deviation from spec §3** in `docs/reference/invariants.md`, so a later session reads a decision rather than
finding a gap.

---

### ADR-039: the internal entry points are undeclared, not inaccessible — accepted
Date: 2026-09-30 | Phase: 10b close-out | Status: Accepted | Decided with the human

**Decision:** `MLKEM_ENABLE_INTERNAL_API` gating the *declarations* is accepted as
sufficient. The symbols remain present in the static archive and **that is stated plainly in
the README and the summary rather than implied away.** No symbol localization.

**The measurement.** `nm` on the **default-built** `libmlkem768.a` — no macro defined:

```
mlkem768::keygen_internal   mlkem768::encaps_internal   mlkem768::decaps_internal
mlkem768::kpke_keygen       mlkem768::kpke_encrypt      mlkem768::kpke_decrypt
```

All six are `T` symbols. `-fvisibility=hidden` does not help: it governs dynamic symbol
tables, and this ships as a static archive. A caller who writes the prototype themselves can
link straight to them.

**Why this is accepted rather than fixed.** FIPS 203 §3.3 says the deterministic interfaces
**"should not"** be exposed — a recommendation against offering them, not a requirement to
make them unreachable. Nothing in the public header declares them, nothing in the
documentation mentions them as usable, and a caller cannot reach them by accident: it takes
deliberately writing a prototype for an undocumented mangled C++ symbol. **Undeclared meets
the standard's intent.**

The alternative is localizing symbols at packaging — `objcopy --localize-symbol`, or an LTO
internalize pass. Both are real changes to the shipped artifact, introduced after every gate
had already run against the current one, and both carry their own failure modes (LTO in
particular would invalidate every result in ADR-034, whose zeroization checks are explicitly
valid only per-translation-unit). Trading a verified artifact for a marginal hardening on the
last day is the wrong way round.

**What makes this honest rather than convenient:** the claim is downgraded to match what is
true. The README's *Not claimed* list now says the internal functions are undeclared but
present in the archive. Had it instead said "the internal API is not exposed", that would
have been a false claim that `nm` refutes in one command.

**Consequences:**
- A future shared-library build would hide them automatically; a static archive will not.
- If symbol localization is ever wanted, it is a deliberate change with its own gate, not a
  packaging tweak.

---

### ADR-040: *(next decision)*

---

## Third-party provenance

Every file not written in this repository. No exceptions, including pre-approved ones.

**COMPLETE AS OF 2026-09-30, and verified by walking the tree rather than by recall.**
`find third_party -type f` returns 14 files: the 12 vendored ones below, plus
`third_party/README.md` and `third_party/fips202/.gitkeep`, which this project wrote.
Regenerate the check with `find third_party -type f | wc -l`.

*This table listed only 4 of the 12 for two phases while claiming "no exceptions" — the
Phase 8a additions were recorded in ADR-015's own table instead. Fixed in Phase 10b.*

| Local path | Upstream repo | Commit hash | License | Local modifications | ADR |
|---|---|---|---|---|---|
| `third_party/doctest/doctest.h` | `doctest/doctest` (v2.5.3) | `2d0a9359a60c51affe2a9bebb1be1dca47868151` | MIT — Viktor Kirilov | none | ADR-005 |
| `third_party/nlohmann/json.hpp` | `nlohmann/json` (v3.12.0) | `55f93686c01528224f448c19128836e7df245f72` | MIT — Niels Lohmann | none | ADR-010 |
| `third_party/fips202/fips202.c` | `pq-crystals/kyber` | `3edd5af5991927164edd4aacebfcbee00b8064e7` | CC0 / public domain *(elected — see the note)* | **none** | ADR-015 |
| `third_party/fips202/fips202.h` | `pq-crystals/kyber` | `3edd5af5991927164edd4aacebfcbee00b8064e7` | CC0 / public domain *(elected)* | **none** | ADR-015 |
| `third_party/fips202/fips202x4.c` | `pq-crystals/kyber` | `3edd5af5991927164edd4aacebfcbee00b8064e7` | CC0 / public domain *(elected)* | **none** | ADR-015 (Phase 8a) |
| `third_party/fips202/fips202x4.h` | `pq-crystals/kyber` | `3edd5af5991927164edd4aacebfcbee00b8064e7` | CC0 / public domain *(elected)* | **none** | ADR-015 (Phase 8a) |
| `third_party/fips202/keccak4x/KeccakP-1600-times4-SIMD256.c` | `pq-crystals/kyber` (`avx2/keccak4x/`) | `3edd5af5991927164edd4aacebfcbee00b8064e7` | CC0 waiver — Keccak/Keyak/Ketje Teams, **stated in the file** | **none** | ADR-015 (Phase 8a) |
| `third_party/fips202/keccak4x/KeccakP-1600-times4-SnP.h` | same | `3edd5af5991927164edd4aacebfcbee00b8064e7` | CC0 waiver — Keccak Teams, **stated in the file** | **none** | ADR-015 (Phase 8a) |
| `third_party/fips202/keccak4x/KeccakP-1600-unrolling.macros` | same | `3edd5af5991927164edd4aacebfcbee00b8064e7` | CC0 waiver — Keccak Teams, **stated in the file** | **none** | ADR-015 (Phase 8a) |
| `third_party/fips202/keccak4x/KeccakP-align.h` | same | `3edd5af5991927164edd4aacebfcbee00b8064e7` | CC0 waiver — Keccak Teams, **stated in the file** | **none** | ADR-015 (Phase 8a) |
| `third_party/fips202/keccak4x/KeccakP-SIMD256-config.h` | same | `3edd5af5991927164edd4aacebfcbee00b8064e7` | **NO licence header of its own** → covered by the upstream top-level `LICENSE` at this commit, quoted below | **none** | ADR-015 (Phase 8a) |
| `third_party/fips202/keccak4x/KeccakP-brg_endian.h` | same | `3edd5af5991927164edd4aacebfcbee00b8064e7` | **BSD-style, Brian Gladman 1998–2008, WITH THREE CONDITIONS — NOT public domain** | **none** | ADR-015 (Phase 8a) |

**On the two licences that are not simply "CC0", because the distinction is load-bearing:**

**1. The pq-crystals files are CC0 BY ELECTION, not by default.** The upstream top-level
`LICENSE` at commit `3edd5af5` reads, verbatim and in its entirety:

```
Public Domain (https://creativecommons.org/share-your-work/public-domain/cc0/);
or Apache 2.0 License (https://www.apache.org/licenses/LICENSE-2.0.html).

For Keccak and AES we are using public-domain
code from sources and by authors listed in
comments on top of the respective files.
```

That is a **dual licence at the recipient's option** — "or". This project **elects the public
domain / CC0 option**, which is why no Apache-2.0 notice or licence copy is required in the
package. Worth stating explicitly: had Apache 2.0 been elected instead, §4 of that licence
would have obliged us to ship a copy of it and retain its notices, so the election is a real
decision and not bookkeeping. It also settles what would otherwise be ambiguous for
`fips202x4.c/h`, which are pq-crystals' *own* wrapper code rather than vendored Keccak, and
so are not covered by the "For Keccak and AES" sentence.

**2. `KeccakP-SIMD256-config.h` is cited to the upstream LICENSE, not inferred from its
siblings.** The file carries no licence header; its entire content is three `#define`s. The
previous position inferred CC0 from the neighbouring Keccak files, which is a guess about
authorship. The upstream top-level `LICENSE` quoted above covers it directly at the pinned
commit, which is an actual authority. (Its sibling files state the Keccak Teams' CC0 waiver
in their own headers and need no such fallback.)

**3. The blanket upstream statement does NOT override a file's own explicit licence.**
`KeccakP-brg_endian.h` lives in the same vendored directory and states BSD-style terms with
three conditions in its own header. Those govern. Condition 2 requires its notice to
accompany **binary** distributions, and `libmlkem768.a` contains the object compiled from the
`.c` file that includes it — so that notice is mandatory for the shipped package, not
optional. Full text in `THIRD_PARTY_NOTICES.txt`.

**Rules:**
- Pin to a commit hash, never a branch or tag.
- "Local modifications: none" is the expected value. Anything else needs justification —
  the value of vendored code is that it is byte-identical to an audited upstream.
- Never reformat vendored files. They are excluded from `make format`.
- Vendored C gets relaxed warning flags (`THIRDPARTY_CFLAGS`), not `-Werror -Wpedantic`.

---

## Test vector provenance

Summary only — full detail lives in `tests/kat/PROVENANCE.md`.

| Vector set | Source | Date fetched | SHA-256 (first 16) |
|---|---|---|---|
| ML-KEM-keyGen-FIPS203 (internalProjection) | `usnistgov/ACVP-Server` @ `975de31eb83d8703` | 2026-09-19 | `d7a62a2c3476957f` |
| ML-KEM-keyGen-FIPS203 (prompt) | same commit | 2026-09-19 | `3f9ce34f6c836c77` |
| ML-KEM-keyGen-FIPS203 (expectedResults) | same commit | 2026-09-19 | `a253d0ad91c95ebe` |
| ML-KEM-encapDecap-FIPS203 (internalProjection) | same commit | 2026-09-19 | `a556952ce869bb89` |
| ML-KEM-encapDecap-FIPS203 (prompt) | same commit | 2026-09-19 | `998e22dfb12efb14` |
| ML-KEM-encapDecap-FIPS203 (expectedResults) | same commit | 2026-09-19 | `9089ec6ff2424da9` |

**Note the upstream directory is `ML-KEM-encapDecap-FIPS203` — singular "Decap".** This
project's own spec writes "encapDecaps"; that path 404s. Full detail, including the
complete field map and the verified implicit-rejection cases, is in
`tests/kat/PROVENANCE.md`.

---

## Spec corrections

Places where `MLKEM768_SPEC.md` or a note in `docs/algorithms/` was found to be wrong, and
what FIPS 203 actually says. **Fix the note in the same commit** — do not leave a known-bad
note in place with only a correction logged here.

| Date | File | What it said | What FIPS 203 says | FIPS ref |
|---|---|---|---|---|
| 2026-09-19 | `MLKEM768_SPEC.md` §10.1, §12, `PROVENANCE.md` template | ACVP directory is `ML-KEM-encapDecaps-FIPS203` | Not a FIPS 203 matter — an upstream path fact. The real ACVP-Server directory is **`ML-KEM-encapDecap-FIPS203`**, singular "Decap". The plural path 404s. | n/a (ACVP-Server layout) |
| 2026-09-19 | `MLKEM768_SPEC.md` §12.1 | Audit via `lscpu` and `/proc/cpuinfo` | Not a FIPS 203 matter — a platform assumption. Neither exists on macOS; the audit used `sysctl machdep.cpu.*`. Equivalent data recorded in `docs/reference/invariants.md`. | n/a (platform) |
| 2026-09-20 | `MLKEM768_SPEC.md` §5.2 | `montgomery_reduce` input `\|a\| <= Q*2^15`, output `\|t\| < Q` | Off by one. Exhaustive evaluation over all 218,169,345 inputs in `[-q*2^15, +q*2^15]` finds **exactly one** violation: `a = +q*2^15` yields `t = 3329 = q`, not `< q`. (`a = -q*2^15` yields 0.) The input contract must be the **strict** `\|a\| < q*2^15`, under which `\|t\| <= 3328` holds everywhere. Every call site satisfies it with >20x margin. | Alg. 9-12 call sites; `docs/bounds.md` |
| 2026-09-19 | `MLKEM768_SPEC.md` §6.2, §6.3 | Declared only `sample_poly_cbd_eta2` and `PRF_eta2` with a fixed 128-byte output | Not a FIPS 203 error — an internal contradiction with spec §1. η1 = 3 for ML-KEM-512, needing 192 PRF bytes, so the `eta2`-only API hardcodes η1 == η2 and makes another parameter set a rewrite. **Fixed**: parameterized on η (ADR-009). | §8 Table 2; Alg. 8 |
| 2026-09-19 | `MLKEM768_SPEC.md` §6.4, §5.3 | "Sample `s[0..2]` ... then `e[0..2]`" (η unstated) | Both `s` **and** `e` are sampled with **η1** in K-PKE.KeyGen (Alg. 13 lines 9 and 13). η2 is used only in K-PKE.Encrypt, for `e1` and `e2`. Invisible for ML-KEM-768 (η1=η2=2); wrong for ML-KEM-512 (η1=3). | Alg. 13, §8 Table 2 |

*(The first two are not FIPS 203 errors — they are errors in this project's spec or in its
platform assumptions. Recorded here because the same table is where a future session will
look.)*

---

## Influential external sources

URLs that materially changed an implementation decision. Not a bibliography — only things
that changed what the code does.

| Date | URL | What it settled |
|---|---|---|
| 2026-09-19 | `https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/` | The actual current ACVP vector paths and the singular-"Decap" directory name. Settled ADR-006/007. |
| 2026-09-19 | `https://github.com/doctest/doctest` @ `2d0a9359a60c51af` | doctest v2.5.3 as the pinned test framework. ADR-005. |
| 2026-09-20 | `https://github.com/pq-crystals/kyber` @ `3edd5af599192716` | Vendored scalar FIPS 202; confirmed `main` is ML-KEM not round-3 Kyber. ADR-015. |
