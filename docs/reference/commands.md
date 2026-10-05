# Every `gmake` target, with what it is for

*Split out of `docs/reference/invariants.md` in the Phase 10b trim (2026-09-30). That file keeps the dozen
commands reached for daily and links here for the rest — the same treatment
`docs/reference/ct-tooling.md` got in the Phase 8 prune.*

**`gmake`, never `make`.** macOS ships GNU Make 3.81, whose 1-second mtime granularity
silently reuses stale objects; the Makefile hard-errors under it. `brew install make`.

---

## Commands

**Use `gmake`, not `make`.** macOS ships GNU Make 3.81, whose 1-second mtime granularity
silently reuses stale objects; the Makefile hard-errors under it. `brew install make`.

```
gmake                # build libmlkem768.a
gmake test           # unit + property + differential tests  (10^5 differential iters)
gmake test-deep      # same, at 10^7 — the gate with real statistical power
gmake kat            # ACVP KATs against the implementation  <- Phase 7 correctness gate
gmake kat-model      # ACVP KATs against the golden model    <- Phase 1 gate
gmake bounds         # coefficient-bound measurement (docs/bounds.md)
gmake audit-div      # machine-level: no div/idiv in the library   <- ADR-018
gmake audit-refs     # every ADR-nnn referenced anywhere resolves  <- ADR-019
gmake audit-zeroize  # secure_zero survives -O3, by disassembly    <- spec 8.3
gmake dudect         # statistical timing test, HOST-ONLY (ADR-035). Calibrates first:
                     # fails if a planted leak is NOT detected. Component rows are
                     # advisory, top-level rows gate -- docs/notes/09-dudect.md
gmake audit-zeroize-sites  # every Zeroizing<T> wrap really erases  <- ADR-034
gmake dudect-ntt-diff  # DIAGNOSTIC, not a gate: our AVX2 ntt vs our scalar ntt vs
                     # pq-crystals', identical harness. Decided the ntt timing row.
gmake dudect-tomsg-sim # DIAGNOSTIC: is poly_tomsg's timing effect exact-repetition or
                     # graded by similarity? Inconclusive by construction -- ADR-035.
gmake bench-kem      # whole-operation KeyGen/Encaps/Decaps
gmake bench          # cycle-count benchmarks
gmake ubsan          # works on the host
gmake fetch-vectors  # verify/download ACVP vectors
gmake env            # resolved toolchain and flags
```

**Docker-only** — these cannot run on the macOS host (ADR-008), and the host targets
fail loudly saying so:

```
gmake docker-build       # once; docker-msan-build once more for the MSan image
gmake docker-ctgrind     # constant-time check under valgrind
gmake docker-asan        # ASan is non-functional on macOS for any C++ program
gmake docker-msan        # needs an MSan-instrumented libc++
gmake docker-fuzz        # libFuzzer + ASan + UBSan, spec 10.4. Differential oracle vs the
                         # golden model -- the only correctness gate the decrypt path has.
                         # FUZZ_RUNS=n to set the budget. NOT in docker-all (too slow).
gmake docker-all         # probe, test, kat, audit-div, audit-refs, audit-zeroize, audit-zeroize-sites, ubsan,
                         # asan, msan, ctgrind.  NOT dudect -- Docker here is a VM and
                         # adds a timing layer to the thing dudect measures (ADR-035).
```

**Comparison against pq-crystals/kyber** (benchmark-only; built OUTSIDE this repo, nothing
vendored — ADR-003/ADR-022). Needed for spec §1 criterion 4, which Phase 9a **closed** —
1.413/1.416/1.403× against the ~1.5× bar (ADR-030). **Margin is only ~0.09×, so any change
to library code re-measures this**, and we meet it while zeroizing 27 wrapped secrets per
operation where pq-crystals zeroizes nothing:

```
gmake kyber-ref          # clone + build the pinned comparison lib to /tmp
gmake bench-vs-kyber     # both implementations in ONE process, interleaved
gmake interop            # spec 10.5: 10^4 each direction, shared secrets must match
gmake bench-energy-build # BUILDS ONLY -- see docs/notes/09-energy.md before running it
```

**Never end a session red.** `gmake test` green and `gmake docker-all` green before any commit.

---
