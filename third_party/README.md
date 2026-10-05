# third_party/

Vendored code. **Never reformat or "fix" anything in here** — the value of vendored code
is that it is byte-identical to an audited upstream. `make format` excludes this directory
by design, and it is built with relaxed warnings (`THIRDPARTY_CFLAGS`), not `-Werror
-Wpedantic`.

Every file here has a provenance row in `DECISIONS.md`: upstream repo, commit hash,
license, local path, local modifications.

| Directory | What | License | Status |
|---|---|---|---|
| `doctest/` | doctest v2.5.3 single-header test framework | MIT | vendored (ADR-005), test-only |
| `fips202/` | Keccak / SHA3 / SHAKE | — | **not yet vendored — Phase 3** (spec §7.1) |

Local modifications to anything here require a `DECISIONS.md` entry justifying why it was
unavoidable.
