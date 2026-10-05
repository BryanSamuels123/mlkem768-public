# Test vector provenance

Filled in during Phase 0 (2026-09-19). The KAT harness is the project's correctness gate,
so the integrity of these files is the integrity of every correctness claim made about
the implementation.

> **Never read these JSON files into context.** They are large (up to 1.4 MB). Inspect
> with `python3 -c` / `jq` and print only structure and counts. See `docs/reference/invariants.md`
> rule 2.

---

## Source

NIST ACVP ML-KEM test vectors from the **`usnistgov/ACVP-Server`** GitHub repository,
**pinned to commit `975de31eb83d87039ec88934fdc47d8c312b892d`** (committed 2026-08-12).

Raw URL base:

```
https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/
```

**Note the upstream directory name is `ML-KEM-encapDecap-FIPS203` — singular "Decap".**
The spec and the template both write "encapDecaps"; the real path does not have the
trailing `s`. Anyone re-deriving the URL from memory will 404.

The files are pinned to a commit rather than a branch so a re-fetch is reproducible.
**The JSON files are committed to this repository** (DECISIONS.md ADR-006) — upstream
ACVP paths move, and a Phase 7 gate that depends on a live URL can break for reasons
unrelated to the code.

---

## Downloaded files

All in `tests/kat/vectors/`. Fetched **2026-09-19**.

| File | Remote path suffix | Size | SHA-256 |
|---|---|---|---|
| `ML-KEM-keyGen-FIPS203-prompt.json` | `ML-KEM-keyGen-FIPS203/prompt.json` | 16 066 | `3f9ce34f6c836c77958bad2729e837c3b213f44ac36c3065976e7acca6389523` |
| `ML-KEM-keyGen-FIPS203-expectedResults.json` | `ML-KEM-keyGen-FIPS203/expectedResults.json` | 544 032 | `a253d0ad91c95ebea5b409673defef0aa49d65d4ed72286399e2e798ddf073a4` |
| `ML-KEM-keyGen-FIPS203-internalProjection.json` | `ML-KEM-keyGen-FIPS203/internalProjection.json` | 558 841 | `d7a62a2c3476957f56dd8d24f9004ea6776ccfe995ffe71a65bb9506dc9c7b1b` |
| `ML-KEM-encapDecap-FIPS203-prompt.json` | `ML-KEM-encapDecap-FIPS203/prompt.json` | 624 189 | `998e22dfb12efb14ce9fdff911ca634b13612819a1806f25da69adba7e16db91` |
| `ML-KEM-encapDecap-FIPS203-expectedResults.json` | `ML-KEM-encapDecap-FIPS203/expectedResults.json` | 190 940 | `9089ec6ff2424da9f2782b89b2f831a329a3e28d6e5e24b802b78ff36ac61cdf` |
| `ML-KEM-encapDecap-FIPS203-internalProjection.json` | `ML-KEM-encapDecap-FIPS203/internalProjection.json` | 1 465 634 | `a556952ce869bb89c3a3196a701dad89647c193a34c86eafb61a9d710d5b810f` |

Verification (macOS has no `sha256sum` in the coreutils sense; `shasum -a 256` is the
portable form, and this host also happens to ship `/sbin/sha256sum`):

```sh
cd tests/kat/vectors && shasum -a 256 *.json > SHA256SUMS
shasum -a 256 -c SHA256SUMS      # verification
```

`make verify-vectors` runs the check. `make fetch-vectors` verifies when the files are
present and **refuses to silently re-download over a good copy**; it fails loudly and
points here when they are absent.

All six files were confirmed to be real JSON (leading `{ "vsId": 42, ...`), not HTML
error pages or git-lfs pointers.

---

## Which file the harness should parse

**Parse `internalProjection.json` only.** It is `prompt` ∪ `expectedResults` in a single
file, and it is the only one carrying the `reason` field that identifies the
implicit-rejection cases.

`internalProjection` was verified programmatically to agree with `expectedResults` on
every `c`, `k`, and `testPassed` across all 165 encapDecap cases. The
prompt/expectedResults pair is retained as an independent cross-check.

---

## Structure confirmed

Both files share a shape. Top level: `vsId`, `algorithm`, `mode`, `revision`, `isSample`,
`testGroups`.

- `algorithm` = `"ML-KEM"`, `revision` = `"FIPS203"`.
- Parameter-set selector: **`parameterSet` == `"ML-KEM-768"`** (exact string). Present on
  groups in `prompt` and `internalProjection`; **absent in `expectedResults`**, which
  carries only `tgId` — join by `tgId` / `tcId`.
- **All hex strings are UPPERCASE** `[0-9A-F]`, unpadded, no `0x` prefix.
- Every test carries `deferred`, which is `false` everywhere in both files.

### keyGen — tests `keygen_internal` (FIPS 203 Alg. 16)

`mode: "keyGen"`. 3 groups (one per parameter set), 25 tests each, 75 total.

**ML-KEM-768 is `tgId: 2`, tcId 26–50, 25 cases**, `testType: "AFT"`.

- Inputs: **`d`** (32 B), **`z`** (32 B)
- Expected: **`ek`** (1184 B), **`dk`** (2400 B)

### encapDecap — tests Alg. 17 / 18 and the §7.2/§7.3 checks

`mode: "encapDecap"`. 12 groups, 165 tests total; **55 for ML-KEM-768**.

**Groups are distinguished by TWO fields.** `testType` alone is not enough — three
different functions all use `VAL`. **Key off `function`.**

| tgId | testType | `function` | n | tcId | Inputs → expected |
|---|---|---|---|---|---|
| 2 | AFT | `encapsulation` | 25 | 26–50 | `ek`, `m` → `c`, `k` (also carries unused `dk`) |
| 5 | VAL | `decapsulation` | 10 | 86–95 | `dk`, `c` → `k`, plus `reason` (also unused `ek`) |
| 9 | VAL | `decapsulationKeyCheck` | 10 | 126–135 | `dk` → `testPassed` (bool), plus `reason`, `ek` |
| 10 | VAL | `encapsulationKeyCheck` | 10 | 136–145 | `ek` → `testPassed` (bool), plus `reason`, `dk` |

Sizes confirmed for ML-KEM-768: `ek`=1184, `dk`=2400, `c`=1088, `k`=32, `m`=32, `d`=`z`=32.

**The shared-secret field is lowercase `k`, not `K`.** Note `k` is also the conventional
name of the module dimension — do not confuse them in the parser.

### Implicit rejection — CONFIRMED PRESENT and verified

`tgId 5` (768, `decapsulation`, VAL) splits 5/5 on a **`reason`** string:

- `"valid decapsulation"` × 5
- `"modified ciphertext"` × 5

Verified **cryptographically, not by label**: for all 5 `"modified ciphertext"` cases the
expected `k` equals `SHAKE256(z ‖ c, 32)` where `z = dk[-32:]` — i.e. exactly `J(z ‖ c)`,
the FIPS 203 implicit-reject secret (Alg. 18 line 7). For all 5 valid cases it does not.
Re-verified independently in the main session, not only by the fetching subagent.

**These 5 cases are the only automated check that implicit rejection works.** A harness
that filters them out reports a green suite on a broken implementation.

`reason` appears **only in `internalProjection.json`** — another reason to parse it.

### KeyCheck reason values (ML-KEM-768)

| Group | Pass reason | Fail reason |
|---|---|---|
| tg 9 `decapsulationKeyCheck` | `"valid decapsulation key"` | `"modified H"` |
| tg 10 `encapsulationKeyCheck` | `"valid encapsulation key"` | `"noisy linear system values too large"` |

5 pass / 5 fail each. These map to the §7.3 dk hash check and the §7.2 ek modulus check
respectively — see `docs/algorithms/alg20-encaps.md` and `alg21-decaps.md`.

---

## Not downloaded

A third upstream directory exists: **`ML-KEM-encapDecap-FIPS203-tr1`**
(`revision: "FIPS203-tr1"`), which adds a `keyFormats: ["seed", "expanded"]` dimension.
Not downloaded — it targets a newer ACVP *test* revision, not a different FIPS 203 spec.
Worth adding later if the seed-format `dk` path (spec §3, `keygen_from_seed`) is to be
covered by KATs rather than only by property tests.

There is no NIST `.rsp`-style KAT file for ML-KEM here; these ACVP JSONs are the whole
gate.

---

## Harness notes

- **Filter to `ML-KEM-768` only.** The files contain 512 and 1024 groups; running them
  against a 768-only build produces confusing failures.
- Expected case counts to assert against: **25** keyGen, **25** encaps AFT, **10** decaps
  VAL, **10** dk-check, **10** ek-check — **80 executable cases** for ML-KEM-768.
  (55 of these are in the encapDecap file; 25 in keyGen.)
- The harness builds with `MLKEM_ENABLE_INTERNAL_API=1`. The default library build must
  not expose those entry points.
- `make kat` and `make kat-model` share one harness with a target selector.
- On failure: print test group, case ID, expected vs actual as a hex diff, and the
  **first differing byte offset**. Exit nonzero.
- Print `PASS n/n` on success, with `n` matching the counts above — **a harness that
  silently skips every case also reports zero failures.** Assert the count.
