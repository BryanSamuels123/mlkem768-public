# KAT harness mutation testing

**A gate that cannot fail is not a gate.** Before building Phase 2 on top of
`make kat-model`, the harness was verified by deliberately breaking the golden model in
nine specific, spec-relevant ways and confirming each one is caught.

Any mutation that still reported `PASS 80/80` would mean the harness is filtering rather
than comparing, or not reaching that code path — a more urgent finding than anything in
Phase 2.

**Result: 9 of 9 detected. No survivors.**

Re-run with `python3 tests/kat/mutation_test.py`. The driver refuses to start on a dirty
`tests/model`, reverts each mutation with `git checkout --`, and verifies the tree is
clean again at the end, so it cannot leave a mutation behind. Point it at `--target kat`
to re-verify the gate against the real implementation at Phase 7.

---

## The 80 cases, by group and testType

Printed by the harness on every run, pass or fail — this is how you confirm each group is
represented rather than silently skipped.

| tgId | testType | function | cases | tcId range | tests |
|---|---|---|---|---|---|
| 2 | AFT | `keyGen` | 25 | 26–50 | Alg. 16 `KeyGen_internal` |
| 2 | AFT | `encapsulation` | 25 | 26–50 | Alg. 17 `Encaps_internal` |
| 5 | VAL | `decapsulation` | 10 | 86–95 | Alg. 18 `Decaps_internal` |
| 9 | VAL | `decapsulationKeyCheck` | 10 | 126–135 | §7.3 hash check |
| 10 | VAL | `encapsulationKeyCheck` | 10 | 136–145 | §7.2 modulus check |
| | | **TOTAL** | **80** | | |

The `decapsulation` group splits 5/5 by its `reason` field, and the two halves are
**independently sensitive** — see M3 vs M6 below:

| `reason` | tcIds | expected `k` |
|---|---|---|
| `valid decapsulation` | 86, 87, 89, 90, 94 | the real shared secret |
| `modified ciphertext` | 88, 91, 92, 93, 95 | `J(z ‖ c)` — the implicit-reject secret |

---

## Results

Baseline: `PASS 80/80`. Each row is failures per group.

| # | Mutation | Spec ref | pass | keyGen | encaps | decaps | ekChk | dkChk |
|---|---|---|---|---|---|---|---|---|
| **M1** | Drop the `‖k` domain separator in `G(d ‖ k)` | Alg. 13 line 1 / #1 | 55/80 | **25** | · | · | · | · |
| **M2** | Swap `i` and `j` in the SampleNTT seed | Alg. 13 line 5 / #3 | 25/80 | **25** | **25** | **5** | · | · |
| **M3** | `invntt` final scale 3303 → 3302 | Alg. 10 line 14 / #6 | 50/80 | · | **25** | **5** | · | · |
| **M4** | Remove the transpose in `u = NTT⁻¹(Âᵀ ∘ ŷ)` | Alg. 14 line 19 / #4 | 50/80 | · | **25** | **5** | · | · |
| **M5** | Swap the `N` counter order (`e1` before `y`) | Alg. 14 lines 9–16 / #5 | 50/80 | · | **25** | **5** | · | · |
| **M6** | Skip the implicit-rejection select; always return `K'` | Alg. 18 lines 9–11 / #10 | 75/80 | · | · | **5** | · | · |
| **M7** | Off-by-one in `Compress_du` rounding (`+q/2` → `+q/2 − 1`) | (4.7) / #9 | 72/80 | · | **7** | **1** | · | · |
| **M8** | Encapsulation key check always passes | §7.2 (7.1) | 75/80 | · | · | · | **5** | · |
| **M9** | Decapsulation key check always passes | §7.3 (7.2) | 75/80 | · | · | · | · | **5** |

`#n` refers to the failure-mode list in `docs/reference/invariants.md`.

**Every group is provably sensitive**: keyGen (M1, M2), encapsulation (M2–M5, M7),
decapsulation (M2–M7), encapsulationKeyCheck (M8), decapsulationKeyCheck (M9).

---

## Why the blast radii differ — each is structurally correct

The groups that *don't* react are as informative as the ones that do.

**M1 hits keyGen only.** `G(d ‖ k)` is reached only from `K-PKE.KeyGen`. Encaps is handed
an `ek` and decaps a `dk`, so neither re-derives `(ρ, σ)`. A Kyber-instead-of-ML-KEM bug
is therefore invisible to every group except keyGen — which is exactly why keyGen vectors
are non-negotiable.

**M3 spares keyGen.** `K-PKE.KeyGen` never calls `NTT⁻¹`: `t̂ = Â ∘ ŝ + ê` is computed and
serialized entirely in the NTT domain. Only Encrypt and Decrypt come back out. So an
inverse-NTT bug cannot be caught by keyGen vectors at all.

**M4 and M5 spare keyGen** because both mutate `K-PKE.Encrypt` only.

**M2 hits all three** because `gen_matrix` is shared by KeyGen and Encrypt. Swapping the
index bytes computes `Â_mut = Âᵀ`, which breaks `t̂ = Â ∘ ŝ` and, independently,
`Âᵀ ∘ ŷ` in Encrypt.

**The 5 decapsulation failures in M2–M5 are the *valid* cases, not the rejection cases.**
A broken encrypt path corrupts the re-encryption `c'`, so `c ≠ c'` and decaps implicitly
rejects — returning `J(z ‖ c)`. For the 5 `modified ciphertext` cases that is *already*
the expected answer, so they still pass. Confirmed empirically: M3 fails exactly
`{86, 87, 89, 90, 94}`.

**M6 is the mirror image and the important one.** Skipping the select fails exactly
`{88, 91, 92, 93, 95}` — the 5 implicit-rejection cases, and nothing else. The two sets
are disjoint and together cover all 10. **M6 is the only mutation that isolates implicit
rejection**, which makes those 5 vectors the sole automated evidence that FIPS 203 §6.3 is
implemented. A harness that filtered them out would report green on a KEM with no
implicit rejection at all.

**M7 is partial by nature, and that is the point.** Changing the rounding addend by 1
alters `Compress_10(x)` only when a multiple of `2q` falls in a 2-wide window — about
`1/3329` per coefficient. Across 768 compressed coefficients that is roughly a 20% chance
per ciphertext, and 7 of 25 encaps cases tripped. A subtle boundary bug does **not**
reliably fail every case, so a gate with only a handful of vectors could miss it entirely.
25 AFT cases caught it; 3 might not have.

---

## Process finding: a refactor can silently open a hole in this gate (Phase 8a)

Phase 8a restructured `gen_matrix` and the noise loops in `src/kpke.cpp` for 4-way
Keccak batching. That renamed the SampleNTT seed array and replaced Encrypt's running
`N++` counter with literal nonce arguments — which killed the **M2** and **M5** anchors.

The harness prints `ANCHOR NOT FOUND -- skipping` and does not pretend to pass, so this
degraded loudly rather than silently. **But a skipped mutation is still a hole in the
gate**, and a 7-of-9 run that prints "no survivors" reads almost exactly like a 9-of-9
one. Both anchors were re-pointed at the batched call sites and re-verified:

| | recorded (Phase 7) | after re-point (Phase 8a) |
|---|---|---|
| M2 | 25/80 — keyGen 25, encaps 25, decaps 5 | **identical** |
| M5 | 50/80 — encaps 25, decaps 5 | **identical** |

Same blast radii, so the re-pointed mutations break the same thing the originals did.

**Standing check: any refactor of `src/kpke.cpp`, `src/kem.cpp`, `src/ntt.cpp` or
`src/poly.cpp` must re-verify that all nine anchors still resolve uniquely** before the
suite's result means anything. Cheap to check — count each `old` string in its file and
assert exactly one match.

---

## Process finding: stale builds silently falsified the first run

The first run reported M2 as keyGen-only — M1's signature. It was re-running M1's binary.

**GNU Make 3.81, which macOS ships, compares mtimes at 1-second granularity.** The driver
reverted one mutation and wrote the next into the same file within the same second, so
make judged `model_kpke.o` up to date and skipped recompiling it. The mutation never
reached the binary, and the result looked plausible rather than obviously broken.

The fix is not a `sleep`: the driver now **deletes** the model objects and the harness
binary before every build, because a missing prerequisite always forces a rebuild and
cannot be defeated by clock granularity. It additionally asserts the mutated translation
unit appears on a compile line, and aborts if it does not.

This is the second time this class of bug has bitten (see docs/notes/ — sanitizer
objects reused across differing flag sets). **Treat any surprising build-dependent result
as stale until proven otherwise**, especially in Phase 2 where the edit-test loop is fast
and `docs/bounds.md` changes alter behaviour without changing declarations.
