# Phase 10a — fuzzing

*2026-09-29. `gmake docker-fuzz`. Spec §10.4.*

---

## 1. What fuzzing is, in plain words

A fuzzer runs the code over and over on machine-generated input, looking for inputs that
make it misbehave. What makes a modern fuzzer more than a random-input loop is **coverage
feedback**: the program is compiled with instrumentation that records which branches an input
reached, and any input that reaches somewhere new is kept and mutated further. The fuzzer
therefore *climbs* into the program rather than bouncing off the front door.

On its own a fuzzer only finds inputs that **crash**. Two additions make it much stronger,
and both are used here:

- **Sanitizers.** Compiled-in checks that turn silent corruption into an immediate, loud
  failure. AddressSanitizer catches reads and writes outside an object's bounds — including
  reads only one byte past the end, which would otherwise return a plausible value and
  corrupt nothing. UndefinedBehaviorSanitizer catches operations the C++ standard leaves
  undefined, where the compiler is free to do anything at all.
- **A differential oracle.** A second, independent implementation of the same specification
  runs on every input and the two results must match exactly. This finds inputs where the
  code does not crash but computes the *wrong answer* — which no crash detector can see.

## 2. What was fuzzed

Two targets, both in the Linux container, because Apple's compiler does not ship libFuzzer.
`gmake fuzz` on the host fails loudly saying so rather than quietly doing nothing.

**`fuzz_decaps` — decapsulation.** Decapsulation is the operation an attacker can feed
arbitrary input to, so it is the one that matters. It is also the operation whose correctness
is hardest to test: the project's own notes record that the standard known-answer tests
cannot see small errors on the decryption path, because a rounding step late in the
computation absorbs them and the result still comes out right. Only 5 of the 80 official test
vectors exercise a successful decapsulation at all.

**`fuzz_keycheck` — the two input-validation checks.** An encapsulation key must be exactly
the right length and every packed 12-bit field must be below the modulus; a decapsulation key
must be the right length and carry a hash that matches the key it contains. Both checks are
fuzzed, in both directions — keys that should be accepted and keys that should be rejected.

## 3. Reachability — the part that is easy to get wrong

**A fuzzer whose inputs mostly fail the first check only tests the first check.** Feeding
1088 random bytes to decapsulation as a "ciphertext" is nearly useless: without a matching
key the work either stops early or produces nothing interesting, and the fuzzer spends its
entire budget on the doorway.

So the fuzzer's own bytes are used to *build* a valid situation first: 32 bytes become one
half of a key seed, 32 more the other half, and a real key pair is generated from them.
32 further bytes become a message, which is encapsulated against that key to produce a real
ciphertext. Only then do the remaining bytes perturb it. Every input therefore runs the
entire decapsulation: unpacking, decompression, the number-theoretic transform, the inner
product, the final rounding, the complete re-encryption, the ciphertext comparison, and the
rejection path.

Two perturbation modes are used, and having only one of them cost a control (§5):

- **PATCH** flips scattered bytes, keeping the ciphertext close to valid. This is where
  decryption's error margin lives.
- **OVERLAY** lets the fuzzer write ciphertext bytes directly. This is what gives it control
  over specific byte *values*, which it needs in order to drive a branch that tests for a
  particular byte pattern.

The corpus is seeded from the official NIST test vectors — real key seeds and real messages —
so the fuzzer starts from inputs that already reach the deep code instead of having to
discover the input layout by mutation.

## 4. The differential oracle

Every input is run through both this implementation and the slow, deliberately
straightforward reference model written in an earlier phase, and the two 32-byte results must
be **byte-for-byte identical**.

This is the part worth emphasising. Almost every perturbed ciphertext is invalid, and the
standard requires that an invalid ciphertext produce a specific, deterministic wrong answer
rather than an error — a value derived by hashing a secret held in the key together with the
ciphertext. So on essentially every input the fuzzer is checking that this implementation
computes exactly the value the specification demands, on precisely the code path the
known-answer tests cannot see. A mismatch is reported as a failure with the input printed,
and stops the run, exactly as a crash would.

The public entry point is also cross-checked against the internal one, so the extra length
and key checks it performs cannot change a result that should be identical.

## 5. The controls — both of which found a real defect in the harness

A fuzzer that reports "no crashes" after a long run proves nothing unless it has been shown
capable of finding a bug it is supposed to find. Two bugs were planted, in a throwaway copy
of the tree so the real source was never modified.

### Control 1 — a memory error: planted, and it exposed that the library was not instrumented

An out-of-bounds read was planted on the decryption path, reachable only when the ciphertext
begins with a specific two-byte pattern. The first attempt to detect it **failed twice**, and
each failure was a genuine defect in the harness rather than a limitation of fuzzing:

**First failure — the fuzzer could not steer the input.** 400,000 runs found nothing. The
original perturbation scheme only flipped bytes at fuzzer-chosen *offsets*, so hitting a
chosen *value* at a chosen offset was a blind search of roughly one in 278,000 per attempt,
and the fuzzer's comparison tracing could not help because the compared byte was not directly
derived from input bytes. **Fix:** the OVERLAY mode described above, which lets the fuzzer
write ciphertext bytes directly.

**Second failure — the sanitizer could not see inside the library.** Still nothing. A
hand-crafted input that was *guaranteed* to satisfy the trigger condition also produced
nothing, which separated "the fuzzer cannot find it" from "the check cannot see it". The
cause: only the fuzz entry point was compiled with the sanitizers, while the library itself
was the ordinary optimized build. **AddressSanitizer cannot report a bad memory access in
code that was not instrumented** — so the setup was a crash detector for the harness, not for
the library, which is the entire point. **Fix:** the library and the model are now rebuilt
with the sanitizers, the same way the existing sanitizer targets do it.

After both fixes: the hand-crafted input reports
`global-buffer-overflow ... in mlkem768::kpke_decrypt`, and **the fuzzer itself finds the
pattern unaided in about 18,000 executions.**

The second fix also changed what the coverage numbers mean. Before it, the fuzzer reported
**163** covered branches; afterwards, **411** — because the earlier figure counted only the
harness and the model. Every coverage number from before that fix was measuring the wrong
thing.

### Control 2 — a wrong answer that does not crash

One byte of the rejection output was corrupted. This crashes nothing and triggers no
sanitizer; only the differential oracle can see it. It was caught **on the first input**,
before the fuzzer printed its first progress line, which is expected since every
decapsulation passes through that line. The reported difference was exactly one bit in byte 7
— the planted change.

Worth recording: the first version of this plant was placed a few lines too early, where a
later copy overwrote it, making it a no-op that would have "passed" while proving nothing.
It was caught by reading the surrounding code before trusting the result.

## 6. Results

Both targets: **no crash, no sanitizer finding, no oracle mismatch.**

| target | executions | time | exec/s | branches | corpus |
|---|---|---|---|---|---|
| `fuzz_decaps` | 300 000 | 1650 s (27 min) | 181 | 412 | 56 inputs |
| `fuzz_keycheck` | 300 000 | ~1270 s (21 min) | 237 | 389 | 77 inputs |

### Which functions the fuzzer actually reached

This is the question that decides whether a clean run meant anything, so it is answered by
measurement rather than by the reachability *argument* in §3. Of the **81 library functions**
instrumented, the fuzzer reached **50**, covering **202 of 744 library branches (27 %)**.

**The whole decryption path is reached**, which was the goal:

```
decaps_internal -> kpke_decrypt -> polyvec_decompress_du -> avx2::ntt
                -> avx2::basemul_acc -> avx2::invntt -> poly_canonicalize
                -> poly_tomsg (Compress_1)
   then the re-encryption: kpke_encrypt -> avx2::cbd2 -> polyvec_compress_du
                -> poly_compress_dv -> ct_cmov (the branchless reject select)
   and both validators: check_encaps_key, check_decaps_key
```

**The 31 unreached functions are unreached for identifiable reasons, not by accident.** This
matters: a list of uncovered functions is only reassuring if each absence is explained.

| unreached | why |
|---|---|
| `generic::ntt`, `generic::invntt`, `generic::prf_x4`, `generic::xof4_*` | the **portable fallback backend**. The container CPU has AVX2, so runtime dispatch never selects it. **Fuzzing covers one backend only** — the portable path is covered instead by the differential tests in `gmake test`, which run both and require bit-identical output. |
| `randombytes`, `set_rng` | the targets call the deterministic `*_internal` entry points, so the random generator is bypassed by design — that is what makes a fuzz input reproducible. |
| `keygen`, `encaps` (public wrappers) | the targets use `keygen_internal` / `encaps_internal`. The public `decaps` **is** exercised. |
| `PRF<2>`, `PRF<3>`, `PRF_x4<3>`, `sample_poly_cbd<3>` | η = 3 does not occur in ML-KEM-768 (η₁ = η₂ = 2), and the scalar PRF is unused because the 4-way batched path is always taken. |
| `poly_basemul`, `basemul`, `avx2::basemul` | the non-accumulating variant; the KEM uses `poly_basemul_acc`. |
| `compress_coeff<d>`, `decompress_coeff<d>`, `tables::zetas*` | reported as 0/1 edges — these are inlined or compile-time constants, so "unreached" here means "fully inlined away", not untested. |
| `poly_reduce` | not called on any fuzzed path. **Worth checking in Phase 10b whether it is dead code** after Phase 8c's lazy-reduction work. |

27 % of branches sounds low in isolation. Most of the shortfall is structural rather than a
gap in testing: the library contains two complete backends and only one runs, the AVX2
routines are heavily unrolled so one input walks a single path through many edges, and the
η = 3 code cannot execute at this parameter set at all.

### The spec's target was not met, and was not quietly shortened

Spec §10.4 asks for **10⁸ executions**. This run did **3 × 10⁵ per target**, at 181 and 237
executions per second. The rate is what it is because each execution does a great deal:
a full key generation, an encapsulation, a decapsulation, **and** a decapsulation through the
reference model, which was written for obvious correctness rather than speed and multiplies
polynomials the slow way. On top of that the whole library is instrumented with two
sanitizers and compiled at low optimization.

At these rates 10⁸ executions per target would take roughly **six to seven days of
continuous running each**. That is
not a reason to claim the target was met, and not a reason to drop the sanitizers or the
oracle to reach a larger number — both of them are what make the run worth doing. The honest
statement is: **10⁸ was not attempted; 3 × 10⁵ per target was, with full instrumentation and
a differential oracle, and the executions, wall time and coverage are reported above.**

A longer run is cheap to ask for — `gmake docker-fuzz FUZZ_RUNS=n` — and is the obvious thing
to leave running unattended.

## 7. Limits

- **Coverage is branch coverage, not proof.** 412 and 389 branches is what these inputs
  exercised; it does not mean the remainder is unreachable or correct.
- **Only the AVX2 backend was fuzzed**, because dispatch selects it on this hardware. The
  portable backend has no fuzz coverage at all; it is covered by the differential tests.
- **The oracle can only catch disagreement.** If both this implementation and the reference
  model misread the specification in the same way, the oracle is silent. That risk is what
  the official NIST vectors cover, and they pass.
- **Length errors are barely fuzzed.** Ciphertexts are deliberately kept well-sized, because
  the length check is covered by the unit tests and fuzzing it would mostly re-test that one
  branch. Wrong lengths are exercised in the key-check target instead.
- **Two operations are not fuzzed at all**: key generation and encapsulation take no
  attacker-controlled input in normal use — their inputs are secrets the caller generates —
  so fuzzing them tests the caller's contract rather than the library's exposure.
  Encapsulation *is* exercised indirectly, since the decapsulation target encapsulates on
  every single input.
