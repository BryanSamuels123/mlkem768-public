# Appendix C — Differences From the CRYSTALS-Kyber Submission

FIPS 203 Appendix C, pp. 47–48. **This is the single most important note in this
directory.** Most ML-KEM material online predates mid-2024 and actually describes round-3
Kyber. Each difference below produces a fully self-consistent implementation that fails
every NIST KAT.

The standard scopes the appendix as covering only differences in **input-output
behavior** of KeyGen / Encaps / Decaps — not differences in presentation or internal
computation.

---

## C.1 — CRYSTALS-Kyber (round 3) vs. FIPS 203

1. **Shared secret length is fixed at 256 bits.** In the round-3 spec it was variable-
   length depending on the application. It can be used directly as a symmetric key.

2. **A different Fujisaki–Okamoto variant.** Verbatim:

   > ML-KEM.Encaps **no longer includes a hash of the ciphertext in the derivation of the
   > shared secret**, and ML-KEM.Decaps has been adjusted to match this change.

   → **There is no final KDF.** `K` comes straight out of `G(m ‖ H(ek))`. Kyber's
   `KDF(K̄ ‖ H(c))` is gone. (Failure mode #2.)

3. **No `m ← H(m)`.** Verbatim:

   > In the third-round specification, the initial randomness `m` in the ML-KEM.Encaps
   > algorithm was first hashed before being used. Specifically, between lines 1 and 2 in
   > Algorithm 20, there was an additional step that performed the operation `m ← H(m)`.
   > The purpose of this step was to safeguard against the use of flawed randomness
   > generation processes. As this standard requires the use of NIST-approved randomness
   > generation, this step is unnecessary and **is not performed in ML-KEM**.

   (Failure mode #2.)

4. **Explicit input checking** was added — see [`alg20-encaps.md`](alg20-encaps.md) and
   [`alg21-decaps.md`](alg21-decaps.md).

   > For example, ML-KEM.Encaps requires that the byte array containing the encapsulation
   > key correctly decodes to an array of integers modulo `q` without any modular
   > reductions.

---

## C.2 — Changes from the FIPS 203 initial public draft (ipd)

The ipd was posted 2023-08-24. Two changes landed in the **final** standard. Both matter
enormously, and material written against the ipd is wrong in exactly these two places:

1. **Domain separation was added to K-PKE.KeyGen.** Verbatim:

   > Based on comments submitted on the draft ML-KEM, **domain separation was added to
   > K-PKE.KeyGen** to prevent the misuse of keys generated to target one security level
   > from being used for a different security level when saving a key as a seed.

   → This is the `(ρ, σ) ← G(d ‖ k)` byte, with **`k = 3`** for ML-KEM-768. Present in the
   final standard, absent from both Kyber and the ipd. (Failure mode #1 — the most common
   cause of KAT failure.) See [`alg13-kpke-keygen.md`](alg13-kpke-keygen.md).

2. **The matrix indices were un-swapped.** Verbatim:

   > Additionally, FIPS 203 ipd had **inadvertently swapped the indices of matrix Â** in
   > K-PKE.KeyGen and K-PKE.Encrypt. This was changed back in the final version of ML-KEM
   > to match CRYSTALS-KYBER.

   → The final standard has `Â[i,j] ← SampleNTT(ρ ‖ j ‖ i)`, **`j` first**. (Failure mode
   #3.) See [`alg07-sample-ntt.md`](alg07-sample-ntt.md).

---

## The three-question checklist for any reference consulted

Per `docs/reference/invariants.md` and spec §0, check any external source against these before trusting it:

| # | Question | ML-KEM answer |
|---|---|---|
| 1 | Is there a `‖k` byte in `G(d ‖ k)`? | **Yes**, `k = 3` for 768 |
| 2 | Is there an `m ← H(m)` in Encaps? | **No** |
| 3 | Is there a final KDF over `H(c)`? | **No** |

A source that gets any of these wrong is describing Kyber or the ipd, not ML-KEM.

Note the irony of #2 in C.2: the ipd "fixed" the index order and the final standard
reverted it, so on that one point Kyber is right and the ipd is wrong.
