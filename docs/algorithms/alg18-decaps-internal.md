# Algorithm 18 — ML-KEM.Decaps_internal(dk, c)

FIPS 203 §6.3, p. 34. **The security-critical algorithm.** Deterministic, no randomness.

```
Input:  decapsulation key dk ∈ 𝔹^(768k+96)
Input:  ciphertext c ∈ 𝔹^(32(du·k+dv))
Output: shared secret key K ∈ 𝔹^32

 1: dk_PKE ← dk[0 : 384k]                  ▷ extract the PKE decryption key
 2: ek_PKE ← dk[384k : 768k+32]            ▷ extract PKE encryption key
 3: h      ← dk[768k+32 : 768k+64]         ▷ extract hash of PKE encryption key
 4: z      ← dk[768k+64 : 768k+96]         ▷ extract implicit rejection value
 5: m' ← K-PKE.Decrypt(dk_PKE, c)          ▷ decrypt ciphertext
 6: (K', r') ← G(m' ‖ h)
 7: K̄  ← J(z ‖ c)
 8: c' ← K-PKE.Encrypt(ek_PKE, m', r')     ▷ re-encrypt using the derived randomness r'
 9: if c ≠ c' then
10:     K' ← K̄                             ▷ if ciphertexts do not match, "implicitly reject"
11: end if
12: return K'
```

## Byte ranges for ML-KEM-768 (k=3)

| Line | Field | Range |
|---|---|---|
| 1 | `dk_PKE` | `dk[0:1152]` |
| 2 | `ek_PKE` | `dk[1152:2336]` |
| 3 | `h` | `dk[2336:2368]` |
| 4 | `z` | `dk[2368:2400]` |

## Note the ORDER: K̄ is computed on line 7, BEFORE the comparison

The standard itself places `K̄ ← J(z ‖ c)` at line 7 — before the re-encryption on line 8
and before the branch on line 9. It is **not** inside the `if`. Compute it
**unconditionally, every time**, regardless of whether the ciphertext turns out valid.

The `if` on lines 9–11 is pseudocode, **not** an implementation instruction. Implement it
as a branchless conditional move over a full-width mask:

```
mask = ct_neq(c, c')              // 0x00 if equal, 0xFF if different — no early exit
K'   = ct_cmov(K', K̄, mask)       // byte-wise select
```

## Normative constant-time requirements (FIPS 203 p. 33, verbatim)

> The "implicit reject" flag computed in step 9 (by comparing `c` and `c'`) is a secret
> piece of intermediate data. As specified in the requirements in Section 3.3, this flag
> **shall be destroyed** prior to ML-KEM.Decaps_internal terminating. In particular,
> **returning the value of the flag as an output in any form is not permitted.**

Consequences (spec §6.4, §8.1):

- The comparison is `ct_neq`, **never** `memcmp`, `std::equal`, or `==` on arrays. This is
  failure mode #10: `memcmp` passes every functional test and fails every security review.
- `ct_neq` needs a **compiler barrier** — the optimizer turns accumulator loops into early
  exits at `-O3`.
- The mask must be destroyed (`secure_zero`) before returning.
- `decaps` must **not** return a distinguishable status for a well-sized but invalid
  ciphertext. Length/type failures are public and may return an error; cryptographic
  failures must not.

## J

`J` is SHAKE256(·, 32) — a different function from `H` (SHA3-256) and `G` (SHA3-512).
`J(z ‖ c)` absorbs 32 + 1088 = 1120 bytes for ML-KEM-768.

## Why implicit rejection exists at all

Decapsulation failure is not purely adversarial — ML-KEM-768 has an intrinsic failure rate
of **2^−164.8** (§5, and `alg15-kpke-decrypt.md`). Implicit rejection converts both an
honest failure and an active attack into an indistinguishable pseudorandom shared secret,
which is what makes the Fujisaki–Okamoto transform IND-CCA2.

## ACVP — this is directly testable

The **encapDecap / VAL / `function: "decapsulation"`** group for ML-KEM-768 (tgId 5) has
10 cases, split 5/5 by a `reason` field:

- `"valid decapsulation"` × 5
- `"modified ciphertext"` × 5 — and for these, the expected `k` **equals**
  `SHAKE256(dk[-32:] ‖ c, 32)`, i.e. exactly `J(z ‖ c)`. Verified against the downloaded
  vectors in Phase 0.

These 5 cases are the only automated check that implicit rejection is implemented
correctly. A harness that filters them out reports a green suite on a broken
implementation.
