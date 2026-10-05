# Algorithm 21 — ML-KEM.Decaps(dk, c) + the §7.3 decapsulation input check

FIPS 203 §7.3, pp. 37–38.

```
Checked input: decapsulation key dk ∈ 𝔹^(768k+96)
Checked input: ciphertext c ∈ 𝔹^(32(du·k+dv))
Output: shared secret key K ∈ 𝔹^32

1: K' ← ML-KEM.Decaps_internal(dk, c)     ▷ run internal decapsulation algorithm
2: return K'
```

## Decapsulation input check — MANDATORY (§7.3)

> **1. (Ciphertext type check)** If `c` is not a byte array of length `32(du·k + dv)` for
> the values of `du`, `dv`, and `k` specified by the relevant parameter set, then input
> checking has failed.
>
> **2. (Decapsulation key type check)** If `dk` is not a byte array of length `768k + 96`
> for the value of `k` specified by the relevant parameter set, then input checking has
> failed.
>
> **3. (Hash check)** Perform the computation (7.2)
>
> ```
> test ← H( dk[384k : 768k+32] )
> ```
>
> If `test ≠ dk[768k+32 : 768k+64]`, then input checking has failed.

For ML-KEM-768: `c` must be **1088** bytes, `dk` must be **2400** bytes, and
`H(dk[1152:2336]) == dk[2336:2368]` — i.e. the stored `H(ek)` must match the stored `ek`.

## Which checks run per-call — this distinction is normative

> ML-KEM.Decaps **shall not** be run with a decapsulation key or a ciphertext unless both
> have been checked. However, checking of the decapsulation key **need not be performed by
> the decapsulating party, nor with every execution** of ML-KEM.Decaps. Instead, assurance
> that this check has been performed can be acquired through other means.
>
> **Ciphertext checking shall be performed with every execution of ML-KEM.Decaps.**

| Check | Frequency |
|---|---|
| Ciphertext length | **Every call.** No exceptions. |
| `dk` length | May be hoisted / done out-of-band |
| `dk` hash check | May be hoisted / done out-of-band |

> This checking process does not guarantee that `dk` is a properly produced output of
> ML-KEM.KeyGen, nor that `c` is a properly produced output of ML-KEM.Encaps.

## Error reporting — the critical distinction

These input checks are about **public, structural** properties: lengths, and a hash of
public data. They **may** return a distinguishable error
(`Status::InvalidCiphertext` / `Status::InvalidDecapsKey`).

A **well-sized but cryptographically invalid** ciphertext must **not** produce a
distinguishable result. It goes all the way through
[Decaps_internal](alg18-decaps-internal.md) and comes back as the implicit-reject secret
`J(z ‖ c)`, indistinguishable from success in both value and timing.

Confusing these two is the difference between a correct implementation and a
Bleichenbacher-style oracle.

## ACVP

The **encapDecap / VAL / `function: "decapsulationKeyCheck"`** group (768: tgId 9, 10
cases) tests the hash check, 5 pass / 5 fail, `reason` ∈ {`"valid decapsulation key"`,
`"modified H"`}. Expected output is a boolean `testPassed`.
