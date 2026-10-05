# Algorithm 20 — ML-KEM.Encaps(ek) + the §7.2 encapsulation key check

FIPS 203 §7.2, pp. 36–37.

```
Checked input: encapsulation key ek ∈ 𝔹^(384k+32)
Output: shared secret key K ∈ 𝔹^32
Output: ciphertext c ∈ 𝔹^(32(du·k+dv))

1: m ←$ 𝔹^32                    ▷ m is 32 random bytes (see Section 3.3)
2: if m == NULL then
3:     return ⊥                 ▷ error indication if random bit generation failed
4: end if
5: (K, c) ← ML-KEM.Encaps_internal(ek, m)
6: return (K, c)
```

## Encapsulation key check — MANDATORY (§7.2)

> **1. (Type check)** If `ek` is not an array of bytes of length `384k + 32` for the value
> of `k` specified by the relevant parameter set, then input checking failed.
>
> **2. (Modulus check)** Perform the computation (7.1)
>
> ```
> test ← ByteEncode_12( ByteDecode_12( ek[0 : 384k] ) )
> ```
>
> If `test ≠ ek[0 : 384k]`, then input checking failed. This check ensures that the
> integers encoded in the public key are in the valid range `[0, q − 1]`.

For ML-KEM-768: length must be **1184**, and the encode-decode roundtrip is over
`ek[0:1152]`.

### Why the modulus check is necessary

`ByteDecode_12` reduces mod `q` and is therefore **not injective** — a 12-bit field can
hold `[3329, 4095]`, which no honest encoder ever produces (see
[`alg06-byte-decode.md`](alg06-byte-decode.md)). Encode-then-compare is the cheapest way
to detect it.

### When it must run

> ML-KEM.Encaps **shall not** be run with an encapsulation key that has not been checked
> as above. However, checking of the encapsulation key **need not be performed by the
> encapsulating party, nor with every execution** of ML-KEM.Encaps. Instead, assurance
> that these checks have been performed can be acquired through other means.

So the check may be hoisted out of the hot path or done once out-of-band — unlike the
ciphertext length check in [`alg21-decaps.md`](alg21-decaps.md), which is per-call.

> It is important to note that this checking process does not guarantee that `ek` is a
> properly produced output of ML-KEM.KeyGen.

## Notes

- The check operates entirely on **public** data, so it may be variable-time.
- `m` is secret and must come from an approved RBG (192-bit strength for ML-KEM-768).
  Maps to `Status::InvalidEncapsKey` / `Status::RngFailure`.

## ACVP

The **encapDecap / VAL / `function: "encapsulationKeyCheck"`** group (768: tgId 10, 10
cases) tests exactly this, 5 pass / 5 fail, with `reason` values
`"valid encapsulation key"` and `"noisy linear system values too large"` — the latter
being the out-of-range 12-bit fields. Expected output is a boolean `testPassed`.
