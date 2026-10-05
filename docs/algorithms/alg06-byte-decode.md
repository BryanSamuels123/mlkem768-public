# Algorithm 6 — ByteDecode_d(B)

FIPS 203 §4.2.1, p. 22.

Decodes a byte array into an array of 256 d-bit integers, for `1 ≤ d ≤ 12`.

```
Input:  byte array B ∈ 𝔹^(32d)
Output: integer array F ∈ ℤ_m^256, where m = 2^d if d < 12, and m = q if d = 12

1: b ← BytesToBits(B)
2: for (i ← 0; i < 256; i++)
3:     F[i] ← ( Σ_{j=0}^{d−1} b[i·d + j] · 2^j )  mod m
4: end for
5: return F
```

## Notes — the non-injectivity, which is load-bearing

FIPS 203 p. 21 states this explicitly:

> For `d` satisfying `1 ≤ d ≤ 11`, the conversion is one-to-one.
>
> For `d = 12`, `ByteDecode_12` produces integers modulo `q` as output. Specifically,
> `ByteDecode_12` converts each 12-bit segment of its input into an integer modulo
> `2^12 = 4096` and then **reduces the result modulo q**. This is no longer a one-to-one
> operation. Indeed, some 12-bit segments could correspond to an integer greater than
> `q − 1 = 3328` but less than 4096. **However, this cannot occur for arrays produced by
> ByteEncode_12.**

So for `d = 12` the `mod m` on line 3 is `mod q`, and a 12-bit field holding
`[3329, 4095]` is silently folded into `[0, 766]`.

This is precisely why the §7.2 **modulus check** exists: an honest encoder never produces
such a field, so `ByteEncode_12(ByteDecode_12(x)) == x` detects it. See `alg20-encaps.md`.

For `d < 12`, `m = 2^d` and the mask is free — the sum cannot exceed `2^d − 1`.
