# Algorithm 5 — ByteEncode_d(F)

FIPS 203 §4.2.1, p. 22.

Encodes an array of 256 d-bit integers into a byte array, for `1 ≤ d ≤ 12`.

```
Input:  integer array F ∈ ℤ_m^256, where m = 2^d if d < 12, and m = q if d = 12
Output: byte array B ∈ 𝔹^(32d)

1: for (i ← 0; i < 256; i++)
2:     a ← F[i]                              ▷ a ∈ ℤ_m
3:     for (j ← 0; j < d; j++)
4:         b[i·d + j] ← a mod 2              ▷ b ∈ {0,1}^(256·d)
5:         a ← (a − b[i·d + j]) / 2          ▷ note a − b[i·d+j] is always even
6:     end for
7: end for
8: B ← BitsToBytes(b)
9: return B
```

## Notes

- Output size `32d` bytes: `d=12 → 384` (a poly), `d=10 → 320`, `d=4 → 128`, `d=1 → 32`.
- Coefficient `i` occupies bits `[i·d, (i+1)·d)` of the bit array, LSB-first within the
  coefficient, and the bit array is packed into bytes LSB-first
  ([Algorithm 3](alg03-bits-to-bytes.md)). Net effect for `d=12`: two coefficients pack
  into three bytes as
  `B[0] = a0 & 0xFF`, `B[1] = (a0 >> 8) | ((a1 & 0x0F) << 4)`, `B[2] = a1 >> 4`.
- **Input must be canonical.** For `d = 12` the input is in `ℤ_q`, i.e. `[0, q)`. Feeding
  it a signed or unreduced coefficient produces garbage silently. This is why
  `docs/bounds.md` marks `poly_tobytes` as requiring canonical `[0,q)`.

## Spec cross-reference

`ByteEncode_12 ∘ ByteDecode_12` is the **encapsulation-key modulus check** of §7.2 —
see `alg20-encaps.md`.
