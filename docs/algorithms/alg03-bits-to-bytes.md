# Algorithm 3 — BitsToBytes(b)

FIPS 203 §4.2.1, p. 20.

Converts a bit array (length a multiple of 8) into an array of bytes.

```
Input:  bit array  b ∈ {0,1}^(8·ℓ)
Output: byte array B ∈ 𝔹^ℓ

1: B ← (0, ..., 0)
2: for (i ← 0; i < 8ℓ; i++)
3:     B[⌊i/8⌋] ← B[⌊i/8⌋] + b[i] · 2^(i mod 8)
4: end for
5: return B
```

## Notes

- **Little-endian at the bit level.** Bit `i` of the array contributes `2^(i mod 8)` to
  its byte — so `b[0]` is the *least* significant bit of `B[0]`.
- The standard's own example (p. 20): the 8-bit string `11010001` corresponds to the byte
  `2^0 + 2^1 + 2^3 + 2^7 = 139`. Note this reads the string left-to-right as
  `b[0]=1, b[1]=1, b[2]=0, b[3]=1, ...`.
- This is failure mode #7 in `docs/reference/invariants.md`. Test with a message `0x01 0x00 ...` and verify
  the **first** coefficient is set, not the eighth.

## Implementation

Never materialize the bit array. `BitsToBytes`/`BytesToBits` exist to define the bit
ordering; `ByteEncode`/`ByteDecode` are implemented directly as bit-packing loops or SIMD
shuffles that produce the same ordering.
