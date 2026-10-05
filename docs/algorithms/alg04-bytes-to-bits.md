# Algorithm 4 — BytesToBits(B)

FIPS 203 §4.2.1, p. 20.

Inverse of BitsToBytes.

```
Input:  byte array B ∈ 𝔹^ℓ
Output: bit array  b ∈ {0,1}^(8·ℓ)

1: C ← B                          ▷ copy B into array C ∈ 𝔹^ℓ
2: for (i ← 0; i < ℓ; i++)
3:     for (j ← 0; j < 8; j++)
4:         b[8i + j] ← C[i] mod 2
5:         C[i] ← ⌊C[i]/2⌋
6:     end for
7: end for
8: return b
```

## Notes

- Line 1 copying into `C` matters only because the pseudocode destroys `C` as it goes;
  `B` is unchanged.
- Bit `8i+j` is bit `j` (LSB-first) of byte `i`. Same little-endian convention as
  [Algorithm 3](alg03-bits-to-bytes.md).

## Implementation

Not materialized. See the note in `alg03-bits-to-bytes.md`.
