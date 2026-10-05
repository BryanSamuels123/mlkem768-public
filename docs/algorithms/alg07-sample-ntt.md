# Algorithm 7 — SampleNTT(B)

FIPS 203 §4.2.2, p. 23.

Takes a 32-byte seed and two indices, and outputs a pseudorandom element of `T_q` by
rejection sampling from SHAKE128.

```
Input:  byte array B ∈ 𝔹^34     ▷ a 32-byte seed along with two indices
Output: array â ∈ ℤ_q^256       ▷ the coefficients of the NTT of a polynomial

 1: ctx ← XOF.Init()
 2: ctx ← XOF.Absorb(ctx, B)              ▷ input the given byte array into XOF
 3: j ← 0
 4: while j < 256 do
 5:     (ctx, C) ← XOF.Squeeze(ctx, 3)    ▷ get a fresh 3-byte array C from XOF
 6:     d1 ← C[0] + 256 · (C[1] mod 16)   ▷ 0 ≤ d1 < 2^12
 7:     d2 ← ⌊C[1]/16⌋ + 16 · C[2]        ▷ 0 ≤ d2 < 2^12
 8:     if d1 < q then
 9:         â[j] ← d1                     ▷ â ∈ ℤ_q^256
10:         j ← j + 1
11:     end if
12:     if d2 < q and j < 256 then
13:         â[j] ← d2
14:         j ← j + 1
15:     end if
16: end while
17: return â
```

## The output is ALREADY in the NTT domain

`SampleNTT` returns an element of `T_q`. It is **not** passed through `NTT()`. The matrix
`Â` in K-PKE.KeyGen is built directly from these outputs and lives permanently in the NTT
domain.

## Index order — failure mode #3

The 34-byte input is `ρ ‖ j ‖ i`:

| Byte range | Content |
|---|---|
| `0..31` | `ρ` (32-byte seed) |
| `32` | **`j`** — the *column* index |
| `33` | **`i`** — the *row* index |

FIPS 203 Alg. 13 line 5 (0-indexed bytes 32 and 33 of the array; the project spec
describes these as "byte 33" and "byte 34" in 1-indexed terms — same thing):

```
Â[i, j] ← SampleNTT(ρ ‖ j ‖ i)
```

**`j` comes first.** This was swapped in the FIPS 203 initial public draft and corrected
in the final standard. Getting it wrong transposes `Â` and produces a fully
self-consistent implementation that fails every KAT. Spec §6.2 requires an explicit
index-order golden-vector test.

## Constant-time status

**Variable time is acceptable and expected.** The input `B` is derived entirely from the
public seed `ρ` and public indices, so the rejection pattern leaks nothing. Spec §8.1
names this as the main permitted variable-time case.

## Loop bound

Default: **do not bound the loop**, per Appendix B. See
[`appendixB-sample-ntt-bounds.md`](appendixB-sample-ntt-bounds.md).

## Implementation notes

- Squeezing 3 bytes at a time is the specified behaviour, but by the equivalence in
  (4.6) / [Algorithm 2](alg02-xof-incremental.md) a bulk squeeze of a whole Keccak block
  (168 bytes for SHAKE128) and then chunking it into 3-byte groups is **identical**.
  Squeeze a full block at a time; refill when exhausted.
- 168 is divisible by 3, so a block boundary never splits a 3-byte group — a convenient
  accident worth relying on deliberately rather than by luck.
- This is where 4-way batched Keccak pays off most: ML-KEM-768 makes **9 independent
  SampleNTT calls** for the 3×3 matrix (spec §7.1).
