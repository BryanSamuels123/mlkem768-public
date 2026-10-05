# Algorithm 14 — K-PKE.Encrypt(ek_PKE, m, r)

FIPS 203 §5.2, p. 30.

```
Input:  encryption key ek_PKE ∈ 𝔹^(384k+32)
Input:  message m ∈ 𝔹^32
Input:  randomness r ∈ 𝔹^32
Output: ciphertext c ∈ 𝔹^(32(du·k + dv))

 1: N ← 0
 2: t̂ ← ByteDecode_12( ek_PKE[0 : 384k] )        ▷ run ByteDecode_12 k times
 3: ρ ← ek_PKE[384k : 384k + 32]                 ▷ extract 32-byte seed from ek_PKE
 4: for (i ← 0; i < k; i++)                      ▷ re-generate Â, exactly as in Alg. 13
 5:     for (j ← 0; j < k; j++)
 6:         Â[i, j] ← SampleNTT(ρ ‖ j ‖ i)       ▷ j and i are bytes 33 and 34
 7:     end for
 8: end for
 9: for (i ← 0; i < k; i++)                      ▷ generate y ∈ (ℤ_q^256)^k
10:     y[i] ← SamplePolyCBD_η1( PRF_η1(r, N) )
11:     N ← N + 1
12: end for
13: for (i ← 0; i < k; i++)                      ▷ generate e1 ∈ (ℤ_q^256)^k
14:     e1[i] ← SamplePolyCBD_η2( PRF_η2(r, N) )
15:     N ← N + 1
16: end for
17: e2 ← SamplePolyCBD_η2( PRF_η2(r, N) )        ▷ sample e2 ∈ ℤ_q^256
18: ŷ ← NTT(y)                                   ▷ run NTT k times
19: u ← NTT^-1( Âᵀ ∘ ŷ ) + e1                    ▷ run NTT^-1 k times
20: μ ← Decompress_1( ByteDecode_1(m) )
21: v ← NTT^-1( t̂ᵀ ∘ ŷ ) + e2 + μ                ▷ encode plaintext m into polynomial v
22: c1 ← ByteEncode_du( Compress_du(u) )         ▷ run each du-op k times
23: c2 ← ByteEncode_dv( Compress_dv(v) )
24: return c ← (c1 ‖ c2)
```

## The transpose on line 19 — failure mode #4

`Âᵀ ∘ ŷ`, **transposed**. KeyGen uses `Â ∘ ŝ` untransposed; Encrypt uses `Âᵀ ∘ ŷ`. Since
`Â[i,j] = SampleNTT(ρ ‖ j ‖ i)`, there are two independent chances to transpose the matrix
and they can cancel — producing something self-consistent that fails every KAT. Test the
index order directly (spec §6.2).

Line 21's `t̂ᵀ ∘ ŷ` is an inner product of two length-k vectors, yielding a single
polynomial.

## N counter order — failure mode #5

`y` = 0,1,2 (**η1**), then `e1` = 3,4,5 (**η2**), then `e2` = 6 (**η2**). One shared
counter. Note this differs from [KeyGen](alg13-kpke-keygen.md), where `e` uses η1.

## The eta split

| Term | Distribution |
|---|---|
| `y` | η1 |
| `e1` | η2 |
| `e2` | η2 |

Identical for ML-KEM-768 (`η1 = η2 = 2`); not identical for ML-KEM-512.

## μ: the message encoding

`μ ← Decompress_1(ByteDecode_1(m))` maps each of the 256 message **bits** to a
coefficient: bit 0 → 0, bit 1 → `Decompress_1(1) = ⌈q/2⌋ = 1665`. That is the
`poly_frommsg` of spec §6.1.

## Compression asymmetry

`u` is compressed to `du = 10` bits, `v` to `dv = 4`. `v` carries the message with an
enormous per-coefficient margin so it tolerates aggressive rounding; `u` is `k×` larger,
so trimming bits there saves `k×` more bytes.

For ML-KEM-768: `c1` = 32·10·3 = **960** bytes, `c2` = 32·4 = **128** bytes,
`c` = **1088** bytes.

## Secrecy

`y`, `e1`, `e2`, `m`, and `r` are all secret (spec §8.1). `ek_PKE`, `ρ`, `Â`, and the
output `c` are public.
