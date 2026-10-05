# Algorithm 13 — K-PKE.KeyGen(d)

FIPS 203 §5.1, p. 29.

```
Input:  randomness d ∈ 𝔹^32
Output: encryption key ek_PKE ∈ 𝔹^(384k+32)
Output: decryption key dk_PKE ∈ 𝔹^(384k)

 1: (ρ, σ) ← G(d ‖ k)                 ▷ expand 32+1 bytes to two pseudorandom 32-byte seeds  [1]
 2: N ← 0
 3: for (i ← 0; i < k; i++)            ▷ generate matrix Â ∈ (ℤ_q^256)^(k×k)
 4:     for (j ← 0; j < k; j++)
 5:         Â[i, j] ← SampleNTT(ρ ‖ j ‖ i)    ▷ j and i are bytes 33 and 34 of the input
 6:     end for
 7: end for
 8: for (i ← 0; i < k; i++)            ▷ generate s ∈ (ℤ_q^256)^k
 9:     s[i] ← SamplePolyCBD_η1( PRF_η1(σ, N) )
10:     N ← N + 1
11: end for
12: for (i ← 0; i < k; i++)            ▷ generate e ∈ (ℤ_q^256)^k
13:     e[i] ← SamplePolyCBD_η1( PRF_η1(σ, N) )
14:     N ← N + 1
15: end for
16: ŝ ← NTT(s)                         ▷ run NTT k times (once per coordinate of s)
17: ê ← NTT(e)                         ▷ run NTT k times
18: t̂ ← Â ∘ ŝ + ê                      ▷ noisy linear system in NTT domain
19: ek_PKE ← ByteEncode_12(t̂) ‖ ρ      ▷ run ByteEncode_12 k times, then append Â-seed
20: dk_PKE ← ByteEncode_12(ŝ)          ▷ run ByteEncode_12 k times
21: return (ek_PKE, dk_PKE)
```

## [1] The `‖k` domain separator — failure mode #1

Line 1 is `G(d ‖ k)`, a **33-byte** input. **`k = 3` for ML-KEM-768.** FIPS 203 footnote 1
on p. 29, verbatim:

> Byte 33 of the input to G is the module dimension `k ∈ {2, 3, 4} ⊂ 𝔹`. This is included
> to establish domain separation between the three parameter sets. For implementations
> that use the seed in place of the private key, this ensures that the expansion will
> produce an unrelated key if the seed is mistakenly expanded using a parameter set other
> than the originally intended one.

Round-3 Kyber does **not** do this. Omitting it is the single most common cause of a
self-consistent implementation failing every NIST KAT.

"Byte 33" is 1-indexed: `d` occupies indices `0..31`, and `k` goes at index **32**.

## Both s and e use η1 — not η2

Lines 9 and 13 both call `SamplePolyCBD_η1` / `PRF_η1`. For ML-KEM-768 this is invisible
because `η1 = η2 = 2`, but it is **not** invisible for ML-KEM-512 (`η1 = 3, η2 = 2`).
Since spec §1 requires the code be structured so other parameter sets are a parameter
change and not a rewrite, wire the η1 in explicitly here rather than reaching for a
generic "eta".

`η2` appears only in [K-PKE.Encrypt](alg14-kpke-encrypt.md), for `e1` and `e2`.

## N counter order is normative — failure mode #5

`s` = 0, 1, 2 then `e` = 3, 4, 5. A single shared counter, incremented across both loops.

## Matrix index order — failure mode #3

`Â[i, j] ← SampleNTT(ρ ‖ j ‖ i)`, **`j` first**. See
[`alg07-sample-ntt.md`](alg07-sample-ntt.md).

## Everything stays in the NTT domain

`t̂`, `ŝ`, and `Â` live **permanently** in the NTT domain and are never transformed back.
`SampleNTT` already produces NTT-domain output, so `Â` is never passed through `NTT()`.
`ek_PKE` and `dk_PKE` both store NTT-domain values.

Line 18's `∘` is matrix-vector multiplication in `T_q`, i.e. `k²` calls to
[MultiplyNTTs](alg11-multiply-ntts.md) with accumulation.

## Caching Â

FIPS 203 §3.3 explicitly permits storing `Â` (p. 29: "The matrix Â generated in steps 3-7
can be stored"). It is derived from the public `ρ`, so caching it leaks nothing. Spec §9.2
item 6 makes this a major batch-encapsulation optimization.

## Sizes for ML-KEM-768 (k=3)

`ek_PKE` = 384·3 + 32 = **1184** bytes. `dk_PKE` = 384·3 = **1152** bytes.
