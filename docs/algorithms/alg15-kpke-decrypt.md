# Algorithm 15 — K-PKE.Decrypt(dk_PKE, c)

FIPS 203 §5.3, p. 31.

```
Input:  decryption key dk_PKE ∈ 𝔹^(384k)
Input:  ciphertext c ∈ 𝔹^(32(du·k + dv))
Output: message m ∈ 𝔹^32

1: c1 ← c[0 : 32·du·k]
2: c2 ← c[32·du·k : 32(du·k + dv)]
3: u' ← Decompress_du( ByteDecode_du(c1) )    ▷ run each k times
4: v' ← Decompress_dv( ByteDecode_dv(c2) )
5: ŝ  ← ByteDecode_12(dk_PKE)                 ▷ run ByteDecode_12 k times
6: w  ← v' − NTT^-1( ŝᵀ ∘ NTT(u') )           ▷ run NTT k times; run NTT^-1 once
7: m  ← ByteEncode_1( Compress_1(w) )         ▷ decode plaintext m from polynomial w
8: return m
```

## Notes

- **`u'` must be re-transformed.** `ŝ` comes out of `dk_PKE` already in the NTT domain
  (KeyGen stored it that way), but `u'` is decompressed in the *normal* domain, so line 6
  applies `NTT()` to it. Only one `NTT^-1` is needed, after the inner product.
- Line 7 is `poly_tomsg`: round each coefficient to the nearer of `{0, ⌈q/2⌋}` and pack
  the resulting bits. It requires **canonical `[0, q)`** input — see `docs/bounds.md`.
- For ML-KEM-768: `c1` is bytes `[0, 960)`, `c2` is bytes `[960, 1088)`.

## Why it works

```
w = v' − ŝᵀu' = μ + (eᵀy − sᵀe1 + e2) + (compression noise)
```

Everything after `μ` is small. While the total stays below `q/4`, `Compress_1` recovers
each bit. For ML-KEM-768 the failure probability is **2^−164.8** — nonzero, which is
precisely why implicit rejection exists in
[Decaps_internal](alg18-decaps-internal.md).

## Secrecy

Everything here is secret: `dk_PKE`, `ŝ`, `w`, and the output `m`. Only `c` is public.
The whole algorithm must be constant-time. In particular `Compress_1` on line 7 operates
on secret data, so its division by `q` must be a multiply-shift, never an integer `div`.
