# Algorithm 16 — ML-KEM.KeyGen_internal(d, z)

FIPS 203 §6.1, p. 32. Deterministic — no randomness is sampled inside.

```
Input:  randomness d ∈ 𝔹^32
Input:  randomness z ∈ 𝔹^32
Output: encapsulation key ek ∈ 𝔹^(384k+32)
Output: decapsulation key dk ∈ 𝔹^(768k+96)

1: (ek_PKE, dk_PKE) ← K-PKE.KeyGen(d)      ▷ run key generation for K-PKE
2: ek ← ek_PKE                             ▷ KEM encaps key is just the PKE encryption key
3: dk ← (dk_PKE ‖ ek ‖ H(ek) ‖ z)          ▷ KEM decaps key includes PKE decryption key
4: return (ek, dk)
```

## dk layout for ML-KEM-768 (k=3)

| Field | Byte range | Length |
|---|---|---|
| `dk_PKE` | `[0, 1152)` | 384k = 1152 |
| `ek` | `[1152, 2336)` | 384k+32 = 1184 |
| `H(ek)` | `[2336, 2368)` | 32 |
| `z` | `[2368, 2400)` | 32 |

Total **2400** = 768k + 96. `ek` is **1184**.

The embedded `ek` and `H(ek)` are redundant-by-construction, which is what makes the §7.3
hash check possible.

## Notes

- `H` is SHA3-256.
- `z` is the implicit-rejection secret, consumed only by
  [Decaps_internal](alg18-decaps-internal.md) line 7.
- **`z` is never used by KeyGen itself** — it is stored verbatim. A KAT failure localized
  to the last 32 bytes of `dk` means `z` was transformed when it should have been copied.
- `(d, z)` is secret and, per §3.3, may be retained in place of `dk` (the seed-expanded
  key form of spec §3). Treat the 64-byte seed with the same protections as `dk`.

## ACVP

This is the algorithm the **keyGen** vectors test: inputs `d`, `z`; expected `ek`, `dk`.
