# Algorithm 17 — ML-KEM.Encaps_internal(ek, m)

FIPS 203 §6.2, p. 33. Deterministic — `m` is supplied, not sampled.

```
Input:  encapsulation key ek ∈ 𝔹^(384k+32)
Input:  randomness m ∈ 𝔹^32
Output: shared secret key K ∈ 𝔹^32
Output: ciphertext c ∈ 𝔹^(32(du·k+dv))

1: (K, r) ← G(m ‖ H(ek))        ▷ derive shared secret key K and randomness r
2: c ← K-PKE.Encrypt(ek, m, r)  ▷ encrypt m using K-PKE with randomness r
3: return (K, c)
```

## The two Kyber differences live here — failure modes #1 and #2

1. **There is no `m ← H(m)`.** Round-3 Kyber hashes the message before use; ML-KEM does
   not. `m` goes into `G` and into `K-PKE.Encrypt` exactly as supplied.
2. **There is no final KDF.** `K` is the first 32 bytes of `G(m ‖ H(ek))` and is returned
   **directly**. Kyber applies `KDF(K̄ ‖ H(c))` at the end; ML-KEM does not.

Both produce a fully self-consistent implementation that fails every NIST KAT.

## G's output split

`G` is SHA3-512 → 64 bytes. `K = G(...)[0:32]`, `r = G(...)[32:64]`. K first.

## Notes

- `H(ek)` is SHA3-256 of the **full 1184-byte** `ek`, not of `t̂` alone.
- In [Decaps_internal](alg18-decaps-internal.md), `H(ek)` is not recomputed — the stored
  `h` from `dk` is used. The two must agree, which is what the §7.3 hash check enforces.
- `m`, `r`, and `K` are all secret (spec §8.1). `ek` and `c` are public.

## ACVP

This is what the **encapDecap / AFT** vectors test: inputs `ek`, `m`; expected `c`, `k`.
