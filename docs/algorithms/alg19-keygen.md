# Algorithm 19 — ML-KEM.KeyGen()

FIPS 203 §7.1, p. 35. The randomized, application-facing key generation.

```
Output: encapsulation key ek ∈ 𝔹^(384k+32)
Output: decapsulation key dk ∈ 𝔹^(768k+96)

1: d ←$ 𝔹^32                              ▷ d is 32 random bytes (see Section 3.3)
2: z ←$ 𝔹^32                              ▷ z is 32 random bytes (see Section 3.3)
3: if d == NULL or z == NULL then
4:     return ⊥                           ▷ error indication if random bit generation failed
5: end if
6: (ek, dk) ← ML-KEM.KeyGen_internal(d, z)
7: return (ek, dk)
```

## Notes

- The RBG failure check on lines 3–5 is **normative**, not optional. Maps to
  `Status::RngFailure` in the project API.
- ML-KEM-768 requires an RBG with **192-bit** security strength (FIPS 203 Table 2).
- `d` and `z` must come from an approved RBG, generated **by the cryptographic module**
  (§3.3, §6). They are secret.
- Per §7.1, the seed `(d, z)` may be **stored** for later re-expansion via
  [KeyGen_internal](alg16-keygen-internal.md):

  > As the seed can be used to compute the decapsulation key, it is sensitive data and
  > **shall be treated with the same safeguards as a decapsulation key**.

  This is the `keygen_seeded` / `keygen_from_seed` pair in the project API (spec §3).
- The project's injected RNG must be thread-safe if the batch API is used (spec §9.3). A
  non-thread-safe RBG shared across threads is a catastrophic, silent security bug.

## Key pair check (§7.1)

To validate a candidate `(ek, dk)` pair, FIPS 203 specifies:

1. **Seed consistency** — if `(d, z)` is available, re-run `KeyGen_internal(d, z)` and
   verify the output equals `(ek, dk)`.
2. **Encapsulation key check** — as in §7.2, see [`alg20-encaps.md`](alg20-encaps.md).
3. **Decapsulation key check** — as in §7.3, see [`alg21-decaps.md`](alg21-decaps.md).
4. **Pair-wise consistency** — sample `m ←$ 𝔹^32`, run
   `(K, c) ← Encaps_internal(ek, m)` then `K' ← Decaps_internal(dk, c)`, and reject
   unless `K == K'`.

> This checking process does **not** guarantee that the key pair is a properly produced
> output of ML-KEM.KeyGen.
