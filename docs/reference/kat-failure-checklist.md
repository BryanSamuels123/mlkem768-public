# When a KAT fails, check these first

*Moved out of `docs/reference/invariants.md` in the Phase 8 close-out prune (2026-09-28). It is reference
material — a debugging checklist you reach for when something is already broken — not a rule, so it does not need to be in context every session.
`docs/reference/invariants.md` links here.*

---

## When a KAT fails, check these first

1. Missing `‖k` domain separator in `G(d ‖ k)` — the most common cause
2. Kyber's FO transform instead of ML-KEM's (extra `m ← H(m)`, or a final KDF)
3. Transposed `Â` — it is `SampleNTT(ρ ‖ j ‖ i)`, with **`j` at byte 33, `i` at byte 34**
4. Missing transpose in `Âᵀ ∘ ŷ` in Encrypt
5. Wrong `N` counter order in noise sampling (KeyGen: `s`=0,1,2 then `e`=3,4,5;
   Encrypt: `y`=0,1,2 then `e1`=3,4,5 then `e2`=6)
6. Montgomery domain mismatch — roundtrip passes, KAT fails, output off by a constant
7. Bit-packing endianness — FIPS 203 is little-endian at the bit level (Alg. 3/4)
8. `int16_t` overflow from over-aggressive lazy reduction
9. Compress rounding — round-half-**up**; the boundary case matters
10. `memcmp` in decaps instead of `ct_neq`
