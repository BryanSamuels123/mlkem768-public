# Algorithm 10 — NTT^-1(f̂)

FIPS 203 §4.3, p. 26.

Computes the polynomial `f ∈ R_q` corresponding to an NTT representation `f̂ ∈ T_q`.

```
Input:  array f̂ ∈ ℤ_q^256     ▷ coefficients of the input NTT representation
Output: array f  ∈ ℤ_q^256     ▷ coefficients of the inverse NTT of the input

 1: f ← f̂                                  ▷ compute in place on a copy
 2: i ← 127
 3: for (len ← 2; len ≤ 128; len ← 2·len)
 4:     for (start ← 0; start < 256; start ← start + 2·len)
 5:         zeta ← ζ^(BitRev7(i)) mod q
 6:         i ← i − 1
 7:         for (j ← start; j < start + len; j++)
 8:             t ← f[j]
 9:             f[j] ← t + f[j + len]        ▷ steps 9-10 done modulo q
10:             f[j + len] ← zeta · (f[j + len] − t)
11:         end for
12:     end for
13: end for
14: f ← f · 3303 mod q                       ▷ multiply every entry by 3303 ≡ 128^-1 mod q
15: return f
```

## Notes

- **The final scale factor is `128^-1 = 3303`, not `256^-1`.** Seven layers, so the
  transform accumulates a factor of `2^7 = 128`. Using `256^-1` is a classic off-by-one-
  layer bug that leaves every output scaled by 2.
  Check: `128 · 3303 = 422784 = 127 · 3329 + 1`. ✓
- `i` counts **down** from 127 to 1, exactly reversing Algorithm 9's ascending order.
  `zetas[0]` is again unused.
- Lines 8–10 are a **Gentleman–Sande** (decimation-in-frequency) butterfly — note it is
  *not* the algebraic inverse of the CT butterfly written backwards; the subtraction
  `f[j+len] − t` uses the **old** `f[j]` saved in `t` on line 8.

## Implementation notes

- Spec §5.3 requires folding the `3303` scaling together with a Montgomery factor so the
  output lands in a known domain. **Document precisely which domain in `DECISIONS.md`
  ADR-004 and mirror it into `docs/reference/invariants.md`.** This is failure mode #6: a domain mismatch
  passes every roundtrip test and fails every KAT, with output off by a constant factor.
- The `128^-1` multiply on line 14 can be merged into the last layer's butterflies rather
  than run as a separate pass.
