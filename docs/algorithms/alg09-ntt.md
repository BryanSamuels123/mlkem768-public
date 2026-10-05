# Algorithm 9 — NTT(f)

FIPS 203 §4.3, p. 26.

Computes the NTT representation `f̂ ∈ T_q` of a polynomial `f ∈ R_q`.

```
Input:  array f ∈ ℤ_q^256      ▷ coefficients of the input polynomial
Output: array f̂ ∈ ℤ_q^256     ▷ coefficients of the NTT of the input

 1: f̂ ← f                                   ▷ compute in place on a copy
 2: i ← 1
 3: for (len ← 128; len ≥ 2; len ← len/2)
 4:     for (start ← 0; start < 256; start ← start + 2·len)
 5:         zeta ← ζ^(BitRev7(i)) mod q
 6:         i ← i + 1
 7:         for (j ← start; j < start + len; j++)
 8:             t ← zeta · f̂[j + len]        ▷ steps 8-10 done modulo q
 9:             f̂[j + len] ← f̂[j] − t
10:             f̂[j] ← f̂[j] + t
11:         end for
12:     end for
13: end for
14: return f̂
```

## Structure

- **7 layers**, not 8: `len` runs `128, 64, 32, 16, 8, 4, 2` and stops at 2.
  `q − 1 = 3328 = 2^8 · 13` admits a primitive 256th root of unity (ζ = 17) but **no**
  512th root, so `X^256 + 1` factors into **128 quadratics**, not 256 linears.
- `i` runs `1 .. 127` across the whole transform (`1 + 2 + 4 + ... + 64 = 127` butterfly
  groups). **`zetas[0]` is never used by this algorithm.**
- Lines 8–10 are a **Cooley–Tukey** (decimation-in-time) butterfly.

## Implementation notes

- Pairing CT forward with **Gentleman–Sande** inverse ([Alg. 10](alg10-inv-ntt.md))
  cancels the bit-reversal permutation at both ends — no explicit reorder step is ever
  needed. Spec §5.3.
- The `zeta ·` on line 8 becomes a `montgomery_reduce` of a product with a
  Montgomery-domain zeta. Record the resulting domain in `DECISIONS.md` ADR-004.
- Line 9/10 order matters: `f̂[j+len]` is written using the **old** `f̂[j]`. A naive
  in-place rewrite that updates `f̂[j]` first is wrong.
- Coefficient growth per layer is what `docs/bounds.md` must bound. `int16_t` overflow
  here is silent and produces wrong-but-plausible output.

## Tests

The **schoolbook differential** (spec §5.3 test 2) is the one that matters:
`invntt(basemul(ntt(a), ntt(b))) == schoolbook_negacyclic(a, b)`. It catches wrong zetas,
wrong layer count, wrong bit-reversal, wrong Montgomery domain, and wrong gamma signs in
one shot.
