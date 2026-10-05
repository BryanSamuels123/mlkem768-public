# Algorithm 12 — BaseCaseMultiply(a0, a1, b0, b1, γ)

FIPS 203 §4.3.1, p. 27.

Computes the product of two degree-one polynomials with respect to a quadratic modulus.

```
Input:  a0, a1, b0, b1 ∈ ℤ_q   ▷ coefficients of a0 + a1·X and b0 + b1·X
Input:  γ ∈ ℤ_q                ▷ the modulus is X² − γ
Output: c0, c1 ∈ ℤ_q           ▷ coefficients of the product

1: c0 ← a0·b0 + a1·b1·γ        ▷ steps 1-2 done modulo q
2: c1 ← a0·b1 + a1·b0
3: return (c0, c1)
```

## Derivation

`(a0 + a1X)(b0 + b1X) = a0b0 + (a0b1 + a1b0)X + a1b1X²`, and `X² ≡ γ` under the modulus
`X² − γ`, so the `X²` term folds into the constant coefficient as `a1·b1·γ`.

## Implementation notes

- Five multiplies as written; the standard Karatsuba trick is usually **not** worth it at
  this size because `a1·b1` is already shared and the Montgomery reductions dominate.
- The usual shape is: `montgomery_reduce(a1 · b1)` first, then multiply by `γ`, then a
  second `montgomery_reduce` — which is why `γ` is stored in the Montgomery domain.
- **The sign of γ alternates** across the 128 coordinates in the flat zeta table — see
  [`appendixA-zetas.md`](appendixA-zetas.md). Implementations commonly store
  `±ζ^(2·BitRev7(i)+1)` and process coordinates in pairs. Getting the sign wrong is caught
  immediately by the schoolbook differential test.
