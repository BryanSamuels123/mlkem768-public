# Algorithm 11 — MultiplyNTTs(f̂, ĝ)

FIPS 203 §4.3.1, p. 27.

Computes the product, in the ring `T_q`, of two NTT representations.

```
Input:  arrays f̂, ĝ ∈ ℤ_q^256
Output: array  ĥ   ∈ ℤ_q^256

1: for (i ← 0; i < 128; i++)
2:     (ĥ[2i], ĥ[2i+1]) ← BaseCaseMultiply( f̂[2i], f̂[2i+1],
                                             ĝ[2i], ĝ[2i+1],
                                             ζ^(2·BitRev7(i)+1) )
3: end for
4: return ĥ
```

## Why this is not a pointwise multiply

From (4.14): `f̂ ∈ T_q` is a vector of **128 degree-one residues** modulo quadratic
polynomials. The `i`-th coordinate of the product is

```
ĥ[2i] + ĥ[2i+1]·X = (f̂[2i] + f̂[2i+1]·X)(ĝ[2i] + ĝ[2i+1]·X)  mod (X² − ζ^(2·BitRev7(i)+1))
```

So each of the 128 coordinates is a degree-1 × degree-1 product reduced modulo its own
quadratic. Multiplication in `T_q` is 128 independent `BaseCaseMultiply` calls, not 256
scalar multiplies.

## Zeta table

The `ζ^(2·BitRev7(i)+1)` values are the **second** Appendix A table — a different table
from the one Algorithms 9/10 use. See [`appendixA-zetas.md`](appendixA-zetas.md).

Note `i` here starts at **0** and runs to 127, unlike Algorithm 9's `i` which starts at 1.

## Implementation

Spec §5.3 wants an accumulating variant `poly_basemul_acc` (`r += a ∘ b`) so the
matrix-vector products in K-PKE avoid `k` temporary polynomials.
