# Compress_d and Decompress_d

FIPS 203 §4.2.1, p. 20, equations (4.7) and (4.8). These are *definitions*, not numbered
algorithms.

```
Compress_d :  ℤ_q  ⟶ ℤ_(2^d)      x ⟼ ⌈(2^d / q) · x⌋  mod 2^d
Decompress_d : ℤ_(2^d) ⟶ ℤ_q      y ⟼ ⌈(q / 2^d) · y⌋
```

Recall `q = 3329`, bit length 12. Defined for `d < 12`.

## Rounding — failure mode #9

`⌈x⌋` is round-to-nearest with **ties rounding up** (FIPS 203 §2.3):

> `⌈x⌋` The rounding of `x` to the nearest integer. If `x = y + 1/2` for some `y ∈ ℤ`,
> then `⌈x⌋ = y + 1`.

The standard also states, verbatim (p. 20):

> Division and rounding in the computation of these functions are performed in the set of
> rational numbers. **Floating-point computations shall not be used.**

## Integer-only forms

For non-negative integer inputs, round-half-up `⌈a/b⌋` is `⌊(2a + b) / 2b⌋`:

```
Compress_d(x)   = ⌊ (2^(d+1) · x + q) / (2q) ⌋  mod 2^d
Decompress_d(y) = ⌊ (2^(d+1) · y · ... ) ⌋  ==  ( y · q + (1 << (d−1)) ) >> d
```

`Decompress_d` needs no modular reduction: the result is already `< q`.

`Compress_d` requires a division by `q`, which is a variable-latency instruction and is
**forbidden on secret data** (spec §8.1). Replace it with a multiply-and-shift
`(x · M) >> S`. **Derive `M` and `S`; do not copy a magic constant** (spec §6.1).

## The free correctness oracle

FIPS 203 p. 20 guarantees:

> `Compress_d(Decompress_d(y)) = y` for all `y ∈ ℤ_(2^d)` and all `d < 12`.

Test this exhaustively. The reverse does **not** hold — compression is lossy — but for `d`
close to 12 the value is not significantly altered.

## Required exhaustive tests (spec §6.1)

- For every `x ∈ [0, 3329)` and every `d ∈ {1, 4, 10}`: optimized `Compress_d(x)` equals
  the exact rational formula computed in 64-bit integers. 3329 × 3 cases.
- For every `y ∈ [0, 2^d)`: same for `Decompress_d`, and the roundtrip identity above.

These run in microseconds and make an entire class of off-by-one bugs impossible.

## Values used by ML-KEM-768

| `d` | Used for | Sizes |
|---|---|---|
| 1 | message bit ↔ coefficient. `Decompress_1(1) = ⌈q/2⌋ = 1665` | 32 B ↔ 256 coeffs |
| 4 | `d_v`, compresses `v` | 256 coeffs → 128 B |
| 10 | `d_u`, compresses each poly of `u` | 256 coeffs → 320 B |
