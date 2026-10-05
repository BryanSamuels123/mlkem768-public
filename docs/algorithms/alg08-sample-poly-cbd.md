# Algorithm 8 — SamplePolyCBD_η(B)

FIPS 203 §4.2.2, p. 23.

Samples the coefficient array of a polynomial `f ∈ R_q` from the centered binomial
distribution `D_η(R_q)`.

```
Input:  byte array B ∈ 𝔹^(64η)
Output: array f ∈ ℤ_q^256       ▷ the coefficients of the sampled polynomial

1: b ← BytesToBits(B)
2: for (i ← 0; i < 256; i++)
3:     x ← Σ_{j=0}^{η−1} b[2iη + j]           ▷ 0 ≤ x ≤ η
4:     y ← Σ_{j=0}^{η−1} b[2iη + η + j]       ▷ 0 ≤ y ≤ η
5:     f[i] ← x − y  mod q                    ▷ 0 ≤ f[i] ≤ η  or  q−η ≤ f[i] ≤ q−1
6: end for
7: return f
```

## For ML-KEM-768: η1 = η2 = 2

- Input is `64η = 128` bytes.
- Each coefficient consumes `2η = 4` bits: 2 bits for `x`, 2 for `y`.
- Output range `{−2, −1, 0, 1, 2}`, i.e. mod q: `{0, 1, 2, 3327, 3328}`.
- Distribution is binomial: `{1, 4, 6, 4, 1}/16` for `{−2,−1,0,1,2}`.

## Constant-time status

**MUST be constant-time** — the output is the secret `s`, `e`, `y`, `e1`, or `e2`.

CBD is constant-time *by construction*: bit-slicing and popcounts, no tables, no
rejection. That property is exactly why ML-KEM uses a centered binomial rather than a
discrete Gaussian.

## API shape — parameterize on η, do not hardcode η = 2

The declaration is `sample_poly_cbd<Eta>`, with `Eta` a template parameter, and the
matching `PRF<Eta>` produces `64·Eta` bytes. Naming either function after the value 2
hardcodes `η1 == η2`, which is true at ML-KEM-768 and **false at ML-KEM-512**
(`η1 = 3` → 192 PRF bytes). Call sites select by **role** (`params::ETA1` /
`params::ETA2`), never by value. See `DECISIONS.md` ADR-009 and spec §6.2/§6.3.

Note `η` in `PRF` selects **output length only** — FIPS 203 §4.1 states it performs no
domain separation, so `PRF<2>(s,b)` is a 128-byte prefix of `PRF<3>(s,b)`. Adding a
domain-separation byte for η would break every KAT.

## Implementation (η = 2)

Branchless, per spec §6.2: load 4 bytes as a `uint32_t`, mask with `0x55555555`, add the
shifted halves to get 2-bit popcounts, then extract nibbles to form `x − y`. The whole
128-byte buffer is 32 `uint32_t` loads.

Note the bit ordering follows [BytesToBits](alg04-bytes-to-bits.md): bit `8i+j` is bit `j`
(LSB-first) of byte `i`.

## Caller contract — the N counter order is normative

`B` comes from `PRF_η(σ, N)`. The counter order is fixed by the standard and is failure
mode #5:

- **KeyGen**: `s[0..2]` with `N = 0,1,2`, then `e[0..2]` with `N = 3,4,5`
- **Encrypt**: `y[0..2]` with `N = 0,1,2`, then `e1[0..2]` with `N = 3,4,5`, then `e2` with `N = 6`
