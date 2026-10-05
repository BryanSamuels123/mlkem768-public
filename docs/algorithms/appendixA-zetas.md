# Appendix A — Precomputed Values for the NTT

FIPS 203 Appendix A, pp. 44–45. Both tables transcribed verbatim.

**These are plain `ℤ_q` values — NOT in the Montgomery domain.** The implementation stores
zetas pre-multiplied by `R` (spec §5.1); the zeta-table unit test must undo the Montgomery
factor before comparing against the values below.

Do not hand-transcribe these into source. Generate them with `tools/gen_zetas.cpp` or a
`consteval` function and assert at build time or in a unit test that they match this file
(spec §5.3).

---

## Table 1 — `ζ^BitRev7(i) mod q` for i ∈ {0, ..., 127}

> The following 128 numbers are the values of `ζ^BitRev7(i) mod q` for `i ∈ {0, …, 127}`.
> These numbers are used in **Algorithms 9 and 10**.

```
   1  1729  2580  3289  2642   630  1897   848
1062  1919   193   797  2786  3260   569  1746
 296  2447  1339  1476  3046    56  2240  1333
1426  2094   535  2882  2393  2879  1974   821
 289   331  3253  1756  1197  2304  2277  2055
 650  1977  2513   632  2865    33  1320  1915
2319  1435   807   452  1438  2868  1534  2402
2647  2617  1481   648  2474  3110  1227   910
  17  2761   583  2649  1637   723  2288  1100
1409  2662  3281   233   756  2156  3015  3050
1703  1651  2789  1789  1847   952  1461  2687
 939  2308  2437  2388   733  2337   268   641
1584  2298  2037  3220   375  2549  2090  1645
1063   319  2773   757  2099   561  2466  2594
2804  1092   403  1026  1143  2150  2775   886
1722  1212  1874  1029  2110  2935   885  2154
```

Note `zetas[0] = 1` (since `ζ^0 = 1`) and is **never used** — Algorithm 9 starts at `i = 1`
and Algorithm 10 starts at `i = 127` and counts down to 1.

`zetas[1] = 1729` is the first value actually consumed.

---

## Table 2 — `ζ^(2·BitRev7(i)+1) mod q` for i ∈ {0, ..., 127}

> When implementing **Algorithm 11**, the values `ζ^(2·BitRev7(i)+1) mod q` need to be
> computed. The following array contains these values for `i ∈ {0, …, 127}`:

Printed in the standard in **signed** form, where `-x` denotes `q - x`:

```
  17   -17  2761 -2761   583  -583  2649 -2649
1637 -1637   723  -723  2288 -2288  1100 -1100
1409 -1409  2662 -2662  3281 -3281   233  -233
 756  -756  2156 -2156  3015 -3015  3050 -3050
1703 -1703  1651 -1651  2789 -2789  1789 -1789
1847 -1847   952  -952  1461 -1461  2687 -2687
 939  -939  2308 -2308  2437 -2437  2388 -2388
 733  -733  2337 -2337   268  -268   641  -641
1584 -1584  2298 -2298  2037 -2037  3220 -3220
 375  -375  2549 -2549  2090 -2090  1645 -1645
1063 -1063   319  -319  2773 -2773   757  -757
2099 -2099   561  -561  2466 -2466  2594 -2594
2804 -2804  1092 -1092   403  -403  1026 -1026
1143 -1143  2150 -2150  2775 -2775   886  -886
1722 -1722  1212 -1212  1874 -1874  1029 -1029
2110 -2110  2935 -2935   885  -885  2154 -2154
```

### The sign structure

Entries alternate in sign in **pairs**: `t2[2m+1] = −t2[2m] (mod q)`. This is why
implementations store only 128 values and process `poly_basemul` coordinates two at a
time, flipping the sign of `γ` on the odd coordinate.

`t2[0] = ζ^1 = 17`.

---

## Verification performed in Phase 0

Both tables were checked computationally against `ζ = 17`, `q = 3329`, and a 7-bit
reversal, before being written here:

- Table 1 reproduces `pow(17, bitrev7(i), 3329)` for all 128 entries — **exact match**.
- Table 2's pair structure `t2[i] == (q − t2[i−1]) mod q` holds for every odd `i`.

Related constants, also verified:

| Constant | Value | Check |
|---|---|---|
| `128^-1 mod q` | **3303** | `3303 · 128 mod 3329 = 1` ✓ |
| `R mod q`, `R = 2^16` | **2285** | |
| `R² mod q` | **1353** | |
| `q^-1 mod 2^16` | **62209** (signed: −3327) | `62209 · 3329 mod 65536 = 1` ✓ |

The `q^-1` value must be derived in a `consteval` function and `static_assert`ed, not
hardcoded (spec §5.1). **Use unsigned arithmetic in that function** — signed overflow is
UB and is rejected outright in a constant expression.
