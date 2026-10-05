# Algorithm 2 — SHAKE128 incremental API, and the XOF wrapper

FIPS 203 §4.1, pp. 19–20. Algorithm 2 (`SHAKE128example`) is an illustrative algorithm
that *defines an equivalence requirement*, not a step of ML-KEM.

## The incremental API

```
ctx ← SHAKE128.Init()
ctx ← SHAKE128.Absorb(ctx, str)          ▷ inject data during the absorbing phase
(ctx, B) ← SHAKE128.Squeeze(ctx, 8·z)    ▷ extract z output BYTES; length given in BITS here
```

## Algorithm 2 — SHAKE128example(str_1..str_m, b_1..b_ℓ)

```
1: ctx ← SHAKE128.Init()
2: for (i ← 1; i ≤ m; i++)
3:     ctx ← SHAKE128.Absorb(ctx, str_i)
4: end for
5: for (j ← 1; j ≤ ℓ; j++)
6:     (ctx, out_j) ← SHAKE128.Squeeze(ctx, 8·b_j)
7: end for
8: output ← out_1 ‖ ... ‖ out_ℓ
```

## The normative equivalence — equation (4.6)

> a single SHAKE128 call of the form
> `output ← SHAKE128(str_1 ‖ ... ‖ str_m, 8b_1 + ... + 8b_ℓ)`
> is equivalent to performing Algorithm 2. **This equivalence holds whether or not `|str_i|`
> and `b_j` are multiples of the SHAKE128 block length.**

This is the property that lets [`SampleNTT`](alg07-sample-ntt.md) squeeze a full 168-byte
Keccak block and chunk it locally instead of squeezing 3 bytes at a time.

Spec §6.3 requires a test for exactly this: squeeze in mismatched chunk sizes (3 bytes at
a time vs. one bulk squeeze) and assert identical output. It catches state-management bugs
at rate boundaries.

## The XOF wrapper

ML-KEM invokes the incremental API only through this wrapper (p. 20):

```
XOF.Init()            = SHAKE128.Init()
XOF.Absorb(ctx, str)  = SHAKE128.Absorb(ctx, str)
XOF.Squeeze(ctx, ℓ)   = SHAKE128.Squeeze(ctx, 8·ℓ)
```

**`XOF.Squeeze` takes its length in BYTES**, the SHAKE128 primitive in bits. This is
consistent with the convention that all wrapper functions measure array lengths in bytes.
Mixing the two up is an 8× length bug.
