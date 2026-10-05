# Extracted FIPS 203 algorithms

Extracted once, in Phase 0, from FIPS 203 itself (the **final**
standard, published 2024-08-13 — not the initial public draft).

**Read these notes. Do not re-read the standard** (see `docs/reference/invariants.md`, *The normative reference*). If a note is
wrong or incomplete, fix the note and log the correction in the "Spec corrections" table
of `DECISIONS.md` — in the same commit.

Pseudocode is transcribed verbatim from the standard, with the PDF's mangled subscripts
and superscripts reconstructed into plain ASCII. Line numbers match the standard's own
numbering so a citation like "Alg. 13 line 5" resolves here.

## Notation used in these notes

| Symbol | Meaning |
|---|---|
| `⌈x⌉` / `⌊x⌋` | ceiling / floor |
| `⌈x⌋` | round to nearest integer, **ties round up**: `⌈y + 1/2⌋ = y + 1` (§2.3) |
| `r mod m` | the unique `r'` in `{0..m-1}` with `m \| (r - r')` — always non-negative |
| `BitRev7(r)` | bit reversal of a 7-bit integer |
| `𝔹ᵏ` | byte array of length k |
| `ℤ_m^256` | array of 256 integers mod m |
| `∥` | concatenation |

## Index

| File | Algorithm | Phase |
|---|---|---|
| `alg02-xof-incremental.md` | SHAKE128 incremental API + XOF wrapper | 3 |
| `alg03-bits-to-bytes.md` | BitsToBytes | 4 |
| `alg04-bytes-to-bits.md` | BytesToBits | 4 |
| `alg05-byte-encode.md` | ByteEncode_d | 4 |
| `alg06-byte-decode.md` | ByteDecode_d | 4 |
| `compress-decompress.md` | Compress_d / Decompress_d (§4.2.1, not numbered) | 4 |
| `alg07-sample-ntt.md` | SampleNTT | 5 |
| `alg08-sample-poly-cbd.md` | SamplePolyCBD_eta | 5 |
| `alg09-ntt.md` | NTT | 2 |
| `alg10-inv-ntt.md` | NTT^-1 | 2 |
| `alg11-multiply-ntts.md` | MultiplyNTTs | 2 |
| `alg12-base-case-multiply.md` | BaseCaseMultiply | 2 |
| `alg13-kpke-keygen.md` | K-PKE.KeyGen | 6 |
| `alg14-kpke-encrypt.md` | K-PKE.Encrypt | 6 |
| `alg15-kpke-decrypt.md` | K-PKE.Decrypt | 6 |
| `alg16-keygen-internal.md` | ML-KEM.KeyGen_internal | 6 |
| `alg17-encaps-internal.md` | ML-KEM.Encaps_internal | 6 |
| `alg18-decaps-internal.md` | ML-KEM.Decaps_internal | 6 |
| `alg19-keygen.md` | ML-KEM.KeyGen | 6 |
| `alg20-encaps.md` | ML-KEM.Encaps (+ §7.2 input checks) | 6 |
| `alg21-decaps.md` | ML-KEM.Decaps (+ §7.3 input checks) | 6 |
| `appendixA-zetas.md` | Both zeta tables | 2 |
| `appendixB-sample-ntt-bounds.md` | SampleNTT while-loop bound | 5 |
| `appendixC-kyber-differences.md` | Differences from round-3 Kyber | all |
| `params-and-conventions.md` | Parameters, hash functions, §3.3 requirements | all |

Algorithm 1 (`ForExample`) is a documentation-formatting example in §3 and has no
cryptographic content. It is not extracted.
