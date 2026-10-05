# Montgomery domain convention (ADR-004)

*Moved out of `docs/reference/invariants.md` in the Phase 8 close-out prune (2026-09-28). It is reference
material — a table you look up when writing arithmetic — not a rule, so it does not need to be in context every session.
`docs/reference/invariants.md` links here.*

---

## Montgomery domain convention

*(ADR-004, Phase 2. Accurate as of the arithmetic layer landing. Keep in sync.)*

- `R = 2^16`. `R mod q = 2285`. `R² mod q = 1353`. `q⁻¹ mod 2^16 = 62209`.
- `mont_mul(a, b)` = `a·b·R⁻¹ mod q`.
- `zetas[]` are stored **pre-multiplied into the Montgomery domain**, centered to
  `[-1664, 1664]`.

| Function | In | Out |
|---|---|---|
| `ntt` | normal | **normal** |
| `poly_basemul`, `basemul`, `poly_basemul_acc` | normal × normal | **× R⁻¹** |
| `invntt` | any | **× R** |
| `poly_to_mont` | normal | **× R** |

- `invntt` folds `128⁻¹` with `R²` as one constant, `R²·128⁻¹ mod q = 1441`.
  **Seven layers, so `128⁻¹ = 3303` — not `256⁻¹`.**
- **`invntt(poly_basemul(ntt a, ntt b)) == a·b` exactly.** The `R⁻¹` and `R` cancel.
- **`invntt(ntt(f)) == f·R`, not `f`.** Looks like a bug; is not.
- `poly_tobytes` expects canonical `[0, q)` — `poly_canonicalize` first.

**Derive every constant with `consteval` + `static_assert`. Transcribe nothing**, not from
the spec, not from a reference implementation, not from a human.

**Every function declaration carries its input domain, output domain, and coefficient
bounds as a comment.** No exceptions.

---
