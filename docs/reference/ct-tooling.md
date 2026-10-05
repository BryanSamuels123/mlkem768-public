# What the constant-time tools can and cannot enforce (ADR-016)

*Moved out of `docs/reference/invariants.md` in the Phase 8 close-out prune (2026-09-28). It is reference
material — a capability matrix you consult when choosing a gate — not a rule, so it does not need to be in context every session.
`docs/reference/invariants.md` links here.*

---

### What the tools can and cannot enforce (ADR-016, measured)

**Three tools, three different blind spots. None is sufficient alone.**

| Tool | Catches | Blind to |
|---|---|---|
| `gmake docker-ctgrind` | secret memory indices, secret loop bounds, early-exit compares (so a `memcmp` in decaps **is** caught) | `div`/`mod` (models values, not timing); a plain `if (secret & 1)` at `-O3` |
| `gmake audit-div` (ADR-018) | **every `div`/`idiv` in the library**, at the machine level, including ones the compiler inserts that appear nowhere in the source | anything that is not a division |
| dudect (Phase 9) | microarchitectural timing variation | needs statistical power; noisy |

So the `div`/`mod` ban **is** machine-enforced by `audit-div` — but only for the
instruction, not for whether a given divisor is secret. Raising an `audit-div` allowance
requires tracing the divisor in the disassembly and a justification row in
`docs/bounds.md`.

A plain `if (secret & 1)` at `-O3` is flattened by clang into a branchless select, so
ctgrind sees no jump. Benign *there*, but **never rely on the optimizer for constant-time
behaviour** — a different optimization level may emit the branch. Write it branchless.

---
