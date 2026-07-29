# 0002 — Python Biscuit library: adopt biscuit-python 0.4.0; replace G-1.G with G-1.G′; this design never seals

## Context

Gate G-1 (`docs/EXPERIMENT_ARCHITECTURE_FINAL.md` Part G; expanded criteria in
`SMOKE_G1_TASK.md`) tested IA-1. Candidates on PyPI: only **`biscuit-python`** is viable — the
official PyO3 bindings over `biscuit-rust` 6.0.0, an Eclipse Foundation project
(`eclipse-biscuit/biscuit-python`, formerly biscuit-auth org), actively maintained (repo pushed
2026-07-14), typed (`py.typed` + `.pyi`), with prebuilt wheels for CPython 3.9–3.13 on
manylinux/musllinux/macOS/Windows, so **no Rust toolchain** is needed locally, in CI, or in
Docker. `biscuit-auth` and `pybiscuit` do not exist on PyPI; `biscuit` is an unrelated dead
project. Full evidence: `smoke/g1/REPORT.md`.

Five of six mandatory checks passed on the first run (mint; offline append with the root secret
structurally out of scope; verification with `κ_pub` alone; byte-identical wire round-trip; and
the make-or-break G-1.F stable prefix identity). **G-1.G (seal terminality) was unexecutable**:
the binding exposes no seal API (absent from the runtime surface, upstream `src/lib.rs`, and the
`.pyi` stubs; no upstream issue requests it). The gate was reported FAIL and stopped for the
author's decision, per the task's gate-outcome rules.

## Decision

[DESIGN] **Adopt `biscuit-python==0.4.0`, pinned exactly**, in `[project].dependencies`.

[DESIGN] **Replace criterion G-1.G (seal terminality) with G-1.G′ (append-detection).** Sealing,
in Biscuit, exists to stop further delegation. In this design that function is already performed
by two project-owned mechanisms, so seal is redundant:

1. **Further attenuation is harmless** — attenuation is monotone (`C_i ⊆ C_{i−1}`, §A.6.1): any
   party appending a block can only narrow authority, never escalate it.
2. **Further delegation is governed by the HTC chain, not by seal** — adding a hop requires a new
   `HTC_i` signed by the **current holder's identity key** (§F.2). An attacker without that key
   cannot produce one; a compromised holder gains nothing by narrowing authority it already
   holds.
3. **A block appended after the terminal hop is rejected by the INV binding** —
   `INV.capability_hash = H(P_n)` (§F.2); the verifier recomputes `H(P_{n+1}) ≠ H(P_n)` and
   refuses the request.

[DESIGN] **This design never seals.** What the design depends on is the pair proved by the gate:
*prefix-stable* (G-1.F: `H(P_0)` unchanged after append, so HTC parent bindings survive a
legitimate append) and *terminal-sensitive* (G-1.G′: `H(P_n) ≠ H(P_{n+1})`, so
`INV.capability_hash` detects an illegitimate post-hoc append). Both hold; the re-run passes all
six mandatory checks (exit 0).

**Rejected fallbacks:**

- *Rust FFI (PyO3/maturin or subprocess bridge)* — **rejected as disproportionate**: it would put
  a Rust toolchain into CI and Docker to preserve a property (seal) this design does not use.
- *Macaroon-style caveat chain (symmetric HMAC)* — **strongly rejected**: it would surrender
  root-**public**-key verification (a real, load-bearing property, §A.6.1/§F.2) to close a gap
  that is not a gap.

Post-gate capability statuses (valid for exactly what ran): mint, offline append, `κ_pub`-only
verification, wire round-trip, stable prefix identity per §A.0.1 (verbatim — no hashing-rule
refinement needed), and append-detection — **verified by gate G-1** for `biscuit-python==0.4.0`.
Monotonicity under a frozen `Γ` (IA-2) and performance (IA-3) remain **[UNVERIFIED-IA]**, gated
by G-2 and G-3. *(Update, 2026-07-29: IA-2 is now **verified by gate G-2** for this same pin,
under the `Ω`/`Γ` frozen by ADR 0016 — `smoke/g2/REPORT.md`. IA-3 is still [UNVERIFIED-IA], gated
by G-3. The sentence above stands as the state at the time of this ADR.)*

## Status

accepted — 2026-07-14 (supersedes the "proposed" version of this ADR recorded at commit
`dca755b`)

**Partially superseded by [0003](0003-capability-commitment-scheme.md) — on the commitment
scheme only.** The `H(P_i)` definition below (hash over raw container bytes, fields 2 + 3) was
found unsound: protobuf is not a canonical encoding. ADR 0003 replaces it with a commitment over
signature-derived `BlockID_i`. **The library selection (`biscuit-python==0.4.0`) and the seal
decision (G-1.G′; this design never seals) stand unchanged.**

## Consequences

- **The pin is exact; any version bump of `biscuit-python` re-triggers G-1.**
- `H(P_i)` is computed by parsing the Biscuit **wire format** (container fields 2 + 3, excluding
  the mutable proof field 4, `[VERIFIED against schema.proto]`), so it depends on the versioned
  format specification rather than the 0.x Python API. A **format** version change would require
  re-verification.
- The Biscuit format has had informal cryptographic review but is **not formally audited**
  (project FAQ) — a disclosed limitation of the study, not a blocker for a measurement
  contribution.
- The availability residual (an in-path adversary can append a block and force a *rejection*,
  never an escalation) is recorded in `docs/threat_model.md`; sealing would not close it.
- Architecture-document edits applied with this decision (same-day commits, never silent):
  D22 note (Part B.2), Part G G-1 row (criterion = F + G′), §F.4 IA-1 status, §F.2 HTC-count
  conjunct (fail-fast defence in depth).
- An upstream `seal()` PyO3 wrapper is an open, **non-blocking** contribution opportunity —
  deliberately not pursued now (off the critical path).
- The capability track (B-cap, B3, B3⁺) is unblocked; next gates in the DAG batch: G-5 (DPoP)
  and G-8 (JCS canonicalisation), each with its own task file.
