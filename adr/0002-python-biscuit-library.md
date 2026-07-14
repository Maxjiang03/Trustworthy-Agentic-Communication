# 0002 — Python Biscuit library (gate G-1)

## Context

Gate G-1 (`docs/EXPERIMENT_ARCHITECTURE_FINAL.md` Part G; expanded criteria in
`SMOKE_G1_TASK.md`) tests IA-1: whether a Python Biscuit library exists that supports the
capability track (mint, offline append, root-public-key verification, stable §A.0.1 prefix
identity, terminal seal). Full evidence: `smoke/g1/REPORT.md`.

Candidates evaluated (PyPI JSON API, GitHub API, upstream source, runtime introspection):

- **`biscuit-python` 0.4.0** — the official binding of the Rust reference implementation
  (eclipse-biscuit org, formerly biscuit-auth; wraps biscuit-rust 6.0.0). Actively maintained
  (repo pushed 2026-07-14), typed, full pre-built wheel coverage (no Rust toolchain needed).
- `biscuit-auth`, `pybiscuit` — do not exist on PyPI. `biscuit` — unrelated dead project.
- No other Python implementation found.

## Decision

**No adoption decision is taken here — the gate FAILED and the choice rests with the author.**
This ADR records the evidence and the options.

Post-gate status of each tested capability (valid for exactly what ran, nothing more):

- [VERIFIED by gate G-1] mint `P_0`; **offline** append `P_{i−1} → P_i` (no root secret in
  scope, enforced structurally in the spike); verification with **only** `κ_pub`
  (`crypto_chain_ok`, §A.6.1), wrong key rejected with `BiscuitValidationError`; wire round-trip
  (byte-identical re-serialization).
- [VERIFIED by gate G-1] **stable prefix identity** (G-1.F): the §A.0.1 hashing rule is
  implementable **verbatim** — the canonical `SignedBlock_i` bytes are container protobuf fields
  2/3 of `to_bytes()` and the mutable proof tail is field 4 ([VERIFIED against the biscuit
  format `schema.proto`]); `id(P_0)` is append-invariant and signer/verifier agree on `id(P_1)`.
  Corroborated by the library's `revocation_ids` (prefix-stable per-block identifiers). **No
  refinement of the §A.0.1 hashing rule is needed.**
- [FAILED — NOT EXPOSED] **seal** (G-1.G): biscuit-python 0.4.0 exposes no seal API (absent
  from every class at runtime, from upstream `src/lib.rs`, and from `biscuit_auth.pyi`; no
  upstream issue requests it). biscuit-rust implements sealing, but it is not callable from
  Python, so "seal, then append must fail" (D22 terminality) cannot be exercised.
- [UNVERIFIED-IA, unchanged] IA-1 as a whole; monotonicity under a frozen `Γ` (IA-2, gate G-2);
  performance (IA-3, gate G-3).

Options for the author, in the order the evidence supports:

1. **[proposed] Accept the narrow gap and refine the G-1.G criterion.** Analysis (from the
   architecture document, not a new design): no Part C/E baseline flow *executes* seal; INV
   already binds `capability_hash = H(P_n)`, so a post-INV append changes the terminal prefix
   hash and the INV binding rejects it at the boundary — seal is defence-in-depth in transit,
   not load-bearing for any hypothesis. Consequence if chosen: adopt `biscuit-python==0.4.0`,
   pin it, update the Part G G-1 row (criterion notes seal-not-exposed with the residual
   documented) and the §F.4/D22 wording ("seals only terminally" stays [VERIFIED] for the
   Biscuit design; the binding cannot exercise it), and record the residual in the threat
   model's assumptions. Optionally also file/contribute the ~small upstream PyO3 `seal()`
   wrapper and revisit on the next release.
2. **Fallback: Rust `biscuit-auth` via FFI (PyO3/maturin) or subprocess bridge.** Preserves
   every property including seal. Cost: Rust toolchain in dev/CI/Docker, build complexity,
   slower iteration.
3. **Fallback: Macaroon-style caveat chain (symmetric HMAC).** **Loses the root-public-key
   verification property** (§F.2, §A.6.1): the verifier must hold the root secret. §C and the
   trust model would need rewriting. Disproportionate to a missing-seal gap; listed because the
   Part G gate-outcome policy names it.

Per SMOKE_G1_TASK STEP 6/8 (FAIL branch): no fallback implemented, no `pyproject.toml` pin, no
architecture-document edit. The `# PENDING GATE` block is unchanged.

## Status

proposed — 2026-07-14 (gate outcome FAIL recorded; adoption/fallback decision pending the
author; supersede or accept via a follow-up entry once decided)

## Consequences

- The capability track (B-cap, B3, B3⁺) stays blocked until the author decides among the
  options above; G-6/G-7 (next DAG tier) are independent of this decision and could proceed.
- Whichever option is chosen updates: Part G G-1 row, §F.4 IA-1 status, and (options 2/3) §C,
  the threat model, Dockerfile/CI — in the same commit as this ADR's acceptance, never
  silently (CLAUDE.md).
- The G-1.F result stands on its own: `H(P_i)` per §A.0.1 is implementable without any rule
  change, whichever Biscuit substrate is chosen (it is a property of the wire format, verified
  against `schema.proto`).
