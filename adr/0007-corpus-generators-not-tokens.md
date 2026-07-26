# 0007 — The sealed confirmatory corpus stores generators and seeds, not minted tokens

## Context

`docs/EXPERIMENT_ARCHITECTURE_FINAL.md` Part H step 3 freezes and hashes "the corpus generator
(code + seed that deterministically produces the confirmatory corpus)". Read carelessly, that
step could be taken to seal **pre-minted Biscuit token bytes**. It cannot: Biscuit tokens are
**not byte-reproducible across mints** — the format uses a single-use ephemeral block key per
append, so two mints of the same logical capability differ in bytes
**[VERIFIED, gate G-1 corrective pass]** (the observation was recorded, non-blocking, in
ADR 0003's consequences). This ADR records the Commander's adjudication of what Part H seals.

## Decision

[DESIGN] The sealed confirmatory corpus consists of **scenario specifications plus deterministic
key seeds**; Biscuit tokens are **minted at campaign runtime** from those sealed inputs. Part H
step 3 may not be read as sealing pre-minted token bytes.

**Why determinism is unaffected** [DESIGN]. Every oracle verdict is a function of the authority
set `C_n = Allowed(P_n; Γ, κ, Ω)` and the sealed scenario, **never** of token bytes (§A.0.1,
§F.1, Part I): the predicates read raw evidence, the sealed `IntendedInvocation`, and the
trusted mediation/ledger records, and every capability-state commitment is over
signature-derived BlockIDs, not container bytes. The `INV.capability_hash` binding is computed
over the **presented** token's BlockID commitment at runtime and compared against the
runtime-presented token, so it remains exact (§F.2, ADR 0003). No verdict changes because a
re-mint produced different bytes.

**Why runtime minting is required anyway** [DESIGN]. The per-hop append is the measured
operation: Phase-2 `delegation_cost` is the offline attenuation `P_{i−1} → P_i` (§E.2
two-phase; Part H latency decomposition). Sealing post-append token bytes would leave nothing
to measure — `delegation_cost` would be unmeasurable. Runtime minting is not a concession to
the format; it is what the experiment measures.

**What the seal therefore covers** [DESIGN]: the scenario specifications; the deterministic
key-seed material for every principal; the corpus generator code; and the derivation rule from
seed to keypair. What it does **not** cover: minted token bytes, ephemeral block keys, or any
per-mint randomness.

**Disjointness under the amendment** [DESIGN]. Part H step 5 asserts disjointness on
**scenario-specification and seed content hashes**, not token bytes — token bytes differ
across mints even for the *same* logical scenario, so a byte-level assertion would be
vacuously true and prove nothing. The step stays executable as amended.

**Seed-disclosure warning** [DESIGN]. Publishing the corpus seeds publishes **every private key
derived from them**. The corpus is a **testbed artifact only**; its keys MUST NOT be reused in
any deployment. This warning is a **binding obligation on the corpus generator when it is
written** (Part H step 3 / Part J.3 item 11) — recorded here, in the Part H note, and in
`fixtures/confirmatory/README.md`. The generator itself is **not** written in this pass
(pre-seal red line: `fixtures/confirmatory/` stays README-only).

## Status

accepted — 2026-07-26

## Consequences

- Part H step 3 is amended: the sealed item is the corpus generator plus seeds and scenario
  specifications, never reproducible token bytes. Part H step 5 is amended: disjointness is
  asserted on specification and seed content hashes. A short Part H note carries the
  non-reproducibility fact `[VERIFIED, G-1]` and the seed-disclosure warning. Registered in
  Part B.2. Same commit as this ADR — never silently.
- `fixtures/confirmatory/README.md` carries the seed-disclosure warning (text only; the
  directory stays otherwise empty until Part H step 4).
- No implementation change now: no corpus generator, no key-seed derivation, no minting code
  is written in this pass. The obligation binds the generator when Part J.3 item 11 builds it.
- The Part H "once" rule, abort rules, and unseal rules are untouched; only what the seal
  covers is clarified.
