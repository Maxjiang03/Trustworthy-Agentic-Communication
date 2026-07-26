# 0008 — The G-4 AS construction spike may start early; its adjudication does not move

## Context

Gate G-4 (`docs/EXPERIMENT_ARCHITECTURE_FINAL.md` Part G) tests IA-4 — the OAuth stack supports
RFC 8693 exchange narrowing to `C_i` plus RFC 9396 `authorization_details`, or a behaviourally
faithful AS can be built (§F.4). The concluded external investigation found **no off-the-shelf
Python AS supporting both** RFC 8693 down-scoped exchange and RFC 9396 `authorization_details`
`[DESIGN, ADR 0004]`, so a behaviourally faithful AS most likely has to be built — making G-4
the schedule's **long pole**. The DAG places G-4 after G-6/G-7
(`G-1 / G-5 / G-8 → G-6 / G-7 → G-2 / G-4 / G-11 → …`); waiting for G-6/G-7 before touching any
AS code would serialize the longest work item behind gates it does not depend on for
*construction* (only for *adjudication*: G-6/G-7 are the construct-validity pair that must hold
before any gate whose results feed comparative claims is judged).

## Decision

[DESIGN] Split **spike start** from **gate adjudication**:

- The **G-4 construction spike** (building the behaviourally faithful OAuth 2.1 AS profile:
  RFC 8693 down-scoped exchange, RFC 9396 `authorization_details`, `cnf`/`jkt` issuance) is
  **authorised to start now**, ahead of G-6/G-7 and in parallel with them.
- The **G-4 PASS adjudication remains exactly where the DAG puts it** — after G-6/G-7 — with
  its pass criteria unchanged: task-narrowed token issues; OAuth-resource ∩ capability
  effective authority enforced; `actor→holder` mapping resolves; `INV.access_token_hash`
  verified (Part G, G.3).

Constraints that do not change:

- **No pass criterion, dependency edge, or evidence grade changes.** IA-4 stays
  `[UNVERIFIED-IA]` until G-4 adjudicates; spike progress is not evidence.
- **Nothing may be pinned on spike progress alone.** The `authlib (RFC 8693 + RFC 9396) →
  gate G-4` line stays in the `# PENDING GATE` block of `pyproject.toml` until G-4 adjudicates
  (ADR 0004 discipline: a pin never precedes its gate).
- **The spike inherits the two items G-5 handed forward**, both still `[UNVERIFIED-IA]`:
  `ath` — REQUIRED when a DPoP proof accompanies an access token to a protected resource
  **[VERIFIED, RFC 9449 §4.2]**, not exercised by G-5's simulated issuance — and DPoP
  **nonce** handling (RFC 9449 §§8–9). Both are re-exercised in the real AS/RS flow this
  spike builds (ADR 0006, smoke/g5/REPORT.md §8).

**Schedule rationale** [DESIGN]: the dissertation submits **11 September 2026**. Starting the
long-pole construction now, while G-6/G-7 run, is the only ordering that leaves room for the
G-4 fallback (build the faithful AS — ADR 0004) without compressing the sealed campaign; it
changes when work *starts*, never what *counts as passing*.

## Status

accepted — 2026-07-26

## Consequences

- The smoke board G-4 row records "construction spike authorised to start" while keeping its
  `G-6/G-7` dependency for adjudication (same commit). No other row changes; the DAG is
  otherwise unaltered.
- If G-6 or G-7 fails, the gate-outcome policy applies unchanged (re-architect interposition,
  highest priority); spike work already done is kept but cannot be adjudicated until the
  construct-validity pair passes.
- The spike produces no pin, no §F.4 status change, and no smoke-board PASS on its own; those
  happen only at G-4 adjudication.
- Registered in Part B.2.
