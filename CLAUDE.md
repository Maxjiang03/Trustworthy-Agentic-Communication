# CLAUDE.md — Project Overview & Working Rules

## What this is
Trustworthy Agentic Communication: a pre-registered, reproducible testbed that measures authorization-scope propagation and its cost at the A2A→MCP boundary (the cross-protocol confused-deputy problem, TV23). MSc Cybersecurity dissertation, University of Glasgow.

## Authoritative design
`docs/EXPERIMENT_ARCHITECTURE_FINAL.md` is the SINGLE source of truth (baselines, capability/HTC/INV, oracle, smoke-gate DAG, freeze/seal loop, workflow). Do not contradict it. If a change is needed, record an ADR in `adr/` and update the doc — never silently diverge.

## Current phase
Experimental apparatus, pilot corpus only. **Eleven smoke gates pass** (`smoke/README.md`); the
golden thread runs end to end — Supervisor → A2A hop (behind a port, ADR 0020) → Specialist → MCP
tool call over the frozen `Ω`. All nine §E.1 ladder arms are built. Since 2026-08-01 the study
**scores four of the five §E.3 families**: F1 (three subcases), three F2 subfamilies, **F3** (the
expired-token and captured-proof-replay rows, over all nine arms), and **F4/F5** (four labelled
fixtures — two attacks and two benign controls — over all nine arms under **both** monitor
configurations). **ADR 0030 closed ADR 0009's last category (c) fields**, so `payload_digest`,
`authz_context_hash` and `label_assertions_digest` have constructions and the boundary-owned
`ContextApprovalMonitor` verifies all three artifact types. **Gate G-15 PASSES**, and its residual
is a *result*, not a limitation: with the shared monitor F4/F5 measure the **monitor**, not the
mechanism — and without one, `B3`/`B3⁺` refuse the benign controls too, so the capability policy
plane is useful **only when a monitor is configured**. Two §E.4 drafting errors on `B-cap` were
adjudicated into **ADR 0031** (`NA → B` on the F3 OAuth controls) and **ADR 0032** (`A† → A` on
F4/F5); both corrected **predictions**, never code. The pilot corpus now carries **two authority
chains** — F4/F5 run on one where their actions are inside `C_1`, or `containment_ok` would mask
the policy conjuncts. **9 of 11 `frozen_parameters` rows are set**; row 5 is deferred by decision
(ADR 0028) and only row 9 remains, read off the measurement box at seal time. Gates G-3, G-9, G-10,
G-12, G-14 remain; `IA-3` and `IA-9` are both untouched. Pre-registration still a stub;
`fixtures/confirmatory/` still empty; **no timing number has been measured or reported anywhere**.
Rows 1 and 2 being SET does **not** authorize measurement: G-3 owns timing and ADR 0025 requires an
adjudicative run on the row 9 sealed platform, which is not yet locked.
*(Update notes, each true when written and superseded by the next: (1) "Repository skeleton,
pre-smoke-test. Implementation logic has NOT begun" — 2026-07-30; (2) "under `B0` and `B3` (the
other seven arms are not built)"; (3) "four arms are built", G-13's two limbs open, rows 1–2 UNSET;
(4) "Nine smoke gates pass … F3, F4 and F5 cannot be scored at all, because `authz_context_hash`
has been ADR 0009 category (c) since the beginning" — superseded by the ADR 0030 / G-15 pass,
2026-08-01.)*

## Pre-registration status
Not yet authored. Per Part H, the pre-registration is written and sealed only AFTER the smoke gates pass, and is derived from the architecture doc. `docs/PRE_REGISTRATION.md` is a stub. Any earlier draft is superseded and must not be reused.

## Evidence grades (use these tags in code comments, docs, ADRs, commit bodies)
- [VERIFIED]      — checked against a primary source (RFC / protocol spec / Biscuit spec or FAQ).
- [DESIGN]        — a project decision; internally consistent, not externally mandated.
- [UNVERIFIED-IA] — a property a library/environment must have, not yet confirmed in code. NEVER state one as fact; each is gated by a smoke test (design Part F.4 / Part G).

## Red lines (do not cross without an explicit instruction from the author)
1. Do NOT create or populate `fixtures/confirmatory/` before sealing (Part H). It stays empty.
2. Do NOT run a confirmatory campaign, seal, or generate v0.5 until every in-scope smoke gate passes on the pilot corpus.
3. Gates G-2, G-6, G-7 are construct-validity life-or-death (Biscuit monotonicity under the frozen authorizer Γ; complete mediation; independent effect ledger). If any fails, STOP and apply the gate-outcome fallback; do not proceed on that branch.
4. The oracle NEVER reads a SUT-computed verdict or digest; it recomputes from raw evidence + sealed truth + the external effect ledger.
5. `τ_gt` is oracle-only; no system-under-test principal may read it.
6. `src/sut/` must never import from `src/harness/`. The dependency is one-way.
7. Never `git push --force`; never rewrite remote history.
8. No credentials, tokens, or secrets in the repo or in code. If a push needs auth you cannot access, STOP and ask the author.

## Layout
`src/sut/` measured system · `src/harness/` instrument · `docs/` design + threat model + frozen parameters · `adr/` one file per decision · `fixtures/pilot` vs `fixtures/confirmatory` strictly disjoint.

`src/sut/oauth_as/` (ADR 0015) is the pinned experiment OAuth 2.1 AS — built at G-4 Phase 2, run out-of-process on loopback, signing key never in an agent process. Two import rules travel with it: no other `src/sut/` module may import it (agents reach it over the wire), and **`src/harness/` may never import it**, notwithstanding the harness's general permission to import `sut` — the oracle and the G-13 verifier reimplement token verification independently (D13/D21). Red line 6 is unchanged.

## Commit convention (Conventional Commits)
`type: summary`, type ∈ {feat, fix, docs, test, build, ci, chore, refactor}. Logically scoped commits (not one giant commit, not one per file). Reference an ADR in the body when a commit encodes a decision. Run `make lint` and `make test` before committing. Push to `origin main` after a coherent unit of work. Never force-push.

## Setup
`make setup` (uv sync) · `make lint` (pre-commit) · `make test` (pytest). Python 3.11+. Determinism: fixed `PYTHONHASHSEED`, single seed source, Ed25519 for signing, RFC 8785 JCS for digests.
