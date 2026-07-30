# 0021 — Phase-1 provisioning happens inside the AS process, on the start-up line

## Context

`B3` runs `oauth_authn = 1` (§E.5) and layers on OAuth rather than replacing it (§A.4, D28), so
every agent needs a Phase-1 base `AT@aud` before any Phase-2 delegation. §E.2 defines Phase 1 as
the **setup** phase: identical across all agents and arms, measured separately as `setup_cost`,
and **excluded from the delegation estimand** — the quantity the arms are compared on is
Phase-2 `delegation_cost` (B2's online exchange vs B3/B-cap's offline attenuation). §E.2
explicitly permits "a pre-issued fixture token" as the Phase-1 path.

`exchange.issue_initial` is exactly that pre-issued path, and it is boxed in twice by existing
decisions: it is deliberately **not reachable from the token endpoint** (the AS serves
`POST /token` and nothing else — the G-4-adjudicated surface, `smoke/g4/DESIGN.md` §5.1), and
**no non-AS module may import it** (ADR 0015 rule 3). The only lawful call site is therefore
inside the AS process itself.

## Decision

[DESIGN] `python -m src.sut.oauth_as <config.json>` mints **one Phase-1 base token per
registered client at start-up** — via `issue_initial`, inside the AS process, where the signing
key already lives — and emits them on the **existing start-up JSON line**, alongside the port,
public JWK, and TLS certificate.

Rules that travel with this:

1. **Coverage is exact, fail-closed.** A `phase1` section, when present, must cover exactly the
   registered client set; a missing or extra client refuses start-up. When absent (pre-EXP1
   documents, e.g. gate G-4's), nothing is minted — the mapping is empty and prior behaviour is
   unchanged.
2. **Tokens are runtime-only.** The start-up line's port/JWK/certificate remain public by
   construction; the Phase-1 tokens are **not** — the stdout pipe is held by the spawning
   runner alone (ADR 0015 rule 1), and the tokens are never written to disk, never committed,
   and never echoed into `results/` (CLAUDE.md red line 8). The `__main__` docstring records
   that the line now carries bearer-sensitive material.
3. **Phase 1 stays identical across arms and outside the delegation estimand** (§E.2): every
   registered client receives its base token through this same path before agents act, whatever
   arm runs, so no arm's Phase-2 measurement includes provisioning work and no arm is
   provisioned differently from another. The timing seam for `setup` (EXP1 STEP 14) brackets
   this path; nothing here is measured in this pass (forbidden action 4).

### Rejected alternative: a new HTTP provisioning endpoint

Rejected on three grounds. **(a)** The AS surface `POST /token` — and nothing else — is what
gate G-4 adjudicated; adding an endpoint after the gate would grow the adjudicated surface
without a gate re-run, exactly the silent-drift pattern the gate discipline exists to prevent.
**(b)** A wire-reachable minting endpoint would let any client with loopback access request
arbitrary base tokens, turning the §E.2 *pre-issued* path into an online issuance path and
weakening the key-isolation story ADR 0015 rule 2 states (the runner gives the seed to the AS
process alone; issuance authority stays with the runner-spawned process, not with whoever can
reach a port). **(c)** It would add a second code path whose behaviour (auth, errors, DPoP?)
would all need specification and tests for no experimental gain — Phase 1 is explicitly not the
measured quantity.

## Status

accepted — 2026-07-30

## Consequences

- `src/sut/oauth_as/__main__.py` gains `mint_phase1_tokens` and emits `phase1_tokens` on the
  start-up line; the AS config document gains an optional `phase1` section
  (`client_id → {subject, audience, scope, authorization_details, lifetime_seconds?}`).
- The B3 arm's provisioning consumes these tokens from the runner (which holds the pipe); the
  MCP boundary's OAuth limb verifies them with `src/sut/authz/boundary.py` **unchanged** —
  `verify_access_token`, `allowed_authority`, `admits` are reused, not reimplemented and not
  extended (EXP1 STEP 11).
- Regression tests cover: exact-coverage fail-closed, absent-section compatibility, and that a
  spawned AS emits verifiable tokens that the boundary accepts.
- Registered in Part B.2 of `docs/EXPERIMENT_ARCHITECTURE_FINAL.md`, same commit.
