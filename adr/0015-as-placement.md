# 0015 — The experiment AS lives in `src/sut/oauth_as/`, out-of-process, and the harness may never import it

## Context

Gate G-4 Phase 1 (`smoke/g4/DESIGN.md`) specifies the pinned experiment authorization server that
Phase 2 builds. The repository has two homes — `src/sut/` (the measured system) and
`src/harness/` (the instrument) — and the AS sits comfortably in neither:

- Its **round-trip cost is inside the measured quantity**: B2 arms perform an online exchange at
  each hop and that latency *is* `delegation_cost` (§E.2). A component whose cost is measured is
  not an instrument.
- Yet the instrument **must not issue the credentials it later adjudicates**. The harness holds
  the independent oracle and the G-13 verifier that recomputes `Allowed(AT_i)`, and D13/D21
  require that the oracle share no implementation with anything it judges.

The layout rule already in force is asymmetric: `src/sut/` must never import `src/harness/`, and
the harness *may* import `sut` (`README.md` §Layout; PROJECT_RULES.md red line 6). That asymmetry is what
makes the placement question sharp — a harness-side verifier could import an AS that lives under
either tree unless a rule forbids it.

## Decision

[DESIGN] The AS is a **subpackage of the measured system**: **`src/sut/oauth_as/`**.
(`as` is a Python keyword and cannot be a package name; `oauth_as` is the importable spelling.)

Four rules travel with it, and Phase 2 implements and tests all four:

1. **Out-of-process.** The AS runs as its own OS process, listening on the loopback interface
   only. No agent process ever hosts it in-process.
2. **Key isolation.** The signing key is generated inside the AS process from a sealed seed
   (ADR 0007's seed→key derivation), never written to disk and never present in any agent
   process. The harness and the boundary hold the **public** key, delivered from sealed
   configuration — never fetched, since the profile publishes no discovery document
   (`DESIGN.md` §5.1).
3. **No agent may import it.** Modules under `src/sut/` other than `src/sut/oauth_as/` MUST NOT
   import `src/sut/oauth_as/`; agents reach the AS only over the wire. Without this, a baseline
   agent could mint the very tokens the baseline is supposed to constrain.
4. **The harness may never import it.** `src/harness/` MUST NOT import `src/sut/oauth_as/`,
   notwithstanding the general permission for the harness to import `sut`. The G-13 verifier and
   the oracle **reimplement** token verification independently (D13/D21, D21's independence
   discipline as applied to `H_JCS` in ADR 0009).

Rules 3 and 4 are import-level rules with a runtime complement: Phase 2 demonstrates that an
SUT-side attempt to mint an `AT` fails. That demonstration is **additional evidence beyond G-4's
pass criteria**, explicitly not a criterion change (ADR 0008).

## Rejected alternatives

- **`src/harness/oauth_as/` (the AS as instrument).** Rejected on two independent grounds. The
  instrument would mint the credentials the instrument later adjudicates, putting the issuer and
  the G-13 verifier in the same tree, where shared implementation is one import away — the
  precise circularity D13/D21 forbid. And it would place a component whose latency is inside the
  measured estimand into the tree defined as *not* measured, a category error the dissertation
  would have to defend at exactly the point where the fair-baseline claim is weakest.
- **A third top-level home (`src/services/`).** Attractive in naming — the AS genuinely is a
  counterparty service rather than an agent — but it buys no isolation the rules above do not
  already buy: a directory does not prevent an import, a stated and tested rule does. It would
  amend the project's two-home layout for a single tenant (the MCP tool host is already
  harness-instrumented at G-6/G-7 and is not a second tenant). Recorded as rejected on cost, not
  on principle; if a second true counterparty service appears, this decision is worth revisiting.

## Consequences

- `README.md` §Layout and PROJECT_RULES.md §Layout are amended in the **same commit** as this ADR to
  name `src/sut/oauth_as/` and carry rules 3 and 4. PROJECT_RULES.md red line 6 is **unchanged**; this
  ADR adds a constraint in its family, it does not edit the red-line list.
- Placing the AS in the measured tree also states the evidential status of its output correctly:
  an `AT` is **SUT-produced evidence the oracle recomputes over**, never a value the oracle
  trusts (PROJECT_RULES.md red line 4, §F.1).
- Phase 2 adds an import-boundary test for rules 3 and 4 alongside the runtime forge test (A4 in
  `DESIGN.md` §10).
- No directory is created in this pass: Phase 1 writes **no AS code**, not even a skeleton.
  *(Update, 2026-07-29: **Phase 2 created it and all four rules were implemented and tested.** The AS
  runs out-of-process on loopback with TLS 1.3; the Ed25519 signing key is derived in-process from the
  sealed seed, never written to disk, and only the public JWK leaves; both import rules were asserted
  programmatically — `src/harness/` and every non-`oauth_as` `src/sut/` module import it **zero**
  times — and a separate agent process started **without** the seed had its forged token rejected by
  the boundary. One honest limit is recorded in `smoke/g4/REPORT.md` §3: isolation rests on the key
  never leaving the process **and** the runner giving the seed to no agent process, since a principal
  holding the seed can derive the key by construction. ADR 0017 records the profile as built.)*
- Registered in Part B.2 of `docs/EXPERIMENT_ARCHITECTURE_FINAL.md`, same commit.

## Status

accepted — 2026-07-27
