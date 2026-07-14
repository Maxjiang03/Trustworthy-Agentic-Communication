# 0001 — Record architecture decisions

## Context

This project is a pre-registered measurement study whose credibility rests on
an auditable trail: decisions must be datable and reviewable, and none may be
made silently after seeing results. The consolidated design document carries
its own internal decision log (D1–D40, Part B), but repository-level choices —
library selections at the Part G gates, gate-outcome fallbacks, seal-time
parameter values — need per-decision records of their own.

## Decision

[DESIGN] We keep Architecture Decision Records in `adr/`, one file per
decision, following `template.md` (Context / Decision / Status /
Consequences).

[DESIGN] `docs/EXPERIMENT_ARCHITECTURE_FINAL.md` is the authoritative single
source of truth for the experiment design. Any change to the design is
recorded as an ADR here **and** reflected in that document; the two must not
diverge.

## Status

accepted — 2026-07-14

## Consequences

- Every Part G gate outcome that triggers a fallback (gate-outcome policy) is
  recorded as an ADR before work continues on that branch.
- Every seal-time parameter value (`docs/frozen_parameters.md`) is fixed via
  an ADR before Part H step 3.
- Commits that encode a decision reference their ADR in the commit body.
