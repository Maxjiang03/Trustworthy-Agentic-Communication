# Architecture Decision Records (ADR)

One file per decision, numbered sequentially: `NNNN-short-slug.md`. Copy
`template.md` to start; its sections are **Context / Decision / Status /
Consequences**.

**Statuses:** `proposed` → `accepted`; a replaced decision becomes
`superseded by NNNN`. Never delete or rewrite a superseded ADR — the trail is
the point.

Rules of the log:

- The authoritative design is `docs/EXPERIMENT_ARCHITECTURE_FINAL.md`
  (ADR 0001). An ADR that changes the design must be accompanied by an update
  to that document — never silently diverge (CLAUDE.md).
- Every Part G gate fallback and every seal-time parameter choice
  (`docs/frozen_parameters.md`) becomes an ADR (design Part J.1 item 4,
  Part J.2 item 9). This is the audit trail against deciding after seeing
  results.
- Commits that encode a decision reference the ADR in the commit body.
- Use the evidence grades [VERIFIED] / [DESIGN] / [UNVERIFIED-IA] on
  load-bearing statements.
