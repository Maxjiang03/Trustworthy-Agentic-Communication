# 0004 — Build-vs-reuse: fork zero repositories; reuse pinned dependencies only, pinned after their gate passes

## Context

Before the remaining Part G gates run, the project needs a recorded boundary between what is
**reused** (external code entering the dependency set) and what is **built from scratch**
(project-owned constructs), so that no later convenience decision blurs it. The question was
investigated externally and is concluded; this ADR records the outcome — it does not re-open it.
It touches the dependency policy already practised for `biscuit-python` (ADR 0002), the oracle
independence rule (D13/D21, §F.1), and the comparator positioning in Part A.

## Decision

[DESIGN] **Fork zero repositories.** External functionality enters this project only as
**pinned dependencies**, each pinned exactly and only **after its feasibility gate passes**:

| Dependency | Gate | Status |
|---|---|---|
| `biscuit-python==0.4.0` | G-1 | pinned (ADR 0002; commitment scheme corrected by ADR 0003) |
| a JCS canonicalisation library | G-8 | this pass; own library-choice ADR |
| a DPoP/JOSE library | G-5 | this pass; own library-choice ADR |
| an OAuth stack for the AS, if viable | G-4 | gate not yet run; `# PENDING GATE` line stays |
| `a2a-python` (official A2A SDK) | its gate has not yet run | not pinned |
| official MCP Python SDK | G-6/G-7 exercise its mediation surface | not pinned |

[DESIGN] **Build from scratch:** the HTC/INV constructs (§F.2 — project-defined signed objects
layered on Biscuit), the nine-arm orchestration (§E.1 ladder), the independent effect ledger and
oracle (§F.1, Part I), the attack-family fixtures (Part E), and — most likely — a behaviourally
faithful OAuth 2.1 Authorization Server: per the external investigation, **no off-the-shelf
Python AS supports both RFC 8693 down-scoped exchange and RFC 9396 rich authorization requests**
`[UNVERIFIED-IA until G-4 — G-4 confirms or refutes it on the pinned candidate]`.

[DESIGN] **AIP (`github.com/sunilp/aip`) is explicitly not forked.** Reusing its code would
violate oracle independence: the oracle must share no implementation with anything it judges
(D13/D21). AIP's role is exactly two things: (a) the citation anchoring the "measurement, not
novel mechanism" positioning, and (b) a comparator — a feature-matched table, or a P3 comparator
arm — noting that AIP's own paper names "a controlled comparison against a real OAuth 2.1
baseline" as future work, which is precisely this study's contribution.

## Status

accepted — 2026-07-25 (records an already-concluded investigation)

## Consequences

- The **pin-only-after-gate** rule stays binding; the `# PENDING GATE` block in `pyproject.toml`
  is its enforcement point.
- Each future pin gets its **own library-choice ADR** (precedent: ADR 0002).
- This ADR does **not** change the gate DAG order; in particular it does not schedule or
  parallelise G-4.
- Registered in the Part B decision register of `docs/EXPERIMENT_ARCHITECTURE_FINAL.md` in the
  same commit (never silently diverge).
