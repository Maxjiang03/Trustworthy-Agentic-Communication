# Smoke Gates — Status Board

Feasibility smoke gates per `docs/EXPERIMENT_ARCHITECTURE_FINAL.md` Part G. **No v0.5, no
sealing, no confirmatory corpus until every in-scope gate passes on the pilot corpus.** Each gate
is a minimal runnable spike, not an experiment. A failing gate stops its branch and applies the
gate-outcome policy (fallbacks), recorded as an ADR.

**Execution DAG (respect dependencies):**

```
G-1 / G-5 / G-8  →  G-6 / G-7  →  G-2 / G-4 / G-11  →  G-12 / G-13  →  G-9 / G-14  →  G-10
```

G-3 (latency spike) may run any time after G-1, but its threshold is fixed beforehand
(`docs/frozen_parameters.md` item 2, currently UNSET). Claim-dependent gates (G-3, G-14, G-15,
INV-only check) run only for claims retained in the sealed scope.

Run a gate: `make gate GATE=g1`

| Gate | Depends on | Status | Report | ADR |
|------|-----------|--------|--------|-----|
| G-1 | — | **PASS** — biscuit-python==0.4.0 pinned; G-1.G′ (append-detection) replaced the seal check by author decision | [g1/REPORT.md](g1/REPORT.md) | [0002](../adr/0002-python-biscuit-library.md) |
| G-2 | G-6/G-7 | blocked — requires frozen authorizer Γ and H(Γ) (`docs/frozen_parameters.md` item 8, UNSET) | — | — |
| G-3 | G-1 (threshold fixed beforehand) | not started | — | — |
| G-4 | G-6/G-7 | not started | — | — |
| G-5 | — | not started | — | — |
| G-6 | G-1/G-5/G-8 | not started | — | — |
| G-7 | G-1/G-5/G-8 | not started | — | — |
| G-8 | — | not started | — | — |
| G-9 | G-12/G-13 | not started | — | — |
| G-10 | all prior DAG gates | not started | — | — |
| G-11 | G-6/G-7 | not started | — | — |
| G-12 | G-2/G-4/G-11 | not started | — | — |
| G-13 | G-2/G-4/G-11 | not started | — | — |
| G-14 | G-12/G-13 | not started | — | — |
| G-15 | claim-dependent | not started | — | — |
