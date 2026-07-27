# TrustworthyAgent

Trustworthy Agentic Communication: a pre-registered, reproducible testbed that measures
authorization-scope propagation and its cost at the A2A→MCP boundary (the cross-protocol
confused-deputy problem, TV23). MSc Cybersecurity dissertation, University of Glasgow.

## Current phase

**Repository skeleton — pre-smoke-test.** Implementation logic has not begun. The next phase is
the feasibility smoke gates (`docs/EXPERIMENT_ARCHITECTURE_FINAL.md`, Part G), pilot corpus only.
The pre-registration is deliberately a stub until the gates pass (`docs/PRE_REGISTRATION.md`).

## Authoritative design

`docs/EXPERIMENT_ARCHITECTURE_FINAL.md` is the single source of truth. Working rules for
contributors (human or AI) are in `CLAUDE.md`; decisions are recorded in `adr/`.

## Setup

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/). The locked environment (`uv.lock`)
is committed.

| Command | Action |
|---|---|
| `make setup` | `uv sync` — create the pinned environment |
| `make lint` | `pre-commit run --all-files` (ruff + ruff-format) |
| `make test` | `pytest -q` |
| `make gate` | placeholder — smoke gates arrive in the smoke-test phase (Part G) |
| `make reproduce` | placeholder — available only after sealing |

Without `make` (e.g. plain Windows), run the underlying commands directly:
`uv sync`, `uvx pre-commit run --all-files`, `uv run pytest -q`.

**Platform note (ADR 0014):** the effect-ledger suite (`tests/test_effect_ledger.py`) and the
G-7 spike are **Windows-only** — the ledger's independence enforcement is Win32 share-mode
locking, so on other platforms those tests are *skipped* (and the spike refuses to run). A
green CI run on `ubuntu-latest` therefore does **not** verify the ledger; every other suite is
cross-platform. Windows is the sealed measurement platform; the POSIX variant is deferred.

## Layout

- `src/sut/` — the measured system (must never import from the harness)
- `src/sut/oauth_as/` — the pinned experiment OAuth 2.1 AS (ADR 0015; built at G-4 Phase 2). Runs
  out-of-process on loopback with its signing key never in an agent process. No other `src/sut/`
  module may import it (agents reach it over the wire), and **`src/harness/` may never import it**
  — the oracle and the G-13 verifier reimplement token verification independently (D13/D21)
- `src/harness/` — the instrument (imports `sut`, never the reverse; except `src/sut/oauth_as/`,
  which it may never import)
- `docs/` — architecture, threat model, frozen parameters, pre-registration stub
- `adr/` — one file per decision
- `fixtures/pilot/` vs `fixtures/confirmatory/` — strictly disjoint; confirmatory stays **empty** until post-seal
- `results/raw|tables|figures/` — write-once raw traces and derived outputs (later phases)

License: MIT (© 2026 Yixian Jiang).
