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

## Layout

- `src/sut/` — the measured system (must never import from the harness)
- `src/harness/` — the instrument (imports `sut`, never the reverse)
- `docs/` — architecture, threat model, frozen parameters, pre-registration stub
- `adr/` — one file per decision
- `fixtures/pilot/` vs `fixtures/confirmatory/` — strictly disjoint; confirmatory stays **empty** until post-seal
- `results/raw|tables|figures/` — write-once raw traces and derived outputs (later phases)

License: MIT (© 2026 Yixian Jiang).
