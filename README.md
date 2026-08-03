# TrustworthyAgent

Trustworthy Agentic Communication: a pre-registered, reproducible testbed that measures
authorization-scope propagation and its cost at the A2A→MCP boundary (the cross-protocol
confused-deputy problem, TV23). MSc Cybersecurity dissertation, University of Glasgow.

## Current phase

**Experimental apparatus, pilot corpus only.** Eight feasibility smoke gates have passed
(`smoke/README.md` is the board), and as of 2026-07-30 the golden thread runs end to end: a
Supervisor, an A2A delegation hop behind a port, a Specialist, an MCP tool call over the frozen
ontology, and **two of the nine arms — `B0` and `B3`**. Seven gates remain (G-3, G-9, G-10,
G-12, G-13, G-14, G-15); the apparatus they need now exists, but **this apparatus adjudicates no
gate**, and no gate status changed when it was built.

The pre-registration is deliberately a stub until the gates pass (`docs/PRE_REGISTRATION.md`),
`fixtures/confirmatory/` stays empty until sealing, and **no latency number has been measured or
reported** — the G-3 threshold and the equivalence margin (`docs/frozen_parameters.md` rows 2 and
1) are UNSET and must be fixed from external engineering need first.

*(Update note, 2026-07-30: this section previously read "Repository skeleton — pre-smoke-test.
Implementation logic has not begun," which was true when written and stopped being true in the
pass that built the apparatus.)*

## Authoritative design

`docs/EXPERIMENT_ARCHITECTURE_FINAL.md` is the single source of truth. Working rules for
contributors (human or AI) are in `PROJECT_RULES.md`; decisions are recorded in `adr/`.

## Setup

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/). The locked environment (`uv.lock`)
is committed.

| Command | Action |
|---|---|
| `make setup` | `uv sync` — create the pinned environment |
| `make lint` | `pre-commit run --all-files` (ruff + ruff-format) |
| `make test` | `pytest -q` |
| `make gate GATE=g1` | run one gate's spike (`smoke/g{1,2,4,5,6,7,8,11}/`). POSIX-flavoured — on Windows run `uv run python smoke/g11/spike.py` directly |
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
  which it may never import). All three import rules are enforced by an AST suite
  (`tests/test_import_redlines.py`), not by convention alone
- `docs/` — architecture, threat model, frozen parameters, pre-registration stub
- `adr/` — one file per decision
- `fixtures/pilot/` vs `fixtures/confirmatory/` — strictly disjoint; confirmatory stays **empty** until post-seal
- `results/raw|tables|figures/` — write-once raw traces and derived outputs (later phases)

License: MIT (© 2026 Yixian Jiang).
