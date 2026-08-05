# BOOTSTRAP_TASK — Repository Skeleton Setup

This session is **SKELETON SETUP ONLY**. Do **not** write implementation logic, do **not** run experiments, do **not** create or populate the confirmatory corpus, and do **not** run smoke tests. Your job: understand the project, build a clean, reproducible, audit-friendly repository skeleton, and commit it to GitHub under a disciplined commit convention.

**GitHub remote (already exists):** `https://github.com/Maxjiang03/TrustworthyAgent.git`

**About this file:** it is the provenance record of how the skeleton was created. Keep it in the repository (repo root or `docs/`, your choice) and commit it.

---

## STEP 0 — Read and orient (before touching anything)

1. List the current working directory. The **only** design document that exists is:
   - `EXPERIMENT_ARCHITECTURE_FINAL.md`

   **Read it end to end before proceeding.** It is the **single source of truth**. It defines: the evidence grades (`[VERIFIED]` / `[DESIGN]` / `[UNVERIFIED-IA]`), the canonical types (`P_i`, `C_i`, `Ω`, `Γ`, `κ`), the baseline ladder (B0, B1, B2-broad-noexchange, B2-exchange-broad, B2-exchange-task, B2-exchange-task-DPoP, B-cap, B3, B3⁺), the capability / HTC / INV design, the independent oracle (Part I), the smoke-gate DAG (Part G), the freeze/seal loop (Part H), and the workflow checklist (Part J) that you are partly implementing now.

2. There is **no pre-registration document yet, and you must not write one.** Per Part H, the pre-registration is authored and sealed only **after** the smoke gates pass. You will create a clearly-marked stub for it (STEP 5).

3. **Do not invent any design element.** If something is unclear, cite the section of the architecture doc and ask.

---

## STEP 1 — Sync with the existing remote (do not clobber anything already there)

5. If the directory is not yet a git repo: `git init` (default branch `main`).
6. Add the remote if absent:
   ```
   git remote add origin https://github.com/Maxjiang03/TrustworthyAgent.git
   ```
7. `git fetch origin`. If `origin/main` already has commits (e.g. a GitHub-generated README or LICENSE), integrate them **without losing them**: `git pull --rebase origin main` (or a soft reset onto `origin/main` if the local tree is empty), then continue on top.
8. **Never** `git push --force`, and never rewrite remote history. If you hit a non-fast-forward you cannot cleanly resolve, **STOP and report**.

---

## STEP 2 — Create the repository skeleton

Create exactly this structure. Placeholder Python modules contain **only** a module docstring stating their future responsibility, plus (where noted) minimal type stubs — **no real logic** (no Biscuit calls, no OAuth flows, no oracle math). Use `.gitkeep` for empty directories.

```
TrustworthyAgent/
├── PROJECT_RULES.md                       # project overview + working rules (exact content in STEP 3)
├── BOOTSTRAP_TASK.md               # this file — provenance record; commit it
├── README.md                       # short: what this is, current phase, setup commands, pointer to docs/
├── LICENSE                         # MIT, copyright holder: Yixian Jiang
├── .gitignore                      # Python, .venv, __pycache__, .env, uv cache; keep results/**/.gitkeep
├── .editorconfig
├── .pre-commit-config.yaml         # ruff lint + ruff-format only
├── pyproject.toml                  # see STEP 4
├── Dockerfile                      # see STEP 4
├── Makefile                        # setup, lint, test, gate, reproduce (see STEP 4)
├── .github/workflows/ci.yml        # pre-commit + pytest on push/PR (see STEP 4)
├── docs/
│   ├── EXPERIMENT_ARCHITECTURE_FINAL.md   # MOVE the existing file from repo root into here
│   ├── PRE_REGISTRATION.md                # STUB ONLY — exact content in STEP 5
│   ├── threat_model.md                    # derived from the architecture doc — see STEP 6
│   └── frozen_parameters.md               # seal-time parameters, all UNSET — see STEP 7
├── adr/
│   ├── README.md                    # how ADRs work (one file per decision; statuses: proposed/accepted/superseded)
│   ├── template.md                  # Context / Decision / Status / Consequences
│   └── 0001-record-architecture-decisions.md   # first ADR: we keep ADRs; the architecture doc is authoritative
├── src/
│   ├── __init__.py
│   ├── sut/                         # the MEASURED system — must NEVER import from harness
│   │   ├── __init__.py
│   │   ├── protocol/__init__.py     # docstring: A2A envelope + MCP tooling substrate (official SDKs) — TODO smoke phase
│   │   ├── authz/__init__.py        # docstring: local OAuth 2.1 AS, RFC 8693 exchange, DPoP — TODO; library choice deferred to gates G-4/G-5
│   │   ├── capability/__init__.py   # docstring: Biscuit signed-block prefix P_i, HTC chain, INV assertion — TODO; library choice deferred to gate G-1
│   │   ├── baselines/__init__.py    # docstring: B0, B1, B2-broad-noexchange, B2-exchange-broad, B2-exchange-task, B2-exchange-task-DPoP, B-cap, B3, B3+ — TODO
│   │   └── agents/__init__.py       # docstring: deterministic Supervisor / Specialist / Tool mocks — TODO
│   └── harness/                     # the INSTRUMENT — imports sut, never the reverse
│       ├── __init__.py
│       ├── schema.py                # TYPE STUBS ONLY (see note below)
│       ├── oracle/__init__.py       # docstring: reference_allow / observed_forwarded / admission_breach / realized_harm / false_block / log_integrity_failure — TODO (Part I)
│       ├── mediation/__init__.py    # docstring: MediationEvent + ToolIngressEvent + immutable effect-ledger interposition — TODO (gates G-6/G-7)
│       └── runner.py                # docstring: experiment matrix runner — TODO
├── fixtures/
│   ├── pilot/.gitkeep               # pilot scenarios land here in the smoke phase
│   └── confirmatory/README.md       # see note below
├── tests/
│   ├── __init__.py
│   └── test_placeholder.py          # one trivial passing test so pytest/CI is green from day one
├── analysis/.gitkeep
└── results/
    ├── raw/.gitkeep                 # write-once raw traces (later)
    ├── tables/.gitkeep
    └── figures/.gitkeep
```

**`src/harness/schema.py` — type stubs only.** Class names and field names with bodies as `...`. Mirror architecture doc **Part F.1**: `EvidenceBundle`, `ApiKeyEvidence`, `OAuthEvidence`, `CapabilityEvidence`, `ObservedRequest`, `IntendedInvocation`, `MediationEvent`, `ToolIngressEvent`, `EffectEvent`, `LabelAssertion`, `DeclassificationArtifact`. **Do not implement validation or logic.**

**`fixtures/confirmatory/README.md`** must state: *this directory stays **empty** until Part H step 4 (post-seal). No scenario file may be added before sealing. Pilot and confirmatory corpora are disjoint by construction.*

---

## STEP 3 — Create `PROJECT_RULES.md` with exactly this content

```markdown
# PROJECT_RULES.md — Project Overview & Working Rules

## What this is
Trustworthy Agentic Communication: a pre-registered, reproducible testbed that measures authorization-scope propagation and its cost at the A2A→MCP boundary (the cross-protocol confused-deputy problem, TV23). MSc Cybersecurity dissertation, University of Glasgow.

## Authoritative design
`docs/EXPERIMENT_ARCHITECTURE_FINAL.md` is the SINGLE source of truth (baselines, capability/HTC/INV, oracle, smoke-gate DAG, freeze/seal loop, workflow). Do not contradict it. If a change is needed, record an ADR in `adr/` and update the doc — never silently diverge.

## Current phase
Repository skeleton, pre-smoke-test. Implementation logic has NOT begun. Next phase: the feasibility smoke gates (design Part G), pilot corpus only.

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

## Commit convention (Conventional Commits)
`type: summary`, type ∈ {feat, fix, docs, test, build, ci, chore, refactor}. Logically scoped commits (not one giant commit, not one per file). Reference an ADR in the body when a commit encodes a decision. Run `make lint` and `make test` before committing. Push to `origin main` after a coherent unit of work. Never force-push.

## Setup
`make setup` (uv sync) · `make lint` (pre-commit) · `make test` (pytest). Python 3.11+. Determinism: fixed `PYTHONHASHSEED`, single seed source, Ed25519 for signing, RFC 8785 JCS for digests.
```

---

## STEP 4 — Pinned environment, hooks, CI (reproducibility is a hard requirement)

**`pyproject.toml`** — project metadata; `requires-python = ">=3.11"`; a `[tool.ruff]` config. Dependencies: **only** libraries that are certain now — `pydantic`, `pyyaml`, `cryptography`, `numpy`, `scipy`, `pytest`. Then add a **commented** "PENDING GATE" block listing libraries whose choice is deliberately deferred:

```
# PENDING GATE — do not pin until the gate decides:
#   Python Biscuit library            -> gate G-1 / G-2
#   authlib (RFC 8693 + RFC 9396)     -> gate G-4
#   DPoP / JOSE library               -> gate G-5
```

**Do not guess these pins.**

**Lock file** — if `uv` is available, run `uv lock` and commit `uv.lock`. If `uv` is **not** installed, **do not fabricate a lock file**; note in `README.md` that `uv` must be installed and `uv lock` run, and continue.

**`Dockerfile`** — `FROM python:3.11-slim`; install `uv`; copy `pyproject` + lock; `uv sync`; `ENV PYTHONHASHSEED=0`. Minimal and pinned.

**`Makefile`** targets:

| target | action |
|---|---|
| `setup` | `uv sync` |
| `lint` | `pre-commit run --all-files` |
| `test` | `pytest -q` |
| `gate` | `echo "Smoke gates run in the smoke-test phase; see docs/EXPERIMENT_ARCHITECTURE_FINAL.md Part G"` |
| `reproduce` | `echo "Available only after sealing; regenerates tables/figures from results/raw/"` |

**`.pre-commit-config.yaml`** — `ruff` + `ruff-format`. Nothing heavier yet.

**`.github/workflows/ci.yml`** — on push and PR to `main`; Python 3.11 + `uv`; `uv sync`; run `pre-commit run --all-files` and `pytest -q`.

---

## STEP 5 — `docs/PRE_REGISTRATION.md` (stub only)

Create it containing exactly this, and nothing more:

```markdown
# Pre-Registration — NOT YET AUTHORED

**Status:** Stub. This document does not exist yet and MUST NOT be drafted ahead of schedule.

Per `EXPERIMENT_ARCHITECTURE_FINAL.md` **Part H**, the pre-registration is authored at **step 2 of the seal loop — after every in-scope smoke gate (Part G) has passed on the pilot corpus** — and is derived from the architecture document. It will freeze: the hypotheses, the oracle predicates, the baseline configurations, the latency estimands, and the equivalence margin. It is then sealed together with the implementation commit, oracle, analysis code, configuration, pinned environment, and corpus generator, under a detached manifest with a public temporal anchor.

**Any earlier draft of this document is superseded and must not be reused.**

Writing or sealing this document before the smoke gates pass would defeat the pre-registration and is prohibited.
```

---

## STEP 6 — `docs/threat_model.md`

Assemble it **from** the architecture document — do not invent content. Draw on:

- **Part A.3** — the three scopes: `U_max`, `U_task`, `τ_gt` (and that `τ_gt` is oracle-only)
- **Part A.5.1** — three identity notions: `resource_owner`, `oauth_actor`, `htc_holder`
- **Part F.2 / F.2.1** — keys, trust root `κ`, HTC chain, identity-plane registry
- **Part D** — attacker capabilities, key possession, tampering points, the four-way DPoP taxonomy

Then append this out-of-scope statement **verbatim** as its own section:

> **Out of scope.** The study concerns authorization-scope propagation. The following are out of scope, and are named so the exclusion is deliberate rather than an omission: prompt injection and goal hijack against the language model; memory or context poisoning; tool-definition poisoning and supply-chain attacks on tool registries; unexpected code execution; and attacks on the enforcement code, the trust store, or the cryptographic primitives. Generalization of the results is claimed only for the threat model and the attack instances constructed here, not for a population of all possible attacks.

---

## STEP 7 — `docs/frozen_parameters.md` (all unset)

State at the top: these **must** be frozen and hashed before sealing (Part H step 3); **none is chosen yet**; the equivalence margin and the G-3 smoke threshold **must** be fixed from external engineering need **before any timing measurement**.

List each with value `⟨UNSET — fix before Part H step 3⟩` and a one-line justification slot:

- Equivalence margin for the "lightweight" claim
- G-3 latency smoke threshold (separate from, and set before, the equivalence margin)
- Freshness window `Δ`
- Context-label → {permit, escalate, block} policy
- `task_authorization_policy` (task → authorized actor principals) for F2 `wrong_principal`
- allowed-sink policy for F4
- Reference LLM-turn denominators (full-turn primary + conservative TTFT) — secondary framing only
- `Ω` (action/resource ontology) and `Γ` (authorizer configuration) — frozen and hashed as `H(Γ)`

---

## STEP 8 — Commit and push (Conventional Commits, logically grouped)

Stage in coherent groups; commit each with a clear message, for example:

1. `chore: initialize repository skeleton and package layout`
2. `build: add pinned Python 3.11 environment (pyproject, uv.lock, Dockerfile)`
3. `ci: add pre-commit (ruff) and GitHub Actions pytest workflow`
4. `docs: add PROJECT_RULES.md, move architecture doc into docs/, add threat model, pre-registration stub, frozen-parameters stub`
5. `docs: add ADR log and initial architecture-decision record`
6. `test: add placeholder test so CI is green`

Run `make lint` and `make test` before the final commit and fix anything they flag. Then:

```
git push -u origin main
```

**If the push fails due to authentication, STOP and tell me exactly what to configure.** Do **not** attempt to enter, store, or generate any credential.

---

## STEP 9 — Report

Finish with:

- the tree you created
- the commits (hash + message)
- whether the push succeeded
- whether CI should pass
- a bullet list of anything I must do next (e.g. install `uv` and run `uv lock`, configure GitHub auth)
