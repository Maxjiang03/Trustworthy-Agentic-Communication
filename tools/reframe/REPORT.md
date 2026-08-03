# The reframe: a rename, six lines of prose, and what was deliberately left alone

This repository is the artifact behind an MSc dissertation. Parts of it were addressed to the tool
that built it rather than to a reader, and that framing does not belong in a submitted artifact.

**Nothing of substance was removed.** The forty ADRs, the fifteen gate reports, the tool evidence
directories and the work-plan specifications are the audit trail that makes this measurement
credible; deleting them would make the repository thinner, not cleaner. What read as scaffolding was
the **addressee**, so the whole change is a rename plus six lines of prose — and a proof strong
enough that no reader has to take that on trust.

**Commit range: `3d2473a..HEAD`** — `3d2473a` is the pre-reframe state, `ef9d7a5` landed the rename,
and the commit carrying this file closed it.

---

## Why a rename rather than a deletion

`CLAUDE.md` was cited by **73 tracked files** — around thirty source modules, the tests, the
`Dockerfile`, `.gitignore`, `.github/workflows/ci.yml`, `.pre-commit-config.yaml`, `adr/README.md`,
five ADRs, three gate reports, the archived work plans, and two fixture READMEs. **Nothing reads it
at runtime**; every occurrence is in a comment, a docstring or Markdown.

Deleting it would therefore have left seventy-three citations pointing at a file that does not exist:
`src/sut/__init__.py` would still say the dependency is one-way *"(CLAUDE.md red line 6)"* and a
reader would find no such document. That is worse than leaving it alone. Hence: rename, and repair
every pointer that could be repaired without touching the measurement.

---

## Path map

| old path | new path | status |
|---|---|---|
| `CLAUDE.md` | `PROJECT_RULES.md` | **done** — `git mv`, repository root |
| `docs/tasks/` | `docs/workplan/` | **deliberately not done** — see below |
| `docs/tasks/archive/**` | `docs/workplan/archive/**` | **deliberately not done** |
| `BOOTSTRAP_TASK.md` | `docs/workplan/BOOTSTRAP_TASK.md` | **deliberately not done** |

Every other path is unchanged. Added by the reframe: `tools/reframe/verify_rename.py`,
`tools/reframe/verify_ast.py`, and this report.

---

## The six exceptions, quoted in full

These are the only lines whose **words** changed. Everything else in the reframe is a citation
following a renamed file. No red-line number, `EXP<n> STEP <n>` identifier, ADR number, gate name,
frozen-parameter row or commit SHA appears in any of them — citations are indexed by those, and
renumbering one would break dozens of pointers silently.

**1 — `PROJECT_RULES.md`, title line**

- before: `# CLAUDE.md — Project Overview & Working Rules`
- after:  `# Project Rules — Overview & Working Rules`

**2 — `PROJECT_RULES.md`, red line 8 (the one sentence in the second person)**

- before: `8. No credentials, tokens, or secrets in the repo or in code. If a push needs auth you cannot access, STOP and ask the author.`
- after:  `8. No credentials, tokens, or secrets in the repo or in code. If a push needs auth that is unavailable, STOP and ask the author.`

**3 — `docs/EXPERIMENT_ARCHITECTURE_FINAL.md`, the Status line**

- before: `This is the specification Claude Code follows to run the feasibility smoke tests in Part G.`
- after:  `This is the specification the implementation follows to run the feasibility smoke tests in Part G.`

**4 — `docs/EXPERIMENT_ARCHITECTURE_FINAL.md`, the Part 0 heading**

- before: `## Part 0 — How to read this document (for Claude Code)`
- after:  `## Part 0 — How to read this document (for the implementer)`

**5 — `docs/EXPERIMENT_ARCHITECTURE_FINAL.md`, the Part G heading**

- before: `# Part G — Feasibility smoke-gate checklist (Claude Code runs these)`
- after:  `# Part G — Feasibility smoke-gate checklist (run these)`

**6 — `docs/EXPERIMENT_ARCHITECTURE_FINAL.md`, the closing paragraph**

- before: `Claude Code: run Part G along the DAG; stop and apply the fallback at any failing gate; do not author or execute the confirmatory corpus; do not generate v0.5.`
- after:  `Part G is run along the DAG; work stops and the fallback applies at any failing gate; the confirmatory corpus is neither authored nor executed here; v0.5 is not generated.`

Every instruction and its force survives in each; only the addressee goes. Exceptions 3–6 sit in the
document Part H step 3 seals and the dissertation cites, which is why they are enumerated one at a
time rather than swept.

---

## Deliberately not done, and why

**These three non-actions are part of the deliverable, not omissions from it.** An open loop recorded
only in a conversation is an open loop that gets rediscovered after the seal, when it can no longer
be closed.

### 1. The thirteen `_banner` strings in `fixtures/pilot/golden_thread/sealed/`, and `fixtures/pilot/golden_thread/generator.py:607`

Those thirteen sealed-corpus documents each carry a human-readable `_banner` citing *"CLAUDE.md red
line 5"*, and `generator.py` is what writes it.

**Editing the banners without the generator means the next regeneration silently reverts them**, and
*edited but reverts* is a worse state than *not edited*. Editing both is the highest-risk change
available before a seal — the sealed corpus is what every gate was adjudicated against — for a JSON
field a reader will not open. **Declared in the pre-registration instead.**

For the record, in case the decision is revisited: nothing hashes those banners, no digest or
manifest covers the corpus files, and `tests/test_pilot_fixtures.py:207` already excludes `_banner`
from fixture comparison. The edit would be *safe*; it is not *worth it* at this point in the
schedule.

### 2. `src/harness/sealed_truth.py:44` — the citation inside the raised `SealedTruthAccessError`

That string still reads `CLAUDE.md`, deliberately.

Changing it touches `src/`, and **the fifteen gates were measured at `0db8b5a`** — a source change
makes that measurement stop describing HEAD and costs a full gate re-run on the row 9 measurement
machine. The string appears only when a SUT module attempts to read sealed truth, which is **already
a failure state** in which a stale citation is the least important fact on the screen. **Zero effect
on any result.**

### 3. Tier 2 — `docs/tasks/` → `docs/workplan/`

A directory name, days before a seal. The benefit does not carry the risk, and the pre-registration
cites the existing paths.

---

## The lesson worth carrying: AST versus bytes

`src/harness/sealed_truth.py:44` was **the only place in twenty-five Python files where substituting
the name would have changed an executable value.** The citation sits inside a raised exception
message, not a comment or a docstring:

```python
raise SealedTruthAccessError(
    f"sealed truth requested from SUT module {module!r} "
    "(CLAUDE.md red line 5; SS A.3: tau_gt is oracle-only)"
)
```

**The byte-level proof passed it happily.** Only the AST comparison saw it — because to a text-level
proof a string literal and a comment are the same thing.

> **"It only changes comments" is a false intuition in Python.** Exception messages, log format
> strings and other constants are **executable values**, and a text-level proof cannot distinguish
> them from prose. A rename sweep over a Python codebase needs a syntactic check as well as a
> byte-level one; the two fail for different reasons, and each is blind to what the other catches.

That is why the two scripts are kept as a pair rather than merged.

---

## The two READMEs, and how they were shown inert first

`fixtures/pilot/golden_thread/README.md` and `fixtures/confirmatory/README.md` **were** substituted,
under a bar lifted for exactly those two files: they are prose documents that happen to live under a
data directory, and a README is the first thing anyone browsing a repository opens.

They were shown inert **before** being edited, five ways:

1. **Nothing references** `fixtures/pilot/golden_thread/README.md` anywhere in the repository.
2. `fixtures/confirmatory/README.md` is referenced in exactly three places —
   `fixtures/pilot/golden_thread/generator.py:661`, `tests/test_pilot_fixtures.py:198` and
   `tests/test_campaign.py:588` — and in **all three by filename only, to EXCLUDE it** from a
   directory-emptiness assertion (red line 1: `fixtures/confirmatory/` stays empty until sealing).
   Its **contents are never read**.
3. The generator **emits no README**; its only mention is that same exclusion.
4. Every fixture traversal globs `*.json` under `sealed/` and `sut_visible/`. Nothing globs `.md` and
   nothing walks the corpus root.
5. **No digest, commitment or manifest covers any fixture path** — no `sha256`, `hashlib` or `h_jcs`
   call in `src/` or `analysis/` takes a fixture, corpus or `.md` path.

Both files contained the literal string, so both are fully reversible and **neither adds an
exception**.

---

## Re-running the proofs

Both hold their baseline at **`3d2473a`**, the pre-reframe state, so **one command establishes the
whole reframe** rather than one commit of it. Re-baselining would split the claim across two
artifacts, and a claim that needs two artifacts to state is a claim someone will eventually state
wrongly.

```
uv run python tools/reframe/verify_rename.py     # bytes:  exits non-zero on any unlisted difference
uv run python tools/reframe/verify_ast.py        # syntax: exits non-zero on any executable change
```

Both accept `--rev` (default `HEAD`; `""` reads the index) and `--baseline`.

**Results at the closing commit:**

```
PASS -- reverse-substituting PROJECT_RULES.md -> CLAUDE.md reproduces 3d2473a byte for byte
        across all 62 changed files, with exactly 6 enumerated exceptions and no others.

PASS -- 25 .py files are AST-identical to 3d2473a with docstrings elided.
        ZERO executable lines changed.
```

`verify_rename.py` compares **git blobs** on both sides rather than working-tree bytes: `core.autocrlf`
is on for this checkout, so the working tree holds CRLF and the object database holds LF, and a
working-tree comparison would report a difference on every line of every file and prove nothing.

Both scripts fail closed on an unenumerated addition, and `verify_rename.py` additionally fails if an
exception matches zero times or more than once — a reworded line that has drifted fails rather than
passing quietly. **A seventh exception means something changed that was not authorised; the correct
response is to stop, not to enumerate it.**
