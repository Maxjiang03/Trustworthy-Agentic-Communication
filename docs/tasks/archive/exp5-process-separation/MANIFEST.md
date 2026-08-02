# EXP5 SUT process-separation task-specification archive — MANIFEST

> **Retrospective records — NOT pre-registration evidence.** This task specification was
> authored during the work it describes. It documents what was asked and when, for provenance
> and audit. It is **not** a pre-registered commitment, it was **not** sealed before the work,
> and it must **never** be cited as pre-registration evidence. The pre-registration is authored
> and sealed only per Part H, after the smoke gates pass.

Archived byte-for-byte (verified with `cmp` against the executed working copy at repo root;
no typo or formatting fixes applied), 2026-08-02:

| File | Lines | SHA-256 |
|---|---|---|
| `EXP5_TASK.md` | 297 | `1690941550d3b2323b6da407631781e74356df7410f4f9ad1cff49d3118b973d` |

## What the block produced

Four phases in Part G's DAG order — process separation, then G-12, then G-9, then G-14 — and
**three gates adjudicated PASS**, taking the board from ten to thirteen.

| Gate | What it established |
|---|---|
| [G-12](../../../../smoke/g12/REPORT.md) | Oracle independence under a lying SUT, in **both** directions, across a real process boundary |
| [G-9](../../../../smoke/g9/REPORT.md) | Multi-process replay detection: exactly one of N concurrent, induced backend error, overflow reached. **`IA-9` moves to verified** |
| [G-14](../../../../smoke/g14/REPORT.md) | The **DPoP/INV attribution**, measured rather than argued: indistinguishable on captured-proof-replay, separated on first-use body mutation |

One ADR, authored during the block:

| ADR | What it settles |
|---|---|
| [0033](../../../../adr/0033-the-replay-cache-is-a-single-writer-arbiter-process.md) | The multi-process replay cache is a **single-writer arbiter process** — atomicity as a property of the shape rather than of a lock, with the rejected alternatives recorded |

The apparatus it added: `src/sut/sut_process/` and `src/harness/sut_process.py` (spawn-never-import,
the third application of ADR 0015 rule 4), `src/sut/replay_arbiter/` and
`src/sut/authz/replay_client.py`, four correlation-ID fault injectors, and a two-mode equivalence
sweep over the full ladder. **In-process stays the default**, so the ten earlier gates were not
silently re-adjudicated.

## Findings the block reported rather than smoothed over

Recorded here because in each case the evidence was gathered and reported, and neither the code nor
the specification was adjusted toward the other.

- **A latent stderr deadlock in both spawners** (`5731b8c`), found by reasoning from a
  platform-split CI failure rather than from logs. Both spawners set `stderr=PIPE` and never read
  it; once the OS buffer filled, the child blocked writing and the parent blocked writing stdin.
  Fixed with `DEVNULL`, **not** by shrinking the test that exposed it.
- **The DROP finding** (G-12): a dropped ledger record and an unreached tool both produce zero
  effects. They are told apart because the evidence has three authors and `admitted ⇒ ingress ⇒
  effect` is a chain a drop breaks — with the residual stated, not hidden.
- **A two-clocks fixture defect** in G-14's first run, which refused every arm before the cache was
  ever reached. The gate catching the block's own fixture error is the gate working.
- **G-9's L4 limb was flaky**, found by STEP 13's standing check re-running all thirteen spikes:
  filling the frozen `2^16` is quadratic (`2,147,450,880` scan steps, counted exactly) and had been
  passing only on machines fast enough to finish inside a 120 s socket budget. The capacity was
  **not** shrunk — that is forbidden action 6 — and the `O(n)` eviction was **not** optimised,
  because that cost is **G-3's** to measure.
- **STEP 13's per-arm sweep** found the two-mode equivalence suite covered four of nine arms,
  excluding the OAuth arms — the direction that would have flattered this work. Widened to all
  nine; **32/32 applicable cells identical across the boundary**.

## Scope note

The block delivered STEP 3–15 in full. What it did **not** do, and did not claim to: **no timing
number was produced anywhere** (G-3 owns timing) and **no test sleeps** — every window is crossed by
advancing an injected instant (ADR 0027); `IA-3` stays `[UNVERIFIED-IA]`; no frozen parameter moved,
and `Δ = 60 s` and the `2^16` capacity are untouched; `frozen_parameters` row 5 stays deferred
(ADR 0028) and row 9 unset; `fixtures/confirmatory/` stays empty; G-3 and G-10 remain not started;
and the pre-registration remains a stub, as Part H requires until every in-scope smoke gate passes.
