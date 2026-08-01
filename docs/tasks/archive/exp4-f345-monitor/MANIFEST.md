# EXP4 F3/F4/F5 + shared-monitor task-specification archive — MANIFEST

> **Retrospective records — NOT pre-registration evidence.** This task specification was
> authored during the work it describes. It documents what was asked and when, for provenance
> and audit. It is **not** a pre-registered commitment, it was **not** sealed before the work,
> and it must **never** be cited as pre-registration evidence. The pre-registration is authored
> and sealed only per Part H, after the smoke gates pass.

Archived byte-for-byte (verified with `cmp` against the executed working copy at repo root;
no typo or formatting fixes applied), 2026-08-01:

| File | Lines | SHA-256 |
|---|---|---|
| `EXP4_TASK.md` | 300 | `a609f64d3e9238fc4a5eddd51d14b81012ad67fff6be57a63e00292734782eac` |

## What the block produced

Three ADRs, all authored during the block. **ADR 0030** was this pass's to write and its values
were this pass's to fix; **ADR 0031** and **ADR 0032** were **adjudicated by the author
mid-block** on evidence gathered here, and corrected §E.4 **predictions** — never code.

| ADR | What it settles |
|---|---|
| [0030](../../../../adr/0030-label-plumbing-and-the-boundary-owned-reference-monitor.md) | The six label-plumbing constructions, closing ADR 0009's **last** category (c) fields; the boundary-owned reference monitor; the ingestion label directory |
| [0031](../../../../adr/0031-e4-bcap-f3-oauth-negative-controls-are-b-not-na.md) | §E.4's `B-cap` F3 OAuth-control cells: `NA` → **B** |
| [0032](../../../../adr/0032-e4-bcap-f4-f5-cells-are-a-not-a-dagger.md) | §E.4's `B-cap` F4/F5 cells: `A†` → plain **A** |

Gate **G-15 PASSES** ([`smoke/g15/REPORT.md`](../../../../smoke/g15/REPORT.md)), wired into CI
beside G-4, G-11 and G-13.

## Two corrections the Commander adjudicated during the block

Both concern `B-cap`, in opposite directions, and both trace to one drafting cause: **§E.4 filled
`B-cap` in as "a capability arm" rather than from its own §E.5 bits.** Recorded here because the
sequence matters — the evidence was gathered, reported, and adjudicated before either cell moved,
and neither the code nor the prediction was adjusted toward the other by this pass.

## Scope note

The block delivered STEP 3–16 in full. What it did **not** do, and did not claim to: no timing
number was produced anywhere (G-3 owns timing); `IA-3` and `IA-9` stay `[UNVERIFIED-IA]`;
`frozen_parameters` row 5 stays deferred (ADR 0028) and row 9 unset; `fixtures/confirmatory/`
stays empty; and the pre-registration remains a stub, as Part H requires until every in-scope
smoke gate passes.
