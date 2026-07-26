# Ledger-platform decision task-specification archive — MANIFEST

> **Retrospective records — NOT pre-registration evidence.** This task specification was
> authored during the work it describes. It documents what was asked and when, for provenance
> and audit. It is **not** a pre-registered commitment, it was **not** sealed before the work,
> and it must **never** be cited as pre-registration evidence. The pre-registration is authored
> and sealed only per Part H, after the smoke gates pass.

Archived byte-for-byte (verified with `cmp` against the executed working copy at repo root,
which is removed in the same commit; no typo or formatting fixes applied), 2026-07-26:

| File | SHA-256 |
|---|---|
| `LEDGER_PLATFORM_TASK.md` | `a2b539d845862a218dc6dd9233fac4bee6cdf9faa4b77e5411d31d2dd1e14470` |

Chronology (all 2026-07-26): a decisions-and-consolidation pass — **no gate was run**, and
G-6/G-7 were neither re-run nor re-adjudicated. The spec recorded the Commander's platform
decision as ADR 0014 (Windows is the sealed measurement platform; the POSIX ledger variant is
deferred post-submission; `LedgerWriter`'s non-Windows raise is preserved, never weakened),
made the ledger suite and the G-7 spike platform-aware so CI is green without a silent
degradation, carried the platform into Part H step 3 / `frozen_parameters` row 9 / the Part J
validity threats / the §F.4 IA-7 residual, opened the G-4 construction spike as a scoping
artifact only (`smoke/g4/SCOPE.md`, ADR 0008, no AS code), and verified the locked environment
(42 passed on Windows; g1/g5/g6/g7/g8 spikes exit 0).
