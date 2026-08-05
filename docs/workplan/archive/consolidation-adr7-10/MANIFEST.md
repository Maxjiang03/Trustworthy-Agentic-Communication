# ADR 0007–0010 consolidation task-specification archive — MANIFEST

> **Retrospective records — NOT pre-registration evidence.** This task specification was
> authored during the work it describes. It documents what was asked and when, for provenance
> and audit. It is **not** a pre-registered commitment, it was **not** sealed before the work,
> and it must **never** be cited as pre-registration evidence. The pre-registration is authored
> and sealed only per Part H, after the smoke gates pass.

Archived byte-for-byte (verified with `cmp` against the executed working copy at repo root,
which is removed in the same commit; no typo or formatting fixes applied), 2026-07-26:

| File | SHA-256 |
|---|---|
| `CONSOLIDATION_ADR7_10_TASK.md` | `14e0044c7b602a31562446f715406a4a350bf2f7e0a225eb3d85282d856124bd` |

Chronology (all 2026-07-26): a decisions-and-consolidation pass — **no gate was run**. The spec
recorded four given Commander decisions as ADR 0007 (sealed corpus stores generators and seeds,
not minted tokens; Part H amended), ADR 0008 (G-4 construction spike authorised early;
adjudication unmoved), ADR 0009 (frozen `H_JCS` construction + digest-field classification;
oracle-side `src/harness/oracle/jcs_digest.py`; JCS suite rewired, 12 tests), and ADR 0010
(§K LLM demonstration retained outside the seal; §J.7), then verified the locked environment
(29 tests passed; G-8 and G-5 spikes exit 0; red lines intact) and archived this file.
