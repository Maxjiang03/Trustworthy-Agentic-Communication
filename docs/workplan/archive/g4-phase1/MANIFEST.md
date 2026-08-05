# G-4 Phase 1 task-specification archive — MANIFEST

> **Retrospective records — NOT pre-registration evidence.** This task specification was
> authored during the work it describes. It documents what was asked and when, for provenance
> and audit. It is **not** a pre-registered commitment, it was **not** sealed before the work,
> and it must **never** be cited as pre-registration evidence. The pre-registration is authored
> and sealed only per Part H, after the smoke gates pass.

Archived byte-for-byte (verified with `cmp` against the executed working copy at repo root,
which is removed in the same commit; no typo or formatting fixes applied), 2026-07-27:

| File | SHA-256 |
|---|---|
| `G4_PHASE1_TASK.md` | `e1babb4cd4de3102e3e6a1e0a5d81de5641f1322b35495db26a2bffe0db09af4` |

Chronology (all 2026-07-27): the design-only first phase of gate G-4 — **no AS was written and
no gate was adjudicated**. The pass read RFC 8693, RFC 9396, RFC 8707, RFC 9449, RFC 9068 and
OAuth 2.1 draft 15 from the document text (recording RFC 8414 as out of scope and RFC 7523 as
not read, rather than skipping them silently); probed `authlib==1.7.2` ephemerally and found it
**UNSUPPORTED** for both halves of IA-4's first limb, confirming ADR 0004's build finding on
evidence rather than recollection; specified the pinned experiment AS profile, its rejection
catalogue, its identity plane, its process/key isolation and its fair-baseline hazards in both
directions (`smoke/g4/DESIGN.md`); resolved the three dependency conflicts with labelled
spike-local stand-ins and re-adjudication triggers, judging the `INV.access_token_hash` limb not
honestly adjudicable before G-11; and decided the AS placement (ADR 0015, `src/sut/oauth_as/`,
with the two import rules). IA-4 remained **[UNVERIFIED-IA]**, G-4's pass criteria and
dependency edges were **unchanged**, and `authlib` remained **unpinned**. Verified on Windows:
`pre-commit` clean, `42 passed`.
