# Gate G-8/G-5 task-specification archive — MANIFEST

> **Retrospective records — NOT pre-registration evidence.** This task specification was
> authored during the work it describes. It documents what was asked and when, for provenance
> and audit. It is **not** a pre-registered commitment, it was **not** sealed before the work,
> and it must **never** be cited as pre-registration evidence. The pre-registration is authored
> and sealed only per Part H, after the smoke gates pass.

Archived byte-for-byte (verified with `cmp` against the executed working copy at repo root,
which is removed in the same commit; no typo or formatting fixes applied), 2026-07-25:

| File | SHA-256 |
|---|---|
| `SMOKE_G8_G5_TASK.md` | `dee3b27d99d90fd5337a6359fa2ceaf16fd0b6c877b5b115001fcdab09a074ab` |

Chronology (all 2026-07-25): the spec ran ADR 0004 (build-vs-reuse), then gate G-8 (RFC 8785
JCS — `rfc8785==0.1.4`, ADR 0005, PASS), then gate G-5 (DPoP binding — `joserfc==1.7.4`,
ADR 0006, PASS), then full locked-environment verification and this archive.
