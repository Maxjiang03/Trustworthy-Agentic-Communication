# Gate G-1 task-specification archive — MANIFEST

> **Retrospective records — NOT pre-registration evidence.** These task specifications were
> authored during the work they describe. They document what was asked and when, for provenance
> and audit. They are **not** pre-registered commitments, they were **not** sealed before the
> work, and they must **never** be cited as pre-registration evidence. The pre-registration is
> authored and sealed only per Part H, after the smoke gates pass.

Archived byte-for-byte (verified with `cmp` against the executed working copies at repo root;
no typo or formatting fixes applied), 2026-07-14:

| File | SHA-256 |
|---|---|
| `SMOKE_G1_TASK.md` | `1352a8c04701eef3b897930d428b1975b6d52cd24aab597346fd224c8b80df12` |
| `SMOKE_G1_RESOLUTION_TASK.md` | `20240a9bd528171e5344469981f63e7de0e3bea0c0905261986fa5e222b9fab1` |
| `SMOKE_G1_CORRECTIVE_TASK.md` | `3c4b37d6cf124bb58b8595e113b993619a6c6acf0f9a32f8284fa1c9ab905f44` |

Chronology (all 2026-07-14): `SMOKE_G1_TASK.md` ran the gate (outcome FAIL, seal not exposed);
`SMOKE_G1_RESOLUTION_TASK.md` carried the author decision (G-1.G → G-1.G′; adopt
biscuit-python==0.4.0; this design never seals; ADR 0002); `SMOKE_G1_CORRECTIVE_TASK.md`
replaced the unsound raw-protobuf-byte commitment with the BlockID commitment (ADR 0003).
