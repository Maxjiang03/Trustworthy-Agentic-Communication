# Gate G-6/G-7 task-specification archive — MANIFEST

> **Retrospective records — NOT pre-registration evidence.** This task specification was
> authored during the work it describes. It documents what was asked and when, for provenance
> and audit. It is **not** a pre-registered commitment, it was **not** sealed before the work,
> and it must **never** be cited as pre-registration evidence. The pre-registration is authored
> and sealed only per Part H, after the smoke gates pass.

Archived byte-for-byte (verified with `cmp` against the executed working copy at repo root,
which is removed in the same commit; no typo or formatting fixes applied), 2026-07-26:

| File | SHA-256 |
|---|---|
| `SMOKE_G6_G7_TASK.md` | `5da7719f69c195972619f312accde52a8f7f6d3b144376fe830e3d1276669002` |

Chronology (all 2026-07-26): the spec ran the ADR 0011 tidy-up (commitment-family hex
encoding; `P_hashes` classified), then gate G-6 (complete mediation — full dispatch-path
enumeration on `mcp` 1.28.1, wrap-at-fn + wrap-on-insert interposition, PASS), then gate G-7
(independent effect ledger — exclusive-share ledger process, PASS; `ingress_request_digest`
settled by ADR 0012), then the `mcp==1.28.1` pin (ADR 0013), full locked-environment
verification (42 tests; all five gate spikes exit 0), and this archive.
