# Gate G-11 task-specification archive — MANIFEST

> **Retrospective records — NOT pre-registration evidence.** This task specification was
> authored during the work it describes. It documents what was asked and when, for provenance
> and audit. It is **not** a pre-registered commitment, it was **not** sealed before the work,
> and it must **never** be cited as pre-registration evidence. The pre-registration is authored
> and sealed only per Part H, after the smoke gates pass.

Archived byte-for-byte (verified with `cmp` against the executed working copy at repo root,
which is removed in the same commit; no typo or formatting fixes applied), 2026-07-29:

| File | SHA-256 |
|---|---|
| `G11_TASK.md` | `589dc7d25290b991ec2dc2d213fb16e0ee9842e617cf45b4d06ce0be3660aac8` |

Chronology (2026-07-29, after the ADR 0016 freeze, G-2 and G-4 Phase 2 the same day): gate **G-11**
ran and **PASSED** — the gate that makes holder binding real. The §F.2 HTC/INV verifier was built at
`src/harness/verifier/` with **every MUST as a separately named check carrying its own reason code**,
so a rejection is attributable; commitments are **reused** from ADR 0003's `commitment.py`, never
reinvented. All **fourteen** named mutations were rejected **for the condition each targets**, and
both positive arms passed — including the **`n = 0` zero-hop case**, with the no-separate-path rule
asserted both behaviourally (no check runs only at `n = 0`) and structurally (an AST scan finding no
branch keyed on the chain length).

Two constructions the specification left open were adjudicated in **ADR 0018**: `access_token_hash`
(the §9 C2 proposal **adopted unchanged**, with a non-ASCII byte failing closed and the three-way
distinctness against `ath` — which consumes the *same* input bytes — and `H_JCS` pinned by test), and
the HTC/INV **signing input**, which is what makes §F.2's domain tags load-bearing in both
directions. The §F.2.1 identity-plane registry was built and frozen in **ADR 0019** as
`frozen_parameters` **row 11** (`H(R) = d1bfc5ff…`), fixing **structure and derivation labels rather
than key bytes** — the line ADR 0016 drew for `Γ`/`κ` — with a stated necessity per entry that the
loader enforces.

Together those closed **both of G-4's residual limbs**: **L4** (`INV.access_token_hash` verified
through the real verifier, a swapped token rejected) and **L3** (`actor→holder` re-run against the
frozen registry, outcome **unchanged**, which is what shows the C3 stand-in had not flattered the
finding). G-4 is therefore a full four-limb closure, and the record shows the **sequence** rather
than back-dating it.

Three findings came from running rather than reading, and all are recorded in `smoke/g11/REPORT.md`:
the identity-plane check was **masking `htc_chain_linkage`**, so a case was added to isolate it,
because a masked check is not a pass; a capability-swap rejects at `htc_prefix_hash` rather than
`htc_child_block_hash` (expectation corrected, not the code); and the Part G row's blanket "each
rejected" **cannot** apply to a *semantically equivalent* container re-encoding, which ADR 0003
requires to be **accepted** with the commitment unchanged — rejecting it would reintroduce the
false-rejection bug ADR 0003 was written to fix. Both halves were tested and **the Part G row was not
edited**. `label_assertions_digest` and `authz_context_hash` remain ADR 0009 category (c) for
**G-15**, and `IA-3` is untouched and stays **[UNVERIFIED-IA]** for **G-3**: this gate establishes
correctness, not cost. Verified on Windows: `pre-commit` clean, spike exit 0 (six mandatory checks),
`240 passed` (the pre-existing 183 plus 57 new platform-independent tests).
