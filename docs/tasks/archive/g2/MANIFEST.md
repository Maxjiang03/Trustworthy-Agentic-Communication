# Gate G-2 task-specification archive — MANIFEST

> **Retrospective records — NOT pre-registration evidence.** This task specification was
> authored during the work it describes. It documents what was asked and when, for provenance
> and audit. It is **not** a pre-registered commitment, it was **not** sealed before the work,
> and it must **never** be cited as pre-registration evidence. The pre-registration is authored
> and sealed only per Part H, after the smoke gates pass.

Archived byte-for-byte (verified with `cmp` against the executed working copy at repo root,
which is removed in the same commit; no typo or formatting fixes applied), 2026-07-29:

| File | SHA-256 |
|---|---|
| `G2_TASK.md` | `2fc1c67940a9de233f2762f247427a5ef1cda8e0c6604c929b24eecac40182ae` |

Chronology (2026-07-29, the same day as the ADR 0016 freeze it adjudicates): gate **G-2** ran and
**PASSED** — the **first pass in the project to run a Biscuit authorizer with policies**, G-1
having verified only the `crypto_chain_ok` mechanics and explicitly deferred the authorizer here.
Criteria (a)–(d) were executed against the frozen `Ω`/`Γ` with every `C_i` **computed** by one
authorizer run per candidate per prefix (`src/harness/authorizer/allowed.py`), never asserted, and
with prefix identity taken from ADR 0003's `BlockID_i`/`commit_prefix` so this gate and G-1 cannot
drift apart. Each check was built so the wrong outcome would be observable as a failure, and each
carries its own negative control. Two construction defects in the spike's own probes were found and
**fixed rather than accommodated** before any result was recorded; **no criterion was weakened**.
The load-bearing finding for (b): the pinned library **verifies third-party tokens under `κ_pub`
alone**, so out-of-profile rejection is load-bearing project code rather than an inherited
guarantee. **IA-2 moved from [UNVERIFIED-IA] to verified by gate G-2**, scoped to
`biscuit-python==0.4.0` and to these frozen bytes — any `Ω`/`Γ` amendment or library bump
re-triggers the gate. The frozen artifact, `Ω`, `Γ`, the ablation delta and `H(Γ)` were left
**byte-intact**, and **no** `frozen_parameters` row was set: STEP 7 **registered** row 10 (the
oracle classification policy — the high-risk action set and the sensitive-label set) with value
**UNSET**, a registration and not a decision. Recorded in `smoke/g2/REPORT.md`. Verified on
Windows: `pre-commit` clean, spike exit 0 (nine mandatory checks), `105 passed` (the pre-existing
63 plus 42 new platform-independent tests).
