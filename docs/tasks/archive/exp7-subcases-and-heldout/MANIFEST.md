# EXP7 subcases, held-out and last-decisions task-specification archive — MANIFEST

> **Retrospective records — NOT pre-registration evidence.** This task specification was
> authored during the work it describes. It documents what was asked and when, for provenance
> and audit. It is **not** a pre-registered commitment, it was **not** sealed before the work,
> and it must **never** be cited as pre-registration evidence. The pre-registration is authored
> and sealed only per Part H, after the smoke gates pass.

Archived byte-for-byte (verified with `cmp` against the executed working copy at repo root;
no typo or formatting fixes applied), 2026-08-02:

| File | Lines | SHA-256 |
|---|---|---|
| `EXP7_TASK.md` | 283 | `30164711bcdf5d03e490d0bf70cc9a7404136d516d9b49838242163ed2982bca` |

*A first, 235-line revision of this spec was read and reported on without code being written; its
Phase A design findings were verified by the Commander and folded into the 283-line revision
archived here. That sequence is recorded because it is the reason the two-level fault design was
corrected before it reached the corpus rather than after.*

## What the block produced

**The oracle now has everything §E.4 asks it to score**, and the last decisions standing between
the apparatus and Part H's seal loop are closed.

| ADR | What it settles |
|---|---|
| [0034](../../../../adr/0034-the-campaign-is-single-process-and-b3-plus-keeps-the-in-process-cache.md) | The campaign is **single-process**; `B3⁺` keeps the in-process cache. A green G-9 does **not** license "the ladder arm has multi-process atomicity" |
| [0035](../../../../adr/0035-e4-f2-invalid-credential-b0-is-a-not-na.md) | §E.4's `F2 invalid_credential` `B0` cell: `NA` → **A**; the adopted **`NA` test**; and `B1`'s missing secret plane |
| [0036](../../../../adr/0036-reference-allow-needs-a-credential-family-gate.md) | `reference_allow`'s **credential family gate**, and the **credential-binding re-mint rule** |
| [0037](../../../../adr/0037-the-held-out-third-is-cut.md) | The **held-out third is cut**; Phase B cancelled, not deferred |

**Five §E.4 subcases promoted from arm unit tests to corpus scenarios**, scored over nine arms from
the **oracle** through the campaign entry point: `F2 invalid_credential`, `F2 unauthenticated_caller`,
`F2 wrong_holder_proof`, `F3 dpop-stolen-AT-key-substitution`, `F3 audience mismatch`. The corpus is
now **13 scenarios, 27 documents**. **Every cell agrees with §E.4; there were no disagreements.**

## Findings the block reported rather than smoothed over

- **The two-level fault design was wrong**, and building it proved it. `B2ExchangeTaskArm.provision`
  verifies the injected subject token and raises before the boundary is reached, so a
  provisioning-level corruption tests the arm's **configuration** and produces no `MediationEvent`.
  §D.2 had said so all along: its adversaries **hold a captured credential and present it**. All
  five faults are presentation-level.
- **Part I's `reference_allow` had no credential gate** (ADR 0036). Every credential subcase runs
  the benign call, so `R ⊆ C_n` held, `admission_breach` was structurally `False`, and
  `realized_harm_F2` needs an effect — so an arm admitting a forged credential whose tool then
  failed **scored completely clean**.
- **The INV's token binding pre-empted the credential conjunct.** `B3`/`B3⁺` blocked at
  `b3_invocation_binding`; the general rule now recorded is that **any presented artifact binding
  the credential being substituted must be re-minted under the arm's own key**. `B-cap` — same
  decision path, no INV — was the control that diagnosed it.
- **`B1`'s secret plane is systematically absent from this project's abstractions**: no §E.5 bit, no
  fault-vocabulary term. Twice, and both times the absence produced a wrong answer about `B1` that
  looked like an answer about something else.
- **An intermittent `test_b_cap.py` failure** was the two-clocks shape a fourth time, fixed by
  deriving both instants from the token's own claims rather than the wall clock.
- **The `NA` reason was replaced, not just the cells**: artifact-absence is a fact about the
  **mechanism**; would-be-identical-instance is a fact about the **corpus** — and `NA` is a statement
  about the corpus.

## Scope note

STEP 3–5 and 8–11 delivered; **Phase B (STEP 6–7) is cancelled by ADR 0037**, not left undone. What
the block did **not** do: **no timing number was produced anywhere**; **no gate was run, prepared or
marked** and no Part G row moved; `IA-3` stays `[UNVERIFIED-IA]`; no frozen row, `Ω`/`Γ`, registry,
policy document or `H(·)` was amended; row 5 stays deferred (ADR 0028) and row 9 unset;
`fixtures/confirmatory/` carries no scenario; and `PRE_REGISTRATION.md` remains a stub — it gained
only a dated record of the ADR 0037 cut, which is Part H step 2's input, not its draft.
