# EXP3 full-ladder task-specification archive — MANIFEST

> **Retrospective records — NOT pre-registration evidence.** This task specification was
> authored during the work it describes. It documents what was asked and when, for provenance
> and audit. It is **not** a pre-registered commitment, it was **not** sealed before the work,
> and it must **never** be cited as pre-registration evidence. The pre-registration is authored
> and sealed only per Part H, after the smoke gates pass.

Archived byte-for-byte (verified with `cmp` against the executed working copy at repo root;
no typo or formatting fixes applied), 2026-07-31:

| File | Lines | SHA-256 |
|---|---|---|
| `EXP3_TASK.md` | 291 | `4777ce9557965d0e262a6f76b5f218eeca71cf68f9377732ed4427d8dac6c3fe` |

Four Commander-approved ADR drafts were supplied alongside it and landed byte-for-byte with only
their Status line changed: **0025** (rows 7 and 2), **0026** (row 1 and the measured segment),
**0027** (row 3 and the replay-cache budget), **0028** (row 5 deferred, `F2 wrong_principal`
unscored). Their values were decided and were not this pass's to change.

## Chronology (2026-07-31, after EXP2's strong-baseline block)

The **third pass of the experimental body**. It completed §E.1's nine-arm ladder and closed
G-13's two open limbs — the arms whose absence had forced G-13 to pass over three of five.

**Phase A** (STEP 3–7) landed the four ADRs, taking `frozen_parameters` from 5 of 11 set to
**9 of 11 set, 1 deferred by decision, 1 read at seal time**; added ADR 0026's `presentation`
seam with its extents asserted structurally; bounded the audit sink; discharged ADR 0028's four
documentation obligations (two of them **recorded rather than discharged**, and named as such);
and cleared two carried observations.

**Phase B** (STEP 8–12) built `B1`, `B2-broad-noexchange`, `B2-exchange-broad`,
`B2-exchange-task-DPoP` and `B3⁺`, and pinned the full nine-arm × four-scenario matrix, which
agrees with §E.4 in **every cell**.

**Phase C** (STEP 13–14) re-adjudicated **G-13 over all five strong baselines**: 38 per-hop
equalities over 20 cells, 18 arm-chains realizing an identical `C_0 → C_1`, all 3 × 5 F1 cells
blocked with attributable causes, and eight would-have-failed worlds. **Both limbs closed.**
`smoke/g13/REPORT.md`.

## Five findings from running rather than reading

1. **ADR 0027's `Δ` contradicted two of the three consumers it named.** `src/sut/dpop.py`
   carried a hard-coded 300 s DPoP window and INV freshness at the boundary had no
   `|now − iat|` rule at all, so setting row 3 to 60 s without rewiring them would have made the
   frozen record a fiction. `src/sut/freshness.py` now holds the window once, named for the
   window rather than for any one consumer.
2. **That new INV freshness window can MASK `B3⁺`, in the direction that flatters the
   hypothesis.** §E.4 predicts `F3 dpop-captured-proof-replay` as `B3` = A and `B3⁺` = B, and
   that single cell is `B3⁺`'s entire reason to exist. A replay constructed **outside** `Δ`
   would be blocked by `B3` too — on freshness, not on duplication — collapsing the distinction.
   The constraint that the fixture must be built **within** `Δ` is now recorded in ADR 0027's
   Consequences, in §E.4 and in §J.2 item 9, **and demonstrated** by a test that shows the
   collapse happening at `now + 61`.
3. **The code cited §F.2 for a rule §F.2 does not contain.** §F.2's Verification MUST list has
   `every nbf ≤ now ≤ exp` and no freshness rule; the check comes from ADR 0027. §F.2 now states
   the distinction once: it defines what makes an artifact **valid**, while freshness is a
   **boundary acceptance policy**. The consequent asymmetry — the harness verifier deliberately
   has no freshness check — is declared, and the D21 agreement suite records that it now covers
   a **strictly smaller** set of conditions than the SUT implements.
4. **ADR 0024's grant rule pointed the wrong way for the broad arms.** §E.4 predicts they
   **admit** `F1-root`, whose element lies outside `U_task`, so on a task-scoped token they
   would have blocked it — destroying the arm whose whole job is to isolate the exchange round
   trip *from* narrowing. **ADR 0029** settles it: the §E.1 **row**, not the client identity,
   determines the grant, as an explicit named per-arm input checked against the arm's own
   declaration. Delegating the broad arms from a different principal was rejected because
   `may_act` would change as a side effect and the arms would then differ in two respects.
5. **`B3⁺` made a new G-13 world constructible.** It is the first arm that can deny a request
   whose authority is identical to an admitted one. **L2.W2** shows a replay-cache denial leaves
   `Allowed(P_i)` untouched, so the gate does not report it as a granularity mismatch — the
   precise confusion matched fairness exists to prevent.

## Two process failures, and the mechanism that closes them

Two pushes in this pass were red on arrival, and **both came from an edit made after the hooks
ran**: a late docstring change and a late line-wrap, each committed on the strength of a hook run
that predated it. "Re-run the hooks last" is a promise; `uvx pre-commit install` is a
**mechanism** — the git hook fires on `git commit` itself, so a post-hook edit cannot slip
through. Installed and verified by a probe commit that the hook **refused**, leaving `HEAD`
unchanged. This changes no tracked file.

## What this pass deliberately did NOT do

Only **G-13** was adjudicated, and only its own row moved. **No timing number was measured,
benchmarked or reported anywhere** — rows 1, 2 and 7 fix bars and denominators *before* any
measurement, exactly as Part H step 2 requires, and `IA-3` stays `[UNVERIFIED-IA]` until G-3 runs
on the row 9 platform, which is not locked. **`IA-9` stays `[UNVERIFIED-IA]`**: `B3⁺` carries a
`jti` cache, and building it is **not** running G-9 — the cache is atomic within one process and
has no backend, so G-9's multi-process criterion and its induced-backend-error path are untested,
and `src/sut/authz/jti_cache.py` says so. **No test sleeps.** Row 5 is deferred by decision and
row 9 is untouched. F3/F4/F5 fixtures, the shared reference monitor, `authz_context_hash` and the
attack suite are **not** built; the F4/F5 grouping hazard is recorded as a forward note in
`tests/test_nine_arm_matrix.py` rather than acted on. `fixtures/confirmatory/` stays empty and
`PRE_REGISTRATION.md` is not drafted. The §E.6 matched ablations are not built.
