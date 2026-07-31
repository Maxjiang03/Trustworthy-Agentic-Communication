# EXP2 strong-baselines task-specification archive — MANIFEST

> **Retrospective records — NOT pre-registration evidence.** This task specification was
> authored during the work it describes. It documents what was asked and when, for provenance
> and audit. It is **not** a pre-registered commitment, it was **not** sealed before the work,
> and it must **never** be cited as pre-registration evidence. The pre-registration is authored
> and sealed only per Part H, after the smoke gates pass.

Archived byte-for-byte (verified with `cmp` against the executed working copy at repo root;
no typo or formatting fixes applied), 2026-07-31:

| File | Lines | SHA-256 |
|---|---|---|
| `EXP2_TASK.md` | 358 | `f3ca68348b77ede33abcb2302b2d9aa1283bf3590fe53584335a678430b00d6b` |

## Chronology (2026-07-31, after EXP1's golden thread)

The **second pass of the experimental body**, and the first since G-11 to adjudicate a gate. It
froze three seal-time parameters, built the middle of the strong-baseline set, and ran **G-13**.

**Phase A** (STEP 3–8) froze `frozen_parameters` rows **4, 6 and 10** as one loadable document
hashed under its own domain tag (`H(Λ)`, ADR 0022), replaced the PILOT-PROVISIONAL stand-in so
the two policy conjuncts became load-bearing in their **refusal** half, gave CI real coverage of
the golden thread by splitting the ledger-gated assertions from the rest (no fallback, no stub —
ADR 0014's ledger refuses to degrade), bound `disabled` to a declared arm identity so `B3`
proper can no longer silently carry an ablation, and replaced the textual
authorizer/containment discriminator with a **structural** one evaluated against `P_0`.

**Phase B** (STEP 9–12) built `B2-exchange-task` and `B-cap`, added the fourth pilot scenario
`gt-f1-chain-tamper`, and pinned the full matrix cell by cell against §E.4 — which it matches
everywhere, with `B0`'s two admissions the measured phenomenon rather than a bug.

**Phase C** (STEP 13–16) built the independent verifier at
`src/harness/verifier/matched_authority.py` and adjudicated **G-13**: 23 per-hop equalities over
12 cells, identical `C_0 → C_1` across the three strong arms, all 3 × 3 F1 cells blocked with
attributable causes, D21 adjudicated, and **every equality shown able to fail** by seven
constructed worlds each judged by the gate's *own* predicate. `smoke/g13/REPORT.md`.

## Three findings from running rather than reading

1. **A coarse Phase-1 base token would have silently cost `B2` a block.** §E.2 says the base
   `AT@aud` expresses no delegation authority, and the pilot provisioned it as the whole frozen
   `Ω`. But the pinned AS enforces `C_i ⊆ C_{i−1}` against the **subject token's own** grant, so
   with a coarse base token the AS would have **issued** an `F1-chain-tamper` widening to
   `(mail.send, mail/outbox)` — an element inside `Ω` — and `B3` would have appeared to win a
   comparison it did not win. **ADR 0024** narrows the *delegating client's* base token to
   `C_0 = U_task`, the OAuth analogue of §A.3's "the AS mints `U_task` as `P_0`". Confirmed by
   measurement, and the counterfactual is now a permanent test recorded as a **result** about
   token exchange under agent delegation, not merely a regression guard.
2. **The fix initially sat with the CALLER, which is not the same as being safe.** `task_grant`
   is opt-in and its default is the dangerous value, so every new call site was a chance to lose
   the guarantee in the direction that flatters the hypothesis. The guarantee moved into the
   ARM: `B2ExchangeTaskArm.provision` reads the authority of the token it actually holds and
   refuses unless it equals the run's `U_task`. Being correctly provisioned today is not the
   same property as being impossible to misprovision.
3. **Rows 4 and 6 do not compose.** ADR 0022's first reading took "the more restrictive of the
   two planes", which falsified **two of the frozen artifact's own necessity statements**: it
   escalated ordinary internal traffic, and left `escalate` surviving only in the cell meant to
   permit. **ADR 0023** corrects it — row 6 is the permit whitelist, row 4 supplies the severity
   of a pair that is not whitelisted, exactly one verdict per cell. The two rows answer different
   questions (*whether* versus *how severe*), so reconciling them was a category error. No pilot
   outcome moved, verified three ways.

## Two process failures worth recording

1. **`main` was pushed red and reported clean.** `uvx pre-commit run --all-files` — the exact
   command CI runs — failed at `8a58494`: three E501 and three files the format hook rewrote
   **in place** without the rewrites ever being staged. The report said "pre-commit clean",
   which was true of a working tree the hook had already fixed. Corrected, and the procedure
   changed: stage → run hooks → **re-stage what they fixed** → run again → confirm no unstaged
   modification remains among the staged paths → commit, then verify the pushed HEAD in a clean
   worktree.
2. **A "purely formatting" commit initially swept in new tests.** Caught before pushing, reset
   (unpushed, no remote history rewritten) and redone so the message describes what the commit
   actually contains.

## What this pass deliberately did NOT do

Only **G-13** was adjudicated. No Part G row, pass criterion, dependency edge or evidence grade
was edited — the gate's *status* lives in `smoke/README.md`, and §F.4 gained only **dated update
notes** closing two residuals G-13 owned. `IA-3` is untouched and stays `[UNVERIFIED-IA]` for
G-3. **No latency, throughput or overhead number was measured, benchmarked or reported
anywhere** — STEP 9's anti-bias requirements are asserted *structurally*, by construction,
identity and call count. `frozen_parameters` rows 1, 2, 3, 5, 7 and 9 stay UNSET, so F2
`wrong_principal` stays unscored. No frozen artifact from ADR 0016/0019 was modified.
`fixtures/confirmatory/` stays empty and the generator refuses to run otherwise. `B1`,
`B2-broad-noexchange`, `B2-exchange-broad`, `B2-exchange-task-DPoP`, `B3⁺`, the jti cache and
every §E.6 ablation arm are **not** built — and G-13's report says so, marking the two unbuilt
strong arms' limbs **open** rather than inherited.
