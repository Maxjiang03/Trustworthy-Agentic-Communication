# TASK — Experimental body, block 4: the F3/F4/F5 families, the shared reference monitor, and gate G-15

Nine arms exist and ten gates pass. What the study can currently score is **F1** — scope
amplification — plus three `F2` subfamilies. **F3, F4 and F5 cannot be scored at all**, and the
reason is one unfixed construction: `authz_context_hash` has been ADR 0009 **category (c)** since
the beginning, deferred to *"the F4 label decision and G-15"*. That decision is this block.

Three families, and they are not equally ready:

- **F3** — `expired token` and `dpop-captured-proof-replay`. Both are constructible **today**, from
  parameters already frozen. No new design decision.
- **F4 / F5** — sensitive egress without declassification, and a high-risk action without approval.
  These need labelled fixtures, a `LabelAssertion` verification path, an `ApprovalArtifact`, and
  `authz_context_hash`. Rows 4, 6 and 10 are frozen (ADR 0022/0023) and enable the **refusal** half
  of both conjuncts; this block builds the **acceptance** half.

Then **G-15**, whose row is short and whose meaning is not: *"no cross-mechanism F4/F5 claim rests
on a monitor-configuration difference."* §E.4's `A†` cells mean **admitted absent the shared
monitor**. With the monitor, the OAuth arms block too — so **F4/F5 measure the monitor, not the
mechanism**, and reporting a monitor-configuration difference as a capability-versus-OAuth advantage
is precisely the error G-15 exists to prevent.

Four phases. **A** (STEP 3–5) freezes the label-plumbing decision. **B** (STEP 6–8) builds F3.
**C** (STEP 9–12) builds the monitor and F4/F5. **D** (STEP 13–14) adjudicates G-15. Each ends
green and committed; report between phases.

---

## STEP 0 — Self-check, and the machine (do this first, report both)

Run `wc -l` and `sha256sum` on this file. Expected: **the line count and digest quoted in the launch
prompt**. If either differs, **STOP and report**.

Confirm `pre-commit` is still installed as a git hook (`ls .git/hooks/pre-commit`). Two red pushes
in block 3 came from edits made after a manual hook run; the installed hook is the mechanism that
makes that impossible.

---

## STEP 1 — Forbidden in this pass

| # | Forbidden | Why |
|---|-----------|-----|
| 1 | **Measuring, benchmarking or reporting any latency number** | Rows 1/2/7 are set; that does **not** authorize measurement. G-3 owns timing, needs the row 9 sealed platform, and is **not in scope** |
| 2 | Running, preparing or marking G-3, G-9, G-12, G-14 or G-10; editing any Part G row, pass criterion, dependency edge or evidence grade | Only **G-15** is adjudicated here. Building an F3 replay fixture is **not** running G-9 or G-14 |
| 3 | **Flattening `A†` into a plain `A`, or letting the F1 arm grouping decide F4/F5** | `tests/test_nine_arm_matrix.py` derives grouping from a hardcoded `STRONG` tuple — correct for F1, where breadth is a **ladder property**; wrong for F4/F5, where the grouping is a **configuration condition** (monitor present or absent). Flattening it produces exactly the false claim G-15 forbids |
| 4 | Reporting **any** F4/F5 cross-mechanism difference without stating the monitor configuration it was measured under | §E.4's footnote is a MUST, not a caveat |
| 5 | Amending rows 4, 6 or 10, `Ω`/`Γ`, the registry, `H(Λ)`/`H(Γ)`/`H(R)`, or rows 1/2/3/7 | ADR 0016/0019/0022/0023/0025/0026/0027. `authz_context_hash` is a **new** construction, not an amendment to any of them |
| 6 | Setting row 5 or row 9 | Row 5 is deferred by decision (ADR 0028); row 9 is read at seal time |
| 7 | Building an F3 replay fixture **outside `Δ`** | ADR 0027's fixture constraint. Outside `Δ`, `B3` blocks on **freshness**, not duplication, and `B3⁺`'s entire cell collapses — in the direction that flatters this work |
| 8 | Letting a **new** check make an existing arm's distinguishing capability unobservable | The standing hazard of this project, four times over. See STEP 15 |
| 9 | Drafting `PRE_REGISTRATION.md`, creating `fixtures/confirmatory/`, sealing, or running a campaign | CLAUDE.md red lines 1–2 |
| 10 | Any import of `src/harness/` from `src/sut/`; of `src/sut/oauth_as/` from a non-AS `src/sut/` module or from `src/harness/`; reuse of a harness implementation as the SUT-side one | Red line 6, ADR 0015 rules 3–4, D13/D21 |
| 11 | Letting a SUT principal read `τ_gt`, `IntendedInvocation`, or any sealed object | §A.3, red line 5 |
| 12 | Secrets or minted tokens on disk, in the repository, or in `results/`; `git push --force`; history rewrite | Red lines 7–8 |

If a step cannot be completed as written, **stop and report the blocker**. Do not substitute a
weaker version and report it as done.

---

## STEP 2 — Read what you are implementing

**Part I in full** — `realized_harm_F3`, `realized_harm_F4`, `realized_harm_F5`,
`valid_declassification`, `valid_approval_binds`, `is_sensitive`, `is_high_risk`, and the
**no-/partial-/multi-effect MUST** (every predicate is over the effect **set**). Then **§F.1's**
`LabelAssertion`, `DeclassificationArtifact`, `ApprovalArtifact` and `EffectEvent` schemas;
**§F.2's** `authz_context_hash` line and the mechanism-neutral rationale beside it; **§A.6/§A.6.1**;
**§E.4's** F3/F4/F5 rows **and the `A†` footnote verbatim**; **§D.2's** four-way DPoP taxonomy;
the **Part G G-15 row verbatim**; and **ADR 0009's** three-way digest classification, since this
block closes its last category (c) field.

Then ADR 0022/0023 (what the frozen policy does and does **not** enable), ADR 0027 (the fixture
constraint), `src/sut/authz/capability_path.py`'s `_context_policy_ok` and `_approval_artifact_ok`,
`src/harness/schema.py`, and `src/harness/policy/frozen_policy.py`.

**Report what turns out underspecified for implementation, and what you did.** Every block has
found some. Do not invent to cover one.

---

# PHASE A — the label-plumbing decision

## STEP 3 — Fix `authz_context_hash` and the label-verification path (ADR 0030)

This is a **design decision**, not a derivation, and it is the last ADR 0009 category (c) field.
Write **ADR 0030** fixing all of it, following the ADR 0018 pattern — a versioned,
domain-separated, length-delimited construction over canonical bytes, with a worked example both
sides reproduce.

Fix, and state a necessity for each:

1. **`authz_context_hash`** over §F.2's named inputs — `task_id`, `audience`, `tool`,
   `canonical_request_digest`, `resource_owner`, `oauth_actor` — under its **own** domain tag.
   Check the tag against every tag in service and extend `_TAGS_IN_USE`. It **must** be
   mechanism-neutral: computable by an OAuth arm holding no capability token, since that is the
   entire reason §F.2 defines it this way and the only thing that makes the shared monitor possible.
2. **`LabelAssertion` verification** — what `payload_digest` is computed over, how `issuer_kid`
   resolves (the frozen registry, or a separate label-issuer set), and the `iat`/`exp` rule. §F.1
   says the construction is *"NOT `H_JCS`"* and defers it here; honour that, and say what it **is**.
3. **`DeclassificationArtifact`** and **`ApprovalArtifact`** — their signed payloads, their binding
   to `authz_context_hash`, and their `replay_rule`.
4. **`EffectEvent.data_labels_touched` and `value_id`** — how the ledger learns which labels an
   effect touched. The schema has the fields; nothing populates them.

**Two constraints on the decision itself, and they are not negotiable.** First, a label that is
merely *asserted* must never be believed: block 2 found `context_policy_ok` reading
`entry.get("label")` with nothing verified, and the fix was to refuse. The acceptance half must be
**verification**, not the removal of that refusal. Second, `Δ` (ADR 0027) governs any freshness
window these artifacts need — do **not** introduce a fourth window.

## STEP 4 — Make both conjuncts accept as well as refuse

`_context_policy_ok` and `_approval_artifact_ok` currently refuse everything they cannot verify.
Give each a verification path per ADR 0030, keeping the refusal for anything that fails it.

Then the check that matters, and it is the one this project keeps needing: **show that acceptance
did not become a hole.** For each conjunct, construct and test — an unsigned artifact, one signed by
an unregistered key, one bound to a *different* `authz_context_hash`, one outside `Δ`, and one
replayed against its `replay_rule`. Each must be refused **for the condition it targets**, not
merely refused.

## STEP 5 — Phase A checkpoint

Regenerate the pilot corpus and **verify no existing outcome moves**: the four scenarios carry no
labels and no artifacts, so nothing should reach the new acceptance paths. Any other difference is a
finding to report. `pre-commit` and `pytest` green; scoped commits; push; verify. **Report before
Phase B.**

---

# PHASE B — the F3 family

## STEP 6 — `F3 expired token`

An OAuth negative control. §E.4 predicts `A` for `B0`/`B1` and `B` for every arm that verifies a
token — including `B-cap`, per §E.1/E6's requirement that it verify audience and expiry.

Block 2 found the trap: a far-future `now` fails `Γ`'s own expiry check first and **masks** the
OAuth limb. Use the pattern that worked — a short-lived base token judged just after its expiry
while the capability's own window is still open — so the block is attributable to the **token's**
expiry. Report which conjunct or which limb fired for each arm.

## STEP 7 — `F3 dpop-captured-proof-replay`, and the constraint that guards it

§D.2: a complete valid method+URI proof plus the token, resubmitted **bit-identically**. §E.4
predicts `A` for every arm **including `B3`**, and `B` for `B3⁺` alone. Not blocked by DPoP (same
method and URI); blocked only by an authenticated-request-ID cache keyed on the `jti`.

**The fixture MUST be constructed within `Δ`** (ADR 0027, forbidden action 7). `B3⁺`'s test suite
already demonstrates both halves — the replay inside `Δ` caught by duplication, the same replay at
`now + 61` blocked by `B3` on freshness. Reuse that demonstration here rather than rebuilding it,
and assert the fixture's construction satisfies the constraint rather than assuming it.

## STEP 8 — Wire F3 through the oracle, and Phase B checkpoint

`realized_harm_F3` compares **three** digests — sealed-intended, independently-observed, and
actual-effect — *precisely so a tampered observation is caught*. Implement it that way; never
compare an effect against a possibly-tampered observed digest alone.

Note in the report, without changing code, that `obs.raw_arguments` is still a canonical
re-serialization rather than captured bytes (§J.5 item 20) — harmless in-process, load-bearing once
an SDK adapter exists, and **G-12's** to close.

Extend the matrix to the two F3 rows over all nine arms; compare cell by cell with §E.4. Commit,
push, verify. **Report before Phase C.**

---

# PHASE C — the shared reference monitor, F4 and F5

## STEP 9 — The boundary-owned monitor, shared by construction

§F.2 makes `authz_context_hash` mechanism-neutral so that **one** monitor can serve every arm. Build
it that way: a **boundary-owned** component, taking the frozen policy and the presented artifacts,
usable by an OAuth arm and a capability arm **without modification**. If it can only be attached to
`B3`, the comparison G-15 governs is impossible.

Attachment is **configuration**, not an arm property: an arm runs `monitor_attached ∈ {true, false}`
and its trace records which. This is what makes `A†` expressible rather than flattened.

## STEP 10 — F4 and F5 fixtures

**F4** — a sensitive-labelled payload egressing without a valid `DeclassificationArtifact`.
**F5** — a high-risk action (`mail.send` or `notes.delete`, row 10) without a valid
`ApprovalArtifact`.

Each needs a **labelled** scenario: `LabelAssertion`s the boundary can verify, and effects whose
`data_labels_touched` the ledger records. Both are sealed-truth-bearing, so the SUT-visible and
sealed documents stay separated exactly as the existing corpus separates them.

Include a **benign labelled control** in each family — a valid artifact that **is** accepted — or
"the monitor blocks" is indistinguishable from "the monitor blocks everything."

`C_0`/`C_1` computed by the frozen authorizer as always. Verify the four existing scenarios are
**byte-identical** after regeneration.

## STEP 11 — Score F4/F5 under **both** configurations

Run each F4/F5 fixture over all nine arms **twice**: `monitor_attached = false` and
`monitor_attached = true`. That is the whole point — one number without the other cannot support or
refute anything §E.4 predicts.

Expected, per §E.4: **without** the monitor, `A†` for the OAuth arms and `B` for `B3`/`B3⁺`;
**with** it, the OAuth arms block too. Report both configurations for every cell, and label each
number with the configuration it was measured under.

## STEP 12 — Restructure the matrix grouping, and Phase C checkpoint

Replace the hardcoded `STRONG` tuple with **per-family grouping**. F1's grouping stays a ladder
property; F4/F5's is a **configuration condition** and must be expressed as one. A test should fail
if an F4/F5 cell is ever recorded without its monitor configuration.

Commit, push, verify. **Report before Phase D.**

---

# PHASE D — gate G-15

## STEP 13 — Adjudicate

The criterion: *F4/F5 comparisons run only among `B3` and its matched ablations, **or** with the
same reference monitor on the OAuth arms.* Establish:

1. **Monitor identity** — the OAuth arms and `B3` run the **same** monitor over the **same** frozen
   policy, structurally (same object or same class, asserted), not by inspection.
2. **Both configurations measured** for every F4/F5 cell.
3. **No cross-mechanism claim rests on a configuration difference.** A test should fail if a
   reported comparison mixes `monitor_attached = true` on one arm with `false` on another.
4. **Every check shown able to fail.** Construct the worlds: a monitor attached to `B3` only, and a
   comparison that mixes configurations. Both must be caught by the gate's **own** predicate.
5. **The `A†` semantics survive** — an `A†` cell recorded without its configuration is caught.

Standard shape: `smoke/g15/spike.py`, `smoke/g15/REPORT.md`, `make gate GATE=g15`. It touches the
policy and the boundary but not the effect ledger — **confirm** platform-independence by running it,
then wire it into CI beside G-4, G-11 and G-13.

## STEP 14 — Adjudicate honestly, and name the residual

**PASS** only if all five hold. If any cannot be honestly adjudicated, **do not mark PASS**: say
which, why, and the smallest correction.

State the residual plainly: with the shared monitor, **F4/F5 measure the monitor rather than the
mechanism**, so no capability-versus-OAuth advantage may be claimed from them either way. That is
not a limitation to be minimised — it is the finding, and it belongs in the results chapter in
those words.

`IA-3` and `IA-9` stay `[UNVERIFIED-IA]`; no other gate's row moves. Update `smoke/README.md`'s
G-15 row and any §F.4 cell this closes, with dated update notes rather than rewrites.

---

## STEP 15 — The standing check: did a new check make an old capability unobservable?

Four blocks running, the same hazard has appeared four times: a label read unverified, a base grant
silently misprovisionable, a freshness window that would have masked `B3⁺`, and an `A†` grouping
that would flatten. Each was dormant, would have become load-bearing later, and **failed toward the
hypothesis**.

This block adds a monitor, an acceptance path and three artifact types. Before reporting, ask
explicitly of **each** arm: *does it still distinguish itself where §E.4 says it does?* In
particular — does `B3` still block F4/F5 for the reason §E.4 attributes, or does an artifact check
now fire first? Does `B3⁺` still uniquely block the F3 replay? Do the OAuth arms still **admit**
where `A†` says they should, absent the monitor? **Report the answer per arm.** A capability that
has become unobservable is indistinguishable, in the results, from one that was never there.

---

## STEP 16 — Commit, push, archive

Scoped Conventional Commits, ADRs referenced in bodies. Archive this spec under
`docs/tasks/archive/exp4-f345-monitor/` with the standing note that task specs are **retrospective
records, NOT pre-registration evidence**, and remove the working copy in the same commit. Push;
verify with `git ls-remote origin main`.

---

## STEP 17 — Stop and report

1. STEP 0 self-check and the git-hook confirmation.
2. The STEP 2 read, and anything **underspecified for implementation**, with what you did.
3. **Phase A:** ADR 0030 — every construction it fixes, the tag distinctness check, the worked
   example, and how the acceptance half is **verification** rather than removed refusal. The five
   negative artifact cases, each refused for the condition it targets.
4. **Phase B:** F3 expired-token, with the conjunct or limb that fired per arm and how `Γ`-expiry
   masking was avoided. F3 replay, with the evidence its fixture sits **within `Δ`**. The
   three-digest `realized_harm_F3`.
5. **Phase C:** the monitor — how sharing is structural rather than duplicated. The labelled
   fixtures and their benign controls. The **full F4/F5 matrix under both configurations**, every
   cell labelled with its configuration, compared to §E.4 including the `A†` semantics.
6. The regrouped matrix, and the test that fails when a configuration label is missing.
7. **Phase D:** G-15's five checks, each with the world in which it fails. The adjudication, and the
   residual stated in the words STEP 14 uses.
8. **STEP 15's answer, per arm.**
9. Confirmation that no timing number was produced, no test sleeps, and no secret reached disk, the
   repository or `results/`.
10. Commits, push verification, counts on both platforms, and anything you could **not** verify.
11. Any point where you were tempted to fill a gap by assumption, to adjust a cell toward the
    prediction, to report an F4/F5 difference without its configuration, or to weaken a refusal in
    order to make an acceptance path work — and what you did instead.
