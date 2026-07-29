# TASK — Gate G-2: adjudicate the frozen `Γ` against the pinned Biscuit library (IA-2)

G-2 is the first pass that **runs a real Biscuit authorizer with policies**. G-1 deliberately did
not — it verified mint, offline append, `κ_pub`-only verification, prefix stability and
append-detection for `biscuit-python==0.4.0`, and its own docstring records that it "does NOT run
an authorizer with policies (that is G-2)". So this gate turns IA-2 from `[UNVERIFIED-IA]` into an
adjudicated result, and it does so against the `Ω`/`Γ` **just frozen in ADR 0016** — not a
stand-in. Its pass criteria are frozen in the Part G G-2 row; this pass **executes** them, it does
not edit them.

What rides on it, in the row's own words: *"IA-2; the entire F1 prevention claim."* If the frozen
`Γ` does not actually hold `C_i ⊆ C_{i−1}` under the real library, the central security result has
no floor. That is why the criterion is *(a)–(d) all hold; every `C_i` computed over `Ω` by the
frozen `Γ`, **not asserted**.*

This task also registers **one** new frozen-parameter row for the unowned oracle policies the
`Ω`/`Γ` freeze exposed (STEP 7). That is a one-line registration, value UNSET — not a decision of
its contents.

---

## STEP 0 — Self-check (do this first, report the result)

Run `wc -l` and `sha256sum` on this file. Expected: **the line count and digest quoted in the
launch prompt**. If either differs, **STOP and report** — do not act on a partial spec.

---

## STEP 1 — Forbidden in this pass

| # | Forbidden | Why |
|---|-----------|-----|
| 1 | Editing the G-2 pass criteria, its dependency edges, or the Part G row | The gate executes frozen criteria; it never rewrites them |
| 2 | Modifying the frozen artifact `src/harness/authorizer/omega_gamma_v1.json`, `Ω`, `Γ`, the ablation delta, or `H(Γ)` | ADR 0016 froze these. If the gate reveals a genuine defect, **STOP and report it for a corrective ADR** — do not silently patch the frozen bytes |
| 3 | Setting or drafting values for **any** `frozen_parameters.md` row, including the new one from STEP 7 | Row 8 is set; every other row stays UNSET. STEP 7 registers an empty row, it does not fill it |
| 4 | Weakening a check to make it pass — accepting an authorizer error as a "pass", catching a rejection you expected to be a rejection and reporting the family as adjudicated when it was not exercised | A gate that cannot fail proves nothing (the G-8 discipline: a real vector must be able to reject) |
| 5 | Pinning any new dependency or editing the `# PENDING GATE` block | `biscuit-python==0.4.0` is already pinned (ADR 0002); nothing new is pinned here |
| 6 | Writing arm implementations, the AS, HTC/INV, agents, protocol adapters, or the oracle | G-2 is an authorizer-semantics gate; it needs tokens and an authorizer, nothing downstream |
| 7 | Sealing a token, or relying on seal in any check | ADR 0002: this design never seals; G-2 must not smuggle it back |
| 8 | Running or adjudicating any other gate (G-4, G-11, …) | One gate at a time |
| 9 | `git push --force`, history rewrite, credentials in the repo | CLAUDE.md red lines 7–8 |

If a step cannot be completed as written, **stop and report the blocker**. Do not substitute a
weaker version and report it as done. In particular, if a criterion turns out **not to be honestly
adjudicable** against the frozen `Γ` as written, say so and stop — as G-4 Phase 1 did with the
`access_token_hash` limb — rather than reporting a pass.

---

## STEP 2 — Read what G-2 adjudicates

Read, and confirm each in the report:

- **The Part G G-2 row, verbatim** — criteria (a)–(d), the "computed not asserted" clause, and the
  sentence binding G-2's `Allowed(P_i)` and G-1's commitment scheme to the **same** ADR 0003 /
  §A.0.1 `BlockID_i` / `commit_prefix`, so the two cannot drift apart.
- **ADR 0016** — the frozen `Ω` (seven elements, the string encoding), the frozen `Γ` (its Datalog,
  the authority-block and attenuation-block templates, `trusted_keys:[kappa]`,
  `third_party_blocks:reject`, `trusting_annotations:forbidden`, default block scoping), the
  matched `−attenuation` delta (`differs_in_exactly:["evaluation.prefix"]`, `override P_0`), and
  the per-criterion rationale ADR 0016 §"(a)–(d)" already argues on paper — **G-2 tests those
  arguments against the library.**
- **ADR 0002** — the Biscuit profile: no third-party blocks, `trusting` forbidden, never sealed,
  and the three project-owned mechanisms that make seal redundant.
- **ADR 0003 / §A.0.1** — `P_i`, `BlockID_i`, `commit_prefix`, and that hashes cover `P_i` (the
  immutable signed-block prefix), never the mutable proof tail.
- **§A.6.1 / §F.3** — monotone attenuation and `INV-2`.
- **`smoke/g1/spike.py`** — specifically its statement that it runs **no** authorizer with
  policies, and which capability operations G-1 already verified, so G-2 neither repeats G-1 nor
  assumes anything G-1 left to G-2.
- **`src/harness/authorizer/frozen_config.py`** — the existing loader/validator/`h_gamma`, which
  G-2 **uses** to obtain the frozen bytes rather than re-deriving `Ω`/`Γ` inline.

State in the report: this is the **first** authorizer-with-policies run in the project, and the
`biscuit-python` authorizer surface it will use is real (`AuthorizerBuilder`, `Authorizer.authorize`,
`Policy`, `Fact`, `Rule`, `ThirdPartyBlock`). Confirm the pinned version is `0.4.0` and unchanged.

---

## STEP 3 — Build the `Allowed(P_i; Γ, κ, Ω)` evaluator the criteria require

The row demands every `C_i` be **computed over `Ω` by the frozen `Γ`**. Implement exactly the
evaluation ADR 0016 specifies: for a presented token prefix `P_i`, run **one authorizer per
element of `Ω`** — inject `operation(<action>,<resource>)` for that candidate plus `time`,
`request_audience`, `request_task` as **authorizer facts** (never token facts), load `Γ`'s Datalog,
and place `x ∈ C_i` iff that run selects `allow`; no policy match ⇒ deny. `C_i` is the set of
candidates that pass.

Requirements:

- The evaluator reads `Γ` and `Ω` **from the frozen artifact via `frozen_config.py`**, so what G-2
  adjudicates is the sealed bytes, not a paraphrase. If the loader is missing a helper the
  evaluator needs, add it to `frozen_config.py` **without changing the artifact or `h_gamma`**, and
  say so.
- Prefix identity and any prefix commitment used here **MUST** be the ADR 0003 / §A.0.1
  `BlockID_i` / `commit_prefix` construction — the same one G-1 used and `commitment.py` implements.
  Do not introduce a second notion of "the prefix". State how the evaluator obtains `P_i` and that
  it matches G-1's.
- The authority block and each attenuation block are built from ADR 0016's **templates**, one
  `right(...)` per element of `C_0` and one `scope(...)` + its consuming `check` per element of
  each `C_i`, the check and its facts in the **same block** so default scoping trusts them.
- Place this evaluator in `src/harness/` (the instrument). `src/sut/` must not import it.

Report the evaluator's location and the exact fact-injection shape.

---

## STEP 4 — Execute criteria (a)–(d), each able to fail

Write `smoke/g2/spike.py`, matching the established spike shape (a `RESULTS` table of
`(check, mandatory, passed, evidence)`, an explicit exit code, no authorizer state leaking across
checks). Each criterion must be constructed so that the **wrong** outcome is observable as a
failure — a criterion that cannot fail is not evidence.

- **(a) appended widening fact — verifies cryptographically AND leaves `C_i ⊆ C_{i−1}`.** Take a
  legitimate chain, append a block carrying a widening `right(...)` (an element in `Ω` but outside
  `C_{i−1}`). Show two things separately: the token **still verifies** under `κ_pub` (the append is
  cryptographically valid — a real Biscuit token), **and** the computed `C_i` (from STEP 3) still
  satisfies `C_i ⊆ C_{i−1}` — the widening fact is trusted by nothing, per ADR 0016 §(a). The
  failing world — where `C_i ⊄ C_{i−1}` — must be what the assertion would catch. Also include the
  legitimate narrowing case (a `scope(...)` that genuinely drops authority) and show `C_i ⊊
  C_{i−1}` strictly, so monotonicity is exercised in both the "stays contained under attack" and
  "actually narrows when legitimate" directions.
- **(b) third-party block / `trusting {attacker_key}` — rejected as out of profile.** Construct (or
  if the library will not let you append one without the machinery, construct as far as the library
  allows and record precisely where it stops) a third-party block, and separately a `trusting
  {attacker_key}` annotation. Show each is **rejected** — structurally/pre-evaluation per ADR 0016
  §(b), citing the exact exception or rejection point with the `biscuit-python` surface that raises
  it. If the library refuses to build the malicious token at all, that **is** the rejection; record
  which layer refused (builder vs. authorizer) rather than reporting a generic pass.
- **(c) `Γ` mutation broadening trust — detected via `H(Γ)`.** Programmatically mutate a **copy** of
  the frozen document in memory (add a trusted key; flip `third_party_blocks` to accept; permit
  `trusting`; edit the Datalog; add an `Ω` element) — **never touch the on-disk artifact** — and
  show each mutation changes `H(Γ)` computed by `frozen_config.h_gamma`. Confirm the on-disk digest
  still equals row 8 afterward, so the gate left the frozen bytes intact.
- **(d) `−attenuation` control admits what full `B3` blocks.** Load the matched ablation via its
  delta, materialize both authorizers, and show on the **same** attacking chain that full `Γ`
  computes `C_n` with the widening **excluded** (request refused) while `−attenuation` — evaluating
  against `Allowed(P_0; …)`, ignoring attenuation blocks — **admits** it. Assert the two forms
  differ **only** in `evaluation.prefix` (the loader/test from ADR 0016 already enforces this; cite
  it), so the control is matched and the difference in outcome is attributable to attenuation alone.

For each, the report states: what was constructed, the observed outcome, the `biscuit-python`
call/exception that produced it, and **what the failing outcome would have been** — the evidence
that the check could have failed.

---

## STEP 5 — Honest-adjudicability check before declaring PASS

Before marking anything, confirm in the report, per criterion, that it was **exercised**, not
assumed:

- If (b) could only be **partially** constructed because the library will not assemble a
  third-party block without a real third-party keypair/request, say exactly how far it went and
  whether the rejection observed is the one the profile relies on. A partial construction that
  still demonstrates rejection at the intended layer is a pass **with its scope stated**; a
  construction that never actually presented the malicious artifact to the authorizer is **not** a
  pass — mark it and stop.
- If any criterion cannot be honestly adjudicated against the frozen `Γ` as written, **do not mark
  G-2 PASS.** Report which limb and why, and propose the smallest correction (a corrective ADR to
  `Γ`, or a follow-on adjudication) — the G-4 Phase 1 precedent.

Only if (a)–(d) are all genuinely exercised and hold: mark G-2 **PASS** on the smoke board and set
IA-2 to verified-by-G-2 in §F.4, citing `biscuit-python==0.4.0` and the frozen `H(Γ)`. Update the
IA-2 row and the smoke board **only** to reflect the true outcome; do not touch other rows.

---

## STEP 6 — Write `smoke/g2/REPORT.md`

The durable record, in the established report shape: the criteria verbatim; the evaluator design
(fact-injection shape, prefix-identity provenance tying it to ADR 0003/G-1); per-criterion
construction, outcome, the exact library call/exception, and the would-have-failed world; the
partial-construction scope for (b) if any; the `H(Γ)` intactness confirmation for (c); and the
grade line — what is now `[VERIFIED]` for `biscuit-python==0.4.0` versus what remains design. State
plainly that G-2 adjudicates authorizer semantics over the frozen `Ω`/`Γ`, and does **not** speak
to HTC/INV (G-11), the AS (G-4), or any runtime arm.

---

## STEP 7 — Register (do not fill) the unowned-policy row

The `Ω`/`Γ` freeze exposed that Part I's `is_high_risk(action)` (F5) and `is_sensitive(label)` (F4)
are policies with **no** frozen-parameters row: row 4 owns label→outcome, row 6 owns sinks, and
nothing owns the high-risk action set or the sensitive-label set. `Ω` supplies a destructive action
(`notes.delete`) without classifying it — correctly, since classification is policy, not
vocabulary.

Add **one** new row to `docs/frozen_parameters.md` — the oracle classification policy: the
high-risk action set and the sensitive-label set — value **UNSET**, with the note that it is fixed
by the ADR that builds the oracle and **must** be frozen before Part H step 3, and that the
sensitive-label set depends on the row 4 label vocabulary (also UNSET). Update the header count
accordingly. **Do not choose its contents.** This mirrors the ledger-platform precedent: register
the obligation now so it cannot be forgotten at seal time; leave the decision to the step that owns
it. Record in the report that this is a registration, not a decision.

Do **not** create an ADR for this row in this pass unless a one-paragraph note is needed to explain
the registration; if so, keep it to the registration rationale and name no contents.

---

## STEP 8 — Commit, push, archive

Logically scoped Conventional Commits, the gate and the row-registration in **separate** commits,
ADRs/rows referenced in the body. `pre-commit run --all-files` and `uv run pytest -q` green before
each (state the Windows count; the six ledger tests stay Windows-only per ADR 0014). Stage new
files **before** running hooks so formatters see them (the ordering fix from the previous pass).
Add the G-2 spike to the same cross-platform expectation as the others (it runs the authorizer,
which is platform-independent, so it must pass on Linux CI too — unlike the Windows-only ledger).
Archive this spec under `docs/tasks/archive/g2/` with the standing MANIFEST note that task specs
are **retrospective records, not pre-registration evidence**. Push and verify with
`git ls-remote origin main`.

---

## STEP 9 — Stop and report

1. STEP 0 self-check.
2. Confirmation of the G-2 criteria read, the ADR-0003/G-1 prefix-identity binding, and that this
   is the first authorizer-with-policies run; pinned version confirmed `0.4.0`.
3. The evaluator: location, fact-injection shape, how it obtains `P_i`, and that it loads `Γ`/`Ω`
   from the frozen artifact rather than re-deriving them.
4. Criteria (a)–(d): per criterion, construction, outcome, the exact `biscuit-python`
   call/exception, and the would-have-failed world.
5. The honest-adjudicability check — especially (b)'s construction scope — and the PASS/҂ decision
   with its justification.
6. IA-2 and the smoke board updated to the true outcome; no other rows touched.
7. The row-7-style registration of the unowned-policy row: added, UNSET, header updated, contents
   not chosen; confirmation rows 1–7 and 9 (and the artifact, and `H(Γ)`) are otherwise untouched.
8. Commits, push verification, Linux/Windows counts, and anything you could not verify yourself.
9. Any point where you were tempted to fill a gap by assumption — or to weaken a check so it would
   pass — and what you did instead.
