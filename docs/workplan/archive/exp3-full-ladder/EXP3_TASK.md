# TASK — Experimental body, block 3: the complete nine-arm ladder, and G-13 closed

Four arms exist: `B0`, `B2-exchange-task`, `B-cap`, `B3`. Five do not: **`B1`**,
**`B2-broad-noexchange`**, **`B2-exchange-broad`**, **`B2-exchange-task-DPoP`**, **`B3⁺`**. This
block builds all five, which completes §E.5's nine-arm ladder, and then **closes G-13's two open
limbs** — `B2-exchange-task-DPoP` and `B3⁺` are precisely the arms whose absence forced G-13 to pass
over three of five strong baselines.

It also lands **four Commander-approved ADRs** fixing `frozen_parameters` rows 1, 2, 3 and 7, and
formally deferring row 5. Their drafts are supplied alongside this spec as **ADR 0025, 0026, 0027
and 0028**; the values in them are decided and are **not** yours to change.

Why G-13's closure sits here rather than later: Part G's **G-10** requires every prior gate in the
DAG, so its open limbs propagate to the final pilot-integration gate and to the seal. They can be
closed only by the two arms this block builds.

Three phases. **Phase A** (STEP 3–7) lands the ADRs and clears two carried observations. **Phase B**
(STEP 8–12) builds the five arms. **Phase C** (STEP 13–14) re-adjudicates G-13. Each ends green and
committed; report between phases.

---

## STEP 1 — Forbidden in this pass

| # | Forbidden | Why |
|---|-----------|-----|
| 1 | **Measuring, benchmarking or reporting any latency number** | Rows 1/2/7 being set does **not** authorize measurement. **G-3** owns timing, it is not in scope, and ADR 0025 requires an adjudicative run on the row 9 sealed platform — which is **not yet locked**. Instrumentation only |
| 2 | Running, preparing or marking G-3, G-9, G-12, G-14, G-15 or G-10; editing any Part G row, pass criterion, dependency edge or evidence grade | Only **G-13** is re-adjudicated here. Building the jti cache is **not** running G-9: `IA-9` stays `[UNVERIFIED-IA]` |
| 3 | Changing any value in the four supplied ADRs | They are the Commander's decisions. If one is unimplementable **as written**, **STOP and report** — do not adapt the value to the code |
| 4 | Setting `frozen_parameters` row 5 or row 9 | Row 5 is **deferred by decision** (ADR 0028) and is never to be filled; row 9 is read off the measurement box at seal time |
| 5 | **Letting a broad arm narrow, or a strong arm broaden** (STEP 9) | A `B2-exchange-broad` that accidentally enforced `C_1` would destroy the arm whose entire job is to isolate the exchange round trip **from** narrowing, and would silently contradict §E.4 |
| 6 | Weakening any arm, or giving any arm avoidable per-hop cost — a new TLS context or connection per hop, name resolution instead of the literal `127.0.0.1`, keys re-parsed per request, disk I/O on the request path | Both directions bias. The `B2` anti-bias suite already exists; the three new OAuth-family arms inherit **every** one of its requirements |
| 7 | Building F3, F4 or F5 fixtures, the shared reference monitor, `authz_context_hash`, or the attack suite | Later blocks. Building `B2-DPoP` and `B3⁺` is building **arms**, not the families that exercise them |
| 8 | Drafting `docs/PRE_REGISTRATION.md`, creating `fixtures/confirmatory/`, sealing, or running a campaign | PROJECT_RULES.md red lines 1–2. ADR 0028's pre-registration obligation is **recorded**, not discharged |
| 9 | Any import of `src/harness/` from `src/sut/`; of `src/sut/oauth_as/` from a non-AS `src/sut/` module or from `src/harness/`; reuse of a harness implementation as the SUT-side one | Red line 6, ADR 0015 rules 3–4, D13/D21 |
| 10 | A standalone-capability (`oauth_authn = 0`) arm in the formal matrix | §E.1/E6 permits it only as a separate exploratory arm, and none is wanted here |
| 11 | Secrets, minted tokens or holder keys on disk, in the repository, or in `results/` | PROJECT_RULES.md red line 8 |
| 12 | `git push --force`, history rewrite | Red line 7 |

If a step cannot be completed as written, **stop and report the blocker**. Do not substitute a
weaker version and report it as done.

---

## STEP 2 — Read what you are implementing

**§E.1's ladder table in full** — every one of the nine rows, and the five columns *receives per-hop
`C_i`* / *prevents F1-terminal* / *binds invocation* / *holder-bound* / *online per-hop*, because
those columns **are** the arms' specification. Then **§E.4's expected matrix** (every row, all nine
columns), **§E.5's bitmasks**, **§D's four-way DPoP taxonomy**, **D34** (the DPoP arm), **D37**
(`B3⁺` jti semantics), **§E.2**, and the **Part G rows for G-13, G-9 and G-14 verbatim** — so you
know which of them this pass may touch (one) and which it may not (two).

Then the four supplied ADRs, **ADR 0017** (the AS profile as built, including its DPoP surface),
**ADR 0024**, `smoke/g4/DESIGN.md` §5.3 and §8.2, `smoke/g5/REPORT.md` (the DPoP/JOSE surface G-5
verified), `smoke/g13/spike.py`, and the existing `src/sut/baselines/`, `src/sut/dpop.py` and
`src/sut/authz/boundary.py`.

**Report what turns out underspecified for implementation, and what you did.** Every block so far
has found some. Do not invent to cover one.

---

# PHASE A — land the four ADRs, and clear two observations

## STEP 3 — Set rows 1, 2, 3 and 7; defer row 5

Add ADR 0025–0028 to `adr/` as supplied — byte-for-byte, then append **only** a Status line change
from `proposed` to `accepted` and today's date. Set `docs/frozen_parameters.md` rows **1, 2, 3 and
7** with the values and justification lines they carry, and re-annotate row **5** as **deferred by
decision (ADR 0028)** rather than an open `⟨UNSET⟩` awaiting a value. Update the header count.

These four rows are **scalars**, not documents: no new frozen artifact and no new hash. Extend
`src/harness/frozen_parameters.py` so that each is loadable and so that **any comparison against an
unset row fails closed**. Rows 8, 10, 11 and `H(Γ)`/`H(R)`/`H(Λ)` are untouched — assert it.

## STEP 4 — The `presentation` seam, and the segment's pinned extent (ADR 0026)

Add the `presentation` span to `GoldenThreadRunner`, bracketing **exactly** `arm.present(...)` and
nothing else. `boundary_verification` keeps its present extent — `arm.decide(...)` alone. Do not
widen it; ADR 0026 rejected that in favour of two spans reported separately and summed.

Then assert the extents **structurally**, because a span whose boundaries rest on a comment drifts:
`presentation` brackets `present` alone; `boundary_verification` brackets `decide` alone; **no
effect-ledger write occurs inside either**; and neither includes `provision` or `delegate`.

`B3`'s audit sink runs inside `decide` and therefore inside the segment. Make it a **bounded
in-memory buffer**, flushed outside the segment, and refuse a sink that performs disk or network
I/O on that path — otherwise `B3` is charged for the apparatus. Test the refusal.

**Emit no number.** The seam exists and is unmeasured; `IA-3` stays `[UNVERIFIED-IA]`.

## STEP 5 — Discharge ADR 0028's documentation obligations

1. §E.4's `F2 wrong_principal` row → **`deferred — unscored (ADR 0028)`**. **Not `NA`**: `NA` asserts
   the arms cannot express the case, which is false — they can, and the study declines to score it.
2. §J gains ADR 0028's validity statement: this study makes **no claim** about task-to-principal
   authorization enforcement, and the absence of a `wrong_principal` result is not evidence that any
   arm fails to handle it.
3. **Release G-4's `may_act` residual** with a dated update note: the spike-local delegation policy
   is now the **final** configuration, sealed with the AS configuration at Part H step 3 (ADR 0017),
   no longer provisional. Append the note; do **not** rewrite `smoke/g4/REPORT.md` or touch its
   adjudication.
4. **Record, do not discharge**, the pre-registration and held-out obligations: before the seal,
   `PRE_REGISTRATION.md` states the deferral and the held-out subset is scanned for any
   `wrong_principal` variant. Neither document exists yet. Put the obligation where it will be seen
   at seal time, and do not draft either.

## STEP 6 — The two carried observations

**O1 — make G-13's D21 residual precise.** It currently reads that agreement is evidence of
independence only because the implementations are structurally distinct, *which a future refactor
could silently undo*. That is broader than the truth: L4's import scan **would** catch a refactor
that made the verifier import `boundary.py` — that is a cross-boundary import and W1 proved the scan
non-vacuous. What the scan cannot catch is **copy-paste convergence**: the token plane rewritten
with the boundary's construction and no import. Restate the residual as that, in
`smoke/g13/REPORT.md` and the module note. A precise residual is auditable; a vague one is ignored.

**O2 — write the chain-tamper exclusion into the analysis plan.** On `gt-f1-chain-tamper` the
exchange arms perform a **failed AS round trip** and receive no token, while the capability arms do
purely local work. **Refusal-path latency is reported as its own series** and is never pooled into a
benign per-arm mean or into ADR 0026's row 1 estimand. Record it where the G-3/RQ4 work will read
it, and cross-reference ADR 0026. This is a **plan**, not a measurement.

## STEP 7 — Phase A checkpoint

`pre-commit run --all-files` and `uv run pytest -q` green — verify the hooks against what is
**staged**, not the working tree. Report Linux counts and the expected Windows split. Scoped
commits, pushed, `git ls-remote origin main` verified. **Report before Phase B.**

---

# PHASE B — the five remaining arms

## STEP 8 — `B1`, the static API key

§E.1: *a static secret adds nothing*. A shared secret presented at the boundary, checked for
equality, expressing **no** authority, **no** audience binding and **no** scope. It authenticates a
caller and does nothing else, and it must be honestly incapable of more.

Expected, per §E.4: admits `F1-root` and `F1-terminal`; blocks `F2 invalid_credential` and
`F2 unauthenticated_caller`; `NA` on `F1-chain-tamper` (it has no chain). Record the `NA` as data
the matrix fixture reads, exactly as `B0`'s is recorded — never as a skipped cell.

## STEP 9 — The two broad OAuth arms, and the grant conflict you must resolve first

`B2-broad-noexchange` (OAuth 2.1, broad, bearer, RFC 8707 resource indicators, **no** exchange) and
`B2-exchange-broad` (**with** the exchange round trip, scope **unchanged** — the arm that isolates
exchange cost **from** narrowing).

**Resolve this before writing either arm.** ADR 0024 provisions **the delegating client's** base
token with authority exactly `C_0 = U_task`, because `B2-exchange-task` needs the AS to enforce
`C_1 ⊆ C_0`. But §E.4 predicts the broad arms **admit** `F1-root`, and `(mail.send, mail/outbox)`
lies **outside** `U_task`. On the supervisor's task-scoped token a broad arm would **block** it —
contradicting §E.4 and destroying the arm.

The ladder row, not the client identity, determines the grant: **broad arms are provisioned with the
coarse `Ω` grant; strong arms with `C_0 = U_task`.** Make the grant an **explicit named per-arm
provisioning input** rather than a consequence of which client happens to be used — do **not**
smuggle breadth in by delegating from a different principal, which would change the `may_act`
relation as a side effect and confound the arms in a second respect.

Write **ADR 0029** recording it: the conflict, that breadth is a **ladder property** of the arm, the
mechanism, and that ADR 0024 is thereby **applied rather than amended** — its rule was always about
what the *mechanism* needs, and the two families of arm need different things. Then a test per arm
asserting its **realized** `C_0` equals what its §E.1 row specifies: `Ω` for the broad arms,
`U_task` for the strong ones. Compute it; never assert it.

`B2-exchange-broad` must still perform a **real** exchange round trip — that round trip **is** what
the arm isolates. An arm that skipped it to save time would measure nothing.

## STEP 10 — `B2-exchange-task-DPoP`

`B2-exchange-task` **plus** DPoP holder binding: `cnf`/`jkt` bound to the holder key, a proof per
request, verified at the boundary. The AS already supports this (`require_dpop`, `cnf_jkt`,
`NonceStore`), `src/sut/dpop.py` exists, and `boundary.verify_dpop_request` exists — this arm is
**wiring plus a proof-signing client**, not new cryptography. Reuse all three unchanged.

Per §E.1 it binds **method + URI only** — not the body, not the arguments, not the tool. Build it so
that limitation is real and observable, because it is exactly what §D's taxonomy and G-14 will later
attribute against `B3`'s invocation binding. Do not accidentally give it body binding.

Anti-bias: the proof key is parsed **once** at provisioning, never per request; one TLS context, one
keep-alive connection, literal `127.0.0.1`. Inherit `B2`'s suite; add the key-parse count.

## STEP 11 — `B3⁺` and the bounded `jti` cache

`B3` **plus** a bounded replay cache consuming the `jti`, built to **ADR 0027's frozen parameters
and no others**: TTL exactly `Δ = 60 s`, capacity exactly **2^16**, **fail-closed on overflow** —
an insertion that cannot be recorded is a **denial**, never an admission and never a silent eviction
of an unexpired entry. The cache key is `(mechanism_tag, jti)`, as G-9's criterion names.

Every consumer of `Δ` takes `now` as an **injected** parameter; none reads a wall clock. Over-window
fixtures **advance the injected instant** — **no test may sleep**, and a test asserts that none does.
Sixty seconds of real waiting per repetition, at ≥ 200 repetitions per configuration, would cost
hours and would make the suite's runtime a function of `Δ`.

**Building this cache is not gate G-9.** G-9 adjudicates atomic multi-process check-and-insert under
concurrency and induced backend error. Do **not** run it, do **not** claim it, and leave `IA-9` at
`[UNVERIFIED-IA]`. Say in the report which G-9 properties this construction does and does not yet
have — a single-process cache that G-9 will later have to make multi-process is an honest state to
be in; one described as if it were already G-9-ready is not.

## STEP 12 — The full nine-arm matrix

Extend the matrix fixture to all nine arms over the four pilot scenarios, driven once through the
real runner over the real AS, and compare **cell by cell** with §E.4's prediction. Report every
cell with its reason code.

**A cell that disagrees with §E.4 is a finding to report, not a number to adjust — and neither is
the prediction to be edited to match.** In particular, the broad arms admitting `F1-root` and
`F1-terminal` is the **predicted** result: it is what the study exists to measure, not a defect.
Commit, push, verify. **Report before Phase C.**

---

# PHASE C — close G-13's open limbs

## STEP 13 — Re-adjudicate G-13 over all five strong baselines

The five arms that receive per-hop `C_i` now all exist: `B2-exchange-task`,
`B2-exchange-task-DPoP`, `B-cap`, `B3`, `B3⁺`. Re-run G-13's existing limbs over all five, using
the independent verifier unchanged.

- **L1** — `Allowed(AT_i) = C_i` / `Allowed(P_i) = C_i` per hop, recomputed from raw presented
  evidence, compared against the **sealed** `C_i`. The two new arms are `B2-exchange-task` and `B3`
  plus a binding layer, so the expectation is that their authority sets are **identical** to those
  arms'. **That expectation is exactly why the limbs must actually run**: an assertion that DPoP and
  a jti cache add no authority is what G-13 said was *expected, not verified*, and this is where it
  stops being expected.
- **L2** — cross-arm identity now over **five** arms, not three.
- **L3** — the F1 subcases on both new arms, with the attributable cause per arm.
- **L4/L5** — unchanged; re-run so the closure rests on a full run rather than an inherited one.
- **Every equality must still be shown able to fail.** The existing seven worlds are re-run; add
  whichever the two new arms make constructible that the old three did not.

If a new arm's authority turns out **not** to equal `C_i`, that is a finding and G-13 does **not**
close. Report it.

## STEP 14 — Update the board honestly

If and only if all five arms hold: the G-13 row becomes **PASS**, with the DPoP and `B3⁺` limbs
recorded as **closed by this pass** and the previous open-limb wording retained as a **dated update
note** rather than deleted — the record must show the sequence, not the destination. State plainly
that the earlier *expected, not verified* language is now **verified**, and by what.

If any limb cannot be closed, **do not mark it closed**: say which, why, and the smallest correction.
`IA-3` stays `[UNVERIFIED-IA]`; `IA-9` stays `[UNVERIFIED-IA]`; no other gate's row moves.

---

## STEP 15 — Commit, push, archive

Scoped Conventional Commits, ADRs referenced in bodies. Stage new files **before** running hooks, and
verify the hooks against the **staged** tree. Archive this spec under
`docs/workplan/archive/exp3-full-ladder/` with the standing note that task specs are **retrospective
records, NOT pre-registration evidence**, and remove the working copy from the repository root in
the same commit. Push; verify with `git ls-remote origin main`.

---

## STEP 16 — Stop and report

1. STEP 0 self-check.
2. The STEP 2 read, and anything **underspecified for implementation**, with what you did.
3. **Phase A:** rows 1/2/3/7 set and row 5 deferred, with the fail-closed behaviour on an unset row.
   The `presentation` seam and the three structural extent assertions. The audit-sink refusal. The
   four ADR 0028 obligations, with the two that were **recorded rather than discharged** named as
   such. O1's restated residual and O2's analysis-plan note.
4. **Phase B:** `B1`. **ADR 0029 and the grant conflict** — how breadth became an explicit per-arm
   input, and each arm's **computed** `C_0` against its §E.1 row. `B2-exchange-task-DPoP`, including
   how its method+URI-only binding is made **observable** rather than merely true. `B3⁺` and the
   cache, with the G-9 properties it does and does **not** yet have stated explicitly.
5. The **nine-arm × four-scenario matrix**, every cell with its reason code, compared to §E.4 cell by
   cell. Any disagreement, unadjusted.
6. **Phase C:** G-13 over five arms — the equalities, the cross-arm identity, the F1 causes, and for
   every equality the world in which it fails. Whether the two limbs closed, and on what evidence.
7. The board and IA cells at their true values; `IA-3` and `IA-9` untouched.
8. Confirmation that **no timing number was produced anywhere**, that no test sleeps, and that no
   secret or token reached disk, the repository or `results/`.
9. Commits, push verification, counts on both platforms, and anything you could **not** verify.
10. Any point where you were tempted to fill a gap by assumption, to adjust a matrix cell toward the
    prediction, to edit the prediction toward a cell, to change an ADR value to fit the code, or to
    describe the jti cache as more G-9-ready than it is — and what you did instead.
