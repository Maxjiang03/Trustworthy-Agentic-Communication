# TASK — Experimental body, block 6: the oracle, the campaign entry point, and the analysis code

Thirteen gates pass and all nine arms exist. What the study still cannot do is **score itself.**

Part I specifies ten predicates. Five exist — `realized_harm_F3`, `log_integrity_failure`,
`observed_forwarded`, `linkage_of`, `oracle_request_digest` — and every one of them arrived as a
by-product of gate G-12. **Seven do not**: `reference_allow`, `admission_breach`, `false_block`,
`realized_harm_F1`, `realized_harm_F2`, `realized_harm_F4`, `realized_harm_F5`.

The consequence is precise and it undercuts what G-12 just established. Today's F1/F4/F5 matrix
cells are `(admitted, reason_code)` pairs compared against §E.4 — that is **the arm's own verdict**,
read back. G-12 proved the oracle is *structurally incapable* of reading a SUT verdict; the matrix
tests are not the oracle, and the confirmatory results must come from the oracle. Until these
predicates exist, the study's security results rest on the system under test grading its own work.

Two further absences block the seal: **Part H step 3 seals "oracle code, analysis code"**, and there
is no analysis code — `analysis/` holds one `.gitkeep`. **ADR 0026's decision rule** is a 95%
bootstrap CI upper bound, and nothing computes one. There is also no single campaign entry point:
each gate has its own fixture, which is right for gates and wrong for a campaign.

Three phases. **A** (STEP 3–5) completes the oracle. **B** (STEP 6–8) builds the campaign entry
point. **C** (STEP 9–10) builds the analysis code. Each ends green and committed; report between
phases. **Stopping at a committed green state has been the right call five times — it remains so.**

---

## STEP 0 — Self-check, and the machine

Run `wc -l` and `sha256sum` on this file. Expected: **the line count and digest quoted in the launch
prompt**. If either differs, **STOP and report**.

Confirm the `pre-commit` git hook is installed. **`pytest` green is not `main` green** — CI runs
seven gate spikes.

---

## STEP 1 — Forbidden in this pass

| # | Forbidden | Why |
|---|-----------|-----|
| 1 | **Producing, benchmarking or reporting any latency number** | You are building the code that will *one day* compute statistics. **G-3 has not run and the measurement platform is not locked.** Building the estimator is in scope; feeding it real timings is not. Test it on **synthetic** inputs |
| 2 | Running, preparing or marking **any** gate; editing any Part G row, pass criterion, dependency edge or evidence grade | No gate is adjudicated in this block. G-10 is next and it is not yours to start |
| 3 | Letting **any** oracle predicate read a SUT verdict, a SUT digest, a reason code, an audit record, or anything under `src/sut/` | Part I: *"reads only raw evidence, sealed `IntendedInvocation`, and the trusted mediation/ledger records."* G-12's L2 scan enforces this — **it must keep passing after you add seven predicates** |
| 4 | Changing a Part I predicate's semantics to make a matrix cell agree | Part I is executable pseudocode and it is the specification. A disagreement between a predicate and a cell is a **finding** |
| 5 | Amending any frozen row, `Ω`/`Γ`, the registry, the policy document, or any `H(·)` | ADR 0016/0019/0022/0023/0025/0026/0027/0030 |
| 6 | Populating `fixtures/confirmatory/`, drafting `PRE_REGISTRATION.md`, generating a held-out subset, sealing, or running a campaign | Red lines 1–2. **Building the entry point is not running the campaign.** The held-out subset is block 7 |
| 7 | Any import of `src/harness/` from `src/sut/`; of `src/sut/oauth_as/` from a non-AS `src/sut/` module or from `src/harness/` | Red line 6, ADR 0015 |
| 8 | Secrets or minted tokens on disk, in the repository, or in `results/`; `git push --force`; history rewrite | Red lines 7–8 |

If a step cannot be completed as written, **stop and report the blocker**. Do not substitute a
weaker version and report it as done.

---

## STEP 2 — Read what you are implementing

**Part I in full, as executable specification** — all ten predicates, the separation of reported
quantities (`reference_allow`, `observed_forwarded`, `admission_breach`, `realized_harm`,
`false_block`, `log_integrity_failure`), and the **no-/partial-/multi-effect MUST**: every
`realized_harm_*` is over the effect **set** — zero effects means no realized harm, a partial effect
that still violates is harm, multiple effects are harm if **any** violates.

Then **§E.4's expected matrix** and its `A†` footnote; **§E.5's** statistical protocol paragraph
(≥ 200 end-to-end per configuration across ≥ 3 batches, ~1,000 micro-benchmark iterations, median /
p95 / IQR / bootstrap CI, decomposition, cold and warm separately, randomised or Latin-square order,
warm-up discarded, and that **security verdicts are deterministic and repetition detects
nondeterminism, not sampling error**); **ADR 0026** (the estimand, the decision rule, the measured
segment, and the chain-tamper exclusion); **ADR 0025** (denominators, secondary aid only);
**Part H steps 2–7**.

Then the code: `src/harness/oracle/predicates.py`, `src/harness/oracle/jcs_digest.py`,
`src/harness/runner.py`, `src/harness/matrix_grouping.py`, `src/harness/schema.py`,
`smoke/g12/spike.py`'s L2 scan, and the existing per-gate fixtures (`smoke/g13/fixture.py`,
`smoke/g14/fixture.py`) as the pattern a campaign entry point generalises.

**Report what turns out underspecified for implementation, and what you did.** Every block has found
some. Do not invent to cover one.

---

# PHASE A — complete the oracle

## STEP 3 — The seven missing predicates

Implement them as Part I writes them, in `src/harness/oracle/predicates.py`:

`reference_allow` · `admission_breach` · `false_block` · `realized_harm_F1` · `realized_harm_F2` ·
`realized_harm_F4` · `realized_harm_F5`

Four points where Part I hands you a decision rather than a definition. Resolve each **explicitly**
and record it — do not let a default happen:

1. **`authority_from_effects`** (used by `realized_harm_F1`) is named but not defined. It maps an
   effect set to the authority actually exercised. Its inputs are `EffectEvent.action` and
   `.resource` — **ledger-side facts**, never the arm's claim. Define it, and say why it cannot
   read anything else.
2. **`reference_allow`** is `R ⊆ C_n` *"plus family-specific gates in the fixture"*. Those gates
   are unstated. For F4 a benign labelled control is allowed **only** with a valid declassification;
   for F5 **only** with a valid approval. Decide where the family gate lives — in the predicate or
   in the sealed record — and be consistent across all five families.
3. **`realized_harm_F2`** takes a `cred_result` with `principal_verified` and `principal`. **No such
   object exists.** It is a harness-side credential-verification result, independent of the arm's
   own check (D21). Say what produces it and how it stays independent.
4. **`false_block`** takes `is_benign`. That is a property of the **scenario**, so it belongs in the
   sealed record, not in a caller's argument. Confirm the pilot corpus carries it, or add it.

## STEP 4 — Prove the oracle still cannot read a verdict

Adding seven predicates is the largest expansion of the oracle since it was built, and **the whole
point of G-12's L2 is that the property survives changes it did not anticipate.**

- Re-run G-12 and confirm L2 still passes with all ten predicates present. Report it.
- Extend L2's forbidden-name list if any new field name could carry a SUT verdict.
- For each new predicate, state in the module which of the three permitted sources it reads:
  sealed `IntendedInvocation`, the trusted mediation record, or the ledger. A predicate that would
  need a fourth source is a finding — report it rather than reaching for one.

## STEP 5 — Every predicate must be shown able to fire, and able to stay silent

The discipline that has caught a real error in every block. For **each** of the seven:

- a world where it fires, and
- a world where it must **not** — a predicate that is always true is not a predicate.

`admission_breach` and `realized_harm` are **separate** quantities (Part I) and must be shown to
come apart: a breach with no effect (admitted, nothing ran) and an effect with no breach (a benign
call that legitimately executed). If your implementation cannot produce both, they are not separate
and that is a finding.

Then the no-/partial-/multi-effect MUST: zero effects ⇒ no harm; one violating effect among several
⇒ harm; a partial effect that still violates ⇒ harm. Test all three per family.

`pre-commit` and `pytest` green, plus every gate spike. Report Linux counts as **measured or
derived**. Commit, push, verify. **Report before Phase B.**

---

# PHASE B — the campaign entry point

## STEP 6 — One entry point, over the existing stack

`src/harness/campaign.py`: one callable that runs **all nine arms × every scenario × every
applicable family**, producing per-cell oracle verdicts and the timing seams, in one artifact.

Build it **over** `GoldenThreadRunner` and the existing boundary/recorder/effector stack — **not a
second stack.** Block 5 established that one stack is what makes the two modes comparable; a
campaign path that assembled its own would be a third. Assert it structurally, as STEP 3 of block 5
did: exactly one `install_boundary(`, one `install_ingress_recorder(`, one `build_server(`.

Its output is **evidence, not verdicts read back**: per cell, the sealed intent reference, the
mediation record, the ledger entries, the observation, and every Part I quantity **separately** —
`reference_allow`, `observed_forwarded`, `admission_breach`, `realized_harm`, `false_block`,
`log_integrity_failure`. Reason codes may be **recorded** for diagnosis; nothing in the scoring path
may **read** one.

## STEP 7 — Make the campaign's own preconditions fail closed

A campaign that silently runs in a wrong configuration produces results nobody can trust. Refuse,
with a named error, if:

- a frozen row it needs is unset — `H(Γ)`, `H(R)`, `H(Λ)` mismatched, or rows 1/2/3/7 absent;
- `run_mode="confirmatory"` and any pilot-provisional artifact is in play (the `PILOT-PROVISIONAL`
  policy, an ablation variant, a fixture from `fixtures/pilot/`);
- an F4/F5 cell would be recorded without its `monitor_attached` configuration (`matrix_grouping`
  already refuses this — route through it rather than around it);
- the effect ledger is unavailable on a run that needs it (ADR 0014: **no silent degradation**).

Also record, per run: the git commit, the resolved frozen-parameter values, `H(Γ)`/`H(R)`/`H(Λ)`,
the SUT mode, and the platform. Part H step 6 needs a manifest; this is what it will hash.

## STEP 8 — Run it on the pilot corpus, and compare against §E.4

Run the entry point over the **pilot** corpus, in-process, and produce the full matrix **from oracle
verdicts** for the first time. Compare cell by cell with §E.4 **and** with what the existing matrix
tests report from reason codes.

**Three outcomes, and they are not the same thing:**

- **They agree** — the arms' self-reports and the oracle's independent verdicts coincide. Report it;
  that agreement is itself worth stating in the dissertation.
- **They disagree** — a **finding**, and a serious one. Report it; adjust neither the predicate nor
  the cell.
- **The oracle cannot score a cell** — say which and why, rather than falling back to the reason
  code.

`fixtures/confirmatory/` stays empty; say so. Commit, push, verify. **Report before Phase C.**

---

# PHASE C — the analysis code

## STEP 9 — The estimator, on synthetic inputs only

`analysis/`: the pre-registered statistical procedure as code, sealed at Part H step 3.

- **The security side is deterministic.** §E.5 is explicit: a fixed author-constructed suite has no
  random-sampling population, so there are **no confidence intervals on security verdicts**.
  Repetition detects **nondeterminism**, not sampling error. Build the nondeterminism check — the
  same sealed scenario twice must give the same verdict — and **no** significance test.
- **The latency side** is the only sampled quantity: median, p95, IQR, and the **95% bootstrap CI**
  ADR 0026's decision rule needs. The estimand is `median(B3) − median(B0)` over
  `presentation + boundary_verification`, warm; the claim stands iff the **CI upper bound < 20 ms**.
  Implement the rule so it returns *stands* / *retracted* and the interval, not a bare number.
- **The chain-tamper exclusion** (ADR 0026, §J.3 item 12): the `gt-f1-chain-tamper` cell is **never**
  pooled into a benign per-arm mean or into the row 1 estimand; refusal-path latency is its own
  series. Enforce it in the code, not in a comment.
- Cold and warm reported separately; warm-up discarded; the decomposition preserved.

**Test it on synthetic inputs whose answer you construct** — a sample whose CI upper bound is known
to sit either side of 20 ms, so both *stands* and *retracted* are exercised. **Emit no real timing
number** (forbidden action 1).

## STEP 10 — Phase C checkpoint

`pre-commit` and `pytest` green, plus every gate spike. Commit, push, verify.

---

## STEP 11 — The standing check

Six blocks, six instances of one hazard: something dormant that became load-bearing later and failed
**toward** the hypothesis. This block adds seven predicates and a scoring path.

Ask explicitly: **does the oracle score any family in a way that favours `B3`?** Specifically —
does `reference_allow`'s family gate treat capability arms and OAuth arms identically? Does
`realized_harm_F1`'s `authority_from_effects` read anything an arm could influence? Does
`false_block` apply the same benign standard to every arm, including the case block 4 found where
an unconfigured `B3` refuses a valid control? **Report the answer per predicate.**

---

## STEP 12 — Commit, push, archive

Scoped Conventional Commits, ADRs referenced in bodies. Archive this spec under
`docs/tasks/archive/exp6-oracle-and-campaign/` with the standing note that task specs are
**retrospective records, NOT pre-registration evidence**, and remove the working copy in the same
commit. Push; verify with `git ls-remote origin main`.

---

## STEP 13 — Stop and report

1. STEP 0 self-check and the hook confirmation.
2. The STEP 2 read, and anything **underspecified for implementation**, with what you did.
3. **Phase A:** the seven predicates, and the four decisions of STEP 3 with the reasoning for each.
   G-12's L2 re-run result. Per predicate, which of the three permitted sources it reads.
4. The fire/stay-silent worlds per predicate; the breach-without-effect and effect-without-breach
   pair; the zero/partial/multiple effect cases per family.
5. **Phase B:** the entry point, the structural one-stack assertion, the four fail-closed
   preconditions, and what the per-run record captures.
6. **The full matrix from oracle verdicts**, compared to §E.4 **and** to the reason-code matrix —
   agreements, disagreements and unscorable cells, each named. Nothing adjusted.
7. **Phase C:** the estimator, the decision rule returning stands/retracted, the chain-tamper
   exclusion enforced in code, and the synthetic tests exercising **both** sides of 20 ms.
   Confirmation that **no real timing number was produced**.
8. STEP 11's answer, per predicate.
9. Commits, push verification, counts on both platforms **stated as measured or derived**, every
   gate spike's result, and anything you could **not** verify.
10. Any point where you were tempted to score from a reason code, to soften a predicate so a cell
    would agree, to build a second stack, or to feed the estimator a real measurement — and what you
    did instead.
