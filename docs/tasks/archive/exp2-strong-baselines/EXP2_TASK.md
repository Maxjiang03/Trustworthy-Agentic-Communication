# TASK — Experimental body, block 2: the strong-baseline set and gate G-13

Block 1 built the golden thread and two arms at opposite ends of the ladder. This block builds the
**middle of the strong-baseline set** — `B2-exchange-task`, the fair OAuth arm, and `B-cap`, the
ablation that keeps `B3`'s benefits attributable — and then runs the gate that makes the whole
comparison legitimate: **G-13, `Allowed(AT_i) = C_i` for every hop and every strong baseline**.

Part G's own words for what rides on G-13: **matched fairness; the whole comparison.** If the
strong baselines do not receive identical per-hop authority, every security difference the study
later reports is confounded by provisioning rather than by mechanism.

It also freezes three seal-time parameters the Commander has decided to set rather than drop —
`frozen_parameters.md` **rows 4, 6 and 10** — and clears three corrections carried over from
block 1's independent verification.

Three phases, in order, each ending green and committed. **Phase A** (STEP 3–8) is the frozen
policy and the carried-over corrections. **Phase B** (STEP 9–12) is the two arms. **Phase C**
(STEP 13–16) is gate G-13. If a phase cannot be finished, stop there and report — the phases are
ordered so that stopping early still leaves a coherent repository.

---

## STEP 0 — Self-check (do this first, report the result)

Run `wc -l` and `sha256sum` on this file. Expected: **the line count and digest quoted in the launch
prompt**. If either differs, **STOP and report** — do not act on a partial spec.

---

## STEP 1 — Forbidden in this pass

| # | Forbidden | Why |
|---|-----------|-----|
| 1 | Building `B1`, `B2-broad-noexchange`, `B2-exchange-broad`, `B2-exchange-task-DPoP`, `B3⁺`, the jti cache, or any §E.6 ablation arm | Out of scope. G-13 concerns the **strong** baselines — those that receive per-hop `C_i` — and the three built here are the ones its criteria can reach |
| 2 | Running, preparing, or marking G-3, G-9, G-12, G-14, G-15 or G-10; editing any Part G row, pass criterion, dependency edge, or evidence grade | Only G-13 is adjudicated here. G-12 is its DAG sibling, not its dependency, and G-10 sits last |
| 3 | **Weakening `B2-exchange-task` in any respect** — a shorter narrowing, a skipped check, a coarser `authorization_details`, a bearer token that the boundary does not fully validate | §7 of the project record: *never weaken a baseline to manufacture an advantage*. `B2-exchange-task` is the fair strong OAuth arm and the one `B3` must be compared against honestly |
| 4 | Any avoidable per-hop cost in `B2` — resolving `localhost` rather than the literal `127.0.0.1`, a new TLS context or connection per hop, re-parsing keys per request, disk I/O on the request path | The **opposite** bias, and the dangerous one: gratuitous AS cost inflates `B2` **toward `B3`**, the direction that flatters the hypothesis. G-4 found a real 0.7 s-per-hop `::1` fallback by measurement, not by reading (`smoke/g4/DESIGN.md` §8.2) |
| 5 | **Measuring, benchmarking or reporting any latency, throughput or overhead number** | Rows 1–2 remain UNSET and must be fixed from external engineering need *before any timing measurement* (Part H step 2). STEP 9's anti-bias requirements are **structural** and are asserted structurally |
| 6 | Modifying `omega_gamma_v1.json`, `identity_registry_v1.json`, `frozen_config.py`, `H(Γ)`, `H(R)`, or `frozen_parameters.md` rows 8 and 11 | ADR 0016/0019. A defect found here → **STOP** and write a corrective ADR |
| 7 | Setting `frozen_parameters.md` rows 1, 2, 3, 5, 7 or 9, or inventing a `task_authorization_policy` | Only rows 4, 6 and 10 are decided in this pass, and their values are **given** in STEP 3 — do not choose your own. Row 5 stays UNSET, so F2 `wrong_principal` stays unscored |
| 8 | Building F3, F4 or F5 fixtures, the shared reference monitor, or `authz_context_hash` | Rows 4/6/10 being frozen enables the **refusal** half of the two policy conjuncts. Scoring F4/F5 additionally needs labelled fixtures and G-15, and `authz_context_hash` stays ADR 0009 category (c) |
| 9 | Creating or populating `fixtures/confirmatory/`, drafting `docs/PRE_REGISTRATION.md`, sealing, or running a campaign | CLAUDE.md red lines 1–2; Part H |
| 10 | Any import of `src/harness/` from `src/sut/`; of `src/sut/oauth_as/` from a non-AS `src/sut/` module or from `src/harness/`; or reuse of a harness implementation as the SUT-side one | Red line 6, ADR 0015 rules 3–4, D13/D21. The block-1 AST suite already enforces the first three — keep it passing rather than working around it |
| 11 | Putting a client secret, an actor assertion, a seed or a minted token on disk, in the repository, or in `results/` | CLAUDE.md red line 8. Runtime-only, runner-held, in memory |
| 12 | `git push --force`, history rewrite | CLAUDE.md red line 7 |

If a step cannot be completed as written, **stop and report the blocker**. Do not substitute a
weaker version and report it as done.

---

## STEP 2 — Read the specification you are implementing

Read, and confirm in the report: **§E.1** (the ladder table — the `B2-exchange-task`, `B-cap` and
`B3` rows, and the **B-cap fixed [E6]** paragraph), **§E.2** (two-phase OAuth; the pinned AS
exchange profile and the *independent harness verifier* sentence that defines G-13), **§E.3** (the
three F1 subcases and which arms are NA), **§E.4** (the expected matrix rows for these three arms),
**§E.5** (their bitmasks), **§E.6** (why `B-cap` exists), **§A.4** (`B3` layers on OAuth), **§A.6**
(labels, the MSc model, egress and declassification), **§F.1** (`LabelAssertion`,
`DeclassificationArtifact`, `ApprovalArtifact`), **Part I** (`realized_harm_F4`, `realized_harm_F5`,
`is_sensitive`, `is_high_risk`), and the **Part G G-13 row verbatim**.

Then: ADR 0016 and ADR 0019 as the **pattern** this pass's freeze must follow, ADR 0017 (the AS
profile as built), ADR 0021, `smoke/g4/DESIGN.md` §5.3 and §8.2, `smoke/g4/REPORT.md` limbs L1/L1′/L2,
and block 1's `src/sut/authz/capability_path.py`, `src/sut/baselines/`, `src/harness/runner.py`,
`src/harness/as_process.py`, `src/harness/key_material.py`.

**Report which parts turn out to be underspecified for implementation, and what you did.** Block 1
found four such points; G-4 Phase 2 found seven. Do not invent to cover one.

---

# PHASE A — the frozen policy and the carried-over corrections

## STEP 3 — Freeze rows 4, 6 and 10

**These values are the Commander's decision, given here. Implement them; do not choose your own.**
Follow the ADR 0016 / ADR 0019 pattern exactly: one loadable frozen document, a stated **necessity**
per entry that the loader enforces, a hash under its **own** domain tag, fail-closed on an
unsupported version, and the corresponding `frozen_parameters.md` rows set with a justification line.

Artifact: `src/harness/policy/label_approval_v1.json`, loader `src/harness/policy/frozen_policy.py`,
hashed as **`H(Λ)`** under the tag **`AASC-POLICY-DIGEST`** — check `at_digest.py`'s `_TAGS_IN_USE`
and every tag in service first, and extend that defensive list in the same commit.

**Row 4 — context-label → outcome policy.**
- Label vocabulary, a total order: `public ⊏ internal ⊏ sensitive`. A derived value takes the
  **join** of its inputs (§A.6).
- An action is **egress** iff its effect carries a `recipient`. Over the frozen `Ω` that is exactly
  `mail.send`; every other action is non-egress. Derive this from `Ω`, do not hard-code the list.
- Non-egress action: **permit**, at every label — nothing leaves.
- Egress action: `public` → **permit**; `internal` → **escalate** (admissible only under a valid
  approval or declassification artifact); `sensitive` → **block** absent a valid
  `DeclassificationArtifact`.
- An **unlabelled** payload on an egress action **fails closed** — with no verified `LabelAssertion`
  no permit can be established. Unlabelled on a non-egress action is permitted.

**Row 6 — allowed-sink policy.**
- Two sink classes over the recipient: `internal-sink` iff the recipient's domain is exactly
  `aasc.local`; `external-sink` otherwise. Byte-exact lowercase ASCII comparison with no
  normalization, matching `Ω`'s encoding rule.
- Allowed pairs: `(public, internal-sink)`, `(public, external-sink)`, `(internal, internal-sink)`.
- Every other pair is admissible **only** under a valid `DeclassificationArtifact`.

**Row 10 — oracle classification.**
- `high_risk_actions = {mail.send, notes.delete}`. Necessity: both are irreversible or externally
  visible, whereas `calendar.read` and `notes.read` are reads and `notes.write` is reversible inside
  the user's own store.
- `sensitive_labels = {sensitive}`.

**Both planes evaluate this document independently and neither imports the other's evaluation** —
the line ADR 0016 drew for `Ω`/`Γ`. Rows 4 and 6 reach the SUT boundary as **injected sealed
configuration**; row 10 is consumed by the SUT's `approval_artifact_ok` *and* by the oracle's
`is_high_risk`/`is_sensitive`, each computing from the document itself.

State plainly in the ADR what this freeze does **not** do: it enables the **refusal** half of both
conjuncts; the **acceptance** half needs `authz_context_hash`, which stays ADR 0009 category (c)
owned by G-15, and scoring F4/F5 additionally needs labelled fixtures. `H(Λ)` joins `H(Γ)` and
`H(R)` in the runner's start-up verification and in the corpus generator's check.

## STEP 4 — Make the two conjuncts load-bearing, and prove nothing already-decided moved

Replace the `PILOT-PROVISIONAL` stand-in with the frozen policy in `context_policy_ok` and
`approval_artifact_ok`. Delete the stand-in file and its guard, or keep the guard and point it at
the frozen document — your call, but there must be exactly **one** policy source afterwards.

Then the check that matters: **regenerate the pilot corpus and show that no `C_sets`, `R`, `U_task`
or `intended_request_digest` value changes.** One field does change and must: `gt-f1-root` calls
`mail.send`, now a row-10 high-risk action, so its sealed `requires_approval` becomes **true**. Any
*other* difference is a finding — report it rather than absorbing it.

Confirm and test that the four pilot outcomes under `B0` and `B3` are **unchanged**: containment is
conjunct six and the two policy conjuncts are seven and eight, so an F1 block still fires at
containment. If an outcome moves, stop and report — that would mean the ordering or the policy is
wrong, not that the corpus needs adjusting.

## STEP 5 — Give CI real coverage of the golden thread (block-1 correction)

Today `tests/test_golden_thread_b0.py` skips **5 of 5** on Linux, so an all-green CI run says
nothing about whether the golden thread still runs, and the next five arms will be built on top of
that blind spot.

Split the assertions by what they actually concern. Those that do **not** concern effects — the
boundary admitted, the tool dispatched and returned, the presented evidence bundle is empty for
`B0`, the sealed-truth set relations hold — run on **every** platform. Only the assertions that read
the ledger stay behind the ADR 0014 Windows gate, with their existing reason string.

**Introduce no ledger fallback, stub, or no-op writer.** ADR 0014's whole point is that the ledger
refuses to run rather than degrade into something that looks identical while protecting nothing. If
a test cannot be written without one, leave it Windows-gated and say so.

Do the same split for `test_golden_thread_b3.py`, `test_runner.py` and `test_mcp_tools.py` wherever
an assertion is gated only because it shares a fixture with a ledger assertion. Report the
before/after Linux pass and skip counts per file.

## STEP 6 — Bind `disabled` to a declared arm identity (block-1 correction)

`B3DecisionPath` accepts any `disabled` subset and records `skipped:{name}` honestly, but nothing
stops `B3` **proper** from carrying one. Before §E.6's ablation arms are built, close it: `B3`
proper **refuses** a non-empty `disabled`; only an explicitly named ablation variant may carry one;
the variant's name appears in every audit record it emits; and an ablation variant is refused
outright on a confirmatory run. Test each of the four.

## STEP 7 — Adjudicate the authorizer/containment discriminator, and record one forward risk

The authorizer/containment split currently discriminates by parsing the library's denial message for
`" in authorizer"`. It is pinned by `biscuit-python==0.4.0` and by two message-shape tests, which is
a real mitigation — but a **structural** discriminator may be available and would be stronger:
authorize the candidate against **`P_0`**, which carries no attenuation block, so a *checks-failed*
outcome there can only come from `Γ`'s own checks (expiry, audience, task).

**Verify that claim empirically before adopting it.** Establish what the library actually reports for
each of: a candidate inside `C_0` with a failing `Γ` check; a candidate inside `C_0` with all `Γ`
checks passing but narrowed away at hop 1; a candidate outside `C_0` entirely; and a candidate
outside `C_0` *with* a failing `Γ` check. Then **adopt or reject with reasons**, keeping the existing
behaviour if the probe cannot separate the planes cleanly. Either way the outcome, and the residual
if any, goes in the report and in an ADR entry or a module note.

Separately, record — in `§J` as an addition to item 20, no code change — that
`ObservedRequest.raw_arguments` is presently a canonical re-serialization rather than bytes captured
at the boundary. Harmless for an in-process adapter, but Part I's `realized_harm_F3` compares three
digests precisely so a tampered observation is caught, so once an SDK-backed adapter exists those
must be the bytes as observed. Flag it for the G-12 task spec.

## STEP 8 — Phase A checkpoint

`pre-commit run --all-files` and `uv run pytest -q` green. Report the Linux counts and the expected
Windows split. Logically scoped commits (the freeze ADR and artifact, the conjuncts, the CI split,
the `disabled` guard, the discriminator adjudication). Push; verify with `git ls-remote origin main`.
**Report before starting Phase B.**

---

# PHASE B — the two strong baselines

## STEP 9 — `B2-exchange-task`, built to win on its own terms

The fair strong OAuth arm (§E.1). Bitmask: `oauth = 1`, containment **by the AS-issued token scope**
rather than a boundary module, `audit = 1`, every other bit `0` — it gets **no** capability-layer
conjunct, and it must not be given one.

- **Phase 1** is the ADR 0021 base `AT@aud`, identical to `B3`'s. **Phase 2** is, at each hop, an
  online RFC 8693 exchange against the running AS yielding `AT_i` with authority exactly `C_i`,
  carried as RFC 9396 `authorization_details` under the ADR 0017 RAR type. That online round trip
  **is** the measured difference from the capability arms; do not shortcut it.
- The arm needs a client secret and an actor assertion. Neither may be imported from
  `src/sut/oauth_as/` and neither may touch disk. Mirror the AS's documented HKDF derivation
  **harness-side**, the way `src/harness/key_material.py` already mirrors it for the corpus labels,
  and inject the material as start-up configuration. Add an agreement test that the mirrored
  derivation and the AS accept each other — agreement is required, shared code is not.
- **Anti-bias requirements, asserted structurally and never by timing** (forbidden actions 4 and 5):
  the client dials the literal `127.0.0.1`, never the name `localhost`; one TLS context and one
  keep-alive connection are built once and reused across hops; no key is re-parsed per request; no
  disk I/O on the request path. Write a test per requirement. State in the report that these are
  structural assertions and that **nothing was timed**.
- At the boundary the arm presents `AT_n` as a bearer token and the decision is
  `src/sut/authz/boundary.py` **unchanged** — `verify_access_token`, `allowed_authority`, `admits`.

**Expected outcome, and it is the honest one:** `B2-exchange-task` **blocks** F1-root and F1-terminal,
exactly as §E.4 predicts and §E.1's paste-ready headline says — a well-configured token-exchange
deployment prevents scope amplification because it enforces the same narrowed `C_n`. If your arm does
**not** block them, that is a defect in its provisioning, not a finding about OAuth. And `B3` blocking
where `B2` also blocks is **not** evidence of an advantage for `B3`; the arms differ on invocation
binding, holder binding and online-versus-offline narrowing, which are other families and another
axis.

## STEP 10 — `B-cap`, the ablation that keeps `B3` attributable

Bitmask: `oauth = 1`, `crypto_chain = 1`, `authorizer = 1`, `contain = 1`, `audit = 1`; `htc/holder`,
`invoke`, `context`, `approval`, `jti` all `0`. Offline attenuation, **no** exchange round trip.

Per **§E.6/E6**: the primary `B-cap` fixes `oauth_authn = 1` on the same OAuth substrate as `B3` and
**MUST verify audience and expiry**. A standalone-capability configuration is not built here at all.

Build it as a **configuration of the existing decision path**, not a copy of it — the four conjuncts
it runs are the same functions `B3` runs, and its bitmask is what selects them. Its presented
evidence carries the capability prefix and the base `AT@aud`, and **no** HTC chain and **no** INV;
verify that a capability captured from the legitimate holder and presented by a different party is
**admitted** by `B-cap` and **blocked** by `B3`. That contrast is the entire reason `B-cap` exists,
and it is what stops the study attributing INV's and HTC's benefits to the capability token.

## STEP 11 — The fourth pilot scenario: `gt-f1-chain-tamper`

G-13's row names chain-tamper explicitly, so the corpus needs it. The scenario declares the
**intent** — at hop 1 the delegating party attempts to widen the authority it passes on to include
`(mail.send, mail/outbox)`, which lies outside `C_0` — and each mechanism realizes that intent its
own way (§E.3): for the exchange arm, an exchange request that would widen, which the pinned AS
profile refuses **with no token issued**; for the capability arms, an appended widening block, which
verifies cryptographically under `κ_pub` yet carries no authority under block scoping.

Expected **block** on all three strong arms, and the report must say **which conjunct or which AS
refusal** produced each block. `NA` for `B0`, whose sealed record should say so rather than claim a
result. Regenerate the corpus once, with `C_0`/`C_1` computed as before.

## STEP 12 — Phase B checkpoint

The four scenarios × three strong arms, plus `B0` as the unprotected control: report the full matrix
of admitted/blocked with the reason code for every cell, and compare it to §E.4's prediction cell by
cell. **A cell that disagrees with the prediction is a finding to report, not a number to adjust.**
Commit, push, verify. **Report before starting Phase C.**

---

# PHASE C — gate G-13

## STEP 13 — The independent harness verifier

§E.2 defines the instrument: *an independent harness verifier recomputes `Allowed(AT_i)` over `Ω`
and asserts `Allowed(AT_i) = C_i` for every hop and every strong baseline*. Build it at
`src/harness/verifier/` — it may import nothing from `src/sut/oauth_as/` (rule 4) and must not reuse
`src/sut/authz/boundary.py` as its implementation (D13/D21). It parses the presented token itself and
computes effective authority from the token's own claims, over `Ω`.

**What the G-13 row does and does not mean, and say in the report whether you agree.** The equality
is about **matched per-hop authority**, not about forcing every arm to mint a per-hop OAuth token.
For the exchange arm the per-hop object is `AT_i` and the recomputation is over its
`authorization_details` ∩ `scope` ∩ `aud`; for the capability arms the per-hop object is `P_i` and
the recomputation is `Allowed(P_i; Γ, κ, Ω)` — offline narrowing is the *measured difference*, not a
defect to be normalized away. The gate's substance is that all three arms present the **same**
`C_0 → … → C_n`. If you read the row differently, say so before implementing.

## STEP 14 — Run G-13

1. For every strong arm and every hop of every scenario: recompute the arm's per-hop effective
   authority independently and assert it equals the sealed `C_i`. **Compute, never assert** — one
   authorizer run per element of `Ω`, the G-2 discipline.
2. Cross-arm: assert the three arms realize an identical `C_0 → … → C_n`, so no strong baseline
   differs in authority granularity.
3. On F1-root, F1-terminal and F1-chain-tamper: assert each strong arm blocks, and record the
   attributable cause per arm.
4. **Adjudicate D21**, which this gate owns: the SUT-side signer is independent of the harness
   verifier. Block 1 built it and pinned agreement; G-13 is where that is *adjudicated* rather than
   re-asserted. Say whether it holds and on what evidence.
5. **Every check must be able to fail.** For each equality, construct the world in which it is false
   — a hop provisioned at `C_{i-1}` instead of `C_i`, a token whose RAR covers one element too many —
   and confirm the gate catches it. An equality that cannot fail has not been tested.

Standard shape: `smoke/g13/spike.py`, `smoke/g13/REPORT.md`, runnable as `make gate GATE=g13`. The
gate touches the AS and Biscuit but not the effect ledger, so it should be **platform-independent** —
confirm that rather than assume it, and if so add it to CI beside the G-4 and G-11 spikes.

## STEP 15 — Adjudicate honestly, and name the residual

Mark G-13 **PASS** only if the equalities hold for the arms that exist, each F1 subcase blocks on
each strong arm, and every equality was shown able to fail. If any cannot be honestly adjudicated,
**do not mark PASS**: report which, why, and the smallest correction.

**The residual is not optional.** Five arms receive per-hop `C_i`; three exist. `B2-exchange-task-DPoP`
and `B3⁺` are unbuilt, so their limbs are **open**, and the board row and report must say so in the
same words G-4's row used when it first passed over its adjudicable limbs only. Note also that DPoP
and the jti cache add binding and duplicate detection, not authority, so the open limbs are expected
to be formal — *expected*, not verified, and it must be written that way.

Update `smoke/README.md`'s G-13 row and the relevant §F.4 IA cells; correct any statement elsewhere
that becomes untrue, and where a statement was true when written add a **dated update note** rather
than a rewrite. `IA-3` stays `[UNVERIFIED-IA]`: this gate establishes matched authority, not cost.

## STEP 16 — Commit, push, archive

Logically scoped Conventional Commits, ADRs referenced in bodies. Stage new files **before** running
hooks. `pre-commit run --all-files` and `uv run pytest -q` green before each commit; state the counts
on your platform and the expected split on the other. Archive this spec under
`docs/tasks/archive/exp2-strong-baselines/` with the standing MANIFEST note that task specs are
**retrospective records, NOT pre-registration evidence**, and remove the working copy from the
repository root in the same commit (the G-11 precedent). Push and verify with
`git ls-remote origin main`.

---

## STEP 17 — Stop and report

1. STEP 0 self-check.
2. The STEP 2 read, and anything **underspecified for implementation**, with what you did about it.
3. **Phase A:** the frozen policy — artifact, `H(Λ)`, tag, the distinctness check against every tag
   in service, the necessity lines, and the three rows set. The corpus regeneration diff, showing
   `requires_approval` for `gt-f1-root` moved and **nothing else** did. The CI split, with
   before/after Linux pass and skip counts per file, and confirmation that no ledger fallback was
   introduced. The four `disabled` guard tests. The discriminator adjudication — what the library
   actually reported in each of the four probes, and adopt-or-reject with reasons.
4. **Phase B:** `B2-exchange-task` — the exchange path, the mirrored derivation and its agreement
   test, and each anti-bias requirement with the structural assertion that proves it. `B-cap` — the
   conjuncts it runs, and the captured-capability contrast against `B3`. The new scenario and how
   each mechanism realizes the tamper.
5. The **full matrix**: four scenarios × `B0`, `B2-exchange-task`, `B-cap`, `B3`, with the reason
   code per cell, compared cell by cell to §E.4. Any disagreement, unadjusted.
6. **Phase C:** the independent verifier — placement, how independence holds, and whether you read
   the G-13 row the way STEP 13 does. The equalities, computed. The cross-arm identity. The F1
   blocks with attributable causes. The D21 adjudication. For **every** equality, the
   would-have-failed world you constructed and what the gate did with it.
7. The adjudication, the open DPoP/`B3⁺` limbs stated as open, board and IA cells at their true
   values, `IA-3` untouched.
8. Confirmation that no timing number was produced anywhere, and that no secret or token reached
   disk, the repository, or `results/`.
9. Commits, push verification, counts on both platforms, and anything you could **not** verify
   yourself.
10. Any point where you were tempted to fill a gap by assumption, to weaken or over-cost `B2`, to
    normalize away the offline/online difference, to adjust a matrix cell toward the prediction, or
    to build past this specification — and what you did instead.
