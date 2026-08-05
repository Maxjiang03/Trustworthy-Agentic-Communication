# TASK — Experimental body, block 7: the missing subcases, the held-out subset, and the last open decisions

Block 6 gave the study an oracle that can score itself and a campaign entry point that can run it.
This block gives that oracle **everything it is supposed to score**, and closes the last decisions
standing between the apparatus and Part H's seal loop.

Three gaps, and each is *not yet built* rather than *built wrong*:

- **Five §E.4 subcases have no corpus scenario.** They are exercised in arm unit tests — `test_b1.py`
  proves `B1` refuses an invalid credential, `test_b2_dpop.py` proves the DPoP arm refuses a
  substituted key — but a unit test establishes *this arm refuses*, while a corpus scenario produces
  *what all nine arms do*, scored by the oracle. Only the second is a result.
- **There is no held-out subset.** Part H step 4 requires the confirmatory corpus to include a
  **held-out third**, and RQ3 asks for outcomes *"on seen and sealed held-out instances"*. Without
  it, half of RQ3 cannot be answered.
- **`B3⁺` is not wired to G-9's arbiter**, which block 5's own sweep found and recorded honestly.
  G-9's PASS is a property of the arbiter; the ladder's `B3⁺` carries an in-process cache. That gap
  needs a **decision**, not a silent default.

**Phase order, revised.** A first reading of this spec established the Phase A design without
writing code and stopped rather than half-build it — the right call, and its findings are folded in
below. Run the phases in this order: **C first** (STEP 8–9: ADR 0034, fully specified and
self-contained), **then A** (STEP 3–5: the five subcases), **then B** (STEP 6–7: the held-out
mechanism). Report between phases; stopping at a committed green state remains the right call, and
a Phase A left half-built would leave the corpus carrying rows the campaign silently skips — worse
than not writing them.

---

## STEP 0 — Self-check, and the machine

and remember that `pytest` green is not `main` green.

---

## STEP 1 — Forbidden in this pass

| # | Forbidden | Why |
|---|-----------|-----|
| 1 | **Producing, benchmarking or reporting any latency number** | G-3 has not run and the platform is not locked |
| 2 | Running, preparing or marking any gate; editing any Part G row, pass criterion, dependency edge or evidence grade | G-10 is next and is not yours to start |
| 3 | **Generating, populating or sealing the confirmatory corpus** | Part H steps 3–6, in that order, and step 3 comes first. This block builds the **held-out mechanism**; it does not run it against `fixtures/confirmatory/`, which stays empty |
| 4 | Drafting `PRE_REGISTRATION.md` | Part H step 2, after G-3 and G-10. Record obligations; do not discharge them |
| 5 | Adding a `wrong_principal` scenario in any form | ADR 0028 deferred it **by decision**, and requires the held-out subset to be **scanned** to confirm none exists |
| 6 | Amending any frozen row, `Ω`/`Γ`, the registry, the policy document, or any `H(·)`; adding an element outside `Ω` | ADR 0016 and the rest of the freeze family |
| 7 | **Weakening an arm so a new subcase produces a tidier row** | Six blocks of the same hazard. A subcase that refuses on an unexpected conjunct is a **finding** |
| 8 | Changing a Part I predicate to make a new subcase score the way §E.4 predicts | Part I is the specification; §E.4 is the prediction. A disagreement between them is a result |
| 9 | Any import of `src/harness/` from `src/sut/`; of `src/sut/oauth_as/` from a non-AS `src/sut/` module or from `src/harness/` | Red line 6, ADR 0015 |
| 10 | Secrets, minted tokens or **seeds** on disk, in the repository, or in `results/`; `git push --force`; history rewrite | Red lines 7–8, and Part H's seed-disclosure warning: publishing corpus seeds publishes every private key derived from them |

If a step cannot be completed as written, **stop and report the blocker**.

---

## STEP 2 — Read what you are implementing

**§E.4's full matrix**, every row; **§D.2's four-way DPoP taxonomy** with each row's predicted
outcome; **Part I** (the predicates block 6 completed, and `realized_harm_F2`'s `cred_result`);
**Part H steps 3–5** — what the seal covers (**generators and seeds, never pre-minted tokens**,
ADR 0007), the held-out third, and the **disjointness check on specification and seed content
hashes, never on token bytes**; **RQ3's** wording on seen versus held-out; **ADR 0007**;
**ADR 0028** (the `wrong_principal` deferral and its scan obligation); **ADR 0027** and **ADR 0033**
(`Δ`, the arbiter, and what G-9 does and does not establish about the ladder's `B3⁺`).

Then: `fixtures/pilot/golden_thread/generator.py`, the existing sealed/SUT-visible split,
`src/harness/campaign.py` and the oracle from block 6, `tests/test_b1.py` and `tests/test_b2_dpop.py`
(the unit-level versions of three subcases you are about to promote), and `smoke/g9/REPORT.md`.

**Report what turns out underspecified for implementation, and what you did.**

---

# PHASE A — the five missing subcases

## STEP 3 — Promote them from unit tests to corpus scenarios

**All five are credential attacks, not authority-scope attacks**, and that is why this step is not
the routine corpus work it looks like. Every scenario built so far is expressible as corpus **data**
— tool, arguments, `R`, chain. None of these five is: each needs a specific **corruption of the
runtime credential**, and the generator has no vocabulary for saying what is wrong with one.

**The mechanism, determined by the first reading and adopted here.** Add a `credential_fault` field
**declared in the sealed document and realized per mechanism** — the same *intent realized per
mechanism* pattern `widening_elements` already uses for chain-tamper. **Sealed, never SUT-visible**,
and that placement is load-bearing: a SUT-visible fault would let an arm branch on *"I am under
attack."* The arm must see only a credential that happens not to verify.

**Two realization levels, and the split is forced by the code, not chosen:**

| fault | level | realization |
|---|---|---|
| `invalid_credential` | provisioning | corrupt the AT signature |
| `unauthenticated_caller` | provisioning | no token |
| `audience_mismatch` | provisioning | a second `ASProcess`, same seed, different corpus audience — genuinely signed, wrong `aud`, and **no change to `src/sut/oauth_as/`** |
| `wrong_registered_holder` | **presentation** | re-sign the INV harness-side, between the arm and the resource server |
| `stolen_AT_key_substitution` | **presentation** | another key's proof against the same token |

**Why the last two cannot be provisioning-level, verified against the code:**
`b3.py`'s `delegate` reads `holder_privates["holder-specialist"]` to name the next holder in the HTC
chain, and `present` reads the same key to sign the INV. Swapping it at setup changes **both**, so
the chain would name an unregistered key and `identity_plane_consistency_ok` would fire instead of
`holder_proof_ok` — a block on the wrong conjunct, which trap 1 below and forbidden action 7 both
target. The fault must sit **between the arm and the resource server**, which is also exactly §D.2's
threat model.

That is small and reuses existing machinery rather than duplicating it: the INV wire is
`{"payload", "signature"}` JSON, and `src/harness/verifier/holder_binding.py` already exports
`INV_TAG`, `signing_input` and `seal(...)`. A harness-side re-sign touches **no** SUT code.

Build one scenario each, on the existing two-chain corpus, computing `C_0`/`C_1` with the frozen
authorizer and asserting them against each spec as the generator already does:

| subcase | what it is | note |
|---|---|---|
| `F2 invalid_credential` | a credential that does not verify | `B0` is `NA` (`oauth_authn = 0`) |
| `F2 unauthenticated_caller` | a caller presenting nothing | `B0` admits; every other arm blocks |
| `F2 wrong_holder_proof / wrong_dpop_key` | a proof from a registered but wrong holder | `NA` for the six arms with `htc_holder = 0`; the registry lookup must **succeed** so only the holder limb can catch it |
| `F3 dpop-stolen-AT-key-substitution` | T-reuse: another key's proof against the same token | §D.2 predicts blocked by DPoP |
| `F3 audience mismatch` | a token for the wrong resource server | ADR 0031 applies: `B-cap` is **`B`**, not `NA` |

**Each `NA` must be recorded in the sealed record with its reason**, as the F1 chain-tamper row
already does, and the campaign must **not run** that cell. `NA` asserts *this arm cannot express the
case* (ADR 0028) — if an arm could express it, it is not `NA`.

**Derive every `NA` from the §E.5 bit governing its row, never from the arm's family.** That is the
ADR 0031/0032 lesson: both corrections existed because §E.4 was drafted by filling `B-cap` in as
"a capability arm" instead of reading its own bits. The first reading's derivation, to be **verified
rather than trusted**: `invalid_credential` → `B0` only; `unauthenticated_caller` → **none**, since
`B0` admits; `wrong_holder_proof` → the six arms with `htc_holder = 0` (`B0`, `B1`, both broad arms,
`B2-exchange-task`, `B-cap`); both F3 rows → none. Recompute each from the bitmask and report any
disagreement with that list.

**Two traps this corpus has already sprung twice; do not spring them a third time.**

1. **Containment must not fire first.** On the F1 chain `mail.send` and `notes.delete` sit outside
   `C_1`, so a scenario placed there is refused by `containment_ok` before the conjunct under test
   runs. Block 4 hit this and built a second chain. **Resolution adopted here:** all five run on the
   **F1 chain with `notes.write`**, where `R ⊆ C_1`, so `containment_ok` passes and only the
   credential conjunct can refuse. Assert per scenario that the block is **attributable to the
   conjunct the subcase targets**, not to containment.
2. **One clock.** Block 4's F4/F5 fixtures and block 5's G-14 fixture both failed first on a frozen
   fake instant meeting an AS minting against the wall clock. Take one live instant at start-up and
   inject it everywhere. Nothing sleeps.

## STEP 4 — `realized_harm_F2` needs its `cred_result`

Part I's `realized_harm_F2` takes a `cred_result` carrying `principal_verified` and `principal`.
Block 6 defined where it comes from; these three F2 subcases are the first to **exercise** it.

It is a **harness-side, independent** credential verification (D21) — it must not be the arm's own
check re-read. Confirm that, and confirm the oracle scores all three F2 subcases from it.

## STEP 5 — Score the five, and Phase A checkpoint

Run the block-6 campaign entry point over the extended pilot corpus and produce the five new rows
**from oracle verdicts**, all nine arms, compared cell by cell with §E.4.

**A disagreement is a finding.** Report it; adjust neither the arm, nor the predicate, nor the
prediction. If a subcase blocks on a conjunct §E.4 does not attribute it to, say which.

`pre-commit` and `pytest` green, plus every gate spike. Counts **measured or derived**. Commit,
push, verify. **Report before Phase B.**

---

# PHASE B — the held-out mechanism

## STEP 6 — Build the split; do not run it against the confirmatory corpus

Part H step 4: the confirmatory corpus is generated **including the held-out third**. Build the
mechanism and exercise it **on the pilot corpus only** (forbidden action 3).

- The split is **deterministic from the sealed seed**, so it is reproducible from sealed inputs and
  is not a choice made at analysis time. A split anyone could redo after seeing results is not a
  held-out set.
- It is **stratified by family**, or RQ3's held-out arm could be answered for some families and not
  others. Say what happens when a family has too few instances to split — refuse, or record the
  family as unsplittable, but do not silently round.
- The generator **seals which instances are held out** before any of them runs, and the campaign
  **cannot read** the split at scoring time — only the analysis can, afterwards. If the campaign
  could see it, "held out" would mean nothing.
- **Disjointness** is asserted on **specification and seed content hashes, never on token bytes**
  (Part H step 5, ADR 0007 — tokens differ across mints even for the same logical scenario).

## STEP 7 — Discharge ADR 0028's scan, and record the rest

- **Scan the split for any `wrong_principal` variant** and confirm none exists. ADR 0028 requires
  this **before the seal**, when the check can still change something. Make it an executed test, not
  a note.
- **Record, do not discharge**: the `PRE_REGISTRATION.md` statement and the confirmatory generation
  itself. Both are Part H steps this block does not reach.

Commit, push, verify. **Report before Phase C.**

---

# PHASE C — the last open decisions

## STEP 8 — `B3⁺` and the arbiter: implement the Commander's ruling

Block 5's sweep established three facts: within one SUT process `B3⁺` blocks the bit-identical
replay and §E.4's cell is unmoved; across two SUT processes it does not, because each arm instance
builds its own `JtiCache`; and **no ladder arm is wired to G-9's arbiter** — `RemoteJtiCache` appears
only in G-9's spike.

**The Commander's ruling: option (b).** The campaign runs in a **single-process** configuration, and
that is stated rather than assumed. Write **ADR 0034** recording:

- what G-9 establishes — that the mechanism is **sound under multi-process concurrency**, adjudicated
  on the arbiter;
- what the ladder measures — `B3⁺` carrying the in-process cache, which is **correct for a
  single-process campaign** and is the configuration §E.4's cell was predicted for;
- that the two are **not the same claim**, and the dissertation must not let a green G-9 be read as
  "the ladder arm has multi-process atomicity";
- the seam that would wire them (`RemoteJtiCache` exists and is tested), so the deferral is a
  **decision**, not an absence;
- a **§J** entry: a multi-process deployment would need the arbiter, and this study does not
  measure that configuration.

Then **assert the campaign configuration structurally**: a confirmatory run refuses to proceed
multi-process while `B3⁺` carries an in-process cache. A ruling that only a reader enforces is not
enforced.

## STEP 9 — Confirm the two carried notes, and Phase C checkpoint

1. **G-9's 900 s budget** is a **timeout budget, not a performance baseline**. One comment line in
   the spike; no ADR. It exists because filling the frozen 2¹⁶ through the real `consume` path is
   quadratic (2,147,450,880 scan steps — an operation count, not a timing).
2. **§J.5 item 20** (`raw_arguments` is a canonical re-serialization, not captured wire bytes) and
   **ADR 0020** (the in-process A2A adapter, not the official SDK) are both construct-validity
   threats that will be **live at seal time**. Confirm both are stated in §J in terms a reader of the
   dissertation would understand, and that neither is described as closed.

`pre-commit` and `pytest` green, plus every gate spike.

---

## STEP 10 — The standing check

Seven blocks, seven instances of one hazard. This block adds five scenarios, a corpus split and a
configuration constraint.

Ask explicitly: **does any new scenario make an existing arm's distinguishing capability
unobservable?** In particular — do the three F2 subcases still let `B2-DPoP` and `B3` separate on
holder binding, or does an earlier conjunct now fire for all of them? Does the held-out split leave
**every family** with instances on both sides? Do all thirteen gates still pass? **Report per arm
and per gate.**

---

## STEP 11 — Commit, push, archive

Scoped Conventional Commits, ADRs referenced in bodies. Archive this spec under
`docs/workplan/archive/exp7-subcases-and-heldout/` with the standing note that task specs are
**retrospective records, NOT pre-registration evidence**, and remove the working copy in the same
commit. Push; verify with `git ls-remote origin main`.

---

## STEP 12 — Stop and report

*(Report the phases in the order you ran them: C, then A, then B.)*

1. STEP 0 self-check and the hook confirmation.
2. The STEP 2 read, and anything **underspecified for implementation**, with what you did.
3. **Phase A:** the five scenarios, each with its computed `C_0`/`C_1`, its `NA` arms with recorded
   reasons, and the evidence that the block is attributable to the conjunct the subcase targets
   rather than to containment. The one-clock handling.
4. `realized_harm_F2`'s `cred_result` — what produces it, and how it stays independent of the arm.
5. **The five new rows from oracle verdicts**, all nine arms, compared cell by cell to §E.4. Every
   disagreement, unadjusted.
6. **Phase B:** the split — deterministic from the sealed seed, stratified by family, sealed before
   any instance runs, unreadable by the campaign, disjointness asserted on specification and seed
   hashes. The `wrong_principal` scan, executed. What was **recorded rather than discharged**.
7. **Phase C:** ADR 0034 and the structural assertion that enforces it. The two carried notes.
8. STEP 10's answer, per arm and per gate.
9. Commits, push verification, counts on both platforms **measured or derived**, every gate spike's
   result, and anything you could **not** verify.
10. Any point where you were tempted to weaken an arm for a tidier row, to adjust a cell toward the
    prediction, to let the campaign see the split, or to build past this specification — and what you
    did instead.
