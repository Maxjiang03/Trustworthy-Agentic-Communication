# TASK — Gate G-4, PHASE 1: primary sources, `authlib` probe, and the pinned AS profile design

**This pass writes NO Authorization Server.** It reads the RFCs, empirically tests whether
`authlib` closes IA-4's first limb, resolves three dependency conflicts that G-4's pass criteria
have with artifacts that are not yet frozen, and produces the design the Phase 2 build will
implement. Phase 2 is a separate task spec, written after the Commander reviews this one.

Rationale for the split: this AS **is** the OAuth 2.1 baseline. Part G lists G-4 as blocking
"IA-4; B2-exchange-task **and the fair-baseline claim**". A design error here does not produce a
failed gate — it produces a straw-man comparator and a dissertation-level validity defect that
would survive to submission. The design gets reviewed before days of code encode it.

---

## STEP 1 — Forbidden in this pass (hard constraints)

| # | Forbidden | Why |
|---|-----------|-----|
| 1 | Any AS implementation: token endpoint, exchange logic, issuance, client, resource server, or a "sketch"/"skeleton" of one | This pass is design-only; Phase 2 builds it |
| 2 | Pinning `authlib` or any other dependency; editing the `# PENDING GATE` block | ADR 0004: a pin never precedes its gate. The probe in STEP 4 is ephemeral and unpinned |
| 3 | Changing G-4's pass criteria, dependency edges, or the Part G row | ADR 0008: criteria unchanged. Evidence may be added; criteria may not be edited |
| 4 | Defining, freezing, or writing values for `Ω` or `Γ`; touching `docs/frozen_parameters.md` row 8 (or any row) | Γ is G-2's to freeze; row 8 stays UNSET |
| 5 | Inventing a construction for `INV.access_token_hash` and writing it as settled | ADR 0009 puts it in category (c), fixed at G-11. See STEP 5 — propose, never assume |
| 6 | Citing any RFC section not actually read in this pass, or reconstructing RFC text from memory | The G-1 §2 / G-8 §2 discipline. `[VERIFIED]` means read |
| 7 | Upgrading IA-4 from `[UNVERIFIED-IA]`; marking G-4 PASS on the smoke board | Adjudication is Phase 2, on the built AS |
| 8 | Touching `src/sut/`, `src/harness/`, `fixtures/confirmatory/`, Part H, `docs/PRE_REGISTRATION.md`, or any existing gate report | Out of scope; `src/harness/` changes belong to Phase 2 under the STEP 7 ADR |
| 9 | Starting G-2, G-11, G-13, G-14, or any other gate | One gate at a time |
| 10 | `git push --force`, history rewrite, credentials in the repo | PROJECT_RULES.md red lines 7–8 |

If any step cannot be completed as written, **stop and report the blocker**. Do not substitute a
weaker version of a step and report it as done.

---

## STEP 2 — Re-read the binding context

Read, and confirm in the report that each was read: `smoke/g4/SCOPE.md` (the whole file — it is
this task's parent), `adr/0008-g4-spike-parallelisation.md`, `adr/0004-*` (build-vs-reuse),
`adr/0006-*` (the joserfc/JOSE scope), `adr/0009-hjcs-construction.md` §"Adjacent digests",
`smoke/g5/REPORT.md` §§8–9, and architecture-doc §E.2, §A.5.1, §F.2 (the INV field list and its
verification list), §F.2.1, §F.4 rows IA-4/IA-5, and the Part G G-4 row.

**State in the report:** G-6 and G-7 are now **PASS**. ADR 0008 held G-4 adjudication "after
G-6/G-7"; that precondition is now satisfied, so Phase 2 may adjudicate. Confirm this reading is
correct, or explain why not.

---

## STEP 3 — Primary-source reading (before any design is written)

Read the sections listed in `smoke/g4/SCOPE.md` §5 **from the RFC text itself**. If a document
cannot be retrieved, say so explicitly and mark those sections **not read** — do not fill the gap
from memory.

Produce, in the report and in the design note, one table per RFC with columns:
**section · what it actually says (your words, no long quotation) · what it obliges the profile to
do · `[VERIFIED]` or `not read`.**

Four questions the reading must answer explicitly, each with a section citation:

1. **RFC 8693 §1.1 — delegation or impersonation?** Which does the pinned profile realize, and
   what does that choice imply for `act` (§4.1) and the `oauth_actor` identity of §A.5.1? These
   are different security models; the profile must name one and justify it.
2. **RFC 8693 §2.1/§2.2.1 — where does narrowing actually live?** §E.2 already records
   `[VERIFIED]` that RFC 8693 does not itself guarantee a narrower token and that
   scope/audience/`authorization_details` are AS-policy-determined. Confirm or correct that
   against the text, and identify precisely which request and response parameters the profile
   uses to express `C_i` and to reject widening beyond `C_{i−1}`.
3. **RFC 9396 §2/§2.1 — how is `C_i` carried?** Which common data fields (`type`, `locations`,
   `actions`, `datatypes`, `identifier`, `privileges`) map onto the experiment's action/resource
   pairs, and what does §5 say about `authorization_details` in the token response? Also §12: what
   does the RFC itself require the AS to enforce?
4. **RFC 8707 §2 and RFC 9449 §5/§7.1 — audience and holder binding.** How is `AT@aud` expressed
   and enforced, and how does a real AS mint `cnf`/`jkt` at the token endpoint (which G-5 only
   simulated)? Plus the two G-5 hand-forwards in AS/RS context: `ath` (§4.2) and the nonce
   protocol (§§8–9).

RFC 9068 and RFC 8414 are read **only if** the design uses JWT access tokens or advertises
discovery respectively; if not used, record them as out of scope rather than silently skipping.

---

## STEP 4 — Empirically probe `authlib` (this is evidence, not construction)

IA-4 is a disjunction: the stack supports RFC 8693 narrowing + RFC 9396 `authorization_details`,
**or** a faithful AS can be built. `smoke/g4/SCOPE.md` §2 marks "no off-the-shelf Python AS
supports both" as an ADR 0004 **project decision, rebuttable — not an external fact**. This step
tests it, in the G-8 spirit: an off-the-shelf candidate is examined against the requirement and
either adopted or rejected **on recorded evidence**.

Write `smoke/g4/probe_authlib.py` — a short, self-contained probe, run in an **ephemeral**
environment (`uv run --with authlib python smoke/g4/probe_authlib.py`), nothing pinned. It must:

- Record the exact version resolved, and enumerate what the installed package actually exposes
  for token exchange and for `authorization_details` — by inspecting the installed source, with
  `file:symbol` citations in the G-6 style, not by trusting documentation or recollection.
- Attempt the smallest concrete thing that would satisfy the requirement: an RFC 8693 exchange
  whose issued token carries a **narrowed** authority expressed as `authorization_details`.
- Record the outcome precisely: supported / partially supported (name exactly which half, and
  what would have to be written by hand) / unsupported (with the failure, not a summary of it).

**Report whichever answer you get.** If `authlib` does close the first limb, that refutes an ADR
0004 finding and changes the plan — say so plainly; do not steer toward the build because the
build was expected. Exit code: 0 if the probe ran and produced a verdict, non-zero only if the
probe itself failed to run.

---

## STEP 5 — Three dependency conflicts: resolve honestly, do not paper over

G-4's pass criterion is *"RFC 8693 exchange under the pinned AS profile yielding `C_i`; verify
OAuth-resource ∩ capability effective authority, `actor→holder` mapping, `INV.access_token_hash`"*.
Three of those limbs depend on artifacts that are **not yet fixed**. Each must be addressed in
the design note, and none may be closed by inventing a frozen value.

- **C1 — `Ω`/`Γ` are UNSET** (`frozen_parameters.md` row 8; G-2 is blocked on exactly this), so
  the capability-side effective authority cannot be computed by the frozen authorizer.
- **C2 — `INV.access_token_hash = H(AT@aud)` has no fixed construction.** ADR 0009 classifies it
  as category (c), *"fixed when INV/HTC are built and mutation-tested (G-11)"*. Note the adjacent
  trap: RFC 9449's `ath` is a base64url SHA-256 over the token string, and the access token is a
  string rather than a JSON object, so `H_JCS` may not apply at all. Two different digests over
  the same token must never be conflated — this is the same class of underspecification G-8
  refused to invent and ADR 0009 later closed.
- **C3 — the identity-plane registry (§F.2.1) is not built**, and the HTC chain that names
  `htc_holder` does not exist yet, so `actor→holder` has nothing to resolve against.

For each, the design note must state: the conflict; the **minimal provisional stand-in** Phase 2
will use (spike-local, explicitly labelled, never promoted to a frozen artifact); what the limb
therefore does and does **not** establish; and the **re-adjudication trigger** — the event
(Γ frozen at G-2, `access_token_hash` fixed at G-11, registry built) that requires G-4's affected
limb to be re-run. This mirrors the standing pin rule: any bump re-triggers its gate.

If you judge that a limb cannot be honestly adjudicated even with a labelled stand-in,
**say so and propose scoping it to a follow-on adjudication** rather than reporting a pass.

---

## STEP 6 — Write `smoke/g4/DESIGN.md`, the pinned AS profile

The specification Phase 2 implements. Required content:

1. **The profile.** Endpoints, grant types, token format, and exactly how, at hop `i`, the AS
   issues `AT_i` with authority `C_i` and **enforces `C_i ⊆ C_{i−1}`, rejecting widening**
   (§E.2). Every mandated behaviour carries its RFC section citation from STEP 3.
2. **Rejection catalogue.** What the AS must refuse and with which error — widening attempts,
   audience mismatch, unknown actor, expired/replayed subject token, malformed
   `authorization_details` — grounded in RFC 8693 §2.2.2/§5 and RFC 9396 §12.
3. **Identity plane.** How `resource_owner`, `oauth_actor`, and `htc_holder` are represented and
   kept distinct, and how the mapping checks **only** `oauth_actor → htc_holder` (§A.5.1 forbids
   requiring `resource_owner = holder`).
4. **Process and key isolation.** The AS runs **out-of-process**; its signing key is never
   present in any agent process. State the mechanism. Phase 2 will additionally demonstrate that
   an SUT-side attempt to mint its own `AT` fails — record this as **additional evidence beyond
   the pass criteria**, explicitly not a criterion change (STEP 1 item 3). Without this, a
   baseline agent could forge the very tokens the baseline is supposed to constrain.
5. **Fair-baseline hazards — both directions, named.** This AS is the comparator B3 is measured
   against, and G-4 blocks the fair-baseline claim.
   - *Too weak:* a toy AS that skips mandated checks makes B2 a straw man and voids the
     comparative claim. Enumerate the checks that must not be dropped for convenience.
   - *Too slow:* B2's measured `delegation_cost` is an online AS round-trip (§E.2) while B3's is
     offline. Gratuitous inefficiency — re-parsing keys per request, avoidable serialization
     round-trips, blocking I/O where the design does not require it — inflates the baseline and
     biases the overhead result **in B3's favour**. State the implementation choices that
     materially affect this and the stance taken. Deliberate pessimization is forbidden;
     micro-optimization beyond a competent straightforward implementation is not required.
     Measurement itself is G-3/G-13, not this gate.
6. **Test plan for Phase 2**, one row per G-4 pass-criterion limb, plus the STEP 5 stand-ins and
   their labels, plus the two G-5 hand-forwards (`ath`, nonce) which the real AS/RS flow must now
   exercise.
7. **Explicit non-goals:** the arms, HTC/INV construction, G-13's `Allowed(AT_i) = C_i`
   verification, the G-14 DPoP taxonomy, and any performance measurement.

---

## STEP 7 — ADR: where the AS lives, and on which side of the boundary

The layout has two homes — `src/sut/` (measured) and `src/harness/` (instrument) — and the AS is
neither comfortably. It is a counterparty service whose round-trip cost is *inside* the measured
quantity, yet the harness must not issue the credentials it later adjudicates.

Write an ADR that decides the placement and records the reasoning, honouring: PROJECT_RULES.md red line
6 (`src/sut/` never imports `src/harness/`); the independence discipline that the oracle never
consumes SUT-computed values; and STEP 6 item 4's process/key isolation. If the decision requires
amending the layout paragraph in `README.md` or `PROJECT_RULES.md`, make that amendment in the **same
commit** as the ADR. If you conclude the choice is genuinely close, present both options with the
trade-off and **stop for the Commander's decision** rather than picking silently.

---

## STEP 8 — Commit and push (documents and the probe only)

Logically scoped Conventional Commits; ADR referenced in the body; `pre-commit run --all-files`
and `uv run pytest -q` green before each commit (expected on Windows: **42 passed**; the six
ledger tests are Windows-only per ADR 0014). Update the `smoke/README.md` G-4 row to reflect
"Phase 1 complete — design under review", still **not adjudicated**, IA-4 still
`[UNVERIFIED-IA]`. Archive this spec under `docs/workplan/archive/g4-phase1/` with the standing
MANIFEST note that task specs are **retrospective records, not pre-registration evidence**.
Push to `origin main` and verify with `git ls-remote origin main`.

---

## STEP 9 — Stop and report

**Do not begin the AS build.** Report, in this order:

1. STEP 0 self-check result.
2. Confirmation of the G-6/G-7 → adjudication-unblocked reading.
3. The RFC tables — including anything **not** read and why — and the four STEP 3 answers.
4. The `authlib` verdict, with the `file:symbol` evidence and the exact failure or success.
5. The three conflicts (C1–C3): stand-in, what each limb will and will not establish,
   re-adjudication trigger.
6. The design note's decisions, especially delegation-vs-impersonation, how `C_i` is carried, and
   the fair-baseline stance in both directions.
7. The placement ADR — or the two options, if you stopped for a decision.
8. Commits, push verification, and anything you were unable to verify yourself.
9. Any point where you were tempted to fill a gap by assumption, and what you did instead.
