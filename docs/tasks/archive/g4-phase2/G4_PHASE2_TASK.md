# TASK — Gate G-4, PHASE 2: build the pinned experiment AS and adjudicate

Phase 1 produced `smoke/g4/DESIGN.md` (613 lines): the RFC reading, the `authlib` rejection, the
pinned AS profile, a seventeen-row rejection catalogue, the identity plane, the fair-baseline
stance in both directions, and a per-limb test plan in §10. **This pass implements that document
and runs the gate.** The design is not re-opened here; where implementation reveals a genuine
defect in it, STOP and report rather than quietly diverging.

This is the project's **first real system code** — a network service with state, not a
three-hundred-line verification module. Every previous gate produced an instrument; this one
produces a component that the measured arms will run against. Two consequences run through the
whole spec: the **minimum that satisfies the design** is the target, and the AS **is the OAuth 2.1
baseline**, so its quality in *both* directions is a methodological property, not a matter of
taste.

Adjudication is unblocked: G-6 and G-7 are PASS (ADR 0008's precondition), and ADR 0016 closed
conflict C1, so limb L2 now runs over the **frozen** `Ω`/`Γ` — themselves adjudicated by G-2 —
with no stand-in.

---

## STEP 0 — Self-check (do this first, report the result)

Run `wc -l` and `sha256sum` on this file. Expected: **the line count and digest quoted in the
launch prompt**. If either differs, **STOP and report** — do not act on a partial spec.

---

## STEP 1 — Forbidden in this pass

| # | Forbidden | Why |
|---|-----------|-----|
| 1 | Editing G-4's pass criteria, dependency edges, evidence grades, or the Part G row | The gate executes frozen criteria (ADR 0008) |
| 2 | Adjudicating limb **L4** (`INV.access_token_hash`), or inventing its construction | DESIGN §9 C2: ADR 0009 category (c), fixed at G-11. Phase 2 tests the **precondition only** — the AT byte string is observable and stable, a swapped token is detectable — and L4 stays scoped to a follow-on run |
| 3 | Modifying `src/harness/authorizer/omega_gamma_v1.json`, `frozen_config.py`, `Γ`, `Ω`, or `H(Γ)`; setting any `frozen_parameters.md` row | ADR 0016 froze row 8; rows 1–7, 9, 10 stay UNSET. A defect found here → STOP, corrective ADR |
| 4 | `src/harness/` importing `src/sut/oauth_as/`, or any other `src/sut/` module importing it | ADR 0015 / DESIGN §5.4: the instrument must never mint or share implementation with what it adjudicates (D13/D21) |
| 5 | Writing the AS signing key to disk, exporting it, or serving a `jwks_uri` | DESIGN §5.4: key born and dies in the AS process; the public key reaches the boundary from sealed configuration |
| 6 | Weakening any §8.1 check "for now", or adding any inefficiency §8.2 rules out | §8.1 makes the baseline a straw man; §8.2 biases overhead **toward B3**. Both corrupt the fair-baseline claim this gate exists to protect |
| 7 | Building the arms, agents, protocol adapters, HTC/INV, the oracle, fixtures, or any performance measurement | DESIGN §11 non-goals. G-11, G-13, G-14, G-15, G-3 own these |
| 8 | Implementing G-13's `Allowed(AT_i) = C_i` verification, or the `R ⊆ C_n` boundary rule beyond what limb L2 needs | G-2's report flagged `R ⊆ C_n` as untested and owned by G-13. Phase 2 must not annex it |
| 9 | Pinning `authlib`, or editing the `# PENDING GATE` block | DESIGN §3: the probe rejected it. Nothing new is pinned unless a dependency is genuinely required — see STEP 3 |
| 10 | Marking G-4 PASS if any adjudicable limb was not genuinely exercised | See STEP 7 |
| 11 | `git push --force`, history rewrite, credentials in the repo | CLAUDE.md red lines 7–8 |

If a step cannot be completed as written, **stop and report the blocker**. Do not substitute a
weaker version and report it as done.

---

## STEP 2 — Read the design you are implementing

Read `smoke/g4/DESIGN.md` **in full** — it is the specification, and §§5–8 were written to be
implemented rather than summarized. Confirm in the report that you read: §5.1 (shape, endpoints,
token format), §5.2 (`C_i` as a single-type RAR array; `expand`; byte-exact containment), §5.3 (the
hop-`i` exchange and the four planes in which widening is refused as an **error**, never a silent
clamp), §5.4 (process and key isolation), §6 (the seventeen-row rejection catalogue), §7 (identity
plane; §7.3's two different "holders"; §7.4's inherited dependency), §8.1/§8.2/§8.3, §9 (C1 closed,
C2 and C3 open with their stand-ins), §10 (the test plan you are executing), §11 (non-goals).

Also read: the **Part G G-4 row verbatim**; **ADR 0015** (placement and the four rules travelling
with it); **ADR 0016** (frozen `Ω`/`Γ`, the string encoding — `Ω`'s action side is the RAR
`actions` value and its resource side the `datatypes`/`identifier` value per DESIGN §5.2);
`smoke/g2/REPORT.md` (what G-2 established about the frozen authorizer, and what it explicitly did
**not** — `R ⊆ C_n`); and `smoke/g5/REPORT.md` §§8–9 for the `ath`/nonce hand-forwards A5/A6 now
exercise for the first time.

State in the report which parts of the design turned out to be **underspecified for
implementation**, if any, and what you did — see STEP 8.

---

## STEP 3 — Build the AS: the minimum that satisfies the design

Implement `src/sut/oauth_as/` per §5. Scope discipline is the governing constraint: **build what
§§5–7 specify and nothing else.** No feature is added because it "might be useful later"; no
endpoint exists that no test exercises. Every hour spent on unspecified capability is taken from
the results chapters.

- **Endpoints and grant.** Exactly §5.1: one token endpoint, the RFC 8693 extension grant, no
  discovery, no `jwks_uri`, no authorization endpoint (§8.2's last row: Phase-1 setup uses the
  pre-issued fixture path, identical across arms and excluded from the delegation estimand).
- **`C_i` carriage and containment.** Per §5.2: single-type RAR array; the product expansion is the
  meaning; containment is set containment over expanded triples with **byte-exact** RFC 8259
  comparison and no normalization. Every value must be a member of the frozen `Ω`; an out-of-`Ω`
  string is a rejection, never an implicitly new authority element.
- **Narrowing and refusal.** Per §5.3: `C_i ⊆ C_{i−1}` enforced across all four planes (RAR
  expansion, audience, scope, expiry); widening produces the §6 error with **no token issued**.
- **Delegation, not impersonation.** `sub` = resource_owner; outermost `act` = current actor;
  prior actors nested and **never consulted** in a decision (RFC 8693 §4.1).
- **Process and key isolation.** Per §5.4, exactly: own process, loopback only, Ed25519 key
  derived in-process at start-up from the ADR 0007 seed, never on disk, only the public key
  leaving, and both import rules holding.
- **Boundary-side verification.** Limb L2 needs the MCP boundary to compute `Allowed(AT_i)` =
  `expand(AT_i.authorization_details)` ∩ the OAuth-resource plane (`aud`, `scope`), independently
  of the AS. Implement only what L2 requires; `R ⊆ C_n` in the general case is G-13's (STEP 1 #8).

**Dependencies.** Prefer the standard library and what is already pinned (`joserfc` for JOSE per
ADR 0006, `rfc8785`, `mcp`). If an HTTP server or client library is genuinely required, state
which, why the pinned set is insufficient, and pin it in the **same commit** with a one-paragraph
ADR — a pin never precedes its justification (ADR 0004).

**Fair-baseline compliance is a deliverable, not a side effect.** Report §8.1 row by row (each
check present and exercised) and §8.2 row by row (each choice implemented as decided, or — if
implementation forced a different choice — the divergence, its bias direction, and why it is
acceptable). §8.3's disclosed RFC 9068 non-conformance must be restated wherever the AS is
described; no document may claim conformance.

---

## STEP 4 — Stand-ins: labelled, bounded, and re-triggered

C3 remains open: no registry, no HTC chain. Use the §9 C3 stand-in — spike-local
`oauth_actor → principal → Ed25519 key`, including a deliberately unmapped actor — and **nothing
more**. It is not the frozen registry (`frozen_parameters` row for the identity-plane registry
stays unset), it is not an HTC chain, and it must print its `SPIKE-LOCAL` banner wherever it
appears (§10's closing rule).

For every stand-in used, the report states what the limb **does** and **does not** establish, and
the event that re-triggers it (G-11 for C3). Same discipline as G-4 Phase 1 and ADR 0016.

---

## STEP 5 — Execute the §10 test plan

Write `smoke/g4/spike.py` in the established shape (a `RESULTS` table of
`(check, mandatory, passed, evidence)`, explicit exit code, no state leaking across checks), plus a
durable test module. Execute §10's rows: **L1, L1′, L2, L3, A1, A2, A3, A4, A5, A6, A7** — and
**L4 as precondition only** (STEP 1 #2).

Each check must be constructed so the **wrong** outcome is observable as a failure — the discipline
G-2 applied throughout. For each, the report gives: what was constructed, the outcome, the exact
call/response/error that produced it, and **what the failing world would have been**.

Specific requirements that are easy to satisfy weakly and must not be:

- **L1′ (widening refused).** All four attempts — extra `actions`, extra `datatypes`, wider
  `resource`, longer `exp` — each rejected with the **exact** §6 error code and status, and each
  verified to have issued **no token**. A silent clamp passing as a refusal is the failure mode:
  assert the absence of a token, not merely that the response differs.
- **L2 (both layers).** Both directions: inside RAR but outside `scope`/`aud` → denied; and the
  converse. Over the **frozen** `Ω`/`Γ`, no stand-in.
- **L3 (`actor→holder`).** Include the negative test asserting the AS/boundary **never** requires
  `resource_owner = holder` (§A.5.1), and that nested `act` history is present but not consulted.
- **A2 (rejection catalogue).** One test per §6 row asserting the **exact** error code and status —
  seventeen rows, seventeen tests. A test that accepts "some error" does not exercise the row.
- **A3 (§12 string rule).** `Read` vs `read`, and NFC-vs-NFD variants, are not equal and do not
  narrow-match. Note ADR 0016 fixed `Ω` as US-ASCII lowercase, so an NFD variant is simply not in
  `Ω` — assert both the encoding rejection and the non-equality.
- **A4 (key isolation — additional evidence, explicitly not a criterion change).** An SUT-side
  attempt to mint an `AT` fails; both ADR 0015 import rules hold, asserted programmatically.
- **A5/A6 (`ath`, nonce).** First real exercise of the G-5 hand-forwards, in a genuine AS/RS flow:
  wrong/missing `ath` rejected; the AT's bound key must match the proof key; the nonce path
  produces `use_dpop_nonce` + `DPoP-Nonce`, retry succeeds, stale nonce rejected, and AS/RS nonce
  namespaces are distinct.

The spike must run on **both** platforms (this is not the Windows-only ledger); confirm it in CI.

---

## STEP 6 — `smoke/g4/REPORT.md`

The durable record: the criteria verbatim; what was built and where; §8.1 and §8.2 row-by-row
compliance; per-limb construction, outcome, exact call/error, and would-have-failed world; the C3
stand-in's scope and re-trigger; L4's precondition-only result and why the limb is not adjudicated;
§8.3's non-conformance restated; and the grade line — what is now `[VERIFIED]` for this AS build
versus what remains design or deferred. State plainly what G-4 does **not** reach: G-13's
`Allowed(AT_i) = C_i`, the DPoP taxonomy (G-14), HTC/INV (G-11), and any timing claim (G-3).

---

## STEP 7 — Adjudicate honestly

Before marking anything, confirm per limb that it was **exercised**, not assumed. Mark G-4 **PASS**
only if L1, L1′, L2, L3 and the A-rows all genuinely hold, with **L4 recorded as scoped out** —
state explicitly that the PASS is over the criteria's adjudicable limbs with L4 pending a
post-G-11 follow-on, so no reader can take it as a full four-limb closure.

If any adjudicable limb cannot honestly pass, **do not mark PASS**: report which, why, and the
smallest correction — the precedent set by G-4 Phase 1 and honoured by G-2.

On PASS: update `smoke/README.md`'s G-4 row and set IA-4 in §F.4 to verified-by-G-4 with its scope
(the AS build, the frozen `Ω`/`Γ`, the C3 stand-in, L4 pending). Touch no other row, and no
criterion text. If a statement elsewhere becomes untrue as a result — G-2's pass handled three such
— correct it; where a statement was true when written, add a dated update note rather than a
rewrite.

---

## STEP 8 — Commit, push, archive

Logically scoped Conventional Commits — the AS build, the gate run, and any documentation update in
**separate** commits; ADRs referenced in bodies. Stage new files **before** running hooks so
formatters see them. `pre-commit run --all-files` and `uv run pytest -q` green before each; state
the Windows count and the expected Linux split. Archive this spec under `docs/tasks/archive/g4-phase2/`
with the standing MANIFEST note that task specs are **retrospective records, not pre-registration
evidence**. Push and verify with `git ls-remote origin main`.

---

## STEP 9 — Stop and report

1. STEP 0 self-check.
2. Confirmation of the design read, and anything **underspecified for implementation** with what
   you did about it.
3. What was built, where, the dependency decision (and any new pin with its ADR), and how the
   §5.4 isolation is realized.
4. §8.1 row by row and §8.2 row by row — compliance or divergence with bias direction.
5. Per limb (L1, L1′, L2, L3, A1–A7, L4-precondition): construction, outcome, exact call/error,
   would-have-failed world.
6. The C3 stand-in: scope, banner, what it does not establish, re-trigger.
7. The adjudication: PASS or not, with L4's scoping stated; IA-4 and the board updated to the true
   outcome; nothing else touched.
8. Commits, push verification, test counts on both platforms, and anything you could not verify
   yourself.
9. Any point where you were tempted to fill a gap by assumption, to weaken a check so it would
   pass, or to build beyond the design — and what you did instead.
