# Gate G-13 — matched per-hop authority across the strong baselines

**Verdict: PASS over the arms that exist, with the `B2-exchange-task-DPoP` and `B3⁺` limbs
OPEN.** Run: `uv run python smoke/g13/spike.py` (or `make gate GATE=g13`). Twelve mandatory
checks, all passed. Platform-independent — the gate touches the AS and Biscuit but never the
effect ledger — and it now runs in CI beside the G-4 and G-11 spikes, confirmed rather than
assumed.

Part G's row: *assert `Allowed(AT_i) = C_i` for every hop and every strong baseline; assert each
realizes the same `C_0→…→C_n` on F1-root/terminal/chain-tamper (chain-tamper NA where no chain)*.
Pass criterion: *equalities hold; no strong baseline differs in authority granularity*. What
rides on it, in Part G's own words: **matched fairness; the whole comparison.**

---

## 1. How the row is read, and why

The row writes `Allowed(AT_i)`. Read literally that concerns OAuth tokens only — but §E.2
applies the identical sentence to *every strong baseline*, and two of the three strong arms mint
no per-hop OAuth token at all. So `AT_i` denotes **the per-hop authority-bearing object**,
whatever the mechanism's is: `AT_i` for the exchange arm, `P_i` for the capability arms. The
pass criterion confirms the reading — *"no strong baseline differs in authority **granularity**"*
is a statement about the sets each arm realizes, not about the format they travel in.

**This report agrees with EXP2 STEP 13's reading**, on that argument. The consequence matters:
online-versus-offline narrowing is the **measured difference** the study exists to report, so the
gate recomputes each arm in its own terms and compares only the resulting `C_0→…→C_n`. Nothing
here normalizes the difference away, and nothing here forces a capability arm to mint a token it
would not mint.

## 2. The instrument

`src/harness/verifier/matched_authority.py`, at the placement §E.2 names. Two planes:

| plane | implementation | why that choice |
|---|---|---|
| token | **new here.** Parses the presented token itself; decides membership **one candidate at a time** over the frozen `Ω`, with the RFC 9396 §2.2 product, the `aud` plane and the `scope` plane inside one question | It must **not** reuse `src/sut/authz/boundary.py`: an instrument sharing the boundary's implementation could not detect a defect in it (D13/D21, STEP 13 by name) |
| capability | **reuses `src/harness/authorizer/allowed.py`** — the `Allowed(P_i; Γ, κ, Ω)` gate G-2 adjudicated, one authorizer run per element of `Ω` | It is already the independent counterpart of `src/sut/capability/authority.py`. A third implementation would add no independence and could disagree with the artifact G-2 verified |

Structurally distinct from the boundary on purpose: the boundary computes a capability-plane
**set** and then applies `scope` per request; the verifier asks a **yes/no question per
candidate** with all three planes inside it. Same frozen inputs, different construction — which
is what makes agreement evidence rather than tautology.

Every set the gate compares is computed from **raw presented evidence** — the `ObservedRequest`
the harness recorded at the boundary — and compared against the **sealed** `C_i`, which no system
under test can read (CLAUDE.md red lines 4 and 5). No arm's return value is trusted anywhere.

## 3. The equalities, computed

**23 per-hop equalities** over **12 (scenario, arm) cells** — four scenarios × three strong arms,
each realizing two hop objects except the one noted below. Every equality holds.

| scenario | `B2-exchange-task` | `B-cap` | `B3` |
|---|---|---|---|
| `gt-benign` | `AT_0=C_0`, `AT_1=C_1` | `P_0=C_0`, `P_1=C_1` | `P_0=C_0`, `P_1=C_1` |
| `gt-f1-root` | `AT_0=C_0`, `AT_1=C_1` | `P_0=C_0`, `P_1=C_1` | `P_0=C_0`, `P_1=C_1` |
| `gt-f1-terminal` | `AT_0=C_0`, `AT_1=C_1` | `P_0=C_0`, `P_1=C_1` | `P_0=C_0`, `P_1=C_1` |
| `gt-f1-chain-tamper` | `AT_0=C_0`; **no `AT_1` exists** | `P_0=C_0`, `P_1=C_1` | `P_0=C_0`, `P_1=C_1` |

with `C_0 = {calendar.read/calendar/work, notes.read/notes/project, notes.write/notes/project}`
and `C_1 = {notes.read/notes/project, notes.write/notes/project}`.

### The one cell where the equality has no object (G-13.L1b)

On `gt-f1-chain-tamper`, `B2-exchange-task` has **no `AT_1`**: the pinned AS profile refused the
widening exchange (`invalid_authorization_details` / `widening-rar`) and issued nothing, so the
delegate presented nothing. This is stated rather than skipped.

The equality cannot be asked, and what holds instead is **stronger**: the arm realized *no hop-1
authority at all*, and an arm that issued nothing cannot have issued too much. The capability
arms *do* realize a hop-1 object on the same scenario, and it equals `C_1` exactly — block
scoping admitted the widening block under `κ_pub` and granted it nothing. So the two mechanisms
differ in the **representation of the refusal**, not in authority granted. That is precisely
§E.3's "each mechanism realizes that intent its own way", and it is why the row carries its own
"NA where no chain" qualifier.

## 4. Cross-arm identity (G-13.L2)

**11 arm-chains compared across the four scenarios; every arm that realizes a full chain realizes
the identical `C_0 → C_1`.** No strong baseline differs in authority granularity. The eleventh
chain is the one truncated cell above; the twelfth does not exist.

## 5. The F1 blocks, with attributable causes (G-13.L3)

All 3 × 3 F1 cells block, and every strong arm admits the benign call — so the blocks are not an
arm refusing everything.

| subcase | `B2-exchange-task` | `B-cap` | `B3` |
|---|---|---|---|
| `gt-f1-root` | `b2_token_scope` | `b3_containment` | `b3_containment` |
| `gt-f1-terminal` | `b2_token_scope` | `b3_containment` | `b3_containment` |
| `gt-f1-chain-tamper` | `b2_exchange_refused` (AS: `widening-rar`) | `b3_containment` | `b3_containment` |

## 6. D21, adjudicated rather than re-asserted (G-13.L4)

Block 1 built the SUT-side signer and pinned agreement; this gate is where that is *adjudicated*.
**It holds**, on three pieces of evidence:

1. **Structure.** `src/sut/capability/signer.py` and `authority.py` import nothing from
   `src/harness/`; `src/harness/verifier/matched_authority.py` and `holder_binding.py` import
   nothing from `src/sut/`. Neither side can inherit the other's mistake.
2. **The instrument does not reuse the measured boundary.** `src.sut.authz.boundary` appears
   nowhere in the verifier's imports — what D13/D21 forbids for an instrument that must be able
   to find a defect in the boundary.
3. **Agreement**, pinned separately by `tests/test_sut_signer_agreement.py`, and by this gate's
   own L1: two independent implementations produced the same `C_i` on every hop of every cell.

**Residual, stated precisely because a vague one is ignored.** Agreement is evidence of
independence *only because* the implementations are structurally distinct, and (1) and (2)
establish that today. *(This paragraph first read "a future refactor could silently undo it".
That was true but broader than the truth, and is superseded here — update, 2026-07-31.)* The
accurate statement is narrower and therefore actionable: L4's import scan **would** catch a
refactor that made the verifier import `src/sut/authz/boundary.py` — that is a cross-boundary
import, and **L4.W1 proved the scan non-vacuous** by flagging one. What the scan **cannot** catch
is **copy-paste convergence**: the token plane rewritten with the boundary's construction — a
capability-plane set built first, `scope` applied per request afterwards — and **no import at
all**. The two would then agree because they are the same algorithm rather than because two
constructions independently reached one answer, and every L1 equality would still pass. **The
guard against that case is review of a change to `matched_authority.py`, not a test**, and it is
recorded as such rather than implied to be covered.

## 7. Every equality was shown able to fail

An equality that cannot fail has not been tested. Each world below is constructed **through the
arms' own interfaces** — a misprovisioned deployment is exactly one that asks for the wrong set
at the hop — and each is then judged by the **same predicate** the real run is judged by.
"It would have failed" is a claim; running the check and watching it return `False` is not.

| world | construction | what the gate's own predicate did |
|---|---|---|
| **L1.W1** — a hop provisioned at `C_{i−1}` instead of `C_i` | the exchange asks for `C_0` | AS **issues** it; `Allowed(AT_1) = C_0`; `equalities_hold` → `False` |
| **L1.W2** — a token whose RAR covers **one** element too many | the exchange asks for `C_1 ∪ {calendar.read/calendar/work}` | issued; `equalities_hold` → `False`. The smallest possible widening is caught, so the equality is not a coarse set-size comparison |
| **L1.W3** — the capability plane's version of W1 | the attenuation block narrows to `C_0` | chain verifies under `κ_pub`; `Allowed(P_1) = C_0`; `equalities_hold` → `False`. So L1 is not carried by the token plane alone |
| **L1.W4** — an unverifiable token | one signature byte changed | the verifier **raises** rather than returning `∅`. Otherwise a forged token would look like one that admits nothing, and every equality against a non-empty `C_i` would fail for the wrong reason while one against an empty `C_i` would pass vacuously |
| **L2.W1** — one arm at a different granularity | `B2` realizing `C_0` at hop 1 | `chains_identical` → `False`; and over two **real** arms the same predicate → `True`, so it discriminates rather than always agreeing |
| **L3.W1** — §E.3's own warning made real | a `B2` that realized only `C_0` | it **admits** `gt-f1-terminal` (`b2_admitted`); `all_blocked` → `False`. This is why matched provisioning is mandatory rather than advisory |
| **L4.W1** — the import scan | a module importing across the boundary both ways | flagged, so L4's clean result is a measurement rather than a scan that finds nothing because it looks for nothing |

## 8. Adjudication, and the residual

**PASS** for the three strong arms that exist: the equalities hold, each F1 subcase blocks on
each of them, every equality was shown able to fail, and D21 holds on the evidence above.

**The open limbs, stated as open rather than passed.** Five arms receive per-hop `C_i` and
**three exist**. `B2-exchange-task-DPoP` and `B3⁺` are **unbuilt**, so their limbs are **open** —
in the same words G-4's row used when it first passed over its adjudicable limbs only. DPoP adds
holder binding and the jti cache adds duplicate detection; **neither adds authority**, so those
limbs are **expected** to be formal — *expected, not verified*, and it must be read that way.
Nothing in this gate establishes them.

**`IA-3` is untouched and stays `[UNVERIFIED-IA]` for G-3.** This gate establishes matched
**authority**, not cost. Nothing here was timed (EXP2 forbidden action 5), and no timing number
was produced anywhere in the pass that built it.

Also out of scope and not established here: the DPoP taxonomy (G-14), the F4/F5 shared reference
monitor (G-15), duplicate replay (G-9), and process-separated mediation (G-12).

**Re-triggered by:** any `Ω`/`Γ` amendment (as it re-triggers G-2), any change to the pinned AS
exchange profile (ADR 0017), any change to `U_task` in the corpus, and the arrival of either
unbuilt arm — at which point its limb must be adjudicated rather than inherited from this row.
