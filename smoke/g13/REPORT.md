# Gate G-13 — matched per-hop authority across the strong baselines

**Verdict: PASS over ALL FIVE strong baselines. The `B2-exchange-task-DPoP` and `B3⁺` limbs are
CLOSED.** Run: `uv run python smoke/g13/spike.py` (or `make gate GATE=g13`). Fifteen mandatory
checks, all passed. Platform-independent — the gate touches the AS and Biscuit but never the
effect ledger — and it runs in CI beside the G-4 and G-11 spikes, confirmed rather than assumed.

Part G's row: *assert `Allowed(AT_i) = C_i` for every hop and every strong baseline; assert each
realizes the same `C_0→…→C_n` on F1-root/terminal/chain-tamper (chain-tamper NA where no chain)*.
Pass criterion: *equalities hold; no strong baseline differs in authority granularity*. What
rides on it, in Part G's own words: **matched fairness; the whole comparison.**

> **Update, 2026-07-31 — the two open limbs are closed.** This report first passed over **three
> of five** strong baselines and recorded, in the same words G-4's row used when it first passed
> over its adjudicable limbs only:
>
> > *Five arms receive per-hop `C_i` and **three exist**. `B2-exchange-task-DPoP` and `B3⁺` are
> > **unbuilt**, so their limbs are **open**. DPoP adds holder binding and the jti cache adds
> > duplicate detection; **neither adds authority**, so those limbs are **expected** to be formal
> > — expected, not verified, and it must be written that way.*
>
> That wording is retained here rather than deleted, because the record must show the sequence
> and not only the destination. Both arms now exist and **both limbs were run for real**. What
> was *expected* is now **verified**; §3, §4 and §9 give what was measured and how.

---

## 1. How the row is read, and why

The row writes `Allowed(AT_i)`. Read literally that concerns OAuth tokens only — but §E.2
applies the identical sentence to *every strong baseline*, and three of the five mint no per-hop
OAuth token at all. So `AT_i` denotes **the per-hop authority-bearing object**: `AT_i` for the
exchange arms, `P_i` for the capability arms. The pass criterion confirms the reading — *"no
strong baseline differs in authority **granularity**"* is a statement about the sets each arm
realizes, not about the format they travel in.

**This report agrees with the reading EXP2 STEP 13 set out**, on that argument. The consequence
matters: online-versus-offline narrowing is the **measured difference** the study exists to
report, so the gate recomputes each arm in its own terms and compares only the resulting
`C_0→…→C_n`. Nothing here normalizes the difference away, and nothing forces a capability arm to
mint a token it would not mint.

## 2. The instrument

`src/harness/verifier/matched_authority.py`, at the placement §E.2 names, **unchanged by this
pass**. Two planes:

| plane | implementation | why that choice |
|---|---|---|
| token | **new at G-13.** Parses the presented token itself; decides membership **one candidate at a time** over the frozen `Ω`, with the RFC 9396 §2.2 product, the `aud` plane and the `scope` plane inside one question | It must **not** reuse `src/sut/authz/boundary.py`: an instrument sharing the boundary's implementation could not detect a defect in it (D13/D21) |
| capability | **reuses `src/harness/authorizer/allowed.py`** — the `Allowed(P_i; Γ, κ, Ω)` gate G-2 adjudicated, one authorizer run per element of `Ω` | It is already the independent counterpart of `src/sut/capability/authority.py`. A third implementation would add no independence and could disagree with the artifact G-2 verified |

Structurally distinct from the boundary on purpose: the boundary computes a capability-plane
**set** then applies `scope` per request; the verifier asks a **yes/no question per candidate**
with all three planes inside it. Same frozen inputs, different construction — which is what makes
agreement evidence rather than tautology.

Every set the gate compares is computed from **raw presented evidence** — the `ObservedRequest`
the harness recorded at the boundary — and compared against the **sealed** `C_i`, which no system
under test can read (PROJECT_RULES.md red lines 4 and 5). No arm's return value is trusted anywhere.

## 3. The equalities, computed (G-13.L1)

**38 per-hop equalities** over **20 (scenario, arm) cells** — four scenarios × five strong arms,
each realizing two hop objects except the two noted below. Every equality holds.

| scenario | `B2-exchange-task` | `B2-exchange-task-DPoP` | `B-cap` | `B3` | `B3⁺` |
|---|---|---|---|---|---|
| `gt-benign` | `AT_0=C_0`, `AT_1=C_1` | `AT_0=C_0`, `AT_1=C_1` | `P_0=C_0`, `P_1=C_1` | `P_0=C_0`, `P_1=C_1` | `P_0=C_0`, `P_1=C_1` |
| `gt-f1-root` | ✓ ✓ | ✓ ✓ | ✓ ✓ | ✓ ✓ | ✓ ✓ |
| `gt-f1-terminal` | ✓ ✓ | ✓ ✓ | ✓ ✓ | ✓ ✓ | ✓ ✓ |
| `gt-f1-chain-tamper` | `AT_0=C_0`; **no `AT_1`** | `AT_0=C_0`; **no `AT_1`** | ✓ ✓ | ✓ ✓ | ✓ ✓ |

with `C_0 = {calendar.read/calendar/work, notes.read/notes/project, notes.write/notes/project}`
and `C_1 = {notes.read/notes/project, notes.write/notes/project}`.

**The two new arms were run, not assumed.** The nine-arm matrix showed `B2-exchange-task-DPoP`
identical to `B2-exchange-task` on every cell and `B3⁺` identical to `B3` — a strong prior, and
**not this check**. The matrix compares **outcomes**; G-13 compares **per-hop authority sets
recomputed from raw evidence**. Passing the first does not establish the second, and an assertion
that two arms are identical is not evidence that they are. Both limbs ran the full recomputation.

### The two cells where the equality has no object (G-13.L1b)

On `gt-f1-chain-tamper`, **both** exchange arms have **no `AT_1`**: the pinned AS profile refuses
the widening exchange (`invalid_authorization_details` / `widening-rar`) and issues nothing, so
neither delegate presents anything. `B2-exchange-task-DPoP` takes the same path as
`B2-exchange-task` and now has none either. Stated rather than skipped, and the reasoning is kept
rather than softened:

The equality cannot be asked, and what holds instead is **stronger** — each arm realized *no hop-1
authority at all*, and **an arm that issued nothing cannot have issued too much**. All three
capability arms *do* realize a hop-1 object on the same scenario and it equals `C_1` exactly:
block scoping admitted the widening block under `κ_pub` and granted it nothing. So the two
mechanisms differ in the **representation of the refusal**, not in authority granted. That is
§E.3's "each mechanism realizes that intent its own way", and it is why the row carries its own
"NA where no chain" qualifier.

### Authority is recomputed independently of acceptance policy (G-13.L1c)

Since ADR 0027 the SUT boundary applies an **INV freshness window** (`|now − iat| ≤ Δ`) that the
§F.2 verifier deliberately does not — §F.2 defines what makes an artifact **valid**, and freshness
is the boundary's **willingness to act on it**. If any part of L1 routed through something
freshness-dependent, the instrument would be measuring **acceptance** and reporting it as
**authority**, and every equality above would be about the wrong quantity.

Checked both ways. **Behaviourally:** all 10 per-hop sets recomputed at an instant **61 s later**
— stale by `Δ`, yet inside each credential's own validity (the capability expires an hour out, the
token five minutes) — are **unchanged**; and the world really is one the boundary refuses,
measured rather than claimed: `B3` at that instant returns `b3_invocation_binding`.
**Structurally:** neither the verifier nor the §A.0.1 authorizer it reuses imports
`src/sut/freshness`, so no part of L1 *can* route through the acceptance window.

## 4. Cross-arm identity, now over five arms (G-13.L2)

**18 arm-chains compared across the four scenarios; every arm that realizes a full chain realizes
the identical `C_0 → C_1`.** No strong baseline differs in authority granularity. The two missing
chains are the truncated cells above.

## 5. The F1 blocks, with attributable causes (G-13.L3)

All **3 × 5** F1 cells block, and every strong arm admits the benign call — so the blocks are not
an arm refusing everything.

| subcase | `B2-exchange-task` | `B2-exchange-task-DPoP` | `B-cap` | `B3` | `B3⁺` |
|---|---|---|---|---|---|
| `gt-f1-root` | `b2_token_scope` | `b2_token_scope` | `b3_containment` | `b3_containment` | `b3_containment` |
| `gt-f1-terminal` | `b2_token_scope` | `b2_token_scope` | `b3_containment` | `b3_containment` | `b3_containment` |
| `gt-f1-chain-tamper` | `b2_exchange_refused` | `b2_exchange_refused` | `b3_containment` | `b3_containment` | `b3_containment` |

## 6. D21, adjudicated rather than re-asserted (G-13.L4)

**It holds**, on three pieces of evidence: (1) `src/sut/capability/` imports nothing from
`src/harness/` and the harness verifiers import nothing from `src/sut/`; (2) the token-plane
verifier does not reuse `src/sut/authz/boundary.py`; (3) agreement, pinned separately by
`tests/test_sut_signer_agreement.py` and by this gate's own L1.

*Scope of (3): that suite covers §F.2's **validity** conditions. Since ADR 0027 the SUT boundary
additionally applies INV freshness, which the §F.2 verifier deliberately does not, so the
agreement is over a **strictly smaller** set of conditions than the SUT implements. Nothing in
G-13 rests on it doing more: L1 compares authority sets, which freshness does not enter — and
G-13.L1c establishes that directly rather than assuming it.*

**Residual, stated precisely because a vague one is ignored.** Agreement is evidence of
independence only while the constructions differ. L4's import scan **would** catch a refactor that
made the verifier import `boundary.py` — that is a cross-boundary import, and **L4.W1 proves the
scan non-vacuous** by flagging one. What the scan **cannot** catch is **copy-paste convergence**:
the token plane rewritten with the boundary's construction — a capability-plane set built first,
`scope` applied per request afterwards — and **no import at all**. The two would then agree
because they are the same algorithm rather than because two constructions independently reached
one answer. **The guard against that case is review of a change to `matched_authority.py`, not a
test**, and it is recorded as such rather than implied to be covered.

## 7. Every equality was shown able to fail

An equality that cannot fail has not been tested. Each world is constructed **through the arms'
own interfaces** and judged by the **same predicate** the real run is judged by.

| world | construction | what the gate's own predicate did |
|---|---|---|
| **L1.W1** — a hop provisioned at `C_{i−1}` | the exchange asks for `C_0` | AS **issues** it; `equalities_hold` → `False` |
| **L1.W2** — a RAR one element too wide | asks for `C_1 ∪ {calendar.read/calendar/work}` | issued; → `False`. The smallest possible widening is caught |
| **L1.W3** — the capability plane's W1 | attenuation narrows to `C_0` | chain verifies under `κ_pub`; → `False`. L1 is not carried by the token plane alone |
| **L1.W4** — an unverifiable token | one signature byte changed | the verifier **raises** rather than returning `∅` |
| **L2.W1** — a granularity mismatch | `B2` realizing `C_0` at hop 1 | `chains_identical` → `False`; over two **real** arms → `True`, so it discriminates |
| **L2.W2** — *(new)* a cache **denial** mistaken for an authority difference | `B3⁺` denies a bit-identical replay | `b3_replay_duplicate`, and the authority recomputed from the **same** bytes is unchanged: L1 → `True`, L2 → `True`. The denial is **not** reported as a granularity mismatch |
| **L3.W1** — §E.3's own warning | a `B2` that realized only `C_0` | it **admits** `gt-f1-terminal`; `all_blocked` → `False` |
| **L4.W1** — the import scan | a module importing across the boundary both ways | flagged, so L4's clean result is a measurement |

**L2.W2 is the world the two new arms made constructible.** `B3⁺` is the first arm that can deny
a request whose authority is identical to an admitted one. If the gate reported that denial as a
granularity mismatch, `B3⁺` would look like an arm realizing a different `C_0 → C_n` — exactly the
confusion matched fairness exists to prevent. The cache changes **admission**, never
`Allowed(P_i)`, which is why `B3⁺` can sit beside `B3` in a matched comparison at all.

## 8. Adjudication

**PASS** for all five strong baselines. The equalities hold, each F1 subcase blocks on each of
them, every equality was shown able to fail, D21 holds, and the instrument was shown to measure
authority rather than acceptance.

## 9. What is now verified, and by what

| previously | now | by what |
|---|---|---|
| `B2-exchange-task-DPoP`'s limb **open** — the arm was unbuilt | **closed** | The arm exists; its `AT_0` and `AT_1` were recomputed from the presented token over `Ω`, one candidate at a time, and equal `C_0` and `C_1` on all four scenarios. It appears in the 18-chain cross-arm identity and in all 3 F1 blocks |
| `B3⁺`'s limb **open** — the arm was unbuilt | **closed** | The arm exists; its `P_0` and `P_1` were recomputed by the frozen authorizer from the presented chain and equal `C_0` and `C_1`. It appears in the cross-arm identity, and L2.W2 additionally shows a cache **denial** leaves `Allowed(P_i)` untouched |
| *"DPoP adds holder binding and the jti cache adds duplicate detection, neither of which adds AUTHORITY — **expected, not verified**"* | **verified** | Measured per hop, from raw evidence, against the sealed `C_i`. Not inferred from the matrix: the matrix compares outcomes, and outcomes are not authority sets |

## 10. Residuals and scope, at their true values

- **`IA-3` is untouched and stays `[UNVERIFIED-IA]` for G-3.** This gate establishes matched
  **authority**, not cost. Nothing here was timed.
- **`IA-9` is untouched and stays `[UNVERIFIED-IA]` for G-9.** `B3⁺` carries a `jti` cache, and
  **building the cache is not running the gate**: it is atomic within one process and has no
  backend, so G-9's multi-process check-and-insert criterion and its induced-backend-error path
  are both untested. `src/sut/authz/jti_cache.py` states exactly which properties it has and
  which it lacks.
- Out of scope and not established here: the DPoP taxonomy (G-14), the F4/F5 shared reference
  monitor (G-15), and process-separated mediation (G-12).
- The D21 copy-paste-convergence residual in §6, which no test can close.

**Re-triggered by:** any `Ω`/`Γ` amendment (as it re-triggers G-2), any change to the pinned AS
exchange profile (ADR 0017), any change to `U_task` or to the ladder grants (ADR 0024/0029), any
change to `Δ` (ADR 0027, which would move L1c's offset), and the arrival of any further arm that
receives per-hop `C_i` — at which point its limb must be adjudicated rather than inherited.
