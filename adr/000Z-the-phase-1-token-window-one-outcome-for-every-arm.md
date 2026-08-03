# 000Z — The phase-1 token window: one expired credential, one outcome

*(Letter placeholder. The Commander assigns the number; this ADR is not numbered by the session that
wrote it. It follows **"One clock per cell: the campaign adopts the cell's clock"**, which is also
unnumbered — referenced here by title. That ADR closed Δ; this one closes the window Δ was the wrong
instrument for.)*

## Context

The one-clock-per-cell work closed the **Δ straddle**: artifacts minted at one instant and judged at
another. It also flagged, without acting on it, that the same *pattern* existed around the OAuth
access token's 300 s window.

**It is worse than that framing.** It reaches the campaign, not just the tests, and there it is
silent.

## The defect, measured

Phase-1 access tokens are minted **once, at AS process start-up** — `default_lifetime_seconds = 300`
in `src/sut/oauth_as/config.py`, a configuration default that **no frozen row bounds** — and are then
reused by every cell of a pass. The exposure clock therefore starts *earlier than the campaign's own
start*.

Measured on `gt-benign`, the **benign control**, with the lifetime pinned to 1 s and the cells run
2.5 s later:

| arm | reason_code | false_block | reference_allow | unscorable |
|---|---|---|---|---|
| `B0` | `b0_no_boundary_check` | False | True | — |
| `B1` | `b1_admitted` | False | True | — |
| `B-cap` / `B3` / `B3+` | `b3_oauth_resource_authorization` | **True** | True | **0** |

**The campaign completed and scored** the three capability arms as false-blocking the benign control.
Nothing was refused; `reference_allow` stayed `True`, so nothing contradicted anything.

### The asymmetry, which is why it survived

The same expiry produces **two different behaviours**:

- the **capability** arms deny through `ConjunctFailed`, are scored, and are **silent**;
- the **`B2`** arms raise `B2ConfigurationError` out of `provision` — *"the injected subject token
  does not verify at this boundary (exp: token has expired)"* — and **abort the pass**, loudly.

One defect, two behaviours, only one of them visible. The loud half is why nobody looked for the
quiet half.

### Why it matters, and not merely for tidiness

The F1 headline rests on the contrast between the strong arms **blocking** `F1-root`/`F1-terminal`
and **admitting** `gt-benign`. **An arm that blocks the benign control has no contrast left.** This
would not have produced a wrong number in a corner of the matrix; it would have removed the result.

### Why the existing guard missed it

`clock_refusal` inspected `artifact_instants` — the `iat` of the ADR 0030 declassification and
approval — against Δ. Correct for what it was built for. The access token is not an ADR 0030
artifact, is not Δ-bound, and carries its own `exp`. It was simply not in the set the guard looked
at.

## STEP 1 — the enumeration, and what it turned up

Before writing the guard: **which credentials handed to a cell carry a validity window at all?**
Enumerated mechanically over every setup dict the harness builds, and committed as
`tests/test_credential_enumeration.py` rather than asserted in prose — a guard covering a set nobody
enumerated is a guard assumed complete.

| setup | fields | time-bound |
|---|:--:|---|
| `B0` (`{}`) | 0 | — |
| `b1_setup` | 2 | — |
| `b3_setup` (`B-cap`/`B3`/`B3⁺`) | 18 | `access_token` |
| `b2_setup` | 22 | `access_token`, **`as_tls_cert_pem`** |
| `b2_dpop_setup` | 25 | `access_token`, **`as_tls_cert_pem`** |

**The enumeration found a second time-bound credential**, which the starting hypothesis did not
predict: the AS's self-signed TLS certificate, minted at start-up with a **86 700 s** window
(`not_valid_before = now − 5 min`, `not_valid_after = now + 1 day`) and handed to every arm that
dials the AS. It is 288× the token's window and it reaches only the OAuth arms, but it is
**time-bound and minted once before the pass** — the same defect — so it is **covered rather than
assumed harmless**.

Everything else is untimed by construction: frozen JSON documents, raw Ed25519 key material, derived
secrets, ports, strings, booleans. HTC, INV and DPoP proofs carry windows but are minted **inside**
the cell at its own instant and never appear in a setup.

## Decision

**Add a validity-coverage check to `clock_refusal`, alongside the Δ check.** A cell whose credential
does not cover the instant it is judged at is **unscorable**, routed through the existing
`unscorable` list with a reason, and never scored — exactly as an `NA` cell is not a result.

Three properties, each load-bearing:

**1. Read `nbf`/`exp` unverified.** No signature check, no chain building, no trust decision
(forbidden action 4). The guard decides **scorability**, never **admission**. A harness precondition
that ran the SUT's verifier would gate the measurement on the very thing being measured.
Demonstrated rather than asserted: a token whose signature is corrupted yields the identical window,
and an AST walk over the guard's four functions asserts no call whose name contains *verify*. `nbf`
is optional, mirroring the SUT's own `claims.get("nbf")` — phase-1 tokens carry none — while `exp` is
not: a credential announcing no expiry cannot be shown to cover anything.

**2. Compare against the instant the cell is judged at, with no second clock.** The value used is
`cell_instant`, the same one handed to `run_scenario` as `now`, and `run.observed.iat` *is* that
value. Introducing a fresh read here would have re-created the defect the previous ADR closed.

**3. It must run BEFORE the cell runs.** This is forced, not chosen: the `B2` half raises inside
`provision`, which happens inside `run_scenario`, so a post-run guard would never see it — and the
whole point is that **one expired credential produces one outcome regardless of which arm holds it**.
The Δ artifact check moved forward with it, from `run.observed.iat` to `cell_instant`; those are the
same value by construction, and keeping two call sites would have made the guard's answer depend on
which half fired first. Measured: the refused-cell and scored-cell sets are **identical** across the
move, in all three passes.

**Detection is by shape, not by field name.** `credential_windows` finds JWT-shaped and
PEM-certificate-shaped values wherever they appear, so a third time-bound credential added to any
setup is picked up by existing code, and the committed enumeration makes its arrival visible rather
than absorbed. A hardcoded `"access_token"` would have covered today and missed tomorrow — which is
precisely how this defect existed.

### One defect found while building the guard, recorded because it would have been silent

The first implementation detected a JWT by `value.count(".") == 2`. **`https://as.aasc.local` has
exactly two dots.** Every issuer, resource server, token endpoint and resource URL in the setup was
therefore classified as an unreadable credential and failed closed — which would have **refused every
cell in the healthy case**. A guard that refuses everything measures nothing, and it would have
passed a test that only ever checked the expired path.

Detection now decides JWT-or-not on the **header** (three non-empty segments, header decodes to a
JSON object carrying `alg`) and only then fails closed on an unreadable payload. It was found by
*running* STEP 1's enumeration rather than by reasoning about it, which is why the specification
asked for the enumeration as a test.

## The failing world, both halves

| | before the guard | after |
|---|---|---|
| `B-cap` / `B3` / `B3⁺` | **scored `false_block = True`**, `unscorable = 0` | **3 unscorable, 0 scored** |
| `B2-exchange-task` | **raised `B2ConfigurationError`**, pass aborted | **1 unscorable, campaign completes** |
| `B0` / `B1` | scored, admitted | scored, admitted — **unchanged** |

`B0` and `B1` hold no time-bound credential and are deliberately untouched: the guard refuses the
cells whose credential expired, not every cell.

**Guard removed on the same code, both halves return**: the capability arms are again scored
`false_block = True` with `reason_code = b3_oauth_resource_authorization` and `reference_allow` still
`True`, and the `B2` arm again raises. Committed as
`tests/test_credential_enumeration.py::TestTheGuardRemovedTheDefectReturns`.

## No cell moved

The healthy case must leave the guard inert. Snapshotted by the method built for the previous ADR —
three passes, the F1 ladder chain and the F4/F5 chain under **both** monitor configurations, every
Part I quantity, reason code, timing-seam name and `unscorable` entry:

```
$ uv run python tools/clock_fix/compare_cells.py \
      tools/clock_fix/evidence/campaign-cells-after.json <fresh snapshot>
0 of 104 cells differ
```

## Reconciling the 18-vs-27 figure

The previous session's self-check reported the Δ guard as **0 scored / 18 refused**, while
`tools/clock_fix/evidence/campaign-cells-straddled-guard-on.json` shows **9 scored / 27 unscorable**
for `F45-monitor-True`. **Both are true, of different runs, and the difference is the scenario set:**

| run | scenarios | cells | outcome |
|---|---|:--:|---|
| `tests/test_campaign_clock.py`'s `straddled` fixture | the **two controls** only | 18 | 0 scored / 18 refused |
| `tools/clock_fix/snapshot_cells.py`'s F4/F5 pass | **all four** F4/F5 scenarios | 36 | 9 scored / 27 refused |

The nine still scored in the wider run are `gt-f5-unapproved-high-risk` × nine arms. That fixture
carries **no approval artifact** — its missing approval *is* the fixture — so it holds no Δ-bound
artifact for the guard to find. The guard refuses exactly the cells carrying a straddled artifact and
no others, which is the more precise statement and the one that should be quoted.

The evidence file also carried 54 refusal strings containing a literal `Δ`, written before that
message was made ASCII. It has been regenerated from current code and now matches what the code
emits.

## Out of scope — deliberately not repaired

These are **declared limitations, not oversights**. The standard days before a seal is *no code
carries risk into the sealed record*, not *every known imperfection is repaired*; every diff is risk.
Each reason is recorded because the reasons are what let a novel instance be recognised.

| left alone | why |
|---|---|
| **Sighting A** and **Sighting B** | Never reproduced under any condition. Both are test-level; neither touches the campaign path, so neither can reach a result. |
| **`test_appended_widening_verifies_but_does_not_widen`** (flake-hunt run 001) | Not a clock straddle — that module reads no wall clock at all. Its candidate cause (a Biscuit runtime limit shrinking an authority set under contention) **cannot reach the campaign**: `src/sut/` never imports `src/harness/authorizer/`. Test-only. |
| A **sweep of module-scoped AS fixtures** across `tests/` | Test fixtures produce no results. A large change to code that cannot affect the sealed record, days before a seal. |
| Anything in **`src/sut/`** | The asymmetry between the two arms' failure modes is real, but it is closed **in the harness**, by refusing the cell before either behaviour matters. Changing an arm would change what §E.4 measured and re-open every gate adjudicated on it. |

## Consequences

- **`src/sut/` is untouched.** No arm changed, no conjunct changed, no frozen parameter moved. The
  300 s lifetime is left exactly where it is: widening it would hide the straddle rather than remove
  it.
- `src/harness/` changed, so *every prior DAG gate passed* — a conjunct of G-10 — was re-measured on
  the row 9 platform.
- The `as_tls_cert_pem` window is now bounded rather than assumed harmless. It has never fired and,
  at a day, is unlikely to; it is covered because it is the same defect, not because it is expected.
- `000X` still needs a superseded-by pointer for its run-001 attribution. **Noted, not added** —
  numbering and cross-linking are the Commander's.
