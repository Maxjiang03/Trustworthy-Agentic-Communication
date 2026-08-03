# One clock per cell — Site B, the campaign

**HEAD at issue: `5246d59`.** Tooling: `tools/clock_fix/snapshot_cells.py`,
`tools/clock_fix/compare_cells.py`; evidence in `tools/clock_fix/evidence/`. Neither tool is a gate,
and neither lives under `smoke/` or is named `spike.py` — in this repository those two together mean
*gate*.

The decision, the rejected alternative and the reasoning are in the ADR
**"One clock per cell: the campaign adopts the cell's clock"**. This file is the raw evidence.

## The defect, measured

`run_campaign` read the wall clock **once per pass**; `run_scenario` read its own **per cell** and
had no way to receive the campaign's. The separation grew with the pass and nothing capped it.

With the campaign instant 61 s behind the cell's epoch, over the two benign controls
(`gt-f4-declassified`, `gt-f5-approved`) × nine arms × both monitor configurations — **18 control
cells per configuration, 36 in all**:

| | admitted | blocked | `false_block = True` |
|---|:--:|:--:|:--:|
| one clock | **32** | 4 | 2 |
| campaign instant 61 s stale | **20** | 16 | 8 |

**Twelve control cells flip; six are newly scored `false_block`.** The four already blocked and two
already `false_block` at one clock are the known G-15 residual — `B3`/`B3⁺` refuse the benign controls
when no monitor is configured — not part of this defect.

Which cells moved, exactly:

```
gt-f4-declassified  × {B2-broad-noexchange, B2-exchange-broad, B2-exchange-task,
                       B2-exchange-task-DPoP, B3, B3+}
    observed_forwarded  True -> False
    admission_breach    True -> False
    reason_code         b2_admitted -> b2_context_policy   (b3_admitted -> b3_context_policy)

gt-f5-approved      × {the same six}
    observed_forwarded  True -> False
    false_block        False -> True
    reason_code         b2_admitted -> b2_approval_artifact (b3_admitted -> b3_approval_artifact)
```

`B0` and `B1` do not move — no boundary check. `B-cap` does not move — its §E.5 bitmask carries
`context = 0`, `approval = 0`, so it consults no monitor. **The flip lands precisely on the six
monitor-consulting arms**, which is what would have made it read as a mechanism result.

**`reference_allow` is bit-identical across the two runs.** The oracle was judged at the stale instant
too, so nothing contradicted anything. That is why this could not surface on its own.

## No §E.4 cell moved

Three passes — the F1 ladder chain, and the F4/F5 chain under **both** monitor configurations — every
Part I quantity, the reason code, the timing-seam names and the `unscorable` list, before the change
and after it:

```
$ uv run python tools/clock_fix/compare_cells.py \
      tools/clock_fix/evidence/campaign-cells-before.json \
      tools/clock_fix/evidence/campaign-cells-after.json
0 of 104 cells differ
```

The two files are **byte-identical**:

```
79131467aa3d5c992e3f0979c6158e1157c7bf9151744eb3024f4bd642b3a44d  campaign-cells-before.json
79131467aa3d5c992e3f0979c6158e1157c7bf9151744eb3024f4bd642b3a44d  campaign-cells-after.json
```

Re-running `snapshot_cells.py` on the fixed code reproduces `campaign-cells-after.json` at **0 of 104
differ**, so the snapshot is stable and the identity above is not an artefact of one lucky run.

## The guard, watched refusing real cells

| run | cells scored | cells refused | control outcome |
|---|:--:|:--:|---|
| one clock (healthy) | 18 | 0 | all 18 admitted |
| artifacts Δ+1 stale, **guard present** | **0** | **18** | nothing scored |
| artifacts Δ+1 stale, **guard removed** | 18 | 0 | **12 flip, 6 `false_block`** |

**Which run these three rows describe, because a second run in this directory reports different
numbers and both are right.** The rows above are `tests/test_campaign_clock.py`'s campaigns, whose
scenario set is **the two benign controls only** — 2 × 9 arms = 18 cells, every one carrying a
Δ-bound artifact, so every one refuses.

`tools/clock_fix/evidence/campaign-cells-straddled-guard-on.json` runs a **wider** set —
`snapshot_cells.py`'s F4/F5 pass takes all four F4/F5 scenarios, 4 × 9 = 36 — and reports **9 scored
/ 27 refused** per configuration. The nine still scored are `gt-f5-unapproved-high-risk` × nine arms:
that fixture carries **no approval artifact** (its missing approval *is* the fixture), so it holds no
Δ-bound artifact for the guard to find.

The precise statement, true of both runs: **the guard refuses exactly the cells carrying a straddled
artifact, and no others.** Quote that rather than either raw count.

The refusal, as recorded in `unscorable`:

```
gt-f4-declassified  B-cap
  the declassification was minted at 1785756733 and the cell was judged at 1785756795, 62s apart,
  which exceeds the frozen freshness window Delta=60s (frozen_parameters row 3, ADR 0027). The
  boundary checks that artifact with `is_fresh(now, iat)`, so this cell would record how long the
  campaign took to reach it and not what the mechanism did. UNSCORABLE, never scored
```

**The guard-removed run is byte-identical to the defect on the pre-fix code:**

```
618207ef167636489e645f11b1105ddb24eab155dd1cf04b99294205f4cbdbe6  (pre-fix code, 61 s stale)
618207ef167636489e645f11b1105ddb24eab155dd1cf04b99294205f4cbdbe6  campaign-cells-straddled-guard-off.json
```

`campaign-cells-straddled-guard-on.json` was **regenerated** when the phase-1 token guard landed. It
had been captured before the refusal message was made ASCII and carried 54 reasons containing a
literal `Δ` that the code no longer emits — a committed record disagreeing with its own code. The
refused-cell and scored-cell **sets** are unchanged across both that refresh and the guard's move to
before the run: 4/32, 27/9 and 27/9 in the three passes, identical.

So the guard is the only thing standing between the campaign and those twelve wrong cells. The
healthy row is the non-vacuity check: the same eighteen cells score cleanly on one clock, so the
middle row is not the campaign refusing everything for an unrelated reason.

`tests/test_campaign_clock.py` runs the healthy and straddled campaigns as **real campaigns** — real
arms, real signed artifacts, no mocked clock — and asserts all three properties.

## Which cells the guard refuses, and which it does not

Per F4/F5 pass, 27 of 36 cells are refused and **9 are still scored**: those of
`gt-f5-unapproved-high-risk`, which carries no Δ-bound artifact — it is the fixture whose approval is
*missing*. The guard refuses exactly the cells that carry a straddled artifact and no others. The F1
pass is untouched (32 scored, 4 `NA`): F1 scenarios mint no Δ-bound artifact.

`LabelAssertion`s are deliberately **not** Δ-bound. §A.6 puts labels at ingestion, before task-time
issuance, so `mint_for_scenario` back-dates them a day on purpose and only their own `iat`/`exp`
binds them. A guard that included them would refuse every labelled cell for a property the boundary
never checks.

## The `SINGLE_USE` question, checked before implementing

Per-cell minting re-mints the approval **per arm**, and the approval carries
`replay_rule = single-use` with a fixed `jti = approval-{scenario_id}`. If the monitor's `jti` cache
were shared, arms two through nine would be refused as duplicates.

**It is per-arm-instance.** Measured:

```
monitor objects distinct: True
cache objects distinct  : True
consume in cache0: Consumption.ADMITTED     # first use
same jti  cache1 : Consumption.ADMITTED     # a DIFFERENT arm's cache — not a duplicate
same jti  cache0 : Consumption.DUPLICATE    # the same cache — a duplicate
```

`ContextApprovalMonitor.__init__` builds its own `JtiCache()` when none is passed, and neither
`b3.py` nor `b2_exchange_task.py` passes one. Independently, before any change: all six
monitor-consuming arms already presented the **identical** approval bytes with
`jti = approval-gt-f5-approved` in one pass and all six were admitted — a shared cache would have
refused five of them. Per-cell minting strictly **reduces** sharing and cannot collide.

## Site A — the two named failures, and a correction

**Run 000 — `test_b3_plus.py::…::test_the_replay_is_constructed_WITHIN_delta`. Straddle LOCATED, and
it is not the window the earlier ADR named.**

| | |
|---|---|
| read 1 | the AS mints `phase1_tokens["agent-specialist"]` when the **module-scoped** `running_as` fixture starts |
| read 2 | `now = int(time.time())` inside the test, injected as `p.now_epoch` |
| window straddled | the **OAuth access token's 300 s lifetime** (`default_lifetime_seconds`) — **not** Δ |

Measured directly:

```
token iat=1785756638 exp=1785756938 lifetime=300s
offset=+0    decide=(True,  'b3_admitted')
offset=+301  decide=(False, 'b3_oauth_resource_authorization')  detail=exp: token has expired
```

The **first** submission refused — exactly what run 000 reported.

**Run 001 — `test_frozen_authorizer_semantics.py::test_appended_widening_verifies_but_does_not_widen`.
NOT a clock straddle. Cause UNDETERMINED.** That module reads no wall clock at all: `NOW` and
`EXPIRY` are frozen `datetime` constants, `RequestContext.now` comes from `NOW`, and
`src/harness/authorizer/allowed.py` reads no clock. **There are not two clocks to straddle**, so the
earlier ADR's attribution is wrong for this one and is corrected here rather than carried forward.

A named candidate, **not a diagnosis**: `allowed()` builds its set from one `authorize_candidate` run
per Ω element, and `authorize_candidate` treats **any** `AuthorizationError` as a deny. A Biscuit
runtime limit exceeded under contention would silently shrink the set, and the observed failure was
`c2 <= c1` with extra items on the left — what a shrunken `c1` looks like. Unconfirmed; no fix is
applied on a guess.

**Sightings A and B remain undetermined and are not claimed closed.** Neither was ever reproduced.

## The reproduction condition, re-run — and what 0/3 does NOT establish

Same condition as the flake hunt: full suite, pinned to one CPU, three busy loops, three runs.
`tools/clock_fix/evidence/reproduction-postfix-summary.json`.

| | before | after |
|---|:--:|:--:|
| reproduction rate | **2/3** | **0/3** |
| counts per run | 1 failed / 1228 passed (×2), 1229 passed | 1271 passed (×3) |

**A green run is not closure**, and this one establishes less than it looks like it does:

- **Three runs is a weak instrument against a 2/3 base rate.** Even if nothing had been fixed,
  three clean runs would happen about **4%** of the time. 0/3 is consistent with a fix and also
  consistent with luck.
- **Run 001's failure was never fixed.** `test_appended_widening_verifies_but_does_not_widen` has no
  located straddle and no change was made to it. Its absence from three runs is **chance, not
  evidence**, and it is not claimed otherwise.
- **Run 000's failure is addressed by construction, not by these three runs.** The module now takes
  its instant from the token's own window, so elapsed module time cannot move it — that claim rests
  on `TestTheInstantComesFromTheTokenNotFromAClock` and on the measurement at `iat + 301`, not on a
  green suite.
- **Sightings A and B were never reproduced at all** and remain undetermined. Three green runs say
  nothing about either.

Wall-clock durations here are **run metadata** — how long a condition took to exercise. They are not
latency figures; G-3 owns cost and its numbers live in `smoke/g3/REPORT.md` only.

## The gates, re-measured

`src/harness/` changed, so *every prior DAG gate passed* — a conjunct of G-10 — stopped being
derivable from the last measurement. All fifteen spikes were re-run on the row 9 platform, unchanged
machine, and all fifteen pass. `smoke/` and `docs/` are untouched: no gate record was rewritten and
no verdict was moved.

## What is NOT in this commit

**Site A's second failure.** `test_appended_widening_verifies_but_does_not_widen` has no located
straddle, so nothing was changed in it. Fixing a failure whose cause you have not found is the
"plausible fix that happens to turn the suite green" this work exists to avoid.

**Site A's fix landed in its own commit, after Site B's**, because Site B is what would corrupt the
sealed result and Site A only makes tests red. The ordering is the point of the ordering.

**Nothing in `src/sut/` changed. No frozen parameter moved. No window was widened, no retry added,
nothing marked flaky, skipped or suppressed. No gate verdict was moved.**
