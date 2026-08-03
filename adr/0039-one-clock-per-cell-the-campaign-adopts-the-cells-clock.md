# 0039 — One clock per cell: the campaign adopts the cell's clock

## Context

[0038](0038-pre-seal-flake-hunt-the-wall-clock-straddle.md) identified a **wall-clock straddle** — two reads of the wall clock separated by an
unbounded amount of execution, compared as if simultaneous — and located it in test fixtures.
Independent verification then found **the same defect at a second site, in the code that will produce
the sealed confirmatory result**. This ADR records that site and its fix.

The two sites are one cause. They are recorded together so the second is not re-derived from nothing.

## Site B — `src/harness/campaign.py`, the site that matters

`run_campaign` read `instant = int(time.time())` **once for the whole pass** and used it for every
scenario's `label_artifacts.mint_for_scenario(now=instant)`, for every `OracleConfig(now=instant)`
and for every `credential_result(..., now=instant)`. `GoldenThreadRunner.run_scenario` read its own
`run_epoch = int(time.time())` **per cell** and had no `now` parameter, so `instant` never reached
it. The boundary checks a harness-minted artifact with `freshness.is_fresh(run_epoch, iat)` against
**Δ** (`frozen_parameters` row 3), which binds long before the artifact's 300 s `exp` does.

The separation between the two reads grew with the pass, and nothing measured or capped it.

### The measured consequence

With the campaign instant 61 s behind the cell's epoch — one cell running a minute into a pass —
over the two benign controls (`gt-f4-declassified`, `gt-f5-approved`) × nine arms × both monitor
configurations:

| | admitted | blocked | `false_block = True` |
|---|:--:|:--:|:--:|
| one clock | 32 | 4 | 2 |
| campaign instant 61 s stale | 20 | 16 | 8 |

**Twelve control cells flip from admitted to blocked; six are newly scored `false_block = True`.**
The reason codes read `b2_context_policy` / `b3_context_policy` on the F4 control and
`b2_approval_artifact` / `b3_approval_artifact` on the F5 control: exactly what a working mechanism
looks like. `B0` and `B1` do not move (no boundary check) and neither does `B-cap` (its §E.5 bitmask
carries `context = 0`, `approval = 0`, so it consults no monitor) — the flip lands precisely on the
six **monitor-consulting** arms.

**It cannot surface on its own.** The oracle is judged at the campaign instant too, so
`reference_allow` is **bit-identical** across the two runs and nothing contradicts anything. The
result would have been a plausible, publishable false-blocking rate attaching to every
monitor-consulting arm — in the one family gate G-15 already established measures the **monitor**
rather than the mechanism.

**Why it never fired.** Run metadata, not a latency figure: an 18-cell in-process ledger-free pass
takes well under a second. Nothing bounds it. `ledger_backed=True` and `sut_mode="separate"` are
slower, the pinned-CPU condition slowed the suite roughly six- to tenfold, and §E.2 specifies ≥200
end-to-end repetitions per configuration across ≥3 batches. **Correctness depended on machine
speed**, which is the property this project exists not to have.

## Decision

### Adopted: the campaign adopts the cell's clock, not the reverse

The wall clock is read **once per cell, immediately before the run**, inside the per-arm loop. That
instant mints the cell's artifacts and is handed to `run_scenario` as a new optional `now`, so **the
cell is judged at the instant its artifacts were built at** — separation zero, not merely within Δ.

Everything computed *after* the run — `OracleConfig` and `credential_result` — reads
`run.observed.iat`, which **is** the runner's `run_epoch`, rather than a campaign copy of it. Not a
convention that the two agree: there is no second value to disagree with.

`run_scenario`'s `now` defaults to `None`, which reads the wall clock exactly as before, so all
thirty-odd existing call sites across the suites and the gate spikes are unchanged by construction.

### Rejected: freeze the cell to the campaign's instant by passing it down

`runner.py` documents an invariant — *"ONE clock for the run: every credential window (capability,
HTC, INV) and the live AS-minted OAuth token are judged against this instant. The scenario supplies
the validity DURATION, never a frozen `now`."* The AS mints against the real wall clock. Freezing the
cell behind it would make a live token look **unexpired when it has expired**: the same straddle, in
the other direction, in the plane where F3 lives.

The adopted design does not conflict with that invariant. It is still one clock for the run; the only
change is that a caller which had to build the cell's material *before* the call may supply the
instant it built at. The corpus still supplies durations and never an instant.

### The guard, fail-closed

Construction closes two of the three seams. The third cannot be closed by construction — the
artifacts must be minted **before** the run — so it is guarded. `clock_refusal` compares each
Δ-bound artifact's `iat`, **read from the minted artifact**, against `run.observed.iat`, **read from
the run**. Both are facts about objects, not about parameters, so a future edit that re-introduces
per-pass minting by some other route is still caught. A cell exceeding Δ is routed to the existing
`unscorable` list with a reason and is **never scored** — not a `B`, not a `false_block`, not a
result, exactly as an `NA` cell is not.

Δ is read from `frozen_parameters.delta_seconds()` (row 3). It is never a literal, and
`tests/test_campaign_clock.py` shows the same separation refused under a smaller Δ and admitted under
a larger one, so the boundary moves with the row rather than with a constant.

**Two of the three artifacts are Δ-bound and one is not.** The boundary calls
`freshness.is_fresh(now, iat)` on the declassification and on the approval. It does **not** on a
`LabelAssertion`: §A.6 puts labels at ingestion, *before* task-time issuance, so `mint_for_scenario`
back-dates them a day on purpose and only their own `iat`/`exp` binds them. A guard that included
them would refuse every labelled cell for a property nothing enforces.

## The consequence that had to be checked first, and its answer

Artifacts were minted **once per scenario** and reused across all nine arms. Per-cell minting
re-mints them **per arm**, and the approval carries `replay_rule = single-use` with a fixed
`jti = f"approval-{scenario_id}"`, consumed through a `jti` cache. If that cache were shared, arms two
through nine would be refused as duplicates.

**It is per-arm-instance, not shared.** Measured three ways:

1. `ContextApprovalMonitor.__init__` builds its own `JtiCache()` when none is passed, and neither
   `b3.py` nor `b2_exchange_task.py` passes one.
2. Directly: three arms provisioned from one setup hold three distinct monitor objects and three
   distinct cache objects; the same `jti` consumed in one is still `ADMITTED` in another, and
   `DUPLICATE` only within the same cache.
3. Behaviourally, before any change: all six monitor-consulting arms already presented the
   **identical** approval bytes with `jti = approval-gt-f5-approved` in one pass and all six were
   admitted. A shared cache would have refused five of them.

So per-cell minting strictly **reduces** sharing and cannot collide. No design question arose.

## No §E.4 cell moved

The fix is in the harness; it must change no arm and therefore no cell. Every campaign cell was
recorded before and after over three passes — the F1 ladder chain, and the F4/F5 chain under **both**
monitor configurations — and compared field by field, including every Part I quantity, the reason
code, the timing-seam names and the `unscorable` list:

**104 cells, 0 differ.**

Committed as `tools/clock_fix/evidence/campaign-cells-before.json` and `-after.json`, with the
comparison reproducible by `tools/clock_fix/compare_cells.py`.

## The guard, watched refusing real cells

A guard nobody has seen refuse anything is untested code making a claim (§6.2). Three measurements:

| | cells scored | cells refused | control outcome |
|---|:--:|:--:|---|
| one clock (healthy) | 18 | 0 | all 18 admitted |
| artifacts minted Δ+1 stale, **guard present** | 0 | 18 | nothing scored |
| artifacts minted Δ+1 stale, **guard removed** | 18 | 0 | 12 flip, 6 `false_block` |

The third row is byte-identical to the defect measured on the pre-fix code — **0 of 104 cells differ**
— so the guard is the only thing standing between the campaign and those twelve wrong cells. The
first row is the non-vacuity check: the same eighteen cells score cleanly on one clock, so the middle
row is not the campaign refusing everything for an unrelated reason.

`tests/test_campaign_clock.py` runs the healthy and straddled campaigns as real campaigns — real
arms, real signed artifacts — and asserts all three properties.

## Site A — the fixtures, and a correction to [0038](0038-pre-seal-flake-hunt-the-wall-clock-straddle.md)

**[0038](0038-pre-seal-flake-hunt-the-wall-clock-straddle.md)'s root cause is correct for one of its
two reproductions and wrong for the other.** Both are recorded here rather than the tidier answer.

**This partially supersedes 0038, and only here.** The correction reaches its **run-001 root-cause
attribution** and nothing else: 0038's reproduction condition and rates, its two named failures, its
evidence-based exclusion of the shared `b3_setup` lead, and its direction-of-failure finding all
stand. 0038 carries the reciprocal note at the attribution and in its Status.

**Run 000 — `test_b3_plus.py::…::test_the_replay_is_constructed_WITHIN_delta`. Straddle LOCATED, and
it is not the one the earlier ADR named.** The two reads are (1) the AS minting
`phase1_tokens["agent-specialist"]` when the **module-scoped** `running_as` fixture starts, and (2)
`now = int(time.time())` inside the test, injected as `p.now_epoch`. The window straddled is the
**OAuth access token's 300 s lifetime** (`default_lifetime_seconds`), not the INV freshness window Δ.
Measured directly: at offset `+0` the arm returns `(True, 'b3_admitted')`; at `+301` it returns
`(False, 'b3_oauth_resource_authorization')` with detail `exp: token has expired` — the **first**
submission refused, exactly as run 000 reported.

**Run 001 — `test_frozen_authorizer_semantics.py::test_appended_widening_verifies_but_does_not_widen`.
NOT a clock straddle. Cause UNDETERMINED.** That module reads no wall clock at all: `NOW` and
`EXPIRY` are frozen `datetime` constants, `RequestContext.now` is supplied from `NOW`, and
`src/harness/authorizer/allowed.py` reads no clock. There are not two clocks to straddle. A named
candidate — not a diagnosis — is that `allowed()` builds its set from one `authorize_candidate` run
per Ω element and `authorize_candidate` treats **any** `AuthorizationError` as a deny, so a Biscuit
runtime limit exceeded under contention would silently shrink the set; the observed failure was
`c2 <= c1` with extra items on the left, which is what a shrunken `c1` looks like. **This has not been
confirmed and no fix is applied on a guess.**

Sightings A and B from [0038](0038-pre-seal-flake-hunt-the-wall-clock-straddle.md) remain **undetermined and are not claimed closed**. Neither
was ever reproduced.

## Status

accepted — 2026-08-03 (the per-cell clock, the guard and its failing world; Site A's fixture fix
landed in the following commit)

**Partially supersedes [0038](0038-pre-seal-flake-hunt-the-wall-clock-straddle.md) — its run-001
root-cause attribution only** (§Site A above). Everything else in 0038 stands.

## Consequences

- **`src/sut/` is untouched.** No arm changed, no conjunct changed, no frozen parameter moved.
- `src/harness/` changed, so *every prior DAG gate passed* — a conjunct of G-10 — is no longer
  derivable from the last measurement and was re-measured on the row 9 platform.
- The campaign's `now` parameter is renamed `artifact_instant` and documented as what it now is: the
  seam that gives the guard a failing world. **Nothing in production passes it.**
- Site A's located straddle (run 000) is **not fixed in this ADR's commit**. It belongs to the fixture
  commit, and the fix is to give the module's OAuth material and its judging instant one clock.
