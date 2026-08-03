# 0038 — The pre-seal flake: a **wall-clock straddle** in test fixtures

## Context

Fifteen gates pass and the DAG is closed at `55c1282`. What remains is the pre-registration, the
seal, and one confirmatory campaign — and **after the seal nothing may change**. An intermittent
defect that survives the seal cannot be fixed without invalidating the campaign, and a campaign
result produced by a racing apparatus is not a measurement. Two sightings were outstanding, one of
them with an **unnamed second failure**.

## The reproduction condition, named

| condition | reproduction rate |
|---|---|
| `tests/test_f45_matrix.py` alone, 6 busy loops, 20 CPUs available | **0/6** |
| `tests/test_f45_matrix.py` alone, **pinned to one CPU**, 3 busy loops | **0/4** |
| **full suite (`tests`), pinned to one CPU, 3 busy loops** | **2/3** |

The pinning is what makes the third row a real condition rather than a weaker one: the module-only
runs went from 2.5 s to ~15 s wall clock, so contention **did** bite, and they still did not
reproduce. **The full suite does.** Sighting B was measured in a container reporting one CPU, and the
full suite is what it ran.

Wall-clock durations here are **run metadata** — how long a condition took to exercise. They are not
latency figures; G-3 owns cost and its numbers live in `smoke/g3/REPORT.md` only.

## Every failure, named

Two of the three runs were **1 failed / 1228 passed**; the third was green (1229 passed). **The failing test was different in each of the two red runs**:

**Run 000** — `tests/test_b3_plus.py::TestTheCellB3PlusExistsFor::test_the_replay_is_constructed_WITHIN_delta`

```
assert freshness.is_fresh(now, now)
assert arm.decide("notes.write", ARGS)[0] is True
E   assert False is True
```

The **first** submission — the one that must be admitted before a replay can be tested — was refused.

**Run 001** — `tests/test_frozen_authorizer_semantics.py::test_appended_widening_verifies_but_does_not_widen`

```
assert c2 <= c1
E   AssertionError: assert frozenset({('...es/project')}) <= frozenset({('...es/meeting')})
E     Extra items in the left set: ...
```

An authority set computed at one instant was compared against one computed at another.

> **Corrected by [0039](0039-one-clock-per-cell-the-campaign-adopts-the-cells-clock.md) — this
> attribution only.** That module reads **no wall clock at all**: `NOW` and `EXPIRY` are frozen
> `datetime` constants and `src/harness/authorizer/allowed.py` reads no clock, so there are not two
> clocks here to straddle. Run 001's cause is **undetermined**; 0039 §Site A records a named
> candidate and applies no fix on it. **Run 000's attribution also moved** — 0039 locates its
> straddle at the OAuth access token's 300 s lifetime rather than at Δ — but the straddle diagnosis
> itself stands for run 000. Everything else below is unaffected.

## Root cause

**Fixtures that read the wall clock more than once, and compare the results as if the reads were
simultaneous.** Under severe slowdown the two reads straddle a validity boundary — an INV freshness
window (`Δ`), a token lifetime, or the authorizer's own `time` fact — and a quantity that was valid
when constructed is judged after it expired.

That is the **same shape** as two defects this project has already fixed: `test_b_cap.py`'s
`test_expiry_is_verified` (EXP7), which re-read `int(time.time())` for its negative arm against a
one-second token, and the fixtures blocks 4 and G-14 corrected. It is the **two-clocks hazard** in
its fourth and fifth instances.

**That the failing test differs run to run is the strongest evidence for this cause and against a
per-test bug**: nothing is wrong with either named test in particular. What fails is whichever
time-sensitive assertion happens to be executing when the machine is slow enough for a window to
close mid-test.

## The stated lead, ruled out on evidence

The handoff recorded a lead: `B-cap` / `B3` / `B3⁺` are provisioned from **one shared `b3_setup`
dict**, shallow-copied per arm, with `B3⁺` last. **The sharing is real** — eight nested objects
(`gamma_document`, `registry_document`, `policy_document`, `holder_privates`, `resolved_keys`,
`as_public_jwk`, `label_issuers`, `approvers`) are the same objects in all three arms.

**It is not the cause.** Measured directly: provisioning the triple from one dict mutates **nothing**
in it, and a full `delegate` → `present` → `decide` cycle for all three arms mutates **nothing**
either, with all three admitting `gt-f4-declassified` correctly. `load_document()` also returns a
fresh object per call rather than a memoised singleton. **The sharing exists and is never written
through.** Ruled out as stated, not as assumed.

## One cause or two — and what is still undetermined

**Sighting A and the two reproductions almost certainly share one cause**: A's named test is
`TestF3ExpiredToken::test_the_block_is_attributable_to_the_TOKEN_not_to_a_masking_limb`, which turns
on a 30 s token lifetime judged 45 s later — the same straddle, in a module whose own docstring
records that the window was **already widened once from 5 s**.

**Sighting B is NOT shown to be the same cause, and this ADR does not claim it is.** B's failures
were three `test_f45_matrix.py` cells with `b3_containment` on a benign control, and this session
**did not reproduce them** (0/6 and 0/4 under two named conditions, neither of which was B's
container). Whether B is the same straddle, or a distinct defect, is **undetermined**.

## Direction of failure

- **The two reproductions read AGAINST the hypothesis.** Both make a capability arm look worse than
  it is: `B3⁺` refusing a first submission it should admit, and an authority set appearing to widen.
- **Sighting A reads TOWARD the hypothesis.** Its assertion is that a block is attributable to the
  token rather than to a masking limb; failure means a masking limb fired — Trap 1, a cell reading
  `B` while measuring something else.
- **Sighting B reads AGAINST the hypothesis** — a spurious false block on a benign control.

So the project's §6.1 pattern (*every dormant defect failed toward the hypothesis*) **does not hold
here**. Three of the four known instances fail against it. That is worth recording precisely because
it breaks the pattern: a timing straddle is direction-agnostic, which is what distinguishes it from
the masking defects earlier blocks found.

## Fix location — REFERRED, not applied

The cause is in **test fixtures**, not in `src/sut/` or `src/harness/`: no arm and no harness module
was changed or needs to be, and the sharing that was suspected is inert. The fix is to make every
time-sensitive fixture take **one** instant and inject it, as `_token_window()` and the G-14 fixture
already do.

**It is not applied here.** This session's budget went to reproduction and root cause, which the task
names as the success condition; a fix landed without its own failing-world demonstration would be
the outcome the task forbids. **No frozen parameter was touched, no window widened, no retry added,
no test marked flaky, and nothing in `src/` changed.**

## Status

accepted — 2026-08-02 (the pre-seal flake hunt; reproduction and root cause, fix referred)

**Partially superseded by [0039](0039-one-clock-per-cell-the-campaign-adopts-the-cells-clock.md) —
on the run-001 root-cause attribution only.** The wall-clock straddle recorded here is **not** the
cause of `test_appended_widening_verifies_but_does_not_widen`; that module reads no wall clock, so
its cause is **undetermined**. 0039 also relocates run 000's straddle from Δ to the OAuth access
token's 300 s lifetime, without disturbing the straddle diagnosis itself. **The reproduction
condition and its rates (0/6, 0/4, 2/3), both named failures, the evidence-based exclusion of the
shared `b3_setup` lead, and the direction-of-failure finding all stand unchanged.**

## Consequences

- The repeat-runner (`tools/repeat_runner.py`) is a committed artifact. It captures **every run's
  complete output to its own file**, so an unnamed failure cannot recur.
- **This defect is pre-seal blocking.** The straddle is direction-agnostic and would corrupt a
  confirmatory campaign silently.
- The fix, and its failing world, belong to the next session.
