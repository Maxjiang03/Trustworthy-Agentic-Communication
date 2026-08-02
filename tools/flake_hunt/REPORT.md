# Pre-seal flake hunt — REPRODUCED, root cause identified, fix referred

**HEAD at issue: `55c1282`.** Runner: `tools/repeat_runner.py`; evidence in `tools/flake_hunt/`. (Not under `smoke/`, not `spike.py` —
in this repository those two together mean *gate*, and this adjudicates nothing).

**Outcome: the suite ends RED under a named condition, with a reproduction rate and a root cause.**
That is this task's success condition, not its failure one.

## Reproduction rate per condition

| # | condition | rate | note |
|---|---|:--:|---|
| 1 | `test_f45_matrix.py` alone, 6 busy loops, 20 CPUs free | **0/6** | contention too weak — 2.5 s wall, unchanged from idle |
| 2 | `test_f45_matrix.py` alone, **pinned to 1 CPU**, 3 busy loops | **0/4** | contention **did** bite: 2.5 s → ~15 s |
| 3 | **full suite, pinned to 1 CPU, 3 busy loops** | **2/3** | 230.7 s, 353.8 s (red); 382.0 s (green) |

Condition 2 is what makes condition 3 meaningful: the module-only runs were slowed six-fold and
**still did not reproduce**. The full suite does. Sighting B ran the full suite in a one-CPU
container.

Wall-clock figures are **run metadata** — how long a condition took to exercise. They are not latency
figures; G-3 owns cost and its numbers live in `smoke/g3/REPORT.md` only.

## Every failure named, with assertion and observed values

**Run 000** — `tests/test_b3_plus.py::TestTheCellB3PlusExistsFor::test_the_replay_is_constructed_WITHIN_delta`

```
assert freshness.is_fresh(now, now)
assert arm.decide("notes.write", ARGS)[0] is True
E   assert False is True
```

The **first** submission, which must be admitted before a replay can be tested, was refused.

**Run 001** — `tests/test_frozen_authorizer_semantics.py::test_appended_widening_verifies_but_does_not_widen`

```
assert c2 <= c1
E   AssertionError: assert frozenset({('...es/project')}) <= frozenset({('...es/meeting')})
E     Extra items in the left set: ...
```

An authority set computed at one instant compared against one computed at another.

Full output for both red runs is kept as `run-000.log` / `run-001.log`; the green run's log was
dropped for size and its counts are in `summary.json`.

## Root cause

**Fixtures read the wall clock more than once and compare the reads as if simultaneous.** Under
severe slowdown the reads straddle a validity boundary — an INV freshness window (`Δ`), a token
lifetime, or the authorizer's `time` fact — and something valid when constructed is judged after it
expired.

**That the failing test differs run to run is the evidence.** Nothing is wrong with either named
test. What fails is whichever time-sensitive assertion is executing when the machine is slow enough
for a window to close mid-test.

Same shape as `test_b_cap.py::test_expiry_is_verified` (fixed in EXP7, which re-read
`int(time.time())` against a one-second token) and the fixtures blocks 4 and G-14 corrected: the
**two-clocks hazard**, fourth and fifth instances.

## The stated lead, ruled out on evidence

`B-cap`/`B3`/`B3⁺` share **one** `b3_setup` dict, shallow-copied, with `B3⁺` last. **The sharing is
real** — 8 nested objects are the same object in all three arms. **It is not the cause**: provisioning
the triple mutates nothing, a full `delegate`→`present`→`decide` cycle across all three mutates
nothing, and all three admit `gt-f4-declassified` correctly. `load_document()` returns a fresh
object per call. **Shared and never written through.**

## One cause or two

Sighting A and the two reproductions almost certainly share one cause — A's test turns on a 30 s
token judged 45 s later, in a module that records the window was **already widened once from 5 s**.

**Sighting B is undetermined.** It did not reproduce here (0/6, 0/4), and neither condition was its
one-CPU container. Whether B is the same straddle or a distinct defect is **not established**, and
this report does not claim it is.

## Direction of failure

| sighting | direction |
|---|---|
| Run 000 (`B3⁺` first use refused) | **against** the hypothesis |
| Run 001 (authority set appears to widen) | **against** |
| Sighting A (masking limb fires — Trap 1) | **toward** |
| Sighting B (spurious false block on a benign control) | **against** |

**§6.1's pattern does not hold here.** Three of four fail *against* the hypothesis. A timing straddle
is direction-agnostic, which is what distinguishes it from the masking defects earlier blocks found —
and worth recording precisely because it breaks the pattern rather than confirming it.

## Fix — REFERRED, not applied

The cause is in **test fixtures**; `src/sut/` and `src/harness/` are untouched and need no change.
The fix is to give every time-sensitive fixture **one** injected instant, as `_token_window()` and
the G-14 fixture already do. It is not applied here: this session's budget went to reproduction and
root cause, and a fix landed without its failing-world demonstration is the outcome this task
forbids.

**Nothing was widened, retried, marked flaky, skipped, or suppressed. No frozen parameter moved.**
