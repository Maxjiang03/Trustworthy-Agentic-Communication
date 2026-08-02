"""The latency side — the only sampled quantity, and ADR 0026's decision rule (STEP 9).

§E.5 makes latency *"the **only** quantity with repeated sampling and confidence
intervals (a genuine random quantity)"*, and ADR 0026 fixes what is estimated
and what settles the claim:

* **estimand** — `median(B3) − median(B0)` over the measured segment
  `presentation + boundary_verification`, **warm**;
* **decision rule** — the "lightweight" claim **stands** iff the **upper bound
  of the 95% bootstrap confidence interval** on that difference is **< 20 ms**.
  *A point estimate below the margin with a CI upper bound above it does not
  support the claim*, so this module returns a **verdict and an interval**,
  never a bare number a reader could compare to the margin themselves.

**Three rules are enforced in the code rather than written in a comment,**
because each is a rule about what must NOT be pooled and a comment cannot
refuse:

1. **The chain-tamper exclusion** (ADR 0026, §J.3 item 12). On
   `gt-f1-chain-tamper` the exchange arms perform a **failed AS round trip** and
   receive no token while the capability arms do purely local work. Pooling that
   cell with benign cells would average a network refusal together with local
   cryptography. `benign_series` **raises** on a chain-tamper sample;
   `refusal_series` is where it goes, as its own series.
2. **Cold and warm are separate.** `series` refuses a mixed-phase pool. Cold and
   warm measure different things and §E.5 asks for both, separately.
3. **The decomposition is preserved.** The segment is the **sum of two spans per
   repetition**, paired by `(scenario, batch, repetition)`. A repetition missing
   either span is refused rather than summed from one — a half-measured
   repetition would silently understate the arm that has the other half, and for
   `B3` the missing half would be `presentation`, which is exactly where its
   per-invocation cryptography lives.

**This module never measures anything.** It takes samples as plain numbers from
its caller and has no clock, no timer and no import of the runner. G-3 has not
run and `frozen_parameters` row 9 (the sealed measurement platform) is not
locked, so feeding it a real timing would produce a number ADR 0025 says cannot
count. Its tests use **synthetic** samples whose answer is constructed.
"""

import random
import statistics
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from analysis.security import AnalysisError

# ADR 0026's measured segment: exactly these two spans, summed per repetition.
MEASURED_SEGMENT_SPANS = ("presentation", "boundary_verification")
# The one cell excluded from every benign per-arm mean and from the row 1
# estimand, by name (ADR 0026).
REFUSAL_PATH_SCENARIO = "gt-f1-chain-tamper"
PHASES = ("cold", "warm")


@dataclass(frozen=True)
class Sample:
    """One timed span. **Never produced here** — supplied by a measurement run.

    `value_ms` is a duration in milliseconds. This module performs arithmetic
    on whatever it is given and makes no claim that any value is real.
    """

    arm: str
    scenario_id: str
    phase: str
    batch: int
    repetition: int
    span: str
    value_ms: float

    def __post_init__(self) -> None:
        if self.phase not in PHASES:
            raise AnalysisError(f"phase must be one of {PHASES}, got {self.phase!r}")


@dataclass(frozen=True)
class Interval:
    low: float
    high: float


@dataclass(frozen=True)
class Descriptives:
    """§E.5's reported shape: median, p95, IQR. Never a bare mean."""

    n: int
    median: float
    p95: float
    iqr: float

    def as_dict(self) -> dict[str, Any]:
        return {"n": self.n, "median": self.median, "p95": self.p95, "iqr": self.iqr}


@dataclass(frozen=True)
class Decision:
    """ADR 0026's rule as a **verdict plus the interval it rests on**.

    `verdict` is `"stands"` or `"retracted"`. It is deliberately not a bare
    number: the rule turns on the CI **upper bound**, and a caller handed only
    a point estimate would be one step away from comparing the wrong quantity
    to the margin.
    """

    verdict: str
    point_estimate_ms: float
    ci: Interval
    margin_ms: float
    confidence: float
    resamples: int
    treatment: Descriptives
    control: Descriptives

    @property
    def stands(self) -> bool:
        return self.verdict == "stands"

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "point_estimate_ms": self.point_estimate_ms,
            "ci_low_ms": self.ci.low,
            "ci_high_ms": self.ci.high,
            "margin_ms": self.margin_ms,
            "confidence": self.confidence,
            "resamples": self.resamples,
            "treatment": self.treatment.as_dict(),
            "control": self.control.as_dict(),
        }


# ---------------------------------------------------------------------------
# building a series — where the three rules refuse
# ---------------------------------------------------------------------------
def discard_warmup(samples: Sequence[Sample], *, per_batch: int) -> list[Sample]:
    """§E.5: *discard warm-up*. Drops the first `per_batch` repetitions of each
    `(arm, scenario, phase, batch)` group, by repetition index rather than by
    position, so the result does not depend on the order the caller happened to
    supply."""
    if per_batch < 0:
        raise AnalysisError("per_batch must be non-negative")
    groups: dict[tuple[str, str, str, int], list[Sample]] = {}
    for sample in samples:
        groups.setdefault((sample.arm, sample.scenario_id, sample.phase, sample.batch), []).append(
            sample
        )
    kept: list[Sample] = []
    for group in groups.values():
        cutoff = sorted({s.repetition for s in group})[:per_batch]
        kept.extend(s for s in group if s.repetition not in cutoff)
    return kept


def _segment_values(samples: Iterable[Sample], *, arm: str, phase: str) -> list[float]:
    """The measured segment per repetition: `presentation + boundary_verification`."""
    if phase not in PHASES:
        raise AnalysisError(f"phase must be one of {PHASES}, got {phase!r}")
    paired: dict[tuple[str, int, int], dict[str, float]] = {}
    for sample in samples:
        if sample.arm != arm or sample.phase != phase:
            continue
        if sample.span not in MEASURED_SEGMENT_SPANS:
            # `setup`, `delegation` and `end_to_end` are reported separately and
            # are NOT part of the row 1 estimand (ADR 0026 excludes each by
            # name). Silently summing one in would change what is measured.
            continue
        key = (sample.scenario_id, sample.batch, sample.repetition)
        paired.setdefault(key, {})[sample.span] = sample.value_ms
    values: list[float] = []
    for key, spans in sorted(paired.items()):
        missing = set(MEASURED_SEGMENT_SPANS) - set(spans)
        if missing:
            raise AnalysisError(
                f"repetition {key} of arm {arm!r} is missing span(s) {sorted(missing)}. The "
                "measured segment is the SUM of both spans; summing from one would understate "
                "the arm that has the other half, and for B3 the missing half is `presentation`, "
                "where its per-invocation cryptography lives"
            )
        values.append(sum(spans[span] for span in MEASURED_SEGMENT_SPANS))
    return values


def benign_series(samples: Iterable[Sample], *, arm: str, phase: str = "warm") -> list[float]:
    """The measured segment for one arm, **excluding the chain-tamper cell**.

    Enforced by refusal rather than by filtering: a caller who passes
    chain-tamper samples into a benign pool has made a mistake ADR 0026 names,
    and silently dropping them would hide it. `refusal_series` is where those
    samples belong.
    """
    rows = list(samples)
    offending = {s.scenario_id for s in rows if s.scenario_id == REFUSAL_PATH_SCENARIO}
    if offending:
        raise AnalysisError(
            f"{REFUSAL_PATH_SCENARIO!r} samples were passed to a BENIGN series. On that cell the "
            "exchange arms perform a failed AS round trip and receive no token while the "
            "capability arms do purely local work, so pooling it with benign cells would average "
            "a network refusal together with local cryptography (ADR 0026, §J.3 item 12). "
            "Refusal-path latency is its own series: use refusal_series()"
        )
    return _segment_values(rows, arm=arm, phase=phase)


def refusal_series(samples: Iterable[Sample], *, arm: str, phase: str = "warm") -> list[float]:
    """The chain-tamper cell **as its own series**, never pooled with benign."""
    rows = [s for s in samples if s.scenario_id == REFUSAL_PATH_SCENARIO]
    if not rows:
        raise AnalysisError(
            f"no {REFUSAL_PATH_SCENARIO!r} samples supplied; an empty refusal series is not a "
            "result and must not be reported as one"
        )
    return _segment_values(rows, arm=arm, phase=phase)


def describe(values: Sequence[float]) -> Descriptives:
    """Median, p95 and IQR — §E.5's shape, computed without a dependency."""
    if not values:
        raise AnalysisError("no values to describe; an empty series has no median")
    ordered = sorted(values)
    return Descriptives(
        n=len(ordered),
        median=statistics.median(ordered),
        p95=_percentile(ordered, 0.95),
        iqr=_percentile(ordered, 0.75) - _percentile(ordered, 0.25),
    )


def _percentile(ordered: Sequence[float], fraction: float) -> float:
    """Linear-interpolation percentile on an already-sorted sequence."""
    if len(ordered) == 1:
        return float(ordered[0])
    position = fraction * (len(ordered) - 1)
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return float(ordered[lower] * (1 - weight) + ordered[upper] * weight)


# ---------------------------------------------------------------------------
# the bootstrap, and ADR 0026's rule
# ---------------------------------------------------------------------------
def bootstrap_median_difference(
    treatment: Sequence[float],
    control: Sequence[float],
    *,
    confidence: float = 0.95,
    resamples: int = 10_000,
    seed: int,
) -> Interval:
    """Percentile bootstrap CI on `median(treatment) − median(control)`.

    Each group is resampled with replacement **independently**, which is the
    right pairing for two condition series measured in interleaved batches
    rather than as matched pairs.

    `seed` is **required**. A bootstrap seeded from the clock would give a
    different interval on every run, and a decision rule that turns on the
    interval's upper bound would then not be reproducible from the sealed
    artifacts — which Part H step 3 requires it to be.
    """
    if not treatment or not control:
        raise AnalysisError("both series need at least one value")
    if not 0 < confidence < 1:
        raise AnalysisError(f"confidence must be in (0, 1), got {confidence}")
    if resamples < 1000:
        raise AnalysisError(
            f"{resamples} resamples is too few for a {confidence:.0%} interval; the tail the "
            "decision rule reads would be estimated from a handful of draws"
        )
    rng = random.Random(seed)
    treatment_list, control_list = list(treatment), list(control)
    differences: list[float] = []
    for _ in range(resamples):
        a = [rng.choice(treatment_list) for _ in treatment_list]
        b = [rng.choice(control_list) for _ in control_list]
        differences.append(statistics.median(a) - statistics.median(b))
    differences.sort()
    alpha = 1.0 - confidence
    return Interval(
        low=_percentile(differences, alpha / 2),
        high=_percentile(differences, 1 - alpha / 2),
    )


def equivalence_decision(
    treatment: Sequence[float],
    control: Sequence[float],
    *,
    margin_ms: float,
    confidence: float = 0.95,
    resamples: int = 10_000,
    seed: int,
) -> Decision:
    """ADR 0026's rule: **stands** iff the CI upper bound is `< margin_ms`.

    Returns the verdict *and* the interval. The asymmetry is the point — a
    point estimate of 3 ms with an interval reaching 24 ms does **not** support
    a 20 ms claim, and a function returning only the point estimate would let
    that mistake be made one line away.
    """
    ci = bootstrap_median_difference(
        treatment, control, confidence=confidence, resamples=resamples, seed=seed
    )
    point = statistics.median(treatment) - statistics.median(control)
    return Decision(
        verdict="stands" if ci.high < margin_ms else "retracted",
        point_estimate_ms=point,
        ci=ci,
        margin_ms=float(margin_ms),
        confidence=confidence,
        resamples=resamples,
        treatment=describe(treatment),
        control=describe(control),
    )


def lightweight_claim(
    samples: Iterable[Sample],
    *,
    margin_ms: float,
    treatment_arm: str = "B3",
    control_arm: str = "B0",
    seed: int,
    resamples: int = 10_000,
) -> Decision:
    """The row 1 estimand end to end: `median(B3) − median(B0)`, **warm**.

    The arms are named by ADR 0026 and are defaults here rather than free
    parameters in spirit: *"no other pair may be substituted for this test, and
    the arms compared are not renegotiated after seeing results."* They remain
    arguments only so the matched-ablation series can reuse the machinery, and
    a caller substituting a different pair is doing something the ADR forbids
    for the row 1 claim.

    Warm only, and the chain-tamper cell is excluded by `benign_series`.
    """
    rows = list(samples)
    return equivalence_decision(
        benign_series(rows, arm=treatment_arm, phase="warm"),
        benign_series(rows, arm=control_arm, phase="warm"),
        margin_ms=margin_ms,
        seed=seed,
        resamples=resamples,
    )


__all__ = [
    "MEASURED_SEGMENT_SPANS",
    "PHASES",
    "REFUSAL_PATH_SCENARIO",
    "Decision",
    "Descriptives",
    "Interval",
    "Sample",
    "benign_series",
    "bootstrap_median_difference",
    "describe",
    "discard_warmup",
    "equivalence_decision",
    "lightweight_claim",
    "refusal_series",
]
