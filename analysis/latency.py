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

**The RQ4 layer (ADR 000X)** completes what the comment inside
`_segment_values` promises: `setup`, `delegation` and `end_to_end` are
*"reported separately"* — by `span_descriptives`, with the same three refusal
rules re-applied per span. `arm_pair_delta` differences two arms under the
§E.5 bitmask **transcription** below and labels each delta by what that
derivation can actually support, refusing the pairs it is known not to
describe (identical rows — §E.5 carries no bit for the RFC 8693 exchange —
and any pair involving `B1`, whose static shared secret has no bit either,
ADR 0035). `llm_turn_fraction` is `frozen_parameters` row 7's secondary
framing. All of it is **descriptives**: the only equivalence decision in this
study remains row 1's, above.
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


# ---------------------------------------------------------------------------
# the RQ4 layer (ADR 000X) — per-span descriptives
# ---------------------------------------------------------------------------
# The five spans the runner records per repetition (`TimingSeams`), §E.5's
# decomposition -- *"decompose into setup / delegation / boundary-verification /
# end-to-end"* -- plus ADR 0026's `presentation` seam. A TRANSCRIPTION: this
# module may import nothing from `src` (the no-measurement guarantee is
# asserted structurally), so a test pins this tuple against the runner's
# `timing.mark(...)` sites and a span added or renamed there re-triggers it.
RQ4_SPANS = ("setup", "delegation", "presentation", "boundary_verification", "end_to_end")

# `arm_pair_delta` accepts this pseudo-span to difference ADR 0026's measured
# segment (`presentation + boundary_verification`), built by `benign_series` --
# the same single implementation the row 1 estimand uses, so the two cannot
# disagree.
MEASURED_SEGMENT = "measured_segment"

# The two series every latency quantity is reported under, never pooled.
SERIES_BENIGN = "benign"
SERIES_REFUSAL_PATH = "refusal_path"


@dataclass(frozen=True)
class SpanReport:
    """`Descriptives` for one `(arm, phase, span)`, for ONE of the two series."""

    arm: str
    phase: str
    span: str
    series: str  # SERIES_BENIGN or SERIES_REFUSAL_PATH
    descriptives: Descriptives

    def as_dict(self) -> dict[str, Any]:
        return {
            "arm": self.arm,
            "phase": self.phase,
            "span": self.span,
            "series": self.series,
            "descriptives": self.descriptives.as_dict(),
        }


def _span_values(samples: Iterable[Sample], *, arm: str, phase: str, span: str) -> list[float]:
    """One span's value per repetition, refusing a repetition that lacks it.

    The repetition universe is every `(scenario, batch, repetition)` key the
    input carries for this arm and phase under ANY span. A repetition that
    exists there but has no value for the requested span is **refused rather
    than skipped**: averaging over the repetitions that do have it would
    silently misreport the arm, and a span the runner records but a campaign
    result does not carry must surface as an error, not as a smaller `n`.
    """
    if phase not in PHASES:
        raise AnalysisError(f"phase must be one of {PHASES}, got {phase!r}")
    if span not in RQ4_SPANS:
        raise AnalysisError(
            f"span must be one of {RQ4_SPANS}, got {span!r}: the runner records exactly these "
            "five (TimingSeams), and a series over a span it does not record could only be "
            "empty or wrong"
        )
    repetitions: dict[tuple[str, int, int], dict[str, float]] = {}
    for sample in samples:
        if sample.arm != arm or sample.phase != phase:
            continue
        key = (sample.scenario_id, sample.batch, sample.repetition)
        repetitions.setdefault(key, {})[sample.span] = sample.value_ms
    values: list[float] = []
    for key, spans in sorted(repetitions.items()):
        if span not in spans:
            raise AnalysisError(
                f"repetition {key} of arm {arm!r} carries no {span!r} span. The runner records "
                f"all of {RQ4_SPANS} per repetition, so an absent span is a defect in what was "
                "handed over; averaging over the repetitions that do have it would silently "
                "misreport the arm"
            )
        values.append(spans[span])
    return values


def benign_span_series(
    samples: Iterable[Sample], *, arm: str, span: str, phase: str = "warm"
) -> list[float]:
    """One RQ4 span for one arm, **excluding the chain-tamper cell**.

    The chain-tamper exclusion (ADR 0026, §J.3 item 12) applies to every span,
    and to `delegation` and `end_to_end` with MORE force than to the measured
    segment: on `gt-f1-chain-tamper` the exchange arms' **failed AS round trip
    lands in `delegation`**, so pooling that cell here would average a network
    refusal into the very component being reported. Same discipline as
    `benign_series`: refuse, never silently filter.
    """
    rows = list(samples)
    if any(s.scenario_id == REFUSAL_PATH_SCENARIO for s in rows):
        raise AnalysisError(
            f"{REFUSAL_PATH_SCENARIO!r} samples were passed to a BENIGN span series. On that "
            "cell the exchange arms perform a failed AS round trip -- which lands in the "
            "`delegation` span -- while the capability arms do purely local work, so pooling "
            "it with benign cells would average a network refusal together with local "
            "cryptography (ADR 0026, §J.3 item 12). Refusal-path latency is its own series: "
            "use refusal_span_series()"
        )
    return _span_values(rows, arm=arm, phase=phase, span=span)


def refusal_span_series(
    samples: Iterable[Sample], *, arm: str, span: str, phase: str = "warm"
) -> list[float]:
    """The chain-tamper cell's span **as its own series**, never pooled."""
    rows = [s for s in samples if s.scenario_id == REFUSAL_PATH_SCENARIO]
    if not rows:
        raise AnalysisError(
            f"no {REFUSAL_PATH_SCENARIO!r} samples supplied; an empty refusal series is not a "
            "result and must not be reported as one"
        )
    return _span_values(rows, arm=arm, phase=phase, span=span)


def span_descriptives(
    samples: Iterable[Sample], *, warmup_per_batch: int
) -> tuple[SpanReport, ...]:
    """RQ4's decomposition: `Descriptives` for every span, arm and phase present.

    §E.5: *"decompose into setup / delegation / boundary-verification /
    end-to-end; report cold and warm separately; … discard warm-up"*. Three
    rules carry over from the row 1 machinery and are re-applied here rather
    than assumed:

    * **warm-up is discarded** through the one existing `discard_warmup`,
      with the count stated by the caller;
    * **cold and warm are never pooled** — every report row names its phase
      and drew from that phase alone;
    * **the refusal path stays its own series** — `gt-f1-chain-tamper` cells
      are reported under `series="refusal_path"`, never inside a benign row,
      because the exchange arms' failed AS round trip lands in `delegation`.

    Every `(arm, phase)` group present must carry every one of the five spans
    in every repetition; a missing span refuses the whole report rather than
    silently reporting what is present (`_span_values`).
    """
    kept = discard_warmup(list(samples), per_batch=warmup_per_batch)
    benign = [s for s in kept if s.scenario_id != REFUSAL_PATH_SCENARIO]
    refusal = [s for s in kept if s.scenario_id == REFUSAL_PATH_SCENARIO]
    reports: list[SpanReport] = []
    for arm in sorted({s.arm for s in kept}):
        for phase in PHASES:
            benign_rows = [s for s in benign if s.arm == arm and s.phase == phase]
            refusal_rows = [s for s in refusal if s.arm == arm and s.phase == phase]
            for span in RQ4_SPANS:
                if benign_rows:
                    series = benign_span_series(benign_rows, arm=arm, span=span, phase=phase)
                    reports.append(SpanReport(arm, phase, span, SERIES_BENIGN, describe(series)))
                if refusal_rows:
                    series = refusal_span_series(refusal_rows, arm=arm, span=span, phase=phase)
                    reports.append(
                        SpanReport(arm, phase, span, SERIES_REFUSAL_PATH, describe(series))
                    )
    return tuple(reports)


# ---------------------------------------------------------------------------
# the RQ4 layer (ADR 000X) — arm-pair deltas under the §E.5 bit derivation
# ---------------------------------------------------------------------------
# §E.5's ten bitmask columns, spelled as its table header spells them.
E5_BITMASK_COLUMNS = (
    "oauth",
    "crypto_chain",
    "authorizer",
    "htc/holder",
    "invoke",
    "contain",
    "context",
    "approval",
    "jti",
    "audit",
)

# §E.5's table, TRANSCRIBED — row labels and cell tokens exactly as the design
# document writes them (bold/italic markers stripped). Cells are opaque tokens
# compared for EQUALITY only: `dpop-cnf`, `(scope in token)` and `root-only`
# are §E.5's own annotations, and inventing a 0/1 reading for them would make
# this stop being a transcription. A test pins every row against the document,
# so an amendment to §E.5 re-triggers it.
#
# Two absences are FINDINGS about the design, recorded in ADR 000X and
# deliberately NOT repaired here: no column carries the RFC 8693 exchange
# (`B2-broad-noexchange` and `B2-exchange-broad` have IDENTICAL rows, yet one
# performs an exchange round trip), and no column carries `B1`'s static shared
# secret (ADR 0035: `B1`'s row is `0…0 1`, `audit` alone).
E5_BITMASK: dict[str, tuple[str, ...]] = {
    "B0": ("0", "0", "0", "0", "0", "0", "0", "0", "0", "0"),
    "B1": ("0", "0", "0", "0", "0", "0", "0", "0", "0", "1"),
    "B2-broad-noexchange": ("1", "0", "0", "0", "0", "0", "0", "0", "0", "1"),
    "B2-exchange-broad": ("1", "0", "0", "0", "0", "0", "0", "0", "0", "1"),
    "B2-exchange-task": ("1", "0", "0", "0", "0", "(scope in token)", "0", "0", "0", "1"),
    "B2-exchange-task-DPoP": (
        "1",
        "0",
        "0",
        "dpop-cnf",
        "0",
        "(scope in token)",
        "0",
        "0",
        "0",
        "1",
    ),
    "B-cap": ("1", "1", "1", "0", "0", "1", "0", "0", "0", "1"),
    "B3": ("1", "1", "1", "1", "1", "1", "1", "1", "0", "1"),
    "B3⁺": ("1", "1", "1", "1", "1", "1", "1", "1", "1", "1"),
    "B3 −attenuation (unsafe control, §E.6)": (
        "1",
        "1",
        "root-only",
        "1",
        "1",
        "1",
        "1",
        "1",
        "0",
        "1",
    ),
    "B3 −holder": ("1", "1", "1", "0", "1", "1", "1", "1", "0", "1"),
    "B3 −invoke": ("1", "1", "1", "1", "0", "1", "1", "1", "0", "1"),
    "B3 −contain": ("1", "1", "1", "1", "1", "0", "1", "1", "0", "1"),
    "B3 −context": ("1", "1", "1", "1", "1", "1", "0", "1", "0", "1"),
    "B3 −approval": ("1", "1", "1", "1", "1", "1", "1", "0", "0", "1"),
}

# The nine ladder arms as the CODE spells them (`Sample.arm` carries these;
# `src/harness/matrix_grouping.py` and the arm classes agree) → the §E.5 row
# label each corresponds to. Identity except `B3+`, which the document writes
# with a superscript. The six matched-ablation rows have no built arm yet, so
# no code name is invented for them here; `e5_bit_difference` also accepts a
# §E.5 row label verbatim.
E5_ROW_FOR_ARM: dict[str, str] = {
    "B0": "B0",
    "B1": "B1",
    "B2-broad-noexchange": "B2-broad-noexchange",
    "B2-exchange-broad": "B2-exchange-broad",
    "B2-exchange-task": "B2-exchange-task",
    "B2-exchange-task-DPoP": "B2-exchange-task-DPoP",
    "B-cap": "B-cap",
    "B3": "B3",
    "B3+": "B3⁺",
}


@dataclass(frozen=True)
class BitDifference:
    """What the §E.5 bit derivation supports for one arm pair.

    `label` is `"mechanism-increment"` (exactly one bit differs; `mechanism`
    names it) or `"composite-delta"` (more than one bit differs; `mechanism`
    is `None` and every differing bit is named). The refused cases never
    construct this object.
    """

    label: str
    differing_bits: tuple[str, ...]
    mechanism: str | None


def e5_bit_difference(treatment_arm: str, control_arm: str) -> BitDifference:
    """The pair's bit difference, computed mechanically from the transcription.

    Refuses the two cases the bitmask is **known not to describe**:

    * **identical rows.** The proven instance is `B2-broad-noexchange` vs
      `B2-exchange-broad`: identical §E.5 rows, yet one performs an RFC 8693
      exchange round trip — §E.5 carries **no bit for the exchange**. A delta
      between such arms is a real quantity, but not one this derivation can
      attribute to anything.
    * **any pair involving `B1`.** §E.5's ten columns carry no bit for `B1`'s
      static shared secret (ADR 0035: its row is `0…0 1`, `audit` alone), so
      the one authentication mechanism it has is invisible to the bitmask and
      no bit difference against it describes what actually changes.

    A one-bit label names the BIT, not everything that changed: because no
    column carries the exchange, a pair in which one arm exchanges and the
    other does not (e.g. `B2-broad-noexchange` → `B2-exchange-task`) still
    carries the unmodelled round trip inside its delta. That limit is a
    finding about the design, recorded in ADR 000X, not repaired here.
    """
    rows: dict[str, tuple[str, ...]] = {}
    for name in (treatment_arm, control_arm):
        row_label = E5_ROW_FOR_ARM.get(name, name)
        if row_label not in E5_BITMASK:
            raise AnalysisError(
                f"{name!r} is neither a §E.5 bitmask row nor a code arm name mapped to one, so "
                "no bit derivation exists for this pair. The bitmask is a transcription; a new "
                "arm is added to §E.5 first, never here"
            )
        rows[name] = E5_BITMASK[row_label]
    if "B1" in (treatment_arm, control_arm):
        raise AnalysisError(
            "a pair involving B1 is refused: §E.5's ten columns carry no bit for B1's static "
            "shared secret — its row is 0…0 1, `audit` alone (ADR 0035) — so the one "
            "authentication mechanism it has is invisible to the bitmask and no bit difference "
            "can describe what actually changes against it"
        )
    differing = tuple(
        column
        for column, ours, theirs in zip(
            E5_BITMASK_COLUMNS, rows[treatment_arm], rows[control_arm], strict=True
        )
        if ours != theirs
    )
    if not differing:
        raise AnalysisError(
            f"{treatment_arm!r} and {control_arm!r} have IDENTICAL §E.5 rows, so the bitmask is "
            "known not to describe whatever differs between them. The proven instance is "
            "B2-broad-noexchange vs B2-exchange-broad: identical rows, yet one performs an "
            "RFC 8693 exchange round trip — §E.5 carries no bit for the exchange. A delta "
            "between them is a real quantity, but not one this derivation can attribute"
        )
    if len(differing) == 1:
        return BitDifference("mechanism-increment", differing, differing[0])
    return BitDifference("composite-delta", differing, None)


@dataclass(frozen=True)
class ArmPairDelta:
    """One arm-pair latency delta, labelled by what §E.5's bits support.

    **Descriptives, not a decision.** §E.5 makes latency the only quantity
    with repeated sampling and confidence intervals, so the interval belongs
    here — but the only equivalence decision in this study is row 1's
    (ADR 0026), so this object carries **no verdict and no margin**, and a
    composite delta must never be relabelled with a single mechanism's name:
    that would report a composite as an isolated cost.
    """

    treatment_arm: str
    control_arm: str
    span: str
    phase: str
    label: str
    differing_bits: tuple[str, ...]
    mechanism: str | None
    point_estimate_ms: float
    ci: Interval
    confidence: float
    resamples: int
    treatment: Descriptives
    control: Descriptives

    def as_dict(self) -> dict[str, Any]:
        return {
            "treatment_arm": self.treatment_arm,
            "control_arm": self.control_arm,
            "span": self.span,
            "phase": self.phase,
            "label": self.label,
            "differing_bits": list(self.differing_bits),
            "mechanism": self.mechanism,
            "point_estimate_ms": self.point_estimate_ms,
            "ci_low_ms": self.ci.low,
            "ci_high_ms": self.ci.high,
            "confidence": self.confidence,
            "resamples": self.resamples,
            "treatment": self.treatment.as_dict(),
            "control": self.control.as_dict(),
        }


def arm_pair_delta(
    samples: Iterable[Sample],
    *,
    treatment_arm: str,
    control_arm: str,
    span: str,
    phase: str = "warm",
    confidence: float = 0.95,
    resamples: int = 10_000,
    seed: int,
) -> ArmPairDelta:
    """`median(treatment) − median(control)` for one span, with a bootstrap CI.

    The §E.5 labelling (`e5_bit_difference`) runs FIRST, so a refused pair is
    refused before any arithmetic is done on its samples. `span` is one of
    `RQ4_SPANS`, or `MEASURED_SEGMENT` to difference ADR 0026's segment
    through the same `benign_series` the row 1 estimand uses. The benign
    series builders enforce the chain-tamper exclusion, so refusal-path
    samples in the input refuse the delta rather than leak into it.

    Returns descriptives with an interval — **never a `Decision`**, and there
    is no margin parameter to compare against: a per-mechanism interval handed
    back with a threshold would read as a second equivalence test, and row 1's
    is the only one in this study (ADR 0026).
    """
    difference = e5_bit_difference(treatment_arm, control_arm)
    rows = list(samples)
    if span == MEASURED_SEGMENT:
        treatment = benign_series(rows, arm=treatment_arm, phase=phase)
        control = benign_series(rows, arm=control_arm, phase=phase)
    else:
        treatment = benign_span_series(rows, arm=treatment_arm, span=span, phase=phase)
        control = benign_span_series(rows, arm=control_arm, span=span, phase=phase)
    ci = bootstrap_median_difference(
        treatment, control, confidence=confidence, resamples=resamples, seed=seed
    )
    return ArmPairDelta(
        treatment_arm=treatment_arm,
        control_arm=control_arm,
        span=span,
        phase=phase,
        label=difference.label,
        differing_bits=difference.differing_bits,
        mechanism=difference.mechanism,
        point_estimate_ms=statistics.median(treatment) - statistics.median(control),
        ci=ci,
        confidence=confidence,
        resamples=resamples,
        treatment=describe(treatment),
        control=describe(control),
    )


# ---------------------------------------------------------------------------
# the RQ4 layer (ADR 000X) — frozen_parameters row 7's secondary framing
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class TurnFraction:
    """A span median as a fraction of the row 7 denominators. Interpretive only.

    Carries the denominators it was computed against so the framing is
    auditable — and **no verdict and no margin**, because no hypothesis, gate
    criterion or retraction rule depends on row 7.
    """

    median_ms: float
    t_full_ms: float
    t_ttft_ms: float
    fraction_of_full_turn: float
    fraction_of_ttft: float

    def as_dict(self) -> dict[str, Any]:
        return {
            "median_ms": self.median_ms,
            "t_full_ms": self.t_full_ms,
            "t_ttft_ms": self.t_ttft_ms,
            "fraction_of_full_turn": self.fraction_of_full_turn,
            "fraction_of_ttft": self.fraction_of_ttft,
        }


def llm_turn_fraction(
    described: Descriptives, *, t_full_ms: float, t_ttft_ms: float
) -> TurnFraction:
    """Row 7's framing: a span's median over each reference denominator.

    **A secondary interpretive aid only** (`frozen_parameters` row 7,
    ADR 0025): `T_full_ms` and `T_ttft_ms` are *fixed constants for
    interpretation, never measurements*, neither is ever re-fitted to observed
    data, and **no hypothesis, gate criterion or retraction rule depends on
    this framing**. §E.5: *"Absolute overhead is the primary result; the
    fraction-of-one-LLM-turn (against both a full-turn and a conservative TTFT
    denominator) is a secondary interpretive aid."*

    Both denominators have exactly ONE source:
    `src.harness.frozen_parameters.llm_turn_denominators()`, the single reader
    of `docs/frozen_parameters.md`. This module may import nothing from `src`
    (the no-measurement guarantee is asserted structurally by test), so the
    caller passes the pair that reader returns — the same shape row 1's margin
    already uses in `lightweight_claim` — and the committed tests feed these
    parameters from that reader. Hardcoding `2000` or `250` anywhere in this
    module would be a second copy of a frozen value, and a test scans this
    module's integer literals to refuse exactly that.
    """
    if t_full_ms <= 0 or t_ttft_ms <= 0:
        raise AnalysisError(
            f"row 7 denominators must be positive, got T_full_ms={t_full_ms}, "
            f"T_ttft_ms={t_ttft_ms}; a zero or negative reference turn is not a framing"
        )
    return TurnFraction(
        median_ms=described.median,
        t_full_ms=float(t_full_ms),
        t_ttft_ms=float(t_ttft_ms),
        fraction_of_full_turn=described.median / t_full_ms,
        fraction_of_ttft=described.median / t_ttft_ms,
    )


__all__ = [
    "E5_BITMASK",
    "E5_BITMASK_COLUMNS",
    "E5_ROW_FOR_ARM",
    "MEASURED_SEGMENT",
    "MEASURED_SEGMENT_SPANS",
    "PHASES",
    "REFUSAL_PATH_SCENARIO",
    "RQ4_SPANS",
    "SERIES_BENIGN",
    "SERIES_REFUSAL_PATH",
    "ArmPairDelta",
    "BitDifference",
    "Decision",
    "Descriptives",
    "Interval",
    "Sample",
    "SpanReport",
    "TurnFraction",
    "arm_pair_delta",
    "benign_series",
    "benign_span_series",
    "bootstrap_median_difference",
    "describe",
    "discard_warmup",
    "e5_bit_difference",
    "equivalence_decision",
    "lightweight_claim",
    "llm_turn_fraction",
    "refusal_series",
    "refusal_span_series",
    "span_descriptives",
]
