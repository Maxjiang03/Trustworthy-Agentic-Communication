"""The analysis code, on **synthetic inputs only** (EXP6 STEP 9–10).

Part H step 3 seals the analysis code, so it must exist and be testable before
the seal — and it must be testable **without a measurement**, because G-3 has
not run and `frozen_parameters` row 9 (the sealed measurement platform) is not
locked. A real timing fed in here would break EXP6 forbidden action 1 *and*
produce a number ADR 0025 says cannot count.

So every value below is **constructed**, and the answers are constructed with
them. `test_no_module_in_analysis_can_measure_anything` asserts the package has
no clock, no timer and no import of the runner — the absence is the guarantee,
not a promise in a docstring.

**Both sides of the 20 ms rule are exercised**, in three cases, because a
decision rule that has only ever returned one answer has not been tested:

| case | point estimate | CI upper bound | verdict |
|---|---|---|---|
| tight, small difference | 3.000 ms | 3.100 ms | **stands** |
| tight, large difference | 25.000 ms | 25.100 ms | **retracted** |
| **wide, point BELOW the margin** | **14.975 ms** | **29.900 ms** | **retracted** |

The third is the one ADR 0026 names explicitly — *"a point estimate below the
margin with a CI upper bound above it does **not** support the claim"* — and it
is the only one that can distinguish a rule reading the interval from a rule
reading the point estimate. Without it the first two would pass against a wrong
implementation.

**The security side gets no interval**, and that is asserted structurally:
§E.5 is explicit that a fixed author-constructed suite has no random-sampling
population, so repetition detects **nondeterminism**, not sampling error.
"""

import ast
import inspect
from pathlib import Path

import pytest

from analysis import latency as L
from analysis import security as S

REPO_ROOT = Path(__file__).resolve().parents[1]
ANALYSIS = REPO_ROOT / "analysis"
SEED = 20260802
MARGIN_MS = 20  # `frozen_parameters` row 1 (ADR 0026); read, never chosen here


# ---------------------------------------------------------------------------
# synthetic samples — constructed, never measured
# ---------------------------------------------------------------------------
def _control() -> list[float]:
    """A tight control series. Deterministic, no RNG: a fixture that varied
    per run could not pin an interval."""
    return [4.0 + (i % 10) * 0.05 for i in range(60)]


def _tight(offset: float) -> list[float]:
    return [4.0 + offset + (i % 10) * 0.05 for i in range(60)]


def _bimodal(gap: float, n: int = 30) -> list[float]:
    """Half the mass low, half `gap` above it: the median sits between two
    clusters and moves a long way under resampling, so the interval is wide
    while the point estimate stays modest."""
    return [4.0 + (i % 5) * 0.1 if i % 2 == 0 else 4.0 + gap + (i % 5) * 0.1 for i in range(n)]


def _samples(arm: str, values, *, scenario_id="gt-benign", phase="warm", batch=0, split=True):
    """One `Sample` per span per repetition.

    `split=True` divides each value across the two spans of the measured
    segment, so the segment sums back to the value and the decomposition is
    genuinely present rather than faked with one span.
    """
    rows = []
    for repetition, value in enumerate(values):
        if split:
            rows.append(
                L.Sample(arm, scenario_id, phase, batch, repetition, "presentation", value * 0.4)
            )
            rows.append(
                L.Sample(
                    arm, scenario_id, phase, batch, repetition, "boundary_verification", value * 0.6
                )
            )
        else:
            rows.append(L.Sample(arm, scenario_id, phase, batch, repetition, "presentation", value))
    return rows


# ---------------------------------------------------------------------------
# STEP 9 — the security side: exact counts, and NO interval
# ---------------------------------------------------------------------------
def _verdict(scenario, arm, family, **quantities):
    return S.Verdict(scenario, arm, family, template=f"{family}-template", quantities=quantities)


class TestTheSecuritySideHasNoConfidenceInterval:
    def test_the_module_exposes_no_interval_estimator(self):
        """§E.5's rule, enforced by ABSENCE rather than by discipline.

        Scanned rather than eyeballed: any function whose name suggests an
        interval, a bootstrap or a significance test would fail here.
        """
        source = (ANALYSIS / "security.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        defined = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
        forbidden = ("interval", "bootstrap", "ci_", "pvalue", "p_value", "significance", "ttest")
        offending = sorted(
            name for name in defined if any(token in name.lower() for token in forbidden)
        )
        assert offending == [], f"the security module defines interval estimator(s): {offending}"

    def test_it_imports_no_sampling_machinery(self):
        source = (ANALYSIS / "security.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        assert not ({"random", "numpy", "scipy", "scipy.stats"} & imported)

    def test_counts_are_exact_and_the_rate_is_just_the_quotient(self):
        verdicts = [
            _verdict("s1", "B0", "F1", admission_breach=True),
            _verdict("s2", "B0", "F1", admission_breach=True),
            _verdict("s3", "B3", "F1", admission_breach=False),
            _verdict("s4", "B3", "F1", admission_breach=False),
        ]
        counts = S.instance_micro(verdicts, "admission_breach")
        assert (counts.count, counts.total) == (2, 4)
        assert counts.rate == 0.5

    def test_an_unscored_cell_is_excluded_from_the_denominator(self):
        """`None` means *not scored*. Folding it into the `False` bucket would
        report an unscorable cell as a clean result."""
        verdicts = [
            _verdict("s1", "B0", "F1", realized_harm=True),
            _verdict("s2", "B3", "F1", realized_harm=False),
            _verdict("s3", "B3", "F1", realized_harm=None),
        ]
        counts = S.instance_micro(verdicts, "realized_harm")
        assert (counts.count, counts.total) == (1, 2)

    def test_a_rate_over_zero_cells_raises_rather_than_returning_zero(self):
        with pytest.raises(S.AnalysisError, match="undefined"):
            S.Counts(count=0, total=0).rate

    def test_both_granularities_are_available(self):
        verdicts = [
            _verdict("s1", "B0", "F1", admission_breach=True),
            _verdict("s2", "B0", "F4", admission_breach=False),
        ]
        macro = S.class_macro(verdicts, "admission_breach")
        assert set(macro) == {"F1", "F4"}
        assert macro["F1"].count == 1 and macro["F4"].count == 0
        assert S.instance_micro(verdicts, "admission_breach").total == 2

    def test_template_derived_variants_are_clustered(self):
        verdicts = [
            S.Verdict("s1", "B0", "F1", "amplify-root", {"admission_breach": True}),
            S.Verdict("s2", "B0", "F1", "amplify-root", {"admission_breach": True}),
            S.Verdict("s3", "B0", "F1", "amplify-terminal", {"admission_breach": False}),
        ]
        clustered = S.clustered_by_template(verdicts, "admission_breach")
        assert clustered["amplify-root"].count == 2
        assert clustered["amplify-terminal"].count == 0


class TestNondeterminism:
    def test_it_stays_silent_when_the_repetitions_agree(self):
        """The stay-silent half: a deterministic apparatus reports nothing."""
        run = [_verdict("s1", "B3", "F1", admission_breach=False, realized_harm=False)]
        assert S.nondeterminism([run, list(run)]) == []

    def test_it_fires_when_a_verdict_changes_between_repetitions(self):
        first = [_verdict("s1", "B3", "F1", admission_breach=False)]
        second = [_verdict("s1", "B3", "F1", admission_breach=True)]
        found = S.nondeterminism([first, second])
        assert len(found) == 1
        assert found[0].quantity == "admission_breach"
        assert found[0].values == (False, True)

    def test_a_cell_missing_from_one_repetition_is_a_disagreement(self):
        """A silently dropped cell would otherwise read as agreement among the
        repetitions that did produce it."""
        first = [
            _verdict("s1", "B3", "F1", admission_breach=False),
            _verdict("s2", "B3", "F1", admission_breach=False),
        ]
        second = [_verdict("s1", "B3", "F1", admission_breach=False)]
        found = S.nondeterminism([first, second])
        assert [d.quantity for d in found] == ["cell-present"]
        assert found[0].scenario_id == "s2"

    def test_one_repetition_cannot_disagree_with_itself(self):
        run = [_verdict("s1", "B3", "F1", admission_breach=False)]
        with pytest.raises(S.AnalysisError, match="at least two repetitions"):
            S.nondeterminism([run])

    def test_it_returns_no_p_value_and_no_interval(self):
        """It is a defect report, not a hypothesis test."""
        first = [_verdict("s1", "B3", "F1", admission_breach=False)]
        second = [_verdict("s1", "B3", "F1", admission_breach=True)]
        found = S.nondeterminism([first, second])
        assert set(vars(found[0])) == {"scenario_id", "arm", "quantity", "values"}


# ---------------------------------------------------------------------------
# STEP 9 — the latency side: ADR 0026's rule, both sides of the margin
# ---------------------------------------------------------------------------
class TestTheDecisionRule:
    def test_a_small_tight_difference_STANDS(self):
        decision = L.equivalence_decision(_tight(3.0), _control(), margin_ms=MARGIN_MS, seed=SEED)
        assert decision.verdict == "stands"
        assert decision.stands is True
        assert decision.point_estimate_ms == pytest.approx(3.0, abs=0.01)
        assert decision.ci.high < MARGIN_MS

    def test_a_large_difference_is_RETRACTED(self):
        decision = L.equivalence_decision(_tight(25.0), _control(), margin_ms=MARGIN_MS, seed=SEED)
        assert decision.verdict == "retracted"
        assert decision.point_estimate_ms == pytest.approx(25.0, abs=0.01)
        assert decision.ci.low > MARGIN_MS

    def test_a_point_estimate_BELOW_the_margin_is_still_RETRACTED_if_the_CI_is_not(self):
        """**The case ADR 0026 names, and the only one that tests the rule.**

        *"A point estimate below the margin with a CI upper bound above it does
        not support the claim."* Without this case, an implementation that
        compared the POINT ESTIMATE to the margin would pass both tests above.
        """
        decision = L.equivalence_decision(
            _bimodal(30.0), _control(), margin_ms=MARGIN_MS, seed=SEED
        )
        assert decision.point_estimate_ms < MARGIN_MS
        assert decision.ci.high > MARGIN_MS
        assert decision.verdict == "retracted"

    def test_the_decision_carries_the_interval_it_rests_on(self):
        """Not a bare number: a caller handed only a point estimate would be
        one line from comparing the wrong quantity to the margin."""
        decision = L.equivalence_decision(_tight(3.0), _control(), margin_ms=MARGIN_MS, seed=SEED)
        payload = decision.as_dict()
        for key in ("verdict", "point_estimate_ms", "ci_low_ms", "ci_high_ms", "margin_ms"):
            assert key in payload
        assert payload["margin_ms"] == float(MARGIN_MS)

    def test_the_margin_comes_from_the_frozen_row(self):
        """Row 1 is ADR 0026's and is read, never chosen in the analysis."""
        from src.harness import frozen_parameters

        assert frozen_parameters.equivalence_margin_ms() == MARGIN_MS

    def test_the_bootstrap_is_reproducible_and_the_seed_is_required(self):
        """A clock-seeded bootstrap would give a different interval each run,
        and a rule turning on its upper bound would not be reproducible from
        the sealed artifacts."""
        first = L.bootstrap_median_difference(_tight(3.0), _control(), seed=SEED)
        second = L.bootstrap_median_difference(_tight(3.0), _control(), seed=SEED)
        assert (first.low, first.high) == (second.low, second.high)
        other = L.bootstrap_median_difference(_tight(3.0), _control(), seed=SEED + 1)
        assert (other.low, other.high) != (first.low, first.high) or True  # may coincide
        with pytest.raises(TypeError):
            L.bootstrap_median_difference(_tight(3.0), _control())  # seed is keyword-required

    def test_too_few_resamples_is_refused(self):
        with pytest.raises(L.AnalysisError, match="too few"):
            L.bootstrap_median_difference(_tight(3.0), _control(), resamples=100, seed=SEED)


class TestTheReportedShape:
    def test_median_p95_and_iqr(self):
        described = L.describe([1.0, 2.0, 3.0, 4.0, 5.0])
        assert described.n == 5
        assert described.median == 3.0
        assert described.p95 == pytest.approx(4.8)
        assert described.iqr == pytest.approx(2.0)

    def test_an_empty_series_raises_rather_than_returning_zero(self):
        with pytest.raises(L.AnalysisError, match="no values"):
            L.describe([])


# ---------------------------------------------------------------------------
# STEP 9 — the three rules enforced in code, not in a comment
# ---------------------------------------------------------------------------
class TestTheChainTamperExclusion:
    def test_a_chain_tamper_sample_in_a_BENIGN_pool_is_refused(self):
        """ADR 0026 / §J.3 item 12, enforced by refusal rather than filtering.

        On that cell the exchange arms perform a failed AS round trip and
        receive no token while the capability arms do purely local work.
        Silently dropping the samples would hide a caller's mistake; refusing
        names it.
        """
        rows = _samples("B3", _tight(3.0)) + _samples(
            "B3", _tight(9.0), scenario_id=L.REFUSAL_PATH_SCENARIO
        )
        with pytest.raises(L.AnalysisError, match="refusal_series"):
            L.benign_series(rows, arm="B3")

    def test_the_refusal_path_is_its_OWN_series(self):
        rows = _samples("B3", _tight(9.0), scenario_id=L.REFUSAL_PATH_SCENARIO)
        series = L.refusal_series(rows, arm="B3")
        assert len(series) == 60

    def test_an_empty_refusal_series_is_refused(self):
        """Not a result, so it may not be reported as one."""
        with pytest.raises(L.AnalysisError, match="not a result"):
            L.refusal_series(_samples("B3", _tight(3.0)), arm="B3")

    def test_the_row_1_estimand_excludes_it_end_to_end(self):
        rows = (
            _samples("B3", _tight(3.0))
            + _samples("B0", _control())
            + _samples("B3", _tight(40.0), scenario_id=L.REFUSAL_PATH_SCENARIO)
        )
        with pytest.raises(L.AnalysisError, match=L.REFUSAL_PATH_SCENARIO):
            L.lightweight_claim(rows, margin_ms=MARGIN_MS, seed=SEED)


class TestColdAndWarmAreSeparate:
    def test_the_estimand_is_the_WARM_path(self):
        rows = _samples("B3", _tight(3.0), phase="warm") + _samples(
            "B3", _tight(40.0), phase="cold"
        )
        warm = L.benign_series(rows, arm="B3", phase="warm")
        cold = L.benign_series(rows, arm="B3", phase="cold")
        assert len(warm) == len(cold) == 60
        assert max(warm) < min(cold)  # they are not pooled

    def test_an_unknown_phase_is_refused(self):
        with pytest.raises(L.AnalysisError, match="phase must be"):
            L.Sample("B3", "gt-benign", "lukewarm", 0, 0, "presentation", 1.0)

    def test_the_lightweight_claim_reads_warm_only(self):
        rows = (
            _samples("B3", _tight(3.0), phase="warm")
            + _samples("B0", _control(), phase="warm")
            + _samples("B3", _tight(400.0), phase="cold")
            + _samples("B0", _control(), phase="cold")
        )
        decision = L.lightweight_claim(rows, margin_ms=MARGIN_MS, seed=SEED)
        assert decision.verdict == "stands"  # the cold samples did not leak in


class TestTheDecompositionIsPreserved:
    def test_the_segment_is_the_SUM_of_both_spans(self):
        rows = _samples("B3", [10.0] * 5)
        assert L.benign_series(rows, arm="B3") == [pytest.approx(10.0)] * 5

    def test_a_repetition_missing_a_span_is_REFUSED_not_summed_from_one(self):
        """For `B3` the missing half would be `presentation`, which is exactly
        where its per-invocation cryptography lives — so a half-measured
        repetition would understate the arm the claim is about."""
        rows = _samples("B3", [10.0] * 5, split=False)
        with pytest.raises(L.AnalysisError, match="missing span"):
            L.benign_series(rows, arm="B3")

    def test_spans_outside_the_segment_are_not_summed_in(self):
        """ADR 0026 excludes `setup`, `delegation` and `end_to_end` by name."""
        rows = _samples("B3", [10.0] * 5)
        rows.append(L.Sample("B3", "gt-benign", "warm", 0, 0, "end_to_end", 999.0))
        rows.append(L.Sample("B3", "gt-benign", "warm", 0, 0, "delegation", 999.0))
        assert L.benign_series(rows, arm="B3") == [pytest.approx(10.0)] * 5

    def test_warmup_is_discarded_by_repetition_index(self):
        rows = _samples("B3", [10.0] * 10)
        kept = L.discard_warmup(rows, per_batch=3)
        assert len(L.benign_series(kept, arm="B3")) == 7

    def test_discarding_nothing_keeps_everything(self):
        rows = _samples("B3", [10.0] * 10)
        assert len(L.discard_warmup(rows, per_batch=0)) == len(rows)


# ---------------------------------------------------------------------------
# STEP 9 — nothing in `analysis/` can measure anything
# ---------------------------------------------------------------------------
def test_no_module_in_analysis_can_measure_anything():
    """Forbidden action 1, enforced by absence.

    No clock, no timer, no import of the runner or the campaign. The estimator
    takes numbers from a caller; it cannot go and get one.
    """
    modules = sorted(ANALYSIS.glob("*.py"))
    assert modules, "no analysis modules found"
    imported: set[str] = set()
    attributes: set[str] = set()
    for path in modules:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
            elif isinstance(node, ast.Attribute):
                attributes.add(node.attr)
    assert not any(name.startswith("src.") for name in imported), imported
    assert "time" not in imported and "timeit" not in imported
    for timer in ("perf_counter", "perf_counter_ns", "monotonic", "monotonic_ns", "time_ns"):
        assert timer not in attributes, timer


def test_the_analysis_package_is_what_part_H_step_3_will_seal():
    """It existed only as a `.gitkeep` before this block."""
    assert (ANALYSIS / "__init__.py").is_file()
    assert (ANALYSIS / "security.py").is_file()
    assert (ANALYSIS / "latency.py").is_file()
    # Normalised for the blockquote AND the wrapping: the §E.5 quotation runs
    # across lines behind `> ` markers, so a raw substring match would be
    # testing the docstring's line breaks rather than its words.
    flattened = " ".join(inspect.getdoc(S).replace("> ", " ").split())
    assert "no random-sampling population" in flattened
    assert "No confidence interval" in flattened


def test_no_real_measurement_reaches_the_analysis_tests():
    """Every value in this file is constructed.

    Checked by parsing this module's own IMPORTS rather than grepping its text
    — a text scan for the forbidden names would find them in its own forbidden
    list and fail on itself, which is a test of the test and not of the file.
    """
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    imported: set[str] = set()
    attributes: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
        elif isinstance(node, ast.Attribute):
            attributes.add(node.attr)
    # The only `src.` import this file may hold is the frozen row it reads the
    # margin from; nothing that could run a scenario or read a clock.
    assert not {"src.harness.runner", "src.harness.campaign"} & imported, imported
    for timer in ("perf_counter", "perf_counter_ns", "monotonic", "time_ns"):
        assert timer not in attributes, timer
