"""The RQ4 analysis layer, on **synthetic inputs only** (ADR 000X).

`analysis/latency.py` implemented the row 1 machinery and promised, in the
comment inside `_segment_values`, that `setup`, `delegation` and `end_to_end`
are *"reported separately"* — and nothing reported them. These tests cover the
three functions that now do: `span_descriptives` (RQ4's decomposition, per
span, cold and warm separate), `arm_pair_delta` (arm-pair deltas labelled by
what the §E.5 bit derivation can support), and `llm_turn_fraction`
(`frozen_parameters` row 7's secondary framing).

**Every refusal is a would-have-failed world, watched happening**, per the
project rule that a check never observed failing is not known to work:

* a refusal-path sample reaching a benign span series — refused, with
  `delegation` and `end_to_end` exercised by name (the failed AS round trip
  lands in `delegation`);
* a span absent from a repetition — refused rather than averaged over what is
  present, and a span absent from EVERY repetition likewise;
* a pair whose §E.5 rows do not differ — refused (no bit for the exchange);
* a pair involving `B1` — refused with the ADR 0035 reason;
* a mixed-phase pool — unbuildable: an out-of-vocabulary phase is refused and
  the two real phases are never pooled into one series;
* the four-bit `B-cap` → `B3` pair — a composite, never one mechanism's name.

The transcriptions are pinned: the §E.5 bitmask against the design document's
own table (an amendment to §E.5 re-triggers the pin), and the five RQ4 spans
against the runner's `timing.mark(...)` sites (read as source text, never
imported). The frozen scalars are pinned the other way round — the forbidden
integer literals are DERIVED from `src/harness/frozen_parameters.py`'s readers
rather than typed here, so no copy of a frozen value exists in this file
either. Each scanner has a negative arm proving it sees an offender.

Like `test_analysis.py`: every value is constructed, nothing is measured, and
the only `src.` imports are the frozen-row reader and the arm-name registry —
neither can produce a timing.
"""

import ast
import inspect
from pathlib import Path

import pytest

from analysis import latency as L

REPO_ROOT = Path(__file__).resolve().parents[1]
SEED = 20260805


# ---------------------------------------------------------------------------
# synthetic samples — constructed, never measured
# ---------------------------------------------------------------------------
def _values(offset: float = 0.0, n: int = 12) -> list[float]:
    """Tight and deterministic, no RNG: a fixture that varied per run could
    not pin an interval. Four distinct values so medians and IQRs are real."""
    return [10.0 + offset + (i % 4) * 0.2 for i in range(n)]


def _five(
    arm: str,
    segment_values: list[float],
    *,
    scenario_id: str = "gt-benign",
    phase: str = "warm",
    batch: int = 0,
    setup_ms: float = 50.0,
    delegation_ms: float = 7.0,
    tail_ms: float = 1.0,
) -> list[L.Sample]:
    """One `Sample` per RQ4 span per repetition, mutually distinguishable.

    The measured-segment halves split 40/60 exactly as `test_analysis.py`
    constructs them, so the segment sums back to `segment_values`. `setup` and
    `delegation` sit far from both halves, so pooling any two spans — or the
    two phases — would move a median detectably; `end_to_end` is the
    consistent total plus `tail_ms` standing in for the tool's own execution.
    """
    rows: list[L.Sample] = []
    for repetition, value in enumerate(segment_values):
        spans = {
            "setup": setup_ms,
            "delegation": delegation_ms,
            "presentation": value * 0.4,
            "boundary_verification": value * 0.6,
            "end_to_end": setup_ms + delegation_ms + value + tail_ms,
        }
        rows.extend(
            L.Sample(arm, scenario_id, phase, batch, repetition, span, ms)
            for span, ms in spans.items()
        )
    return rows


# ---------------------------------------------------------------------------
# scanners used by the pins, each with a negative arm below
# ---------------------------------------------------------------------------
def _mark_span_names(source: str) -> set[str]:
    """Every string literal passed first to a `.mark(...)` call in `source`."""
    names: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "mark"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            names.add(node.args[0].value)
    return names


def _parse_e5(section: str) -> tuple[tuple[str, ...] | None, dict[str, tuple[str, ...]]]:
    """The §E.5 markdown table as `(columns, {row label: cells})`.

    Bold/italic markers are stripped; nothing else is normalised, so the
    comparison against the transcription is cell-for-cell.
    """
    columns: tuple[str, ...] | None = None
    rows: dict[str, tuple[str, ...]] = {}
    for line in section.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        cells = [cell.strip().strip("*").strip() for cell in stripped.strip("|").split("|")]
        if columns is None:
            columns = tuple(cells[1:])
            continue
        if all(set(cell) <= set(":- ") for cell in cells):
            continue
        rows[cells[0]] = tuple(cells[1:])
    return columns, rows


def _e5_section() -> str:
    text = (REPO_ROOT / "docs" / "EXPERIMENT_ARCHITECTURE_FINAL.md").read_text(encoding="utf-8")
    start = text.index("## E.5 Module bitmask")
    return text[start : text.index("\n## ", start)]


def _numeric_literals(source: str) -> set[float]:
    return {
        node.value
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Constant)
        and isinstance(node.value, (int, float))
        and not isinstance(node.value, bool)
    }


# ---------------------------------------------------------------------------
# STEP 1 — per-span descriptives: RQ4's decomposition
# ---------------------------------------------------------------------------
class TestPerSpanDescriptives:
    def test_every_span_arm_and_phase_present_is_reported(self):
        """Cold's `setup` is 500 while warm's is 50: had the phases been
        pooled, both medians would sit between the two, so the exact values
        are the non-pooling evidence, not just the row count."""
        rows = (
            _five("B3", _values(2.0))
            + _five("B3", _values(40.0), phase="cold", setup_ms=500.0)
            + _five("B0", _values())
        )
        reports = L.span_descriptives(rows, warmup_per_batch=0)
        covered = {(r.arm, r.phase, r.span) for r in reports}
        assert covered == (
            {("B3", "warm", span) for span in L.RQ4_SPANS}
            | {("B3", "cold", span) for span in L.RQ4_SPANS}
            | {("B0", "warm", span) for span in L.RQ4_SPANS}
        )
        assert all(report.series == L.SERIES_BENIGN for report in reports)
        by = {(r.arm, r.phase, r.span): r.descriptives for r in reports}
        assert by[("B3", "warm", "setup")].median == pytest.approx(50.0)
        assert by[("B3", "cold", "setup")].median == pytest.approx(500.0)
        assert by[("B3", "warm", "delegation")].median == pytest.approx(7.0)
        assert by[("B3", "warm", "presentation")].median == pytest.approx(0.4 * 12.3)
        assert by[("B3", "warm", "boundary_verification")].median == pytest.approx(0.6 * 12.3)
        assert by[("B3", "warm", "end_to_end")].median == pytest.approx(50.0 + 7.0 + 12.3 + 1.0)
        assert by[("B0", "warm", "end_to_end")].median == pytest.approx(50.0 + 7.0 + 10.3 + 1.0)

    def test_warmup_is_discarded_through_the_existing_function(self):
        rows = _five("B3", [10.0] * 10)
        reports = L.span_descriptives(rows, warmup_per_batch=3)
        assert reports and all(report.descriptives.n == 7 for report in reports)

    def test_the_refusal_path_is_its_own_series_where_the_round_trip_lands(self):
        """On `gt-f1-chain-tamper` the exchange arms' failed AS round trip
        lands in `delegation` — so that span, and `end_to_end` above it, are
        where pooling would hide the most. Both series are reported, neither
        polluted by the other."""
        benign = _five("B2-exchange-task", _values())
        tamper = _five(
            "B2-exchange-task",
            _values(),
            scenario_id=L.REFUSAL_PATH_SCENARIO,
            delegation_ms=300.0,
        )
        reports = L.span_descriptives(benign + tamper, warmup_per_batch=0)
        by = {(r.span, r.series): r.descriptives for r in reports}
        assert by[("delegation", L.SERIES_REFUSAL_PATH)].median == pytest.approx(300.0)
        assert by[("delegation", L.SERIES_BENIGN)].median == pytest.approx(7.0)
        assert by[("end_to_end", L.SERIES_REFUSAL_PATH)].median == pytest.approx(
            50.0 + 300.0 + 10.3 + 1.0
        )
        assert by[("end_to_end", L.SERIES_BENIGN)].median == pytest.approx(50.0 + 7.0 + 10.3 + 1.0)

    def test_a_refusal_path_sample_reaching_a_benign_span_series_is_refused(self):
        rows = _five("B3", _values()) + _five("B3", _values(), scenario_id=L.REFUSAL_PATH_SCENARIO)
        for span in ("delegation", "end_to_end"):
            with pytest.raises(L.AnalysisError, match="refusal_span_series"):
                L.benign_span_series(rows, arm="B3", span=span)

    def test_an_empty_refusal_span_series_is_refused(self):
        with pytest.raises(L.AnalysisError, match="not a result"):
            L.refusal_span_series(_five("B3", _values()), arm="B3", span="delegation")

    def test_a_repetition_missing_a_span_is_refused_not_averaged(self):
        """Drop `end_to_end` from ONE repetition: the series that would
        silently shrink to the repetitions that have it is refused instead,
        and the whole report refuses with it. The spans every repetition does
        carry remain individually buildable."""
        rows = [
            s for s in _five("B3", [10.0] * 6) if not (s.repetition == 3 and s.span == "end_to_end")
        ]
        with pytest.raises(L.AnalysisError, match="carries no 'end_to_end'"):
            L.benign_span_series(rows, arm="B3", span="end_to_end")
        with pytest.raises(L.AnalysisError, match="carries no 'end_to_end'"):
            L.span_descriptives(rows, warmup_per_batch=0)
        assert len(L.benign_span_series(rows, arm="B3", span="setup")) == 6

    def test_a_span_missing_from_every_repetition_is_refused_not_skipped(self):
        """The world where a campaign result stops carrying a span the runner
        records: the report refuses rather than quietly covering four spans."""
        rows = [s for s in _five("B3", [10.0] * 6) if s.span != "end_to_end"]
        with pytest.raises(L.AnalysisError, match="carries no 'end_to_end'"):
            L.span_descriptives(rows, warmup_per_batch=0)

    def test_phases_are_never_pooled_and_a_mixed_phase_pool_is_unbuildable(self):
        """A mixed-phase pool cannot be requested: each series names one
        phase, a phase outside the vocabulary is refused, and a `Sample`
        cannot even be constructed with one (`test_analysis.py` pins that).
        The cold values sit far above warm, so a pooled series would
        interleave — `max(warm) < min(cold)` is the would-have-failed check."""
        rows = _five("B3", _values()) + _five("B3", _values(80.0), phase="cold")
        warm = L.benign_span_series(rows, arm="B3", span="presentation", phase="warm")
        cold = L.benign_span_series(rows, arm="B3", span="presentation", phase="cold")
        assert len(warm) == len(cold) == 12
        assert max(warm) < min(cold)
        with pytest.raises(L.AnalysisError, match="phase must be"):
            L.benign_span_series(rows, arm="B3", span="presentation", phase="lukewarm")
        with pytest.raises(L.AnalysisError, match="span must be"):
            L.benign_span_series(rows, arm="B3", span="tool_execution")


class TestTheSpanTranscriptionPin:
    def test_rq4_spans_are_exactly_the_runners_mark_sites(self):
        """`RQ4_SPANS` is a transcription — `analysis/` may not import the
        runner — so the runner's own `timing.mark("...")` call sites, read as
        source text, pin it. A seam added, removed or renamed there fails
        here and re-triggers the transcription."""
        source = (REPO_ROOT / "src" / "harness" / "runner.py").read_text(encoding="utf-8")
        assert _mark_span_names(source) == set(L.RQ4_SPANS)

    def test_the_span_scanner_sees_a_would_be_sixth_seam(self):
        assert _mark_span_names('timing.mark("tool_execution", a, b)') == {"tool_execution"}

    def test_the_measured_segment_stays_inside_the_five(self):
        assert set(L.MEASURED_SEGMENT_SPANS) < set(L.RQ4_SPANS)
        assert L.MEASURED_SEGMENT not in L.RQ4_SPANS


# ---------------------------------------------------------------------------
# STEP 2 — the §E.5 transcription, and what the derivation can support
# ---------------------------------------------------------------------------
class TestTheBitmaskTranscription:
    def test_the_bitmask_is_pinned_to_the_design_documents_table(self):
        columns, rows = _parse_e5(_e5_section())
        assert columns == L.E5_BITMASK_COLUMNS
        assert rows == L.E5_BITMASK

    def test_the_pin_sees_an_amendment(self):
        """Negative arm: flip one bit of `B1`'s row in the parsed text and
        the comparison fails — an amendment to §E.5 genuinely re-triggers."""
        doctored = _e5_section().replace("| B1 | 0 |", "| B1 | 1 |", 1)
        _, rows = _parse_e5(doctored)
        assert rows["B1"][0] == "1"
        assert rows != L.E5_BITMASK

    def test_no_bit_was_invented(self):
        """The two gaps are FINDINGS, present in the transcription exactly as
        §E.5 carries them, not repaired: no exchange column anywhere, the two
        broad arms' rows identical, and `B1`'s row `audit` alone (ADR 0035)."""
        assert len(L.E5_BITMASK_COLUMNS) == 10
        assert not any("exchange" in column for column in L.E5_BITMASK_COLUMNS)
        assert not any("secret" in column or "key" in column for column in L.E5_BITMASK_COLUMNS)
        assert L.E5_BITMASK["B2-broad-noexchange"] == L.E5_BITMASK["B2-exchange-broad"]
        b1 = dict(zip(L.E5_BITMASK_COLUMNS, L.E5_BITMASK["B1"], strict=True))
        assert b1["audit"] == "1"
        assert all(bit == "0" for column, bit in b1.items() if column != "audit")

    def test_the_arm_name_bridge_covers_exactly_the_nine_built_arms(self):
        from src.harness import matrix_grouping

        assert set(L.E5_ROW_FOR_ARM) == set(matrix_grouping.ARMS)
        assert set(L.E5_ROW_FOR_ARM.values()) <= set(L.E5_BITMASK)


class TestPairLabelling:
    def test_the_dpop_increment_is_a_clean_single_bit(self):
        difference = L.e5_bit_difference("B2-exchange-task-DPoP", "B2-exchange-task")
        assert difference.label == "mechanism-increment"
        assert difference.differing_bits == ("htc/holder",)
        assert difference.mechanism == "htc/holder"

    def test_the_jti_increment_is_a_clean_single_bit(self):
        difference = L.e5_bit_difference("B3+", "B3")  # code name bridges to §E.5's B3⁺
        assert difference.label == "mechanism-increment"
        assert difference.differing_bits == ("jti",)
        assert difference.mechanism == "jti"

    def test_the_four_bit_pair_is_a_composite_never_one_mechanisms_name(self):
        """The acceptance standard's named failing world: a confident
        per-mechanism number for `B-cap` → `B3` has failed the task however
        correct its arithmetic. Four bits differ; the label must say so and
        no single mechanism's name may ride on the result."""
        difference = L.e5_bit_difference("B3", "B-cap")
        assert difference.label == "composite-delta"
        assert set(difference.differing_bits) == {"htc/holder", "invoke", "context", "approval"}
        assert difference.mechanism is None

    def test_an_identical_row_pair_is_refused_because_the_exchange_has_no_bit(self):
        with pytest.raises(L.AnalysisError, match="no bit for the exchange"):
            L.e5_bit_difference("B2-exchange-broad", "B2-broad-noexchange")

    def test_a_b1_pair_is_refused_with_the_adr_0035_reason(self):
        for treatment, control in (("B1", "B0"), ("B2-broad-noexchange", "B1")):
            with pytest.raises(L.AnalysisError, match="ADR 0035"):
                L.e5_bit_difference(treatment, control)

    def test_an_arm_outside_the_transcription_is_refused(self):
        with pytest.raises(L.AnalysisError, match="§E.5"):
            L.e5_bit_difference("B9-imagined", "B0")

    def test_every_matched_ablation_is_a_single_bit_off_b3(self):
        """§E.6's matched leave-one-out property, confirmed mechanically from
        the transcription alone: each ablation row differs from `B3` in
        exactly the conjunct it disables."""
        expected = {
            "B3 −attenuation (unsafe control, §E.6)": "authorizer",
            "B3 −holder": "htc/holder",
            "B3 −invoke": "invoke",
            "B3 −contain": "contain",
            "B3 −context": "context",
            "B3 −approval": "approval",
        }
        for row, bit in expected.items():
            difference = L.e5_bit_difference("B3", row)
            assert (difference.label, difference.mechanism) == ("mechanism-increment", bit)


class TestArmPairDeltas:
    def test_a_delta_carries_point_interval_label_and_no_verdict(self):
        rows = _five("B3+", _values(2.0)) + _five("B3", _values())
        delta = L.arm_pair_delta(
            rows,
            treatment_arm="B3+",
            control_arm="B3",
            span="boundary_verification",
            seed=SEED,
        )
        assert (delta.label, delta.mechanism) == ("mechanism-increment", "jti")
        assert delta.point_estimate_ms == pytest.approx(0.6 * 2.0, abs=0.02)
        assert delta.ci.low <= delta.point_estimate_ms <= delta.ci.high
        assert not isinstance(delta, L.Decision)
        assert "verdict" not in vars(delta) and "margin_ms" not in vars(delta)
        payload = delta.as_dict()
        assert "verdict" not in payload and "margin_ms" not in payload

    def test_the_measured_segment_route_reuses_the_row_1_series_builder(self):
        """`MEASURED_SEGMENT` goes through `benign_series` itself, so the
        segment cannot be summed two ways — and the chain-tamper refusal the
        delta inherits there is the segment builder's own."""
        rows = _five("B3+", _values(2.0)) + _five("B3", _values())
        delta = L.arm_pair_delta(
            rows,
            treatment_arm="B3+",
            control_arm="B3",
            span=L.MEASURED_SEGMENT,
            seed=SEED,
        )
        assert delta.point_estimate_ms == pytest.approx(2.0, abs=0.02)
        tampered = rows + _five("B3", _values(), scenario_id=L.REFUSAL_PATH_SCENARIO)
        with pytest.raises(L.AnalysisError, match="refusal_series"):
            L.arm_pair_delta(
                tampered,
                treatment_arm="B3+",
                control_arm="B3",
                span=L.MEASURED_SEGMENT,
                seed=SEED,
            )

    def test_a_span_route_refuses_refusal_path_samples(self):
        rows = (
            _five("B3+", _values(2.0))
            + _five("B3", _values())
            + _five("B3", _values(), scenario_id=L.REFUSAL_PATH_SCENARIO)
        )
        with pytest.raises(L.AnalysisError, match="refusal_span_series"):
            L.arm_pair_delta(
                rows, treatment_arm="B3+", control_arm="B3", span="delegation", seed=SEED
            )

    def test_a_refused_pair_is_refused_before_any_arithmetic(self):
        """Empty samples: were the §E.5 refusal to run after series building,
        these would raise about empty series rather than about the pair."""
        with pytest.raises(L.AnalysisError, match="ADR 0035"):
            L.arm_pair_delta([], treatment_arm="B1", control_arm="B0", span="delegation", seed=SEED)
        with pytest.raises(L.AnalysisError, match="exchange"):
            L.arm_pair_delta(
                [],
                treatment_arm="B2-exchange-broad",
                control_arm="B2-broad-noexchange",
                span="delegation",
                seed=SEED,
            )

    def test_a_pair_whose_phases_do_not_overlap_cannot_pool(self):
        """Treatment measured warm, control only cold: the phases are never
        pooled to make the delta computable — the empty warm control series
        refuses instead."""
        rows = _five("B3+", _values(2.0), phase="warm") + _five("B3", _values(), phase="cold")
        with pytest.raises(L.AnalysisError, match="at least one value"):
            L.arm_pair_delta(
                rows, treatment_arm="B3+", control_arm="B3", span="delegation", seed=SEED
            )

    def test_no_margin_parameter_exists_anywhere_in_the_rq4_layer(self):
        """Forbidden action 4's signature half: nothing here can be handed a
        threshold, so nothing here can look like a second equivalence test."""
        for function in (
            L.arm_pair_delta,
            L.span_descriptives,
            L.llm_turn_fraction,
            L.e5_bit_difference,
        ):
            parameters = inspect.signature(function).parameters
            assert not any("margin" in name for name in parameters), function.__name__

    def test_the_only_decision_producers_are_row_1s(self):
        """Forbidden action 4's return-type half, asserted structurally: the
        RQ4 layer added no function returning a `Decision`."""
        tree = ast.parse((REPO_ROOT / "analysis" / "latency.py").read_text(encoding="utf-8"))
        producers = {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef)
            and isinstance(node.returns, ast.Name)
            and node.returns.id == "Decision"
        }
        assert producers == {"equivalence_decision", "lightweight_claim"}


# ---------------------------------------------------------------------------
# STEP 3 — frozen_parameters row 7's secondary framing
# ---------------------------------------------------------------------------
class TestRowSevenFraming:
    def test_the_fractions_come_from_the_frozen_row_not_from_literals(self):
        """Row 7 has one reader (`llm_turn_denominators`); the test feeds the
        framing from it, so the expected fractions are derived, never typed."""
        from src.harness import frozen_parameters

        t_full, t_ttft = frozen_parameters.llm_turn_denominators()
        fraction = L.llm_turn_fraction(
            L.describe([3.0, 3.0, 3.0]), t_full_ms=t_full, t_ttft_ms=t_ttft
        )
        assert fraction.median_ms == pytest.approx(3.0)
        assert (fraction.t_full_ms, fraction.t_ttft_ms) == (float(t_full), float(t_ttft))
        assert fraction.fraction_of_full_turn == pytest.approx(3.0 / t_full)
        assert fraction.fraction_of_ttft == pytest.approx(3.0 / t_ttft)

    def test_the_framing_returns_no_verdict_and_no_margin(self):
        from src.harness import frozen_parameters

        t_full, t_ttft = frozen_parameters.llm_turn_denominators()
        fraction = L.llm_turn_fraction(L.describe([3.0]), t_full_ms=t_full, t_ttft_ms=t_ttft)
        assert not isinstance(fraction, L.Decision)
        assert set(vars(fraction)) == {
            "median_ms",
            "t_full_ms",
            "t_ttft_ms",
            "fraction_of_full_turn",
            "fraction_of_ttft",
        }
        assert "verdict" not in fraction.as_dict() and "margin_ms" not in fraction.as_dict()

    def test_non_positive_denominators_are_refused(self):
        for t_full, t_ttft in ((0.0, 1.0), (1.0, -3.0)):
            with pytest.raises(L.AnalysisError, match="positive"):
                L.llm_turn_fraction(L.describe([3.0]), t_full_ms=t_full, t_ttft_ms=t_ttft)

    def test_no_frozen_scalar_literal_appears_in_the_module_or_in_this_file(self):
        """Forbidden action 5, with the forbidden set DERIVED from the single
        reader rather than typed: a hardcoded margin or denominator in the
        module — or in this file — fails here."""
        from src.harness import frozen_parameters

        forbidden = {
            frozen_parameters.equivalence_margin_ms(),
            *frozen_parameters.llm_turn_denominators(),
        }
        for path in (REPO_ROOT / "analysis" / "latency.py", Path(__file__)):
            literals = _numeric_literals(path.read_text(encoding="utf-8"))
            assert forbidden.isdisjoint(literals), (path.name, sorted(forbidden & literals))

    def test_the_literal_scanner_sees_a_planted_frozen_value(self):
        from src.harness import frozen_parameters

        t_full, _ = frozen_parameters.llm_turn_denominators()
        assert t_full in _numeric_literals(f"x = {t_full}")
