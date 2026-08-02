"""The scalar frozen-parameter rows: 1, 2, 3 and 7 set; 5 deferred; 9 unset.

Every test has a positive arm and a negative arm so no assertion can pass
vacuously. Under test: the values ADR 0025/0026/0027 fixed, the fail-closed
behaviour on a row that has no value, the **distinction** between a row nobody
has decided yet and one decided not to exist (ADR 0028), and the agreement
between the frozen document and the SUT-side constant that cannot import it.

**No number here is measured.** These rows fix bars and denominators *before*
any timing measurement, as Part H step 2 requires; asserting a bar exists is
not measuring anything against it. `IA-3` stays `[UNVERIFIED-IA]`.

Platform-independent.
"""

import re
from pathlib import Path

import pytest

from src.harness import frozen_parameters as fp
from src.sut import dpop, freshness

REPO_ROOT = Path(__file__).resolve().parents[1]
DOCUMENT = REPO_ROOT / "docs" / "frozen_parameters.md"


class TestTheValuesAreTheAdrValues:
    """The four ADRs' values, landed exactly. Not adapted to the code."""

    def test_row_1_equivalence_margin(self):
        assert fp.equivalence_margin_ms() == 20  # ADR 0026

    def test_row_2_g3_threshold(self):
        assert fp.g3_threshold_ms() == 5  # ADR 0025

    def test_row_3_delta_and_capacity(self):
        assert fp.delta_seconds() == 60  # ADR 0027
        assert fp.replay_cache_capacity() == 65536  # 2^16

    def test_row_7_denominators(self):
        assert fp.llm_turn_denominators() == (2000, 250)  # ADR 0025

    def test_rows_1_and_2_are_deliberately_different(self):
        """ADR 0026 records the asymmetry rather than reconciling it.

        A gate threshold wants headroom; an equivalence margin encodes what the
        field already tolerates. They answer different questions and are not
        required to agree -- so a future edit that "tidied" them into one value
        would be discarding a decision, and this test says so.
        """
        assert fp.g3_threshold_ms() != fp.equivalence_margin_ms()
        assert fp.g3_threshold_ms() < fp.equivalence_margin_ms()

    def test_the_anchors_hold_arithmetically(self):
        """The justifications are checkable, not decorative.

        ADR 0025: 5 ms is 2% of `T_ttft` and 0.25% of `T_full`.
        ADR 0026: 20 ms is 1% of `T_full`.
        """
        t_full, t_ttft = fp.llm_turn_denominators()
        assert fp.g3_threshold_ms() / t_ttft == pytest.approx(0.02)
        assert fp.g3_threshold_ms() / t_full == pytest.approx(0.0025)
        assert fp.equivalence_margin_ms() / t_full == pytest.approx(0.01)


class TestUnsetRowsFailClosed:
    def test_row_9_is_SET_and_was_read_from_the_machine(self):
        """*Update, 2026-08-02: this asserted row 9 RAISED `RowUnset`, which was
        correct until the platform was locked (EXP8B STEP 3).*

        It is the only frozen row that is **read rather than chosen**, so what
        is asserted now is that it resolves and that it carries the identity the
        machine reported — not a transcription. ADR 0025: any change to it
        invalidates a G-3 adjudication on the previous platform.
        """
        platform = fp.sealed_measurement_platform()
        assert platform  # resolves rather than raising
        for machine_read in ("26200.8875", "i7-12700H", "12P/8E"):
            assert machine_read in platform, machine_read

    def test_row_5_is_deferred_by_decision_not_merely_unset(self):
        """The distinction is the whole point of ADR 0028's annotation.

        `RowDeferred` is a distinct type so a caller can tell "nobody has
        decided this yet" from "this was decided not to exist". Collapsing them
        would invite someone to fill row 5 later to make an error go away.
        """
        with pytest.raises(fp.RowDeferred) as raised:
            fp.task_authorization_policy()
        assert "ADR 0028" in str(raised.value)
        assert isinstance(raised.value, fp.FrozenParametersError)
        # Negative arm: the two absences are NOT the same class.
        assert not issubclass(fp.RowDeferred, fp.RowUnset)
        assert not issubclass(fp.RowUnset, fp.RowDeferred)

    def test_a_missing_token_raises_rather_than_defaulting(self, tmp_path):
        stripped = tmp_path / "no-row.md"
        stripped.write_text(
            DOCUMENT.read_text(encoding="utf-8").replace("delta_seconds = 60", "delta_seconds = ?"),
            encoding="utf-8",
        )
        with pytest.raises(fp.RowUnset):
            fp.delta_seconds(stripped)
        # Positive arm: the unmodified document still reads.
        assert fp.delta_seconds(DOCUMENT) == 60

    def test_a_conflicting_duplicate_raises(self, tmp_path):
        """A document that contradicts itself must stop everything on top of it."""
        contradictory = tmp_path / "conflict.md"
        text = DOCUMENT.read_text(encoding="utf-8")
        contradictory.write_text(text + "\n\nequivalence_margin_ms = 999\n", encoding="utf-8")
        with pytest.raises(fp.FrozenParametersError) as raised:
            fp.equivalence_margin_ms(contradictory)
        assert "conflicting" in str(raised.value)
        # Negative arm: a REPEATED but identical value is fine, because the
        # document legitimately restates a value in a justification line.
        repeated = tmp_path / "repeat.md"
        repeated.write_text(text + "\n\nequivalence_margin_ms = 20\n", encoding="utf-8")
        assert fp.equivalence_margin_ms(repeated) == 20


class TestOneWindowThreeConsumers:
    """ADR 0027's central claim, made structural rather than conventional."""

    def test_the_sut_side_constant_agrees_with_the_frozen_row(self):
        """Agreement, not shared code: `src/sut/` may not import the harness.

        The same pattern ADR 0016 drew for `Omega`/`Gamma` and ADR 0015 rule 4
        draws for the AS's derivations. An amendment to row 3 that forgot the
        SUT-side constant fails here rather than leaving the code and the
        frozen record quietly disagreeing.
        """
        assert freshness.DELTA_SECONDS == fp.delta_seconds()
        assert freshness.REPLAY_CACHE_CAPACITY == fp.replay_cache_capacity()

    def test_the_dpop_window_is_that_same_delta(self):
        """Consumer 2 of 3. It was 300 s before ADR 0027 fixed the window."""
        assert dpop.IAT_WINDOW_SECONDS == freshness.DELTA_SECONDS == 60

    def test_the_freshness_rule_is_symmetric(self):
        """A timestamp from the future is as much a failure as a stale one.

        RFC 7519's leeway allowance covers skew, which has no preferred
        direction, so a one-sided rule would accept an arbitrarily
        future-dated assertion.
        """
        assert freshness.is_fresh(1_000, 1_000)
        assert freshness.is_fresh(1_000, 1_000 - 60)
        assert freshness.is_fresh(1_000, 1_000 + 60)
        assert not freshness.is_fresh(1_000, 1_000 - 61)
        assert not freshness.is_fresh(1_000, 1_000 + 61)

    def test_the_third_consumer_is_the_sut_boundary_not_the_harness_verifier(self):
        """The asymmetry is DECLARED, so it is pinned rather than left implicit.

        `invocation_binding_ok` applies `|now - iat| <= Delta`; the harness
        verifier deliberately does **not**. That verifier implements SS F.2's
        **validity** MUST list -- `every nbf <= now <= exp` and no freshness
        rule -- which is what gate G-11 adjudicated, and boundary acceptance
        policy is a different question. Adding freshness there would change
        what G-11 verified, so this test protects the adjudicated scope in
        both directions: it fails if the SUT loses the check, and it fails if
        the verifier gains one.
        """
        sut = (REPO_ROOT / "src" / "sut" / "authz" / "capability_path.py").read_text(
            encoding="utf-8"
        )
        verifier = (REPO_ROOT / "src" / "harness" / "verifier" / "holder_binding.py").read_text(
            encoding="utf-8"
        )
        assert "freshness.is_fresh" in sut
        assert "is_fresh" not in verifier and "DELTA_SECONDS" not in verifier
        # And the consequence, which the agreement suite records: D21 agreement
        # therefore covers a strictly smaller set of conditions than the SUT
        # implements.
        agreement = (REPO_ROOT / "tests" / "test_sut_signer_agreement.py").read_text(
            encoding="utf-8"
        )
        assert "strictly smaller set of conditions" in agreement

    def test_no_consumer_reads_a_wall_clock(self):
        """ADR 0027's injectable-clock condition, asserted on the source.

        `is_fresh` takes `now`; nothing in the module calls `time.time()`. That
        is what makes an over-window fixture able to advance an instant instead
        of sleeping.
        """
        source = (REPO_ROOT / "src" / "sut" / "freshness.py").read_text(encoding="utf-8")
        assert "time.time" not in source and "import time" not in source
        # Negative arm: the scan can see a wall-clock call where one exists.
        assert "time.time" in (REPO_ROOT / "src" / "sut" / "dpop.py").read_text(encoding="utf-8")


class TestTheAdrsLanded:
    @pytest.mark.parametrize(
        "stem,rows",
        [
            ("0025-llm-turn-denominators-and-the-g3-latency-threshold", "rows 7 and 2"),
            ("0026-the-equivalence-margin-and-the-measured-segment", "row 1"),
            ("0027-the-freshness-window-and-the-replay-cache-budget", "row 3"),
            ("0028-f2-wrong-principal-deferred-row-5-not-frozen", "row 5"),
        ],
    )
    def test_each_adr_is_accepted_and_names_its_rows(self, stem, rows):
        text = (REPO_ROOT / "adr" / f"{stem}.md").read_text(encoding="utf-8")
        status = re.search(r"## Status\n\n(.+)", text)
        assert status is not None
        assert status.group(1).startswith("accepted — 2026-07-31")
        assert rows in status.group(1)

    def test_the_document_header_counts_what_is_set(self):
        header = DOCUMENT.read_text(encoding="utf-8").splitlines()[0]
        assert "10 of 11 set" in header
        assert "1 deferred by decision" in header

    def test_NO_row_is_still_open(self):
        """*Update, 2026-08-02: this asserted exactly one open row -- row 9 --
        which was correct until it was locked.* Ten of eleven are now set and
        row 5 is deferred by decision (ADR 0028), so nothing is merely
        awaiting a value."""
        text = DOCUMENT.read_text(encoding="utf-8")
        open_rows = [line for line in text.splitlines() if "⟨UNSET" in line]
        assert open_rows == []
