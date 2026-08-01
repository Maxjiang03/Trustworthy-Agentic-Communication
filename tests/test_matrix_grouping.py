"""Per-family grouping, and the rule that an F4/F5 cell is not a result without
its configuration (EXP4 STEP 12; the predicate gate G-15 will adjudicate).

Two families, two kinds of grouping, and conflating them is the error §E.4's
`A†` footnote exists to prevent. This suite pins that the conflation is
**caught by a predicate** rather than by a reviewer noticing.
"""

import pytest

from src.harness import matrix_grouping as grouping
from src.harness.matrix_grouping import Cell, MatrixError, comparison_is_sound, label


def f1(arm, admitted=True):
    return Cell(family="F1", subcase="F1-root", arm=arm, admitted=admitted, reason_code="r")


def f4(arm, *, admitted, monitor_attached):
    return Cell(
        family="F4",
        subcase="gt-f4-sensitive-egress",
        arm=arm,
        admitted=admitted,
        reason_code="r",
        monitor_attached=monitor_attached,
    )


class TestAConfigurationCellCannotHideItsConfiguration:
    @pytest.mark.parametrize("family", sorted(grouping.CONFIGURATION_FAMILIES))
    def test_recording_one_without_it_raises(self, family):
        with pytest.raises(MatrixError, match="without its monitor configuration"):
            Cell(family=family, subcase="x", arm="B3", admitted=True, reason_code="r")

    @pytest.mark.parametrize("family", sorted(grouping.CONFIGURATION_FAMILIES))
    def test_and_recording_one_WITH_it_is_fine(self, family):
        cell = Cell(
            family=family,
            subcase="x",
            arm="B3",
            admitted=True,
            reason_code="r",
            monitor_attached=False,
        )
        assert cell.monitor_attached is False

    @pytest.mark.parametrize("family", sorted(grouping.LADDER_FAMILIES))
    def test_a_ladder_cell_may_NOT_carry_one(self, family):
        """The opposite error, and it matters too: a configuration on an F1
        cell would suggest the cell could move with configuration. It cannot --
        F1 is decided by where the arm sits on the ladder."""
        with pytest.raises(MatrixError, match="LADDER property"):
            Cell(
                family=family,
                subcase="x",
                arm="B3",
                admitted=True,
                reason_code="r",
                monitor_attached=True,
            )

    def test_a_family_with_no_declared_grouping_is_refused(self):
        """A new family must CHOOSE, rather than defaulting into whichever
        branch happens to be first."""
        with pytest.raises(MatrixError, match="declares no grouping"):
            Cell(family="F9", subcase="x", arm="B3", admitted=True, reason_code="r")

    def test_an_unknown_arm_is_refused(self):
        with pytest.raises(MatrixError, match="not an"):
            f1("B4")


class TestAComparisonMayNotMixConfigurations:
    def test_the_same_configuration_compares(self):
        ok, reason = comparison_is_sound(
            [
                f4("B3", admitted=False, monitor_attached=True),
                f4("B2-exchange-task", admitted=False, monitor_attached=True),
            ]
        )
        assert ok and reason == ""

    def test_MIXING_them_is_refused(self):
        """The G-15 failure world, and the reason the predicate exists: "B3
        blocks and the OAuth arm does not" is a statement about MONITORS when
        one arm had one and the other did not."""
        ok, reason = comparison_is_sound(
            [
                f4("B3", admitted=False, monitor_attached=True),
                f4("B2-exchange-task", admitted=True, monitor_attached=False),
            ]
        )
        assert ok is False
        assert "mixes monitor configurations" in reason
        assert "not a capability-vs-OAuth advantage" in reason
        # The message names WHICH arms sat on which side, so the finding is
        # actionable rather than merely a refusal.
        assert "B3" in reason and "B2-exchange-task" in reason

    def test_a_ladder_family_comparison_needs_no_configuration(self):
        ok, reason = comparison_is_sound([f1("B3"), f1("B0")])
        assert ok and reason == ""

    def test_mixing_a_ladder_family_with_a_configuration_family_is_refused(self):
        ok, reason = comparison_is_sound(
            [f1("B3"), f4("B2-exchange-task", admitted=True, monitor_attached=False)]
        )
        assert ok is False
        assert "grouped by different things" in reason

    def test_an_empty_comparison_supports_nothing(self):
        ok, reason = comparison_is_sound([])
        assert ok is False and "supports nothing" in reason

    def test_it_accepts_a_mapping_too(self):
        ok, _ = comparison_is_sound(
            {
                "B3": f4("B3", admitted=False, monitor_attached=True),
                "B2-exchange-task": f4("B2-exchange-task", admitted=False, monitor_attached=True),
            }
        )
        assert ok


class TestTheDaggerSurvivesRendering:
    def test_an_admitted_unmonitored_configuration_cell_renders_with_the_dagger(self):
        cell = f4("B2-exchange-task", admitted=True, monitor_attached=False)
        assert label(cell) == "A† (monitor_attached=false)"

    def test_a_blocked_cell_carries_no_dagger_but_still_carries_the_configuration(self):
        cell = f4("B2-exchange-task", admitted=False, monitor_attached=True)
        assert label(cell) == "B (monitor_attached=true)"

    def test_an_admitted_MONITORED_cell_is_not_a_dagger(self):
        """`A†` means *admitted absent the monitor*. An arm admitting WITH one
        attached is a different claim and must not borrow the annotation."""
        cell = f4("B-cap", admitted=True, monitor_attached=True)
        assert label(cell) == "A (monitor_attached=true)"

    def test_a_ladder_cell_renders_bare(self):
        assert label(f1("B3")) == "A"

    def test_no_configuration_cell_can_render_as_a_bare_letter(self):
        for admitted in (True, False):
            for attached in (True, False):
                rendered = label(f4("B3", admitted=admitted, monitor_attached=attached))
                assert "monitor_attached=" in rendered
                assert rendered not in ("A", "B")


class TestThePolicyPlaneSetIsHonest:
    def test_it_is_exactly_the_arms_whose_bitmask_selects_both_conjuncts(self):
        """`POLICY_PLANE` is what makes "attaching a monitor is a no-op here"
        checkable rather than asserted. Derived from the bitmasks, not from a
        list someone kept in step."""
        from src.sut.baselines.b0 import B0Arm
        from src.sut.baselines.b1 import B1Arm
        from src.sut.baselines.b2_broad import B2BroadNoExchangeArm, B2ExchangeBroadArm
        from src.sut.baselines.b2_dpop import B2ExchangeTaskDPoPArm
        from src.sut.baselines.b2_exchange_task import B2ExchangeTaskArm
        from src.sut.baselines.b3 import B3Arm
        from src.sut.baselines.b3_plus import B3PlusArm
        from src.sut.baselines.b_cap import BCapArm

        classes = {
            "B0": B0Arm,
            "B1": B1Arm,
            "B2-broad-noexchange": B2BroadNoExchangeArm,
            "B2-exchange-broad": B2ExchangeBroadArm,
            "B2-exchange-task": B2ExchangeTaskArm,
            "B2-exchange-task-DPoP": B2ExchangeTaskDPoPArm,
            "B-cap": BCapArm,
            "B3": B3Arm,
            "B3+": B3PlusArm,
        }
        assert set(classes) == set(grouping.ARMS)
        derived = {
            name
            for name, cls in classes.items()
            if cls.bitmask.context == 1 and cls.bitmask.approval == 1
        }
        assert derived == set(grouping.POLICY_PLANE)

    def test_b_cap_is_deliberately_outside_it(self):
        """The finding `tests/test_f45_matrix.py` records: `B-cap` is a
        capability arm carrying `A†`, but it has no policy plane, so attaching
        the shared monitor to it moves nothing."""
        assert "B-cap" not in grouping.POLICY_PLANE
        assert "B-cap" in grouping.STRONG  # ...while still being an F1-strong arm
