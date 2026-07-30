"""The Phase A checkpoint: the golden thread under B0 (EXP1 STEP 9).

Expected, and expected BECAUSE IT IS THE VULNERABILITY BEING MEASURED, not
because the code is wrong: B0 admits `gt-f1-root` and `gt-f1-terminal`, and
the effect ledger INDEPENDENTLY records an effect whose authority lies
outside `C_1` -- and, for `gt-f1-root`, outside `U_task` itself. Every
conclusion about an EFFECT is read off the LEDGER, never off an agent's
self-report (red line 4; the G-7 discipline).

**The platform split (EXP2 STEP 5).** The assertions are separated by what
they actually concern. Admission, dispatch, the shape of the presented
evidence and the sealed-truth relations are not effect claims and do not
touch the ledger, so they run on **every** platform -- previously this whole
file skipped on Linux, which meant an all-green CI run said nothing about
whether the golden thread still ran at all. Only the assertions that read
the ledger stay behind the ADR 0014 Windows gate. No ledger fallback, stub or
no-op writer was introduced: the cross-platform runs are explicitly NOT
ledger-backed, and asking one for effect evidence raises rather than
returning an empty list.
"""

import shutil
import sys
from pathlib import Path

import pytest

from src.harness.runner import GoldenThreadRunner, RunnerError
from src.sut.baselines.b0 import B0Arm

REPO_ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ("gt-benign", "gt-f1-root", "gt-f1-terminal")

WIN32_ONLY = pytest.mark.skipif(
    sys.platform != "win32",
    reason="ADR 0014 (recorded platform decision, not a gap): the ledger's independence "
    "enforcement is Win32 share-mode locking (CreateFileW, FILE_SHARE_READ only), which has "
    "no direct POSIX equivalent; Windows is the sealed measurement platform and the POSIX "
    "variant is deferred to after submission",
)


def _ledger_authority(run) -> frozenset[tuple[str, str]]:
    """The authority actually exercised, from the LEDGER alone (SS A.5's `A`)."""
    return frozenset((e["action"], e["resource"]) for e in run.effects())


# --------------------------------------------------------------------------
# Cross-platform: everything that is not an effect claim
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def unledgered_runs():
    """All three scenarios under B0, run WITHOUT the effect ledger.

    Not a POSIX ledger and not a substitute for one: these runs record no
    effects at all, and `effects()` raises on them.
    """
    runner = GoldenThreadRunner()
    return {
        scenario_id: runner.run_scenario(scenario_id, B0Arm(), ledger_backed=False)
        for scenario_id in SCENARIOS
    }


class TestGoldenThreadRunsEverywhere:
    def test_the_boundary_admitted_every_scenario(self, unledgered_runs):
        for scenario_id, run in unledgered_runs.items():
            assert len(run.mediation_events) == 1, scenario_id
            event = run.mediation_events[0]
            assert event.admitted is True, scenario_id
            assert event.reason_code == "b0_no_boundary_check", scenario_id
            assert event.correlation_id == run.correlation_id, scenario_id

    def test_the_tool_dispatched_and_returned(self, unledgered_runs):
        for scenario_id, run in unledgered_runs.items():
            assert run.tool_result_error is False, scenario_id
            # The observed tool is the one the scenario scripted.
            assert run.observed.tool == run.intent.tool, scenario_id

    def test_b0_presents_no_evidence_at_all(self, unledgered_runs):
        for run in unledgered_runs.values():
            assert run.presentation == {}
            assert run.observed.evidence.capability is None
            assert run.observed.evidence.oauth is None
            assert run.observed.evidence.api_key is None

    def test_the_sealed_set_relations_hold(self, unledgered_runs):
        benign = unledgered_runs["gt-benign"]
        assert benign.intent.R <= benign.intent.C_sets[-1]
        root = unledgered_runs["gt-f1-root"]
        assert not root.intent.R <= root.intent.U_task
        terminal = unledgered_runs["gt-f1-terminal"]
        assert terminal.intent.R <= terminal.intent.U_task
        assert not terminal.intent.R <= terminal.intent.C_sets[-1]

    def test_correlation_is_harness_minted_and_fresh(self, unledgered_runs):
        ids = {run.correlation_id for run in unledgered_runs.values()}
        assert len(ids) == len(unledgered_runs)
        assert all(len(cid) == 32 for cid in ids)

    def test_an_unledgered_run_refuses_to_supply_effect_evidence(self, unledgered_runs):
        """The anti-vacuity guard: absence of a ledger is not absence of effect."""
        for run in unledgered_runs.values():
            assert run.ledger_path is None
            with pytest.raises(RunnerError):
                run.effects()
            with pytest.raises(RunnerError):
                run.ledger_entries()


# --------------------------------------------------------------------------
# Windows-only: the effect claims, which need the real ledger
# --------------------------------------------------------------------------


@WIN32_ONLY
class TestTheAmplifiedEffectIsOnTheLedger:
    @pytest.fixture(scope="class")
    @staticmethod
    def runs():
        ledger_dir = REPO_ROOT / "tests" / "_ledger_tmp_gt_b0"
        ledger_dir.mkdir(parents=True, exist_ok=True)
        runner = GoldenThreadRunner(ledger_dir=ledger_dir)
        result = {
            scenario_id: runner.run_scenario(scenario_id, B0Arm()) for scenario_id in SCENARIOS
        }
        yield result
        shutil.rmtree(ledger_dir, ignore_errors=True)

    def test_benign_effect_is_within_C1(self, runs):
        # The false-blocking control's dual: the benign call is inside the
        # narrowed authority, so B0's admission of IT is not evidence of the
        # vulnerability -- the F1 admissions below are.
        run = runs["gt-benign"]
        exercised = _ledger_authority(run)
        assert exercised == frozenset({("notes.write", "notes/project")})
        assert exercised <= run.intent.C_sets[-1]

    def test_f1_root_effect_outside_U_task(self, runs):
        run = runs["gt-f1-root"]
        exercised = _ledger_authority(run)
        assert exercised == frozenset({("mail.send", "mail/outbox")})
        # Outside the narrowed authority AND outside the root grant itself:
        assert not exercised <= run.intent.C_sets[-1]
        assert not exercised <= run.intent.U_task
        # ... and the ledger, not the agent, is the witness:
        assert len(run.effects()) == 1
        assert run.effects()[0]["correlation_id"] == run.correlation_id

    def test_f1_terminal_effect_outside_C1_inside_U_task(self, runs):
        run = runs["gt-f1-terminal"]
        exercised = _ledger_authority(run)
        assert exercised == frozenset({("calendar.read", "calendar/work")})
        assert not exercised <= run.intent.C_sets[-1]  # outside the narrowed C_1
        assert exercised <= run.intent.U_task  # inside the root grant (SS E.3)
