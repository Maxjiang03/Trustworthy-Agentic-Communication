"""The Phase A checkpoint: the golden thread under B0 (EXP1 STEP 9).

Expected, and expected BECAUSE IT IS THE VULNERABILITY BEING MEASURED, not
because the code is wrong: B0 admits `gt-f1-root` and `gt-f1-terminal`, and
the effect ledger INDEPENDENTLY records an effect whose authority lies
outside `C_1` -- and, for `gt-f1-root`, outside `U_task` itself. Every
conclusion here is read off the LEDGER and the sealed truth, never off an
agent's self-report (red line 4; the G-7 discipline).

Windows-only (ADR 0014): the run needs the exclusive-share effect ledger.
"""

import shutil
import sys
from pathlib import Path

import pytest

from src.harness.runner import GoldenThreadRunner
from src.sut.baselines.b0 import B0Arm

REPO_ROOT = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="ADR 0014 (recorded platform decision, not a gap): the ledger's independence "
    "enforcement is Win32 share-mode locking (CreateFileW, FILE_SHARE_READ only), which has "
    "no direct POSIX equivalent; Windows is the sealed measurement platform and the POSIX "
    "variant is deferred to after submission",
)


@pytest.fixture(scope="module")
def runs():
    """All three scenarios under B0, run once for the module."""
    ledger_dir = REPO_ROOT / "tests" / "_ledger_tmp_gt_b0"
    ledger_dir.mkdir(parents=True, exist_ok=True)
    runner = GoldenThreadRunner(ledger_dir=ledger_dir)
    result = {
        scenario_id: runner.run_scenario(scenario_id, B0Arm())
        for scenario_id in ("gt-benign", "gt-f1-root", "gt-f1-terminal")
    }
    yield result
    shutil.rmtree(ledger_dir, ignore_errors=True)


def _ledger_authority(run) -> frozenset[tuple[str, str]]:
    """The authority actually exercised, from the LEDGER alone (SS A.5's `A`)."""
    return frozenset((e["action"], e["resource"]) for e in run.effects())


class TestB0AdmitsEverything:
    def test_all_three_scenarios_admitted(self, runs):
        for scenario_id, run in runs.items():
            assert run.mediation_events[-1].admitted is True, scenario_id
            assert run.tool_result_error is False, scenario_id

    def test_benign_effect_is_within_C1(self, runs):
        # The false-blocking control's dual: the benign call is inside the
        # narrowed authority, so B0's admission of IT is not evidence of the
        # vulnerability -- the F1 admissions below are.
        run = runs["gt-benign"]
        exercised = _ledger_authority(run)
        assert exercised == frozenset({("notes.write", "notes/project")})
        assert exercised <= run.intent.C_sets[-1]


class TestTheAmplifiedEffectIsOnTheLedger:
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

    def test_the_conclusion_never_reads_a_self_report(self, runs):
        # Structural arm: the ScenarioRun fields consulted above are the sealed
        # intent and the ledger file; B0 has no self-report channel at all, and
        # the presented evidence bundle is empty.
        for run in runs.values():
            assert run.presentation == {}
            assert run.observed.evidence.capability is None
            assert run.observed.evidence.oauth is None
            assert run.observed.evidence.api_key is None
