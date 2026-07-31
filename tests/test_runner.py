"""Regression suite for the harness runner (EXP1 STEP 8).

Every test has a positive arm and a negative arm so no assertion can pass
vacuously. The ledger-backed scenario runs are Windows-only (ADR 0014); the
freeze verification and correlation-minting tests are platform-independent.
"""

import shutil
import sys
from pathlib import Path

import pytest

from src.harness import frozen_parameters, runner
from src.harness.authorizer import frozen_config

REPO_ROOT = Path(__file__).resolve().parents[1]

WIN32_ONLY = pytest.mark.skipif(
    sys.platform != "win32",
    reason="ADR 0014 (recorded platform decision, not a gap): the ledger's independence "
    "enforcement is Win32 share-mode locking (CreateFileW, FILE_SHARE_READ only), which has "
    "no direct POSIX equivalent; Windows is the sealed measurement platform and the POSIX "
    "variant is deferred to after submission",
)


class TestCorrelationId:
    def test_128_bit_hex(self):
        cid = runner.mint_correlation_id()
        assert len(cid) == 32
        assert int(cid, 16) >= 0  # hex-decodable

    def test_fresh_per_invocation(self):
        minted = {runner.mint_correlation_id() for _ in range(64)}
        assert len(minted) == 64


class TestFrozenConfigurationVerification:
    def test_current_artifacts_verify(self):
        runner.verify_frozen_configuration()  # must not raise

    def test_mismatch_fails_closed(self, monkeypatch):
        # Negative arm: a drifted recorded value must refuse start-up.
        monkeypatch.setattr(frozen_parameters, "expected_h_gamma", lambda: "00" * 32)
        with pytest.raises(runner.FrozenConfigurationMismatch):
            runner.verify_frozen_configuration()

    def test_registry_mismatch_fails_closed(self, monkeypatch):
        monkeypatch.setattr(frozen_parameters, "expected_h_registry", lambda: "11" * 32)
        with pytest.raises(runner.FrozenConfigurationMismatch):
            runner.verify_frozen_configuration()

    def test_artifact_drift_fails_closed(self, monkeypatch):
        # The dual arm: recorded value intact, artifact mutated.
        real_load = frozen_config.load_document

        def mutated():
            doc = real_load()
            doc["omega"]["elements"].append(["mail.send", "mail/outbox2"])
            return doc

        monkeypatch.setattr(frozen_config, "load_document", mutated)
        with pytest.raises(Exception):  # structure or hash check, either fails closed
            runner.verify_frozen_configuration()


class TestScenarioRunEverywhere:
    """The record kinds that do not touch the ledger (EXP2 STEP 5).

    Previously these shared a fixture with the effect assertions and so were
    invisible to Linux CI. They are not effect claims, so they run on every
    platform against a run that is explicitly NOT ledger-backed.
    """

    def test_records_and_correlation_without_the_ledger(self):
        from src.sut.baselines.b0 import B0Arm

        gt_runner = runner.GoldenThreadRunner()
        run = gt_runner.run_scenario("gt-benign", B0Arm(), ledger_backed=False)
        assert len(run.mediation_events) == 1
        assert run.mediation_events[0].admitted is True
        assert run.mediation_events[0].correlation_id == run.correlation_id
        assert run.observed.correlation_id == run.correlation_id
        assert run.observed.tool == "notes.write"
        assert run.intent.correlation_id == run.correlation_id
        assert run.intent.P_hashes == []  # B0 carries no capability
        assert run.tool_result_error is False
        assert set(run.timing.recorded()) == {
            "setup",
            "delegation",
            "presentation",  # ADR 0026's new seam: `arm.present(...)` alone
            "boundary_verification",
            "end_to_end",
        }

    def test_an_arm_that_raises_is_a_denial_without_the_ledger(self):
        from src.sut.baselines.b0 import B0Arm

        class RaisingArm(B0Arm):
            name = "B0-raising"

            def decide(self, tool, arguments):
                raise RuntimeError("boundary blew up")

        gt_runner = runner.GoldenThreadRunner()
        run = gt_runner.run_scenario("gt-benign", RaisingArm(), ledger_backed=False)
        assert run.mediation_events[-1].admitted is False
        assert run.mediation_events[-1].reason_code.startswith("arm_error:")
        assert run.tool_result_error is True

    def test_a_ledger_backed_run_needs_a_ledger_directory(self):
        from src.sut.baselines.b0 import B0Arm

        # Negative arm: the non-ledger mode is opt-in, never a silent default.
        with pytest.raises(runner.RunnerError):
            runner.GoldenThreadRunner().run_scenario("gt-benign", B0Arm())


@WIN32_ONLY
class TestScenarioRunB0:
    @pytest.fixture()
    def ledger_dir(self):
        directory = REPO_ROOT / "tests" / "_ledger_tmp_runner"
        directory.mkdir(parents=True, exist_ok=True)
        yield directory
        shutil.rmtree(directory, ignore_errors=True)

    def test_benign_run_produces_the_four_record_kinds(self, ledger_dir):
        from src.sut.baselines.b0 import B0Arm

        gt_runner = runner.GoldenThreadRunner(ledger_dir=ledger_dir)
        run = gt_runner.run_scenario("gt-benign", B0Arm())

        # MediationEvent: exactly one, admitted, carrying the harness cid.
        assert len(run.mediation_events) == 1
        event = run.mediation_events[0]
        assert event.admitted is True
        assert event.correlation_id == run.correlation_id

        # Ledger: ingress + effect, correlated.
        entries = run.ledger_entries()
        ingress = [e for e in entries if "ingress_request_digest" in e]
        effects = run.effects()
        assert len(ingress) == 1 and ingress[0]["correlation_id"] == run.correlation_id
        assert len(effects) == 1 and effects[0]["correlation_id"] == run.correlation_id

        # ObservedRequest: raw evidence, no SUT digest anywhere.
        assert run.observed.correlation_id == run.correlation_id
        assert run.observed.tool == "notes.write"
        assert run.observed.evidence.capability is None  # B0 presents nothing
        assert run.observed.evidence.oauth is None

        # IntendedInvocation: completed with the same cid; B0 has no hops.
        assert run.intent.correlation_id == run.correlation_id
        assert run.intent.P_hashes == []
        assert run.intent.tau_gt == frozenset({("notes.write", "notes/project")})
        assert run.tool_result_error is False

    def test_correlation_ids_differ_across_invocations(self, ledger_dir):
        from src.sut.baselines.b0 import B0Arm

        gt_runner = runner.GoldenThreadRunner(ledger_dir=ledger_dir)
        first = gt_runner.run_scenario("gt-benign", B0Arm())
        second = gt_runner.run_scenario("gt-benign", B0Arm())
        assert first.correlation_id != second.correlation_id

    def test_an_arm_that_raises_is_a_denial(self, ledger_dir):
        from src.sut.baselines.b0 import B0Arm

        class RaisingArm(B0Arm):
            name = "B0-raising"

            def decide(self, tool, arguments):
                raise RuntimeError("boundary blew up")

        gt_runner = runner.GoldenThreadRunner(ledger_dir=ledger_dir)
        run = gt_runner.run_scenario("gt-benign", RaisingArm())
        assert run.mediation_events[-1].admitted is False
        assert run.mediation_events[-1].reason_code.startswith("arm_error:")
        assert run.effects() == []  # fail closed: the tool never ran
        assert run.tool_result_error is True
