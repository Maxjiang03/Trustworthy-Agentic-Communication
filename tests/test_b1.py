"""`B1` -- the static API key, SS E.1's appendix arm (EXP3 STEP 8).

Every test has a positive arm and a negative arm so no assertion can pass
vacuously. What is under test is that `B1` **authenticates a caller and does
nothing else**, and is honestly incapable of more: SS E.1's `Isolates` column
says *a static secret adds nothing*, and that is only measurable if the arm
cannot add anything.

Expected per SS E.4: **admits** `F1-root` and `F1-terminal` -- those admissions
are the measured phenomenon, not a defect -- **blocks** `F2 invalid_credential`
and `F2 unauthenticated_caller`, and is **NA** on `F1-chain-tamper`, which the
sealed record carries as data.

Platform-independent: no test here touches the effect ledger.
"""

import ast
import json
from pathlib import Path

import pytest

from src.harness import key_material
from src.harness.runner import GoldenThreadRunner
from src.sut.baselines import b1 as b1mod
from src.sut.baselines.b1 import B1Arm
from src.sut.baselines.base import HopContext, InvocationContext

REPO_ROOT = Path(__file__).resolve().parents[1]
SEED = bytes.fromhex("e1" * 32)
CORPUS = REPO_ROOT / "fixtures" / "pilot" / "golden_thread"


def _visible(scenario_id: str) -> dict:
    return json.loads((CORPUS / "sut_visible" / f"{scenario_id}.json").read_text(encoding="utf-8"))


def _sealed(scenario_id: str) -> dict:
    return json.loads((CORPUS / "sealed" / f"{scenario_id}.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def runner():
    return GoldenThreadRunner()


@pytest.fixture(scope="module")
def setup(runner):
    return runner.b1_setup()


def _armed(setup, scenario_id="gt-benign"):
    """Provision, delegate and present, as the golden thread would."""
    visible = _visible(scenario_id)
    arm = B1Arm()
    arm.provision(setup)
    credentials = arm.delegate(
        HopContext(
            task_id=visible["task_id"],
            audience=visible["audience"],
            from_agent=visible["supervisor"],
            to_agent=visible["specialist"],
            authority_elements=tuple(map(tuple, visible["authority_elements"])),
            attenuation_elements=tuple(map(tuple, visible["attenuation_elements"])),
            widening_elements=tuple(map(tuple, visible["widening_elements"])),
            now_epoch=0,
            expiry_epoch=3600,
        )
    )
    wire = arm.present(
        credentials,
        InvocationContext(
            tool=visible["delegation_intent"]["tool"],
            arguments=visible["delegation_intent"]["arguments"],
            method=visible["method"],
            task_id=visible["task_id"],
            audience=visible["audience"],
            invocation_id="cid-b1",
            now_epoch=0,
        ),
    )
    return arm, credentials, wire


class TestItAuthenticatesAndNothingElse:
    def test_a_valid_key_is_admitted(self, setup):
        arm, _, _ = _armed(setup)
        assert arm.decide("notes.write", {"resource": "notes/project"}) == (
            True,
            b1mod.REASON_ADMITTED,
        )

    def test_a_wrong_secret_is_refused(self, setup):
        """F2 `invalid_credential`."""
        arm, credentials, _ = _armed(setup)
        arm.present(dict(credentials, api_key_secret="not-the-secret"), _invocation())
        admitted, reason = arm.decide("notes.write", {"resource": "notes/project"})
        assert (admitted, reason) == (False, b1mod.REASON_INVALID_CREDENTIAL)

    def test_a_wrong_key_id_is_refused(self, setup):
        arm, credentials, _ = _armed(setup)
        arm.present(dict(credentials, api_key_id="someone-elses-key"), _invocation())
        assert arm.decide("notes.write", {})[1] == b1mod.REASON_INVALID_CREDENTIAL

    def test_no_credential_at_all_is_refused(self, setup):
        """F2 `unauthenticated_caller`."""
        arm = B1Arm()
        arm.provision(setup)
        arm.present({}, _invocation())
        assert arm.decide("notes.write", {}) == (False, b1mod.REASON_NO_CREDENTIAL)

    def test_an_unprovisioned_arm_fails_closed(self):
        assert B1Arm().decide("notes.write", {}) == (False, b1mod.REASON_NOT_PROVISIONED)

    def test_provisioning_refuses_incomplete_or_empty_material(self, setup):
        with pytest.raises(b1mod.B1ConfigurationError):
            B1Arm().provision({"api_key_id": "pilot-api-key"})
        with pytest.raises(b1mod.B1ConfigurationError):
            B1Arm().provision(dict(setup, api_key_secret=""))
        B1Arm().provision(setup)  # positive arm


class TestItIsIncapableOfAuthorizing:
    """SS E.1's claim is only measurable if the arm cannot add anything."""

    def test_the_verdict_function_takes_no_request(self):
        """Structural: there is no parameter through which the call could arrive.

        Not a promise that `tool` and `arguments` are ignored -- a signature
        that cannot receive them.
        """
        source = (REPO_ROOT / "src" / "sut" / "baselines" / "b1.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        decide = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == "_decide"
        )
        assert [arg.arg for arg in decide.args.args] == ["self"]
        # Negative arm: the PUBLIC `decide` does take them, because the arm
        # interface requires it -- so the emptiness above is a real narrowing
        # rather than an artefact of how the scan reads the file.
        public = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == "decide"
        )
        assert [arg.arg for arg in public.args.args] == ["self", "tool", "arguments"]

    def test_the_verdict_does_not_move_with_the_request(self, setup):
        """Behavioural: the same key admits every tool, in and out of the grant."""
        arm, _, _ = _armed(setup)
        for tool, arguments in (
            ("notes.write", {"resource": "notes/project"}),
            ("mail.send", {"to": "partner@example.test", "subject": "s", "body": "b"}),
            ("notes.delete", {"resource": "notes/project"}),
            ("calendar.read", {"resource": "calendar/personal"}),
        ):
            assert arm.decide(tool, arguments) == (True, b1mod.REASON_ADMITTED)

    def test_the_bitmask_is_the_ss_e5_row(self):
        # oauth | crypto_chain | authorizer | htc/holder | invoke | contain |
        # context | approval | jti | audit
        assert B1Arm().bitmask.as_bits() == (0, 0, 0, 0, 0, 0, 0, 0, 0, 1)
        assert B1Arm().bitmask.enabled_conjuncts() == frozenset()

    def test_it_imports_no_authorization_layer(self):
        source = (REPO_ROOT / "src" / "sut" / "baselines" / "b1.py").read_text(encoding="utf-8")
        imported: set[str] = set()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
            elif isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
        assert not any(name.startswith("src.sut.capability") for name in imported)
        assert not any(name.startswith("src.sut.oauth_as") for name in imported)
        assert not any(name.startswith("src.harness") for name in imported)
        assert "src.sut.authz.boundary" not in imported
        assert "src.sut.protocol.required_authority" not in imported
        # Negative arm: it DOES import the shared audit buffer, since audit = 1.
        assert "src.sut.authz.capability_path" in imported

    def test_the_delegation_carries_no_per_hop_object(self, setup):
        """Which is why `F1-chain-tamper` is NA for it (SS E.3)."""
        _, credentials, _ = _armed(setup, "gt-f1-chain-tamper")
        assert set(credentials) == {"api_key_id", "api_key_secret"}
        # The hop declared a widening intent; the arm has nowhere to put it.
        assert _visible("gt-f1-chain-tamper")["widening_elements"] != []


class TestTheSecretNeverReachesARecord:
    def test_the_presented_wire_carries_the_id_only(self, setup):
        _, credentials, wire = _armed(setup)
        assert wire == {"api_key_id": "pilot-api-key"}
        assert credentials["api_key_secret"] not in json.dumps(wire)

    def test_the_evidence_bundle_records_a_reference(self, runner, setup):
        run = runner.run_scenario("gt-benign", B1Arm(), setup=setup, ledger_backed=False)
        evidence = run.observed.evidence
        assert evidence.api_key is not None
        assert evidence.api_key.raw_key_ref == "pilot-api-key"
        assert evidence.oauth is None and evidence.capability is None
        # The secret appears nowhere in the observed record.
        secret = key_material.b1_api_key(SEED, "pilot-api-key")
        assert secret not in run.observed.model_dump_json()


class TestTheGoldenThreadUnderB1:
    """SS E.4's prediction. The admissions ARE the measurement."""

    @pytest.mark.parametrize(
        "scenario_id,admitted",
        [("gt-benign", True), ("gt-f1-root", True), ("gt-f1-terminal", True)],
    )
    def test_pilot_outcome(self, runner, setup, scenario_id, admitted):
        run = runner.run_scenario(scenario_id, B1Arm(), setup=setup, ledger_backed=False)
        event = run.mediation_events[-1]
        assert (event.admitted, event.reason_code) == (admitted, b1mod.REASON_ADMITTED)

    def test_chain_tamper_is_na_and_recorded_as_data(self):
        """Never a skipped cell: the matrix fixture reads it from the record."""
        sealed = _sealed("gt-f1-chain-tamper")
        assert "B1" in sealed["not_applicable"]["arms"]
        assert "no per-hop authority chain" in sealed["not_applicable"]["reason"]
        # Negative arm: it is NA on that subcase alone.
        for scenario_id in ("gt-benign", "gt-f1-root", "gt-f1-terminal"):
            assert _sealed(scenario_id)["not_applicable"]["arms"] == []


def _invocation():
    visible = _visible("gt-benign")
    return InvocationContext(
        tool="notes.write",
        arguments={"resource": "notes/project"},
        method=visible["method"],
        task_id=visible["task_id"],
        audience=visible["audience"],
        invocation_id="cid-b1",
        now_epoch=0,
    )
