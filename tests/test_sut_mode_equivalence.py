"""The two SUT modes drive ONE stack, and agree cell for cell (EXP5 STEP 3).

Separation is only useful if it changes **where** the SUT runs and nothing
else. This suite runs the same scenarios both ways and asserts the outcomes are
identical — which is what lets a later gate compare a fault-injected separated
run against an honest one and attribute the difference to the fault.

**Why the modes cannot silently diverge.** There is one MCP server, one
mediation boundary, one ingress recorder and one effector, built once in
`run_scenario` and driven by both paths. `sut_mode` selects only how the agents
are reached: in-process the Supervisor is called directly, separated the child
runs both agents and emits an `invoke` event per tool call. A second stack for
the separated path would let the two drift apart, and the comparison below
would then be measuring the drift.

**In-process stays the DEFAULT.** Ten gates were adjudicated in-process; a
default flip would silently re-adjudicate all of them.

Platform-independent: `ledger_backed=False` throughout, so no effect ledger is
opened and no Win32 handle is involved.
"""

import inspect

import pytest

from src.harness import key_material
from src.harness.as_process import ASProcess, golden_thread_as_document
from src.harness.authorizer import frozen_config
from src.harness.runner import GoldenThreadRunner, RunnerError
from src.harness.verifier import registry as reg
from src.sut.baselines.b0 import B0Arm
from src.sut.baselines.b3 import B3Arm
from src.sut.baselines.b3_plus import B3PlusArm
from src.sut.baselines.b_cap import BCapArm

SEED = bytes.fromhex("e1" * 32)
ISSUER = "https://as.aasc.local"
AUDIENCE = "https://mcp.aasc.local/tools"

# The capability arms plus `B0`, over the F1 chain. The exchange arms are
# excluded only because each adds a live AS round trip per mode and the
# property under test is the process boundary, not the exchange -- their
# in-process behaviour is already pinned by the nine-arm matrix.
ARMS = {"B0": B0Arm, "B-cap": BCapArm, "B3": B3Arm, "B3+": B3PlusArm}
SCENARIOS = ("gt-benign", "gt-f1-root", "gt-f1-terminal")


@pytest.fixture(scope="module")
def runner():
    return GoldenThreadRunner()


@pytest.fixture(scope="module")
def running_as(runner):
    registry_document = reg.load_document()
    document = golden_thread_as_document(
        corpus={"issuer": ISSUER, "audience": AUDIENCE},
        registry_document=registry_document,
        resolved_keys=key_material.resolve_public(SEED),
        identity_jwks=key_material.identity_jwks(SEED, registry_document["principals"]),
        omega_elements=frozen_config.load_document()["omega"]["elements"],
        task_grant=runner.task_grant("gt-benign"),
    )
    with ASProcess(document, SEED) as process:
        yield process


@pytest.fixture(scope="module")
def setup(runner, running_as):
    return runner.b3_setup(
        access_token=running_as.phase1_tokens["agent-specialist"],
        as_public_jwk=running_as.public_jwk,
    )


@pytest.fixture(scope="module")
def both_modes(runner, setup):
    """`(scenario, arm, mode) -> outcome`. Every cell run once, per mode."""
    cells = {}
    for scenario_id in SCENARIOS:
        for arm_name, factory in ARMS.items():
            for mode in ("in-process", "separate"):
                run = runner.run_scenario(
                    scenario_id,
                    factory(),
                    setup=setup if arm_name != "B0" else {},
                    ledger_backed=False,
                    sut_mode=mode,
                )
                event = run.mediation_events[-1]
                cells[(scenario_id, arm_name, mode)] = {
                    "admitted": event.admitted,
                    "reason_code": event.reason_code,
                    "tool": run.observed.tool,
                    "raw_arguments": run.observed.raw_arguments,
                    "correlation_id": run.correlation_id,
                    "intent_present": run.intent is not None,
                }
    return cells


class TestTheModesAgree:
    @pytest.mark.parametrize("arm_name", sorted(ARMS))
    @pytest.mark.parametrize("scenario_id", SCENARIOS)
    def test_the_admission_outcome_is_identical(self, both_modes, scenario_id, arm_name):
        """The cell §E.4 predicts must not depend on where the SUT runs."""
        in_process = both_modes[(scenario_id, arm_name, "in-process")]
        separate = both_modes[(scenario_id, arm_name, "separate")]
        assert (in_process["admitted"], in_process["reason_code"]) == (
            separate["admitted"],
            separate["reason_code"],
        ), f"{scenario_id}/{arm_name} moved across the process boundary"

    @pytest.mark.parametrize("arm_name", sorted(ARMS))
    @pytest.mark.parametrize("scenario_id", SCENARIOS)
    def test_the_observed_request_is_identical(self, both_modes, scenario_id, arm_name):
        """What the boundary observed — the bytes the oracle recomputes from —
        must not move either, or `realized_harm_F3` would be scoring the
        transport rather than the request."""
        in_process = both_modes[(scenario_id, arm_name, "in-process")]
        separate = both_modes[(scenario_id, arm_name, "separate")]
        assert in_process["tool"] == separate["tool"]
        assert in_process["raw_arguments"] == separate["raw_arguments"]

    @pytest.mark.parametrize("arm_name", sorted(ARMS))
    def test_the_intent_is_sealed_in_both_modes(self, both_modes, arm_name):
        for scenario_id in SCENARIOS:
            for mode in ("in-process", "separate"):
                assert both_modes[(scenario_id, arm_name, mode)]["intent_present"] is True

    def test_the_correlation_id_is_fresh_per_run_in_both_modes(self, both_modes):
        """Harness-minted per invocation (§F.1), so no two runs share one and
        the separated path did not start reusing it."""
        ids = [cell["correlation_id"] for cell in both_modes.values()]
        assert len(set(ids)) == len(ids)

    def test_the_comparison_is_not_vacuous(self, both_modes):
        """Negative arm: the cells are not all the same outcome, so agreement
        above is agreement about something."""
        outcomes = {(cell["admitted"], cell["reason_code"]) for cell in both_modes.values()}
        assert len(outcomes) > 1


class TestTheModesShareOneStack:
    def test_in_process_is_the_default(self):
        """Ten gates were adjudicated in-process; a default flip would silently
        re-adjudicate all of them."""
        signature = inspect.signature(GoldenThreadRunner.run_scenario)
        assert signature.parameters["sut_mode"].default == "in-process"

    def test_an_unknown_mode_fails_closed(self, runner):
        with pytest.raises(RunnerError, match="unknown sut_mode"):
            runner.run_scenario("gt-benign", B0Arm(), setup={}, sut_mode="somewhere-else")

    def test_there_is_one_boundary_installation_for_both_modes(self):
        """Structural: `run_scenario` installs the boundary, the recorder and
        the effector once, above the `sut_mode` branch. A second stack would
        let the modes diverge silently."""
        source = inspect.getsource(GoldenThreadRunner.run_scenario)
        assert source.count("install_boundary(") == 1
        assert source.count("install_ingress_recorder(") == 1
        assert source.count("build_server(") == 1

    def test_the_separated_path_reuses_the_same_session_call(self):
        """The child's tool call goes through `call_over_session`, which is the
        same function the in-process agent uses — so both cross the same
        boundary."""
        source = inspect.getsource(GoldenThreadRunner.run_scenario)
        assert source.count("call_over_session") >= 3  # defined, used by each mode
