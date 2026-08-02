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

*Update, 2026-08-02 — EXP5 STEP 13, the standing check. Widened from four arms
to all NINE, and from three scenarios to the full four.* This module covered
`B0`, `B-cap`, `B3` and `B3⁺` only, excluding the five OAuth arms "because each
adds a live AS round trip per mode and the property under test is the process
boundary, not the exchange". That reasoning was wrong in a way worth recording
rather than deleting: **the exchange is exactly what a process boundary could
break**, because it is the one thing an arm does that leaves its own address
space — a token exchange over TLS, a DPoP proof minted against a resource URL —
and none of it had ever been run from the child. The cells it would have missed
are the OAuth arms', which is the direction that flatters this work: an OAuth
arm silently admitting an `F1` case in separated mode because its exchange
failed differently there would have made the capability arms look better for a
transport reason. Sixty-four cells now, `9 × 4` minus the `F1-chain-tamper`
row's four `NA` arms, each run in both modes.
"""

import inspect
import json
from pathlib import Path

import pytest

from src.harness import key_material
from src.harness import matrix_grouping as grouping
from src.harness.as_process import ASProcess, golden_thread_as_document
from src.harness.authorizer import frozen_config
from src.harness.runner import GoldenThreadRunner, RunnerError
from src.harness.verifier import registry as reg
from src.sut.baselines.b0 import B0Arm
from src.sut.baselines.b1 import B1Arm
from src.sut.baselines.b2_broad import B2BroadNoExchangeArm, B2ExchangeBroadArm
from src.sut.baselines.b2_dpop import B2ExchangeTaskDPoPArm
from src.sut.baselines.b2_exchange_task import B2ExchangeTaskArm
from src.sut.baselines.b3 import B3Arm
from src.sut.baselines.b3_plus import B3PlusArm
from src.sut.baselines.b_cap import BCapArm

REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS = REPO_ROOT / "fixtures" / "pilot" / "golden_thread"
SEED = bytes.fromhex("e1" * 32)
ISSUER = "https://as.aasc.local"
AUDIENCE = "https://mcp.aasc.local/tools"

# The whole §E.1 ladder, in §E.4's column order (imported, not re-listed: a
# tenth arm must appear here without an edit).
ARMS = grouping.ARMS
SCENARIOS = ("gt-benign", "gt-f1-root", "gt-f1-terminal", "gt-f1-chain-tamper")
MODES = ("in-process", "separate")


def _sealed(scenario_id: str) -> dict:
    return json.loads((CORPUS / "sealed" / f"{scenario_id}.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def runner():
    return GoldenThreadRunner()


@pytest.fixture(scope="module")
def as_document(runner):
    registry_document = reg.load_document()
    return golden_thread_as_document(
        corpus={"issuer": ISSUER, "audience": AUDIENCE},
        registry_document=registry_document,
        resolved_keys=key_material.resolve_public(SEED),
        identity_jwks=key_material.identity_jwks(SEED, registry_document["principals"]),
        omega_elements=frozen_config.load_document()["omega"]["elements"],
        task_grant=runner.task_grant("gt-benign"),
    )


@pytest.fixture(scope="module")
def running_as(as_document):
    with ASProcess(as_document, SEED) as process:
        yield process


@pytest.fixture(scope="module")
def factories(runner, running_as, as_document):
    """The same nine `(class, setup)` pairs the nine-arm matrix provisions.

    Built here from one AS rather than imported from that module, because a
    fixture shared between two suites would make one of them depend on the
    other's collection order.
    """
    b3_setup = runner.b3_setup(
        access_token=running_as.phase1_tokens["agent-specialist"],
        as_public_jwk=running_as.public_jwk,
    )
    common = {
        "as_public_jwk": running_as.public_jwk,
        "as_port": running_as.port,
        "as_tls_cert_pem": running_as.tls_cert_pem,
    }
    broad_setup = runner.b2_setup(
        scenario_id="gt-benign",
        access_token=running_as.phase1_tokens["agent-supervisor:broad"],
        ladder_grant="broad",
        **common,
    )
    task_setup = runner.b2_setup(
        scenario_id="gt-benign",
        access_token=running_as.phase1_tokens["agent-supervisor"],
        ladder_grant="task",
        **common,
    )
    dpop_setup = runner.b2_dpop_setup(
        scenario_id="gt-benign",
        access_token=running_as.phase1_tokens["agent-supervisor"],
        as_token_endpoint=as_document["token_endpoint"],
        **common,
    )
    return {
        "B0": (B0Arm, {}),
        "B1": (B1Arm, runner.b1_setup()),
        "B2-broad-noexchange": (B2BroadNoExchangeArm, broad_setup),
        "B2-exchange-broad": (B2ExchangeBroadArm, broad_setup),
        "B2-exchange-task": (B2ExchangeTaskArm, task_setup),
        "B2-exchange-task-DPoP": (B2ExchangeTaskDPoPArm, dpop_setup),
        "B-cap": (BCapArm, b3_setup),
        "B3": (B3Arm, b3_setup),
        "B3+": (B3PlusArm, b3_setup),
    }


@pytest.fixture(scope="module")
def both_modes(runner, factories):
    """`(scenario, arm, mode) -> outcome`. Every applicable cell, once per mode.

    `NA` cells are **not run**: an arm with no per-hop authority chain cannot
    express `F1-chain-tamper`, and running it would manufacture a result.
    """
    cells = {}
    opened = []
    try:
        for scenario_id in SCENARIOS:
            not_applicable = set(_sealed(scenario_id)["not_applicable"]["arms"])
            for arm_name in ARMS:
                if arm_name in not_applicable:
                    continue
                factory, setup = factories[arm_name]
                for mode in MODES:
                    arm = factory()
                    opened.append(arm)
                    run = runner.run_scenario(
                        scenario_id,
                        arm,
                        setup=setup,
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
        yield cells
    finally:
        for arm in opened:
            if hasattr(arm, "close"):
                arm.close()


def _applicable() -> list[tuple[str, str]]:
    return [
        (scenario_id, arm_name)
        for scenario_id in SCENARIOS
        for arm_name in ARMS
        if arm_name not in set(_sealed(scenario_id)["not_applicable"]["arms"])
    ]


class TestTheModesAgree:
    @pytest.mark.parametrize("cell", _applicable())
    def test_the_admission_outcome_is_identical(self, both_modes, cell):
        """The cell §E.4 predicts must not depend on where the SUT runs."""
        scenario_id, arm_name = cell
        in_process = both_modes[(scenario_id, arm_name, "in-process")]
        separate = both_modes[(scenario_id, arm_name, "separate")]
        assert (in_process["admitted"], in_process["reason_code"]) == (
            separate["admitted"],
            separate["reason_code"],
        ), f"{scenario_id}/{arm_name} moved across the process boundary"

    @pytest.mark.parametrize("cell", _applicable())
    def test_the_observed_request_is_identical(self, both_modes, cell):
        """What the boundary observed — the bytes the oracle recomputes from —
        must not move either, or `realized_harm_F3` would be scoring the
        transport rather than the request."""
        scenario_id, arm_name = cell
        in_process = both_modes[(scenario_id, arm_name, "in-process")]
        separate = both_modes[(scenario_id, arm_name, "separate")]
        assert in_process["tool"] == separate["tool"]
        assert in_process["raw_arguments"] == separate["raw_arguments"]

    def test_the_intent_is_sealed_in_both_modes(self, both_modes):
        for cell in both_modes.values():
            assert cell["intent_present"] is True

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


class TestEveryArmCrossesTheBoundary:
    """STEP 13's per-arm question, asserted rather than left to the parametrize
    list: a suite that quietly stopped covering an arm would still be green."""

    def test_all_nine_arms_were_run_in_both_modes(self, both_modes):
        for mode in MODES:
            covered = {arm for _, arm, cell_mode in both_modes if cell_mode == mode}
            assert covered == set(ARMS), f"{mode} is missing {set(ARMS) - covered}"
        assert len(ARMS) == 9

    def test_the_oauth_arms_are_covered_and_not_excluded(self, both_modes):
        """The exchange is the one thing an arm does that leaves its address
        space, so it is the part a process boundary could most plausibly break.
        Named explicitly so a future 'skip the slow arms' edit fails here."""
        exchange_arms = {
            "B2-broad-noexchange",
            "B2-exchange-broad",
            "B2-exchange-task",
            "B2-exchange-task-DPoP",
        }
        for arm_name in exchange_arms:
            assert (
                "gt-benign",
                arm_name,
                "separate",
            ) in both_modes

    def test_every_applicable_cell_was_run(self, both_modes):
        expected = {(s, a, m) for s, a in _applicable() for m in MODES}
        assert set(both_modes) == expected


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
