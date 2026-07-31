"""The two broad OAuth arms, and the ADR 0029 grant rule (EXP3 STEP 9).

Every test has a positive arm and a negative arm so no assertion can pass
vacuously. Three things are under test:

1. **Breadth is a property of the ARM, not of the token it is handed.** Each
   arm declares its SS E.1 row; provisioning refuses a row that disagrees; and
   the arm then verifies the token it actually holds against that row's grant.
2. **Each arm's realized `C_0` is what its SS E.1 row specifies** -- `Omega`
   for the broad rows, `U_task` for the strong ones -- **computed** by the
   independent verifier from the presented token, never asserted.
3. **A broad arm never narrows, and a broad exchange arm still exchanges.**
   `B2-exchange-broad` isolates the round trip FROM narrowing, so an
   implementation that quietly narrowed would destroy it and silently
   contradict SS E.4; one that skipped the round trip would measure nothing.

Platform-independent; nothing here is timed.
"""

import ast
import json
import time
from pathlib import Path

import pytest

from src.harness import key_material
from src.harness.as_process import RAR_TYPE, ASProcess, golden_thread_as_document
from src.harness.authorizer import frozen_config
from src.harness.runner import GoldenThreadRunner, RunnerError
from src.harness.verifier import matched_authority as ma
from src.harness.verifier import registry as reg
from src.sut.baselines.b2_broad import B2BroadNoExchangeArm, B2ExchangeBroadArm
from src.sut.baselines.b2_exchange_task import B2ConfigurationError, B2ExchangeTaskArm
from src.sut.baselines.base import HopContext

REPO_ROOT = Path(__file__).resolve().parents[1]
SEED = bytes.fromhex("e1" * 32)
CORPUS = REPO_ROOT / "fixtures" / "pilot" / "golden_thread"
ISSUER = "https://as.aasc.local"
AUDIENCE = "https://mcp.aasc.local/tools"


def _visible(scenario_id: str) -> dict:
    return json.loads((CORPUS / "sut_visible" / f"{scenario_id}.json").read_text(encoding="utf-8"))


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
        task_grant=runner.task_grant(),
    )
    with ASProcess(document, SEED) as process:
        yield process


@pytest.fixture(scope="module")
def token_config(running_as):
    return ma.TokenVerifierConfig(
        issuer=ISSUER,
        resource_server=AUDIENCE,
        as_public_jwk=running_as.public_jwk,
        rar_type=RAR_TYPE,
        required_scope="mcp.invoke",
    )


def _setup(runner, running_as, ladder_grant):
    client = "agent-supervisor" + ("" if ladder_grant == "task" else ":broad")
    return runner.b2_setup(
        access_token=running_as.phase1_tokens[client],
        as_public_jwk=running_as.public_jwk,
        as_port=running_as.port,
        as_tls_cert_pem=running_as.tls_cert_pem,
        ladder_grant=ladder_grant,
    )


def _hop(scenario_id="gt-benign", now=None):
    visible = _visible(scenario_id)
    now = int(time.time()) if now is None else now
    return HopContext(
        task_id=visible["task_id"],
        audience=visible["audience"],
        from_agent=visible["supervisor"],
        to_agent=visible["specialist"],
        authority_elements=tuple(map(tuple, visible["authority_elements"])),
        attenuation_elements=tuple(map(tuple, visible["attenuation_elements"])),
        widening_elements=tuple(map(tuple, visible["widening_elements"])),
        now_epoch=now,
        expiry_epoch=now + int(visible["validity_seconds"]),
    )


ROWS = [
    (B2BroadNoExchangeArm, "broad"),
    (B2ExchangeBroadArm, "broad"),
    (B2ExchangeTaskArm, "task"),
]


class TestBreadthIsAPropertyOfTheArm:
    @pytest.mark.parametrize("factory,expected", ROWS)
    def test_each_arm_declares_its_row(self, factory, expected):
        assert factory.ladder_grant == expected

    @pytest.mark.parametrize("factory,declared", ROWS)
    def test_a_row_that_disagrees_is_refused(self, runner, running_as, factory, declared):
        """Breadth cannot be smuggled in by handing over the other token."""
        wrong = "task" if declared == "broad" else "broad"
        arm = factory()
        with pytest.raises(B2ConfigurationError) as raised:
            arm.provision(_setup(runner, running_as, wrong))
        assert "ADR 0029" in str(raised.value)
        assert declared in str(raised.value)
        arm.close()

    @pytest.mark.parametrize("factory,declared", ROWS)
    def test_the_matching_row_provisions(self, runner, running_as, factory, declared):
        """Positive arm: the refusals above are not refusing everything."""
        arm = factory()
        arm.provision(_setup(runner, running_as, declared))
        arm.close()

    def test_a_token_from_the_wrong_grant_is_refused_even_with_the_right_name(
        self, runner, running_as
    ):
        """The row NAME is not enough: the token is verified against the row.

        A caller who declared `broad` and handed the task-scoped token would
        otherwise get a silently narrow broad arm.
        """
        setup = _setup(runner, running_as, "broad")
        swapped = dict(setup, access_token=running_as.phase1_tokens["agent-supervisor"])
        with pytest.raises(B2ConfigurationError) as raised:
            B2ExchangeBroadArm().provision(swapped)
        assert "'broad' row" in str(raised.value)

    def test_the_runner_refuses_an_unknown_row(self, runner, running_as):
        with pytest.raises(RunnerError):
            _setup(runner, running_as, "somewhere-in-between")


class TestTheRealizedGrantMatchesTheRow:
    """Computed from the presented token by the independent verifier."""

    @pytest.mark.parametrize("factory,declared", ROWS)
    def test_realized_c0_equals_the_rows_grant(
        self, runner, running_as, token_config, factory, declared
    ):
        setup = _setup(runner, running_as, declared)
        realized = ma.token_allowed(
            setup["access_token"], token_config, ma.omega(), now=int(time.time())
        )
        expected = frozenset(map(tuple, runner.ladder_grant_elements(declared)))
        assert realized == expected
        if declared == "broad":
            assert realized == ma.omega()
            assert len(realized) == 7
        else:
            assert realized < ma.omega()
            assert len(realized) == 3

    def test_the_two_rows_really_differ(self, runner):
        """Otherwise every assertion above would hold vacuously."""
        broad = frozenset(map(tuple, runner.ladder_grant_elements("broad")))
        task = frozenset(map(tuple, runner.ladder_grant_elements("task")))
        assert task < broad
        # And the element F1-root needs is in one and not the other -- which is
        # the whole reason the two rows cannot share a grant.
        assert ("mail.send", "mail/outbox") in broad
        assert ("mail.send", "mail/outbox") not in task


class TestABroadArmNeverNarrows:
    def test_the_broad_exchange_still_performs_a_real_round_trip(self, runner, running_as):
        """The round trip IS what this arm isolates; skipping it measures nothing."""
        arm = B2ExchangeBroadArm()
        arm.provision(_setup(runner, running_as, "broad"))
        try:
            credentials = arm.delegate(_hop())
        finally:
            arm.close()
        assert "access_token" in credentials
        assert len(arm.exchanges) == 1 and arm.exchanges[0]["issued"] is True

    def test_and_the_authority_does_not_move(self, runner, running_as, token_config):
        """`Allowed(AT_1) = Allowed(AT_0) = Omega`: exchanged, not narrowed."""
        setup = _setup(runner, running_as, "broad")
        arm = B2ExchangeBroadArm()
        arm.provision(setup)
        try:
            credentials = arm.delegate(_hop())
        finally:
            arm.close()
        now = int(time.time())
        before = ma.token_allowed(setup["access_token"], token_config, ma.omega(), now=now)
        after = ma.token_allowed(credentials["access_token"], token_config, ma.omega(), now=now)
        assert after == before == ma.omega()
        # Negative arm: the task row, through the SAME code, DOES narrow -- so
        # the equality above is the arm's row and not the code being inert.
        task_setup = _setup(runner, running_as, "task")
        narrowing = B2ExchangeTaskArm()
        narrowing.provision(task_setup)
        try:
            narrowed = narrowing.delegate(_hop())
        finally:
            narrowing.close()
        assert (
            ma.token_allowed(narrowed["access_token"], token_config, ma.omega(), now=now) < before
        )

    def test_the_no_exchange_arm_forwards_and_never_dials(self, runner, running_as):
        setup = _setup(runner, running_as, "broad")
        arm = B2BroadNoExchangeArm()
        arm.provision(setup)
        try:
            credentials = arm.delegate(_hop())
            # An arm that never dials should not hold a socket, nor a context.
            assert arm._connection is None
            assert arm._tls_context is None
        finally:
            arm.close()
        assert credentials["access_token"] == setup["access_token"]
        assert arm.exchanges[0]["exchanged"] is False
        # Negative arm: the exchange arms DO build one.
        dialer = B2ExchangeBroadArm()
        dialer.provision(setup)
        assert dialer._connection is not None
        dialer.close()

    def test_a_broad_hop_ignores_the_declared_widening(self, runner, running_as, token_config):
        """SS E.3 marks chain-tamper NA for the broad arms, and this is why.

        The widening target is already inside a broad row's grant, so there is
        no narrowing for it to tamper with.
        """
        setup = _setup(runner, running_as, "broad")
        arm = B2ExchangeBroadArm()
        arm.provision(setup)
        try:
            credentials = arm.delegate(_hop("gt-f1-chain-tamper"))
        finally:
            arm.close()
        assert _visible("gt-f1-chain-tamper")["widening_elements"] == [["mail.send", "mail/outbox"]]
        assert "access_token" in credentials  # issued: nothing was widened
        realized = ma.token_allowed(
            credentials["access_token"], token_config, ma.omega(), now=int(time.time())
        )
        assert realized == ma.omega()


class TestTheArmsAreConfigurationsNotCopies:
    @pytest.mark.parametrize("factory", [B2BroadNoExchangeArm, B2ExchangeBroadArm])
    def test_provisioning_and_decision_are_the_shared_functions(self, factory):
        assert factory.provision is B2ExchangeTaskArm.provision
        assert factory.decide is B2ExchangeTaskArm.decide
        assert factory.present is B2ExchangeTaskArm.present

    def test_only_the_no_exchange_arm_overrides_delegate(self):
        assert B2ExchangeBroadArm.delegate is B2ExchangeTaskArm.delegate
        assert B2BroadNoExchangeArm.delegate is not B2ExchangeTaskArm.delegate

    def test_the_bitmasks_are_the_ss_e5_rows(self):
        # oauth | crypto_chain | authorizer | htc/holder | invoke | contain |
        # context | approval | jti | audit -- `contain = 0` for both broad rows
        assert B2BroadNoExchangeArm().bitmask.as_bits() == (1, 0, 0, 0, 0, 0, 0, 0, 0, 1)
        assert B2ExchangeBroadArm().bitmask.as_bits() == (1, 0, 0, 0, 0, 0, 0, 0, 0, 1)
        # Negative arm: the task row sets `contain`, which is the difference.
        assert B2ExchangeTaskArm().bitmask.contain == 1

    def test_no_capability_layer_is_imported(self):
        source = (REPO_ROOT / "src" / "sut" / "baselines" / "b2_broad.py").read_text(
            encoding="utf-8"
        )
        imported: set[str] = set()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
            elif isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
        assert not any(name.startswith("src.sut.capability") for name in imported)
        assert not any(name.startswith("src.sut.oauth_as") for name in imported)
        assert not any(name.startswith("src.harness") for name in imported)
        assert "src.sut.baselines.b2_exchange_task" in imported


class TestTheGoldenThreadUnderTheBroadArms:
    """SS E.4's prediction: they ADMIT F1-root and F1-terminal.

    That is what the study exists to measure -- audience binding alone does
    not attenuate, and a broad exchange narrows nothing -- not a defect.
    """

    @pytest.mark.parametrize("factory", [B2BroadNoExchangeArm, B2ExchangeBroadArm])
    @pytest.mark.parametrize("scenario_id", ["gt-benign", "gt-f1-root", "gt-f1-terminal"])
    def test_every_pilot_scenario_is_admitted(self, runner, running_as, factory, scenario_id):
        arm = factory()
        try:
            run = runner.run_scenario(
                scenario_id, arm, setup=_setup(runner, running_as, "broad"), ledger_backed=False
            )
        finally:
            arm.close()
        event = run.mediation_events[-1]
        assert (event.admitted, event.reason_code) == (True, "b2_admitted")

    def test_the_task_row_blocks_the_same_two_scenarios(self, runner, running_as):
        """The contrast the broad arms exist to provide."""
        for scenario_id in ("gt-f1-root", "gt-f1-terminal"):
            arm = B2ExchangeTaskArm()
            try:
                run = runner.run_scenario(
                    scenario_id, arm, setup=_setup(runner, running_as, "task"), ledger_backed=False
                )
            finally:
                arm.close()
            assert run.mediation_events[-1].admitted is False
