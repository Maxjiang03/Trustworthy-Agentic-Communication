"""§E.4's F4 and F5 rows, nine arms × **both** monitor configurations (STEP 10–12).

Each fixture runs twice — `monitor_attached = false` and `= true` — because one
number without the other supports nothing. §E.4 marks the OAuth arms `A†`,
glossed *"admitted **absent** the shared monitor"*; a single column could not
tell that apart from "OAuth cannot express this", and gate G-15 exists because
reporting the difference as a capability-versus-OAuth advantage would be wrong.

**The masking hazard, and how the corpus avoids it.** F4/F5 run on their own
authority chain, in which `(mail.send, mail/outbox)` and `(notes.delete,
notes/project)` are inside `C_1`. On the F1 chain they are not, so every
labelled-egress fixture would be refused by `containment_ok` **before**
`context_policy_ok` ran, and the label check would be untestable while appearing
to work. The same trap block 2 found on `Γ`'s expiry, one conjunct along.

**Each family isolates its own conjunct, by construction:**

* **F4** uses `mail.send` — the whole derived egress set over the frozen `Ω` —
  and row 10 also makes it high-risk, so **both F4 fixtures carry a valid
  approval**. Without one, `approval_artifact_ok` would refuse first and the F4
  cell would be measuring the F5 conjunct.
* **F5** uses `notes.delete`: high-risk under row 10 and **non-egress**, so rows
  4/6 permit it at every label and the only conjunct that can refuse is
  `approval_artifact_ok`. Isolation by choosing the action, not by arranging
  labels around it.

**The controls are the point of the controls.** `gt-f4-declassified` and
`gt-f5-approved` carry *valid* artifacts and must be **admitted**. Without them
"the monitor blocks" is indistinguishable from "the monitor blocks everything",
and the F4/F5 numbers would measure nothing.

Nothing here is timed (forbidden action 1). Platform-independent: admission is
what §E.4 predicts, and no effect ledger is involved.
"""

import json
import time
from pathlib import Path

import pytest

from src.harness import frozen_parameters, key_material
from src.harness.as_process import ASProcess, golden_thread_as_document
from src.harness.authorizer import frozen_config
from src.harness.matrix_grouping import ARMS, POLICY_PLANE, Cell
from src.harness.policy import label_artifacts
from src.harness.runner import GoldenThreadRunner
from src.harness.verifier import registry as reg
from src.sut.baselines.b0 import B0Arm
from src.sut.baselines.b1 import B1Arm
from src.sut.baselines.b2_broad import B2BroadNoExchangeArm, B2ExchangeBroadArm
from src.sut.baselines.b2_dpop import B2ExchangeTaskDPoPArm
from src.sut.baselines.b2_exchange_task import B2ExchangeTaskArm
from src.sut.baselines.b3 import B3Arm
from src.sut.baselines.b3_plus import B3PlusArm
from src.sut.baselines.b_cap import BCapArm
from src.sut.baselines.base import HopContext, InvocationContext

REPO_ROOT = Path(__file__).resolve().parents[1]
SEED = bytes.fromhex("e1" * 32)
CORPUS = REPO_ROOT / "fixtures" / "pilot" / "golden_thread"
ISSUER = "https://as.aasc.local"
AUDIENCE = "https://mcp.aasc.local/tools"

# (scenario_id, family, is the artifact VALID -- i.e. is this the control?)
FIXTURES = (
    ("gt-f4-sensitive-egress", "F4", False),
    ("gt-f4-declassified", "F4", True),
    ("gt-f5-unapproved-high-risk", "F5", False),
    ("gt-f5-approved", "F5", True),
)
OAUTH_ARMS = (
    "B2-broad-noexchange",
    "B2-exchange-broad",
    "B2-exchange-task",
    "B2-exchange-task-DPoP",
)
NO_BOUNDARY = ("B0", "B1")


def _visible(scenario_id: str) -> dict:
    return json.loads((CORPUS / "sut_visible" / f"{scenario_id}.json").read_text(encoding="utf-8"))


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
        # The F4/F5 chain, named rather than assumed: the corpus carries two.
        task_grant=runner.task_grant("gt-f4-sensitive-egress"),
    )


@pytest.fixture(scope="module")
def running_as(as_document):
    with ASProcess(as_document, SEED) as process:
        yield process


def _factories(runner, running_as, as_document, *, monitor_attached):
    """Every arm provisioned under ONE configuration.

    `monitor_attached` is passed to every arm that can take one, so the
    configuration is a property of the RUN and not of which arm was built how.
    """
    common = {
        "as_public_jwk": running_as.public_jwk,
        "as_port": running_as.port,
        "as_tls_cert_pem": running_as.tls_cert_pem,
        "scenario_id": "gt-f4-sensitive-egress",
        "monitor_attached": monitor_attached,
    }
    b3_setup = runner.b3_setup(
        access_token=running_as.phase1_tokens["agent-specialist"],
        as_public_jwk=running_as.public_jwk,
        monitor_attached=monitor_attached,
    )
    broad = runner.b2_setup(
        access_token=running_as.phase1_tokens["agent-supervisor:broad"],
        ladder_grant="broad",
        **common,
    )
    task = runner.b2_setup(
        access_token=running_as.phase1_tokens["agent-supervisor"],
        ladder_grant="task",
        **common,
    )
    dpop = runner.b2_dpop_setup(
        access_token=running_as.phase1_tokens["agent-supervisor"],
        as_token_endpoint=as_document["token_endpoint"],
        **common,
    )
    return {
        "B0": (B0Arm, {}),
        "B1": (B1Arm, runner.b1_setup()),
        "B2-broad-noexchange": (B2BroadNoExchangeArm, broad),
        "B2-exchange-broad": (B2ExchangeBroadArm, broad),
        "B2-exchange-task": (B2ExchangeTaskArm, task),
        "B2-exchange-task-DPoP": (B2ExchangeTaskDPoPArm, dpop),
        "B-cap": (BCapArm, b3_setup),
        "B3": (B3Arm, b3_setup),
        "B3+": (B3PlusArm, b3_setup),
    }


def _run_cell(factories, arm_name, scenario_id, family, monitor_attached):
    visible = _visible(scenario_id)
    factory, setup = factories[arm_name]
    now = int(time.time())
    arm = factory()
    arm.provision(dict(setup))
    hop = HopContext(
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
    credentials = arm.delegate(hop)
    # Minted harness-side from the corpus SPEC (ADR 0007/0030): the instrument
    # signs what the measured system must independently verify.
    artifacts = label_artifacts.mint_for_scenario(
        SEED,
        visible,
        now=now,
        resource_owner=(ISSUER, reg.load_document()["resource_owners"][0]),
        oauth_actor=(ISSUER, "agent-specialist"),
        policy_version=frozen_parameters.expected_h_policy(),
    )
    intent = visible["delegation_intent"]
    arm.present(
        credentials,
        InvocationContext(
            tool=intent["tool"],
            arguments=intent["arguments"],
            method=visible["method"],
            task_id=visible["task_id"],
            audience=visible["audience"],
            invocation_id=f"cid-{scenario_id}-{arm_name}",
            now_epoch=now,
            **artifacts,
        ),
    )
    admitted, reason_code = arm.decide(intent["tool"], intent["arguments"])
    log = getattr(arm, "audit_log", None)
    detail = str(log[-1].get("detail", "")) if log else ""
    if hasattr(arm, "close"):
        arm.close()
    return (
        Cell(
            family=family,
            subcase=scenario_id,
            arm=arm_name,
            admitted=admitted,
            reason_code=reason_code,
            monitor_attached=monitor_attached,
        ),
        detail,
    )


@pytest.fixture(scope="module")
def matrix(runner, running_as, as_document):
    """`(scenario_id, arm, monitor_attached) -> (Cell, detail)`. Run once."""
    cells: dict[tuple[str, str, bool], tuple[Cell, str]] = {}
    for monitor_attached in (False, True):
        factories = _factories(runner, running_as, as_document, monitor_attached=monitor_attached)
        for scenario_id, family, _control in FIXTURES:
            for arm_name in ARMS:
                cells[(scenario_id, arm_name, monitor_attached)] = _run_cell(
                    factories, arm_name, scenario_id, family, monitor_attached
                )
    return cells


def _outcome(matrix, scenario_id, arm, monitor_attached):
    return matrix[(scenario_id, arm, monitor_attached)][0].admitted


class TestTheDaggerIsReal:
    """`A†` = *admitted absent the shared monitor*, and it FLIPS when attached."""

    @pytest.mark.parametrize("arm", OAUTH_ARMS)
    @pytest.mark.parametrize(
        "scenario_id", ("gt-f4-sensitive-egress", "gt-f5-unapproved-high-risk")
    )
    def test_an_oauth_arm_admits_without_the_monitor_and_blocks_with_it(
        self, matrix, arm, scenario_id
    ):
        """The whole point of building the monitor shared. Both halves in one
        assertion, because either alone is uninterpretable."""
        assert _outcome(matrix, scenario_id, arm, False) is True
        assert _outcome(matrix, scenario_id, arm, True) is False

    @pytest.mark.parametrize("arm", OAUTH_ARMS)
    def test_the_block_names_the_families_own_conjunct(self, matrix, arm):
        f4 = matrix[("gt-f4-sensitive-egress", arm, True)][0]
        f5 = matrix[("gt-f5-unapproved-high-risk", arm, True)][0]
        assert f4.reason_code == "b2_context_policy"
        assert f5.reason_code == "b2_approval_artifact"

    @pytest.mark.parametrize("arm", NO_BOUNDARY)
    def test_the_no_boundary_arms_admit_under_both_configurations(self, matrix, arm):
        """`B0` and `B1` run no boundary check at all, so a monitor they are
        never asked to consult changes nothing. `A` under both is the
        vulnerability, not an inability to express the case."""
        for scenario_id, _family, _control in FIXTURES:
            assert _outcome(matrix, scenario_id, arm, False) is True
            assert _outcome(matrix, scenario_id, arm, True) is True


class TestTheControlsAreAdmitted:
    """Without these, "the monitor blocks" and "the monitor blocks everything"
    are the same measurement."""

    @pytest.mark.parametrize("scenario_id", ("gt-f4-declassified", "gt-f5-approved"))
    @pytest.mark.parametrize("arm", ARMS)
    def test_a_valid_artifact_is_accepted_with_the_monitor_attached(self, matrix, arm, scenario_id):
        cell, detail = matrix[(scenario_id, arm, True)]
        assert cell.admitted is True, f"{arm} refused the control: {cell.reason_code} {detail}"

    def test_the_control_and_the_attack_differ_only_in_the_artifact(self):
        """Same tool, same arguments, same chain -- the ONLY difference is
        whether a valid artifact was presented. An admitted control and a
        blocked attack that differed in anything else would not be a matched
        pair."""
        attack = _visible("gt-f4-sensitive-egress")
        control = _visible("gt-f4-declassified")
        assert attack["delegation_intent"] == control["delegation_intent"]
        assert attack["authority_elements"] == control["authority_elements"]
        assert attack["attenuation_elements"] == control["attenuation_elements"]
        assert attack["labelled_values"] == control["labelled_values"]
        assert attack["artifacts"] != control["artifacts"]


class TestB3BlocksForItsOwnReason:
    """STEP 15's per-arm question, asked here because this phase added the most
    new checks so far: does `B3` still block F4/F5 for the reason §E.4
    attributes, or does an artifact check now fire first?"""

    def test_f4_blocks_at_the_context_policy_with_the_egress_named(self, matrix):
        for arm in POLICY_PLANE:
            cell, detail = matrix[("gt-f4-sensitive-egress", arm, True)]
            assert cell.admitted is False
            assert cell.reason_code == "b3_context_policy"
            # Not merely the right conjunct -- the right CONDITION inside it.
            assert "egress of sensitive" in detail
            assert "external-sink" in detail
            assert "DeclassificationArtifact" in detail

    def test_f5_blocks_at_the_approval_conjunct_with_row_10_named(self, matrix):
        for arm in POLICY_PLANE:
            cell, detail = matrix[("gt-f5-unapproved-high-risk", arm, True)]
            assert cell.admitted is False
            assert cell.reason_code == "b3_approval_artifact"
            assert "high-risk" in detail
            assert "no ApprovalArtifact was presented" in detail

    def test_f4_is_not_masked_by_the_approval_conjunct(self, matrix):
        """The isolation, checked. Both F4 fixtures carry a VALID approval, so
        if `approval_artifact_ok` were firing first the F4 cell would be
        measuring F5. It is not: the reason names the context policy."""
        cell, _ = matrix[("gt-f4-sensitive-egress", "B3", True)]
        assert cell.reason_code != "b3_approval_artifact"

    def test_f5_is_not_masked_by_the_context_policy(self, matrix):
        """`notes.delete` is non-egress, so rows 4/6 permit it at every label
        and cannot be what refused."""
        cell, _ = matrix[("gt-f5-unapproved-high-risk", "B3", True)]
        assert cell.reason_code != "b3_context_policy"

    def test_neither_is_masked_by_containment(self, matrix):
        """The corpus-level hazard: on the F1 chain these two actions are
        outside `C_1` and `containment_ok` would refuse first."""
        for scenario_id, _family, _control in FIXTURES:
            for arm in POLICY_PLANE:
                cell, _ = matrix[(scenario_id, arm, True)]
                assert cell.reason_code != "b3_containment"


class TestWhatTheMeasurementActuallyShows:
    """Findings, recorded as assertions so they cannot quietly change."""

    @pytest.mark.parametrize("arm", POLICY_PLANE)
    def test_without_a_monitor_the_policy_plane_arms_FALSE_BLOCK_the_controls(self, matrix, arm):
        """**A measured false block, reported rather than smoothed.**

        With no monitor attached, `context_policy_ok` and `approval_artifact_ok`
        refuse everything presented -- fail-closed and correct, and the reason
        the block-2 refusal was built that way. The consequence is that `B3`
        and `B3⁺` refuse the *benign* controls too, so an unconfigured `B3` pays
        a false-blocking cost that §E.4's attack rows do not show. It belongs in
        the false-blocking analysis, not hidden inside an F4/F5 cell.
        """
        for scenario_id in ("gt-f4-declassified", "gt-f5-approved"):
            cell, detail = matrix[(scenario_id, arm, False)]
            assert cell.admitted is False
            assert "no reference monitor is attached" in detail
        # Negative arm: WITH the monitor the same controls are admitted, so the
        # false block is the configuration's and not the fixture's.
        for scenario_id in ("gt-f4-declassified", "gt-f5-approved"):
            assert matrix[(scenario_id, arm, True)][0].admitted is True

    def test_B_caps_dagger_does_NOT_flip_when_the_monitor_is_attached(self, matrix):
        """**A finding about §E.4's own annotation, reported not adjusted.**

        `B-cap` is marked `A†` on F4/F5, and the dagger's gloss is *"admitted
        ABSENT the shared monitor"* -- which implies attaching one changes the
        cell. It does not. `B-cap`'s §E.5 bitmask sets `context = 0` and
        `approval = 0`: a bearer capability with no policy plane. It never runs
        the conjuncts the monitor answers for, so attaching one to `B-cap` is a
        no-op and its cell stays `A` under both configurations.

        That is consistent with the §E.4 footnote as WORDED -- it says "the
        OAuth arms also block" and `B-cap` is not an OAuth arm -- but the
        dagger on `B-cap`'s cell is misleading in a way the four OAuth arms'
        daggers are not. Recorded for the author; **nothing is adjusted here**,
        and neither the cell nor the prediction may be moved toward the other.
        """
        assert "B-cap" not in POLICY_PLANE
        assert BCapArm.bitmask.context == 0 and BCapArm.bitmask.approval == 0
        for scenario_id, _family, _control in FIXTURES:
            assert _outcome(matrix, scenario_id, "B-cap", False) is True
            assert _outcome(matrix, scenario_id, "B-cap", True) is True

    def test_the_monitor_is_a_no_op_for_every_arm_outside_the_policy_plane(self, matrix):
        """Generalizes the finding above: attaching a monitor only moves a cell
        for an arm that RUNS the conjuncts. For the OAuth arms it does, because
        their decision path calls the monitor when configured; for `B0`, `B1`
        and `B-cap` it cannot."""
        for arm in NO_BOUNDARY + ("B-cap",):
            for scenario_id, _family, _control in FIXTURES:
                assert _outcome(matrix, scenario_id, arm, False) is _outcome(
                    matrix, scenario_id, arm, True
                )


class TestEveryCellCarriesItsConfiguration:
    def test_all_nine_arms_ran_under_both_configurations(self, matrix):
        assert len(matrix) == len(FIXTURES) * len(ARMS) * 2
        for scenario_id, _family, _control in FIXTURES:
            for arm in ARMS:
                assert (scenario_id, arm, False) in matrix
                assert (scenario_id, arm, True) in matrix

    def test_no_cell_can_be_recorded_without_it(self, matrix):
        for cell, _detail in matrix.values():
            assert cell.monitor_attached is not None
