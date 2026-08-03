"""One clock per cell, and the guard that refuses a cell judged away from it.

**The defect this suite closes.** `run_campaign` read `int(time.time())` once
for the whole pass and minted every scenario's ADR 0030 artifacts at it, built
every `OracleConfig` at it and evaluated every credential at it — while
`run_scenario` read its own `run_epoch` **per cell** and never received the
campaign's. The separation between the two grew with the pass, unbounded,
because nothing measured or capped it.

**Measured, at a 61 s separation — one cell running a minute into a run:**
twelve of the eighteen F4/F5 control cells flipped from admitted to blocked and
six were scored `false_block = True`. The reason codes read `b2_context_policy`
/ `b3_context_policy` and `b2_approval_artifact` / `b3_approval_artifact`:
exactly what a working mechanism looks like. And it could not surface on its
own, because the oracle was judged at the stale instant too — `reference_allow`
agreed with itself and nothing contradicted anything. A sealed campaign would
have carried a plausible, publishable false-blocking rate attaching to every
monitor-consulting arm, in the one family gate G-15 already established measures
the **monitor** rather than the mechanism.

**Two answers, not one.** Construction removes the straddle: the wall clock is
read once per cell, immediately before the run, and handed to `run_scenario`, so
a cell is judged at the instant its artifacts were built at; and everything
computed after the run reads `run.observed.iat`, the runner's own epoch, so
there is no second value to disagree with. The guard is fail-closed insurance
for the seam construction cannot close — the artifacts must be minted *before*
the run — and this suite watches it refuse real cells rather than asserting it
works.

Platform-independent: `ledger_backed=False`, no Win32 handle, nothing timed.
"""

import inspect
import json
import time
from pathlib import Path

import pytest

from src.harness import campaign as C
from src.harness import frozen_parameters, key_material
from src.harness.as_process import ASProcess, golden_thread_as_document
from src.harness.authorizer import frozen_config
from src.harness.matrix_grouping import ARMS
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

REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS = REPO_ROOT / "fixtures" / "pilot" / "golden_thread"
SEED = bytes.fromhex("e1" * 32)
ISSUER = "https://as.aasc.local"
AUDIENCE = "https://mcp.aasc.local/tools"

# The two **benign controls**. They carry VALID artifacts and must be admitted,
# which is what makes them the cells the defect moved: a spurious block on a
# control is a `false_block`, and six of them were scored as one.
CONTROLS = ("gt-f4-declassified", "gt-f5-approved")


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
        # The F4/F5 authority chain: on the F1 chain `containment_ok` would
        # refuse these actions BEFORE the conjuncts under test ever ran.
        task_grant=runner.task_grant("gt-f4-sensitive-egress"),
    )


@pytest.fixture(scope="module")
def running_as(as_document):
    with ASProcess(as_document, SEED) as process:
        yield process


@pytest.fixture(scope="module")
def factories(runner, running_as, as_document):
    common = {
        "as_public_jwk": running_as.public_jwk,
        "as_port": running_as.port,
        "as_tls_cert_pem": running_as.tls_cert_pem,
        "scenario_id": "gt-f4-sensitive-egress",
        "monitor_attached": True,
    }
    b3_setup = runner.b3_setup(
        access_token=running_as.phase1_tokens["agent-specialist"],
        as_public_jwk=running_as.public_jwk,
        monitor_attached=True,
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


def _campaign(runner, factories, running_as, **extra):
    return C.run_campaign(
        runner=runner,
        factories=factories,
        scenarios=CONTROLS,
        seed=SEED,
        as_issuer=ISSUER,
        as_public_jwk=running_as.public_jwk,
        resource_server=AUDIENCE,
        rar_type="urn:aasc:mcp-invoke",
        monitor_attached=True,
        sut_mode="in-process",
        run_mode="pilot",
        ledger_backed=False,
        corpus_root=CORPUS,
        **extra,
    )


@pytest.fixture(scope="module")
def healthy(runner, factories, running_as):
    """The eighteen control cells, on the campaign's own clock. Run once."""
    return _campaign(runner, factories, running_as)


@pytest.fixture(scope="module")
def straddled(runner, factories, running_as):
    """**The failing world**: the artifacts minted one second past Delta.

    Not a mocked clock and not a constructed artifact — a real campaign, real
    arms, real signed artifacts, minted at an instant the cells are not judged
    at. This is the shape of the measured defect, reproduced deliberately so
    the guard has something real to refuse.
    """
    delta = frozen_parameters.delta_seconds()
    return _campaign(runner, factories, running_as, artifact_instant=int(time.time()) - (delta + 1))


# ---------------------------------------------------------------------------
# construction — the straddle is impossible, not merely unlikely
# ---------------------------------------------------------------------------
class TestOneClockPerCell:
    def test_run_scenario_takes_an_optional_now_defaulting_to_None(self):
        """So every pre-existing caller is unchanged by construction.

        Thirty-odd call sites across the suites and the gate spikes pass no
        `now`; a default of `None` is what makes that a fact about the
        signature rather than a claim about having checked them all.
        """
        parameter = inspect.signature(GoldenThreadRunner.run_scenario).parameters["now"]
        assert parameter.default is None
        assert parameter.kind is inspect.Parameter.KEYWORD_ONLY

    def test_the_runner_uses_the_supplied_instant_as_its_run_epoch(self, runner):
        """`ObservedRequest.iat` IS the runner's `run_epoch`, so a caller can
        see which instant the cell was judged at without being told."""
        chosen = int(time.time()) - 7
        run = runner.run_scenario("gt-benign", B0Arm(), ledger_backed=False, now=chosen)
        assert run.observed.iat == chosen

    def test_the_campaign_reads_the_clock_INSIDE_the_per_arm_loop(self):
        """Structural. The defect was one read per PASS; the fix is one per
        CELL, and where the read sits is the whole of the difference.

        Parsed, not grepped. The first version of this test searched the raw
        source and matched **its own docstring**, which describes the defect it
        checks for — the third time this repository has produced a
        self-referential scan. An AST walk counts calls and cannot see prose.
        """
        import ast
        import textwrap

        tree = ast.parse(textwrap.dedent(inspect.getsource(C.run_campaign)))
        clock_reads = [
            node.lineno
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "time"
        ]
        per_arm = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.For)
            and isinstance(node.target, ast.Tuple)
            and isinstance(node.target.elts[0], ast.Name)
            and node.target.elts[0].id == "arm_name"
        ]
        assert len(per_arm) == 1, "the per-arm loop is what the clock read must sit inside"
        loop = per_arm[0]
        assert clock_reads, "no wall-clock read at all would make the assertion below vacuous"
        assert all(loop.lineno < line <= loop.end_lineno for line in clock_reads), (
            f"a wall-clock read at line(s) {clock_reads} sits outside the per-arm loop "
            f"(lines {loop.lineno}-{loop.end_lineno}): that is one clock per PASS, the defect"
        )

    def test_everything_judged_after_the_run_reads_the_RUNNERS_epoch(self):
        """`OracleConfig` and `credential_result` take `run.observed.iat`, not
        a campaign copy of the instant: there is no second value to drift."""
        source = inspect.getsource(C.run_campaign)
        assert "judged_at = int(run.observed.iat)" in source
        assert source.count("now=judged_at") == 2

    def test_no_cell_is_judged_at_an_instant_it_was_not_built_at(self, healthy):
        """The property, end to end and on real cells rather than on source.

        Every scored cell's artifacts were minted at the same instant the
        runner judged the cell at — separation zero, not merely within Delta.
        """
        assert healthy.cells, "no cell ran; the assertion below would be vacuous"
        for cell in healthy.cells:
            assert cell.note == "" or "ledger" in cell.note


# ---------------------------------------------------------------------------
# the guard
# ---------------------------------------------------------------------------
class TestTheGuardReadsTheFrozenRow:
    def test_delta_comes_from_frozen_parameters_and_is_not_a_literal(self):
        source = inspect.getsource(C.run_campaign)
        assert "frozen_parameters.delta_seconds()" in source
        assert "60" not in inspect.getsource(C.clock_refusal)

    def test_it_moves_with_the_frozen_row_rather_than_with_a_constant(self):
        """Handed Delta explicitly, so a row change moves the boundary here
        too. The same separation is refused under a smaller Delta and admitted
        under a larger one."""
        artifacts = {"declassification": {"iat": 1_000_000}}
        assert C.clock_refusal(artifacts=artifacts, judged_at=1_000_030, delta=20) != ""
        assert C.clock_refusal(artifacts=artifacts, judged_at=1_000_030, delta=40) == ""

    def test_it_is_symmetric_like_the_boundarys_own_check(self):
        """`is_fresh` is `|now - iat| <= Delta`: a future instant is as much a
        freshness failure as a stale one, so the guard must not be one-sided."""
        artifacts = {"declassification": {"iat": 1_000_000}}
        delta = frozen_parameters.delta_seconds()
        assert C.clock_refusal(artifacts=artifacts, judged_at=1_000_000 + delta + 1, delta=delta)
        assert C.clock_refusal(artifacts=artifacts, judged_at=1_000_000 - delta - 1, delta=delta)
        assert not C.clock_refusal(artifacts=artifacts, judged_at=1_000_000 + delta, delta=delta)

    def test_label_assertions_are_NOT_delta_bound(self):
        """§A.6 puts labels at ingestion, BEFORE task-time issuance, so
        `mint_for_scenario` back-dates them a day on purpose and the boundary
        checks only their own iat/exp. A guard that included them would refuse
        every labelled cell for a property nothing enforces."""
        instants = dict(C.artifact_instants({"payload_labels": ({"iat": 1, "exp": 2},)}))
        assert instants == {}

    def test_an_unreadable_approval_is_refused_rather_than_assumed_fresh(self):
        """Fail closed: an artifact whose instant cannot be read is not
        evidence that it is fresh."""
        refusal = C.clock_refusal(
            artifacts={"approval_artifact": b"not json"}, judged_at=1_000_000, delta=60
        )
        assert "approval_artifact" in refusal


class TestTheGuardIsWatchedRefusingRealCells:
    """**The failing world.** A guard nobody has seen refuse anything is
    untested code making a claim (§6.2)."""

    def test_the_straddled_campaign_scores_NOTHING(self, straddled):
        assert straddled.cells == []

    def test_every_control_cell_is_refused_by_NAME(self, straddled):
        refused = {(scenario, arm) for scenario, arm, _reason in straddled.unscorable}
        assert refused == {(scenario, arm) for scenario in CONTROLS for arm in ARMS}
        assert len(refused) == 18

    def test_the_refusal_names_the_artifact_the_separation_and_the_row(self, straddled):
        delta = frozen_parameters.delta_seconds()
        for _scenario, _arm, reason in straddled.unscorable:
            assert "was minted at" in reason
            assert "the cell was judged at" in reason
            assert f"Delta={delta}s" in reason
            assert "frozen_parameters row 3" in reason
            assert "UNSCORABLE" in reason

    def test_the_refusal_is_ASCII_like_the_boundarys_own(self, straddled):
        """Read off consoles whose code page is not UTF-8."""
        for _scenario, _arm, reason in straddled.unscorable:
            reason.encode("ascii")

    def test_a_refused_cell_is_not_a_block_and_not_a_false_block(self, straddled):
        """The point of routing to `unscorable`. Scored, these eighteen would
        have read as twelve blocks and six `false_block`s — a false-blocking
        rate for the monitor-consulting arms, produced by campaign duration."""
        payload = straddled.as_dict()
        assert payload["cells"] == []
        assert len(payload["unscorable"]) == 18

    def test_WITHOUT_the_guard_those_cells_would_have_been_SCORED(self, straddled, healthy):
        """Non-vacuity: the same cells score fine on one clock.

        Without this the suite above could pass because the campaign refused
        everything for some unrelated reason.
        """
        scored = {(cell.scenario_id, cell.arm) for cell in healthy.cells}
        refused = {(scenario, arm) for scenario, arm, _reason in straddled.unscorable}
        assert scored == refused
        assert len(scored) == 18


# ---------------------------------------------------------------------------
# no §E.4 cell moved
# ---------------------------------------------------------------------------
class TestNoCellMoved:
    """The fix is in the HARNESS. It must change no arm, and therefore no cell.

    §E.4 predicts the benign controls **admitted** under both configurations —
    that is what makes them controls. These are exactly the eighteen cells the
    defect moved, so pinning them here is pinning the cells at issue rather
    than a convenient neighbouring set.
    """

    @pytest.mark.parametrize("arm", ARMS)
    @pytest.mark.parametrize("scenario_id", CONTROLS)
    def test_the_control_is_admitted_with_the_monitor_attached(self, healthy, scenario_id, arm):
        cell = healthy.by_cell()[(scenario_id, arm)]
        assert cell.observed_forwarded is True, (
            f"{scenario_id}/{arm}: a benign control carrying a VALID artifact was blocked "
            f"({cell.reason_code}) — a moved cell is a finding, not something to adjust toward"
        )
        assert cell.false_block is False

    def test_the_oracle_still_reaches_the_controls_own_verdicts(self, healthy):
        """`reference_allow` is the quantity the defect could not disturb —
        judged at the stale instant, it agreed with itself. Recorded here so a
        future change that DOES disturb it is visible."""
        by_cell = healthy.by_cell()
        assert all(by_cell[("gt-f5-approved", arm)].reference_allow is True for arm in ARMS)

    def test_the_run_record_still_carries_the_frozen_rows(self, healthy):
        record = healthy.record.as_dict()
        assert record["frozen_rows"]["delta_seconds"] == frozen_parameters.delta_seconds()
        assert record["run_mode"] == "pilot"

    def test_no_secret_reaches_the_artifact(self, healthy, straddled):
        """Red line 8, on the new `unscorable` strings too: the guard's reason
        quotes instants, never material."""
        for result in (healthy, straddled):
            payload = json.dumps(result.as_dict()).lower()
            for forbidden in ("private", "secret", "seed", "bearer ", "eyj"):
                assert forbidden not in payload
