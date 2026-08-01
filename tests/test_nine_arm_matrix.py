"""The complete SS E.1 ladder: nine arms x four pilot scenarios (EXP3 STEP 12).

Every cell is run **once**, through the real runner over the real AS, and
compared to **SS E.4's prediction** cell by cell. The predictions are written
out here as data because *a cell that disagrees with SS E.4 is a finding to
report, not a number to adjust -- and neither is the prediction to be edited to
match the cell*.

**The broad arms admitting `F1-root` and `F1-terminal` is the PREDICTED
result.** It is what the study exists to measure -- that a static secret adds
nothing, that audience binding alone does not attenuate, and that a broad
exchange narrows nothing -- not a defect to be fixed.

`gt-f1-chain-tamper` is **NA** for the four arms with no per-hop authority
chain (SS E.3: `B0`, `B1`, `B2-broad-noexchange`, `B2-exchange-broad`). NA is
read from the sealed record and the cell is **not run**: an NA cell is not a
result and must never be scored as one.

Nothing here is timed (EXP3 forbidden action 1). Platform-independent: every
cell runs without the effect ledger, which changes no admission outcome.

**The grouping, and why it is imported rather than local** (EXP4 STEP 12,
discharging this module's forward note). F1's grouping is a **ladder property**:
an arm either receives per-hop `C_i` or it does not, and no configuration moves
it. F4/F5's is a **configuration condition** -- SS E.4 marks the OAuth arms
`A-dagger`, *admitted ABSENT the shared monitor*, and they block WITH it. Both
groupings now live in `src/harness/matrix_grouping.py`, so extending the matrix
means choosing one rather than copying a tuple: a family is declared LADDER or
CONFIGURATION, and a configuration family's cell cannot be constructed without
its `monitor_attached`. Flattening such a cell into a plain `A` would report a
reference-monitor-configuration difference as a capability-versus-OAuth
advantage, which is the precise error gate **G-15** exists to prevent.
"""

import json
from pathlib import Path

import pytest

from src.harness import key_material
from src.harness import matrix_grouping as grouping
from src.harness.as_process import ASProcess, golden_thread_as_document
from src.harness.authorizer import frozen_config
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
SEED = bytes.fromhex("e1" * 32)
CORPUS = REPO_ROOT / "fixtures" / "pilot" / "golden_thread"
ISSUER = "https://as.aasc.local"
AUDIENCE = "https://mcp.aasc.local/tools"

SCENARIOS = ("gt-benign", "gt-f1-root", "gt-f1-terminal", "gt-f1-chain-tamper")
# SS E.1's ladder and F1's grouping, now imported from `matrix_grouping` rather
# than hardcoded here (EXP4 STEP 12). The forward note below said this table
# derived its grouping from a local `STRONG` tuple and that the shape was right
# for F1 and wrong for F4/F5; that is now expressed rather than warned about --
# `STRONG` is F1's LADDER grouping, and F4/F5's CONFIGURATION grouping lives
# beside it in the same module. `tests/test_f45_matrix.py` uses the other one.
ARMS = grouping.ARMS
STRONG = grouping.STRONG

_ADMIT = {
    "B0": "b0_no_boundary_check",
    "B1": "b1_admitted",
    "B2-broad-noexchange": "b2_admitted",
    "B2-exchange-broad": "b2_admitted",
    "B2-exchange-task": "b2_admitted",
    "B2-exchange-task-DPoP": "b2_admitted",
    "B-cap": "b3_admitted",
    "B3": "b3_admitted",
    "B3+": "b3_admitted",
}
_F1_BLOCK = {
    "B2-exchange-task": "b2_token_scope",
    "B2-exchange-task-DPoP": "b2_token_scope",
    "B-cap": "b3_containment",
    "B3": "b3_containment",
    "B3+": "b3_containment",
}
_TAMPER_BLOCK = dict(
    _F1_BLOCK,
    **{
        "B2-exchange-task": "b2_exchange_refused",
        "B2-exchange-task-DPoP": "b2_exchange_refused",
    },
)

# SS E.4's expected matrix for the nine arms, as (admitted, reason_code).
# `gt-benign` is the false-blocking control and is not in SS E.4's table; every
# arm must admit it, or the F1 rows below would be uninformative.
EXPECTED: dict[tuple[str, str], tuple[bool, str]] = {}
for _arm in ARMS:
    EXPECTED[("gt-benign", _arm)] = (True, _ADMIT[_arm])
for _scenario in ("gt-f1-root", "gt-f1-terminal"):
    for _arm in ARMS:
        EXPECTED[(_scenario, _arm)] = (
            (False, _F1_BLOCK[_arm]) if _arm in STRONG else (True, _ADMIT[_arm])
        )
for _arm in STRONG:  # the other four are NA and are not run
    EXPECTED[("gt-f1-chain-tamper", _arm)] = (False, _TAMPER_BLOCK[_arm])


def _visible(scenario_id: str) -> dict:
    return json.loads((CORPUS / "sut_visible" / f"{scenario_id}.json").read_text(encoding="utf-8"))


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
        # ONE AS serves all nine arms. `task_grant` narrows the delegating
        # client's base token to `C_0 = U_task` (ADR 0024) and mints the same
        # client a named coarse `Omega` grant for the broad rows (ADR 0029).
        task_grant=runner.task_grant("gt-benign"),
    )


@pytest.fixture(scope="module")
def running_as(as_document):
    with ASProcess(as_document, SEED) as process:
        yield process


@pytest.fixture(scope="module")
def matrix(runner, running_as, as_document):
    """Every applicable cell, run exactly once. (scenario, arm) -> record."""
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
    factories = {
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
    cells: dict[tuple[str, str], dict] = {}
    opened: list = []
    try:
        for scenario_id in SCENARIOS:
            not_applicable = set(_sealed(scenario_id)["not_applicable"]["arms"])
            for arm_name in ARMS:
                if arm_name in not_applicable:
                    continue
                factory, setup = factories[arm_name]
                arm = factory()
                opened.append(arm)
                run = runner.run_scenario(scenario_id, arm, setup=setup, ledger_backed=False)
                event = run.mediation_events[-1]
                cells[(scenario_id, arm_name)] = {
                    "admitted": event.admitted,
                    "reason_code": event.reason_code,
                    "arm": arm,
                    "run": run,
                }
        yield cells
    finally:
        for arm in opened:
            if hasattr(arm, "close"):
                arm.close()


class TestTheMatrixAgreesWithTheSpecification:
    @pytest.mark.parametrize("cell", sorted(EXPECTED))
    def test_cell(self, matrix, cell):
        expected = EXPECTED[cell]
        record = matrix[cell]
        assert (record["admitted"], record["reason_code"]) == expected, (
            f"{cell} produced {(record['admitted'], record['reason_code'])}, "
            f"SS E.4 predicts {expected} -- a disagreement is a FINDING, and neither "
            f"the cell nor the prediction may be adjusted toward the other"
        )

    def test_every_applicable_cell_was_run(self, matrix):
        """No cell silently skipped, none silently added, all nine arms present."""
        assert set(matrix) == set(EXPECTED)
        assert {arm for _, arm in matrix} == set(ARMS)
        assert len(ARMS) == 9

    def test_the_na_cells_are_read_from_the_record_and_not_run(self, matrix):
        sealed = _sealed("gt-f1-chain-tamper")
        na = set(sealed["not_applicable"]["arms"])
        assert na == {"B0", "B1", "B2-broad-noexchange", "B2-exchange-broad"}
        assert "no per-hop authority chain" in sealed["not_applicable"]["reason"]
        for arm_name in na:
            assert ("gt-f1-chain-tamper", arm_name) not in matrix
            # Negative arm: each IS applicable elsewhere, and admits there --
            # so the NA is about this subcase, not about the arm.
            assert matrix[("gt-f1-root", arm_name)]["admitted"] is True

    def test_the_weak_arms_admit_both_f1_subcases(self, matrix):
        """SS E.1's `Isolates` column, measured.

        `B0`: the vulnerability exists. `B1`: a static secret adds nothing.
        `B2-broad-noexchange`: audience binding alone does not attenuate.
        `B2-exchange-broad`: the round trip without narrowing narrows nothing.
        These admissions are the measured phenomenon, not defects.
        """
        weak = [arm for arm in ARMS if arm not in STRONG]
        assert weak == ["B0", "B1", "B2-broad-noexchange", "B2-exchange-broad"]
        for scenario_id in ("gt-f1-root", "gt-f1-terminal"):
            for arm_name in weak:
                assert matrix[(scenario_id, arm_name)]["admitted"] is True

    def test_every_strong_arm_blocks_every_f1_subcase(self, matrix):
        for scenario_id in ("gt-f1-root", "gt-f1-terminal", "gt-f1-chain-tamper"):
            for arm_name in STRONG:
                assert matrix[(scenario_id, arm_name)]["admitted"] is False, (
                    f"{arm_name} admitted {scenario_id}"
                )
        # Negative arm: every arm on the ladder admits the benign call, so no
        # block above is an arm refusing everything.
        for arm_name in ARMS:
            assert matrix[("gt-benign", arm_name)]["admitted"] is True

    def test_the_exchange_round_trip_is_isolated_from_narrowing(self, matrix):
        """The pair of arms that makes the isolation readable.

        `B2-exchange-broad` and `B2-exchange-task` both perform a real online
        exchange; they differ only in whether it narrows. They therefore differ
        on F1 exactly where narrowing matters -- which is what lets a later
        cost comparison attribute the round trip separately from its effect.
        """
        for scenario_id in ("gt-f1-root", "gt-f1-terminal"):
            assert matrix[(scenario_id, "B2-exchange-broad")]["admitted"] is True
            assert matrix[(scenario_id, "B2-exchange-task")]["admitted"] is False
        broad = matrix[("gt-benign", "B2-exchange-broad")]["arm"]
        task = matrix[("gt-benign", "B2-exchange-task")]["arm"]
        assert broad.exchanges[-1]["issued"] is True
        assert task.exchanges[-1]["issued"] is True

    def test_the_two_no_exchange_rows_never_dialled(self, matrix):
        """`B0` and `B1` have no AS at all; `B2-broad-noexchange` has one and
        does not use it -- which is the difference the ladder measures."""
        no_exchange = matrix[("gt-benign", "B2-broad-noexchange")]["arm"]
        assert no_exchange.exchanges[-1]["exchanged"] is False
        assert no_exchange._connection is None

    def test_dpop_adds_binding_and_not_authority(self, matrix):
        """Every F1 cell is identical to `B2-exchange-task`'s.

        SS D: DPoP closes T-reuse; it changes no authority set, which is why
        G-13 can treat the two arms as realizing the same `C_0 -> C_n`.
        """
        for scenario_id in SCENARIOS:
            plain = matrix[(scenario_id, "B2-exchange-task")]
            bound = matrix[(scenario_id, "B2-exchange-task-DPoP")]
            assert (plain["admitted"], plain["reason_code"]) == (
                bound["admitted"],
                bound["reason_code"],
            )

    def test_the_jti_cache_adds_duplicate_detection_and_not_authority(self, matrix):
        """Every `B3+` cell is identical to `B3`'s over the pilot corpus.

        The corpus carries no bit-identical replay -- that is an F3 fixture and
        is not built here (EXP3 forbidden action 7) -- so on these four
        scenarios the cache changes nothing, which is exactly right: it adds
        duplicate detection, not authority. `tests/test_b3_plus.py` exercises
        the one cell where they differ.
        """
        for scenario_id in SCENARIOS:
            plain = matrix[(scenario_id, "B3")]
            plus = matrix[(scenario_id, "B3+")]
            assert (plain["admitted"], plain["reason_code"]) == (
                plus["admitted"],
                plus["reason_code"],
            )


class TestTheEvidenceEachArmPresents:
    """SS F.1 bundles, so the ladder is readable off the record too."""

    def test_each_arm_presents_what_its_part_c_row_says(self, matrix):
        evidence = {arm: matrix[("gt-benign", arm)]["run"].observed.evidence for arm in ARMS}
        # B0: a plain call.
        assert evidence["B0"].oauth is None and evidence["B0"].capability is None
        assert evidence["B0"].api_key is None
        # B1: an API key reference and nothing else.
        assert evidence["B1"].api_key is not None
        assert evidence["B1"].oauth is None and evidence["B1"].capability is None
        # Every OAuth arm: a bearer token, no capability.
        for arm in (
            "B2-broad-noexchange",
            "B2-exchange-broad",
            "B2-exchange-task",
            "B2-exchange-task-DPoP",
        ):
            assert evidence[arm].oauth is not None, arm
            assert evidence[arm].capability is None, arm
            assert evidence[arm].api_key is None, arm
        # B-cap: a capability with NO holder plane.
        assert evidence["B-cap"].capability is not None
        assert evidence["B-cap"].capability.htc_chain == []
        assert evidence["B-cap"].capability.invocation_assertion == b""
        # B3 and B3+: capability + HTC chain + INV.
        for arm in ("B3", "B3+"):
            capability = evidence[arm].capability
            assert capability is not None and len(capability.htc_chain) == 2
            assert capability.invocation_assertion != b""


# --------------------------------------------------------------------------
# `gt-f1-chain-tamper`: which refusal produced each block, over five arms
# --------------------------------------------------------------------------
class TestChainTamperAttribution:
    def test_the_scenario_declares_an_intent_not_a_realization(self):
        visible = _visible("gt-f1-chain-tamper")
        assert visible["widening_elements"] == [["mail.send", "mail/outbox"]]
        # Negative arm: the benign scenarios declare none, so the field is the
        # tamper and not a fixture-wide constant.
        assert _visible("gt-benign")["widening_elements"] == []

    def test_the_widening_target_is_inside_omega_and_outside_c0(self):
        """Otherwise it would not be a widening at all.

        Outside `Omega` and every mechanism refuses it as malformed; inside
        `C_0` and it grants nothing new.
        """
        omega = frozenset((a, r) for a, r in frozen_config.load_document()["omega"]["elements"])
        target = frozenset({("mail.send", "mail/outbox")})
        c0 = frozenset(map(tuple, _sealed("gt-f1-chain-tamper")["C_sets"][0]))
        assert target <= omega
        assert not target & c0

    @pytest.mark.parametrize("arm_name", ["B2-exchange-task", "B2-exchange-task-DPoP"])
    def test_the_exchange_arms_were_refused_and_issued_no_token(self, matrix, arm_name):
        record = matrix[("gt-f1-chain-tamper", arm_name)]
        arm = record["arm"]
        assert record["reason_code"] == "b2_exchange_refused"
        assert arm.exchanges[-1]["issued"] is False
        assert "invalid_authorization_details" in arm.audit_log[-1]["detail"]
        # No token issued means nothing to present: the SS F.1 bundle is empty.
        evidence = record["run"].observed.evidence
        assert evidence.oauth is None and evidence.capability is None
        # Negative arm: the same arm on the benign scenario DID get a token.
        benign = matrix[("gt-benign", arm_name)]
        assert benign["arm"].exchanges[-1]["issued"] is True
        assert benign["run"].observed.evidence.oauth is not None

    @pytest.mark.parametrize("arm_name", ["B-cap", "B3", "B3+"])
    def test_capability_arms_the_widening_block_verifies_but_grants_nothing(self, matrix, arm_name):
        """The tamper is cryptographically valid and authoritatively empty.

        `crypto_chain_ok` passed -- the appended block really does verify under
        `kappa_pub` -- and the block still fell at containment, because block
        scoping lets a later block narrow what block 0 granted and never widen
        it. That is the property SS E.3 predicts for the capability arms.
        """
        record = matrix[("gt-f1-chain-tamper", arm_name)]
        arm = record["arm"]
        assert record["reason_code"] == "b3_containment"
        evaluated = arm.audit_log[-1]["evaluated"]
        # A conjunct is appended only AFTER it succeeds, so these two say
        # exactly what happened: the appended block verified under `kappa_pub`,
        # and containment is the conjunct that refused.
        assert "crypto_chain_ok" in evaluated, "the widening block failed to verify at all"
        assert "authorizer_policy_ok" in evaluated
        assert "containment_ok" not in evaluated
        # And the element it refused is the one the tamper tried to add.
        assert "('mail.send', 'mail/outbox')" in arm.audit_log[-1]["detail"]
        assert "R exceeds C_n" in arm.audit_log[-1]["detail"]

    @pytest.mark.parametrize("arm_name", ["B-cap", "B3", "B3+"])
    def test_the_tampered_chain_is_a_prefix_extension_of_the_untampered_one(self, matrix, arm_name):
        """The tamper is in the appended block, not a forged root.

        Two signed blocks, exactly as the benign hop produces -- so the arm is
        rejecting the tamper's AUTHORITY, not its shape.
        """
        tampered = matrix[("gt-f1-chain-tamper", arm_name)]["run"].observed.evidence.capability
        benign = matrix[("gt-benign", arm_name)]["run"].observed.evidence.capability
        assert len(tampered.signed_blocks) == len(benign.signed_blocks) == 2
        # Negative arm: the bytes DO differ, so the widening really is carried.
        assert tampered.signed_blocks[1] != benign.signed_blocks[1]

    def test_c_sets_are_unchanged_by_the_attempt(self):
        """That the tamper changes nothing is the measurement.

        The sealed sets are the legitimate chain's throughout, and the
        generator recomputes them with the frozen authorizer rather than
        copying them from another scenario.
        """
        tamper = _sealed("gt-f1-chain-tamper")
        benign = _sealed("gt-benign")
        assert tamper["C_sets"] == benign["C_sets"]
        assert tamper["U_task"] == benign["U_task"]
        # Negative arm: the two scenarios are not identical -- R and the
        # subcase differ, which is what makes the equality above informative.
        assert tamper["R"] != benign["R"]
        assert tamper["attack_subcase"] == "F1:chain-tamper"
