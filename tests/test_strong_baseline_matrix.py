"""The strong-baseline matrix: four scenarios x four arms (EXP2 STEP 11-12).

`B0` as the unprotected control, plus the three arms that receive per-hop
`C_i` and exist today: `B2-exchange-task`, `B-cap`, `B3`. Every cell is run
once, through the real runner over the real AS, and compared to **SS E.4's
prediction**. A cell that disagreed with the prediction would be a finding to
report, not a number to adjust -- so the predictions are written out here as
data and asserted cell by cell.

`gt-f1-chain-tamper` is **NA** for `B0` (SS E.3: no per-hop authority chain to
tamper with). NA is read from the sealed record and the cell is **not run**:
an NA cell is not a result and must never be scored as one.

The two mechanisms realize the same tamper INTENT differently, and this file
records which refusal produced each block:

* `B2-exchange-task` -- the exchange request would widen, the pinned AS
  profile refuses it as `invalid_authorization_details` / `widening-rar`, and
  **no token is issued**; the delegate presents nothing.
* `B-cap` and `B3` -- the widening block is appended and **verifies
  cryptographically** under `kappa_pub` (`crypto_chain_ok` passes), yet carries
  no authority under block scoping, so the block falls where an F1 block
  should: at containment.

Nothing here is timed (EXP2 forbidden action 5). Platform-independent: every
cell runs without the effect ledger, which changes no admission outcome.
"""

import json
from pathlib import Path

import pytest

from src.harness import key_material
from src.harness.as_process import ASProcess, golden_thread_as_document
from src.harness.authorizer import frozen_config
from src.harness.runner import GoldenThreadRunner
from src.harness.verifier import registry as reg
from src.sut.baselines.b0 import B0Arm
from src.sut.baselines.b2_exchange_task import B2ExchangeTaskArm
from src.sut.baselines.b3 import B3Arm
from src.sut.baselines.b_cap import BCapArm

REPO_ROOT = Path(__file__).resolve().parents[1]
SEED = bytes.fromhex("e1" * 32)
CORPUS = REPO_ROOT / "fixtures" / "pilot" / "golden_thread"
ISSUER = "https://as.aasc.local"
AUDIENCE = "https://mcp.aasc.local/tools"

SCENARIOS = ("gt-benign", "gt-f1-root", "gt-f1-terminal", "gt-f1-chain-tamper")
ARMS = ("B0", "B2-exchange-task", "B-cap", "B3")

# SS E.4's expected matrix for the arms that exist, as (admitted, reason_code).
# `gt-benign` is the false-blocking control and is not in SS E.4's table; every
# arm must admit it, or the F1 blocks below would be uninformative.
EXPECTED = {
    ("gt-benign", "B0"): (True, "b0_no_boundary_check"),
    ("gt-benign", "B2-exchange-task"): (True, "b2_admitted"),
    ("gt-benign", "B-cap"): (True, "b3_admitted"),
    ("gt-benign", "B3"): (True, "b3_admitted"),
    ("gt-f1-root", "B0"): (True, "b0_no_boundary_check"),  # SS E.4: A -- the vulnerability
    ("gt-f1-root", "B2-exchange-task"): (False, "b2_token_scope"),
    ("gt-f1-root", "B-cap"): (False, "b3_containment"),
    ("gt-f1-root", "B3"): (False, "b3_containment"),
    ("gt-f1-terminal", "B0"): (True, "b0_no_boundary_check"),
    ("gt-f1-terminal", "B2-exchange-task"): (False, "b2_token_scope"),
    ("gt-f1-terminal", "B-cap"): (False, "b3_containment"),
    ("gt-f1-terminal", "B3"): (False, "b3_containment"),
    # ("gt-f1-chain-tamper", "B0") is NA and is not run.
    ("gt-f1-chain-tamper", "B2-exchange-task"): (False, "b2_exchange_refused"),
    ("gt-f1-chain-tamper", "B-cap"): (False, "b3_containment"),
    ("gt-f1-chain-tamper", "B3"): (False, "b3_containment"),
}


def _sealed(scenario_id: str) -> dict:
    return json.loads((CORPUS / "sealed" / f"{scenario_id}.json").read_text(encoding="utf-8"))


def _visible(scenario_id: str) -> dict:
    return json.loads((CORPUS / "sut_visible" / f"{scenario_id}.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def running_as():
    registry_document = reg.load_document()
    document = golden_thread_as_document(
        corpus={"issuer": ISSUER, "audience": AUDIENCE},
        registry_document=registry_document,
        resolved_keys=key_material.resolve_public(SEED),
        identity_jwks=key_material.identity_jwks(SEED, registry_document["principals"]),
        omega_elements=frozen_config.load_document()["omega"]["elements"],
        # One AS serves every arm: `task_grant` narrows only the DELEGATING
        # client's base token, and `B3`/`B-cap` present the specialist's, which
        # stays the coarse ADR 0021 base `AT@aud`.
        task_grant=_visible("gt-benign")["authority_elements"],
    )
    with ASProcess(document, SEED) as process:
        yield process


@pytest.fixture(scope="module")
def matrix(running_as):
    """Every applicable cell, run exactly once. Returns (scenario, arm) -> record."""
    runner = GoldenThreadRunner()
    b3_setup = runner.b3_setup(
        access_token=running_as.phase1_tokens["agent-specialist"],
        as_public_jwk=running_as.public_jwk,
    )
    b2_setup = runner.b2_setup(
        access_token=running_as.phase1_tokens["agent-supervisor"],
        as_public_jwk=running_as.public_jwk,
        as_port=running_as.port,
        as_tls_cert_pem=running_as.tls_cert_pem,
    )
    factories = {
        "B0": (B0Arm, {}),
        "B2-exchange-task": (B2ExchangeTaskArm, b2_setup),
        "B-cap": (BCapArm, b3_setup),
        "B3": (B3Arm, b3_setup),
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


# --------------------------------------------------------------------------
# The matrix, cell by cell against SS E.4
# --------------------------------------------------------------------------
class TestTheMatrixAgreesWithTheSpecification:
    @pytest.mark.parametrize("cell", sorted(EXPECTED))
    def test_cell(self, matrix, cell):
        expected = EXPECTED[cell]
        record = matrix[cell]
        assert (record["admitted"], record["reason_code"]) == expected, (
            f"{cell} produced {(record['admitted'], record['reason_code'])}, "
            f"SS E.4 predicts {expected} -- a disagreement is a FINDING, not a "
            f"number to adjust"
        )

    def test_every_applicable_cell_was_run(self, matrix):
        """No cell is silently skipped, and none is silently added."""
        assert set(matrix) == set(EXPECTED)

    def test_b0_is_na_on_chain_tamper_and_was_not_run(self, matrix):
        """SS E.3. NA is not a result: `B0` has no per-hop authority chain."""
        assert ("gt-f1-chain-tamper", "B0") not in matrix
        sealed = _sealed("gt-f1-chain-tamper")
        assert "B0" in sealed["not_applicable"]["arms"]
        assert "no per-hop authority chain" in sealed["not_applicable"]["reason"]
        # Negative arm: `B0` IS applicable everywhere else, and admits there --
        # so the NA is about this subcase, not about B0 being unrunnable.
        assert matrix[("gt-f1-root", "B0")]["admitted"] is True

    def test_b0_admits_both_f1_subcases(self, matrix):
        """SS E.1: what `B0` isolates is that the vulnerability EXISTS.

        These two admissions are the measured phenomenon, not a bug.
        """
        assert matrix[("gt-f1-root", "B0")]["admitted"] is True
        assert matrix[("gt-f1-terminal", "B0")]["admitted"] is True

    def test_every_strong_arm_blocks_every_f1_subcase(self, matrix):
        for scenario_id in ("gt-f1-root", "gt-f1-terminal", "gt-f1-chain-tamper"):
            for arm_name in ("B2-exchange-task", "B-cap", "B3"):
                assert matrix[(scenario_id, arm_name)]["admitted"] is False, (
                    f"{arm_name} admitted {scenario_id}"
                )
        # Negative arm: all three admit the benign call, so the blocks above
        # are not an arm that refuses everything.
        for arm_name in ("B2-exchange-task", "B-cap", "B3"):
            assert matrix[("gt-benign", arm_name)]["admitted"] is True

    def test_b3_blocking_where_b2_blocks_is_not_an_advantage(self, matrix):
        """SS E.1's honest headline, asserted as a property of the matrix.

        On F1, `B2-exchange-task` and `B3` agree on every cell -- a
        well-configured token-exchange deployment prevents scope amplification
        because it enforces the same narrowed `C_n`. The arms differ on other
        axes and other families, which this pass does not measure.
        """
        for scenario_id in ("gt-f1-root", "gt-f1-terminal", "gt-f1-chain-tamper"):
            b2 = matrix[(scenario_id, "B2-exchange-task")]["admitted"]
            b3 = matrix[(scenario_id, "B3")]["admitted"]
            assert b2 == b3 is False


# --------------------------------------------------------------------------
# `gt-f1-chain-tamper`: which refusal produced each block
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

    def test_b2_the_as_refused_and_issued_no_token(self, matrix):
        record = matrix[("gt-f1-chain-tamper", "B2-exchange-task")]
        arm = record["arm"]
        assert record["reason_code"] == "b2_exchange_refused"
        assert arm.exchanges[-1]["issued"] is False
        assert "invalid_authorization_details" in arm.audit_log[-1]["detail"]
        # No token issued means nothing to present: the SS F.1 bundle is empty.
        evidence = record["run"].observed.evidence
        assert evidence.oauth is None and evidence.capability is None
        # Negative arm: the same arm on the benign scenario DID get a token.
        benign = matrix[("gt-benign", "B2-exchange-task")]
        assert benign["arm"].exchanges[-1]["issued"] is True
        assert benign["run"].observed.evidence.oauth is not None

    @pytest.mark.parametrize("arm_name", ["B-cap", "B3"])
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

    @pytest.mark.parametrize("arm_name", ["B-cap", "B3"])
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
