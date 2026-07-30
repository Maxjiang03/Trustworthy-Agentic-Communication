"""The golden thread under B3, and the would-have-failed worlds (EXP1 STEP 13).

Two things are proven here, and the second is the one that has caught a real
error every round:

1. **B3 on the three pilot scenarios.** `gt-benign` is admitted; `gt-f1-root`
   and `gt-f1-terminal` are blocked at `R subset-of C_n` with that reason
   code and **no EffectEvent in the ledger** -- the LEDGER, not the agent, is
   what shows nothing executed.
2. **The wrong-outcome world is observable.** For each block, disabling the
   containment conjunct shows the call *would* be admitted -- so the block is
   attributable to containment and not masked by an earlier conjunct (the
   G-11 masking lesson). The same construction runs for `htc_chain_ok` and
   `invocation_binding_ok` with a wrong-holder INV and a tool/argument
   substitution.

Windows-only where the effect ledger is involved (ADR 0014); the
decision-path-only tests run everywhere.
"""

import json
import shutil
import sys
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.harness import key_material
from src.harness.as_process import ASProcess, golden_thread_as_document
from src.harness.authorizer import frozen_config
from src.harness.runner import GoldenThreadRunner
from src.harness.verifier import registry as reg
from src.sut.authz.capability_path import REASON_CODES
from src.sut.baselines.b3 import B3Arm
from src.sut.capability import signer

REPO_ROOT = Path(__file__).resolve().parents[1]
SEED = bytes.fromhex("e1" * 32)

WIN32_ONLY = pytest.mark.skipif(
    sys.platform != "win32",
    reason="ADR 0014 (recorded platform decision, not a gap): the ledger's independence "
    "enforcement is Win32 share-mode locking (CreateFileW, FILE_SHARE_READ only), which has "
    "no direct POSIX equivalent; Windows is the sealed measurement platform and the POSIX "
    "variant is deferred to after submission",
)


def _identity_jwks(registry_document: dict) -> dict[str, dict[str, str]]:
    return {
        principal: {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": key_material.public_wire(
                key_material.holder_private(SEED, f"identity-{principal}")
            ),
        }
        for principal in registry_document["principals"]
    }


@pytest.fixture(scope="module")
def running_as():
    registry_document = reg.load_document()
    document = golden_thread_as_document(
        corpus={"issuer": "https://as.aasc.local", "audience": "https://mcp.aasc.local/tools"},
        registry_document=registry_document,
        resolved_keys=key_material.resolve_public(SEED),
        identity_jwks=_identity_jwks(registry_document),
        omega_elements=frozen_config.load_document()["omega"]["elements"],
    )
    with ASProcess(document, SEED) as process:
        yield process


@pytest.fixture(scope="module")
def ledger_dir():
    directory = REPO_ROOT / "tests" / "_ledger_tmp_gt_b3"
    directory.mkdir(parents=True, exist_ok=True)
    yield directory
    shutil.rmtree(directory, ignore_errors=True)


def _setup(runner: GoldenThreadRunner, running_as) -> dict:
    return runner.b3_setup(
        access_token=running_as.phase1_tokens["agent-specialist"],
        as_public_jwk=running_as.public_jwk,
    )


@WIN32_ONLY
class TestB3EndToEnd:
    @pytest.fixture(scope="class")
    @staticmethod
    def runs(ledger_dir, running_as):
        runner = GoldenThreadRunner(ledger_dir=ledger_dir)
        setup = _setup(runner, running_as)
        return {
            scenario_id: runner.run_scenario(scenario_id, B3Arm(), setup=setup)
            for scenario_id in ("gt-benign", "gt-f1-root", "gt-f1-terminal")
        }

    def test_benign_is_admitted_and_the_effect_is_recorded(self, runs):
        run = runs["gt-benign"]
        assert run.mediation_events[-1].admitted is True
        assert run.mediation_events[-1].reason_code == "b3_admitted"
        effects = run.effects()
        assert len(effects) == 1
        assert (effects[0]["action"], effects[0]["resource"]) == ("notes.write", "notes/project")

    def test_f1_root_blocked_at_containment_with_no_effect(self, runs):
        run = runs["gt-f1-root"]
        event = run.mediation_events[-1]
        assert event.admitted is False
        assert event.reason_code == REASON_CODES["containment_ok"]
        # The ledger -- not the agent -- shows nothing executed.
        assert run.effects() == []
        assert run.ledger_entries() == []

    def test_f1_terminal_blocked_at_containment_with_no_effect(self, runs):
        run = runs["gt-f1-terminal"]
        event = run.mediation_events[-1]
        assert event.admitted is False
        assert event.reason_code == REASON_CODES["containment_ok"]
        assert run.effects() == []

    def test_every_earlier_conjunct_passed_before_the_block(self, runs):
        """The block is attributable: the audit log shows containment was
        reached, so no earlier conjunct masked it."""
        for scenario_id in ("gt-f1-root", "gt-f1-terminal"):
            entry = runs[scenario_id].audit_log[-1]
            assert entry["reason_code"] == REASON_CODES["containment_ok"]
            assert entry["evaluated"] == [
                "crypto_chain_ok",
                "authorizer_policy_ok",
                "htc_chain_ok",
                "holder_proof_ok",
                "invocation_binding_ok",
            ]

    def test_timing_seams_exist_and_are_unmeasured(self, runs):
        # EXP1 STEP 14: the seams exist and are correlated; this suite asserts
        # their PRESENCE and never a duration (forbidden action 4).
        run = runs["gt-benign"]
        assert run.timing is not None
        assert run.timing.correlation_id == run.correlation_id
        assert set(run.timing.recorded()) == {
            "setup",
            "delegation",
            "boundary_verification",
            "end_to_end",
        }


class TestWouldHaveFailedWorlds:
    """Construct the wrong-outcome world and confirm it is observable."""

    @pytest.fixture(scope="class")
    @staticmethod
    def staged(running_as):
        """A provisioned B3 arm with a real staged presentation, no ledger needed."""
        # The setup mapping is assembled directly here (no ledger directory):
        # these tests exercise the decision path alone.
        from src.harness import as_process

        policy = json.loads(
            (REPO_ROOT / "fixtures" / "pilot" / "policies" / "pilot_policy_v0.json").read_text(
                encoding="utf-8"
            )
        )
        setup = {
            "gamma_document": frozen_config.load_document(),
            "registry_document": reg.load_document(),
            "resolved_keys": key_material.resolve_public(SEED),
            "kappa_private": key_material.derive_raw(SEED, "kappa"),
            "holder_privates": {
                label: key_material.derive_raw(SEED, label)
                for label in ("holder-supervisor", "holder-specialist", "holder-worker")
            },
            "access_token": running_as.phase1_tokens["agent-specialist"],
            "as_public_jwk": running_as.public_jwk,
            "issuer": "https://as.aasc.local",
            "resource_server": "https://mcp.aasc.local/tools",
            "rar_type": as_process.RAR_TYPE,
            "pilot_policy": policy,
            "run_mode": "pilot",
        }
        visible = json.loads(
            (
                REPO_ROOT
                / "fixtures"
                / "pilot"
                / "golden_thread"
                / "sut_visible"
                / "gt-benign.json"
            ).read_text(encoding="utf-8")
        )
        return setup, visible

    def _arm_with_presentation(self, setup, visible, *, tool, arguments, disabled=frozenset()):
        from src.sut.baselines.base import HopContext, InvocationContext

        run_epoch = int(time.time())  # one clock for the whole construction
        arm = B3Arm()
        arm.provision(setup)
        if disabled:
            arm._decision_path._disabled = disabled
        hop = HopContext(
            task_id=visible["task_id"],
            audience=visible["audience"],
            from_agent=visible["supervisor"],
            to_agent=visible["specialist"],
            authority_elements=tuple(map(tuple, visible["authority_elements"])),
            attenuation_elements=tuple(map(tuple, visible["attenuation_elements"])),
            now_epoch=run_epoch,
            expiry_epoch=run_epoch + int(visible["validity_seconds"]),
        )
        credentials = arm.delegate(hop)
        arm.present(
            credentials,
            InvocationContext(
                tool=tool,
                arguments=arguments,
                method=visible["method"],
                task_id=visible["task_id"],
                audience=visible["audience"],
                invocation_id="cid-counterfactual",
                now_epoch=run_epoch,
            ),
        )
        return arm, credentials

    # -- containment: the F1 blocks are attributable, not masked ------------ #
    @pytest.mark.parametrize(
        "tool,arguments",
        [
            ("mail.send", {"to": "partner@example.test", "subject": "s", "body": "b"}),
            ("calendar.read", {"resource": "calendar/work"}),
        ],
    )
    def test_containment_block_would_be_admitted_without_the_conjunct(
        self, staged, tool, arguments
    ):
        setup, visible = staged
        arm, _ = self._arm_with_presentation(setup, visible, tool=tool, arguments=arguments)
        admitted, reason = arm.decide(tool, arguments)
        assert admitted is False
        assert reason == REASON_CODES["containment_ok"]

        # The would-have-failed world: containment disabled, everything else on.
        ablated, _ = self._arm_with_presentation(
            setup, visible, tool=tool, arguments=arguments, disabled=frozenset({"containment_ok"})
        )
        assert ablated.decide(tool, arguments) == (True, "b3_admitted"), (
            "with containment disabled the call must be ADMITTED -- otherwise the block "
            "was masked by another conjunct, not attributable to containment"
        )

    # -- htc_chain_ok: a wrong-holder INV ----------------------------------- #
    def test_wrong_holder_inv_blocks_and_is_attributable(self, staged):
        setup, visible = staged
        tool, arguments = "notes.write", {"resource": "notes/project", "content": "x"}
        arm, credentials = self._arm_with_presentation(
            setup, visible, tool=tool, arguments=arguments
        )
        assert arm.decide(tool, arguments) == (True, "b3_admitted")  # baseline: admitted

        # Re-sign the INV with a REGISTERED but wrong holder (the worker), so
        # the registry check passes and only the holder limb can catch it --
        # the G-11 construction that isolates the intended condition.
        wrong = Ed25519PrivateKey.from_private_bytes(setup["holder_privates"]["holder-worker"])
        terminal = signer.MintedHop(
            bytes(credentials["capability_hops"][-1]),
            tuple(bytes(b) for b in credentials["block_ids"][-1]),
        )
        forged = signer.issue_inv(
            terminal,
            holder_private=wrong,
            holder_kid="kid-holder-worker",
            raw_at=credentials["access_token"],
            raw_arguments=arguments,
            task_id=visible["task_id"],
            audience=visible["audience"],
            method=visible["method"],
            tool=tool,
            label_assertions_digest="00" * 32,
            invocation_id="cid-counterfactual",
            iat=int(time.time()),
            nbf=int(time.time()),
            exp=int(time.time()) + 300,
        )
        import dataclasses

        arm._staged = dataclasses.replace(arm._staged, invocation_assertion=forged)
        admitted, reason = arm.decide(tool, arguments)
        assert admitted is False
        assert reason == REASON_CODES["holder_proof_ok"]

        # Would-have-failed world: with the holder limb disabled, the same
        # forged INV is admitted -- the block was that limb's, not another's.
        arm._decision_path._disabled = frozenset({"holder_proof_ok"})
        assert arm.decide(tool, arguments) == (True, "b3_admitted")

    # -- invocation_binding_ok: tool and argument substitution -------------- #
    def test_tool_substitution_blocks_at_invocation_binding(self, staged):
        setup, visible = staged
        signed_tool = "notes.write"
        arguments = {"resource": "notes/project", "content": "x"}
        arm, _ = self._arm_with_presentation(setup, visible, tool=signed_tool, arguments=arguments)
        # Substitute the TOOL after signing, keeping arguments in-scope for the
        # substituted tool so containment cannot be what blocks.
        substituted_args = {"resource": "notes/project"}
        admitted, reason = arm.decide("notes.read", substituted_args)
        assert admitted is False
        assert reason == REASON_CODES["invocation_binding_ok"]

        arm._decision_path._disabled = frozenset({"invocation_binding_ok"})
        assert arm.decide("notes.read", substituted_args) == (True, "b3_admitted")

    def test_argument_substitution_blocks_at_invocation_binding(self, staged):
        setup, visible = staged
        tool = "notes.write"
        arm, _ = self._arm_with_presentation(
            setup, visible, tool=tool, arguments={"resource": "notes/project", "content": "x"}
        )
        tampered = {"resource": "notes/project", "content": "TAMPERED"}
        admitted, reason = arm.decide(tool, tampered)
        assert admitted is False
        assert reason == REASON_CODES["invocation_binding_ok"]

        arm._decision_path._disabled = frozenset({"invocation_binding_ok"})
        assert arm.decide(tool, tampered) == (True, "b3_admitted")


class TestGammaCheckDiscriminator:
    """The library message shapes the authorizer/containment split rests on.

    Found by the counterfactual suite, not by reading: the naive reading
    ("any failed check means the authorizer refused") also matched the
    ATTENUATION block's check and so attributed every F1 block to
    `authorizer_policy_ok`, masking containment -- the G-11 lesson exactly.
    These tests pin both shapes so a library bump cannot silently restore
    the masking.
    """

    def _denial(self, *, element, audience, task, now_offset=0):
        from datetime import datetime, timedelta, timezone

        from biscuit_auth import KeyPair

        from src.harness.authorizer import allowed as authz

        doc = frozen_config.load_document()
        keypair = KeyPair()
        chain = authz.build_chain(
            doc,
            keypair.private_key,
            keypair.public_key,
            [
                ("calendar.read", "calendar/work"),
                ("notes.read", "notes/project"),
                ("notes.write", "notes/project"),
            ],
            [[("notes.read", "notes/project"), ("notes.write", "notes/project")]],
            audience="https://mcp.aasc.local/tools",
            task="task-gt-pilot",
            expiry=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        context = authz.RequestContext(
            now=datetime.now(timezone.utc) + timedelta(seconds=now_offset),
            audience=audience,
            task=task,
        )
        permitted, evidence = authz.authorize_candidate(
            chain.prefix(1), keypair.public_key, doc["gamma"], element, context
        )
        assert permitted is False
        return evidence

    def test_a_gamma_check_failure_is_reported_in_authorizer(self):
        from src.sut.authz.capability_path import gamma_checks_in

        evidence = self._denial(
            element=("notes.write", "notes/project"),
            audience="https://wrong.audience/",
            task="task-gt-pilot",
        )
        assert "in authorizer" in evidence
        assert gamma_checks_in(evidence) != ""  # the check plane: attributable here

    def test_an_attenuation_block_check_is_reported_in_a_block_and_ignored(self):
        from src.sut.authz.capability_path import gamma_checks_in

        # F1-terminal shape: narrowed away at hop 1, everything else valid.
        evidence = self._denial(
            element=("calendar.read", "calendar/work"),
            audience="https://mcp.aasc.local/tools",
            task="task-gt-pilot",
        )
        assert "in block" in evidence
        assert "in authorizer" not in evidence
        assert gamma_checks_in(evidence) == "", (
            "an attenuation-block check is the AUTHORITY plane; attributing it to "
            "authorizer_policy_ok masks containment"
        )

    def test_an_out_of_authority_element_is_also_ignored(self):
        from src.sut.authz.capability_path import gamma_checks_in

        # F1-root shape: outside C_0 entirely.
        evidence = self._denial(
            element=("mail.send", "mail/outbox"),
            audience="https://mcp.aasc.local/tools",
            task="task-gt-pilot",
        )
        assert gamma_checks_in(evidence) == ""


class TestPolicyDependentConjunctsAreGatedNotDefaulted:
    def test_construction_without_a_policy_fails(self, running_as):
        from src.sut.authz.capability_path import PilotPolicy, PilotPolicyError

        with pytest.raises(PilotPolicyError):
            PilotPolicy.load(None, run_mode="pilot")

    def test_a_policy_without_the_banner_is_refused(self):
        from src.sut.authz.capability_path import PilotPolicy, PilotPolicyError

        with pytest.raises(PilotPolicyError):
            PilotPolicy.load({"context": {}, "approval": {}}, run_mode="pilot")

    def test_a_confirmatory_run_refuses_the_pilot_stand_in(self):
        from src.sut.authz.capability_path import PilotPolicy, PilotPolicyError

        policy = json.loads(
            (REPO_ROOT / "fixtures" / "pilot" / "policies" / "pilot_policy_v0.json").read_text(
                encoding="utf-8"
            )
        )
        with pytest.raises(PilotPolicyError):
            PilotPolicy.load(policy, run_mode="confirmatory")
        # Positive arm: the same object loads for a pilot run.
        assert PilotPolicy.load(policy, run_mode="pilot").high_risk_actions == frozenset()

    def test_the_pilot_scenarios_make_neither_conjunct_load_bearing(self):
        policy = json.loads(
            (REPO_ROOT / "fixtures" / "pilot" / "policies" / "pilot_policy_v0.json").read_text(
                encoding="utf-8"
            )
        )
        # No high-risk action set (row 10 UNSET) and no label support (rows 4/6
        # UNSET); the corpus carries no LabelAssertion and no approval artifact,
        # so F4/F5 stay unscored.
        assert policy["approval"]["high_risk_actions"] == []
        assert policy["context"]["labels_supported"] is False
        for scenario_id in ("gt-benign", "gt-f1-root", "gt-f1-terminal"):
            sealed = json.loads(
                (
                    REPO_ROOT
                    / "fixtures"
                    / "pilot"
                    / "golden_thread"
                    / "sealed"
                    / f"{scenario_id}.json"
                ).read_text(encoding="utf-8")
            )
            assert sealed["intended_labels"] == []
            assert sealed["requires_approval"] is False
