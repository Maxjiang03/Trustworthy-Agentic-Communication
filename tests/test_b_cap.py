"""`B-cap` -- the ablation that keeps `B3`'s benefits attributable (EXP2 STEP 10).

Every test has a positive arm and a negative arm so no assertion can pass
vacuously. Three things are under test:

1. **It is a CONFIGURATION of the existing decision path, not a copy.** The
   four conjuncts it runs are the same functions `B3` runs, in the same
   `CapabilityDecisionPath`, and the SS E.5 bitmask is what selects them.
2. **SS E.1's `B-cap fixed [E6]` paragraph holds.** `oauth_authn = 1` on the
   same OAuth substrate as `B3`, and audience and expiry are **verified** --
   each shown by the world in which it is violated.
3. **The captured-capability contrast**, which is the entire reason `B-cap`
   exists: one capability, captured from its legitimate holder and presented by
   a different party, is **admitted** by `B-cap` and **blocked** by `B3`. That
   is what stops the study attributing INV's and HTC's benefits to the
   capability token.

Platform-independent: no test here touches the effect ledger.
"""

import copy
import dataclasses
import json
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.harness import key_material
from src.harness.as_process import ASProcess, golden_thread_as_document
from src.harness.authorizer import frozen_config
from src.harness.runner import GoldenThreadRunner
from src.harness.verifier import registry as reg
from src.sut.authz.capability_path import REASON_CODES, CapabilityDecisionPath
from src.sut.baselines.b3 import B3Arm
from src.sut.baselines.b_cap import BCapArm, capture
from src.sut.baselines.base import HopContext, InvocationContext
from src.sut.capability import signer

REPO_ROOT = Path(__file__).resolve().parents[1]
SEED = bytes.fromhex("e1" * 32)
CORPUS = REPO_ROOT / "fixtures" / "pilot" / "golden_thread"
ISSUER = "https://as.aasc.local"
AUDIENCE = "https://mcp.aasc.local/tools"

BENIGN_TOOL = "notes.write"
BENIGN_ARGS = {"resource": "notes/project", "content": "x"}


def _visible(scenario_id: str) -> dict:
    return json.loads((CORPUS / "sut_visible" / f"{scenario_id}.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def as_document():
    registry_document = reg.load_document()
    document = golden_thread_as_document(
        corpus={"issuer": ISSUER, "audience": AUDIENCE},
        registry_document=registry_document,
        resolved_keys=key_material.resolve_public(SEED),
        identity_jwks=key_material.identity_jwks(SEED, registry_document["principals"]),
        omega_elements=frozen_config.load_document()["omega"]["elements"],
    )
    # One client is provisioned with a one-second base token, so the expiry
    # limb can be exercised without waiting and without moving the capability
    # plane's clock more than a few seconds (its window is an hour).
    document = copy.deepcopy(document)
    document["phase1"]["agent-worker"]["lifetime_seconds"] = 1
    return document


@pytest.fixture(scope="module")
def running_as(as_document):
    with ASProcess(as_document, SEED) as process:
        yield process


@pytest.fixture(scope="module")
def runner():
    return GoldenThreadRunner()


@pytest.fixture(scope="module")
def setup(runner, running_as):
    return runner.b3_setup(
        access_token=running_as.phase1_tokens["agent-specialist"],
        as_public_jwk=running_as.public_jwk,
    )


def _hop(visible: dict, now: int) -> HopContext:
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


def _invocation(visible: dict, now: int, *, tool: str, arguments: dict) -> InvocationContext:
    return InvocationContext(
        tool=tool,
        arguments=arguments,
        method=visible["method"],
        task_id=visible["task_id"],
        audience=visible["audience"],
        invocation_id="cid-b-cap",
        now_epoch=now,
    )


def _token_window(token: str) -> tuple[int, int]:
    """`(iat, exp)` read from the access token's own claims, **unverified**.

    Unverified on purpose, and it is a test reading the artifact under test to
    find an instant inside its window -- never a verification path. The point
    is that the instant a window-sensitive assertion uses must come from the
    window, not from a wall clock that has nothing to do with when the AS
    happened to mint.
    """
    import base64

    payload = token.split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    return int(claims["iat"]), int(claims["exp"])


def _armed(arm, setup, visible, *, tool=BENIGN_TOOL, arguments=None, now=None):
    """Provision, delegate and present in one construction, on one clock."""
    now = int(time.time()) if now is None else now
    arm.provision(setup)
    credentials = arm.delegate(_hop(visible, now))
    arm.present(
        credentials, _invocation(visible, now, tool=tool, arguments=arguments or BENIGN_ARGS)
    )
    return arm, credentials, now


# --------------------------------------------------------------------------
# 1. A configuration of the existing decision path, not a copy
# --------------------------------------------------------------------------
class TestItIsAConfigurationNotACopy:
    def test_the_bitmask_is_the_ss_e5_row(self):
        # oauth | crypto_chain | authorizer | htc/holder | invoke | contain |
        # context | approval | jti | audit
        assert BCapArm().bitmask.as_bits() == (1, 1, 1, 0, 0, 1, 0, 0, 0, 1)

    def test_the_bitmask_selects_exactly_four_conjuncts(self):
        assert BCapArm().bitmask.enabled_conjuncts() == {
            "oauth_resource_authorization_ok",
            "crypto_chain_ok",
            "authorizer_policy_ok",
            "containment_ok",
        }
        # Negative arm: B3's bitmask selects all ten, so the four above are a
        # SELECTION from one shared set rather than a smaller private one.
        assert BCapArm().bitmask.enabled_conjuncts() < B3Arm().bitmask.enabled_conjuncts()

    def test_provisioning_is_the_same_function_b3_runs(self):
        """Structural: not a re-implementation that could drift."""
        assert BCapArm.provision is B3Arm.provision
        assert BCapArm.decide is B3Arm.decide
        # Negative arm: the two operations that PRODUCE planes B-cap does not
        # carry are its own, or it would pay for an HTC hop and an INV.
        assert BCapArm.delegate is not B3Arm.delegate
        assert BCapArm.present is not B3Arm.present

    def test_it_runs_the_shared_decision_path(self, setup):
        arm = BCapArm()
        arm.provision(setup)
        assert isinstance(arm._decision_path, CapabilityDecisionPath)

    def test_the_trace_records_the_absent_conjuncts_rather_than_hiding_them(self, setup):
        arm, _, _ = _armed(BCapArm(), setup, _visible("gt-benign"))
        assert arm.decide(BENIGN_TOOL, BENIGN_ARGS) == (True, "b3_admitted")
        evaluated = arm.audit_log[-1]["evaluated"]
        assert "absent:htc_chain_ok" in evaluated
        assert "absent:holder_proof_ok" in evaluated
        assert "absent:invocation_binding_ok" in evaluated
        assert "absent:context_policy_ok" in evaluated
        assert "absent:approval_artifact_ok" in evaluated
        assert "absent:identity_plane_consistency_ok" in evaluated
        # Positive arm: the four it DOES run are recorded plainly.
        for name in (
            "crypto_chain_ok",
            "authorizer_policy_ok",
            "containment_ok",
            "oauth_resource_authorization_ok",
        ):
            assert name in evaluated
        # And `absent` is not `skipped`: B-cap is a ladder position, not an
        # SS E.6 ablation.
        assert not any(entry.startswith("skipped:") for entry in evaluated)
        assert arm.audit_log[-1]["is_ablation"] is False
        assert arm.audit_log[-1]["arm"] == "B-cap"

    def test_it_is_not_an_ablation_and_may_not_carry_one(self, setup):
        from src.sut.baselines.base import ArmIdentityError

        assert BCapArm().identity.is_ablation is False
        with pytest.raises(ArmIdentityError):
            BCapArm().provision(dict(setup, disabled=["containment_ok"]))

    def test_no_htc_and_no_inv_are_produced(self, setup):
        arm, credentials, _ = _armed(BCapArm(), setup, _visible("gt-benign"))
        assert credentials["htc_chain"] == []
        assert arm._staged.htc_chain == ()
        assert arm._staged.invocation_assertion == b""
        # Negative arm: B3, on the same hop, produces both.
        b3, b3_credentials, _ = _armed(B3Arm(), setup, _visible("gt-benign"))
        assert len(b3_credentials["htc_chain"]) == 2
        assert b3._staged.invocation_assertion != b""


# --------------------------------------------------------------------------
# 2. SS E.1's `B-cap fixed [E6]`: oauth_authn = 1, audience AND expiry verified
# --------------------------------------------------------------------------
class TestOAuthAuthnIsOnAndVerifies:
    def test_a_valid_token_is_admitted(self, setup):
        """Positive arm for both refusals below."""
        arm, _, _ = _armed(BCapArm(), setup, _visible("gt-benign"))
        assert arm.decide(BENIGN_TOOL, BENIGN_ARGS) == (True, "b3_admitted")

    def test_audience_is_verified(self, setup):
        """The RS believes it is a different resource server, so `aud` no longer
        names it -- SS E.4's OAuth audience-mismatch negative control."""
        arm, _, _ = _armed(
            BCapArm(),
            dict(setup, resource_server="https://other.aasc.local/tools"),
            _visible("gt-benign"),
        )
        admitted, reason = arm.decide(BENIGN_TOOL, BENIGN_ARGS)
        assert admitted is False
        assert reason == REASON_CODES["oauth_resource_authorization_ok"]
        assert "aud" in arm.audit_log[-1]["detail"]

    def test_expiry_is_verified(self, setup, running_as):
        """A one-second base token, judged five seconds past its own `exp`.

        The capability's own window is an hour, so it is still valid at that
        instant -- which is what makes the block attributable to the TOKEN's
        expiry rather than to the capability's.

        **Both instants are derived from the token's own claims, and neither
        re-reads the wall clock.** The negative arm previously staged at
        `int(time.time())`, which made it a race against the module-scoped AS:
        the `agent-worker` token lives one second from AS start-up, so once the
        fixture had been up longer than that, the arm that must ADMIT was
        staged past `exp` and the test flipped. It failed intermittently on
        Linux, passed in isolation, and never showed on Windows.

        That is the two-clocks shape for the fourth time -- the OAuth plane
        mints against the wall clock while the capability plane is judged at an
        injected instant (blocks 2, 4 and G-14 each hit it). The fix is the one
        those three used: inject the instant. It is taken from `iat`/`exp`
        rather than from a clock, so the window cannot drift out from under it
        however long the AS has been up, and the token's lifetime is left at one
        second -- widening it would have hidden the defect rather than removed
        it.
        """
        token = running_as.phase1_tokens["agent-worker"]
        issued_at, expires_at = _token_window(token)
        assert issued_at < expires_at, "the worker token has no window to be inside"

        arm, _, _ = _armed(
            BCapArm(),
            dict(setup, access_token=token),
            _visible("gt-benign"),
            now=issued_at,
        )
        # Re-stage at an instant past the token's exp but inside the
        # capability's, which runs an hour from `issued_at`.
        arm._staged = dataclasses.replace(arm._staged, now_epoch=expires_at + 5)
        admitted, reason = arm.decide(BENIGN_TOOL, BENIGN_ARGS)
        assert admitted is False
        assert reason == REASON_CODES["oauth_resource_authorization_ok"]
        assert "exp" in arm.audit_log[-1]["detail"]
        # Negative arm: the SAME token at an instant INSIDE its window --
        # `iat`, read from the token itself -- is admitted, so the refusal is
        # the expiry and not the token itself.
        fresh, _, _ = _armed(
            BCapArm(),
            dict(setup, access_token=token),
            _visible("gt-benign"),
            now=issued_at,
        )
        assert fresh.decide(BENIGN_TOOL, BENIGN_ARGS) == (True, "b3_admitted")

    def test_the_expiry_test_reads_no_wall_clock(self):
        """The guard that keeps the flake removed rather than merely fixed.

        The defect was a race, so "it passed" is not evidence: the old form
        passed whenever the module-scoped AS happened to be younger than the
        one-second token, which is most of the time on a fast machine and was
        why Windows never showed it. What removes the race is that **both
        instants come from the token's window**, so this asserts exactly that
        — a future edit reintroducing a wall-clock read here fails here.
        """
        import inspect

        source = inspect.getsource(TestOAuthAuthnIsOnAndVerifies.test_expiry_is_verified)
        body = source.split('"""')[2]  # past the docstring, which discusses the clock
        assert "time.time()" not in body
        assert "_token_window(" in body
        assert "issued_at" in body and "expires_at" in body

    def test_a_standalone_capability_configuration_is_not_built(self):
        """SS E.1: `oauth_authn = 0` may exist only as a separate exploratory
        arm, never in the formal matrix. There is no such arm here."""
        assert BCapArm.bitmask.oauth_authn == 1


# --------------------------------------------------------------------------
# 3. The captured-capability contrast -- the reason B-cap exists
# --------------------------------------------------------------------------
class TestCapturedCapabilityContrast:
    """One capability, captured from its legitimate holder and presented by a
    different party. `B-cap` admits it; `B3` blocks it."""

    @staticmethod
    def _capturing_party_inv(credentials, setup, visible, now) -> bytes:
        """A self-signed INV from a REGISTERED but different holder (the worker).

        Registered on purpose: the registry lookup then succeeds, so only the
        holder limb can catch it -- the G-11 construction that isolates the
        intended condition instead of letting an earlier check mask it.
        """
        wrong = Ed25519PrivateKey.from_private_bytes(setup["holder_privates"]["holder-worker"])
        terminal = signer.MintedHop(
            bytes(credentials["capability_hops"][-1]),
            tuple(bytes(b) for b in credentials["block_ids"][-1]),
        )
        return signer.issue_inv(
            terminal,
            holder_private=wrong,
            holder_kid="kid-holder-worker",
            raw_at=credentials["access_token"],
            raw_arguments=BENIGN_ARGS,
            task_id=visible["task_id"],
            audience=visible["audience"],
            method=visible["method"],
            tool=BENIGN_TOOL,
            label_assertions_digest="00" * 32,
            invocation_id="cid-b-cap",
            iat=now,
            nbf=now,
            exp=now + 300,
        )

    def test_b_cap_admits_a_captured_capability(self, setup):
        visible = _visible("gt-benign")
        legitimate, credentials, now = _armed(B3Arm(), setup, visible)
        assert legitimate.decide(BENIGN_TOOL, BENIGN_ARGS) == (True, "b3_admitted")

        # A DIFFERENT party: an arm that never delegated, holding only what it
        # captured off the wire.
        thief = BCapArm()
        thief.provision(setup)
        thief.present(
            capture(credentials), _invocation(visible, now, tool=BENIGN_TOOL, arguments=BENIGN_ARGS)
        )
        assert thief.decide(BENIGN_TOOL, BENIGN_ARGS) == (True, "b3_admitted"), (
            "B-cap is a BEARER capability: it must admit, and that is the "
            "measurement B3's holder binding is compared against"
        )

    def test_b3_blocks_the_same_captured_capability(self, setup):
        visible = _visible("gt-benign")
        legitimate, credentials, now = _armed(B3Arm(), setup, visible)

        # The capturing party has the whole wire -- capability, HTC chain and
        # base token -- and can only sign an INV with its OWN key.
        thief = B3Arm()
        thief.provision(setup)
        thief.present(
            credentials, _invocation(visible, now, tool=BENIGN_TOOL, arguments=BENIGN_ARGS)
        )
        thief._staged = dataclasses.replace(
            thief._staged,
            invocation_assertion=self._capturing_party_inv(credentials, setup, visible, now),
        )
        admitted, reason = thief.decide(BENIGN_TOOL, BENIGN_ARGS)
        assert admitted is False
        assert reason == REASON_CODES["holder_proof_ok"]

    def test_the_contrast_is_attributable_to_the_holder_plane_alone(self, setup):
        """Both arms saw the SAME capability and the SAME base token.

        So the difference cannot be the capability, the authority set, or the
        OAuth layer -- the three things `B-cap` and `B3` share. It is the HTC
        chain and the INV, which is exactly what the ladder claims.
        """
        visible = _visible("gt-benign")
        _, credentials, now = _armed(B3Arm(), setup, visible)
        captured = capture(credentials)
        assert captured["capability_hops"] == [bytes(hop) for hop in credentials["capability_hops"]]
        assert captured["access_token"] == credentials["access_token"]
        assert captured["htc_chain"] == []  # the holder plane is what is missing


# --------------------------------------------------------------------------
# The golden thread under B-cap
# --------------------------------------------------------------------------
class TestTheGoldenThreadUnderBCap:
    @pytest.mark.parametrize(
        "scenario_id,admitted,reason",
        [
            ("gt-benign", True, "b3_admitted"),
            ("gt-f1-root", False, REASON_CODES["containment_ok"]),
            ("gt-f1-terminal", False, REASON_CODES["containment_ok"]),
        ],
    )
    def test_pilot_outcome(self, runner, setup, scenario_id, admitted, reason):
        run = runner.run_scenario(scenario_id, BCapArm(), setup=setup, ledger_backed=False)
        event = run.mediation_events[-1]
        assert (event.admitted, event.reason_code) == (admitted, reason)

    def test_the_presented_evidence_carries_a_capability_but_no_holder_plane(self, runner, setup):
        run = runner.run_scenario("gt-benign", BCapArm(), setup=setup, ledger_backed=False)
        evidence = run.observed.evidence
        assert evidence.capability is not None
        assert evidence.oauth is not None
        assert evidence.capability.htc_chain == []
        assert evidence.capability.invocation_assertion == b""
        assert len(evidence.capability.signed_blocks) == 2
        # The sealed record still commits to the presented chain, because a
        # capability WAS presented.
        assert len(run.intent.P_hashes) == 2
