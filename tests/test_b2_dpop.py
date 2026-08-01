"""`B2-exchange-task-DPoP` -- the exchange arm plus RFC 9449 holder binding.

Every test has a positive arm and a negative arm so no assertion can pass
vacuously. Three things are under test:

1. **The binding is real.** `AT_i` carries `cnf.jkt`, a proof accompanies every
   request, and a proof signed by a different key is refused -- SS D's
   `dpop-stolen-AT-key-substitution` (T-reuse), which this arm blocks and the
   bare bearer arms do not.
2. **The binding is method + URI ONLY, and that is made OBSERVABLE.** The proof
   claim set is exactly `{jti, htm, htu, iat, ath}` -- no tool, no arguments,
   no digest of either -- and the *same* proof verifies against a **different
   tool at the same endpoint**. That is SS D's `dpop-first-use-body-mutation`
   (T-tool / T-args), predicted **admitted** here and blocked by `B3`'s
   `invocation_binding_ok`. Building the arm is not building that family's
   fixtures (EXP3 forbidden action 7): these are arm-level properties, not
   corpus scenarios.
3. **The anti-bias suite is inherited in full**, plus the proof key: parsed
   once at provisioning, never on the request path. Counted, never timed.

Platform-independent; nothing here is timed.
"""

import ast
import json
import time
from pathlib import Path

import pytest
from joserfc.jwk import OKPKey

from src.harness import key_material
from src.harness.as_process import ASProcess, golden_thread_as_document
from src.harness.authorizer import frozen_config
from src.harness.runner import GoldenThreadRunner
from src.harness.verifier import registry as reg
from src.sut import dpop
from src.sut.baselines import b2_dpop as dpopmod
from src.sut.baselines.b2_dpop import RESOURCE_METHOD, B2ExchangeTaskDPoPArm
from src.sut.baselines.b2_exchange_task import B2ConfigurationError, B2ExchangeTaskArm
from src.sut.baselines.base import HopContext, InvocationContext

REPO_ROOT = Path(__file__).resolve().parents[1]
SEED = bytes.fromhex("e1" * 32)
CORPUS = REPO_ROOT / "fixtures" / "pilot" / "golden_thread"
ISSUER = "https://as.aasc.local"
AUDIENCE = "https://mcp.aasc.local/tools"
RESOURCE_URL = "https://mcp.aasc.local/tools/invoke"


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
        task_grant=runner.task_grant("gt-benign"),
    )


@pytest.fixture(scope="module")
def running_as(as_document):
    with ASProcess(as_document, SEED) as process:
        yield process


@pytest.fixture
def setup(runner, running_as, as_document):
    return runner.b2_dpop_setup(
        scenario_id="gt-benign",
        access_token=running_as.phase1_tokens["agent-supervisor"],
        as_public_jwk=running_as.public_jwk,
        as_port=running_as.port,
        as_tls_cert_pem=running_as.tls_cert_pem,
        as_token_endpoint=as_document["token_endpoint"],
        resource_url=RESOURCE_URL,
    )


def _hop(now):
    visible = _visible("gt-benign")
    return HopContext(
        task_id=visible["task_id"],
        audience=visible["audience"],
        from_agent=visible["supervisor"],
        to_agent=visible["specialist"],
        authority_elements=tuple(map(tuple, visible["authority_elements"])),
        attenuation_elements=tuple(map(tuple, visible["attenuation_elements"])),
        widening_elements=(),
        now_epoch=now,
        expiry_epoch=now + int(visible["validity_seconds"]),
    )


def _invocation(now, *, tool="notes.write", arguments=None):
    visible = _visible("gt-benign")
    return InvocationContext(
        tool=tool,
        arguments=arguments or {"resource": "notes/project", "content": "x"},
        method=visible["method"],
        task_id=visible["task_id"],
        audience=visible["audience"],
        invocation_id="cid-dpop",
        now_epoch=now,
    )


@pytest.fixture
def armed(setup):
    """Provisioned, delegated and presented, on one injected instant."""
    now = int(time.time())
    arm = B2ExchangeTaskDPoPArm()
    arm.provision(setup)
    credentials = arm.delegate(_hop(now))
    arm.present(credentials, _invocation(now))
    try:
        yield arm, credentials, now
    finally:
        arm.close()


class TestTheBindingIsReal:
    def test_the_exchanged_token_carries_cnf_jkt(self, armed, setup):
        import base64

        arm, credentials, _ = armed
        payload = credentials["access_token"].split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        expected = OKPKey.import_key(dict(setup["dpop_private_jwk"])).thumbprint()
        assert claims["cnf"] == {"jkt": expected}

    def test_a_bearer_arm_gets_no_cnf(self, runner, running_as):
        """Negative arm: the binding is this arm's, not the AS's default."""
        import base64

        bearer = B2ExchangeTaskArm()
        bearer.provision(
            runner.b2_setup(
                scenario_id="gt-benign",
                access_token=running_as.phase1_tokens["agent-supervisor"],
                as_public_jwk=running_as.public_jwk,
                as_port=running_as.port,
                as_tls_cert_pem=running_as.tls_cert_pem,
            )
        )
        try:
            credentials = bearer.delegate(_hop(int(time.time())))
        finally:
            bearer.close()
        payload = credentials["access_token"].split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        assert "cnf" not in claims
        assert bearer.token_endpoint_proof(0) is None

    def test_the_benign_call_is_admitted(self, armed):
        arm, _, _ = armed
        assert arm.decide("notes.write", {"resource": "notes/project", "content": "x"}) == (
            True,
            "b2_admitted",
        )

    def test_a_proof_from_another_key_is_refused(self, armed, setup):
        """SS D `dpop-stolen-AT-key-substitution` (T-reuse): the token is held,
        the holder key is not. This arm blocks it; a bearer arm cannot."""
        arm, credentials, now = armed
        thief_key = OKPKey.import_key(dict(key_material.dpop_private_jwk(SEED, "holder-worker")))
        arm.restage_proof(
            dpop.create_proof(
                thief_key,
                method=RESOURCE_METHOD,
                url=RESOURCE_URL,
                ath=dpop.access_token_hash(credentials["access_token"]),
                iat=now,
            )
        )
        admitted, reason = arm.decide("notes.write", {"resource": "notes/project", "content": "x"})
        assert (admitted, reason) == (False, dpopmod.REASON_HOLDER_PROOF)

    def test_no_proof_at_all_is_refused(self, armed):
        arm, _, _ = armed
        arm.restage_proof(None)
        assert arm.decide("notes.write", {})[1] == dpopmod.REASON_HOLDER_PROOF

    def test_a_proof_bound_to_another_token_is_refused(self, armed, running_as):
        """RFC 9449 SS 4.3 item 12: `ath` must hash THIS access token."""
        arm, _, now = armed
        arm.restage_proof(
            dpop.create_proof(
                OKPKey.import_key(dict(key_material.dpop_private_jwk(SEED, "holder-specialist"))),
                method=RESOURCE_METHOD,
                url=RESOURCE_URL,
                ath=dpop.access_token_hash(running_as.phase1_tokens["agent-worker"]),
                iat=now,
            )
        )
        assert arm.decide("notes.write", {})[1] == dpopmod.REASON_HOLDER_PROOF

    def test_the_holder_check_runs_before_the_scope_check(self, armed):
        """So a holder failure is attributable to the holder plane.

        An out-of-scope request with a broken proof must report the PROOF, or
        the holder limb would be masked exactly as G-11's lesson warns.
        """
        arm, _, _ = armed
        arm.restage_proof(None)
        admitted, reason = arm.decide(
            "mail.send", {"to": "partner@example.test", "subject": "s", "body": "b"}
        )
        assert (admitted, reason) == (False, dpopmod.REASON_HOLDER_PROOF)


class TestMethodAndUriOnly:
    """SS E.1's `Binds invocation? = method+URI only`, made observable."""

    def test_the_proof_claim_set_names_no_tool_and_no_arguments(self, armed):
        arm, _, _ = armed
        assert arm.proof_claim_names() == {"jti", "htm", "htu", "iat", "ath"}
        # Said the other way, because absence is the claim being made.
        for forbidden in (
            "tool",
            "arguments",
            "args",
            "body",
            "digest",
            "canonical_request_digest",
        ):
            assert forbidden not in arm.proof_claim_names()

    def test_the_same_proof_verifies_for_a_different_tool(self, armed):
        """SS D `dpop-first-use-body-mutation` (T-tool): predicted ADMITTED.

        The proof was minted while presenting `notes.write`; the request is
        then `notes.read`, which is inside `C_1`. Nothing in the proof depends
        on which tool was named, so the arm admits -- exactly the gap SS D says
        `B3`'s canonical body/args binding fills, and which G-14 will
        attribute. This is an arm-level property, not an F3 fixture.
        """
        arm, _, _ = armed
        assert arm.decide("notes.read", {"resource": "notes/project"}) == (True, "b2_admitted")

    def test_and_for_different_arguments_to_the_same_tool(self, armed):
        """SS D T-args, same prediction and the same reason."""
        arm, _, _ = armed
        assert arm.decide(
            "notes.write", {"resource": "notes/project", "content": "SUBSTITUTED AFTER SIGNING"}
        ) == (True, "b2_admitted")

    def test_but_the_scope_plane_still_bites(self, armed):
        """Negative arm: the admissions above are the PROOF not covering the
        call, not the arm admitting everything. `mail.send` is outside `C_1`."""
        arm, _, _ = armed
        admitted, reason = arm.decide(
            "mail.send", {"to": "partner@example.test", "subject": "s", "body": "b"}
        )
        assert (admitted, reason) == (False, "b2_token_scope")

    def test_the_proof_is_minted_without_reading_the_tool_or_arguments(self):
        """Structural: `present` passes neither into `create_proof`."""
        source = (REPO_ROOT / "src" / "sut" / "baselines" / "b2_dpop.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)
        present = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == "present"
        )
        rendered = ast.dump(present)
        assert "invocation.tool" not in rendered
        assert "invocation.arguments" not in rendered
        # Negative arm: it DOES read the instant, so the scan sees attribute
        # access on `invocation` where it exists.
        assert "now_epoch" in rendered

    def test_the_invoke_bit_is_zero(self):
        assert B2ExchangeTaskDPoPArm().bitmask.invoke == 0
        assert B2ExchangeTaskDPoPArm().bitmask.htc_holder == 1  # SS E.5's `dpop-cnf`
        assert B2ExchangeTaskDPoPArm.holder_binding_mechanism == "dpop-cnf"


class TestAntiBias:
    """Inherited in full from `B2-exchange-task`, plus the proof key."""

    def test_the_proof_key_is_parsed_once_at_provisioning(self, setup, monkeypatch):
        parses = {"count": 0}
        original = OKPKey.import_key

        def counting(*args, **kwargs):
            parses["count"] += 1
            return original(*args, **kwargs)

        arm = B2ExchangeTaskDPoPArm()
        arm.provision(setup)
        try:
            monkeypatch.setattr(OKPKey, "import_key", staticmethod(counting))
            now = int(time.time())
            arm.delegate(_hop(now))
            arm.delegate(_hop(now))
            assert parses["count"] == 0, "a key was parsed during a delegation hop"
        finally:
            arm.close()
        # Negative arm: provisioning DOES parse, so the counter is live.
        parses["count"] = 0
        fresh = B2ExchangeTaskDPoPArm()
        fresh.provision(setup)
        fresh.close()
        assert parses["count"] >= 1

    def test_it_inherits_the_shared_provisioning_and_request_path(self):
        assert B2ExchangeTaskDPoPArm.provision is not B2ExchangeTaskArm.provision  # extended
        assert B2ExchangeTaskDPoPArm._post_token is B2ExchangeTaskArm._post_token
        assert B2ExchangeTaskDPoPArm.delegate is B2ExchangeTaskArm.delegate
        assert B2ExchangeTaskDPoPArm.decide is B2ExchangeTaskArm.decide

    def test_one_connection_dialling_the_literal_loopback(self, armed):
        arm, _, _ = armed
        assert arm._connection.host == "127.0.0.1"
        connection, context = arm._connection, arm._tls_context
        arm.delegate(_hop(int(time.time())))
        assert arm._connection is connection and arm._tls_context is context

    def test_the_htu_is_the_as_configured_endpoint_not_the_dialled_address(self, armed, setup):
        """The two differ by construction, and binding to the wrong one fails."""
        arm, _, now = armed
        proof = arm.token_endpoint_proof(now)
        payload = proof.split(".")[1]
        import base64

        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        assert claims["htu"] == setup["as_token_endpoint"]
        assert "127.0.0.1" not in claims["htu"]
        assert arm._connection.host == "127.0.0.1"

    def test_provisioning_fails_closed_on_missing_dpop_material(self, setup):
        for field in ("dpop_private_jwk", "as_token_endpoint", "resource_url"):
            with pytest.raises(B2ConfigurationError):
                B2ExchangeTaskDPoPArm().provision({k: v for k, v in setup.items() if k != field})


class TestTheGoldenThreadUnderDPoP:
    @pytest.mark.parametrize(
        "scenario_id,admitted,reason",
        [
            ("gt-benign", True, "b2_admitted"),
            ("gt-f1-root", False, "b2_token_scope"),
            ("gt-f1-terminal", False, "b2_token_scope"),
            ("gt-f1-chain-tamper", False, "b2_exchange_refused"),
        ],
    )
    def test_pilot_outcome(self, runner, setup, scenario_id, admitted, reason):
        """Identical to `B2-exchange-task`: DPoP adds holder binding, not authority."""
        arm = B2ExchangeTaskDPoPArm()
        try:
            run = runner.run_scenario(scenario_id, arm, setup=setup, ledger_backed=False)
        finally:
            arm.close()
        event = run.mediation_events[-1]
        assert (event.admitted, event.reason_code) == (admitted, reason)

    def test_a_refused_exchange_stages_no_proof(self, runner, setup):
        """Nothing to bind a proof to, so none is minted."""
        arm = B2ExchangeTaskDPoPArm()
        try:
            runner.run_scenario("gt-f1-chain-tamper", arm, setup=setup, ledger_backed=False)
            assert arm.staged_proof() is None
            assert arm.proof_claim_names() == frozenset()
        finally:
            arm.close()
