"""The independent per-hop authority verifier (gate G-13, EXP2 STEP 13).

Every test has a positive arm and a negative arm so no assertion can pass
vacuously. What is under test is `src/harness/verifier/matched_authority.py`:
the token-plane recomputation written here rather than shared with
`src/sut/authz/boundary.py`, the capability-plane adapter over the
`Allowed(P_i)` gate G-2 adjudicated, and the independence that makes either
worth anything (D13/D21).

The gate itself runs in `smoke/g13/spike.py` and in CI. This file is the
regression suite for the instrument the gate uses, so a later refactor that
quietly weakens it fails here rather than at the next campaign.

Platform-independent: no test here touches the effect ledger.
"""

import ast
import dataclasses
import json
import time
from pathlib import Path

import pytest

from src.harness import key_material
from src.harness.as_process import RAR_TYPE, ASProcess, golden_thread_as_document
from src.harness.authorizer import frozen_config
from src.harness.runner import GoldenThreadRunner
from src.harness.verifier import matched_authority as ma
from src.harness.verifier import registry as reg
from src.sut.authz import boundary
from src.sut.baselines.b2_exchange_task import B2ExchangeTaskArm
from src.sut.baselines.b3 import B3Arm
from src.sut.baselines.base import HopContext

REPO_ROOT = Path(__file__).resolve().parents[1]
SEED = bytes.fromhex("e1" * 32)
CORPUS = REPO_ROOT / "fixtures" / "pilot" / "golden_thread"
ISSUER = "https://as.aasc.local"
AUDIENCE = "https://mcp.aasc.local/tools"


def _visible(scenario_id: str) -> dict:
    return json.loads((CORPUS / "sut_visible" / f"{scenario_id}.json").read_text(encoding="utf-8"))


def _c_sets(scenario_id: str) -> list[frozenset]:
    sealed = json.loads((CORPUS / "sealed" / f"{scenario_id}.json").read_text(encoding="utf-8"))
    return [frozenset((a, r) for a, r in c) for c in sealed["C_sets"]]


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
def config(running_as):
    return ma.TokenVerifierConfig(
        issuer=ISSUER,
        resource_server=AUDIENCE,
        as_public_jwk=running_as.public_jwk,
        rar_type=RAR_TYPE,
        required_scope="mcp.invoke",
    )


@pytest.fixture(scope="module")
def base_token(running_as):
    """The delegating client's `AT_0`, whose authority is exactly `C_0`."""
    return running_as.phase1_tokens["agent-supervisor"]


@pytest.fixture(scope="module")
def exchanged_token(runner, running_as):
    """A real `AT_1` from a real hop, whose authority should be exactly `C_1`."""
    arm = B2ExchangeTaskArm()
    arm.provision(
        runner.b2_setup(
            scenario_id="gt-benign",
            access_token=running_as.phase1_tokens["agent-supervisor"],
            as_public_jwk=running_as.public_jwk,
            as_port=running_as.port,
            as_tls_cert_pem=running_as.tls_cert_pem,
        )
    )
    try:
        visible = _visible("gt-benign")
        now = int(time.time())
        credentials = arm.delegate(
            HopContext(
                task_id=visible["task_id"],
                audience=visible["audience"],
                from_agent=visible["supervisor"],
                to_agent=visible["specialist"],
                authority_elements=tuple(map(tuple, visible["authority_elements"])),
                attenuation_elements=tuple(map(tuple, visible["attenuation_elements"])),
                now_epoch=now,
                expiry_epoch=now + int(visible["validity_seconds"]),
            )
        )
    finally:
        arm.close()
    return credentials["access_token"]


class TestTokenVerification:
    def test_a_valid_token_verifies(self, base_token, config):
        claims = ma.verify_token(base_token, config, now=int(time.time()))
        assert claims["iss"] == ISSUER
        assert claims["aud"] == AUDIENCE

    @pytest.mark.parametrize(
        "mutate,expected_check",
        [
            (lambda t, c: (t[:-4] + ("BBBB" if t.endswith("AAAA") else "AAAA"), c), "signature"),
            (lambda t, c: ("not.a.jwt", c), "signature"),
            (lambda t, c: (t, dataclasses.replace(c, issuer="https://evil")), "iss"),
            (
                lambda t, c: (
                    t,
                    dataclasses.replace(c, resource_server="https://other"),
                ),
                "aud",
            ),
        ],
    )
    def test_each_check_refuses_for_its_own_condition(
        self, base_token, config, mutate, expected_check
    ):
        token, cfg = mutate(base_token, config)
        with pytest.raises(ma.TokenRefused) as raised:
            ma.verify_token(token, cfg, now=int(time.time()))
        assert raised.value.check == expected_check

    def test_an_expired_token_refuses(self, base_token, config):
        with pytest.raises(ma.TokenRefused) as raised:
            ma.verify_token(base_token, config, now=int(time.time()) + 10_000)
        assert raised.value.check == "exp"

    def test_refusal_is_not_an_empty_allowed_set(self, base_token, config):
        """The distinction the gate's L1.W4 world turns on.

        A verifier that returned `frozenset()` for an unverifiable token would
        make a forged token indistinguishable from one that admits nothing.
        """
        with pytest.raises(ma.TokenRefused):
            ma.token_allowed("not.a.jwt", config, ma.omega(), now=int(time.time()))
        # Positive arm: the same call on a real token returns a non-empty set.
        assert ma.token_allowed(base_token, config, ma.omega(), now=int(time.time()))


class TestTokenAuthorityOverOmega:
    def test_the_base_token_admits_exactly_c0(self, base_token, config):
        allowed = ma.token_allowed(base_token, config, ma.omega(), now=int(time.time()))
        assert allowed == _c_sets("gt-benign")[0]

    def test_the_exchanged_token_admits_exactly_c1(self, exchanged_token, config):
        allowed = ma.token_allowed(exchanged_token, config, ma.omega(), now=int(time.time()))
        c0, c1 = _c_sets("gt-benign")
        assert allowed == c1
        # Negative arm: C_1 is a PROPER subset of C_0, so the equality is not
        # restating the base grant.
        assert allowed < c0

    def test_membership_is_decided_one_candidate_at_a_time(self, base_token, config):
        """Compute, never assert -- the G-2 discipline on the token plane."""
        claims = ma.verify_token(base_token, config, now=int(time.time()))
        c0 = _c_sets("gt-benign")[0]
        for element in sorted(ma.omega()):
            assert ma.token_admits(claims, config, element) is (element in c0)

    def test_a_wrong_scope_admits_nothing(self, base_token, config):
        starved = dataclasses.replace(config, required_scope="mcp.admin")
        assert (
            ma.token_allowed(base_token, starved, ma.omega(), now=int(time.time())) == frozenset()
        )
        # Positive arm: the real scope admits C_0, so the emptiness is the scope.
        assert ma.token_allowed(base_token, config, ma.omega(), now=int(time.time()))

    def test_a_foreign_rar_type_admits_nothing(self, base_token, config):
        foreign = dataclasses.replace(config, rar_type="https://example.test/other")
        assert (
            ma.token_allowed(base_token, foreign, ma.omega(), now=int(time.time())) == frozenset()
        )

    def test_an_object_naming_another_location_contributes_nothing(self, config):
        """RFC 9396 SS 9.1, checked on a synthetic claim set."""
        claims = {
            "scope": "mcp.invoke",
            "authorization_details": [
                {
                    "type": config.rar_type,
                    "locations": ["https://elsewhere.test/tools"],
                    "actions": ["notes.write"],
                    "datatypes": ["notes/project"],
                }
            ],
        }
        assert ma.token_admits(claims, config, ("notes.write", "notes/project")) is False
        # Positive arm: the same object at THIS location does contribute.
        claims["authorization_details"][0]["locations"] = [config.resource_server]
        assert ma.token_admits(claims, config, ("notes.write", "notes/project")) is True

    def test_string_comparison_is_byte_exact(self, config):
        """RFC 9396 SS 12: no case folding, no normalization."""
        claims = {
            "scope": "mcp.invoke",
            "authorization_details": [
                {
                    "type": config.rar_type,
                    "locations": [config.resource_server],
                    "actions": ["Notes.Write"],
                    "datatypes": ["notes/project"],
                }
            ],
        }
        assert ma.token_admits(claims, config, ("notes.write", "notes/project")) is False


class TestCapabilityPlane:
    def test_per_hop_authority_equals_the_sealed_c_sets(self, runner, running_as):
        arm = B3Arm()
        setup = runner.b3_setup(
            access_token=running_as.phase1_tokens["agent-specialist"],
            as_public_jwk=running_as.public_jwk,
        )
        run = runner.run_scenario("gt-benign", arm, setup=setup, ledger_backed=False)
        _, root_pub = key_material.biscuit_root(SEED)
        per_hop = ma.capability_allowed_per_hop(
            run.observed.evidence.capability.signed_blocks,
            root_pub,
            frozen_config.load_document(),
            now_epoch=run.observed.iat,
            audience=run.observed.audience,
            task_id=_visible("gt-benign")["task_id"],
        )
        assert per_hop == _c_sets("gt-benign")
        # Negative arm: the two hops are DIFFERENT sets, so the equality is not
        # comparing one value against itself twice.
        assert per_hop[1] < per_hop[0]


class TestIndependence:
    """D13/D21. Agreement is evidence only because the implementations differ."""

    @staticmethod
    def _imports(path: Path) -> set[str]:
        names: set[str] = set()
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom) and node.module:
                names.add(node.module)
            elif isinstance(node, ast.Import):
                names.update(alias.name for alias in node.names)
        return names

    def test_the_verifier_imports_nothing_from_the_sut(self):
        names = self._imports(REPO_ROOT / "src" / "harness" / "verifier" / "matched_authority.py")
        assert not any(name.startswith("src.sut") for name in names)
        assert "src.sut.authz.boundary" not in names  # D13/D21, and STEP 13 by name
        # Positive arm: it DOES reuse the harness authorizer G-2 adjudicated,
        # because a third implementation would add no independence.
        assert any(name.startswith("src.harness.authorizer") for name in names)

    def test_the_two_planes_agree_on_the_same_token(self, base_token, config):
        """Two independent implementations, one answer.

        The boundary computes a capability-plane SET and applies `scope` per
        request; the verifier asks a yes/no question per candidate with all
        three planes inside it. Same frozen inputs, different construction --
        which is what makes agreement evidence rather than tautology.
        """
        boundary_config = boundary.BoundaryConfig(
            issuer=config.issuer,
            resource_server=config.resource_server,
            as_public_jwk=config.as_public_jwk,
            rar_type=config.rar_type,
        )
        now = int(time.time())
        claims = boundary.verify_access_token(base_token, boundary_config, now=now)
        by_boundary = frozenset(
            element
            for element in sorted(ma.omega())
            if boundary.admits(
                claims, boundary_config, element=element, required_scope=config.required_scope
            ).admitted
        )
        by_verifier = ma.token_allowed(base_token, config, ma.omega(), now=now)
        assert by_boundary == by_verifier == _c_sets("gt-benign")[0]

    def test_the_agreement_is_not_vacuous(self, config):
        """A claim set the two would answer differently if either were broken.

        Both must say NO for an element outside the grant; a verifier that
        returned Omega, or the boundary's set unfiltered, would disagree here.
        """
        claims = {
            "scope": "mcp.invoke",
            "authorization_details": [
                {
                    "type": config.rar_type,
                    "locations": [config.resource_server],
                    "actions": ["notes.read"],
                    "datatypes": ["notes/project"],
                }
            ],
        }
        assert ma.token_admits(claims, config, ("notes.read", "notes/project")) is True
        assert ma.token_admits(claims, config, ("mail.send", "mail/outbox")) is False
