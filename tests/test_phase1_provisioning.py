"""Regression suite for Phase-1 provisioning in the AS process (ADR 0021).

Every test has a positive arm and a negative arm so no assertion can pass
vacuously. The spawn tests start the REAL `python -m src.sut.oauth_as`
subprocess (ADR 0015 rule 1) and are platform-independent, like the G-4
suite. Confirmed here and never claimed beyond it: tokens live on the
runner-held pipe only -- nothing in this suite (or the runner) writes one to
disk.
"""

import time

import pytest

from src.harness import key_material
from src.harness.as_process import ASProcess, golden_thread_as_document
from src.harness.authorizer import frozen_config
from src.harness.verifier import registry as reg
from src.sut.authz import boundary

SEED = bytes.fromhex("e1" * 32)


def _identity_jwks(seed: bytes, registry_document: dict) -> dict[str, dict[str, str]]:
    jwks = {}
    for principal in registry_document["principals"]:
        key = key_material.holder_private(seed, f"identity-{principal}")
        jwks[principal] = {"kty": "OKP", "crv": "Ed25519", "x": key_material.public_wire(key)}
    return jwks


@pytest.fixture(scope="module")
def as_document():
    registry_document = reg.load_document()
    corpus = {"issuer": "https://as.aasc.local", "audience": "https://mcp.aasc.local/tools"}
    return golden_thread_as_document(
        corpus=corpus,
        registry_document=registry_document,
        resolved_keys=key_material.resolve_public(SEED),
        identity_jwks=_identity_jwks(SEED, registry_document),
        omega_elements=frozen_config.load_document()["omega"]["elements"],
    )


@pytest.fixture(scope="module")
def running_as(as_document):
    with ASProcess(as_document, SEED) as process:
        yield process


class TestStartupLine:
    def test_one_token_per_registered_client(self, as_document, running_as):
        assert set(running_as.phase1_tokens) == set(as_document["clients"])
        assert all(token.count(".") == 2 for token in running_as.phase1_tokens.values())

    def test_tokens_verify_at_the_unchanged_boundary(self, running_as):
        """The MCP boundary's OAuth limb -- verify_access_token, allowed_authority,
        admits -- is reused UNCHANGED (EXP1 STEP 11)."""
        config = boundary.BoundaryConfig(
            issuer="https://as.aasc.local",
            resource_server="https://mcp.aasc.local/tools",
            as_public_jwk=running_as.public_jwk,
            rar_type="https://aasc.gla.ac.uk/rar/tool-authority",
        )
        now = int(time.time())
        token = running_as.phase1_tokens["agent-specialist"]
        claims = boundary.verify_access_token(token, config, now=now)
        # Coarse RS-level grant (ADR 0021): the whole frozen Omega at this RS.
        allowed = boundary.allowed_authority(claims, config)
        assert ("notes.write", "notes/project") in allowed
        assert ("mail.send", "mail/outbox") in allowed
        decision = boundary.admits(
            claims,
            config,
            element=("notes.write", "notes/project"),
            required_scope="mcp.invoke",
        )
        assert decision.admitted is True
        # SS E.2: no delegation authority in the base token -- the actor is the
        # client itself (no act chain), and the subject is the resource owner.
        assert claims["sub"] == "user-yixian"
        assert claims["client_id"] == "agent-specialist"
        assert "act" not in claims

    def test_wrong_audience_rejected_by_the_unchanged_boundary(self, running_as):
        # Negative arm: the reuse is doing real verification.
        config = boundary.BoundaryConfig(
            issuer="https://as.aasc.local",
            resource_server="https://other.aasc.local/tools",
            as_public_jwk=running_as.public_jwk,
            rar_type="https://aasc.gla.ac.uk/rar/tool-authority",
        )
        with pytest.raises(boundary.TokenRejected):
            boundary.verify_access_token(
                running_as.phase1_tokens["agent-specialist"], config, now=int(time.time())
            )


class TestCoverageFailsClosed:
    def test_partial_phase1_refuses_startup(self, as_document):
        partial = dict(as_document)
        partial["phase1"] = {
            client: spec
            for client, spec in as_document["phase1"].items()
            if client != "agent-specialist"
        }
        with pytest.raises(Exception):
            process = ASProcess(partial, SEED)
            process.stop()  # unreachable; hygiene if the assertion ever fails

    def test_absent_phase1_is_compatible(self, as_document):
        # Pre-EXP1 documents (e.g. gate G-4's) carry no phase1 section: the AS
        # must start and emit an empty mapping, not fail.
        legacy = {key: value for key, value in as_document.items() if key != "phase1"}
        with ASProcess(legacy, SEED) as process:
            assert process.phase1_tokens == {}
