"""The harness-side agreement suite for the SUT capability signer (EXP1 STEP 10).

Two independent implementations, one specification: the SUT signer
(`src/sut/capability/`, written from ADR 0003/0009/0018 and SS F.2) and the
harness verifier (`src/harness/verifier/holder_binding.py`). Agreement is
REQUIRED; shared code is NOT -- the import red-line suite keeps the trees
apart, and this suite proves the byte-level agreement that independence must
not cost. A disagreement here is a FINDING to report, never something to
reconcile by making one side call the other.

Every test has a positive arm and a negative arm so no assertion can pass
vacuously.
"""

import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.harness import key_material
from src.harness.authorizer import frozen_config
from src.harness.oracle import commitment as harness_commitment
from src.harness.oracle.jcs_digest import h_jcs as harness_h_jcs
from src.harness.verifier import holder_binding as hb
from src.harness.verifier import registry as reg
from src.harness.verifier.at_digest import access_token_hash as harness_at_hash
from src.sut.capability import digests as sut_digests
from src.sut.capability import signer as sut_signer

SEED = bytes.fromhex("e1" * 32)  # the pilot corpus seed
TASK_ID = "task-gt-pilot"
AUDIENCE = "https://mcp.aasc.local/tools"
METHOD = "tools/call"
TOOL = "notes.write"
ARGUMENTS = {"resource": "notes/project", "content": "Meeting summary: agreed the Q3 review plan."}
# ADR 0018's worked example, pinned on BOTH implementations.
ADR_0018_TOKEN = (
    "eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiYXQrand0In0.eyJzdWIiOiJ1c2VyLXlpeGlhbiJ9.c2lnbmF0dXJl"
)
ADR_0018_ANSWER = "600b4e6e581a15b4b3e847e093120ba87c6126851fd347f18994020c40010e13"
LABELS_DIGEST = "00" * 32  # bound by the INV signature; construction G-15's (rows 4/6 UNSET)


@pytest.fixture(scope="module")
def issuer() -> sut_signer.CapabilityIssuer:
    gamma_doc = frozen_config.load_document()
    return sut_signer.CapabilityIssuer(gamma_doc, key_material.derive_raw(SEED, "kappa"))


@pytest.fixture(scope="module")
def bound_registry():
    resolved = key_material.resolve_public(SEED)
    return reg.bind(reg.load_document(), lambda label: resolved[label])


def _holder(label: str) -> Ed25519PrivateKey:
    return key_material.holder_private(SEED, label)


class TestDigestAgreement:
    def test_commit_prefix_byte_for_byte(self, issuer):
        hop = issuer.mint_root(
            [("notes.write", "notes/project")],
            audience=AUDIENCE,
            task_id=TASK_ID,
            expiry_epoch=int(time.time()) + 600,
        )
        two = issuer.attenuate(hop, [("notes.write", "notes/project")])
        ids = list(two.block_ids)
        for upto in (0, 1):
            assert sut_digests.commit_prefix(ids, upto) == harness_commitment.commit_prefix(
                ids, upto
            )

    def test_commit_prefix_disagrees_on_different_input(self, issuer):
        # Negative arm: agreement is input-sensitive, not constant.
        hop = issuer.mint_root(
            [("notes.write", "notes/project")],
            audience=AUDIENCE,
            task_id=TASK_ID,
            expiry_epoch=int(time.time()) + 600,
        )
        ids = list(hop.block_ids)
        mutated = [bytes(reversed(ids[0]))]
        assert sut_digests.commit_prefix(ids, 0) != harness_commitment.commit_prefix(mutated, 0)

    def test_h_jcs_byte_for_byte(self):
        for obj in (
            ARGUMENTS,
            {"b": 1, "a": [2, 3], "nested": {"y": None, "x": "ünïcode"}},
            {},
        ):
            assert sut_digests.h_jcs(obj) == harness_h_jcs(obj)
        assert sut_digests.h_jcs({"a": 1}) != harness_h_jcs({"a": 2})

    def test_access_token_hash_pinned_to_the_adr_0018_answer(self):
        assert sut_digests.access_token_hash(ADR_0018_TOKEN) == ADR_0018_ANSWER
        assert harness_at_hash(ADR_0018_TOKEN) == ADR_0018_ANSWER

    def test_access_token_hash_non_ascii_fails_closed_on_both_sides(self):
        with pytest.raises(sut_digests.SutDigestError):
            sut_digests.access_token_hash("ey£token")
        with pytest.raises(Exception):
            harness_at_hash("ey£token")

    def test_unsupported_versions_fail_closed_on_both_sides(self):
        with pytest.raises(sut_digests.SutDigestError):
            sut_digests.commit_ids([b"x" * 64], version=2)
        with pytest.raises(Exception):
            harness_commitment.commit_ids([b"x" * 64], version=2)


class TestKeyMaterialConsistency:
    def test_biscuit_and_cryptography_kappa_agree(self, issuer):
        # Load-bearing assumption of the registry binding: the same 32 raw
        # bytes back both the Biscuit root and the HTC_0 signing key.
        resolved = key_material.resolve_public(SEED)
        assert issuer.root_public_wire() == resolved["kappa"]


class TestSutSignedChainVerifiesUnderHarness:
    def _presentation(self, issuer, *, depth: int, arguments=None, inv_key=None, cid="cid-agree"):
        now = int(time.time())
        arguments = ARGUMENTS if arguments is None else arguments
        root = issuer.mint_root(
            [
                ("calendar.read", "calendar/work"),
                ("notes.read", "notes/project"),
                ("notes.write", "notes/project"),
            ],
            audience=AUDIENCE,
            task_id=TASK_ID,
            expiry_epoch=now + 600,
        )
        supervisor, specialist = _holder("holder-supervisor"), _holder("holder-specialist")
        if depth == 0:
            terminal_hop, terminal_key, terminal_kid = root, supervisor, "kid-holder-supervisor"
            chain = [
                issuer.issue_htc0(
                    root,
                    as_root_kid="kid-as-root",
                    initial_holder_pubkey=sut_signer.public_wire(supervisor),
                    task_id=TASK_ID,
                    audience=AUDIENCE,
                    iat=now - 10,
                    nbf=now - 10,
                    exp=now + 600,
                )
            ]
        else:
            hop1 = issuer.attenuate(
                root, [("notes.read", "notes/project"), ("notes.write", "notes/project")]
            )
            chain = [
                issuer.issue_htc0(
                    root,
                    as_root_kid="kid-as-root",
                    initial_holder_pubkey=sut_signer.public_wire(supervisor),
                    task_id=TASK_ID,
                    audience=AUDIENCE,
                    iat=now - 10,
                    nbf=now - 10,
                    exp=now + 600,
                ),
                sut_signer.issue_htc_hop(
                    hop1,
                    index=1,
                    signer_private=supervisor,
                    signer_kid="kid-holder-supervisor",
                    next_holder_pubkey=sut_signer.public_wire(specialist),
                    task_id=TASK_ID,
                    audience=AUDIENCE,
                    iat=now - 5,
                    nbf=now - 5,
                    exp=now + 540,
                ),
            ]
            terminal_hop, terminal_key, terminal_kid = hop1, specialist, "kid-holder-specialist"
        inv = sut_signer.issue_inv(
            terminal_hop,
            holder_private=inv_key or terminal_key,
            holder_kid=terminal_kid,
            raw_at=ADR_0018_TOKEN,
            raw_arguments=arguments,
            task_id=TASK_ID,
            audience=AUDIENCE,
            method=METHOD,
            tool=TOOL,
            label_assertions_digest=LABELS_DIGEST,
            invocation_id=cid,
            iat=now - 1,
            nbf=now - 1,
            exp=now + 300,
        )
        return hb.PresentedEvidence(
            token_bytes=terminal_hop.token_bytes,
            htc_chain=tuple(chain),
            invocation_assertion=inv,
            raw_at=ADR_0018_TOKEN,
            raw_arguments=arguments,
            task_id=TASK_ID,
            audience=AUDIENCE,
            method=METHOD,
            tool=TOOL,
        ), issuer.root_public

    def test_two_hop_sut_chain_passes_the_full_harness_verification(self, issuer, bound_registry):
        evidence, root_pub = self._presentation(issuer, depth=1)
        result = hb.verify(evidence, bound_registry, root_pub, now=int(time.time()))
        assert result.inv_payload["invocation_id"] == "cid-agree"
        assert result.terminal_holder_pubkey == sut_signer.public_wire(_holder("holder-specialist"))

    def test_zero_hop_sut_chain_passes_too(self, issuer, bound_registry):
        # SS F.2 zero-hop MUST, exercised from the SUT side: HTC_0 alone, INV
        # signed by the initial holder.
        evidence, root_pub = self._presentation(issuer, depth=0)
        result = hb.verify(evidence, bound_registry, root_pub, now=int(time.time()))
        assert len(result.htc_payloads) == 1

    def test_the_agreement_is_not_vacuous_wrong_holder_rejected(self, issuer, bound_registry):
        # A wrong-holder INV (signed by the supervisor instead of the terminal
        # specialist) must be REJECTED by the harness verifier.
        evidence, root_pub = self._presentation(
            issuer, depth=1, inv_key=_holder("holder-supervisor")
        )
        with pytest.raises(hb.HolderBindingRejected) as excinfo:
            hb.verify(evidence, bound_registry, root_pub, now=int(time.time()))
        assert excinfo.value.reason_code in (hb.INV_TERMINAL_HOLDER, hb.INV_SIGNATURE)

    def test_argument_tamper_rejected(self, issuer, bound_registry):
        # The INV binds H_JCS(arguments): presenting different raw arguments
        # than the signed ones must fail at the request digest.
        evidence, root_pub = self._presentation(issuer, depth=1)
        tampered = hb.PresentedEvidence(
            token_bytes=evidence.token_bytes,
            htc_chain=evidence.htc_chain,
            invocation_assertion=evidence.invocation_assertion,
            raw_at=evidence.raw_at,
            raw_arguments={"resource": "notes/project", "content": "TAMPERED"},
            task_id=evidence.task_id,
            audience=evidence.audience,
            method=evidence.method,
            tool=evidence.tool,
        )
        with pytest.raises(hb.HolderBindingRejected) as excinfo:
            hb.verify(tampered, bound_registry, root_pub, now=int(time.time()))
        assert excinfo.value.reason_code == hb.INV_REQUEST_DIGEST
