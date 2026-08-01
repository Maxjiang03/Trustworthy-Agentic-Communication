"""Minting the three ADR 0030 artifacts, harness-side (fixtures and gates).

The instrument mints what the measured system must verify: a `LabelAssertion`
signed by the trusted **label issuer**, and a `DeclassificationArtifact` /
`ApprovalArtifact` signed by the trusted **approver**. Both key sets are derived
from the sealed corpus seed under ADR 0007's rule -- the artifact fixes
derivation labels, never key bytes -- and injected as start-up configuration,
exactly as ADR 0019 does for the identity plane.

**Two roles, two derivation labels, deliberately disjoint.** A label issuer
asserts what data *is*; an approver authorizes an *action*. Sharing one key
would let whoever labels a payload also approve a high-risk action on it, so the
monitor refuses a configuration in which a kid appears in both sets, and these
two derivations cannot collide because their `info` labels differ.

Nothing here is ever written to disk: the private halves live in memory for the
run and the fixtures store **specifications**, never minted artifacts -- the same
rule ADR 0007 applies to tokens, for the same reason.
"""

from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.harness import key_material
from src.harness.verifier import label_context as lc

LABEL_ISSUER_LABEL = "label-issuer"
APPROVER_LABEL = "approver"
LABEL_ISSUER_KID = "kid-label-issuer"
APPROVER_KID = "kid-approver"


def label_issuer_private(seed: bytes) -> Ed25519PrivateKey:
    return key_material.holder_private(seed, LABEL_ISSUER_LABEL)


def approver_private(seed: bytes) -> Ed25519PrivateKey:
    return key_material.holder_private(seed, APPROVER_LABEL)


def trusted_sets(seed: bytes) -> "tuple[dict[str, str], dict[str, str]]":
    """`(label_issuers, approvers)` as the monitor takes them: kid -> public wire."""
    return (
        {LABEL_ISSUER_KID: key_material.public_wire(label_issuer_private(seed))},
        {APPROVER_KID: key_material.public_wire(approver_private(seed))},
    )


def _signed(tag: bytes, payload: dict[str, Any], private: Ed25519PrivateKey) -> dict[str, Any]:
    """The payload plus its base64url signature over ADR 0030's signing input."""
    signature = private.sign(lc.signing_input(tag, payload))
    return dict(payload, signature=key_material.urlsafe_b64encode(signature).rstrip(b"=").decode())


def issue_label_assertion(
    seed: bytes, *, value: "str | bytes", label: str, iat: int, exp: int
) -> dict[str, Any]:
    """A `LabelAssertion` over a data VALUE, resolved by `payload_digest` (SS A.6).

    No `Delta` window: SS A.6 states labels *"are asserted at ingestion by a
    trusted source (they exist before task-time capability issuance)"*, so a
    per-request freshness window would refuse every genuinely pre-labelled
    payload. Its bound is its own `iat`/`exp`.
    """
    return _signed(
        lc.LABEL_ASSERTION_TAG,
        {
            "payload_digest": lc.payload_digest(value),
            "label": label,
            "issuer_kid": LABEL_ISSUER_KID,
            "iat": iat,
            "exp": exp,
        },
        label_issuer_private(seed),
    )


def issue_declassification(
    seed: bytes,
    *,
    task_id: str,
    audience: str,
    tool: str,
    request_digest: str,
    recipient: str,
    value: "str | bytes",
    from_label: str,
    to_label: str,
    policy_version: str,
    iat: int,
    nbf: int,
    exp: int,
    jti: str,
) -> dict[str, Any]:
    """A `DeclassificationArtifact` bound to ONE request's `authz_context_hash`.

    `request_digest` is that hash (ADR 0030): binding the request differently
    from an approval would give one boundary two notions of "this request".
    """
    return _signed(
        lc.DECLASSIFICATION_TAG,
        {
            "task_id": task_id,
            "audience": audience,
            "tool": tool,
            "request_digest": request_digest,
            "recipient": recipient,
            "payload_digest": lc.payload_digest(value),
            "from_label": from_label,
            "to_label": to_label,
            "policy_version": policy_version,
            "approver_kid": APPROVER_KID,
            "iat": iat,
            "nbf": nbf,
            "exp": exp,
            "jti": jti,
        },
        approver_private(seed),
    )


def issue_approval(
    seed: bytes,
    *,
    authz_context_hash: str,
    iat: int,
    nbf: int,
    exp: int,
    jti: str,
    replay_rule: str = "single-use",
) -> bytes:
    """An `ApprovalArtifact`, as SS F.1 carries it: raw signed-envelope bytes."""
    import json

    payload = {
        "authz_context_hash": authz_context_hash,
        "approver_kid": APPROVER_KID,
        "iat": iat,
        "nbf": nbf,
        "exp": exp,
        "jti": jti,
        "replay_rule": replay_rule,
    }
    signature = approver_private(seed).sign(lc.signing_input(lc.APPROVAL_TAG, payload))
    return json.dumps(
        {
            "payload": payload,
            "signature": key_material.urlsafe_b64encode(signature).rstrip(b"=").decode(),
        }
    ).encode("utf-8")
