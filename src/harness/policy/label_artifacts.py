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


def mint_for_scenario(
    seed: bytes,
    visible: "dict[str, Any]",
    *,
    now: int,
    resource_owner: "tuple[str, str]",
    oauth_actor: "tuple[str, str]",
    policy_version: str,
    declassify_to: str = "public",
) -> "dict[str, Any]":
    """Mint the ADR 0030 artifacts a corpus scenario's SPEC calls for.

    The fixtures store `labelled_values` and an `artifacts` flag pair, never a
    minted artifact and never a signature (ADR 0007) -- exactly the rule that
    keeps tokens out of the corpus, for the same reason. This is where the
    specification becomes signed bytes, at run time, in memory.

    Minted **harness-side with the harness's own implementation** of
    `authz_context_hash` (D21): the instrument signs what the measured system
    must independently verify. If the two constructions disagreed, every
    artifact would fail to bind and the F4/F5 controls would refuse -- which is
    why `tests/test_label_context_agreement.py` pins them byte-for-byte.

    Returns `{payload_labels, declassification, approval_artifact}`, shaped for
    an `InvocationContext`. A scenario that declares no artifacts gets empty
    values, so an unlabelled scenario is unaffected.
    """
    from src.harness.oracle.jcs_digest import h_jcs

    intent = visible["delegation_intent"]
    tool, arguments = intent["tool"], intent["arguments"]
    labels = [
        issue_label_assertion(
            seed,
            value=entry["value"],
            label=entry["label"],
            # SS A.6: labels exist BEFORE task-time issuance. A day-old
            # assertion valid for a further day is the NORMAL case, and Delta
            # deliberately does not apply to it (ADR 0030).
            iat=now - 86_400,
            exp=now + 86_400,
        )
        for entry in visible.get("labelled_values", [])
    ]
    wanted = visible.get("artifacts", {})
    context_hash = lc.authz_context_hash(
        task_id=visible["task_id"],
        audience=visible["audience"],
        tool=tool,
        canonical_request_digest=h_jcs(dict(arguments)),
        resource_owner=resource_owner,
        oauth_actor=oauth_actor,
    )
    declassification = None
    if wanted.get("declassification"):
        entry = visible["labelled_values"][0]
        declassification = issue_declassification(
            seed,
            task_id=visible["task_id"],
            audience=visible["audience"],
            tool=tool,
            # The SAME notion of "this request" the approval binds to: one
            # boundary with two would be one binding too many (ADR 0030).
            request_digest=context_hash,
            recipient=arguments.get("to", ""),
            value=entry["value"],
            from_label=entry["label"],
            to_label=declassify_to,
            policy_version=policy_version,
            iat=now,
            nbf=now - 5,
            exp=now + 300,
            jti=f"declass-{visible['scenario_id']}",
        )
    approval = None
    if wanted.get("approval"):
        approval = issue_approval(
            seed,
            authz_context_hash=context_hash,
            iat=now,
            nbf=now - 5,
            exp=now + 300,
            jti=f"approval-{visible['scenario_id']}",
        )
    return {
        "payload_labels": tuple(labels),
        "declassification": declassification,
        "approval_artifact": approval,
    }
