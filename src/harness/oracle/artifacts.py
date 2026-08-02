"""Oracle-side artifact validation — Part I's `valid_*` helpers (EXP6 STEP 3).

Part I names four helpers and defines none of them:

    is_sensitive(lbl)                       valid_declassification(obs, lbl, e)
    is_high_risk(action)                    valid_approval_binds(approval, e)

The first two are **row 10** of the frozen label/approval policy (ADR 0022) and
already exist harness-side in `src/harness/policy/frozen_policy.py`; they are
re-exported here so the oracle reaches one implementation. The other two are
built here.

**Why not reuse the SUT's monitor.** `src/sut/authz/reference_monitor.py`
verifies the same artifacts, and importing it would be a red line 4 violation
in substance even though the values are not "verdicts": the oracle would be
accepting the measured system's arithmetic about whether the measured system's
own input was valid. D21's rule is an independent implementation, which is what
this is — the same rule that made `matched_authority.py` reimplement token
verification rather than share the boundary's.

**Trust anchors are a REQUIRED argument, never a default.** `OracleConfig` has
no default trusted-key set and no default policy. An artifact validates only
against keys the caller names, because a defaulted trusted set would let an
artifact signed by any key in the process validate — and the F4/F5 controls
would then pass for the wrong reason. Fail closed is the whole discipline here:
every helper below returns `False` on anything it cannot positively verify.

**What each reads.** Only raw evidence (the presented artifact bytes, which the
harness observed at the boundary), the trusted ledger (`EffectEvent` fields),
sealed truth (`intent`), and sealed configuration (`OracleConfig`). No SUT
verdict, no SUT digest, no reason code, no audit record.
"""

import json
from base64 import urlsafe_b64decode
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from src.harness.policy.frozen_policy import LabelApprovalPolicy
from src.harness.verifier import label_context as lc

# The §F.1 field sets, exact. A payload whose fields differ is malformed, not
# "close enough": an artifact with an extra field signs something this oracle
# did not check, and one with a missing field was never bound to it.
DECLASSIFICATION_FIELDS = frozenset(
    {
        "task_id",
        "audience",
        "tool",
        "request_digest",
        "recipient",
        "payload_digest",
        "from_label",
        "to_label",
        "policy_version",
        "approver_kid",
        "iat",
        "nbf",
        "exp",
        "jti",
    }
)
APPROVAL_FIELDS = frozenset(
    {"authz_context_hash", "approver_kid", "iat", "nbf", "exp", "jti", "replay_rule"}
)


@dataclass(frozen=True)
class OracleConfig:
    """The sealed configuration the oracle needs to judge an artifact.

    Every field is **required**. Each is sealed configuration or a corpus
    scenario specification — never a SUT product, and never a run-time value
    any measured principal could influence.

    `task_id` is here for a reason worth stating rather than hiding: §F.2's
    `authz_context_hash` binds a `task_id`, and the sealed `IntendedInvocation`
    of Part F.1 **carries no `task_id` field**. So the oracle cannot bind a
    presented artifact to the sealed task from sealed truth alone. It is taken
    from the corpus scenario specification, which is a sealed INPUT to the run
    rather than an output of it — reported as a Part I underspecification
    (EXP6 STEP 4's "a predicate that would need a fourth source is a finding").
    """

    policy: LabelApprovalPolicy
    trusted_label_issuers: Mapping[str, str]  # kid -> public wire
    trusted_approvers: Mapping[str, str]  # kid -> public wire
    task_id: str
    now: int

    def __post_init__(self) -> None:
        shared = set(self.trusted_label_issuers) & set(self.trusted_approvers)
        if shared:
            # A kid that both labels data and approves actions could label a
            # payload public and then approve acting on it. The monitor refuses
            # this configuration (ADR 0030); so does the oracle that judges it.
            raise ValueError(
                f"kid(s) {sorted(shared)} appear as BOTH label issuer and approver; the two roles "
                "are deliberately disjoint (ADR 0030) and a shared key collapses them"
            )


def is_sensitive(policy: LabelApprovalPolicy, label: str) -> bool:
    """Row 10's sensitive-label set. Data, not a judgement made here."""
    return policy.is_sensitive(label)


def is_high_risk(policy: LabelApprovalPolicy, action: str) -> bool:
    """Row 10's high-risk action set."""
    return policy.is_high_risk(action)


# ---------------------------------------------------------------------------
# verification primitives
# ---------------------------------------------------------------------------
def _unb64u(text: str) -> bytes:
    return urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _verify(tag: bytes, payload: dict, signature: Any, public_wire: str) -> bool:
    try:
        key = Ed25519PublicKey.from_public_bytes(_unb64u(public_wire))
        raw = signature if isinstance(signature, bytes) else _unb64u(str(signature))
        key.verify(raw, lc.signing_input(tag, payload))
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def _field(obj: Any, name: str) -> Any:
    if isinstance(obj, Mapping):
        return obj.get(name)
    return getattr(obj, name, None)


def _payload_of(artifact: Any, fields: "frozenset[str]") -> "dict | None":
    """The signed payload, or `None` if the field set is not EXACTLY `fields`."""
    if artifact is None:
        return None
    if isinstance(artifact, Mapping):
        present = dict(artifact)
    else:
        present = {
            name: getattr(artifact, name)
            for name in fields | {"signature"}
            if hasattr(artifact, name)
        }
    if set(present) - {"signature"} != set(fields):
        return None
    return {name: value for name, value in present.items() if name != "signature"}


def _in_window(payload: Mapping[str, Any], now: int) -> bool:
    try:
        return int(payload["nbf"]) <= now < int(payload["exp"])
    except (KeyError, TypeError, ValueError):
        return False


# ---------------------------------------------------------------------------
# Part I's two undefined validators
# ---------------------------------------------------------------------------
def valid_declassification(
    intent: Any, observation: Any, label: str, effect: Any, config: OracleConfig
) -> bool:
    """Does the presented declassification authorise THIS effect, for THIS label?

    Every conjunct must hold; any failure is `False`, never an exception that a
    caller could read as "not applicable".

    1. an artifact is present and its field set is exactly §F.1's;
    2. its `approver_kid` is in the **named** trusted approver set, and the
       signature verifies under that key in the `AASC-DECLASS-v1` domain;
    3. `policy_version` equals the frozen `H(Λ)` this run is judged under, so
       an artifact issued under some other policy cannot be replayed into this
       one;
    4. it is inside its own `nbf`/`exp` window at the judging instant;
    5. it binds THIS request — `request_digest` equals the `authz_context_hash`
       the oracle recomputes from the **sealed** intended digest, so an
       artifact minted for a different request does not transfer;
    6. it binds THIS payload — `payload_digest` equals the **effect's** own
       join key, taken from the ledger and not from the labels the request
       carried (stripping a label must not make an exfiltration look harmless);
    7. it binds THIS recipient — `recipient` equals the effect's recipient;
    8. it declassifies the label in question, `from_label == label`, to a
       target that row 10 does **not** call sensitive.
    """
    payload = _payload_of(_field(observation, "declassification"), DECLASSIFICATION_FIELDS)
    if payload is None:
        return False
    artifact = _field(observation, "declassification")
    kid = str(payload.get("approver_kid", ""))
    public_wire = config.trusted_approvers.get(kid)
    if public_wire is None:
        return False
    if not _verify(lc.DECLASSIFICATION_TAG, payload, _field(artifact, "signature"), public_wire):
        return False
    if payload.get("policy_version") != config.policy.document_digest:
        return False
    if not _in_window(payload, config.now):
        return False
    expected_context = lc.authz_context_hash(
        task_id=config.task_id,
        audience=_field(intent, "audience"),
        tool=_field(intent, "tool"),
        canonical_request_digest=_field(intent, "intended_request_digest"),
        resource_owner=_field(intent, "resource_owner"),
        oauth_actor=_field(intent, "oauth_actor"),
    )
    if payload.get("request_digest") != expected_context:
        return False
    if payload.get("payload_digest") != _field(effect, "payload_digest"):
        return False
    if payload.get("recipient") != _field(effect, "recipient"):
        return False
    if payload.get("from_label") != label:
        return False
    return not is_sensitive(config.policy, str(payload.get("to_label", "")))


def valid_approval_binds(intent: Any, approval: Any, effect: Any, config: OracleConfig) -> bool:
    """Does the presented approval bind THIS request and THIS effect?

    Same discipline as above. The approval is carried as raw signed-envelope
    bytes (§F.1), so it is parsed here rather than assumed to be an object —
    and a parse failure is a refusal, not an exception.

    The binding is `authz_context_hash`, which is **mechanism-neutral** by
    construction (§F.2): the same artifact binds identically for a capability
    arm and for an OAuth arm, which is exactly what makes one shared monitor —
    and one shared oracle predicate — legitimate across the ladder.
    """
    if approval is None:
        return False
    if isinstance(approval, (bytes, bytearray)):
        try:
            envelope = json.loads(bytes(approval).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return False
    elif isinstance(approval, Mapping):
        envelope = dict(approval)
    else:
        return False
    payload = envelope.get("payload")
    if not isinstance(payload, Mapping) or set(payload) != set(APPROVAL_FIELDS):
        return False
    payload = dict(payload)
    kid = str(payload.get("approver_kid", ""))
    public_wire = config.trusted_approvers.get(kid)
    if public_wire is None:
        return False
    if not _verify(lc.APPROVAL_TAG, payload, envelope.get("signature"), public_wire):
        return False
    if not _in_window(payload, config.now):
        return False
    expected_context = lc.authz_context_hash(
        task_id=config.task_id,
        audience=_field(intent, "audience"),
        tool=_field(intent, "tool"),
        canonical_request_digest=_field(intent, "intended_request_digest"),
        resource_owner=_field(intent, "resource_owner"),
        oauth_actor=_field(intent, "oauth_actor"),
    )
    if payload.get("authz_context_hash") != expected_context:
        return False
    # ...and the effect it is offered for must be the one the intent names.
    return (_field(effect, "tool"), _field(effect, "audience")) == (
        _field(intent, "tool"),
        _field(intent, "audience"),
    )
