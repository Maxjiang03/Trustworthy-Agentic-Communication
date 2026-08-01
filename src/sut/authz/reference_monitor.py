"""The boundary-owned context/approval reference monitor (ADR 0030, gate G-15).

SS F.2 makes `authz_context_hash` **mechanism-neutral** for exactly one reason:
so that **one** monitor can serve every arm. This is that monitor. It takes the
frozen policy (rows 4/6/10, ADR 0022/0023), the trusted issuer sets, and the
artifacts a request presents -- and it takes **nothing** that only a capability
arm could supply. An OAuth arm holding no capability token attaches the same
class over the same policy without modification, which is what makes the
comparison gate **G-15** governs possible at all. If it could only be attached
to `B3`, that comparison would be impossible and every F4/F5 number would be a
statement about which arm happened to have a monitor.

**Attachment is CONFIGURATION, not an arm property.** An arm runs with
`monitor_attached ∈ {true, false}` and its trace records which. That is what
makes SS E.4's `A†` -- *admitted **absent** the shared monitor* -- expressible
rather than flattened into a plain `A`.

**The acceptance half is VERIFICATION, not the removal of a refusal.** Block 2
found `_context_policy_ok` reading `entry.get("label")` off an unverified
mapping, and the fix was to refuse everything. This monitor does not undo that
refusal: it *earns* an acceptance by checking a signature under a trusted issuer,
the artifact's own window, its binding to **this** request's
`authz_context_hash`, the frozen policy version it was issued under, and its
single-use rule. Anything that fails any of those is refused exactly as before,
with the condition named.

**Two windows, and no third.** ADR 0027's `Delta` governs the two artifacts that
authorize *this* invocation -- a `DeclassificationArtifact` and an
`ApprovalArtifact` are per-request objects, so `|now - iat| <= Delta` applies.
A `LabelAssertion` is **not** per-request: SS A.6 states that labels *"are
asserted at ingestion by a trusted source (they exist before task-time capability
issuance)"*, so applying `Delta` to one would refuse every genuinely pre-labelled
payload and make the MSc model unimplementable. Its bound is its own issuer-set
`iat`/`exp`, which is the artifact's own validity rather than a fourth window
constant. ADR 0030 records that asymmetry as a decision rather than leaving it
to be inferred.

**Two trusted sets, deliberately disjoint.** A **label issuer** asserts what data
*is*; an **approver** authorizes an *action*. Conflating them would let whoever
labels a payload also approve a high-risk action on it, so the sets are separate
by kid and by derivation label, and a signature from one set is refused in the
other's domain.
"""

import json
from base64 import urlsafe_b64decode
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from src.sut import freshness
from src.sut.authz import label_context as lc
from src.sut.authz.jti_cache import Consumption, JtiCache
from src.sut.jcs import h_jcs

# SS F.1 payload shapes, minus `signature`, which the signature is taken over.
_LABEL_FIELDS = {"payload_digest", "label", "issuer_kid", "iat", "exp"}
_DECLASS_FIELDS = {
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
_APPROVAL_FIELDS = {
    "authz_context_hash",
    "approver_kid",
    "iat",
    "nbf",
    "exp",
    "jti",
    "replay_rule",
}

# SS F.1 gives `ApprovalArtifact` a `replay_rule` field and gives the
# declassification only a `jti`. ADR 0030 fixes ONE rule for both: an artifact
# authorizes ONE invocation. The approval carries it as a value this profile
# checks; the declassification's is a property of the profile, so no field is
# added to SS F.1's schema to carry it.
SINGLE_USE = "single-use"
APPROVAL_MECHANISM_TAG = "approval"
DECLASS_MECHANISM_TAG = "declass"


class MonitorConfigurationError(Exception):
    """The monitor was misconfigured. Construction-time, fail closed."""


@dataclass(frozen=True)
class RequestContext:
    """SS F.2's six named inputs, and nothing a capability arm alone could give."""

    task_id: str
    audience: str
    tool: str
    canonical_request_digest: str
    resource_owner: tuple[str, str]
    oauth_actor: tuple[str, str]

    @classmethod
    def for_request(
        cls,
        *,
        task_id: str,
        audience: str,
        tool: str,
        arguments: Mapping[str, Any],
        resource_owner: tuple[str, str],
        oauth_actor: tuple[str, str],
    ) -> "RequestContext":
        """Build the context from the arguments the BOUNDARY received.

        Every arm goes through here, so `canonical_request_digest` is `H_JCS`
        of the same object computed by the same code on every arm -- structural
        agreement rather than each arm being trusted to remember the same rule.
        That matters more than it looks: if an OAuth arm and `B3` computed the
        digest even slightly differently they would derive different
        `authz_context_hash` values for one request, and an artifact issued for
        that request would bind on one arm and not the other. The F4/F5
        comparison would then be measuring a digest disagreement.

        The arguments are the boundary's own view -- never a requester's
        account of its own request.
        """
        return cls(
            task_id=task_id,
            audience=audience,
            tool=tool,
            canonical_request_digest=h_jcs(dict(arguments)),
            resource_owner=tuple(resource_owner),
            oauth_actor=tuple(oauth_actor),
        )

    def authz_context_hash(self) -> str:
        return lc.authz_context_hash(
            task_id=self.task_id,
            audience=self.audience,
            tool=self.tool,
            canonical_request_digest=self.canonical_request_digest,
            resource_owner=self.resource_owner,
            oauth_actor=self.oauth_actor,
        )


@dataclass(frozen=True)
class MonitorDecision:
    """One verdict, with the condition named when it refuses."""

    admitted: bool
    reason: str = ""
    verified_labels: tuple[str, ...] = ()

    @property
    def refused(self) -> bool:
        return not self.admitted


ADMIT = MonitorDecision(admitted=True)


class ContextApprovalMonitor:
    """The shared monitor. One class, one policy, every arm."""

    def __init__(
        self,
        *,
        policy,
        label_issuers: Mapping[str, str],
        approvers: Mapping[str, str],
        policy_version: str,
        jti_cache: JtiCache | None = None,
    ) -> None:
        if not policy_version:
            raise MonitorConfigurationError(
                "the monitor needs the frozen policy version it evaluates under: an artifact "
                "issued under one rows-4/6 policy must not survive an amendment to it"
            )
        shared = sorted(set(label_issuers) & set(approvers))
        if shared:
            raise MonitorConfigurationError(
                f"a kid appears in both trusted sets: {shared}. "
                "A label issuer asserts what data IS; an approver authorizes an ACTION. "
                "Conflating them would let whoever labels a payload also approve a high-risk "
                "action on it (ADR 0030)"
            )
        self._policy = policy
        self._label_issuers = dict(label_issuers)
        self._approvers = dict(approvers)
        self._policy_version = policy_version
        # Reuses ADR 0027's cache under its own mechanism tags -- no second
        # cache and no fourth window.
        self._jti_cache = jti_cache if jti_cache is not None else JtiCache()

    # -- verification primitives --------------------------------------------- #
    @staticmethod
    def _unb64u(text: str) -> bytes:
        return urlsafe_b64decode(text + "=" * (-len(text) % 4))

    def _verify_signature(self, tag: bytes, payload: dict, signature, public_wire: str) -> bool:
        try:
            key = Ed25519PublicKey.from_public_bytes(self._unb64u(public_wire))
            raw = signature if isinstance(signature, bytes) else self._unb64u(str(signature))
            key.verify(raw, lc.signing_input(tag, payload))
        except (InvalidSignature, ValueError, TypeError):
            return False
        return True

    @staticmethod
    def _payload_of(artifact: Any, fields: set[str]) -> "dict | None":
        """The signed payload of a presented artifact, or `None` if malformed.

        Accepts a mapping or a pydantic model; the payload is every SS F.1 field
        except `signature`, and the field set must match **exactly** -- a
        missing field would leave something unbound and an extra one would be
        signed but unchecked.
        """
        if hasattr(artifact, "model_dump"):
            data = artifact.model_dump()
        elif isinstance(artifact, Mapping):
            data = dict(artifact)
        else:
            return None
        payload = {key: value for key, value in data.items() if key != "signature"}
        if set(payload) != fields:
            return None
        return payload

    @staticmethod
    def _signature_of(artifact: Any):
        if hasattr(artifact, "signature"):
            return artifact.signature
        if isinstance(artifact, Mapping):
            return artifact.get("signature")
        return None

    # -- 1. LabelAssertion ---------------------------------------------------- #
    def verified_labels(
        self, *, assertions, carried_payloads: Mapping[str, Any], now: int
    ) -> "tuple[dict[str, str], str]":
        """Resolve labels BY PAYLOAD DIGEST (SS A.6), verifying every one.

        Returns `(payload_digest -> label, "")` or `({}, reason)`. A label that
        is merely asserted is never believed: an assertion whose signature does
        not verify under a **trusted label issuer**, whose window has passed, or
        whose label is outside the frozen vocabulary is refused, and so is one
        that names a payload this request does not carry -- otherwise a
        presented assertion could relabel a value that is not there.
        """
        resolved: dict[str, str] = {}
        for index, assertion in enumerate(assertions or ()):
            payload = self._payload_of(assertion, _LABEL_FIELDS)
            if payload is None:
                return {}, f"label assertion {index} is not the SS F.1 shape"
            issuer = self._label_issuers.get(payload["issuer_kid"])
            if issuer is None:
                return {}, (
                    f"label assertion {index} names issuer_kid "
                    f"{payload['issuer_kid']!r}, which is not a trusted label issuer"
                )
            if not self._verify_signature(
                lc.LABEL_ASSERTION_TAG, payload, self._signature_of(assertion), issuer
            ):
                return {}, (
                    f"label assertion {index} does not verify in the "
                    f"{lc.LABEL_ASSERTION_TAG.decode()} domain under its named issuer"
                )
            # SS A.6: labels exist BEFORE task-time issuance, so `Delta` must not
            # apply here -- only the issuer's own validity window.
            if not payload["iat"] <= now <= payload["exp"]:
                return {}, f"label assertion {index} is outside its own iat/exp window"
            if payload["label"] not in self._policy.order:
                return {}, (
                    f"label assertion {index} carries {payload['label']!r}, which is outside "
                    "the frozen label vocabulary (rows 4/6, ADR 0022)"
                )
            digest = payload["payload_digest"]
            if digest not in carried_payloads:
                return {}, (f"label assertion {index} names a payload this request does not carry")
            existing = resolved.get(digest)
            if existing is not None and existing != payload["label"]:
                return {}, (
                    f"two verified assertions disagree on the label of one payload: "
                    f"{existing!r} and {payload['label']!r}"
                )
            resolved[digest] = payload["label"]
        return resolved, ""

    # -- 2. context_policy_ok ------------------------------------------------- #
    def context_decision(
        self,
        context: RequestContext,
        *,
        assertions,
        carried_payloads: Mapping[str, Any],
        declassification,
        recipient: str | None,
        now: int,
    ) -> MonitorDecision:
        """Rows 4 and 6 over VERIFIED labels, with declassification as the
        acceptance path (ADR 0022/0023 + ADR 0030)."""
        resolved, reason = self.verified_labels(
            assertions=assertions, carried_payloads=carried_payloads, now=now
        )
        if reason:
            return MonitorDecision(False, reason)
        labels = tuple(sorted(set(resolved.values())))
        if recipient is None:
            # Non-egress: permit at every label, and unlabelled too -- nothing
            # leaves, so no egress policy can apply.
            return MonitorDecision(True, "", labels)
        label = self._policy.join(list(labels)) if labels else None
        outcome = self._policy.egress_decision(label, recipient)
        if outcome == "permit":
            return MonitorDecision(True, "", labels)
        # `escalate` and `block` are both admissible only under a valid
        # declassification, which is the acceptance half this ADR builds.
        sink = self._policy.sink_class(recipient)
        if declassification is None:
            return MonitorDecision(
                False,
                f"egress of {label or 'an unlabelled payload'} to {sink} is {outcome} under the "
                f"frozen policy and no DeclassificationArtifact was presented",
                labels,
            )
        covered = self._declassification_covers(
            context,
            declassification,
            resolved=resolved,
            label=label,
            recipient=recipient,
            sink=sink,
            now=now,
        )
        if covered.refused:
            return MonitorDecision(covered.admitted, covered.reason, labels)
        return MonitorDecision(True, "", labels)

    def _declassification_covers(
        self,
        context: RequestContext,
        artifact,
        *,
        resolved: Mapping[str, str],
        label: str | None,
        recipient: str,
        sink: str,
        now: int,
    ) -> MonitorDecision:
        payload = self._payload_of(artifact, _DECLASS_FIELDS)
        if payload is None:
            return MonitorDecision(False, "the declassification is not the SS F.1 shape")
        approver = self._approvers.get(payload["approver_kid"])
        if approver is None:
            return MonitorDecision(
                False,
                f"the declassification names approver_kid {payload['approver_kid']!r}, "
                "which is not a trusted approver",
            )
        if not self._verify_signature(
            lc.DECLASSIFICATION_TAG, payload, self._signature_of(artifact), approver
        ):
            return MonitorDecision(
                False,
                f"the declassification does not verify in the "
                f"{lc.DECLASSIFICATION_TAG.decode()} domain under its named approver",
            )
        if payload["request_digest"] != context.authz_context_hash():
            return MonitorDecision(
                False,
                "the declassification is bound to a different authz_context_hash, so it "
                "authorizes some other request",
            )
        if payload["policy_version"] != self._policy_version:
            return MonitorDecision(
                False,
                "the declassification was issued under a different frozen policy version; "
                "rows 4/6 decide whether this pair needs declassifying at all",
            )
        if not payload["nbf"] <= now <= payload["exp"]:
            return MonitorDecision(False, "the declassification is outside its validity window")
        if not freshness.is_fresh(now, payload["iat"]):
            return MonitorDecision(
                False,
                f"the declassification is outside the frozen freshness window Delta="
                f"{freshness.DELTA_SECONDS}s (ADR 0027)",
            )
        if payload["recipient"] != recipient or payload["tool"] != context.tool:
            return MonitorDecision(
                False, "the declassification names a different recipient or tool"
            )
        if payload["task_id"] != context.task_id or payload["audience"] != context.audience:
            return MonitorDecision(False, "the declassification names a different task or audience")
        if resolved.get(payload["payload_digest"]) != payload["from_label"]:
            return MonitorDecision(
                False,
                "the declassification's from_label does not match the VERIFIED label of the "
                "payload it names",
            )
        if payload["from_label"] != label:
            return MonitorDecision(
                False, "the declassification covers a payload other than the one that blocks"
            )
        if (payload["to_label"], sink) not in self._policy.allowed_pairs:
            return MonitorDecision(
                False,
                f"declassifying to {payload['to_label']!r} still does not permit egress to "
                f"{sink} under the frozen allowed-sink policy",
            )
        outcome = self._jti_cache.consume(DECLASS_MECHANISM_TAG, payload["jti"], now=now)
        if outcome is not Consumption.ADMITTED:
            return MonitorDecision(
                False,
                f"the declassification jti was already consumed ({outcome.value}); ADR 0030 "
                "fixes every artifact as single-use",
            )
        return ADMIT

    # -- 3. approval_artifact_ok ---------------------------------------------- #
    def approval_decision(
        self, context: RequestContext, *, approval, now: int, high_risk: bool
    ) -> MonitorDecision:
        """Row 10's high-risk set with a verifiable `ApprovalArtifact` (ADR 0030)."""
        if not high_risk:
            if approval is None:
                return ADMIT
            # A presented approval for a non-high-risk action is still verified
            # rather than ignored: an artifact nobody checks is an artifact an
            # attacker may shape freely.
            return self._approval_binds(context, approval, now=now)
        if approval is None:
            return MonitorDecision(
                False,
                f"{context.tool!r} is a frozen high-risk action (row 10, ADR 0022) and no "
                "ApprovalArtifact was presented",
            )
        return self._approval_binds(context, approval, now=now)

    def _approval_binds(self, context: RequestContext, approval, *, now: int) -> MonitorDecision:
        artifact = approval
        if isinstance(approval, (bytes, bytearray)):
            try:
                envelope = json.loads(bytes(approval))
            except (ValueError, TypeError):
                return MonitorDecision(False, "the approval artifact is not a signed envelope")
            if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"}:
                return MonitorDecision(False, "the approval envelope must be {payload, signature}")
            artifact = dict(envelope["payload"], signature=envelope["signature"])
        payload = self._payload_of(artifact, _APPROVAL_FIELDS)
        if payload is None:
            return MonitorDecision(False, "the approval artifact is not the SS F.2 shape")
        approver = self._approvers.get(payload["approver_kid"])
        if approver is None:
            return MonitorDecision(
                False,
                f"the approval names approver_kid {payload['approver_kid']!r}, which is not a "
                "trusted approver",
            )
        if not self._verify_signature(
            lc.APPROVAL_TAG, payload, self._signature_of(artifact), approver
        ):
            return MonitorDecision(
                False,
                f"the approval does not verify in the {lc.APPROVAL_TAG.decode()} domain under "
                "its named approver",
            )
        if payload["authz_context_hash"] != context.authz_context_hash():
            return MonitorDecision(
                False,
                "the approval is bound to a different authz_context_hash, so it authorizes "
                "some other request",
            )
        if payload["replay_rule"] != SINGLE_USE:
            return MonitorDecision(
                False,
                f"unsupported replay_rule {payload['replay_rule']!r}; ADR 0030 accepts only "
                f"{SINGLE_USE!r} and fails closed on any other",
            )
        if not payload["nbf"] <= now <= payload["exp"]:
            return MonitorDecision(False, "the approval is outside its validity window")
        if not freshness.is_fresh(now, payload["iat"]):
            return MonitorDecision(
                False,
                f"the approval is outside the frozen freshness window Delta="
                f"{freshness.DELTA_SECONDS}s (ADR 0027)",
            )
        outcome = self._jti_cache.consume(APPROVAL_MECHANISM_TAG, payload["jti"], now=now)
        if outcome is not Consumption.ADMITTED:
            return MonitorDecision(
                False,
                f"the approval jti was already consumed ({outcome.value}); its replay_rule is "
                f"{SINGLE_USE!r}",
            )
        return ADMIT
