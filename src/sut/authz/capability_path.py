"""The B3 boundary decision path: every SS A.5 conjunct a named function (EXP1 STEP 12).

Ten conjuncts, evaluated in the specification's order, each carrying its own
reason code so a block is attributable to exactly one condition -- the shape
gate G-11 established harness-side, now built SUT-side and independently:

    crypto_chain_ok                  b3_crypto_chain
    authorizer_policy_ok             b3_authorizer_policy
    htc_chain_ok                     b3_htc_chain
    holder_proof_ok                  b3_holder_proof
    invocation_binding_ok            b3_invocation_binding
    R subset-of C_n                  b3_containment
    context_policy_ok                b3_context_policy
    approval_artifact_ok             b3_approval_artifact
    oauth_resource_authorization_ok  b3_oauth_resource_authorization
    identity_plane_consistency_ok    b3_identity_plane_consistency

`C_n = Allowed(P_n; Gamma, kappa, Omega)` is computed HERE, SUT-side, by
`src/sut/capability/authority.py` -- one authorizer run per candidate, as
G-2 did, never asserted and never imported from the harness (red line 6).

**The authorizer-policy / containment split, so authority blocks are never
masked.** SS A.5 lists `authorizer_policy_ok(P_n; Gamma)` and `R subset-of
C_n` as separate conjuncts, and they overlap by construction -- `C_n` is
itself computed by running the authorizer, so an out-of-authority element
"fails the authorizer" too. G-11's masking lesson decides the split: an
F1 amplification MUST be attributable to containment, which is also what
Part I's `reference_allow` (`R subset-of C_sets[-1]`) scores. So
`authorizer_policy_ok` owns the **check plane** -- `Gamma`'s own checks
(expiry, audience, task) plus the SS A.6.1 out-of-profile structural
rejection -- and the **authority** question falls through to containment.

Discriminating the two needs care, and the naive version was wrong: the
pinned library's denial message lists **every** failed check, including the
attenuation block's own `check if operation(...), scope(...)`, which is the
narrowing -- i.e. the authority plane. Matching "checks failed" alone
therefore attributed every F1 block to `authorizer_policy_ok` and **masked
containment**; the counterfactual suite caught it. The discriminator is the
check's **origin**: only a check reported `in authorizer` is Gamma's
[VERIFIED by probe on `biscuit-python==0.4.0`, pinned by a test that asserts
both message shapes -- `Check n<deg>N in authorizer` for a Gamma check and
`Check n<deg>N in block n<deg>M` for the attenuation check].

**Orthogonality for the SS E.6 ablations.** `invocation_binding_ok` checks
the INV's *bindings* and window but never re-verifies its signature -- who
signed is `holder_proof_ok`'s question (with `htc_chain_ok`, the -holder
pair). That separation is what makes each ablation a matched leave-one-out.
The `disabled` set is that seam: a disabled conjunct is skipped and recorded,
never silently absent. This pass uses it only for the STEP 13
would-have-failed counterfactuals; no ablation arm is built (forbidden 11).

**Two conjuncts cannot honestly be frozen yet** (rows 4/6/10 UNSET): the
policy object is injected configuration and construction fails without one;
the pilot stand-in carries a PILOT-PROVISIONAL banner and a guard refuses it
on a confirmatory run; and the pilot scenarios carry no LabelAssertion and
no high-risk action, so neither conjunct is load-bearing here -- F4/F5 stay
unscored until those rows are frozen by ADR.

`audit = 1` for B3: the structured JSONL decision log is emitted OFF the
decision path -- a sink failure can cost log completeness, never a
prevention outcome (SS E.5).
"""

import json
from base64 import urlsafe_b64decode
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from src.sut.authz.boundary import BoundaryConfig, TokenRejected, admits, verify_access_token
from src.sut.authz.registry_view import RegistryView, RegistryViewError
from src.sut.capability import authority
from src.sut.capability.digests import access_token_hash, commit_prefix, h_jcs
from src.sut.protocol.required_authority import RequiredAuthorityError, required_authority

HTC_TAG = b"AASC-HTC-v1"
INV_TAG = b"AASC-INV-v1"
SCHEMA_VERSION = 1
PILOT_BANNER = "PILOT-PROVISIONAL"

CONJUNCT_ORDER = (
    "crypto_chain_ok",
    "authorizer_policy_ok",
    "htc_chain_ok",
    "holder_proof_ok",
    "invocation_binding_ok",
    "containment_ok",
    "context_policy_ok",
    "approval_artifact_ok",
    "oauth_resource_authorization_ok",
    "identity_plane_consistency_ok",
)

REASON_CODES = {
    "crypto_chain_ok": "b3_crypto_chain",
    "authorizer_policy_ok": "b3_authorizer_policy",
    "htc_chain_ok": "b3_htc_chain",
    "holder_proof_ok": "b3_holder_proof",
    "invocation_binding_ok": "b3_invocation_binding",
    "containment_ok": "b3_containment",
    "context_policy_ok": "b3_context_policy",
    "approval_artifact_ok": "b3_approval_artifact",
    "oauth_resource_authorization_ok": "b3_oauth_resource_authorization",
    "identity_plane_consistency_ok": "b3_identity_plane_consistency",
}
REASON_ADMITTED = "b3_admitted"

_HTC_FIELDS = {
    "schema_version",
    "kid",
    "prefix_hash",
    "child_block_hash",
    "signer_pubkey",
    "next_holder_pubkey",
    "task_id",
    "audience",
    "iat",
    "nbf",
    "exp",
    "depth",
}
_INV_FIELDS = {
    "schema_version",
    "kid",
    "capability_hash",
    "access_token_hash",
    "task_id",
    "audience",
    "method",
    "tool",
    "canonical_request_digest",
    "label_assertions_digest",
    "invocation_id",
    "iat",
    "nbf",
    "exp",
}


def gamma_checks_in(denial_message: str) -> str:
    """The failed checks that belong to `Gamma` (the AUTHORIZER), if any.

    The library reports every failed check in one message, tagging each with
    its origin: `Check n<deg>N in authorizer` for one of `Gamma`'s own checks
    (expiry, audience, task) and `Check n<deg>N in block n<deg>M` for a check
    carried in a token block -- which, under the frozen templates, is the
    attenuation narrowing and therefore the AUTHORITY plane. Returning only
    the authorizer-origin entries is what keeps containment attributable
    (module docstring; the naive "any failed check" reading masked it).
    """
    flattened = denial_message.replace("\n", " ")
    marker = "checks failed:"
    if marker not in flattened:
        return ""
    listed = flattened.split(marker, 1)[1]
    # Entries are comma-separated `Check n<deg>N in <origin>: <datalog>`.
    authorizer_entries = [
        entry.strip()
        for entry in listed.split("Check ")
        if entry.strip() and " in authorizer" in entry
    ]
    return "; ".join(f"Check {entry}" for entry in authorizer_entries)[:200]


class ConjunctFailed(Exception):
    """One named SS A.5 conjunct refused. `reason_code` names which."""

    def __init__(self, conjunct: str, detail: str) -> None:
        super().__init__(f"{REASON_CODES[conjunct]}: {detail}")
        self.conjunct = conjunct
        self.reason_code = REASON_CODES[conjunct]
        self.detail = detail


class PilotPolicyError(Exception):
    """The policy-dependent conjuncts were misconfigured. Construction-time, fail closed."""


@dataclass(frozen=True)
class PilotPolicy:
    """The injected stand-in for rows 4/6 (context) and 10 (approval).

    Never a silent default: `load` refuses a missing policy, a missing
    PILOT-PROVISIONAL banner, and any run marked confirmatory.
    """

    banner: str
    high_risk_actions: frozenset[str]
    labels_supported: bool

    @classmethod
    def load(cls, policy: Mapping[str, Any] | None, *, run_mode: str) -> "PilotPolicy":
        if policy is None:
            raise PilotPolicyError(
                "no context/approval policy was injected; rows 4/6/10 are UNSET and "
                "defaulting is forbidden (EXP1 STEP 12)"
            )
        banner = str(policy.get("_banner", ""))
        if PILOT_BANNER not in banner:
            raise PilotPolicyError(
                "the injected policy does not carry the PILOT-PROVISIONAL banner"
            )
        if run_mode == "confirmatory":
            raise PilotPolicyError(
                "a PILOT-PROVISIONAL policy may never drive a confirmatory run "
                "(rows 4/6/10 are UNSET)"
            )
        if run_mode != "pilot":
            raise PilotPolicyError(f"unknown run mode {run_mode!r}")
        return cls(
            banner=banner,
            high_risk_actions=frozenset(policy.get("approval", {}).get("high_risk_actions", [])),
            labels_supported=bool(policy.get("context", {}).get("labels_supported", False)),
        )


@dataclass(frozen=True)
class B3Presentation:
    """What the Specialist presents at the boundary (the staged wire material)."""

    capability_hops: tuple[bytes, ...]
    htc_chain: tuple[bytes, ...]
    invocation_assertion: bytes
    access_token: str
    task_id: str
    audience: str
    method: str
    now_epoch: int
    payload_labels: tuple[Mapping[str, Any], ...] = ()
    approval_artifact: bytes | None = None


@dataclass
class Decision:
    admitted: bool
    reason_code: str
    evaluated: list[str] = field(default_factory=list)
    detail: str = ""


def _unb64u(text: str) -> bytes:
    return urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _parse_wire(wire: bytes, fields: set[str], conjunct: str) -> tuple[dict[str, Any], bytes]:
    try:
        envelope = json.loads(wire)
    except (ValueError, TypeError) as exc:
        raise ConjunctFailed(conjunct, "not a well-formed signed envelope") from exc
    if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"}:
        raise ConjunctFailed(conjunct, "envelope must be {payload, signature}")
    payload = envelope["payload"]
    if not isinstance(payload, dict) or set(payload) != fields:
        raise ConjunctFailed(conjunct, "payload fields do not match the SS F.2 schema")
    if payload["schema_version"] != SCHEMA_VERSION:
        raise ConjunctFailed(conjunct, f"unsupported schema_version {payload['schema_version']!r}")
    try:
        signature = _unb64u(envelope["signature"])
    except (ValueError, TypeError) as exc:
        raise ConjunctFailed(conjunct, "signature is not base64url") from exc
    return payload, signature


def _verify_domain_signature(
    tag: bytes, payload: dict[str, Any], signature: bytes, pubkey_wire: str, conjunct: str
) -> None:
    try:
        key = Ed25519PublicKey.from_public_bytes(_unb64u(pubkey_wire))
    except (ValueError, TypeError) as exc:
        raise ConjunctFailed(conjunct, "signer key is not raw Ed25519") from exc
    canonical = rfc8785.dumps(payload)
    message = tag + bytes([SCHEMA_VERSION]) + len(canonical).to_bytes(4, "big") + canonical
    try:
        key.verify(signature, message)
    except InvalidSignature as exc:
        raise ConjunctFailed(
            conjunct, f"signature does not verify in the {tag.decode()} domain"
        ) from exc


class CapabilityDecisionPath:
    """The B3 arm's boundary decision: the ten conjuncts over one presentation."""

    def __init__(
        self,
        *,
        gamma_document: Mapping[str, Any],
        registry_view: RegistryView,
        oauth_config: BoundaryConfig,
        pilot_policy: PilotPolicy,
        oauth_required_scope: str = "mcp.invoke",
        disabled: frozenset[str] = frozenset(),
        audit_sink: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        unknown = disabled - set(CONJUNCT_ORDER)
        if unknown:
            raise PilotPolicyError(f"cannot disable unknown conjuncts {sorted(unknown)}")
        self._gamma = dict(gamma_document)
        self._registry = registry_view
        self._oauth_config = oauth_config
        self._policy = pilot_policy
        self._scope = oauth_required_scope
        self._disabled = disabled
        self._audit_sink = audit_sink
        self._root_public = authority.root_public_from_wire(_unb64u(registry_view.as_root_pubkey))

    # ------------------------------------------------------------------ #
    def decide(
        self, presentation: B3Presentation, tool: str, arguments: Mapping[str, Any]
    ) -> Decision:
        """Evaluate the conjuncts in SS A.5 order; first failure names the block."""
        state: dict[str, Any] = {}
        decision = Decision(admitted=True, reason_code=REASON_ADMITTED)
        conjuncts: dict[str, Callable[..., None]] = {
            "crypto_chain_ok": self._crypto_chain_ok,
            "authorizer_policy_ok": self._authorizer_policy_ok,
            "htc_chain_ok": self._htc_chain_ok,
            "holder_proof_ok": self._holder_proof_ok,
            "invocation_binding_ok": self._invocation_binding_ok,
            "containment_ok": self._containment_ok,
            "context_policy_ok": self._context_policy_ok,
            "approval_artifact_ok": self._approval_artifact_ok,
            "oauth_resource_authorization_ok": self._oauth_resource_authorization_ok,
            "identity_plane_consistency_ok": self._identity_plane_consistency_ok,
        }
        try:
            for name in CONJUNCT_ORDER:
                if name in self._disabled:
                    decision.evaluated.append(f"skipped:{name}")
                    continue
                conjuncts[name](presentation, tool, arguments, state)
                decision.evaluated.append(name)
        except ConjunctFailed as failure:
            decision = Decision(
                admitted=False,
                reason_code=failure.reason_code,
                evaluated=decision.evaluated,
                detail=failure.detail,
            )
        self._audit(decision, tool)
        return decision

    def _audit(self, decision: Decision, tool: str) -> None:
        # audit=1, OFF the decision path: a sink failure never changes the outcome.
        if self._audit_sink is None:
            return
        try:
            self._audit_sink(
                {
                    "layer": "b3-boundary",
                    "tool": tool,
                    "admitted": decision.admitted,
                    "reason_code": decision.reason_code,
                    "evaluated": list(decision.evaluated),
                    "detail": decision.detail,
                }
            )
        except Exception:  # noqa: BLE001 -- log loss is never a prevention outcome
            pass

    # -- 1. crypto_chain_ok ------------------------------------------------ #
    def _crypto_chain_ok(self, p: B3Presentation, tool, arguments, state) -> None:
        from biscuit_auth import Biscuit

        if not p.capability_hops:
            raise ConjunctFailed("crypto_chain_ok", "no capability was presented")
        previous_ids: list[bytes] = []
        for index, hop in enumerate(p.capability_hops):
            try:
                verified = Biscuit.from_bytes(bytes(hop), self._root_public)
            except Exception as exc:  # noqa: BLE001 -- library validation error
                raise ConjunctFailed(
                    "crypto_chain_ok",
                    f"hop {index} does not verify under kappa: {type(exc).__name__}",
                ) from exc
            ids = [bytes.fromhex(rid) for rid in verified.revocation_ids]
            if len(ids) != index + 1 or ids[: len(previous_ids)] != previous_ids:
                raise ConjunctFailed(
                    "crypto_chain_ok", f"hop {index} is not a prefix extension of hop {index - 1}"
                )
            previous_ids = ids
        state["block_ids"] = previous_ids
        state["terminal"] = bytes(p.capability_hops[-1])

    # -- 2. authorizer_policy_ok ------------------------------------------- #
    def _authorizer_policy_ok(self, p: B3Presentation, tool, arguments, state) -> None:
        terminal = state.get("terminal", bytes(p.capability_hops[-1]))
        try:
            authority.reject_out_of_profile(terminal)
        except authority.OutOfProfileError as exc:
            raise ConjunctFailed("authorizer_policy_ok", str(exc)) from exc
        # The check-plane probe: a failed Gamma check (expiry/audience/task)
        # fails HERE; a failed BLOCK check is the attenuation narrowing, so it
        # falls through to containment and an F1 block is never masked.
        try:
            elements = sorted(required_authority(tool, arguments))
        except RequiredAuthorityError as exc:
            raise ConjunctFailed("authorizer_policy_ok", f"no well-formed R: {exc}") from exc
        for element in elements:
            failed_checks = self._failed_gamma_checks(terminal, element, p)
            if failed_checks:
                raise ConjunctFailed("authorizer_policy_ok", f"Gamma check failed: {failed_checks}")

    def _failed_gamma_checks(
        self, token_bytes: bytes, element: tuple[str, str], p: B3Presentation
    ) -> str:
        from datetime import datetime, timezone

        from biscuit_auth import AuthorizationError, AuthorizerBuilder, Biscuit, Fact

        token = Biscuit.from_bytes(token_bytes, self._root_public)
        builder = AuthorizerBuilder(self._gamma["gamma"]["datalog"]["authorizer"])
        action, resource = element
        builder.add_fact(
            Fact("operation({action}, {resource})", {"action": action, "resource": resource})
        )
        builder.add_fact(
            Fact("time({t})", {"t": datetime.fromtimestamp(p.now_epoch, tz=timezone.utc)})
        )
        builder.add_fact(Fact("request_audience({aud})", {"aud": p.audience}))
        builder.add_fact(Fact("request_task({task})", {"task": p.task_id}))
        try:
            builder.build(token).authorize()
        except AuthorizationError as exc:
            return gamma_checks_in(str(exc))
        return ""

    # -- 3. htc_chain_ok ---------------------------------------------------- #
    def _htc_chain_ok(self, p: B3Presentation, tool, arguments, state) -> None:
        block_ids = state.get("block_ids")
        if block_ids is None:
            raise ConjunctFailed("htc_chain_ok", "no verified capability chain to cover")
        if not p.htc_chain:
            raise ConjunctFailed("htc_chain_ok", "no HTC chain was presented")
        if len(p.htc_chain) != len(block_ids):
            raise ConjunctFailed(
                "htc_chain_ok",
                f"{len(p.htc_chain)} HTCs do not cover {len(block_ids)} signed blocks",
            )
        payloads: list[dict[str, Any]] = []
        previous: dict[str, Any] | None = None
        for index, wire in enumerate(p.htc_chain):
            payload, signature = _parse_wire(bytes(wire), _HTC_FIELDS, "htc_chain_ok")
            if index == 0:
                if payload["kid"] != self._registry.as_root_kid:
                    raise ConjunctFailed("htc_chain_ok", "HTC_0 kid is not the AS root kid")
                if payload["signer_pubkey"] != self._registry.as_root_pubkey:
                    raise ConjunctFailed("htc_chain_ok", "HTC_0 signer is not kappa")
                _verify_domain_signature(
                    HTC_TAG, payload, signature, self._registry.as_root_pubkey, "htc_chain_ok"
                )
            else:
                if payload["signer_pubkey"] != previous["next_holder_pubkey"]:
                    raise ConjunctFailed(
                        "htc_chain_ok",
                        f"HTC_{index}.signer_pubkey is not HTC_{index - 1}.next_holder_pubkey",
                    )
                try:
                    principal = self._registry.principal_of_kid(payload["kid"])
                    if self._registry.holder_key(principal) != payload["signer_pubkey"]:
                        raise ConjunctFailed(
                            "htc_chain_ok",
                            f"HTC_{index} kid names a principal whose key is not the signer",
                        )
                    self._registry.principal_of_key(payload["next_holder_pubkey"])
                except RegistryViewError as exc:
                    raise ConjunctFailed("htc_chain_ok", str(exc)) from exc
                _verify_domain_signature(
                    HTC_TAG, payload, signature, payload["signer_pubkey"], "htc_chain_ok"
                )
                if payload["task_id"] != previous["task_id"]:
                    raise ConjunctFailed("htc_chain_ok", "task_id changed along the chain")
                if payload["audience"] != previous["audience"]:
                    raise ConjunctFailed("htc_chain_ok", "audience changed along the chain")
                if payload["exp"] > previous["exp"]:
                    raise ConjunctFailed("htc_chain_ok", "exp increased along the chain")
            if payload["depth"] != index:
                raise ConjunctFailed("htc_chain_ok", f"depth not contiguous at hop {index}")
            if not payload["nbf"] <= p.now_epoch <= payload["exp"]:
                raise ConjunctFailed("htc_chain_ok", f"HTC_{index} outside its validity window")
            expected_prefix = commit_prefix(block_ids, max(index - 1, 0)).hex()
            if payload["prefix_hash"] != expected_prefix:
                raise ConjunctFailed(
                    "htc_chain_ok", f"HTC_{index}.prefix_hash does not match the presented prefix"
                )
            if payload["child_block_hash"] != block_ids[index].hex():
                raise ConjunctFailed(
                    "htc_chain_ok", f"HTC_{index}.child_block_hash is not SignedBlock_{index}"
                )
            payloads.append(payload)
            previous = payload
        state["htc_payloads"] = payloads
        state["terminal_holder"] = payloads[-1]["next_holder_pubkey"]

    # -- 4. holder_proof_ok -------------------------------------------------- #
    def _holder_proof_ok(self, p: B3Presentation, tool, arguments, state) -> None:
        inv, signature = self._inv_payload(p, state, conjunct="holder_proof_ok")
        terminal_holder = state.get("terminal_holder")
        if terminal_holder is None:
            raise ConjunctFailed("holder_proof_ok", "no terminal holder key (chain unverified)")
        try:
            terminal_principal = self._registry.principal_of_key(terminal_holder)
            if self._registry.principal_of_kid(inv["kid"]) != terminal_principal:
                raise ConjunctFailed(
                    "holder_proof_ok", "INV.kid is not the terminal holder the last HTC names"
                )
        except RegistryViewError as exc:
            raise ConjunctFailed("holder_proof_ok", str(exc)) from exc
        _verify_domain_signature(INV_TAG, inv, signature, terminal_holder, "holder_proof_ok")
        state["inv_signature_verified"] = True

    # -- 5. invocation_binding_ok -------------------------------------------- #
    def _invocation_binding_ok(self, p: B3Presentation, tool, arguments, state) -> None:
        # Bindings and window ONLY: who signed is holder_proof_ok's question,
        # which keeps the SS E.6 -holder / -invoke ablations orthogonal.
        inv, _ = self._inv_payload(p, state, conjunct="invocation_binding_ok")
        block_ids = state.get("block_ids")
        if block_ids is not None:
            expected = commit_prefix(block_ids, len(block_ids) - 1).hex()
            if inv["capability_hash"] != expected:
                raise ConjunctFailed(
                    "invocation_binding_ok",
                    "INV.capability_hash does not match the presented capability",
                )
        if inv["access_token_hash"] != access_token_hash(p.access_token):
            raise ConjunctFailed(
                "invocation_binding_ok", "INV.access_token_hash does not match the presented AT"
            )
        if inv["canonical_request_digest"] != h_jcs(dict(arguments)):
            raise ConjunctFailed(
                "invocation_binding_ok",
                "INV.canonical_request_digest does not match the concrete arguments",
            )
        if inv["task_id"] != p.task_id:
            raise ConjunctFailed("invocation_binding_ok", "INV.task_id does not bind this task")
        if inv["audience"] != p.audience:
            raise ConjunctFailed(
                "invocation_binding_ok", "INV.audience does not bind this audience"
            )
        if inv["method"] != p.method:
            raise ConjunctFailed("invocation_binding_ok", "INV.method does not bind this method")
        if inv["tool"] != tool:
            raise ConjunctFailed("invocation_binding_ok", "INV.tool does not bind the invoked tool")
        if not inv["invocation_id"]:
            raise ConjunctFailed("invocation_binding_ok", "INV carries no invocation id")
        if not inv["nbf"] <= p.now_epoch <= inv["exp"]:
            raise ConjunctFailed("invocation_binding_ok", "INV outside its validity window")

    def _inv_payload(self, p: B3Presentation, state, *, conjunct: str) -> tuple[dict, bytes]:
        if "inv_payload" not in state:
            payload, signature = _parse_wire(bytes(p.invocation_assertion), _INV_FIELDS, conjunct)
            state["inv_payload"] = payload
            state["inv_signature"] = signature
        return state["inv_payload"], state["inv_signature"]

    # -- 6. R subset-of C_n --------------------------------------------------- #
    def _containment_ok(self, p: B3Presentation, tool, arguments, state) -> None:
        try:
            required = required_authority(tool, arguments)
        except RequiredAuthorityError as exc:
            raise ConjunctFailed("containment_ok", f"no well-formed R: {exc}") from exc
        allowed = authority.allowed_set(
            bytes(p.capability_hops[-1]),
            self._root_public,
            self._gamma,
            now_epoch=p.now_epoch,
            audience=p.audience,
            task_id=p.task_id,
        )
        state["C_n"] = allowed
        if not required <= allowed:
            outside = sorted(required - allowed)
            raise ConjunctFailed(
                "containment_ok", f"R exceeds C_n: {outside} outside the effective authority"
            )

    # -- 7. context_policy_ok -------------------------------------------------- #
    def _context_policy_ok(self, p: B3Presentation, tool, arguments, state) -> None:
        # Rows 4/6 are UNSET: the pilot policy supports NO label evaluation, so
        # any presented LabelAssertion is un-evaluable and fails closed. The
        # pilot scenarios carry none -- the conjunct is not load-bearing here,
        # and F4 stays unscored until the rows are frozen by ADR.
        if p.payload_labels and not self._policy.labels_supported:
            raise ConjunctFailed(
                "context_policy_ok",
                "payload labels presented but rows 4/6 are UNSET (no frozen label policy)",
            )

    # -- 8. approval_artifact_ok ------------------------------------------------ #
    def _approval_artifact_ok(self, p: B3Presentation, tool, arguments, state) -> None:
        # Row 10 is UNSET: the pilot high-risk set is EMPTY, so no action can
        # require approval, and any presented artifact is un-verifiable
        # (authz_context_hash is ADR 0009 category (c), G-15's) -- fail closed
        # rather than pretend to verify. F5 stays unscored.
        if tool in self._policy.high_risk_actions:
            raise ConjunctFailed(
                "approval_artifact_ok",
                "high-risk action but row 10 is UNSET; no approval artifact can verify",
            )
        if p.approval_artifact is not None:
            raise ConjunctFailed(
                "approval_artifact_ok",
                "an approval artifact was presented but row 10 is UNSET (unverifiable)",
            )

    # -- 9. oauth_resource_authorization_ok ------------------------------------- #
    def _oauth_resource_authorization_ok(self, p: B3Presentation, tool, arguments, state) -> None:
        # Reuses src/sut/authz/boundary.py UNCHANGED (EXP1 STEP 11):
        # verify_access_token, allowed_authority via admits.
        try:
            claims = verify_access_token(p.access_token, self._oauth_config, now=p.now_epoch)
        except TokenRejected as exc:
            raise ConjunctFailed(
                "oauth_resource_authorization_ok", f"{exc.reason}: {exc.description}"
            ) from exc
        try:
            elements = sorted(required_authority(tool, arguments))
        except RequiredAuthorityError as exc:
            raise ConjunctFailed(
                "oauth_resource_authorization_ok", f"no well-formed R: {exc}"
            ) from exc
        for element in elements:
            decision = admits(
                claims, self._oauth_config, element=element, required_scope=self._scope
            )
            if not decision.admitted:
                raise ConjunctFailed("oauth_resource_authorization_ok", decision.reason)
        state["oauth_claims"] = claims

    # -- 10. identity_plane_consistency_ok --------------------------------------- #
    def _identity_plane_consistency_ok(self, p: B3Presentation, tool, arguments, state) -> None:
        claims = state.get("oauth_claims")
        if claims is None:
            raise ConjunctFailed(
                "identity_plane_consistency_ok", "no verified OAuth claims to map from"
            )
        # oauth_actor = outermost act.sub, else client_id (SS A.5.1; RFC 8693
        # SS 4.1: nested actors are audit history and are never consulted).
        act = claims.get("act")
        actor_claim = act.get("sub") if isinstance(act, dict) else claims.get("client_id")
        if not isinstance(actor_claim, str) or not actor_claim:
            raise ConjunctFailed("identity_plane_consistency_ok", "no oauth_actor claim")
        # SS A.5.1: the mapping targets the terminal htc_holder key the chain
        # NAMES. Verifying the chain is htc_chain_ok's job; when that conjunct
        # ran, the verified value is in `state`; when it is ablated (SS E.6
        # -holder), the name is read from the presented terminal HTC unverified
        # -- so this conjunct never masks the holder limb.
        terminal_holder = state.get("terminal_holder")
        if terminal_holder is None:
            terminal_holder = self._named_terminal_holder(p)
        try:
            principal = self._registry.actor_of(actor_claim)
            expected_key = self._registry.holder_key(principal)
        except RegistryViewError as exc:
            raise ConjunctFailed("identity_plane_consistency_ok", str(exc)) from exc
        if expected_key != terminal_holder:
            raise ConjunctFailed(
                "identity_plane_consistency_ok",
                f"oauth_actor {actor_claim!r} does not map to the terminal htc_holder key",
            )
        # Deliberately NOT checked: resource_owner == holder (SS A.5.1 MUST NOT).

    def _named_terminal_holder(self, p: B3Presentation) -> str:
        if not p.htc_chain:
            raise ConjunctFailed(
                "identity_plane_consistency_ok", "no HTC chain names a terminal holder"
            )
        try:
            envelope = json.loads(bytes(p.htc_chain[-1]))
            named = envelope["payload"]["next_holder_pubkey"]
        except (ValueError, TypeError, KeyError) as exc:
            raise ConjunctFailed(
                "identity_plane_consistency_ok", "terminal HTC names no holder key"
            ) from exc
        if not isinstance(named, str) or not named:
            raise ConjunctFailed(
                "identity_plane_consistency_ok", "terminal HTC names no holder key"
            )
        return named
