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

Discriminating the two needs care, and the first attempt was wrong: the
pinned library's denial message lists **every** failed check, including the
attenuation block's own `check if operation(...), scope(...)`, which is the
narrowing -- i.e. the authority plane. Matching "checks failed" alone
therefore attributed every F1 block to `authorizer_policy_ok` and **masked
containment**; the counterfactual suite caught it.

**The discriminator is now STRUCTURAL, not textual** (EXP2 STEP 7). The check
plane is evaluated against **`P_0`**, the authority prefix, which carries no
attenuation block -- so nothing there can fail for a narrowing reason, and
`Allowed(P_0; Gamma, kappa, Omega)` is empty **iff** one of `Gamma`'s own
checks refused.

**Sound by CONSTRUCTION, not merely by probe.** Read off the frozen templates
(ADR 0016), and each clause is asserted by test:

1. the **authority block template carries no `check` at all** -- it is four
   facts (`right/2`, `token_audience/1`, `token_task/1`, `expiry/1`);
2. the **only token-carried check** is the attenuation template's, and it
   consumes `scope/2`, a predicate that appears in **neither** block 0 nor
   `Gamma`;
3. `Gamma`'s three checks consume `expiry/1`, `token_audience/1`,
   `token_task/1` (block-0 facts) plus injected facts, and **none mentions
   `operation/2`** -- so they are candidate-independent and either all pass or
   some fail regardless of which element is probed.

`P_0` contains only block 0, so by (1) the only checks that can run against it
are `Gamma`'s, and by (3) their verdict does not depend on the candidate.
`Allowed(P_0)` is therefore empty exactly when a `Gamma` check refused (or the
authority block grants nothing in `Omega` -- the residual below).

**The dependency this creates, stated because it is easy to lose:** any
`Gamma` amendment re-triggers gate **G-2** *and* this soundness argument. A
future `Gamma` whose check consumed `scope/2`, or an authority block template
that gained a check, or a `Gamma` check that mentioned `operation/2`, would
each break a clause above -- so the structural test is part of what an
amendment must re-establish, not merely the gate.

Four probes established the behaviour on `biscuit-python==0.4.0` before it was
adopted, and the regression suite pins all four:

| probe | outcome against `P_0` |
|---|---|
| inside `C_0`, failing `Gamma` check | `Allowed(P_0)` **empty** -> the check plane |
| inside `C_0`, narrowed away at hop 1 | **permitted** -> falls through to containment |
| outside `C_0` entirely | denied, but no check failed; `Allowed(P_0)` non-empty -> falls through |
| outside `C_0` **and** a failing `Gamma` check | `Allowed(P_0)` **empty** -> the check plane |

No denial message is parsed on the decision path any more. `gamma_checks_in`
below is retained **only** as an independent second witness for the
regression suite -- a canary that fires if a library bump changes the message
shapes the earlier reading depended on.

**Residual, stated rather than hidden:** a capability whose authority block
grants nothing inside `Omega` yields an empty `Allowed(P_0)` for that reason
alone, and is attributed to `authorizer_policy_ok` rather than to
containment. `C_0 = U_task` is non-empty in every scenario the design defines,
so this is degenerate here; it is recorded because the attribution, not the
outcome, is what would differ.

**Orthogonality for the SS E.6 ablations.** `invocation_binding_ok` checks
the INV's *bindings* and window but never re-verifies its signature -- who
signed is `holder_proof_ok`'s question (with `htc_chain_ok`, the -holder
pair). That separation is what makes each ablation a matched leave-one-out.
The `disabled` set is that seam: a disabled conjunct is skipped and recorded,
never silently absent. This pass uses it only for the STEP 13
would-have-failed counterfactuals; no ablation arm is built (forbidden 11).

**The two policy conjuncts are load-bearing, in their REFUSAL half only**
(rows 4/6/10 frozen by ADR 0022, composition amended by ADR 0023). The policy
object is injected configuration and construction fails without one; both
planes evaluate the same frozen bytes and neither imports the other's
evaluation. What the freeze does *not* give is the acceptance half: a
`LabelAssertion`, a `DeclassificationArtifact` and an `ApprovalArtifact` all
hinge on constructions deferred to the F4 label-plumbing decision and
`authz_context_hash` (ADR 0009 category (c), owned by G-15), so each is
**refused with its reason stated** rather than read at face value. F4/F5 stay
unscored until then.
*(Update note: this paragraph read "Two conjuncts cannot honestly be frozen
yet (rows 4/6/10 UNSET)" and was true when written; ADR 0022/0023 froze them.)*

`audit = 1` for B3: the structured JSONL decision log is emitted OFF the
decision path -- a sink failure can cost log completeness, never a
prevention outcome (SS E.5).
"""

import json
from base64 import urlsafe_b64decode
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from src.sut import freshness
from src.sut.authz.boundary import BoundaryConfig, TokenRejected, admits, verify_access_token
from src.sut.authz.jti_cache import Consumption, JtiCache
from src.sut.authz.registry_view import RegistryView, RegistryViewError
from src.sut.baselines.base import ArmIdentity
from src.sut.capability import authority
from src.sut.capability.digests import access_token_hash, commit_prefix, h_jcs
from src.sut.protocol.required_authority import (
    RequiredAuthorityError,
    egress_recipient,
    required_authority,
)

HTC_TAG = b"AASC-HTC-v1"
INV_TAG = b"AASC-INV-v1"
SCHEMA_VERSION = 1

# The three verdicts (ADR 0022, composition amended by ADR 0023). They are not
# ordered here: since ADR 0023 exactly one of them is produced per cell, so
# there is nothing to combine and no restrictiveness ranking to apply.
PERMIT, ESCALATE, BLOCK = "permit", "escalate", "block"

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
# SS F.5's two denials. Not SS A.5 conjuncts: the `jti` is consumed AFTER
# every conjunct passes and BEFORE the tool executes, so a duplicate is
# reported as itself rather than being folded into an earlier condition.
REASON_REPLAY_DUPLICATE = "b3_replay_duplicate"
REASON_REPLAY_CAPACITY = "b3_replay_capacity"
# The SS F.5 key namespace for INV-carried ids. G-14 attaches the same
# cache to `B2-DPoP`, whose ids come from a DPoP proof; the tag is what
# keeps the two from colliding.
INV_MECHANISM_TAG = "inv"

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

    **Not on the decision path.** Since EXP2 STEP 7 the authorizer/containment
    split is decided structurally against `P_0` (module docstring), so nothing
    in production parses a denial message. This function is retained as the
    regression suite's **independent second witness**: it reads the library's
    per-check origin tags (`Check n<deg>N in authorizer` for one of `Gamma`'s
    own checks, `Check n<deg>N in block n<deg>M` for a check carried in a
    token block, i.e. the attenuation narrowing), and the suite asserts it
    agrees with the structural discriminator on all four probe cases. It is a
    canary: if a library bump changes those shapes, a test says so and nothing
    on the decision path is affected.
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


class PolicyConfigurationError(Exception):
    """The policy-dependent conjuncts were misconfigured. Construction-time, fail closed."""


class AuditSinkError(Exception):
    """The audit sink is not one the decision path will accept (ADR 0026)."""


class BoundedAuditBuffer:
    """`audit = 1` without charging the arm for the apparatus (ADR 0026).

    `_audit` runs **inside** `decide`, hence inside the measured segment
    (`frozen_parameters` row 1). A sink that performed disk or network I/O
    there would put the instrument's cost inside the number the "lightweight"
    claim is settled by, so ADR 0026 requires the sink to be a **bounded
    in-memory buffer flushed outside the segment**, asserted structurally
    rather than left to convention.

    Structural, two ways. The decision path accepts **only** this type, so an
    arbitrary callable cannot be wired in; and this type's `append` is a
    `deque` push and nothing else, which a test proves by trapping `open` and
    `socket.socket` around a real append.

    **Overflow drops the oldest record and counts it** -- deliberately the
    opposite of the `jti` cache's fail-closed overflow (ADR 0027). SS E.5 is
    explicit that `audit` never sits on the decision path: a sink failure may
    cost log completeness, never a prevention outcome. Turning an audit
    overflow into a denial would make logging load-bearing, which is exactly
    what that separation forbids. `dropped` is exposed so completeness is
    reported rather than assumed.
    """

    __slots__ = ("_records", "dropped")

    def __init__(self, capacity: int = 4096) -> None:
        if capacity < 1:
            raise AuditSinkError("an audit buffer needs a positive capacity")
        self._records: deque[dict[str, Any]] = deque(maxlen=capacity)
        self.dropped = 0

    def append(self, record: dict[str, Any]) -> None:
        if len(self._records) == self._records.maxlen:
            self.dropped += 1
        self._records.append(record)

    def drain(self) -> list[dict[str, Any]]:
        """Read the buffer out. Called OUTSIDE the segment, by the runner."""
        return list(self._records)

    # Sequence surface, so a caller reads `buffer[-1]` as it would a list.
    def __len__(self) -> int:
        return len(self._records)

    def __iter__(self):
        return iter(self._records)

    def __getitem__(self, index):
        return list(self._records)[index]


@dataclass(frozen=True)
class BoundaryPolicy:
    """Rows 4/6/10 as the boundary consumes them (ADR 0022).

    Built from the **frozen document itself**, injected as sealed
    configuration by the runner -- the SUT never imports the harness loader
    (red line 6), it evaluates the same bytes independently, exactly the line
    ADR 0016 drew for `Omega`/`Gamma`. There is one policy source: the
    PILOT-PROVISIONAL stand-in is gone.

    What this enables is the **refusal** half of both conjuncts. The
    acceptance half needs `authz_context_hash` (ADR 0009 category (c), owned
    by G-15), so a high-risk action is refused because no approval artifact
    can verify -- not because approval is impossible in principle.
    """

    order: tuple[str, ...]
    egress_outcome: dict[str, str]
    non_egress_outcome: str
    unlabelled_egress: str
    unlabelled_non_egress: str
    internal_sink_domain: str
    allowed_pairs: frozenset[tuple[str, str]]
    high_risk_actions: frozenset[str]
    sensitive_labels: frozenset[str]

    @classmethod
    def load(cls, document: Mapping[str, Any] | None) -> "BoundaryPolicy":
        """Build from the frozen document. A missing document fails closed."""
        if document is None:
            raise PolicyConfigurationError(
                "no label/approval policy was injected; defaulting is forbidden (ADR 0022)"
            )
        try:
            row4 = document["row4_context_policy"]
            order = tuple(row4["label_vocabulary"]["total_order"])
            egress = {
                entry["label"]: entry["outcome"]
                for entry in row4["outcomes"]
                if entry["action_class"] == "egress"
            }
            non_egress = next(
                entry["outcome"]
                for entry in row4["outcomes"]
                if entry["action_class"] == "non_egress"
            )
            unlabelled = {entry["action_class"]: entry["outcome"] for entry in row4["unlabelled"]}
            row6 = document["row6_sink_policy"]
            internal = next(
                entry for entry in row6["sink_classes"] if entry["sink"] == "internal-sink"
            )
            row10 = document["row10_oracle_classification"]
            return cls(
                order=order,
                egress_outcome=egress,
                non_egress_outcome=non_egress,
                unlabelled_egress=unlabelled["egress"],
                unlabelled_non_egress=unlabelled["non_egress"],
                internal_sink_domain=internal["internal_domain"],
                allowed_pairs=frozenset(
                    (entry["label"], entry["sink"]) for entry in row6["allowed_pairs"]
                ),
                high_risk_actions=frozenset(
                    entry["action"] for entry in row10["high_risk_actions"]
                ),
                sensitive_labels=frozenset(entry["label"] for entry in row10["sensitive_labels"]),
            )
        except (KeyError, StopIteration, TypeError) as exc:
            raise PolicyConfigurationError(
                f"the injected policy document is not the frozen shape: {exc!r}"
            ) from exc

    def sink_class(self, recipient: str) -> str:
        domain = recipient.rpartition("@")[2]
        return "internal-sink" if domain == self.internal_sink_domain else "external-sink"

    def egress_decision(self, label: str | None, recipient: str | None) -> str:
        """The row 4 + row 6 verdict for one egress (ADR 0023).

        **Row 6 is the permit whitelist; row 4 supplies the severity.** One
        verdict per cell, never two combined -- the rows answer different
        questions, so composing them as two verdicts over one cell was the
        category error ADR 0023 corrects.
        """
        if label is None:
            return self.unlabelled_egress  # fail closed
        if label not in self.order:
            raise PolicyConfigurationError(f"label {label!r} is outside the frozen vocabulary")
        if recipient is None:
            return BLOCK  # declared egress with no classifiable recipient
        if (label, self.sink_class(recipient)) in self.allowed_pairs:
            return PERMIT
        return self.egress_outcome[label]  # row 4 as the severity of the refusal


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
    """The capability boundary decision: the SS A.5 conjuncts over one presentation.

    Two distinct notions of "this arm does not run that conjunct", deliberately
    kept apart:

    * **`enabled`** -- which conjuncts the ARM's mechanism has at all, selected
      by its SS E.5 bitmask. `B-cap` legitimately runs four of the ten because
      it carries no HTC, no INV, and no policy plane; that is its ladder
      position, not an ablation.
    * **`disabled`** -- the SS E.6 ablation seam: `B3` with exactly ONE conjunct
      removed and everything else intact. Guarded, because nothing previously
      stopped `B3` **proper** from silently carrying one (EXP2 STEP 6):
      `B3` proper refuses a non-empty `disabled`; only a declared ablation
      variant may carry one, and exactly the one it is named for; the variant's
      name appears in every audit record it emits; and an ablation variant is
      refused outright on a confirmatory run.
    """

    def __init__(
        self,
        *,
        gamma_document: Mapping[str, Any],
        registry_view: RegistryView,
        oauth_config: BoundaryConfig,
        policy: BoundaryPolicy,
        arm_identity: "ArmIdentity",
        enabled: frozenset[str] | None = None,
        oauth_required_scope: str = "mcp.invoke",
        disabled: frozenset[str] = frozenset(),
        run_mode: str = "pilot",
        audit_buffer: "BoundedAuditBuffer | None" = None,
        jti_cache: "JtiCache | None" = None,
    ) -> None:
        # ADR 0026: the sink runs inside `decide`, hence inside the measured
        # segment, so the decision path accepts ONLY a bounded in-memory
        # buffer. An arbitrary callable -- one that could write a file or
        # open a socket on that path -- is refused at construction rather
        # than trusted not to.
        if audit_buffer is not None and not isinstance(audit_buffer, BoundedAuditBuffer):
            raise AuditSinkError(
                f"audit sink {type(audit_buffer).__name__!r} is not a BoundedAuditBuffer: "
                "the sink runs inside the measured segment (frozen_parameters row 1), so "
                "a sink that could perform disk or network I/O there would charge the arm "
                "for the apparatus (ADR 0026)"
            )
        unknown = (disabled | (enabled or frozenset())) - set(CONJUNCT_ORDER)
        if unknown:
            raise PolicyConfigurationError(f"unknown conjunct name(s) {sorted(unknown)}")
        arm_identity.check_disabled(disabled, run_mode=run_mode)
        self._gamma = dict(gamma_document)
        self._registry = registry_view
        self._oauth_config = oauth_config
        self._policy = policy
        self._identity = arm_identity
        self._enabled = frozenset(CONJUNCT_ORDER) if enabled is None else enabled
        self._scope = oauth_required_scope
        self._disabled = disabled
        self._audit_buffer = audit_buffer
        # SS E.5 bit 9. `None` for `B3` -- which is why `B3` admits
        # bit-identical replay, the residual SS E.1 says `B3+` closes.
        self._jti_cache = jti_cache
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
                if name not in self._enabled:
                    # The arm's bitmask does not carry this conjunct at all
                    # (its ladder position), recorded so the trace is honest.
                    decision.evaluated.append(f"absent:{name}")
                    continue
                if name in self._disabled:
                    # An SS E.6 ablation: present in the mechanism, removed for
                    # this variant, and never silent.
                    decision.evaluated.append(f"skipped:{name}")
                    continue
                conjuncts[name](presentation, tool, arguments, state)
                decision.evaluated.append(name)
            # SS F.5: the `jti` is consumed AFTER all other conjuncts pass and
            # BEFORE the tool executes. Placed here, outside the conjunct loop,
            # because it is not an SS A.5 conjunct -- SS A.5 lists ten and this
            # is not one of them -- and because consuming an id for a request
            # that was going to be refused anyway would burn it for a
            # legitimate retry.
            self._consume_jti(presentation, state, decision)
        except ConjunctFailed as failure:
            decision = Decision(
                admitted=False,
                reason_code=failure.reason_code,
                evaluated=decision.evaluated,
                detail=failure.detail,
            )
        self._audit(decision, tool)
        return decision

    def _consume_jti(self, p: B3Presentation, state, decision: Decision) -> None:
        """`B3+`'s replay layer (SS F.5, D37). Absent for `B3`, and that is the arm.

        `now` is injected (`p.now_epoch`), never read from a wall clock, so an
        over-window fixture advances a logical instant instead of waiting
        `Delta` (ADR 0027).
        """
        if self._jti_cache is None:
            return
        inv = state.get("inv_payload")
        if inv is None:
            # No INV means no authenticated per-request id to consume. SS E.4's
            # footnote makes the same point for the bare bearer arm: the replay
            # cache cannot attach to a credential that carries no id, so this
            # is a refusal rather than a silent pass.
            decision.admitted = False
            decision.reason_code = REASON_REPLAY_DUPLICATE
            decision.detail = "no INV was verified, so there is no authenticated jti to consume"
            return
        outcome = self._jti_cache.consume(INV_MECHANISM_TAG, inv["invocation_id"], now=p.now_epoch)
        if outcome is Consumption.ADMITTED:
            decision.evaluated.append("jti_consumed")
            return
        decision.admitted = False
        if outcome is Consumption.DUPLICATE:
            decision.reason_code = REASON_REPLAY_DUPLICATE
            decision.detail = (
                f"invocation id {inv['invocation_id']!r} was already admitted within Delta="
                f"{self._jti_cache.ttl_seconds}s (SS F.5: at-most-once ADMISSION per jti)"
            )
            return
        decision.reason_code = REASON_REPLAY_CAPACITY
        decision.detail = (
            f"the replay cache holds {self._jti_cache.capacity} unexpired entries; SS F.5 "
            "fails CLOSED on capacity rather than admitting on doubt or evicting an "
            "unexpired entry (ADR 0027)"
        )

    def _audit(self, decision: Decision, tool: str) -> None:
        # audit=1, OFF the decision path: a sink failure never changes the outcome.
        if self._audit_buffer is None:
            return
        try:
            self._audit_buffer.append(
                {
                    "layer": "capability-boundary",
                    # The arm's declared identity, in EVERY record: an ablation
                    # variant's trace can never be mistaken for B3 proper's.
                    "arm": self._identity.name,
                    "is_ablation": self._identity.is_ablation,
                    "ablates": self._identity.ablates,
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
        # The STRUCTURAL check-plane probe (EXP2 STEP 7): evaluate the
        # AUTHORITY prefix P_0, which carries no attenuation block. Nothing
        # there can fail for a narrowing reason, so an empty Allowed(P_0) means
        # one of Gamma's own checks refused -- and a narrowed-away or
        # out-of-C_0 candidate falls through to containment, unmasked.
        # `required_authority` still runs so a malformed request is refused
        # here rather than surfacing later as a spurious containment verdict.
        try:
            required_authority(tool, arguments)
        except RequiredAuthorityError as exc:
            raise ConjunctFailed("authorizer_policy_ok", f"no well-formed R: {exc}") from exc
        authority_prefix = bytes(p.capability_hops[0])
        admitted_at_root = authority.allowed_set(
            authority_prefix,
            self._root_public,
            self._gamma,
            now_epoch=p.now_epoch,
            audience=p.audience,
            task_id=p.task_id,
        )
        if not admitted_at_root:
            raise ConjunctFailed(
                "authorizer_policy_ok",
                "Gamma admits nothing at the authority prefix P_0: one of its own checks "
                "(expiry, audience, task) refused, or the authority block grants nothing in Omega",
            )

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
        # BOUNDARY ACCEPTANCE POLICY, from **ADR 0027** -- not SS F.2, whose
        # Verification MUST list contains `every nbf <= now <= exp` and no
        # `|now - iat| <= Delta` rule at all. The two answer different
        # questions and SS F.2 states the distinction: SS F.2 defines what makes
        # an INV **valid**, and this defines what this boundary is willing to
        # **accept**. The check above is the issuer's chosen validity window;
        # this is how recently the assertion was made.
        #
        # ADR 0027 fixes one `Delta` for this, the DPoP proof `iat` window and
        # the `jti` cache TTL, so G-14's two arms cannot differ in window and
        # any difference it reports is attributable to the mechanisms rather
        # than to the clock. `now` is injected, never read from a wall clock.
        #
        # **Consequence for B3+ fixtures, recorded because it runs toward this
        # project's own hypothesis:** SS E.4 predicts `F3
        # dpop-captured-proof-replay` as `B3 = A` and `B3+ = B`, and that one
        # cell is B3+'s entire reason to exist. A bit-identical replay
        # constructed OUTSIDE `Delta` would now be blocked HERE, by B3, which
        # would collapse the distinction. The fixture MUST be constructed
        # WITHIN `Delta` so that only duplicate detection can catch it
        # (ADR 0027 Consequences; SS E.4; SS J.2 item 9).
        if not freshness.is_fresh(p.now_epoch, inv["iat"]):
            raise ConjunctFailed(
                "invocation_binding_ok",
                f"INV iat is outside the frozen freshness window Delta="
                f"{freshness.DELTA_SECONDS}s (ADR 0027, frozen_parameters row 3)",
            )

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
        """Rows 4 and 6, frozen by ADR 0022/0023, over the concrete request.

        Egress is DERIVED, never enumerated: the tool is egress iff the server
        policy declares a recipient argument for it, which over the frozen
        `Omega` is exactly `mail.send`.

        **A presented label is REFUSED, never read**, exactly as the sibling
        `approval_artifact_ok` refuses a presented `ApprovalArtifact`. SS F.1's
        `LabelAssertion` declares five things that would have to be checked --
        `signature`, `issuer_kid`, `iat`/`exp`, and a `payload_digest` bound to
        the payload bytes -- and its digest construction is deferred to the F4
        label-plumbing decision (ADR 0009 category (c), owned by G-15), so not
        one of them can be verified today. Reading the bare `label` field would
        let an agent-supplied string decide a security verdict and turn a
        `sensitive` egress into a `permit` -- precisely what `required_authority`
        exists to prevent. So the label plane is either verifiable or refused.

        Only the **refusal** half is decided here. `escalate` means admissible
        under a valid approval or declassification artifact, and neither can
        be verified until `authz_context_hash` is fixed -- so `escalate`
        refuses, and says why.
        """
        if p.payload_labels:
            raise ConjunctFailed(
                "context_policy_ok",
                f"{len(p.payload_labels)} label assertion(s) were presented, but no "
                "LabelAssertion can be verified: its payload_digest construction is deferred "
                "to the F4 label-plumbing decision (ADR 0009 category (c), owned by G-15), so "
                "the signature, issuer_kid and iat/exp it declares cannot be checked either. "
                "A self-declared label is not evidence and must not decide a verdict",
            )
        recipient = egress_recipient(tool, arguments)
        if recipient is None:
            # Non-egress: permit at every label, and unlabelled is permitted
            # too -- nothing leaves, so no egress policy can apply.
            return
        # The SS A.6 join over the VERIFIED labels, which is empty by
        # construction while the refusal above stands: so the frozen unlabelled
        # rule decides. The outcome is still READ from the injected document
        # rather than assumed, which is why the three-way dispatch stays -- it
        # is the policy that fails this closed, not this function.
        outcome = self._policy.egress_decision(None, recipient)
        if outcome == PERMIT:
            return
        if outcome == ESCALATE:
            raise ConjunctFailed(
                "context_policy_ok",
                f"egress to {self._policy.sink_class(recipient)} escalates; no "
                "declassification or approval artifact can verify until authz_context_hash "
                "is fixed (ADR 0009 category (c), G-15)",
            )
        raise ConjunctFailed(
            "context_policy_ok",
            f"egress of an unlabelled payload to {self._policy.sink_class(recipient)} is "
            "blocked by the frozen policy (ADR 0022/0023): with no verifiable LabelAssertion "
            "no permit can be established",
        )

    # -- 8. approval_artifact_ok ------------------------------------------------ #
    def _approval_artifact_ok(self, p: B3Presentation, tool, arguments, state) -> None:
        """Row 10's high-risk set, frozen by ADR 0022.

        The **refusal** half only: a high-risk action requires a valid
        `ApprovalArtifact`, and none can verify until `authz_context_hash` is
        fixed (ADR 0009 category (c), owned by G-15). So a high-risk action
        refuses and says exactly why, rather than pretending to verify.
        """
        if tool in self._policy.high_risk_actions:
            raise ConjunctFailed(
                "approval_artifact_ok",
                f"{tool!r} is a frozen high-risk action (ADR 0022 row 10) and requires an "
                "approval artifact; none can verify until authz_context_hash is fixed "
                "(ADR 0009 category (c), G-15)",
            )
        if p.approval_artifact is not None:
            raise ConjunctFailed(
                "approval_artifact_ok",
                "an approval artifact was presented but authz_context_hash is unfixed, so it "
                "cannot be verified (ADR 0009 category (c), G-15)",
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
