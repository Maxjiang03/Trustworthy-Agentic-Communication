"""`B3`: the full control layer (SS E.5 bits `1 1 1 1 1 1 1 1 0 1`).

Part C row: Phase-2 hop appends a block (`P_{i-1} -> P_i`) **plus an HTC
hop**, offline -- no AS round trip; the boundary sees `AT@aud` (authn) + the
capability `C_n` + the HTC chain + the INV. B3 layers on OAuth, never
replaces it (SS A.4, D28): effective authority is the intersection of the
OAuth resource plane and the capability plane.

Provisioning material arrives INJECTED (EXP1 STEP 12): the frozen
`Omega`/`Gamma` and registry documents as data, the runner-resolved public
keys, this arm's key material, the Phase-1 base token from the AS start-up
line (ADR 0021), and the frozen rows 4/6/10 policy document (ADR 0022/0023),
which the arm evaluates itself and refuses to default if absent.

`jti_cache = 0`: B3 does not close bit-identical replay (that is B3+ and
gate G-9); `audit = 1`: the decision path emits its structured log off the
decision path.
"""

from collections.abc import Mapping
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.sut.authz.boundary import BoundaryConfig
from src.sut.authz.capability_path import (
    B3Presentation,
    BoundaryPolicy,
    BoundedAuditBuffer,
    CapabilityDecisionPath,
)
from src.sut.authz.label_context import label_assertions_digest
from src.sut.authz.reference_monitor import ContextApprovalMonitor
from src.sut.authz.registry_view import build_view
from src.sut.baselines.base import ArmBitmask, ArmIdentity, HopContext, InvocationContext
from src.sut.capability import signer
from src.sut.capability.signer import CapabilityIssuer

REASON_NOT_PROVISIONED = "b3_not_provisioned"
REASON_NOT_PRESENTED = "b3_nothing_presented"


class B3Arm:
    """Offline attenuation + HTC hop at delegation; the ten conjuncts at the boundary."""

    # `name` is an instance attribute taken from the declared identity, so an
    # SS E.6 variant cannot present itself as B3 proper.
    bitmask = ArmBitmask(
        oauth_authn=1,
        crypto_chain=1,
        authorizer=1,
        htc_holder=1,
        invoke=1,
        contain=1,
        context=1,
        approval=1,
        jti_cache=0,
        audit=1,
    )

    def __init__(self, identity: ArmIdentity | None = None) -> None:
        # B3 PROPER declares itself non-ablation, so the decision path refuses
        # any `disabled` conjunct it is handed (EXP2 STEP 6). An SS E.6 variant
        # passes its own declared identity instead.
        self.identity = identity or ArmIdentity(name="B3")
        self.name = self.identity.name
        self._setup: dict[str, Any] | None = None
        self._issuer: CapabilityIssuer | None = None
        self._decision_path: CapabilityDecisionPath | None = None
        self._staged: B3Presentation | None = None
        # ADR 0026: bounded and in-memory, because `_audit` runs inside
        # `decide` and therefore inside the measured segment. Drained by
        # the runner OUTSIDE the segment.
        self.audit_log = BoundedAuditBuffer()

    # -- provision: Phase-1 setup (SS E.2), all inputs injected -------------- #
    def provision(self, setup: Mapping[str, Any]) -> None:
        required = {
            "gamma_document",
            "registry_document",
            "resolved_keys",
            "kappa_private",
            "holder_privates",
            "access_token",
            "as_public_jwk",
            "issuer",
            "resource_server",
            "rar_type",
            "policy_document",
            "label_issuers",
            "approvers",
            "policy_version",
            "resource_owner",
            "oauth_actor",
            "run_mode",
        }
        missing = required - set(setup)
        if missing:
            raise ValueError(f"{self.name} provisioning is missing {sorted(missing)}")
        # The frozen ADR 0022 document, injected as sealed configuration and
        # evaluated here independently -- never imported from the harness.
        policy = BoundaryPolicy.load(setup["policy_document"])
        registry_view = build_view(setup["registry_document"], setup["resolved_keys"])
        # ADR 0030's boundary-owned monitor. `B3` runs it because its SS E.5
        # bitmask sets `context = 1` and `approval = 1` -- its ladder position.
        # The SAME class is attached to an OAuth arm as configuration, which is
        # what gate G-15 governs; nothing here is capability-specific.
        monitor = (
            ContextApprovalMonitor(
                policy=policy,
                label_issuers=setup["label_issuers"],
                approvers=setup["approvers"],
                policy_version=setup["policy_version"],
            )
            if setup.get("monitor_attached", True)
            else None
        )
        self._issuer = CapabilityIssuer(setup["gamma_document"], setup["kappa_private"])
        self._decision_path = CapabilityDecisionPath(
            gamma_document=setup["gamma_document"],
            registry_view=registry_view,
            oauth_config=BoundaryConfig(
                issuer=setup["issuer"],
                resource_server=setup["resource_server"],
                as_public_jwk=setup["as_public_jwk"],
                rar_type=setup["rar_type"],
            ),
            policy=policy,
            arm_identity=self.identity,
            enabled=self.bitmask.enabled_conjuncts(),
            disabled=frozenset(setup.get("disabled", ())),
            run_mode=setup["run_mode"],
            audit_buffer=self.audit_log,
            monitor=monitor,
        )
        self._setup = dict(setup)

    def attach_replay_cache(self, cache) -> None:
        """Attach the shared authenticated-request-id cache (gate G-14).

        The SAME method name and the SAME object `B2-DPoP` takes, so the gate
        attaches one cache to both arms rather than two that behave alike.
        `B3` proper carries `jti_cache = 0` as its LADDER position -- attaching
        one here is CONFIGURATION and moves no bit, exactly as ADR 0030's
        monitor is configuration for the policy conjuncts. (`B3+` is the arm
        whose bitmask sets the bit; this seam is what G-14 uses to put the same
        cache on an arm whose ladder position does not include one.)
        """
        if self._decision_path is None:
            raise RuntimeError(REASON_NOT_PROVISIONED)
        self._decision_path._jti_cache = cache

    # -- delegate: the offline Phase-2 hop (SS E.2) --------------------------- #
    def delegate(self, hop: HopContext) -> Mapping[str, Any]:
        if self._issuer is None or self._setup is None:
            raise RuntimeError(REASON_NOT_PROVISIONED)
        holders = self._setup["holder_privates"]
        supervisor = Ed25519PrivateKey.from_private_bytes(holders["holder-supervisor"])
        specialist_pub = signer.public_wire(
            Ed25519PrivateKey.from_private_bytes(holders["holder-specialist"])
        )
        # Task-start issuance: kappa mints U_task as P_0 and names the initial
        # holder in HTC_0 (SS A.3: the AS mints; the Supervisor only narrows).
        root_hop = self._issuer.mint_root(
            list(hop.authority_elements),
            audience=hop.audience,
            task_id=hop.task_id,
            expiry_epoch=hop.expiry_epoch,
        )
        htc0 = self._issuer.issue_htc0(
            root_hop,
            as_root_kid="kid-as-root",
            initial_holder_pubkey=signer.public_wire(supervisor),
            task_id=hop.task_id,
            audience=hop.audience,
            iat=hop.now_epoch,
            nbf=hop.now_epoch,
            exp=hop.expiry_epoch,
        )
        # The measured Phase-2 operation: offline append + HTC hop, no AS trip.
        # `widening_elements` is the SS E.3 chain-tamper intent as a capability
        # arm realizes it -- appended to the SAME block, so what goes on the
        # wire verifies under `kappa_pub` yet carries no authority: block
        # scoping lets a later block narrow what block 0 granted, never widen
        # it. Empty for every benign scenario.
        attenuated = self._issuer.attenuate(
            root_hop, list(hop.attenuation_elements) + list(hop.widening_elements)
        )
        htc1 = signer.issue_htc_hop(
            attenuated,
            index=1,
            signer_private=supervisor,
            signer_kid="kid-holder-supervisor",
            next_holder_pubkey=specialist_pub,
            task_id=hop.task_id,
            audience=hop.audience,
            iat=hop.now_epoch,
            nbf=hop.now_epoch,
            exp=hop.expiry_epoch - 60,  # non-increasing along the chain (SS F.2)
        )
        return {
            "capability_hops": [root_hop.token_bytes, attenuated.token_bytes],
            "block_ids": [list(root_hop.block_ids), list(attenuated.block_ids)],
            "htc_chain": [htc0, htc1],
            "access_token": self._setup["access_token"],
            "audience": hop.audience,
        }

    # -- present: sign the INV for THIS invocation and stage the wire -------- #
    def present(
        self, credentials: Mapping[str, Any], invocation: InvocationContext
    ) -> Mapping[str, Any]:
        if self._setup is None:
            raise RuntimeError(REASON_NOT_PROVISIONED)
        holders = self._setup["holder_privates"]
        specialist = Ed25519PrivateKey.from_private_bytes(holders["holder-specialist"])
        terminal = signer.MintedHop(
            bytes(credentials["capability_hops"][-1]),
            tuple(bytes(b) for b in credentials["block_ids"][-1]),
        )
        inv = signer.issue_inv(
            terminal,
            holder_private=specialist,
            holder_kid="kid-holder-specialist",
            raw_at=credentials["access_token"],
            raw_arguments=dict(invocation.arguments),
            task_id=invocation.task_id,
            audience=invocation.audience,
            method=invocation.method,
            tool=invocation.tool,
            # ADR 0030 closes this ADR 0009 category (c) field too: the INV
            # binds the SORTED join keys of the labels presented with it, so a
            # label set cannot be swapped after signing. The empty set has a
            # real digest, so "no labels" is bound rather than left unfilled.
            label_assertions_digest=label_assertions_digest(
                [entry["payload_digest"] for entry in invocation.payload_labels]
            ),
            invocation_id=invocation.invocation_id,  # the harness-minted correlation id
            iat=invocation.now_epoch,
            nbf=invocation.now_epoch,
            exp=invocation.now_epoch + 300,
        )
        presentation = {
            "capability_hops": [bytes(hop) for hop in credentials["capability_hops"]],
            "htc_chain": [bytes(htc) for htc in credentials["htc_chain"]],
            "invocation_assertion": inv,
            "access_token": credentials["access_token"],
        }
        self._staged = B3Presentation(
            capability_hops=tuple(presentation["capability_hops"]),
            htc_chain=tuple(presentation["htc_chain"]),
            invocation_assertion=inv,
            access_token=credentials["access_token"],
            task_id=invocation.task_id,
            audience=invocation.audience,
            method=invocation.method,
            now_epoch=invocation.now_epoch,
            payload_labels=tuple(invocation.payload_labels),
            declassification=invocation.declassification,
            approval_artifact=invocation.approval_artifact,
            # SS F.2's remaining named inputs, from injected identity
            # CONFIGURATION rather than from any sealed document (red line 5).
            resource_owner=tuple(self._setup["resource_owner"]),
            oauth_actor=tuple(self._setup["oauth_actor"]),
        )
        return presentation

    # -- decide: the ten SS A.5 conjuncts over the staged presentation -------- #
    def decide(self, tool: str, arguments: Mapping[str, Any]) -> tuple[bool, str]:
        if self._decision_path is None:
            return False, REASON_NOT_PROVISIONED  # fail closed
        if self._staged is None:
            return False, REASON_NOT_PRESENTED  # fail closed: nothing presented
        decision = self._decision_path.decide(self._staged, tool, arguments)
        return decision.admitted, decision.reason_code
