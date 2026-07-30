"""`B3`: the full control layer (SS E.5 bits `1 1 1 1 1 1 1 1 0 1`).

Part C row: Phase-2 hop appends a block (`P_{i-1} -> P_i`) **plus an HTC
hop**, offline -- no AS round trip; the boundary sees `AT@aud` (authn) + the
capability `C_n` + the HTC chain + the INV. B3 layers on OAuth, never
replaces it (SS A.4, D28): effective authority is the intersection of the
OAuth resource plane and the capability plane.

Provisioning material arrives INJECTED (EXP1 STEP 12): the frozen
`Omega`/`Gamma` and registry documents as data, the runner-resolved public
keys, this arm's key material, the Phase-1 base token from the AS start-up
line (ADR 0021), and the PILOT-PROVISIONAL policy object -- construction
fails if none is supplied, and the loader refuses a confirmatory run.

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
    CapabilityDecisionPath,
    PilotPolicy,
)
from src.sut.authz.registry_view import build_view
from src.sut.baselines.base import ArmBitmask, HopContext, InvocationContext
from src.sut.capability import signer
from src.sut.capability.signer import CapabilityIssuer

REASON_NOT_PROVISIONED = "b3_not_provisioned"
REASON_NOT_PRESENTED = "b3_nothing_presented"


class B3Arm:
    """Offline attenuation + HTC hop at delegation; the ten conjuncts at the boundary."""

    name = "B3"
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

    def __init__(self) -> None:
        self._setup: dict[str, Any] | None = None
        self._issuer: CapabilityIssuer | None = None
        self._decision_path: CapabilityDecisionPath | None = None
        self._staged: B3Presentation | None = None
        self.audit_log: list[dict[str, Any]] = []

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
            "pilot_policy",
            "run_mode",
        }
        missing = required - set(setup)
        if missing:
            raise ValueError(f"B3 provisioning is missing {sorted(missing)}")
        policy = PilotPolicy.load(setup["pilot_policy"], run_mode=setup["run_mode"])
        registry_view = build_view(setup["registry_document"], setup["resolved_keys"])
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
            pilot_policy=policy,
            audit_sink=self.audit_log.append,
        )
        self._setup = dict(setup)

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
        attenuated = self._issuer.attenuate(root_hop, list(hop.attenuation_elements))
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
            label_assertions_digest="00" * 32,  # bound, not recomputed (rows 4/6; G-15)
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
