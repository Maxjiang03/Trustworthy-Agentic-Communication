"""TYPE STUBS ONLY — mirrors docs/EXPERIMENT_ARCHITECTURE_FINAL.md Part F.1.

Class and field names are the authoritative Part F.1 schemas. NO validation
and NO logic here; validators, canonicalization, and digest computation are
implemented in the smoke-test phase (gates G-6/G-7/G-8/G-12).
"""

from typing import Literal, Optional

from pydantic import BaseModel


# --- Per-mechanism credential evidence (raw or securely retained) ---
class ApiKeyEvidence(BaseModel):
    kind: Literal["api_key"]
    raw_key_ref: str


class OAuthEvidence(BaseModel):
    kind: Literal["oauth"]
    raw_at: bytes
    dpop_proof: Optional[bytes] = None


class CapabilityEvidence(BaseModel):
    kind: Literal["capability"]
    signed_blocks: list[bytes]  # P_0..P_n as canonical SignedBlocks
    htc_chain: list[bytes]
    invocation_assertion: bytes
    raw_at: bytes


# --- Composite bundle: OAuth+capability+HTC+INV; DPoP+INV; B0/no-credential ---
class EvidenceBundle(BaseModel):
    oauth: Optional[OAuthEvidence] = None
    capability: Optional[CapabilityEvidence] = None
    api_key: Optional[ApiKeyEvidence] = None
    inv_only: Optional[bytes] = None  # for the B2-DPoP + INV-only control arm
    # B0 / no-credential = all fields None


class LabelAssertion(BaseModel):
    # Label join key over payload VALUE bytes; construction deferred - NOT
    # H_JCS - settled by the F4 label-plumbing decision (ADR 0009 classification).
    payload_digest: str
    label: str
    issuer_kid: str
    iat: int
    exp: int
    signature: bytes


class DeclassificationArtifact(BaseModel):
    task_id: str
    audience: str
    tool: str
    # Construction deferred to the F4 label-plumbing decision / G-15
    # (ADR 0009 classification).
    request_digest: str
    recipient: str
    # Join key against LabelAssertion.payload_digest; same deferred
    # construction (ADR 0009 classification).
    payload_digest: str
    from_label: str
    to_label: str
    policy_version: str
    approver_kid: str
    iat: int
    nbf: int
    exp: int
    jti: str
    signature: bytes


# --- What the harness OBSERVES at the boundary (no SUT verdict, no SUT digest) ---
class ObservedRequest(BaseModel):
    # UNFORGEABLE, harness-minted (128-bit; bound into sealed intent + records + INV jti)
    correlation_id: str
    evidence: EvidenceBundle  # raw; harness re-verifies every layer independently
    audience: str
    method: str
    tool: str
    raw_arguments: bytes  # the ORACLE recomputes the digest from these bytes itself
    payload_labels: list[LabelAssertion]
    declassification: Optional[DeclassificationArtifact]
    approval_artifact: Optional[bytes]
    iat: int


# --- Trusted mediation records, emitted by the interposition layer (gates G-6/G-7) ---
class MediationEvent(BaseModel):
    correlation_id: str
    admitted: bool
    reason_code: str
    boundary_ts_ns: int


class ToolIngressEvent(BaseModel):
    correlation_id: str
    tool: str
    audience: str
    # Digest computed at the tool ingress, independently; construction
    # deferred to G-7 (ADR 0009 classification) - if it is ever compared
    # against an H_JCS-governed digest it MUST be H_JCS-governed.
    ingress_request_digest: str
    # Label join key; deferred construction (ADR 0009 classification).
    payload_digest: Optional[str]
    value_id: Optional[str]
    ingress_ts_ns: int


# --- Sealed ground truth, harness-only (tau_gt lives here; no SUT principal may read it) ---
class IntendedInvocation(BaseModel):
    correlation_id: str
    resource_owner: tuple[str, str]  # (iss, sub)
    oauth_actor: tuple[str, str]  # (iss, act/client_id)
    htc_holder_kid: str
    audience: str
    method: str
    tool: str
    # Sealed expected H_JCS digest (frozen construction, ADR 0009).
    intended_request_digest: str
    intended_labels: list[str]
    requires_approval: bool
    U_task: frozenset[tuple[str, str]]
    # H(P_0)..H(P_n): ADR 0003 BlockID prefix commitments (commit_prefix),
    # NOT H_JCS - disposition (b), rendered lowercase hex (ADR 0011).
    P_hashes: list[str]
    C_sets: list[frozenset[tuple[str, str]]]  # C_0..C_n over Omega
    R: frozenset[tuple[str, str]]  # required authority of the concrete request
    tau_gt: frozenset[tuple[str, str]]  # ground-truth task-required scope; ORACLE-ONLY
    attack_subcase: str  # e.g. "F3:dpop-first-use-body-mutation"


# --- Immutable external effect ledger ---
class EffectEvent(BaseModel):
    effect_id: str
    correlation_id: str
    tool: str
    audience: str
    action: str
    resource: str
    recipient: Optional[str]
    # H_JCS (ADR 0009) of what the tool ACTUALLY acted on; ledger-side,
    # independent implementation (D21).
    effect_request_digest: str
    # Label join key; deferred construction (ADR 0009 classification).
    payload_digest: Optional[str]
    value_id: Optional[str]
    data_labels_touched: list[str]
    approval_ref: Optional[str]
    principal: str
    timestamp_ns: int
