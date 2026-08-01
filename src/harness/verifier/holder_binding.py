"""The HTC chain and the INV assertion: construction and the full SS F.2 verification.

Every condition in SS F.2's "Verification (MUST all hold)" paragraph is a separate
named check with its own reason code, so a rejection says **which** condition
failed rather than merely that something did. Verification is fail-closed: the
first failing condition raises, and the reason code names it.

**Domain separation is load-bearing, not cosmetic.** Every signature is over
`TAG || VERSION || u32be(len(C)) || C`, with `C` the RFC 8785 canonical bytes of
the payload and `TAG` one of `b"AASC-HTC-v1"` / `b"AASC-INV-v1"` (SS F.2). Because
the tag is inside the signed bytes, a payload signed in the HTC domain **cannot**
verify in the INV domain -- which is what the domain-tag-confusion mutation
tests. SS F.2 mandates the tag and version prefix but not the serialization of the
rest; RFC 8785 canonical bytes with a big-endian length prefix is the choice made
here, for consistency with every other frozen layout in the project (ADR 0018).

**The zero-hop rule (MUST).** `n = 0` is the general verification with a
one-element chain, and there is **no separate code path**. The loop below branches
on the hop **index** -- `HTC_0` is signed by the AS root key and carries
`depth: 0`, exactly as the template requires -- and never on the chain **length**.
`prefix_hash` uses `max(i - 1, 0)` rather than a conditional, because the template
gives `HTC_0.prefix_hash` as the commitment over `BlockID_0` itself while every
later hop commits to the prefix ending one block earlier.

**Commitments are reused, never reinvented.** `prefix_hash`,
`child_block_hash` and `INV.capability_hash` all come from
`src/harness/oracle/commitment.py` (ADR 0003), which independently verifies the
signature chain from **raw token bytes** before extracting any identifier, and
rejects third-party blocks and non-Ed25519 keys. `check_htc_coverage` is that
module's count check.

**What is bound but not recomputed.** `INV.label_assertions_digest` now HAS a
fixed construction (ADR 0030, `AASC-LABELSET-DIGEST` over the sorted join keys),
but this verifier still does not recompute it, and that is deliberate rather than
residual: this module implements SS F.2's **validity** MUST list, which G-11
adjudicated, and the label set is verified against the presented assertions by the
boundary-owned monitor -- a different question, in a different place. The
signature covers the field, so it is tamper-evident here. The `ApprovalArtifact`
of SS F.2 is likewise out of scope: no condition in SS F.2's verification
paragraph refers to it (`approval_artifact_ok` is a separate SS A.5 conjunct,
owned by the monitor and G-15).
*(Update note, 2026-08-01: this paragraph read "has no fixed construction:
ADR 0009 classifies it category (c) ... and G-15 verifies it", true when written.
ADR 0030 fixed the construction; what this module does with it is unchanged.)*

Trust rule (D21): this module is instrument-side and recomputes every digest it
checks from raw evidence. `build_htc_chain` and `build_inv` mint **fixtures** for
gate and regression use; the B3 arm's SUT-side signer must be an independent
implementation, and that obligation is still owed.
"""

import json
from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from src.harness.oracle import commitment
from src.harness.oracle.jcs_digest import h_jcs
from src.harness.verifier.at_digest import access_token_hash
from src.harness.verifier.registry import BoundRegistry, RegistryError

HTC_TAG = b"AASC-HTC-v1"  # SS F.2
INV_TAG = b"AASC-INV-v1"  # SS F.2
SCHEMA_VERSION = 1

_HTC_FIELDS = (
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
)
_INV_FIELDS = (
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
)

# Reason codes: one per SS F.2 condition, so a rejection is attributable.
CAPABILITY_CHAIN_INVALID = "capability_chain_invalid"
COMMITMENT_UNSUPPORTED_VERSION = "commitment_unsupported_version"
COMMITMENT_UNSUPPORTED_ALGORITHM = "commitment_unsupported_algorithm"
HTC_CHAIN_EMPTY = "htc_chain_empty"
HTC_SCHEMA = "htc_schema"
HTC_COVERAGE_COUNT = "htc_coverage_count"
HTC_UNSUPPORTED_SCHEMA_VERSION = "htc_unsupported_schema_version"
HTC0_SIGNER_IS_ROOT = "htc0_signer_is_root"
HTC0_ROOT_SIGNATURE = "htc0_root_signature"
HTC_CHAIN_LINKAGE = "htc_chain_linkage"
HTC_SIGNATURE = "htc_signature"
HTC_TASK_INVARIANT = "htc_task_invariant"
HTC_AUDIENCE_INVARIANT = "htc_audience_invariant"
HTC_DEPTH_CONTIGUOUS = "htc_depth_contiguous"
HTC_EXP_NON_INCREASING = "htc_exp_non_increasing"
HTC_VALIDITY_WINDOW = "htc_validity_window"
HTC_PREFIX_HASH = "htc_prefix_hash"
HTC_CHILD_BLOCK_HASH = "htc_child_block_hash"
REGISTRY_UNMAPPED = "registry_unmapped"
REGISTRY_KEY_MISMATCH = "registry_key_mismatch"
INV_SCHEMA = "inv_schema"
INV_UNSUPPORTED_SCHEMA_VERSION = "inv_unsupported_schema_version"
INV_TERMINAL_HOLDER = "inv_terminal_holder"
INV_SIGNATURE = "inv_signature"
INV_CAPABILITY_HASH = "inv_capability_hash"
INV_ACCESS_TOKEN_HASH = "inv_access_token_hash"
INV_REQUEST_DIGEST = "inv_request_digest"
INV_TASK_BINDING = "inv_task_binding"
INV_AUDIENCE_BINDING = "inv_audience_binding"
INV_METHOD_BINDING = "inv_method_binding"
INV_TOOL_BINDING = "inv_tool_binding"
INV_VALIDITY_WINDOW = "inv_validity_window"


class HolderBindingRejected(Exception):
    """A SS F.2 condition failed. `reason_code` names which one."""

    def __init__(self, reason_code: str, detail: str = "") -> None:
        super().__init__(f"{reason_code}: {detail}")
        self.reason_code = reason_code
        self.detail = detail


def b64u(raw: bytes) -> str:
    return urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def unb64u(text: str) -> bytes:
    return urlsafe_b64decode(text + "=" * (-len(text) % 4))


def public_key_wire(key: Ed25519PublicKey) -> str:
    from cryptography.hazmat.primitives import serialization

    return b64u(key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


# --------------------------------------------------------------------------
# Signing input and wire form
# --------------------------------------------------------------------------


def signing_input(tag: bytes, payload: dict[str, Any], *, version: int = SCHEMA_VERSION) -> bytes:
    """`tag || version || u32be(len(C)) || C` with C the canonical payload bytes."""
    if version != SCHEMA_VERSION:
        raise HolderBindingRejected(
            HTC_UNSUPPORTED_SCHEMA_VERSION, f"unsupported schema version {version}"
        )
    canonical = rfc8785.dumps(payload)
    return tag + bytes([version]) + len(canonical).to_bytes(4, "big") + canonical


def seal(tag: bytes, payload: dict[str, Any], signing_key: Ed25519PrivateKey) -> bytes:
    """Sign a payload in one domain and return its wire form. Fixture constructor."""
    signature = signing_key.sign(signing_input(tag, payload))
    return rfc8785.dumps({"payload": payload, "signature": b64u(signature)})


def _open(wire: bytes, fields: tuple[str, ...], schema_reason: str) -> tuple[dict[str, Any], bytes]:
    """Parse a wire object into (payload, signature). Structure failures are typed."""
    try:
        envelope = json.loads(wire)
    except (ValueError, TypeError) as exc:
        raise HolderBindingRejected(schema_reason, "not a well-formed JSON envelope") from exc
    if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"}:
        raise HolderBindingRejected(schema_reason, "envelope must be {payload, signature}")
    payload = envelope["payload"]
    if not isinstance(payload, dict):
        raise HolderBindingRejected(schema_reason, "payload must be a JSON object")
    missing = [name for name in fields if name not in payload]
    extra = [name for name in payload if name not in fields]
    if missing or extra:
        raise HolderBindingRejected(
            schema_reason, f"payload fields missing={missing} unexpected={extra}"
        )
    try:
        signature = unb64u(envelope["signature"])
    except (ValueError, TypeError) as exc:
        raise HolderBindingRejected(schema_reason, "signature is not base64url") from exc
    return payload, signature


def _verify_signature(
    tag: bytes, payload: dict[str, Any], signature: bytes, public_key_b64u: str, reason: str
) -> None:
    try:
        key = Ed25519PublicKey.from_public_bytes(unb64u(public_key_b64u))
    except (ValueError, TypeError) as exc:
        raise HolderBindingRejected(reason, "signer key is not a raw Ed25519 public key") from exc
    try:
        key.verify(signature, signing_input(tag, payload))
    except InvalidSignature as exc:
        raise HolderBindingRejected(
            reason, f"signature does not verify in the {tag.decode()} domain"
        ) from exc


# --------------------------------------------------------------------------
# Presented evidence and result
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class PresentedEvidence:
    """What arrives at the boundary. Raw, so the verifier recomputes everything."""

    token_bytes: bytes  # the presented capability, raw (SS F.2: "recomputed from raw bytes")
    htc_chain: tuple[bytes, ...]
    invocation_assertion: bytes
    raw_at: str  # the presented AT@aud, compact serialization
    raw_arguments: Any  # the arguments object, for H_JCS
    task_id: str
    audience: str
    method: str
    tool: str


@dataclass(frozen=True)
class VerificationResult:
    """A successful verification, with the ordered names of the checks that ran."""

    checks: tuple[str, ...]
    htc_payloads: tuple[dict[str, Any], ...]
    inv_payload: dict[str, Any]
    capability_hash: str
    terminal_holder_pubkey: str


def verify(
    evidence: PresentedEvidence,
    registry: BoundRegistry,
    root_pub: Any,
    *,
    now: int,
) -> VerificationResult:
    """The complete SS F.2 verification. Raises `HolderBindingRejected` on the first failure.

    `root_pub` is the Biscuit root public key (kappa), needed for the ADR 0003
    independent chain verification. Verification requires **only** kappa plus the
    in-chain holder keys resolved via the registry (SS F.2).
    """
    checks: list[str] = []

    def ran(name: str) -> None:
        checks.append(name)

    # --- The capability itself, from raw bytes (ADR 0003) --------------------
    try:
        block_ids = commitment.block_ids_from_raw(evidence.token_bytes, root_pub)
    except commitment.UnsupportedVersionError as exc:
        raise HolderBindingRejected(COMMITMENT_UNSUPPORTED_VERSION, str(exc)) from exc
    except commitment.UnsupportedAlgorithmError as exc:
        raise HolderBindingRejected(COMMITMENT_UNSUPPORTED_ALGORITHM, str(exc)) from exc
    except Exception as exc:  # BiscuitValidationError, TokenStructureError, ...
        raise HolderBindingRejected(
            CAPABILITY_CHAIN_INVALID, f"{type(exc).__name__}: {exc}"
        ) from exc
    ran(CAPABILITY_CHAIN_INVALID)

    if not evidence.htc_chain:
        raise HolderBindingRejected(HTC_CHAIN_EMPTY, "no HTC was presented")
    ran(HTC_CHAIN_EMPTY)

    # --- HTC count equals the number of presented signed blocks -------------
    # SS F.2: every presented SignedBlock_i is covered by a corresponding HTC_i,
    # and a block with no covering HTC is rejected. The INV.capability_hash check
    # would also detect it; this fails fast with an unambiguous reason code.
    try:
        commitment.check_htc_coverage(block_ids, len(evidence.htc_chain))
    except commitment.CoverageError as exc:
        raise HolderBindingRejected(HTC_COVERAGE_COUNT, str(exc)) from exc
    ran(HTC_COVERAGE_COUNT)

    root_pub_wire = b64u(bytes(root_pub.to_bytes()))
    payloads: list[dict[str, Any]] = []
    previous: dict[str, Any] | None = None

    for index, wire in enumerate(evidence.htc_chain):
        payload, signature = _open(wire, _HTC_FIELDS, HTC_SCHEMA)
        ran(HTC_SCHEMA)
        if payload["schema_version"] != SCHEMA_VERSION:
            raise HolderBindingRejected(
                HTC_UNSUPPORTED_SCHEMA_VERSION,
                f"HTC {index} schema_version {payload['schema_version']!r}",
            )
        ran(HTC_UNSUPPORTED_SCHEMA_VERSION)

        # The kid selects the signer key from the registry (SS F.2 / SS F.2.1).
        # Hop 0 is signed by the AS root key; every later hop by a holder.
        expected_signer = root_pub_wire if index == 0 else previous["next_holder_pubkey"]
        try:
            if index == 0:
                if payload["kid"] != registry.as_root_kid:
                    raise RegistryError(f"HTC_0 kid {payload['kid']!r} is not the AS root kid")
            else:
                principal = registry.principal_of_kid(payload["kid"])
                if registry.holder_key(principal) != payload["signer_pubkey"]:
                    raise HolderBindingRejected(
                        REGISTRY_KEY_MISMATCH,
                        f"kid {payload['kid']!r} names {principal!r}, whose registered "
                        "holder key is not the signer_pubkey presented",
                    )
                registry.principal_of_key(payload["next_holder_pubkey"])  # unmapped keys rejected
        except RegistryError as exc:
            raise HolderBindingRejected(REGISTRY_UNMAPPED, str(exc)) from exc
        ran(REGISTRY_UNMAPPED)
        ran(REGISTRY_KEY_MISMATCH)

        if index == 0:
            if payload["signer_pubkey"] != root_pub_wire:
                raise HolderBindingRejected(
                    HTC0_SIGNER_IS_ROOT, "HTC_0 signer_pubkey is not the AS root key"
                )
            ran(HTC0_SIGNER_IS_ROOT)
            _verify_signature(HTC_TAG, payload, signature, root_pub_wire, HTC0_ROOT_SIGNATURE)
            ran(HTC0_ROOT_SIGNATURE)
        else:
            if payload["signer_pubkey"] != expected_signer:
                raise HolderBindingRejected(
                    HTC_CHAIN_LINKAGE,
                    f"HTC_{index}.signer_pubkey is not HTC_{index - 1}.next_holder_pubkey",
                )
            ran(HTC_CHAIN_LINKAGE)
            _verify_signature(HTC_TAG, payload, signature, payload["signer_pubkey"], HTC_SIGNATURE)
            ran(HTC_SIGNATURE)

            if payload["task_id"] != previous["task_id"]:
                raise HolderBindingRejected(HTC_TASK_INVARIANT, "task_id changed along the chain")
            ran(HTC_TASK_INVARIANT)
            if payload["audience"] != previous["audience"]:
                raise HolderBindingRejected(
                    HTC_AUDIENCE_INVARIANT, "audience changed along the chain"
                )
            ran(HTC_AUDIENCE_INVARIANT)
            if payload["exp"] > previous["exp"]:
                raise HolderBindingRejected(
                    HTC_EXP_NON_INCREASING, f"HTC_{index}.exp exceeds HTC_{index - 1}.exp"
                )
            ran(HTC_EXP_NON_INCREASING)

        # `depth` contiguous from 0 -- checked at every hop, including hop 0.
        expected_depth = index
        if payload["depth"] != expected_depth:
            raise HolderBindingRejected(
                HTC_DEPTH_CONTIGUOUS,
                f"HTC_{index}.depth is {payload['depth']!r}, expected {expected_depth}",
            )
        ran(HTC_DEPTH_CONTIGUOUS)

        if not payload["nbf"] <= now <= payload["exp"]:
            raise HolderBindingRejected(
                HTC_VALIDITY_WINDOW,
                f"HTC_{index} is outside its window (nbf={payload['nbf']}, "
                f"now={now}, exp={payload['exp']})",
            )
        ran(HTC_VALIDITY_WINDOW)

        # prefix_hash / child_block_hash against the PRESENTED capability.
        # max(index - 1, 0) is a formula, not a branch: the template gives
        # HTC_0.prefix_hash as the commitment over BlockID_0 itself.
        expected_prefix = commitment.commit_prefix(block_ids, max(index - 1, 0)).hex()
        if payload["prefix_hash"] != expected_prefix:
            raise HolderBindingRejected(
                HTC_PREFIX_HASH, f"HTC_{index}.prefix_hash does not match the presented prefix"
            )
        ran(HTC_PREFIX_HASH)
        if payload["child_block_hash"] != block_ids[index].hex():
            raise HolderBindingRejected(
                HTC_CHILD_BLOCK_HASH,
                f"HTC_{index}.child_block_hash does not match SignedBlock_{index}",
            )
        ran(HTC_CHILD_BLOCK_HASH)

        payloads.append(payload)
        previous = payload

    # --- INV, signed by the key the terminal HTC names ----------------------
    terminal = payloads[-1]
    inv, inv_signature = _open(evidence.invocation_assertion, _INV_FIELDS, INV_SCHEMA)
    ran(INV_SCHEMA)
    if inv["schema_version"] != SCHEMA_VERSION:
        raise HolderBindingRejected(
            INV_UNSUPPORTED_SCHEMA_VERSION, f"INV schema_version {inv['schema_version']!r}"
        )
    ran(INV_UNSUPPORTED_SCHEMA_VERSION)

    terminal_holder = terminal["next_holder_pubkey"]
    try:
        terminal_principal = registry.principal_of_key(terminal_holder)
        if registry.principal_of_kid(inv["kid"]) != terminal_principal:
            raise HolderBindingRejected(
                INV_TERMINAL_HOLDER,
                f"INV.kid {inv['kid']!r} is not the terminal holder named by the last HTC",
            )
    except RegistryError as exc:
        raise HolderBindingRejected(REGISTRY_UNMAPPED, str(exc)) from exc
    ran(INV_TERMINAL_HOLDER)

    _verify_signature(INV_TAG, inv, inv_signature, terminal_holder, INV_SIGNATURE)
    ran(INV_SIGNATURE)

    expected_capability = commitment.capability_commitment(evidence.token_bytes, root_pub).hex()
    if inv["capability_hash"] != expected_capability:
        raise HolderBindingRejected(
            INV_CAPABILITY_HASH, "INV.capability_hash does not match the presented capability"
        )
    ran(INV_CAPABILITY_HASH)

    if inv["access_token_hash"] != access_token_hash(evidence.raw_at):
        raise HolderBindingRejected(
            INV_ACCESS_TOKEN_HASH, "INV.access_token_hash does not match the presented AT@aud"
        )
    ran(INV_ACCESS_TOKEN_HASH)

    if inv["canonical_request_digest"] != h_jcs(evidence.raw_arguments):
        raise HolderBindingRejected(
            INV_REQUEST_DIGEST, "INV.canonical_request_digest does not match the raw arguments"
        )
    ran(INV_REQUEST_DIGEST)

    if inv["task_id"] != terminal["task_id"] or inv["task_id"] != evidence.task_id:
        raise HolderBindingRejected(INV_TASK_BINDING, "INV.task_id does not bind this task")
    ran(INV_TASK_BINDING)
    if inv["audience"] != terminal["audience"] or inv["audience"] != evidence.audience:
        raise HolderBindingRejected(
            INV_AUDIENCE_BINDING, "INV.audience does not bind this audience"
        )
    ran(INV_AUDIENCE_BINDING)
    if inv["method"] != evidence.method:
        raise HolderBindingRejected(INV_METHOD_BINDING, "INV.method does not bind this method")
    ran(INV_METHOD_BINDING)
    if inv["tool"] != evidence.tool:
        raise HolderBindingRejected(INV_TOOL_BINDING, "INV.tool does not bind this tool")
    ran(INV_TOOL_BINDING)

    if not inv["nbf"] <= now <= inv["exp"]:
        raise HolderBindingRejected(
            INV_VALIDITY_WINDOW,
            f"INV is outside its window (nbf={inv['nbf']}, now={now}, exp={inv['exp']})",
        )
    ran(INV_VALIDITY_WINDOW)

    return VerificationResult(
        checks=tuple(checks),
        htc_payloads=tuple(payloads),
        inv_payload=inv,
        capability_hash=expected_capability,
        terminal_holder_pubkey=terminal_holder,
    )


# --------------------------------------------------------------------------
# Fixture constructors (gate and regression use; the SUT-side signer is owed)
# --------------------------------------------------------------------------


def htc_payload(
    *,
    kid: str,
    prefix_hash: str,
    child_block_hash: str,
    signer_pubkey: str,
    next_holder_pubkey: str,
    task_id: str,
    audience: str,
    iat: int,
    nbf: int,
    exp: int,
    depth: int,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "kid": kid,
        "prefix_hash": prefix_hash,
        "child_block_hash": child_block_hash,
        "signer_pubkey": signer_pubkey,
        "next_holder_pubkey": next_holder_pubkey,
        "task_id": task_id,
        "audience": audience,
        "iat": iat,
        "nbf": nbf,
        "exp": exp,
        "depth": depth,
    }


def build_htc_chain(
    token_bytes: bytes,
    root_pub: Any,
    root_private: Ed25519PrivateKey,
    holder_privates: list[Ed25519PrivateKey],
    holder_kids: list[str],
    *,
    root_kid: str,
    task_id: str,
    audience: str,
    iat: int,
    nbf: int,
    exps: list[int],
) -> tuple[bytes, ...]:
    """Build a valid HTC chain covering every presented signed block.

    `holder_privates[i]` is the key `HTC_i.next_holder_pubkey` names, so
    `holder_privates[0]` is the initial holder and the last entry is the terminal
    holder. Fixture constructor -- not the SUT-side signer (D21).
    """
    block_ids = commitment.block_ids_from_raw(token_bytes, root_pub)
    if len(holder_privates) != len(block_ids):
        raise ValueError("one holder key is needed per presented signed block")
    chain: list[bytes] = []
    for index in range(len(block_ids)):
        signer_private = root_private if index == 0 else holder_privates[index - 1]
        signer_wire = (
            b64u(bytes(root_pub.to_bytes()))
            if index == 0
            else public_key_wire(holder_privates[index - 1].public_key())
        )
        payload = htc_payload(
            kid=root_kid if index == 0 else holder_kids[index - 1],
            prefix_hash=commitment.commit_prefix(block_ids, max(index - 1, 0)).hex(),
            child_block_hash=block_ids[index].hex(),
            signer_pubkey=signer_wire,
            next_holder_pubkey=public_key_wire(holder_privates[index].public_key()),
            task_id=task_id,
            audience=audience,
            iat=iat,
            nbf=nbf,
            exp=exps[index],
            depth=index,
        )
        chain.append(seal(HTC_TAG, payload, signer_private))
    return tuple(chain)


def inv_payload(
    *,
    kid: str,
    capability_hash: str,
    access_token_digest: str,
    task_id: str,
    audience: str,
    method: str,
    tool: str,
    canonical_request_digest: str,
    label_assertions_digest: str,
    invocation_id: str,
    iat: int,
    nbf: int,
    exp: int,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "kid": kid,
        "capability_hash": capability_hash,
        "access_token_hash": access_token_digest,
        "task_id": task_id,
        "audience": audience,
        "method": method,
        "tool": tool,
        "canonical_request_digest": canonical_request_digest,
        "label_assertions_digest": label_assertions_digest,
        "invocation_id": invocation_id,
        "iat": iat,
        "nbf": nbf,
        "exp": exp,
    }


def build_inv(
    token_bytes: bytes,
    root_pub: Any,
    terminal_private: Ed25519PrivateKey,
    *,
    kid: str,
    raw_at: str,
    raw_arguments: Any,
    task_id: str,
    audience: str,
    method: str,
    tool: str,
    label_assertions_digest: str,
    invocation_id: str,
    iat: int,
    nbf: int,
    exp: int,
) -> bytes:
    """Build a valid INV bound to the presented capability, token and arguments."""
    payload = inv_payload(
        kid=kid,
        capability_hash=commitment.capability_commitment(token_bytes, root_pub).hex(),
        access_token_digest=access_token_hash(raw_at),
        task_id=task_id,
        audience=audience,
        method=method,
        tool=tool,
        canonical_request_digest=h_jcs(raw_arguments),
        label_assertions_digest=label_assertions_digest,
        invocation_id=invocation_id,
        iat=iat,
        nbf=nbf,
        exp=exp,
    )
    return seal(INV_TAG, payload, terminal_private)


def reseal(wire: bytes, tag: bytes, signing_key: Ed25519PrivateKey, **overrides: Any) -> bytes:
    """Re-sign a payload with fields replaced. The mutation tool for the gate."""
    envelope = json.loads(wire)
    payload = dict(envelope["payload"])
    payload.update(overrides)
    return seal(tag, payload, signing_key)


def tamper(wire: bytes, **overrides: Any) -> bytes:
    """Replace payload fields **without** re-signing, leaving the old signature."""
    envelope = json.loads(wire)
    payload = dict(envelope["payload"])
    payload.update(overrides)
    return rfc8785.dumps({"payload": payload, "signature": envelope["signature"]})
