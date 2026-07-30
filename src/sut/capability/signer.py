"""The SUT-side capability signer: mint, attenuate, HTC chain, INV (SS F.2).

The B3 arm's own signer, written **from SS F.2's signed-payload templates and
ADR 0018's byte layouts** -- a second implementation on purpose (D21; EXP1
forbidden action 7). It imports nothing from `src/harness/`; the frozen
`Omega`/`Gamma` document reaches it as injected data (ADR 0016's data-not-code
discipline), and key material is injected by the composition root.

What SS F.2 and ADR 0018 fix, implemented here:

* every signature is Ed25519 over
  `TAG || schema_version || u32be(len(C)) || C`, `C` the RFC 8785 canonical
  payload bytes, TAG one of `b"AASC-HTC-v1"` / `b"AASC-INV-v1"`;
* the wire form is the canonical JSON of
  `{"payload": ..., "signature": base64url(sig)}`;
* `HTC_0` is signed by the AS root key `kappa` with
  `prefix_hash = commit_prefix(BlockID_0..BlockID_0)` and carries the initial
  holder; `HTC_i (i>=1)` is signed by holder `i-1` with
  `prefix_hash = commit_prefix(BlockID_0..BlockID_{i-1})`,
  `child_block_hash = BlockID_i`, task/audience copied unchanged, `exp`
  non-increasing, `depth` contiguous -- the prefix rule is the formula
  `commit_prefix(ids, max(i - 1, 0))`, never a length-keyed branch (SS F.2
  zero-hop MUST);
* the INV binds `capability_hash` (the terminal ADR 0003 commitment),
  `access_token_hash`, task, audience, method, tool,
  `canonical_request_digest = H_JCS(raw_arguments)`, and the invocation id
  the harness minted (SS F.1: the INV `jti` IS the correlation id).

Block identifiers come from the pinned Biscuit library's revocation
identifiers after verification under `kappa_pub` -- the library is shared
pinned infrastructure (gate G-1), not harness code.
"""

from base64 import urlsafe_b64encode
from dataclasses import dataclass
from typing import Any

import rfc8785
from biscuit_auth import (
    Algorithm,
    Biscuit,
    BiscuitBuilder,
    BlockBuilder,
    KeyPair,
    PrivateKey,
    PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.sut.capability.digests import access_token_hash, commit_prefix, h_jcs

HTC_TAG = b"AASC-HTC-v1"
INV_TAG = b"AASC-INV-v1"
SCHEMA_VERSION = 1

_ELEMENT_PLACEHOLDERS = ("<action>", "<resource>")


class SutSignerError(Exception):
    """Base: the SUT-side signer failed closed."""


def b64u(raw: bytes) -> str:
    return urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def public_wire(private: Ed25519PrivateKey) -> str:
    raw = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return b64u(raw)


def signing_input(tag: bytes, payload: dict[str, Any]) -> bytes:
    """ADR 0018: `TAG || schema_version || u32be(len(C)) || C`."""
    version = payload.get("schema_version")
    if version != SCHEMA_VERSION:
        raise SutSignerError(f"unsupported schema_version {version!r}")
    canonical = rfc8785.dumps(payload)
    return tag + bytes([version]) + len(canonical).to_bytes(4, "big") + canonical


def sign_wire(tag: bytes, payload: dict[str, Any], key: Ed25519PrivateKey) -> bytes:
    """The ADR 0018 wire form: canonical JSON of {payload, signature}."""
    signature = key.sign(signing_input(tag, payload))
    return rfc8785.dumps({"payload": payload, "signature": b64u(signature)})


# --------------------------------------------------------------------------
# Minting from the frozen templates (data in, tokens out)
# --------------------------------------------------------------------------


def _render(template: str, elements: list[tuple[str, str]], **values: str) -> str:
    """Instantiate one frozen Datalog template: element lines fan out per
    element of the authority set; scalar placeholders substitute once."""
    lines: list[str] = []
    for line in template.splitlines():
        if any(marker in line for marker in _ELEMENT_PLACEHOLDERS):
            for action, resource in elements:
                lines.append(line.replace("<action>", action).replace("<resource>", resource))
            continue
        for key, value in values.items():
            line = line.replace(f"<{key}>", value)
        lines.append(line)
    rendered = "\n".join(lines) + "\n"
    unresolved = [
        line for line in lines if "<" in line and ">" in line and not line.strip().startswith("//")
    ]
    if unresolved:
        raise SutSignerError(f"unsubstituted placeholder(s): {unresolved!r}")
    return rendered


def _instant(epoch: int) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class MintedHop:
    """One hop's serialized prefix and its ordered BlockIDs."""

    token_bytes: bytes
    block_ids: tuple[bytes, ...]


class CapabilityIssuer:
    """Mints `P_0` and appends attenuation blocks from the frozen templates.

    Holds `kappa` (the capability root secret). In this pilot apparatus the
    issuer runs in the provisioning context of the arm -- never inside an
    agent object -- and the process-level isolation of `kappa` is a stated
    residual for G-13, not a claim made here.
    """

    def __init__(self, gamma_document: dict[str, Any], root_private_bytes: bytes) -> None:
        self._templates = gamma_document["gamma"]["datalog"]
        self._root_private = PrivateKey.from_bytes(root_private_bytes, Algorithm.Ed25519)
        self._root_signing = Ed25519PrivateKey.from_private_bytes(root_private_bytes)
        self.root_public: PublicKey = KeyPair.from_private_key(self._root_private).public_key

    def root_public_wire(self) -> str:
        return b64u(bytes(self.root_public.to_bytes()))

    def mint_root(
        self,
        authority_elements: list[tuple[str, str]],
        *,
        audience: str,
        task_id: str,
        expiry_epoch: int,
    ) -> MintedHop:
        """`P_0`: the authority block, signed by kappa (SS A.3: the AS mints
        U_task; the Supervisor only ever narrows it)."""
        code = _render(
            self._templates["authority_block_template"],
            authority_elements,
            audience=audience,
            task_id=task_id,
            instant=_instant(expiry_epoch),
        )
        token = BiscuitBuilder(code).build(self._root_private)
        return MintedHop(bytes(token.to_bytes()), tuple(self._block_ids(bytes(token.to_bytes()))))

    def attenuate(
        self, parent: MintedHop, attenuation_elements: list[tuple[str, str]]
    ) -> MintedHop:
        """`P_{i-1} -> P_i`: the offline append (SS E.2 Phase 2 for B3)."""
        token = Biscuit.from_bytes(parent.token_bytes, self.root_public)
        appended = token.append(
            BlockBuilder(
                _render(self._templates["attenuation_block_template"], attenuation_elements)
            )
        )
        raw = bytes(appended.to_bytes())
        return MintedHop(raw, tuple(self._block_ids(raw)))

    def _block_ids(self, token_bytes: bytes) -> list[bytes]:
        verified = Biscuit.from_bytes(token_bytes, self.root_public)
        return [bytes.fromhex(rid) for rid in verified.revocation_ids]

    # -- HTC_0, signed by kappa (SS F.2 template) --------------------------
    def issue_htc0(
        self,
        root_hop: MintedHop,
        *,
        as_root_kid: str,
        initial_holder_pubkey: str,
        task_id: str,
        audience: str,
        iat: int,
        nbf: int,
        exp: int,
    ) -> bytes:
        payload = {
            "schema_version": SCHEMA_VERSION,
            "kid": as_root_kid,
            "prefix_hash": commit_prefix(list(root_hop.block_ids), 0).hex(),
            "child_block_hash": root_hop.block_ids[0].hex(),
            "signer_pubkey": self.root_public_wire(),
            "next_holder_pubkey": initial_holder_pubkey,
            "task_id": task_id,
            "audience": audience,
            "iat": iat,
            "nbf": nbf,
            "exp": exp,
            "depth": 0,
        }
        return sign_wire(HTC_TAG, payload, self._root_signing)


def issue_htc_hop(
    hop: MintedHop,
    *,
    index: int,
    signer_private: Ed25519PrivateKey,
    signer_kid: str,
    next_holder_pubkey: str,
    task_id: str,
    audience: str,
    iat: int,
    nbf: int,
    exp: int,
) -> bytes:
    """`HTC_i (i >= 1)`, signed by the CURRENT holder's identity key.

    The prefix rule is the SS F.2 formula: the parent prefix commitment ends
    one block earlier -- `commit_prefix(ids, max(index - 1, 0))`.
    """
    if index < 1:
        raise SutSignerError("hop 0 is the issuer's (issue_htc0)")
    payload = {
        "schema_version": SCHEMA_VERSION,
        "kid": signer_kid,
        "prefix_hash": commit_prefix(list(hop.block_ids), max(index - 1, 0)).hex(),
        "child_block_hash": hop.block_ids[index].hex(),
        "signer_pubkey": public_wire(signer_private),
        "next_holder_pubkey": next_holder_pubkey,
        "task_id": task_id,
        "audience": audience,
        "iat": iat,
        "nbf": nbf,
        "exp": exp,
        "depth": index,
    }
    return sign_wire(HTC_TAG, payload, signer_private)


def issue_inv(
    terminal_hop: MintedHop,
    *,
    holder_private: Ed25519PrivateKey,
    holder_kid: str,
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
    """The per-invocation assertion, signed by the TERMINAL holder (SS F.2).

    `invocation_id` is the harness-minted correlation id (SS F.1) -- received,
    never minted here. `label_assertions_digest` is bound by the signature but
    has no fixed construction yet (rows 4/6 UNSET; G-15's to verify).
    """
    payload = {
        "schema_version": SCHEMA_VERSION,
        "kid": holder_kid,
        "capability_hash": commit_prefix(
            list(terminal_hop.block_ids), len(terminal_hop.block_ids) - 1
        ).hex(),
        "access_token_hash": access_token_hash(raw_at),
        "task_id": task_id,
        "audience": audience,
        "method": method,
        "tool": tool,
        "canonical_request_digest": h_jcs(raw_arguments),
        "label_assertions_digest": label_assertions_digest,
        "invocation_id": invocation_id,
        "iat": iat,
        "nbf": nbf,
        "exp": exp,
    }
    return sign_wire(INV_TAG, payload, holder_private)
