"""The SS F.2.1 identity-plane registry: loader, binder, and `H(R)` (ADR 0019).

SS F.2.1: `actor_of(.)` maps an OAuth `act`/`client_id` claim to a **single**
principal; the registry maps that principal to **exactly one** `htc_holder`
public key; every actor claim and holder key used in a scenario MUST resolve to
exactly one principal, and unmapped actors **and** unmapped keys are rejected.
`resource_owner` subjects are recorded but are **not** part of the holder
mapping -- SS A.5.1 forbids requiring `resource_owner = holder`.

**Why the frozen artifact holds key *references*, not key bytes.** SS F.2.1 lists
the registry among the artifacts frozen and hashed **before** sealing, but holder
keys are per-campaign material derived from sealed seeds (ADR 0007). Freezing key
bytes would either pin one campaign's keys into a pre-campaign artifact or make
the artifact unfreezable. The artifact therefore fixes the **structure** -- the
principals, their kids, the actor->principal mapping, and each principal's
derivation label -- and `bind()` resolves labels to actual public keys at campaign
start. `H(R)` covers that structure and **not** the key bytes. This is exactly
the line ADR 0016 drew for `Gamma`, which freezes "the cardinality and role of
the trusted-key set, not the key bytes".

`H(R)` construction (ADR 0019), the same tagged, versioned, length-delimited
family as ADR 0003/0009/0016/0018 with its own tag:

    C     = RFC 8785 canonical UTF-8 bytes of the whole document
    H(R)  = lowercase_hex( SHA-256( TAG || 0x01 || u32be(len(C)) || C ) )

It is **data, not code**: the SUT receives the same bytes as start-up
configuration from the runner, never by importing the harness (red line 6).
"""

import copy
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import rfc8785

TAG = b"AASC-REGISTRY-DIGEST"  # 20 bytes; distinct from every tag in use
VERSION = 0x01  # any other value fails closed
CONFIG_VERSION = 1

DOCUMENT_PATH = Path(__file__).with_name("identity_registry_v1.json")

_PRINCIPAL_RE = re.compile(r"^[a-z0-9]+$")
_ACTOR_RE = re.compile(r"^agent-[a-z0-9]+$")
_KID_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")


class RegistryError(Exception):
    """Base: the registry layer failed closed."""


class UnsupportedVersionError(RegistryError):
    """Document `config_version`, or `H(R)` version, other than the pinned one."""


class RegistryStructureError(RegistryError):
    """The document violates an invariant the freeze guarantees."""


class UnmappedError(RegistryError):
    """An actor claim, kid, or holder key that resolves to no principal."""


def load_document(path: Path = DOCUMENT_PATH) -> dict[str, Any]:
    """Read, validate, and return the frozen registry document. Fails closed."""
    doc = json.loads(path.read_text(encoding="utf-8"))
    if doc.get("config_version") != CONFIG_VERSION:
        raise UnsupportedVersionError(f"unsupported config_version {doc.get('config_version')!r}")
    _validate(doc)
    return doc


def _validate(doc: dict[str, Any]) -> None:
    principals = doc["principals"]
    kids: set[str] = set()

    root = doc["as_root"]
    if not _KID_RE.match(root["kid"]):
        raise RegistryStructureError(f"as_root kid {root['kid']!r} violates the encoding")
    kids.add(root["kid"])

    for name, entry in principals.items():
        if not _PRINCIPAL_RE.match(name):
            raise RegistryStructureError(f"principal {name!r} violates the encoding")
        if not _KID_RE.match(entry["kid"]):
            raise RegistryStructureError(f"kid {entry['kid']!r} violates the encoding")
        if entry["kid"] in kids:
            # Exactly one key per principal, and one principal per kid: a
            # duplicate kid would make `kid` ambiguous as a key selector (SS F.2).
            raise RegistryStructureError(f"duplicate kid {entry['kid']!r}")
        kids.add(entry["kid"])
        if not entry.get("key_reference"):
            raise RegistryStructureError(f"principal {name!r} has no key_reference")
        if not entry.get("necessity"):
            # Every entry states the requirement that forces it (ADR 0019).
            raise RegistryStructureError(f"principal {name!r} has no necessity")

    seen_actors: set[str] = set()
    for actor, principal in doc["actors"].items():
        if not _ACTOR_RE.match(actor):
            raise RegistryStructureError(f"actor claim {actor!r} violates the encoding")
        if principal not in principals:
            raise RegistryStructureError(f"actor {actor!r} maps to unknown principal {principal!r}")
        if actor in seen_actors:
            raise RegistryStructureError(f"duplicate actor claim {actor!r}")
        seen_actors.add(actor)

    overlap = set(doc["resource_owners"]) & set(doc["actors"])
    if overlap:
        # SS F.2.1: resource owners are recorded but are NOT part of the holder
        # mapping. An identifier that is both would blur the two planes.
        raise RegistryStructureError(f"resource owner(s) also present as actors: {sorted(overlap)}")


def h_registry(doc: dict[str, Any], *, version: int = 1) -> str:
    """`H(R)` over the whole document (ADR 0019). Fails closed on a bad version."""
    if version != VERSION:
        raise UnsupportedVersionError(f"unsupported H(R) version {version}")
    canonical = rfc8785.dumps(doc)
    digest = hashlib.sha256()
    digest.update(TAG)
    digest.update(bytes([version]))
    digest.update(len(canonical).to_bytes(4, "big"))
    digest.update(canonical)
    return digest.hexdigest()


@dataclass(frozen=True)
class BoundRegistry:
    """The runtime registry: labels resolved to actual public keys.

    Built by `bind()` at campaign start. The lookups below are the SS F.2.1
    operations, and each rejects rather than returning a default.
    """

    as_root_kid: str
    as_root_pubkey: str  # base64url unpadded raw Ed25519
    kid_to_principal: dict[str, str]
    principal_to_key: dict[str, str]
    actor_to_principal: dict[str, str]
    resource_owners: frozenset[str]
    document_digest: str

    def actor_of(self, actor_claim: str) -> str:
        """An OAuth `act`/`client_id` claim to exactly one principal, or reject."""
        principal = self.actor_to_principal.get(actor_claim)
        if principal is None:
            raise UnmappedError(f"actor claim {actor_claim!r} resolves to no principal")
        return principal

    def holder_key(self, principal: str) -> str:
        """A principal to exactly one `htc_holder` public key, or reject."""
        key = self.principal_to_key.get(principal)
        if key is None:
            raise UnmappedError(f"principal {principal!r} has no holder key")
        return key

    def principal_of_kid(self, kid: str) -> str:
        """A `kid` to the principal whose key it selects, or reject."""
        principal = self.kid_to_principal.get(kid)
        if principal is None:
            raise UnmappedError(f"kid {kid!r} resolves to no principal")
        return principal

    def principal_of_key(self, public_key: str) -> str:
        """A holder key back to its principal, or reject.

        SS F.2.1 requires **unmapped keys** to be rejected too, not only unmapped
        actor claims, so the reverse lookup is a first-class operation.
        """
        for principal, key in self.principal_to_key.items():
            if key == public_key:
                return principal
        raise UnmappedError("holder key resolves to no principal")

    def is_resource_owner(self, subject: str) -> bool:
        """Recorded, and never used as a holder (SS A.5.1 MUST NOT)."""
        return subject in self.resource_owners


def bind(doc: dict[str, Any], resolve_key: Any) -> BoundRegistry:
    """Resolve each `key_reference` to a public key, producing the runtime registry.

    `resolve_key(label) -> base64url public key` is supplied by the runner, which
    holds the sealed seeds (ADR 0007). The registry document itself contains no
    key bytes, so this is where per-campaign material enters -- and the only place.
    """
    principal_to_key: dict[str, str] = {}
    kid_to_principal: dict[str, str] = {}
    for name, entry in doc["principals"].items():
        key = resolve_key(entry["key_reference"])
        if key in principal_to_key.values():
            raise RegistryStructureError(
                f"holder key for {name!r} collides with another principal's; "
                "exactly one principal per key (SS F.2.1)"
            )
        principal_to_key[name] = key
        kid_to_principal[entry["kid"]] = name
    root = doc["as_root"]
    return BoundRegistry(
        as_root_kid=root["kid"],
        as_root_pubkey=resolve_key(root["key_reference"]),
        kid_to_principal=kid_to_principal,
        principal_to_key=principal_to_key,
        actor_to_principal=dict(doc["actors"]),
        resource_owners=frozenset(doc["resource_owners"]),
        document_digest=h_registry(doc),
    )


def document(doc: dict[str, Any]) -> dict[str, Any]:
    """A defensive copy, so a caller cannot mutate the frozen document in place."""
    return copy.deepcopy(doc)
