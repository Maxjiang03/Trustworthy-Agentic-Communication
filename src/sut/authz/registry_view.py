"""SUT-side identity-plane view (SS F.2.1), built from injected sealed configuration.

The B3 boundary needs the frozen registry for `identity_plane_consistency_ok`
and the HTC/INV kid resolution. It receives the registry **as data injected
by the runner** -- the frozen document plus the runner-resolved public keys
-- mirroring how the AS public key already reaches the boundary (sealed
configuration, no `jwks_uri`). It must not, and does not, import
`src/harness/verifier/registry` (red line 6; EXP1 STEP 12): this is the
SUT's own small reading of SS F.2.1, written from the section text.

SS F.2.1's operative rules, implemented: every actor claim resolves to
exactly one principal; every principal maps to exactly one `htc_holder`
key; unmapped actors AND unmapped keys are rejected; `resource_owner`
subjects are recorded but are never part of the holder mapping (SS A.5.1
MUST NOT require `resource_owner = holder`).
"""

from dataclasses import dataclass
from typing import Any


class RegistryViewError(Exception):
    """An unmapped actor, kid, or key. Fail closed, never a default."""


@dataclass(frozen=True)
class RegistryView:
    """The bound identity plane as the SUT boundary consumes it."""

    as_root_kid: str
    as_root_pubkey: str  # base64url unpadded raw Ed25519
    actor_to_principal: dict[str, str]
    principal_to_key: dict[str, str]
    kid_to_principal: dict[str, str]
    resource_owners: frozenset[str]

    def actor_of(self, actor_claim: str) -> str:
        principal = self.actor_to_principal.get(actor_claim)
        if principal is None:
            raise RegistryViewError(f"actor claim {actor_claim!r} resolves to no principal")
        return principal

    def holder_key(self, principal: str) -> str:
        key = self.principal_to_key.get(principal)
        if key is None:
            raise RegistryViewError(f"principal {principal!r} has no holder key")
        return key

    def principal_of_kid(self, kid: str) -> str:
        principal = self.kid_to_principal.get(kid)
        if principal is None:
            raise RegistryViewError(f"kid {kid!r} resolves to no principal")
        return principal

    def principal_of_key(self, public_key: str) -> str:
        for principal, key in self.principal_to_key.items():
            if key == public_key:
                return principal
        raise RegistryViewError("holder key resolves to no principal")


def build_view(document: dict[str, Any], resolved_keys: dict[str, str]) -> RegistryView:
    """The runner-injected document + resolved keys -> the runtime view.

    `resolved_keys` maps the document's derivation labels to public keys
    (base64url raw Ed25519); the document itself carries no key bytes
    (ADR 0019). A label the runner did not resolve fails closed.
    """
    principal_to_key: dict[str, str] = {}
    kid_to_principal: dict[str, str] = {}
    for principal, entry in document["principals"].items():
        label = entry["key_reference"]
        if label not in resolved_keys:
            raise RegistryViewError(f"no resolved key for derivation label {label!r}")
        key = resolved_keys[label]
        if key in principal_to_key.values():
            raise RegistryViewError(f"holder key for {principal!r} collides with another's")
        principal_to_key[principal] = key
        kid_to_principal[entry["kid"]] = principal
    root = document["as_root"]
    if root["key_reference"] not in resolved_keys:
        raise RegistryViewError("no resolved key for the AS root")
    return RegistryView(
        as_root_kid=root["kid"],
        as_root_pubkey=resolved_keys[root["key_reference"]],
        actor_to_principal=dict(document["actors"]),
        principal_to_key=principal_to_key,
        kid_to_principal=kid_to_principal,
        resource_owners=frozenset(document["resource_owners"]),
    )
