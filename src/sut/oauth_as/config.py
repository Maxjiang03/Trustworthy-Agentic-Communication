"""Start-up configuration for the AS. Everything frozen arrives as **data**.

The AS never imports the harness (CLAUDE.md red line 6), so the frozen ontology
`Omega` reaches it the way ADR 0016 prescribes -- as start-up configuration
supplied by the runner, not by importing `src/harness/authorizer/`. The same is
true of the AS public key at the boundary: sealed configuration, never a
`jwks_uri` (DESIGN SS 5.1).

Two members are **spike-local stand-ins at Phase 2**, and both are labelled
wherever they surface (DESIGN SS 9 C3, SS 7.4):

* `registry` -- the identity-plane registry. The frozen registry is a seal-time
  artifact (SS F.2.1, Part H step 3) and the holder key here is a raw spike key,
  **not** the terminal key of a verified HTC chain. Re-triggered at **G-11**.
* `delegation_policy` -- the `may_act` source. The frozen
  `task_authorization_policy` is `frozen_parameters` row 5, **UNSET**; the F2
  `wrong_principal` family is not scored until that row is fixed by its own ADR.
"""

from dataclasses import dataclass, field
from typing import Any

SPIKE_LOCAL_BANNER = "SPIKE-LOCAL — NOT A FROZEN ARTIFACT"


@dataclass(frozen=True)
class RegistryEntry:
    """One identity-plane row: an OAuth actor, its principal, and its keys.

    `identity_jwk` verifies the principal's **actor assertion**;
    `holder_jwk` is the `htc_holder` key the identity plane maps to. They are
    kept as separate fields because DESIGN SS 7.3 warns that the DPoP holder and
    the HTC holder must never be conflated -- and at Phase 2 the holder key is a
    spike key standing in for a real HTC terminal key.
    """

    principal: str
    identity_jwk: dict[str, str]
    holder_jwk: dict[str, str]


@dataclass(frozen=True)
class ASConfig:
    """Everything the AS needs, injected at start-up. No global state."""

    issuer: str
    token_endpoint: str
    rar_type: str
    omega: frozenset[tuple[str, str]]
    resource_servers: frozenset[str]
    clients: dict[str, str]  # client_id -> secret, derived from sealed seeds
    registry: dict[str, RegistryEntry]  # oauth_actor -> entry  [SPIKE-LOCAL]
    delegation_policy: dict[str, str]  # principal -> principal it may delegate to  [SPIKE-LOCAL]
    default_lifetime_seconds: int = 300
    require_dpop: bool = False
    require_dpop_nonce: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def resolve_actor(self, actor_id: str) -> RegistryEntry | None:
        """The identity-plane lookup: exactly one principal, or nothing."""
        return self.registry.get(actor_id)
