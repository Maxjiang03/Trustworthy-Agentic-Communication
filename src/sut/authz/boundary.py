"""The MCP boundary's token verification and effective authority (limb L2).

`smoke/g4/DESIGN.md` SS 5.4 closing paragraph, SS 6 resource-server row, and
SS 10 rows L2, L3, A5, A7.

This module **reimplements** validation rather than sharing it with the AS: it
imports nothing from `src/sut/oauth_as/` (ADR 0015 rule 3) and holds only the AS
**public** key, delivered from sealed configuration -- there is no `jwks_uri` to
fetch (SS 5.1). The RAR expansion is recomputed here from the token's own claim;
the boundary never trusts an AS-supplied summary of what the token permits.

`Allowed(AT_i)` is the **intersection of two planes**:

* the **capability plane** -- `expand(AT_i.authorization_details)`, filtered to
  this resource server (RFC 9396 SS 9.1);
* the **OAuth-resource plane** -- `aud` names this RS [VERIFIED, RFC 9068 SS 4
  MUST] and `scope` covers the request [VERIFIED, OAuth 2.1 SS 5.2, SS 7.1.4].

Neither plane alone can admit a request the other denies, which is exactly what
the G-4 pass criterion means by "both layers enforced".
"""

from dataclasses import dataclass
from typing import Any

from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import OKPKey

from src.sut.dpop import DPoPError, NonceStore, verify_proof

ALGS = ["Ed25519"]  # ADR 0006 allowlist; `alg: none` can never match
AT_TYP = "at+jwt"  # RFC 9068 SS 2.1

INVALID_TOKEN = "invalid_token"  # RFC 9068 SS 4


class TokenRejected(Exception):
    """RFC 9068 SS 4 rejection. `reason` names which check refused."""

    def __init__(self, reason: str, description: str = "") -> None:
        super().__init__(f"{INVALID_TOKEN} ({reason}): {description}")
        self.error = INVALID_TOKEN
        self.reason = reason
        self.description = description


@dataclass(frozen=True)
class BoundaryConfig:
    """What the boundary knows, all from sealed configuration."""

    issuer: str
    resource_server: str  # this RS's own identifier; `aud` must name it
    as_public_jwk: dict[str, str]
    rar_type: str

    def public_key(self) -> OKPKey:
        return OKPKey.import_key(dict(self.as_public_jwk))


def verify_access_token(
    token: str, config: BoundaryConfig, *, now: int, leeway: int = 0
) -> dict[str, Any]:
    """RFC 9068 SS 4, in the order the RFC lists the MUSTs.

    `typ` is `at+jwt`; `alg: none` is rejected; `iss` matches exactly; `aud`
    names this RS; the signature verifies under the AS key; `exp` has not
    passed. Every failure is `invalid_token`.
    """
    try:
        extracted = jwt.decode(token, config.public_key(), algorithms=ALGS)
    except JoseError as exc:
        raise TokenRejected("signature", type(exc).__name__) from exc
    except ValueError as exc:
        raise TokenRejected("malformed", "not a well-formed JWT") from exc

    header = extracted.header
    if header.get("typ") != AT_TYP:
        raise TokenRejected("typ", f"typ is {header.get('typ')!r}, expected {AT_TYP!r}")
    if header.get("alg") not in ALGS:
        raise TokenRejected("alg", f"alg {header.get('alg')!r} is not allowed")

    claims = dict(extracted.claims)
    if claims.get("iss") != config.issuer:
        raise TokenRejected("iss", "issuer does not match exactly")
    if not _audience_names(claims.get("aud"), config.resource_server):
        raise TokenRejected("aud", "audience does not name this resource server")
    expires_at = claims.get("exp")
    if not isinstance(expires_at, int) or now - leeway >= expires_at:
        raise TokenRejected("exp", "token has expired")
    return claims


def _audience_names(audience: Any, resource_server: str) -> bool:
    if isinstance(audience, str):
        return audience == resource_server
    if isinstance(audience, list):
        return resource_server in audience
    return False


def capability_plane(claims: dict[str, Any], config: BoundaryConfig) -> frozenset[tuple[str, str]]:
    """`expand(AT.authorization_details)` for this RS, projected onto `Omega` pairs.

    Recomputed from the token's own claim, applying RFC 9396 SS 2.2's product
    rule; objects of another `type`, or naming another location, contribute
    nothing.
    """
    details = claims.get("authorization_details") or []
    if not isinstance(details, list):
        return frozenset()
    pairs: set[tuple[str, str]] = set()
    for entry in details:
        if not isinstance(entry, dict) or entry.get("type") != config.rar_type:
            continue
        locations = entry.get("locations") or []
        if config.resource_server not in locations:
            continue
        for action in entry.get("actions") or []:
            for datatype in entry.get("datatypes") or []:
                pairs.add((action, datatype))
    return frozenset(pairs)


def scope_plane(claims: dict[str, Any]) -> frozenset[str]:
    """The granted OAuth scope strings (OAuth 2.1 SS 5.2)."""
    scope = claims.get("scope")
    return frozenset(scope.split()) if isinstance(scope, str) else frozenset()


@dataclass(frozen=True)
class Decision:
    """Why the boundary admitted or refused one concrete request."""

    admitted: bool
    reason: str
    allowed: frozenset[tuple[str, str]]


def allowed_authority(claims: dict[str, Any], config: BoundaryConfig) -> frozenset[tuple[str, str]]:
    """`Allowed(AT_i)` -- the capability plane, given the audience plane held.

    `verify_access_token` has already enforced that `aud` names this RS, so the
    audience conjunct of the intersection is satisfied by construction; the
    scope conjunct is applied per request in `admits`, because scope is a
    property of the *request*, not of the authority set.
    """
    return capability_plane(claims, config)


def admits(
    claims: dict[str, Any],
    config: BoundaryConfig,
    *,
    element: tuple[str, str],
    required_scope: str,
) -> Decision:
    """Both layers, for one required authority element.

    Admits only if the element is in the capability plane **and** the request's
    scope is covered by the token's scope. A request inside the RAR but outside
    `scope` is denied, and one inside `scope` but outside the RAR is denied --
    the two directions limb L2 requires.

    Scoped deliberately: this is a single-element containment check, which is
    what L2 needs. The general `R subset-of C_n` rule and G-13's
    `Allowed(AT_i) = C_i` equality are **not** implemented here.
    """
    allowed = allowed_authority(claims, config)
    if element not in allowed:
        return Decision(False, "outside the capability plane (authorization_details)", allowed)
    if required_scope and required_scope not in scope_plane(claims):
        return Decision(False, "outside the OAuth-resource plane (scope)", allowed)
    return Decision(True, "admitted by both layers", allowed)


def verify_dpop_request(
    token: str,
    claims: dict[str, Any],
    proof_headers: list[str],
    *,
    method: str,
    url: str,
    now: int,
    nonce_store: NonceStore | None = None,
    nonce_required: bool = False,
) -> str:
    """RFC 9449 SS 4.3 items 1-12 at a protected resource, returning the proof `jkt`.

    Item 12 is the one G-5 could not reach: `ath` must equal the hash of *this*
    access token, and the key the token is bound to (`cnf.jkt`) must match the
    proof key [VERIFIED, RFC 9449 SS 4.3 item 12, SS 7.1]. The RS "MUST NOT grant
    access unless all checks are successful", so any failure raises.
    """
    bound = claims.get("cnf", {}).get("jkt") if isinstance(claims.get("cnf"), dict) else None
    if bound is None:
        raise TokenRejected("cnf", "token is not DPoP-bound but a proof was presented")
    try:
        result = verify_proof(
            proof_headers,
            method=method,
            url=url,
            now=now,
            nonce_store=nonce_store,
            nonce_required=nonce_required,
            access_token=token,
            bound_jkt=bound,
        )
    except DPoPError as exc:
        raise TokenRejected(f"dpop-item-{exc.item}", exc.description) from exc
    return result.jkt
