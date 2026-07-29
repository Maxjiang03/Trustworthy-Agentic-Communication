"""JWT access tokens and actor assertions.

`smoke/g4/DESIGN.md` SS 5.1 (token format and claim set) and SS 5.3 steps 2, 3
and 9. Access tokens are JWTs typed `at+jwt` and signed **Ed25519**.

**Disclosed non-conformance (SS 8.3), restated wherever this AS is described.**
RFC 9068 SS 2.1 requires a conforming AS and RS to include **RS256** among their
supported signature algorithms. This project signs Ed25519 everywhere with an
explicit algorithm allowlist (ADR 0006), deliberately excluding RSA. The profile
therefore uses the RFC 9068 **shape** -- `typ: at+jwt`, the required claim set,
`aud` from `resource`, the SS 4 validation rules -- while being **not RFC
9068-conformant**. No document may describe it as "RFC 9068-compliant". The
benchmark is self-contained and claims no external interoperability.

Delegation, never impersonation [VERIFIED, RFC 8693 SS 1.1]: `sub` is always the
resource owner and the actor is carried in `act`, never written into `sub`. The
**outermost** `act` is the current actor; prior actors nest beneath it and are
audit history that MUST NOT enter a decision [VERIFIED, RFC 8693 SS 4.1].
"""

import secrets
from dataclasses import dataclass
from typing import Any

from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import OKPKey

from src.sut.oauth_as.errors import INVALID_REQUEST, OAuthError
from src.sut.oauth_as.keys import ALGS, SigningKey

AT_TYP = "at+jwt"  # RFC 9068 SS 2.1
ACTOR_ASSERTION_TYP = "JWT"

TOKEN_TYPE_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"  # RFC 8693 SS 3
TOKEN_TYPE_JWT = "urn:ietf:params:oauth:token-type:jwt"  # RFC 8693 SS 3
GRANT_TYPE_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"  # RFC 8693 SS 2.1


@dataclass(frozen=True)
class AccessToken:
    """A minted access token and the claims it carries."""

    value: str
    claims: dict[str, Any]


def mint_access_token(
    signing_key: SigningKey,
    *,
    issuer: str,
    subject: str,
    audience: str,
    client_id: str,
    issued_at: int,
    expires_at: int,
    scope: str,
    authorization_details: list[dict[str, Any]],
    act: dict[str, Any] | None = None,
    may_act: dict[str, Any] | None = None,
    cnf_jkt: str | None = None,
) -> AccessToken:
    """Issue `AT_i` (SS 5.3 step 9). RFC 9068 SS 2.2's seven claims are always present."""
    claims: dict[str, Any] = {
        "iss": issuer,
        "sub": subject,  # the resource owner -- never the actor
        "aud": audience,
        "client_id": client_id,
        "iat": issued_at,
        "exp": expires_at,
        "jti": secrets.token_urlsafe(16),
        "scope": scope,
        "authorization_details": authorization_details,
    }
    if act is not None:
        claims["act"] = act
    if may_act is not None:
        claims["may_act"] = may_act  # RFC 8693 SS 4.4
    if cnf_jkt is not None:
        claims["cnf"] = {"jkt": cnf_jkt}  # RFC 9449 SS 6.1, DPoP arm only
    value = jwt.encode(
        {"alg": ALGS[0], "typ": AT_TYP}, claims, signing_key.private, algorithms=ALGS
    )
    return AccessToken(value=value, claims=claims)


def verify_access_token(
    token: str,
    public_key: OKPKey,
    *,
    issuer: str,
    now: int,
    known_audiences: frozenset[str],
) -> dict[str, Any]:
    """Validate a `subject_token` (SS 5.3 step 2; RFC 8693 SS 2.1 MUST).

    Signature under the AS key, `typ`, `iss`, a recognised `aud`, `exp`/`nbf`,
    and therefore that this AS issued it. Any failure is `invalid_request`
    [VERIFIED, RFC 8693 SS 2.2.2 MUST].
    """
    try:
        decoded = jwt.decode(token, public_key, algorithms=ALGS)
    except JoseError as exc:
        raise OAuthError(
            INVALID_REQUEST, "subject-token", f"subject_token does not verify: {type(exc).__name__}"
        ) from exc
    except ValueError as exc:
        raise OAuthError(
            INVALID_REQUEST, "subject-token", "subject_token is not a well-formed JWT"
        ) from exc

    if decoded.header.get("typ") != AT_TYP:
        raise OAuthError(INVALID_REQUEST, "subject-token", "subject_token is not an at+jwt")
    claims = dict(decoded.claims)
    if claims.get("iss") != issuer:
        # Not issued by this AS -- SS 6 row 8.
        raise OAuthError(
            INVALID_REQUEST, "subject-token-foreign", "subject_token has a foreign iss"
        )
    if claims.get("aud") not in known_audiences:
        raise OAuthError(INVALID_REQUEST, "subject-token", "subject_token aud is not a known RS")
    _check_window(claims, now, "subject_token", "subject-token-expired")
    return claims


def verify_actor_assertion(
    assertion: str,
    public_key: OKPKey,
    *,
    audience: str,
    now: int,
) -> dict[str, Any]:
    """Validate an `actor_token` (SS 5.3 step 3; RFC 8693 SS 2.1 MUST).

    A short JWT signed by the delegate's own Ed25519 identity key, audience =
    this AS. `[DESIGN]` -- deliberately **not** described as an RFC 7523
    assertion, which SS 1.7 records as not read.
    """
    try:
        decoded = jwt.decode(assertion, public_key, algorithms=ALGS)
    except (JoseError, ValueError) as exc:
        raise OAuthError(
            INVALID_REQUEST, "actor-token", f"actor_token does not verify: {type(exc).__name__}"
        ) from exc
    claims = dict(decoded.claims)
    if claims.get("aud") != audience:
        raise OAuthError(INVALID_REQUEST, "actor-token", "actor_token audience is not this AS")
    if not claims.get("sub"):
        raise OAuthError(INVALID_REQUEST, "actor-token", "actor_token has no sub")
    _check_window(claims, now, "actor_token", "actor-token")
    return claims


def _check_window(claims: dict[str, Any], now: int, label: str, row: str) -> None:
    expires_at = claims.get("exp")
    if not isinstance(expires_at, int):
        raise OAuthError(INVALID_REQUEST, row, f"{label} has no integer exp")
    if now >= expires_at:
        raise OAuthError(INVALID_REQUEST, row, f"{label} has expired")
    not_before = claims.get("nbf")
    if isinstance(not_before, int) and now < not_before:
        raise OAuthError(INVALID_REQUEST, row, f"{label} is not yet valid")


def current_actor(claims: dict[str, Any]) -> str:
    """The **outermost** `act.sub`, or `client_id` at hop 0.

    [VERIFIED, RFC 8693 SS 4.1] "the consumer of a token MUST only consider the
    token's top-level claims and the party identified as the current actor by
    the `act` claim. Prior actors ... are informational only." Nested `act`
    values are never read here, and nothing else in this package reads them.
    """
    act = claims.get("act")
    if isinstance(act, dict) and isinstance(act.get("sub"), str):
        return act["sub"]
    return str(claims.get("client_id", ""))


def nest_actor(previous_act: dict[str, Any] | None, new_actor: str) -> dict[str, Any]:
    """The new `act`: current actor outermost, prior chain nested beneath it."""
    act: dict[str, Any] = {"sub": new_actor}
    if previous_act is not None:
        act["act"] = previous_act
    return act
