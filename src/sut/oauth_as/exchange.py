"""The RFC 8693 token exchange at hop `i` -- `smoke/g4/DESIGN.md` SS 5.3.

The ten steps run **in this order, all fail-closed**, and every refusal raises
an `OAuthError` carrying the exact SS 6 catalogue code and status. Because a
refusal is an exception, a rejected exchange **cannot** have issued a token:
there is one `mint_access_token` call and it is the last thing that happens.

The single most important property, and the easiest to lose: **the AS never
silently narrows a widening request to the intersection.** A widening attempt is
an *error*, not a clamp, because a silent clamp would make `F1-chain-tamper`
indistinguishable from a benign narrowing (SS 5.3 step 7, SS 8.1 item 3).

Narrowing is enforced in **all four planes** -- RAR expansion, audience, scope
and expiry -- with byte-exact RFC 8259 string comparison and no normalization
[VERIFIED, RFC 9396 SS 12].
"""

import base64
import json
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from joserfc.jwk import OKPKey

from src.sut.dpop import DPoPError, NonceStore, verify_proof
from src.sut.oauth_as import rar
from src.sut.oauth_as.config import ASConfig
from src.sut.oauth_as.errors import (
    INVALID_AUTHORIZATION_DETAILS,
    INVALID_DPOP_PROOF,
    INVALID_REQUEST,
    INVALID_TARGET,
    UNSUPPORTED_GRANT_TYPE,
    USE_DPOP_NONCE,
    OAuthError,
    invalid_client,
)
from src.sut.oauth_as.keys import SigningKey, secrets_equal
from src.sut.oauth_as.tokens import (
    GRANT_TYPE_TOKEN_EXCHANGE,
    TOKEN_TYPE_ACCESS_TOKEN,
    TOKEN_TYPE_JWT,
    AccessToken,
    current_actor,
    mint_access_token,
    nest_actor,
    verify_access_token,
    verify_actor_assertion,
)

# A profile extension parameter, permitted by OAuth 2.1 SS 4.4 ("plus any
# additional parameters"). DESIGN SS 5.3 step 7 requires `exp_i <= exp_{i-1}` and
# SS 6 lists `exp_i > exp_{i-1}` as a widening error, but the SS 5.3 request table
# names no parameter through which a client could ask for a longer lifetime.
# Without one that row would be untestable, so the profile recognises this name
# and treats an over-long request as the SS 6 widening error -- never a clamp.
REQUESTED_EXPIRES_IN = "requested_expires_in"

_KNOWN_PARAMETERS = {
    "grant_type",
    "subject_token",
    "subject_token_type",
    "actor_token",
    "actor_token_type",
    "resource",
    "audience",
    "scope",
    "authorization_details",
    "requested_token_type",
    "client_id",
    "client_secret",
    REQUESTED_EXPIRES_IN,
}

# Parameters a client is allowed to repeat: RFC 8707 SS 2 permits several
# `resource` values, and RFC 8693 SS 2.1.1 makes asking for several targets an
# `invalid_target` rather than a malformed request. Everything else repeated is
# `invalid_request` (OAuth 2.1 SS 3.2.2).
_REPEATABLE = {"resource", "audience"}


@dataclass(frozen=True)
class TokenResponse:
    """The SS 5.3 step 10 success response."""

    access_token: str
    issued_token_type: str
    token_type: str
    expires_in: int
    authorization_details: list[dict[str, Any]]
    scope: str | None  # RFC 8693 SS 2.2.1: REQUIRED when it differs from the request
    claims: dict[str, Any]

    def body(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "access_token": self.access_token,
            "issued_token_type": self.issued_token_type,
            "token_type": self.token_type,
            "expires_in": self.expires_in,
            "authorization_details": self.authorization_details,
        }
        if self.scope is not None:
            payload["scope"] = self.scope
        return payload


def parse_form(body: str) -> dict[str, Any]:
    """Parse the form body per OAuth 2.1 SS 3.2.2, fail-closed on repetition.

    Unrecognized parameters are ignored (MUST); valueless parameters are treated
    as omitted (MUST); no parameter may appear twice unless an extension says so.
    """
    pairs = parse_qsl(body, keep_blank_values=True)
    form: dict[str, Any] = {}
    for name, value in pairs:
        if name not in _KNOWN_PARAMETERS:
            continue  # MUST ignore unrecognized parameters
        if value == "":
            continue  # valueless parameters are treated as omitted
        if name in _REPEATABLE:
            form.setdefault(name, []).append(value)
        elif name in form:
            raise OAuthError(
                INVALID_REQUEST, "malformed-request", f"parameter {name!r} appears more than once"
            )
        else:
            form[name] = value
    return form


def _require(form: dict[str, Any], name: str) -> str:
    value = form.get(name)
    if not isinstance(value, str) or not value:
        raise OAuthError(
            INVALID_REQUEST, "malformed-request", f"missing required parameter {name!r}"
        )
    return value


def _scope_set(scope: str | None) -> frozenset[str]:
    return frozenset((scope or "").split())


def exchange(
    form: dict[str, Any],
    *,
    config: ASConfig,
    signing_key: SigningKey,
    client_credentials: tuple[str, str] | None,
    used_authorization_header: bool = False,
    dpop_proofs: list[str] | None = None,
    nonce_store: NonceStore | None = None,
    now: int | None = None,
) -> TokenResponse:
    """Run the SS 5.3 exchange. Returns a response, or raises an `OAuthError`."""
    now = int(time.time()) if now is None else now
    dpop_proofs = dpop_proofs or []

    # --- Step 0: grant type (OAuth 2.1 SS 3.2.4) -----------------------------
    grant_type = form.get("grant_type")
    if grant_type != GRANT_TYPE_TOKEN_EXCHANGE:
        raise OAuthError(
            UNSUPPORTED_GRANT_TYPE, "grant-type", f"unsupported grant_type {grant_type!r}"
        )

    # --- Step 1: authenticate the client (OAuth 2.1 SS 3.2.1 MUST) -----------
    # RFC 8693 SS 2.1 warns that omitting this lets *anyone possessing* a
    # compromised token leverage it into further tokens.
    if client_credentials is None:
        raise invalid_client(
            "client authentication is required", used_authorization_header=used_authorization_header
        )
    client_id, client_secret = client_credentials
    expected = config.clients.get(client_id)
    if expected is None or not secrets_equal(expected, client_secret):
        raise invalid_client(
            "unknown client or bad secret", used_authorization_header=used_authorization_header
        )

    # --- Step 2: validate the subject token (RFC 8693 SS 2.1 MUST) -----------
    subject_token = _require(form, "subject_token")
    subject_token_type = _require(form, "subject_token_type")
    if subject_token_type != TOKEN_TYPE_ACCESS_TOKEN:
        raise OAuthError(
            INVALID_REQUEST,
            "malformed-request",
            f"unsupported subject_token_type {subject_token_type!r}",
        )
    subject_claims = verify_access_token(
        subject_token,
        signing_key.public,
        issuer=config.issuer,
        now=now,
        known_audiences=config.resource_servers,
    )

    # --- Step 3: validate the actor token (RFC 8693 SS 2.1 MUST) -------------
    actor_token = form.get("actor_token")
    actor_token_type = form.get("actor_token_type")
    if actor_token is not None and actor_token_type is None:
        # RFC 8693 SS 2.1: REQUIRED iff `actor_token` is present.
        raise OAuthError(
            INVALID_REQUEST, "actor-token-type", "actor_token_type is required with actor_token"
        )
    if actor_token is None:
        raise OAuthError(
            INVALID_REQUEST, "actor-token", "this profile requires an actor_token at every hop"
        )
    if actor_token_type != TOKEN_TYPE_JWT:
        raise OAuthError(
            INVALID_REQUEST,
            "actor-token-type",
            f"unsupported actor_token_type {actor_token_type!r}",
        )

    # --- Step 4: resolve identities through the registry ---------------------
    # `oauth_actor` of the subject token is its OUTERMOST `act` (or `client_id`
    # at hop 0). Nested actors are audit history and are never read here
    # [VERIFIED, RFC 8693 SS 4.1 MUST].
    previous_actor_id = current_actor(subject_claims)
    client_entry = config.resolve_actor(client_id)
    if client_entry is None:
        raise OAuthError(
            INVALID_REQUEST, "unmapped-principal", f"client {client_id!r} resolves to no principal"
        )

    # SS 5.3's opening sentence: "The **delegating** agent (holder of AT_{i-1}) is
    # the client of the exchange." Enforced, because client authentication alone
    # does not imply it: without this check any *other* registered client that
    # came to possess the token could exchange it onward, which is the abuse
    # RFC 8693 SS 2.1 warns about in the case it does cover (unauthenticated
    # clients). Refused as "unacceptable based on policy" (SS 2.2.2).
    previous_entry = config.resolve_actor(previous_actor_id)
    if previous_entry is None or previous_entry.principal != client_entry.principal:
        raise OAuthError(
            INVALID_REQUEST,
            "unauthorized-delegator",
            f"client {client_id!r} is not the current holder of the presented subject_token",
        )

    unverified_actor = _peek_actor_subject(actor_token)
    actor_entry = config.resolve_actor(unverified_actor)
    if actor_entry is None:
        raise OAuthError(
            INVALID_REQUEST,
            "unmapped-principal",
            f"requested actor {unverified_actor!r} resolves to no principal",
        )
    actor_claims = verify_actor_assertion(
        actor_token,
        OKPKey.import_key(dict(actor_entry.identity_jwk)),
        audience=config.issuer,
        now=now,
    )
    requested_actor = actor_claims["sub"]
    if requested_actor != unverified_actor:
        raise OAuthError(
            INVALID_REQUEST, "actor-token", "actor_token subject changed under verification"
        )

    # --- Step 5: delegation permission (RFC 8693 SS 4.4 `may_act`) -----------
    may_act = subject_claims.get("may_act")
    permitted = may_act.get("sub") if isinstance(may_act, dict) else None
    if permitted is None or permitted != actor_entry.principal:
        raise OAuthError(
            INVALID_REQUEST,
            "may-act",
            f"principal {actor_entry.principal!r} is not permitted to act for this subject",
        )

    # --- Step 6: parse and validate `authorization_details` (RFC 9396 SS 5) --
    raw_details = form.get("authorization_details")
    if raw_details is None:
        raise OAuthError(
            INVALID_AUTHORIZATION_DETAILS, "rar-missing-field", "authorization_details is required"
        )
    try:
        requested_details = json.loads(raw_details)
    except ValueError as exc:
        raise OAuthError(
            INVALID_AUTHORIZATION_DETAILS,
            "rar-wrong-type",
            "authorization_details is not valid JSON",
        ) from exc
    requested_details = rar.validate_details(
        requested_details, rar_type=config.rar_type, omega=config.omega
    )

    # --- Target selection (RFC 8707 SS 2; RFC 8693 SS 2.1.1) -----------------
    resources = form.get("resource") or []
    audiences = form.get("audience") or []
    if len(resources) + len(audiences) > 1:
        raise OAuthError(
            INVALID_TARGET, "multi-target", "exactly one target may be requested per exchange"
        )
    if not resources:
        raise OAuthError(INVALID_TARGET, "audience", "a single `resource` target is required")
    requested_resource = resources[0]
    if not _is_absolute_uri_without_fragment(requested_resource):
        raise OAuthError(
            INVALID_TARGET,
            "malformed-resource",
            "resource must be an absolute URI without a fragment",
        )
    if requested_resource not in config.resource_servers:
        raise OAuthError(INVALID_TARGET, "audience", "unknown or unissuable target")

    # --- Step 7: containment, in all four planes -----------------------------
    previous_details = subject_claims.get("authorization_details") or []
    if not rar.contains(previous_details, requested_details):
        raise OAuthError(
            INVALID_AUTHORIZATION_DETAILS,
            "widening-rar",
            "requested authorization_details are not contained in the subject token's",
        )

    previous_audience = subject_claims.get("aud")
    if requested_resource != previous_audience:
        # The audience plane: RFC 8707 SS 2.2 puts acceptable values at the AS's
        # discretion; this profile narrows to the subject token's own audience.
        raise OAuthError(
            INVALID_TARGET, "audience", "requested resource is not the subject token's audience"
        )

    requested_scope = form.get("scope")
    previous_scope = _scope_set(subject_claims.get("scope"))
    granted_scope_set = (
        _scope_set(requested_scope) if requested_scope is not None else previous_scope
    )
    if not granted_scope_set <= previous_scope:
        raise OAuthError(
            INVALID_AUTHORIZATION_DETAILS,
            "widening-scope",
            "requested scope exceeds the subject token's",
        )

    # The expiry plane. The distinction below is the whole of "error, never
    # clamp", applied where it actually belongs:
    #
    #  * an **explicit** `requested_expires_in` beyond `exp_{i-1}` is a widening
    #    *request* and is refused as an error -- silently reducing it would hide
    #    an attempt to extend authority in time;
    #  * with **no** lifetime requested, the AS chooses `exp_i` itself, and caps
    #    its own default at `exp_{i-1}`. Nothing the client asked for is being
    #    quietly reduced, so this is AS policy, not a clamp.
    #
    # DESIGN SS 5.3 step 7 fixes the invariant `exp_i <= exp_{i-1}` but names no
    # default-lifetime policy. Without the cap, a fixed default equal to the
    # root's lifetime makes **hop 2 impossible** -- the parent's remaining
    # lifetime is always shorter by the elapsed time -- which would break the
    # per-hop exchange SS E.2 requires. Recorded in `smoke/g4/REPORT.md`.
    previous_exp = int(subject_claims["exp"])
    if REQUESTED_EXPIRES_IN in form:
        try:
            lifetime = int(form[REQUESTED_EXPIRES_IN])
        except ValueError as exc:
            raise OAuthError(
                INVALID_REQUEST, "malformed-request", f"{REQUESTED_EXPIRES_IN} must be an integer"
            ) from exc
        expires_at = now + lifetime
        if expires_at > previous_exp:
            raise OAuthError(
                INVALID_AUTHORIZATION_DETAILS,
                "widening-expiry",
                "requested lifetime extends beyond the subject token's exp",
            )
    else:
        expires_at = min(now + config.default_lifetime_seconds, previous_exp)
    if expires_at <= now:
        raise OAuthError(
            INVALID_REQUEST,
            "subject-token-expired",
            "the subject token leaves no lifetime to grant",
        )

    # --- Step 8: DPoP (RFC 9449 SS 5) ---------------------------------------
    cnf_jkt = None
    if config.require_dpop or dpop_proofs:
        if not dpop_proofs:
            raise OAuthError(
                INVALID_DPOP_PROOF, "dpop-proof", "a DPoP proof is required at the token endpoint"
            )
        if config.require_dpop_nonce and not _proof_carries_valid_nonce(dpop_proofs, nonce_store):
            nonce = nonce_store.issue() if nonce_store else ""
            raise OAuthError(
                USE_DPOP_NONCE,
                "dpop-nonce",
                "a server-provided nonce is required",
                headers={"DPoP-Nonce": nonce},
            )
        try:
            result = verify_proof(
                dpop_proofs,
                method="POST",
                url=config.token_endpoint,
                now=now,
                nonce_store=nonce_store,
                nonce_required=config.require_dpop_nonce,
            )
        except DPoPError as exc:
            raise OAuthError(INVALID_DPOP_PROOF, "dpop-proof", str(exc)) from exc
        cnf_jkt = result.jkt

    # --- Step 9: issue AT_i --------------------------------------------------
    granted_details = rar.filter_to_audience(requested_details, requested_resource)
    granted_scope = " ".join(sorted(granted_scope_set))
    next_permitted = config.delegation_policy.get(actor_entry.principal)
    token = mint_access_token(
        signing_key,
        issuer=config.issuer,
        subject=subject_claims["sub"],  # the resource owner, never the actor
        audience=requested_resource,
        client_id=client_id,
        issued_at=now,
        expires_at=expires_at,
        scope=granted_scope,
        authorization_details=granted_details,
        act=nest_actor(subject_claims.get("act"), requested_actor),
        may_act={"sub": next_permitted} if next_permitted else None,
        cnf_jkt=cnf_jkt,
    )

    # --- Step 10: respond ----------------------------------------------------
    # RFC 8693 SS 2.2.1: `scope` is OPTIONAL only when identical to the request.
    scope_differs = requested_scope is None or _scope_set(requested_scope) != granted_scope_set
    return TokenResponse(
        access_token=token.value,
        issued_token_type=TOKEN_TYPE_ACCESS_TOKEN,
        token_type="DPoP" if cnf_jkt else "Bearer",  # RFC 9449 SS 5 MUST
        expires_in=expires_at - now,
        authorization_details=granted_details,
        scope=granted_scope if scope_differs else None,
        claims=token.claims,
    )


def issue_initial(
    *,
    config: ASConfig,
    signing_key: SigningKey,
    subject: str,
    client_id: str,
    audience: str,
    scope: str,
    authorization_details: list[dict[str, Any]],
    lifetime_seconds: int | None = None,
    now: int | None = None,
    cnf_jkt: str | None = None,
) -> AccessToken:
    """Mint `AT_0` on the **provisioning** path, not over HTTP.

    DESIGN SS 5.1 / SS 8.2 last row: the AS runs no authorization endpoint;
    Phase-1 setup uses the pre-issued fixture path SS E.2 permits, identical for
    every arm and excluded from the delegation estimand. This function is that
    path, so it is deliberately **not** reachable from the token endpoint.
    """
    now = int(time.time()) if now is None else now
    rar.validate_details(authorization_details, rar_type=config.rar_type, omega=config.omega)
    client_entry = config.resolve_actor(client_id)
    permitted = config.delegation_policy.get(client_entry.principal) if client_entry else None
    return mint_access_token(
        signing_key,
        issuer=config.issuer,
        subject=subject,
        audience=audience,
        client_id=client_id,
        issued_at=now,
        expires_at=now + (lifetime_seconds or config.default_lifetime_seconds),
        scope=scope,
        authorization_details=rar.filter_to_audience(authorization_details, audience),
        act=None,  # hop 0 has no `act`; `oauth_actor` falls back to client_id (SS A.5.1)
        may_act={"sub": permitted} if permitted else None,
        cnf_jkt=cnf_jkt,
    )


def _peek_actor_subject(assertion: str) -> str:
    """Read the unverified `sub` of an actor assertion, to find its key.

    Only used to look up which registered key to verify **with**; the assertion
    is verified immediately afterwards and the verified `sub` is compared
    against this value, so an attacker cannot gain anything by lying here.
    """
    try:
        payload = assertion.split(".")[1]
        padded = payload + "=" * (-len(payload) % 4)
        return str(json.loads(base64.urlsafe_b64decode(padded)).get("sub", ""))
    except (IndexError, ValueError):
        raise OAuthError(
            INVALID_REQUEST, "actor-token", "actor_token is not a well-formed JWT"
        ) from None


def _proof_carries_valid_nonce(proofs: list[str], nonce_store: NonceStore | None) -> bool:
    if nonce_store is None or len(proofs) != 1:
        return False
    try:
        payload = proofs[0].split(".")[1]
        padded = payload + "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded))
    except (IndexError, ValueError):
        return False
    return nonce_store.is_valid(claims.get("nonce"))


def _is_absolute_uri_without_fragment(value: str) -> bool:
    """RFC 8707 SS 2: absolute URI, no fragment."""
    parts = urlsplit(value)
    return bool(parts.scheme) and bool(parts.netloc) and not parts.fragment
