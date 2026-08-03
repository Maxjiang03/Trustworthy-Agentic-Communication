"""Matched per-hop authority, recomputed independently (gate G-13).

SS E.2 defines the instrument: *an independent harness verifier recomputes
`Allowed(AT_i)` over `Omega` and asserts `Allowed(AT_i) = C_i` for every hop
and every strong baseline*. This module is that verifier. It is the
**instrument**, so it lives under `src/harness/` and recomputes everything it
checks from **raw presented evidence** -- never from a value a system under
test computed (D13/D21, PROJECT_RULES.md red line 4).

**How the reading of `AT_i` is settled.** The Part G row writes `Allowed(AT_i)`,
but SS E.2 applies the same sentence to *every strong baseline* -- including the
capability arms, which mint no per-hop OAuth token at all. `AT_i` therefore
denotes **the per-hop authority-bearing object**, whatever the mechanism's is:
`AT_i` for the exchange arm and `P_i` for the capability arms. The pass
criterion is *"no strong baseline differs in authority granularity"*, which is a
statement about the SETS each arm realizes and not about the format they travel
in. Online-versus-offline narrowing is the **measured difference** the study
exists to report, not a defect to normalize away, so this module recomputes each
arm in its own terms and compares only the resulting `C_0 -> ... -> C_n`.

**Two planes, two independent implementations, neither the SUT's.**

* The **token plane** is new here. It parses the presented token itself and
  decides membership **one candidate at a time** over the frozen `Omega` -- the
  G-2 discipline of *compute, never assert*, applied to RFC 9396
  `authorization_details` intersected with the `aud` and `scope` planes. It
  deliberately does **not** reuse `src/sut/authz/boundary.py`: that module is
  the measured system's boundary, and an instrument sharing its implementation
  could not detect a defect in it (D13/D21). It imports nothing from
  `src/sut/` at all, and nothing from `src/sut/oauth_as/` in particular
  (ADR 0015 rule 4), so it cannot inherit either end's mistake.
* The **capability plane** reuses `src/harness/authorizer/allowed.py`, the
  harness's own `Allowed(P_i; Gamma, kappa, Omega)` that gate G-2 adjudicated --
  one authorizer run per element of `Omega`, over the frozen `Gamma`. That is
  already the independent counterpart of `src/sut/capability/authority.py`;
  reimplementing it a third time would add no independence and would risk
  disagreeing with the artifact G-2 verified.

Structurally distinct from the boundary on purpose: the boundary computes a
capability-plane SET and then applies `scope` per request, while this module
asks a yes/no question per candidate with all three planes inside it. Same
frozen inputs, different construction -- which is what makes agreement
evidence rather than tautology.

**The residual that leaves, stated precisely enough to be auditable.** Gate
G-13's L1 is an agreement test between this module and the SUT, and agreement
is evidence of independence only while the two constructions really differ. It
is tempting to record that as "a future refactor could undo it", but that is
broader than the truth and a vague residual is one nobody acts on. Precisely:
G-13's L4 import scan **would** catch a refactor that made this module import
`src/sut/authz/boundary.py`, because that is a cross-boundary import and L4.W1
proved the scan non-vacuous by flagging one. What no import scan can catch is
**copy-paste convergence** -- this token plane rewritten with the boundary's
construction (a capability-plane set built first, `scope` applied per request
afterwards) and no import at all. The two would then agree because they are the
same algorithm rather than because two constructions independently reached one
answer, and every L1 equality would still pass. **The guard against that is
review of a change to this module, not a test**, and saying so is the point of
recording it here.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import OKPKey

from src.harness.authorizer import allowed as capability_authorizer
from src.harness.authorizer import frozen_config

ALGS = ["Ed25519"]  # ADR 0006 allowlist; `alg: none` can never match
AT_TYP = "at+jwt"  # RFC 9068 SS 2.1


class TokenRefused(Exception):
    """The presented token did not verify. `check` names which condition."""

    def __init__(self, check: str, detail: str) -> None:
        super().__init__(f"{check}: {detail}")
        self.check = check
        self.detail = detail


@dataclass(frozen=True)
class TokenVerifierConfig:
    """What the verifier knows, all from sealed configuration.

    `as_public_jwk` arrives as data, never from a `jwks_uri` -- the pinned
    profile publishes none (`smoke/g4/DESIGN.md` SS 5.1).
    """

    issuer: str
    resource_server: str
    as_public_jwk: dict[str, str]
    rar_type: str
    required_scope: str


def verify_token(token: str, config: TokenVerifierConfig, *, now: int) -> dict[str, Any]:
    """RFC 9068 SS 4, reimplemented here rather than shared with the boundary.

    Signature under the AS key with an explicit algorithm allowlist, `typ`,
    exact `iss`, `aud` naming this resource server, and `exp` in the future.
    Every failure raises: an unverifiable token has no authority to recompute,
    and must never be read as one that happens to admit nothing.
    """
    try:
        decoded = jwt.decode(token, OKPKey.import_key(dict(config.as_public_jwk)), algorithms=ALGS)
    except JoseError as exc:
        raise TokenRefused("signature", type(exc).__name__) from exc
    except (ValueError, TypeError) as exc:
        raise TokenRefused("malformed", "not a well-formed JWT") from exc
    header = decoded.header
    if header.get("alg") not in ALGS:
        raise TokenRefused("alg", f"alg {header.get('alg')!r} is outside the ADR 0006 allowlist")
    if header.get("typ") != AT_TYP:
        raise TokenRefused("typ", f"typ is {header.get('typ')!r}, expected {AT_TYP!r}")
    claims = dict(decoded.claims)
    if claims.get("iss") != config.issuer:
        raise TokenRefused("iss", "issuer does not match exactly")
    audience = claims.get("aud")
    names_rs = (
        audience == config.resource_server
        if isinstance(audience, str)
        else config.resource_server in audience
        if isinstance(audience, list)
        else False
    )
    if not names_rs:
        raise TokenRefused("aud", "audience does not name this resource server")
    expires_at = claims.get("exp")
    if not isinstance(expires_at, int) or now >= expires_at:
        raise TokenRefused("exp", "token has expired")
    return claims


def token_admits(claims: dict[str, Any], config: TokenVerifierConfig, element) -> bool:
    """Does this token admit ONE candidate `(action, resource)`?

    All three planes, inside one question: the RFC 9396 SS 2.2 product of an
    `authorization_details` object of this profile's `type` whose single
    `locations` value is this resource server, intersected with the OAuth
    `scope` plane. `verify_token` has already established the `aud` plane, and
    is a precondition of calling this.

    The expansion is recomputed per candidate from the token's OWN claim. The
    verifier never trusts an AS-supplied summary of what a token permits, and
    never reads a set the boundary computed.
    """
    if config.required_scope:
        scope = claims.get("scope")
        granted = frozenset(scope.split()) if isinstance(scope, str) else frozenset()
        if config.required_scope not in granted:
            return False
    action, resource = element
    details = claims.get("authorization_details")
    if not isinstance(details, list):
        return False
    for entry in details:
        if not isinstance(entry, dict) or entry.get("type") != config.rar_type:
            continue
        if entry.get("locations") != [config.resource_server]:
            # RFC 9396 SS 9.1: an object naming another location contributes
            # nothing here. One location per object is the ADR 0017 profile
            # restriction, so anything else is not a well-formed grant for us.
            continue
        actions = entry.get("actions")
        datatypes = entry.get("datatypes")
        if not isinstance(actions, list) or not isinstance(datatypes, list):
            continue
        # RFC 9396 SS 12: byte-exact RFC 8259 string equality, no normalization.
        if action in actions and resource in datatypes:
            return True
    return False


def token_allowed(
    token: str,
    config: TokenVerifierConfig,
    omega,
    *,
    now: int,
) -> frozenset[tuple[str, str]]:
    """`Allowed(AT)` over `Omega`: one membership decision per element.

    Compute, never assert (the G-2 discipline). The set is built by asking the
    token about each element of the frozen ontology in turn, so a defect that
    made one element wrongly admitted cannot hide inside a bulk expansion.
    """
    claims = verify_token(token, config, now=now)
    return frozenset(element for element in sorted(omega) if token_admits(claims, config, element))


def capability_allowed_per_hop(
    hops,
    root_pub,
    document: dict[str, Any],
    *,
    now_epoch: int,
    audience: str,
    task_id: str,
) -> list[frozenset[tuple[str, str]]]:
    """`Allowed(P_i; Gamma, kappa, Omega)` for `i = 0 .. n`, from raw hop bytes.

    Each prefix is authorized on its own: `Chain` verifies from ADR 0003 block
    identifiers that hop `i` really extends hop `i-1`, so the prefix relation is
    read from signatures rather than assumed from call order, and `allowed`
    then runs the frozen authorizer once per element of `Omega`.
    """
    raw = [bytes(hop) for hop in hops]
    context = capability_authorizer.RequestContext(
        now=datetime.fromtimestamp(now_epoch, tz=timezone.utc),
        audience=audience,
        task=task_id,
    )
    per_hop: list[frozenset[tuple[str, str]]] = []
    for index in range(len(raw)):
        # A truncated chain, so `evaluation.prefix = P_n` selects hop `index`
        # without this module reaching past what the frozen Gamma names.
        chain = capability_authorizer.Chain(tuple(raw[: index + 1]), root_pub)
        per_hop.append(capability_authorizer.allowed(chain, document, context))
    return per_hop


def omega() -> frozenset[tuple[str, str]]:
    """The frozen ontology, read from the artifact ADR 0016 sealed."""
    return frozen_config.omega(frozen_config.load_document())
