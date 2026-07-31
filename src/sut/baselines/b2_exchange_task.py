"""`B2-exchange-task`: the fair strong OAuth arm (SS E.1, SS E.5 bits
`1 0 0 0 0 (scope in token) 0 0 0 1`).

OAuth 2.1 with an online RFC 8693 token exchange at **every** delegation hop,
narrowed to `C_i` and carried as RFC 9396 `authorization_details` under the
ADR 0017 project RAR type. It gets **no** capability-layer conjunct and must
not be given one: no crypto chain, no HTC, no INV, no policy plane.
Containment is enforced **by the AS-issued token's own scope**, which is what
the SS E.5 parenthetical marks -- not by a boundary module.

**Built to win on its own terms** (EXP2 forbidden action 3 -- never weaken a
baseline to manufacture an advantage). SS E.4's prediction, and SS E.1's
paste-ready headline, are that a well-configured token-exchange deployment
prevents scope amplification, because it enforces the same narrowed `C_n`. If
this arm did not block `F1-root` and `F1-terminal` that would be a defect in
its provisioning, not a finding about OAuth. And `B3` blocking where this arm
also blocks is **not** evidence of an advantage for `B3`: the arms differ on
invocation binding, holder binding, and online-versus-offline narrowing, which
are other families and another axis.

**Two phases (SS E.2).**

* *Phase 1* is the ADR 0021 base `AT@aud` from the AS start-up line -- the
  same pre-issued path, the same `issue_initial` call and the same shape as
  `B3`'s. The delegating client's base token carries authority exactly
  `C_0 = U_task`, because here the token IS the authority plane and the AS
  enforces `C_i subset-of C_{i-1}` against the subject token's own grant.
  **The arm checks this itself and refuses otherwise** -- see
  `_check_subject_token_is_the_task_grant`, which exists because a coarse base
  token would silently make `F1-chain-tamper` issuable and would cost this arm
  a block it should win.
* *Phase 2* is, at each hop, a real **online** round trip to the running AS.
  That round trip **is** the measured difference from the capability arms and
  is never shortcut: no cached token, no offline mint, no local narrowing.

**Anti-bias, and it is the dangerous direction.** Gratuitous AS cost inflates
`B2` **toward `B3`** -- toward this project's own hypothesis. G-4 found a real
0.7 s-per-hop `::1` fallback by measurement rather than by reading
(`smoke/g4/DESIGN.md` SS 8.2). Four things are therefore fixed here, each
asserted **structurally** by a test and **never** by timing (EXP2 forbidden
actions 4 and 5 -- nothing in this pass measures a duration):

1. the client dials the literal loopback address `127.0.0.1`, never the name
   `localhost`, whose resolution tries `::1` first on a dual-stack host;
2. one TLS context and one keep-alive HTTP/1.1 connection are built at
   provisioning time and reused across every hop;
3. no key is parsed on the request path -- the actor-assertion signing key and
   the boundary's AS public key are parsed once, at provisioning;
4. no disk I/O on the request path -- the TLS trust anchor arrives as PEM
   **text** in the injected configuration (`cadata=`), never as a file.

**Isolation.** This module imports nothing from `src/sut/oauth_as/` (ADR 0015
rule 3): it reaches the AS over the wire, and the three RFC 8693 URNs it needs
are duplicated here as wire-level protocol facts, the way the boundary
duplicates token validation rather than importing it. Its client secret and
its actor-assertion key arrive as injected start-up configuration, derived
harness-side by `src/harness/key_material` from the sealed seed; neither
touches disk (CLAUDE.md red line 8).

At the boundary the arm presents `AT_n` as a bearer token and the decision is
`src/sut/authz/boundary.py` **unchanged** -- `verify_access_token`,
`allowed_authority` via `admits`.
"""

import base64
import http.client
import json
import ssl
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

from joserfc import jwt
from joserfc.jwk import OKPKey

from src.sut.authz.boundary import (
    BoundaryConfig,
    TokenRejected,
    admits,
    allowed_authority,
    verify_access_token,
)
from src.sut.baselines.base import ArmBitmask, HopContext, InvocationContext
from src.sut.protocol.required_authority import RequiredAuthorityError, required_authority

# Wire-level protocol constants, duplicated rather than imported (ADR 0015
# rule 3). They are RFC-defined URNs, not project decisions.
GRANT_TYPE_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"  # RFC 8693 SS 2.1
TOKEN_TYPE_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"  # RFC 8693 SS 3
TOKEN_TYPE_JWT = "urn:ietf:params:oauth:token-type:jwt"  # RFC 8693 SS 3
ALGS = ["Ed25519"]  # ADR 0006 allowlist; `alg: none` can never match

# The literal loopback address. Named as a constant so the anti-bias test can
# assert the module never dials anything else (requirement 1 above).
LOOPBACK = "127.0.0.1"

REASON_ADMITTED = "b2_admitted"
REASON_TOKEN_REJECTED = "b2_oauth_token_rejected"
REASON_TOKEN_SCOPE = "b2_token_scope"  # outside the AS-issued token's authority
REASON_EXCHANGE_REFUSED = "b2_exchange_refused"  # the AS issued no token at all
REASON_MALFORMED_REQUEST = "b2_no_required_authority"
REASON_NOT_PROVISIONED = "b2_not_provisioned"
REASON_NOT_PRESENTED = "b2_nothing_presented"


class B2ConfigurationError(Exception):
    """Provisioning was incomplete. Construction-time, fail closed."""


@dataclass(frozen=True)
class ExchangeRefusal:
    """An exchange the AS refused. **No token was issued.**

    Kept as data rather than raised out of `delegate`, because a refused hop is
    a security OUTCOME to be measured, not a harness crash: the delegate holds
    no `AT_i`, presents nothing, and the boundary refuses -- with the AS's own
    catalogue row recorded so SS E.3's "which AS refusal produced the block"
    is answerable per scenario.
    """

    status: int
    error: str
    error_description: str

    def summary(self) -> str:
        return f"AS refused the exchange ({self.status} {self.error}): {self.error_description}"


@dataclass(frozen=True)
class B2Presentation:
    """What the delegate presents at the boundary: a bearer token, or nothing."""

    access_token: str | None
    audience: str
    now_epoch: int
    refusal: ExchangeRefusal | None = None


class B2ExchangeTaskArm:
    """Online per-hop RFC 8693 narrowing; bearer `AT_n` verified at the boundary."""

    name = "B2-exchange-task"
    # SS E.1 ladder properties, declared as DATA on the arm (ADR 0029). The
    # ROW decides how broad this arm's base grant is -- not which client
    # happens to be used -- and provisioning refuses a grant that disagrees
    # with the row. `B2-exchange-broad` and `B2-broad-noexchange` override
    # `ladder_grant`; the no-exchange arm additionally overrides
    # `performs_exchange`, and the broad exchange arm `narrows_at_the_hop`.
    ladder_grant = "task"  # receives per-hop `C_i`
    performs_exchange = True  # an ONLINE round trip per hop
    narrows_at_the_hop = True  # ... which narrows, rather than restating
    bitmask = ArmBitmask(
        oauth_authn=1,
        crypto_chain=0,
        authorizer=0,
        htc_holder=0,
        invoke=0,
        # SS E.5's "(scope in token)": containment is the AS-issued token's, not
        # a boundary module's. The bit is 1 because the property HOLDS; the
        # mechanism is `authorization_details`, which `admits` reads.
        contain=1,
        context=0,
        approval=0,
        jti_cache=0,
        audit=1,
    )

    def __init__(self) -> None:
        self._setup: dict[str, Any] | None = None
        self._tls_context: ssl.SSLContext | None = None
        self._connection: http.client.HTTPSConnection | None = None
        self._actor_key: OKPKey | None = None
        self._oauth_config: BoundaryConfig | None = None
        self._authorization: str = ""
        self._staged: B2Presentation | None = None
        self.exchanges: list[dict[str, Any]] = []  # one record per hop, for the matrix
        self.audit_log: list[dict[str, Any]] = []

    # -- provision: Phase-1 setup (SS E.2); everything parsed ONCE ------------ #
    def provision(self, setup: Mapping[str, Any]) -> None:
        required = {
            "as_port",
            "as_tls_cert_pem",
            "as_public_jwk",
            "issuer",
            "resource_server",
            "rar_type",
            "access_token",
            "client_id",
            "client_secret",
            "actor_id",
            "actor_identity_private_jwk",
            "scope",
            "ladder_grant",
            "grant_elements",
            "run_mode",
        }
        missing = required - set(setup)
        if missing:
            raise B2ConfigurationError(f"{self.name} provisioning is missing {sorted(missing)}")

        # ADR 0029: the SS E.1 row this arm occupies decides its base grant,
        # so the injected `ladder_grant` must NAME that row and cannot silently
        # differ from it.
        declared = type(self).ladder_grant
        if setup["ladder_grant"] != declared:
            raise B2ConfigurationError(
                f"{self.name} occupies the {declared!r} row of the SS E.1 ladder but was "
                f"provisioned as {setup['ladder_grant']!r}. Breadth is a property of the ARM, "
                "not of whichever client's token it happens to be handed (ADR 0029)"
            )
        if self.performs_exchange:
            # Requirement 2: ONE TLS context, built here and never rebuilt. The
            # trust anchor is PEM text from the injected configuration, so no
            # certificate is read from -- or written to -- disk (requirement 4).
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.load_verify_locations(cadata=setup["as_tls_cert_pem"])
            self._tls_context = context
            # Requirement 1: the literal loopback address. The AS certificate
            # carries a `127.0.0.1` IP SAN, so hostname verification still
            # holds. Requirement 2 again: ONE keep-alive connection, reused
            # across hops.
            self._connection = http.client.HTTPSConnection(
                LOOPBACK, int(setup["as_port"]), context=context, timeout=15
            )
        # Requirement 3: keys parsed once, here. The actor-assertion signing
        # key and (inside BoundaryConfig) the AS public key are never re-parsed
        # per request.
        self._actor_key = OKPKey.import_key(dict(setup["actor_identity_private_jwk"]))
        self._oauth_config = BoundaryConfig(
            issuer=setup["issuer"],
            resource_server=setup["resource_server"],
            as_public_jwk=setup["as_public_jwk"],
            rar_type=setup["rar_type"],
        )
        # `client_secret_basic` (OAuth 2.1 SS 3.2.1), encoded once. The secret
        # is runtime-only, injected, and never written anywhere.
        credentials = f"{setup['client_id']}:{setup['client_secret']}".encode()
        self._authorization = "Basic " + base64.b64encode(credentials).decode("ascii")
        self._check_subject_token_matches_the_ladder_grant(setup)
        self._setup = dict(setup)

    # -- the ADR 0024/0029 guarantee, held by the ARM -------------------------- #
    def _check_subject_token_matches_the_ladder_grant(self, setup: Mapping[str, Any]) -> None:
        """Refuse a subject token whose authority is not exactly this row's grant.

        **This arm can otherwise be misprovisioned silently, and it fails
        TOWARD the hypothesis.** The AS enforces `C_i subset-of C_{i-1}`
        against the subject token's OWN `authorization_details`, so a base
        token left at the pilot's coarse `Omega` grant means the AS enforces
        only `C_1 subset-of Omega`. `F1-chain-tamper` widens to
        `(mail.send, mail/outbox)`, an element that IS in `Omega`, so the AS
        would **issue** the widened `AT_1`, this arm would lose SS E.3's
        predicted block for a provisioning reason, and `B3` would appear to
        win a comparison it did not win. Forbidden action 3 forbids weakening
        `B2` in any respect; being provisioned so its own containment check is
        toothless is exactly that.

        ADR 0024 put the fix in the AS document, which left the guarantee with
        the CALLER -- and `task_grant` is opt-in with the dangerous value as
        its default. The guarantee lives here instead: the arm reads the
        authority of the token it actually holds, out of that token's own
        claims, and refuses to provision unless it equals the `U_task` it was
        given for the run. Being correctly provisioned today is not the same
        property as being impossible to misprovision.

        The equality is `==`, not `subset-of`: a subject token carrying LESS
        than its row's grant would make the arm unable to pass on what the row
        specifies and would show up as a spurious block, which is the opposite
        bias and equally unacceptable.

        **ADR 0029 generalises the check without weakening it.** `U_task` is
        the STRONG rows' grant; the BROAD rows' is the coarse `Omega`, because
        SS E.4 predicts they ADMIT `F1-root` and `(mail.send, mail/outbox)`
        lies outside `U_task` -- on a task-scoped token a broad arm would
        block it, contradicting SS E.4 and destroying the arm whose whole job
        is to isolate the exchange round trip FROM narrowing. Which grant
        applies is read from `type(self).ladder_grant`, checked above, so the
        arm still cannot be handed a grant its row does not specify.
        """
        assert self._oauth_config is not None
        declared = type(self).ladder_grant
        expected = frozenset((action, resource) for action, resource in setup["grant_elements"])
        if not expected:
            raise B2ConfigurationError(
                f"{self.name}: `grant_elements` is empty; the arm cannot verify its own "
                "provisioning against nothing (ADR 0024/0029)"
            )
        try:
            claims = verify_access_token(
                setup["access_token"], self._oauth_config, now=int(time.time())
            )
        except TokenRejected as exc:
            raise B2ConfigurationError(
                f"{self.name}: the injected subject token does not verify at this boundary "
                f"({exc.reason}: {exc.description}), so its authority cannot be checked "
                "against its ladder row's grant (ADR 0024/0029)"
            ) from exc
        granted = allowed_authority(claims, self._oauth_config)
        if granted != expected:
            raise B2ConfigurationError(
                f"{self.name}: the injected subject token grants {sorted(granted)}, but the "
                f"{declared!r} row of the SS E.1 ladder specifies {sorted(expected)}. "
                "ADR 0024/0029: the AS enforces per-hop containment against this token's own "
                "authorization_details, so a token wider than the row would let a chain-tamper "
                "hop be ISSUED and cost a strong arm a block it should win, while one narrower "
                "than the row would make a broad arm block what SS E.4 predicts it admits."
            )

    # -- delegate: the ONLINE Phase-2 hop (SS E.2) ---------------------------- #
    def delegate(self, hop: HopContext) -> Mapping[str, Any]:
        """One real round trip to the AS, yielding `AT_i` with authority `C_i`.

        `hop.widening_elements` is the SS E.3 chain-tamper INTENT, realized the
        way this mechanism realizes it: the elements are added to the requested
        `authorization_details`, so what goes on the wire is an exchange that
        would widen. The pinned AS profile refuses it as `widening-rar` and
        **issues no token** -- never silently clamping to the intersection,
        which would make a tamper indistinguishable from a benign narrowing.
        """
        if self._setup is None or self._connection is None:
            raise RuntimeError(REASON_NOT_PROVISIONED)
        requested = self._requested_elements(hop)
        details = [
            {
                "type": self._setup["rar_type"],
                "locations": [hop.audience],
                "actions": [action],
                "datatypes": [resource],
            }
            for action, resource in requested
        ]
        form = {
            "grant_type": GRANT_TYPE_TOKEN_EXCHANGE,
            "subject_token": self._setup["access_token"],
            "subject_token_type": TOKEN_TYPE_ACCESS_TOKEN,
            "actor_token": self._actor_assertion(hop.now_epoch),
            "actor_token_type": TOKEN_TYPE_JWT,
            "resource": hop.audience,
            "scope": self._setup["scope"],
            "authorization_details": json.dumps(details),
        }
        status, body = self._post_token(form, now_epoch=hop.now_epoch)
        if status != 200 or "access_token" not in body:
            refusal = ExchangeRefusal(
                status=status,
                error=str(body.get("error", "unknown_error")),
                error_description=str(body.get("error_description", "")),
            )
            self.exchanges.append(
                {"hop": len(self.exchanges), "issued": False, "refusal": refusal.summary()}
            )
            # No token issued: the credential the envelope carries is EMPTY.
            return {"audience": hop.audience, "exchange_refusal": refusal}
        self.exchanges.append(
            {
                "hop": len(self.exchanges),
                "issued": True,
                "authorization_details": body.get("authorization_details", []),
                "scope": body.get("scope"),
            }
        )
        return {
            "access_token": body["access_token"],
            "audience": hop.audience,
            "authorization_details": body.get("authorization_details", []),
        }

    def _requested_elements(self, hop: HopContext) -> tuple[tuple[str, str], ...]:
        """What this row asks the AS for at the hop.

        A NARROWING row asks for `C_i` (plus, on `F1-chain-tamper`, the
        widening the scenario declares -- which the AS refuses). A BROAD row
        asks for **exactly what it already holds**, which is the whole point:
        `B2-exchange-broad` isolates the exchange round trip **from**
        narrowing, so an implementation that quietly narrowed would destroy
        the arm and silently contradict SS E.4. `widening_elements` is not
        added on a broad row -- it is already inside that row's grant, which
        is why SS E.3 marks the subcase **NA** for the broad arms rather than
        expecting a block.
        """
        if self.narrows_at_the_hop:
            return tuple(hop.attenuation_elements) + tuple(hop.widening_elements)
        return tuple((action, resource) for action, resource in self._setup["grant_elements"])

    def _actor_assertion(self, now_epoch: int) -> str:
        """The delegate's actor assertion, signed with the key parsed at provision.

        `[DESIGN]` -- deliberately not described as an RFC 7523 assertion;
        `smoke/g4/DESIGN.md` SS 1.7 records RFC 7523 as not read. Minted fresh
        per hop so its window is honest, but the KEY is the one parsed once at
        provisioning time (anti-bias requirement 3).
        """
        return jwt.encode(
            {"alg": ALGS[0], "typ": "JWT"},
            {
                "sub": self._setup["actor_id"],
                "aud": self._setup["issuer"],
                "iat": now_epoch,
                "exp": now_epoch + 120,
            },
            self._actor_key,
            algorithms=ALGS,
        )

    def token_endpoint_proof(self, now_epoch: int) -> str | None:
        """A DPoP proof for the token endpoint, or `None` for a bearer arm.

        The seam `B2-exchange-task-DPoP` fills (RFC 9449 SS 5). Bearer arms
        return `None` and send no `DPoP` header at all, so the AS binds no
        `cnf` -- which is exactly the difference the ladder measures.
        """
        return None

    def _post_token(self, form: Mapping[str, Any], *, now_epoch: int) -> tuple[int, dict[str, Any]]:
        """POST the exchange over the ONE reused keep-alive connection.

        A dropped keep-alive is reconnected once on the SAME connection object
        (`http.client` reconnects in `request`), never by building a second
        connection or a second TLS context.
        """
        body = urlencode(dict(form), doseq=True).encode("ascii")
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": self._authorization,
            "Content-Length": str(len(body)),
        }
        proof = self.token_endpoint_proof(now_epoch)
        if proof is not None:
            headers["DPoP"] = proof
        connection = self._connection
        assert connection is not None
        connection.request("POST", "/token", body=body, headers=headers)
        response = connection.getresponse()
        payload = response.read()  # drained, so the connection stays reusable
        parsed = json.loads(payload) if payload else {}
        return response.status, parsed

    # -- present: stage `AT_n` as a bearer token ------------------------------ #
    def present(
        self, credentials: Mapping[str, Any], invocation: InvocationContext
    ) -> Mapping[str, Any]:
        if self._setup is None:
            raise RuntimeError(REASON_NOT_PROVISIONED)
        refusal = credentials.get("exchange_refusal")
        token = credentials.get("access_token")
        self._staged = B2Presentation(
            access_token=token,
            audience=invocation.audience,
            now_epoch=invocation.now_epoch,
            refusal=refusal,
        )
        # A refused hop leaves the delegate with NOTHING to present. The wire is
        # empty, and the SS F.1 bundle built from it is empty too -- which is
        # the honest record of what happened.
        return {"access_token": token} if token is not None else {}

    # -- decide: `src/sut/authz/boundary.py`, unchanged ----------------------- #
    def decide(self, tool: str, arguments: Mapping[str, Any]) -> tuple[bool, str]:
        admitted, reason, detail = self._decide(tool, arguments)
        self._audit(tool, admitted, reason, detail)
        return admitted, reason

    def _decide(self, tool: str, arguments: Mapping[str, Any]) -> tuple[bool, str, str]:
        if self._oauth_config is None:
            return False, REASON_NOT_PROVISIONED, "no boundary configuration"
        if self._staged is None:
            return False, REASON_NOT_PRESENTED, "nothing was presented"
        staged = self._staged
        if staged.refusal is not None:
            return False, REASON_EXCHANGE_REFUSED, staged.refusal.summary()
        if not staged.access_token:
            return False, REASON_NOT_PRESENTED, "no access token was presented"
        try:
            claims = verify_access_token(
                staged.access_token, self._oauth_config, now=staged.now_epoch
            )
        except TokenRejected as exc:
            return False, REASON_TOKEN_REJECTED, f"{exc.reason}: {exc.description}"
        holder = self.check_holder_binding(staged, claims)
        if holder is not None:
            return holder
        try:
            elements = sorted(required_authority(tool, arguments))
        except RequiredAuthorityError as exc:
            return False, REASON_MALFORMED_REQUEST, str(exc)
        for element in elements:
            decision = admits(
                claims, self._oauth_config, element=element, required_scope=self._setup["scope"]
            )
            if not decision.admitted:
                return (
                    False,
                    REASON_TOKEN_SCOPE,
                    f"{element} is {decision.reason}",
                )
        return True, REASON_ADMITTED, ""

    def check_holder_binding(self, staged, claims) -> "tuple[bool, str, str] | None":
        """The holder-binding layer, or `None` when the arm is a bare bearer.

        Returns a refusal triple to block, or `None` to fall through. The seam
        `B2-exchange-task-DPoP` fills; for every bearer arm on the ladder there
        is nothing to check, and SS E.1's `Holder-bound? = no` is that absence.

        Placed AFTER token verification -- there is no `cnf` to compare
        against until the token verifies -- and BEFORE the scope check, so a
        holder failure is attributable to the holder plane rather than being
        masked by an out-of-scope request.
        """
        return None

    def _audit(self, tool: str, admitted: bool, reason: str, detail: str) -> None:
        # audit=1, OFF the decision path: a sink failure never changes the outcome.
        try:
            self.audit_log.append(
                {
                    "layer": "oauth-boundary",
                    "arm": self.name,
                    "tool": tool,
                    "admitted": admitted,
                    "reason_code": reason,
                    "detail": detail,
                }
            )
        except Exception:  # noqa: BLE001 -- log loss is never a prevention outcome
            pass

    def close(self) -> None:
        """Release the keep-alive connection. Never called on the request path."""
        if self._connection is not None:
            self._connection.close()
