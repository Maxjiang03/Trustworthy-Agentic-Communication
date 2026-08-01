"""`B2-exchange-task-DPoP` [D34]: the exchange arm plus RFC 9449 holder binding.

SS E.1's row: everything `B2-exchange-task` has, **plus** a `cnf`/`jkt`-bound
token and a proof per request. `Holder-bound? = yes (key)`; `Binds invocation?
= method+URI only`. SS E.5 bits `1 0 0 dpop-cnf 0 (scope in token) 0 0 0 1`.

**This arm is wiring plus a proof-signing client, not new cryptography**, and it
is built that way deliberately. All three pieces exist and are reused
**unchanged**: the AS's DPoP surface (`require_dpop`, `cnf_jkt`, `NonceStore`,
adjudicated at G-4), `src/sut/dpop.py`'s RFC 9449 SS 4.3 verifier (items 1-11 at
the token endpoint, item 12 at a protected resource), and
`boundary.verify_dpop_request`. Reimplementing any of them would put a second
construction beside one a gate already verified.

**Two proofs, one key.** The arm signs a proof over `POST <token endpoint>` on
the exchange, which makes the AS bind `cnf.jkt` to that key; and a proof over
`POST <resource URL>` carrying `ath` at the boundary, which
`verify_dpop_request` checks against the presented token and its `cnf`. One key
signs both, which is what makes the binding mean anything -- a token bound to a
key nobody holds proves nothing.

**Method + URI only, and the limitation is made OBSERVABLE rather than merely
true.** A DPoP proof covers `htm`, `htu`, `iat`, `jti` and `ath`
**[VERIFIED, RFC 9449 SS 4.2]** -- not the tool, not the arguments, not the
body. `proof_claim_names()` exposes exactly what a proof carries so a test can
read it, and the same proof verifies against a **different tool at the same
endpoint**, because nothing in it depends on which tool was named. That is
SS D's `dpop-first-use-body-mutation` (T-tool / T-args), predicted **admitted**
for this arm and **blocked** by `B3`'s `invocation_binding_ok`. It is exactly
the gap SS D says `B3`'s canonical body/args binding fills, and G-14 will
attribute it. **Building the arm is not building that family's fixtures**
(EXP3 forbidden action 7): what is here is an arm-level property, not a corpus
scenario.

Do not accidentally give it body binding. The proof is minted from the
invocation's *endpoint and instant*, never from its tool or arguments, and a
test asserts the claim set.

**Anti-bias, inherited in full and extended by one.** The four structural
requirements of `B2-exchange-task` apply unchanged -- literal `127.0.0.1`, one
TLS context and one keep-alive connection, no key parsed on the request path,
no disk I/O on the request path -- and the proof key adds a fifth instance of
the third: it is parsed **once**, at provisioning, and reused to sign every
proof. Counted, never timed (EXP3 forbidden actions 1 and 6).

`Delta` is ADR 0027's, shared with the `jti` cache and INV freshness, so G-14's
two arms cannot differ in window. `now` is injected at both proof sites.
"""

from collections.abc import Mapping
from typing import Any

from joserfc.jwk import OKPKey

from src.sut import dpop
from src.sut.authz.boundary import TokenRejected, verify_dpop_request
from src.sut.authz.jti_cache import Consumption
from src.sut.baselines.b2_exchange_task import (
    REASON_NOT_PROVISIONED,
    B2ConfigurationError,
    B2ExchangeTaskArm,
)
from src.sut.baselines.base import ArmBitmask, InvocationContext

# The HTTP method the protected resource is addressed with. MCP's own `method`
# (`tools/call`) is a JSON-RPC method, not an HTTP one; RFC 9449's `htm` is the
# HTTP method, so the two are deliberately not conflated.
RESOURCE_METHOD = "POST"

REASON_HOLDER_PROOF = "b2dpop_holder_proof"
# Gate G-14's shared authenticated-request-id cache, when one is attached.
REASON_REPLAY_DUPLICATE = "b2dpop_replay_duplicate"
# The DPoP proof's own `jti` is this arm's authenticated request id. It is
# NAMESPACED apart from `B3`'s INV `invocation_id` (SS F.5's
# `(mechanism_tag, jti)` key) because the two come from different mechanisms
# and, sharing one cache, could otherwise collide and let one arm deny the
# other's request.
DPOP_MECHANISM_TAG = "dpop"


class B2ExchangeTaskDPoPArm(B2ExchangeTaskArm):
    """`B2-exchange-task` + DPoP. A configuration of it, not a copy."""

    name = "B2-exchange-task-DPoP"
    ladder_grant = "task"
    performs_exchange = True
    narrows_at_the_hop = True
    # SS E.1: holder-bound by KEY. The mechanism is named because the ladder
    # has two different ones and conflating them is the trap SS D warns about:
    # the DPoP holder is a proof key, `B3`'s is the terminal HTC identity key.
    holder_binding_mechanism = "dpop-cnf"
    bitmask = ArmBitmask(
        oauth_authn=1,
        crypto_chain=0,
        authorizer=0,
        # SS E.5's `dpop-cnf`: the column is non-zero because the arm IS
        # holder-bound. It selects no SS A.5 conjunct -- this arm runs no
        # `CapabilityDecisionPath` at all, so `enabled_conjuncts()` is not
        # consulted for it; the binding is RFC 9449's, checked below.
        htc_holder=1,
        invoke=0,  # method+URI only: NOT the tool, NOT the arguments
        contain=1,  # "(scope in token)", as for every exchange row
        context=0,
        approval=0,
        jti_cache=0,
        audit=1,
    )

    def __init__(self) -> None:
        super().__init__()
        self._proof_key: OKPKey | None = None
        # CONFIGURATION, exactly as ADR 0030's monitor is for the policy
        # conjuncts: `None` unless a run attaches one, and the SS E.5 bitmask
        # does not move either way (`jti_cache = 0` remains this arm's LADDER
        # position). Gate G-14 attaches the SAME cache object here and on `B3`.
        self._replay_cache: Any = None
        self._token_endpoint: str | None = None
        self._resource_url: str | None = None
        self._staged_proof: str | None = None

    # -- provision: the proof key parsed ONCE ------------------------------- #
    def provision(self, setup: Mapping[str, Any]) -> None:
        missing = {"dpop_private_jwk", "as_token_endpoint", "resource_url"} - set(setup)
        if missing:
            raise B2ConfigurationError(f"{self.name} provisioning is missing {sorted(missing)}")
        super().provision(setup)
        # Anti-bias requirement 3, extended: parsed here and never again. Every
        # proof this arm signs -- one per exchange, one per invocation -- uses
        # this object.
        self._proof_key = OKPKey.import_key(dict(setup["dpop_private_jwk"]))
        self._token_endpoint = setup["as_token_endpoint"]
        self._resource_url = setup["resource_url"]

    # -- the exchange proof: makes the AS bind `cnf.jkt` -------------------- #
    def token_endpoint_proof(self, now_epoch: int) -> str:
        """RFC 9449 SS 5: a proof at the token endpoint, so `AT_i` carries `cnf`.

        `htu` is the AS's **configured** token endpoint, which is what the AS
        compares against -- not the loopback address the client dials. The two
        differ by construction here (ADR 0017's profile publishes a logical
        issuer; the socket is on `127.0.0.1`), and binding the proof to the
        dialled address would be rejected as `htu` mismatch.
        """
        if self._proof_key is None or self._token_endpoint is None:
            raise RuntimeError(REASON_NOT_PROVISIONED)
        return dpop.create_proof(
            self._proof_key,
            method="POST",
            url=self._token_endpoint,
            iat=now_epoch,  # injected, never a wall clock (ADR 0027)
        )

    # -- present: mint the per-invocation proof ----------------------------- #
    def present(
        self, credentials: Mapping[str, Any], invocation: InvocationContext
    ) -> Mapping[str, Any]:
        wire = super().present(credentials, invocation)
        token = credentials.get("access_token")
        if self._proof_key is None or self._resource_url is None:
            raise RuntimeError(REASON_NOT_PROVISIONED)
        if token is None:
            # A refused exchange leaves nothing to bind a proof to.
            self._staged_proof = None
            return wire
        # `ath` binds the proof to THIS access token (RFC 9449 SS 4.3 item 12).
        # Nothing here reads `invocation.tool` or `invocation.arguments`: the
        # proof covers method + URI, and giving it body binding would make this
        # arm indistinguishable from `B3` on the very axis SS D separates them.
        self._staged_proof = dpop.create_proof(
            self._proof_key,
            method=RESOURCE_METHOD,
            url=self._resource_url,
            ath=dpop.access_token_hash(token),
            iat=invocation.now_epoch,
        )
        return dict(wire, dpop_proof=self._staged_proof)

    # -- the holder-binding layer at the boundary --------------------------- #
    def check_holder_binding(self, staged, claims) -> "tuple[bool, str, str] | None":
        """RFC 9449 SS 4.3 item 12, through `boundary.verify_dpop_request` UNCHANGED.

        `ath` must equal the hash of *this* access token and the token's
        `cnf.jkt` must match the proof key, so a stolen token presented by a
        party without the key fails -- SS D's `dpop-stolen-AT-key-substitution`
        (T-reuse), which this arm blocks and the bare bearer arms do not.
        """
        if self._staged_proof is None:
            return False, REASON_HOLDER_PROOF, "no DPoP proof was presented"
        try:
            verify_dpop_request(
                staged.access_token,
                claims,
                [self._staged_proof],
                method=RESOURCE_METHOD,
                url=self._resource_url,
                now=staged.now_epoch,
            )
        except TokenRejected as exc:
            return False, REASON_HOLDER_PROOF, f"{exc.reason}: {exc.description}"
        return self._consume_request_id(staged)

    # -- G-14: the shared authenticated-request-id cache --------------------- #
    def attach_replay_cache(self, cache: Any) -> None:
        """Attach the shared cache. Configuration, not a ladder property.

        The SAME object gate G-14 attaches to `B3`, so the two arms are
        compared on one cache rather than on two that behave alike -- the
        discipline G-15 established for the reference monitor. A cache that is
        merely equivalent is not the same cache, and this gate is an
        attribution claim.
        """
        self._replay_cache = cache

    def _consume_request_id(self, staged: Any) -> "tuple[bool, str, str] | None":
        """SS F.5's check-and-insert, AFTER every other check has passed.

        The id consumed is the DPoP proof's own `jti` -- an **authenticated**
        request id, because the proof is signed by the key `cnf.jkt` binds the
        token to. That is what makes the cache meaningful here and impossible
        on a bare bearer arm (gate G-14, claim 3).
        """
        if self._replay_cache is None:
            return None
        proof = self._staged_proof
        if proof is None:
            return None
        import base64
        import json

        payload = proof.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        jti = claims.get("jti")
        if not jti:
            # No authenticated id to consume: fail closed rather than admit.
            return False, REASON_REPLAY_DUPLICATE, "the DPoP proof carries no jti to consume"
        outcome = self._replay_cache.consume(DPOP_MECHANISM_TAG, str(jti), now=staged.now_epoch)
        if outcome is not Consumption.ADMITTED:
            return (
                False,
                REASON_REPLAY_DUPLICATE,
                f"DPoP proof jti {jti!r} was already admitted within Delta "
                f"({outcome.value}; SS F.5: at-most-once ADMISSION per jti)",
            )
        return None

    # -- what a proof actually covers, exposed so a test can read it -------- #
    def proof_claim_names(self) -> frozenset[str]:
        """The claim set of the staged proof.

        Exposed to make SS E.1's *method+URI only* **observable** rather than
        merely true: a reader (and a test) can see that no claim names the
        tool, the arguments or any digest of them.
        """
        if self._staged_proof is None:
            return frozenset()
        import base64
        import json

        payload = self._staged_proof.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        return frozenset(claims)

    def staged_proof(self) -> str | None:
        """The proof as presented, for a test that must replay or mutate it."""
        return self._staged_proof

    def restage_proof(self, proof: str | None) -> None:
        """Replace the staged proof. Test seam; never used on the run path."""
        self._staged_proof = proof


def dpop_jwk(private_raw_jwk: dict[str, Any]) -> dict[str, Any]:
    """The public half of a DPoP key, as `cnf.jkt` is computed over."""
    return {k: v for k, v in private_raw_jwk.items() if k != "d"}
