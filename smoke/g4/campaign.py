"""Spike-local campaign fixture for gate G-4 Phase 2.

**SPIKE-LOCAL — NOT A FROZEN ARTIFACT.** Everything this module invents is a
stand-in that `smoke/g4/DESIGN.md` SS 9 named in advance, and each carries the
event that re-triggers the limb depending on it:

* **C3, the identity-plane registry** -- `oauth_actor -> principal -> Ed25519
  public key`, including a deliberately unmapped actor to exercise rejection.
  The holder key here is a **raw spike key, not the terminal key of a verified
  HTC chain**. The frozen registry is a seal-time artifact (SS F.2.1, Part H
  step 3). **Re-triggered at G-11.**
* **The `may_act` delegation policy** -- the frozen `task_authorization_policy`
  is `frozen_parameters` row 5, **UNSET**; the F2 `wrong_principal` family is
  not scored until that row is fixed by its own ADR (DESIGN SS 7.4).
* **The campaign seed and the RAR type URI** -- run-time values for this gate.

What is **not** a stand-in: `Omega` is the **frozen** ontology, loaded from
`src/harness/authorizer/omega_gamma_v1.json` and passed to the AS as start-up
configuration (ADR 0016 closed conflict C1, so limb L2 needs no `Omega_spike`).
Loading it here is the *runner's* job, which is why this module -- not the AS --
touches the harness: `src/sut/` must never import `src/harness/` (red line 6).
"""

import base64
import http.client
import json
import ssl
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from joserfc import jwt  # noqa: E402
from joserfc.jwk import OKPKey  # noqa: E402

from src.harness.authorizer import frozen_config  # noqa: E402  (runner role: reads frozen data)
from src.sut.oauth_as.config import SPIKE_LOCAL_BANNER, ASConfig, RegistryEntry  # noqa: E402
from src.sut.oauth_as.exchange import issue_initial  # noqa: E402
from src.sut.oauth_as.keys import (  # noqa: E402
    ALGS,
    derive_client_secret,
    derive_identity_key,
    derive_signing_key,
    derive_tls_key,
)
from src.sut.oauth_as.server import build_tls_context, serve_in_thread  # noqa: E402
from src.sut.oauth_as.tokens import (  # noqa: E402
    GRANT_TYPE_TOKEN_EXCHANGE,
    TOKEN_TYPE_ACCESS_TOKEN,
    TOKEN_TYPE_JWT,
)

BANNER = SPIKE_LOCAL_BANNER

SEED = bytes.fromhex("a1" * 32)  # SPIKE-LOCAL campaign seed
ISSUER = "https://as.aasc.local"
RESOURCE_SERVER = "https://mcp.aasc.local/tools"
OTHER_RESOURCE_SERVER = "https://other.aasc.local/tools"
RAR_TYPE = "https://aasc.gla.ac.uk/rar/tool-authority"  # SS 2.1 collision-resistant namespace
RESOURCE_URL = "https://mcp.aasc.local/tools/invoke"  # a protected-resource URL, for DPoP

SUPERVISOR = "agent-supervisor"
SPECIALIST = "agent-specialist"
WORKER = "agent-worker"  # a third hop, so a nested `act` chain exists to inspect
UNMAPPED = "agent-unmapped"  # deliberately absent from the registry (C3 requires it)

USER = "user-yixian"
SCOPE_FULL = "mcp.invoke mcp.read"
SCOPE_NARROW = "mcp.invoke"


def omega() -> frozenset[tuple[str, str]]:
    """The **frozen** ontology, read by the runner and handed to the AS as data."""
    return frozen_config.omega(frozen_config.load_document())


def rar(actions: list[str], datatypes: list[str], location: str = RESOURCE_SERVER) -> dict:
    return {
        "type": RAR_TYPE,
        "locations": [location],
        "actions": actions,
        "datatypes": datatypes,
    }


# The golden thread of ADR 0016 SS 1, expressed over the frozen Omega. Each
# object is split so that every expanded (action, resource) pair is an Omega
# element -- RFC 9396 SS 2 explicitly allows several entries of one type.
C0_DETAILS = [
    rar(["calendar.read"], ["calendar/work"]),
    rar(["notes.read"], ["notes/project", "notes/meeting"]),
    rar(["notes.write"], ["notes/project"]),
    rar(["mail.send"], ["mail/outbox"]),
]
C1_DETAILS = [
    rar(["notes.read"], ["notes/project", "notes/meeting"]),
    rar(["notes.write"], ["notes/project"]),
]
# In Omega, outside C_0 -- the amplification target.
OUTSIDE_C0 = rar(["notes.delete"], ["notes/project"])
# In Omega, outside C_0, on the calendar branch.
OUTSIDE_C0_CALENDAR = rar(["calendar.read"], ["calendar/personal"])


def build_registry() -> dict[str, RegistryEntry]:
    """C3 stand-in. `UNMAPPED` is deliberately absent so rejection is exercised."""
    return {
        SUPERVISOR: RegistryEntry(
            principal="supervisor",
            identity_jwk=derive_identity_key(SEED, "supervisor").public_jwk,
            holder_jwk=derive_identity_key(SEED, "holder-supervisor").public_jwk,
        ),
        SPECIALIST: RegistryEntry(
            principal="specialist",
            identity_jwk=derive_identity_key(SEED, "specialist").public_jwk,
            holder_jwk=derive_identity_key(SEED, "holder-specialist").public_jwk,
        ),
        WORKER: RegistryEntry(
            principal="worker",
            identity_jwk=derive_identity_key(SEED, "worker").public_jwk,
            holder_jwk=derive_identity_key(SEED, "holder-worker").public_jwk,
        ),
    }


def build_config(token_endpoint: str = "", **overrides: Any) -> ASConfig:
    base = {
        "issuer": ISSUER,
        "token_endpoint": token_endpoint,
        "rar_type": RAR_TYPE,
        "omega": omega(),
        "resource_servers": frozenset({RESOURCE_SERVER}),
        "clients": {
            name: derive_client_secret(SEED, name) for name in (SUPERVISOR, SPECIALIST, WORKER)
        },
        "registry": build_registry(),
        # SPIKE-LOCAL may_act policy: supervisor -> specialist -> worker.
        "delegation_policy": {"supervisor": "specialist", "specialist": "worker"},
        "default_lifetime_seconds": 300,
    }
    base.update(overrides)
    return ASConfig(**base)


def actor_assertion(
    actor_id: str, *, audience: str = ISSUER, lifetime: int = 120, now: int | None = None
) -> str:
    """A delegate's actor assertion: a short JWT signed by its own identity key.

    `[DESIGN]` -- deliberately not described as an RFC 7523 assertion; DESIGN
    SS 1.7 records RFC 7523 as not read.
    """
    now = int(time.time()) if now is None else now
    principal = {SUPERVISOR: "supervisor", SPECIALIST: "specialist", WORKER: "worker"}.get(
        actor_id, actor_id
    )
    key = derive_identity_key(SEED, principal)
    return jwt.encode(
        {"alg": ALGS[0], "typ": "JWT"},
        {"sub": actor_id, "aud": audience, "iat": now, "exp": now + lifetime},
        key.private,
        algorithms=ALGS,
    )


@dataclass
class Campaign:
    """A running AS plus everything needed to drive it over the wire."""

    server: Any
    config: ASConfig
    signing_key: Any
    cert_pem: bytes
    endpoint: str

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def client_context(self) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_verify_locations(cadata=self.cert_pem.decode("ascii"))
        return context

    def connect(self) -> http.client.HTTPSConnection:
        """One keep-alive connection, reused across hops (DESIGN SS 8.2).

        Dials the literal loopback address rather than the name `localhost`:
        resolving the name tries `::1` first on a dual-stack host and waits for
        it to fail, which added most of a second to every exchange. The AS
        certificate carries a `127.0.0.1` IP SAN so verification still holds.
        """
        return http.client.HTTPSConnection(
            "127.0.0.1", self.server.port, context=self.client_context(), timeout=15
        )

    def post_token(
        self,
        form: dict[str, Any],
        *,
        client: str | None = SUPERVISOR,
        secret: str | None = None,
        connection: http.client.HTTPSConnection | None = None,
        dpop: str | list[str] | None = None,
        raw_body: str | None = None,
    ) -> tuple[int, dict, dict]:
        """POST the exchange. Returns (status, JSON body, response headers)."""
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if client is not None:
            secret = derive_client_secret(SEED, client) if secret is None else secret
            token = base64.b64encode(f"{client}:{secret}".encode()).decode("ascii")
            headers["Authorization"] = f"Basic {token}"
        own = connection is None
        connection = connection or self.connect()
        body = raw_body if raw_body is not None else urlencode(form, doseq=True)
        proofs = [dpop] if isinstance(dpop, str) else (dpop or [])
        try:
            connection.putrequest("POST", "/token")
            for name, value in headers.items():
                connection.putheader(name, value)
            for proof in proofs:
                connection.putheader("DPoP", proof)
            connection.putheader("Content-Length", str(len(body.encode())))
            connection.endheaders()
            connection.send(body.encode())
            response = connection.getresponse()
            payload = response.read()
            parsed = json.loads(payload) if payload else {}
            return response.status, parsed, dict(response.getheaders())
        finally:
            if own:
                connection.close()

    def exchange_form(
        self,
        subject_token: str,
        details: list[dict],
        *,
        actor: str = SPECIALIST,
        resource: str | list[str] = RESOURCE_SERVER,
        scope: str | None = SCOPE_NARROW,
        assertion: str | None = None,
        **extra: Any,
    ) -> dict[str, Any]:
        form: dict[str, Any] = {
            "grant_type": GRANT_TYPE_TOKEN_EXCHANGE,
            "subject_token": subject_token,
            "subject_token_type": TOKEN_TYPE_ACCESS_TOKEN,
            "actor_token": assertion if assertion is not None else actor_assertion(actor),
            "actor_token_type": TOKEN_TYPE_JWT,
            "resource": resource,
            "authorization_details": json.dumps(details),
        }
        if scope is not None:
            form["scope"] = scope
        form.update(extra)
        return form

    def issue_root(
        self,
        *,
        details: list[dict] | None = None,
        scope: str = SCOPE_FULL,
        lifetime: int = 600,
        client: str = SUPERVISOR,
        cnf_jkt: str | None = None,
    ):
        """`AT_0` on the provisioning path (DESIGN SS 5.1 / SS 8.2 last row)."""
        return issue_initial(
            config=self.config,
            signing_key=self.signing_key,
            subject=USER,
            client_id=client,
            audience=RESOURCE_SERVER,
            scope=scope,
            authorization_details=C0_DETAILS if details is None else details,
            lifetime_seconds=lifetime,
            cnf_jkt=cnf_jkt,
        )


def start(**overrides: Any) -> Campaign:
    """Start an AS on an ephemeral loopback port with TLS 1.3."""
    signing_key = derive_signing_key(SEED)
    tls_context, cert_pem = build_tls_context(derive_tls_key(SEED))
    config = build_config(**overrides)
    server, _ = serve_in_thread(config, signing_key, tls_context)
    endpoint = f"https://localhost:{server.port}/token"
    # The endpoint URL is only knowable after binding; DPoP `htu` must match it.
    config = build_config(token_endpoint=endpoint, **overrides)
    server.as_config = config
    return Campaign(
        server=server,
        config=config,
        signing_key=signing_key,
        cert_pem=cert_pem,
        endpoint=endpoint,
    )


def public_jwk() -> dict[str, str]:
    return derive_signing_key(SEED).public_jwk


def holder_key(actor_id: str) -> OKPKey:
    """The spike registry's holder key for an actor (SPIKE-LOCAL, not an HTC key)."""
    entry = build_registry()[actor_id]
    return OKPKey.import_key(dict(entry.holder_jwk))
