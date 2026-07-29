"""DPoP proof handling shared by the AS token endpoint and the MCP boundary.

RFC 9449, re-read in AS/RS context at G-4 Phase 1 (`smoke/g4/DESIGN.md` SS 1.4).
G-5 verified the JOSE surface with a **simulated** mint; this module is the
first place the proofs are validated in a real AS/RS flow, which is what
DESIGN SS 10 rows A5, A6 and A7 exercise.

It lives beside the AS rather than inside it, because both the AS and the
resource-server side need it and **no `src/sut/` module other than
`src/sut/oauth_as/` may import `src/sut/oauth_as/`** (ADR 0015 rule 3). Nothing
here touches an AS signing key: a DPoP proof is signed by the *client's* key and
verified with the public key embedded in its own header, so sharing this code
grants no ability to mint an access token.

Checks are numbered as in RFC 9449 SS 4.3. Items 1-11 apply at the token
endpoint; **item 12** (`ath` equals the hash of *that* access token, and the
token's bound key matches the proof key) applies only at a protected resource
[VERIFIED, RFC 9449 SS 4.3, SS 7.1].
"""

import hashlib
import json
import secrets
import time
from base64 import urlsafe_b64encode
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

from joserfc import jws
from joserfc.errors import JoseError
from joserfc.jwk import OKPKey

ALGS = ["Ed25519"]  # RFC 9864 identifier; ADR 0006 allowlist, never `none`
DPOP_TYP = "dpop+jwt"  # RFC 9449 SS 4.2
IAT_WINDOW_SECONDS = 300  # SS 4.3 item 11: "within an acceptable timeframe"

_REQUIRED_CLAIMS = ("jti", "htm", "htu", "iat")  # SS 4.2


class DPoPError(Exception):
    """A proof failed one of the RFC 9449 SS 4.3 checks. Carries the item number."""

    def __init__(self, item: int, description: str) -> None:
        super().__init__(f"item {item}: {description}")
        self.item = item
        self.description = description


def b64u(raw: bytes) -> str:
    return urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def access_token_hash(token: str) -> str:
    """`ath` = base64url(SHA-256(ASCII(access token))) [VERIFIED, RFC 9449 SS 4.2].

    Deliberately **not** `H_JCS`: that is defined over the RFC 8785 canonical
    bytes of a JSON object and renders lowercase hex (ADR 0009). Different
    domain, different encoding, different purpose -- DESIGN SS 9 C2 names the
    conflation as a trap. Two digests over the same token must never be merged.
    """
    return b64u(hashlib.sha256(token.encode("ascii")).digest())


def normalize_htu(url: str) -> str:
    """RFC 3986 syntax-based normalization, then drop query and fragment.

    RFC 9449 SS 4.3 item 9: `htu` is the request URI "without query and fragment
    parts", and servers SHOULD apply scheme- and syntax-based normalization
    before comparing. Closes the G-5 residual (DESIGN SS 10 row A7).
    """
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = parts.hostname.lower() if parts.hostname else ""
    port = parts.port
    default_port = {"http": 80, "https": 443}.get(scheme)
    netloc = host if port is None or port == default_port else f"{host}:{port}"
    path = _remove_dot_segments(parts.path) or "/"
    return urlunsplit((scheme, netloc, path, "", ""))


def _remove_dot_segments(path: str) -> str:
    """RFC 3986 SS 5.2.4."""
    out: list[str] = []
    for segment in path.split("/"):
        if segment == ".":
            continue
        if segment == "..":
            if out and out[-1] != "":
                out.pop()
            continue
        out.append(segment)
    return "/".join(out)


@dataclass
class NonceStore:
    """Server-provided DPoP nonces (RFC 9449 SS 8 at the AS, SS 9 at the RS).

    AS and RS nonces are **distinct namespaces** and each is only accepted by
    its issuer [VERIFIED, RFC 9449 SS 9]. Enforced two ways at once: separate
    store instances, and a namespace tag inside the nonce value, so a nonce
    lifted from one server is rejected by the other even if the stores were
    merged by mistake.
    """

    namespace: str
    _issued: set[str] = field(default_factory=set)

    def issue(self) -> str:
        """Unpredictable (SS 8: "MUST be unpredictable")."""
        nonce = f"{self.namespace}.{secrets.token_urlsafe(24)}"
        self._issued.add(nonce)
        return nonce

    def is_valid(self, nonce: str | None) -> bool:
        return bool(nonce) and nonce in self._issued

    def retire(self, nonce: str) -> None:
        """Make a previously issued nonce stale, for the stale-nonce test."""
        self._issued.discard(nonce)


@dataclass(frozen=True)
class ProofResult:
    """A validated proof: its public key, thumbprint, and claims."""

    key: OKPKey
    jkt: str
    claims: dict


def create_proof(
    key: OKPKey,
    *,
    method: str,
    url: str,
    nonce: str | None = None,
    ath: str | None = None,
    iat: int | None = None,
    typ: str = DPOP_TYP,
) -> str:
    """Build a DPoP proof (client side; used by the spike and the tests)."""
    header = {"typ": typ, "alg": ALGS[0], "jwk": key.as_dict(private=False)}
    claims = {
        "jti": secrets.token_urlsafe(16),
        "htm": method,
        "htu": normalize_htu(url),
        "iat": int(time.time()) if iat is None else iat,
    }
    if nonce is not None:
        claims["nonce"] = nonce
    if ath is not None:
        claims["ath"] = ath
    return jws.serialize_compact(header, json.dumps(claims).encode(), key, algorithms=ALGS)


def verify_proof(
    proof_headers: list[str],
    *,
    method: str,
    url: str,
    now: int | None = None,
    nonce_store: NonceStore | None = None,
    nonce_required: bool = False,
    access_token: str | None = None,
    bound_jkt: str | None = None,
) -> ProofResult:
    """RFC 9449 SS 4.3 items 1-11, plus item 12 when `access_token` is given.

    Raises `DPoPError` naming the item that failed, so a test can assert which
    check refused rather than merely that something did.
    """
    now = int(time.time()) if now is None else now

    if len(proof_headers) != 1:  # item 1
        raise DPoPError(1, f"expected exactly one DPoP header, got {len(proof_headers)}")
    proof = proof_headers[0]

    try:  # item 2
        obj = jws.extract_compact(proof.encode())
    except (JoseError, ValueError) as exc:
        raise DPoPError(2, f"not a well-formed JWT: {type(exc).__name__}") from exc

    header = obj.headers()
    if header.get("typ") != DPOP_TYP:  # item 4
        raise DPoPError(4, f"typ is {header.get('typ')!r}, expected {DPOP_TYP!r}")
    if header.get("alg") not in ALGS:  # item 5
        raise DPoPError(5, f"alg {header.get('alg')!r} is not an allowed asymmetric algorithm")
    jwk_dict = header.get("jwk")
    if not isinstance(jwk_dict, dict):
        raise DPoPError(2, "header has no embedded jwk")
    if "d" in jwk_dict:  # item 7
        raise DPoPError(7, "embedded jwk contains a private key")

    try:  # item 6
        embedded = OKPKey.import_key(jwk_dict)
        jws.deserialize_compact(proof, embedded, algorithms=ALGS)
    except (JoseError, ValueError) as exc:
        raise DPoPError(6, f"signature does not verify: {type(exc).__name__}") from exc

    claims = json.loads(obj.payload)
    missing = [name for name in _REQUIRED_CLAIMS if name not in claims]
    if missing:  # item 3
        raise DPoPError(3, f"missing required claim(s): {missing}")

    if claims["htm"] != method:  # item 8
        raise DPoPError(8, f"htm {claims['htm']!r} does not match {method!r}")
    if normalize_htu(claims["htu"]) != normalize_htu(url):  # item 9
        raise DPoPError(9, f"htu {claims['htu']!r} does not match {url!r}")

    if nonce_required or "nonce" in claims:  # item 10
        if nonce_store is None or not nonce_store.is_valid(claims.get("nonce")):
            raise DPoPError(10, "nonce is missing, stale, or from another server's namespace")

    if not isinstance(claims["iat"], int) or abs(now - claims["iat"]) > IAT_WINDOW_SECONDS:
        raise DPoPError(11, "iat is outside the acceptable window")  # item 11

    if access_token is not None:  # item 12 -- protected resource only
        if "ath" not in claims:
            raise DPoPError(12, "ath is required when a proof accompanies an access token")
        if claims["ath"] != access_token_hash(access_token):
            raise DPoPError(12, "ath does not match the presented access token")
        if bound_jkt is not None and bound_jkt != embedded.thumbprint():
            raise DPoPError(12, "the access token is bound to a different key than the proof")

    return ProofResult(key=embedded, jkt=embedded.thumbprint(), claims=claims)
