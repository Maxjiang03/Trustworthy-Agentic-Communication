"""Key material for the AS, derived in-process and never written to disk.

`smoke/g4/DESIGN.md` SS 5.4 and ADR 0015 rule 2: the Ed25519 signing key is
generated **inside the AS process** at start-up from the sealed per-principal
seed (ADR 0007's seed->keypair derivation), held only in that process's memory,
never written to disk and never exported. Only the **public** key leaves, and it
reaches the boundary and the harness verifier from sealed configuration rather
than over the wire -- the profile publishes no `jwks_uri` (SS 5.1).

Isolation therefore rests on two things together, and the report says so
plainly: the private key never leaving this process, and the **runner giving the
seed only to this process**. A principal holding the seed can derive the key by
construction; that is what "sealed" means operationally.

The derivation is HKDF-SHA256 over the seed with a per-purpose `info` label, so
one seed yields independent signing, TLS and client-secret material that cannot
be confused with one another. ADR 0007 seals "the derivation rule from seed to
keypair"; this module is that rule for the AS `[DESIGN]`.
"""

import hmac
from base64 import urlsafe_b64encode
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from joserfc.jwk import OKPKey

# RFC 9864 fully-specified JWS algorithm identifier for Ed25519, matching G-5 /
# ADR 0006. joserfc's default registry excludes it per RFC 8725 hygiene, so
# every call passes this explicit allowlist -- never a wildcard, never `none`.
ALG = "Ed25519"
ALGS = [ALG]

_INFO_SIGNING = b"AASC-G4-AS-SIGNING-KEY"
_INFO_TLS = b"AASC-G4-AS-TLS-KEY"
_INFO_CLIENT_SECRET = b"AASC-G4-CLIENT-SECRET"
_INFO_IDENTITY = b"AASC-G4-PRINCIPAL-IDENTITY-KEY"


def b64u(raw: bytes) -> str:
    return urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _derive(seed: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(seed)


@dataclass(frozen=True)
class SigningKey:
    """An Ed25519 keypair whose private half never leaves this object."""

    private: OKPKey
    public_jwk: dict[str, str]

    @property
    def public(self) -> OKPKey:
        return OKPKey.import_key(dict(self.public_jwk))

    def thumbprint(self) -> str:
        return self.public.thumbprint()


def _keypair_from_raw(raw_private: bytes) -> SigningKey:
    private = Ed25519PrivateKey.from_private_bytes(raw_private)
    raw_public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    public_jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64u(raw_public)}
    jwk = dict(public_jwk, d=b64u(raw_private))
    return SigningKey(private=OKPKey.import_key(jwk), public_jwk=public_jwk)


def derive_signing_key(seed: bytes) -> SigningKey:
    """The AS signing key. Called once at start-up (SS 8.2: parse once, reuse)."""
    return _keypair_from_raw(_derive(seed, _INFO_SIGNING))


def derive_identity_key(seed: bytes, principal: str) -> SigningKey:
    """A principal's Ed25519 identity key, used to sign its actor assertion.

    In the campaign each principal derives its own from its own sealed seed; the
    AS only ever holds the public half, through the registry.
    """
    return _keypair_from_raw(_derive(seed, _INFO_IDENTITY + b":" + principal.encode("ascii")))


def derive_tls_key(seed: bytes) -> Ed25519PrivateKey:
    """The loopback TLS key (SS 5.1). Distinct from the signing key by `info` label."""
    return Ed25519PrivateKey.from_private_bytes(_derive(seed, _INFO_TLS))


def derive_client_secret(seed: bytes, client_id: str) -> str:
    """Client secrets derived at run time from sealed seeds, never in the repository.

    SS 5.1 (`client_secret_basic`) and CLAUDE.md red line 8.
    """
    return b64u(_derive(seed, _INFO_CLIENT_SECRET + b":" + client_id.encode("ascii")))


def secrets_equal(left: str, right: str) -> bool:
    """Constant-time comparison for client-secret checking."""
    return hmac.compare_digest(left, right)
