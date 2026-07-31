"""The pilot seed -> keypair derivation rule (ADR 0007), held by the runner.

ADR 0007 seals *scenario specifications, deterministic key seeds, and the
derivation rule from seed to keypair*; tokens and keys are minted at run time
from those inputs. This module is that rule for the golden-thread pilot
corpus: HKDF-SHA256 over the corpus seed with a per-label `info` string,
mirroring the AS's in-process derivation (`src/sut/oauth_as/keys.py`) and the
G-11 fixture. The labels are the frozen registry's `key_reference` values
(ADR 0019: the artifact fixes derivation labels, never key bytes), so binding
the registry with `resolve_public` yields exactly the keys this rule derives.

Seed-disclosure warning (ADR 0007, binding): publishing a corpus seed
publishes every private key derived from it. Pilot corpus keys are testbed
artifacts only and MUST NOT be reused in any deployment.

Trust rule: this module is HARNESS-side. SUT principals never read a seed or
a fixture file; the runner derives key objects here and injects each
principal's own material as start-up configuration (the pattern
`src/harness/verifier/registry.bind` fixes for public keys).
"""

from base64 import urlsafe_b64encode
from collections.abc import Iterable

from biscuit_auth import Algorithm, KeyPair, PrivateKey, PublicKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# The pilot derivation rule's domain prefix. Recorded in the corpus document
# for provenance; the loader asserts the recorded value matches this constant
# so the rule cannot silently drift from what the corpus declares.
DERIVATION_INFO_PREFIX = b"AASC-EXP1-PILOT-KEY:"


def derive_raw(seed: bytes, label: str) -> bytes:
    """32 bytes of key material for one derivation label."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=DERIVATION_INFO_PREFIX + label.encode("ascii"),
    ).derive(seed)


def biscuit_root(seed: bytes, label: str = "kappa") -> tuple[PrivateKey, PublicKey]:
    """`kappa` as a Biscuit keypair (mint + verify)."""
    private = PrivateKey.from_bytes(derive_raw(seed, label), Algorithm.Ed25519)
    return private, KeyPair.from_private_key(private).public_key


def root_signing_key(seed: bytes, label: str = "kappa") -> Ed25519PrivateKey:
    """`kappa` as a `cryptography` key, for signing `HTC_0` (SS F.2).

    The same 32 raw bytes back both objects, so the Biscuit root and the
    HTC_0 signer are one key -- exactly the SS F.2 template (`Sign_kappa`).
    """
    return Ed25519PrivateKey.from_private_bytes(derive_raw(seed, label))


def holder_private(seed: bytes, label: str) -> Ed25519PrivateKey:
    """A holder identity key named by a registry `key_reference` label."""
    return Ed25519PrivateKey.from_private_bytes(derive_raw(seed, label))


def public_wire(private: Ed25519PrivateKey) -> str:
    """base64url unpadded raw Ed25519 public key (the registry wire encoding)."""
    raw = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def resolve_public(seed: bytes) -> "dict[str, str]":
    """label -> public key wire form, for `registry.bind` (ADR 0019).

    Deliberately eager and total over the labels the frozen registry names, so
    an unknown label is a KeyError at bind time rather than a silent default.
    """
    labels = ("kappa", "holder-supervisor", "holder-specialist", "holder-worker")
    return {label: public_wire(holder_private(seed, label)) for label in labels}


# ---------------------------------------------------------------------------
# Identity-plane keys: the principal's own key, which signs its RFC 8693
# actor assertion. Distinct from `holder-*` by derivation label, because
# `smoke/g4/DESIGN.md` SS 7.3 warns the two must never be conflated.
# ---------------------------------------------------------------------------
_IDENTITY_PREFIX = "identity-"


def identity_private(seed: bytes, principal: str) -> Ed25519PrivateKey:
    """A principal's identity key, under this corpus's derivation rule."""
    return holder_private(seed, f"{_IDENTITY_PREFIX}{principal}")


def identity_public_jwk(seed: bytes, principal: str) -> "dict[str, str]":
    """The public half, as the AS's registry carries it."""
    return {"kty": "OKP", "crv": "Ed25519", "x": public_wire(identity_private(seed, principal))}


def identity_jwks(seed: bytes, principals: Iterable[str]) -> "dict[str, dict[str, str]]":
    """principal -> public identity JWK, as the AS registry carries them.

    One construction site for the derivation label, so the AS's registry and
    the arm that signs an actor assertion cannot drift apart by a typo.
    """
    return {principal: identity_public_jwk(seed, principal) for principal in principals}


def identity_private_jwk(seed: bytes, principal: str) -> "dict[str, str]":
    """The private half, injected into the arm that must sign an actor assertion.

    Runtime-only, runner-held, in memory: like every other value this module
    derives, it MUST never be written to disk, committed, or echoed into
    `results/` (CLAUDE.md red line 8, ADR 0021 rule 2).
    """
    private = identity_private(seed, principal)
    raw = private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    return dict(
        identity_public_jwk(seed, principal),
        d=urlsafe_b64encode(raw).rstrip(b"=").decode("ascii"),
    )


# ---------------------------------------------------------------------------
# The AS's own derivations, MIRRORED rather than imported.
#
# `src/harness/` may never import `src/sut/oauth_as/` (ADR 0015 rule 4), and
# `B2-exchange-task` needs the client secret the AS derives in-process. So the
# rule is reimplemented here from the AS's DOCUMENTED derivation, exactly as
# this module already mirrors the corpus-label rule -- agreement is required,
# shared code is not, and a test drives a real exchange to prove the two ends
# accept each other. If the AS's `info` label ever changes, that test fails
# rather than the arm silently losing its ability to authenticate.
# ---------------------------------------------------------------------------
AS_CLIENT_SECRET_INFO = b"AASC-G4-CLIENT-SECRET"


def as_client_secret(seed: bytes, client_id: str) -> str:
    """Mirror of `src/sut/oauth_as/keys.derive_client_secret` (not an import)."""
    raw = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=AS_CLIENT_SECRET_INFO + b":" + client_id.encode("ascii"),
    ).derive(seed)
    return urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
