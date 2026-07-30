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
