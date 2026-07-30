"""`INV.access_token_hash` -- the frozen digest binding the presented OAuth token.

ADR 0018, adjudicating `smoke/g4/DESIGN.md` SS 9 C2 and closing ADR 0009's
category (c) for this field. SS F.2 gives the field as `H(AT@aud)` and fixes no
construction; this is that construction.

    t                  = the access token exactly as presented at the boundary,
                         its compact serialization, ASCII bytes
    access_token_hash  = lowercase_hex( SHA-256( TAG || 0x01 || u32be(len(t)) || t ) )

Same tagged, versioned, length-delimited family as ADR 0003 `commitment.py`,
ADR 0009 `jcs_digest.py` and ADR 0016 `frozen_config.py`, with its **own** domain
tag and no algorithm byte (a hash change is a new VERSION, not a parameter), and
fail-closed on an unsupported version.

**Three digests over the same token, deliberately mutually distinct.** SS 9 C2
named this trap and it is real:

| Digest | Over | Rendering |
|---|---|---|
| `ath` (RFC 9449 SS 4.2) | ASCII **token string** | base64url, unpadded |
| `H_JCS` (ADR 0009) | canonical bytes of a **JSON object** | lowercase hex |
| `access_token_hash` (here) | ASCII **token string** | lowercase hex |

`ath` and this construction take the same input bytes, so **only the domain tag
and the output encoding keep them apart** -- which is exactly why the tag is
load-bearing rather than decorative, and why a test asserts all three differ.

**Non-ASCII input fails closed.** A JWS compact serialization is base64url
characters and dots by construction, so any byte outside ASCII means the input is
not a well-formed presented token. It is refused rather than encoded as UTF-8,
which would silently admit two different byte strings to one digest.

Trust rule (D21): this module is instrument-side. The B3 arm's INV signer must
compute the same value with an **independent** implementation, and the verifier
never consumes a SUT-computed digest -- it recomputes from the presented token.
"""

import hashlib

TAG = b"AASC-AT-DIGEST"  # 14 bytes; distinct from every tag in use
VERSION = 0x01  # any other value fails closed

# Tags already in use, kept here so a future addition collides visibly.
_TAGS_IN_USE = (
    b"AASC-CAP-COMMIT",  # ADR 0003, capability commitment
    b"AASC-JCS-DIGEST",  # ADR 0009, H_JCS
    b"AASC-GAMMA-DIGEST",  # ADR 0016, H(Gamma)
    b"AASC-HTC-v1",  # SS F.2, HTC signature domain
    b"AASC-INV-v1",  # SS F.2, INV signature domain
    b"AASC-REGISTRY-DIGEST",  # ADR 0019, H(R)
    b"AASC-POLICY-DIGEST",  # ADR 0022, H(Lambda) -- frozen rows 4/6/10
)
assert TAG not in _TAGS_IN_USE, "access_token_hash tag must be unique"
# Pairwise distinctness across the whole family, not merely against this tag:
# a new construction that collided with any tag in service would silently let
# one digest be reinterpreted as another.
assert len(set(_TAGS_IN_USE + (TAG,))) == len(_TAGS_IN_USE) + 1, "domain tags must be distinct"


class AccessTokenDigestError(Exception):
    """Base: the access-token digest layer failed closed."""


class UnsupportedVersionError(AccessTokenDigestError):
    """A version other than VERSION was requested."""


class NonAsciiTokenError(AccessTokenDigestError):
    """The presented token is not ASCII, so it is not a compact serialization."""


def access_token_hash(token: str | bytes, *, version: int = 1) -> str:
    """`H(AT@aud)` per ADR 0018. Fails closed on an unsupported version or non-ASCII input."""
    if version != VERSION:
        raise UnsupportedVersionError(f"unsupported access_token_hash version {version}")
    if isinstance(token, str):
        try:
            raw = token.encode("ascii")
        except UnicodeEncodeError as exc:
            raise NonAsciiTokenError(
                "the presented access token contains non-ASCII characters"
            ) from exc
    else:
        raw = bytes(token)
        if any(byte > 0x7F for byte in raw):
            raise NonAsciiTokenError("the presented access token contains non-ASCII bytes")
    digest = hashlib.sha256()
    digest.update(TAG)
    digest.update(bytes([version]))
    digest.update(len(raw).to_bytes(4, "big"))
    digest.update(raw)
    return digest.hexdigest()
