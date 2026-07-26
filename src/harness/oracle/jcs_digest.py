"""Oracle-side frozen H_JCS digest over RFC 8785 canonical bytes.

ADR 0009. H_JCS is the digest named by SS F.2 (INV.canonical_request_digest =
H_JCS(raw_arguments)) and Part I (oracle_digest = H_JCS(obs.raw_arguments)):
SHA-256 over a versioned, domain-separated, length-delimited encoding of the
RFC 8785 canonical bytes, rendered as lowercase hexadecimal. Deliberately the
same construction family as the capability commitment (commitment.py,
ADR 0003) so the two can never be confused with each other or with a bare
digest; the domain tag is distinct, and there is no algorithm byte because
H_JCS has no algorithm registry (the hash is fixed by the version).

Byte layout (must reproduce byte-for-byte in any independent implementation):

    C      = RFC 8785 canonical UTF-8 bytes of the arguments object
             (rfc8785==0.1.4, ADR 0005)
    H_JCS  = lowercase_hex( SHA-256( TAG || VERSION || u32be(len(C)) || C ) )

Trust rule (D21, CLAUDE.md red line 4): this module is ORACLE-side. The
SUT-side computation must be written independently later; the oracle never
consumes a SUT-computed digest. Everything fails closed: an unsupported
version raises, and out-of-model input propagates the pinned library's typed
CanonicalizationError (NaN/Infinity, lone surrogates, non-string keys,
|int| >= 2^53, non-JSON types) - never swallowed, never coerced.
"""

import hashlib

import rfc8785

TAG = b"AASC-JCS-DIGEST"  # fixed ASCII domain-separation tag; != AASC-CAP-COMMIT
VERSION = 0x01  # any other value fails closed


class JcsDigestError(Exception):
    """Base: the H_JCS layer failed closed."""


class UnsupportedVersionError(JcsDigestError):
    """H_JCS version other than VERSION."""


def canonicalize(obj: object) -> bytes:
    """RFC 8785 canonical UTF-8 bytes of obj via the pinned library (ADR 0005).

    Out-of-model input raises rfc8785.CanonicalizationError (typed; the
    Float/IntegerDomainError subclasses included) - propagated, fail closed.
    """
    return rfc8785.dumps(obj)


def h_jcs(obj: object, *, version: int = 1) -> str:
    """Frozen H_JCS of obj (ADR 0009): lowercase-hex SHA-256 over
    TAG || version || u32be(len(C)) || C, with C = canonicalize(obj).

    Raises UnsupportedVersionError on any version other than VERSION;
    propagates canonicalization errors unchanged.
    """
    if version != VERSION:
        raise UnsupportedVersionError(f"unsupported H_JCS version {version}")
    canonical = canonicalize(obj)
    digest = hashlib.sha256()
    digest.update(TAG)
    digest.update(bytes([version]))
    digest.update(len(canonical).to_bytes(4, "big"))
    digest.update(canonical)
    return digest.hexdigest()
