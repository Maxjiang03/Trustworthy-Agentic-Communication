"""SUT-side digest constructions, written from the ADRs (D21: a second implementation).

This module is the B3 arm's own implementation of the three frozen digest
layouts, written **from the ADR texts** -- ADR 0003 (SS A.0.1 capability
commitment), ADR 0009 (`H_JCS`), ADR 0018 (`access_token_hash`) -- and
deliberately **not** from `src/harness/` source, which it must never import
(red line 6; EXP1 forbidden action 7). Agreement with the harness is a
*verified property* (the harness-side agreement suite compares byte-for-byte
on known vectors), never a shared code path: that is what lets gate G-13
treat the two sides as independent witnesses.

The three layouts, as the ADRs fix them (every one versioned, domain-tagged,
length-delimited, fail-closed on an unsupported version):

    commit_prefix (ADR 0003; SS A.0.1)
        SHA-256( "AASC-CAP-COMMIT" || 0x01 || 0x01(alg=Ed25519)
                 || u32be(count) || ( u32be(len(id)) || id )* )
        over the ordered BlockID sequence; BlockID_i is block i's signature
        (the Biscuit revocation identifier).

    H_JCS (ADR 0009)
        lowercase_hex( SHA-256( "AASC-JCS-DIGEST" || 0x01
                                || u32be(len(C)) || C ) )
        with C the RFC 8785 canonical UTF-8 bytes; no algorithm byte.

    access_token_hash (ADR 0018)
        lowercase_hex( SHA-256( "AASC-AT-DIGEST" || 0x01
                                || u32be(len(t)) || t ) )
        with t the presented token's ASCII bytes; non-ASCII fails closed.
"""

import hashlib

import rfc8785

CAP_COMMIT_TAG = b"AASC-CAP-COMMIT"
JCS_TAG = b"AASC-JCS-DIGEST"
AT_TAG = b"AASC-AT-DIGEST"
VERSION = 0x01
ALG_ED25519 = 0x01


class SutDigestError(Exception):
    """Base: the SUT-side digest layer failed closed."""


def commit_ids(block_ids: list[bytes], *, version: int = 1, alg: int = 1) -> bytes:
    """ADR 0003 commitment over an ordered BlockID sequence."""
    if version != VERSION:
        raise SutDigestError(f"unsupported commitment version {version}")
    if alg != ALG_ED25519:
        raise SutDigestError(f"unsupported commitment algorithm {alg}")
    material = CAP_COMMIT_TAG + bytes([version, alg]) + len(block_ids).to_bytes(4, "big")
    for block_id in block_ids:
        material += len(block_id).to_bytes(4, "big") + block_id
    return hashlib.sha256(material).digest()


def commit_prefix(block_ids: list[bytes], upto: int) -> bytes:
    """Commitment over `BlockID_0..BlockID_upto` inclusive (SS A.0.1)."""
    if not 0 <= upto < len(block_ids):
        raise SutDigestError(f"prefix index {upto} out of range for {len(block_ids)} ids")
    return commit_ids(list(block_ids[: upto + 1]))


def h_jcs(obj: object, *, version: int = 1) -> str:
    """ADR 0009 `H_JCS`: canonicalization errors propagate (fail closed)."""
    if version != VERSION:
        raise SutDigestError(f"unsupported H_JCS version {version}")
    canonical = rfc8785.dumps(obj)
    material = JCS_TAG + bytes([version]) + len(canonical).to_bytes(4, "big") + canonical
    return hashlib.sha256(material).hexdigest()


def access_token_hash(token: str, *, version: int = 1) -> str:
    """ADR 0018 `H(AT@aud)` over the token exactly as presented."""
    if version != VERSION:
        raise SutDigestError(f"unsupported access_token_hash version {version}")
    try:
        raw = token.encode("ascii")
    except UnicodeEncodeError as exc:
        raise SutDigestError("a presented access token must be ASCII") from exc
    material = AT_TAG + bytes([version]) + len(raw).to_bytes(4, "big") + raw
    return hashlib.sha256(material).hexdigest()
