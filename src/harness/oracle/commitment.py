"""Oracle-side capability commitment over signature-derived block identifiers.

ADR 0003. Replaces the raw-container-byte `H(P_i)` of ADR 0002, which was
unsound: protobuf is NOT a canonical encoding, so a semantically equivalent
re-encoding changes raw bytes and would falsely reject a legitimate request.
Commitments here bind the ordered block sequence, not an encoding.

`BlockID_i` is block `i`'s signature — the Biscuit *revocation identifier*
[VERIFIED: Biscuit SPECIFICATIONS.md, "Revocation identifiers": "The
revocation identifier for a block is its signature"]. Under signature payload
v0 the signature covers the block's serialized Datalog, the carried next
public key, and its algorithm; chain position is enforced by signature-chain
verification (block i's signature must verify under the key carried in block
i-1), which this module performs before extracting any identifier.

Trust rule (D21, CLAUDE.md red line 4): every function here starts from RAW
token bytes plus the root public key and recomputes everything itself. None
accepts a parsed object, a digest, or any value computed by a system under
test. Everything fails closed.
"""

import hashlib

from biscuit_auth import Biscuit, PublicKey

TAG = b"AASC-CAP-COMMIT"  # fixed ASCII domain-separation tag
VERSION = 0x01  # any other value fails closed
ALG_ED25519 = 0x01  # commitment alg registry: 0x01 = Ed25519 only

_ED25519_PUBKEY_LEN = 32  # raw Ed25519 public key; SEC1-compressed P-256 is 33
_ED25519_SIG_LEN = 64
_WIRE_ALG_ED25519 = 0  # schema.proto: PublicKey.Algorithm.Ed25519 = 0

# Biscuit container, top level [VERIFIED against schema.proto]:
#   Biscuit { rootKeyId=1; authority=2 (SignedBlock); blocks=3 (repeated); proof=4 }
#   SignedBlock { block=1; nextKey=2 (PublicKey); signature=3; externalSignature=4; version=5 }
#   PublicKey { algorithm=1; key=2 }
_FIELD_AUTHORITY = 2
_FIELD_BLOCKS = 3
_SB_NEXTKEY = 2
_SB_SIGNATURE = 3
_SB_EXTERNAL_SIG = 4
_PK_ALGORITHM = 1


class CommitmentError(Exception):
    """Base: the commitment layer failed closed."""


class UnsupportedVersionError(CommitmentError):
    """Commitment version other than VERSION."""


class UnsupportedAlgorithmError(CommitmentError):
    """Key or commitment algorithm other than Ed25519 (design mandate D8)."""


class TokenStructureError(CommitmentError):
    """Container structure inconsistent with the verified chain."""


class CoverageError(CommitmentError):
    """HTC count does not cover every presented signed block."""


def _read_varint(buf: bytes, i: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        if i >= len(buf):
            raise TokenStructureError("truncated varint")
        byte = buf[i]
        i += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, i


def _wire_fields(buf: bytes) -> list[tuple[int, object]]:
    """Split one protobuf message into (field_no, payload) pairs, fail-closed."""
    i, out = 0, []
    while i < len(buf):
        tag, i = _read_varint(buf, i)
        field_no, wire_type = tag >> 3, tag & 7
        if wire_type == 2:
            length, i = _read_varint(buf, i)
            if i + length > len(buf):
                raise TokenStructureError("length-delimited field overruns buffer")
            out.append((field_no, buf[i : i + length]))
            i += length
        elif wire_type == 0:
            value, i = _read_varint(buf, i)
            out.append((field_no, value))
        else:
            raise TokenStructureError(f"unexpected wire type {wire_type} for field {field_no}")
    return out


def _reject_non_ed25519(token_bytes: bytes, root_pub: PublicKey) -> None:
    """Fail closed on any non-Ed25519 key in the chain (design mandate D8).

    The root key algorithm is discriminated by serialized length (raw Ed25519
    keys are 32 bytes; SEC1-compressed P-256 keys are 33). Every carried
    nextKey's algorithm enum is read from the wire and must be Ed25519 (0).
    """
    if len(bytes(root_pub.to_bytes())) != _ED25519_PUBKEY_LEN:
        raise UnsupportedAlgorithmError("root public key is not Ed25519; failing closed")
    for field_no, payload in _wire_fields(token_bytes):
        if field_no in (_FIELD_AUTHORITY, _FIELD_BLOCKS):
            if not isinstance(payload, bytes):
                raise TokenStructureError("signed block field is not length-delimited")
            sub = _wire_fields(payload)
            if any(f == _SB_EXTERNAL_SIG for f, _ in sub):
                # Third-party blocks are out of the MSc profile (SS A.6.1).
                raise TokenStructureError("external (third-party) signature present")
            for f, value in sub:
                if f == _SB_NEXTKEY:
                    if not isinstance(value, bytes):
                        raise TokenStructureError("nextKey field is not length-delimited")
                    algs = [v for pf, v in _wire_fields(value) if pf == _PK_ALGORITHM]
                    if any(a != _WIRE_ALG_ED25519 for a in algs):
                        raise UnsupportedAlgorithmError(
                            "non-Ed25519 next key in chain; failing closed"
                        )


def block_ids_from_raw(token_bytes: bytes, root_pub: PublicKey) -> list[bytes]:
    """Independently verify the chain against root_pub, then extract ordered BlockIDs.

    Raises on any verification failure. NEVER trusts a caller-supplied parse
    or digest: verification and extraction both start from the raw bytes.
    """
    if not isinstance(token_bytes, (bytes, bytearray)):
        raise TokenStructureError("token must be raw bytes")
    token_bytes = bytes(token_bytes)
    _reject_non_ed25519(token_bytes, root_pub)

    # Independent chain verification; BiscuitValidationError propagates (fail closed).
    verified = Biscuit.from_bytes(token_bytes, root_pub)

    block_ids = [bytes.fromhex(rid) for rid in verified.revocation_ids]

    wire_block_count = sum(
        1 for f, _ in _wire_fields(token_bytes) if f in (_FIELD_AUTHORITY, _FIELD_BLOCKS)
    )
    if len(block_ids) != verified.block_count() or len(block_ids) != wire_block_count:
        raise TokenStructureError(
            f"identifier/block count mismatch: {len(block_ids)} revocation ids, "
            f"{verified.block_count()} verified blocks, {wire_block_count} wire blocks"
        )
    if any(len(bid) != _ED25519_SIG_LEN for bid in block_ids):
        raise UnsupportedAlgorithmError("block identifier is not an Ed25519 signature")
    return block_ids


def commit_ids(block_ids: list[bytes], *, version: int = 1, alg: int = 1) -> bytes:
    """Commitment over an exact BlockID sequence (versioned, domain-separated,
    length-delimited). Raises on unsupported version or alg."""
    if version != VERSION:
        raise UnsupportedVersionError(f"unsupported commitment version {version}")
    if alg != ALG_ED25519:
        raise UnsupportedAlgorithmError(f"unsupported commitment algorithm {alg}")
    digest = hashlib.sha256()
    digest.update(TAG)
    digest.update(bytes([version]))
    digest.update(bytes([alg]))
    digest.update(len(block_ids).to_bytes(4, "big"))
    for block_id in block_ids:
        digest.update(len(block_id).to_bytes(4, "big"))
        digest.update(block_id)
    return digest.digest()


def commit_prefix(block_ids: list[bytes], upto: int, *, version: int = 1, alg: int = 1) -> bytes:
    """Commitment over BlockID_0..BlockID_upto (inclusive)."""
    if not 0 <= upto < len(block_ids):
        raise CommitmentError(f"prefix index {upto} out of range for {len(block_ids)} blocks")
    return commit_ids(block_ids[: upto + 1], version=version, alg=alg)


def capability_commitment(token_bytes: bytes, root_pub: PublicKey) -> bytes:
    """Terminal commitment over all BlockIDs. This is H(P_n) (SS A.0.1, ADR 0003)."""
    block_ids = block_ids_from_raw(token_bytes, root_pub)
    return commit_prefix(block_ids, len(block_ids) - 1)


def check_htc_coverage(block_ids: list[bytes], htc_count: int) -> None:
    """Fail closed unless htc_count == len(block_ids).

    Count check only — this function does NOT sign or verify HTCs (that is
    gate G-11 territory); it guarantees no presented block lacks a covering
    HTC entry (SS F.2 count conjunct).
    """
    if htc_count != len(block_ids):
        raise CoverageError(
            f"HTC coverage mismatch: {htc_count} HTC entries for {len(block_ids)} signed blocks"
        )
