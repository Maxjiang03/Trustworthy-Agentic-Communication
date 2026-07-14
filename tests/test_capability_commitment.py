"""Regression suite for the ADR 0003 capability commitment (gate G-1 corrective).

Every test has a positive arm and a negative arm so no assertion can pass
vacuously. The wire re-encoders below are deliberately test-local and
independent of src/harness/oracle/commitment.py: they simulate a component
elsewhere in the path that re-emits the container.

Pilot vocabulary only — NOT the frozen ontology Omega.
"""

import subprocess
import sys
from hashlib import sha256
from pathlib import Path

import pytest
from biscuit_auth import (
    Biscuit,
    BiscuitBuilder,
    BiscuitValidationError,
    BlockBuilder,
    KeyPair,
    PrivateKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from src.harness.oracle.commitment import (
    CommitmentError,
    CoverageError,
    UnsupportedAlgorithmError,
    UnsupportedVersionError,
    block_ids_from_raw,
    capability_commitment,
    check_htc_coverage,
    commit_ids,
    commit_prefix,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
PILOT_FACTS = 'right("calendar", "read"); right("notes", "write");'
PILOT_CHECK = 'check if right("calendar", "read");'
PILOT_CHECK_ALT = 'check if right("notes", "write");'


def _mint_chain(depth: int) -> tuple[KeyPair, list[bytes]]:
    """Root keypair plus token snapshots P_0..P_depth."""
    keypair = KeyPair()
    token = BiscuitBuilder(PILOT_FACTS).build(keypair.private_key)
    snapshots = [bytes(token.to_bytes())]
    for _ in range(depth):
        token = token.append(BlockBuilder(PILOT_CHECK))
        snapshots.append(bytes(token.to_bytes()))
    return keypair, snapshots


# --- test-local wire helpers (independent of the oracle implementation) ---


def _read_varint(buf: bytes, i: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        byte = buf[i]
        i += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, i


def _fields(buf: bytes) -> list[tuple[int, int, object]]:
    i, out = 0, []
    while i < len(buf):
        tag, i = _read_varint(buf, i)
        field_no, wire_type = tag >> 3, tag & 7
        if wire_type == 2:
            length, i = _read_varint(buf, i)
            out.append((field_no, wire_type, buf[i : i + length]))
            i += length
        elif wire_type == 0:
            value, i = _read_varint(buf, i)
            out.append((field_no, wire_type, value))
        else:
            raise ValueError(f"unexpected wire type {wire_type}")
    return out


def _emit_varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _emit(field_list: list[tuple[int, int, object]]) -> bytes:
    out = bytearray()
    for field_no, wire_type, payload in field_list:
        out += _emit_varint((field_no << 3) | wire_type)
        if wire_type == 2:
            out += _emit_varint(len(payload)) + payload
        else:
            out += _emit_varint(payload)
    return bytes(out)


def _reorder_top_level(raw: bytes) -> bytes:
    """Semantically equivalent container: proof field emitted first."""
    top = _fields(raw)
    return _emit([top[-1]] + top[:-1])


def _reorder_inner_authority(raw: bytes) -> bytes:
    """Semantically equivalent container: authority SignedBlock fields reversed."""
    top = _fields(raw)
    reordered = None
    for field_no, wire_type, payload in top:
        if field_no == 2:
            reordered = _emit(list(reversed(_fields(payload))))
    return _emit([(f, w, reordered) if f == 2 else (f, w, p) for f, w, p in top])


def _nonminimal_inner_varint(raw: bytes) -> bytes:
    """Semantically equivalent container: one inner length varint padded."""
    top = _fields(raw)
    rebuilt = None
    for field_no, wire_type, payload in top:
        if field_no == 2:
            out = bytearray()
            for f, w, v in _fields(payload):
                out += _emit_varint((f << 3) | w)
                if w == 2:
                    length = _emit_varint(len(v))
                    if f == 1:  # pad the Datalog-bytes length varint
                        length = length[:-1] + bytes([length[-1] | 0x80, 0x00])
                    out += length + v
                else:
                    out += _emit_varint(v)
            rebuilt = bytes(out)
    return _emit([(f, w, rebuilt) if f == 2 else (f, w, p) for f, w, p in top])


def _flip_byte_in_authority_datalog(raw: bytes) -> bytes:
    """Mutate one byte of the authority block's signed Datalog content."""
    top = _fields(raw)
    mutated = None
    for field_no, wire_type, payload in top:
        if field_no == 2:
            sub = []
            for f, w, v in _fields(payload):
                if f == 1:
                    v = bytes([v[0] ^ 0x01]) + v[1:]
                sub.append((f, w, v))
            mutated = _emit(sub)
    return _emit([(f, w, mutated) if f == 2 else (f, w, p) for f, w, p in top])


def _swap_appended_blocks(raw: bytes) -> bytes:
    """Swap the order of the two appended blocks (field 3 occurrences)."""
    top = _fields(raw)
    block_positions = [i for i, (f, _, _) in enumerate(top) if f == 3]
    assert len(block_positions) >= 2, "need depth >= 2 to swap"
    i, j = block_positions[0], block_positions[1]
    top[i], top[j] = top[j], top[i]
    return _emit(top)


def _truncate_terminal_block(raw: bytes) -> bytes:
    """Drop the terminal appended block, keeping everything else."""
    top = _fields(raw)
    last_block = max(i for i, (f, _, _) in enumerate(top) if f == 3)
    return _emit(top[:last_block] + top[last_block + 1 :])


def _legacy_raw_byte_hash(raw: bytes) -> str:
    """The superseded ADR 0002 scheme: SHA-256 over raw container block bytes."""
    digest = sha256()
    for field_no, _, payload in _fields(raw):
        if field_no in (2, 3):
            digest.update(len(payload).to_bytes(8, "big"))
            digest.update(payload)
    return digest.hexdigest()


# --- the tests ---


def test_commitment_is_encoding_independent() -> None:
    keypair, snapshots = _mint_chain(1)
    raw = snapshots[1]
    original = capability_commitment(raw, keypair.public_key)

    re_encodings = {
        "top-level field reorder": _reorder_top_level(raw),
        "inner SignedBlock field reorder": _reorder_inner_authority(raw),
        "non-minimal inner varint": _nonminimal_inner_varint(raw),
    }
    for name, alternative in re_encodings.items():
        assert alternative != raw, f"{name}: re-encoding must change the raw bytes"
        try:
            Biscuit.from_bytes(alternative, keypair.public_key)
        except BiscuitValidationError:  # pragma: no cover - reportable finding
            pytest.fail(
                f"FINDING (report to author): the library rejected the semantically "
                f"equivalent re-encoding '{name}'. This reduces but does not eliminate "
                f"the raw-byte-hash risk; the commitment correction still stands."
            )
        assert capability_commitment(alternative, keypair.public_key) == original, (
            f"{name}: BlockID commitment must be encoding-independent"
        )

    # The demonstration that the correction was necessary: for re-encodings that
    # touch bytes inside the committed region, the OLD raw-byte hash differs.
    for name in ("inner SignedBlock field reorder", "non-minimal inner varint"):
        assert _legacy_raw_byte_hash(re_encodings[name]) != _legacy_raw_byte_hash(raw), (
            f"{name}: the superseded raw-protobuf-byte hash should have differed"
        )

    # Negative arm: a genuinely different block yields a different commitment.
    base = Biscuit.from_bytes(snapshots[0], keypair.public_key)
    different = bytes(base.append(BlockBuilder(PILOT_CHECK_ALT)).to_bytes())
    assert capability_commitment(different, keypair.public_key) != original


def test_append_preserves_all_prior_prefix_commitments() -> None:
    keypair, snapshots = _mint_chain(3)  # P_0..P_3
    ids_per_state = [block_ids_from_raw(s, keypair.public_key) for s in snapshots]

    terminal = [commit_prefix(ids, len(ids) - 1) for ids in ids_per_state]
    for k in range(1, 4):
        for j in range(k):  # every prior prefix commitment is unchanged
            assert commit_prefix(ids_per_state[k], j) == commit_prefix(ids_per_state[j], j), (
                f"prefix commit(P_{j}) changed after append {k}"
            )
        assert terminal[k] != terminal[k - 1], "terminal commitment must change on append"

    # Negative arm: 'unchanged' is not vacuous — different prefixes differ.
    assert commit_prefix(ids_per_state[1], 0) != commit_prefix(ids_per_state[1], 1)


def test_mutation_fails_closed() -> None:
    keypair, snapshots = _mint_chain(1)
    raw = snapshots[1]
    # Positive arm: the unmutated token verifies and commits.
    assert capability_commitment(raw, keypair.public_key)

    mutated = _flip_byte_in_authority_datalog(raw)
    assert mutated != raw
    with pytest.raises(BiscuitValidationError):
        block_ids_from_raw(mutated, keypair.public_key)


def test_truncation_fails_closed() -> None:
    keypair, snapshots = _mint_chain(2)
    raw = snapshots[2]
    original_ids = block_ids_from_raw(raw, keypair.public_key)
    original_commit = commit_prefix(original_ids, len(original_ids) - 1)

    # Positive arm: the intact token passes both the commitment and coverage.
    check_htc_coverage(original_ids, len(original_ids))

    truncated = _truncate_terminal_block(raw)
    try:
        truncated_ids = block_ids_from_raw(truncated, keypair.public_key)
    except (BiscuitValidationError, CommitmentError):
        return  # verification failed closed — acceptable per the gate criterion
    assert commit_prefix(truncated_ids, len(truncated_ids) - 1) != original_commit
    with pytest.raises(CoverageError):
        check_htc_coverage(truncated_ids, len(original_ids))


def test_block_reordering_fails_closed() -> None:
    keypair, snapshots = _mint_chain(2)
    raw = snapshots[2]
    # Positive arm: the correctly ordered token verifies.
    assert block_ids_from_raw(raw, keypair.public_key)

    swapped = _swap_appended_blocks(raw)
    assert swapped != raw
    try:
        block_ids_from_raw(swapped, keypair.public_key)
    except (BiscuitValidationError, CommitmentError):
        return
    pytest.fail(
        "MAJOR FINDING (stop and report): the library accepted a block reordering; "
        "the signature chain did not bind block position."
    )


def test_missing_htc_coverage_fails_closed() -> None:
    keypair, snapshots = _mint_chain(2)
    ids = block_ids_from_raw(snapshots[2], keypair.public_key)  # n+1 = 3 BlockIDs
    check_htc_coverage(ids, len(ids))  # positive arm: n+1 entries passes
    with pytest.raises(CoverageError):
        check_htc_coverage(ids, len(ids) - 1)  # only n HTC entries


def test_unsupported_version_fails_closed() -> None:
    keypair, snapshots = _mint_chain(1)
    ids = block_ids_from_raw(snapshots[1], keypair.public_key)
    assert commit_prefix(ids, 0, version=1)  # positive arm
    with pytest.raises(UnsupportedVersionError):
        commit_prefix(ids, 0, version=2)


def test_unsupported_algorithm_fails_closed() -> None:
    # Positive arm: an Ed25519 token is accepted.
    keypair, snapshots = _mint_chain(1)
    assert block_ids_from_raw(snapshots[1], keypair.public_key)
    with pytest.raises(UnsupportedAlgorithmError):
        commit_prefix(block_ids_from_raw(snapshots[1], keypair.public_key), 0, alg=2)

    # A token minted under Secp256r1 (supported by the library) must be
    # rejected at extraction: the design mandates Ed25519 (D8).
    ec_key = ec.generate_private_key(ec.SECP256R1())
    der = ec_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    secp_keypair = KeyPair.from_private_key(PrivateKey.from_der(der))
    secp_raw = bytes(BiscuitBuilder(PILOT_FACTS).build(secp_keypair.private_key).to_bytes())
    # The library itself verifies this token; the commitment layer must not.
    assert Biscuit.from_bytes(secp_raw, secp_keypair.public_key)
    with pytest.raises(UnsupportedAlgorithmError):
        block_ids_from_raw(secp_raw, secp_keypair.public_key)


_VERIFIER_SNIPPET = (
    "import sys\n"
    "from biscuit_auth import Algorithm, PublicKey\n"
    "from src.harness.oracle.commitment import capability_commitment\n"
    "token = bytes.fromhex(sys.argv[1])\n"
    "pub = PublicKey.from_bytes(bytes.fromhex(sys.argv[2]), Algorithm.Ed25519)\n"
    "print(capability_commitment(token, pub).hex())\n"
)


def test_signer_and_verifier_are_separate_processes() -> None:
    keypair, snapshots = _mint_chain(1)
    raw = snapshots[1]
    pub_hex = bytes(keypair.public_key.to_bytes()).hex()
    signer_commit = capability_commitment(raw, keypair.public_key).hex()

    verifier = subprocess.run(
        [sys.executable, "-c", _VERIFIER_SNIPPET, raw.hex(), pub_hex],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=120,
    )
    assert verifier.returncode == 0, f"verifier subprocess failed: {verifier.stderr}"
    assert verifier.stdout.strip() == signer_commit, (
        "independent subprocess verifier must reproduce the signer's commitment"
    )

    # Negative arm: a tampered token must fail or diverge in the subprocess.
    tampered = _flip_byte_in_authority_datalog(raw)
    verifier_neg = subprocess.run(
        [sys.executable, "-c", _VERIFIER_SNIPPET, tampered.hex(), pub_hex],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=120,
    )
    assert verifier_neg.returncode != 0 or verifier_neg.stdout.strip() != signer_commit


def test_no_assertion_passes_vacuously() -> None:
    a = bytes([0xAA]) * 64
    b = bytes([0xBB]) * 64
    assert commit_ids([]) != commit_ids([a])
    assert commit_ids([a]) != commit_ids([b])
    assert commit_ids([a, b]) != commit_ids([b, a])  # order matters
    assert commit_ids([a, b]) != commit_ids([a])
    assert commit_ids([a]) == commit_ids([a])  # deterministic
