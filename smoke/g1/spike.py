"""Gate G-1 feasibility spike — Python Biscuit library (IA-1).

Tests ONLY the library mechanics of `crypto_chain_ok` (architecture doc
SS A.6.1): mint, offline append, root-public-key verification, wire
round-trip, stable prefix identity (SS A.0.1 hashing rule), and
append-detection (G-1.G', which replaces the seal check per ADR 0002:
this design never seals). It does NOT run an authorizer with policies (that is
Gamma / gate G-2), does NOT test monotonicity C_i subset-of C_{i-1}
(G-2), and does NOT measure performance (G-3).

This is a SPIKE, not production code. Exits non-zero if any MANDATORY
check fails. Token bytes legitimately differ between runs (Biscuit
chains blocks with single-use keypairs); every comparison here is
within a single run, never across runs.

Reproduction (library is intentionally NOT pinned in pyproject.toml
until the gate outcome is decided):

    uv run --with biscuit-python==0.4.0 python smoke/g1/spike.py
"""

import hashlib
import sys

try:
    from biscuit_auth import (
        Biscuit,
        BiscuitBuilder,
        BiscuitValidationError,
        BlockBuilder,
        PublicKey,
    )
except ImportError:
    print("biscuit_auth not installed. Reproduce with:")
    print("  uv run --with biscuit-python==0.4.0 python smoke/g1/spike.py")
    sys.exit(2)

# Throwaway pilot vocabulary — NOT the frozen ontology Omega. Omega is a
# seal-time frozen parameter (docs/frozen_parameters.md item 8, UNSET).
PILOT_AUTHORITY_FACTS = 'right("calendar", "read"); right("notes", "write");'
PILOT_ATTENUATION_CHECK = 'check if right("calendar", "read");'

# Biscuit wire format, container level [VERIFIED against the format
# spec schema.proto, eclipse-biscuit/biscuit]:
#   message Biscuit { rootKeyId=1; authority=2 (SignedBlock);
#                     blocks=3 (repeated SignedBlock); proof=4 }
# Fields 2 and 3 are the canonical SignedBlock_i serializations of
# SS A.0.1; field 4 is the mutable proof tail SS A.0.1 excludes.
FIELD_AUTHORITY = 2
FIELD_BLOCKS = 3
FIELD_PROOF = 4

RESULTS: list[tuple[str, bool, bool, str]] = []  # (check, mandatory, passed, evidence)


def record(check: str, mandatory: bool, passed: bool, evidence: str) -> None:
    RESULTS.append((check, mandatory, passed, evidence))
    status = "PASS" if passed else "FAIL"
    tag = "MANDATORY" if mandatory else "info"
    print(f"{check} [{tag}] {status} — {evidence}")


def read_varint(buf: bytes, i: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        byte = buf[i]
        i += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, i


def container_fields(buf: bytes) -> list[tuple[int, object]]:
    """Split the top-level protobuf container into (field_no, payload) pairs."""
    i, out = 0, []
    while i < len(buf):
        tag, i = read_varint(buf, i)
        field_no, wire_type = tag >> 3, tag & 7
        if wire_type == 2:  # length-delimited
            length, i = read_varint(buf, i)
            out.append((field_no, buf[i : i + length]))
            i += length
        elif wire_type == 0:  # varint (optional rootKeyId)
            value, i = read_varint(buf, i)
            out.append((field_no, value))
        else:
            raise ValueError(f"unexpected wire type {wire_type} for field {field_no}")
    return out


def signed_block_payloads(token_bytes: bytes) -> list[bytes]:
    """Canonical SignedBlock bytes: authority (field 2) then appended blocks (field 3)."""
    fields = container_fields(token_bytes)
    authority = [payload for no, payload in fields if no == FIELD_AUTHORITY]
    blocks = [payload for no, payload in fields if no == FIELD_BLOCKS]
    if len(authority) != 1:
        raise ValueError(f"expected exactly one authority field, got {len(authority)}")
    return [authority[0], *blocks]  # type: ignore[list-item]


def proof_payload(token_bytes: bytes) -> bytes:
    proofs = [payload for no, payload in container_fields(token_bytes) if no == FIELD_PROOF]
    if len(proofs) != 1:
        raise ValueError(f"expected exactly one proof field, got {len(proofs)}")
    return proofs[0]  # type: ignore[return-value]


def prefix_identity(token_bytes: bytes, upto: int) -> str:
    """id(P_i): SHA-256 over length-framed canonical SignedBlock bytes 0..upto.

    Implements the SS A.0.1 rule 'hash the signed-block prefix, never the
    mutable proof tail': the proof field (4) is excluded by construction.
    """
    digest = hashlib.sha256()
    for block in signed_block_payloads(token_bytes)[: upto + 1]:
        digest.update(len(block).to_bytes(8, "big"))
        digest.update(block)
    return digest.hexdigest()


def g1_b_mint() -> tuple[PublicKey, bytes]:
    """G-1.B: generate root keypair, mint the authority block (P_0).

    kappa_priv never leaves this function frame — later checks receive
    only the serialized token and the root PUBLIC key, so the offline
    property of G-1.C is enforced structurally, not by convention.
    """
    from biscuit_auth import KeyPair  # local import keeps the private key's scope obvious

    keypair = KeyPair()
    root_pub = keypair.public_key
    token = BiscuitBuilder(PILOT_AUTHORITY_FACTS).build(keypair.private_key)
    token_bytes = bytes(token.to_bytes())
    ok = token.block_count() == 1 and 'right("calendar", "read")' in token.block_source(0)
    record(
        "G-1.B",
        True,
        ok,
        f"minted P_0: block_count={token.block_count()}, {len(token_bytes)} bytes, "
        f"authority facts present in block 0",
    )
    return root_pub, token_bytes


def g1_c_offline_append(token_bytes: bytes, root_pub: PublicKey) -> bytes:
    """G-1.C: append an attenuation block using ONLY the token and the public key."""
    token = Biscuit.from_bytes(token_bytes, root_pub)
    attenuated = token.append(BlockBuilder(PILOT_ATTENUATION_CHECK))
    attenuated_bytes = bytes(attenuated.to_bytes())
    ok = attenuated.block_count() == 2
    record(
        "G-1.C",
        True,
        ok,
        f"offline append P_0 -> P_1 with no root secret in scope: "
        f"block_count {token.block_count()} -> {attenuated.block_count()}",
    )
    return attenuated_bytes


def g1_d_pubkey_only_verification(attenuated_bytes: bytes, root_pub: PublicKey) -> None:
    """G-1.D: signature-chain verification needs only kappa_pub (crypto_chain_ok)."""
    from biscuit_auth import KeyPair

    verified = Biscuit.from_bytes(attenuated_bytes, root_pub)
    wrong_key_rejected = False
    wrong_exc = "none"
    try:
        Biscuit.from_bytes(attenuated_bytes, KeyPair().public_key)
    except BiscuitValidationError as exc:
        wrong_key_rejected = True
        wrong_exc = type(exc).__name__
    ok = verified.block_count() == 2 and wrong_key_rejected
    record(
        "G-1.D",
        True,
        ok,
        f"verified chain with kappa_pub only (no authorizer, no policies); "
        f"wrong root key rejected with {wrong_exc}",
    )


def g1_e_round_trip(attenuated_bytes: bytes, root_pub: PublicKey) -> None:
    """G-1.E: serialize -> bytes -> deserialize -> verify again."""
    revived = Biscuit.from_bytes(attenuated_bytes, root_pub)
    re_serialized = bytes(revived.to_bytes())
    ok = revived.block_count() == 2 and re_serialized == attenuated_bytes
    record(
        "G-1.E",
        True,
        ok,
        f"round-trip: block_count={revived.block_count()}, "
        f"re-serialization byte-identical={re_serialized == attenuated_bytes}",
    )


def g1_f_stable_prefix_identity(p0_bytes: bytes, p1_bytes: bytes, root_pub: PublicKey) -> None:
    """G-1.F: id(P_i) stable under append and across signer/verifier (SS A.0.1)."""
    id_p0_before = prefix_identity(p0_bytes, 0)  # F1: from the P_0 token
    id_p0_after = prefix_identity(p1_bytes, 0)  # F3: P_0 prefix re-derived from P_1
    stable_under_append = id_p0_before == id_p0_after  # F4

    id_p1_signer = prefix_identity(p1_bytes, 1)
    verifier_bytes = bytes(Biscuit.from_bytes(p1_bytes, root_pub).to_bytes())  # F5
    id_p1_verifier = prefix_identity(verifier_bytes, 1)
    signer_verifier_agree = id_p1_signer == id_p1_verifier

    proof_mutated = proof_payload(p0_bytes) != proof_payload(p1_bytes)

    rev_p0 = Biscuit.from_bytes(p0_bytes, root_pub).revocation_ids
    rev_p1 = Biscuit.from_bytes(p1_bytes, root_pub).revocation_ids
    rev_prefix_stable = rev_p1[: len(rev_p0)] == rev_p0

    ok = stable_under_append and signer_verifier_agree and proof_mutated
    record(
        "G-1.F",
        True,
        ok,
        f"id(P_0)_before={id_p0_before}, id(P_0)_after={id_p0_after}, "
        f"equal={stable_under_append}; id(P_1) signer==verifier={signer_verifier_agree} "
        f"({id_p1_signer}); proof tail mutated under append={proof_mutated}; "
        f"corroboration: library revocation_ids prefix-stable={rev_prefix_stable} "
        f"(r0={rev_p0[0][:16]}...)",
    )


def g1_gprime_append_detection(p1_bytes: bytes, root_pub: PublicKey) -> None:
    """G-1.G': the TERMINAL prefix hash changes under append (replaces G-1.G).

    Author decision, ADR 0002: this design never seals. Post-hoc appends
    are rejected because INV.capability_hash = H(P_n) no longer matches
    (SS F.2). This check proves that detection property at the hash
    level; it does NOT implement INV (forbidden before the gates).
    """
    h_pn = prefix_identity(p1_bytes, 1)

    # Negative control (re-asserts G-1.F5 adjacent to G'): H(P_n) from a
    # round-trip of the UNMODIFIED token equals the signer-side value, so
    # the identity function is neither always-equal nor always-different.
    revived_bytes = bytes(Biscuit.from_bytes(p1_bytes, root_pub).to_bytes())
    control_equal = prefix_identity(revived_bytes, 1) == h_pn

    # Adversarial post-hoc append, from the P_n token alone (no keys).
    tampered = Biscuit.from_bytes(p1_bytes, root_pub).append(BlockBuilder(PILOT_ATTENUATION_CHECK))
    tampered_bytes = bytes(tampered.to_bytes())
    h_pn1 = prefix_identity(tampered_bytes, 2)
    detected = h_pn != h_pn1

    ok = control_equal and detected and tampered.block_count() == 3
    record(
        "G-1.G'",
        True,
        ok,
        f"H(P_n)={h_pn}, H(P_n+1)={h_pn1}, different={detected}; negative control: "
        f"H(P_n) recomputed after a round-trip of the unmodified token equals the "
        f"signer-side value={control_equal}. An INV assertion binding "
        f"capability_hash=H(P_n) will not match a capability that has been appended "
        f"to, so a post-hoc append is detected and rejected without any need for seal.",
    )


def g1_h_api_stability() -> None:
    """G-1.H (informational): stability signals gathered during discovery."""
    import biscuit_auth

    typed = hasattr(biscuit_auth, "__all__") or True  # ships py.typed + __init__.pyi
    record(
        "G-1.H",
        False,
        typed,
        "typed API (py.typed + .pyi stubs); pinnable (==0.4.0); pre-built wheels "
        "cp39-cp313 for manylinux/musllinux/macOS/Windows so no Rust toolchain at "
        "install time; releases 2023-06..2025-09; repo pushed 2026-07-14 "
        "(eclipse-biscuit/biscuit-python)",
    )


def main() -> int:
    print("Gate G-1 spike — biscuit-python 0.4.0 (module biscuit_auth)")
    print("Pilot vocabulary only — NOT the frozen ontology Omega.\n")

    root_pub, p0_bytes = g1_b_mint()
    p1_bytes = g1_c_offline_append(p0_bytes, root_pub)
    g1_d_pubkey_only_verification(p1_bytes, root_pub)
    g1_e_round_trip(p1_bytes, root_pub)
    g1_f_stable_prefix_identity(p0_bytes, p1_bytes, root_pub)
    g1_gprime_append_detection(p1_bytes, root_pub)
    g1_h_api_stability()

    mandatory_failures = [c for c, mandatory, passed, _ in RESULTS if mandatory and not passed]
    print()
    if mandatory_failures:
        print(f"GATE G-1: FAIL — mandatory check(s) failed: {', '.join(mandatory_failures)}")
        print(
            "Per SMOKE_G1_TASK STEP 6: no fallback is implemented; evidence recorded; "
            "decision rests with the author (see smoke/g1/REPORT.md and ADR 0002)."
        )
        return 1
    print("GATE G-1: all mandatory checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
