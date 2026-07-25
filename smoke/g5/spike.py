"""Gate G-5 feasibility spike — DPoP-bound token issuance and verification (IA-5).

Tests ONLY that a DPoP-bound (cnf/jkt) access token can be issued and
verified with a LOCALLY SIMULATED mint function (architecture doc SS F.4
IA-5): the real Authorization Server integration is gate G-4, and the
four-way DPoP attacker taxonomy (Part D) is gate G-14 — neither runs
here. The DPoP proof covers method+URI only, not tool or body
[VERIFIED, RFC 9449 SS 4.2: "only these two message parts are covered
by the DPoP proof"] — exactly the gap the INV body/args binding closes
(SS C / Part D), which this gate does not test.

RFC checks implemented (verifier below): RFC 9449 SS 4.3 items 3-9 and
11 plus the SS 6.1 cnf/jkt binding (SS 4.3 item 12, second bullet).
Out of scope for this simulated-issuance gate and marked as such:
`ath` (REQUIRED only when the proof accompanies an access token at a
protected resource, RFC 9449 SS 4.2 — re-exercised at G-4/G-14) and
`nonce` (REQUIRED only when the server issued one, SS 4.2; OPTIONAL
mechanism, SS 8-9).

This is a SPIKE, not production code. Exits non-zero if any MANDATORY
check fails. The issuer private key never leaves the mint function's
frame (the G-1 structural discipline).

Reproduction (joserfc==1.7.4 is pinned in pyproject.toml per ADR 0006;
the --with form reproduces the original pre-pin ephemeral run):

    uv run --with joserfc==1.7.4 python smoke/g5/spike.py
    uv run python smoke/g5/spike.py
"""

import hashlib
import json
import secrets
import sys
import time
from base64 import urlsafe_b64encode

try:
    from joserfc import jws
    from joserfc.errors import JoseError
    from joserfc.jwk import OKPKey
except ImportError:
    print("joserfc not installed. Reproduce with:")
    print("  uv run --with joserfc==1.7.4 python smoke/g5/spike.py")
    sys.exit(2)

# RFC 9864 fully-specified JWS algorithm identifier for Ed25519 (the
# project-wide signature choice). joserfc's default registry excludes it
# per RFC 8725 hygiene, so every call passes an explicit allowlist.
ALG = "Ed25519"
ALGS = [ALG]

# RFC 8037 Appendix A.2 public key and A.3 known-answer thumbprint.
RFC8037_A2_PUB = {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
}
RFC8037_A3_THUMB_B64 = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
RFC8037_A3_THUMB_HEX = "90facafea9b1556698540f70c0117a22ea37bd5cf3ed3c47093c1707282b4b89"

HTM = "POST"
HTU = "https://mcp.example/rpc"
IAT_WINDOW_SECONDS = 300  # explicit acceptance window, RFC 9449 SS 4.3 item 11

RESULTS: list[tuple[str, bool, bool, str]] = []  # (check, mandatory, passed, evidence)


def record(check: str, mandatory: bool, passed: bool, evidence: str) -> None:
    RESULTS.append((check, mandatory, passed, evidence))
    status = "PASS" if passed else "FAIL"
    tag = "MANDATORY" if mandatory else "info"
    print(f"{check} [{tag}] {status} — {evidence}")


def thumbprint_rfc7638(jwk_dict: dict) -> str:
    """Independent RFC 7638 thumbprint: required members only, lexicographic
    order, no whitespace (RFC 7638 SS 3, SS 3.3); for OKP the required members
    are crv, kty, x (RFC 8037 SS 2). Cross-checks the library's thumbprint().
    """
    canonical = json.dumps(
        {"crv": jwk_dict["crv"], "kty": jwk_dict["kty"], "x": jwk_dict["x"]},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    digest = hashlib.sha256(canonical).digest()
    return urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def mint_dpop_bound_token(holder_jkt: str) -> tuple[str, OKPKey]:
    """Simulated LOCAL mint: issue an access token bound to holder_jkt.

    The issuer private key is created inside this frame and never leaves
    it — callers receive only the signed token and the issuer PUBLIC key.
    This simulates AS issuance for the gate; the real AS is gate G-4.
    """
    issuer_keypair = OKPKey.generate_key("Ed25519")
    now = int(time.time())
    claims = {
        "iss": "https://as.pilot.local",
        "sub": "user@pilot.local",
        "aud": HTU,
        "iat": now,
        "exp": now + 600,
        "cnf": {"jkt": holder_jkt},  # RFC 9449 SS 6.1 via RFC 7800 cnf
    }
    token = jws.serialize_compact(
        {"typ": "at+jwt", "alg": ALG},
        json.dumps(claims).encode(),
        issuer_keypair,
        algorithms=ALGS,
    )
    issuer_pub = OKPKey.import_key(issuer_keypair.as_dict(private=False))
    return token, issuer_pub


def make_dpop_proof(holder_key: OKPKey, htm: str, htu: str, iat: int | None = None) -> str:
    """Build a DPoP proof JWT per RFC 9449 SS 4.2 (jti, htm, htu, iat; header
    typ/alg/jwk with the PUBLIC key only)."""
    claims = {
        "jti": secrets.token_urlsafe(16),  # >= 96 bits of randomness, SS 4.2
        "htm": htm,
        "htu": htu,
        "iat": int(time.time()) if iat is None else iat,
    }
    header = {"typ": "dpop+jwt", "alg": ALG, "jwk": holder_key.as_dict(private=False)}
    return jws.serialize_compact(header, json.dumps(claims).encode(), holder_key, algorithms=ALGS)


def verify_dpop_proof(
    proof: str,
    expected_htm: str,
    expected_htu: str,
    token_cnf_jkt: str,
    now: int | None = None,
) -> tuple[bool, str]:
    """RFC 9449 SS 4.3 verifier subset for this gate. Returns (ok, reason).

    Implements SS 4.3 items 3 (required claims), 4 (typ), 5 (alg allowlist),
    6 (signature under the header jwk), 7 (no private key in jwk), 8 (htm),
    9 (htu), 11 (iat window), and the SS 6.1 binding check (item 12, second
    bullet): thumbprint(proof jwk) == token cnf.jkt. `ath` and `nonce` are
    out of scope here (see module docstring). Fail-closed: any parse or
    signature error returns a rejection, never an allow.
    """
    now = int(time.time()) if now is None else now
    try:
        obj = jws.extract_compact(proof.encode())
        header = obj.headers()
        if header.get("typ") != "dpop+jwt":  # SS 4.3 item 4
            return False, "typ_mismatch"
        if header.get("alg") not in ALGS:  # SS 4.3 item 5
            return False, "alg_not_acceptable"
        jwk_dict = header.get("jwk")
        if not isinstance(jwk_dict, dict):
            return False, "jwk_missing"
        if "d" in jwk_dict:  # SS 4.3 item 7
            return False, "jwk_contains_private_key"
        embedded = OKPKey.import_key(jwk_dict)
        verified = jws.deserialize_compact(proof, embedded, algorithms=ALGS)  # item 6
        claims = json.loads(verified.payload)
        for required in ("jti", "htm", "htu", "iat"):  # SS 4.3 item 3
            if required not in claims:
                return False, f"missing_{required}"
        if claims["htm"] != expected_htm:  # SS 4.3 item 8
            return False, "htm_mismatch"
        if claims["htu"] != expected_htu:  # SS 4.3 item 9
            return False, "htu_mismatch"
        if abs(now - int(claims["iat"])) > IAT_WINDOW_SECONDS:  # SS 4.3 item 11
            return False, "iat_outside_window"
        if thumbprint_rfc7638(jwk_dict) != token_cnf_jkt:  # SS 6 / item 12
            return False, "cnf_jkt_mismatch"
        return True, "ok"
    except (JoseError, ValueError, KeyError) as exc:
        return False, f"invalid_proof:{type(exc).__name__}"


def g5_a_thumbprint() -> OKPKey:
    """G-5.A: holder keypair; jkt per RFC 7638/8037; known-answer reproduced."""
    holder = OKPKey.generate_key("Ed25519")
    lib_thumb = holder.thumbprint()
    own_thumb = thumbprint_rfc7638(holder.as_dict(private=False))

    ka_lib = OKPKey.import_key(RFC8037_A2_PUB).thumbprint()
    ka_own = thumbprint_rfc7638(RFC8037_A2_PUB)
    ka_hex = hashlib.sha256(
        json.dumps(
            {"crv": "Ed25519", "kty": "OKP", "x": RFC8037_A2_PUB["x"]},
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).hexdigest()

    ok = (
        lib_thumb == own_thumb
        and ka_lib == ka_own == RFC8037_A3_THUMB_B64
        and ka_hex == RFC8037_A3_THUMB_HEX
    )
    record(
        "G-5.A",
        True,
        ok,
        f"holder keypair generated; jkt library==independent-RFC7638={lib_thumb == own_thumb} "
        f"({lib_thumb}); RFC 8037 A.3 known answer reproduced by both paths "
        f"({ka_lib}; sha256 hex {ka_hex})",
    )
    return holder


def g5_b_mint(holder: OKPKey) -> tuple[str, str]:
    """G-5.B: local mint issues a token whose cnf.jkt equals the holder jkt."""
    holder_jkt = holder.thumbprint()
    token, issuer_pub = mint_dpop_bound_token(holder_jkt)
    verified = jws.deserialize_compact(token, issuer_pub, algorithms=ALGS)
    claims = json.loads(verified.payload)
    cnf_jkt = claims.get("cnf", {}).get("jkt")
    issuer_differs = issuer_pub.as_dict(private=False)["x"] != holder.as_dict(private=False)["x"]
    ok = cnf_jkt == holder_jkt and issuer_differs
    record(
        "G-5.B",
        True,
        ok,
        f"token verified under issuer pub; cnf.jkt == holder jkt: {cnf_jkt == holder_jkt} "
        f"({cnf_jkt}); issuer key != holder key: {issuer_differs}; issuer private key "
        f"never left the mint frame (structural)",
    )
    return token, cnf_jkt


def g5_c_valid_proof(holder: OKPKey, cnf_jkt: str) -> str:
    """G-5.C: a proof over htm+htu verifies against the token binding."""
    proof = make_dpop_proof(holder, HTM, HTU)
    ok, reason = verify_dpop_proof(proof, HTM, HTU, cnf_jkt)
    record(
        "G-5.C",
        True,
        ok and reason == "ok",
        f"proof (typ=dpop+jwt, alg={ALG}, jwk=holder pub; jti/htm/htu/iat) verified: "
        f"signature under header jwk, typ, htm, htu, iat in ±{IAT_WINDOW_SECONDS}s window, "
        f"jti present, thumbprint(jwk)==cnf.jkt -> reason={reason}",
    )
    return proof


def g5_d_wrong_holder(cnf_jkt: str) -> None:
    """G-5.D: a proof signed by a DIFFERENT keypair over the same htm/htu is
    rejected specifically at the cnf.jkt <-> proof-jwk thumbprint comparison."""
    attacker = OKPKey.generate_key("Ed25519")
    stolen_proof = make_dpop_proof(attacker, HTM, HTU)  # self-consistent, wrong key
    ok, reason = verify_dpop_proof(stolen_proof, HTM, HTU, cnf_jkt)
    record(
        "G-5.D",
        True,
        (not ok) and reason == "cnf_jkt_mismatch",
        f"wrong-holder proof (attacker keypair, same htm/htu, internally valid "
        f"signature) rejected={not ok} at reason={reason} — the thumbprint binding, "
        f"not an incidental failure",
    )


def g5_e_htm_htu_mismatch(holder: OKPKey, cnf_jkt: str) -> None:
    """G-5.E: htm mismatch and htu mismatch are each rejected independently."""
    htm_proof = make_dpop_proof(holder, "GET", HTU)  # wrong method, right URI
    htm_ok, htm_reason = verify_dpop_proof(htm_proof, HTM, HTU, cnf_jkt)
    htu_proof = make_dpop_proof(holder, HTM, "https://other.example/rpc")  # right method
    htu_ok, htu_reason = verify_dpop_proof(htu_proof, HTM, HTU, cnf_jkt)
    ok = (
        (not htm_ok)
        and htm_reason == "htm_mismatch"
        and (not htu_ok)
        and htu_reason == "htu_mismatch"
    )
    record(
        "G-5.E",
        True,
        ok,
        f"htm mismatch rejected={not htm_ok} (reason={htm_reason}); "
        f"htu mismatch rejected={not htu_ok} (reason={htu_reason}) — independently",
    )


def g5_f_negative_control(valid_proof: str, cnf_jkt: str) -> None:
    """G-5.F: the valid proof still verifies after D/E — rejection logic is
    not rejecting everything."""
    ok, reason = verify_dpop_proof(valid_proof, HTM, HTU, cnf_jkt)
    record(
        "G-5.F",
        True,
        ok and reason == "ok",
        f"the G-5.C proof re-verifies after the rejection checks: {ok} (reason={reason})",
    )


def main() -> int:
    print("Gate G-5 spike — DPoP binding via joserfc 1.7.4 (alg=Ed25519, RFC 9864)")
    print("Local simulated mint — the real AS is gate G-4. Pilot values, NOT Omega.\n")

    holder = g5_a_thumbprint()
    _token, cnf_jkt = g5_b_mint(holder)
    valid_proof = g5_c_valid_proof(holder, cnf_jkt)
    g5_d_wrong_holder(cnf_jkt)
    g5_e_htm_htu_mismatch(holder, cnf_jkt)
    g5_f_negative_control(valid_proof, cnf_jkt)

    mandatory_failures = [c for c, mandatory, passed, _ in RESULTS if mandatory and not passed]
    print()
    if mandatory_failures:
        print(f"GATE G-5: FAIL — mandatory check(s) failed: {', '.join(mandatory_failures)}")
        print(
            "Per SMOKE_G8_G5_TASK STEP 1: write the FAIL report, set the board row, "
            "commit the docs, STOP the whole pass."
        )
        return 1
    print("GATE G-5: all mandatory checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
