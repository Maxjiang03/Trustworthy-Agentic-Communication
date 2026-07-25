"""Regression suite for DPoP binding (gate G-5, ADR 0006).

Exactly six tests, each with positive and negative arms. All helpers are
TEST-LOCAL by design: the production DPoP verifier is built with the
B2-DPoP arm and re-tested at G-11/G-14, so no src/ module exists this
pass. The four-way DPoP attacker taxonomy (Part D) is gate G-14, not
this suite. The DPoP proof covers method+URI only [VERIFIED, RFC 9449
SS 4.2]; nothing here claims tool/body binding (that is INV, gate G-11).

Known-answer vectors are from RFC 8037 Appendix A.2/A.3, never invented.
Pilot values only — NOT the frozen ontology Omega.
"""

import hashlib
import json
import secrets
import time
from base64 import urlsafe_b64encode

from joserfc import jws
from joserfc.errors import JoseError
from joserfc.jwk import OKPKey

ALG = "Ed25519"  # RFC 9864 fully-specified identifier; explicit allowlist below
ALGS = [ALG]
HTM = "POST"
HTU = "https://mcp.example/rpc"
IAT_WINDOW_SECONDS = 300  # RFC 9449 SS 4.3 item 11: explicit acceptance window

RFC8037_A2_PUB = {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
}
RFC8037_A3_THUMB_B64 = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
RFC8037_A3_THUMB_HEX = "90facafea9b1556698540f70c0117a22ea37bd5cf3ed3c47093c1707282b4b89"


# --- test-local helpers (no src/ module this pass; see module docstring) -------


def _thumbprint_rfc7638(jwk_dict: dict) -> str:
    """RFC 7638 SS 3/SS 3.3: required members only ({crv, kty, x} for OKP per
    RFC 8037 SS 2), lexicographic order, no whitespace, SHA-256, base64url."""
    canonical = json.dumps(
        {"crv": jwk_dict["crv"], "kty": jwk_dict["kty"], "x": jwk_dict["x"]},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return urlsafe_b64encode(hashlib.sha256(canonical).digest()).rstrip(b"=").decode("ascii")


def _mint(holder_jkt: str) -> tuple[str, OKPKey]:
    """Simulated local issuance: token with cnf.jkt (RFC 9449 SS 6.1); the
    issuer private key never leaves this frame."""
    issuer = OKPKey.generate_key("Ed25519")
    now = int(time.time())
    claims = {
        "iss": "https://as.pilot.local",
        "sub": "user@pilot.local",
        "aud": HTU,
        "iat": now,
        "exp": now + 600,
        "cnf": {"jkt": holder_jkt},
    }
    token = jws.serialize_compact(
        {"typ": "at+jwt", "alg": ALG}, json.dumps(claims).encode(), issuer, algorithms=ALGS
    )
    return token, OKPKey.import_key(issuer.as_dict(private=False))


def _proof(holder: OKPKey, htm: str, htu: str) -> str:
    """DPoP proof JWT per RFC 9449 SS 4.2: typ/alg/jwk header; jti/htm/htu/iat."""
    claims = {"jti": secrets.token_urlsafe(16), "htm": htm, "htu": htu, "iat": int(time.time())}
    header = {"typ": "dpop+jwt", "alg": ALG, "jwk": holder.as_dict(private=False)}
    return jws.serialize_compact(header, json.dumps(claims).encode(), holder, algorithms=ALGS)


def _verify(proof: str, htm: str, htu: str, cnf_jkt: str) -> tuple[bool, str]:
    """RFC 9449 SS 4.3 items 3-9, 11 + the SS 6.1 cnf/jkt binding. Fail-closed."""
    try:
        header = jws.extract_compact(proof.encode()).headers()
        if header.get("typ") != "dpop+jwt":
            return False, "typ_mismatch"
        if header.get("alg") not in ALGS:
            return False, "alg_not_acceptable"
        jwk_dict = header.get("jwk")
        if not isinstance(jwk_dict, dict) or "d" in jwk_dict:
            return False, "jwk_invalid"
        verified = jws.deserialize_compact(proof, OKPKey.import_key(jwk_dict), algorithms=ALGS)
        claims = json.loads(verified.payload)
        for required in ("jti", "htm", "htu", "iat"):
            if required not in claims:
                return False, f"missing_{required}"
        if claims["htm"] != htm:
            return False, "htm_mismatch"
        if claims["htu"] != htu:
            return False, "htu_mismatch"
        if abs(int(time.time()) - int(claims["iat"])) > IAT_WINDOW_SECONDS:
            return False, "iat_outside_window"
        if _thumbprint_rfc7638(jwk_dict) != cnf_jkt:
            return False, "cnf_jkt_mismatch"
        return True, "ok"
    except (JoseError, ValueError, KeyError) as exc:
        return False, f"invalid_proof:{type(exc).__name__}"


def _cnf_jkt_of(token: str, issuer_pub: OKPKey) -> str:
    claims = json.loads(jws.deserialize_compact(token, issuer_pub, algorithms=ALGS).payload)
    return claims["cnf"]["jkt"]


# --- 1. valid-proof verify -----------------------------------------------------


def test_valid_proof_verifies():
    holder = OKPKey.generate_key("Ed25519")
    token, issuer_pub = _mint(holder.thumbprint())
    cnf_jkt = _cnf_jkt_of(token, issuer_pub)
    # Positive: the full happy path verifies with reason "ok".
    ok, reason = _verify(_proof(holder, HTM, HTU), HTM, HTU, cnf_jkt)
    assert ok and reason == "ok"
    # Negative: a signature-tampered proof fails closed, never verifies.
    proof = _proof(holder, HTM, HTU)
    tampered = proof[:-6] + ("AAAAAA" if not proof.endswith("AAAAAA") else "BBBBBB")
    ok2, reason2 = _verify(tampered, HTM, HTU, cnf_jkt)
    assert not ok2 and reason2.startswith("invalid_proof")


# --- 2. wrong-holder reject ----------------------------------------------------


def test_wrong_holder_rejected():
    holder = OKPKey.generate_key("Ed25519")
    token, issuer_pub = _mint(holder.thumbprint())
    cnf_jkt = _cnf_jkt_of(token, issuer_pub)
    # Negative: an attacker keypair signs an internally consistent proof over
    # the SAME htm/htu — rejected precisely at the thumbprint binding.
    attacker = OKPKey.generate_key("Ed25519")
    ok, reason = _verify(_proof(attacker, HTM, HTU), HTM, HTU, cnf_jkt)
    assert not ok and reason == "cnf_jkt_mismatch"
    # Positive: the legitimate holder's proof passes (rejection is specific).
    ok2, reason2 = _verify(_proof(holder, HTM, HTU), HTM, HTU, cnf_jkt)
    assert ok2 and reason2 == "ok"


# --- 3. htm mismatch reject ----------------------------------------------------


def test_htm_mismatch_rejected():
    holder = OKPKey.generate_key("Ed25519")
    token, issuer_pub = _mint(holder.thumbprint())
    cnf_jkt = _cnf_jkt_of(token, issuer_pub)
    # Negative: proof over GET presented for a POST request.
    ok, reason = _verify(_proof(holder, "GET", HTU), HTM, HTU, cnf_jkt)
    assert not ok and reason == "htm_mismatch"
    # Positive: matching method passes.
    ok2, _ = _verify(_proof(holder, HTM, HTU), HTM, HTU, cnf_jkt)
    assert ok2


# --- 4. htu mismatch reject ----------------------------------------------------


def test_htu_mismatch_rejected():
    holder = OKPKey.generate_key("Ed25519")
    token, issuer_pub = _mint(holder.thumbprint())
    cnf_jkt = _cnf_jkt_of(token, issuer_pub)
    # Negative: proof over a different target URI, same method.
    ok, reason = _verify(_proof(holder, HTM, "https://other.example/rpc"), HTM, HTU, cnf_jkt)
    assert not ok and reason == "htu_mismatch"
    # Positive: matching URI passes.
    ok2, _ = _verify(_proof(holder, HTM, HTU), HTM, HTU, cnf_jkt)
    assert ok2


# --- 5. cnf.jkt mismatch reject ------------------------------------------------


def test_cnf_jkt_mismatch_rejected():
    holder = OKPKey.generate_key("Ed25519")
    other = OKPKey.generate_key("Ed25519")
    # Negative: the TOKEN is bound to a different key than the prover's —
    # the presenting holder's own valid proof must not satisfy it.
    token, issuer_pub = _mint(other.thumbprint())
    cnf_jkt = _cnf_jkt_of(token, issuer_pub)
    ok, reason = _verify(_proof(holder, HTM, HTU), HTM, HTU, cnf_jkt)
    assert not ok and reason == "cnf_jkt_mismatch"
    # Positive: a token bound to the prover's key verifies.
    token2, issuer_pub2 = _mint(holder.thumbprint())
    ok2, reason2 = _verify(_proof(holder, HTM, HTU), HTM, HTU, _cnf_jkt_of(token2, issuer_pub2))
    assert ok2 and reason2 == "ok"


# --- 6. thumbprint known-answer / determinism ----------------------------------


def test_thumbprint_known_answer_and_determinism():
    # Positive: RFC 8037 A.3 known answer reproduced by BOTH the library and
    # the independent RFC 7638 computation, including the hex form.
    lib = OKPKey.import_key(RFC8037_A2_PUB).thumbprint()
    own = _thumbprint_rfc7638(RFC8037_A2_PUB)
    assert lib == own == RFC8037_A3_THUMB_B64
    canonical = json.dumps(
        {"crv": "Ed25519", "kty": "OKP", "x": RFC8037_A2_PUB["x"]},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    assert hashlib.sha256(canonical).hexdigest() == RFC8037_A3_THUMB_HEX
    # Determinism: repeated computation is stable.
    key = OKPKey.generate_key("Ed25519")
    assert key.thumbprint() == key.thumbprint() == _thumbprint_rfc7638(key.as_dict(private=False))
    # Negative: a different key yields a different thumbprint.
    assert key.thumbprint() != lib
    assert key.thumbprint() != OKPKey.generate_key("Ed25519").thumbprint()
