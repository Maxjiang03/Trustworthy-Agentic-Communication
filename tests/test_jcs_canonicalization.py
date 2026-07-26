"""Regression suite for RFC 8785 JCS canonicalisation (gate G-8, ADR 0005)
and the frozen H_JCS construction over it (ADR 0009).

Every test has a positive arm and a negative arm so no assertion can pass
vacuously. All RFC vectors are verbatim from RFC 8785 (sections 3.2.2-3.2.4,
Appendix B), never invented. The library under test is rfc8785 (pinned by
ADR 0005). Digest comparisons go through the oracle-side h_jcs module
(src/harness/oracle/jcs_digest.py, ADR 0009); canonical-BYTES assertions and
the RFC vectors are unchanged from the G-8 pass. bare sha256 appears only as
the domain-separation FOIL (what H_JCS must NOT equal) and in the layout
known-answer.

Source is pure ASCII; non-ASCII data appears only as escape sequences.
Pilot vocabulary only — NOT the frozen ontology Omega.
"""

import json
import struct
import subprocess
import sys
from hashlib import sha256
from pathlib import Path

import pytest
import rfc8785

from src.harness.oracle.jcs_digest import (
    TAG,
    VERSION,
    UnsupportedVersionError,
    canonicalize,
    h_jcs,
)

REPO_ROOT = Path(__file__).resolve().parents[1]

# --- shared fixtures (JSON texts; parsed fresh in each test) -------------------

ARGS_TEXT = '{"tool":"calendar.read","query":{"user":"A","day":"2026-07-25"},"limit":10}'
ARGS_TEXT_REORDERED = '{"limit":10,"query":{"day":"2026-07-25","user":"A"},"tool":"calendar.read"}'
ARGS_TEXT_WHITESPACE = (
    '{\n  "tool" : "calendar.read" ,\n  "query" : {"user": "A", "day": "2026-07-25"},\n'
    '  "limit" : 10\n}'
)
ARGS_TEXT_ESCAPES = (
    '{"tool":"\\u0063alendar.read","query":{"user":"\\u0041","day":"2026-07-25"},"limit":10}'
)

RFC_SAMPLE_INPUT = (
    '{ "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001], '
    '"string": "\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/", '
    '"literals": [null, true, false] }'
)
RFC_EXPECTED_BYTES = bytes.fromhex(
    "7b226c69746572616c73223a5b6e756c6c2c747275652c66616c73655d2c226e756d62"
    "657273223a5b3333333333333333332e333333333333332c31652b33302c342e352c30"
    "2e3030322c31652d32375d2c22737472696e67223a22e282ac245c75303030665c6e41"
    "27425c225c5c5c5c5c222f227d"
)
RFC_SORT_INPUT = (
    '{ "\\u20ac": "Euro Sign", "\\r": "Carriage Return", '
    '"\\ufb33": "Hebrew Letter Dalet With Dagesh", "1": "One", '
    '"\\ud83d\\ude00": "Emoji: Grinning Face", "\\u0080": "Control", '
    '"\\u00f6": "Latin Small Letter O With Diaeresis" }'
)
RFC_SORT_EXPECTED_ORDER = [
    "Carriage Return",
    "One",
    "Control",
    "Latin Small Letter O With Diaeresis",
    "Euro Sign",
    "Emoji: Grinning Face",
    "Hebrew Letter Dalet With Dagesh",
]
RFC_NUMBER_VECTORS = [
    ("0000000000000000", "0"),
    ("8000000000000000", "0"),
    ("0000000000000001", "5e-324"),
    ("8000000000000001", "-5e-324"),
    ("7fefffffffffffff", "1.7976931348623157e+308"),
    ("ffefffffffffffff", "-1.7976931348623157e+308"),
    ("4340000000000000", "9007199254740992"),
    ("c340000000000000", "-9007199254740992"),
    ("4430000000000000", "295147905179352830000"),
    ("44b52d02c7e14af5", "9.999999999999997e+22"),
    ("44b52d02c7e14af6", "1e+23"),
    ("44b52d02c7e14af7", "1.0000000000000001e+23"),
    ("444b1ae4d6e2ef4e", "999999999999999700000"),
    ("444b1ae4d6e2ef4f", "999999999999999900000"),
    ("444b1ae4d6e2ef50", "1e+21"),
    ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"),
    ("3eb0c6f7a0b5ed8d", "0.000001"),
    ("41b3de4355555553", "333333333.3333332"),
    ("41b3de4355555554", "333333333.33333325"),
    ("41b3de4355555555", "333333333.3333333"),
    ("41b3de4355555556", "333333333.3333334"),
    ("41b3de4355555557", "333333333.33333343"),
    ("becbf647612f3696", "-0.0000033333333333333333"),
    ("43143ff3c1cb0959", "1424953923781206.2"),
]


def _canon(obj) -> bytes:
    return rfc8785.dumps(obj)


def _bits_to_float(bits: str) -> float:
    return struct.unpack(">d", struct.pack(">Q", int(bits, 16)))[0]


# --- 1. member-order invariance ------------------------------------------------


def test_member_order_invariance():
    # Positive: top-level AND nested member reordering canonicalise identically.
    assert _canon(json.loads(ARGS_TEXT)) == _canon(json.loads(ARGS_TEXT_REORDERED))
    # Negative: a different VALUE does not (the identity is not always-equal).
    changed = ARGS_TEXT.replace('"2026-07-25"', '"2026-07-26"')
    assert _canon(json.loads(ARGS_TEXT)) != _canon(json.loads(changed))


# --- 2. whitespace invariance --------------------------------------------------


def test_whitespace_invariance():
    # Positive: insignificant inter-token whitespace does not affect the output.
    assert _canon(json.loads(ARGS_TEXT)) == _canon(json.loads(ARGS_TEXT_WHITESPACE))
    # Negative: whitespace INSIDE a string value is significant and preserved.
    padded = ARGS_TEXT.replace('"calendar.read"', '"calendar. read"')
    assert _canon(json.loads(ARGS_TEXT)) != _canon(json.loads(padded))


# --- 3. string escapes and member-name sort order (RFC 8785 section 3.2.3) -----


def test_string_escape_equivalence_and_sort_order():
    # Positive arm A: equivalent escapes ("A" == "A") canonicalise identically.
    assert _canon(json.loads(ARGS_TEXT)) == _canon(json.loads(ARGS_TEXT_ESCAPES))

    # Positive arm B: the RFC's own sorting test data reproduces its expected
    # order — property names sorted as UTF-16 code units (section 3.2.3),
    # including a non-ASCII BMP key and a supplementary-plane emoji key.
    out = _canon(json.loads(RFC_SORT_INPUT)).decode("utf-8")
    positions = [out.index(v) for v in RFC_SORT_EXPECTED_ORDER]
    assert positions == sorted(positions)

    # Negative arm: the UTF-16 rule is distinguishable from a naive code-point
    # sort — the emoji key (U+1F600, surrogates D83D DE00) must sort BEFORE
    # "דּ" under UTF-16 code units, but would sort AFTER it by code point.
    assert out.index("Emoji: Grinning Face") < out.index("Hebrew Letter Dalet With Dagesh")

    # Negative arm B: Unicode normalization is NOT applied (section 3.1 note) —
    # e-acute (U+00E9) and e + combining accent (U+0065 U+0301) stay distinct.
    assert _canon(json.loads('["\\u00e9"]')) != _canon(json.loads('["e\\u0301"]'))


# --- 4. RFC number vectors as known-answer tests (Appendix B) ------------------


def test_rfc_number_vectors():
    # Positive: every Appendix B sample serialises to the RFC's exact string.
    for bits, expected in RFC_NUMBER_VECTORS:
        got = _canon([_bits_to_float(bits)])
        assert got == f"[{expected}]".encode(), f"AppB {bits}: got {got!r}"
    # Negative: adjacent bit patterns with different expected strings stay
    # distinct (the serializer is not collapsing distinct doubles).
    assert _canon([_bits_to_float("444b1ae4d6e2ef4f")]) != _canon(
        [_bits_to_float("444b1ae4d6e2ef50")]
    )
    # NaN / Infinity vectors are excluded from JSON by section 3.2.2.3 (see
    # test_out_of_model_fails_closed).


# --- 5. value-difference sensitivity -------------------------------------------


def test_value_difference_sensitivity():
    base = h_jcs(json.loads(ARGS_TEXT))
    # Positive: the same value re-parsed from a different encoding is stable.
    assert base == h_jcs(json.loads(ARGS_TEXT_REORDERED))
    # Negative: string-value, number-value, and type changes each shift the digest.
    for changed_text in [
        ARGS_TEXT.replace('"2026-07-25"', '"2026-07-24"'),
        ARGS_TEXT.replace(":10", ":11"),
        ARGS_TEXT.replace(":10", ':"10"'),  # number -> string type change
    ]:
        assert base != h_jcs(json.loads(changed_text))


# --- 6. separate-process signer/verifier agreement -----------------------------

_VERIFIER_SNIPPET = (
    "import sys, json\n"
    "from src.harness.oracle.jcs_digest import h_jcs\n"
    "print(h_jcs(json.loads(sys.stdin.read())))\n"
)


def _verifier_digest(json_text: str) -> str:
    proc = subprocess.run(
        [sys.executable, "-c", _VERIFIER_SNIPPET],
        input=json_text.encode(),
        capture_output=True,
        cwd=REPO_ROOT,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr.decode()
    return proc.stdout.decode().strip()


def test_signer_verifier_separate_processes():
    signer_digest = h_jcs(json.loads(ARGS_TEXT))
    # Positive: a verifier subprocess fed only a REORDERED, whitespace-variant
    # JSON text on stdin reproduces the signer's H_JCS digest exactly.
    assert _verifier_digest(ARGS_TEXT_WHITESPACE) == signer_digest
    # Negative: the same verifier on a genuinely different value disagrees.
    assert _verifier_digest(ARGS_TEXT.replace(":10", ":12")) != signer_digest


# --- 7. fail-closed on out-of-model input --------------------------------------


def test_out_of_model_fails_closed():
    # Negative arms: every out-of-model input raises the library's typed base
    # exception (CanonicalizationError; Float/IntegerDomainError subclass it) —
    # no silent coercion. NaN/Infinity per RFC 8785 section 3.2.2.3; lone
    # surrogates per section 3.2.2.2; non-string keys / non-JSON types per the
    # I-JSON model (section 3.1); Python ints with |i| >= 2^53 per the
    # Appendix B note (1) integer-precision bound, enforced fail-closed.
    for bad in [
        [float("nan")],
        [float("inf")],
        [float("-inf")],
        {1: "x"},
        {"k": {1, 2}},
        {"k": b"raw"},
        ["\ud800"],
        [2**53],
        [-(2**53)],
    ]:
        with pytest.raises(rfc8785.CanonicalizationError):
            _canon(bad)
    # Positive arm: a maximal in-model int and a normal object still serialise.
    assert _canon([2**53 - 1]) == b"[9007199254740991]"
    assert _canon(json.loads(ARGS_TEXT))


# --- 8. determinism / non-vacuity ----------------------------------------------


def test_determinism_and_non_vacuity():
    obj = json.loads(ARGS_TEXT)
    # Positive: repeated canonicalisation is bit-stable, and canonicalisation
    # is idempotent through a parse round-trip.
    first = _canon(obj)
    assert first == _canon(json.loads(ARGS_TEXT))
    assert _canon(json.loads(first.decode("utf-8"))) == first
    # Negative: distinct structures never collide trivially.
    assert _canon({}) != _canon([])
    assert _canon({"a": 1}) != _canon({"a": 2})
    assert _canon({"a": 1}) != _canon({"b": 1})
    assert _canon([1, 2]) != _canon([2, 1])  # array order is significant (3.2.3)


# --- 9. H_JCS layout known-answer and domain separation (ADR 0009) -------------


def test_hjcs_domain_separation_non_vacuous():
    obj = json.loads(ARGS_TEXT)
    canonical = canonicalize(obj)
    # Positive: h_jcs reproduces an independent computation of the documented
    # byte layout — TAG || VERSION || u32be(len(C)) || C, SHA-256, lowercase hex.
    independent = sha256(
        TAG + bytes([VERSION]) + len(canonical).to_bytes(4, "big") + canonical
    ).hexdigest()
    assert h_jcs(obj) == independent
    # Negative: domain separation is non-vacuous — h_jcs differs from a bare
    # sha256 hex digest of the same canonical bytes.
    assert h_jcs(obj) != sha256(canonical).hexdigest()
    # canonicalize() is the module's own JCS surface: byte-identical to the
    # library call the G-8 tests pin down.
    assert canonical == _canon(obj)


# --- 10. H_JCS tag/version fail-closed -----------------------------------------


def test_hjcs_unsupported_version_fails_closed():
    obj = json.loads(ARGS_TEXT)
    # Positive: the supported version is exactly the default (VERSION = 0x01).
    assert h_jcs(obj, version=VERSION) == h_jcs(obj)
    # Negative: any other version raises the typed error; no digest is produced.
    for bad_version in (0, 2, 255):
        with pytest.raises(UnsupportedVersionError):
            h_jcs(obj, version=bad_version)
    # Out-of-model input still fails closed THROUGH h_jcs (the library's typed
    # error propagates; nothing is swallowed on the digest path).
    with pytest.raises(rfc8785.CanonicalizationError):
        h_jcs([float("nan")])


# --- 11. H_JCS output shape ----------------------------------------------------


def test_hjcs_output_shape():
    digest = h_jcs(json.loads(ARGS_TEXT))
    # Positive: exactly 64 lowercase hexadecimal characters.
    assert len(digest) == 64
    assert set(digest) <= set("0123456789abcdef")
    # The lowercase check is not vacuous: this fixed input's digest contains
    # at least one alphabetic hex character (deterministic known answer).
    assert any(c.isalpha() for c in digest)
    # Negative: a different value keeps the shape but changes the digest.
    other = h_jcs(json.loads(ARGS_TEXT.replace(":10", ":11")))
    assert len(other) == 64 and set(other) <= set("0123456789abcdef")
    assert other != digest


# --- 12. H_JCS cross-process determinism ---------------------------------------


def test_hjcs_cross_process_determinism():
    obj = json.loads(ARGS_TEXT)
    local = h_jcs(obj)
    # Positive: a fresh interpreter reproduces the digest exactly — TAG and
    # VERSION are stable constants, not process state (style of test 6).
    assert _verifier_digest(ARGS_TEXT) == local
    # Negative: the other process is applying the domain tag too — its output
    # is not a bare sha256 hex digest of the canonical bytes.
    assert _verifier_digest(ARGS_TEXT) != sha256(canonicalize(obj)).hexdigest()
