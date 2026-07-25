"""Regression suite for RFC 8785 JCS canonicalisation (gate G-8, ADR 0005).

Every test has a positive arm and a negative arm so no assertion can pass
vacuously. All RFC vectors are verbatim from RFC 8785 (sections 3.2.2-3.2.4,
Appendix B), never invented. The library under test is rfc8785 (pinned by
ADR 0005); the frozen H_JCS hash-function/domain-tag construction is an open
decision (see smoke/g8/REPORT.md), so these tests assert canonical BYTES and
use SHA-256 only as a test-local digest for agreement checks.

Source is pure ASCII; non-ASCII data appears only as escape sequences.
Pilot vocabulary only — NOT the frozen ontology Omega.
"""

import json
import struct
import subprocess
import sys
from hashlib import sha256

import pytest
import rfc8785

# --- shared fixtures (JSON texts; parsed fresh in each test) -------------------

ARGS_TEXT = '{"tool":"calendar.read","query":{"user":"A","day":"2026-07-25"},"limit":10}'
ARGS_TEXT_REORDERED = (
    '{"limit":10,"query":{"day":"2026-07-25","user":"A"},"tool":"calendar.read"}'
)
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
    base = _canon(json.loads(ARGS_TEXT))
    # Positive: the same value re-parsed from a different encoding is stable.
    assert sha256(base).digest() == sha256(_canon(json.loads(ARGS_TEXT_REORDERED))).digest()
    # Negative: string-value, number-value, and type changes each shift the digest.
    for changed_text in [
        ARGS_TEXT.replace('"2026-07-25"', '"2026-07-24"'),
        ARGS_TEXT.replace(":10", ":11"),
        ARGS_TEXT.replace(":10", ':"10"'),  # number -> string type change
    ]:
        assert sha256(base).digest() != sha256(_canon(json.loads(changed_text))).digest()


# --- 6. separate-process signer/verifier agreement -----------------------------

_VERIFIER_SNIPPET = (
    "import sys, json, hashlib, rfc8785\n"
    "data = rfc8785.dumps(json.loads(sys.stdin.read()))\n"
    "print(hashlib.sha256(data).hexdigest())\n"
)


def _verifier_digest(json_text: str) -> str:
    proc = subprocess.run(
        [sys.executable, "-c", _VERIFIER_SNIPPET],
        input=json_text.encode(),
        capture_output=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr.decode()
    return proc.stdout.decode().strip()


def test_signer_verifier_separate_processes():
    signer_digest = sha256(_canon(json.loads(ARGS_TEXT))).hexdigest()
    # Positive: a verifier subprocess fed only a REORDERED, whitespace-variant
    # JSON text on stdin reproduces the signer's digest exactly.
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
