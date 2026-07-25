"""Gate G-8 feasibility spike — RFC 8785 JCS canonicalisation (IA-8).

Tests ONLY that RFC 8785 canonicalisation agrees across signer and
verifier (architecture doc SS F.4 IA-8), underwriting
INV.canonical_request_digest = H_JCS(raw_arguments) (SS F.2, the T-args
defence). It does NOT implement INV (that binding is G-11), does NOT
freeze the H_JCS hash-function/domain-tag construction (underspecified
in the doc; recorded as an open decision — see smoke/g8/REPORT.md), and
does NOT measure performance (G-3).

This is a SPIKE, not production code. Exits non-zero if any MANDATORY
check fails. The SHA-256 digests printed here are spike-local evidence
values; the frozen H_JCS construction is an open decision.

All RFC vectors are taken verbatim from RFC 8785 (sections 3.2.2-3.2.4
and Appendix B), never invented. Source is pure ASCII; non-ASCII data
appears only as JSON/Python escape sequences.

Reproduction (rfc8785==0.1.4 is pinned in pyproject.toml per ADR 0005;
the --with form reproduces the original pre-pin ephemeral run):

    uv run --with rfc8785==0.1.4 python smoke/g8/spike.py
    uv run python smoke/g8/spike.py
"""

import hashlib
import json
import struct
import subprocess
import sys

try:
    import rfc8785
except ImportError:
    print("rfc8785 not installed. Reproduce with:")
    print("  uv run --with rfc8785==0.1.4 python smoke/g8/spike.py")
    sys.exit(2)

RESULTS: list[tuple[str, bool, bool, str]] = []  # (check, mandatory, passed, evidence)


def record(check: str, mandatory: bool, passed: bool, evidence: str) -> None:
    RESULTS.append((check, mandatory, passed, evidence))
    status = "PASS" if passed else "FAIL"
    tag = "MANDATORY" if mandatory else "info"
    print(f"{check} [{tag}] {status} — {evidence}")


def canon(obj) -> bytes:
    return rfc8785.dumps(obj)


def digest(data: bytes) -> str:
    """Spike-local evidence digest (SHA-256 hex). NOT the frozen H_JCS."""
    return hashlib.sha256(data).hexdigest()


# --- Semantically identical pilot arguments, three encodings (G-8.A) ------------
# Same object as JSON text with: (1) one member order; (2) another member
# order incl. a reordered NESTED object, plus insignificant whitespace;
# (3) equivalent string escapes ("A" == "A", "é" == e-acute).
ARGS_TEXT_1 = '{"tool":"calendar.read","query":{"user":"A","day":"2026-07-25"},"limit":10}'
ARGS_TEXT_2 = (
    '{\n  "limit": 10,\n  "query": {"day": "2026-07-25", "user": "A"},\n'
    '  "tool": "calendar.read"\n}'
)
ARGS_TEXT_3 = '{"tool":"calendar.read","query":{"user":"\\u0041","day":"2026-07-25"},"limit":10}'


def g8_a_encoding_invariance() -> bytes:
    """G-8.A: member order / whitespace / escape variants canonicalise identically."""
    c1 = canon(json.loads(ARGS_TEXT_1))
    c2 = canon(json.loads(ARGS_TEXT_2))
    c3 = canon(json.loads(ARGS_TEXT_3))
    ok = c1 == c2 == c3 and digest(c1) == digest(c2) == digest(c3)
    record(
        "G-8.A",
        True,
        ok,
        f"three semantically identical encodings -> byte-identical canonical form "
        f"({c1!r}); spike-evidence sha256={digest(c1)}",
    )
    return c1


def g8_b_process_separation(signer_canonical: bytes) -> None:
    """G-8.B: a separate-process verifier, fed only JSON text on stdin, agrees.

    The verifier subprocess receives a DIFFERENT (reordered, whitespace-
    variant) JSON text of the same arguments — mirroring the G-1 test-9
    discipline: no shared in-process state, only serialized input.
    """
    verifier_src = (
        "import sys, json, hashlib, rfc8785\n"
        "data = rfc8785.dumps(json.loads(sys.stdin.read()))\n"
        "print(data.hex())\n"
        "print(hashlib.sha256(data).hexdigest())\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", verifier_src],
        input=ARGS_TEXT_2.encode(),
        capture_output=True,
        timeout=60,
    )
    lines = proc.stdout.decode().split()
    verifier_canonical = bytes.fromhex(lines[0]) if proc.returncode == 0 and lines else b""
    verifier_digest = lines[1] if proc.returncode == 0 and len(lines) > 1 else "<none>"
    ok = (
        proc.returncode == 0
        and verifier_canonical == signer_canonical
        and verifier_digest == digest(signer_canonical)
    )
    record(
        "G-8.B",
        True,
        ok,
        f"verifier subprocess (stdin=reordered JSON text only) exit={proc.returncode}; "
        f"canonical bytes identical={verifier_canonical == signer_canonical}; "
        f"digest equal={verifier_digest == digest(signer_canonical)} ({verifier_digest})",
    )


# --- RFC-provided vectors (G-8.C) ----------------------------------------------
# RFC 8785 section 3.2.2 sample (JSON escapes verbatim; backslashes doubled
# for Python) and its section 3.2.4 canonical UTF-8 bytes.
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
# RFC 8785 section 3.2.3 sorting test data and expected value order.
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
# RFC 8785 Appendix B Table 1 (IEEE 754 bit pattern -> exact JSON string).
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


def g8_c_rfc_vectors() -> None:
    """G-8.C: the RFC's own vectors reproduce exactly (bytes, sorting, numbers)."""
    got_bytes = canon(json.loads(RFC_SAMPLE_INPUT))
    bytes_ok = got_bytes == RFC_EXPECTED_BYTES

    out = canon(json.loads(RFC_SORT_INPUT)).decode("utf-8")
    positions = [out.index(v) for v in RFC_SORT_EXPECTED_ORDER]
    sort_ok = positions == sorted(positions)

    failures = []
    for bits, expected in RFC_NUMBER_VECTORS:
        value = struct.unpack(">d", struct.pack(">Q", int(bits, 16)))[0]
        got = canon([value])
        if got != f"[{expected}]".encode():
            failures.append(f"{bits}: got {got!r}")
    numbers_ok = not failures

    ok = bytes_ok and sort_ok and numbers_ok
    record(
        "G-8.C",
        True,
        ok,
        f"3.2.4 byte vector reproduced={bytes_ok} "
        f"(sha256={digest(got_bytes)}); 3.2.3 sort order reproduced={sort_ok} "
        f"(UTF-16 code-unit order incl. supplementary-plane emoji key); Appendix B "
        f"numbers {len(RFC_NUMBER_VECTORS) - len(failures)}/{len(RFC_NUMBER_VECTORS)}"
        + (f"; failures: {failures}" if failures else ""),
    )


def g8_d_value_sensitivity() -> None:
    """G-8.D: a genuine value difference yields a different digest (non-vacuity)."""
    base = canon(json.loads(ARGS_TEXT_1))
    changed_value = canon(
        json.loads(ARGS_TEXT_1.replace('"day":"2026-07-25"', '"day":"2026-07-26"'))
    )
    changed_number = canon(json.loads(ARGS_TEXT_1.replace("10", "11")))
    ok = digest(base) != digest(changed_value) and digest(base) != digest(changed_number)
    record(
        "G-8.D",
        True,
        ok,
        f"changed string value -> digest differs ({digest(changed_value)[:16]}...); "
        f"changed number -> digest differs ({digest(changed_number)[:16]}...); "
        f"base={digest(base)[:16]}... — the identity is neither always-equal nor "
        f"always-different",
    )


def g8_e_fail_closed() -> None:
    """G-8.E: out-of-model inputs fail closed with a typed exception, no coercion."""
    cases = [
        ("NaN", [float("nan")]),
        ("Infinity", [float("inf")]),
        ("-Infinity", [float("-inf")]),
        ("non-string key", {1: "x"}),
        ("non-JSON type (set)", {"k": {1, 2}}),
        ("non-JSON type (bytes)", {"k": b"raw"}),
        ("lone surrogate", ["\ud800"]),
    ]
    outcomes = []
    all_rejected = True
    for name, bad in cases:
        try:
            got = canon(bad)
            all_rejected = False
            outcomes.append(f"{name}: ACCEPTED ({got!r})")
        except Exception as exc:  # noqa: BLE001 — the spike records any raise as fail-closed
            outcomes.append(f"{name}: {type(exc).__name__}")
    record("G-8.E", True, all_rejected, "; ".join(outcomes))


def main() -> int:
    print("Gate G-8 spike — RFC 8785 JCS canonicalisation via rfc8785 0.1.4")
    print("Vectors verbatim from RFC 8785; pilot arguments are throwaway, NOT Omega.\n")

    signer_canonical = g8_a_encoding_invariance()
    g8_b_process_separation(signer_canonical)
    g8_c_rfc_vectors()
    g8_d_value_sensitivity()
    g8_e_fail_closed()

    mandatory_failures = [c for c, mandatory, passed, _ in RESULTS if mandatory and not passed]
    print()
    if mandatory_failures:
        print(f"GATE G-8: FAIL — mandatory check(s) failed: {', '.join(mandatory_failures)}")
        print(
            "Per SMOKE_G8_G5_TASK STEP 1: write the FAIL report, set the board row, "
            "commit the docs, STOP the whole pass."
        )
        return 1
    print("GATE G-8: all mandatory checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
