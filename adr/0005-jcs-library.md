# 0005 — JCS library: adopt rfc8785 0.1.4 for RFC 8785 canonicalisation (gate G-8)

## Context

Gate G-8 (`docs/EXPERIMENT_ARCHITECTURE_FINAL.md` Part G) tests IA-8 — "RFC 8785 JCS
canonicalization agrees across signer and verifier" (§F.4) — which underwrites
`INV.canonical_request_digest = H_JCS(raw_arguments)` (§F.2), the T-args defence. Candidates on
PyPI, evaluated against RFC 8785's **own** vectors (§3.2.3 sorting test data, the §3.2.4 canonical
byte vector, the Appendix B number table) at runtime — full evidence: `smoke/g8/REPORT.md`:

| Candidate | Verdict |
|---|---|
| **`rfc8785`** 0.1.4 | **Chosen.** Trail of Bits; pure Python (`py3-none-any` wheel, no toolchain anywhere); Apache-2.0; typed (`py.typed`); repo pushed 2026-07-24 (the day before this gate) — actively maintained. **Conformant on every vector run:** §3.2.4 byte vector reproduced exactly, §3.2.3 UTF-16 code-unit sort order reproduced (including the supplementary-plane emoji key), Appendix B numbers 24/24. Fails closed with a typed exception hierarchy (`CanonicalizationError` base; `FloatDomainError`/`IntegerDomainError` subclasses) on NaN/Infinity, lone surrogates, non-string keys, and non-JSON types — no silent coercion. |
| `jcs` 0.2.1 | Rejected. Conformant on the same vectors, but unmaintained (last release and last repo push 2022-04-10), and out-of-model inputs fail incidentally (`AttributeError` on a non-string key) rather than by design — unacceptable for a fail-closed boundary dependency. |
| `canonicaljson` 2.0.0 | Rejected — **demonstrated non-conformant to RFC 8785** (it implements Matrix canonical JSON, a different algorithm): 10/24 Appendix B number vectors fail (repr-style floats, e.g. `1e-06` for `0.000001`, `9007199254740992.0` for `9007199254740992`), the §3.2.3 sort order fails on the supplementary-plane key (code-point sort, not UTF-16 code units), and a non-string key is silently coerced. |

## Decision

[DESIGN] **Adopt `rfc8785==0.1.4`, pinned exactly** in `[project].dependencies`, as the JCS
canonicalisation dependency for both the spike and the permanent regression suite
(`tests/test_jcs_canonicalization.py`). Hand-rolling JCS (fallback of last resort) is not needed:
a conformant, maintained, pure-Python library exists; the ES6 number-serialisation edge cases it
gets right (Appendix B 24/24) are exactly the part a hand-rolled implementation would most likely
get wrong.

[VERIFIED, gate G-8] For exactly `rfc8785==0.1.4` and exactly what ran: encoding-invariant
canonicalisation (member order, insignificant whitespace, equivalent escapes), separate-process
signer/verifier agreement, RFC vector conformance, value-difference sensitivity, and fail-closed
rejection of out-of-model input.

**Not decided here:** the frozen `H_JCS` construction (hash function, domain tag, digest string
encoding) is **underspecified in the architecture document** and is deliberately **not**
invented; no `src/harness/oracle/jcs_digest.py` is created. The gap is recorded as an open
decision in `smoke/g8/REPORT.md` §9 for the Commander.

## Status

accepted — 2026-07-25

## Consequences

- **The pin is exact; any version bump of `rfc8785` re-triggers G-8** (0.1.x, Development Status
  "Beta" — same 0.x discipline as the biscuit-python pin, ADR 0002).
- Library behaviour note (conservative, fail-closed, recorded): Python `int` inputs with
  `|i| >= 2^53` raise `IntegerDomainError` — the library enforces RFC 8785 Appendix B note (1)'s
  integer-precision SHOULD as a hard bound instead of silently losing precision. In-model floats
  (e.g. IEEE-754 `2^53`) serialise per the Appendix B table. Fixture authors must keep integer
  arguments within `±(2^53 − 1)`.
- `uv.lock` regenerated; `uv sync --frozen` verified. No Dockerfile or CI change (pure-Python
  wheel).
- §F.4 IA-8 row → verified-by-gate with residuals; smoke board row G-8 → PASS (same pass, never
  silent).
- The SUT-side canonicalisation at implementation time must be an **independent** computation
  from the oracle's (D21 obligation, as in ADR 0003); both may use the same pinned library, but
  the oracle never consumes a SUT-computed digest (§F.1).
