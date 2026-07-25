# Gate G-8 Report — RFC 8785 JCS canonicalisation

## 1. Gate

- **Gate:** G-8 (feasibility spike, first tier of the Part G DAG: `G-1 / G-5 / G-8 → …`)
- **Assumption tested:** IA-8 — *"RFC 8785 JCS canonicalization agrees across signer and
  verifier"* (`docs/EXPERIMENT_ARCHITECTURE_FINAL.md` §F.4). Pass criterion (Part G):
  canonicalise identical arguments on signer and verifier; digests **byte-identical**. This
  underwrites `INV.canonical_request_digest = H_JCS(raw_arguments)` (§F.2) — the T-args defence.
- **Date:** 2026-07-25.
- **Blocks on failure:** IA-8; invocation binding (T-args); the F3 body-mutation distinction.

## 2. Primary-source verification (RFC 8785, read in full)

Claims relied on, each checked against the RFC text itself:

- The scheme produces a canonical, "hashable" representation for cryptographic methods
  **[VERIFIED, RFC 8785 §1]**; input is constrained to the I-JSON subset: no duplicate property
  names, strings expressible as Unicode, numbers expressible as IEEE 754 doubles
  **[VERIFIED, §3.1]**.
- Whitespace between tokens MUST NOT be emitted **[VERIFIED, §3.2.1]**.
- String serialisation: control characters U+0000–U+001F as lowercase `\uhhhh` except the
  predefined `\b \t \n \f \r`; everything else "as is" except `\` and `"`; lone surrogates MUST
  terminate with an error **[VERIFIED, §3.2.2.2]**. Unicode normalization is NOT applied
  **[VERIFIED, §3.1 note]**.
- Number serialisation follows ECMA-262 §7.1.12.1 including the "Note 2" enhancement; NaN and
  Infinity MUST terminate with an error **[VERIFIED, §3.2.2.3]**.
- Property sorting is recursive; array element order MUST NOT change; names are sorted in their
  raw (unescaped) form as arrays of **UTF-16 code units** compared as unsigned integers
  **[VERIFIED, §3.2.3]**. Output is UTF-8 **[VERIFIED, §3.2.4]**.
- Test vectors taken **from the RFC's own text**: the §3.2.2 sample object with its §3.2.4
  canonical UTF-8 byte dump; the §3.2.3 sorting test data with its expected order; the Appendix B
  Table 1 number samples given as IEEE 754 bit patterns (used bit-exact via `struct`).

## 3. Library discovery (G-1 §2 discipline)

| Candidate | Verdict |
|---|---|
| **`rfc8785`** | **Chosen and adopted (ADR 0005).** 0.1.4 (2024-09-27), Trail of Bits, Apache-2.0, pure Python (`py3-none-any` wheel — no toolchain change anywhere), typed (`py.typed` present), docs site, repo `trailofbits/rfc8785.py` pushed 2026-07-24 — actively maintained. **Runtime conformance: every RFC vector passed** (§3.2.4 byte vector exact; §3.2.3 sort order exact incl. the supplementary-plane emoji key; Appendix B 24/24). Typed fail-closed exceptions: `CanonicalizationError` (base, a `ValueError`), `FloatDomainError`, `IntegerDomainError`. |
| `jcs` | Rejected. 0.2.1 (2022-04-10) — unmaintained for over four years (repo last pushed 2022-04-10). Conformant on the vectors run, but out-of-model input fails **incidentally** (non-string key → `AttributeError: 'int' object has no attribute 'encode'`), not by design — wrong failure mode for a fail-closed boundary dependency. |
| `canonicaljson` | Rejected — **demonstrated non-conformant with RFC 8785** (it implements Matrix canonical JSON, a different algorithm, exactly as the task warned). Probe evidence: 10/24 Appendix B vectors fail (`[0.0]` for zero, `[9007199254740992.0]`, `[2.9514790517935283e+20]` instead of `295147905179352830000`, `[1e-06]` instead of `0.000001`, `[9.999999999999997e-07]` instead of `9.999999999999997e-7`); §3.2.3 sort order wrong for the emoji key (code-point order, not UTF-16 code units); non-string key `{1: "x"}` silently coerced to `{"1":"x"}`. Maintained (repo pushed 2026-05-06) but the wrong algorithm. |

Discovery method: PyPI JSON API (versions, wheels, licences, classifiers), GitHub repo API
(activity, archived flag), and a runtime conformance probe executing all three candidates against
the RFC's own vectors. Hand-rolling JCS (the last-resort fallback) was not needed.

## 4. Results

Passing run: `uv run --with rfc8785==0.1.4 python smoke/g8/spike.py` → **exit code 0**; re-run
inside the locked environment after the pin (`uv run python smoke/g8/spike.py`) → **exit code 0**.

| Check | Mandatory | Result | Evidence |
|---|:---:|:---:|---|
| G-8.A encoding invariance | yes | **PASS** | three semantically identical encodings (member reorder incl. nested; insignificant whitespace; `A` escape) → **byte-identical** canonical form `{"limit":10,"query":{"day":"2026-07-25","user":"A"},"tool":"calendar.read"}`; spike-evidence sha256 `1892de68e8ea76aeebd3293846b1911471c7efbb53d501021f4ada6e6840648e` |
| G-8.B separate-process signer/verifier | yes | **PASS** | verifier subprocess received **only reordered JSON text on stdin**, exit 0; canonical bytes identical=True; digest equal=True (`1892de68…` both sides) — mirrors the G-1 test-9 discipline |
| G-8.C RFC vectors | yes | **PASS** | §3.2.4 byte vector reproduced exactly (sha256 `2d5e01a318d0f0879ab568c4be289c8b1f64ef8921a53c6277d5e069978baacb`); §3.2.3 sort order reproduced (UTF-16 code-unit order incl. emoji key); Appendix B numbers **24/24** |
| G-8.D value sensitivity | yes | **PASS** | changed string value → digest differs (`7f887837…`); changed number → digest differs (`6d2ff510…`); base `1892de68…` — neither always-equal nor always-different |
| G-8.E fail-closed | yes | **PASS** | NaN/Infinity/−Infinity → `FloatDomainError`; non-string key, set, bytes, lone surrogate → `CanonicalizationError` — typed exceptions, no silent coercion |

Permanent regression suite `tests/test_jcs_canonicalization.py` — **8 tests, 8 passed**
(`8 passed` in the locked environment), each with positive and negative arms: (1) member-order
invariance; (2) whitespace invariance; (3) escape equivalence + §3.2.3 sort order incl. the
UTF-16-vs-code-point distinguishing case and the no-normalization case; (4) Appendix B
known-answer vectors; (5) value-difference sensitivity; (6) separate-process agreement;
(7) fail-closed on out-of-model input (incl. the `|int| ≥ 2^53` bound); (8) determinism,
idempotence through a parse round-trip, non-vacuity.

## 5. Outcome

**PASS** — all five mandatory spike checks and all eight regression tests green; `rfc8785==0.1.4`
pinned (ADR 0005).

## 6. Consequences for the design

- `rfc8785==0.1.4` pinned exactly in `pyproject.toml`; `uv.lock` regenerated;
  `uv sync --frozen` verified. No Dockerfile or CI change.
- §F.4 IA-8 → verified-by-gate with residuals; smoke board G-8 → PASS (same pass).
- Fixture-authoring constraint (ADR 0005): integer arguments must stay within `±(2^53 − 1)` —
  larger Python ints are rejected fail-closed (`IntegerDomainError`), never silently rounded.

## 7. Reproduction

```
uv run --with rfc8785==0.1.4 python smoke/g8/spike.py    # pre-pin form, works always
uv run python smoke/g8/spike.py                          # after the ADR 0005 pin
make gate GATE=g8                                        # equivalent, via the venv
uv run pytest tests/test_jcs_canonicalization.py -q      # permanent suite
```

## 8. Residual risks

- `rfc8785` is at **0.1.4 — a 0.x API**, Development Status "Beta". The pin is exact; **any
  version bump re-triggers G-8** (the regression suite is the re-trigger harness).
- The library enforces the Appendix B note (1) integer bound (`|int| < 2^53`) as a hard error —
  conservative and fail-closed, but stricter than some other JCS implementations; disclosed to
  fixture authors.
- RFC 8785 is an **Informational** (Independent Submission) RFC, not a Standards Track document;
  it is nonetheless the de-facto JCS reference, is what §F.2 names, and its conformance is
  empirically vector-tested here.

## 9. What this gate does NOT establish

- **Not** the frozen `H_JCS` construction. The architecture document specifies the
  canonicalisation (RFC 8785) but **not** the digest construction over it: §F.2
  (`canonical_request_digest: H_JCS(raw_arguments)`) and Part I (`oracle_digest =
  H_JCS(obs.raw_arguments)`) name no hash function (SHA-256 is named only in §A.0.1, which scopes
  itself to capability-state commitments); no domain tag is stated for digests (§F.2's domain-tag
  MUST covers HTC/INV **signatures**); and the string encoding of `intended_request_digest` /
  `effect_request_digest` (hex vs base64url) is unspecified. Per the task's no-invention rule, no
  `src/harness/oracle/jcs_digest.py` was created; **open decision for the Commander** (spike and
  tests assert canonical bytes and use SHA-256 only as test-local evidence).
- **Not** the full INV binding (`capability_hash`, `access_token_hash`, tool/method/audience,
  windows) — that is **G-11**; INV is not implemented.
- **Not** mediation (G-6), the effect ledger (G-7), or any performance property (G-3).
- **Not** the frozen ontology `Ω` — the spike's arguments are throwaway pilot values.
