# 0006 — DPoP/JOSE library: adopt joserfc 1.7.4 for the G-5-verified JOSE surface

## Context

Gate G-5 (`docs/EXPERIMENT_ARCHITECTURE_FINAL.md` Part G) tests IA-5 — "A DPoP-bound (cnf/jkt)
access token can be issued/verified in the local AS" (§F.4). In this pass issuance is **simulated
locally** (a mint function inside the spike); the real AS is gate G-4. The DPoP-specific
validation logic (RFC 9449 §4.3) is written in the spike/tests; the pinned dependency is the
**minimal JOSE library** sufficient to construct and verify DPoP proof JWTs, preferring
Ed25519 (the project-wide signature choice). Candidates, all checked at runtime against the
RFC 8037 A.3 known-answer thumbprint and an Ed25519 DPoP-shaped sign/verify round trip — full
evidence: `smoke/g5/REPORT.md`:

| Candidate | Verdict |
|---|---|
| **`joserfc`** 1.7.4 | **Chosen.** JOSE-only (JWS/JWE/JWK/JWA/JWT), by the authlib author; BSD-3-Clause; typed; stable 1.x; pure-Python wheel; repo pushed 2026-07-25 (the day of this gate). RFC 8037 A.3 thumbprint known answer reproduced (`OKPKey.thumbprint()`); Ed25519 sign/verify with the header-embedded `jwk`; wrong-key and tampered tokens rejected with a typed `BadSignatureError`. Supports the **RFC 9864 fully-specified `Ed25519` JWS algorithm identifier** (the polymorphic `EdDSA` identifier is deprecated by RFC 9864 — joserfc itself warns on it); its default registry excludes non-recommended algorithms per RFC 8725 hygiene, so every call sites an explicit `algorithms=["Ed25519"]` allowlist — a fail-closed default we keep. |
| `jwcrypto` 1.5.8 | Rejected. Functionally conformant in the probe (thumbprint known answer, Ed25519 round trip, wrong-key reject) and maintained — but **LGPL-3.0** (licence friction against this MIT project when a BSD-3 alternative is equally capable) and untyped. |
| `PyJWT` 2.13.0 | Rejected. MIT and maintained; Ed25519 DPoP-shaped sign/verify works — but it **does not expose an RFC 7638 thumbprint** (`PyJWK` has no `thumbprint()` in 2.13.0), so the security-critical jkt computation would have to be hand-rolled. |
| `authlib` 1.7.2 | Rejected for this gate. Not minimal (a full OAuth/OIDC stack); pinning it here would blur the pin's meaning against the **G-4-pending** RFC 8693 + RFC 9396 surface (`# PENDING GATE` line stays). It remains the G-4 candidate. |

## Decision

[DESIGN] **Adopt `joserfc==1.7.4`, pinned exactly**, for **exactly the G-5-verified JOSE/DPoP
surface**: JWS compact serialize/deserialize with `alg=Ed25519` under an explicit allowlist,
OKP (Ed25519) JWK generate/import/export, and RFC 7638 SHA-256 thumbprints. A pin never asserts
more than its gate verified; nothing about RFC 8693/9396 is claimed (that is G-4, and the
`authlib → G-4` pending line is unchanged).

[VERIFIED, gate G-5] For exactly `joserfc==1.7.4` and exactly what ran: jkt computation per
RFC 7638/RFC 8037 (library and an independent implementation agree; RFC 8037 A.3 known answer
reproduced in base64url and hex), local mint of a `cnf`/`jkt`-bound token (issuer key ≠ holder
key; issuer private key frame-local), DPoP proof verification per RFC 9449 §4.3 items 3–9 and 11
plus the §6.1 thumbprint binding, wrong-holder rejection **specifically at the
`cnf.jkt` ↔ proof-`jwk` comparison**, independent `htm`/`htu` mismatch rejection, and a
negative control (the valid proof still verifies).

[VERIFIED, RFC 9449 §4.2] The DPoP proof covers the HTTP method and target URI only ("only
these two message parts are covered by the DPoP proof") — the standing architecture-document
claim is confirmed against the RFC text. `ath` is REQUIRED only when the proof accompanies an
access token at a protected resource (§4.2) and `nonce` only when the server issued one
(§4.2, §§8–9); both are out of scope of this simulated-issuance gate and are re-exercised with
the real AS (G-4) and the replay taxonomy (G-14).

## Status

accepted — 2026-07-25

## Consequences

- **The pin is exact; any version bump of `joserfc` re-triggers G-5.**
- The `DPoP / JOSE library → gate G-5` line is removed from the `# PENDING GATE` block;
  the `authlib → G-4` line stays (authlib was not pinned).
- All signing uses the RFC 9864 `Ed25519` identifier with an explicit algorithm allowlist at
  every call site; the deprecated polymorphic `EdDSA` identifier is not used.
- `uv.lock` regenerated; `uv sync --frozen` verified. No Dockerfile or CI change.
- §F.4 IA-5 → verified-by-gate with residuals; smoke board row G-5 → PASS (same pass).
- The production DPoP verifier for the B2-DPoP arm is built later and re-tested at G-11/G-14;
  the spike/test verifier is the reference for its checks. The G-4 AS must issue real
  `cnf`/`jkt` tokens; if authlib cannot realize the profile, the G-4 fallback applies
  (build a behaviourally faithful AS — ADR 0004).
