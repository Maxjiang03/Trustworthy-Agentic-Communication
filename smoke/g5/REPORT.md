# Gate G-5 Report — DPoP-bound token issuance and verification

## 1. Gate

- **Gate:** G-5 (feasibility spike, first tier of the Part G DAG: `G-1 / G-5 / G-8 → …`)
- **Assumption tested:** IA-5 — *"A DPoP-bound (cnf/jkt) access token can be issued/verified in
  the local AS"* (`docs/EXPERIMENT_ARCHITECTURE_FINAL.md` §F.4). Pass criterion (Part G):
  issue/verify a DPoP-bound (`cnf`/`jkt`) token; proof over method+URI; reject a wrong-holder
  proof. **"The local AS" is simulated locally in this pass** (a mint function inside the
  spike); the real AS integration is re-exercised at G-4.
- **Date:** 2026-07-25.
- **Blocks on failure:** IA-5; the DPoP arm (B2-exchange-task-DPoP, D34) and H4a.

## 2. Primary-source verification (RFC texts read directly)

- **RFC 9449 §4.2:** DPoP proof JWT header MUST contain `typ` (= `dpop+jwt`), `alg` (asymmetric,
  not `none`, no MAC), `jwk` (public key; MUST NOT contain a private key); payload MUST contain
  `jti` (≥ 96 bits randomness guidance), `htm`, `htu`, `iat` **[VERIFIED]**. *"Of the HTTP
  request, only the HTTP method and URI are included in the DPoP JWT; therefore, only these two
  message parts are covered by the DPoP proof"* **[VERIFIED, §4.2]** — the architecture
  document's standing method+URI-only claim is confirmed verbatim; DPoP does **not** bind tool
  or body (that is INV's role, §C/Part D — not tested here).
- **RFC 9449 §4.2 (conditional claims):** `ath` (base64url SHA-256 of the access token) is
  REQUIRED **only** when the proof accompanies an access token at a protected resource; `nonce`
  is REQUIRED **only** when the server provided one via `DPoP-Nonce` (optional mechanism,
  §§8–9) **[VERIFIED]**. Both are out of scope of this simulated-issuance gate — recorded as
  residuals re-exercised at G-4 (real AS/RS flow) and G-14 (replay taxonomy).
- **RFC 9449 §4.3:** the server-side validation list (items 1–12); this gate implements items
  3–9 and 11 plus item 12's key-binding bullet **[VERIFIED]**.
- **RFC 9449 §6/§6.1:** the RS MUST ensure the proof public key matches the token-bound key;
  `jkt` = base64url encoding of the RFC 7638 JWK SHA-256 Thumbprint of the DPoP public key,
  carried under the RFC 7800 `cnf` claim **[VERIFIED]**.
- **RFC 7800 §3.1:** `cnf` is the JWT confirmation-claim container **[VERIFIED]**.
- **RFC 7638 §3/§3.2/§3.3:** thumbprint = hash of the UTF-8 octets of a JSON object containing
  **only the required members** of the key, **lexicographically ordered**, with no whitespace
  **[VERIFIED]**.
- **RFC 8037 §2:** OKP key type; for thumbprints the three public fields are included in
  lexicographic order `crv`, `kty`, `x` **[VERIFIED]**. **Appendix A.3 provides a known-answer
  OKP thumbprint** for the A.2 Ed25519 key: canonical form
  `{"crv":"Ed25519","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`, SHA-256
  hex `90facafea9b1556698540f70c0117a22ea37bd5cf3ed3c47093c1707282b4b89`, base64url
  `kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k` **[VERIFIED]** — used as the known-answer test
  (G-5.A), not constructed by hand.
- **RFC 9864 (via the library's own warning, then confirmed):** the polymorphic `EdDSA` JWS
  identifier is deprecated in favour of fully-specified `Ed25519`/`Ed448`; the spike uses
  `alg=Ed25519` with an explicit allowlist.

## 3. Library discovery (G-1 §2 discipline)

Selection rule: the **minimal** JOSE library sufficient for DPoP proof JWTs, preferring
Ed25519. The DPoP validation logic itself is written in the spike/tests (a small profile over
JWS); the pin is the JOSE dependency.

| Candidate | Verdict |
|---|---|
| **`joserfc`** | **Chosen and adopted (ADR 0006).** 1.7.4 (2026-07-19), JOSE-only, BSD-3-Clause, typed, pure-Python wheel, repo `authlib/joserfc` pushed 2026-07-25. Probe: RFC 8037 A.3 thumbprint known answer reproduced; Ed25519 DPoP-shaped JWT signed and verified under the header-embedded `jwk`; wrong-key and tampered inputs rejected with typed `BadSignatureError`; `as_dict(private=False)` never leaks `d`. Supports the RFC 9864 `Ed25519` identifier; default registry excludes non-recommended algorithms (RFC 8725 hygiene) so all calls use an explicit `algorithms=["Ed25519"]` allowlist. |
| `jwcrypto` | Rejected. Probe fully conformant (thumbprint known answer, Ed25519 round trip, wrong-key reject) and maintained (1.5.8, repo pushed 2026-07-20) — but **LGPL-3.0** against this MIT project when an equally capable BSD-3 library exists, and untyped. |
| `PyJWT` | Rejected. 2.13.0, MIT, maintained; Ed25519 DPoP-shaped sign/verify passed — but **no RFC 7638 thumbprint API** (`PyJWK.thumbprint` absent), so the security-critical `jkt` computation would be hand-rolled. |
| `authlib` (JOSE surface) | Rejected for this gate: not minimal (full OAuth/OIDC stack), and pinning it here would entangle the **G-4-pending** RFC 8693 + RFC 9396 surface. Remains the G-4 candidate; the `# PENDING GATE` authlib line stays. |

Discovery method: PyPI JSON API, GitHub repo API, runtime probes of all candidates against the
RFC 8037 A.3 known answer and an Ed25519 DPoP-shaped round trip.

## 4. Results

Passing run: `uv run --with joserfc==1.7.4 python smoke/g5/spike.py` → **exit code 0**; re-run
inside the locked environment after the pin → **exit code 0**.

| Check | Mandatory | Result | Evidence |
|---|:---:|:---:|---|
| G-5.A jkt + known answer | yes | **PASS** | holder keypair generated; library `thumbprint()` == independent RFC 7638 computation; RFC 8037 A.3 known answer reproduced by **both** paths (`kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k`; SHA-256 hex `90facafe…2b4b89`) |
| G-5.B local mint | yes | **PASS** | token verified under the issuer public key; `cnf.jkt` == holder thumbprint; issuer key ≠ holder key; issuer private key never left the mint frame (structural, G-1 discipline) |
| G-5.C valid proof | yes | **PASS** | proof (`typ=dpop+jwt`, `alg=Ed25519`, header `jwk`; `jti`/`htm`/`htu`/`iat`) verified: signature under its own header key, typ, htm, htu, `iat` within an explicit ±300 s window (§4.3 item 11), `jti` present, thumbprint(jwk) == `cnf.jkt` → reason `ok` |
| G-5.D wrong holder | yes | **PASS** | attacker-keypair proof over the **same** htm/htu (internally valid signature) rejected **specifically** at reason `cnf_jkt_mismatch` — the thumbprint comparison, not an incidental failure |
| G-5.E htm/htu mismatch | yes | **PASS** | `htm` mismatch rejected (reason `htm_mismatch`); `htu` mismatch rejected (reason `htu_mismatch`) — each independently, with all other conjuncts valid |
| G-5.F negative control | yes | **PASS** | the G-5.C proof re-verifies after D/E (reason `ok`) — the rejection logic is not rejecting everything |

Permanent regression suite `tests/test_dpop_binding.py` — **6 tests, 6 passed**, positive and
negative arms, test-local helpers only (no `src/` module this pass — the production verifier is
built with the B2-DPoP arm and re-tested at G-11/G-14): valid-proof verify (+ tampered-proof
fail-closed), wrong-holder reject (+ legitimate-holder pass), `htm` reject, `htu` reject,
`cnf.jkt` mismatch reject (token bound to a different key), thumbprint known-answer/determinism.

## 5. Outcome

**PASS** — all six mandatory spike checks and all six regression tests green; `joserfc==1.7.4`
pinned for exactly the G-5-verified JOSE surface (ADR 0006).

## 6. Consequences for the design

- `joserfc==1.7.4` pinned; the `DPoP / JOSE library → gate G-5` line removed from the
  `# PENDING GATE` block; **the `authlib → G-4` line stays** (authlib not pinned). `uv.lock`
  regenerated; `uv sync --frozen` verified.
- §F.4 IA-5 → verified-by-gate with residuals; smoke board G-5 → PASS (same pass).
- Project signing uses the RFC 9864 `Ed25519` JWS identifier with explicit allowlists.

## 7. Reproduction

```
uv run --with joserfc==1.7.4 python smoke/g5/spike.py    # pre-pin form, works always
uv run python smoke/g5/spike.py                          # after the ADR 0006 pin
make gate GATE=g5                                        # equivalent, via the venv
uv run pytest tests/test_dpop_binding.py -q              # permanent suite
```

## 8. Residual risks

- The AS is **simulated** (frame-local mint). Everything about a real issuance flow — token
  endpoint semantics, `ath` at the resource server, nonce challenges, RFC 8693/9396 — remains
  **[UNVERIFIED-IA]** until **G-4**.
- `joserfc` is 1.x (stable), but the pin is exact and **any bump re-triggers G-5**.
- The verifier here checks `htu` by exact string comparison; RFC 9449 §4.3 additionally
  recommends RFC 3986 syntax-/scheme-based normalization before comparing `htu` — a production
  concern for the B2-DPoP arm build, noted for G-11/G-14.
- Ed25519 (RFC 8037) is used for DPoP proofs per the project-wide signature choice; ecosystem
  DPoP examples typically use ES256 — interop with external systems is not claimed and not
  needed (the benchmark is self-contained).

## 9. What this gate does NOT establish

- **Not** the real AS (G-4): no token endpoint, no RFC 8693 exchange, no RFC 9396 RAR, no
  `ath`/nonce handling.
- **Not** the four-way DPoP attacker taxonomy (Part D) — that is **G-14** (captured-proof
  replay, first-use body mutation, compromised holder are not exercised here).
- **Not** replay semantics or the jti cache — **G-9** (B3⁺) and G-14.
- **Not** any claim beyond method+URI binding: DPoP does not bind tool or body
  **[VERIFIED, RFC 9449 §4.2]**; body/args binding is INV (G-11).
- **Not** the identity-plane mapping (`oauth_actor → htc_holder`, §A.5.1) — G-4/G-13.
