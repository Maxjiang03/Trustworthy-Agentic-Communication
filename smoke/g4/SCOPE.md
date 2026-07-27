# Gate G-4 — construction-spike SCOPE (opened under ADR 0008; **no adjudication**)

> **This is a scoping artifact, not a gate run.** It opens the G-4 **construction spike** that
> ADR 0008 already authorised to start ahead of G-6/G-7. **No AS code exists yet**: this pass
> wrote no endpoint, no token-exchange logic, and no client. Nothing here adjudicates G-4,
> changes its criteria, or upgrades any evidence grade. IA-4 remains **[UNVERIFIED-IA]**.

## 1. Pass criteria — copied verbatim from the Part G G-4 row

The row (`docs/EXPERIMENT_ARCHITECTURE_FINAL.md` §G.3), reproduced exactly, not paraphrased:

| Gate | Runs | Pass criterion | Blocks |
|------|------|----------------|--------|
| **G-4** | RFC 8693 exchange under the pinned AS profile yielding `C_i`; verify OAuth-resource ∩ capability effective authority, `actor→holder` mapping, `INV.access_token_hash` | Task-narrowed token issues; both layers enforced; actor mapping resolves | IA-4; B2-exchange-task and the fair-baseline claim |

The gate-outcome policy for this row, also verbatim: **"G-4 fails → build a behaviourally
faithful AS enforcing the mandated checks directly; disclose it."**

The assumption under test, §F.4 row IA-4, verbatim: *"The OAuth stack (`authlib`) supports
RFC 8693 exchange narrowing to `C_i` + RFC 9396 authorization_details, or a behaviourally
faithful AS can be built"* — status **[UNVERIFIED-IA]**, gate G-4.

## 2. Why a build is the likely path

The concluded external investigation found that **no off-the-shelf Python AS supports both
RFC 8693 down-scoped exchange and RFC 9396 `authorization_details`** `[DESIGN, ADR 0004]`, so a
**behaviourally faithful AS most likely has to be built** — which is also why ADR 0008 calls
G-4 the schedule's long pole and authorised the construction spike to start early. That finding
is a recorded project decision, **not** an externally verified fact about `authlib`: G-4 itself
confirms or refutes it on the pinned candidate, and the gate-outcome fallback above is what
applies if it holds.

## 3. Items handed forward by G-5 — both still `[UNVERIFIED-IA]`

G-5 verified the DPoP/JOSE surface with issuance **simulated locally**; two items were
explicitly deferred to the real AS/RS flow this spike builds (ADR 0006, `smoke/g5/REPORT.md`
§8, ADR 0008):

1. **`ath`** — the base64url SHA-256 hash of the access token, **REQUIRED when a DPoP proof
   accompanies an access token to a protected resource** `[VERIFIED, RFC 9449 §4.2 — the RFC
   text was read at G-5]`. What is **[UNVERIFIED-IA]** is that the AS/RS flow issues and
   validates it correctly; G-5 exercised no protected-resource request.
2. **DPoP nonce handling** — server-provided nonces via the `DPoP-Nonce` header and the
   `use_dpop_nonce` error (RFC 9449 §§8–9), an optional mechanism G-5 did not exercise
   **[UNVERIFIED-IA]**.

Neither may be described as working until this spike demonstrates it and G-4 adjudicates it.

## 4. Standing constraints on this spike

- **`authlib` stays unpinned.** The `#   authlib (RFC 8693 + RFC 9396)     -> gate G-4` line
  stays in the `# PENDING GATE` block of `pyproject.toml` **until G-4 adjudicates**. Nothing
  may be pinned on spike progress alone (ADR 0004 pin-only-after-gate rule; ADR 0008).
- **Adjudication does not move.** G-4's PASS adjudication stays **after G-6/G-7**, where the
  DAG puts it, with the §1 pass criteria **unchanged** (ADR 0008). Spike progress is not
  evidence and produces no §F.4 status change and no smoke-board PASS.
- **Grades.** IA-4 stays **[UNVERIFIED-IA]** for the whole life of the spike. No statement
  about RFC 8693/9396 support may be written as fact before adjudication.
- **Boundaries this spike does not cross:** it does not start G-2, G-11, or any other gate; it
  does not define or freeze `Ω` or `Γ` (`docs/frozen_parameters.md` item 8 stays UNSET); it
  does not touch `src/sut/`, `fixtures/confirmatory/`, Part H, or the pre-registration.

## 5. Primary sources to read **before any AS code is written**

Each must be read against the RFC text itself (the G-1 §2 / G-8 §2 discipline: primary source,
section-cited, `[VERIFIED]` only for what was actually read). **None of the "not yet read"
items below has been read in this pass** — this is the reading list, not a claim.

**RFC 8693 (OAuth 2.0 Token Exchange)** — not yet read:
- §1.1 delegation vs impersonation (which one the pinned profile realizes, and why)
- §2.1 request parameters: `grant_type`, `resource`, `audience`, `scope`, `requested_token_type`,
  `subject_token`(`_type`), `actor_token`(`_type`) — the exact narrowing surface
- §2.2.1 successful response (`issued_token_type`, `scope` semantics when narrowed) and §2.2.2 errors
- §4.1 the `act` claim (feeds `oauth_actor`, §A.5.1) and §4.3 `may_act`
- §5 security considerations (what the AS must refuse)

**RFC 9396 (Rich Authorization Requests)** — not yet read:
- §2 `authorization_details` and §2.1 common data fields (`type`, `locations`, `actions`,
  `datatypes`, `identifier`, `privileges`) — the carrier for `C_i` beyond scope strings
- §2.2 multiple authorization details; §3 the authorization request
- §5 `authorization_details` in the token response; §6 introspection
- §7 AS metadata (`authorization_details_types_supported`)
- §12 security considerations

**OAuth 2.1 (`draft-ietf-oauth-v2-1`)** — not yet read: the baseline the arms sit on (PKCE
required, no implicit/ROPC, exact redirect-URI matching, bearer-token handling) — D2's "real
OAuth 2.1 baseline".

**RFC 8707 (Resource Indicators)** — not yet read: §2 the `resource` parameter, and how
audience restriction (`AT@aud`, Part C) is expressed and enforced.

**RFC 9449 (DPoP)** — §4.2 and §§8–9 were read at G-5 `[VERIFIED]`; **re-read in the AS/RS
context** for token-endpoint DPoP-bound issuance (`cnf`/`jkt` minted by a real AS, §5/§7.1) and
the nonce protocol, neither of which G-5 exercised.

**RFC 7800 (`cnf`)** — §3.1 was read at G-5 `[VERIFIED]`; no re-read expected unless the AS
carries a confirmation method other than `jkt`.

**RFC 9068 (JWT profile for OAuth 2.0 access tokens)** — not yet read: `typ: at+jwt` and the
required claim set, if the AS issues JWT access tokens (G-5's simulated mint used `at+jwt`).

**RFC 8414 (AS metadata)** — not yet read, and **only if** the spike advertises discovery;
otherwise explicitly out of scope, not silently skipped.

**Corrections from the Phase 1 reading (2026-07-27), recorded rather than silently fixed.** The
RFCs were read in [`DESIGN.md`](DESIGN.md) §1, and two section numbers listed above are wrong
against the published text: RFC 8693 **§4.4** is `may_act` (§4.3 is the `client_id` claim), and in
RFC 9396 the token response is **§7** (§5 is the authorization *error* response), introspection is
**§9.2**, and AS metadata is **§10**. `DESIGN.md` §1 is authoritative for what was actually read.

**Architecture-document sections to re-read alongside them** (not RFCs, but binding):
§E.2 the pinned experiment AS profile (`AT_i` with exactly authority `C_i`, enforcing
`C_i ⊆ C_{i−1}`, rejecting widening); §A.5.1 the three identity notions and the
`oauth_actor → htc_holder` mapping the gate must resolve; §F.2 `INV.access_token_hash =
H(AT@aud)`; §F.2.1 the identity-plane registry.

## 6. Not in scope for the spike

Building the arms, the HTC/INV constructs, the effect ledger, or any fixture; G-13's
`Allowed(AT_i) = C_i` verification (a separate gate); the four-way DPoP taxonomy (G-14); and
any performance measurement (G-3, whose threshold must be fixed externally first).
