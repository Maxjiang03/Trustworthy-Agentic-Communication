# Gate G-4 — the pinned experiment AS profile (Phase 1 design; **no AS code exists**)

> **Status.** This is the specification Phase 2 implements. **Nothing here adjudicates G-4.**
> IA-4 remains **[UNVERIFIED-IA]**; the smoke board stays "not adjudicated"; `authlib` stays
> unpinned. G-4's pass criteria, dependency edges, and Part G row are **unchanged** (ADR 0008) —
> this document adds evidence and a build specification, it does not edit a criterion.
> Parent scope: [`SCOPE.md`](SCOPE.md). Probe: [`probe_authlib.py`](probe_authlib.py).
>
> *(Update, 2026-07-29: **Phase 2 has since been executed.** The AS was built at
> `src/sut/oauth_as/` and G-4 **PASSED over its adjudicable limbs** — `IA-4` is now verified by its
> **second** limb, and `authlib` is still unpinned. The paragraph above stands as the state of this
> document when it was written; the gate record is [`REPORT.md`](REPORT.md), the values §5.2 left
> to "the Phase 2 ADR" are fixed in **ADR 0017**, and the title's "no AS code exists" describes
> Phase 1 only. **Unchanged by that pass:** every pass criterion, dependency edge and evidence
> grade (ADR 0008); §9 C2 — the `INV.access_token_hash` limb is **still not adjudicated** and is
> scoped to a follow-on run after **G-11**, so G-4 is **not** fully closed; and §9 C3 — the
> identity-registry stand-in re-triggers the `actor→holder` limb at G-11.)*
>
> **Adjudication precondition is now satisfied.** ADR 0008 placed G-4 adjudication "after
> G-6/G-7"; both are **PASS** (§F.4 IA-6/IA-7, `smoke/README.md`), so Phase 2 may adjudicate —
> subject to §9's limb-by-limb honesty about what is and is not yet adjudicable.

---

## 1. Primary-source reading — what was read, and what it obliges

Read from the RFC text itself on **2026-07-27** (`rfc-editor.org` plain text; OAuth 2.1 from
`ietf.org/archive/id/draft-ietf-oauth-v2-1-15.txt`, the current revision 15 dated 2 March 2026).
`[VERIFIED]` below means *these words were read in this pass*; anything not read is marked
**not read** and is not relied on.

### 1.1 RFC 8693 — OAuth 2.0 Token Exchange

| § | What it says | What it obliges the profile to do | Grade |
|---|---|---|---|
| 1.1 | Impersonation makes A *indistinguishable from* B; delegation keeps A's identity separate and is expressed by a **composite token** naming both the subject and the actor, typically `subject_token` = party on whose behalf, `actor_token` = party the rights are delegated to. Issuing a composite token is at AS discretion. | Realize **delegation, never impersonation** (§4 below); carry both identities; never collapse the actor into the subject. | [VERIFIED] |
| 2.1 | Extension grant at the token endpoint, HTTP POST, form-encoded. `grant_type` REQUIRED; `resource`, `audience`, `scope`, `requested_token_type`, `actor_token` OPTIONAL; `subject_token`/`subject_token_type` REQUIRED; `actor_token_type` REQUIRED iff `actor_token` present. The AS **MUST** validate the subject token and, if present, the actor token. Omitting client authentication "allows for a compromised token to be leveraged via an STS into other tokens by **anyone possessing** the compromised token." | Use exactly these parameters; authenticate the client; validate both input tokens before issuing anything. | [VERIFIED] |
| 2.1.1 | Requested rights are the **Cartesian product** of all scopes at all target services; `invalid_target` tells a client it asked for too many targets. | One exchange per hop targets exactly one audience; no multi-target requests in the MSc profile. | [VERIFIED] |
| 2.2.1 | Response: `access_token`, `issued_token_type`, `token_type` REQUIRED; `expires_in` RECOMMENDED; **`scope` is OPTIONAL only if the issued scope is identical to the requested scope — otherwise REQUIRED**. | The AS may issue *less* than asked and must then say so. Narrowing is expressible in the response, and the client is told what it actually got. | [VERIFIED] |
| 2.2.2 | Invalid request, or invalid/unacceptable-by-policy `subject_token`/`actor_token` → **MUST** be `invalid_request`. Unwilling/unable to issue for a named target → `invalid_target` SHOULD. Other codes may be used as appropriate. | Fixes two rows of the rejection catalogue (§6) exactly. | [VERIFIED] |
| 3 | Token type identifiers are URIs: `…:token-type:access_token`, `…:refresh_token`, `…:id_token`, `…:saml1`, `…:saml2`, and `urn:ietf:params:oauth:token-type:jwt` (from JWT §9). | Use `access_token` for subject/issued tokens and `jwt` for the actor assertion (§5.3). | [VERIFIED] |
| 4.1 | `act` identifies the **current** actor; nesting expresses a delegation chain, outermost = current. **"For the purpose of applying access-control policy, the consumer of a token MUST only consider the token's top-level claims and the party identified as the current actor by the `act` claim. Prior actors … are informational only."** | `actor_of(AT)` reads the **outermost** `act` only. Nested actors are audit history and MUST NOT enter a decision. | [VERIFIED] |
| 4.3 | `client_id` claim = the client that requested the token. **Correction:** `may_act` is **§4.4**, not §4.3 as `SCOPE.md` §5 listed it; §4.3 is `client_id`. | `oauth_actor` may fall back to `(iss, client_id)` per §A.5.1 when no `act` is present (hop 0). | [VERIFIED] |
| 4.4 | `may_act` states that a party is **authorized to become the actor** for the subject; the AS can use `may_act` in the subject token to decide whether the requested delegation is permitted. | This is the spec-native home for the frozen `task_authorization_policy` (§7.4). | [VERIFIED] |
| 5 | Delegation and impersonation both create abuse potential; the `scope` claim plus limited lifetime is *suggested* to restrict the contexts in which delegated rights are exercised. | Confirms the narrowing obligation is **advisory** in the RFC — the enforcement is ours (§4, answer 2). | [VERIFIED] |

### 1.2 RFC 9396 — Rich Authorization Requests

| § | What it says | What it obliges the profile to do | Grade |
|---|---|---|---|
| 2 | `authorization_details` is a JSON **array of objects**; `type` is REQUIRED and determines the allowable contents; an array MAY contain several entries of the same type. | `C_i` is carried as an array of one project-defined type (§5.2). | [VERIFIED] |
| 2.1 | The AS controls the interpretation of `type` and of the fields it allows; for cross-server deployment a **collision-resistant namespace (a URI the designer controls)** is RECOMMENDED. | Use one namespaced project type; its exact string is fixed by the Phase 2 ADR. | [VERIFIED] |
| 2.2 | Common fields: `locations`, `actions`, `datatypes`, `identifier`, `privileges`. **"When different common data fields are used in combination, the permissions the client requests are the *product* of all the values"** — one object means all `actions` at all `locations` for all `datatypes`. | The meaning of a RAR object is a **set of triples**, so containment must be computed on the expansion, never on the JSON (§5.3). | [VERIFIED] |
| 3, 3.1, 3.2 | RAR may be used wherever `scope` is; `scope` and RAR may coexist and the AS **MUST** process both together; the `resource` parameter (RFC 8707) does **not** affect RAR processing. | Keep the two planes explicit: `scope`+`resource` are the OAuth-resource plane, RAR is the capability-authority plane; their **intersection** is the effective authority (pass-criterion limb 2). | [VERIFIED] |
| 5 | The AS **MUST refuse** unknown RAR types or non-conforming details, and **MUST abort** with `invalid_authorization_details` for: unknown `type`; unknown fields in a known type; wrong field types; invalid values; missing required fields. | Five mandatory rejection rows, verbatim (§6). | [VERIFIED] |
| 6 | On a token request, the AS checks whether the underlying grant allows issuing an AT with the requested details; otherwise `invalid_authorization_details`. | This is the error code for a **widening** attempt (§6). | [VERIFIED] |
| 6.1 | **"Since the semantics of the fields … will be implementation specific …, there is no standardized mechanism to compare two arbitrary authorization detail requests. An AS should not rely on simple object comparison in most cases."** Worked examples show `write` subsuming `read` and `privileges: admin` subsuming both. | The `C_i ⊆ C_{i−1}` comparison **must be defined by this project** and documented; and `privileges` is excluded precisely because its subsumption semantics are API-defined (§5.2). | [VERIFIED] |
| 7, 7.1 | The AS **MUST** return the `authorization_details` as granted and assigned to the access token; they are determined by the token request's parameter; the AS MAY omit values, and MAY *enrich* them. | The token response echoes the granted `C_i`, which is what the client forwards and what the harness verifier reads (G-13). No enrichment in the MSc profile. | [VERIFIED] |
| 9, 9.1, 9.2 | The AS **MUST** make the details available to the RS; for JWT ATs it is RECOMMENDED to add the RAR object **filtered to the specific audience** as a **top-level claim**; introspection is the alternative. | JWT ATs carry `authorization_details` top-level; **no introspection round trip** (§8, "too slow"). | [VERIFIED] |
| 10 | Support is advertised via `authorization_details_types_supported` in RFC 8414 metadata. | Not used — the profile advertises no discovery (§2). | [VERIFIED] |
| 12 | RAR travelling through the user agent must be integrity-protected by the client; **"All string comparisons … are to be done as defined by [RFC8259]. No additional transformation or normalization is to be done in evaluating equivalence of string values."**; `locations` enables unambiguous per-RS assignment; the AS **MUST** sanitize the data to prevent injection. | Exact byte-for-byte string equality in the containment check — no case folding, no Unicode normalization, no trimming. Fixes a real widening loophole. | [VERIFIED] |

### 1.3 RFC 8707 — Resource Indicators

| § | What it says | What it obliges the profile to do | Grade |
|---|---|---|---|
| 2 | `resource` MUST be an absolute URI, no fragment, SHOULD NOT carry a query; multiple values allowed; `invalid_target` is the error; **"The authorization server SHOULD audience-restrict issued access tokens to the resource(s) indicated"**, communicated as the JWT `aud` claim; the AS may use the exact value or map it. | `AT@aud` = the MCP resource-server URI passed as `resource`; exactly one per exchange. | [VERIFIED] |
| 2.2 | On a token request the acceptable resource values are at the AS's **sole discretion by local policy**; for code/refresh grants policy *may* limit them to those originally granted or a subset. | Audience narrowing, like scope narrowing, is our policy to enforce — the RFC only permits it. | [VERIFIED] |

### 1.4 RFC 9449 — DPoP (re-read in AS/RS context; §4.2/§4.3 were read at G-5)

| § | What it says | What it obliges the profile to do | Grade |
|---|---|---|---|
| 4.2 | Proof header carries `typ: dpop+jwt`, asymmetric `alg`, public `jwk`; payload carries `jti`, `htm`, `htu`, `iat`; **`ath` (base64url SHA-256 of the ASCII access-token value) MUST be present when the proof accompanies an access token at a protected resource**; `nonce` MUST be present when the server supplied one. Only method and URI are covered. | `ath` is REQUIRED at the MCP boundary in the DPoP arm — G-5 exercised no protected-resource request, so this is new work. | [VERIFIED] |
| 4.3 | Twelve receiver checks, including item 12: with an access token, verify `ath` equals the hash of *that* token **and** that the key the AT is bound to matches the proof key. Servers SHOULD apply RFC 3986 syntax/scheme normalization before comparing `htu`. | The RS-side verifier list for the DPoP arm; `htu` normalization closes the G-5 residual. | [VERIFIED] |
| 5 | The client **MUST** send a valid DPoP proof at the token endpoint for a DPoP-bound token, for **all** grant types — which includes an extension grant such as token exchange. Invalid proof → `invalid_dpop_proof`. The AS associates the AT with the proof's public key and **MUST** return `token_type: DPoP`. | The B2-DPoP arm's exchange carries a DPoP proof; the response's `token_type` distinguishes it from the bearer arms. | [VERIFIED] |
| 6, 6.1 | The RS MUST be able to tell a DPoP-bound token and verify the binding; for JWT ATs the binding is `cnf.jkt` = base64url of the RFC 7638 SHA-256 JWK thumbprint of the DPoP public key. | Exactly what G-5 verified with a simulated mint — Phase 2 mints it at a real endpoint. | [VERIFIED] |
| 7, 7.1 | Protected-resource requests MUST carry both proof and token; `ath` prevents a captured signature being replayed against a *different* token; the AT is sent with the `DPoP` auth scheme; the RS **MUST NOT grant access unless all checks succeed**; `ath` alone does **not** prevent proof replay or bind the request. | Confirms the Part D taxonomy: `ath` closes token-substitution, not replay and not body/args — which is the B3/INV gap. | [VERIFIED] |
| 8, 8.1, 8.2 | The AS MAY require a nonce: respond HTTP 400 `use_dpop_nonce` with a `DPoP-Nonce` header; nonces MUST be unpredictable; a mismatched nonce MUST be rejected; a new nonce may ride on a 200 response to save a round trip; nonce responses should be uncacheable. | If nonces are enabled, each *first* exchange costs an extra round trip — a measurable, disclosable cost (§8). | [VERIFIED] |
| 9 | The RS may provide its own nonce via `DPoP-Nonce` with HTTP 401 + `WWW-Authenticate: DPoP error="use_dpop_nonce"`. AS and RS nonces are distinct and only accepted by their issuer. | Two nonce namespaces must not be conflated. | [VERIFIED] |

### 1.5 OAuth 2.1 (`draft-ietf-oauth-v2-1-15`) — the baseline the arms sit on

| § | What it says | What it obliges the profile to do | Grade |
|---|---|---|---|
| 1.4.1 | ATs are meant to be *less* privileged than the granting user; **"The authorization server MAY fully or partially ignore the scope requested by the client, based on the authorization server policy"**, and MUST report the granted scope when it differs. | Second independent confirmation that narrowing is AS policy. | [VERIFIED] |
| 1.5 | Communication security: TLS-class protection MUST be used; **"All the OAuth protocol URLs (URLs exposed by the AS, RS and Client) MUST use the https scheme except for loopback interface *redirect URIs*"**. | The loopback exception covers redirect URIs only — a plain-HTTP token endpoint is a deviation, which §8 confronts rather than hides. | [VERIFIED] |
| 1.8 | OAuth 2.1 = OAuth 2.0 + BCP: PKCE required, Implicit and ROPC not specified, strict string matching of redirect URIs. | Constrains the *authorization endpoint*, which this profile does not run (§2) — stated, not silently skipped. | [VERIFIED] |
| 3.2, 3.2.1, 3.2.2 | Token endpoint: POST only; MUST ignore unrecognized parameters; valueless parameters treated as omitted; no parameter repeated twice unless an extension says otherwise; confidential clients MUST authenticate; the AS MUST require client authentication for confidential clients and authenticate it when included. | Fixes the endpoint's parsing and client-authentication behaviour. | [VERIFIED] |
| 3.2.4 | Error response is HTTP 400 + JSON with `error` ∈ {`invalid_request`, `invalid_client`, `invalid_grant`, `unauthorized_client`, `unsupported_grant_type`, `invalid_scope`}; `invalid_client` MAY be 401 (MUST be 401 with `WWW-Authenticate` if the client used the Authorization header). | Completes the rejection catalogue (§6). | [VERIFIED] |
| 4.4 | Extension grants: absolute-URI `grant_type` at the token endpoint plus any additional parameters; success/error responses are those of §3.2.3/§3.2.4. | This is the hook RFC 8693 plugs into — the exchange is an ordinary OAuth 2.1 extension grant. | [VERIFIED] |
| 5, 5.2 | The RS MUST validate the token and ensure its scope covers the request; validation methods are out of scope but include introspection or a structured JWT. | The MCP boundary validates the JWT AT offline. | [VERIFIED] |
| 7.1.4 | Privilege restriction: ATs SHOULD be restricted to the minimum required, SHOULD be audience-restricted preferably to a **single** RS, and SHOULD be restricted to certain resources and actions — with `scope`/`resource`/`authorization_details` named as the means, and the RS "obliged to verify, for every request". | The pinned profile is the BCP-recommended configuration, not an exotic one. Directly supports the fair-baseline claim. | [VERIFIED] |

### 1.6 RFC 9068 — JWT profile for OAuth 2.0 access tokens (read: the design uses JWT ATs)

| § | What it says | What it obliges the profile to do | Grade |
|---|---|---|---|
| 2.1 | JWT ATs MUST be signed, MUST NOT use `none`, asymmetric RECOMMENDED; `typ` MUST be the `application/at+jwt` media type (SHOULD be written `at+jwt`); **"Authorization servers and resource servers conforming to this specification MUST include RS256 … among their supported signature algorithms."** | **Conflict, disclosed in §8.3:** the project signs Ed25519 everywhere (ADR 0006). The profile is *RFC 9068-shaped* — `at+jwt` typing and the required claim set — but **not RFC 9068-conformant**, because RS256 is deliberately not supported. Never claim conformance. | [VERIFIED] |
| 2.2 | REQUIRED claims: `iss`, `exp`, `aud`, `sub`, `client_id`, `iat`, `jti`. | The AT claim set (§5.1). | [VERIFIED] |
| 2.2.3 | If the request had `scope`, the AT SHOULD carry a `scope` claim; every scope string MUST be meaningful for the resources in `aud`. | Keeps the OAuth-resource plane coherent with the audience. | [VERIFIED] |
| 3 | If the request has `resource` (RFC 8707), the AT's `aud` SHOULD equal it; the AS **MUST NOT** issue a JWT AT whose granted authorization would be **ambiguous**. | One `resource` per exchange, `aud` = that value; ambiguity is a rejection, not a merge. | [VERIFIED] |
| 4 | The RS MUST verify `typ` is `at+jwt`, MUST reject `alg: none`, MUST match `iss` exactly, MUST reject a token whose `aud` does not name this RS, MUST validate the signature with AS-provided keys, MUST check `exp`; failures → `invalid_token`. AS metadata (RFC 8414) is only **SHOULD** for publishing keys. | The boundary's AT verifier; the AS public key is delivered from sealed configuration instead of `jwks_uri` (§2). | [VERIFIED] |

### 1.7 Read at G-5 and relied on unchanged; and what was deliberately **not** read

- **RFC 7800 §3.1** (`cnf`) — read and `[VERIFIED]` at G-5 (ADR 0006). The profile carries no
  confirmation method other than `jkt`, so `SCOPE.md` §5's "no re-read expected" holds. **Not
  re-read in this pass**, and nothing new is claimed from it.
- **RFC 8414 (AS metadata)** — **not read, and out of scope by design decision**, not skipped:
  the profile publishes **no** discovery document and no `jwks_uri` (§2). Consequently RFC 9396
  §10's `authorization_details_types_supported` and RFC 9449 §5.1's
  `dpop_signing_alg_values_supported` are also out of scope. If Phase 2 ever advertises
  discovery, RFC 8414 must be read first and this row updated.
- **RFC 7638 / RFC 8037** — thumbprint and Ed25519 JOSE, read and `[VERIFIED]` at G-5; unchanged.
- **RFC 9101 / RFC 9126** (signed request objects, PAR), cited by RFC 9396 §12 as the way to
  integrity-protect RAR **through a user agent** — **not read, and not applicable**: this profile
  sends RAR only on a direct back-channel token request, never through a browser.
- **RFC 7523** (JWT client auth / assertions) — **not read**. The actor assertion of §5.3 is
  therefore specified here as a *project-defined* JWT validated by the AS, `[DESIGN]`, and is
  **not** described as an RFC 7523 assertion. If Phase 2 wants that label, RFC 7523 gets read first.

---

## 2. The four questions STEP 3 required, answered with citations

**Answer 1 — delegation, not impersonation.** The profile realizes **delegation**
`[VERIFIED, RFC 8693 §1.1]`. Under impersonation the actor is "indistinguishable from" the
subject; that would collapse `oauth_actor` into `resource_owner` and destroy §A.5.1's three-way
split, the identity-plane check, and the whole F2 `wrong_principal` family — the arm could not
even express "the wrong agent presented a valid token". Delegation is expressed by a composite
token: `sub` = `resource_owner`, `act.sub` = the current actor, nested `act` for prior hops
`[VERIFIED, RFC 8693 §4.1]`. The consequence for §A.5.1 is a hard rule: `actor_of(AT)` reads the
**outermost `act` only**, because "the consumer of a token MUST only consider the token's
top-level claims and the party identified as the current actor" — nested actors are audit
history and MUST NOT enter any decision `[VERIFIED, RFC 8693 §4.1]`. At hop 0 there is no `act`
and `oauth_actor = (iss, client_id)`, which §A.5.1 already provides for.

**Answer 2 — narrowing lives in AS policy; §E.2's `[VERIFIED]` claim is CONFIRMED, not corrected.**
Nothing in RFC 8693 obliges a narrower token. §2.2.1 makes the issued `scope` reportable
precisely *because* it may differ from what was asked; §5 only *suggests* `scope` and short
lifetimes to "restrict the contexts in which the delegated rights can be exercised"; OAuth 2.1
§1.4.1 independently says the AS "MAY fully or partially ignore the scope requested"; RFC 8707
§2.2 puts acceptable `resource` values at the AS's "sole discretion based on local policy"; and
RFC 9396 §6.1 states outright that **"there is no standardized mechanism to compare two arbitrary
authorization detail requests"** and that an AS "should not rely on simple object comparison"
`[all VERIFIED]`. So the architecture document's standing claim — RFC 8693 does not by itself
guarantee a narrower token, and scope/audience/`authorization_details` are AS-policy-determined —
is **confirmed against the text**, and the repealed "RFC 8693 inherently down-scopes" phrasing
(§B.1) is confirmed to have been correctly repealed.

Where narrowing is *expressed*: request side — `authorization_details` (the authority, §5.2),
`resource` (the audience), `scope` (the OAuth-resource plane), `subject_token` (= `AT_{i−1}`),
`actor_token` (the delegate); response side — `access_token`, `issued_token_type`, `token_type`,
`expires_in`, `scope` (REQUIRED when narrowed) and the granted `authorization_details` (RFC 9396
§7 MUST). Where widening is *rejected*: the AS recomputes the requested authority and refuses
unless `expand(AD_req) ⊆ expand(AD_{i−1})` **and** `resource_req ∈ resources(AT_{i−1})` **and**
`scope_req ⊆ scope(AT_{i−1})` **and** `exp_i ≤ exp_{i−1}` (§5.3).

**Answer 3 — how `C_i` is carried.** As a single-type `authorization_details` array
`[VERIFIED, RFC 9396 §2]`, with the mapping in §5.2: `type` = one project-namespaced URI
(§2.1 RECOMMENDS a controlled namespace); `locations` = the MCP resource-server URI (the same
value as `resource`, so the two planes are checkably consistent); `actions` = the action side of
`Ω`; `datatypes`/`identifier` = the resource side; **`privileges` is forbidden** in the MSc
profile because §6.1's own example shows `privileges: admin` subsuming both `read` and `write` —
API-defined subsumption is exactly the widening hazard the gate exists to catch. The crucial
semantic is §2.2's **product rule**: one object means all its `actions` at all its `locations`
for all its `datatypes`, so `C_i` is the **set expansion** of the array, and containment is
computed on that set, never on the JSON objects. §7 obliges the AS to return the granted
`authorization_details` in the token response, and §9.1 RECOMMENDS carrying them in a JWT AT as
a top-level claim filtered to the audience — which is what the boundary and the harness verifier
(G-13) read. §12 adds a MUST that silently prevents a whole class of bypass: **string comparison
is RFC 8259 equality with no transformation or normalization**, so the containment check uses
exact byte equality, never case folding or Unicode normalization. §12 also requires the AS to
sanitize RAR input against injection, and §5 lists the five conditions under which the AS MUST
abort with `invalid_authorization_details`.

**Answer 4 — audience and holder binding.** `AT@aud` is expressed by the `resource` parameter,
an absolute URI without a fragment `[VERIFIED, RFC 8707 §2]`; the AS SHOULD audience-restrict the
issued token to it, communicated as the JWT `aud` claim (§2), and RFC 9068 §3 says `aud` SHOULD
equal the `resource` value. Enforcement is on the RS side and is a **MUST**: reject any token
whose `aud` does not name this resource server `[VERIFIED, RFC 9068 §4]`; OAuth 2.1 §7.1.4 adds
that every RS is "obliged to verify, for every request". A real AS mints holder binding by
requiring a DPoP proof at the token endpoint for **all** grant types — including this extension
grant — rejecting a bad proof with `invalid_dpop_proof`, associating the AT with the proof's
public key, and returning `token_type: DPoP` `[VERIFIED, RFC 9449 §5]`; for a JWT AT the binding
is `cnf.jkt` = base64url(RFC 7638 SHA-256 JWK thumbprint) `[VERIFIED, RFC 9449 §6.1]`. The two
G-5 hand-forwards, in AS/RS context: **`ath`** is REQUIRED on every protected-resource proof and
the RS must check it equals the hash of *that* token and that the token's bound key matches the
proof key `[VERIFIED, RFC 9449 §4.2, §4.3 item 12, §7, §7.1]`; **nonces** are an AS/RS option
where a missing or stale nonce is answered with `use_dpop_nonce` plus a `DPoP-Nonce` header (AS:
HTTP 400; RS: HTTP 401 + `WWW-Authenticate: DPoP`), nonces must be unpredictable, and a fresh
nonce may ride on a 200 response to avoid an extra round trip `[VERIFIED, RFC 9449 §§8–9]`.
Both remain **[UNVERIFIED-IA]** as *implementations* until Phase 2 exercises them.

---

## 3. `authlib` — what the probe found (evidence; adjudicates nothing)

`uv run --with authlib python smoke/g4/probe_authlib.py` → **exit 0**, verdict **UNSUPPORTED**
for `authlib==1.7.2` (resolved ephemerally 2026-07-27; nothing pinned).

- `authlib/oauth2/rfc8693/` **exists as a package** and its docstring says *"This module
  represents an implementation of OAuth 2.0 Token Exchange"* — and it is a **162-byte
  `__init__.py` containing only that docstring**: zero public symbols, no `__all__`, no other
  module. A directory-name inventory alone would have scored this as support; content
  inspection refutes it. The probe's verdict was consequently made content-based.
- The RFC 8693 grant-type URN `urn:ietf:params:oauth:grant-type:token-exchange` occurs **nowhere**
  in the installed source, and neither do `subject_token`, `actor_token`, `requested_token_type`,
  or `issued_token_type`. `authlib/oauth2/rfc6749/grants` exports exactly
  `AuthorizationCodeGrant, BaseGrant, ClientCredentialsGrant, ImplicitGrant, RefreshTokenGrant,
  ResourceOwnerPasswordCredentialsGrant` — no exchange grant.
- `authorization_details` occurs **nowhere** in the installed source; there is no `rfc9396`
  package; and `authlib/oauth2/rfc6750/token.py:BearerTokenGenerator.__call__(self, grant_type,
  client, user, scope, expires_in, include_refresh_token)` neither accepts nor emits it — so the
  RFC 9396 §7 MUST could not be satisfied without replacing the token-response builder.
- What *is* present is the generic extension-grant framework:
  `authlib/oauth2/rfc6749/authorization_server.py:AuthorizationServer.register_grant(self,
  grant_cls, extensions=None)` plus `BaseGrant` — i.e. the hook OAuth 2.1 §4.4 describes, and
  nothing that fills it.

**Consequence, stated plainly:** the probe **confirms** ADR 0004's finding on this candidate
rather than refuting it — both halves of IA-4's first limb would have to be written by hand,
which is precisely IA-4's **second** limb, "a behaviourally faithful AS can be built". Had the
probe found support, this document would have recorded the refutation and changed the plan.
`authlib` stays **unpinned**; the `# PENDING GATE` line is untouched; IA-4 stays
**[UNVERIFIED-IA]**; nothing is adjudicated here.

---

## 4. Non-goal of §§5–8: they specify, they do not build

No endpoint, exchange routine, client, or resource server was written in this pass. Everything
below is a specification for Phase 2.

---

## 5. The pinned experiment AS profile

### 5.1 Shape, endpoints, token format

`[DESIGN]` One process, one endpoint, no discovery:

| Item | Decision | Basis |
|---|---|---|
| Endpoints | **`POST /token` only.** No authorization endpoint, no introspection, no revocation, no `.well-known` metadata, no `jwks_uri`. | The measured quantity is the Phase-2 delegation round trip (§E.2); Phase-1 setup uses the pre-issued-fixture path §E.2 already permits. RFC 8414 stays out of scope (§1.7). |
| AS public key | Delivered to the boundary and to the harness verifier **from sealed configuration**, never fetched. | RFC 9068 §4 makes metadata publication a SHOULD, not a MUST; sealed delivery is stronger and keeps discovery out of scope. |
| Grant type | Extension grant `urn:ietf:params:oauth:grant-type:token-exchange`, POST, form-encoded, unrecognized parameters ignored, no parameter repeated. | RFC 8693 §2.1; OAuth 2.1 §§3.2/3.2.2/4.4. |
| Client authentication | **Required for every exchange.** `client_secret_basic`, with secrets **derived at run time from the sealed per-principal seeds** (ADR 0007's seed→key derivation extended to client secrets) so no secret is ever in the repository. | OAuth 2.1 §3.2.1 MUST; RFC 8693 §2.1's warning that omitting it lets *anyone holding a compromised token* mint further tokens. CLAUDE.md red line 8. |
| Token format | **JWT**, `typ: at+jwt`, signed **Ed25519** (RFC 9864 identifier, explicit algorithm allowlist, per ADR 0006). | RFC 9068 §2.1 for typing; ADR 0006 for the algorithm — see the disclosed non-conformance in §8.3. |
| AT claims | `iss, exp, aud, sub, client_id, iat, jti` (all REQUIRED) + `scope` + `authorization_details` (top-level, filtered to the audience) + `act` (+ nested `act`) + `cnf.jkt` in the DPoP arm only. | RFC 9068 §§2.2/2.2.3/3; RFC 9396 §9.1; RFC 8693 §4.1; RFC 9449 §6.1. |
| Lifetimes | `exp_i ≤ exp_{i−1}`, non-increasing along the chain, mirroring the HTC rule (§F.2). | RFC 8693 §5 (limited lifetime as an abuse control); project symmetry `[DESIGN]`. |
| Transport | **TLS 1.3 on the loopback interface**, per-campaign self-signed certificate generated at run time from sealed seeds; HTTP keep-alive so the handshake is amortized as in a real deployment. | OAuth 2.1 §1.5 MUST (its `http` exception covers loopback **redirect URIs** only). Contingency and bias direction in §8.2. |

### 5.2 How `C_i` is expressed

`[DESIGN, grounded in RFC 9396 §§2/2.1/2.2]` One project-namespaced RAR type (exact string fixed
by the Phase 2 ADR; it is part of the AS configuration the seal already hashes, **not** a new
`frozen_parameters` row unless the Commander rules otherwise):

```jsonc
[
  {
    "type":      "<project-namespaced URI>",   // §2 REQUIRED; §2.1 collision-resistant namespace
    "locations": ["<MCP resource-server URI>"],// §2.2; identical to the `resource` parameter
    "actions":   ["<action ∈ Ω>", "..."],      // §2.2 action side of Ω
    "datatypes": ["<resource-kind ∈ Ω>"],      // §2.2 resource side of Ω
    "identifier":"<specific resource ∈ Ω>"     // §2.2, optional, when a single object is meant
  }
]
```

Forbidden in the MSc profile: `privileges` (API-defined subsumption, RFC 9396 §6.1); any
API-specific extension field; any `type` other than the project type; more than one `locations`
value per object. Every value must be a member of `Ω` — an out-of-`Ω` string is a rejection
(§6), never an implicitly new authority element.

**Meaning (the product rule, RFC 9396 §2.2):**

```
expand(AD) = ⋃_{o ∈ AD}  { (l, a, d) | l ∈ o.locations, a ∈ o.actions, d ∈ o.datatypes }
C_i        = expand(AD_i)        # the capability-plane authority carried by AT_i
```

### 5.3 The exchange at hop `i`, and the enforcement of `C_i ⊆ C_{i−1}`

`[DESIGN]` The **delegating** agent (holder of `AT_{i−1}`) is the client of the exchange; the
delegate is named by an **actor assertion** — a short JWT signed by the delegate's own Ed25519
identity key, obtained **during Phase-1 provisioning** and reused for the campaign, so the
measured Phase-2 hop remains exactly **one** AS round trip (§8.2). Request:

| Parameter | Value | Basis |
|---|---|---|
| `grant_type` | `urn:ietf:params:oauth:grant-type:token-exchange` | RFC 8693 §2.1 |
| `subject_token` / `subject_token_type` | `AT_{i−1}` / `urn:ietf:params:oauth:token-type:access_token` | RFC 8693 §2.1, §3 |
| `actor_token` / `actor_token_type` | delegate assertion / `urn:ietf:params:oauth:token-type:jwt` | RFC 8693 §2.1, §3 (`actor_token_type` REQUIRED iff `actor_token` present) |
| `resource` | the MCP resource-server URI (exactly one) | RFC 8707 §2 |
| `scope` | the OAuth-plane scope for hop `i` | RFC 8693 §2.1 |
| `authorization_details` | `AD_i`, the requested `C_i` | RFC 9396 §6 |
| `DPoP` header | DPoP-arm only: proof over `POST` + the token-endpoint URI | RFC 9449 §5 |

Then, **in this order, all fail-closed**:

1. Authenticate the client (OAuth 2.1 §3.2.1); unauthenticated or unknown → `invalid_client`.
2. Validate `subject_token`: signature under the AS key, `iss`, `aud`, `exp`/`nbf`, and that it
   was issued by this AS (RFC 8693 §2.1 MUST). Invalid → `invalid_request` (§2.2.2 MUST).
3. Validate `actor_token`: signature under the delegate's registered identity key, `exp`,
   audience = this AS (RFC 8693 §2.1 MUST). Invalid → `invalid_request`.
4. Resolve identities: `resource_owner` = `(iss, sub)` of the subject token; the **requested
   actor** = the actor assertion's subject; the **current actor** of the subject token = its
   outermost `act` (or `client_id` at hop 0). Both the client and the requested actor MUST
   resolve, through the identity-plane registry (§F.2.1), to exactly one principal each;
   unmapped → reject (§6).
5. Delegation permission: the requested actor MUST be permitted for this subject/task — checked
   against the subject token's `may_act` (RFC 8693 §4.4), populated at issuance from the frozen
   `task_authorization_policy` (`frozen_parameters` item 5; see §7.4). Not permitted →
   `invalid_request`.
6. Parse `authorization_details` and **abort with `invalid_authorization_details`** on any of
   RFC 9396 §5's five conditions (unknown type; unknown fields; wrong field types; invalid
   values; missing required fields), plus this profile's own additions: a forbidden field
   (`privileges`), a value outside `Ω`, or more than one `locations` entry.
7. **Containment — the core check.** With exact RFC 8259 string equality and no normalization
   (RFC 9396 §12), require **all** of:
   - `expand(AD_req) ⊆ expand(AD_{i−1})` — the capability plane;
   - `resource_req ∈ aud(AT_{i−1})` — the audience plane (RFC 8707 §2.2 policy);
   - `scope_req ⊆ scope(AT_{i−1})` — the OAuth-resource plane;
   - `exp_i ≤ exp_{i−1}`.
   Any violation → **`invalid_authorization_details`** (RFC 9396 §6: the underlying grant does
   not allow the requested details) — or `invalid_target` when the failure is specifically an
   unissuable `resource` (RFC 8693 §2.2.2, RFC 8707 §2). **The AS never silently narrows a
   widening request to the intersection**: a widening attempt is an error, not a clamp, because
   a silent clamp would make `F1-chain-tamper` indistinguishable from a benign narrowing.
8. DPoP arm only: validate the proof (RFC 9449 §4.3 items 1–11; item 12 does not apply at the
   token endpoint), else `invalid_dpop_proof`; if nonces are enabled and the proof lacks/stales
   one, answer HTTP 400 `use_dpop_nonce` with a `DPoP-Nonce` header (§8).
9. Issue `AT_i`: `sub` = `resource_owner`; `act` = the new current actor with the previous `act`
   nested beneath it (RFC 8693 §4.1); `aud` = `resource_req`; `authorization_details` = the
   granted `AD_i` **filtered to that audience** (RFC 9396 §9.1); `scope` = the granted scope;
   `cnf.jkt` in the DPoP arm (RFC 9449 §6.1); fresh `jti`; `exp_i`.
10. Respond 200 with `access_token`, `issued_token_type =
    urn:ietf:params:oauth:token-type:access_token`, `token_type` (`Bearer`, or `DPoP` in the DPoP
    arm — RFC 9449 §5 MUST), `expires_in`, the granted `authorization_details` (RFC 9396 §7
    MUST), and `scope` **whenever it differs from the request** (RFC 8693 §2.2.1 REQUIRED).

### 5.4 Process and key isolation — the mechanism, stated

`[DESIGN, ADR 0015]` The AS lives at **`src/sut/oauth_as/`** and runs **out-of-process**:

- **Process.** Its own OS process, started by the harness runner before a campaign and bound to
  the **loopback interface only** (no external socket). Agents reach it exclusively over that
  socket; no agent hosts it in-process.
- **Key.** The Ed25519 signing key is generated **inside the AS process** at start-up from the
  sealed per-principal seed (ADR 0007's seed→key derivation), held only in that process's memory,
  **never written to disk** and never exported. Only the **public** key leaves the process, and it
  reaches the boundary and the harness verifier from **sealed configuration**, not over the wire
  (no `jwks_uri`, §5.1).
- **Import rules (ADR 0015).** No other `src/sut/` module may import `src/sut/oauth_as/`, and
  **`src/harness/` may never import it** — notwithstanding the harness's general permission to
  import `sut` — so the instrument can neither mint nor share implementation with what it
  adjudicates (D13/D21). The G-13 verifier reimplements token verification independently.
- **Why this matters for the baseline.** Without it a baseline agent could **forge the very
  tokens the baseline is supposed to constrain**, and every B2 result would measure nothing.
  Phase 2 therefore demonstrates that an SUT-side attempt to mint an `AT` fails (test A4), and
  that both import rules hold. That demonstration is **additional evidence beyond G-4's pass
  criteria — explicitly not a criterion change** (ADR 0008; task STEP 1 item 3).

**Effective authority at the boundary (pass-criterion limb 2).** The MCP boundary independently
computes `Allowed(AT_i)` = `expand(AT_i.authorization_details)` **∩** the OAuth-resource plane
(`aud` matches this RS, per RFC 9068 §4 MUST; `scope` covers the request, per OAuth 2.1 §5), and
authorizes only if the required authority `R` is contained in that intersection. Both layers are
therefore enforced, and neither alone can admit a request the other denies.

---

## 6. Rejection catalogue — what the AS must refuse, and with which error

| Condition | Error | HTTP | Basis |
|---|---|---|---|
| Client unauthenticated / unknown / unsupported auth method | `invalid_client` | 400, or **401 with `WWW-Authenticate`** if the client used the Authorization header | OAuth 2.1 §3.2.4 |
| `grant_type` not the exchange URN | `unsupported_grant_type` | 400 | OAuth 2.1 §3.2.4 |
| Missing/duplicated/valueless required parameter; malformed request | `invalid_request` | 400 | OAuth 2.1 §§3.2.2/3.2.4 |
| `subject_token` invalid, expired, wrong issuer/audience, or unacceptable by policy | `invalid_request` | 400 | RFC 8693 §2.2.2 (**MUST**) |
| `actor_token` invalid/expired, or `actor_token_type` missing while `actor_token` present | `invalid_request` | 400 | RFC 8693 §2.1, §2.2.2 |
| Actor or client not resolvable to exactly one principal in the registry | `invalid_request` | 400 | RFC 8693 §2.2.2 ("unacceptable based on policy"); §F.2.1 |
| Requested actor not permitted for this subject/task (`may_act` / `task_authorization_policy`) | `invalid_request` | 400 | RFC 8693 §4.4 |
| Replayed `subject_token` used after its `exp`, or a token this AS did not issue | `invalid_request` | 400 | RFC 8693 §2.1/§2.2.2 |
| RAR: unknown `type`; unknown field in a known type; wrong field type; invalid value; missing required field | `invalid_authorization_details` | 400 | RFC 9396 §5 (**MUST refuse, MUST abort**) |
| RAR: forbidden `privileges` field; value outside `Ω`; multiple `locations` in one object | `invalid_authorization_details` | 400 | Profile restriction `[DESIGN]`, on §5's "unknown fields / invalid values" footing |
| **Widening**: `expand(AD_req) ⊄ expand(AD_{i−1})`, or `scope_req ⊄ scope(AT_{i−1})`, or `exp_i > exp_{i−1}` | `invalid_authorization_details` | 400 | RFC 9396 §6 (grant does not allow the requested details) |
| Audience mismatch: `resource_req ∉ aud(AT_{i−1})`, unknown or unissuable target, malformed `resource` URI | `invalid_target` | 400 | RFC 8693 §2.2.2 (SHOULD); RFC 8707 §2 |
| More than one target requested (multi-`resource`/`audience`) | `invalid_target` | 400 | RFC 8693 §2.1.1 |
| DPoP arm: missing/invalid proof at the token endpoint | `invalid_dpop_proof` | 400 | RFC 9449 §5 |
| DPoP arm: nonce required but absent or stale | `use_dpop_nonce` + `DPoP-Nonce` header | 400 | RFC 9449 §8 |

Resource-server side (the MCP boundary), for completeness: `typ ≠ at+jwt`, `alg: none`, `iss`
mismatch, `aud` not naming this RS, bad signature, or expired → **`invalid_token`**
`[VERIFIED, RFC 9068 §4]`; DPoP arm additionally the §4.3 twelve checks, and "MUST NOT grant
access unless all checks are successful" `[VERIFIED, RFC 9449 §7.1]`.

---

## 7. Identity plane

### 7.1 Representation, kept distinct by construction

| Notion (§A.5.1) | Where it lives | Never |
|---|---|---|
| `resource_owner = (iss, sub)` | AT `iss` + `sub` | Never compared against a holder key |
| `oauth_actor = (iss, act)` or `(iss, client_id)` | AT **outermost** `act.sub`; `client_id` at hop 0 | Nested `act` values are **audit history only** `[VERIFIED, RFC 8693 §4.1 MUST]` |
| `htc_holder` | The Ed25519 public key named by the terminal HTC (§F.2) | **Never appears in the AT** |

### 7.2 The mapping check, and what it must not become

`actor_of(AT)` → exactly one principal; the registry (§F.2.1) maps that principal to exactly one
`htc_holder` public key; an unmapped actor or key is rejected. The check is
**`oauth_actor → htc_holder` only**. Requiring `resource_owner = holder` is **forbidden**
(§A.5.1 MUST NOT) — delegation means the actor is *not* the resource owner, and a profile that
demanded equality would reject every legitimate delegated call in the study.

### 7.3 Two different "holders" that must never be conflated

In **B2-DPoP** the holder is the **DPoP key**, bound by `cnf.jkt` and proved per RFC 9449 §7.1.
In **B3** the holder is the **HTC terminal identity key**, proved by the HTC chain and the INV
signature (D23 superseded by D31: `cnf` is used *only* in the DPoP arm). They are different keys
proving different things; the identity-plane check of §7.2 governs the capability arms, and the
`cnf.jkt` ↔ proof-`jwk` comparison (verified at G-5) governs the DPoP arm.

### 7.4 A dependency this profile inherits, named rather than assumed

`may_act` is the spec-native carrier for "which principals may act for this subject on this task"
`[VERIFIED, RFC 8693 §4.4]`, and its content comes from the frozen `task_authorization_policy`
(`frozen_parameters` **item 5, UNSET**). That item is not a G-4 pass-criterion limb — the
criterion says only "actor mapping resolves" — but the F2 `wrong_principal` family depends on it,
so Phase 2 uses a spike-local policy, explicitly labelled, and the F2 family is not scored until
item 5 is fixed by its own ADR.

---

## 8. Fair-baseline hazards — both directions, named

This AS **is** the comparator B3 is measured against, and G-4 blocks "B2-exchange-task and the
fair-baseline claim" (Part G). A defect here is not a failed gate; it is a straw man.

### 8.1 Too weak — checks that MUST NOT be dropped for convenience

Dropping any of these would make B2 lose on a technicality rather than on the mechanism, and
voids the comparative claim:

1. Client authentication on every exchange (OAuth 2.1 §3.2.1; RFC 8693 §2.1's explicit warning).
2. Full validation of `subject_token` **and** `actor_token` before issuance (RFC 8693 §2.1 MUST).
3. Widening refusal in all four planes — RAR expansion, audience, scope, expiry — and **as an
   error, never a silent clamp** (§5.3 step 7).
4. All five RFC 9396 §5 MUST-refuse conditions, with `invalid_authorization_details`.
5. Exact RFC 8259 string comparison, no normalization (RFC 9396 §12) — a case-insensitive or
   Unicode-normalizing comparison is a real widening bypass.
6. Audience restriction to exactly one RS, and RS-side `aud` rejection (RFC 8707 §2; RFC 9068 §4
   MUST; OAuth 2.1 §7.1.4).
7. Expiry enforcement at both AS and RS.
8. `act`-based access control using the **outermost** actor only (RFC 8693 §4.1 MUST).
9. DPoP arm: the RFC 9449 §4.3 checks and §7.1's "MUST NOT grant access unless all checks
   succeed", including `ath` (§4.2).
10. Registry rejection of unmapped actors/keys (§F.2.1).

A tenth-of-a-second saved by skipping any of these is a result that means nothing.

### 8.2 Too slow — implementation choices that would bias the overhead result toward B3

B2's measured `delegation_cost` is an **online** AS round trip while B3's is **offline** (§E.2),
so any gratuitous inefficiency in the AS inflates the very quantity the study reports. Stance:
**a competent, straightforward implementation; deliberate pessimization is forbidden;
micro-optimization beyond that is not required.** Measurement itself is G-3/G-13, not this gate.
The choices that materially matter, each with the direction of its bias stated:

| Choice | Decision | Bias if done wrong |
|---|---|---|
| Key material | Parse the Ed25519 signing key **once at start-up**; reuse the signer object | Re-parsing per request inflates B2 (**toward B3**) |
| Token verification at the boundary | **Offline JWT verification**; no introspection round trip (RFC 9068; RFC 9396 §9.1 lets RAR ride in the JWT) | An introspection call would double the round trips (**toward B3**) |
| Connection handling | HTTP **keep-alive**, connection reused across hops | Per-hop TCP+TLS setup inflates B2 (**toward B3**) |
| Transport | TLS 1.3 on loopback (OAuth 2.1 §1.5 MUST). *Contingency:* if TLS on loopback proves to add unstable variance, fall back to plain-loopback HTTP and **disclose** — that fallback removes real deployment cost from B2 and therefore biases **against our own overhead claim** (conservative), which is the acceptable direction | Either direction is acceptable only if **stated** |
| State | In-memory registry and policy; no database, no disk I/O on the request path | Disk/DB latency inflates B2 (**toward B3**) |
| Serialization | Build the response once; no redundant encode/decode cycles | Avoidable round trips inflate B2 (**toward B3**) |
| Concurrency | One in-flight exchange at a time during timing runs | Queueing delay would be measured as protocol cost (**toward B3**) |
| Actor assertion | Provisioned in **Phase 1** and reused; never fetched per hop | A per-hop fetch would add a whole round trip that RFC 8693 does not require (**toward B3**) |
| DPoP nonces | If enabled, the first exchange costs one extra round trip (RFC 9449 §8); report `setup` and `steady-state` separately rather than averaging them | Averaging the challenge into every hop inflates B2 (**toward B3**) |
| Authorization endpoint | Not run; Phase-1 setup uses the pre-issued fixture path §E.2 permits, identical for **every** arm and excluded from the delegation estimand | Only defensible because it is excluded and identical across arms — stated, not hidden |

### 8.3 One disclosed non-conformance, on the record

RFC 9068 §2.1 requires a conforming AS and RS to **include RS256 among their supported
signature algorithms** `[VERIFIED]`. This project signs Ed25519 everywhere with an explicit
algorithm allowlist (ADR 0006), deliberately excluding RSA. The profile therefore uses the
RFC 9068 **shape** — `typ: at+jwt`, the required claim set, `aud` from `resource`, the §4
validation rules — while being **not RFC 9068-conformant**. Consistent with G-5's stance on
Ed25519 DPoP proofs (`smoke/g5/REPORT.md` §8), the benchmark is self-contained and no external
interoperability is claimed. **No document may describe the AT profile as "RFC 9068-compliant".**
Adding RS256 purely to claim the label would introduce an algorithm the project deliberately
excluded and widen the verifier's accepted-algorithm surface; that trade was declined
knowingly, not overlooked.

---

## 9. The three dependency conflicts (STEP 5) — resolved honestly

None is closed by inventing a frozen value. Every stand-in is **spike-local, explicitly
labelled, and never promoted to a frozen artifact**; each carries the event that re-triggers the
affected limb, mirroring the standing pin rule that any bump re-triggers its gate.

### C1 — `Ω` and `Γ` were UNSET — **CLOSED 2026-07-29 by ADR 0016**

> **Closed.** `Ω` (7 elements over 5 tools) and `Γ` (the MSc-profile authorizer plus its matched
> `−attenuation` ablation) are frozen in `src/harness/authorizer/omega_gamma_v1.json` and hashed as
> `H(Γ)`; `docs/frozen_parameters.md` row 8 is set. **Phase 2 needs no `Ω_spike`/`Γ_spike`**: the
> effective-authority limb (**L2**, §10) runs against the frozen values, and the value-level
> re-adjudication trigger below is discharged in advance — nothing in L2 is now provisional on a
> spike vocabulary. Two things are unchanged: G-4's pass criteria (ADR 0008), and the fact that
> **G-2 has still not run** — the freeze gives G-2 something to test, it does not test it, so IA-2
> remains **[UNVERIFIED-IA]** and no claim about Biscuit monotonicity under `Γ` may be made from
> this closure. A later amendment of `Ω`/`Γ` (permitted by ADR 0016 until Part H step 3) re-opens
> this limb.
>
> *(Update, 2026-07-29: G-2 has since run and **PASSED**; IA-2 is verified by that gate
> (`smoke/g2/REPORT.md`). The sentence above stands as the state at closure. This changes nothing
> for G-4: its pass criteria are unchanged (ADR 0008), **IA-4 remains [UNVERIFIED-IA]**, `authlib`
> stays unpinned, and G-2's result speaks only to authorizer semantics over the frozen `Ω`/`Γ` —
> not to the AS, the OAuth layer, or the `Allowed(AT_i) = C_i` equality, which is G-13's.)*
>
> The record of the stand-in that was planned, and of what it would and would not have
> established, is kept below unchanged.

- **Stand-in.** `Ω_spike` — a small enumerated action/resource-kind vocabulary defined inside
  `smoke/g4/`, and `Γ_spike` — a minimal authorizer sufficient to compute `Allowed(P_i)` for the
  spike's chain. Both live under the spike, both carry a `SPIKE-LOCAL — NOT THE FROZEN Ω/Γ`
  banner, neither is written to `docs/frozen_parameters.md` (row 8 stays UNSET), and neither may
  be imported by `src/`.
- **Establishes.** That the AS's containment check and the boundary's `Allowed(AT_i)` ∩
  OAuth-resource computation are **mechanically correct over a well-formed vocabulary**: a
  narrowing exchange succeeds, a widening exchange is refused with the right error, and the
  effective authority is the intersection of the two planes.
- **Does NOT establish.** That the *frozen* authorizer yields these `C_i`; nothing about
  Biscuit monotonicity under `Γ` (that is **G-2**, IA-2); and therefore nothing about the F1
  prevention claim.
- **Re-adjudication trigger.** `Γ` frozen and hashed at **G-2** ⇒ re-run G-4's effective-authority
  limb against the frozen `Ω`/`Γ` before any confirmatory result is reported.

### C2 — `INV.access_token_hash = H(AT@aud)` has no fixed construction — **CLOSED 2026-07-29 by ADR 0018 at G-11**

> **Closed.** ADR 0018 **adopted the proposal below unchanged** and gate G-11 verified the binding
> through the real HTC/INV verifier, rejecting a swapped token as `inv_access_token_hash`. The
> judgement recorded below — that the limb could not be honestly adjudicated at Phase 2 because INV
> did not yet exist — held, and refusing to invent the construction there is what made this
> adjudication an adjudication rather than a ratification. The three-way distinctness the trap warned
> about is now pinned by test: `access_token_hash` (lowercase hex, tagged) differs from `ath`
> (base64url over the **same** input bytes) and from `H_JCS` (over canonical JSON). Still open, and
> **not** closed by ADR 0018: `label_assertions_digest` and `authz_context_hash` remain ADR 0009
> category (c), deferred to the F4 label decision (`frozen_parameters` rows 4/6, UNSET) and **G-15**.
> The record below is kept unchanged.


ADR 0009 classifies it **category (c)**, *"fixed when INV/HTC are built and mutation-tested
(G-11)"*. The adjacent trap is real and now confirmed against the text: RFC 9449's `ath` is
**base64url(SHA-256(ASCII(token)))** `[VERIFIED, §4.2]` over a **string**, whereas `H_JCS` is
defined over the RFC 8785 canonical bytes of a **JSON object** (ADR 0009) and renders lowercase
hex — different domain, different encoding, different purpose. **Two digests over the same token
must never be conflated**, and `H_JCS` must not be assumed to apply.

- **Proposal, never an assumption.** The natural candidate is the same tagged/versioned/
  length-delimited family as ADR 0003/0009, over the ASCII token bytes:
  `lowercase_hex( SHA-256( b"AASC-AT-DIGEST" ‖ 0x01 ‖ u32be(len(t)) ‖ t ) )` — distinct from both
  `ath` and `H_JCS` by tag and encoding. **This is a proposal for G-11 to adjudicate; it is not
  settled here and no code may treat it as settled.**
- **Judgement: this limb cannot be honestly adjudicated at Phase 2.** INV does not exist yet
  (it is built and mutation-tested at G-11), so there is nothing to verify `access_token_hash`
  *in*. A stand-in digest would let us report a pass on a construction that G-11 may replace —
  the same underspecification G-8 refused to invent and ADR 0009 later closed.
- **Proposed scoping (for the Commander, not enacted here).** Phase 2 adjudicates the AS-side
  **precondition** only: the exact AT byte string presented at the boundary is observable and
  stable, so any digest binding is computable over it, and a swapped token is detectable. The
  `INV.access_token_hash` limb itself is adjudicated in a **follow-on G-4 run after G-11**.
  G-4's pass criterion is **unchanged** — what is scoped is *when* it can honestly be evaluated,
  and until then the smoke board must not show G-4 as fully adjudicated.
- **Re-adjudication trigger.** `access_token_hash` fixed at **G-11** ⇒ run the follow-on limb.

### C3 — the identity-plane registry is not built and no HTC chain exists — **CLOSED 2026-07-29 by ADR 0019 at G-11**

> **Closed.** The registry is built and frozen as `src/harness/verifier/identity_registry_v1.json`
> (ADR 0019, `H(R) = d1bfc5ff…`, `docs/frozen_parameters.md` **row 11**), and G-11 re-ran the
> `actor→holder` limb against it. The outcome is **unchanged** from the stand-in — the actor resolves
> to exactly one principal and one holder key, an unmapped actor is rejected, and
> `resource_owner = holder` is never required — which is the useful result: the stand-in had not
> flattered the finding. What the stand-in explicitly could not establish and G-11 now does: the
> resolved key is checked by a verifier that also validates the HTC chain it terminates. Two things
> the freeze deliberately does **not** cover: `H(R)` hashes structure and derivation labels, **not**
> key bytes (per-campaign material sealed at Part H step 3, the same line ADR 0016 drew for `Γ`/`κ`);
> and the `task_authorization_policy` is **not** this registry — row 5 stays UNSET, so F2
> `wrong_principal` stays unscored. The record below is kept unchanged.


- **Stand-in.** A spike-local registry: `oauth_actor → principal → Ed25519 public key`, with the
  key being a **raw spike key, not the terminal key of a real HTC chain**, plus at least one
  deliberately unmapped actor to exercise rejection. Labelled `SPIKE-LOCAL`; the frozen registry
  remains a seal-time artifact (§F.2.1, Part H step 3).
- **Establishes.** That the AS emits `act`/`client_id` from which `actor_of(·)` resolves to
  exactly one principal and exactly one holder key; that an unmapped actor is **rejected**; and
  that the check is `oauth_actor → htc_holder` only, never `resource_owner = holder`.
- **Does NOT establish.** That the resolved key is the terminal holder of a verified HTC chain
  (**G-11**), nor the contents of the frozen registry (seal time), nor anything about
  `holder_proof_ok`.
- **Re-adjudication trigger.** The HTC chain and the identity-plane registry built at **G-11**
  ⇒ re-run the `actor→holder` limb end-to-end against a real terminal holder key.

---

## 10. Phase-2 test plan

One row per G-4 pass-criterion limb, then the stand-ins, then the two G-5 hand-forwards.

| # | Limb / item | Test | Adjudicable at Phase 2? |
|---|---|---|---|
| L1 | *Task-narrowed token issues* | Exchange `AT_{i−1}` → `AT_i` with `AD_i ⊊ AD_{i−1}`; assert the response carries the granted RAR (RFC 9396 §7) and `scope` when narrowed (RFC 8693 §2.2.1); assert `expand(AT_i.AD) = C_i` | **Yes** |
| L1′ | *Widening refused* | Four widening attempts — extra `actions`, extra `datatypes`, wider `resource`, longer `exp` — each rejected with the §6 error, **no token issued**, no silent clamp | **Yes** |
| L2 | *Both layers enforced; OAuth-resource ∩ capability effective authority* | At the boundary, `Allowed(AT_i)` ∩ OAuth plane; a request inside RAR but outside `scope`/`aud` is denied, and vice versa | **Yes, over the frozen `Ω`/`Γ`** (ADR 0016 closed C1; no stand-in) — re-run only if `Ω`/`Γ` are amended |
| L3 | *`actor→holder` mapping resolves* | Registry resolution for a valid actor; rejection for an unmapped actor; a negative test asserting the AS/boundary never requires `resource_owner = holder`; nested-`act` history present but **not** consulted (RFC 8693 §4.1) | **Yes, with the spike registry** (C3) — re-run at G-11 |
| L4 | *`INV.access_token_hash` verified* | Precondition only: the presented AT byte string is observable and stable at the boundary; a swapped token is detectable | **No — scoped to a follow-on run after G-11** (C2) |
| A1 | Delegation semantics | `sub` = resource_owner, outermost `act` = current actor, prior actor nested; impersonation-shaped issuance (actor written into `sub`) is absent | Yes |
| A2 | Rejection catalogue | One test per row of §6, asserting the **exact** error code and status | Yes |
| A3 | RFC 9396 §12 string rule | `Read` vs `read`, and NFC-vs-NFD variants of an action string, are **not** equal and do not narrow-match | Yes |
| A4 | Key isolation (**additional evidence, not a criterion change**) | An SUT-side attempt to mint its own `AT` fails: the signing key is absent from every agent process | Yes |
| A5 | `ath` (G-5 hand-forward) | A protected-resource call in the DPoP arm carries `ath`; a proof with a wrong/missing `ath` is rejected; the AT's bound key must match the proof key (RFC 9449 §4.3 item 12, §7.1) | Yes — first real exercise |
| A6 | DPoP nonce (G-5 hand-forward) | Nonce-required path: HTTP 400 `use_dpop_nonce` + `DPoP-Nonce`; retry with the nonce succeeds; a stale nonce is rejected; AS and RS nonce namespaces are distinct (§§8–9) | Yes — first real exercise |
| A7 | `htu` normalization | RFC 3986 syntax/scheme normalization before comparison (closes the G-5 residual) | Yes |

Every stand-in used in a test prints its `SPIKE-LOCAL` banner in the report, so no reader can
mistake a spike value for a frozen one.

---

## 11. Explicit non-goals

Building the arms; the HTC/INV constructs (**G-11**); the effect ledger (**G-7**, done) and any
fixture; G-13's `Allowed(AT_i) = C_i` verification across all baselines; the four-way DPoP
taxonomy (**G-14**); the F4/F5 reference-monitor work (**G-15**); any performance measurement
(**G-3**, whose threshold must be fixed externally first); freezing `Ω`, `Γ`, the registry, or
the `task_authorization_policy`; and any change to G-4's pass criteria, dependency edges, or
evidence grades.

(Historical note, 2026-07-29: `Ω` and `Γ` were frozen afterwards, in a separate pass — **ADR
0016** — which is what closed §9's C1. The registry and the `task_authorization_policy` remain
unfrozen, and none of this changed a G-4 criterion.)
