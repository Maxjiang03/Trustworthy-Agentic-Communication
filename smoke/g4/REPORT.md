# Gate G-4 Report (Phase 2) — the pinned experiment AS, built and adjudicated

**Outcome: PASS over the criteria's adjudicable limbs.** L1, L1′, L2, L3 and A1–A7 all hold.
**Limb L4 (`INV.access_token_hash`) is NOT closed** — it is scoped to a follow-on run after G-11
(§9 C2), and only its AS-side precondition was tested here. **This is not a full four-limb
closure**, and the smoke board must not be read as one.

Built 2026-07-29. `smoke/g4/spike.py` exit 0, twelve mandatory checks; regression suite
`tests/test_oauth_as.py`, 78 tests. The AS is `src/sut/oauth_as/` (ADR 0015); the boundary side is
`src/sut/authz/boundary.py`; DPoP is shared at `src/sut/dpop.py`.

**Disclosed non-conformance, restated here as §8.3 requires.** RFC 9068 §2.1 requires a conforming
AS and RS to include **RS256** among their supported signature algorithms. This project signs
Ed25519 everywhere with an explicit algorithm allowlist (ADR 0006), deliberately excluding RSA. The
profile uses the RFC 9068 **shape** — `typ: at+jwt`, the required claim set, `aud` from `resource`,
the §4 validation rules — and is **not RFC 9068-conformant**. No document may describe it as
"RFC 9068-compliant".

## 1. Gate

The Part G G-4 row, reproduced exactly, not paraphrased:

| Gate | Runs | Pass criterion | Blocks |
|------|------|----------------|--------|
| **G-4** | RFC 8693 exchange under the pinned AS profile yielding `C_i`; verify OAuth-resource ∩ capability effective authority, `actor→holder` mapping, `INV.access_token_hash` | Task-narrowed token issues; both layers enforced; actor mapping resolves | IA-4; B2-exchange-task and the fair-baseline claim |

The gate-outcome policy, also verbatim: **"G-4 fails → build a behaviourally faithful AS enforcing
the mandated checks directly; disclose it."** That is in fact the path taken — the `authlib` probe
found the candidate UNSUPPORTED at Phase 1, so IA-4's *second* limb ("or a behaviourally faithful
AS can be built") is what this pass discharges. The AS was built by hand and is disclosed
throughout.

Adjudication precondition satisfied: G-6 and G-7 are PASS (ADR 0008), and ADR 0016 closed conflict
C1 so limb L2 runs over the **frozen** `Ω` with no stand-in.

## 2. The design read, and what was underspecified for implementation

`smoke/g4/DESIGN.md` was read in full (613 lines): §5.1 shape/endpoints/token format, §5.2 `C_i` as
a single-type RAR array with `expand` and byte-exact containment, §5.3 the hop-`i` exchange and the
four planes in which widening is an **error**, §5.4 process and key isolation, §6 the rejection
catalogue, §7 the identity plane including §7.3's two different "holders" and §7.4's inherited
dependency, §8.1/§8.2/§8.3, §9 (C1 closed; C2 and C3 open), §10 the test plan, §11 non-goals. Also
read: the Part G G-4 row verbatim, ADR 0015 and its four travelling rules, ADR 0016 (the frozen `Ω`
and its US-ASCII lowercase encoding, mapped onto RAR `actions` and `datatypes`), `smoke/g2/REPORT.md`
(what G-2 established, and that `R ⊆ C_n` is explicitly **not** established and belongs to G-13),
and `smoke/g5/REPORT.md` §§8–9 for the `ath`/nonce hand-forwards.

Seven points were underspecified for implementation. None was filled by silent assumption; each
resolution is recorded here.

1. **No request parameter through which a client can ask for a lifetime.** §5.3's request table names
   none, yet §5.3 step 7 and §6 row 11 both require `exp_i > exp_{i−1}` to be a **refusable
   widening** — untestable if it cannot be requested. Resolved with a profile extension parameter
   `requested_expires_in`, which OAuth 2.1 §4.4 permits ("plus any additional parameters").
2. **No default-lifetime policy — and the naive reading makes hop 2 impossible.** With a fixed
   default equal to the root's lifetime, the parent's *remaining* lifetime is always shorter by the
   elapsed time, so the second hop always violates `exp_i ≤ exp_{i−1}`. Observed directly: hop 2
   returned `400 invalid_authorization_details "requested lifetime extends beyond the subject
   token's exp"`. That would break the per-hop exchange §E.2 requires. Resolved by separating two
   different things: an **explicit** over-long `requested_expires_in` is a widening **error**
   (L1′ row 4, unchanged), while with **no** lifetime requested the AS caps **its own** default at
   `exp_{i−1}`. Nothing the client asked for is quietly reduced, so this is AS policy, not the
   silent clamp §5.3 forbids. Pinned by `test_unrequested_default_lifetime_is_capped_not_refused`,
   whose negative arm keeps the explicit case an error.
3. **`identifier` semantics.** §5.2 lists it as permitted, but RFC 9396 §2.2's product rule covers
   only `locations` × `actions` × `datatypes` — `identifier` is not a product field, so a naive
   implementation would give it no meaning or, worse, a second unexpanded authority channel.
   Resolved: `identifier` MUST be one of the object's own `datatypes`, so it can restate or narrow
   but never widen; anything else is `invalid_authorization_details`.
4. **Pair-level versus value-level `Ω` membership.** §5.2 says "every value must be a member of
   `Ω`", which is weaker than what §A.0.1 requires: `C_i ⊆ Ω` is a constraint on the **pair**. An
   object with `actions: [notes.read, notes.write]` and `datatypes: [notes/project, notes/meeting]`
   expands to four pairs, of which `(notes.write, notes/meeting)` is **not** an `Ω` element even
   though both strings are. Resolved by checking membership **pairwise**; splitting such a request
   across several same-type objects is the RFC-sanctioned expression (§2 allows several entries of
   one type). Pinned by `test_pairs_outside_omega_are_rejected_even_when_each_value_is_valid`.
5. **The catalogue's row count.** The task specification describes §6 as a "seventeen-row"
   catalogue and asks for "seventeen rows, seventeen tests". The table in §6 has **15** data rows,
   plus a closing resource-server paragraph enumerating six more conditions (`typ ≠ at+jwt`,
   `alg: none`, `iss` mismatch, `aud` not naming this RS, bad signature, expired → `invalid_token`).
   Recorded rather than reconciled by guesswork, and covered as a **superset**: 24 AS-side
   catalogue checks in the spike over the 13 rows reachable without the DPoP arm (rows 14–15 are
   A5/A6), plus the resource-server conditions at the boundary.
6. **`may_act` has nothing to key on.** §7.4 says the policy answers "which principals may act for
   this subject **on this task**", but §5.1's AT claim set contains no task claim, and inventing one
   would add a claim the design does not specify. Resolved with a **SPIKE-LOCAL** policy keyed on
   the current actor's principal (a delegation chain: supervisor → specialist → worker), written
   into `may_act` as the RFC 8693 §4.4 single object. The frozen `task_authorization_policy`
   (`frozen_parameters` row 5, **UNSET**) will key on subject and task; the F2 `wrong_principal`
   family is not scored until then (§7.4).
7. **`audience` versus `resource`.** RFC 8693 §2.1 defines both; §5.3's table names only `resource`.
   Resolved: exactly one `resource` is required, and any additional `resource` or `audience` value
   counts toward the multi-target check (`invalid_target`, RFC 8693 §2.1.1).

**One check the design states but the first implementation omitted.** §5.3's opening sentence says
*"The **delegating** agent (holder of `AT_{i−1}`) is the client of the exchange"*, but the numbered
steps never restate it, and the first working AS resolved the subject token's current actor and then
never used it — caught by the linter as a dead variable rather than by a test, which is worth
admitting. Client authentication alone does **not** imply the property: without the check, any
*other* registered client that came to possess a token could exchange it onward, which is the abuse
RFC 8693 §2.1 warns about in the neighbouring case it does cover. Now enforced — the client's
principal must equal the principal of the subject token's outermost `act` (or `client_id` at hop 0) —
refused as `invalid_request` ("unacceptable based on policy", §2.2.2), and pinned by
`test_only_the_current_holder_may_exchange_the_token` with a positive arm showing the genuine holder
still succeeds.

## 3. What was built, where, and how isolation is realized

| Module | Role |
|---|---|
| `src/sut/oauth_as/server.py` | `POST /token` only, TLS 1.3 on loopback, HTTP/1.1 keep-alive |
| `src/sut/oauth_as/exchange.py` | the ten fail-closed §5.3 steps; `parse_form`; `issue_initial` |
| `src/sut/oauth_as/rar.py` | RFC 9396 validation, `expand`, containment, audience filtering |
| `src/sut/oauth_as/tokens.py` | `at+jwt` mint/verify, actor assertions, `act` nesting |
| `src/sut/oauth_as/keys.py` | seed→Ed25519 derivation, client secrets, algorithm allowlist |
| `src/sut/oauth_as/errors.py` | the §6 catalogue as code, each row named |
| `src/sut/oauth_as/config.py` | start-up configuration; `Ω`, registry and policy all injected |
| `src/sut/oauth_as/__main__.py` | out-of-process entry point; seed from the environment |
| `src/sut/dpop.py` | RFC 9449 proofs, nonce stores, `htu` normalization (shared, AS + RS) |
| `src/sut/authz/boundary.py` | RS-side `invalid_token` checks and `Allowed(AT_i)` (limb L2) |

**Endpoints.** Exactly one. No authorization endpoint, no introspection, no revocation, no
`.well-known` metadata, no `jwks_uri`; a `GET` to either a discovery path or `/jwks` returns 404,
asserted by `test_no_discovery_or_jwks_endpoint`. `AT_0` is minted by `issue_initial`, a library
call on the **provisioning** path — not reachable over HTTP — which is the pre-issued fixture path
§E.2 permits and §8.2's last row requires.

**Dependencies: nothing new is pinned.** The stdlib supplies the HTTP server and client
(`http.server`, `http.client`, `ssl`); `joserfc==1.7.4` (ADR 0006) supplies JOSE; `cryptography`,
already a dependency, supplies HKDF derivation and the run-time self-signed certificate. All three
were probed before writing code: TLS 1.3 negotiated on loopback, the connection reused, and an
Ed25519 `at+jwt` round-tripped with tamper and wrong-key rejection. The `# PENDING GATE` block is
untouched and `authlib` remains unpinned.

**§5.4 isolation, as realized.** The AS runs in its own OS process bound to `127.0.0.1` only. The
Ed25519 signing key is derived **inside** that process by HKDF-SHA256 from the sealed seed, which
arrives in the environment variable `AASC_G4_AS_SEED` — never on the command line, where a process
listing would expose it. The key is never written to disk and never exported; only the public JWK
leaves, on one stdout line together with the bound port and the TLS certificate, all three public
by construction. The configuration file carries **no secret**: client secrets are derived in-process
from the same seed under a distinct HKDF `info` label.

Stated plainly, because it is the honest limit of the claim: **isolation rests on two things
together** — the private key never leaving the process, *and* the runner giving the seed to no agent
process. A principal holding the seed can derive the key by construction; that is what "sealed"
means operationally.

One mechanism is disclosed rather than glossed: stdlib `ssl` can only load a certificate chain from
a **file**, so the run-time **TLS** key is written to a private temporary file and deleted
immediately once the context holds it. That is the TLS key, not the AS signing key, which never
leaves memory. `test_the_as_signing_key_is_never_written_to_disk` scans the project trees for the
private scalar and finds nothing.

## 4. §8.1 — every check that must not be dropped, row by row

All ten are present **and exercised**; none was weakened "for now". Dropping any would make B2 lose
on a technicality rather than on the mechanism.

| # | §8.1 check | Where | Exercised by |
|---|---|---|---|
| 1 | Client authentication on every exchange | `exchange` step 1 | `client-unauthenticated` → 400; `client-bad-secret` → **401 + `WWW-Authenticate`** |
| 2 | Full validation of `subject_token` **and** `actor_token` before issuance | steps 2–3 | tampered / expired / foreign subject; malformed actor; missing `actor_token_type` |
| 3 | Widening refusal in all four planes, **as an error, never a silent clamp** | step 7 | L1′: four attempts, each asserting the **absence** of `access_token` |
| 4 | All five RFC 9396 §5 MUST-refuse conditions, with `invalid_authorization_details` | `rar.validate_details` | five tests + three profile additions |
| 5 | Exact RFC 8259 string comparison, no normalization | `rar.contains` (`str` equality) | A3: `Notes.read` and an NFD variant both refused |
| 6 | Audience restriction to exactly one RS, and RS-side `aud` rejection | step 7 + `boundary` | `multi-target` → `invalid_target`; token presented to another RS → `invalid_token (aud)` |
| 7 | Expiry enforcement at **both** AS and RS | `_check_window`, step 7, `boundary` | expired subject refused; expired AT refused at the boundary |
| 8 | `act`-based access control using the **outermost** actor only | `current_actor` | nested chain present, `current_actor` returns the outermost |
| 9 | DPoP §4.3 checks and §7.1's "MUST NOT grant access unless all succeed", including `ath` | `dpop.verify_proof` | items 1, 7, 8, 9, 10, 12 each asserted by number |
| 10 | Registry rejection of unmapped actors/keys | step 4 | unmapped actor → 400 `invalid_request` |

## 5. §8.2 — the efficiency choices, row by row, with bias direction

B2's `delegation_cost` is an **online** round trip while B3's is offline, so gratuitous inefficiency
inflates the very quantity the study reports — biasing the result **toward B3**, toward this study's
own hypothesis. Each row was implemented as decided.

| §8.2 choice | Implemented | Note |
|---|---|---|
| Key material parsed once at start-up, signer reused | Yes — `derive_signing_key` is called once in `__main__`; the `SigningKey` is held by the server | Re-parsing per request would inflate B2 |
| Offline JWT verification at the boundary, no introspection | Yes — `boundary.verify_access_token` is offline; no introspection endpoint exists to call | RAR rides in the JWT (RFC 9396 §9.1) |
| HTTP keep-alive, connection reused across hops | Yes — `protocol_version = "HTTP/1.1"`; pinned by `test_connection_is_reused_across_hops`, which asserts one socket serves three exchanges and that TLS 1.3 was negotiated | See the divergence below |
| TLS 1.3 on loopback | Yes — `minimum_version = TLSv1_3`, negotiated `TLSv1.3` asserted. **The §8.2 plain-HTTP contingency was NOT invoked** | It was offered for unstable variance, which this gate does not measure; invoking it for convenience would have been using a licence granted for another reason |
| In-memory state, no disk I/O on the request path | Yes — registry, clients and policy are in-memory dicts; `exchange` reads no file | |
| Response built once | Yes — one `TokenResponse.body()`, one `json.dumps` | |
| One in-flight exchange at a time **during timing runs** | **Not implemented, and not this gate's to implement.** The server is threaded so a client cannot deadlock it; serializing exchanges is a property of the *measurement protocol* at **G-3**, not of the AS | Stated rather than claimed |
| Actor assertion provisioned in Phase 1 and reused, never fetched per hop | Yes — assertions are provisioned by the fixture; the AS makes **no** outbound network call at all | A per-hop fetch would add a round trip RFC 8693 does not require |
| DPoP nonces: first exchange costs one extra round trip; report setup and steady state separately | Implemented and demonstrated (A6). The *reporting* separation is G-3's | |
| No authorization endpoint; Phase-1 setup uses the pre-issued fixture path | Yes — `issue_initial` is a library call; `GET` returns 404 | Defensible only because it is excluded from the estimand and identical across arms |

**One divergence, with its bias direction, found by measurement rather than by reading.** The first
working implementation dialled the AS by the name `localhost`. On a dual-stack host that resolves
`::1` first and waits for the connection to fail before falling back to IPv4, adding roughly
**0.7 s to every exchange** — the regression suite took **108.5 s**. That is precisely the
"per-hop TCP+TLS setup inflates B2 (**toward B3**)" hazard §8.2 names. Fixed by adding a `127.0.0.1`
IP SAN to the run-time certificate and dialling the literal loopback address: the same suite now
takes **2.69 s**, a 40× reduction. Recorded because it was a real §8.2 violation that reading the
code would not have revealed, and because a reader deserves to know the overhead figures this AS
will produce were not shaped by an accident of name resolution.

## 6. Per-limb results

`uv run python smoke/g4/spike.py` — exit 0. Scenario: the ADR 0016 golden thread over the frozen
`Ω`, `C_0` (5 elements) → `C_1` (3) → hop 2, with `Ω \ C_0` as the amplification surface.

### L1 — a task-narrowed token issues

**Constructed.** `AT_0` (authority `C_0`, scope `mcp.invoke mcp.read`, 600 s) exchanged for `AT_1`
with `AD_1 ⊊ AD_0`, over TLS 1.3.

**Observed.** `200`; the response carries the granted `authorization_details` (RFC 9396 §7 MUST),
`issued_token_type = urn:ietf:params:oauth:token-type:access_token`, and `token_type: Bearer`.
`scope` is **omitted** when identical to the request and **reported** as `mcp.invoke mcp.read` when
the client omits `scope` and the AS therefore grants something different (RFC 8693 §2.2.1). At the
boundary, `expand(AT_1.AD)` = `{(notes.read, notes/project), (notes.read, notes/meeting),
(notes.write, notes/project)}`, equal to the requested `C_1`.

**Failing world.** Granted details absent from the response (the client could not forward `C_1`, and
G-13's verifier would have nothing to read); or a narrowed scope silently unreported; or the
expansion disagreeing with the request, which would mean the token does not carry the authority the
exchange claimed to grant.

### L1′ — widening refused, in four planes, with no token issued

| Attempt | Response | Token issued |
|---|---|---|
| extra `actions` (`notes.delete`) | `400 invalid_authorization_details` | **no** |
| extra `datatypes` (`calendar/personal`) | `400 invalid_authorization_details` | **no** |
| wider `resource` (another RS) | `400 invalid_target` | **no** |
| longer `exp` (`requested_expires_in=99999`) | `400 invalid_authorization_details` | **no** |

Each assertion is on the **absence of `access_token`**, not merely on a differing response, because
a silent clamp is the failure mode: a `200` carrying the intersection would make `F1-chain-tamper`
indistinguishable from a benign narrowing. **Control:** the same request narrowed instead of widened
is issued `200`, so the refusals are about the widening and not about the request shape.

**Failing world.** A `200` with a clamped `authorization_details`, which the naive
"intersect and continue" implementation produces and which no assertion on the status code alone
would catch.

### L2 — both layers enforced, over the frozen `Ω`

**Observed.** `Allowed(AT_1)` = the three elements above, a subset of the frozen `Ω`. Inside both
planes → **admitted**. Inside the RAR but outside `scope` (`mcp.read` against a token scoped
`mcp.invoke`) → **denied**, "outside the OAuth-resource plane (scope)". Inside `scope` but outside
the RAR (`mail.send`) → **denied**, "outside the capability plane (authorization_details)". The same
token presented to a different resource server → `invalid_token (aud)` (RFC 9068 §4 MUST). RAR
objects naming another location contribute no authority.

No stand-in: ADR 0016 closed C1, so this ran against the frozen ontology, itself adjudicated by G-2.

**Failing world.** Either plane alone admitting what the other denies — which is exactly what
"both layers enforced" excludes, and what would let an over-broad scope or an over-broad RAR pass
unilaterally.

### L3 — `actor→holder` resolves (C3 stand-in)

**Observed.** The outermost `act.sub` = `agent-specialist` resolves to exactly one principal
(`specialist`) and exactly one holder key (`jkt=sQrQTknCmsdI0FMB…`). An unmapped actor is
**rejected** `400 invalid_request`. `resource_owner = user-yixian` differs from the actor and is
**absent from the holder registry** — the profile never requires `resource_owner = holder`
(§A.5.1 MUST NOT), and a profile that demanded equality would reject every legitimate delegated call
in the study. At hop 2 the `act` chain nests the prior actor `agent-specialist` beneath the current
`agent-worker`, and `current_actor` returns the **outermost** only (RFC 8693 §4.1 MUST).

**Failing world.** An unmapped actor admitted (the identity plane would not be enforced at all), or
a nested actor read as current — which would let a spent hop's identity authorize a later call.

### A1 — delegation, never impersonation

`sub` is the resource owner; the actor is **never** written into `sub`, so the impersonation shape
RFC 8693 §1.1 describes is absent; the outermost `act.sub` is the current actor; at hop 0 there is
no `act` and `oauth_actor` falls back to `client_id` (§A.5.1). **Failing world:** under
impersonation `sub` would carry the agent, collapsing §A.5.1's three-way split and with it the F2
`wrong_principal` family — the arm could not even express "the wrong agent presented a valid token".

### A2 — the rejection catalogue, exact code and status

24 AS-side checks over the 13 rows reachable without the DPoP arm, each asserting the exact code,
the exact status, and that **no token was issued**:

`client-unauthenticated → 400 invalid_client` · `client-bad-secret → 401 invalid_client` (with
`WWW-Authenticate`, OAuth 2.1 §3.2.4) · `grant-type → 400 unsupported_grant_type` ·
`missing-parameter → 400 invalid_request` · `duplicated-parameter → 400 invalid_request` ·
`subject-token-invalid / -expired / -foreign → 400 invalid_request` ·
`actor-token-invalid → 400 invalid_request` · `actor-token-type-missing → 400 invalid_request` ·
`unmapped-principal → 400 invalid_request` · `may-act → 400 invalid_request` ·
`rar-unknown-type / -unknown-field / -wrong-field-type / -invalid-value / -missing-field → 400
invalid_authorization_details` · `rar-privileges / -outside-omega / -multi-location → 400
invalid_authorization_details` · `widening → 400 invalid_authorization_details` ·
`audience-unknown / resource-malformed / multi-target → 400 invalid_target`.

Rows 14–15 (`invalid_dpop_proof`, `use_dpop_nonce`) are exercised by A5/A6. The resource-server
conditions are exercised at the boundary as `invalid_token` with the failing check named (`typ`,
`alg`, `iss`, `aud`, `exp`, signature).

**Failing world.** Any row answering a different code or status — a test that accepted "some error"
would have passed against an AS that refuses everything for the wrong reason, which is why each
assertion names the code.

### A3 — the RFC 9396 §12 string rule

`Notes.read` is refused `400 invalid_authorization_details`; an NFD variant of `notes/project` is
refused likewise. The two forms are **unequal as strings** yet **would collide under
normalization** — which is precisely the widening bypass the MUST forbids. Because ADR 0016 froze
`Ω` as US-ASCII lowercase, a decomposed variant is additionally simply not an `Ω` element, so both
the encoding rejection and the non-equality hold. **Control:** the exact frozen strings are
accepted, so the refusals are about the strings and not the request. **Failing world:** a
case-folding or NFC-normalizing comparison, under which `Notes.read` would narrow-match `notes.read`
and an attacker could widen authority through spelling.

### A4 — key isolation (additional evidence, explicitly not a criterion change)

Both ADR 0015 import rules asserted **programmatically** by scanning every `.py` file: `src/harness/`
importing `src.sut.oauth_as` → **none**; other `src/sut/` modules importing it → **none**. A separate
agent process, started **without** the sealed seed (`seed_in_env=False`), minted a maximal-authority
token with a key of its own and presented it to the boundary holding the **real** AS public key: the
boundary **rejected** it, `invalid_token (signature)`. **Positive arm:** a genuine AS-issued token is
accepted by that same verifier, so the rejection is about the key and not a verifier that refuses
everything. The forge script requires the real AS public key as an argument and exits non-zero
without it — verifying a forgery against its own key would have proved nothing.

### A5 — `ath`, the first real exercise of the G-5 hand-forward

A proof carrying `ath = base64url(SHA-256(ASCII(AT)))` is accepted at a protected resource and
returns the bound `jkt`. Missing `ath`, a wrong `ath`, and a proof signed by a key other than the one
`cnf.jkt` binds are each rejected at **RFC 9449 §4.3 item 12**. `test_ath_is_not_h_jcs` pins the §9
C2 trap: `ath` is unpadded base64url over an ASCII **string**, `H_JCS` is lowercase hex over the
RFC 8785 canonical bytes of a JSON **object**, and the two digests over the same token must never be
conflated. **Failing world:** a captured proof replayable against a *different* token, which is
exactly what `ath` exists to prevent.

### A6 — DPoP nonces, the first real exercise

A proof with no nonce is answered `HTTP 400 use_dpop_nonce` with a `DPoP-Nonce` header
(`as.qowTomuG0QZCn…`); the retry carrying it succeeds with `token_type: DPoP` (RFC 9449 §5 MUST); a
retired nonce is refused `400 use_dpop_nonce`; and AS and RS nonces are **mutually invalid** (§9).
Namespace separation is enforced twice over — separate stores *and* a namespace tag inside the nonce
— so a nonce lifted from one server fails at the other even if the stores were merged by mistake.
**Failing world:** a stale nonce accepted (the challenge would be theatre), or an RS nonce
satisfying the AS — the conflation §9 warns against.

### A7 — `htu` normalization, closing the G-5 residual

Four equivalent forms are accepted after RFC 3986 syntax- and scheme-based normalization: default
port `:443`, uppercase scheme and host, a `./` dot segment, and a query plus fragment. A genuinely
different path is still refused at **item 9**, and a wrong method at **item 8**. **Failing world:**
normalization accepting a different resource — laundering a mismatch rather than normalizing an
equivalent form — which would let a proof minted for one endpoint authorize a call to another.

### L4 — precondition only; the limb is **not** adjudicated

Shown: the AT byte string presented at the boundary is observable and ASCII-stable, and a different
token is a different byte string with a different digest, so any digest binding is computable over it
and a swap is detectable.

**Not shown, deliberately.** `INV.access_token_hash` is **not** verified, because INV does not exist
until it is built and mutation-tested at **G-11** — there is nothing to verify a digest *in*. The
`AASC-AT-DIGEST` construction §9 C2 sketches remains a **proposal for G-11**; no code here treats it
as settled, and the SHA-256 used above is illustrative only. Reporting a pass on a stand-in digest
would be a pass on a construction G-11 may replace — the same underspecification G-8 refused to
invent and ADR 0009 later closed properly.

## 7. The C3 stand-in: scope, banner, and re-trigger

The spike-local registry lives in `smoke/g4/campaign.py` and prints
`SPIKE-LOCAL — NOT A FROZEN ARTIFACT` in the spike header and in the L3 evidence line.

- **Establishes.** That the AS emits `act`/`client_id` from which `actor_of(·)` resolves to exactly
  one principal and exactly one holder key; that an unmapped actor is **rejected**; and that the
  check is `oauth_actor → htc_holder` only, never `resource_owner = holder`.
- **Does NOT establish.** That the resolved key is the terminal holder of a **verified HTC chain**
  (the holder keys here are raw spike keys); nor the contents of the frozen identity-plane registry,
  which stays a seal-time artifact (§F.2.1, Part H step 3); nor anything about `holder_proof_ok`.
- **Re-trigger.** The HTC chain and the registry are built at **G-11** ⇒ re-run the `actor→holder`
  limb end-to-end against a real terminal holder key.

The `may_act` delegation policy is the same kind of stand-in: the frozen `task_authorization_policy`
is `frozen_parameters` **row 5, UNSET**, and the F2 `wrong_principal` family is **not scored** until
that row is fixed by its own ADR (§7.4). No `frozen_parameters` row was set in this pass.

## 8. Outcome and grades

**G-4 PASSES over its adjudicable limbs**, with L4 pending a post-G-11 follow-on.

`[VERIFIED]` for **this AS build** (`src/sut/oauth_as/`, `joserfc==1.7.4`, stdlib HTTP/TLS): an
RFC 8693 exchange under the pinned profile issues a task-narrowed token carrying `C_i` as a
single-type RFC 9396 RAR array and reporting the granted scope when it differs; widening is refused
as an error with no token issued in all four planes; the fifteen-row catalogue answers with the exact
codes and statuses; containment is byte-exact with no normalization and confined to the frozen `Ω`;
the boundary independently enforces the **intersection** of the capability and OAuth-resource planes;
delegation semantics carry `sub` = owner with the actor in a nested `act` whose outermost element
alone is consulted; the `actor→holder` mapping resolves and rejects unmapped actors; `ath`, DPoP
nonces and `htu` normalization behave per RFC 9449; and the AS signing key stays inside the AS
process, with both ADR 0015 import rules holding.

**IA-4 moves from [UNVERIFIED-IA] to verified by gate G-4**, by its **second** limb — "a
behaviourally faithful AS can be built" — the first limb having been refuted for `authlib==1.7.2`
at Phase 1. Scope and residuals in §9.

What remains `[DESIGN]`: the profile's *choices* (the RAR type URI, the four-plane narrowing policy,
the `requested_expires_in` extension, the `identifier` rule), and everything §9 lists.

## 9. Residual risks

- **L4 is open.** `INV.access_token_hash` is adjudicated in a follow-on G-4 run **after G-11**. The
  smoke board must not show G-4 as fully adjudicated until then.
- **The C3 stand-in.** The holder keys are spike keys, not HTC terminal keys; re-triggered at G-11.
- **Row 5 is UNSET.** `may_act` is populated from a spike-local policy; the F2 `wrong_principal`
  family is not scored until the frozen `task_authorization_policy` exists.
- **Not RFC 9068-conformant**, by decision (§8.3). No interoperability with external systems is
  claimed.
- **`authlib` stays unpinned.** The `# PENDING GATE` block is unchanged; the probe's UNSUPPORTED
  verdict stands for `authlib==1.7.2` and nothing here revisits it.
- **Exact pins.** `joserfc==1.7.4` (any bump re-triggers G-5); `Ω`/`Γ` amendments re-trigger G-2
  **and** this gate's effective-authority limb (ADR 0016).
- **The TLS key touches a temporary file** for the duration of one `load_cert_chain` call, because
  stdlib `ssl` offers no in-memory alternative. The AS **signing** key never does.
- **Seed custody is the isolation boundary.** Anyone holding the campaign seed can derive the AS
  signing key; the guarantee is that the runner gives it to no agent process.
- **Client secrets are derived, not stored.** No secret appears in the repository or in the AS
  configuration file (CLAUDE.md red line 8).
- **The AS is single-tenant and stateless apart from nonces.** No revocation list, no replay cache
  (B3⁺'s `jti` cache is **G-9**), no rate limiting.

## 10. What this gate does NOT establish

- **Not G-13's `Allowed(AT_i) = C_i`** across baselines, nor matched per-hop authority. The
  boundary's containment check here is deliberately single-element, only what L2 needs; G-2's report
  already flagged the general `R ⊆ C_n` rule as untested and G-13's, and this pass did not annex it.
- **Not the four-way DPoP taxonomy** — captured-proof replay, first-use body mutation, compromised
  holder are **G-14**. `ath` closes token substitution only; it neither prevents proof replay nor
  binds the request body [VERIFIED, RFC 9449 §7.1].
- **Not HTC or INV** — holder proofs, `capability_hash`, `access_token_hash` are **G-11**.
- **Not the arms, agents, protocol adapters, fixtures, or the oracle.** No MCP server was built:
  the resource-server checks run as the boundary's verification logic, which is what a real RS calls,
  rather than over a second socket — protocol adapters being a §11 non-goal.
- **No timing claim.** Every figure in §5 is a build-time observation, not a measurement. Latency is
  **G-3**, whose threshold must be fixed externally first.
- **No `frozen_parameters` row was set**; rows 1–7, 9 and 10 remain UNSET, and row 8 and the frozen
  artifact are byte-unchanged.

## 11. Reproduction

```
uv sync --frozen
uv run python smoke/g4/spike.py          # exit 0; twelve mandatory checks
uv run pytest -q tests/test_oauth_as.py  # 78 tests
```

The regression suite is the durable form of this gate and is **platform-independent** — it drives a
loopback TLS socket, so unlike the Windows-only effect-ledger tests (ADR 0014) it must pass on Linux
CI too. The AS can also be run out-of-process as the runner will start it:

```
AASC_G4_AS_SEED=<hex> python -m src.sut.oauth_as <config.json>
```

which prints one JSON line carrying the bound port, the AS **public** JWK, and the TLS certificate.
